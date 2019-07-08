/***
 *      _____                         
 *     |  __ \                        
 *     | |__) |_ _ _ __ ___  ___ _ __ 
 *     |  ___/ _` | '__/ __|/ _ \ '__|
 *     | |  | (_| | |  \__ \  __/ |   
 *     |_|   \__,_|_|  |___/\___|_|   
 *                                    
 *                                    
 */

#include "parser.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#define RAWHTTP_PARSER_CHUNK_SIZE 1024
#define RAWHTTP_PARSER_BUFFER_INITIAL_SIZE 1024 // Must be greater than RAWHTTP_PARSER_CHUNK_SIZE
#define RAWHTTP_PARSER_REQUEST_HEADER_DEFAULT_CAPACITY 16
#define RECORD_PROTOCOL_DATA_MAX_SIZE 16384

#define LITTLE_ENDIAN_16(x) (((unsigned short)(x)[1]) | ((unsigned short)(x)[0] << 8))
#define LITTLE_ENDIAN_24(x) (((unsigned int)(x)[2]) | ((unsigned int)(x)[1] << 8) | ((unsigned int)(x)[0] << 16))


#include <stdio.h>
static void rawhttps_parser_buffer_print(const rawhttps_parser_buffer* phb)
{
	printf("Printing parser buffer...\n");
	for (int i = 0; i < phb->packet_size; ++i)
	{
		printf("%02hhX ", phb->buffer[i]);
	}
	printf("\n");
}

static void rawhttps_print_record_header(const record_header* rp)
{
	printf("**RECORD_PACKET**\n\tHandshake Type: %02X\n\tSSL_VERSION: %hu\n\tRECORD_LENGTH: %hu\n",
		rp->protocol_type, rp->ssl_version, rp->record_length);
}

static void rawhttps_print_handshake_header(const handshake_header* hp)
{
	printf("**HANDSHAKE_PACKET**\n\tMessage Type: %02X\n\tMessage Length: %u\n", hp->message_type, hp->message_length);
}

static void rawhttps_print_clienthello_message(const client_hello_message* chmt)
{
	char random_number[1024];
	long long written = 0;
	for (long long i = 0; i < 32; ++i)
		written += sprintf(random_number + written, "%02X ", chmt->random_number[i]);

	char msg[] = "**CLIENTHELLO_MESSAGE*\n" \
		"random number: %.*s\n" \
		"session_id_length: %u\n" \
		"cipher_suites_length: %hu\n" \
		"compression_methods_length: %u\n" \
		"extensions_length: %u\n";
	printf(msg, written, random_number, chmt->session_id_length, chmt->cipher_suites_length,
		chmt->compression_methods_length, chmt->extensions_length);
}

static long long rawhttps_parser_fetch_next_chunk(rawhttps_parser_buffer* phb, int connected_socket)
{
	long long size_needed = phb->buffer_end + RAWHTTP_PARSER_CHUNK_SIZE;
	if (size_needed > phb->buffer_size)
	{
		phb->buffer = realloc(phb->buffer, size_needed);
		phb->buffer_size = size_needed;
	}

	long long size_read;
	if ((size_read = read(connected_socket, phb->buffer + phb->buffer_end, RAWHTTP_PARSER_CHUNK_SIZE)) < 0)
		return -1;
	if (size_read == 0)
		return -1;
	phb->buffer_end += size_read;

	return size_read;
}

static void rawhttps_parser_buffer_clear(rawhttps_parser_buffer* phb)
{
	memmove(phb->buffer, phb->buffer + phb->buffer_position, phb->buffer_end - phb->buffer_position);
	phb->buffer_end = phb->buffer_end - phb->buffer_position;
	phb->buffer_position = 0;
	phb->packet_size = 0;
}

static int rawhttps_parser_fetch_next_bytes(rawhttps_parser_buffer* phb, int connected_socket, unsigned char** ptr, long long num)
{
	while (phb->packet_size + num > phb->buffer_end)
		if (rawhttps_parser_fetch_next_chunk(phb, connected_socket) == -1)
			return -1;

	phb->packet_size += num;
	*ptr = phb->buffer + phb->packet_size - num;
	return 0;
}

static int rawhttps_parser_fetch_record(rawhttps_parser_buffer* phb, int connected_socket)
{
	unsigned char* ptr;

	// fetch record header.
	// the fourth/fifth bytes are the length
	if (rawhttps_parser_fetch_next_bytes(phb, connected_socket, &ptr, 5))
		return -1;

	unsigned short record_length = LITTLE_ENDIAN_16(ptr + 3);

	// get record
	if (rawhttps_parser_fetch_next_bytes(phb, connected_socket, &ptr, record_length))
		return -1;

	return 0;
}

static int rawhttps_parser_get_next_bytes(rawhttps_parser_buffer* phb, long long num, unsigned char** ptr)
{
	if (phb->buffer_position + num > phb->packet_size)
		return -1;

	phb->buffer_position += num;
	*ptr = phb->buffer + phb->buffer_position - num;
	return 0;
}

static int rawhttps_parser_buffer_create(rawhttps_parser_buffer* phb)
{
	phb->buffer = malloc(sizeof(char) * RAWHTTP_PARSER_BUFFER_INITIAL_SIZE);
	if (!phb->buffer) return -1;
	phb->buffer_size = RAWHTTP_PARSER_BUFFER_INITIAL_SIZE;
	phb->buffer_end = 0;
	phb->packet_size = 0;
	phb->buffer_position = 0;
	return 0;
}

static void rawhttps_parser_buffer_destroy(rawhttps_parser_buffer* phb)
{
	free(phb->buffer);
}

int rawhttps_parser_message_buffer_create(rawhttps_message_buffer* message_buffer)
{
	if (rawhttps_parser_buffer_create(&message_buffer->message_buffer))
		return -1;
	if (rawhttps_parser_buffer_create(&message_buffer->record_buffer))
		return -1;
	message_buffer->type = 0;
	return 0;
}

int rawhttps_parser_message_buffer_destroy(rawhttps_message_buffer* message_buffer)
{
	rawhttps_parser_buffer_destroy(&message_buffer->message_buffer);
	rawhttps_parser_buffer_destroy(&message_buffer->record_buffer);
	return 0;
}

static long long rawhttps_get_record_data(rawhttps_parser_buffer* record_buffer, int connected_socket, unsigned char* data,	protocol_type* type)
{
	unsigned char* ptr;

	if (rawhttps_parser_fetch_record(record_buffer, connected_socket))
		return -1;

	if (rawhttps_parser_get_next_bytes(record_buffer, 5, &ptr))
		return -1;
	unsigned short record_length = LITTLE_ENDIAN_16(ptr + 3);
	*type = *ptr;
	assert(record_length < RECORD_PROTOCOL_DATA_MAX_SIZE);
	if (rawhttps_parser_get_next_bytes(record_buffer, record_length, &ptr))
		return -1;

	memcpy(data, ptr, record_length);

	rawhttps_parser_buffer_clear(record_buffer);
	return record_length;
}

static long long rawhttps_parser_message_fetch_next_chunk(rawhttps_message_buffer* message_buffer, int connected_socket)
{
	long long size_needed = message_buffer->message_buffer.buffer_end + RECORD_PROTOCOL_DATA_MAX_SIZE;
	if (size_needed > message_buffer->message_buffer.buffer_size)
	{
		message_buffer->message_buffer.buffer = realloc(message_buffer->message_buffer.buffer, size_needed);
		message_buffer->message_buffer.buffer_size = size_needed;
	}

	long long size_read;
	if ((size_read = rawhttps_get_record_data(&message_buffer->record_buffer, connected_socket,
		message_buffer->message_buffer.buffer + message_buffer->message_buffer.buffer_end, &message_buffer->type)) < 0)
		return -1;
	if (size_read == 0)
		return -1;
	message_buffer->message_buffer.buffer_end += size_read;

	return size_read;
}

static int rawhttps_parser_message_fetch_next_bytes(rawhttps_message_buffer* message_buffer, int connected_socket,
	unsigned char** ptr, long long num)
{
	while (message_buffer->message_buffer.packet_size + num > message_buffer->message_buffer.buffer_end)
		if (rawhttps_parser_message_fetch_next_chunk(message_buffer, connected_socket) == -1)
			return -1;

	message_buffer->message_buffer.packet_size += num;
	*ptr = message_buffer->message_buffer.buffer + message_buffer->message_buffer.packet_size - num;
	return 0;
}

static int rawhttps_parser_message_fetch_record_data_if_buffer_empty(rawhttps_message_buffer* message_buffer, int connected_socket)
{
	while (message_buffer->message_buffer.buffer_end == 0)
		if (rawhttps_parser_message_fetch_next_chunk(message_buffer, connected_socket) == -1)
			return -1;

	return 0;
}

static int rawhttps_parser_message_fetch_message(rawhttps_message_buffer* message_buffer, int connected_socket)
{
	unsigned char* ptr;
	unsigned short message_length;

	// We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_parser_message_fetch_record_data_if_buffer_empty(message_buffer, connected_socket))
		return -1;
	switch (message_buffer->type)
	{
		case HANDSHAKE_PROTOCOL: {
			if (rawhttps_parser_message_fetch_next_bytes(message_buffer, connected_socket, &ptr, 4))
				return -1;
			message_length = LITTLE_ENDIAN_24(ptr + 1);
		} break;
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			message_length = 1; break;
		} break;
	}
	if (rawhttps_parser_message_fetch_next_bytes(message_buffer, connected_socket, &ptr, message_length))
		return -1;
	return 0;
}

static int rawhttps_parser_message_parse(tls_packet* packet, rawhttps_message_buffer* message_buffer)
{
	unsigned char* ptr;

	switch (packet->type)
	{
		// handshake protocol type
		case HANDSHAKE_PROTOCOL: {
			handshake_packet hp;
			// request 4 bytes, to get the type and the length.
			if (rawhttps_parser_get_next_bytes(&message_buffer->message_buffer, 4, &ptr))
				return -1;
			hp.hh.message_type = *ptr; ++ptr;
			hp.hh.message_length = LITTLE_ENDIAN_24(ptr); ptr += 3;

			rawhttps_print_handshake_header(&hp.hh);

			if (rawhttps_parser_get_next_bytes(&message_buffer->message_buffer, hp.hh.message_length, &ptr))
				return -1;

			switch (hp.hh.message_type)
			{
				// clienthello message
				case CLIENT_HELLO_MESSAGE: {
					hp.message.chm.ssl_version = LITTLE_ENDIAN_16(ptr); ptr += 2;
					hp.message.chm.random_number = ptr; ptr += 32;
					hp.message.chm.session_id_length = *ptr; ++ptr;
					hp.message.chm.session_id = ptr; ptr += hp.message.chm.session_id_length;
					hp.message.chm.cipher_suites_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
					hp.message.chm.cipher_suites = (unsigned short*)(ptr); ptr += hp.message.chm.cipher_suites_length;
					
					hp.message.chm.compression_methods_length = *ptr; ++ptr;
					hp.message.chm.compression_methods = ptr; ptr += hp.message.chm.compression_methods_length;

					hp.message.chm.extensions_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
					hp.message.chm.extensions = ptr; ptr += hp.message.chm.extensions_length;

					rawhttps_print_clienthello_message(&hp.message.chm);
				} break;
				case SERVER_CERTIFICATE_MESSAGE:
				case SERVER_HELLO_DONE_MESSAGE:
				case SERVER_HELLO_MESSAGE: {
					// @todo: fix leaks...
					return -1;
				}
				case CLIENT_KEY_EXCHANGE_MESSAGE: {
					hp.message.ckem.premaster_secret_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
					hp.message.ckem.premaster_secret = ptr;
				} break;
			}

			packet->subprotocol.hp = hp;
		} break;
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			change_cipher_spec_packet ccsp;
			if (rawhttps_parser_get_next_bytes(&message_buffer->message_buffer, 1, &ptr))
				return -1;
			ccsp.message = *ptr; ++ptr;
			packet->subprotocol.ccsp = ccsp;
		} break;
	}
	
	return 0;
}

int rawhttps_parser_parse_ssl_packet(tls_packet* packet, rawhttps_message_buffer* message_buffer, int connected_socket)
{
	// Get Message Data
	if (rawhttps_parser_message_fetch_message(message_buffer, connected_socket))
		return -1;

	// Parse to TLS Packet
	packet->type = message_buffer->type;
	if (rawhttps_parser_message_parse(packet, message_buffer))
		return -1;

	// Release Message Data
	rawhttps_parser_buffer_clear(&message_buffer->message_buffer);
	return 0;
}