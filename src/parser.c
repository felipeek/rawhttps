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
#include "aes_cbc.h"

#define RAWHTTP_PARSER_CHUNK_SIZE 1024
#define RAWHTTP_PARSER_BUFFER_INITIAL_SIZE 1024 // Must be greater than RAWHTTP_PARSER_CHUNK_SIZE
#define RAWHTTP_PARSER_REQUEST_HEADER_DEFAULT_CAPACITY 16

#define LITTLE_ENDIAN_16(x) (((unsigned short)(x)[1]) | ((unsigned short)(x)[0] << 8))
#define LITTLE_ENDIAN_24(x) (((unsigned int)(x)[2]) | ((unsigned int)(x)[1] << 8) | ((unsigned int)(x)[0] << 16))

#include <stdio.h>
static void rawhttps_parser_buffer_print(const rawhttps_parser_buffer* phb)
{
	printf("Printing parser buffer...\n");
	for (int i = 0; i < phb->buffer_position_fetch; ++i)
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

// creates rawhttps_parser_buffer
static int rawhttps_parser_buffer_create(rawhttps_parser_buffer* phb)
{
	phb->buffer = malloc(sizeof(char) * RAWHTTP_PARSER_BUFFER_INITIAL_SIZE);
	if (!phb->buffer) return -1;
	phb->buffer_size = RAWHTTP_PARSER_BUFFER_INITIAL_SIZE;
	phb->buffer_end = 0;
	phb->buffer_position_fetch = 0;
	phb->buffer_position_get = 0;
	return 0;
}

// destroys rawhttps_parser_buffer
static void rawhttps_parser_buffer_destroy(rawhttps_parser_buffer* phb)
{
	free(phb->buffer);
}

// creates rawhttps_parser_state
int rawhttps_parser_state_create(rawhttps_parser_state* ps)
{
	if (rawhttps_parser_buffer_create(&ps->message_buffer))
		return -1;
	if (rawhttps_parser_buffer_create(&ps->record_buffer))
		return -1;
	ps->type = 0;
	return 0;
}

// destroys rawhttps_parser_state
int rawhttps_parser_state_destroy(rawhttps_parser_state* ps)
{
	rawhttps_parser_buffer_destroy(&ps->message_buffer);
	rawhttps_parser_buffer_destroy(&ps->record_buffer);
	return 0;
}

// fetches the next chunk of tcp data and stores in the phb buffer
static long long rawhttps_parser_fetch_next_tcp_chunk(rawhttps_parser_buffer* phb, int connected_socket)
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

// clear the phb buffer.
// data which was already used via 'get' functions will be released and the pointers will be adjusted
static void rawhttps_parser_buffer_clear(rawhttps_parser_buffer* phb)
{
	// As of now, this function should only be called after we had successfully parsed some kind of packet.
	// The buffer_position_fetch and buffer_position_get MUST be the same, since our code only fetches until the end of the next
	// packet, and after that we build the packet by getting also until the end of the packet.
	assert(phb->buffer_position_fetch == phb->buffer_position_get);
	memmove(phb->buffer, phb->buffer + phb->buffer_position_get, phb->buffer_end - phb->buffer_position_get);
	phb->buffer_end -= phb->buffer_position_get;
	phb->buffer_position_fetch -= phb->buffer_position_get;
	phb->buffer_position_get = 0;
}

// guarantees that the next 'num' bytes are available in the phb buffer.
static int rawhttps_parser_guarantee_next_bytes(rawhttps_parser_buffer* phb, int connected_socket, unsigned char** ptr, long long num)
{
	while (phb->buffer_position_fetch + num > phb->buffer_end)
		if (rawhttps_parser_fetch_next_tcp_chunk(phb, connected_socket) == -1)
			return -1;

	phb->buffer_position_fetch += num;
	*ptr = phb->buffer + phb->buffer_position_fetch - num;
	return 0;
}

// guarantees that the next record packet is available as a whole in the phb buffer.
static int rawhttps_parser_guarantee_record(rawhttps_parser_buffer* phb, int connected_socket)
{
	unsigned char* ptr;

	// fetch record header.
	// the fourth/fifth bytes are the length
	if (rawhttps_parser_guarantee_next_bytes(phb, connected_socket, &ptr, 5))
		return -1;

	unsigned short record_length = LITTLE_ENDIAN_16(ptr + 3);

	// get record
	if (rawhttps_parser_guarantee_next_bytes(phb, connected_socket, &ptr, record_length))
		return -1;

	return 0;
}

// gets next 'num' bytes from phb buffer.
// this function basically increments the internal buffer_position_get pointer and returns a pointer to the data via 'ptr'
// if the data was not fetched previously by the 'fetch' functions, an error is returned.
static int rawhttps_parser_get_next_bytes(rawhttps_parser_buffer* phb, long long num, unsigned char** ptr)
{
	if (phb->buffer_position_get + num > phb->buffer_position_fetch)
		return -1;

	phb->buffer_position_get += num;
	*ptr = phb->buffer + phb->buffer_position_get - num;
	return 0;
}

// gets the data of the next record packet and stores in the received buffer. The type is also returned via 'type'
static long long rawhttps_get_record_data(rawhttps_parser_buffer* record_buffer, int connected_socket,
	unsigned char* data, protocol_type* type, rawhttps_parser_crypto_data* cd)
{
	unsigned char* ptr;

	if (rawhttps_parser_guarantee_record(record_buffer, connected_socket))
		return -1;

	if (rawhttps_parser_get_next_bytes(record_buffer, 5, &ptr))
		return -1;
	unsigned short record_length = LITTLE_ENDIAN_16(ptr + 3);
	*type = *ptr;
	assert(record_length < RECORD_PROTOCOL_DATA_MAX_SIZE);
	if (rawhttps_parser_get_next_bytes(record_buffer, record_length, &ptr))
		return -1;

	if (cd->encryption_enabled)
		// currently we are skipping bytes if record_length % 16 != 0, they will be trash!
		aes_128_cbc_decrypt(ptr, cd->server_write_key, cd->server_write_IV, record_length / 16, data);
	else
		memcpy(data, ptr, record_length);

	rawhttps_parser_buffer_clear(record_buffer);
	return record_length;
}

// fetches the next record data and stores in the message buffer
static long long rawhttps_parser_message_fetch_next_record(rawhttps_parser_state* ps, int connected_socket,
	rawhttps_parser_crypto_data* cd)
{
	long long size_needed = ps->message_buffer.buffer_end + RECORD_PROTOCOL_DATA_MAX_SIZE;
	if (size_needed > ps->message_buffer.buffer_size)
	{
		ps->message_buffer.buffer = realloc(ps->message_buffer.buffer, size_needed);
		ps->message_buffer.buffer_size = size_needed;
	}

	long long size_read;
	if ((size_read = rawhttps_get_record_data(&ps->record_buffer, connected_socket,
		ps->message_buffer.buffer + ps->message_buffer.buffer_end, &ps->type, cd)) < 0)
		return -1;
	if (size_read == 0)
		return -1;
	ps->message_buffer.buffer_end += size_read;

	return size_read;
}

// fetches the next record data and stores it in the message buffer if and only if the message buffer is empty
// this is useful to force the protocol type to be fetched when the message buffer is empty...
static int rawhttps_parser_message_fetch_next_record_if_buffer_empty(rawhttps_parser_state* ps, int connected_socket,
	rawhttps_parser_crypto_data* cd)
{
	while (ps->message_buffer.buffer_end == 0)
		if (rawhttps_parser_message_fetch_next_record(ps, connected_socket, cd) == -1)
			return -1;

	return 0;
}

// guarantees that the next 'num' bytes are available in the message_buffer.
static int rawhttps_parser_message_guarantee_next_bytes(rawhttps_parser_state* ps, int connected_socket,
	unsigned char** ptr, long long num, rawhttps_parser_crypto_data* cd)
{
	while (ps->message_buffer.buffer_position_fetch + num > ps->message_buffer.buffer_end)
		if (rawhttps_parser_message_fetch_next_record(ps, connected_socket, cd) == -1)
			return -1;

	ps->message_buffer.buffer_position_fetch += num;
	*ptr = ps->message_buffer.buffer + ps->message_buffer.buffer_position_fetch - num;
	return 0;
}

// fetches the next message into the message_buffer
// this function makes sure that the next message is fully fetched and stored into the message_buffer
static int rawhttps_parser_message_guarantee_next_message(rawhttps_parser_state* ps, int connected_socket, rawhttps_parser_crypto_data* cd)
{
	unsigned char* ptr;
	unsigned short message_length;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_parser_message_fetch_next_record_if_buffer_empty(ps, connected_socket, cd))
		return -1;
	
	// Based on the protocol type, we can proceed by fetching the message length
	switch (ps->type)
	{
		case HANDSHAKE_PROTOCOL: {
			// For the handshake protocol, we must fetch 4 bytes to get the message length in the last 3 bytes. (the first byte is the message type)
			if (rawhttps_parser_message_guarantee_next_bytes(ps, connected_socket, &ptr, 4, cd))
				return -1;
			message_length = LITTLE_ENDIAN_24(ptr + 1);
		} break;
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			// For the change cipher spec protocol, the message length is always 1.
			message_length = 1; break;
		} break;
	}
	
	// Now, we just make sure that we fetched 'message_length' bytes and we are sure that the whole message is in the buffer :)
	if (rawhttps_parser_message_guarantee_next_bytes(ps, connected_socket, &ptr, message_length, cd))
		return -1;

	return 0;
}

// parses the next message into a tls_packet (packet parameter)
// this function assumes that the whole message was already fetched and is available in ps->message_buffer!
// also, packet->type must already be set by the caller.
static int rawhttps_parser_message_parse(tls_packet* packet, rawhttps_parser_state* ps)
{
	unsigned char* ptr;

	switch (packet->type)
	{
		// HANDSHAKE PROTOCOL TYPE
		case HANDSHAKE_PROTOCOL: {
			handshake_packet hp;
			// If we have a handshake packet, we must first get the first 4 bytes to get the message type and the message length.
			if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 4, &ptr))
				return -1;
			hp.hh.message_type = *ptr; ++ptr;
			hp.hh.message_length = LITTLE_ENDIAN_24(ptr); ptr += 3;

			rawhttps_print_handshake_header(&hp.hh);

			switch (hp.hh.message_type)
			{
				case CLIENT_HELLO_MESSAGE: {
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 2, &ptr)) return -1;
					hp.message.chm.ssl_version = LITTLE_ENDIAN_16(ptr);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 32, &ptr)) return -1;
					memcpy(hp.message.chm.random_number, ptr, 32);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 1, &ptr)) return -1;
					hp.message.chm.session_id_length = *ptr;
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.chm.session_id_length, &ptr)) return -1;
					hp.message.chm.session_id = malloc(sizeof(unsigned char) * hp.message.chm.session_id_length);
					memcpy(hp.message.chm.session_id, ptr, hp.message.chm.session_id_length);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 2, &ptr)) return -1;
					hp.message.chm.cipher_suites_length = LITTLE_ENDIAN_16(ptr);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.chm.cipher_suites_length, &ptr)) return -1;
					hp.message.chm.cipher_suites = malloc(sizeof(unsigned char) * hp.message.chm.session_id_length);
					memcpy(hp.message.chm.cipher_suites, ptr, hp.message.chm.cipher_suites_length);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 1, &ptr)) return -1;
					hp.message.chm.compression_methods_length = *ptr;
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.chm.compression_methods_length, &ptr)) return -1;
					hp.message.chm.compression_methods = malloc(sizeof(unsigned char) * hp.message.chm.compression_methods_length);
					memcpy(hp.message.chm.compression_methods, ptr, hp.message.chm.compression_methods_length);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 2, &ptr)) return -1;
					hp.message.chm.extensions_length = LITTLE_ENDIAN_16(ptr);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.chm.extensions_length, &ptr)) return -1;
					hp.message.chm.extensions = malloc(sizeof(unsigned char) * hp.message.chm.extensions_length);
					memcpy(hp.message.chm.extensions, ptr, hp.message.chm.extensions_length);

					rawhttps_print_clienthello_message(&hp.message.chm);
				} break;
				case CLIENT_KEY_EXCHANGE_MESSAGE: {
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 2, &ptr)) return -1;
					hp.message.ckem.premaster_secret_length = LITTLE_ENDIAN_16(ptr);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.ckem.premaster_secret_length, &ptr)) return -1;
					hp.message.ckem.premaster_secret = malloc(sizeof(unsigned char) * hp.message.ckem.premaster_secret_length);
					memcpy(hp.message.ckem.premaster_secret, ptr, hp.message.ckem.premaster_secret_length);
				} break;
				// Since we are the server, it doesn't make sense for us to parse these messages
				case SERVER_CERTIFICATE_MESSAGE:
				case SERVER_HELLO_DONE_MESSAGE:
				case SERVER_HELLO_MESSAGE: {
					return -1;
				}
			}

			packet->subprotocol.hp = hp;
		} break;
		// CHANGE CIPHER SPEC PROTOCOL TYPE
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			change_cipher_spec_packet ccsp;
			// If we have a change_cipher_spec packet, we can be sure that we only have to get a single byte, which is the 'message'
			// This byte must already be in the buffer! If it isn't, we throw an error
			if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 1, &ptr)) return -1;
			ccsp.message = *ptr;
			packet->subprotocol.ccsp = ccsp;
		} break;
	}
	
	// @TODO: We must decide how we will release packets.

	return 0;
}

// Parses the next SSL packet. The packet is returned via parameter 'packet'
int rawhttps_parser_parse_ssl_packet(rawhttps_parser_crypto_data* cd, tls_packet* packet, rawhttps_parser_state* ps,
	int connected_socket, dynamic_buffer* handshake_messages)
{
	// Get Message Data
	if (rawhttps_parser_message_guarantee_next_message(ps, connected_socket, cd))
		return -1;

	// Parse to TLS Packet
	packet->type = ps->type;

	// If the packet has type HANDSHAKE_PROTOCOL, before parsing we need to add its content to the handshake_messages buffer
	// This is needed by the full handshake when the FINISHED message is received.
	if (packet->type == HANDSHAKE_PROTOCOL)
		util_dynamic_buffer_add(handshake_messages, ps->message_buffer.buffer, ps->message_buffer.buffer_position_fetch);

	if (rawhttps_parser_message_parse(packet, ps))
		return -1;

	// Release Message Data
	rawhttps_parser_buffer_clear(&ps->message_buffer);
	return 0;
}