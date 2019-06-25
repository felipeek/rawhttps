#include "http_parser.h"
#include "server.h"
#include "logger.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "util.h"

#define PARSER_CHUNK_SIZE 1024
#define PARSER_BUFFER_INITIAL_SIZE 1024 // Must be greater than PARSER_CHUNK_SIZE
#define REQUEST_HEADER_DEFAULT_CAPACITY 16

#define LITTLE_ENDIAN_16(x) (((u16)(x)[1]) | ((u16)(x)[0] << 8))
#define LITTLE_ENDIAN_24(x) (((u32)(x)[2]) | ((u32)(x)[1] << 8) | ((u32)(x)[0] << 16))
#define LITTLE_ENDIAN_32(x) (((u32)(x)[3]) | ((u32)(x)[2] << 8) | ((u32)(x)[1] << 16) | ((u32)(x)[0] << 24))

typedef struct {
	unsigned char* buffer;
	s64 buffer_size;
	s64 buffer_end;
	s64 buffer_position;
} parser_buffer;

static s64 fetch_next_chunk(parser_buffer* pb, s32 connected_socket)
{
	s64 size_needed = pb->buffer_end + PARSER_CHUNK_SIZE;
	if (size_needed > pb->buffer_size)
	{
		pb->buffer = realloc(pb->buffer, size_needed);
		pb->buffer_size = size_needed;
	}

	s64 size_read;
	if ((size_read = read(connected_socket, pb->buffer + pb->buffer_end, PARSER_CHUNK_SIZE)) < 0)
	{
		logger_log_error("fetch_next_chunk: error reading next chunk of data: %s", strerror(errno));
		return -1;
	}
	if (size_read == 0)
	{
		logger_log_error("fetch_next_chunk: no more data to receive");
		return -1;
	}
	pb->buffer_end += size_read;

	logger_log_debug("fetch_next_chunk: got packet with %d bytes", size_read);
	return size_read;
}

// lets make rawhttp also have this function to make the parser a bit better
static unsigned char* get_next_bytes(parser_buffer* pb, s64 num, s32 connected_socket)
{
	while (pb->buffer_position + num > pb->buffer_end)
		if (fetch_next_chunk(pb, connected_socket) == -1)
		{
			logger_log_error("get_next_bytes: parser error; error getting next bytes");
			return NULL;
		}

	pb->buffer_position += num;
	return pb->buffer + pb->buffer_position - num;
}

static void print_record_header(const record_header* rp)
{
	char buffer[1024];
	sprintf(buffer, "**RECORD_PACKET**\n\tHandshake Type: %02X\n\tSSL_VERSION: %hu\n\tRECORD_LENGTH: %hu\n",
		rp->protocol_type, rp->ssl_version, rp->record_length);
	logger_log_debug(buffer);
}

static void print_handshake_header(const handshake_header* hp)
{
	char buffer[1024];
	sprintf(buffer, "**HANDSHAKE_PACKET**\n\tMessage Type: %02X\n\tMessage Length: %u\n",
		hp->message_type, hp->message_length);
	logger_log_debug(buffer);
}

static void print_clienthello_message(const client_hello_message* chmt)
{
	char random_number[1024];
	s64 written = 0;
	for (s64 i = 0; i < 32; ++i)
		written += sprintf(random_number + written, "%02X ", chmt->random_number[i]);

	char msg[] = "**CLIENTHELLO_MESSAGE*\n" \
		"random number: %.*s\n" \
		"session_id_length: %u\n" \
		"cipher_suites_length: %hu\n" \
		"compression_methods_length: %u\n" \
		"extensions_length: %u\n";
	char buffer[1024];
	sprintf(buffer, msg, written, random_number, chmt->session_id_length, chmt->cipher_suites_length,
		chmt->compression_methods_length, chmt->extensions_length);
	logger_log_debug(buffer);
}

s32 rawhttp_parser_parse(tls_packet* packet, s32 connected_socket)
{
	unsigned char* ptr;

	parser_buffer pb;
	pb.buffer = malloc(sizeof(char) * PARSER_BUFFER_INITIAL_SIZE);
	pb.buffer_size = PARSER_BUFFER_INITIAL_SIZE;
	pb.buffer_end = 0;
	pb.buffer_position = 0;

	ptr = get_next_bytes(&pb, 5, connected_socket); if (!ptr) return -1;

	packet->rh.protocol_type = *ptr; ++ptr;
	packet->rh.ssl_version = LITTLE_ENDIAN_16(ptr); ptr += 2;
	packet->rh.record_length = LITTLE_ENDIAN_16(ptr); ptr += 2;

	print_record_header(&packet->rh);

	ptr = get_next_bytes(&pb, packet->rh.record_length, connected_socket); if (!ptr) return -1;
	logger_log_debug("fetched total size %d", pb.buffer_end);
	util_buffer_print_hex(pb.buffer, pb.buffer_end);

	switch (packet->rh.protocol_type)
	{
		// Handshake protocol type
		case HANDSHAKE_PROTOCOL: {
			packet->subprotocol.hp.hh.message_type = *ptr; ++ptr;
			packet->subprotocol.hp.hh.message_length = LITTLE_ENDIAN_24(ptr); ptr += 3;

			print_handshake_header(&packet->subprotocol.hp.hh);

			switch (packet->subprotocol.hp.hh.message_type)
			{
				// ClientHello message
				case CLIENT_HELLO_MESSAGE: {
					packet->subprotocol.hp.message.chm.ssl_version = LITTLE_ENDIAN_16(ptr); ptr += 2;
					packet->subprotocol.hp.message.chm.random_number = ptr; ptr += 32;
					packet->subprotocol.hp.message.chm.session_id_length = *ptr; ++ptr;
					packet->subprotocol.hp.message.chm.session_id = ptr; ptr += packet->subprotocol.hp.message.chm.session_id_length;
					packet->subprotocol.hp.message.chm.cipher_suites_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
					packet->subprotocol.hp.message.chm.cipher_suites = (u16*)(ptr); ptr += packet->subprotocol.hp.message.chm.cipher_suites_length;
					
					packet->subprotocol.hp.message.chm.compression_methods_length = *ptr; ++ptr;
					packet->subprotocol.hp.message.chm.compression_methods = ptr; ptr += packet->subprotocol.hp.message.chm.compression_methods_length;

					packet->subprotocol.hp.message.chm.extensions_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
					packet->subprotocol.hp.message.chm.extensions = ptr; ptr += packet->subprotocol.hp.message.chm.extensions_length;

					print_clienthello_message(&packet->subprotocol.hp.message.chm);
				} break;
				case SERVER_HELLO_MESSAGE: {
					// @TODO: fix leaks...
					return -1;
				}
				case CLIENT_KEY_EXCHANGE_MESSAGE: {
					packet->subprotocol.hp.message.ckem.premaster_secret_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
					packet->subprotocol.hp.message.ckem.premaster_secret = ptr;
				} break;
			}
		} break;
	}


	return 0;
}