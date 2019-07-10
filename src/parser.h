#ifndef RAWHTTPS_PARSER_H
#define RAWHTTPS_PARSER_H
#include "protocol.h"
#include "util.h"
typedef struct {
	unsigned char* buffer;
	long long buffer_size;
	long long buffer_end;

	long long buffer_position_get;
	long long buffer_position_fetch;
} rawhttps_parser_buffer;

typedef struct {
	rawhttps_parser_buffer record_buffer;
	rawhttps_parser_buffer message_buffer;
	protocol_type type;
} rawhttps_parser_state;

typedef struct {
	int encryption_enabled;
	unsigned char server_write_key[16];
	unsigned char server_write_IV[16];
} rawhttps_parser_crypto_data;

int rawhttps_parser_state_create(rawhttps_parser_state* ps);
int rawhttps_parser_state_destroy(rawhttps_parser_state* ps);
int rawhttps_parser_parse_ssl_packet(rawhttps_parser_crypto_data* cd, tls_packet* packet, rawhttps_parser_state* ps,
	int connected_socket, dynamic_buffer* handshake_messages);

#endif