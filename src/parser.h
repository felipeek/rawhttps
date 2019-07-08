#ifndef RAWHTTPS_PARSER_H
#define RAWHTTPS_PARSER_H
#include "protocol.h"
typedef struct {
	unsigned char* buffer;
	long long buffer_size;
	long long buffer_end;
	long long buffer_position;
	long long packet_size;
} rawhttps_parser_buffer;

typedef struct {
	rawhttps_parser_buffer record_buffer;
	rawhttps_parser_buffer message_buffer;
	protocol_type type;
} rawhttps_message_buffer;

int rawhttps_parser_message_buffer_create(rawhttps_message_buffer* message_buffer);
int rawhttps_parser_message_buffer_destroy(rawhttps_message_buffer* message_buffer);
int rawhttps_parser_parse_ssl_packet(tls_packet* packet, rawhttps_message_buffer* message_buffer, int connected_socket);

#endif