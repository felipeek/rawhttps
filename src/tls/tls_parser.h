#ifndef RAWHTTPS_TLS_PARSER_H
#define RAWHTTPS_TLS_PARSER_H
#include "protocol.h"
#include "../util.h"
#include "record.h"
typedef struct {
	unsigned char* buffer;
	long long buffer_size;
	long long buffer_end;

	long long buffer_position_get;
} rawhttps_higher_layer_buffer;

typedef struct {
	rawhttps_record_buffer record_buffer;
	rawhttps_higher_layer_buffer higher_layer_buffer;
	protocol_type type;
} rawhttps_tls_parser_state;

int rawhttps_tls_parser_state_create(rawhttps_tls_parser_state* ps);
void rawhttps_tls_parser_state_destroy(rawhttps_tls_parser_state* ps);
int rawhttps_tls_parser_change_cipher_spec_parse(change_cipher_spec_packet* packet, rawhttps_tls_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_cs);
int rawhttps_tls_parser_handshake_packet_parse(handshake_packet* packet, rawhttps_tls_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_cs, dynamic_buffer* handshake_messages);
int rawhttps_tls_parser_protocol_type_get_next(rawhttps_tls_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_connection_state, protocol_type* type);
int rawhttps_tls_parser_application_data_parse(char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE], long long* bytes_written,
	rawhttps_tls_parser_state* ps, int connected_socket, rawhttps_connection_state* client_cs);
void rawhttps_tls_parser_change_cipher_spec_release(change_cipher_spec_packet* packet);
void rawhttps_tls_parser_handshake_packet_release(handshake_packet* packet);
#endif