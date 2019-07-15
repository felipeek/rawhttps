#ifndef RAWHTTPS_TLS_H
#define RAWHTTPS_TLS_H
#include "tls_parser.h"
#include "protocol.h"
#include "../util.h"
#include "crypto/asn1.h"

typedef struct
{
	rawhttps_tls_parser_state ps;
	rawhttps_security_parameters pending_client_security_parameters;
	rawhttps_security_parameters pending_server_security_parameters;
	rawhttps_connection_state client_connection_state;
	rawhttps_connection_state server_connection_state;
	dynamic_buffer handshake_messages;
	int hanshake_completed;
	RSA_Certificate certificate;
	PrivateKey private_key;
} rawhttps_tls_state;

int rawhttps_tls_state_create(rawhttps_tls_state* ts, const char* certificate_path, const char* private_key_path);
void rawhttps_tls_state_destroy(rawhttps_tls_state* ts);
int rawhttps_tls_handshake(rawhttps_tls_state* ts, int connected_socket);
long long rawhttps_tls_read(rawhttps_tls_state* ts, int connected_socket,
	unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE]);
long long rawhttps_tls_write(rawhttps_tls_state* ts, int connected_socket,
	unsigned char* data, long long count);
#endif