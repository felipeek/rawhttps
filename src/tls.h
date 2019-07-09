#ifndef RAWHTTPS_TLS_H
#define RAWHTTPS_TLS_H
#include "parser.h"
#include "protocol.h"
#include "util.h"

typedef struct
{
	unsigned char client_random_number[32];
	unsigned char server_random_number[32];
	// The premaster secret has 48 bytes when the key-exchange method is RSA! Be careful when implementing DH!
	unsigned char pre_master_secret[48];
	unsigned char master_secret[48];

	unsigned char client_write_mac_key[20];
	unsigned char server_write_mac_key[20];
	unsigned char client_write_key[16];
	unsigned char server_write_key[16];
	unsigned char client_write_IV[16];
	unsigned char server_write_IV[16];

	int encryption_enabled;
} rawhttps_tls_state;

int rawhttps_tls_state_create(rawhttps_tls_state* ts);
void rawhttps_tls_state_destroy(rawhttps_tls_state* ts);
int rawhttps_tls_handshake(rawhttps_tls_state* ts, rawhttps_parser_state* ps, int connected_socket);

#endif