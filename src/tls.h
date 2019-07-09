#ifndef RAWHTTPS_TLS_H
#define RAWHTTPS_TLS_H
#include "parser.h"
#include "protocol.h"

int rawhttps_tls_state_create(rawhttps_tls_state* ts);
void rawhttps_tls_state_destroy(rawhttps_tls_state* ts);
int rawhttps_tls_handshake(rawhttps_tls_state* ts, rawhttps_parser_state* ps, int connected_socket);

#endif