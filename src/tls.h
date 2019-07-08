#ifndef RAWHTTPS_TLS_H
#define RAWHTTPS_TLS_H
#include "parser.h"
#include "protocol.h"

int rawhttps_tls_handshake(rawhttps_message_buffer* message_buffer, int connected_socket);

#endif