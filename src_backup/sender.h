#ifndef RAWHTTP_SENDER_H
#define RAWHTTP_SENDER_H
#include "http_parser.h"

s32 rawhttp_sender_send_server_hello(s32 connected_socket, u16 selected_cipher_suite);
s32 rawhttp_sender_send_server_certificate(s32 connected_socket, u8* certificate, s32 certificate_size);
s32 rawhttp_sender_send_server_hello_done(s32 connected_socket);
#endif