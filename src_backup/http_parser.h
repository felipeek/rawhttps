#ifndef RAWHTTP_PARSER_H
#define RAWHTTP_PARSER_H
#include "common.h"
#include "server.h"

typedef enum {
	HANDSHAKE_PROTOCOL = 0x16,
	CHANGE_CIPHER_SPEC_PROTOCOL = 0x14
} protocol_type;

typedef enum {
	CLIENT_HELLO_MESSAGE = 0x01,
	SERVER_HELLO_MESSAGE = 0x02,
	SERVER_CERTIFICATE_MESSAGE = 0x0B,
	SERVER_HELLO_DONE_MESSAGE = 0x0E,
	CLIENT_KEY_EXCHANGE_MESSAGE = 0x10,
} handshake_message_type;

typedef enum {
	CHANGE_CIPHER_SPEC_MESSAGE = 0x01
} change_cipher_spec_type;

typedef struct {
	protocol_type protocol_type;
	u16 ssl_version;
	u16 record_length;
} record_header;

typedef struct {
	handshake_message_type message_type;
	u32 message_length;
} handshake_header;

typedef struct {
	u16 ssl_version;
	u8* random_number; // 32 bytes
	u8 session_id_length;
	u8* session_id;
	u16 cipher_suites_length;
	u16* cipher_suites;
	u8 compression_methods_length;
	u8* compression_methods;
	u16 extensions_length;
	u8* extensions;
} client_hello_message;

typedef struct {
	u16 ssl_version;
	u8* random_number;
	u8 session_id_length;
	u8* session_id;
	u16 selected_cipher_suite;
	u8 selected_compression_method;
	u16 extensions_length;
	u8* extensions;
} server_hello_message;

typedef struct {
	u32 size;
	u8* data;
} certificate_info;

typedef struct {
	u32 number_of_certificates;
	certificate_info* certificate_info;
} server_certificate_message;

typedef struct {
	u16 premaster_secret_length;
	u8* premaster_secret;
} client_key_exchange_message;

typedef struct {
	handshake_header hh;
	union {
		client_hello_message chm;
		server_hello_message shm;
		server_certificate_message scm;
		client_key_exchange_message ckem;
	} message;
} handshake_packet;

typedef struct {
	u8 message;
} change_cipher_spec_packet;

typedef struct {
	record_header rh;
	union {
		handshake_packet hp;
		change_cipher_spec_packet ccsp;
	} subprotocol;
} tls_packet;

s32 rawhttp_parser_parse(tls_packet* packet, s32 connected_socket);
#endif