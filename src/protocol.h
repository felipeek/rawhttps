#ifndef RAWHTTPS_PROTOCOL_H
#define RAWHTTPS_PROTOCOL_H
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
	unsigned short ssl_version;
	unsigned short record_length;
} record_header;

typedef struct {
	handshake_message_type message_type;
	unsigned int message_length;
} handshake_header;

typedef struct {
	unsigned short ssl_version;
	unsigned char* random_number; // 32 bytes
	unsigned char session_id_length;
	unsigned char* session_id;
	unsigned short cipher_suites_length;
	unsigned short* cipher_suites;
	unsigned char compression_methods_length;
	unsigned char* compression_methods;
	unsigned short extensions_length;
	unsigned char* extensions;
} client_hello_message;

typedef struct {
	unsigned short ssl_version;
	unsigned char* random_number;
	unsigned char session_id_length;
	unsigned char* session_id;
	unsigned short selected_cipher_suite;
	unsigned char selected_compression_method;
	unsigned short extensions_length;
	unsigned char* extensions;
} server_hello_message;

typedef struct {
	unsigned int size;
	unsigned char* data;
} certificate_info;

typedef struct {
	unsigned int number_of_certificates;
	certificate_info* certificate_info;
} server_certificate_message;

typedef struct {
	unsigned short premaster_secret_length;
	unsigned char* premaster_secret;
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
	unsigned char message;
} change_cipher_spec_packet;

typedef struct {
	protocol_type type;
	union {
		handshake_packet hp;
		change_cipher_spec_packet ccsp;
	} subprotocol;
} tls_packet;
#endif