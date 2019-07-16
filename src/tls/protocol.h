#ifndef RAWHTTPS_PROTOCOL_H
#define RAWHTTPS_PROTOCOL_H

#define BIG_ENDIAN_16(x) ((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
// note: for BIG_ENDIAN_24, since we receive an unsigned int, we keep the last byte untouched, i.e.
// 01 02 03 04 05 06 00 00 is transformed to 05 06 03 04 01 02 00 00
#define BIG_ENDIAN_24(x) ((((x) & 0x000000FF) << 16) | (((x) & 0x00FF0000) >> 16) | ((x) & 0x0000FF00))
#define BIG_ENDIAN_32(x) ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))
#define BIG_ENDIAN_64(X) ((((X) & 0xff00000000000000) >> 56) | \
    (((X) & 0xff000000000000) >> 40) | \
    (((X) & 0xff0000000000) >> 24) | \
    (((X) & 0xff00000000) >> 8) | \
    (((X) & 0xff000000) << 8) | \
    (((X) & 0xff0000) << 24) | \
    (((X) & 0xff00) << 40) | \
    (((X) & 0xff) << 56))
#define LITTLE_ENDIAN_16(x) (((unsigned short)(x)[1]) | ((unsigned short)(x)[0] << 8))
#define LITTLE_ENDIAN_24(x) (((unsigned int)(x)[2]) | ((unsigned int)(x)[1] << 8) | ((unsigned int)(x)[0] << 16))

// In the record protocol, the cipher text can have 2048 bytes more than the plain text
// Reference: https://tools.ietf.org/html/rfc5246#section-6.2.3 (TLS 1.2)
#define RECORD_PROTOCOL_TLS_HEADER_SIZE 5
#define RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE 16384
#define RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE (RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE + RECORD_PROTOCOL_TLS_HEADER_SIZE)
#define RECORD_PROTOCOL_TLS_CIPHER_TEXT_FRAGMENT_MAX_SIZE (RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE + 2048)
#define RECORD_PROTOCOL_TLS_CIPHER_TEXT_MAX_SIZE (RECORD_PROTOCOL_TLS_CIPHER_TEXT_FRAGMENT_MAX_SIZE + RECORD_PROTOCOL_TLS_HEADER_SIZE)

#define TLS12 0x0303
#define TLS11 0x0302
#define TLS10 0x0301

#define CLIENT_RANDOM_SIZE 32
#define SERVER_RANDOM_SIZE 32
#define MASTER_SECRET_SIZE 48

// The maximum size for the key material is 128 bytes (TLS 1.2)
// ref: https://tools.ietf.org/html/rfc5246#section-6.3
#define KEY_BLOCK_MAX_LENGTH 128
// https://tools.ietf.org/html/rfc5246#appendix-C
#define CIPHER_MAC_KEY_MAX_LENGTH 32	// mac_key_length
#define CIPHER_ENC_KEY_MAX_LENGTH 32	// Key Material
#define CIPHER_IV_MAX_LENGTH 16			// IV Size 
#define CIPHER_BLOCK_SIZE_MAX_LENGTH 32	// Block Size
#define CIPHER_MAC_MAX_LENGTH 32		// mac_length

typedef enum {
	TLS_NULL_WITH_NULL_NULL = 0x0000,
	TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
} cipher_suite_type;

typedef enum {
	HANDSHAKE_PROTOCOL = 0x16,
	CHANGE_CIPHER_SPEC_PROTOCOL = 0x14,
	APPLICATION_DATA_PROTOCOL = 0x17
} protocol_type;

typedef enum {
	CLIENT_HELLO_MESSAGE = 0x01,
	SERVER_HELLO_MESSAGE = 0x02,
	SERVER_CERTIFICATE_MESSAGE = 0x0B,
	SERVER_HELLO_DONE_MESSAGE = 0x0E,
	CLIENT_KEY_EXCHANGE_MESSAGE = 0x10,
	FINISHED_MESSAGE = 0x14
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
	unsigned char client_random[CLIENT_RANDOM_SIZE];
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

typedef enum {
	BULK_CIPHER_ALGORITHM_NULL,
	BULK_CIPHER_ALGORITHM_RC4,
	BULK_CIPHER_ALGORITHM_DES,
	BULK_CIPHER_ALGORITHM_AES
} bulk_cipher_algorithm_type;

typedef enum {
	CIPHER_STREAM,
	CIPHER_BLOCK,
	CIPHER_AEAD
} cipher_type;

typedef enum {
	MAC_ALGORITHM_NULL,
	MAC_ALGORITHM_HMAC_MD5,
	MAC_ALGORITHM_HMAC_SHA1,
	MAC_ALGORITHM_HMAC_SHA256,
	MAC_ALGORITHM_HMAC_SHA384,
	MAC_ALGORITHM_HMAC_SHA512
} mac_algorithm_type;

typedef enum {
	CONNECTION_END_CLIENT,
	CONNECTION_END_SERVER
} connection_end;

typedef struct {
	//prf_algorithm_type prf_algorithm;
	bulk_cipher_algorithm_type bulk_cipher_algorithm;
	cipher_type cipher;
	unsigned char enc_key_length;
	unsigned char block_length;
	unsigned char fixed_iv_length;
	unsigned char record_iv_length;
	mac_algorithm_type mac_algorithm;
	unsigned char mac_length;
	unsigned char mac_key_length;
	unsigned char master_secret[MASTER_SECRET_SIZE];
	unsigned char client_random[CLIENT_RANDOM_SIZE];
	unsigned char server_random[SERVER_RANDOM_SIZE];
} rawhttps_security_parameters;

typedef struct {
	unsigned char enc_key[CIPHER_ENC_KEY_MAX_LENGTH];
	unsigned char iv[CIPHER_IV_MAX_LENGTH];
} cipher_state;

typedef struct {
	rawhttps_security_parameters security_parameters;
	cipher_state cipher_state;
	unsigned char mac_key[CIPHER_MAC_KEY_MAX_LENGTH];
	unsigned long long sequence_number;
} rawhttps_connection_state;
#endif