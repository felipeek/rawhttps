#include "tls.h"
#include "parser.h"
#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include "hobig.h"
#include "asn1.h"
#include "pkcs1.h"

// SENDER !
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define BIG_ENDIAN_16(x) ((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
// note: for BIG_ENDIAN_24, since we receive an unsigned int, we keep the last byte untouched, i.e.
// 01 02 03 04 05 06 00 00 is transformed to 05 06 03 04 01 02 00 00
#define BIG_ENDIAN_24(x) ((((x) & 0x000000FF) << 16) | (((x) & 0x00FF0000) >> 16) | ((x) & 0x0000FF00))
#define BIG_ENDIAN_32(x) ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))

static int send_record(const char* data, int record_size, protocol_type type, int connected_socket)
{
	struct iovec iov[2];
	unsigned char record_header[5];
	record_header[0] = type;
	*(unsigned short*)(record_header + 1) = BIG_ENDIAN_16(0x0301);
	*(unsigned short*)(record_header + 3) = BIG_ENDIAN_16(record_size);

	iov[0].iov_base = record_header;
	iov[0].iov_len = 5;
	iov[1].iov_base = data;
	iov[1].iov_len = record_size;

	ssize_t written = writev(connected_socket, iov, 2);

	// @TODO: in an excepcional case, writev() could write less bytes than requested...
	// we should look at writev() documentation and decide what to do in this particular case
	// for now, throw an error...
	if (written != 5 + record_size)
		return -1;
	
	return 0;
}

static int send_higher_layer_packet(const char* data, long long size, protocol_type type, int connected_socket)
{
	long long size_remaining = size;
	while (size_remaining > 0)
	{
		long long size_to_send = MIN(RECORD_PROTOCOL_DATA_MAX_SIZE, size_remaining);
		long long buffer_position = size - size_remaining;
		if (send_record(data + buffer_position, size_to_send, type, connected_socket))
			return -1;
		size_remaining -= size_to_send;
	}

	return 0;
}

static void gen_random_number(unsigned char* random_number)
{
	// todo: this should be a random number and the four first bytes must be unix time
	for (int i = 0; i < 32; ++i)
		random_number[i] = i;
}

static int rawhttp_sender_send_server_hello(int connected_socket, unsigned short selected_cipher_suite)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	unsigned char random_number[32];
	gen_random_number(random_number);


	unsigned short extensions_length = 0;
	unsigned char session_id_length = 0;
	unsigned char* session_id = NULL;
	unsigned short selected_cipher_suite_be = BIG_ENDIAN_16(selected_cipher_suite);
	unsigned char selected_compression_method = 0;
	unsigned short extensions_length_be = BIG_ENDIAN_16(extensions_length);
	unsigned char* extensions = BIG_ENDIAN_16(0);

	unsigned char message_type = SERVER_HELLO_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(2 + 32 + 1 + session_id_length + 2 + 1 + 2 + extensions_length);
	unsigned short ssl_version_be = BIG_ENDIAN_16(0x0301);

	util_dynamic_buffer_add(&db, &message_type, 1);						// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes) [PLACEHOLDER]
	util_dynamic_buffer_add(&db, &ssl_version_be, 2);					// SSL Version (2 Bytes)
	util_dynamic_buffer_add(&db, random_number, 32);					// Random Number (32 Bytes)
	util_dynamic_buffer_add(&db, &session_id_length, 1);				// Session ID Length (1 Byte)
	util_dynamic_buffer_add(&db, session_id, 0);						// Session ID (n Bytes)
	util_dynamic_buffer_add(&db, &selected_cipher_suite_be, 2);			// Selected Cipher Suite (2 Bytes)
	util_dynamic_buffer_add(&db, &selected_compression_method, 1);		// Selected Compression Method (1 Byte)
	util_dynamic_buffer_add(&db, &extensions_length_be, 2);				// Extensions Length (2 Bytes)
	util_dynamic_buffer_add(&db, extensions, 0);						// Extensions (n Bytes)

	if (send_higher_layer_packet(db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// for now, this function expects a single certificate
static int rawhttp_sender_send_server_certificate(int connected_socket, unsigned char* certificate, int certificate_size)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	// For now, we are hardcoding a single certificate!
	unsigned int number_of_certificates = 1;
	certificate_info certificates[1];
	certificates[0].data = certificate;
	certificates[0].size = certificate_size;
	// -------------

	unsigned int certificates_length = 0;
	for (int i = 0; i < number_of_certificates; ++i)
		certificates_length += certificates[i].size + 3;		// we need to add +3 because each certificate requires 3 bytes for its own length

	unsigned int certificates_length_be = BIG_ENDIAN_24(certificates_length);
	unsigned char message_type = SERVER_CERTIFICATE_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(3 + certificates_length); // initial 3 bytes are the length of all certificates + their individual lengths

	util_dynamic_buffer_add(&db, &message_type, 1);						// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes) [PLACEHOLDER]
	util_dynamic_buffer_add(&db, &certificates_length_be, 3);
	for (int i = 0; i < number_of_certificates; ++i)
	{
		unsigned int size = BIG_ENDIAN_24(certificates[i].size);
		util_dynamic_buffer_add(&db, &size, 3);
		util_dynamic_buffer_add(&db, certificates[i].data, certificates[i].size);
	}

	if (send_higher_layer_packet(db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

static int rawhttp_sender_send_server_hello_done(int connected_socket)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	unsigned char message_type = SERVER_HELLO_DONE_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(0);

	util_dynamic_buffer_add(&db, &message_type, 1);						// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes) [PLACEHOLDER]

	if (send_higher_layer_packet(db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

int rawhttps_tls_handshake(rawhttps_parser_state* ps, int connected_socket)
{
	tls_packet p;
	while (1)
	{
		if (rawhttps_parser_parse_ssl_packet(&p, ps, connected_socket))
			return -1;
		switch (p.type)
		{
			case HANDSHAKE_PROTOCOL: {
				switch (p.subprotocol.hp.hh.message_type)
				{
					case CLIENT_HELLO_MESSAGE: {
						// we received a client hello message
						// lets send a server hello message
						unsigned short selected_cipher_suite = 0x0035;
						rawhttp_sender_send_server_hello(connected_socket, selected_cipher_suite);
						int cert_size;
						unsigned char* cert = util_file_to_memory("./certificate/cert_binary", &cert_size);
						rawhttp_sender_send_server_certificate(connected_socket, cert, cert_size);
						free(cert);
						rawhttp_sender_send_server_hello_done(connected_socket);
					} break;
					case CLIENT_KEY_EXCHANGE_MESSAGE: {
						unsigned int pre_master_secret_length = p.subprotocol.hp.message.ckem.premaster_secret_length;
						unsigned char* pre_master_secret = p.subprotocol.hp.message.ckem.premaster_secret;
						printf("Printing premaster secret...");
						util_buffer_print_hex(pre_master_secret, (long long)pre_master_secret_length);

						int err = 0;
						PrivateKey pk = asn1_parse_pem_private_key_from_file("./certificate/key_decrypted.pem", &err);
						hobig_int_print(pk.PrivateExponent);
						printf("\n");
						/*
						HoBigInt i = hobig_int_new_from_memory(pre_master_secret, pre_master_secret_length);
						HoBigInt res = hobig_int_mod_div(&i, &pk.PrivateExponent, &pk.public.N);
						printf("ERR: %d", err);
						*/
						HoBigInt pre_master_secret_bi = hobig_int_new_from_memory((s8*)pre_master_secret, pre_master_secret_length);
						//Decrypt_Data dd = decrypt_pkcs1_v1_5(pk, pre_master_secret_bi, &err);
						//printf("error? %d", err);
						//util_buffer_print_hex((unsigned char*)dd.data, dd.length);
					} break;
					case SERVER_HELLO_MESSAGE:
					case SERVER_CERTIFICATE_MESSAGE:
					case SERVER_HELLO_DONE_MESSAGE: {
						printf("not supported");
						continue;
					} break;
				}
			} break;
			case CHANGE_CIPHER_SPEC_PROTOCOL: {
				switch (p.subprotocol.ccsp.message) {
					case CHANGE_CIPHER_SPEC_MESSAGE: {
						printf("Client asked to activate encryption via CHANGE_CIPHER_SPEC message\n");
						getchar();
					} break;
				}
			} break;
		}
	}
}
