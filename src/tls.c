#include "tls.h"
#include "parser.h"
#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <memory.h>
#include <assert.h>
#include "hobig.h"
#include "asn1.h"
#include "pkcs1.h"
#include "hmac.h"
#include "common.h"
#include "crypto_hashes.h"

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define BIG_ENDIAN_16(x) ((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
// note: for BIG_ENDIAN_24, since we receive an unsigned int, we keep the last byte untouched, i.e.
// 01 02 03 04 05 06 00 00 is transformed to 05 06 03 04 01 02 00 00
#define BIG_ENDIAN_24(x) ((((x) & 0x000000FF) << 16) | (((x) & 0x00FF0000) >> 16) | ((x) & 0x0000FF00))
#define BIG_ENDIAN_32(x) ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))

int rawhttps_tls_state_create(rawhttps_tls_state* ts)
{
	ts->encryption_enabled = false;
	util_dynamic_buffer_new(&ts->handshake_messages, 10 * 1024 /* @TODO: changeme */);
	return 0;
}

void rawhttps_tls_state_destroy(rawhttps_tls_state* ts)
{
	util_dynamic_buffer_free(&ts->handshake_messages);
}

// sends a single record packet to the client
static int send_record(const unsigned char* data, int record_size, protocol_type type, int connected_socket)
{
	struct iovec iov[2];
	unsigned char record_header[5];
	record_header[0] = type;
	*(unsigned short*)(record_header + 1) = BIG_ENDIAN_16(TLS12);
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

// receives a higher layer packet, splits the packet into several record packets and send to the client
static int send_higher_layer_packet(const unsigned char* data, long long size, protocol_type type, int connected_socket)
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

// generates the random number that is sent in the SERVER_HELLO packet and it's later used to generate the master key
// @TODO: this function must be implemented correctly
static void server_hello_random_number_generate(unsigned char* random_number)
{
	// todo: this should be a random number and the four first bytes must be unix time
	for (int i = 0; i < 32; ++i)
		random_number[i] = i;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_HELLO
static int rawhttp_handshake_server_hello_message_send(int connected_socket, unsigned short selected_cipher_suite,
	unsigned char* random_number, dynamic_buffer* handshake_messages)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	unsigned short extensions_length = 0;
	unsigned char session_id_length = 0;
	unsigned char* session_id = NULL;
	unsigned short selected_cipher_suite_be = BIG_ENDIAN_16(selected_cipher_suite);
	unsigned char selected_compression_method = 0;
	unsigned short extensions_length_be = BIG_ENDIAN_16(extensions_length);
	unsigned char* extensions = BIG_ENDIAN_16(0);

	unsigned char message_type = SERVER_HELLO_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(2 + 32 + 1 + session_id_length + 2 + 1 + 2 + extensions_length);
	unsigned short ssl_version_be = BIG_ENDIAN_16(TLS12);

	util_dynamic_buffer_add(&db, &message_type, 1);						// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);				// Message Length (3 Bytes) [PLACEHOLDER]
	util_dynamic_buffer_add(&db, &ssl_version_be, 2);					// SSL Version (2 Bytes)
	util_dynamic_buffer_add(&db, random_number, 32);					// Random Number (32 Bytes)
	util_dynamic_buffer_add(&db, &session_id_length, 1);				// Session ID Length (1 Byte)
	util_dynamic_buffer_add(&db, session_id, 0);						// Session ID (n Bytes)
	util_dynamic_buffer_add(&db, &selected_cipher_suite_be, 2);			// Selected Cipher Suite (2 Bytes)
	util_dynamic_buffer_add(&db, &selected_compression_method, 1);		// Selected Compression Method (1 Byte)
	util_dynamic_buffer_add(&db, &extensions_length_be, 2);				// Extensions Length (2 Bytes)
	util_dynamic_buffer_add(&db, extensions, 0);						// Extensions (n Bytes)

	// We could even use the same dynamic buffer here...
	util_dynamic_buffer_add(handshake_messages, db.buffer, db.size);

	if (send_higher_layer_packet(db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_CERTIFICATE
// for now, this function receives a single certificate!
// @todo: support a chain of certificates
static int rawhttp_handshake_server_certificate_message_send(int connected_socket, unsigned char* certificate,
	int certificate_size, dynamic_buffer* handshake_messages)
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

	// We could even use the same dynamic buffer here...
	util_dynamic_buffer_add(handshake_messages, db.buffer, db.size);

	if (send_higher_layer_packet(db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_HELLO_DONE
static int rawhttp_handshake_server_hello_done_message_send(int connected_socket, dynamic_buffer* handshake_messages)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	unsigned char message_type = SERVER_HELLO_DONE_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(0);

	util_dynamic_buffer_add(&db, &message_type, 1);						// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes) [PLACEHOLDER]

	// We could even use the same dynamic buffer here...
	util_dynamic_buffer_add(handshake_messages, db.buffer, db.size);

	if (send_higher_layer_packet(db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

static int pre_master_secret_decrypt(unsigned char* result, unsigned char* encrypted, int length)
{
	int err = 0;
	PrivateKey pk = asn1_parse_pem_private_key_from_file("./certificate/key_decrypted.pem", &err);
	if (err) return -1;
	HoBigInt encrypted_big_int = hobig_int_new_from_memory((char*)encrypted, length);
	Decrypt_Data dd = decrypt_pkcs1_v1_5(pk, encrypted_big_int, &err);
	if (err) return -1;
	assert(dd.length == 48);	// RSA!
	memcpy(result, dd.data, 48);
	return 0;
}

static int get_parser_crypto_data(rawhttps_parser_crypto_data* cd, const rawhttps_tls_state* ts)
{
	cd->encryption_enabled = ts->encryption_enabled;
	if (ts->encryption_enabled)
	{
		// @TODO: FIX ME
		// *******************************
		memcpy(cd->server_write_IV, ts->client_write_IV, 16);
		memcpy(cd->server_write_key, ts->client_write_key, 16);
	}
	return 0;
}

// performs the TLS handshake
int rawhttps_tls_handshake(rawhttps_tls_state* ts, rawhttps_parser_state* ps, int connected_socket)
{
	rawhttps_parser_crypto_data cd;
	tls_packet p;
	while (1)
	{
		if (get_parser_crypto_data(&cd, ts))
			return -1;
		if (rawhttps_parser_parse_ssl_packet(&cd, &p, ps, connected_socket, &ts->handshake_messages))
			return -1;
		switch (p.type)
		{
			case HANDSHAKE_PROTOCOL: {
				switch (p.subprotocol.hp.hh.message_type)
				{
					case CLIENT_HELLO_MESSAGE: {
						memcpy(ts->client_random_number, p.subprotocol.hp.message.chm.random_number, 32);
						printf("Printing client random number...\n");
						util_buffer_print_hex(ts->client_random_number, (long long)32);
						// we received a client hello message
						// lets send a server hello message
						//unsigned short selected_cipher_suite = 0x0035; // TLS_RSA_WITH_AES_256_CBC_SHA
						unsigned short selected_cipher_suite = 0x002f; // TLS_RSA_WITH_AES_128_CBC_SHA
						server_hello_random_number_generate(ts->server_random_number);
						rawhttp_handshake_server_hello_message_send(connected_socket, selected_cipher_suite, ts->server_random_number, &ts->handshake_messages);
						int cert_size;
						unsigned char* cert = util_file_to_memory("./certificate/cert_binary", &cert_size);
						rawhttp_handshake_server_certificate_message_send(connected_socket, cert, cert_size, &ts->handshake_messages);
						free(cert);
						rawhttp_handshake_server_hello_done_message_send(connected_socket, &ts->handshake_messages);
					} break;
					case CLIENT_KEY_EXCHANGE_MESSAGE: {
						unsigned int encrypted_pre_master_secret_length = p.subprotocol.hp.message.ckem.premaster_secret_length;
						unsigned char* encrypted_pre_master_secret = p.subprotocol.hp.message.ckem.premaster_secret;
						if (pre_master_secret_decrypt(ts->pre_master_secret, encrypted_pre_master_secret, encrypted_pre_master_secret_length))
							return -1;

						unsigned char seed[64];
						memcpy(seed, ts->client_random_number, 32);
						memcpy(seed + 32, ts->server_random_number, 32);

						printf("Printing premaster secret...");
						util_buffer_print_hex(ts->pre_master_secret, (long long)48);
						printf("\n\n");

						printf("Printing seed...");
						util_buffer_print_hex(seed, (long long)64);
						printf("\n\n");

						// generate master secret !
						prf12(sha1, 20, (char*)ts->pre_master_secret, 48, "master secret", sizeof("master secret") - 1,
							(char*)seed, 64, (char*)ts->master_secret, 48);

						printf("Printing MASTER SECRET...");
						util_buffer_print_hex(ts->master_secret, 48);
						printf("\n\n");

						unsigned char key_block[104];
						prf12(sha256, 32, (char*)ts->master_secret, 48, "key expansion", sizeof("key expansion") - 1,
							(char*)seed, 64, (char*)key_block, 104);

						memcpy(ts->client_write_mac_key, key_block, 20);
						memcpy(ts->server_write_mac_key, key_block + 20, 20);
						memcpy(ts->client_write_key, key_block + 20 + 20, 16);
						memcpy(ts->server_write_key, key_block + 20 + 20 + 16, 16);
						memcpy(ts->client_write_IV, key_block + 20 + 20 + 16 + 16, 16);
						memcpy(ts->server_write_IV, key_block + 20 + 20 + 16 + 16 + 16, 16);
					} break;
					case FINISHED_MESSAGE: {
						// Here we need to check if the decryption worked!
						printf("PRINTING HANDSHAKE MESSAGES WITH SIZE %lld ...\n\n\n\n", ts->handshake_messages.size);
						util_buffer_print_hex(ts->handshake_messages.buffer, ts->handshake_messages.size);
						printf("\n\n\n\n");
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
						ts->encryption_enabled = true;
					} break;
				}
			} break;
		}
	}
}
