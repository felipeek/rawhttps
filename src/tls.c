#include "tls.h"
#include "parser.h"
#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <memory.h>
#include <assert.h>
#include "hobig.h"
#include "asn1.h"
#include "pkcs1.h"
#include "hmac.h"
#include "common.h"
#include "crypto_hashes.h"
#include "aes_cbc.h"

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define BIG_ENDIAN_16(x) ((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
// note: for BIG_ENDIAN_24, since we receive an unsigned int, we keep the last byte untouched, i.e.
// 01 02 03 04 05 06 00 00 is transformed to 05 06 03 04 01 02 00 00
#define BIG_ENDIAN_24(x) ((((x) & 0x000000FF) << 16) | (((x) & 0x00FF0000) >> 16) | ((x) & 0x0000FF00))
#define BIG_ENDIAN_32(x) ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))

int rawhttps_tls_state_create(rawhttps_tls_state* ts)
{
	memset(&ts->cd, 0, sizeof(rawhttps_crypto_data));
	util_dynamic_buffer_new(&ts->handshake_messages, 10 * 1024 /* @TODO: changeme */);
	return 0;
}

void rawhttps_tls_state_destroy(rawhttps_tls_state* ts)
{
	util_dynamic_buffer_free(&ts->handshake_messages);
}

// sends a single record packet to the client
static int send_record(const unsigned char* record_header, int record_header_length, const unsigned char* record_data,
	int record_data_length, protocol_type type, int connected_socket)
{
	struct iovec iov[2];
	iov[0].iov_base = record_header;
	iov[0].iov_len = record_header_length;
	iov[1].iov_base = record_data;
	iov[1].iov_len = record_data_length;

	struct msghdr hdr = {0};
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;
	// MSG_NOSIGNAL to avoid SIGPIPE error
	ssize_t written = sendmsg(connected_socket, &hdr, MSG_NOSIGNAL);

	if (written < 0)
	{
		printf("Error sending record: %s\n", strerror(errno));
		return -1;
	}

	// @TODO: in an excepcional case, writev() could write less bytes than requested...
	// we should look at writev() documentation and decide what to do in this particular case
	// for now, throw an error...
	if (written != record_header_length + record_data_length)
		return -1;
	
	return 0;
}

// receives a higher layer packet, splits the packet into several record packets and send to the client
static int send_higher_layer_packet(const rawhttps_crypto_data* cd, const unsigned char* data, long long size,
	protocol_type type, int connected_socket)
{
	long long size_remaining = size;
	unsigned char* record_data = NULL;
	unsigned long long record_data_length = 0;
	unsigned char record_header[5] = {0};

	if (cd->encryption_enabled) record_data = calloc(1, RECORD_PROTOCOL_DATA_MAX_SIZE);

	while (size_remaining > 0)
	{
		long long higher_layer_size_to_send = 0;

		if (cd->encryption_enabled)
		{
			const unsigned int IV_SIZE = 16;
			const unsigned int MAC_SIZE = 20;
			const unsigned int BLOCK_CIPHER_BLOCK_LENGTH = 16;
			// The record_data will have:
			// 16 Bytes for IV
			// N bytes for the higher layer message (it may have only part of it)
			// 20 Bytes for the MAC
			// M bytes for padding
			// 1 byte for padding length (M)
			// ---
			// Padding: Padding that is added to force the length of the plaintext to be
			// an integral multiple of the block cipher's block length
			// https://tools.ietf.org/html/rfc5246#section-6.2.3.2
			record_data_length = IV_SIZE + MAC_SIZE + 1; // +1 for padding_length
			higher_layer_size_to_send = MIN(RECORD_PROTOCOL_DATA_MAX_SIZE - record_data_length, size_remaining);
			record_data_length += higher_layer_size_to_send;
			unsigned char padding_length = BLOCK_CIPHER_BLOCK_LENGTH - ((record_data_length - IV_SIZE) % BLOCK_CIPHER_BLOCK_LENGTH);
			record_data_length += padding_length;
			// we assume that RECORD_PROTOCOL_DATA_MAX_SIZE - IV_SIZE is divisible by the block cipher's block length
			// if it's not visibile, this code should be fixed
			assert(record_data_length <= RECORD_PROTOCOL_DATA_MAX_SIZE);

			record_header[0] = type;
			*(unsigned short*)(record_header + 1) = BIG_ENDIAN_16(TLS12);
			*(unsigned short*)(record_header + 3) = BIG_ENDIAN_16(record_data_length);

			// Calculate IV
			// For now, we are using the Server Write IV as the CBC IV for all packets
			// This must be random and new for each packet
			// TODO
			const unsigned char* IV = cd->server_write_IV;

			// Calculate MAC
			// TODO
			// just for testing, this thing should be redesigned.
			unsigned char mac[20] = {0};
			dynamic_buffer mac_message;
			util_dynamic_buffer_new(&mac_message, 1024);
			util_dynamic_buffer_add(&mac_message, cd->seq_number, 8);
			unsigned char mac_tls_type = type;
			unsigned short mac_tls_version = BIG_ENDIAN_16(TLS12);
			unsigned short mac_tls_length = BIG_ENDIAN_16(higher_layer_size_to_send);
			util_dynamic_buffer_add(&mac_message, &mac_tls_type, 1);
			util_dynamic_buffer_add(&mac_message, &mac_tls_version, 2);
			util_dynamic_buffer_add(&mac_message, &mac_tls_length, 2);
			*(unsigned short*)(record_header + 3) = BIG_ENDIAN_16(record_data_length);
			util_dynamic_buffer_add(&mac_message, data + size - size_remaining, higher_layer_size_to_send);
			hmac(sha1, cd->server_write_mac_key, 20, mac_message.buffer, mac_message.size, mac, 20);

			unsigned char* record_data_ptr = record_data;
			memcpy(record_data_ptr, IV, IV_SIZE);
			record_data_ptr += IV_SIZE;
			long long buffer_position = size - size_remaining;
			memcpy(record_data_ptr, data + buffer_position, higher_layer_size_to_send);
			record_data_ptr += higher_layer_size_to_send;
			memcpy(record_data_ptr, mac, MAC_SIZE);
			record_data_ptr += MAC_SIZE;
			for (int i = 0; i < padding_length; ++i)
				record_data_ptr[i] = padding_length;
			record_data_ptr += padding_length;
			record_data_ptr[0] = padding_length;

			// Encrypt data
			unsigned char* data_to_encrypt = record_data + IV_SIZE; // Skip IV! We don't want to encrypt the IV
			unsigned int data_to_encrypt_size = record_data_length - IV_SIZE;
			assert(data_to_encrypt_size % BLOCK_CIPHER_BLOCK_LENGTH == 0);
			unsigned char* result = calloc(1, data_to_encrypt_size);
			aes_128_cbc_encrypt(data_to_encrypt, cd->server_write_key, IV, data_to_encrypt_size / BLOCK_CIPHER_BLOCK_LENGTH, result);
			memcpy(data_to_encrypt, result, data_to_encrypt_size);
		}
		else
		{
			higher_layer_size_to_send = MIN(RECORD_PROTOCOL_DATA_MAX_SIZE, size_remaining);
			long long buffer_position = size - size_remaining;
			record_data = data + buffer_position;
			record_data_length = higher_layer_size_to_send;

			record_header[0] = type;
			*(unsigned short*)(record_header + 1) = BIG_ENDIAN_16(TLS12);
			*(unsigned short*)(record_header + 3) = BIG_ENDIAN_16(record_data_length);
		}

		// Send record packet
		if (send_record(record_header, 5, record_data, record_data_length, type, connected_socket))
		{
			if (cd->encryption_enabled) free(record_data);
			return -1;
		}

		size_remaining -= higher_layer_size_to_send;
	}

	if (cd->encryption_enabled) free(record_data);

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
static int handshake_server_hello_message_send(const rawhttps_crypto_data* cd, int connected_socket, unsigned short selected_cipher_suite,
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

	if (send_higher_layer_packet(cd, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_CERTIFICATE
// for now, this function receives a single certificate!
// @todo: support a chain of certificates
static int handshake_server_certificate_message_send(const rawhttps_crypto_data* cd, int connected_socket,
	unsigned char* certificate, int certificate_size, dynamic_buffer* handshake_messages)
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

	if (send_higher_layer_packet(cd, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_HELLO_DONE
static int handshake_server_hello_done_message_send(const rawhttps_crypto_data* cd, int connected_socket, dynamic_buffer* handshake_messages)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	unsigned char message_type = SERVER_HELLO_DONE_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(0);

	util_dynamic_buffer_add(&db, &message_type, 1);						// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes) [PLACEHOLDER]

	// We could even use the same dynamic buffer here...
	util_dynamic_buffer_add(handshake_messages, db.buffer, db.size);

	if (send_higher_layer_packet(cd, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new CHANGE_CIPHER_SPEC message
static int change_cipher_spec_send(const rawhttps_crypto_data* cd, int connected_socket)
{
	unsigned char ccs_type = CHANGE_CIPHER_SPEC_MESSAGE;

	if (send_higher_layer_packet(cd, (const unsigned char*)&ccs_type, sizeof(ccs_type), CHANGE_CIPHER_SPEC_PROTOCOL, connected_socket))
		return -1;

	return 0;
}

// send to the client a new CHANGE_CIPHER_SPEC message
static int handshake_finished_message_send(const rawhttps_crypto_data* cd, int connected_socket, unsigned char verify_data[12])
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 16);

	unsigned char message_type = FINISHED_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(12);

	util_dynamic_buffer_add(&db, &message_type, 1);							// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes)
	util_dynamic_buffer_add(&db, verify_data, 12);							// Verify Data (12 Bytes)

	if (send_higher_layer_packet(cd, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	return 0;
}

static int pre_master_secret_decrypt(unsigned char* result, unsigned char* encrypted, int length)
{
	int err = 0;
	PrivateKey pk = asn1_parse_pem_private_key_from_file("./certificate/new_cert/key.pem", &err);
	if (err) return -1;
	HoBigInt encrypted_big_int = hobig_int_new_from_memory((char*)encrypted, length);
	Decrypt_Data dd = decrypt_pkcs1_v1_5(pk, encrypted_big_int, &err);
	if (err) return -1;
	assert(dd.length == 48);	// RSA!
	memcpy(result, dd.data, 48);
	return 0;
}

// performs the TLS handshake
int rawhttps_tls_handshake(rawhttps_tls_state* ts, rawhttps_parser_state* ps, int connected_socket)
{
	tls_packet p;
	while (1)
	{
		if (rawhttps_parser_parse_ssl_packet(&ts->cd, &p, ps, connected_socket, &ts->handshake_messages))
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
						handshake_server_hello_message_send(&ts->cd, connected_socket, selected_cipher_suite,
							ts->server_random_number, &ts->handshake_messages);
						int cert_size;
						unsigned char* cert = util_file_to_memory("./certificate/new_cert/cert.bin", &cert_size);
						//int err = 0;
						//RSA_Certificate cert = asn1_parse_pem_certificate_from_file("./certificate/new_cert/cert.pem", &err);
						//if (err)
						//{
						//	printf("Fatal error parsing certificate!\n");
						//	return -1;
						//}
						handshake_server_certificate_message_send(&ts->cd, connected_socket, cert, cert_size, &ts->handshake_messages);
						handshake_server_hello_done_message_send(&ts->cd, connected_socket, &ts->handshake_messages);
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
						prf12(sha256, 32, ts->pre_master_secret, 48, "master secret", sizeof("master secret") - 1,
							seed, 64, ts->master_secret, 48);

						printf("Printing MASTER SECRET...");
						util_buffer_print_hex(ts->master_secret, 48);
						printf("\n\n");

						memcpy(seed, ts->server_random_number, 32);
						memcpy(seed + 32, ts->client_random_number, 32);

						unsigned char key_block[104];
						prf12(sha256, 32, ts->master_secret, 48, "key expansion", sizeof("key expansion") - 1,
							seed, 64, key_block, 104);

						memcpy(ts->cd.client_write_mac_key, key_block, 20);
						memcpy(ts->cd.server_write_mac_key, key_block + 20, 20);
						memcpy(ts->cd.client_write_key, key_block + 20 + 20, 16);
						memcpy(ts->cd.server_write_key, key_block + 20 + 20 + 16, 16);
						memcpy(ts->cd.client_write_IV, key_block + 20 + 20 + 16 + 16, 16);
						memcpy(ts->cd.server_write_IV, key_block + 20 + 20 + 16 + 16 + 16, 16);
					} break;
					case FINISHED_MESSAGE: {
						// Here we need to check if the decryption worked!
						printf("PRINTING HANDSHAKE MESSAGES WITH SIZE %lld ...\n\n\n\n", ts->handshake_messages.size);
						util_buffer_print_hex(ts->handshake_messages.buffer, ts->handshake_messages.size);
						printf("\n\n\n\n");
						change_cipher_spec_send(&ts->cd, connected_socket);
						ts->cd.encryption_enabled = true;

						unsigned char handshake_messages_hash[32];
						unsigned char verify_data[12];
						sha256(ts->handshake_messages.buffer, ts->handshake_messages.size, handshake_messages_hash);

						prf12(sha256, 32, ts->master_secret, 48, "server finished", sizeof("server finished") - 1,
							handshake_messages_hash, 32, verify_data, 12);
						
						// Chamar prf12 com SHA256 para gerar o MAC no final do Record usando mac_write_key
						// O tamanho desse MAC deve ser considerado no campo do record_length
						// Mas Não é considerado no campo do message_length (high-level protocol)
						// Sepá tem que concatenar o IV no pacote
						handshake_finished_message_send(&ts->cd, connected_socket, verify_data);
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
						ts->cd.decryption_enabled = true;
					} break;
				}
			} break;
		}
	}
}
