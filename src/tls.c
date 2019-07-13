#include "tls.h"
#include "parser.h"
#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <assert.h>
#include "hobig.h"
#include "asn1.h"
#include "pkcs1.h"
#include "common.h"
#include "crypto_hashes.h"

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define PRE_MASTER_SECRET_SIZE 48

static void security_parameters_set_for_cipher_suite(cipher_suite_type cipher_suite, rawhttps_security_parameters* sp, connection_end entity)
{
	switch (cipher_suite)
	{
		case TLS_NULL_WITH_NULL_NULL: {
			sp->entity = entity;
			sp->cipher = CIPHER_STREAM;
			sp->prf_algorithm = TLS_PRF_SHA256;
			sp->bulk_cipher_algorithm = BULK_CIPHER_ALGORITHM_NULL;
			sp->mac_algorithm = MAC_ALGORITHM_NULL;
			sp->enc_key_length = 0;
			sp->fixed_iv_length = 0;
			sp->mac_key_length = 0;
			sp->mac_length = 0;
			sp->record_iv_length = 0;
			sp->block_length = 0;
		} break;
		case TLS_RSA_WITH_AES_128_CBC_SHA: {
			sp->entity = entity;
			sp->cipher = CIPHER_BLOCK;
			sp->prf_algorithm = TLS_PRF_SHA256;
			sp->bulk_cipher_algorithm = BULK_CIPHER_ALGORITHM_AES;
			sp->mac_algorithm = MAC_ALGORITHM_HMAC_SHA1;
			sp->enc_key_length = 16;
			sp->fixed_iv_length = 16;
			sp->mac_key_length = 20;
			sp->mac_length = 20;
			sp->record_iv_length = 16;
			sp->block_length = 16;
		} break;
	}
}

int rawhttps_tls_state_create(rawhttps_tls_state* ts)
{
	memset(ts, 0, sizeof(rawhttps_tls_state));
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->client_connection_state.security_parameters, CONNECTION_END_CLIENT);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->server_connection_state.security_parameters, CONNECTION_END_SERVER);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_client_security_parameters, CONNECTION_END_CLIENT);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_server_security_parameters, CONNECTION_END_SERVER);
	util_dynamic_buffer_new(&ts->handshake_messages, 10 * 1024 /* @TODO: changeme */);
	return 0;
}

void rawhttps_tls_state_destroy(rawhttps_tls_state* ts)
{
	util_dynamic_buffer_free(&ts->handshake_messages);
}

// generates the random number that is sent in the SERVER_HELLO packet and it's later used to generate the master key
// @TODO: this function must be implemented correctly
static void server_hello_random_number_generate(unsigned char server_random[32])
{
	// todo: this should be a random number and the four first bytes must be unix time
	for (int i = 0; i < 32; ++i)
		server_random[i] = i;
}

// receives a higher layer packet, splits the packet into several record packets and send to the client
static int send_higher_layer_packet(const rawhttps_connection_state* server_cs, const unsigned char* data, long long size,
	protocol_type type, int connected_socket)
{
	long long size_remaining = size;
	while (size_remaining > 0)
	{
		long long size_to_send = MIN(RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE, size_remaining);
		long long buffer_position = size - size_remaining;

		if (rawhttps_record_send(server_cs, data + buffer_position, size_to_send, type, connected_socket))
			return -1;
		size_remaining -= size_to_send;
	}

	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_HELLO
static int handshake_server_hello_message_send(const rawhttps_connection_state* server_cs, int connected_socket, unsigned short selected_cipher_suite,
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

	if (send_higher_layer_packet(server_cs, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_CERTIFICATE
// for now, this function receives a single certificate!
// @todo: support a chain of certificates
static int handshake_server_certificate_message_send(const rawhttps_connection_state* server_cs, int connected_socket,
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

	if (send_higher_layer_packet(server_cs, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_HELLO_DONE
static int handshake_server_hello_done_message_send(const rawhttps_connection_state* server_cs, int connected_socket, dynamic_buffer* handshake_messages)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	unsigned char message_type = SERVER_HELLO_DONE_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(0);

	util_dynamic_buffer_add(&db, &message_type, 1);						// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes) [PLACEHOLDER]

	// We could even use the same dynamic buffer here...
	util_dynamic_buffer_add(handshake_messages, db.buffer, db.size);

	if (send_higher_layer_packet(server_cs, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new CHANGE_CIPHER_SPEC message
static int change_cipher_spec_send(const rawhttps_connection_state* server_cs, int connected_socket)
{
	unsigned char ccs_type = CHANGE_CIPHER_SPEC_MESSAGE;

	if (send_higher_layer_packet(server_cs, (const unsigned char*)&ccs_type, sizeof(ccs_type), CHANGE_CIPHER_SPEC_PROTOCOL, connected_socket))
		return -1;

	return 0;
}

// send to the client a new CHANGE_CIPHER_SPEC message
static int handshake_finished_message_send(const rawhttps_connection_state* server_cs, int connected_socket, unsigned char verify_data[12])
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 16);

	unsigned char message_type = FINISHED_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(12);

	util_dynamic_buffer_add(&db, &message_type, 1);							// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes)
	util_dynamic_buffer_add(&db, verify_data, 12);							// Verify Data (12 Bytes)

	if (send_higher_layer_packet(server_cs, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	return 0;
}

static int application_data_send(const rawhttps_connection_state* server_cs, int connected_socket,
	unsigned char* content, long long content_length)
{
	if (send_higher_layer_packet(server_cs, content, content_length, APPLICATION_DATA_PROTOCOL, connected_socket))
		return -1;

	return 0;
}

static int pre_master_secret_decrypt(unsigned char* result, unsigned char* encrypted, int length)
{
	int err = 0;
	//PrivateKey pk = asn1_parse_pem_private_key_from_file("./certificate/new_cert/key.pem", &err);
	PrivateKey pk = asn1_parse_pem_private_certificate_key_from_file("./certificate/other_cert/key.pem", &err);
	if (err) return -1;
	HoBigInt encrypted_big_int = hobig_int_new_from_memory((char*)encrypted, length);
	Decrypt_Data dd = decrypt_pkcs1_v1_5(pk, encrypted_big_int, &err);
	if (err) return -1;
	assert(dd.length == 48);	// RSA!
	memcpy(result, dd.data, 48);
	return 0;
}

static void rsa_generate_master_secret(unsigned char pre_master_secret[PRE_MASTER_SECRET_SIZE], unsigned char client_random[CLIENT_RANDOM_SIZE],
	unsigned char server_random[SERVER_RANDOM_SIZE], unsigned char master_secret[MASTER_SECRET_SIZE])
{
	unsigned char seed[CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE];
	memcpy(seed, client_random, CLIENT_RANDOM_SIZE);
	memcpy(seed + CLIENT_RANDOM_SIZE, server_random, SERVER_RANDOM_SIZE);

	// @TODO: check which PRF to use...

	// Generate the master secret
	prf12(sha256, 32, pre_master_secret, PRE_MASTER_SECRET_SIZE, "master secret", sizeof("master secret") - 1, seed,
		CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE, master_secret, MASTER_SECRET_SIZE);
}

static void generate_connection_state_from_security_parameters(const rawhttps_security_parameters* sp, rawhttps_connection_state* cs)
{
	unsigned char seed[CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE];
	memcpy(seed, sp->server_random, SERVER_RANDOM_SIZE);
	memcpy(seed + SERVER_RANDOM_SIZE, sp->client_random, CLIENT_RANDOM_SIZE);

	// @TODO: check which PRF to use...

	// The maximum size for the key material is 128 bytes (TLS 1.2)
	// ref: https://tools.ietf.org/html/rfc5246#section-6.3
	unsigned char key_block[128];
	prf12(sha256, 32, sp->master_secret, MASTER_SECRET_SIZE, "key expansion", sizeof("key expansion") - 1,
		seed, SERVER_RANDOM_SIZE + CLIENT_RANDOM_SIZE, key_block,
		sp->mac_key_length + sp->mac_key_length + sp->enc_key_length + sp->enc_key_length +
		sp->fixed_iv_length + sp->fixed_iv_length);
	assert(sp->mac_key_length + sp->mac_key_length + sp->enc_key_length + sp->enc_key_length +
		sp->fixed_iv_length + sp->fixed_iv_length <= 128);

	unsigned char* key_block_ptr = key_block;
	if (sp->entity == CONNECTION_END_CLIENT) memcpy(cs->cipher_state.mac_key, key_block_ptr, sp->mac_key_length);
	key_block_ptr += sp->mac_key_length;
	if (sp->entity == CONNECTION_END_SERVER) memcpy(cs->cipher_state.mac_key, key_block_ptr, sp->mac_key_length);
	key_block_ptr += sp->mac_key_length;
	if (sp->entity == CONNECTION_END_CLIENT) memcpy(cs->cipher_state.enc_key, key_block_ptr, sp->enc_key_length);
	key_block_ptr += sp->enc_key_length;
	if (sp->entity == CONNECTION_END_SERVER) memcpy(cs->cipher_state.enc_key, key_block_ptr, sp->enc_key_length);
	key_block_ptr += sp->enc_key_length;
	if (sp->entity == CONNECTION_END_CLIENT) memcpy(cs->cipher_state.iv, key_block_ptr, sp->fixed_iv_length);
	key_block_ptr += sp->fixed_iv_length;
	if (sp->entity == CONNECTION_END_SERVER) memcpy(cs->cipher_state.iv, key_block_ptr, sp->fixed_iv_length);

	cs->security_parameters = *sp;
	cs->sequence_number = 0;
}

static void apply_pending_client_cipher(rawhttps_tls_state* ts)
{
	generate_connection_state_from_security_parameters(&ts->pending_client_security_parameters, &ts->client_connection_state);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_client_security_parameters, CONNECTION_END_CLIENT);
}

static void apply_pending_server_cipher(rawhttps_tls_state* ts)
{
	generate_connection_state_from_security_parameters(&ts->pending_server_security_parameters, &ts->server_connection_state);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_server_security_parameters, CONNECTION_END_SERVER);
}

static void generate_verify_data_from_handshake_messages(const dynamic_buffer* all_handshake_messages, unsigned char master_secret[MASTER_SECRET_SIZE],
	unsigned char verify_data[12])
{
	// @TODO: check these hardcoded lengths and create constants if possible
	unsigned char handshake_messages_hash[32];
	sha256(all_handshake_messages->buffer, all_handshake_messages->size, handshake_messages_hash);

	prf12(sha256, 32, master_secret, MASTER_SECRET_SIZE, "server finished", sizeof("server finished") - 1,
		handshake_messages_hash, 32, verify_data, 12);
}

// performs the TLS handshake
int rawhttps_tls_handshake(rawhttps_tls_state* ts, rawhttps_parser_state* ps, int connected_socket)
{
	tls_packet p;
	protocol_type type;

	while (1)
	{
		// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
		if (rawhttps_parser_protocol_type_get_next(ps, connected_socket, &ts->client_connection_state, &type))
			return -1;

		switch (type)
		{
			case HANDSHAKE_PROTOCOL: {
				if (rawhttps_parser_handshake_packet_parse(&p, ps, connected_socket, &ts->client_connection_state, &ts->handshake_messages))
					return -1;
				switch (p.subprotocol.hp.hh.message_type)
				{
					case CLIENT_HELLO_MESSAGE: {
						memcpy(ts->pending_client_security_parameters.client_random, p.subprotocol.hp.message.chm.client_random, CLIENT_RANDOM_SIZE);
						memcpy(ts->pending_server_security_parameters.client_random, p.subprotocol.hp.message.chm.client_random, CLIENT_RANDOM_SIZE);
						printf("Printing client random number...\n");
						util_buffer_print_hex(p.subprotocol.hp.message.chm.client_random, (long long)CLIENT_RANDOM_SIZE);
						// we received a client hello message
						// lets send a server hello message
						unsigned short selected_cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA;
						
						unsigned char server_random[SERVER_RANDOM_SIZE];
						server_hello_random_number_generate(server_random);
						memcpy(ts->pending_client_security_parameters.server_random, server_random, SERVER_RANDOM_SIZE);
						memcpy(ts->pending_server_security_parameters.server_random, server_random, SERVER_RANDOM_SIZE);
						printf("Printing server random number...\n");
						util_buffer_print_hex(server_random, (long long)CLIENT_RANDOM_SIZE);
						handshake_server_hello_message_send(&ts->server_connection_state, connected_socket, selected_cipher_suite,
							server_random, &ts->handshake_messages);
						security_parameters_set_for_cipher_suite(selected_cipher_suite, &ts->pending_client_security_parameters, CONNECTION_END_CLIENT);
						security_parameters_set_for_cipher_suite(selected_cipher_suite, &ts->pending_server_security_parameters, CONNECTION_END_SERVER);

						#if 1
						int err = 0;
						RSA_Certificate cert = asn1_parse_pem_certificate_from_file("./certificate/other_cert/cert.pem", err);
						if (err != 0) {
							printf("error parsing certificate\n");
							return -1;
						}
						handshake_server_certificate_message_send(&ts->server_connection_state, connected_socket, cert.raw.data,
							cert.raw.length, &ts->handshake_messages);
						#endif
						#if 0
						// @TODO: Certs should not be hardcoded
						int cert_size;
						unsigned char* cert = util_file_to_memory("./certificate/new_cert/cert.bin", &cert_size);
						handshake_server_certificate_message_send(&ts->server_connection_state, connected_socket, cert, cert_size, &ts->handshake_messages);
						#endif
						handshake_server_hello_done_message_send(&ts->server_connection_state, connected_socket, &ts->handshake_messages);
					} break;
					case CLIENT_KEY_EXCHANGE_MESSAGE: {
						unsigned char pre_master_secret[PRE_MASTER_SECRET_SIZE];
						unsigned char master_secret[MASTER_SECRET_SIZE];

						unsigned int encrypted_pre_master_secret_length = p.subprotocol.hp.message.ckem.premaster_secret_length;
						unsigned char* encrypted_pre_master_secret = p.subprotocol.hp.message.ckem.premaster_secret;
						if (pre_master_secret_decrypt(pre_master_secret, encrypted_pre_master_secret, encrypted_pre_master_secret_length))
							return -1;

						printf("Printing premaster secret...\n");
						util_buffer_print_hex(pre_master_secret, (long long)PRE_MASTER_SECRET_SIZE);

						// client_random and server_random should be the same for both client_security_params and server_security_params...
						// so it should not matter which security_parameter we pick (from client_connection_state or server_connection_state)
						rsa_generate_master_secret(pre_master_secret, ts->pending_client_security_parameters.client_random,
							ts->pending_client_security_parameters.server_random, master_secret);
						memcpy(ts->pending_client_security_parameters.master_secret, master_secret, MASTER_SECRET_SIZE);
						memcpy(ts->pending_server_security_parameters.master_secret, master_secret, MASTER_SECRET_SIZE);

						printf("Printing MASTER SECRET...");
						util_buffer_print_hex(master_secret, MASTER_SECRET_SIZE);
					} break;
					case FINISHED_MESSAGE: {
						// Here we need to check if the decryption worked!
						// @TODO!
						change_cipher_spec_send(&ts->server_connection_state, connected_socket);
						apply_pending_server_cipher(ts);

						unsigned char verify_data[12];
						generate_verify_data_from_handshake_messages(&ts->handshake_messages,
							ts->server_connection_state.security_parameters.master_secret, verify_data);
						handshake_finished_message_send(&ts->server_connection_state, connected_socket, verify_data);
						ts->hanshake_completed = true;
						return 0;
					} break;
					case SERVER_HELLO_MESSAGE:
					case SERVER_CERTIFICATE_MESSAGE:
					case SERVER_HELLO_DONE_MESSAGE: {
						printf("not supported\n");
						continue;
					} break;
				}
			} break;
			case CHANGE_CIPHER_SPEC_PROTOCOL: {
				if (rawhttps_parser_change_cipher_spec_parse(&p, ps, connected_socket, &ts->client_connection_state))
					return -1;
				switch (p.subprotocol.ccsp.message) {
					case CHANGE_CIPHER_SPEC_MESSAGE: {
						printf("Client asked to activate encryption via CHANGE_CIPHER_SPEC message\n");
						apply_pending_client_cipher(ts);
					} break;
				}
			} break;
			case APPLICATION_DATA_PROTOCOL: {
				printf("Application Data received before handshake was finished");
				return -1;
			} break;
		}
	}

	return -1;
}

long long rawhttps_tls_read(rawhttps_tls_state* ts, rawhttps_parser_state* ps, int connected_socket,
	unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE])
{
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_parser_protocol_type_get_next(ps, connected_socket, &ts->client_connection_state, &type))
		return -1;

	switch (type)
	{
		case HANDSHAKE_PROTOCOL: {
			printf("Received handshake protocol inside tls_read\n");
			return -1;
		} break;
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			printf("Received change cipher spec protocol inside tls_read\n");
			return -1;
		} break;
		case APPLICATION_DATA_PROTOCOL: {
			long long bytes_written;
			if (rawhttps_parser_application_data_parse(data, &bytes_written, ps, connected_socket, &ts->client_connection_state))
				return -1;
			return bytes_written;
		} break;
	}

	return -1;
}