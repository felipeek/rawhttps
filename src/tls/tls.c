#include "tls.h"
#include "../util.h"
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <assert.h>
#include "crypto/hobig.h"
#include "crypto/asn1.h"
#include "crypto/pkcs1.h"
#include "../common.h"
#include "crypto/crypto_hashes.h"
#include "tls_sender.h"

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

int rawhttps_tls_state_create(rawhttps_tls_state* ts, const char* certificate_path, const char* private_key_path)
{
	int err = 0;
	memset(ts, 0, sizeof(rawhttps_tls_state));
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->client_connection_state.security_parameters, CONNECTION_END_CLIENT);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->server_connection_state.security_parameters, CONNECTION_END_SERVER);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_client_security_parameters, CONNECTION_END_CLIENT);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_server_security_parameters, CONNECTION_END_SERVER);
	util_dynamic_buffer_new(&ts->handshake_messages, 10 * 1024 /* @TODO: changeme */);
	if (rawhttps_tls_parser_state_create(&ts->ps)) return -1;
	// @TODO(psv): function below returns error.
	ts->certificate = asn1_parse_pem_certificate_from_file(certificate_path, 0);
	if (err) return -1;
	ts->private_key = asn1_parse_pem_private_certificate_key_from_file(private_key_path, &err);
	if (err) return -1;
	return 0;
}

void rawhttps_tls_state_destroy(rawhttps_tls_state* ts)
{
	util_dynamic_buffer_free(&ts->handshake_messages);
	rawhttps_tls_parser_state_destroy(&ts->ps);
}

// generates the random number that is sent in the SERVER_HELLO packet and it's later used to generate the master key
// @TODO: this function must be implemented correctly
static void server_hello_random_number_generate(unsigned char server_random[32])
{
	// todo: this should be a random number and the four first bytes must be unix time
	for (int i = 0; i < 32; ++i)
		server_random[i] = i;
}

static int pre_master_secret_decrypt(PrivateKey* pk, unsigned char* result, unsigned char* encrypted, int length)
{
	int err;
	HoBigInt encrypted_big_int = hobig_int_new_from_memory((char*)encrypted, length);
	Decrypt_Data dd = decrypt_pkcs1_v1_5(*pk, encrypted_big_int, &err);
	if (err) return -1;
	assert(dd.length == 48);	// RSA!
	memcpy(result, dd.data, 48);
	return 0;
}

static void rsa_master_secret_generate(unsigned char pre_master_secret[PRE_MASTER_SECRET_SIZE], unsigned char client_random[CLIENT_RANDOM_SIZE],
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

static void connection_state_from_security_parameters_generate(const rawhttps_security_parameters* sp, rawhttps_connection_state* cs)
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

static void pending_client_cipher_apply(rawhttps_tls_state* ts)
{
	connection_state_from_security_parameters_generate(&ts->pending_client_security_parameters, &ts->client_connection_state);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_client_security_parameters, CONNECTION_END_CLIENT);
}

static void pending_server_cipher_apply(rawhttps_tls_state* ts)
{
	connection_state_from_security_parameters_generate(&ts->pending_server_security_parameters, &ts->server_connection_state);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_server_security_parameters, CONNECTION_END_SERVER);
}

static void verify_data_generate(const dynamic_buffer* all_handshake_messages, unsigned char master_secret[MASTER_SECRET_SIZE],
	unsigned char verify_data[12])
{
	// @TODO: check these hardcoded lengths and create constants if possible
	unsigned char handshake_messages_hash[32];
	sha256(all_handshake_messages->buffer, all_handshake_messages->size, handshake_messages_hash);

	prf12(sha256, 32, master_secret, MASTER_SECRET_SIZE, "server finished", sizeof("server finished") - 1,
		handshake_messages_hash, 32, verify_data, 12);
}

static int handshake_client_hello_get(rawhttps_tls_state* ts, int connected_socket)
{
	tls_packet p;
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
		return -1;

	// We expect a handshake packet (with message CLIENT_HELLO)
	if (type != HANDSHAKE_PROTOCOL)
		return -1;

	if (rawhttps_tls_parser_handshake_packet_parse(&p, &ts->ps, connected_socket, &ts->client_connection_state, &ts->handshake_messages))
		return -1;

	// We expect a handshake packet (with message CLIENT_HELLO)
	if (p.subprotocol.hp.hh.message_type != CLIENT_HELLO_MESSAGE)
		return -1;

	memcpy(ts->pending_client_security_parameters.client_random, p.subprotocol.hp.message.chm.client_random, CLIENT_RANDOM_SIZE);
	memcpy(ts->pending_server_security_parameters.client_random, p.subprotocol.hp.message.chm.client_random, CLIENT_RANDOM_SIZE);
	printf("Printing client random number...\n");
	util_buffer_print_hex(p.subprotocol.hp.message.chm.client_random, (long long)CLIENT_RANDOM_SIZE);

	return 0;
}

static int handshake_server_hello_send(rawhttps_tls_state* ts, int connected_socket, cipher_suite_type selected_cipher_suite)
{
	unsigned char server_random[SERVER_RANDOM_SIZE];
	server_hello_random_number_generate(server_random);
	memcpy(ts->pending_client_security_parameters.server_random, server_random, SERVER_RANDOM_SIZE);
	memcpy(ts->pending_server_security_parameters.server_random, server_random, SERVER_RANDOM_SIZE);
	printf("Printing server random number...\n");
	util_buffer_print_hex(server_random, (long long)CLIENT_RANDOM_SIZE);
	if (rawhttps_tls_sender_handshake_server_hello_message_send(&ts->server_connection_state, connected_socket,
		selected_cipher_suite, server_random, &ts->handshake_messages))
		return -1;
	security_parameters_set_for_cipher_suite(selected_cipher_suite, &ts->pending_client_security_parameters, CONNECTION_END_CLIENT);
	security_parameters_set_for_cipher_suite(selected_cipher_suite, &ts->pending_server_security_parameters, CONNECTION_END_SERVER);
	return 0;
}

static int handshake_certificate_send(rawhttps_tls_state* ts, int connected_socket)
{
	return rawhttps_tls_sender_handshake_server_certificate_message_send(&ts->server_connection_state, connected_socket,
		ts->certificate.raw.data, ts->certificate.raw.length, &ts->handshake_messages);
}

static int handshake_server_hello_done_send(rawhttps_tls_state* ts, int connected_socket)
{
	return rawhttps_tls_sender_handshake_server_hello_done_message_send(&ts->server_connection_state, connected_socket,
		&ts->handshake_messages);
}

static int handshake_client_key_exchange_get(rawhttps_tls_state* ts, int connected_socket)
{
	tls_packet p;
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
		return -1;

	// We expect a handshake packet (with message CLIENT_KEY_EXCHANGE)
	if (type != HANDSHAKE_PROTOCOL)
		return -1;

	if (rawhttps_tls_parser_handshake_packet_parse(&p, &ts->ps, connected_socket, &ts->client_connection_state, &ts->handshake_messages))
		return -1;

	// We expect a handshake packet (with message CLIENT_KEY_EXCHANGE)
	if (p.subprotocol.hp.hh.message_type != CLIENT_KEY_EXCHANGE_MESSAGE)
		return -1;
	
	unsigned char pre_master_secret[PRE_MASTER_SECRET_SIZE];
	unsigned char master_secret[MASTER_SECRET_SIZE];

	unsigned int encrypted_pre_master_secret_length = p.subprotocol.hp.message.ckem.premaster_secret_length;
	unsigned char* encrypted_pre_master_secret = p.subprotocol.hp.message.ckem.premaster_secret;
	if (pre_master_secret_decrypt(&ts->private_key, pre_master_secret, encrypted_pre_master_secret, encrypted_pre_master_secret_length))
		return -1;

	printf("Printing premaster secret...\n");
	util_buffer_print_hex(pre_master_secret, (long long)PRE_MASTER_SECRET_SIZE);

	// client_random and server_random should be the same for both client_security_params and server_security_params...
	// so it should not matter which security_parameter we pick (from client_connection_state or server_connection_state)
	rsa_master_secret_generate(pre_master_secret, ts->pending_client_security_parameters.client_random,
		ts->pending_client_security_parameters.server_random, master_secret);
	memcpy(ts->pending_client_security_parameters.master_secret, master_secret, MASTER_SECRET_SIZE);
	memcpy(ts->pending_server_security_parameters.master_secret, master_secret, MASTER_SECRET_SIZE);

	printf("Printing MASTER SECRET...");
	util_buffer_print_hex(master_secret, MASTER_SECRET_SIZE);
	return 0;
}

static int handshake_change_cipher_spec_get(rawhttps_tls_state* ts, int connected_socket)
{
	tls_packet p;
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
		return -1;

	// We expect a CHANGE_CIPHER_SPEC packet
	if (type != CHANGE_CIPHER_SPEC_PROTOCOL)
		return -1;

	if (rawhttps_tls_parser_change_cipher_spec_parse(&p, &ts->ps, connected_socket, &ts->client_connection_state))
		return -1;

	if (p.subprotocol.ccsp.message != CHANGE_CIPHER_SPEC_MESSAGE)
		return -1;

	pending_client_cipher_apply(ts);
	return 0;
}

static int handshake_finished_get(rawhttps_tls_state* ts, int connected_socket)
{
	tls_packet p;
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
		return -1;

	// We expect a handshake packet (with message FINISHED)
	if (type != HANDSHAKE_PROTOCOL)
		return -1;

	if (rawhttps_tls_parser_handshake_packet_parse(&p, &ts->ps, connected_socket, &ts->client_connection_state, &ts->handshake_messages))
		return -1;

	// We expect a handshake packet (with message FINISHED)
	if (p.subprotocol.hp.hh.message_type != FINISHED_MESSAGE)
		return -1;
	
	return 0;
}

static int handshake_change_cipher_spec_send(rawhttps_tls_state* ts, int connected_socket)
{
	if (rawhttps_tls_sender_change_cipher_spec_send(&ts->server_connection_state, connected_socket))
		return -1;
	pending_server_cipher_apply(ts);
	return 0;
}

static int handshake_finished_send(rawhttps_tls_state* ts, int connected_socket)
{
	unsigned char verify_data[12];
	verify_data_generate(&ts->handshake_messages,
		ts->server_connection_state.security_parameters.master_secret, verify_data);
	rawhttps_tls_sender_handshake_finished_message_send(&ts->server_connection_state, connected_socket, verify_data);

	return 0;
}

// performs the TLS handshake
int rawhttps_tls_handshake(rawhttps_tls_state* ts, int connected_socket)
{
	if (handshake_client_hello_get(ts, connected_socket))
		return -1;
	
	if (handshake_server_hello_send(ts, connected_socket, TLS_RSA_WITH_AES_128_CBC_SHA))
		return -1;

	if (handshake_certificate_send(ts, connected_socket))
		return -1;
	
	if (handshake_server_hello_done_send(ts, connected_socket))
		return -1;

	if (handshake_client_key_exchange_get(ts, connected_socket))
		return -1;
	
	if (handshake_change_cipher_spec_get(ts, connected_socket))
		return -1;

	if (handshake_finished_get(ts, connected_socket))
		return -1;

	if (handshake_change_cipher_spec_send(ts, connected_socket))
		return -1;
	
	if (handshake_finished_send(ts, connected_socket))
		return -1;

	ts->handshake_completed = true;
	return 0;
}

long long rawhttps_tls_read(rawhttps_tls_state* ts, int connected_socket,
	unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE])
{
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
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
			if (rawhttps_tls_parser_application_data_parse(data, &bytes_written, &ts->ps, connected_socket, &ts->client_connection_state))
				return -1;
			return bytes_written;
		} break;
	}

	return -1;
}

long long rawhttps_tls_write(rawhttps_tls_state* ts, int connected_socket,
	unsigned char* data, long long count)
{
	return rawhttps_tls_sender_application_data_send(&ts->server_connection_state, connected_socket, data, count);
}