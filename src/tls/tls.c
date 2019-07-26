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
#include "crypto/hmac.h"
#include "../logger.h"

#define PRE_MASTER_SECRET_SIZE 48

static void security_parameters_set_for_cipher_suite(cipher_suite_type cipher_suite, rawhttps_security_parameters* sp)
{
	switch (cipher_suite)
	{
		case TLS_NULL_WITH_NULL_NULL: {
			sp->cipher = CIPHER_STREAM;
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
			sp->cipher = CIPHER_BLOCK;
			sp->bulk_cipher_algorithm = BULK_CIPHER_ALGORITHM_AES;
			sp->mac_algorithm = MAC_ALGORITHM_HMAC_SHA1;
			sp->enc_key_length = 16;
			sp->fixed_iv_length = 16;
			sp->mac_key_length = 20;
			sp->mac_length = 20;
			sp->record_iv_length = 16;
			sp->block_length = 16;
		} break;
		case TLS_RSA_WITH_AES_128_CBC_SHA256: {
			sp->cipher = CIPHER_BLOCK;
			sp->bulk_cipher_algorithm = BULK_CIPHER_ALGORITHM_AES;
			sp->mac_algorithm = MAC_ALGORITHM_HMAC_SHA256;
			sp->enc_key_length = 16;
			sp->fixed_iv_length = 16;
			sp->mac_key_length = 32;
			sp->mac_length = 32;
			sp->record_iv_length = 16;
			sp->block_length = 16;
		} break;
	}

	assert(sp->enc_key_length <= CIPHER_ENC_KEY_MAX_LENGTH);
	assert(sp->mac_key_length <= CIPHER_MAC_KEY_MAX_LENGTH);
	assert(sp->fixed_iv_length <= CIPHER_IV_MAX_LENGTH);
	assert(sp->mac_length <= CIPHER_MAC_MAX_LENGTH);
	assert(sp->block_length <= CIPHER_BLOCK_SIZE_MAX_LENGTH);
}

static void prf(const unsigned char* secret, int secret_length, const char* label, int label_length,
    const unsigned char* seed, int seed_length, unsigned char* result, int result_length)
{
	rawhttps_prf12(rawhttps_sha256, 32, secret, secret_length, label, label_length, seed, seed_length, result, result_length);
}

int rawhttps_tls_state_create(rawhttps_tls_state* ts, const char* certificate_path, const char* private_key_path)
{
	int err = 0;
	memset(ts, 0, sizeof(rawhttps_tls_state));
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->client_connection_state.security_parameters);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->server_connection_state.security_parameters);
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_security_parameters);
	rawhttps_util_dynamic_buffer_new(&ts->handshake_messages, 10 * 1024 /* @TODO: changeme */);
	if (rawhttps_tls_parser_state_create(&ts->ps)) {
		rawhttps_logger_log_error("Error creating TLS parser state");
		return -1;
	}
	ts->certificate = asn1_parse_pem_certificate_from_file(certificate_path, 0);
	if (err) {
		rawhttps_logger_log_error("Error parsing PEM certificate from file (path: %s)", certificate_path);
		return -1;
	}
	ts->private_key = asn1_parse_pem_private_certificate_key_from_file(private_key_path, &err);
	if (err) {
		rawhttps_logger_log_error("Error parsing PEM private key from file (path: %s)", private_key_path);
		return -1;
	}
	return 0;
}

void rawhttps_tls_state_destroy(rawhttps_tls_state* ts)
{
	rawhttps_util_dynamic_buffer_free(&ts->handshake_messages);
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

static int pre_master_secret_decrypt(rawhttps_private_key* pk, unsigned char* result, unsigned char* encrypted, int length)
{
	int err = 0;
	rawhttps_ho_big_int encrypted_big_int = hobig_int_new_from_memory(encrypted, length);
	rawhttps_decrypt_data dd = decrypt_pkcs1_v1_5(*pk, encrypted_big_int, &err);
	if (err) {
		rawhttps_logger_log_error("Error decrypting premaster secret");
		return -1;
	}
	assert(dd.length == 48);	// RSA!
	memcpy(result, dd.data, 48);
	return 0;
}

static void rsa_master_secret_generate(unsigned char pre_master_secret[PRE_MASTER_SECRET_SIZE],
	unsigned char client_random[CLIENT_RANDOM_SIZE], unsigned char server_random[SERVER_RANDOM_SIZE], unsigned char master_secret[MASTER_SECRET_SIZE])
{
	unsigned char seed[CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE];
	memcpy(seed, client_random, CLIENT_RANDOM_SIZE);
	memcpy(seed + CLIENT_RANDOM_SIZE, server_random, SERVER_RANDOM_SIZE);

	// Generate the master secret
	prf(pre_master_secret, PRE_MASTER_SECRET_SIZE, "master secret", sizeof("master secret") - 1, seed,
		CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE, master_secret, MASTER_SECRET_SIZE);
}

static void connection_state_from_security_parameters_generate(const rawhttps_security_parameters* sp,
	rawhttps_connection_state* cs, connection_end entity)
{
	unsigned char seed[CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE];
	memcpy(seed, sp->server_random, SERVER_RANDOM_SIZE);
	memcpy(seed + SERVER_RANDOM_SIZE, sp->client_random, CLIENT_RANDOM_SIZE);

	unsigned char key_block[KEY_BLOCK_MAX_LENGTH];
	prf(sp->master_secret, MASTER_SECRET_SIZE, "key expansion", sizeof("key expansion") - 1,
		seed, SERVER_RANDOM_SIZE + CLIENT_RANDOM_SIZE, key_block,
		sp->mac_key_length + sp->mac_key_length + sp->enc_key_length + sp->enc_key_length +
		sp->fixed_iv_length + sp->fixed_iv_length);
	assert(sp->mac_key_length + sp->mac_key_length + sp->enc_key_length + sp->enc_key_length +
		sp->fixed_iv_length + sp->fixed_iv_length <= KEY_BLOCK_MAX_LENGTH);

	unsigned char* key_block_ptr = key_block;
	if (entity == CONNECTION_END_CLIENT) memcpy(cs->mac_key, key_block_ptr, sp->mac_key_length);
	key_block_ptr += sp->mac_key_length;
	if (entity == CONNECTION_END_SERVER) memcpy(cs->mac_key, key_block_ptr, sp->mac_key_length);
	key_block_ptr += sp->mac_key_length;
	if (entity == CONNECTION_END_CLIENT) memcpy(cs->cipher_state.enc_key, key_block_ptr, sp->enc_key_length);
	key_block_ptr += sp->enc_key_length;
	if (entity == CONNECTION_END_SERVER) memcpy(cs->cipher_state.enc_key, key_block_ptr, sp->enc_key_length);
	key_block_ptr += sp->enc_key_length;
	if (entity == CONNECTION_END_CLIENT) memcpy(cs->cipher_state.iv, key_block_ptr, sp->fixed_iv_length);
	key_block_ptr += sp->fixed_iv_length;
	if (entity == CONNECTION_END_SERVER) memcpy(cs->cipher_state.iv, key_block_ptr, sp->fixed_iv_length);

	cs->security_parameters = *sp;
	cs->sequence_number = 0;
}

static void pending_client_cipher_apply(rawhttps_tls_state* ts)
{
	connection_state_from_security_parameters_generate(&ts->pending_security_parameters, &ts->client_connection_state, CONNECTION_END_CLIENT);
	rawhttps_logger_log_debug("Client cipher was applied");
	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Client Mac Key", ts->client_connection_state.mac_key,
		ts->client_connection_state.security_parameters.mac_key_length);
	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Client Enc Key", ts->client_connection_state.cipher_state.enc_key,
		ts->client_connection_state.security_parameters.enc_key_length);
	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Client Fixed IV", ts->client_connection_state.cipher_state.iv,
		ts->client_connection_state.security_parameters.fixed_iv_length);
}

static void pending_server_cipher_apply(rawhttps_tls_state* ts)
{
	connection_state_from_security_parameters_generate(&ts->pending_security_parameters, &ts->server_connection_state, CONNECTION_END_SERVER);
	rawhttps_logger_log_debug("Server cipher was applied");
	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Server Mac Key", ts->server_connection_state.mac_key,
		ts->server_connection_state.security_parameters.mac_key_length);
	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Server Enc Key", ts->server_connection_state.cipher_state.enc_key,
		ts->server_connection_state.security_parameters.enc_key_length);
	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Server Fixed IV", ts->server_connection_state.cipher_state.iv,
		ts->server_connection_state.security_parameters.fixed_iv_length);

	// Reset security parameters
	security_parameters_set_for_cipher_suite(TLS_NULL_WITH_NULL_NULL, &ts->pending_security_parameters);
}

static void verify_data_generate(const rawhttps_util_dynamic_buffer* all_handshake_messages, unsigned char master_secret[MASTER_SECRET_SIZE],
	unsigned char verify_data[12])
{
	// @TODO: check these hardcoded lengths and create constants if possible
	unsigned char handshake_messages_hash[32];
	rawhttps_sha256(all_handshake_messages->buffer, all_handshake_messages->size, handshake_messages_hash);

	prf(master_secret, MASTER_SECRET_SIZE, "server finished", sizeof("server finished") - 1, handshake_messages_hash, 32, verify_data, 12);
}

static int cipher_suite_choose(cipher_suite_type* chosen_cipher_suite, const unsigned short* client_cipher_suites,
	unsigned short client_cipher_suites_length)
{
	unsigned short supported_cipher_suites[] = { TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA };
	for (int i = 0; i < sizeof(supported_cipher_suites) / sizeof(unsigned short); ++i)
	{
		cipher_suite_type current = supported_cipher_suites[i];
		for (int j = 0; j < (int)client_cipher_suites_length; ++j)
			if (current == client_cipher_suites[j])
			{
				*chosen_cipher_suite = current;
				rawhttps_logger_log_info("Cipher 0x%04hX was chosen for the TLS connection.", *chosen_cipher_suite);
				return 0;
			}
	}

	return -1;
}

static int handshake_client_hello_get(rawhttps_tls_state* ts, int connected_socket, unsigned short** client_cipher_suites,
	unsigned short* client_cipher_suites_length)
{
	handshake_packet p;
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
		return -1;

	// We expect a handshake packet (with message CLIENT_HELLO)
	if (type != HANDSHAKE_PROTOCOL)
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	if (rawhttps_tls_parser_handshake_packet_parse(&p, &ts->ps, connected_socket, &ts->client_connection_state, &ts->handshake_messages))
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	// We expect a handshake packet (with message CLIENT_HELLO)
	if (p.hh.message_type != CLIENT_HELLO_MESSAGE)
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	memcpy(ts->pending_security_parameters.client_random, p.message.chm.client_random, CLIENT_RANDOM_SIZE);
	*client_cipher_suites = malloc(p.message.chm.cipher_suites_length * 2);
	memcpy(*client_cipher_suites, p.message.chm.cipher_suites, p.message.chm.cipher_suites_length * 2);
	*client_cipher_suites_length = p.message.chm.cipher_suites_length;
	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Client Random", ts->pending_security_parameters.client_random,
		(long long)CLIENT_RANDOM_SIZE);

	rawhttps_tls_parser_handshake_packet_release(&p);

	return 0;
}

static int handshake_server_hello_send(rawhttps_tls_state* ts, int connected_socket, cipher_suite_type selected_cipher_suite)
{
	unsigned char server_random[SERVER_RANDOM_SIZE];
	server_hello_random_number_generate(server_random);
	memcpy(ts->pending_security_parameters.server_random, server_random, SERVER_RANDOM_SIZE);
	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Server Random", ts->pending_security_parameters.server_random,
		(long long)SERVER_RANDOM_SIZE);
	if (rawhttps_tls_sender_handshake_server_hello_message_send(&ts->server_connection_state, connected_socket,
		selected_cipher_suite, server_random, &ts->handshake_messages))
		return -1;
	security_parameters_set_for_cipher_suite(selected_cipher_suite, &ts->pending_security_parameters);
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
	handshake_packet p;
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	// We expect a handshake packet (with message CLIENT_KEY_EXCHANGE)
	if (type != HANDSHAKE_PROTOCOL)
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	if (rawhttps_tls_parser_handshake_packet_parse(&p, &ts->ps, connected_socket, &ts->client_connection_state, &ts->handshake_messages))
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	// We expect a handshake packet (with message CLIENT_KEY_EXCHANGE)
	if (p.hh.message_type != CLIENT_KEY_EXCHANGE_MESSAGE)
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}
	
	unsigned char pre_master_secret[PRE_MASTER_SECRET_SIZE];
	unsigned char master_secret[MASTER_SECRET_SIZE];

	unsigned int encrypted_pre_master_secret_length = p.message.ckem.premaster_secret_length;
	unsigned char* encrypted_pre_master_secret = p.message.ckem.premaster_secret;
	if (pre_master_secret_decrypt(&ts->private_key, pre_master_secret, encrypted_pre_master_secret, encrypted_pre_master_secret_length))
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Decrypted PreMasterSecret", pre_master_secret, (long long)PRE_MASTER_SECRET_SIZE);

	rsa_master_secret_generate(pre_master_secret, ts->pending_security_parameters.client_random,
		ts->pending_security_parameters.server_random, master_secret);
	memcpy(ts->pending_security_parameters.master_secret, master_secret, MASTER_SECRET_SIZE);

	rawhttps_logger_log_hex(RAWHTTPS_LOG_LEVEL_DEBUG, "Master Secret", master_secret, (long long)MASTER_SECRET_SIZE);

	rawhttps_tls_parser_handshake_packet_release(&p);

	return 0;
}

static int handshake_change_cipher_spec_get(rawhttps_tls_state* ts, int connected_socket)
{
	change_cipher_spec_packet p;
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
	{
		rawhttps_tls_parser_change_cipher_spec_release(&p);
		return -1;
	}

	// We expect a CHANGE_CIPHER_SPEC packet
	if (type != CHANGE_CIPHER_SPEC_PROTOCOL)
	{
		rawhttps_tls_parser_change_cipher_spec_release(&p);
		return -1;
	}

	if (rawhttps_tls_parser_change_cipher_spec_parse(&p, &ts->ps, connected_socket, &ts->client_connection_state))
	{
		rawhttps_tls_parser_change_cipher_spec_release(&p);
		return -1;
	}

	if (p.message != CHANGE_CIPHER_SPEC_MESSAGE)
	{
		rawhttps_tls_parser_change_cipher_spec_release(&p);
		return -1;
	}

	pending_client_cipher_apply(ts);
	rawhttps_tls_parser_change_cipher_spec_release(&p);
	return 0;
}

static int handshake_finished_get(rawhttps_tls_state* ts, int connected_socket)
{
	handshake_packet p;
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	// We expect a handshake packet (with message FINISHED)
	if (type != HANDSHAKE_PROTOCOL)
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	if (rawhttps_tls_parser_handshake_packet_parse(&p, &ts->ps, connected_socket, &ts->client_connection_state, &ts->handshake_messages))
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}

	// We expect a handshake packet (with message FINISHED)
	if (p.hh.message_type != FINISHED_MESSAGE)
	{
		rawhttps_tls_parser_handshake_packet_release(&p);
		return -1;
	}
	
	rawhttps_tls_parser_handshake_packet_release(&p);
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
	unsigned short* client_cipher_suites;
	unsigned short client_cipher_suites_length;
	if (handshake_client_hello_get(ts, connected_socket, &client_cipher_suites, &client_cipher_suites_length))
	{
		rawhttps_logger_log_error("Error receiving CLIENT_HELLO message");
		return -1;
	}

	cipher_suite_type chosen_cipher;
	if (cipher_suite_choose(&chosen_cipher, client_cipher_suites, client_cipher_suites_length))
	{
		rawhttps_logger_log_error("Error selecting the cipher suite for TLS connection");
		return -1;
	}
	
	if (handshake_server_hello_send(ts, connected_socket, chosen_cipher))
	{
		rawhttps_logger_log_error("Error sending SERVER_HELLO message");
		return -1;
	}

	if (handshake_certificate_send(ts, connected_socket))
	{
		rawhttps_logger_log_error("Error sending CERTIFICATE message");
		return -1;
	}
	
	if (handshake_server_hello_done_send(ts, connected_socket))
	{
		rawhttps_logger_log_error("Error sending SERVER_HELLO_DONE message");
		return -1;
	}

	if (handshake_client_key_exchange_get(ts, connected_socket))
	{
		rawhttps_logger_log_error("Error receiving CLIENT_KEY_EXCHANGE message");
		return -1;
	}
	
	if (handshake_change_cipher_spec_get(ts, connected_socket))
	{
		rawhttps_logger_log_error("Error receiving CHANGE_CIPHER_SPEC");
		return -1;
	}

	if (handshake_finished_get(ts, connected_socket))
	{
		rawhttps_logger_log_error("Error receiving FINISHED message");
		return -1;
	}

	if (handshake_change_cipher_spec_send(ts, connected_socket))
	{
		rawhttps_logger_log_error("Error sending CHANGE_CIPHER_SPEC message");
		return -1;
	}
	
	if (handshake_finished_send(ts, connected_socket))
	{
		rawhttps_logger_log_error("Error sending FINISHED message");
		return -1;
	}

	ts->handshake_completed = true;

	free(client_cipher_suites);
	return 0;
}

long long rawhttps_tls_read(rawhttps_tls_state* ts, int connected_socket,
	unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE])
{
	protocol_type type;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_tls_parser_protocol_type_get_next(&ts->ps, connected_socket, &ts->client_connection_state, &type))
		return -1;

	switch (type)
	{
		case HANDSHAKE_PROTOCOL: {
			rawhttps_logger_log_error("Received HANDSHAKE protocol inside tls_read");
			return -1;
		} break;
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			rawhttps_logger_log_error("Received CHANGE_CIPHER_SPEC protocol inside tls_read");
			return -1;
		} break;
		case APPLICATION_DATA_PROTOCOL: {
			long long bytes_written;
			if (rawhttps_tls_parser_application_data_parse(data, &bytes_written, &ts->ps, connected_socket, &ts->client_connection_state))
			{
				rawhttps_logger_log_error("Error parsing application data");
				return -1;
			}
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