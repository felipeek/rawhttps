#include "record.h"
#include <assert.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "crypto/aes_cbc.h"
#include "crypto/aes256_cbc.h"
#include "../util.h"
#include "crypto/crypto_hashes.h"
#include "crypto/hmac.h"
#include "protocol.h"
#include "../logger.h"
#include "crypto/random.h"

#define RECORD_PARSER_CHUNK_SIZE 1024
#define RECORD_BUFFER_INITIAL_SIZE 1024

#define LITTLE_ENDIAN_16(x) (((unsigned short)(x)[1]) | ((unsigned short)(x)[0] << 8))
#define LITTLE_ENDIAN_24(x) (((unsigned int)(x)[2]) | ((unsigned int)(x)[1] << 8) | ((unsigned int)(x)[0] << 16))

/* READING/PARSING FUNCTIONS */

// creates rawhttps_parser_state
int rawhttps_record_buffer_create(rawhttps_record_buffer* record_buffer)
{
	record_buffer->buffer = malloc(sizeof(char) * RECORD_BUFFER_INITIAL_SIZE);
	if (!record_buffer->buffer) return -1;
	record_buffer->buffer_size = RECORD_BUFFER_INITIAL_SIZE;
	record_buffer->buffer_end = 0;
	record_buffer->buffer_position_fetch = 0;
	record_buffer->buffer_position_get = 0;
	return 0;
}

// destroys rawhttps_parser_buffer
void rawhttps_record_buffer_destroy(rawhttps_record_buffer* record_buffer)
{
	free(record_buffer->buffer);
}

// clear the phb buffer.
// data which was already used via 'get' functions will be released and the pointers will be adjusted
static void rawhttps_record_buffer_clear(rawhttps_record_buffer* record_buffer)
{
	memmove(record_buffer->buffer, record_buffer->buffer + record_buffer->buffer_position_get,
		record_buffer->buffer_end - record_buffer->buffer_position_get);
	record_buffer->buffer_end -= record_buffer->buffer_position_get;
	record_buffer->buffer_position_fetch -= record_buffer->buffer_position_get;
	record_buffer->buffer_position_get = 0;
}

// fetches the next chunk of tcp data and stores in the phb buffer
static long long record_fetch_next_tcp_chunk(rawhttps_record_buffer* record_buffer, int connected_socket)
{
	long long size_needed = record_buffer->buffer_end + RECORD_PARSER_CHUNK_SIZE;
	if (size_needed > record_buffer->buffer_size)
	{
		record_buffer->buffer = realloc(record_buffer->buffer, size_needed);
		record_buffer->buffer_size = size_needed;
	}

	long long size_read;
	if ((size_read = read(connected_socket, record_buffer->buffer + record_buffer->buffer_end, RECORD_PARSER_CHUNK_SIZE)) < 0)
	{
		rawhttps_logger_log_error("Error reading data from connection socket: %s", strerror(errno));
		return -1;
	}
	if (size_read == 0)
	{
		rawhttps_logger_log_error("Error reading data from connection socket: (size_read == 0)");
		return -1;
	}
	record_buffer->buffer_end += size_read;

	return size_read;
}

// guarantees that the next 'num' bytes are available in the phb buffer.
static int record_guarantee_next_bytes(rawhttps_record_buffer* record_buffer, int connected_socket, unsigned char** ptr, long long num)
{
	while (record_buffer->buffer_position_fetch + num > record_buffer->buffer_end)
		if (record_fetch_next_tcp_chunk(record_buffer, connected_socket) == -1)
			return -1;

	record_buffer->buffer_position_fetch += num;
	*ptr = record_buffer->buffer + record_buffer->buffer_position_fetch - num;
	return 0;
}

// guarantees that the next record packet is available as a whole in the phb buffer.
static int record_guarantee_record(rawhttps_record_buffer* record_buffer, int connected_socket)
{
	unsigned char* ptr;

	// fetch record header.
	// the fourth/fifth bytes are the length
	if (record_guarantee_next_bytes(record_buffer, connected_socket, &ptr, 5))
		return -1;

	unsigned short record_length = LITTLE_ENDIAN_16(ptr + 3);

	// get record
	if (record_guarantee_next_bytes(record_buffer, connected_socket, &ptr, record_length))
		return -1;

	return 0;
}

// gets next 'num' bytes from phb buffer.
// this function basically increments the internal buffer_position_get pointer and returns a pointer to the data via 'ptr'
// if the data was not fetched previously by the 'fetch' functions, an error is returned.
static int record_get_next_bytes(rawhttps_record_buffer* record_buffer, long long num, unsigned char** ptr)
{
	if (record_buffer->buffer_position_get + num > record_buffer->buffer_position_fetch)
		return -1;

	record_buffer->buffer_position_get += num;
	*ptr = record_buffer->buffer + record_buffer->buffer_position_get - num;
	return 0;
}

static int mac(const rawhttps_connection_state* server_cs, const unsigned char* mac_message, int mac_message_length, unsigned char* result)
{
	switch(server_cs->security_parameters.mac_algorithm)
	{
		case MAC_ALGORITHM_HMAC_SHA1: {
			rawhttps_hmac(rawhttps_sha1, server_cs->mac_key, server_cs->security_parameters.mac_length, mac_message, mac_message_length, result,
				server_cs->security_parameters.mac_length);
			return 0;
		} break;
		case MAC_ALGORITHM_HMAC_SHA256: {
			rawhttps_hmac(rawhttps_sha256, server_cs->mac_key, server_cs->security_parameters.mac_length, mac_message, mac_message_length, result,
				server_cs->security_parameters.mac_length);
			return 0;
		} break;
		case MAC_ALGORITHM_NULL:
		case MAC_ALGORITHM_HMAC_MD5:
		case MAC_ALGORITHM_HMAC_SHA384:
		case MAC_ALGORITHM_HMAC_SHA512: {
			rawhttps_logger_log_error("Error calculating MAC: mac algorithm not supported");
			return -1;
		} break;
	}

	rawhttps_logger_log_error("Error calculating MAC: mac algorithm not supported");
	return -1;
}

static int build_mac_message(rawhttps_connection_state* cs, const unsigned char* fragment, int fragment_length, protocol_type type,
	unsigned char* result)
{
	unsigned long long seq_number_be = BIG_ENDIAN_64(cs->sequence_number);
	unsigned char mac_tls_type = type;
	unsigned short mac_tls_version = BIG_ENDIAN_16(TLS12);
	unsigned short mac_tls_length = BIG_ENDIAN_16(fragment_length);
	int mac_message_length = sizeof(seq_number_be) + sizeof(mac_tls_type) + sizeof(mac_tls_version) + sizeof(mac_tls_length) + fragment_length;
	unsigned char* mac_message = calloc(1, mac_message_length);
	*(unsigned long long*)(mac_message + 0) = seq_number_be;
	*(unsigned char*)(mac_message + 8) = mac_tls_type;
	*(unsigned short*)(mac_message + 9) = mac_tls_version;
	*(unsigned short*)(mac_message + 11) = mac_tls_length;
	memcpy(mac_message + 13, fragment, fragment_length);
	int r = mac(cs, mac_message, mac_message_length, result);
	free(mac_message);
	++cs->sequence_number;
	return r;
}

static int cipher_stream_decrypt(const rawhttps_connection_state* client_cs, unsigned char* record_data,
	unsigned short record_data_length, unsigned char result[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE])
{
	switch(client_cs->security_parameters.bulk_cipher_algorithm)
	{
		case BULK_CIPHER_ALGORITHM_NULL: {
			memcpy(result, record_data, record_data_length);
			return record_data_length;
		} break;
		case BULK_CIPHER_ALGORITHM_AES:
		case BULK_CIPHER_ALGORITHM_DES:
		case BULK_CIPHER_ALGORITHM_RC4: {
			rawhttps_logger_log_error("Error decrypting cipher stream: bulk cipher algorithm not supported");
			return -1;
		} break;
	}

	rawhttps_logger_log_error("Error decrypting cipher stream: bulk cipher algorithm not supported");
	return -1;
}

static int cipher_block_decrypt(rawhttps_connection_state* client_cs, unsigned char* record_data,
	unsigned short record_data_length, unsigned char result[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE], protocol_type type)
{
	// Parts of the encrypted block
	unsigned char* record_iv = record_data;
	unsigned char record_iv_length = client_cs->security_parameters.record_iv_length;
	unsigned char* record_data_without_iv = record_data + record_iv_length;
	unsigned short record_data_without_iv_length = record_data_length - (unsigned char)record_iv_length;

	if (record_data_without_iv_length < 0) {
		rawhttps_logger_log_error("Error decrypting cipher block: Record data without IV is negative.");
		return -1;
	}

	switch (client_cs->security_parameters.bulk_cipher_algorithm)
	{
		case BULK_CIPHER_ALGORITHM_AES: {
			int block_count = (int)record_data_without_iv_length / client_cs->security_parameters.block_length;

			if (block_count == 0 || (int)record_data_without_iv_length % client_cs->security_parameters.block_length != 0) {
				rawhttps_logger_log_error("Error decrypting cipher block: Malformed encrypted record data");
				return -1;
			}

			switch (client_cs->security_parameters.enc_key_length)
			{
				case 16: rawhttps_aes_128_cbc_decrypt(record_data_without_iv, client_cs->cipher_state.enc_key,
					record_iv, block_count, result); break;
				case 32: rawhttps_aes_256_cbc_decrypt(record_data_without_iv, client_cs->cipher_state.enc_key,
					record_iv, result, block_count); break;
				default: return -1;
			}
		} break;
		case BULK_CIPHER_ALGORITHM_NULL:
		case BULK_CIPHER_ALGORITHM_DES:
		case BULK_CIPHER_ALGORITHM_RC4: {
			rawhttps_logger_log_error("Error decrypting cipher block: bulk cipher algorithm not supported");
			return -1;
		} break;
		default: {
			rawhttps_logger_log_error("Error decrypting cipher block: bulk cipher algorithm not supported");
			return -1;
		} break;
	}
	
	// Parts of the already decrypted block
	int padding_length_position = record_data_without_iv_length - 1;
	if (padding_length_position < 0) {
		rawhttps_logger_log_error("Error decrypting cipher block: Wrong padding length position");
		return -1;
	}
	unsigned char padding_length = result[padding_length_position];
	int padding_position = padding_length_position - padding_length;
	if (padding_position >= record_data_without_iv_length || padding_position < 0) {
		rawhttps_logger_log_error("Error decrypting cipher block: Wrong padding position");
		return -1;
	}
	for (int i = padding_position; i < record_data_without_iv_length; ++i) {
		if (result[i] != padding_length) {
			rawhttps_logger_log_error("Error decrypting cipher block: Malformed padding");
			return -1;
		}
	}
	int mac_position = padding_position - client_cs->security_parameters.mac_length;
	int content_position = 0;
	if (mac_position + client_cs->security_parameters.mac_length >= record_data_without_iv_length || mac_position < 0) {
		rawhttps_logger_log_error("Error decrypting cipher block: Wrong MAC position");
		return -1;
	}
	unsigned char* mac = &result[mac_position];
	unsigned char* content = &result[content_position];
	int content_length = mac_position;

	// Re-calculate mac to check integrity
	unsigned char calculated_mac[CIPHER_MAC_MAX_LENGTH];
	build_mac_message(client_cs, content, content_length, type, calculated_mac);
	if (memcmp(mac, calculated_mac, client_cs->security_parameters.mac_length))
	{
		rawhttps_logger_log_error("Client sent an incorrect MAC");
		return -1;
	}
	return content_length;
}

static int record_data_decrypt(rawhttps_connection_state* client_cs, unsigned char* record_data,
	unsigned short record_data_length, unsigned char result[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE], protocol_type type)
{
	// @TODO: We need to check the MAC here!
	switch (client_cs->security_parameters.cipher)
	{
		case CIPHER_STREAM: {
			return cipher_stream_decrypt(client_cs, record_data, record_data_length, result);
		} break;
		case CIPHER_BLOCK: {
			return cipher_block_decrypt(client_cs, record_data, record_data_length, result, type);
		} break;
		case CIPHER_AEAD: {
			rawhttps_logger_log_error("Error decrypting record data: cipher type not supported");
			return -1;
		}
	}

	rawhttps_logger_log_error("Error decrypting record data: cipher type not supported");
	return -1;
}

static void alert_packet_print(alert_level level, alert_description description)
{
	rawhttps_log_level log_level = RAWHTTPS_LOG_LEVEL_WARNING;
	switch (level)
	{
		case ALERT_LEVEL_WARNING: {
			log_level = RAWHTTPS_LOG_LEVEL_WARNING;
		} break;
		case ALERT_LEVEL_FATAL: {
			log_level = RAWHTTPS_LOG_LEVEL_ERROR;
		} break;
	}

	switch (description)
	{
		case CLOSE_NOTIFY: {
			rawhttps_logger_log(log_level, "CLOSE_NOTIFY alert received");
		} break;
		case UNEXPECTED_MESSAGE: {
			rawhttps_logger_log(log_level, "UNEXPECTED_MESSAGE alert received");
		} break;
		case BAD_RECORD_MAC: {
			rawhttps_logger_log(log_level, "BAD_RECORD_MAC alert received");
		} break;
		case DECRYPTION_FAILED_RESERVED: {
			rawhttps_logger_log(log_level, "DECRYPTION_FAILED_RESERVED alert received");
		} break;
		case RECORD_OVERFLOW: {
			rawhttps_logger_log(log_level, "RECORD_OVERFLOW alert received");
		} break;
		case DECOMPRESSION_FAILURE: {
			rawhttps_logger_log(log_level, "DECOMPRESSION_FAILURE alert received");
		} break;
		case HANDSHAKE_FAILURE: {
			rawhttps_logger_log(log_level, "HANDSHAKE_FAILURE alert received");
		} break;
		case NO_CERTIFICATE_RESERVED: {
			rawhttps_logger_log(log_level, "NO_CERTIFICATE_RESERVED alert received");
		} break;
		case BAD_CERTIFICATE: {
			rawhttps_logger_log(log_level, "BAD_CERTIFICATE alert received");
		} break;
		case UNSUPPORTED_CERTIFICATE: {
			rawhttps_logger_log(log_level, "UNSUPPORTED_CERTIFICATE alert received");
		} break;
		case CERTIFICATE_REVOKED: {
			rawhttps_logger_log(log_level, "CERTIFICATE_REVOKED alert received");
		} break;
		case CERTIFICATE_EXPIRED: {
			rawhttps_logger_log(log_level, "CERTIFICATE_EXPIRED alert received");
		} break;
		case CERTIFICATE_UNKNOWN: {
			rawhttps_logger_log(log_level, "CERTIFICATE_UNKNOWN alert received");
		} break;
		case ILLEGAL_PARAMETER: {
			rawhttps_logger_log(log_level, "ILLEGAL_PARAMETER alert received");
		} break;
		case UNKNOWN_CA: {
			rawhttps_logger_log(log_level, "UNKNOWN_CA alert received");
		} break;
		case ACCESS_DENIED: {
			rawhttps_logger_log(log_level, "ACCESS_DENIED alert received");
		} break;
		case DECODE_ERROR: {
			rawhttps_logger_log(log_level, "DECODE_ERROR alert received");
		} break;
		case DECRYPT_ERROR: {
			rawhttps_logger_log(log_level, "DECRYPT_ERROR alert received");
		} break;
		case EXPORT_RESTRICTION_RESERVED: {
			rawhttps_logger_log(log_level, "EXPORT_RESTRICTION_RESERVED alert received");
		} break;
		case PROTOCOL_VERSION: {
			rawhttps_logger_log(log_level, "PROTOCOL_VERSION alert received");
		} break;
		case INSUFFICIENT_SECURITY: {
			rawhttps_logger_log(log_level, "INSUFFICIENT_SECURITY alert received");
		} break;
		case INTERNAL_ERROR: {
			rawhttps_logger_log(log_level, "INTERNAL_ERROR alert received");
		} break;
		case USER_CANCELED: {
			rawhttps_logger_log(log_level, "USER_CANCELED alert received");
		} break;
		case NO_RENEGOTIATION: {
			rawhttps_logger_log(log_level, "NO_RENEGOTIATION alert received");
		} break;
		case UNSUPPORTED_EXTENSION: {
			rawhttps_logger_log(log_level, "UNSUPPORTED_EXTENSION alert received");
		} break;
		default: {
			rawhttps_logger_log(log_level, "UNDEFINED alert received");
		} break;
	}
}

// Gets the data of the next record packet and stores in the received buffer. The type is also returned via 'type'
long long rawhttps_record_get(rawhttps_record_buffer* record_buffer, int connected_socket,
	unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE], protocol_type* type, rawhttps_connection_state* client_cs,
	record_status* status)
{
	unsigned char* ptr;
	*status = RAWHTTPS_RECORD_STATUS_NONE;

	if (record_guarantee_record(record_buffer, connected_socket))
	{
		*status = RAWHTTPS_RECORD_STATUS_IO_ERROR;
		return -1;
	}

	if (record_get_next_bytes(record_buffer, 5, &ptr))
	{
		*status = RAWHTTPS_RECORD_STATUS_IO_ERROR;
		return -1;
	}
	unsigned short record_length = LITTLE_ENDIAN_16(ptr + 3);
	*type = *ptr;
	assert(record_length <= RECORD_PROTOCOL_TLS_CIPHER_TEXT_FRAGMENT_MAX_SIZE);
	if (record_get_next_bytes(record_buffer, record_length, &ptr))
	{
		*status = RAWHTTPS_RECORD_STATUS_IO_ERROR;
		return -1;
	}

	long long decrypted_record_data_length = record_data_decrypt(client_cs, ptr, record_length, data, *type);
	if (decrypted_record_data_length == -1) {
		*status = RAWHTTPS_RECORD_STATUS_MALFORMED_PACKET;
		return -1;
	}
	assert(decrypted_record_data_length <= RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE);
	rawhttps_record_buffer_clear(record_buffer);

	// Test for alerts or whether the record packet has some error
	switch (*type)
	{
		case ALERT_PROTOCOL: {
			if (decrypted_record_data_length != 2)
			{
				// malformed alert packet
				*status = RAWHTTPS_RECORD_STATUS_MALFORMED_PACKET;
				return -1;
			}
			alert_level level = data[0];
			alert_description description = data[1];

			alert_packet_print(level, description);

			if (description == CLOSE_NOTIFY)
			{
				*status = RAWHTTPS_RECORD_STATUS_CLOSE_NOTIFY;
				rawhttps_logger_log_warning("CLOSE_NOTIFY was received! Connection shall be closed");
				return -1;
			} else if (level == ALERT_LEVEL_FATAL) {
				*status = RAWHTTPS_RECORD_STATUS_FATAL_ALERT;
				rawhttps_logger_log_error("An FATAL alert was received! Connection shall be closed");
				return -1;
			} else if (level == ALERT_LEVEL_WARNING) {
				// If we received a warning alert, we just try it again
				return rawhttps_record_get(record_buffer, connected_socket, data, type, client_cs, status);
			}
		} break;
		default: {

		} break;
	}

	return decrypted_record_data_length;
}

/* WRITING/SENDING FUNCTIONS */

// sends a single record packet to the client
static int send_cipher_text(const unsigned char* cipher_text, int cipher_text_length, int connected_socket)
{
	// MSG_NOSIGNAL to avoid SIGPIPE error
	ssize_t written = send(connected_socket, cipher_text, cipher_text_length, MSG_NOSIGNAL);

	if (written < 0)
	{
		rawhttps_logger_log_error("Error sending record: %s", strerror(errno));
		return -1;
	}

	// @TODO: in an excepcional case, writev() could write less bytes than requested...
	// we should look at writev() documentation and decide what to do in this particular case
	// for now, throw an error...
	if (written != cipher_text_length)
	{
		rawhttps_logger_log_error("Error sending record: (written != cipher_text_length)");
		return -1;
	}
	
	return 0;
}


static int cipher_stream_encrypt(const rawhttps_connection_state* server_cs, unsigned char cipher_text[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE],
	int cipher_text_length)
{
	switch(server_cs->security_parameters.bulk_cipher_algorithm)
	{
		case BULK_CIPHER_ALGORITHM_NULL: {
			return 0;
		} break;
		case BULK_CIPHER_ALGORITHM_AES:
		case BULK_CIPHER_ALGORITHM_DES:
		case BULK_CIPHER_ALGORITHM_RC4: {
			rawhttps_logger_log_error("Error encrypting cipher stream: bulk cipher algorithm not supported");
			return -1;
		} break;
	}

	rawhttps_logger_log_error("Error encrypting cipher stream: bulk cipher algorithm not supported");
	return -1;
}

static int cipher_block_encrypt(rawhttps_connection_state* server_cs, unsigned char cipher_text[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE],
	int cipher_text_length)
{
	// Structure defined in: https://tools.ietf.org/html/rfc5246#section-6.2.3.2
	switch(server_cs->security_parameters.bulk_cipher_algorithm)
	{
		case BULK_CIPHER_ALGORITHM_AES: {
			// Encrypt data
			unsigned char* iv = cipher_text + RECORD_PROTOCOL_TLS_HEADER_SIZE;
			unsigned char* generic_block_cipher = cipher_text + RECORD_PROTOCOL_TLS_HEADER_SIZE + server_cs->security_parameters.record_iv_length;
			unsigned int generic_block_cipher_size = cipher_text_length - RECORD_PROTOCOL_TLS_HEADER_SIZE - server_cs->security_parameters.record_iv_length;
			assert(generic_block_cipher_size % server_cs->security_parameters.block_length == 0);
			switch (server_cs->security_parameters.enc_key_length)
			{
				case 16: rawhttps_aes_128_cbc_encrypt(generic_block_cipher, server_cs->cipher_state.enc_key, iv,
					generic_block_cipher_size / server_cs->security_parameters.block_length, generic_block_cipher); break;
				case 32: rawhttps_aes_256_cbc_encrypt(generic_block_cipher, server_cs->cipher_state.enc_key, iv,
					generic_block_cipher, generic_block_cipher_size / server_cs->security_parameters.block_length); break;
				default: return -1;
			}
			return 0;
		} break;
		case BULK_CIPHER_ALGORITHM_NULL:
		case BULK_CIPHER_ALGORITHM_DES:
		case BULK_CIPHER_ALGORITHM_RC4: {
			rawhttps_logger_log_error("Error encrypting cipher block: bulk cipher algorithm not supported");
			return -1;
		} break;
	}

	rawhttps_logger_log_error("Error encrypting cipher block: bulk cipher algorithm not supported");
	return -1;
}

static int encrypt_tls_cipher_text_fragment(rawhttps_connection_state* server_cs, unsigned char cipher_text[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE],
	int cipher_text_length)
{
	switch(server_cs->security_parameters.cipher)
	{
		case CIPHER_STREAM: {
			return cipher_stream_encrypt(server_cs, cipher_text, cipher_text_length);
		} break;
		case CIPHER_BLOCK: {
			return cipher_block_encrypt(server_cs, cipher_text, cipher_text_length);
		} break;
		case CIPHER_AEAD: {
			rawhttps_logger_log_error("Error encrypting cipher text fragment: cipher type not supported");
			return -1;
		} break;
	}

	rawhttps_logger_log_error("Error encrypting cipher text fragment: cipher type not supported");
	return -1;
}

// @TODO !
static void generate_random_iv(unsigned char iv_length, unsigned char* iv)
{
	for (int i = 0; i < iv_length; ++i)
	{
		unsigned long long r = random_64bit_integer();
		iv[i] = (unsigned char)(r & 0xFF);
	}
}

static int build_tls_cipher_text(rawhttps_connection_state* server_cs, const unsigned char* fragment, int fragment_length,
	protocol_type type, unsigned char cipher_text[RECORD_PROTOCOL_TLS_CIPHER_TEXT_MAX_SIZE])
{
	switch (server_cs->security_parameters.cipher)
	{
		case CIPHER_STREAM: {
			unsigned char record_header[RECORD_PROTOCOL_TLS_HEADER_SIZE];
			*(unsigned char*)(record_header + 0) = type;
			*(unsigned short*)(record_header + 1) = BIG_ENDIAN_16(TLS12);
			*(unsigned short*)(record_header + 3) = BIG_ENDIAN_16(fragment_length);

			int cipher_text_size = RECORD_PROTOCOL_TLS_HEADER_SIZE + fragment_length;
			unsigned char* cipher_text_ptr = cipher_text;
			memcpy(cipher_text_ptr, record_header, RECORD_PROTOCOL_TLS_HEADER_SIZE);
			cipher_text_ptr += RECORD_PROTOCOL_TLS_HEADER_SIZE;
			memcpy(cipher_text_ptr, fragment, fragment_length);

			return cipher_text_size;
		} break;
		case CIPHER_BLOCK: {
			// Structure defined in: https://tools.ietf.org/html/rfc5246#section-6.2.3.2
			unsigned int cipher_text_content_length = server_cs->security_parameters.record_iv_length + fragment_length +
				server_cs->security_parameters.mac_length + 1; // +1 for padding_length
			unsigned char padding_length = server_cs->security_parameters.block_length - ((cipher_text_content_length -
				server_cs->security_parameters.record_iv_length) % server_cs->security_parameters.block_length);
			cipher_text_content_length += padding_length;
			assert(cipher_text_content_length <= RECORD_PROTOCOL_TLS_CIPHER_TEXT_FRAGMENT_MAX_SIZE);

			unsigned char record_header[RECORD_PROTOCOL_TLS_HEADER_SIZE];
			*(unsigned char*)(record_header + 0) = type;
			*(unsigned short*)(record_header + 1) = BIG_ENDIAN_16(TLS12);
			*(unsigned short*)(record_header + 3) = BIG_ENDIAN_16(cipher_text_content_length);

			int cipher_text_size = RECORD_PROTOCOL_TLS_HEADER_SIZE + cipher_text_content_length;
			unsigned char* cipher_text_ptr = cipher_text;
			memcpy(cipher_text_ptr, record_header, RECORD_PROTOCOL_TLS_HEADER_SIZE);
			cipher_text_ptr += RECORD_PROTOCOL_TLS_HEADER_SIZE;
			generate_random_iv(server_cs->security_parameters.record_iv_length, cipher_text_ptr);
			cipher_text_ptr += server_cs->security_parameters.record_iv_length;
			memcpy(cipher_text_ptr, fragment, fragment_length);
			cipher_text_ptr += fragment_length;
			if (build_mac_message(server_cs, fragment, fragment_length, type, cipher_text_ptr))
				return -1;
			cipher_text_ptr += server_cs->security_parameters.mac_length;
			memset(cipher_text_ptr, padding_length, padding_length);
			cipher_text_ptr += padding_length;
			cipher_text_ptr[0] = padding_length;

			return cipher_text_size;
		} break;
		case CIPHER_AEAD: {
			rawhttps_logger_log_error("Error building cipher text: cipher type not supported");
			return -1;
		} break;
	}

	rawhttps_logger_log_error("Error building cipher text: cipher type not supported");
	return -1;
}

int rawhttps_record_send(rawhttps_connection_state* server_cs, const unsigned char* data, int data_length,
	protocol_type type, int connected_socket)
{
	unsigned char cipher_text[RECORD_PROTOCOL_TLS_CIPHER_TEXT_MAX_SIZE];
	int cipher_text_length;
	if ((cipher_text_length = build_tls_cipher_text(server_cs, data, data_length, type, cipher_text)) == -1)
	{
		rawhttps_logger_log_error("Error building TLS cipher text");
		return -1;
	}

	if (encrypt_tls_cipher_text_fragment(server_cs, cipher_text, cipher_text_length))
	{
		rawhttps_logger_log_error("Error encrypting TLS cipher text fragment");
		return -1;
	}

	// Send record packet
	if (send_cipher_text(cipher_text, cipher_text_length, connected_socket))
	{
		rawhttps_logger_log_error("Error sending TLS cipher text");
		return -1;
	}

	return 0;
}