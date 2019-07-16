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
#include "../util.h"
#include "crypto/crypto_hashes.h"
#include "crypto/hmac.h"
#include "protocol.h"

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
		return -1;
	if (size_read == 0)
		return -1;
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

static int cipher_stream_decrypt(const rawhttps_connection_state* client_cs, unsigned char* record_data,
	unsigned short record_data_length, unsigned char result[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE])
{
	switch(client_cs->security_parameters.bulk_cipher_algorithm)
	{
		case BULK_CIPHER_ALGORITHM_NULL: {
			memcpy(result, record_data, record_data_length);
			return record_data_length;
		} break;
		case BULK_CIPHER_ALGORITHM_AES: {
			return -1;
		} break;
		case BULK_CIPHER_ALGORITHM_DES: {
			return -1;
		} break;
		case BULK_CIPHER_ALGORITHM_RC4: {
			return -1;
		} break;
	}

	return -1;
}

static int cipher_block_decrypt(const rawhttps_connection_state* client_cs, unsigned char* record_data,
	unsigned short record_data_length, unsigned char result[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE])
{
	switch(client_cs->security_parameters.bulk_cipher_algorithm)
	{
		case BULK_CIPHER_ALGORITHM_NULL: {
			return -1;
		} break;
		case BULK_CIPHER_ALGORITHM_AES: {
			unsigned char record_iv_length = client_cs->security_parameters.record_iv_length;
			unsigned short record_data_without_iv_length = record_data_length - (unsigned char)record_iv_length;
			unsigned char* record_iv = record_data;
			unsigned char* record_data_without_iv = record_data + record_iv_length;
			int block_count = (int)record_data_without_iv_length / client_cs->security_parameters.block_length;
			switch (client_cs->security_parameters.enc_key_length)
			{
				case 16: aes_128_cbc_decrypt(record_data_without_iv, client_cs->cipher_state.enc_key,
					record_iv, block_count, result); break;
				default: return -1;
			}
			unsigned char padding_length = result[record_data_without_iv_length - 1];
			return record_data_without_iv_length - client_cs->security_parameters.mac_length - padding_length - 1;
		} break;
		case BULK_CIPHER_ALGORITHM_DES: {
			return -1;
		} break;
		case BULK_CIPHER_ALGORITHM_RC4: {
			return -1;
		} break;
	}
	
	return -1;
}

static int record_data_decrypt(const rawhttps_connection_state* client_cs, unsigned char* record_data,
	unsigned short record_data_length, unsigned char result[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE])
{
	// @TODO: We need to check the MAC here!
	switch (client_cs->security_parameters.cipher)
	{
		case CIPHER_STREAM: {
			return cipher_stream_decrypt(client_cs, record_data, record_data_length, result);
		} break;
		case CIPHER_BLOCK: {
			return cipher_block_decrypt(client_cs, record_data, record_data_length, result);
		} break;
		case CIPHER_AEAD: {
			return -1;
		}
	}

	return -1;
}

// gets the data of the next record packet and stores in the received buffer. The type is also returned via 'type'
long long rawhttps_record_get(rawhttps_record_buffer* record_buffer, int connected_socket,
	unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE], protocol_type* type, rawhttps_connection_state* client_cs)
{
	unsigned char* ptr;

	if (record_guarantee_record(record_buffer, connected_socket))
		return -1;

	if (record_get_next_bytes(record_buffer, 5, &ptr))
		return -1;
	unsigned short record_length = LITTLE_ENDIAN_16(ptr + 3);
	*type = *ptr;
	assert(record_length <= RECORD_PROTOCOL_TLS_CIPHER_TEXT_FRAGMENT_MAX_SIZE);
	if (record_get_next_bytes(record_buffer, record_length, &ptr))
		return -1;

	long long decrypted_record_data_length = record_data_decrypt(client_cs, ptr, record_length, data);
	assert(decrypted_record_data_length <= RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE);
	rawhttps_record_buffer_clear(record_buffer);

	++client_cs->sequence_number;

	return decrypted_record_data_length;
}

/* WRITING/SENDING FUNCTIONS */

// sends a single record packet to the client
static int send_cipher_text(const unsigned char* cipher_text, int cipher_text_length, int connected_socket)
{
	struct iovec iov[2];
	iov[0].iov_base = cipher_text;
	iov[0].iov_len = cipher_text_length;

	struct msghdr hdr = {0};
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 1;
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
	if (written != cipher_text_length)
		return -1;
	
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
		case BULK_CIPHER_ALGORITHM_AES: {
			return -1;
		} break;
		case BULK_CIPHER_ALGORITHM_DES: {
			return -1;
		} break;
		case BULK_CIPHER_ALGORITHM_RC4: {
			return -1;
		} break;
	}

	return -1;
}

static int cipher_block_encrypt(rawhttps_connection_state* server_cs, unsigned char cipher_text[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE],
	int cipher_text_length)
{
	// Structure defined in: https://tools.ietf.org/html/rfc5246#section-6.2.3.2
	switch(server_cs->security_parameters.bulk_cipher_algorithm)
	{
		case BULK_CIPHER_ALGORITHM_NULL: {
			return -1;
		} break;
		case BULK_CIPHER_ALGORITHM_AES: {
			// Encrypt data
			unsigned char* iv = cipher_text + RECORD_PROTOCOL_TLS_HEADER_SIZE;
			unsigned char* generic_block_cipher = cipher_text + RECORD_PROTOCOL_TLS_HEADER_SIZE + server_cs->security_parameters.record_iv_length;
			unsigned int generic_block_cipher_size = cipher_text_length - RECORD_PROTOCOL_TLS_HEADER_SIZE - server_cs->security_parameters.record_iv_length;
			assert(generic_block_cipher_size % server_cs->security_parameters.block_length == 0);
			switch (server_cs->security_parameters.enc_key_length)
			{
				case 16: aes_128_cbc_encrypt(generic_block_cipher, server_cs->cipher_state.enc_key, iv,
					generic_block_cipher_size / server_cs->security_parameters.block_length, generic_block_cipher); break;
				default: return -1;
			}
			return 0;
		} break;
		case BULK_CIPHER_ALGORITHM_DES: {
			return -1;
		} break;
		case BULK_CIPHER_ALGORITHM_RC4: {
			return -1;
		} break;
	}

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
			return -1;
		} break;
	}
	return -1;
}

// @TODO !
static void generate_random_iv(unsigned char iv_length, unsigned char* iv)
{
	for (int i = 0; i < iv_length; ++i)
		iv[i] = i;
}

static int mac(const rawhttps_connection_state* server_cs, const unsigned char* mac_message, int mac_message_length, unsigned char* result)
{
	switch(server_cs->security_parameters.mac_algorithm)
	{
		case MAC_ALGORITHM_NULL: {
			return -1;
		} break;
		case MAC_ALGORITHM_HMAC_MD5: {
			return -1;
		} break;
		case MAC_ALGORITHM_HMAC_SHA1: {
			hmac(sha1, server_cs->mac_key, server_cs->security_parameters.mac_length, mac_message, mac_message_length, result,
				server_cs->security_parameters.mac_length);
			return 0;
		} break;
		case MAC_ALGORITHM_HMAC_SHA256: {
			return -1;
		} break;
		case MAC_ALGORITHM_HMAC_SHA384: {
			return -1;
		} break;
		case MAC_ALGORITHM_HMAC_SHA512: {
			return -1;
		} break;
	}
	return -1;
}

static int build_mac_message(const rawhttps_connection_state* server_cs, const unsigned char* fragment, int fragment_length, protocol_type type,
	unsigned char* result)
{
	unsigned long long seq_number_be = BIG_ENDIAN_64(server_cs->sequence_number);
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
	int r = mac(server_cs, mac_message, mac_message_length, result);
	free(mac_message);
	return r;
}

static int build_tls_cipher_text(const rawhttps_connection_state* server_cs, const unsigned char* fragment, int fragment_length,
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
			printf("Cipher type not supported\n");
			return -1;
		} break;
	}

	return -1;
}

int rawhttps_record_send(rawhttps_connection_state* server_cs, const unsigned char* data, int data_length,
	protocol_type type, int connected_socket)
{
	unsigned char cipher_text[RECORD_PROTOCOL_TLS_CIPHER_TEXT_MAX_SIZE];
	int cipher_text_length;
	if ((cipher_text_length = build_tls_cipher_text(server_cs, data, data_length, type, cipher_text)) == -1)
		return -1;

	if (encrypt_tls_cipher_text_fragment(server_cs, cipher_text, cipher_text_length))
		return -1;

	// Send record packet
	if (send_cipher_text(cipher_text, cipher_text_length, connected_socket))
	{
		printf("Error sending cipher text\n");
		return -1;
	}

	++server_cs->sequence_number;

	return 0;
}