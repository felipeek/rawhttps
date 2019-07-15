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

static int record_data_decrypt(const rawhttps_connection_state* client_connection_state, unsigned char* record_data,
	unsigned short record_data_length, unsigned char* result)
{
	switch (client_connection_state->security_parameters.cipher)
	{
		case CIPHER_STREAM: {
			memcpy(result, record_data, record_data_length);
			return record_data_length;
		} break;
		case CIPHER_BLOCK: {
			unsigned char record_iv_length = client_connection_state->security_parameters.record_iv_length;
			unsigned short record_data_without_iv_length = record_data_length - (unsigned char)record_iv_length;
			unsigned char* record_iv = record_data;
			unsigned char* record_data_without_iv = record_data + record_iv_length;
			int block_count = (int)record_data_without_iv_length / client_connection_state->security_parameters.block_length;
			// @TODO: here we should depend on bulk algorithm
			aes_128_cbc_decrypt(record_data_without_iv, client_connection_state->cipher_state.enc_key, record_iv, block_count, result);
			unsigned char padding_length = result[record_data_without_iv_length - 1];
			return record_data_without_iv_length - client_connection_state->security_parameters.mac_length - padding_length - 1;
		} break;
		case CIPHER_AEAD: {
			printf("Cipher type not supported\n");
			return -1;
		} break;
	}

	return -1;
}

// gets the data of the next record packet and stores in the received buffer. The type is also returned via 'type'
long long rawhttps_record_get(rawhttps_record_buffer* record_buffer, int connected_socket,
	unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE], protocol_type* type, const rawhttps_connection_state* client_connection_state)
{
	unsigned char* ptr;

	if (record_guarantee_record(record_buffer, connected_socket))
		return -1;

	if (record_get_next_bytes(record_buffer, 5, &ptr))
		return -1;
	unsigned short record_length = LITTLE_ENDIAN_16(ptr + 3);
	*type = *ptr;
	assert(record_length <= RECORD_PROTOCOL_TLS_CIPHER_TEXT_MAX_SIZE);
	if (record_get_next_bytes(record_buffer, record_length, &ptr))
		return -1;

	long long decrypted_record_data_length = record_data_decrypt(client_connection_state, ptr, record_length, data);
	assert(decrypted_record_data_length <= RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE);
	rawhttps_record_buffer_clear(record_buffer);
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

static int build_tls_cipher_text(const rawhttps_connection_state* server_cs, const unsigned char* fragment, int fragment_length,
	protocol_type type, int connected_socket, unsigned char** _cipher_text)
{
	switch (server_cs->security_parameters.cipher)
	{
		case CIPHER_STREAM: {
			unsigned char record_header[5];
			record_header[0] = type;
			*(unsigned short*)(record_header + 1) = BIG_ENDIAN_16(TLS12);
			*(unsigned short*)(record_header + 3) = BIG_ENDIAN_16(fragment_length);

			int cipher_text_size = sizeof(record_header) + fragment_length;
			unsigned char* cipher_text = malloc(cipher_text_size);
			unsigned char* cipher_text_ptr = cipher_text;
			memcpy(cipher_text_ptr, record_header, sizeof(record_header));
			cipher_text_ptr += sizeof(record_header);
			memcpy(cipher_text_ptr, fragment, fragment_length);

			*_cipher_text = cipher_text;
			return cipher_text_size;
		} break;
		case CIPHER_BLOCK: {
			// The fragment will have:
			// 16 Bytes for IV
			// N bytes for the higher layer message (it may have only part of it)
			// 20 Bytes for the MAC
			// M bytes for padding
			// 1 byte for padding length (M)
			// ---
			// Padding: Padding that is added to force the length of the plaintext to be
			// an integral multiple of the block cipher's block length
			// https://tools.ietf.org/html/rfc5246#section-6.2.3.2
			unsigned int cipher_text_content_length = server_cs->security_parameters.record_iv_length + fragment_length +
				server_cs->security_parameters.mac_length + 1; // +1 for padding_length
			unsigned char padding_length = server_cs->security_parameters.block_length - ((cipher_text_content_length -
				server_cs->security_parameters.record_iv_length) % server_cs->security_parameters.block_length);
			cipher_text_content_length += padding_length;
			assert(cipher_text_content_length <= RECORD_PROTOCOL_TLS_CIPHER_TEXT_MAX_SIZE);

			unsigned char record_header[5];
			record_header[0] = type;
			*(unsigned short*)(record_header + 1) = BIG_ENDIAN_16(TLS12);
			*(unsigned short*)(record_header + 3) = BIG_ENDIAN_16(cipher_text_content_length);

			// Calculate IV
			// For now, we are using the Server Write IV as the CBC IV for all packets
			// This must be random and new for each packet
			// TODO
			const unsigned char* IV = server_cs->cipher_state.iv;

			// Calculate MAC
			// TODO
			// just for testing, this thing should be redesigned.
			unsigned char mac[20] = {0}; // TODO: not 20
			dynamic_buffer mac_message;
			util_dynamic_buffer_new(&mac_message, 1024);
			unsigned long long seq_number_be = BIG_ENDIAN_64(server_cs->sequence_number);
			util_dynamic_buffer_add(&mac_message, &seq_number_be, 8);
			unsigned char mac_tls_type = type;
			unsigned short mac_tls_version = BIG_ENDIAN_16(TLS12);
			unsigned short mac_tls_length = BIG_ENDIAN_16(fragment_length);
			util_dynamic_buffer_add(&mac_message, &mac_tls_type, 1);
			util_dynamic_buffer_add(&mac_message, &mac_tls_version, 2);
			util_dynamic_buffer_add(&mac_message, &mac_tls_length, 2);
			util_dynamic_buffer_add(&mac_message, fragment, fragment_length);
			// @TODO: here we should depend on security_parameters.mac_algorithm
			hmac(sha1, server_cs->cipher_state.mac_key, server_cs->security_parameters.mac_length,
				mac_message.buffer, mac_message.size, mac, server_cs->security_parameters.mac_length);

			int cipher_text_size = sizeof(record_header) + cipher_text_content_length;
			unsigned char* cipher_text = malloc(cipher_text_size);
			unsigned char* cipher_text_ptr = cipher_text;
			memcpy(cipher_text_ptr, record_header, sizeof(record_header));
			cipher_text_ptr += sizeof(record_header);
			memcpy(cipher_text_ptr, IV, server_cs->security_parameters.record_iv_length);
			cipher_text_ptr += server_cs->security_parameters.record_iv_length;
			memcpy(cipher_text_ptr, fragment, fragment_length);
			cipher_text_ptr += fragment_length;
			memcpy(cipher_text_ptr, mac, server_cs->security_parameters.mac_length);
			cipher_text_ptr += server_cs->security_parameters.mac_length;
			memset(cipher_text_ptr, padding_length, padding_length);
			cipher_text_ptr += padding_length;
			cipher_text_ptr[0] = padding_length;

			// Encrypt data
			unsigned char* data_to_encrypt = cipher_text + sizeof(record_header) + server_cs->security_parameters.record_iv_length;
			unsigned int data_to_encrypt_size = cipher_text_content_length - server_cs->security_parameters.record_iv_length;
			assert(data_to_encrypt_size % server_cs->security_parameters.block_length == 0);
			unsigned char* result = calloc(1, data_to_encrypt_size); 	// @todo: I think we dont need this
			// @TODO: here we should depend on security_parameters.bulk_algorithm
			aes_128_cbc_encrypt(data_to_encrypt, server_cs->cipher_state.enc_key, IV,
				data_to_encrypt_size / server_cs->security_parameters.block_length, result);
			memcpy(data_to_encrypt, result, data_to_encrypt_size);
			rawhttps_connection_state* _server_cs = (rawhttps_connection_state*)server_cs;
			++_server_cs->sequence_number; // FIX

			*_cipher_text = cipher_text;
			return cipher_text_size;
		} break;
		case CIPHER_AEAD: {
			printf("Cipher type not supported\n");
			return -1;
		} break;
	}

	return -1;
}

int rawhttps_record_send(const rawhttps_connection_state* server_cs, const unsigned char* data, int data_length,
	protocol_type type, int connected_socket)
{
	unsigned char* cipher_text;
	int cipher_text_length = build_tls_cipher_text(server_cs, data, data_length, type, connected_socket, &cipher_text);

	// Send record packet
	if (send_cipher_text(cipher_text, cipher_text_length, connected_socket))
	{
		printf("Error sending cipher text\n");
		return -1;
	}

	return 0;
}