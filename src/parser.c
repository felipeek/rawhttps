/***
 *      _____                         
 *     |  __ \                        
 *     | |__) |_ _ _ __ ___  ___ _ __ 
 *     |  ___/ _` | '__/ __|/ _ \ '__|
 *     | |  | (_| | |  \__ \  __/ |   
 *     |_|   \__,_|_|  |___/\___|_|   
 *                                    
 *                                    
 */

#include "parser.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "record.h"

#define RAWHTTP_PARSER_CHUNK_SIZE 1024
#define RAWHTTP_PARSER_REQUEST_HEADER_DEFAULT_CAPACITY 16
#define RAWHTTPS_MESSAGE_BUFFER_INITIAL_SIZE 1024

#define LITTLE_ENDIAN_16(x) (((unsigned short)(x)[1]) | ((unsigned short)(x)[0] << 8))
#define LITTLE_ENDIAN_24(x) (((unsigned int)(x)[2]) | ((unsigned int)(x)[1] << 8) | ((unsigned int)(x)[0] << 16))

// creates rawhttps_parser_buffer
static int rawhttps_message_buffer_create(rawhttps_message_buffer* message_buffer)
{
	message_buffer->buffer = malloc(sizeof(char) * RAWHTTPS_MESSAGE_BUFFER_INITIAL_SIZE);
	if (!message_buffer->buffer) return -1;
	message_buffer->buffer_size = RAWHTTPS_MESSAGE_BUFFER_INITIAL_SIZE;
	message_buffer->buffer_end = 0;
	message_buffer->buffer_position_fetch = 0;
	message_buffer->buffer_position_get = 0;
	return 0;
}

// destroys rawhttps_parser_buffer
static void rawhttps_message_buffer_destroy(rawhttps_message_buffer* message_buffer)
{
	free(message_buffer->buffer);
}

// creates rawhttps_parser_state
int rawhttps_parser_state_create(rawhttps_parser_state* ps)
{
	if (rawhttps_message_buffer_create(&ps->message_buffer))
		return -1;
	if (rawhttps_record_buffer_create(&ps->record_buffer))
		return -1;
	ps->type = 0;
	return 0;
}

// destroys rawhttps_parser_state
int rawhttps_parser_state_destroy(rawhttps_parser_state* ps)
{
	rawhttps_message_buffer_destroy(&ps->message_buffer);
	rawhttps_record_buffer_destroy(&ps->record_buffer);
	return 0;
}

// clear the phb buffer.
// data which was already used via 'get' functions will be released and the pointers will be adjusted
static void rawhttps_message_buffer_clear(rawhttps_message_buffer* message_buffer)
{
	memmove(message_buffer->buffer, message_buffer->buffer + message_buffer->buffer_position_get,
		message_buffer->buffer_end - message_buffer->buffer_position_get);
	message_buffer->buffer_end -= message_buffer->buffer_position_get;
	message_buffer->buffer_position_fetch -= message_buffer->buffer_position_get;
	message_buffer->buffer_position_get = 0;
}

// fetches the next record data and stores in the message buffer
static long long rawhttps_parser_message_fetch_next_record(rawhttps_parser_state* ps, int connected_socket,
	const rawhttps_connection_state* client_connection_state)
{
	long long size_needed = ps->message_buffer.buffer_end + RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE;
	if (size_needed > ps->message_buffer.buffer_size)
	{
		ps->message_buffer.buffer = realloc(ps->message_buffer.buffer, size_needed);
		ps->message_buffer.buffer_size = size_needed;
	}

	long long size_read;
	if ((size_read = rawhttps_record_get_data(&ps->record_buffer, connected_socket,
		ps->message_buffer.buffer + ps->message_buffer.buffer_end, &ps->type, client_connection_state)) < 0)
		return -1;
	if (size_read == 0)
		return -1;
	ps->message_buffer.buffer_end += size_read;

	return size_read;
}

// fetches the next record data and stores it in the message buffer if and only if the message buffer is empty
// this is useful to force the protocol type to be fetched when the message buffer is empty...
static int rawhttps_parser_message_fetch_next_record_if_buffer_empty(rawhttps_parser_state* ps, int connected_socket,
	const rawhttps_connection_state* client_connection_state)
{
	while (ps->message_buffer.buffer_end == 0)
		if (rawhttps_parser_message_fetch_next_record(ps, connected_socket, client_connection_state) == -1)
			return -1;

	return 0;
}

// guarantees that the next 'num' bytes are available in the message_buffer.
static int rawhttps_parser_message_guarantee_next_bytes(rawhttps_parser_state* ps, int connected_socket,
	unsigned char** ptr, long long num, const rawhttps_connection_state* client_connection_state)
{
	while (ps->message_buffer.buffer_position_fetch + num > ps->message_buffer.buffer_end)
		if (rawhttps_parser_message_fetch_next_record(ps, connected_socket, client_connection_state) == -1)
			return -1;

	ps->message_buffer.buffer_position_fetch += num;
	*ptr = ps->message_buffer.buffer + ps->message_buffer.buffer_position_fetch - num;
	return 0;
}

// fetches the next message into the message_buffer
// this function makes sure that the next message is fully fetched and stored into the message_buffer
static int rawhttps_parser_message_guarantee_next_message(rawhttps_parser_state* ps,
	int connected_socket, const rawhttps_connection_state* client_connection_state)
{
	unsigned char* ptr;
	unsigned short message_length;

	// Little hack: We need to force fetching a new record data, so we are able to get the protocol type!
	if (rawhttps_parser_message_fetch_next_record_if_buffer_empty(ps, connected_socket, client_connection_state))
		return -1;
	
	// Based on the protocol type, we can proceed by fetching the message length
	switch (ps->type)
	{
		case HANDSHAKE_PROTOCOL: {
			// For the handshake protocol, we must fetch 4 bytes to get the message length in the last 3 bytes. (the first byte is the message type)
			if (rawhttps_parser_message_guarantee_next_bytes(ps, connected_socket, &ptr, 4, client_connection_state))
				return -1;
			message_length = LITTLE_ENDIAN_24(ptr + 1);
		} break;
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			// For the change cipher spec protocol, the message length is always 1.
			message_length = 1;
		} break;
		case APPLICATION_DATA_PROTOCOL: {
			if (rawhttps_parser_message_guarantee_next_bytes(ps, connected_socket, &ptr, 30, client_connection_state))
				return -1;
			message_length = 0;
		} break;
		default: {
			message_length = 0;
		} break;
	}
	
	// Now, we just make sure that we fetched 'message_length' bytes and we are sure that the whole message is in the buffer :)
	if (rawhttps_parser_message_guarantee_next_bytes(ps, connected_socket, &ptr, message_length, client_connection_state))
		return -1;

	return 0;
}

// gets next 'num' bytes from phb buffer.
// this function basically increments the internal buffer_position_get pointer and returns a pointer to the data via 'ptr'
// if the data was not fetched previously by the 'fetch' functions, an error is returned.
static int rawhttps_parser_get_next_bytes(rawhttps_message_buffer* message_buffer, long long num, unsigned char** ptr)
{
	if (message_buffer->buffer_position_get + num > message_buffer->buffer_position_fetch)
		return -1;

	message_buffer->buffer_position_get += num;
	*ptr = message_buffer->buffer + message_buffer->buffer_position_get - num;
	return 0;
}

// parses the next message into a tls_packet (packet parameter)
// this function assumes that the whole message was already fetched and is available in ps->message_buffer!
// also, packet->type must already be set by the caller.
static int rawhttps_parser_message_parse(tls_packet* packet, rawhttps_parser_state* ps)
{
	unsigned char* ptr;

	switch (packet->type)
	{
		// HANDSHAKE PROTOCOL TYPE
		case HANDSHAKE_PROTOCOL: {
			handshake_packet hp;
			// If we have a handshake packet, we must first get the first 4 bytes to get the message type and the message length.
			if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 4, &ptr))
				return -1;
			hp.hh.message_type = *ptr; ++ptr;
			hp.hh.message_length = LITTLE_ENDIAN_24(ptr); ptr += 3;

			switch (hp.hh.message_type)
			{
				case CLIENT_HELLO_MESSAGE: {
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 2, &ptr)) return -1;
					hp.message.chm.ssl_version = LITTLE_ENDIAN_16(ptr);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 32, &ptr)) return -1;
					memcpy(hp.message.chm.client_random, ptr, 32);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 1, &ptr)) return -1;
					hp.message.chm.session_id_length = *ptr;
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.chm.session_id_length, &ptr)) return -1;
					hp.message.chm.session_id = malloc(sizeof(unsigned char) * hp.message.chm.session_id_length);
					memcpy(hp.message.chm.session_id, ptr, hp.message.chm.session_id_length);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 2, &ptr)) return -1;
					hp.message.chm.cipher_suites_length = LITTLE_ENDIAN_16(ptr);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.chm.cipher_suites_length, &ptr)) return -1;
					hp.message.chm.cipher_suites = malloc(sizeof(unsigned char) * hp.message.chm.session_id_length);
					memcpy(hp.message.chm.cipher_suites, ptr, hp.message.chm.cipher_suites_length);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 1, &ptr)) return -1;
					hp.message.chm.compression_methods_length = *ptr;
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.chm.compression_methods_length, &ptr)) return -1;
					hp.message.chm.compression_methods = malloc(sizeof(unsigned char) * hp.message.chm.compression_methods_length);
					memcpy(hp.message.chm.compression_methods, ptr, hp.message.chm.compression_methods_length);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 2, &ptr)) return -1;
					hp.message.chm.extensions_length = LITTLE_ENDIAN_16(ptr);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.chm.extensions_length, &ptr)) return -1;
					hp.message.chm.extensions = malloc(sizeof(unsigned char) * hp.message.chm.extensions_length);
					memcpy(hp.message.chm.extensions, ptr, hp.message.chm.extensions_length);
				} break;
				case CLIENT_KEY_EXCHANGE_MESSAGE: {
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 2, &ptr)) return -1;
					hp.message.ckem.premaster_secret_length = LITTLE_ENDIAN_16(ptr);
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, hp.message.ckem.premaster_secret_length, &ptr)) return -1;
					hp.message.ckem.premaster_secret = malloc(sizeof(unsigned char) * hp.message.ckem.premaster_secret_length);
					memcpy(hp.message.ckem.premaster_secret, ptr, hp.message.ckem.premaster_secret_length);
				} break;
				// Since we are the server, it doesn't make sense for us to parse these messages
				case SERVER_CERTIFICATE_MESSAGE:
				case SERVER_HELLO_DONE_MESSAGE:
				case SERVER_HELLO_MESSAGE: {
					return -1;
				} break;
				case FINISHED_MESSAGE: {
					// TODO
					if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 12, &ptr)) return -1;
				} break;
			}

			packet->subprotocol.hp = hp;
		} break;
		// CHANGE CIPHER SPEC PROTOCOL TYPE
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			change_cipher_spec_packet ccsp;
			// If we have a change_cipher_spec packet, we can be sure that we only have to get a single byte, which is the 'message'
			// This byte must already be in the buffer! If it isn't, we throw an error
			if (rawhttps_parser_get_next_bytes(&ps->message_buffer, 1, &ptr)) return -1;
			ccsp.message = *ptr;
			packet->subprotocol.ccsp = ccsp;
		} break;
		case APPLICATION_DATA_PROTOCOL: {

		} break;
	}
	
	// @TODO: We must decide how we will release packets.

	return 0;
}

// Parses the next SSL packet. The packet is returned via parameter 'packet'
int rawhttps_parser_parse_ssl_packet(const rawhttps_connection_state* client_connection_state, tls_packet* packet,
	rawhttps_parser_state* ps, int connected_socket, dynamic_buffer* handshake_messages)
{
	// Get Message Data
	if (rawhttps_parser_message_guarantee_next_message(ps, connected_socket, client_connection_state))
		return -1;

	// Parse to TLS Packet
	packet->type = ps->type;

	// If the packet has type HANDSHAKE_PROTOCOL, before parsing we need to add its content to the handshake_messages buffer
	// This is needed by the full handshake when the FINISHED message is received.
	if (packet->type == HANDSHAKE_PROTOCOL)
		util_dynamic_buffer_add(handshake_messages, ps->message_buffer.buffer, ps->message_buffer.buffer_position_fetch);

	if (rawhttps_parser_message_parse(packet, ps))
		return -1;

	// Release Message Data
	rawhttps_message_buffer_clear(&ps->message_buffer);
	return 0;
}