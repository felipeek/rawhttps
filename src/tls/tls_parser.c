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

#include "tls_parser.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "record.h"

#define RAWHTTPS_PARSER_CHUNK_SIZE 1024
#define RAWHTTPS_PARSER_REQUEST_HEADER_DEFAULT_CAPACITY 16
#define RAWHTTPS_MESSAGE_BUFFER_INITIAL_SIZE 1024

// creates rawhttps_parser_buffer
static int higher_layer_buffer_create(rawhttps_higher_layer_buffer* higher_layer_buffer)
{
	higher_layer_buffer->buffer = malloc(sizeof(char) * RAWHTTPS_MESSAGE_BUFFER_INITIAL_SIZE);
	if (!higher_layer_buffer->buffer) return -1;
	higher_layer_buffer->buffer_size = RAWHTTPS_MESSAGE_BUFFER_INITIAL_SIZE;
	higher_layer_buffer->buffer_end = 0;
	higher_layer_buffer->buffer_position_get = 0;
	return 0;
}

// destroys rawhttps_parser_buffer
static void higher_layer_buffer_destroy(rawhttps_higher_layer_buffer* higher_layer_buffer)
{
	free(higher_layer_buffer->buffer);
}

// creates rawhttps_tls_parser_state
int rawhttps_tls_parser_state_create(rawhttps_tls_parser_state* ps)
{
	if (higher_layer_buffer_create(&ps->higher_layer_buffer))
		return -1;
	if (rawhttps_record_buffer_create(&ps->record_buffer))
		return -1;
	ps->type = 0;
	return 0;
}

// destroys rawhttps_tls_parser_state
void rawhttps_tls_parser_state_destroy(rawhttps_tls_parser_state* ps)
{
	higher_layer_buffer_destroy(&ps->higher_layer_buffer);
	rawhttps_record_buffer_destroy(&ps->record_buffer);
}

// clear the phb buffer.
// data which was already used via 'get' functions will be released and the pointers will be adjusted
static void higher_layer_buffer_clear(rawhttps_higher_layer_buffer* higher_layer_buffer)
{
	memmove(higher_layer_buffer->buffer, higher_layer_buffer->buffer + higher_layer_buffer->buffer_position_get,
		higher_layer_buffer->buffer_end - higher_layer_buffer->buffer_position_get);
	higher_layer_buffer->buffer_end -= higher_layer_buffer->buffer_position_get;
	higher_layer_buffer->buffer_position_get = 0;
}

// fetches the next record data and stores in the message buffer
static long long tls_parser_fetch_next_record(rawhttps_tls_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_cs)
{
	long long size_needed = ps->higher_layer_buffer.buffer_end + RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE;
	if (size_needed > ps->higher_layer_buffer.buffer_size)
	{
		ps->higher_layer_buffer.buffer = realloc(ps->higher_layer_buffer.buffer, size_needed);
		ps->higher_layer_buffer.buffer_size = size_needed;
	}

	long long size_read;
	if ((size_read = rawhttps_record_get(&ps->record_buffer, connected_socket,
		ps->higher_layer_buffer.buffer + ps->higher_layer_buffer.buffer_end, &ps->type, client_cs)) < 0)
		return -1;
	if (size_read == 0)
		return -1;
	ps->higher_layer_buffer.buffer_end += size_read;

	return size_read;
}

// This function is a little 'hack'
// It fetches the next record data and stores it in the message buffer if and only if the message buffer is empty
// This way, we are sure that the protocol type will be fetched if the message buffer is empty.
// If the message buffer is not empty, we use the type that was already there... This needs to be this way because
// a single record might encapsulate more than one higher-level messages, which all must share the same protocol_type
int rawhttps_tls_parser_protocol_type_get_next(rawhttps_tls_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_cs, protocol_type* type)
{
	while (ps->higher_layer_buffer.buffer_end == 0)
		if (tls_parser_fetch_next_record(ps, connected_socket, client_cs) == -1)
			return -1;

	*type = ps->type;
	return 0;
}

// gets next 'num' bytes from phb buffer.
static int tls_parser_get_next_bytes(rawhttps_tls_parser_state* ps, long long num, unsigned char** ptr, int connected_socket,
	rawhttps_connection_state* client_cs)
{
	while (ps->higher_layer_buffer.buffer_position_get + num > ps->higher_layer_buffer.buffer_end)
		if (tls_parser_fetch_next_record(ps, connected_socket, client_cs) == -1)
			return -1;

	ps->higher_layer_buffer.buffer_position_get += num;
	*ptr = ps->higher_layer_buffer.buffer + ps->higher_layer_buffer.buffer_position_get - num;
	return 0;
}

// gets next 'num' bytes from phb buffer.
static long long tls_parser_get_next_available_bytes(rawhttps_tls_parser_state* ps, unsigned char** ptr, int connected_socket)
{
	long long available_bytes = ps->higher_layer_buffer.buffer_end - ps->higher_layer_buffer.buffer_position_get;
	if (available_bytes == 0) return -1;
	ps->higher_layer_buffer.buffer_position_get += available_bytes;
	*ptr = ps->higher_layer_buffer.buffer + ps->higher_layer_buffer.buffer_position_get - available_bytes;
	return available_bytes;
}

// parses the next message into a tls_packet (packet parameter)
int rawhttps_tls_parser_application_data_parse(unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE], long long* bytes_written,
	rawhttps_tls_parser_state* ps, int connected_socket, rawhttps_connection_state* client_cs)
{
	// If we have remainings from last parse, we have an error (forgot to clear buffer)
	assert(ps->higher_layer_buffer.buffer_position_get == 0);

	unsigned char* ptr;
	*bytes_written = tls_parser_get_next_available_bytes(ps, &ptr, connected_socket);
	if (*bytes_written == -1) return -1;

	assert(*bytes_written < RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE);
	memcpy(data, ptr, *bytes_written);
	
	// @TODO: We must decide how we will release packets.

	// Release Message Data
	higher_layer_buffer_clear(&ps->higher_layer_buffer);
	return 0;
}

// parses the next message into a tls_packet (packet parameter)
int rawhttps_tls_parser_change_cipher_spec_parse(change_cipher_spec_packet* packet, rawhttps_tls_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_cs)
{
	// If we have remainings from last parse, we have an error (forgot to clear buffer)
	assert(ps->higher_layer_buffer.buffer_position_get == 0);

	unsigned char* ptr;
	// If we have a change_cipher_spec packet, we can be sure that we only have to get a single byte, which is the 'message'
	if (tls_parser_get_next_bytes(ps, 1, &ptr, connected_socket, client_cs))
		return -1;
	packet->message = *ptr;
	
	// @TODO: We must decide how we will release packets.

	// Release Message Data
	higher_layer_buffer_clear(&ps->higher_layer_buffer);
	return 0;
}

// parses the next message into a tls_packet (packet parameter)
int rawhttps_tls_parser_handshake_packet_parse(handshake_packet* packet, rawhttps_tls_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_cs, dynamic_buffer* handshake_messages)
{
	// If we have remainings from last parse, we have an error (forgot to clear buffer)
	assert(ps->higher_layer_buffer.buffer_position_get == 0);

	unsigned char* ptr;

	// If we have a handshake packet, we must first get the first 4 bytes to get the message type and the message length.
	if (tls_parser_get_next_bytes(ps, 4, &ptr, connected_socket, client_cs))
		return -1;
	// Before parsing we need to add its content to the handshake_messages buffer
	// This is needed by the full handshake when the FINISHED message is received.
	util_dynamic_buffer_add(handshake_messages, ptr, 4);
	packet->hh.message_type = *ptr; ++ptr;
	packet->hh.message_length = LITTLE_ENDIAN_24(ptr); ptr += 3;
	if (tls_parser_get_next_bytes(ps, packet->hh.message_length, &ptr, connected_socket, client_cs))
		return -1;
	// If the packet has type HANDSHAKE_PROTOCOL, before parsing we need to add its content to the handshake_messages buffer
	// This is needed by the full handshake when the FINISHED message is received.
	util_dynamic_buffer_add(handshake_messages, ptr, packet->hh.message_length);

	switch (packet->hh.message_type)
	{
		case CLIENT_HELLO_MESSAGE: {
			packet->message.chm.ssl_version = LITTLE_ENDIAN_16(ptr); ptr += 2;
			memcpy(packet->message.chm.client_random, ptr, 32); ptr += 32;
			packet->message.chm.session_id_length = *ptr; ptr += 1;
			packet->message.chm.session_id = malloc(packet->message.chm.session_id_length);
			memcpy(packet->message.chm.session_id, ptr, packet->message.chm.session_id_length); ptr += packet->message.chm.session_id_length;
			packet->message.chm.cipher_suites_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
			packet->message.chm.cipher_suites = malloc(packet->message.chm.cipher_suites_length);
			packet->message.chm.cipher_suites_length /= 2;
			for (int i = 0; i < (int)packet->message.chm.cipher_suites_length; ++i) {
				packet->message.chm.cipher_suites[i] = LITTLE_ENDIAN_16(ptr); ptr += 2;
			}
			packet->message.chm.compression_methods_length = *ptr; ptr += 1;
			packet->message.chm.compression_methods = malloc(packet->message.chm.compression_methods_length);
			memcpy(packet->message.chm.compression_methods, ptr, packet->message.chm.compression_methods_length); ptr += packet->message.chm.compression_methods_length;
			packet->message.chm.extensions_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
			packet->message.chm.extensions = malloc(packet->message.chm.extensions_length);
			memcpy(packet->message.chm.extensions, ptr, packet->message.chm.extensions_length); ptr += packet->message.chm.extensions_length;
		} break;
		case CLIENT_KEY_EXCHANGE_MESSAGE: {
			packet->message.ckem.premaster_secret_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
			packet->message.ckem.premaster_secret = malloc(packet->message.ckem.premaster_secret_length);
			memcpy(packet->message.ckem.premaster_secret, ptr, packet->message.ckem.premaster_secret_length); ptr += packet->message.ckem.premaster_secret_length;
		} break;
		// Since we are the server, it doesn't make sense for us to parse these messages
		case SERVER_CERTIFICATE_MESSAGE:
		case SERVER_HELLO_DONE_MESSAGE:
		case SERVER_HELLO_MESSAGE: {
			return -1;
		} break;
		case FINISHED_MESSAGE: {
			// TODO
			//12 bytes of verify data
		} break;
	}

	// Release Message Data
	higher_layer_buffer_clear(&ps->higher_layer_buffer);
	return 0;
}

void rawhttps_tls_parser_change_cipher_spec_release(change_cipher_spec_packet* packet)
{
}

void rawhttps_tls_parser_handshake_packet_release(handshake_packet* packet)
{
	switch (packet->hh.message_type)
	{
		case CLIENT_HELLO_MESSAGE: {
			if (packet->message.chm.cipher_suites_length > 0)
				free(packet->message.chm.cipher_suites);
			if (packet->message.chm.compression_methods_length > 0)
				free(packet->message.chm.compression_methods);
			if (packet->message.chm.extensions_length > 0)
				free(packet->message.chm.extensions);
			if (packet->message.chm.session_id_length > 0)
				free(packet->message.chm.session_id);
		} break;
		case CLIENT_KEY_EXCHANGE_MESSAGE: {
			if (packet->message.ckem.premaster_secret_length > 0)
				free(packet->message.ckem.premaster_secret);
		} break;
		// Since we are the server, it doesn't make sense for us to parse these messages
		case SERVER_CERTIFICATE_MESSAGE:
		case SERVER_HELLO_DONE_MESSAGE:
		case SERVER_HELLO_MESSAGE: {
			return;
		} break;
		case FINISHED_MESSAGE: {
		} break;
	}
}