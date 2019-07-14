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

// creates rawhttps_parser_buffer
static int rawhttps_message_buffer_create(rawhttps_message_buffer* message_buffer)
{
	message_buffer->buffer = malloc(sizeof(char) * RAWHTTPS_MESSAGE_BUFFER_INITIAL_SIZE);
	if (!message_buffer->buffer) return -1;
	message_buffer->buffer_size = RAWHTTPS_MESSAGE_BUFFER_INITIAL_SIZE;
	message_buffer->buffer_end = 0;
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
void rawhttps_parser_state_destroy(rawhttps_parser_state* ps)
{
	rawhttps_message_buffer_destroy(&ps->message_buffer);
	rawhttps_record_buffer_destroy(&ps->record_buffer);
}

// clear the phb buffer.
// data which was already used via 'get' functions will be released and the pointers will be adjusted
static void rawhttps_message_buffer_clear(rawhttps_message_buffer* message_buffer)
{
	memmove(message_buffer->buffer, message_buffer->buffer + message_buffer->buffer_position_get,
		message_buffer->buffer_end - message_buffer->buffer_position_get);
	message_buffer->buffer_end -= message_buffer->buffer_position_get;
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
	if ((size_read = rawhttps_record_get(&ps->record_buffer, connected_socket,
		ps->message_buffer.buffer + ps->message_buffer.buffer_end, &ps->type, client_connection_state)) < 0)
		return -1;
	if (size_read == 0)
		return -1;
	ps->message_buffer.buffer_end += size_read;

	return size_read;
}

// This function is a little 'hack'
// It fetches the next record data and stores it in the message buffer if and only if the message buffer is empty
// This way, we are sure that the protocol type will be fetched if the message buffer is empty.
// If the message buffer is not empty, we use the type that was already there... This needs to be this way because
// a single record might encapsulate more than one higher-level messages, which all must share the same protocol_type
int rawhttps_parser_protocol_type_get_next(rawhttps_parser_state* ps, int connected_socket,
	const rawhttps_connection_state* client_connection_state, protocol_type* type)
{
	while (ps->message_buffer.buffer_end == 0)
		if (rawhttps_parser_message_fetch_next_record(ps, connected_socket, client_connection_state) == -1)
			return -1;

	*type = ps->type;
	return 0;
}

// gets next 'num' bytes from phb buffer.
static int rawhttps_parser_get_next_bytes(rawhttps_parser_state* ps, long long num, unsigned char** ptr, int connected_socket,
	const rawhttps_connection_state* client_connection_state)
{
	while (ps->message_buffer.buffer_position_get + num > ps->message_buffer.buffer_end)
		if (rawhttps_parser_message_fetch_next_record(ps, connected_socket, client_connection_state) == -1)
			return -1;

	ps->message_buffer.buffer_position_get += num;
	*ptr = ps->message_buffer.buffer + ps->message_buffer.buffer_position_get - num;
	return 0;
}

// gets next 'num' bytes from phb buffer.
static long long rawhttps_parser_get_next_available_bytes(rawhttps_parser_state* ps, unsigned char** ptr, int connected_socket)
{
	long long available_bytes = ps->message_buffer.buffer_end - ps->message_buffer.buffer_position_get;
	if (available_bytes == 0) return -1;
	ps->message_buffer.buffer_position_get += available_bytes;
	*ptr = ps->message_buffer.buffer + ps->message_buffer.buffer_position_get - available_bytes;
	return available_bytes;
}

// parses the next message into a tls_packet (packet parameter)
int rawhttps_parser_application_data_parse(char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE], long long* bytes_written, rawhttps_parser_state* ps,
	int connected_socket, rawhttps_connection_state* client_cs)
{
	// If we have remainings from last parse, we have an error (forgot to clear buffer)
	assert(ps->message_buffer.buffer_position_get == 0);

	unsigned char* ptr;
	*bytes_written = rawhttps_parser_get_next_available_bytes(ps, &ptr, connected_socket);
	if (*bytes_written == -1) return -1;

	assert(*bytes_written < RECORD_PROTOCOL_TLS_PLAIN_TEXT_MAX_SIZE);
	memcpy(data, ptr, *bytes_written);
	
	// @TODO: We must decide how we will release packets.

	// Release Message Data
	rawhttps_message_buffer_clear(&ps->message_buffer);
	return 0;
}

// parses the next message into a tls_packet (packet parameter)
int rawhttps_parser_change_cipher_spec_parse(tls_packet* packet, rawhttps_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_cs)
{
	// If we have remainings from last parse, we have an error (forgot to clear buffer)
	assert(ps->message_buffer.buffer_position_get == 0);

	unsigned char* ptr;
	packet->type = CHANGE_CIPHER_SPEC_PROTOCOL;

	change_cipher_spec_packet ccsp;
	// If we have a change_cipher_spec packet, we can be sure that we only have to get a single byte, which is the 'message'
	if (rawhttps_parser_get_next_bytes(ps, 1, &ptr, connected_socket, client_cs))
		return -1;
	ccsp.message = *ptr;
	packet->subprotocol.ccsp = ccsp;
	
	// @TODO: We must decide how we will release packets.

	// Release Message Data
	rawhttps_message_buffer_clear(&ps->message_buffer);
	return 0;
}

// parses the next message into a tls_packet (packet parameter)
int rawhttps_parser_handshake_packet_parse(tls_packet* packet, rawhttps_parser_state* ps, int connected_socket,
	rawhttps_connection_state* client_cs, dynamic_buffer* handshake_messages)
{
	// If we have remainings from last parse, we have an error (forgot to clear buffer)
	assert(ps->message_buffer.buffer_position_get == 0);

	unsigned char* ptr;
	packet->type = HANDSHAKE_PROTOCOL;

	handshake_packet hp;
	// If we have a handshake packet, we must first get the first 4 bytes to get the message type and the message length.
	if (rawhttps_parser_get_next_bytes(ps, 4, &ptr, connected_socket, client_cs))
		return -1;
	// Before parsing we need to add its content to the handshake_messages buffer
	// This is needed by the full handshake when the FINISHED message is received.
	util_dynamic_buffer_add(handshake_messages, ptr, 4);
	hp.hh.message_type = *ptr; ++ptr;
	hp.hh.message_length = LITTLE_ENDIAN_24(ptr); ptr += 3;
	if (rawhttps_parser_get_next_bytes(ps, hp.hh.message_length, &ptr, connected_socket, client_cs))
		return -1;
	// If the packet has type HANDSHAKE_PROTOCOL, before parsing we need to add its content to the handshake_messages buffer
	// This is needed by the full handshake when the FINISHED message is received.
	util_dynamic_buffer_add(handshake_messages, ptr, hp.hh.message_length);

	switch (hp.hh.message_type)
	{
		case CLIENT_HELLO_MESSAGE: {
			hp.message.chm.ssl_version = LITTLE_ENDIAN_16(ptr); ptr += 2;
			memcpy(hp.message.chm.client_random, ptr, 32); ptr += 32;
			hp.message.chm.session_id_length = *ptr; ptr += 1;
			hp.message.chm.session_id = malloc(hp.message.chm.session_id_length);
			memcpy(hp.message.chm.session_id, ptr, hp.message.chm.session_id_length); ptr += hp.message.chm.session_id_length;
			hp.message.chm.cipher_suites_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
			hp.message.chm.cipher_suites = malloc(hp.message.chm.session_id_length);
			memcpy(hp.message.chm.cipher_suites, ptr, hp.message.chm.cipher_suites_length); ptr += hp.message.chm.session_id_length;
			hp.message.chm.compression_methods_length = *ptr; ptr += 1;
			hp.message.chm.compression_methods = malloc(hp.message.chm.compression_methods_length);
			memcpy(hp.message.chm.compression_methods, ptr, hp.message.chm.compression_methods_length); ptr += hp.message.chm.compression_methods_length;
			hp.message.chm.extensions_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
			hp.message.chm.extensions = malloc(hp.message.chm.extensions_length);
			memcpy(hp.message.chm.extensions, ptr, hp.message.chm.extensions_length); ptr += hp.message.chm.extensions_length;
		} break;
		case CLIENT_KEY_EXCHANGE_MESSAGE: {
			hp.message.ckem.premaster_secret_length = LITTLE_ENDIAN_16(ptr); ptr += 2;
			hp.message.ckem.premaster_secret = malloc(hp.message.ckem.premaster_secret_length);
			memcpy(hp.message.ckem.premaster_secret, ptr, hp.message.ckem.premaster_secret_length); ptr += hp.message.ckem.premaster_secret_length;
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

	packet->subprotocol.hp = hp;
	
	// @TODO: We must decide how we will release packets.

	// Release Message Data
	rawhttps_message_buffer_clear(&ps->message_buffer);
	return 0;
}