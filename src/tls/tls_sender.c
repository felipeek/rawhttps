#include "tls_sender.h"
#include "record.h"
#include <stdlib.h>
#include "../logger.h"

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

// receives a higher layer packet, splits the packet into several record packets and send to the client
static int higher_layer_packet_send(rawhttps_connection_state* server_cs, const unsigned char* data, long long size,
	protocol_type type, int connected_socket)
{
	long long size_remaining = size;
	while (size_remaining > 0)
	{
		long long size_to_send = MIN(RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE, size_remaining);
		long long buffer_position = size - size_remaining;

		if (rawhttps_record_send(server_cs, data + buffer_position, size_to_send, type, connected_socket))
		{
			rawhttps_logger_log_error("Error sending record data");
			return -1;
		}
		size_remaining -= size_to_send;
	}

	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_HELLO
int rawhttps_tls_sender_handshake_server_hello_message_send(rawhttps_connection_state* server_cs, int connected_socket,
	unsigned short selected_cipher_suite, unsigned char* random_number, dynamic_buffer* handshake_messages)
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

	if (higher_layer_packet_send(server_cs, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_CERTIFICATE
// for now, this function receives a single certificate!
// @todo: support a chain of certificates
int rawhttps_tls_sender_handshake_server_certificate_message_send(rawhttps_connection_state* server_cs, int connected_socket,
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

	if (higher_layer_packet_send(server_cs, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new HANDSHAKE packet, with message type SERVER_HELLO_DONE
int rawhttps_tls_sender_handshake_server_hello_done_message_send(rawhttps_connection_state* server_cs, int connected_socket,
	dynamic_buffer* handshake_messages)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	unsigned char message_type = SERVER_HELLO_DONE_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(0);

	util_dynamic_buffer_add(&db, &message_type, 1);						// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes) [PLACEHOLDER]

	// We could even use the same dynamic buffer here...
	util_dynamic_buffer_add(handshake_messages, db.buffer, db.size);

	if (higher_layer_packet_send(server_cs, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new CHANGE_CIPHER_SPEC message
int rawhttps_tls_sender_handshake_finished_message_send(rawhttps_connection_state* server_cs, int connected_socket,
	unsigned char verify_data[12])
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 16);

	unsigned char message_type = FINISHED_MESSAGE;
	unsigned int message_length_be = BIG_ENDIAN_24(12);

	util_dynamic_buffer_add(&db, &message_type, 1);							// Message Type (1 Byte)
	util_dynamic_buffer_add(&db, &message_length_be, 3);					// Message Length (3 Bytes)
	util_dynamic_buffer_add(&db, verify_data, 12);							// Verify Data (12 Bytes)

	if (higher_layer_packet_send(server_cs, db.buffer, db.size, HANDSHAKE_PROTOCOL, connected_socket))
		return -1;

	util_dynamic_buffer_free(&db);
	return 0;
}

// send to the client a new CHANGE_CIPHER_SPEC message
int rawhttps_tls_sender_change_cipher_spec_send(rawhttps_connection_state* server_cs, int connected_socket)
{
	unsigned char ccs_type = CHANGE_CIPHER_SPEC_MESSAGE;

	if (higher_layer_packet_send(server_cs, (const unsigned char*)&ccs_type, sizeof(ccs_type), CHANGE_CIPHER_SPEC_PROTOCOL, connected_socket))
		return -1;

	return 0;
}

// send to the client a new APPLICATION_DATA message
int rawhttps_tls_sender_application_data_send(rawhttps_connection_state* server_cs, int connected_socket,
	unsigned char* content, long long content_length)
{
	if (higher_layer_packet_send(server_cs, content, content_length, APPLICATION_DATA_PROTOCOL, connected_socket))
		return -1;

	return 0;
}
