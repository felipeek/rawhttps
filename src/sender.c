#include "sender.h"
#include <stdlib.h>
#include "util.h"
#include <unistd.h>
#include "logger.h"

#define BIG_ENDIAN_16(x) (((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8))
// note: for BIG_ENDIAN_24, since we receive an u32, we keep the last byte untouched, i.e.
// 01 02 03 04 05 06 00 00 is transformed to 05 06 03 04 01 02 00 00
#define BIG_ENDIAN_24(x) (((x & 0x000000FF) << 16) | ((x & 0x00FF0000) >> 16) | (x & 0x0000FF00))
#define BIG_ENDIAN_32(x) (((x & 0xFF000000) >> 24) | ((x & 0x00FF0000) >> 8) | ((x & 0x0000FF00) << 8) | ((x & 0x000000FF) << 24))

static void fill_record_protocol_information(const record_header* rh, dynamic_buffer* db)
{
	u16 ssl_version_be = BIG_ENDIAN_16(rh->ssl_version);
	u16 record_length_be = BIG_ENDIAN_16(rh->record_length);

	util_dynamic_buffer_add(db, &rh->protocol_type, 1);
	util_dynamic_buffer_add(db, &ssl_version_be, 2);
	util_dynamic_buffer_add(db, &record_length_be, 2);
}

static void fill_handshake_protocol_information(const handshake_header* hh, dynamic_buffer* db)
{
	u32 message_length_be = BIG_ENDIAN_24(hh->message_length);

	util_dynamic_buffer_add(db, &hh->message_type, 1);
	util_dynamic_buffer_add(db, &message_length_be, 3);
}

static void fill_server_hello_message_information(const server_hello_message* shm, dynamic_buffer* db)
{
	u16 ssl_version_be = BIG_ENDIAN_16(shm->ssl_version);
	u16 selected_cipher_suite_be = BIG_ENDIAN_16(shm->selected_cipher_suite);
	u16 extensions_length_be = BIG_ENDIAN_16(shm->extensions_length);

	util_dynamic_buffer_add(db, &ssl_version_be, 2);
	util_dynamic_buffer_add(db, shm->random_number, 32);
	util_dynamic_buffer_add(db, &shm->session_id_length, 1);
	util_dynamic_buffer_add(db, shm->session_id, shm->session_id_length);
	util_dynamic_buffer_add(db, &selected_cipher_suite_be, 2);
	util_dynamic_buffer_add(db, &shm->selected_compression_method, 1);
	util_dynamic_buffer_add(db, &extensions_length_be, 2);
	util_dynamic_buffer_add(db, shm->extensions, shm->extensions_length);
}

static void fill_server_certificate_message_information(const server_certificate_message* scm, dynamic_buffer* db)
{
	u32 certificates_length = 0;
	for (s32 i = 0; i < scm->number_of_certificates; ++i)
		certificates_length += scm->certificate_info[i].size + 3;
	certificates_length = BIG_ENDIAN_24(certificates_length);

	util_dynamic_buffer_add(db, &certificates_length, 3);
	for (s32 i = 0; i < scm->number_of_certificates; ++i)
	{
		u32 size = BIG_ENDIAN_24(scm->certificate_info[i].size);
		util_dynamic_buffer_add(db, &size, 3);
		util_dynamic_buffer_add(db, scm->certificate_info[i].data, scm->certificate_info[i].size);
	}
}

static void fill_server_hello_done_message_information(dynamic_buffer* db)
{

}

static void send_packet(const tls_packet* tp, s32 connected_socket)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	fill_record_protocol_information(&tp->rh, &db);

	switch (tp->rh.protocol_type)
	{
		case HANDSHAKE_PROTOCOL: {
			fill_handshake_protocol_information(&tp->subprotocol.hp.hh, &db);
			switch (tp->subprotocol.hp.hh.message_type)
			{
				case CLIENT_HELLO_MESSAGE: {
					logger_log_error("send_packet: trying to send client message");
				} break;
				case SERVER_HELLO_MESSAGE: {
					fill_server_hello_message_information(&tp->subprotocol.hp.message.shm, &db);
				} break;
				case SERVER_CERTIFICATE_MESSAGE: {
					fill_server_certificate_message_information(&tp->subprotocol.hp.message.scm, &db);
				} break;
				case SERVER_HELLO_DONE_MESSAGE: {
					fill_server_hello_done_message_information(&db);
				} break;
			}
		} break;
	}

	write(connected_socket, db.buffer, db.size);
	util_dynamic_buffer_free(&db);
}

static void gen_random_number(u8* random_number)
{
	// todo: this should be a random number and the four first bytes must be unix time
	for (s32 i = 0; i < 32; ++i)
		random_number[i] = i;
}

s32 rawhttp_sender_send_server_hello(s32 connected_socket, u16 selected_cipher_suite)
{
	u8 random_number[32];
	gen_random_number(random_number);

	u8 session_id_length = 0;
	u16 extensions_length = 0;

	tls_packet tp;
	tp.subprotocol.hp.hh.message_type = SERVER_HELLO_MESSAGE;
	tp.subprotocol.hp.hh.message_length = 2 + 32 + 1 + session_id_length + 2 + 1 + 2 + extensions_length;
	tp.subprotocol.hp.message.shm.ssl_version = 0x0301; // hardcoding TLS 1.0 for now
	tp.subprotocol.hp.message.shm.random_number = (u8*)random_number;
	tp.subprotocol.hp.message.shm.session_id_length = 0; //@todo
	tp.subprotocol.hp.message.shm.session_id = NULL; //@todo
	tp.subprotocol.hp.message.shm.selected_cipher_suite = selected_cipher_suite;
	tp.subprotocol.hp.message.shm.selected_compression_method = 0; //@todo
	tp.subprotocol.hp.message.shm.extensions_length = 0; //@todo
	tp.subprotocol.hp.message.shm.extensions = NULL; //@todo

	tp.rh.protocol_type = HANDSHAKE_PROTOCOL;
	// @TODO: record_length is not message_length + 4... actually ideally it is... but we can't exceed record's maximum size
	// so here we need to split the packet if necessary and calculate the record_length for each packet
	tp.rh.record_length = (u16)tp.subprotocol.hp.hh.message_length + 4;
	tp.rh.ssl_version = 0x0301; // hardcoding TLS 1.0 for now.

	send_packet(&tp, connected_socket);

	return 0;
}

// for now, this function excepts a single certificate
s32 rawhttp_sender_send_server_certificate(s32 connected_socket, u8* certificate, s32 certificate_size)
{
	certificate_info cert_info;
	cert_info.data = certificate;
	cert_info.size = certificate_size;

	tls_packet tp;
	tp.subprotocol.hp.message.scm.number_of_certificates = 1;
	tp.subprotocol.hp.message.scm.certificate_info = &cert_info;
	tp.subprotocol.hp.hh.message_type = SERVER_CERTIFICATE_MESSAGE;
	tp.subprotocol.hp.hh.message_length = 3;
	for (s32 i = 0; i < tp.subprotocol.hp.message.scm.number_of_certificates; ++i)
		tp.subprotocol.hp.hh.message_length += tp.subprotocol.hp.message.scm.certificate_info[i].size + 3;

	tp.rh.protocol_type = HANDSHAKE_PROTOCOL;
	// @TODO: record_length is not message_length + 4... actually ideally it is... but we can't exceed record's maximum size
	// so here we need to split the packet if necessary and calculate the record_length for each packet
	tp.rh.record_length = (u16)tp.subprotocol.hp.hh.message_length + 4;
	tp.rh.ssl_version = 0x0301; // hardcoding TLS 1.0 for now.

	send_packet(&tp, connected_socket);
	
	return 0;
}

s32 rawhttp_sender_send_server_hello_done(s32 connected_socket)
{
	tls_packet tp;
	tp.subprotocol.hp.hh.message_type = SERVER_HELLO_DONE_MESSAGE;
	tp.subprotocol.hp.hh.message_length = 0;
	tp.rh.protocol_type = HANDSHAKE_PROTOCOL;
	// @TODO: record_length is not message_length + 4... actually ideally it is... but we can't exceed record's maximum size
	// so here we need to split the packet if necessary and calculate the record_length for each packet
	tp.rh.record_length = (u16)tp.subprotocol.hp.hh.message_length + 4;
	tp.rh.ssl_version = 0x0301; // hardcoding TLS 1.0 for now.

	send_packet(&tp, connected_socket);
	
	return 0;
}