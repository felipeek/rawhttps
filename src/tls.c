#include "tls.h"
#include "parser.h"
#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "hobig.h"
#include "asn1.h"
#include "pkcs1.h"

// SENDER !

#define BIG_ENDIAN_16(x) (((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8))
// note: for BIG_ENDIAN_24, since we receive an unsigned int, we keep the last byte untouched, i.e.
// 01 02 03 04 05 06 00 00 is transformed to 05 06 03 04 01 02 00 00
#define BIG_ENDIAN_24(x) (((x & 0x000000FF) << 16) | ((x & 0x00FF0000) >> 16) | (x & 0x0000FF00))
#define BIG_ENDIAN_32(x) (((x & 0xFF000000) >> 24) | ((x & 0x00FF0000) >> 8) | ((x & 0x0000FF00) << 8) | ((x & 0x000000FF) << 24))

static void fill_record_protocol_information(const record_header* rh, dynamic_buffer* db)
{
	unsigned short ssl_version_be = BIG_ENDIAN_16(rh->ssl_version);
	unsigned short record_length_be = BIG_ENDIAN_16(rh->record_length);

	util_dynamic_buffer_add(db, &rh->protocol_type, 1);
	util_dynamic_buffer_add(db, &ssl_version_be, 2);
	util_dynamic_buffer_add(db, &record_length_be, 2);
}

static void fill_handshake_protocol_information(const handshake_header* hh, dynamic_buffer* db)
{
	unsigned int message_length_be = BIG_ENDIAN_24(hh->message_length);

	util_dynamic_buffer_add(db, &hh->message_type, 1);
	util_dynamic_buffer_add(db, &message_length_be, 3);
}

static void fill_server_hello_message_information(const server_hello_message* shm, dynamic_buffer* db)
{
	unsigned short ssl_version_be = BIG_ENDIAN_16(shm->ssl_version);
	unsigned short selected_cipher_suite_be = BIG_ENDIAN_16(shm->selected_cipher_suite);
	unsigned short extensions_length_be = BIG_ENDIAN_16(shm->extensions_length);

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
	unsigned int certificates_length = 0;
	for (int i = 0; i < scm->number_of_certificates; ++i)
		certificates_length += scm->certificate_info[i].size + 3;
	certificates_length = BIG_ENDIAN_24(certificates_length);

	util_dynamic_buffer_add(db, &certificates_length, 3);
	for (int i = 0; i < scm->number_of_certificates; ++i)
	{
		unsigned int size = BIG_ENDIAN_24(scm->certificate_info[i].size);
		util_dynamic_buffer_add(db, &size, 3);
		util_dynamic_buffer_add(db, scm->certificate_info[i].data, scm->certificate_info[i].size);
	}
}

static void fill_server_hello_done_message_information(dynamic_buffer* db)
{

}

static void send_packet(const record_header* rh, const tls_packet* tp, int connected_socket)
{
	dynamic_buffer db;
	util_dynamic_buffer_new(&db, 1024);

	// this must be redone! we must split the tls packet into several record packets...
	fill_record_protocol_information(rh, &db);

	switch (rh->protocol_type)
	{
		case HANDSHAKE_PROTOCOL: {
			fill_handshake_protocol_information(&tp->subprotocol.hp.hh, &db);
			switch (tp->subprotocol.hp.hh.message_type)
			{
				case CLIENT_KEY_EXCHANGE_MESSAGE:
				case CLIENT_HELLO_MESSAGE: {
					printf("send_packet: trying to send client message");
					util_dynamic_buffer_free(&db);
					return;
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
		case CHANGE_CIPHER_SPEC_PROTOCOL: {
			printf("TO DO!");
		} break;
	}

	write(connected_socket, db.buffer, db.size);
	util_dynamic_buffer_free(&db);
}

static void gen_random_number(unsigned char* random_number)
{
	// todo: this should be a random number and the four first bytes must be unix time
	for (int i = 0; i < 32; ++i)
		random_number[i] = i;
}

static int rawhttp_sender_send_server_hello(int connected_socket, unsigned short selected_cipher_suite)
{
	unsigned char random_number[32];
	gen_random_number(random_number);

	unsigned char session_id_length = 0;
	unsigned short extensions_length = 0;

	tls_packet tp;
	tp.subprotocol.hp.hh.message_type = SERVER_HELLO_MESSAGE;
	tp.subprotocol.hp.hh.message_length = 2 + 32 + 1 + session_id_length + 2 + 1 + 2 + extensions_length;
	tp.subprotocol.hp.message.shm.ssl_version = 0x0301; // hardcoding TLS 1.0 for now
	tp.subprotocol.hp.message.shm.random_number = (unsigned char*)random_number;
	tp.subprotocol.hp.message.shm.session_id_length = 0; //@todo
	tp.subprotocol.hp.message.shm.session_id = NULL; //@todo
	tp.subprotocol.hp.message.shm.selected_cipher_suite = selected_cipher_suite;
	tp.subprotocol.hp.message.shm.selected_compression_method = 0; //@todo
	tp.subprotocol.hp.message.shm.extensions_length = 0; //@todo
	tp.subprotocol.hp.message.shm.extensions = NULL; //@todo

	record_header rh;
	rh.protocol_type = HANDSHAKE_PROTOCOL;
	// @TODO: record_length is not message_length + 4... actually ideally it is... but we can't exceed record's maximum size
	// so here we need to split the packet if necessary and calculate the record_length for each packet
	rh.record_length = (unsigned short)tp.subprotocol.hp.hh.message_length + 4;
	rh.ssl_version = 0x0301; // hardcoding TLS 1.0 for now.

	send_packet(&rh, &tp, connected_socket);

	return 0;
}

// for now, this function excepts a single certificate
static int rawhttp_sender_send_server_certificate(int connected_socket, unsigned char* certificate, int certificate_size)
{
	certificate_info cert_info;
	cert_info.data = certificate;
	cert_info.size = certificate_size;

	tls_packet tp;
	tp.subprotocol.hp.message.scm.number_of_certificates = 1;
	tp.subprotocol.hp.message.scm.certificate_info = &cert_info;
	tp.subprotocol.hp.hh.message_type = SERVER_CERTIFICATE_MESSAGE;
	tp.subprotocol.hp.hh.message_length = 3;
	for (int i = 0; i < tp.subprotocol.hp.message.scm.number_of_certificates; ++i)
		tp.subprotocol.hp.hh.message_length += tp.subprotocol.hp.message.scm.certificate_info[i].size + 3;

	record_header rh;
	rh.protocol_type = HANDSHAKE_PROTOCOL;
	// @TODO: record_length is not message_length + 4... actually ideally it is... but we can't exceed record's maximum size
	// so here we need to split the packet if necessary and calculate the record_length for each packet
	rh.record_length = (unsigned short)tp.subprotocol.hp.hh.message_length + 4;
	rh.ssl_version = 0x0301; // hardcoding TLS 1.0 for now.

	send_packet(&rh, &tp, connected_socket);
	
	return 0;
}

static int rawhttp_sender_send_server_hello_done(int connected_socket)
{
	tls_packet tp;
	tp.subprotocol.hp.hh.message_type = SERVER_HELLO_DONE_MESSAGE;
	tp.subprotocol.hp.hh.message_length = 0;

	record_header rh;
	rh.protocol_type = HANDSHAKE_PROTOCOL;
	// @TODO: record_length is not message_length + 4... actually ideally it is... but we can't exceed record's maximum size
	// so here we need to split the packet if necessary and calculate the record_length for each packet
	rh.record_length = (unsigned short)tp.subprotocol.hp.hh.message_length + 4;
	rh.ssl_version = 0x0301; // hardcoding TLS 1.0 for now.

	send_packet(&rh, &tp, connected_socket);
	
	return 0;
}

int rawhttps_tls_handshake(rawhttps_message_buffer* message_buffer, int connected_socket)
{
	tls_packet p;
	while (1)
	{
		if (rawhttps_parser_parse_ssl_packet(&p, message_buffer, connected_socket))
			return -1;
		switch (p.type)
		{
			case HANDSHAKE_PROTOCOL: {
				switch (p.subprotocol.hp.hh.message_type)
				{
					case CLIENT_HELLO_MESSAGE: {
						// we received a client hello message
						// lets send a server hello message
						unsigned short selected_cipher_suite = 0x0035;
						rawhttp_sender_send_server_hello(connected_socket, selected_cipher_suite);
						int cert_size;
						unsigned char* cert = util_file_to_memory("./certificate/cert_binary", &cert_size);
						rawhttp_sender_send_server_certificate(connected_socket, cert, cert_size);
						free(cert);
						rawhttp_sender_send_server_hello_done(connected_socket);
					} break;
					case CLIENT_KEY_EXCHANGE_MESSAGE: {
						unsigned int pre_master_secret_length = p.subprotocol.hp.message.ckem.premaster_secret_length;
						unsigned char* pre_master_secret = p.subprotocol.hp.message.ckem.premaster_secret;
						printf("Printing premaster secret...");
						util_buffer_print_hex(pre_master_secret, (long long)pre_master_secret_length);

						int err = 0;
						PrivateKey pk = asn1_parse_pem_private_key_from_file("./certificate/key_decrypted.pem", &err);
						hobig_int_print(pk.PrivateExponent);
						printf("\n");
						/*
						HoBigInt i = hobig_int_new_from_memory(pre_master_secret, pre_master_secret_length);
						HoBigInt res = hobig_int_mod_div(&i, &pk.PrivateExponent, &pk.public.N);
						printf("ERR: %d", err);
						*/
						HoBigInt pre_master_secret_bi = hobig_int_new_from_memory((s8*)pre_master_secret, pre_master_secret_length);
						//Decrypt_Data dd = decrypt_pkcs1_v1_5(pk, pre_master_secret_bi, &err);
						//printf("error? %d", err);
						//util_buffer_print_hex((unsigned char*)dd.data, dd.length);
					} break;
					case SERVER_HELLO_MESSAGE:
					case SERVER_CERTIFICATE_MESSAGE:
					case SERVER_HELLO_DONE_MESSAGE: {
						printf("not supported");
						continue;
					} break;
				}
			} break;
			case CHANGE_CIPHER_SPEC_PROTOCOL: {
				switch (p.subprotocol.ccsp.message) {
					case CHANGE_CIPHER_SPEC_MESSAGE: {
						printf("Client asked to activate encryption via CHANGE_CIPHER_SPEC message\n");
						getchar();
					} break;
				}
			} break;
		}
	}
}
