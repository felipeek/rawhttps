#include "server.h"
#include "logger.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <light_array.h>
#include "http_parser.h"
#include "sender.h"
#include "util.h"
#include "hobig.h"
#include "asn1.h"

#define MAX_QUEUE_SERVER_PENDING_CONNECTIONS 5
#define RESPONSE_HEADER_DEFAULT_CAPACITY 16

s32 rawhttp_server_init(rawhttp_server* server, s32 port)
{
	server->sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// workaround for dev purposes (avoiding error binding socket: Address already in use)
	s32 option = 1;
	setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	option = 1;
	setsockopt(server->sockfd, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option));


	if (server->sockfd == -1)
	{
		logger_log_error("rawhttp_server_init: error creating socket: %s", strerror(errno));
		return -1;
	}

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(struct sockaddr_in));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(port);

	if (bind(server->sockfd, (struct sockaddr*)&server_address, sizeof(server_address)) == -1)
	{
		logger_log_error("rawhttp_server_init: error binding socket: %s", strerror(errno));
		return -1;
	}

	server->port = port;

	return 0;
}

static void* new_connection_callback(void* arg)
{
	rawhttp_connection* connection = (rawhttp_connection*)arg;
	char* client_ip_ascii = inet_ntoa(connection->client_address.sin_addr);
	logger_log_info("new_connection_callback: accepted connection from client %s", client_ip_ascii);

	for (;;)
	{
		tls_packet p;
		rawhttp_parser_parse(&p, connection->connected_socket);
		switch (p.rh.protocol_type)
		{
			case HANDSHAKE_PROTOCOL: {
				switch (p.subprotocol.hp.hh.message_type)
				{
					case CLIENT_HELLO_MESSAGE: {
						// we received a client hello message
						// lets send a server hello message
						u16 selected_cipher_suite = 0x0035;
						rawhttp_sender_send_server_hello(connection->connected_socket, selected_cipher_suite);
						s32 cert_size;
						u8* cert = util_file_to_memory("./certificate/cert_binary", &cert_size);
						rawhttp_sender_send_server_certificate(connection->connected_socket, cert, cert_size);
						free(cert);
						rawhttp_sender_send_server_hello_done(connection->connected_socket);

						rawhttp_parser_parse(&p, connection->connected_socket);
						if (p.rh.protocol_type == HANDSHAKE_PROTOCOL && p.subprotocol.hp.hh.message_type)
						{
							switch (p.subprotocol.hp.hh.message_type)
							{
								case SERVER_CERTIFICATE_MESSAGE:
								case SERVER_HELLO_MESSAGE:
								case CLIENT_HELLO_MESSAGE:
								case SERVER_HELLO_DONE_MESSAGE: {
									logger_log_error("not supported");
									continue;
								} break;
								case CLIENT_KEY_EXCHANGE_MESSAGE: {
									u32 pre_master_secret_length = p.subprotocol.hp.message.ckem.premaster_secret_length;
									u8* pre_master_secret = p.subprotocol.hp.message.ckem.premaster_secret;
									logger_log_debug("Printing premaster secret...");
									util_buffer_print_hex(pre_master_secret, (s64)pre_master_secret_length);

									s32 err = 0;
									PrivateKey pk = asn1_parse_pem_private_key_from_file("./certificate/key_decrypted.pem", &err);
									hobig_int_print(pk.PrivateExponent);
									printf("\n");
									HoBigInt i = hobig_int_new_from_memory(pre_master_secret, pre_master_secret_length);
									HoBigInt res = hobig_int_mod_div(&i, &pk.PrivateExponent, &pk.public.N);
									logger_log_debug("ERR: %d", err);
								} break;
							}
						}
						else
						{
							logger_log_error("not supported");
							continue;
						}
						
					} break;
					case SERVER_HELLO_MESSAGE:
					case SERVER_CERTIFICATE_MESSAGE:
					case CLIENT_KEY_EXCHANGE_MESSAGE:
					case SERVER_HELLO_DONE_MESSAGE: {
						logger_log_error("not supported");
						continue;
					} break;
				}
			} break;
		}
	}

	close(connection->connected_socket);
	free(connection);
	logger_log_info("new_connection_callback: destroyed connection from client %s", client_ip_ascii);
	return NULL;
}

s32 rawhttp_server_listen(rawhttp_server* server)
{
	if (listen(server->sockfd, MAX_QUEUE_SERVER_PENDING_CONNECTIONS) == -1)
	{
		logger_log_error("rawhttp_server_listen: error listening socket: %s", strerror(errno));
		return -1;
	}

	struct sockaddr_in client_address;

	while (1)
	{
		socklen_t client_address_length = sizeof(client_address);
		s32 connected_socket = accept(server->sockfd, (struct sockaddr*)&client_address, &client_address_length);
		if (connected_socket == -1)
		{
			logger_log_error("rawhttp_server_listen: error accepting socket: %s", strerror(errno));
			return -1;
		}

		pthread_t connection_thread;
		rawhttp_connection* connection = malloc(sizeof(rawhttp_connection));
		connection->server = server;
		connection->connected_socket = connected_socket;
		connection->client_address = client_address;
		if (pthread_create(&connection_thread, NULL, new_connection_callback, connection))
		{
			logger_log_error("rawhttp_server_listen: error creating thread for new connection: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}
