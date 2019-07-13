/***
 *       _____                          
 *      / ____|                         
 *     | (___   ___ _ ____   _____ _ __ 
 *      \___ \ / _ \ '__\ \ / / _ \ '__|
 *      ____) |  __/ |   \ V /  __/ |   
 *     |_____/ \___|_|    \_/ \___|_|   
 *                                      
 *                                      
 */

#include "server.h"
#include "tls.h"
#include "parser.h"
#include "common.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
	rawhttps_server* server;
	struct sockaddr_in client_address;
	int connected_socket;
} rawhttps_connection;

#define RAWHTTP_SERVER_MAX_QUEUE_SERVER_PENDING_CONNECTIONS 5

int rawhttps_server_init(rawhttps_server* server, int port)
{
	server->sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// workaround for dev purposes (avoiding error binding socket: Address already in use)
	int option = 1;
	setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	option = 1;
	setsockopt(server->sockfd, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option));

	int keepalive = 1;
	setsockopt(server->sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive , sizeof(keepalive ));


	if (server->sockfd == -1)
		return -1;

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(struct sockaddr_in));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(port);

	if (bind(server->sockfd, (struct sockaddr*)&server_address, sizeof(server_address)) == -1)
		return -1;

	server->port = port;
	server->initialized = true;

	return 0;
}

int rawhttps_server_destroy(rawhttps_server* server)
{
	// Note: Calling this function will not kill running threads
	// The server socket will be released, causing the listen thread to eventually stop
	// But there may be other threads running with opened connections
	// @TODO: This should be fixed asap. Then the log mutex can also be destroyed.
	if (server->initialized)
	{
		shutdown(server->sockfd, SHUT_RDWR);
		close(server->sockfd);
	}

	return 0;
}

static void* rawhttps_server_new_connection_callback(void* arg)
{
	rawhttps_connection* connection = (rawhttps_connection*)arg;
	char* client_ip_ascii = inet_ntoa(connection->client_address.sin_addr);

	rawhttps_parser_state ps;
	rawhttps_tls_state ts;
	if (rawhttps_parser_state_create(&ps))
		return NULL;
	if (rawhttps_tls_state_create(&ts))
		return NULL;
	if (rawhttps_tls_handshake(&ts, &ps, connection->connected_socket))
	{
		printf("Error in TLS handshake\n");
		printf("Connection with client %s will be destroyed\n", client_ip_ascii);
		rawhttps_parser_state_destroy(&ps);
		return NULL;
	}

	printf("TODO now...\n");
	getchar();

	rawhttps_parser_state_destroy(&ps);
	rawhttps_tls_state_destroy(&ts);

	close(connection->connected_socket);
	free(connection);
	printf("Destroyed connection from client %s", client_ip_ascii);
	return NULL;
}

int rawhttps_server_listen(rawhttps_server* server)
{
	if (listen(server->sockfd, RAWHTTP_SERVER_MAX_QUEUE_SERVER_PENDING_CONNECTIONS) == -1)
		return -1;

	struct sockaddr_in client_address;

	while (1)
	{
		socklen_t client_address_length = sizeof(client_address);
		int connected_socket = accept(server->sockfd, (struct sockaddr*)&client_address, &client_address_length);
		if (connected_socket == -1)
		{
			if (errno == EBADF)
				return 0; // Server socket was closed. Exiting gracefully..
			return -1;
		}

		pthread_t connection_thread;
		rawhttps_connection* connection = malloc(sizeof(rawhttps_connection));
		connection->server = server;
		connection->connected_socket = connected_socket;
		connection->client_address = client_address;
		if (pthread_create(&connection_thread, NULL, rawhttps_server_new_connection_callback, connection))
			return -1;
	}

	return 0;
}