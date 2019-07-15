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
#include "tls/tls.h"
#include "tls/tls_parser.h"
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
#include "http/http_parser.h"

#define RAWHTTP_SERVER_MAX_QUEUE_SERVER_PENDING_CONNECTIONS 5

typedef struct {
	rawhttps_server* server;
	struct sockaddr_in client_address;
	int connected_socket;
} rawhttps_connection;

int rawhttps_server_init(rawhttps_server* server, int port, const char* certificate_path, int certificate_path_length,
	const char* private_key_path, int private_key_path_length)
{
	// PATH_MAX includes nul
	if (private_key_path_length > PATH_MAX - 1) return -1;
	if (certificate_path_length > PATH_MAX - 1) return -1;
	if (rawhttp_handler_tree_create(&server->handlers, 16 /* change me */)) return -1;

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

	strncpy(server->certificate_path, certificate_path, certificate_path_length);
	strncpy(server->private_key_path, private_key_path, private_key_path_length);
	server->certificate_path[certificate_path_length] = '\0';
	server->private_key_path[private_key_path_length] = '\0';

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
		rawhttp_handler_tree_destroy(&server->handlers);
	}

	return 0;
}

static void* rawhttps_server_new_connection_callback(void* arg)
{
	rawhttps_connection* connection = (rawhttps_connection*)arg;
	char* client_ip_ascii = inet_ntoa(connection->client_address.sin_addr);

	rawhttps_tls_state ts;
	if (rawhttps_tls_state_create(&ts, connection->server->certificate_path, connection->server->private_key_path))
		return NULL;
	if (rawhttps_tls_handshake(&ts, connection->connected_socket))
	{
		printf("Error in TLS handshake\n");
		printf("Connection with client %s will be destroyed\n", client_ip_ascii);
		rawhttps_tls_state_destroy(&ts);
		return NULL;
	}

	rawhttps_http_parser_state hps;
	rawhttp_request request;
	rawhttp_http_parser_state_create(&hps, &ts);
	if (rawhttp_parser_parse(&hps, &request, connection->connected_socket))
	{
		printf("Error parsing HTTP packet. Connection was dropped or syntax was invalid");
		printf("Connection with client %s will be destroyed", client_ip_ascii);
		return NULL;
	}

	const rawhttp_server_handler* handler = rawhttp_handler_tree_get(&connection->server->handlers, request.uri, request.uri_size);
	if (handler)
	{
		printf("calling handler for uri %.*s\n", request.uri_size, request.uri);
		rawhttp_response response;
		if (rawhttp_response_new(&response))
		{
			printf("Error creating new rawhttp_response");
			rawhttp_header_destroy(&request.header);
			rawhttp_http_parser_state_destroy(&hps);
			rawhttps_tls_state_destroy(&ts);
			return NULL;
		}
		rawhttp_response_connection_information rci;
		rci.connected_socket = connection->connected_socket;
		rci.ts = &ts;
		handler->handle(&rci, &request, &response);
		if (rawhttp_response_destroy(&response))
		{
			printf("Error destroying rawhttp_response");
			rawhttp_header_destroy(&request.header);
			rawhttp_http_parser_state_destroy(&hps);
			rawhttps_tls_state_destroy(&ts);
			return NULL;
		}
	}
	else
	{
		char buf[] = "HTTP/1.0 404 Not Found\n"
			"Connection: Keep-Alive\n"
			"Content-Length: 9\n"
			"\n"
			"404 Error";
		write(request.connected_socket, buf, sizeof(buf) - 1);
	}
	rawhttp_header_destroy(&request.header);
	rawhttp_http_parser_state_destroy(&hps);
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


int rawhttp_server_register_handle(rawhttps_server* server, const char* pattern, long long pattern_size, rawhttp_server_handle_func handle)
{
	return rawhttp_handler_tree_put(&server->handlers, pattern, pattern_size, handle);
}