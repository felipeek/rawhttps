#ifndef RAWHTTP_SERVER_H
#define RAWHTTP_SERVER_H
#include "common.h"
#include <netinet/in.h>

typedef struct {
	s32 sockfd;
	s32 port;
} rawhttp_server;

typedef struct {
	rawhttp_server* server;
	struct sockaddr_in client_address;
	s32 connected_socket;
} rawhttp_connection;

s32 rawhttp_server_init(rawhttp_server* server, s32 port);
s32 rawhttp_server_listen(rawhttp_server* server);

#endif