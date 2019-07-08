#include <stdio.h>
#include "server.h"
#include <signal.h>

rawhttps_server server;

void close_server(int signum)
{
	// Stops the server and releases resources
	rawhttps_server_destroy(&server);
}

int main()
{
	signal(SIGINT, close_server);

	rawhttps_server_init(&server, 8080);

	// Starts the server. This blocks!
	rawhttps_server_listen(&server);

	return 0;
}