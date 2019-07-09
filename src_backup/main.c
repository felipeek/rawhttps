#include <stdio.h>
#include "server.h"
#include "common.h"

int main()
{
	rawhttp_server server;
	rawhttp_server_init(&server, 443);
	rawhttp_server_listen(&server);

	return 0;
}