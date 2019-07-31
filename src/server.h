#ifndef RAWHTTPS_SERVER_H
#define RAWHTTPS_SERVER_H
#include "http/http_handler_tree.h"
#include "linux/limits.h"

typedef struct {
	int sockfd;
	int port;
	int initialized;
	rawhttps_handler_tree handlers;
	rawhttps_rsa_certificate certificate;
	rawhttps_private_key private_key;
} rawhttps_server;

int rawhttps_server_init(rawhttps_server* server, int port, const char* certificate_path, const char* private_key_path);
int rawhttps_server_destroy(rawhttps_server* server);
int rawhttps_server_register_handle(rawhttps_server* server, const char* pattern, long long pattern_size, rawhttps_server_handle_func handle);
int rawhttps_server_listen(rawhttps_server* server);
#endif