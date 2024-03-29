#ifndef RAWHTTPS_HTTP_PARSER_H
#define RAWHTTPS_HTTP_PARSER_H
#include "http_request.h"
#include "../tls/tls.h"
typedef struct {
	char* buffer;
	long long buffer_size;
	long long buffer_end;
	long long buffer_position;
	long long header_size;
} rawhttps_http_parser_buffer;
typedef struct {
	rawhttps_http_parser_buffer hpb;
	rawhttps_tls_state* ts;
} rawhttps_http_parser_state;
int rawhttps_http_parser_state_create(rawhttps_http_parser_state* hps, rawhttps_tls_state* ts);
void rawhttps_http_parser_state_destroy(rawhttps_http_parser_state* hps);
int rawhttps_parser_parse(rawhttps_http_parser_state* hps, rawhttps_request* request, int connected_socket);
#endif