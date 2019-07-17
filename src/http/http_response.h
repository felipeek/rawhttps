#ifndef RAWHTTPS_HTTP_RESPONSE_H
#define RAWHTTPS_HTTP_RESPONSE_H
#include <sys/types.h>
#include "../tls/tls.h"

typedef struct {
	rawhttps_tls_state* ts;
	int connected_socket;
} rawhttps_response_connection_information;

typedef struct {
	const char* header;
	long long header_size;
	const char* value;
	long long value_size;
} rawhttps_response_header;

// Struct received in the handler callback used to set information about the HTTP response you want to send.
// headers: all response headers. Use the function rawhttps_response_add_header to add new headers here.
// headers_size: size of headers, used internally by rawhttps
// headers_capacity: capacity of headers, used internally by rawhttps
// response_content: a pointer to the response body. You need to set this field before calling rawhttps_response_flush!
// response_content_size: size, in bytes, of response_content. You also need to set this field before calling rawhttps_response_flush!
// status_code: response's status code. Default value is 200, feel free to change it.
typedef struct {
	rawhttps_response_header* headers;
	long long headers_size;
	long long headers_capacity;
	char* response_content;
	long long response_content_size;
	int status_code;
} rawhttps_response;
int rawhttps_response_new(rawhttps_response* response);
int rawhttps_response_destroy(rawhttps_response* response);
void rawhttps_response_add_header(rawhttps_response* response, const char* header, long long header_size, const char* value, long long value_size);
ssize_t rawhttps_response_flush(const void* internal, rawhttps_response* response);
#endif