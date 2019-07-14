#ifndef RAWHTTPS_HTTP_REQUEST_H
#define RAWHTTPS_HTTP_REQUEST_H
#include "http_header.h"
#include "http.h"
// Struct received in the handler callback used to fetch information about the HTTP request.
// method: http method (duh)
// data: this is a pointer to the raw HTTP request data. You don't need to directly access this field
// uri: the received URI, also known as the endpoint...
// uri_size: size of the uri in bytes
// header: all received headers. Please use the function rawhttp_header_get to retrieve the headers, since this is actually a hash table
// connected_socket: connection socket's file descriptor, managed internally by rawhttp
typedef struct {
	rawhttp_method method;
	const char* data;
	const char* uri;
	long long uri_size;
	rawhttp_header header;
	int connected_socket;
} rawhttp_request;
#endif