#include "http_parser.h"
#include "http.h"
#include "http_request.h"
#include "../tls/record.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "../tls/tls.h"

#define RAWHTTP_PARSER_REQUEST_HEADER_DEFAULT_CAPACITY 16

static long long rawhttp_parser_fetch_next_chunk(rawhttps_http_parser_buffer* hpb, int connected_socket, rawhttps_tls_state* ts)
{
	long long size_needed = hpb->buffer_end + RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE;
	if (size_needed > hpb->buffer_size)
	{
		hpb->buffer = realloc(hpb->buffer, size_needed);
		hpb->buffer_size = size_needed;
	}

	long long size_read;
	if ((size_read = rawhttps_tls_read(ts, connected_socket, hpb->buffer + hpb->buffer_end)) == -1)
		return -1;
	if (size_read == 0)
	{
		// TODO
		printf("TODO ...");
		return -1;
	}
	hpb->buffer_end += size_read;

	printf("Fetched %lld bytes from client.\n", size_read);
	return size_read;
}

// lets make rawhttp also have this function to make the parser a bit better
static int rawhttp_parser_fetch_next_byte(rawhttps_http_parser_buffer* hpb, int connected_socket, char* c, rawhttps_tls_state* ts)
{
	while (hpb->header_size + 1 > hpb->buffer_end)
		if (rawhttp_parser_fetch_next_chunk(hpb, connected_socket, ts) == -1)
			return -1;

	++hpb->header_size;
	*c = hpb->buffer[hpb->header_size - 1];
	return 0;
}

static int rawhttp_parser_fetch_header(rawhttps_http_parser_buffer* hpb, int connected_socket, rawhttps_tls_state* ts)
{
	char c;

	for (;;)
	{
		if (rawhttp_parser_fetch_next_byte(hpb, connected_socket, &c, ts))
			return -1;
		
		if (c == '\r')
		{
			if (rawhttp_parser_fetch_next_byte(hpb, connected_socket, &c, ts))
				return -1;

			if (c == '\n')
			{
				if (rawhttp_parser_fetch_next_byte(hpb, connected_socket, &c, ts))
					return -1;

				if (c == '\r')
				{
					if (rawhttp_parser_fetch_next_byte(hpb, connected_socket, &c, ts))
						return -1;

					if (c == '\n')
						return 0;
				}
			}
		}
	}
}

static int rawhttp_parser_get_next_bytes(rawhttps_http_parser_buffer* hpb, long long num, int connected_socket, char** ptr)
{
	if (hpb->buffer_position + num > hpb->header_size)
		return -1;

	hpb->buffer_position += num;
	*ptr = hpb->buffer + hpb->buffer_position - num;
	return 0;
}

static int rawhttp_parser_get_next_string(rawhttps_http_parser_buffer* hpb, int connected_socket, char** string_ptr, long long* string_size)
{
	char* ptr;
	if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
		return -1;

	while (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
	{
		if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
			return -1;
	}

	*string_ptr = ptr;
	*string_size = 0;

	while (*ptr != ' ' && *ptr != '\r' && *ptr != '\n')
	{
		++*string_size;
		if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
			return -1;
	}

	return 0;
}

static int rawhttp_parser_get_request_header(rawhttps_http_parser_buffer* hpb, int connected_socket, char** request_header_ptr,
	long long* request_header_size, char** request_header_value_ptr, long long* request_header_value_size)
{
	char* ptr;
	if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
		return -1;

	while (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
	{
		if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
			return -1;
	}

	*request_header_ptr = ptr;
	*request_header_size = 0;

	while (*ptr != ' ' && *ptr != '\r' && *ptr != '\n' && *ptr != ':')
	{
		++*request_header_size;
		if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
			return -1;
	}

	// skip 1 byte to make sure that we skip ':', when necessary ... this is necessary when there is no space in header (e.g. header:value)
	if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
		return -1;

	while (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
	{
		if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
			return -1;
	}

	*request_header_value_ptr = ptr;
	*request_header_value_size = 0;

	// For the request header value, we must expect spaces (' ') and colons (':') to be part of the value
	while (*ptr != '\r' && *ptr != '\n')
	{
		++*request_header_value_size;
		if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
			return -1;
	}

	// the last field must be a '\n'!
	if (rawhttp_parser_get_next_bytes(hpb, 1, connected_socket, &ptr))
		return -1;
	if (*ptr != '\n')
	{
		// error!
		return -1;
	}

	return 0;
}

static int rawhttp_parser_end_of_header(rawhttps_http_parser_buffer* hpb)
{
	// If there is only two more bytes to reach header_size, they are \r\n
	// thus, there are no more headers to parse
	return hpb->header_size == hpb->buffer_position + 2;
}

int rawhttps_http_parser_buffer_create(rawhttps_http_parser_buffer* hpb)
{
	hpb->buffer = malloc(sizeof(char) * RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE);
	if (!hpb->buffer) return -1;
	hpb->buffer_size = RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE;
	hpb->buffer_end = 0;
	hpb->header_size = 0;
	hpb->buffer_position = 0;
	return 0;
}

void rawhttps_http_parser_buffer_destroy(rawhttps_http_parser_buffer* hpb)
{
	free(hpb->buffer);
}

int rawhttp_http_parser_state_create(rawhttps_http_parser_state* hps, rawhttps_tls_state* ts)
{
	hps->ts = ts;
	return rawhttps_http_parser_buffer_create(&hps->hpb);
}

void rawhttp_http_parser_state_destroy(rawhttps_http_parser_state* hps)
{
	rawhttps_http_parser_buffer_destroy(&hps->hpb);
}

int rawhttp_parser_parse(rawhttps_http_parser_state* hps, rawhttp_request* request, int connected_socket)
{
	if (rawhttp_parser_fetch_header(&hps->hpb, connected_socket, hps->ts))
		return -1;

	request->connected_socket = connected_socket;

	if (rawhttp_header_create(&request->header, RAWHTTP_PARSER_REQUEST_HEADER_DEFAULT_CAPACITY))
		return -1;

	// First we get the HTTP method
	long long http_method_size;
	char* http_method;
	if (rawhttp_parser_get_next_string(&hps->hpb, connected_socket, &http_method, &http_method_size))
	{
		rawhttp_header_destroy(&request->header);
		return -1;
	}
	
	if (!strncmp(http_method, "GET", http_method_size))
		request->method = HTTP_GET;
	else if (!strncmp(http_method, "HEAD", http_method_size))
		request->method = HTTP_HEAD;
	else if (!strncmp(http_method, "POST", http_method_size))
		request->method = HTTP_POST;
	else if (!strncmp(http_method, "PUT", http_method_size))
		request->method = HTTP_PUT;
	else if (!strncmp(http_method, "DELETE", http_method_size))
		request->method = HTTP_DELETE;
	else if (!strncmp(http_method, "TRACE", http_method_size))
		request->method = HTTP_TRACE;
	else if (!strncmp(http_method, "OPTIONS", http_method_size))
		request->method = HTTP_OPTIONS;
	else if (!strncmp(http_method, "CONNECT", http_method_size))
		request->method = HTTP_CONNECT;
	else if (!strncmp(http_method, "PATCH", http_method_size))
		request->method = HTTP_PATCH;
	else
		request->method = -1;

	// Now we get the URI
	long long uri_size;
	char* uri;
	if (rawhttp_parser_get_next_string(&hps->hpb, connected_socket, &uri, &uri_size))
	{
		rawhttp_header_destroy(&request->header);
		return -1;
	}
	request->uri = uri;
	request->uri_size = uri_size;

	// Now we get the version
	// Ignore the version for now
	// ...
	long long version_size;
	char* version;
	if (rawhttp_parser_get_next_string(&hps->hpb, connected_socket, &version, &version_size))
	{
		rawhttp_header_destroy(&request->header);
		return -1;
	}

	// Parse all request header fields
	for (;;)
	{
		if (rawhttp_parser_end_of_header(&hps->hpb))
			break;
	
		// Get the next request header
		long long request_header_size, request_header_value_size;
		char* request_header;
		char* request_header_value;
		if (rawhttp_parser_get_request_header(&hps->hpb, connected_socket, &request_header, &request_header_size,
			&request_header_value, &request_header_value_size))
		{
			rawhttp_header_destroy(&request->header);
			return -1;
		}

		printf("Received header %.*s = %.*s\n", request_header_size, request_header, request_header_value_size, request_header_value);

		if (rawhttp_header_put(&request->header, request_header, request_header_size, request_header_value, request_header_value_size))
		{
			rawhttp_header_destroy(&request->header);
			return -1;
		}
	}

	// At this point, we should start parsing the request body.
	// Part of the request body may be already in &hps->hpb.
	// &hps->hpb->buffer_end - &hps->hpb->header_size gives the part of the buffer that is already the request body
	// We should receive a callback from the user and start feeding him the body, beggining by this part, if it exists
	// We must feed the body in chunks, since it may be a big chunk of data
	// This was not implemented yet.

	return 0;
}