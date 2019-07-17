#include "http_response.h"
#include <stdlib.h>
#include <memory.h>
#include "../tls/tls.h"

typedef struct {
	char* buffer;
	long long size;
	long long capacity;
} rawhttps_response_dynamic_buffer;

int rawhttps_response_new(rawhttps_response* response)
{
	response->headers_size = 0;
	response->headers_capacity = 32;
	response->headers = calloc(response->headers_capacity, sizeof(rawhttps_response_header));
	response->status_code = 200;
	return 0;
}

int rawhttps_response_destroy(rawhttps_response* response)
{
	free(response->headers);
	return 0;
}

void rawhttps_response_add_header(rawhttps_response* response, const char* header, long long header_size, const char* value, long long value_size)
{
	if (response->headers_capacity == response->headers_size)
	{
		long long new_capacity = response->headers_capacity * 2;
		response->headers = realloc(response->headers, new_capacity);
		response->headers_capacity = new_capacity;
	}

	rawhttps_response_header rh;
	rh.header = header;
	rh.header_size = header_size;
	rh.value = value;
	rh.value_size = value_size;

	response->headers[response->headers_size++] = rh;
}

static void rawhttps_response_dynamic_buffer_add(rawhttps_response_dynamic_buffer* db, const char* msg, long long msg_size)
{
	while (db->size + msg_size + 1 >= db->capacity)
	{
		db->buffer = realloc(db->buffer, 2 * db->capacity);
		db->capacity *= 2;
	}

	memcpy(db->buffer + db->size, msg, msg_size);
	(db->buffer)[db->size + msg_size + 1] = '\0';
	db->size += msg_size;
}

ssize_t rawhttps_response_flush(const void* internal, rawhttps_response* response)
{
	#define CONTENT_LENGTH_HEADER "Content-Length"
	const rawhttps_response_connection_information* connection = (rawhttps_response_connection_information*)internal;

	char buffer[64];
	char content_length_buffer[64];
	int content_length_buffer_written = sprintf(content_length_buffer, "%lld", response->response_content_size);
	rawhttps_response_add_header(response, CONTENT_LENGTH_HEADER, sizeof(CONTENT_LENGTH_HEADER) - 1,
		content_length_buffer, content_length_buffer_written);

	rawhttps_response_dynamic_buffer data_to_send;
	data_to_send.buffer = calloc(1, 1024);
	data_to_send.capacity = 1024;
	data_to_send.size = 0;

	int status_line_written = sprintf(buffer, "HTTP/1.1 %d\r\n", response->status_code);
	rawhttps_response_dynamic_buffer_add(&data_to_send, buffer, status_line_written);

	for (long long i = 0; i < response->headers_size; ++i)
	{
		rawhttps_response_header* rh = &response->headers[i];
		rawhttps_response_dynamic_buffer_add(&data_to_send, rh->header, rh->header_size);
		rawhttps_response_dynamic_buffer_add(&data_to_send, ": ", 2);
		rawhttps_response_dynamic_buffer_add(&data_to_send, rh->value, rh->value_size);
		rawhttps_response_dynamic_buffer_add(&data_to_send, "\r\n", 2);
	}

	rawhttps_response_dynamic_buffer_add(&data_to_send, "\r\n", 2);

	rawhttps_response_dynamic_buffer_add(&data_to_send, response->response_content, response->response_content_size);

	long long written = rawhttps_tls_write(connection->ts, connection->connected_socket, data_to_send.buffer, data_to_send.size);

	free(data_to_send.buffer);

	return written;
}