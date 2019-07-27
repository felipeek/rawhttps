#ifndef RAWHTTPS_RECORD_H
#define RAWHTTPS_RECORD_H
#include "protocol.h"
typedef struct {
	unsigned char* buffer;
	long long buffer_size;
	long long buffer_end;

	long long buffer_position_get;
	long long buffer_position_fetch;
} rawhttps_record_buffer;

typedef enum {
	RAWHTTPS_RECORD_STATUS_NONE,
	RAWHTTPS_RECORD_STATUS_CLOSE_NOTIFY,
	RAWHTTPS_RECORD_STATUS_IO_ERROR,
	RAWHTTPS_RECORD_STATUS_MALFORMED_PACKET,
	RAWHTTPS_RECORD_STATUS_FATAL_ALERT
} record_status;

int rawhttps_record_buffer_create(rawhttps_record_buffer* record_buffer);
void rawhttps_record_buffer_destroy(rawhttps_record_buffer* record_buffer);

long long rawhttps_record_get(rawhttps_record_buffer* record_buffer, int connected_socket,
	unsigned char data[RECORD_PROTOCOL_TLS_PLAIN_TEXT_FRAGMENT_MAX_SIZE], protocol_type* type, rawhttps_connection_state* client_cs,
	record_status* status);
int rawhttps_record_send(rawhttps_connection_state* server_cs, const unsigned char* data, int data_length,
	protocol_type type, int connected_socket);
#endif