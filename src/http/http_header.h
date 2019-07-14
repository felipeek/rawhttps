#ifndef RAWHTTPS_HTTP_HEADER_H
#define RAWHTTPS_HTTP_HEADER_H
#include "hash_table.h"
typedef struct
{
	rawhttp_hash_table ht;
} rawhttp_header;
typedef struct
{
	const char* value;
	long long value_size;
} rawhttp_header_value;
int rawhttp_header_create(rawhttp_header* http_header, unsigned long long capacity);
const rawhttp_header_value* rawhttp_header_get(const rawhttp_header* http_header, const char* header, long long header_name);
int rawhttp_header_put(rawhttp_header* http_header, const char* header, long long header_size, const char* value, long long value_size);
int rawhttp_header_destroy(rawhttp_header* http_header);
#endif