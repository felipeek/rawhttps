#ifndef RAWHTTPS_HTTP_HEADER_H
#define RAWHTTPS_HTTP_HEADER_H
#include "hash_table.h"
typedef struct
{
	rawhttps_hash_table ht;
} rawhttps_header;
typedef struct
{
	const char* value;
	long long value_size;
} rawhttps_header_value;
int rawhttps_header_create(rawhttps_header* http_header, unsigned long long capacity);
const rawhttps_header_value* rawhttps_header_get(const rawhttps_header* http_header, const char* header, long long header_name);
int rawhttps_header_put(rawhttps_header* http_header, const char* header, long long header_size, const char* value, long long value_size);
int rawhttps_header_destroy(rawhttps_header* http_header);
#endif