#include "http_header.h"

int rawhttp_header_create(rawhttp_header* http_header, unsigned long long capacity)
{
	return rawhttp_ht_hash_table_create(&http_header->ht, capacity, sizeof(rawhttp_header_value));
}

const rawhttp_header_value* rawhttp_header_get(const rawhttp_header* http_header, const char* header, long long header_name)
{
	return rawhttp_ht_hash_table_get(&http_header->ht, header, header_name);
}

int rawhttp_header_put(rawhttp_header* http_header, const char* header, long long header_size, const char* value, long long value_size)
{
	rawhttp_header_value rhv;
	rhv.value = value;
	rhv.value_size = value_size;
	return rawhttp_ht_hash_table_put(&http_header->ht, header, header_size, &rhv);
}

int rawhttp_header_destroy(rawhttp_header* http_header)
{
	return rawhttp_ht_hash_table_destroy(&http_header->ht);
}