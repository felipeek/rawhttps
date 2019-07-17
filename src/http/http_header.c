#include "http_header.h"

int rawhttps_header_create(rawhttps_header* http_header, unsigned long long capacity)
{
	return rawhttps_ht_hash_table_create(&http_header->ht, capacity, sizeof(rawhttps_header_value));
}

const rawhttps_header_value* rawhttps_header_get(const rawhttps_header* http_header, const char* header, long long header_name)
{
	return rawhttps_ht_hash_table_get(&http_header->ht, header, header_name);
}

int rawhttps_header_put(rawhttps_header* http_header, const char* header, long long header_size, const char* value, long long value_size)
{
	rawhttps_header_value rhv;
	rhv.value = value;
	rhv.value_size = value_size;
	return rawhttps_ht_hash_table_put(&http_header->ht, header, header_size, &rhv);
}

int rawhttps_header_destroy(rawhttps_header* http_header)
{
	return rawhttps_ht_hash_table_destroy(&http_header->ht);
}