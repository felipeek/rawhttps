#ifndef RAWHTTPS_HASH_TABLE_H
#define RAWHTTPS_HASH_TABLE_H

typedef struct
{
	void* elements;
	long long capacity;
	long long element_size;
} rawhttp_hash_table;

int rawhttp_ht_hash_table_create(rawhttp_hash_table* ht, long long capacity, long long element_size);
const void* rawhttp_ht_hash_table_get(const rawhttp_hash_table* ht, const char* key, long long key_size);
int rawhttp_ht_hash_table_put(rawhttp_hash_table* ht, const char* key, long long key_size, const void* value);
int rawhttp_ht_hash_table_destroy(rawhttp_hash_table* ht);

#endif