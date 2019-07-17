#ifndef RAWHTTPS_HASH_TABLE_H
#define RAWHTTPS_HASH_TABLE_H

typedef struct
{
	void* elements;
	long long capacity;
	long long element_size;
} rawhttps_hash_table;

int rawhttps_ht_hash_table_create(rawhttps_hash_table* ht, long long capacity, long long element_size);
const void* rawhttps_ht_hash_table_get(const rawhttps_hash_table* ht, const char* key, long long key_size);
int rawhttps_ht_hash_table_put(rawhttps_hash_table* ht, const char* key, long long key_size, const void* value);
int rawhttps_ht_hash_table_destroy(rawhttps_hash_table* ht);

#endif