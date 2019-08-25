#include "hash_table.h"
#include "../common.h"
#include <stdlib.h>
#include <string.h>

/***
 *      _    _           _       _______    _     _      
 *     | |  | |         | |     |__   __|  | |   | |     
 *     | |__| | __ _ ___| |__      | | __ _| |__ | | ___ 
 *     |  __  |/ _` / __| '_ \     | |/ _` | '_ \| |/ _ \
 *     | |  | | (_| \__ \ | | |    | | (_| | |_) | |  __/
 *     |_|  |_|\__,_|___/_| |_|    |_|\__,_|_.__/|_|\___|
 *                                                       
 *                                                       
 */

typedef struct
{
	const char* key;
	long long key_size;
	int valid;
} rawhttps_ht_hash_table_element;

static int rawhttps_ht_grow(rawhttps_hash_table* ht, long long new_capacity);

static unsigned long long rawhttps_ht_hash(const char* str, long long str_size)
{
	unsigned long long hash = 5381;
	long long c;

	for (; str_size > 0; --str_size)
	{
		c = *str++;
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
}

static rawhttps_ht_hash_table_element* rawhttps_ht_get_element_on_index(const rawhttps_hash_table* ht, long long index)
{
	return (rawhttps_ht_hash_table_element*)((unsigned char*)ht->elements + index * (sizeof(rawhttps_ht_hash_table_element) + ht->element_size));
}

static void* rawhttps_ht_get_value_on_index(const rawhttps_hash_table* ht, long long index)
{
	return (void*)((unsigned char*)ht->elements + index * (sizeof(rawhttps_ht_hash_table_element) + ht->element_size) + sizeof(rawhttps_ht_hash_table_element));
}

static void rawhttps_ht_put_element_on_index(const rawhttps_hash_table* ht, long long index, rawhttps_ht_hash_table_element* element)
{
	*(rawhttps_ht_hash_table_element*)((unsigned char*)ht->elements + index * (sizeof(rawhttps_ht_hash_table_element) + ht->element_size)) = *element;
}

static void rawhttps_ht_put_value_on_index(const rawhttps_hash_table* ht, long long index, const void* value)
{
	memcpy(((unsigned char*)ht->elements + index * (sizeof(rawhttps_ht_hash_table_element) + ht->element_size) + sizeof(rawhttps_ht_hash_table_element)), value, ht->element_size);
}

int rawhttps_ht_hash_table_create(rawhttps_hash_table* ht, long long capacity, long long element_size)
{
	ht->elements = calloc(capacity, sizeof(rawhttps_ht_hash_table_element) + element_size);
	if (!ht->elements)
		return -1;
	ht->capacity = capacity;
	ht->element_size = element_size;

	return 0;
}

const void* rawhttps_ht_hash_table_get(const rawhttps_hash_table* ht, const char* key, long long key_size)
{
	unsigned long long requested_key_hash = rawhttps_ht_hash(key, key_size);
	long long hash_table_position = requested_key_hash % ht->capacity;
	long long positions_scanned = 0;

	while (positions_scanned < ht->capacity)
	{
		rawhttps_ht_hash_table_element* current_element = rawhttps_ht_get_element_on_index(ht, hash_table_position);
		// Test if the current field has content
		if (!current_element->valid)
			break;
		// Test if the key is equal
		if (key_size != current_element->key_size || !strncmp(key, current_element->key, key_size))
			return rawhttps_ht_get_value_on_index(ht, hash_table_position);

		hash_table_position = (hash_table_position + 1) % ht->capacity;
		++positions_scanned;
	}

	return NULL;
}

int rawhttps_ht_hash_table_put(rawhttps_hash_table* ht, const char* key, long long key_size, const void* value)
{
	unsigned long long requested_key_hash = rawhttps_ht_hash(key, key_size);
	long long hash_table_position = requested_key_hash % ht->capacity;
	long long positions_scanned = 0;

	while (positions_scanned < ht->capacity)
	{
		rawhttps_ht_hash_table_element* current_element = rawhttps_ht_get_element_on_index(ht, hash_table_position);
		// Test if the current field has content
		if (!current_element->valid)
		{
			current_element->key = key;
			current_element->key_size = key_size;
			current_element->valid = true;
			rawhttps_ht_put_element_on_index(ht, hash_table_position, current_element);
			rawhttps_ht_put_value_on_index(ht, hash_table_position, value);
			return 0;
		}
		else
		{
			// Just for safety, we check if the key is the same to throw an error
			if (key_size == current_element->key_size && !strncmp(key, current_element->key, key_size))
				return -1;
		}

		hash_table_position = (hash_table_position + 1) % ht->capacity;
		++positions_scanned;
	}

	if (rawhttps_ht_grow(ht, 2 * ht->capacity))
		return -1;

	return rawhttps_ht_hash_table_put(ht, key, key_size, value);
}

static int rawhttps_ht_grow(rawhttps_hash_table* ht, long long new_capacity)
{
	rawhttps_hash_table old_ht = *ht;

	if (rawhttps_ht_hash_table_create(ht, new_capacity, old_ht.element_size))
		return -1;

	for (long long i = 0; i < old_ht.capacity; ++i)
	{
		rawhttps_ht_hash_table_element* current_element = rawhttps_ht_get_element_on_index(&old_ht, i);
		void* current_value = rawhttps_ht_get_value_on_index(&old_ht, i);
		if (current_element->valid)
			if (rawhttps_ht_hash_table_put(ht, current_element->key, current_element->key_size, current_value))
				return -1;
	}

	// Manually delete old hash table
	free(old_ht.elements);

	return 0;
}

int rawhttps_ht_hash_table_destroy(rawhttps_hash_table* ht)
{
	free(ht->elements);
	return 0;
}