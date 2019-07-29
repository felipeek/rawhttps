#pragma once
#include <stdlib.h>
#include <string.h>

void  memdebug_init();
void  memdebug_destroy();

void* memdebug_malloc(size_t size, const char* filename, int line);
void* memdebug_calloc(size_t count, size_t size, const char* filename, int line);
void* memdebug_realloc(void* block, size_t size, const char* filename, int line);
void  memdebug_free(void* block, const char* filename, int line);

typedef struct {
	void* elements;
	long long capacity;
	long long element_size;
} memdebug_hash_table;

int memdebug_ht_hash_table_create(memdebug_hash_table* ht, long long capacity, long long element_size);
const void* memdebug_ht_hash_table_get(const memdebug_hash_table* ht, void* key);
int memdebug_ht_hash_table_put(memdebug_hash_table* ht, void* key, const void* value);
int memdebug_ht_hash_table_remove(memdebug_hash_table* ht, void* key);
int memdebug_ht_hash_table_destroy(memdebug_hash_table* ht);

typedef struct {
    memdebug_hash_table table;

    size_t current_memory_allocated;

    size_t total_memory_allocd;
    size_t total_memory_freed;
    size_t total_memory_reallocd;

    int alloc_count;
    int free_count;
	int realloc_count;
} Memdebug_Info;
Memdebug_Info memdebug_get_global_info();

#if defined(MEMDEBUG_IMPLEMENT)

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
	void* key;
	int valid;
} memdebug_ht_hash_table_element;

static int memdebug_ht_grow(memdebug_hash_table* ht, long long new_capacity);

static memdebug_ht_hash_table_element* memdebug_ht_get_element_on_index(const memdebug_hash_table* ht, long long index)
{
	return (memdebug_ht_hash_table_element*)((unsigned char*)ht->elements + index * (sizeof(memdebug_ht_hash_table_element) + ht->element_size));
}

static void* memdebug_ht_get_value_on_index(const memdebug_hash_table* ht, long long index)
{
	return (void*)((unsigned char*)ht->elements + index * (sizeof(memdebug_ht_hash_table_element) + ht->element_size) + sizeof(memdebug_ht_hash_table_element));
}

static void memdebug_ht_put_element_on_index(const memdebug_hash_table* ht, long long index, memdebug_ht_hash_table_element* element)
{
	*(memdebug_ht_hash_table_element*)((unsigned char*)ht->elements + index * (sizeof(memdebug_ht_hash_table_element) + ht->element_size)) = *element;
}

static void memdebug_ht_put_value_on_index(const memdebug_hash_table* ht, long long index, const void* value)
{
	memcpy(((unsigned char*)ht->elements + index * (sizeof(memdebug_ht_hash_table_element) + ht->element_size) + sizeof(memdebug_ht_hash_table_element)), value, ht->element_size);
}

int memdebug_ht_hash_table_create(memdebug_hash_table* ht, long long capacity, long long element_size)
{
	ht->elements = calloc(capacity, sizeof(memdebug_ht_hash_table_element) + element_size);
	if (!ht->elements)
		return -1;
	ht->capacity = capacity;
	ht->element_size = element_size;

	return 0;
}

const void* memdebug_ht_hash_table_get(const memdebug_hash_table* ht, void* key)
{
	unsigned long long requested_key_hash = (unsigned long long)key;
	long long hash_table_position = requested_key_hash % ht->capacity;
	long long positions_scanned = 0;

	while (positions_scanned < ht->capacity)
	{
		memdebug_ht_hash_table_element* current_element = memdebug_ht_get_element_on_index(ht, hash_table_position);
		// Test if the current field has content
		if (!current_element->valid)
			break;
		// Test if the key is equal
		if (key == current_element->key)
			return memdebug_ht_get_value_on_index(ht, hash_table_position);
		// If the key is not equal, we check if the hash is equal... If it is, we shall keep searching
		if (requested_key_hash != (unsigned long long)current_element->key)
			break;

		hash_table_position = (hash_table_position + 1) % ht->capacity;
		++positions_scanned;
	}

	return NULL;
}

int memdebug_ht_hash_table_remove(memdebug_hash_table* ht, void* key)
{
	unsigned long long requested_key_hash = (unsigned long long)key;
	long long hash_table_position = requested_key_hash % ht->capacity;
	long long positions_scanned = 0;

	while (positions_scanned < ht->capacity)
	{
		memdebug_ht_hash_table_element* current_element = memdebug_ht_get_element_on_index(ht, hash_table_position);
        // Just for safety, we check if the key is the same to throw an error
        if (current_element->valid) 
        {
            if(key == current_element->key) {
                current_element->valid = 0;
                return 0;
            }
        } else {
            return -1;
        }

		hash_table_position = (hash_table_position + 1) % ht->capacity;
		++positions_scanned;
	}

	return -1;
}

int memdebug_ht_hash_table_put(memdebug_hash_table* ht, void* key, const void* value)
{
	unsigned long long requested_key_hash = (unsigned long long)key;
	long long hash_table_position = requested_key_hash % ht->capacity;
	long long positions_scanned = 0;

	while (positions_scanned < ht->capacity)
	{
		memdebug_ht_hash_table_element* current_element = memdebug_ht_get_element_on_index(ht, hash_table_position);
		// Test if the current field has content
		if (!current_element->valid)
		{
			current_element->key = key;
			current_element->valid = 1;
			memdebug_ht_put_element_on_index(ht, hash_table_position, current_element);
			memdebug_ht_put_value_on_index(ht, hash_table_position, value);
			return 0;
		}
		else
		{
			// Just for safety, we check if the key is the same to throw an error
			if (key == current_element->key)
				return -1;
		}

		hash_table_position = (hash_table_position + 1) % ht->capacity;
		++positions_scanned;
	}

	if (memdebug_ht_grow(ht, 2 * ht->capacity))
		return -1;

	return memdebug_ht_hash_table_put(ht, key, value);
}

static int memdebug_ht_grow(memdebug_hash_table* ht, long long new_capacity)
{
	memdebug_hash_table old_ht = *ht;

	if (memdebug_ht_hash_table_create(ht, new_capacity, old_ht.element_size))
		return -1;

	for (long long i = 0; i < old_ht.capacity; ++i)
	{
		memdebug_ht_hash_table_element* current_element = memdebug_ht_get_element_on_index(&old_ht, i);
		void* current_value = memdebug_ht_get_value_on_index(&old_ht, i);
		if (current_element->valid)
			if (memdebug_ht_hash_table_put(ht, current_element->key, current_value))
				return -1;
	}

	// Manually delete old hash table
	free(old_ht.elements);

	return 0;
}

int memdebug_ht_hash_table_destroy(memdebug_hash_table* ht)
{
	free(ht->elements);
	return 0;
}

// MEMDEBUG

typedef struct {
    void* ptr;
    
    const char* allocation_filename;
    const char* last_realloc_filename;

    int allocation_line;
    int last_realloc_line;

    size_t bytes_allocated;
    size_t realloc_count;
} Memdebug_MemoryElement;

static Memdebug_Info global_memdebug_info;

void memdebug_init() {
    memdebug_ht_hash_table_create(&global_memdebug_info.table, 1024* 1024 * 4, sizeof(Memdebug_MemoryElement));
}

void memdebug_destroy() {
    memdebug_ht_hash_table_destroy(&global_memdebug_info.table);
}

void* memdebug_malloc(size_t size, const char* filename, int line){
    global_memdebug_info.alloc_count++;
    global_memdebug_info.total_memory_allocd += size;
    global_memdebug_info.current_memory_allocated += size;
    
    Memdebug_MemoryElement element = {0};
    element.bytes_allocated = size;
    element.allocation_filename = filename;
    element.allocation_line = line;
    element.ptr = malloc(size);
    element.realloc_count = 0;

    memdebug_ht_hash_table_put(&global_memdebug_info.table, element.ptr, &element);

    return element.ptr;
}

void* memdebug_calloc(size_t count, size_t size, const char* filename, int line){
    global_memdebug_info.alloc_count++;
    global_memdebug_info.total_memory_allocd += (size * count);
    global_memdebug_info.current_memory_allocated += (size * count);

    Memdebug_MemoryElement element = {0};
    element.bytes_allocated = (size * count);
    element.allocation_filename = filename;
    element.allocation_line = line;
    element.ptr = calloc(count, size);
    element.realloc_count = 0;

    memdebug_ht_hash_table_put(&global_memdebug_info.table, element.ptr, &element);

    return element.ptr;
}

void* memdebug_realloc(void* block, size_t size, const char* filename, int line){
    Memdebug_MemoryElement* element = (Memdebug_MemoryElement*)memdebug_ht_hash_table_get(&global_memdebug_info.table, block);
    if(size <= element->bytes_allocated)
        return block;
    
    size_t size_diff = size - element->bytes_allocated;

	global_memdebug_info.realloc_count++;
    global_memdebug_info.current_memory_allocated += size_diff;
    global_memdebug_info.total_memory_allocd += size_diff;
    global_memdebug_info.total_memory_reallocd += size_diff;

    element->bytes_allocated += size_diff;
    element->last_realloc_filename = filename;
    element->last_realloc_line = line;
    element->realloc_count++;
    element->ptr = realloc(block, size);

	if(block != element->ptr) {
		memdebug_ht_hash_table_remove(&global_memdebug_info.table, block);
		memdebug_ht_hash_table_put(&global_memdebug_info.table, element->ptr, element);
	}

    return element->ptr;
}

void memdebug_free(void* block, const char* filename, int line){
    Memdebug_MemoryElement* element = (Memdebug_MemoryElement*)memdebug_ht_hash_table_get(&global_memdebug_info.table, block);

    global_memdebug_info.free_count++;
    global_memdebug_info.current_memory_allocated -= (element->bytes_allocated);
    global_memdebug_info.total_memory_freed += (element->bytes_allocated);

    memdebug_ht_hash_table_remove(&global_memdebug_info.table, element->ptr);

    free(element->ptr);
}

#include <stdio.h>

void memdebug_print_stats() {
    printf("Total allocation count: %d\n", global_memdebug_info.alloc_count);
    printf("Total free count:       %d\n", global_memdebug_info.free_count);
	printf("Total realloc count:    %d\n", global_memdebug_info.realloc_count);
    printf("Current allocated:      %lu\n", global_memdebug_info.current_memory_allocated);
    printf("Total allocated:        %lu\n", global_memdebug_info.total_memory_allocd);
    printf("Total freed:            %lu\n", global_memdebug_info.total_memory_freed);
    printf("Total reallocated:      %lu\n", global_memdebug_info.total_memory_reallocd);
}

void memdebug_print_still_allocated() {
    for(int i = 0; i < global_memdebug_info.table.capacity; ++i) {
        memdebug_ht_hash_table_element* element = memdebug_ht_get_element_on_index(&global_memdebug_info.table, i);
        if(element->valid) {
			Memdebug_MemoryElement* me = memdebug_ht_get_value_on_index(&global_memdebug_info.table, i);
			printf("%s:%d: Allocated %lu bytes\n", me->allocation_filename, me->allocation_line, me->bytes_allocated);
			if(me->last_realloc_filename) {
				printf("   - Last realloc'd at: %s:%d\n", me->last_realloc_filename, me->last_realloc_line);
			}
        }
    }
}

void memdebug_reset_stats() {
	global_memdebug_info.alloc_count = 0;
	global_memdebug_info.free_count = 0;
	global_memdebug_info.realloc_count = 0;
	global_memdebug_info.current_memory_allocated = 0;
	global_memdebug_info.total_memory_allocd = 0;
	global_memdebug_info.total_memory_freed = 0;
	global_memdebug_info.total_memory_reallocd = 0;

	memdebug_ht_hash_table_destroy(&global_memdebug_info.table);

	memdebug_init();
}

Memdebug_Info memdebug_get_global_info() {
	return global_memdebug_info;
}

#endif

#define malloc(S) memdebug_malloc(S, __FILE__, __LINE__)
#define calloc(C, S) memdebug_calloc(C, S, __FILE__, __LINE__)
#define realloc(B, S) memdebug_realloc(B, S, __FILE__, __LINE__)
#define free(B) memdebug_free(B, __FILE__, __LINE__)