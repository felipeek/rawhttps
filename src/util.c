#include "util.h"
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include "logger.h"

void rawhttps_util_dynamic_buffer_new(rawhttps_util_dynamic_buffer* db, long long capacity)
{
	db->buffer = calloc(1, capacity);
	db->capacity = capacity;
	db->size = 0;
}

void rawhttps_util_dynamic_buffer_free(rawhttps_util_dynamic_buffer* db)
{
	free(db->buffer);
}

void rawhttps_util_dynamic_buffer_add(rawhttps_util_dynamic_buffer* db, const void* msg, long long msg_size)
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

unsigned char* rawhttps_util_file_to_memory(const char* path, int* file_size)
{
	FILE* file = fopen(path, "rb");
	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* result = malloc(*file_size * sizeof(unsigned char));
	fread(result, sizeof(unsigned char), *file_size, file);
	fclose(file);
	return result;
}
