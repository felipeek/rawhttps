#include "util.h"
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include "logger.h"

void util_dynamic_buffer_new(dynamic_buffer* db, s64 capacity)
{
	db->buffer = calloc(1, capacity);
	db->capacity = capacity;
	db->size = 0;
}

void util_dynamic_buffer_free(dynamic_buffer* db)
{
	free(db->buffer);
}

void util_dynamic_buffer_add(dynamic_buffer* db, const void* msg, s64 msg_size)
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

void util_buffer_print_hex(const unsigned char* msg, s64 size)
{
	char aux[16];
	dynamic_buffer log_db;
	util_dynamic_buffer_new(&log_db, 1024);

	for (s64 i = 0; i < size; ++i)
	{
		s32 s = sprintf(aux, "%02hhX ", msg[i]);
		util_dynamic_buffer_add(&log_db, aux, s);
	}

	logger_log_debug("%.*s", log_db.size, log_db.buffer);
}

u8* util_file_to_memory(const s8* path, s32* file_size)
{
	FILE* file = fopen(path, "rb");
	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	u8* result = malloc(*file_size * sizeof(u8));
	fread(result, sizeof(u8), *file_size, file);
	fclose(file);
	return result;
}