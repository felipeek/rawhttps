#ifndef RAWHTTP_UTIL_H
#define RAWHTTP_UTIL_H
#include "common.h"

typedef struct {
	char* buffer;
	s64 size;
	s64 capacity;
} dynamic_buffer;

void util_dynamic_buffer_new(dynamic_buffer* db, s64 capacity);
void util_dynamic_buffer_free(dynamic_buffer* db);
void util_dynamic_buffer_add(dynamic_buffer* db, const void* msg, s64 msg_size);
void util_buffer_print_hex(const unsigned char* msg, s64 size);
u8* util_file_to_memory(const s8* path, s32* file_size);

#endif