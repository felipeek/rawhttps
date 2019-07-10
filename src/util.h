#ifndef RAWHTTP_UTIL_H
#define RAWHTTP_UTIL_H
#include "common.h"

typedef struct {
	unsigned char* buffer;
	long long size;
	long long capacity;
} dynamic_buffer;

void util_dynamic_buffer_new(dynamic_buffer* db, long long capacity);
void util_dynamic_buffer_free(dynamic_buffer* db);
void util_dynamic_buffer_add(dynamic_buffer* db, const void* msg, long long msg_size);
void util_buffer_print_hex(const unsigned char* msg, int size);
unsigned char* util_file_to_memory(const char* path, int* file_size);

#endif