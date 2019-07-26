#ifndef RAWHTTPS_UTIL_H
#define RAWHTTPS_UTIL_H
#include "common.h"

typedef struct {
	unsigned char* buffer;
	long long size;
	long long capacity;
} rawhttps_util_dynamic_buffer;

void rawhttps_util_dynamic_buffer_new(rawhttps_util_dynamic_buffer* db, long long capacity);
void rawhttps_util_dynamic_buffer_free(rawhttps_util_dynamic_buffer* db);
void rawhttps_util_dynamic_buffer_add(rawhttps_util_dynamic_buffer* db, const void* msg, long long msg_size);
unsigned char* rawhttps_util_file_to_memory(const char* path, int* file_size);

#endif