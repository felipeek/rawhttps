#pragma once
#include <stdint.h>

void sha1(const char* buffer, int length, char out[20]);
void sha1_to_string(char in[20], char out[40]);

void sha256(const char* buffer, int length, char out[32]);
void sha256_to_string(char in[32], char out[64]);

void md5(const char* buffer, int length, char out[16]);
void md5_to_string(char in[16], char out[32]);