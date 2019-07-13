#pragma once
#include <stdint.h>

void sha1(const unsigned char* buffer, int length, unsigned char out[20]);
void sha1_to_string(unsigned char in[20], unsigned char out[40]);

void sha256(const unsigned char* buffer, int length, unsigned char out[32]);
void sha256_to_string(char in[32], char out[64]);

void md5(const unsigned char* buffer, int length, unsigned char out[16]);
void md5_to_string(unsigned char in[16], unsigned char out[32]);