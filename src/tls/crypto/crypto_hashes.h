#pragma once
#include <stdint.h>

void rawhttps_sha1(const unsigned char* buffer, int length, unsigned char out[20]);
void rawhttps_sha1_to_string(unsigned char in[20], unsigned char out[40]);

void rawhttps_sha256(const unsigned char* buffer, int length, unsigned char out[32]);
void rawhttps_sha256_to_string(char in[32], char out[64]);

void rawhttps_md5(const unsigned char* buffer, int length, unsigned char out[16]);
void rawhttps_md5_to_string(unsigned char in[16], unsigned char out[32]);