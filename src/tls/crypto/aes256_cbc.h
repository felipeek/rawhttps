#pragma once
extern void rawhttps_aes_256_cbc_encrypt(const unsigned char* block, const unsigned char key[32], const unsigned char IV[16], unsigned char* result, int block_count);
extern void rawhttps_aes_256_cbc_decrypt(const unsigned char* block, const unsigned char key[32], const unsigned char IV[16], unsigned char* result, int block_count);