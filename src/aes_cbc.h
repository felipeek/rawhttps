#pragma once
void aes_128_cbc_encrypt(unsigned char* block, unsigned char key[16], unsigned char IV[16], int block_count, unsigned char* result);
void aes_128_cbc_decrypt(unsigned char* block, unsigned char key[16], unsigned char IV[16], int block_count, unsigned char* result);