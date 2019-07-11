#pragma once
void aes_128_cbc_encrypt(const unsigned char* block, const unsigned char key[16], const unsigned char IV[16], int block_count, unsigned char* result);
void aes_128_cbc_decrypt(const unsigned char* block, const unsigned char key[16], const unsigned char IV[16], int block_count, unsigned char* result);