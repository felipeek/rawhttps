#pragma once 

void rawhttps_hmac(void(*hash_function)(const unsigned char*, int, unsigned char*),
    const unsigned char* key, int key_length, 
    const unsigned char* message, int message_length, 
    unsigned char* result, int result_length);

void rawhttps_phash(void(*hash_function)(const unsigned char*, int, unsigned char*), 
    int hash_result_length_bytes,
    const unsigned char* secret, int secret_length, 
    const unsigned char* seed, int seed_length, 
    unsigned char* result, int result_length_bytes);

void rawhttps_prf10(
    const unsigned char* secret, int secret_length, 
    const char* label, int label_length, 
    const unsigned char* seed, int seed_length,
    unsigned char* result, int result_length);

void rawhttps_prf12(void(*hash_function)(const unsigned char*, int, unsigned char*), 
    int hash_result_length,
    const unsigned char* secret, int secret_length,
    const char* label, int label_length,
    const unsigned char* seed, int seed_length,
    unsigned char* result, int result_length);