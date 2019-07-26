#include "hmac.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "crypto_hashes.h"

#define MAX(A, B) ((A > B) ? (A) : (B))
#define MIN(A, B) ((A < B) ? (A) : (B))

void
rawhttps_hmac(
    void(*hash_function)(const unsigned char*, int, unsigned char*),
    const unsigned char* key, int key_length, 
    const unsigned char* message, int message_length, 
    unsigned char* result, int result_length) 
{
    #define HMAC_BLOCK_SIZE 64
    unsigned char temp_key[HMAC_BLOCK_SIZE] = {0};
    unsigned char o_key_pad[HMAC_BLOCK_SIZE] = {0};
    unsigned char i_key_pad[HMAC_BLOCK_SIZE] = {0};

    if(key_length > HMAC_BLOCK_SIZE) {
        hash_function(key, key_length, temp_key);
    }
    if(key_length < HMAC_BLOCK_SIZE) {
        memcpy(temp_key, key, key_length);
    }
    
    for(int i = 0; i < HMAC_BLOCK_SIZE; ++i) {
        o_key_pad[i] = 0x5c ^ temp_key[i];
        i_key_pad[i] = 0x36 ^ temp_key[i];
    }

    unsigned char* m = calloc(1, MAX(message_length, HMAC_BLOCK_SIZE) + HMAC_BLOCK_SIZE + 1);
    memcpy(m, i_key_pad, HMAC_BLOCK_SIZE);
    memcpy(m + HMAC_BLOCK_SIZE, message, message_length);

    unsigned char h[512] = {0}; // enough space for all types of hashes
    hash_function(m, message_length + HMAC_BLOCK_SIZE, h);

    memcpy(m, o_key_pad, HMAC_BLOCK_SIZE);
    memcpy(m + HMAC_BLOCK_SIZE, h, result_length);

    hash_function(m, HMAC_BLOCK_SIZE + result_length, result);
    free(m);
}

void rawhttps_phash(
    void(*hash_function)(const unsigned char*, int, unsigned char*), 
    int hash_result_length_bytes,
    const unsigned char* secret, int secret_length, 
    const unsigned char* seed, int seed_length, 
    unsigned char* result, int result_length_bytes) 
{
    int length = result_length_bytes;
    unsigned char A[512] = {0};
    unsigned char T[512] = {0};

    // Calculate A(1) = rawhttps_hmacsecret, A(0))
    rawhttps_hmac(hash_function, secret, secret_length, seed, seed_length, A, hash_result_length_bytes);

    if(length == 0) return;
    unsigned char* temp = calloc(1, hash_result_length_bytes + seed_length);

    int offset = 0;
    while(length > 0) {
        // Next A
        memcpy(temp, A, hash_result_length_bytes);
        memcpy(temp + hash_result_length_bytes, seed, seed_length);

        rawhttps_hmac(hash_function, secret, secret_length, temp, hash_result_length_bytes + seed_length, T, hash_result_length_bytes);
        int a = MIN(length, hash_result_length_bytes);
        memcpy(result + offset, T, a);
        length -= a;
        offset += a;

        rawhttps_hmac(hash_function, secret, secret_length, A, hash_result_length_bytes, A, hash_result_length_bytes);
    }

    free(temp);
}

// prf12 implements the TLS v1.2 pseudo-random function
void rawhttps_prf12(void(*hash_function)(const unsigned char*, int, unsigned char*), 
    int hash_result_length,
    const unsigned char* secret, int secret_length,
    const char* label, int label_length,
    const unsigned char* seed, int seed_length,
    unsigned char* result, int result_length) 
{
    int label_and_seed_length = label_length + seed_length;
    unsigned char* label_and_seed = calloc(1, label_and_seed_length);

    memcpy(label_and_seed, label, label_length);
    memcpy(label_and_seed + label_length, seed, seed_length);

    rawhttps_phash(hash_function, hash_result_length, secret, secret_length, label_and_seed, label_and_seed_length, result, result_length);

    free(label_and_seed);
}

// prf10 implements the TLS v1.0 pseudo-random function
void rawhttps_prf10(
    const unsigned char* secret, int secret_length, 
    const char* label, int label_length, 
    const unsigned char* seed, int seed_length,
    unsigned char* result, int result_length) 
{
    const int MD5_RESULT_LENGTH = 16;
    const int SHA1_RESULT_LENGTH = 20;

    int label_and_seed_length = label_length + seed_length;
    unsigned char* label_and_seed = calloc(1, label_and_seed_length);
    memcpy(label_and_seed, label, label_length);
    memcpy(label_and_seed + label_length, seed, seed_length);

    int s1_len = (secret_length + 1) / 2;
    int s2_len = secret_length - (secret_length / 2);
    unsigned char* s1 = calloc(1, s1_len);
	unsigned char* s2 = calloc(1, s2_len);

    memcpy(s1, secret, s1_len);
    memcpy(s2, secret + s1_len, s2_len);

    rawhttps_phash(rawhttps_md5, MD5_RESULT_LENGTH, s1,  s1_len, label_and_seed, label_and_seed_length, result, result_length);

    unsigned char* res_temp = calloc(1, result_length);
	rawhttps_phash(rawhttps_sha1, SHA1_RESULT_LENGTH, s2, s2_len, label_and_seed, label_and_seed_length, res_temp, result_length);

	for (int i = 0; i < result_length; ++i) {
        result[i] ^= res_temp[i];
	}

    free(s1);
    free(s2);
    free(label_and_seed);
    free(res_temp);
}
