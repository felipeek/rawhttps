#include "pkcs1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <light_array.h>

extern u64 random_integer(u64 min, u64 max);

#define BIG_ENDIAN_64(X) ((((X) & 0xff00000000000000) >> 56) | \
    (((X) & 0xff000000000000) >> 40) | \
    (((X) & 0xff0000000000) >> 24) | \
    (((X) & 0xff00000000) >> 8) | \
    (((X) & 0xff000000) << 8) | \
    (((X) & 0xff0000) << 24) | \
    (((X) & 0xff00) << 40) | \
    (((X) & 0xff) << 56))

Decrypt_Data
decrypt_pkcs1_v1_5(PrivateKey pk, HoBigInt encrypted, int* error) {
    HoBigInt decr = hobig_int_mod_div(&encrypted, &pk.PrivateExponent, &pk.public.N);
    if(array_length(decr.value) % 32 != 0) {
        // error, encrypted message does not contain 2048 bits
        fprintf(stderr, "Encrypted message must contain 2048 or 4096 bits\n");
        if(error) *error |= 1;
        return (Decrypt_Data){0};
    }

    if(((decr.value[array_length(decr.value) - 1] & 0xffff000000000000) >> 48) != 0x0002) {
        // format invalid, but do not accuse error to not be
        // vulnerable to attacks like the one described by
        // https://www.youtube.com/watch?v=y9n5FQlKA6g
    }

	// replace first byte by 0xff just to skip it since its value is 0x0 and we need to find a 0x0 byte
	decr.value[array_length(decr.value) - 1] |= 0xff00000000000000;

    int index = 0;
    for(int i = array_length(decr.value) - 1; i >= 0; --i) {
        // sweep every byte searching for 0xff
        u64 v = decr.value[i];
        for(int k = 56; k >= 0; k -= 8) {
            if(((v >> k) & 0xff) == 0x00) {
                index = (i * 64) + k;
                goto end_loop;
            }
        }
    }
end_loop:
    index /= 8; // index in bytes

    Decrypt_Data result = {0};
    // index has the bit count from the base
    result.data = calloc(1, index);
    result.length = index;

    // Copy into memory from little endian to big endian
    for(int i = 0; i < index; ++i) {
        char b = ((char*)decr.value)[i];
        result.data[index - i - 1] = b;
    }
    
    return result;
}

HoBigInt
encrypt_pkcs1_v1_5(PublicKey pk, const char* in, int length_bytes) {
    char out[256];

    // Cannot encrypt something bigger than 128 bits or 16 bytes
    if(length_bytes > 32) return (HoBigInt){0};

    // Always mode 2, meaning encryption
    // First 16 bits are 0x0002 for mode 2
    out[0] = 0;
    out[1] = 2;

    // Generate random padding not containing a byte 0xff
    int padding_byte_count = 256 - length_bytes - 2 - 1;
    for(int i = 0; i < padding_byte_count; ++i) {
        out[i + 2] = random_integer(1, 0xff + 1);
    }
    out[padding_byte_count + 2] = 0x00;

    memcpy(out+padding_byte_count + 3, in, length_bytes);

    HoBigInt rsa_plain_text = hobig_int_new_from_memory((const char*)out, 256);

    HoBigInt encrypted = hobig_int_mod_div(&rsa_plain_text, &pk.E, &pk.N);

    hobig_int_print(encrypted);
    printf("\n");

    return encrypted;
}