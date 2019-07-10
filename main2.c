#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "aes_cbc.h"

static void*
load_entire_file(const char* filename, int* out_size) {
    FILE* file = fopen(filename, "rb");

    if(!file) {
        fprintf(stderr, "Could not find file %s\n", filename);
        return 0;
    }

    fseek(file, 0, SEEK_END);
    int file_size = (int)ftell(file);
    fseek(file, 0, SEEK_SET);

    if(file_size == 0) {
        fclose(file);
        fprintf(stderr, "File %s is empty\n", filename);
        return 0;
    }

    void* memory = calloc(1, file_size + 1);

    if(fread(memory, file_size, 1, file) != 1) {
        fclose(file);
        free(memory);
        fprintf(stderr, "Could not read entire file %s\n", filename);
        return 0;
    }
    fclose(file);

    if(out_size) *out_size = file_size;
    return memory;
}

int main()
{
	int out_size;
	unsigned char* encrypted_text = load_entire_file("./arquivo2", &out_size);
	//unsigned char encrypted_text[] = {0x25, 0x97, 0xbd, 0x69, 0xa8, 0x0c, 0x8a, 0xc6, 0x21, 0x50, 0x6c, 0x9d, 0x45, 0x22, 0x34, 0xb1};
	//unsigned char key[] = {0x0c, 0xd9, 0x5b, 0x5e, 0x21, 0xb6, 0x38, 0x77, 0xb8, 0x6e, 0xa0, 0x31, 0x7d, 0xd6, 0x3a, 0x6f};
	unsigned char key[] = "0123456789ABCDEF";
	unsigned char iv[16] = {0};
	unsigned char* result = calloc(1, out_size);

	unsigned char my_own_text[] = "HHHHoshoyoHoshoyoHoHoshoyoHoshoyooshoyoHoshoyoHoHoshoyoHoshoyooshoyoHoshoyoHoHoshoyoHoshoyooshoyoHoshoyoHoHoshoyoHoshoyoHo123456";
	//aes_128_cbc_encrypt(my_own_text, key, iv, 128 / 16, result);
	aes_128_cbc_decrypt(encrypted_text, key, iv, out_size / 16, result);
	//aes_128_cbc_decrypt(result, key, iv, 128 / 16, result);
	
	//for (int i = 0; i < out_size; ++i)
	//	printf("%02x ", result[i]);

	puts(result);
}