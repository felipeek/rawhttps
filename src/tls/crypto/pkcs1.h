#pragma once
#include "../../common.h"
#include "hobig.h"
#include "asn1.h"
typedef struct {
    char* data;
    int   length;
} Decrypt_Data;

Decrypt_Data decrypt_pkcs1_v1_5(PrivateKey pk, HoBigInt encrypted, int* error);
HoBigInt encrypt_pkcs1_v1_5(PublicKey pk, const char* in, int length_bytes);