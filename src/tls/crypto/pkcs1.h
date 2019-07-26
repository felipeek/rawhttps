#pragma once
#include "../../common.h"
#include "hobig.h"
#include "asn1.h"
typedef struct {
    char* data;
    int   length;
} rawhttps_decrypt_data;

rawhttps_decrypt_data decrypt_pkcs1_v1_5(rawhttps_private_key pk, rawhttps_ho_big_int encrypted, int* error);
rawhttps_ho_big_int encrypt_pkcs1_v1_5(rawhttps_public_key pk, const char* in, int length_bytes);