#define MEMDEBUG_IMPLEMENT
#include <memdebug.h>
#include <stdio.h>
#include "pkcs1.h"
#include "asn1.h"
#include "../color.h"

void
test_encrypt_pkcs1(rawhttps_private_key priv_key, rawhttps_public_key pub_key) {
    int error = 0;
    const char expected[] = "Hello World";

    rawhttps_ho_big_int encrypted = encrypt_pkcs1_v1_5(pub_key, expected, sizeof(expected) - 1);
    rawhttps_decrypt_data data = decrypt_pkcs1_v1_5(priv_key, encrypted, &error);

    if(error == 0 && (data.length == sizeof(expected) - 1 && strncmp(expected, data.data, data.length) == 0)) {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    } else {
        printf("%sERROR%s: %s\n", ColorRed, ColorReset, __FUNCTION__);
    } 
}

int main() {
    memdebug_init();

    int error = 0;

    rawhttps_private_key priv_key = asn1_parse_pem_private_key_from_file("data/private_rsa.pem", &error);
    rawhttps_public_key pub_key = asn1_parse_pem_public_key_from_file("data/public_rsa.pem", &error);

    if(error != 0) {
        printf("Error\n");
    }

    test_encrypt_pkcs1(priv_key, pub_key);

    memdebug_destroy();
    return 0;
}