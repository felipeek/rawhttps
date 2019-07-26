#include <stdio.h>
#include <assert.h>
#include <asn1.h>
#include "../color.h"

void print_public_key(rawhttps_public_key pk) {
    hobig_int_print(pk.E);
    printf("\n\n");
    hobig_int_print(pk.N);
    printf("\n\n");
}
void print_private_key(rawhttps_private_key pk) {
    hobig_int_print(pk.public.E);
    printf("\n\n");
    hobig_int_print(pk.public.N);
    printf("\n\n");
    hobig_int_print(pk.PrivateExponent);
    printf("\n\n");
    hobig_int_print(pk.P);
    printf("\n\n");
    hobig_int_print(pk.Q);
    printf("\n\n");
    hobig_int_print(pk.DP);
    printf("\n\n");
    hobig_int_print(pk.DQ);
    printf("\n\n");
    hobig_int_print(pk.QINV);
    printf("\n\n");
}

void test_asn1_load_certificate(const char* filename, int print) {
    int err = 0;
    rawhttps_rsa_certificate cert = asn1_parse_pem_certificate_from_file(filename, &err);
    assert(err == 0);
    if(print) {
        print_public_key(cert.public_key);
    }

    if(err != 0) {
        printf("%sERROR%s: %s\n", ColorRed, ColorReset, __FUNCTION__);
    } else {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

void test_asn1_load_private_certificate_key(const char* filename, int print) {
    int err = 0;
    rawhttps_private_key pk = asn1_parse_pem_private_certificate_key_from_file(filename, &err);
    assert(err == 0);
    if(print){
        print_private_key(pk);
    }

    if(err != 0) {
        printf("%sERROR%s: %s\n", ColorRed, ColorReset, __FUNCTION__);
    } else {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

void test_asn1_load_private_rsa_key(const char* filename, int print) {
    int err = 0;
    rawhttps_private_key pk = asn1_parse_pem_private_key_from_file(filename, &err);
    assert(err == 0);
    if(print) {
        print_private_key(pk);
    }

    if(err != 0) {
        printf("%sERROR%s: %s\n", ColorRed, ColorReset, __FUNCTION__);
    } else {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

void test_asn1_load_public_rsa_key(const char* filename, int print) {
    int err = 0;
    rawhttps_public_key pk = asn1_parse_pem_public_key_from_file(filename, &err);
    assert(err == 0);
    if(print) {
        print_public_key(pk);
    }

    if(err != 0) {
        printf("%sERROR%s: %s\n", ColorRed, ColorReset, __FUNCTION__);
    } else {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

int main() {
    test_asn1_load_certificate("../../certificate/other_cert/cert.pem", 0);
    test_asn1_load_certificate("data/certificate.pem", 0);
    test_asn1_load_private_certificate_key("data/cert_key.pem", 0);
    test_asn1_load_private_rsa_key("data/private_rsa.pem", 0);
    test_asn1_load_public_rsa_key("data/public_rsa.pem", 0);
    
    return 0;
}