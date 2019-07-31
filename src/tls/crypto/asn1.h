#pragma once
#include "hobig.h"

typedef struct {
    unsigned char* data;
    int   length;
    int   error;
} rawhttps_base64_data;

rawhttps_base64_data rawhttps_base64_decode(const unsigned char* in, int length);

typedef struct {
    rawhttps_ho_big_int E; // public exponent
    rawhttps_ho_big_int N; // public modulus
} rawhttps_public_key;

typedef struct {
    rawhttps_public_key public;
    rawhttps_ho_big_int  P;
    rawhttps_ho_big_int  Q;
    rawhttps_ho_big_int  PrivateExponent;
    rawhttps_ho_big_int  DP;
    rawhttps_ho_big_int  DQ;
    rawhttps_ho_big_int  QINV;
} rawhttps_private_key;

typedef enum {
    Sig_RSA,
    Sig_MD2WithRSA,
    Sig_MD5WithRSA,
    Sig_SHA1WithRSA,
    Sig_SHA256WithRSA,
    Sig_SHA384WithRSA,
    Sig_SHA512WithRSA,
    Sig_RSAPSS,
    Sig_DSAWithSHA1,
    Sig_DSAWithSHA256,
    Sig_ECDSAWithSHA1,
    Sig_ECDSAWithSHA256,
    Sig_ECDSAWithSHA384,
    Sig_ECDSAWithSHA512,
} rawhttps_signature_algorithm;

typedef struct {
    int         length;
    const char* data;
} rawhttps_cert_metadata;

typedef struct {
    rawhttps_ho_big_int            serial_number;
    rawhttps_public_key           public_key;
    rawhttps_signature_algorithm type;
    rawhttps_signature_algorithm rawhttps_signature_algorithm;
    rawhttps_cert_metadata       common_name;
    rawhttps_cert_metadata       country;
    rawhttps_cert_metadata       state;
    rawhttps_cert_metadata       locality;
    rawhttps_cert_metadata       organization;
    rawhttps_cert_metadata       email;
	rawhttps_base64_data         raw;
    void* raw_der;
    void* arena;
} rawhttps_rsa_certificate;

rawhttps_public_key       asn1_parse_public_key_from_file(const char* filename, int* error);
rawhttps_public_key       asn1_parse_pem_public_key_from_file(const char* filename, int* error);
rawhttps_private_key      asn1_parse_pem_private_key_from_file(const char* filename, int* error);
rawhttps_private_key      asn1_parse_pem_private_certificate_key_from_file(const char* filename, int* error);
rawhttps_rsa_certificate asn1_parse_pem_certificate_from_file(const char* filename, int* error);

void asn1_pem_certificate_free(rawhttps_rsa_certificate certificate);

// RSA Certificate in the PEM format
rawhttps_rsa_certificate asn1_parse_pem_certificate(const unsigned char* data, int length, int* error, int is_base64_encoded);

rawhttps_private_key asn1_parse_pem_private_certificate_key(const unsigned char* data, int length_bytes, int* error, int is_base64_encoded);

// Public Key in the format of openssl
rawhttps_public_key asn1_parse_public_key(const unsigned char* data, int length, int* error, int is_base64_encoded);

// Public Key in the PEM format
rawhttps_public_key asn1_parse_pem_public(const unsigned char* data, int length, int* error, int is_base64_encoded);

// Private Key in the PEM format
rawhttps_private_key asn1_parse_pem_private(const unsigned char* data, int length, int* error, int is_base64_encoded);

// Free functions
void public_key_free(rawhttps_public_key p);
void private_key_free(rawhttps_private_key p);

// Print functions
void public_key_print(rawhttps_public_key pk);
void private_key_print(rawhttps_private_key pk);