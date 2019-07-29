#pragma once

#if defined(DEBUG_MEMORY)
#include <memdebug.h>
#endif

typedef struct {
    int                negative;
    unsigned long long int* value;    // dynamic light_array
} rawhttps_ho_big_int;

// Result structs
typedef struct {
    rawhttps_ho_big_int quotient;
    rawhttps_ho_big_int remainder;
} rawhttps_ho_big_int_div_result;

// Create and destroy
rawhttps_ho_big_int hobig_int_new(unsigned long long int v);
void     hobig_free(rawhttps_ho_big_int v);
rawhttps_ho_big_int hobig_int_copy(rawhttps_ho_big_int v);
rawhttps_ho_big_int hobig_int_new_from_memory(const unsigned char* m, int length);
rawhttps_ho_big_int hobig_int_new_decimal(const char* number, unsigned int* error);

// Comparison
int hobig_int_compare_signed(rawhttps_ho_big_int* left, rawhttps_ho_big_int* right);
int hobig_int_compare_absolute(rawhttps_ho_big_int* left, rawhttps_ho_big_int* right);

// Arithmetic
void               hobig_int_add(rawhttps_ho_big_int* dst, rawhttps_ho_big_int* src);
void               hobig_int_sub(rawhttps_ho_big_int* dst, rawhttps_ho_big_int* src);
rawhttps_ho_big_int           hobig_int_mul(rawhttps_ho_big_int* x, rawhttps_ho_big_int* y);
rawhttps_ho_big_int_div_result hobig_int_div(rawhttps_ho_big_int* dividend, rawhttps_ho_big_int* divisor);
rawhttps_ho_big_int           hobig_int_mod_div(rawhttps_ho_big_int* n, rawhttps_ho_big_int* exp, rawhttps_ho_big_int* m);
rawhttps_ho_big_int           hobig_int_gcd(rawhttps_ho_big_int* a, rawhttps_ho_big_int* b);

// Misc
int      hobig_int_bitcount(rawhttps_ho_big_int* v);
rawhttps_ho_big_int hobig_random(rawhttps_ho_big_int* max);
rawhttps_ho_big_int hobig_random_bitcount(int nbits);

// Print
void hobig_int_print(rawhttps_ho_big_int n);
