#include "hobig.h"

typedef int bool;
typedef unsigned char u8;
typedef unsigned long long int u64;
typedef long long int s64;
#define true 1
#define false 0

#include <stdarg.h>
#include <assert.h>
#include "light_array.h"
#include "table.h"

extern u64 div_word(u64 dividend_high, u64 dividend_low, u64 divisor, u64* out_remainder);
extern u64 mul_word(u64 val1, u64 val2, u64* higher);
extern u64 add_u64(u64 x, u64 y, u64 carry, u64* result);
extern u64 sub_u64(u64 x, u64 y, u64 carry, u64* result);
extern u64 random_integer(u64 min, u64 max);
extern u64 random_64bit_integer();

#if defined(__linux__)
#include <time.h>
double os_time_us() {
    struct timespec t_spec;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t_spec);
    u64 res = t_spec.tv_nsec + 1000000000 * t_spec.tv_sec;
    return (double)res / 1000.0;
}
#else
u64 random_integer(u64 min, u64 max) {
    return 1;
}
u64 random_64bit_integer() {
    return 1;
}

double os_time_us() {
    return 0.0;
}
#endif

typedef enum {
    TIME_SLOT_MULTIPLY,
    TIME_SLOT_DIVIDE,
    TIME_SLOT_ADD,
    TIME_SLOT_SUBTRACT,
    TIME_SLOT_COMPARE,
    TIME_SLOT_MOD_DIV,
} TimeSlot;
static double elapsed_times[64];
static int    execution_count[64];

#define COLLECT_TIMES 1

#if COLLECT_TIMES
#define TIME_COUNT() double time_count_start = os_time_us()
#define TIME_END(X) elapsed_times[X] += os_time_us() - time_count_start; execution_count[X]++
#else
#define TIME_COUNT()
#define TIME_END(X)
#endif

void
print_time_slots() {
    printf("Multiply:  %.2f ms, executed %d times\n", 0.001 * elapsed_times[TIME_SLOT_MULTIPLY], execution_count[TIME_SLOT_MULTIPLY]);
    printf("Divide:    %.2f ms, executed %d times\n", 0.001 * elapsed_times[TIME_SLOT_DIVIDE], execution_count[TIME_SLOT_DIVIDE]);
    printf("Add:       %.2f ms, executed %d times\n", 0.001 * elapsed_times[TIME_SLOT_ADD], execution_count[TIME_SLOT_ADD]);
    printf("Subtract:  %.2f ms, executed %d times\n", 0.001 * elapsed_times[TIME_SLOT_SUBTRACT], execution_count[TIME_SLOT_SUBTRACT]);
    printf("Compare:   %.2f ms, executed %d times\n", 0.001 * elapsed_times[TIME_SLOT_COMPARE], execution_count[TIME_SLOT_COMPARE]);
    printf("ModDivide: %.2f ms, executed %d times\n", 0.001 * elapsed_times[TIME_SLOT_MOD_DIV], execution_count[TIME_SLOT_MOD_DIV]);
}

HoBigInt 
hobig_int_new(u64 v) {
    HoBigInt result = { 0, array_new(u64) };
    array_push(result.value, v);
    return result;
}

HoBigInt
hobig_int_make(u64 n) {
    HoBigInt result = {0, array_new_len(u64, n) };
    return result;
}

void
hobig_free(HoBigInt v) {
    if(v.value) array_free(v.value);
}

static void 
print_number(unsigned char* num, int length) {
    bool seen_number = false;
    for(int i = length-1; i >= 0; --i) {
        if(num[i] == 0 && !seen_number)
            continue;
        else
            seen_number = true;
        printf("%d", num[i]);
    }
    if(!seen_number) printf("0");
}

// Returns the number of leading zeros
static int 
hobig_int_leading_zeros_count(HoBigInt n) {
    u64 v = n.value[array_length(n.value) - 1];

    int c = 64;
    for(int i = 0; i < 64; ++i, --c) {
        if(v == 0) break;
        v >>= 1;
    }

    return c;
}

int
hobig_int_bitcount(HoBigInt* v) {
    int word_bit_count =  (int)(array_length(v->value) * sizeof(*v->value) * 8);

    return word_bit_count - hobig_int_leading_zeros_count(*v);
}

u64 bigendian_word(u64 v) {
    u64 r = 
        ((v & 0xff00000000000000) >> 56) |
        ((v & 0xff000000000000) >> 40) |
        ((v & 0xff0000000000) >> 24) |
        ((v & 0xff00000000) >> 8) |
        ((v & 0xff000000) << 8) |
        ((v & 0xff0000) << 24) |
        ((v & 0xff00) << 40) |
        ((v & 0xff) << 56)
    ;
    return r;
}

HoBigInt
hobig_int_new_from_memory(const unsigned char* m, int length) {
    HoBigInt result = {0};
    if(length == 0) return result;

    int arr_length = (length + sizeof(u64) - 1) / sizeof(u64);
    result.value = array_new_len(u64, arr_length);

    int i = length;
	for (int k = 0; i >= sizeof(u64); k++) {
        result.value[k] = bigendian_word(*(u64*)&m[i-sizeof(u64)]);
		i -= sizeof(u64);
    }
    if (i > 0) {
		u64 d = 0;
		for (int s = 0; i > 0; s += 8) {
			d |= (u64)(m[i-1]) << s;
			i--;
		}
	    result.value[arr_length-1] = d;
	}

    array_length(result.value) = arr_length;

    return result;
}

// a will be the destination
static void 
big_dec_sum(u8* dst, u8* src, int length) {
    u8 carry = 0;
    for(int i = 0; i < length; ++i) {
        u8 a = dst[i];
        u8 b = src[i];
        dst[i] = mult_table[a][b][carry][0]; // this is the result
        carry = mult_table[a][b][carry][1];
    }
}

void 
hobig_int_print(HoBigInt n) {
    if(!n.value || array_length(n.value) == 0){
        printf("0");
        return;
    }

    if(n.negative) {
        printf("-");
    }
    size_t length = (array_length(n.value) + 1) * 64;

    u8* result = calloc(length, 1); // The result is at least the size of the binary number + 1
    u8* buffer = calloc(length, 1); // Buffer that will hold powers of 2 in decimal
    buffer[0] = 1;

    for(int k = 0; k < array_length(n.value); k++) {
        u64 v = n.value[k];
        for(int i = 0; i < sizeof(*n.value) * 8; ++i) {
            int bit = (v >> i) & 1;
            if(bit) {
                big_dec_sum(result, buffer, length);
            }
            big_dec_sum(buffer, buffer, length);
        }
    }

    print_number(result, length);

    free(result);
    free(buffer);
}

HoBigInt
hobig_int_copy(HoBigInt v) {
    HoBigInt result = {0};
    result.negative = v.negative;
    result.value = array_copy(v.value);
    return result;
}

static void
multiply_by_pow2(HoBigInt* n, int power) {
    int word_size_bytes = sizeof(*n->value);
    int word_size_bits = word_size_bytes * 8;
    int word_shift_count = power / word_size_bits;
    int shift_amount = (power % word_size_bits);

    u64 s = 0;
    for(int i = 0; i < array_length(n->value); ++i) {
        u64 d = n->value[i] >> (word_size_bits - shift_amount);
        n->value[i] <<= shift_amount;
        n->value[i] |= s;
        s = d;
    }
    if(s) {
        // grow array
        array_push(n->value, s);
    }

    if(word_shift_count) {
        // insert zeros at the beggining
        array_allocate(n->value, word_shift_count);
        memcpy(n->value + array_length(n->value), n->value, array_length(n->value) * word_size_bytes);
        memset(n->value, 0, word_shift_count * word_size_bytes);
        array_length(n->value) += word_shift_count;
    }
}

// Compares two numbers considering sign
// Return value:
//  1 -> left is bigger
//  0 -> they are equal
// -1 -> right is bigger
int
hobig_int_compare_signed(HoBigInt* left, HoBigInt* right) {
    TIME_COUNT();
    // Check the sign first
    if(left->negative != right->negative) {
        if(left->negative) { TIME_END(TIME_SLOT_COMPARE); return -1; }
        TIME_END(TIME_SLOT_COMPARE);
        return 1;
    }

    // If both are negative, the biggest absolute will be
    // the lower value.
    int negative = (left->negative && right->negative) ? -1 : 1;

    size_t llen = array_length(left->value);
    size_t rlen = array_length(right->value);

    if(llen > rlen) { TIME_END(TIME_SLOT_COMPARE); return 1 * negative; }
    if(llen < rlen) { TIME_END(TIME_SLOT_COMPARE); return -1 * negative; }

    for(int i = llen - 1;; --i) {
        if(left->value[i] > right->value[i]) {
            TIME_END(TIME_SLOT_COMPARE);
            return 1 * negative;
        } else if (left->value[i] < right->value[i]) {
            TIME_END(TIME_SLOT_COMPARE);
            return -1 * negative;
        }
        if(i == 0) break;
    }
    
    TIME_END(TIME_SLOT_COMPARE);
    return 0;
}

// Compares the absolute value of two numbers, ignoring the sign
// Return value:
//  1 -> left is bigger
//  0 -> they are equal
// -1 -> right is bigger
int
hobig_int_compare_absolute(HoBigInt* left, HoBigInt* right) {
    TIME_COUNT();
    if(left->value == right->value) {
        TIME_END(TIME_SLOT_COMPARE);
        return 0;
    }

    size_t llen = array_length(left->value);
    size_t rlen = array_length(right->value);

    if(llen > rlen) { TIME_END(TIME_SLOT_COMPARE); return 1; }
    if(llen < rlen) { TIME_END(TIME_SLOT_COMPARE); return -1; }


    for(int i = llen - 1;; --i) {
        if(left->value[i] > right->value[i]) {
            TIME_END(TIME_SLOT_COMPARE);
            return 1;
        } else if (left->value[i] < right->value[i]) {
            TIME_END(TIME_SLOT_COMPARE);
            return -1;
        }
        if(i == 0) break;
    }

    TIME_END(TIME_SLOT_COMPARE);
    return 0;
}

void
hobig_int_sub(HoBigInt* dst, HoBigInt* src);

static u64 
add_hobig_slice(u64* z, u64 zlen, u64* x, HoBigInt y) {
    u64 c = 0;
    for (u64 i = 0; i < zlen; ++i) {
        c = add_u64(x[i], y.value[i], c, &z[i]);
    }
    return c;
}

// The resulting carry c is either 0 or 1.
static u64 
sub_hobig_slice(u64* z, u64 zlen, u64* x, HoBigInt y) {
    u64 c = 0;
    for (u64 i = 0; i < zlen; ++i) {
        c = sub_u64(x[i], y.value[i], c, &z[i]);
    }
    return c;
}

int greater_than(u64 x1, u64 x2, u64 y1, u64 y2) {
	return ((x1 > y1) || (x1 == y1 && x2 > y2));
}

void 
hobig_int_add(HoBigInt* dst, HoBigInt* src) {
    TIME_COUNT();
    // Check to see if a subtraction is preferred
    if(dst->negative != src->negative) {
        // Subtract instead
        if(dst->negative) {
            // -x + y => -x -(-y)
            src->negative = 1;
            hobig_int_sub(dst, src);
            src->negative = 0;
        } else {
            // x + (-y) => x - y
            src->negative = 0;
            hobig_int_sub(dst, src);
            src->negative = 1;
        }
        TIME_END(TIME_SLOT_ADD);
        return;
    }

    HoBigInt s = {0};
    int free_source = 0;
    if(dst == src) {
        s = hobig_int_copy(*src);
        src = &s;
        free_source = 1;
    }

    // destination is at least the size of src or bigger
    if(array_length(dst->value) < array_length(src->value)) {
        size_t count = array_length(src->value) - array_length(dst->value);
        array_allocate(dst->value, count);
        memset(dst->value + array_length(dst->value), 0, count * sizeof(*dst->value));
        array_length(dst->value) = array_length(src->value);
    }
    u64 carry = 0;
    for(int i = 0; i < array_length(src->value); ++i) {
        u64 sum = dst->value[i] + src->value[i] + carry;
        if(sum < src->value[i] || 
            (sum == src->value[i] && dst->value[i] > 0 && src->value[i] > 0)) {
            carry = 1;
        } else {
            carry = 0;
        }
        dst->value[i] = sum;
    }
    if(carry) {
        if(array_length(src->value) == array_length(dst->value)) {
            // grow destination
            array_push(dst->value, 1);
        } else {
            // destination is bigger, so sum 1 to it
            if(dst->value[array_length(src->value)] != (u64)-1) {
                dst->value[array_length(src->value)] += 1;
            } else {
                HoBigInt big_one = hobig_int_new(1);
                hobig_int_add(dst, &big_one);
            }
        }
    }

    if(free_source) {
        hobig_free(*src);
    }

    TIME_END(TIME_SLOT_ADD);
}

void
hobig_int_sub(HoBigInt* dst, HoBigInt* src) {
    TIME_COUNT();
    int comparison = hobig_int_compare_absolute(dst, src);

    int dst_sign = dst->negative;
    int src_sign = src->negative;

    if(dst->negative != src->negative) {
        assert(comparison != 0);
        // if different sign and dst > src perform an absolute sum
        dst->negative = 0;
        src->negative = 0;
        
        hobig_int_add(dst, src);
        // final sign is going to be the destination sign, since its absolute
        // value is bigger.
        dst->negative = dst_sign;

        // restore src
        src->negative = src_sign;
        TIME_END(TIME_SLOT_SUBTRACT);
        return;
    }

    switch(comparison) {
        case 0: {
            // Result is 0
            dst->negative = 0;
            *dst->value = 0;
            array_length(dst->value) = 1;
        } break;
        case 1: {
            // dst > src
            u64 borrow = 0;
            for(int i = 0; i < array_length(src->value); ++i) {
                u64 start = dst->value[i];
                dst->value[i] -= borrow;
                dst->value[i] -= (src->value[i]);
                if(dst->value[i] > start 
                    || (dst->value[i] == start && dst->value[i] > 0 && src->value[i] > 0)) {
                    borrow = 1;
                } else {
                    borrow = 0;
                }
            }
            if(borrow) {
                dst->value[array_length(src->value)] -= 1;
            }
        } break;
        case -1: {
            // dst < src
            dst->negative = (dst->negative) ? 0 : 1;
            u64 borrow = 0;
            for(int i = 0; i < array_length(src->value); ++i) {
                u64 start = src->value[i];
                dst->value[i] = src->value[i] - borrow - dst->value[i];
                if(dst->value[i] > start) {
                    borrow = 1;
                } else {
                    borrow = 0;
                }
            }
            assert(borrow == 0);
        } break;
        default: assert(0); break;
    }
    // Reduce the array size of destination if it is the case
    size_t dst_length = array_length(dst->value);
    size_t reduction = 0;
    for(size_t i = dst_length - 1;;--i) {
        if(dst->value[i] == 0)
            reduction++;
        else
            break;
        if(i == 0) break;
    }
    array_length(dst->value) -= reduction;

    TIME_END(TIME_SLOT_SUBTRACT);
}

static void 
hobig_int_mul_pow10(HoBigInt* start, int p) {
    if(p == 0) {
        return;
    }
    // 8x + 2x
    for(int i = 0; i < p; ++i) {
        HoBigInt copy2 = hobig_int_copy(*start);

        multiply_by_pow2(start, 3);     // multiply by 8
        multiply_by_pow2(&copy2, 1);    // multiply by 2

        hobig_int_add(start, &copy2);   // sum the result

        array_free(copy2.value);        // free temporary
    }
}

void hobig_int_normalize(HoBigInt* n) {
    int i = 1;
    for(; i < array_length(n->value) && n->value[array_length(n->value) - i] == 0; ++i);
    i--;
    array_length(n->value) -= i;
}
static void 
multiply_and_add(u64 x, u64 y, u64 c, u64* rh, u64* rl) {
    u64 res_high = mul_word(x, y, rh);
    *rl = res_high + c;
	if (*rl < res_high) {
		(*rh)++;
	}
}

u64 multiply_and_add_vector(HoBigInt z, HoBigInt x, u64 y, u64 r) {
	u64 c = r;
	for (int i = 0; i < array_length(z.value); ++i) {
        multiply_and_add(x.value[i], y, c, &c, &z.value[i]);
	}
    return c;
}
HoBigInt 
hobig_int_mul(HoBigInt* x, HoBigInt* y) {
    TIME_COUNT();

    u64      result_length = array_length(x->value) + array_length(y->value);
    HoBigInt result = hobig_int_make(result_length);
    array_length(result.value) = result_length;

	for (u64 i = 0; i < array_length(y->value); ++i) {
        u64 d = y->value[i];
		if (d != 0) {
            u64 c = 0;

            for (u64 k = 0; k < array_length(x->value); ++k) {
                u64 h = 0, l = 0;
                multiply_and_add(x->value[k], d, (result.value + i)[k], &h, &l);
                c = add_u64(l, c, 0, &(result.value + i)[k]);
                c += h;
            }

            result.value[array_length(x->value) + i] = c;
		}
	}
    hobig_int_normalize(&result);

    TIME_END(TIME_SLOT_MULTIPLY);
	return result;
}

HoBigInt 
hobig_int_new_decimal(const char* number, unsigned int* error) {
    HoBigInt result = {0};
    if(error) *error = 0;

    int len = strlen(number);
    if(len == 0) {
        if(error) *error = 1;
        return result;
    }

    int sign = 0;
    int index = 0;
    if(number[index] == '-') {
        sign = 1;
        index++;
    }

    int first = number[len - 1] - 0x30;
    if(first < 0 || first > 9) {
        if(error) *error = 1;
        return result;
    }
    result.value = array_new(u64);
    array_push(result.value, first);

    // All digits to be used in multiplication
    HoBigInt digits[10] = { 0 };
    for(int i = 1; i < 10; ++i) {
        digits[i] = hobig_int_new(i);
    }

    // Powers of ten that will be used for every step
    HoBigInt powers_of_ten = hobig_int_new(1);

    for(int i = len - 2; i >= index; --i) {
        int n = number[i] - 0x30;
        if(n < 0 || n > 9) {
            // Not a decimal number
            if(error) *error = 1;
            break;
        }

        // Calculate n * 10^power
        // Start at 10^1

        // Generate the power of 10
        hobig_int_mul_pow10(&powers_of_ten, 1);

        // When the digit is 0, we still advance the powers of 10
        // but we do not attempt to sum up anything to the number
        if(n == 0) continue;

        // Grab a copy to be used to multiply by the digit value
        HoBigInt pow10val = hobig_int_copy(powers_of_ten);

        // Multiply by the digit value n
        HoBigInt rr = hobig_int_mul(&pow10val, &digits[n]);
        hobig_free(pow10val);
        pow10val = rr;

        // Sum it back to the final result
        hobig_int_add(&result, &pow10val);

        // Free temporary
        hobig_free(pow10val);
    }

    // Free digits
    for(int i = 1; i < 10; ++i) {
        hobig_free(digits[i]);
    }
    // Free suppor power of 10
    hobig_free(powers_of_ten);

    if(error && *error) {
        hobig_free(result);
    }

    result.negative = sign; // do it only now, to leave the sums positive

    return result;
}

// Same as dividing by 2^shift_amt
static void 
hobig_int_shr(HoBigInt* v, int shift_amt) {
    if(shift_amt == 0) return;
    int opposite = 64 - shift_amt;
    u64 mask = (0xffffffffffffffff << opposite);
    v->value[0] >>= shift_amt;

    for(u64 i = 1; i < array_length(v->value); ++i) {
        u64 current = v->value[i];
        v->value[i] >>= shift_amt;
        v->value[i - 1] |= (mask & (current << opposite));
    }
}

// Same as multiplying by 2^shift_amt
static void 
hobig_int_shl(HoBigInt* v, int shift_amt) {
    if(shift_amt == 0) return;
    int opposite = 64 - shift_amt;
    u64 mask = (0xffffffffffffffff >> opposite);
    u64 prev = 0;
    for(u64 i = 0; i < array_length(v->value); ++i) {
        u64 current = v->value[i];
        v->value[i] <<= shift_amt;
        v->value[i] |= prev;
        prev = (current >> opposite) & mask;
    }
}

// Use the euclidean algorithm to calculate GCD(a, b) (Greatest common divisor).
HoBigInt
hobig_int_gcd(HoBigInt* a, HoBigInt* b) {
    if(array_length(a->value) == 1 && *a->value == 0) {
        return hobig_int_copy(*b);
    }
    if(array_length(b->value) == 1 && *b->value == 0) {
        return hobig_int_copy(*a);
    }
    HoBigInt_DivResult d = hobig_int_div(a, b);
    return hobig_int_gcd(b, &d.remainder);
}

HoBigInt
hobig_random_bitcount(int nbits) {
    HoBigInt result = {0};
    if(nbits == 0) return hobig_int_new(0);

    int blocks = ((nbits + nbits % 64) / 64);
    u64 mask = 0xffffffffffffffff >> (64 - (nbits % 64));

    result = hobig_int_make(blocks);
    array_length(result.value) = blocks;
    for(int i = 0; i < blocks; ++i) {
        result.value[i] = random_64bit_integer();
    }
    result.value[blocks - 1] &= mask;
    return result;
}

HoBigInt
hobig_random(HoBigInt* max) {
    HoBigInt r = hobig_int_copy(*max);
    u64 m = r.value[array_length(r.value) - 1];
    u64 r0 = random_integer(0, m);
    r.value[array_length(r.value) - 1] = r0;

    for(int i = 0; i < array_length(r.value) - 1; ++i) {
        r.value[0] = random_64bit_integer();
    }

    assert(hobig_int_compare_absolute(max, &r) == 1);
    return r;
}

HoBigInt
hobig_int_mod_div(HoBigInt* n, HoBigInt* exp, HoBigInt* m) {
    HoBigInt answer = hobig_int_new(1);
    HoBigInt_DivResult r = hobig_int_div(n, m);

    HoBigInt base = r.remainder;
    hobig_free(r.quotient);

    HoBigInt e = hobig_int_copy(*exp);

	while (e.value[0] > 0) {
		if ((e.value[0] & 1) == 1) {
            HoBigInt nansw = hobig_int_mul(&answer, &base);
            hobig_free(answer);
            answer = nansw;
            
            HoBigInt_DivResult r = hobig_int_div(&answer, m);
            hobig_free(r.quotient);
			answer = r.remainder;
		}

        hobig_int_shr(&e, 1);

        HoBigInt sqbase = hobig_int_mul(&base, &base);
        hobig_free(base);
        base = sqbase;

        HoBigInt_DivResult bb = hobig_int_div(&base, m);
        hobig_free(bb.quotient);
        hobig_free(base);
        base = bb.remainder;
	}

    return answer;
}

/*
    Adapted from Golang's implementation of divLarge
    https://golang.org/src/math/big/nat.go#L687

    Knuth, Volume 2, section 4.3.1, Algorithm D.
 */
static HoBigInt_DivResult 
hobig_int_div_knuth(HoBigInt* u, HoBigInt* v) {
	assert(array_length(u->value) >= array_length(v->value));
    TIME_COUNT();
    HoBigInt_DivResult result = {0};

	int n = (int)array_length(v->value);
	int m = (int)array_length(u->value) - n;

	// D1
	int shift = hobig_int_leading_zeros_count(*v);

	HoBigInt v0 = hobig_int_copy(*v);
    hobig_int_shl(&v0, shift);

    HoBigInt u0 = hobig_int_copy(*u);
    array_push(u0.value, 0); // allocate 1 more word
    hobig_int_shl(&u0, shift);

    // Final quotient
    HoBigInt q = hobig_int_make(m + 1);
    array_length(q.value) = m + 1;

    HoBigInt qhatv = hobig_int_make(n + 1);
    array_length(qhatv.value) = n + 1;

    // D2
    u64 vn1 = v0.value[n - 1];

    for (int j = m; j >= 0; --j) {
		// D3
		u64 qhat = 0;
        u64 ujn = u0.value[j + n];
		if (ujn != vn1) {
            u64 rhat = 0;
            qhat = div_word(ujn, u0.value[j+n-1], vn1, &rhat);

			// x1 | x2 = q̂v_{n-2}
			u64 vn2 = v0.value[n-2];
            u64 x1 = 0;
            u64 x2 = mul_word(qhat, vn2, &x1);

			// test if q̂v_{n-2} > br̂ + u_{j+n-2}
			u64 ujn2 = u0.value[j+n-2];

            while (greater_than(x1, x2, rhat, ujn2)) {
				qhat--;
				u64 prevRhat = rhat;
				rhat += vn1;
				// v[n-1] >= 0, so this tests for overflow.
				if (rhat < prevRhat) {
					break;
				}
                x2 = mul_word(qhat, vn2, &x1);
			}
		}

		// D4.
        u64 prev_qhatlen = array_length(qhatv.value);
        array_length(qhatv.value) = n;
		qhatv.value[n] = multiply_and_add_vector(qhatv, v0, qhat, 0);
        array_length(qhatv.value) = prev_qhatlen;

        u64 c = sub_hobig_slice(u0.value + j, array_length(qhatv.value), u0.value + j, qhatv);
		if (c != 0) {
            c = add_hobig_slice(u0.value + j, n, u0.value + j, v0);
			u0.value[j+n] += c;
			qhat--;
		}

		q.value[j] = qhat;
	}

    hobig_free(qhatv);

    // normalize q
    hobig_int_normalize(&q);

    hobig_int_shr(&u0, shift);
    hobig_int_normalize(&u0);

    result.quotient = q;
    result.remainder = u0;

    TIME_END(TIME_SLOT_DIVIDE);
    return result;
}

HoBigInt_DivResult 
hobig_int_div(HoBigInt* u, HoBigInt* v) {
    HoBigInt_DivResult result = {0};

    switch(hobig_int_compare_absolute(u, v)) {
        case -1: {
            result.quotient = hobig_int_new(0);
            result.remainder = hobig_int_copy(*u);
            return result;
        }
        case 0: {
            result.quotient = hobig_int_new(1);
            result.remainder = hobig_int_new(0);
            return result;
        }
        case 1: break;
    }

    return hobig_int_div_knuth(u, v);
}