#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BIG_ENDIAN_32(X) (((X) << 24) | (((X) << 8) & 0xff0000) | (((X) >> 8) & 0xff00) | ((X) >> 24))

#define SHA1_BLOCK_INTS 16

static uint64_t 
u32_to_str_base16(uint32_t value, int leading_zeros, char* buffer)
{
    int i = 0;
    for (; i < 8; i += 1) {
        uint32_t f = (value & 0xf0000000) >> 28;
        if(f > 9) buffer[i] = (char)f + 0x57;
        else buffer[i] = (char)f + 0x30;
        value <<= 4;
    }
    return i;
}

/*
    -----------------------------------
    -------------- SHA1 ---------------
    -----------------------------------
 */

static void 
sha1_buffer_to_block(const unsigned char* buffer, int length, uint32_t block[16]) {
    for (uint64_t i = 0; i < SHA1_BLOCK_INTS; i += 1) {
        block[i] = ((uint32_t)(buffer[4*i+3] & 0xff) | ((uint32_t)(buffer[4*i+2] & 0xff)<<8)
            | ((uint32_t)(buffer[4*i+1] & 0xff)<<16)
            | ((uint32_t)(buffer[4*i+0] & 0xff)<<24));
    }
}

static uint32_t 
rol(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32 - bits));
}

static uint32_t 
blk(uint32_t block[16], uint32_t i) {
    return rol(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i], 1);
}

static void 
R0(uint32_t block[16], uint32_t v, uint32_t* w, uint32_t x, uint32_t y, uint32_t* z, uint64_t i) {
    // not checking lvalue here
    *z += ((*w&(x^y))^y) + block[i] + 0x5a827999 + rol(v, 5);
    *w = rol(*w, 30);
}

static void 
R1(uint32_t block[16], uint32_t v, uint32_t* w, uint32_t x, uint32_t y, uint32_t* z, uint64_t i) {
    block[i] = blk(block, (uint32_t)i);
    *z += ((*w&(x^y))^y) + block[i] + 0x5a827999 + rol(v, 5);
    *w = rol(*w, 30);
}


static void 
R2(uint32_t block[16], uint32_t v, uint32_t* w, uint32_t x, uint32_t y, uint32_t* z, uint64_t i) {
    block[i] = blk(block, (uint32_t)i);
    *z += (*w^x^y) + block[i] + 0x6ed9eba1 + rol(v, 5);
    *w = rol(*w, 30);
}

static void 
R3(uint32_t block[16], uint32_t v, uint32_t* w, uint32_t x, uint32_t y, uint32_t* z, uint64_t i) {
    block[i] = blk(block, (uint32_t)i);
    *z += (((*w|x)&y)|(*w&x)) + block[i] + 0x8f1bbcdc + rol(v, 5);
    *w = rol(*w, 30);
}

static void 
R4(uint32_t block[16], uint32_t v, uint32_t* w, uint32_t x, uint32_t y, uint32_t* z, uint64_t i) {
    block[i] = blk(block, (uint32_t)i);
    *z += (*w^x^y) + block[i] + 0xca62c1d6 + rol(v, 5);
    *w = rol(*w, 30);
}

static void 
sha1_transform(uint32_t digest[5], uint32_t block[16]) {
    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];
 
    R0(block, a, &b, c, d, &e,  0);
    R0(block, e, &a, b, c, &d,  1);
    R0(block, d, &e, a, b, &c,  2);
    R0(block, c, &d, e, a, &b,  3);
    R0(block, b, &c, d, e, &a,  4);
    R0(block, a, &b, c, d, &e,  5);
    R0(block, e, &a, b, c, &d,  6);
    R0(block, d, &e, a, b, &c,  7);
    R0(block, c, &d, e, a, &b,  8);
    R0(block, b, &c, d, e, &a,  9);
    R0(block, a, &b, c, d, &e, 10);
    R0(block, e, &a, b, c, &d, 11);
    R0(block, d, &e, a, b, &c, 12);
    R0(block, c, &d, e, a, &b, 13);
    R0(block, b, &c, d, e, &a, 14);
    R0(block, a, &b, c, d, &e, 15);
    R1(block, e, &a, b, c, &d,  0);
    R1(block, d, &e, a, b, &c,  1);
    R1(block, c, &d, e, a, &b,  2);
    R1(block, b, &c, d, e, &a,  3);
    R2(block, a, &b, c, d, &e,  4);
    R2(block, e, &a, b, c, &d,  5);
    R2(block, d, &e, a, b, &c,  6);
    R2(block, c, &d, e, a, &b,  7);
    R2(block, b, &c, d, e, &a,  8);
    R2(block, a, &b, c, d, &e,  9);
    R2(block, e, &a, b, c, &d, 10);
    R2(block, d, &e, a, b, &c, 11);
    R2(block, c, &d, e, a, &b, 12);
    R2(block, b, &c, d, e, &a, 13);
    R2(block, a, &b, c, d, &e, 14);
    R2(block, e, &a, b, c, &d, 15);
    R2(block, d, &e, a, b, &c,  0);
    R2(block, c, &d, e, a, &b,  1);
    R2(block, b, &c, d, e, &a,  2);
    R2(block, a, &b, c, d, &e,  3);
    R2(block, e, &a, b, c, &d,  4);
    R2(block, d, &e, a, b, &c,  5);
    R2(block, c, &d, e, a, &b,  6);
    R2(block, b, &c, d, e, &a,  7);
    R3(block, a, &b, c, d, &e,  8);
    R3(block, e, &a, b, c, &d,  9);
    R3(block, d, &e, a, b, &c, 10);
    R3(block, c, &d, e, a, &b, 11);
    R3(block, b, &c, d, e, &a, 12);
    R3(block, a, &b, c, d, &e, 13);
    R3(block, e, &a, b, c, &d, 14);
    R3(block, d, &e, a, b, &c, 15);
    R3(block, c, &d, e, a, &b,  0);
    R3(block, b, &c, d, e, &a,  1);
    R3(block, a, &b, c, d, &e,  2);
    R3(block, e, &a, b, c, &d,  3);
    R3(block, d, &e, a, b, &c,  4);
    R3(block, c, &d, e, a, &b,  5);
    R3(block, b, &c, d, e, &a,  6);
    R3(block, a, &b, c, d, &e,  7);
    R3(block, e, &a, b, c, &d,  8);
    R3(block, d, &e, a, b, &c,  9);
    R3(block, c, &d, e, a, &b, 10);
    R3(block, b, &c, d, e, &a, 11);
    R4(block, a, &b, c, d, &e, 12);
    R4(block, e, &a, b, c, &d, 13);
    R4(block, d, &e, a, b, &c, 14);
    R4(block, c, &d, e, a, &b, 15);
    R4(block, b, &c, d, e, &a,  0);
    R4(block, a, &b, c, d, &e,  1);
    R4(block, e, &a, b, c, &d,  2);
    R4(block, d, &e, a, b, &c,  3);
    R4(block, c, &d, e, a, &b,  4);
    R4(block, b, &c, d, e, &a,  5);
    R4(block, a, &b, c, d, &e,  6);
    R4(block, e, &a, b, c, &d,  7);
    R4(block, d, &e, a, b, &c,  8);
    R4(block, c, &d, e, a, &b,  9);
    R4(block, b, &c, d, e, &a, 10);
    R4(block, a, &b, c, d, &e, 11);
    R4(block, e, &a, b, c, &d, 12);
    R4(block, d, &e, a, b, &c, 13);
    R4(block, c, &d, e, a, &b, 14);
    R4(block, b, &c, d, e, &a, 15);

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
}

void 
rawhttps_sha1(const unsigned char* buffer, int length, unsigned char out[20]) {
    uint32_t digest[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint32_t block[16] = {0};

    uint64_t total_bits = length * 8;

    // for each 64 bit chunk do
    for(int i = 0; i < length / 64; ++i) {
        sha1_buffer_to_block(buffer, 64, block);
        sha1_transform(digest, block);
        buffer += 64;
    }

    unsigned char last_buffer[64] = {0};

    // n is the amount of bytes still left
    int n = length % 64;
    // copy it to the buffer with padding
    memcpy(last_buffer, buffer, n);

    last_buffer[n++] = 0x80; // this is safe, since n <= 63

    if(n > 56) {
        // there is no more space to put the length
        sha1_buffer_to_block(last_buffer, n, block);
        sha1_transform(digest, block);
        memset(last_buffer, 0, 64);
        sha1_buffer_to_block(last_buffer, n, block);
        block[SHA1_BLOCK_INTS - 1] = (uint32_t)total_bits;
        block[SHA1_BLOCK_INTS - 2] = (uint32_t)(total_bits >> 32);
        sha1_transform(digest, block);
    } else {
        // there is still space
        sha1_buffer_to_block(last_buffer, n, block);

        block[SHA1_BLOCK_INTS - 1] = (uint32_t)total_bits;
        block[SHA1_BLOCK_INTS - 2] = (uint32_t)(total_bits >> 32);
        sha1_transform(digest, block);
    }

    ((uint32_t*)out)[0] = BIG_ENDIAN_32(digest[0]);
    ((uint32_t*)out)[1] = BIG_ENDIAN_32(digest[1]);
    ((uint32_t*)out)[2] = BIG_ENDIAN_32(digest[2]);
    ((uint32_t*)out)[3] = BIG_ENDIAN_32(digest[3]);
    ((uint32_t*)out)[4] = BIG_ENDIAN_32(digest[4]);
}

void 
rawhttps_sha1_to_string(unsigned char in[20], unsigned char out[40]) {
    const int SHA1_DIGEST_SIZE = 5;
    for (uint64_t i = 0; i < SHA1_DIGEST_SIZE; i += 1) {
        uint32_t v = ((uint32_t*)in)[i];
        u32_to_str_base16(BIG_ENDIAN_32(v), 1, (char*)out + (i * 8));
    }
}

/*
    --------------------------------------
    -------------- SHA 256 ---------------
    --------------------------------------
 */

static uint32_t 
sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void 
sha256_transform(const unsigned char* buffer, uint32_t digest[8], uint32_t ms[64]) {
    #define ROL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
    #define ROR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
    #define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
    #define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
    #define EP0(x) (ROR(x,2) ^ ROR(x,13) ^ ROR(x,22))
    #define EP1(x) (ROR(x,6) ^ ROR(x,11) ^ ROR(x,25))
    #define S0(x) (ROR(x,7) ^ ROR(x,18) ^ ((x) >> 3))
    #define S1(x) (ROR(x,17) ^ ROR(x,19) ^ ((x) >> 10))

    for(int i = 0; i < 16; ++i) {
        ms[i] = BIG_ENDIAN_32(((uint32_t*)buffer)[i]);
    }
    for(int i = 16; i < 64; ++i) {
        ms[i] = S1(ms[i - 2]) + ms[i - 7] + S0(ms[i - 15]) + ms[i - 16];
    }

    uint32_t a = digest[0];
	uint32_t b = digest[1];
	uint32_t c = digest[2];
	uint32_t d = digest[3];
	uint32_t e = digest[4];
	uint32_t f = digest[5];
	uint32_t g = digest[6];
	uint32_t h = digest[7];

    for (int i = 0; i < 64; ++i) {
		uint32_t t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + ms[i];
		uint32_t t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
	digest[5] += f;
	digest[6] += g;
	digest[7] += h;
}

void 
rawhttps_sha256(const unsigned char* buffer, int length, unsigned char out[32]) {
    uint64_t total_bits = length * 8;

    uint32_t digest[8] = { 
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint32_t message_schedule[64] = {0};

    // for each 64 bit chunk do
    for(int i = 0; i < length / 64; ++i) {
        sha256_transform(buffer, digest, message_schedule);
        buffer += 64;
    }

    unsigned char last_buffer[64] = {0};
    // n is the amount of bytes still left
    int n = length % 64;
    // copy it to the buffer with padding
    memcpy(last_buffer, buffer, n);

    last_buffer[n++] = 0x80;

    if(n > 56) {
        // there is no more space to put the length
        sha256_transform(last_buffer, digest, message_schedule);
        memset(last_buffer, 0, 64);
        ((uint32_t*)last_buffer)[16 - 1] = BIG_ENDIAN_32((uint32_t)total_bits);
        ((uint32_t*)last_buffer)[16 - 2] = BIG_ENDIAN_32((uint32_t)(total_bits >> 32));
        sha256_transform(last_buffer, digest, message_schedule);
    } else {
        // there is still space
        ((uint32_t*)last_buffer)[16 - 1] = BIG_ENDIAN_32((uint32_t)total_bits);
        ((uint32_t*)last_buffer)[16 - 2] = BIG_ENDIAN_32((uint32_t)(total_bits >> 32));
        sha256_transform(last_buffer, digest, message_schedule);
    }

    ((uint32_t*)out)[0] = BIG_ENDIAN_32(digest[0]);
    ((uint32_t*)out)[1] = BIG_ENDIAN_32(digest[1]);
    ((uint32_t*)out)[2] = BIG_ENDIAN_32(digest[2]);
    ((uint32_t*)out)[3] = BIG_ENDIAN_32(digest[3]);
    ((uint32_t*)out)[4] = BIG_ENDIAN_32(digest[4]);
    ((uint32_t*)out)[5] = BIG_ENDIAN_32(digest[5]);
    ((uint32_t*)out)[6] = BIG_ENDIAN_32(digest[6]);
    ((uint32_t*)out)[7] = BIG_ENDIAN_32(digest[7]);
}

void 
rawhttps_sha256_to_string(unsigned char in[32], unsigned char out[64]) {
    const int SHA256_DIGEST_SIZE = 8;
    for (uint64_t i = 0; i < SHA256_DIGEST_SIZE; i += 1) {
        uint32_t v = ((uint32_t*)in)[i];
        u32_to_str_base16(BIG_ENDIAN_32(v), 1, (char*)out + (i * 8));
    }
}


/*
    ---------------------------------------
    ----------------- MD5 -----------------
    ---------------------------------------
 */

#define MD5_BLOCK_INTS 16

static uint32_t md5_r[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};
static uint32_t md5_k[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

void md5_buffer_to_block(unsigned char* buffer, uint32_t block[16]) {
    for (uint64_t i = 0; i < MD5_BLOCK_INTS; i += 1) {
        block[i] = ((uint32_t)(buffer[4*i+3] & 0xff) | ((uint32_t)(buffer[4*i+2] & 0xff)<<8)
            | ((uint32_t)(buffer[4*i+1] & 0xff)<<16)
            | ((uint32_t)(buffer[4*i+0] & 0xff)<<24));
    }
}

static void 
md5_transform(uint32_t digest[4], uint32_t block[16]) {
    uint32_t A = digest[0];
    uint32_t B = digest[1];
    uint32_t C = digest[2];
    uint32_t D = digest[3];

    for (int i = 0; i < 64; i += 1) {
        uint32_t F = 0;
        uint32_t g = 0;

        if (i >= 0 && i <= 15) {
            F = (B & C) | ((~B) & D);
            g = i;
        } else if (i < 32) {
            F = (D & B) | ((~D) & C);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            F = B ^ C ^ D;
            g = (3 * i + 5) % 16;
        } else {
            F = C ^ (B | (~D));
            g = (7 * i) % 16;
        }
        F = F + A + md5_k[i] + block[g];
        uint32_t temp = D;
        D = C;
        C = B;
        B = B + ROL(F, md5_r[i]);
        A = temp;
    }
    //Add this chunk's hash to result so far:
    digest[0] += A;
    digest[1] += B;
    digest[2] += C;
    digest[3] += D;
}

void 
rawhttps_md5(const unsigned char* buffer, int length, unsigned char out[16]) {
    uint32_t digest[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    uint32_t block[16] = {0};

    uint64_t total_bits = length * 8;

    // for each 64 bit chunk do
    for(int i = 0; i < length / 64; ++i) {
        memcpy(block, buffer, 64);
        md5_transform(digest, block);
        buffer += 64;
    }

    unsigned char last_buffer[64] = {0};

    // n is the amount of bytes still left
    int n = length % 64;
    // copy it to the buffer with padding
    memcpy(last_buffer, buffer, n);

    last_buffer[n++] = 0x80; // this is safe, since n <= 63

    if(n > 56) {
        // there is no more space to put the length
        memcpy(block, last_buffer, 64);
        md5_transform(digest, block);
        memset(last_buffer, 0, 64);
        memcpy(block, last_buffer, 64);
        block[MD5_BLOCK_INTS - 1] = (uint32_t)(total_bits >> 32);
        block[MD5_BLOCK_INTS - 2] = (uint32_t)(total_bits);
        md5_transform(digest, block);
    } else {
        // there is still space
        //buffer_to_block(last_buffer, block);
        memcpy(block, last_buffer, 64);

        block[MD5_BLOCK_INTS - 1] = (uint32_t)(total_bits >> 32);
        block[MD5_BLOCK_INTS - 2] = (uint32_t)(total_bits);
        md5_transform(digest, block);
    }

    ((uint32_t*)out)[0] = digest[0];
    ((uint32_t*)out)[1] = digest[1];
    ((uint32_t*)out)[2] = digest[2];
    ((uint32_t*)out)[3] = digest[3];
}

void 
rawhttps_md5_to_string(unsigned char in[16], unsigned char out[32]) {
    const int MD5_DIGEST_SIZE = 4;
    for (uint64_t i = 0; i < MD5_DIGEST_SIZE; i += 1) {
        uint32_t v = ((uint32_t*)in)[i];
        u32_to_str_base16(BIG_ENDIAN_32(v), 1, (char*)out + (i * 8));
    }
}