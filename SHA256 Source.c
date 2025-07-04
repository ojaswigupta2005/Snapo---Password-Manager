#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Right Rotation
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

// SHA functions
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))               // choose(chooses from y or z depending on x)
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) // majority
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))   // to calculate W
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10)) // to calculate W

// hexadecimal of 1st 32 bits of the decimal of cube roots of 1st 64 primes
// consts defined by SHA-256
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

typedef struct
{
    uint8_t data[64];  // whole 512 bit block
    uint32_t datalen;  // current length
    uint64_t bitlen;   // input length in bits
    uint32_t state[8]; // Hash state(H0 TO H7)
} SHA256_CTX;

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    // breaking into 16 32-bit words
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) |
               (data[j + 2] << 8) | (data[j + 3]);
    // calculating further Ws
    for (; i < 64; ++i) // semicolon tells to start where i left off earlier(W15...W16,W17)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    // initialize hash values
    // hexadecimal of 1st 32 bits of the decimal of sqrt of 1st 8 primes
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // main compression loop
    // calculating the ts
    for (i = 0; i < 64; ++i)
    {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // adding compressed prt to original hash values
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;

    // initial hash values
    // sqrt of 1st 8 prime no.s ke decimal ka 32 bits
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// processe in 512-bit blocks
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len)
{
    for (uint32_t i = 0; i < len; ++i)
    {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64)
        {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

// finalizing the hash value
void sha256_final(SHA256_CTX *ctx, uint8_t hash[])
{
    uint32_t i = ctx->datalen;

    // Padding i.e. adding 0s till the 512-xth element
    if (ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    // storing in form of 8 bits ke pieces
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    // Copy final state to hash
    for (i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 8; ++j)
            hash[i + (j * 4)] = (ctx->state[j] >> (24 - i * 8)) & 0x000000ff;
    }
}

void sha256_string(const char *str, char outputBuffer[65])
{
    uint8_t hash[32];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)str, strlen(str));
    sha256_final(&ctx, hash);

    for (int i = 0; i < 32; ++i)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);

    outputBuffer[64] = 0; // null terminator
}