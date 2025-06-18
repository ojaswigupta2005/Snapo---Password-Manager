#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct
{
    uint8_t data[64];  // Input data block
    uint32_t datalen;  // Current data length
    uint64_t bitlen;   // Total bit length of message
    uint32_t state[8]; // Hash state (A-H)
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);
void sha256_string(const char *str, char outputBuffer[65]);

#endif
