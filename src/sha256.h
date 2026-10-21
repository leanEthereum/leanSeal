// Portable SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and the labelled hash
// TH(label, x) = SHA256(u8(len(label)) || label || x) of SPEC.md section 1.
// Speed does not matter here: the chain steps have their own backends (chain.h).
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t h[8];
  uint64_t len;  // bytes absorbed so far
  uint8_t buf[64];
  size_t fill;
} sha256_ctx;

extern const uint32_t SHA256_K[64];
extern const uint32_t SHA256_IV[8];

void sha256_compress(uint32_t h[8], const uint8_t block[64]);
void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(uint8_t out[32], const void *data, size_t len);

void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t keylen, const void *msg, size_t len);

// Labelled hash over the concatenation of up to four parts; unused parts are NULL/0.
void th(uint8_t out[32], const char *label, const void *a, size_t alen, const void *b, size_t blen,
        const void *c, size_t clen, const void *d, size_t dlen);

// Constant-time equality of two byte strings of the same length.
int ct_equal(const uint8_t *a, const uint8_t *b, size_t len);
// Overwrite secrets in a way the compiler may not remove.
void secure_zero(void *p, size_t len);

static inline uint32_t load_be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline uint64_t load_be64(const uint8_t *p) { return (uint64_t)load_be32(p) << 32 | load_be32(p + 4); }
static inline void store_be32(uint8_t *p, uint32_t x) {
  p[0] = x >> 24, p[1] = x >> 16, p[2] = x >> 8, p[3] = x;
}
static inline void store_be64(uint8_t *p, uint64_t x) {
  store_be32(p, x >> 32);
  store_be32(p + 4, (uint32_t)x);
}
