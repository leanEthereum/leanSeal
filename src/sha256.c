#include "sha256.h"

#include <string.h>

const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

const uint32_t SHA256_IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

#define ROR(x, r) ((x) >> (r) | (x) << (32 - (r)))

void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
  uint32_t w[64];
  for (int t = 0; t < 16; t++) w[t] = load_be32(block + 4 * t);
  for (int t = 16; t < 64; t++) {
    uint32_t s0 = ROR(w[t - 15], 7) ^ ROR(w[t - 15], 18) ^ (w[t - 15] >> 3);
    uint32_t s1 = ROR(w[t - 2], 17) ^ ROR(w[t - 2], 19) ^ (w[t - 2] >> 10);
    w[t] = w[t - 16] + s0 + w[t - 7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
  for (int t = 0; t < 64; t++) {
    uint32_t t1 = k + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[t] + w[t];
    uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    k = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
  }
  h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e, h[5] += f, h[6] += g, h[7] += k;
}

void sha256_init(sha256_ctx *c) {
  memcpy(c->h, SHA256_IV, sizeof c->h);
  c->len = 0;
  c->fill = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len) {
  const uint8_t *p = data;
  c->len += len;
  while (len > 0) {
    size_t take = 64 - c->fill < len ? 64 - c->fill : len;
    memcpy(c->buf + c->fill, p, take);
    c->fill += take, p += take, len -= take;
    if (c->fill == 64) {
      sha256_compress(c->h, c->buf);
      c->fill = 0;
    }
  }
}

void sha256_final(sha256_ctx *c, uint8_t out[32]) {
  uint64_t bits = c->len * 8;
  uint8_t pad[72] = {0x80};
  size_t padlen = (c->fill < 56 ? 56 : 120) - c->fill;
  store_be64(pad + padlen, bits);
  sha256_update(c, pad, padlen + 8);
  for (int k = 0; k < 8; k++) store_be32(out + 4 * k, c->h[k]);
  secure_zero(c, sizeof *c);
}

void sha256(uint8_t out[32], const void *data, size_t len) {
  sha256_ctx c;
  sha256_init(&c);
  sha256_update(&c, data, len);
  sha256_final(&c, out);
}

void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t keylen, const void *msg, size_t len) {
  uint8_t k[64] = {0}, pad[64], inner[32];
  if (keylen > 64)
    sha256(k, key, keylen);
  else
    memcpy(k, key, keylen);
  sha256_ctx c;
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
  sha256_init(&c);
  sha256_update(&c, pad, 64);
  sha256_update(&c, msg, len);
  sha256_final(&c, inner);
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
  sha256_init(&c);
  sha256_update(&c, pad, 64);
  sha256_update(&c, inner, 32);
  sha256_final(&c, out);
  secure_zero(k, sizeof k), secure_zero(pad, sizeof pad), secure_zero(inner, sizeof inner);
}

void th(uint8_t out[32], const char *label, const void *a, size_t alen, const void *b, size_t blen,
        const void *c, size_t clen, const void *d, size_t dlen) {
  size_t ll = strlen(label);
  uint8_t l8 = (uint8_t)ll;
  sha256_ctx s;
  sha256_init(&s);
  sha256_update(&s, &l8, 1);
  sha256_update(&s, label, ll);
  if (alen) sha256_update(&s, a, alen);
  if (blen) sha256_update(&s, b, blen);
  if (clen) sha256_update(&s, c, clen);
  if (dlen) sha256_update(&s, d, dlen);
  sha256_final(&s, out);
}

int ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

void secure_zero(void *p, size_t len) {
  volatile uint8_t *v = p;
  while (len--) *v++ = 0;
}
