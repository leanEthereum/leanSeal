// Randomness for salts, links and nonces. rng_os() is the only source for real
// use; rng_test() is a deterministic generator for test vectors and must never
// protect anything.
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
  int deterministic;
  uint8_t seed[32];
  uint64_t counter;
} cs_rng;

void rng_os(cs_rng *r);
void rng_test(cs_rng *r, const void *seed, size_t len);
// Returns 0 on success.
int rng_bytes(cs_rng *r, uint8_t *out, size_t len);
