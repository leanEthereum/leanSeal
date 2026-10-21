// The chain step F_i(s) = SHA256(s || salt || be32(i)) of SPEC.md section 3, iterated.
//
// A state is eight 32-bit words: the state bytes are be32(st[0]) || ... || be32(st[7]),
// which is also how SHA-256 outputs its digest, so steps chain without byte swaps.
// Three backends compute the same function: ARMv8 SHA2 instructions, x86 SHA
// extensions, and portable C. run() is for one chain (solving, latency-bound);
// run_lanes() interleaves several independent chains (generation, throughput-bound).
#pragma once
#include <stdint.h>

#define CHAIN_MAX_LANES 4

// Message words W8..W12 of every step of one chain: the salt and the chain index.
typedef struct {
  uint32_t w[5];
} chain_tail;

void chain_tail_init(chain_tail *t, const uint8_t salt[16], uint32_t index);

typedef struct {
  const char *name;
  int lanes;  // chains to interleave per thread for best throughput
  void (*run)(uint32_t st[8], const chain_tail *t, uint64_t steps);
  // lanes in 1..CHAIN_MAX_LANES; lane l uses tails[l].
  void (*run_lanes)(uint32_t (*st)[8], const chain_tail *tails, int lanes, uint64_t steps);
} chain_backend;

// The fastest backend this CPU supports, unless the environment variable
// CHAINSEAL_BACKEND names another available one.
const chain_backend *chain_best(void);
// All backends this CPU supports, portable last. Returns how many were written.
int chain_backends(const chain_backend **out, int max);
