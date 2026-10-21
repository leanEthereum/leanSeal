#include "chain.h"

#include <stdlib.h>
#include <string.h>

#include "sha256.h"

void chain_tail_init(chain_tail *t, const uint8_t salt[16], uint32_t index) {
  for (int k = 0; k < 4; k++) t->w[k] = load_be32(salt + 4 * k);
  t->w[4] = index;
}

// Words W13..W15: padding for a 52-byte (416-bit) message.
#define PAD13 0x80000000u
#define PAD15 416u

// ---------------------------------------------------------------- portable

#define ROR(x, r) ((x) >> (r) | (x) << (32 - (r)))

static void step_portable(uint32_t st[8], const chain_tail *t) {
  uint32_t w[64];
  memcpy(w, st, 32);
  memcpy(w + 8, t->w, 20);
  w[13] = PAD13, w[14] = 0, w[15] = PAD15;
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = SHA256_IV[0], b = SHA256_IV[1], c = SHA256_IV[2], d = SHA256_IV[3];
  uint32_t e = SHA256_IV[4], f = SHA256_IV[5], g = SHA256_IV[6], h = SHA256_IV[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i];
    uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
  }
  st[0] = SHA256_IV[0] + a, st[1] = SHA256_IV[1] + b, st[2] = SHA256_IV[2] + c, st[3] = SHA256_IV[3] + d;
  st[4] = SHA256_IV[4] + e, st[5] = SHA256_IV[5] + f, st[6] = SHA256_IV[6] + g, st[7] = SHA256_IV[7] + h;
}

static void run_portable(uint32_t st[8], const chain_tail *t, uint64_t steps) {
  for (uint64_t j = 0; j < steps; j++) step_portable(st, t);
}

static void run_lanes_portable(uint32_t (*st)[8], const chain_tail *tails, int lanes, uint64_t steps) {
  for (int l = 0; l < lanes; l++) run_portable(st[l], &tails[l], steps);
}

static const chain_backend BACKEND_PORTABLE = {"portable", 1, run_portable, run_lanes_portable};

// ---------------------------------------------------------------- ARMv8 SHA2

#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)
#include <arm_neon.h>
#define HAVE_ARM 1

// Four rounds on every lane, then (optionally) the next four message words.
#define A_ROUND4(g, M)                                              \
  for (int l = 0; l < L; l++) {                                     \
    uint32x4_t wk = vaddq_u32(M[l], vld1q_u32(&SHA256_K[4 * (g)])); \
    uint32x4_t prev = s0[l];                                        \
    s0[l] = vsha256hq_u32(s0[l], s1[l], wk);                        \
    s1[l] = vsha256h2q_u32(s1[l], prev, wk);                        \
  }
#define A_SCHED(A, B, C, D) \
  for (int l = 0; l < L; l++) A[l] = vsha256su1q_u32(vsha256su0q_u32(A[l], B[l]), C[l], D[l]);

static inline __attribute__((always_inline)) void arm_steps(uint32x4_t *lo, uint32x4_t *hi, const uint32x4_t *t2,
                                                            const uint32x4_t *t3, const int L, uint64_t steps) {
  const uint32x4_t iv0 = vld1q_u32(SHA256_IV), iv1 = vld1q_u32(SHA256_IV + 4);
  uint32x4_t m0[CHAIN_MAX_LANES], m1[CHAIN_MAX_LANES], m2[CHAIN_MAX_LANES], m3[CHAIN_MAX_LANES];
  uint32x4_t s0[CHAIN_MAX_LANES], s1[CHAIN_MAX_LANES];
  for (uint64_t j = 0; j < steps; j++) {
    for (int l = 0; l < L; l++) {
      m0[l] = lo[l], m1[l] = hi[l], m2[l] = t2[l], m3[l] = t3[l];
      s0[l] = iv0, s1[l] = iv1;
    }
    A_ROUND4(0, m0) A_SCHED(m0, m1, m2, m3)
    A_ROUND4(1, m1) A_SCHED(m1, m2, m3, m0)
    A_ROUND4(2, m2) A_SCHED(m2, m3, m0, m1)
    A_ROUND4(3, m3) A_SCHED(m3, m0, m1, m2)
    A_ROUND4(4, m0) A_SCHED(m0, m1, m2, m3)
    A_ROUND4(5, m1) A_SCHED(m1, m2, m3, m0)
    A_ROUND4(6, m2) A_SCHED(m2, m3, m0, m1)
    A_ROUND4(7, m3) A_SCHED(m3, m0, m1, m2)
    A_ROUND4(8, m0) A_SCHED(m0, m1, m2, m3)
    A_ROUND4(9, m1) A_SCHED(m1, m2, m3, m0)
    A_ROUND4(10, m2) A_SCHED(m2, m3, m0, m1)
    A_ROUND4(11, m3) A_SCHED(m3, m0, m1, m2)
    A_ROUND4(12, m0)
    A_ROUND4(13, m1)
    A_ROUND4(14, m2)
    A_ROUND4(15, m3)
    for (int l = 0; l < L; l++) lo[l] = vaddq_u32(s0[l], iv0), hi[l] = vaddq_u32(s1[l], iv1);
  }
}

static inline __attribute__((always_inline)) void arm_run_L(uint32_t (*st)[8], const chain_tail *tails, const int L,
                                                            uint64_t steps) {
  uint32x4_t lo[CHAIN_MAX_LANES], hi[CHAIN_MAX_LANES], t2[CHAIN_MAX_LANES], t3[CHAIN_MAX_LANES];
  for (int l = 0; l < L; l++) {
    lo[l] = vld1q_u32(st[l]), hi[l] = vld1q_u32(st[l] + 4);
    const uint32_t w3[4] = {tails[l].w[4], PAD13, 0, PAD15};
    t2[l] = vld1q_u32(tails[l].w), t3[l] = vld1q_u32(w3);
  }
  arm_steps(lo, hi, t2, t3, L, steps);
  for (int l = 0; l < L; l++) vst1q_u32(st[l], lo[l]), vst1q_u32(st[l] + 4, hi[l]);
}

static void run_arm(uint32_t st[8], const chain_tail *t, uint64_t steps) {
  arm_run_L((uint32_t(*)[8])st, t, 1, steps);
}

static void run_lanes_arm(uint32_t (*st)[8], const chain_tail *tails, int lanes, uint64_t steps) {
  for (int l = 0; l < lanes; l += 2) {
    if (lanes - l >= 2)
      arm_run_L(st + l, tails + l, 2, steps);
    else
      arm_run_L(st + l, tails + l, 1, steps);
  }
}

// Two interleaved chains already saturate an Apple M4 core (65 M steps/s against
// 42 M for one chain; more lanes add nothing), and small groups balance better.
static const chain_backend BACKEND_ARM = {"armv8-sha2", 2, run_arm, run_lanes_arm};
#endif

// ---------------------------------------------------------------- x86 SHA extensions

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <cpuid.h>
#include <immintrin.h>
#define HAVE_SHANI 1
#define SHANI_TARGET __attribute__((target("sha,sse4.1,ssse3")))
#include "chain_shani.h"

SHANI_TARGET static void run_shani(uint32_t st[8], const chain_tail *t, uint64_t steps) {
  shani_run_L((uint32_t(*)[8])st, t, 1, steps);
}

SHANI_TARGET static void run_lanes_shani(uint32_t (*st)[8], const chain_tail *tails, int lanes, uint64_t steps) {
  for (int l = 0; l < lanes; l += 2) {
    if (lanes - l >= 2)
      shani_run_L(st + l, tails + l, 2, steps);
    else
      shani_run_L(st + l, tails + l, 1, steps);
  }
}

static int cpu_has_shani(void) {
  unsigned a, b, c, d;
  if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
  if (!(c & (1u << 19)) || !(c & (1u << 9))) return 0;  // SSE4.1, SSSE3
  if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return 0;
  return (b >> 29) & 1;  // SHA
}

static const chain_backend BACKEND_SHANI = {"x86-sha-ni", 2, run_shani, run_lanes_shani};
#endif

// ---------------------------------------------------------------- selection

int chain_backends(const chain_backend **out, int max) {
  int k = 0;
#ifdef HAVE_ARM
  if (k < max) out[k++] = &BACKEND_ARM;
#endif
#ifdef HAVE_SHANI
  if (k < max && cpu_has_shani()) out[k++] = &BACKEND_SHANI;
#endif
  if (k < max) out[k++] = &BACKEND_PORTABLE;
  return k;
}

const chain_backend *chain_best(void) {
  const chain_backend *all[4];
  int k = chain_backends(all, 4);
  const char *want = getenv("CHAINSEAL_BACKEND");
  if (want)
    for (int i = 0; i < k; i++)
      if (!strcmp(all[i]->name, want)) return all[i];
  return all[0];
}
