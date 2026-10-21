// The x86 SHA-NI chain step, shared by chain.c (real intrinsics) and
// tests/shani_emu.c (intrinsics emulated from the Intel SDM definitions, so the
// logic can be tested on machines without SHA-NI). The includer provides
// __m128i, the intrinsics, SHANI_TARGET, PAD13 and PAD15.
#pragma once
#include "chain.h"
#include "sha256.h"

// The SHA-NI round instruction keeps the state as ABEF and CDGH; the message
// words, and our stored state, are in natural order (lane 0 = word 0).
// Between steps we convert the digest back to natural order, which is the
// message of the next step.
#define X_ROUNDS(g, M)                                                             \
  for (int l = 0; l < L; l++) {                                                    \
    wk[l] = _mm_add_epi32(M[l], _mm_loadu_si128((const __m128i *)&SHA256_K[4 * (g)])); \
    S1[l] = _mm_sha256rnds2_epu32(S1[l], S0[l], wk[l]);                             \
  }
#define X_ROUNDS_HI()                                                    \
  for (int l = 0; l < L; l++) {                                          \
    wk[l] = _mm_shuffle_epi32(wk[l], 0x0E);                              \
    S0[l] = _mm_sha256rnds2_epu32(S0[l], S1[l], wk[l]);                  \
  }
#define X_MSG2(Mc, Mn, Mp) \
  for (int l = 0; l < L; l++) Mn[l] = _mm_sha256msg2_epu32(_mm_add_epi32(Mn[l], _mm_alignr_epi8(Mc[l], Mp[l], 4)), Mc[l]);
#define X_MSG1(Mc, Mp) \
  for (int l = 0; l < L; l++) Mp[l] = _mm_sha256msg1_epu32(Mp[l], Mc[l]);

// One group of four rounds g, with message Mc = W[4g..4g+3]; Mn and Mp are the
// next and previous message registers. msg2 runs for g = 3..14, msg1 for g = 1..12.
#define X_GROUP(g, Mc, Mn, Mp)            \
  X_ROUNDS(g, Mc)                         \
  if ((g) >= 3 && (g) <= 14) { X_MSG2(Mc, Mn, Mp) } \
  X_ROUNDS_HI()                           \
  if ((g) >= 1 && (g) <= 12) { X_MSG1(Mc, Mp) }

SHANI_TARGET static inline __attribute__((always_inline)) void shani_steps(__m128i *lo, __m128i *hi, const __m128i *t2,
                                                                           const __m128i *t3, const int L,
                                                                           uint64_t steps) {
  // IV in ABEF / CDGH order.
  __m128i a = _mm_loadu_si128((const __m128i *)SHA256_IV), e = _mm_loadu_si128((const __m128i *)(SHA256_IV + 4));
  a = _mm_shuffle_epi32(a, 0xB1);  // CDAB
  e = _mm_shuffle_epi32(e, 0x1B);  // EFGH
  const __m128i IV0 = _mm_alignr_epi8(a, e, 8);     // ABEF
  const __m128i IV1 = _mm_blend_epi16(e, a, 0xF0);  // CDGH
  __m128i M0[CHAIN_MAX_LANES], M1[CHAIN_MAX_LANES], M2[CHAIN_MAX_LANES], M3[CHAIN_MAX_LANES];
  __m128i S0[CHAIN_MAX_LANES], S1[CHAIN_MAX_LANES], wk[CHAIN_MAX_LANES];
  for (uint64_t j = 0; j < steps; j++) {
    for (int l = 0; l < L; l++) {
      M0[l] = lo[l], M1[l] = hi[l], M2[l] = t2[l], M3[l] = t3[l];
      S0[l] = IV0, S1[l] = IV1;
    }
    X_GROUP(0, M0, M1, M3)
    X_GROUP(1, M1, M2, M0)
    X_GROUP(2, M2, M3, M1)
    X_GROUP(3, M3, M0, M2)
    X_GROUP(4, M0, M1, M3)
    X_GROUP(5, M1, M2, M0)
    X_GROUP(6, M2, M3, M1)
    X_GROUP(7, M3, M0, M2)
    X_GROUP(8, M0, M1, M3)
    X_GROUP(9, M1, M2, M0)
    X_GROUP(10, M2, M3, M1)
    X_GROUP(11, M3, M0, M2)
    X_GROUP(12, M0, M1, M3)
    X_GROUP(13, M1, M2, M0)
    X_GROUP(14, M2, M3, M1)
    X_GROUP(15, M3, M0, M2)
    for (int l = 0; l < L; l++) {
      __m128i abef = _mm_add_epi32(S0[l], IV0), cdgh = _mm_add_epi32(S1[l], IV1);
      __m128i feba = _mm_shuffle_epi32(abef, 0x1B), dchg = _mm_shuffle_epi32(cdgh, 0xB1);
      lo[l] = _mm_blend_epi16(feba, dchg, 0xF0);  // A B C D in lanes 0..3
      hi[l] = _mm_alignr_epi8(dchg, feba, 8);     // E F G H
    }
  }
}

SHANI_TARGET static inline __attribute__((always_inline)) void shani_run_L(uint32_t (*st)[8], const chain_tail *tails,
                                                                           const int L, uint64_t steps) {
  __m128i lo[CHAIN_MAX_LANES], hi[CHAIN_MAX_LANES], t2[CHAIN_MAX_LANES], t3[CHAIN_MAX_LANES];
  for (int l = 0; l < L; l++) {
    lo[l] = _mm_loadu_si128((const __m128i *)st[l]), hi[l] = _mm_loadu_si128((const __m128i *)(st[l] + 4));
    t2[l] = _mm_loadu_si128((const __m128i *)tails[l].w);
    t3[l] = _mm_setr_epi32((int)tails[l].w[4], (int)PAD13, 0, (int)PAD15);
  }
  shani_steps(lo, hi, t2, t3, L, steps);
  for (int l = 0; l < L; l++) {
    _mm_storeu_si128((__m128i *)st[l], lo[l]);
    _mm_storeu_si128((__m128i *)(st[l] + 4), hi[l]);
  }
}
