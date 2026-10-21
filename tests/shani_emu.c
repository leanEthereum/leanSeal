// Runs the x86 SHA-NI chain step (src/chain_shani.h) on any machine, with the
// intrinsics it uses emulated in C from their definitions in the Intel SDM, and
// checks it against plain SHA-256. This tests the SHA-NI logic (the ABEF/CDGH
// state layout and the message schedule); it cannot catch compiler or CPU issues,
// which only a run on x86 hardware can.
#include <stdio.h>
#include <string.h>

#include "chain.h"
#include "rng.h"
#include "sha256.h"

typedef struct {
  uint32_t l[4];  // lane i is bits 32i+31 .. 32i
} __m128i;

#define SHANI_TARGET
#define PAD13 0x80000000u
#define PAD15 416u
#define ROR(x, r) ((x) >> (r) | (x) << (32 - (r)))

static __m128i _mm_loadu_si128(const __m128i *p) {
  __m128i r;
  memcpy(&r, p, 16);
  return r;
}
static void _mm_storeu_si128(__m128i *p, __m128i a) { memcpy(p, &a, 16); }
static __m128i _mm_setr_epi32(int e0, int e1, int e2, int e3) {
  return (__m128i){{(uint32_t)e0, (uint32_t)e1, (uint32_t)e2, (uint32_t)e3}};
}
static __m128i _mm_add_epi32(__m128i a, __m128i b) {
  for (int i = 0; i < 4; i++) a.l[i] += b.l[i];
  return a;
}
static __m128i _mm_shuffle_epi32(__m128i a, int imm) {
  __m128i r;
  for (int i = 0; i < 4; i++) r.l[i] = a.l[(imm >> (2 * i)) & 3];
  return r;
}
// The 32-byte concatenation a:b (b in the low half) shifted right by imm bytes.
static __m128i _mm_alignr_epi8(__m128i a, __m128i b, int imm) {
  uint8_t t[32];
  __m128i r;
  memcpy(t, &b, 16), memcpy(t + 16, &a, 16);
  memcpy(&r, t + imm, 16);
  return r;
}
// 16-bit element j comes from b if bit j of imm is set, else from a.
static __m128i _mm_blend_epi16(__m128i a, __m128i b, int imm) {
  uint16_t x[8], y[8];
  memcpy(x, &a, 16), memcpy(y, &b, 16);
  for (int j = 0; j < 8; j++)
    if (imm >> j & 1) x[j] = y[j];
  memcpy(&a, x, 16);
  return a;
}

// SHA256RNDS2: a = SRC1 = {H, G, D, C} in lanes 0..3, b = SRC2 = {F, E, B, A},
// k = XMM0 with WK0, WK1 in lanes 0, 1. Returns {F, E, B, A} after two rounds.
static __m128i _mm_sha256rnds2_epu32(__m128i a, __m128i b, __m128i k) {
  uint32_t A = b.l[3], B = b.l[2], C = a.l[3], D = a.l[2], E = b.l[1], F = b.l[0], G = a.l[1], H = a.l[0];
  for (int i = 0; i < 2; i++) {
    uint32_t ch = (E & F) ^ (~E & G), maj = (A & B) ^ (A & C) ^ (B & C);
    uint32_t s1 = ROR(E, 6) ^ ROR(E, 11) ^ ROR(E, 25), s0 = ROR(A, 2) ^ ROR(A, 13) ^ ROR(A, 22);
    uint32_t t = ch + s1 + k.l[i] + H;
    uint32_t A2 = t + maj + s0, E2 = t + D;
    H = G, G = F, F = E, E = E2, D = C, C = B, B = A, A = A2;
  }
  return (__m128i){{F, E, B, A}};
}
static uint32_t sig0(uint32_t x) { return ROR(x, 7) ^ ROR(x, 18) ^ (x >> 3); }
static uint32_t sig1(uint32_t x) { return ROR(x, 17) ^ ROR(x, 19) ^ (x >> 10); }
// SHA256MSG1: W0..W3 from a, W4 from b lane 0; returns Wi + sig0(Wi+1).
static __m128i _mm_sha256msg1_epu32(__m128i a, __m128i b) {
  return (__m128i){{a.l[0] + sig0(a.l[1]), a.l[1] + sig0(a.l[2]), a.l[2] + sig0(a.l[3]), a.l[3] + sig0(b.l[0])}};
}
// SHA256MSG2: W14, W15 from b lanes 2, 3; returns W16..W19.
static __m128i _mm_sha256msg2_epu32(__m128i a, __m128i b) {
  uint32_t w16 = a.l[0] + sig1(b.l[2]), w17 = a.l[1] + sig1(b.l[3]);
  uint32_t w18 = a.l[2] + sig1(w16), w19 = a.l[3] + sig1(w17);
  return (__m128i){{w16, w17, w18, w19}};
}

#include "../src/chain_shani.h"

int main(void) {
  cs_rng rng;
  rng_test(&rng, "shani emulation", 15);
  int bad = 0, runs = 0;
  const uint64_t steps_list[] = {1, 2, 3, 10, 100};
  for (int L = 1; L <= 2; L++)
    for (size_t si = 0; si < sizeof steps_list / sizeof steps_list[0]; si++)
      for (int rep = 0; rep < 20; rep++) {
        uint32_t st[2][8], want[2][8];
        chain_tail t[2];
        for (int l = 0; l < L; l++) {
          uint8_t salt[16], s[52];
          uint32_t index;
          rng_bytes(&rng, salt, 16), rng_bytes(&rng, s, 32), rng_bytes(&rng, (uint8_t *)&index, 4);
          chain_tail_init(&t[l], salt, index);
          for (int w = 0; w < 8; w++) st[l][w] = load_be32(s + 4 * w);
          memcpy(s + 32, salt, 16), store_be32(s + 48, index);
          for (uint64_t j = 0; j < steps_list[si]; j++) sha256(s, s, 52);
          for (int w = 0; w < 8; w++) want[l][w] = load_be32(s + 4 * w);
        }
        if (L == 1) shani_run_L(st, t, 1, steps_list[si]);
        else shani_run_L(st, t, 2, steps_list[si]);
        bad += memcmp(st, want, sizeof st[0] * L) != 0;
        runs++;
      }
  printf("sha-ni logic under emulation: %d of %d runs match SHA-256\n", runs - bad, runs);
  return bad != 0;
}
