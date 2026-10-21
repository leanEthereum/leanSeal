// Unit tests for the chainseal library. Run by `make test`.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chainseal.h"
#include "sha256.h"

static int failures, checks;

#define CHECK(cond, ...)                                       \
  do {                                                         \
    checks++;                                                  \
    if (!(cond)) {                                             \
      failures++;                                              \
      fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);     \
      fprintf(stderr, __VA_ARGS__);                            \
      fprintf(stderr, "\n");                                   \
    }                                                          \
  } while (0)

static void unhex(uint8_t *out, const char *hex) {
  for (size_t i = 0; hex[2 * i]; i++) sscanf(hex + 2 * i, "%2hhx", &out[i]);
}

static int eq_hex(const uint8_t *got, const char *hex) {
  uint8_t want[64];
  unhex(want, hex);
  return !memcmp(got, want, strlen(hex) / 2);
}

static cs_rng rng;

// ---------------------------------------------------------------- SHA-256, HMAC, TH

static void test_sha256(void) {
  uint8_t d[32];
  sha256(d, "", 0);
  CHECK(eq_hex(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256 empty");
  sha256(d, "abc", 3);
  CHECK(eq_hex(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256 abc");
  const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  sha256(d, m448, strlen(m448));
  CHECK(eq_hex(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), "sha256 448 bits");
  sha256_ctx c;
  sha256_init(&c);
  uint8_t a[1000];
  memset(a, 'a', sizeof a);
  for (int i = 0; i < 1000; i++) sha256_update(&c, a, sizeof a);
  sha256_final(&c, d);
  CHECK(eq_hex(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), "sha256 million a");

  // Incremental hashing at every split point matches one shot.
  uint8_t msg[200], one[32], two[32];
  rng_bytes(&rng, msg, sizeof msg);
  for (size_t len = 0; len <= sizeof msg; len += 7) {
    sha256(one, msg, len);
    for (size_t cut = 0; cut <= len; cut += 3) {
      sha256_init(&c);
      sha256_update(&c, msg, cut);
      sha256_update(&c, msg + cut, len - cut);
      sha256_final(&c, two);
      CHECK(!memcmp(one, two, 32), "sha256 split %zu/%zu", cut, len);
    }
  }
}

static void test_hmac(void) {  // RFC 4231 cases 1, 2, 3, 6, 7
  uint8_t d[32], k[131];
  memset(k, 0x0b, 20);
  hmac_sha256(d, k, 20, "Hi There", 8);
  CHECK(eq_hex(d, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), "hmac case 1");
  hmac_sha256(d, (const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28);
  CHECK(eq_hex(d, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), "hmac case 2");
  uint8_t dd[50];
  memset(k, 0xaa, sizeof k), memset(dd, 0xdd, sizeof dd);
  hmac_sha256(d, k, 20, dd, 50);
  CHECK(eq_hex(d, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"), "hmac case 3");
  const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
  hmac_sha256(d, k, 131, m6, strlen(m6));
  CHECK(eq_hex(d, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"), "hmac case 6");
  const char *m7 =
      "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be "
      "hashed before being used by the HMAC algorithm.";
  hmac_sha256(d, k, 131, m7, strlen(m7));
  CHECK(eq_hex(d, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"), "hmac case 7");
}

static void test_th(void) {
  uint8_t got[32], want[32], buf[128];
  const char *label = "chainseal/v1/key";
  uint8_t a[5] = {1, 2, 3, 4, 5}, b[3] = {9, 8, 7};
  th(got, label, a, 5, NULL, 0, b, 3, NULL, 0);
  size_t L = strlen(label), n = 0;
  buf[n++] = (uint8_t)L;
  memcpy(buf + n, label, L), n += L;
  memcpy(buf + n, a, 5), n += 5;
  memcpy(buf + n, b, 3), n += 3;
  sha256(want, buf, n);
  CHECK(!memcmp(got, want, 32), "TH is SHA256(u8(len) || label || parts)");
}

// ---------------------------------------------------------------- chain backends

static void test_backends(void) {
  const chain_backend *all[4];
  int k = chain_backends(all, 4);
  CHECK(k >= 1 && !strcmp(all[k - 1]->name, "portable"), "portable backend always present");
  const uint64_t steps_list[] = {0, 1, 2, 3, 17, 100};
  for (int bi = 0; bi < k; bi++) {
    const chain_backend *be = all[bi];
    CHECK(be->lanes >= 1 && be->lanes <= CHAIN_MAX_LANES, "%s lanes", be->name);
    for (int lanes = 1; lanes <= be->lanes; lanes++) {
      for (size_t si = 0; si < sizeof steps_list / sizeof steps_list[0]; si++) {
        uint64_t steps = steps_list[si];
        uint32_t st[CHAIN_MAX_LANES][8], one[CHAIN_MAX_LANES][8], want[CHAIN_MAX_LANES][8];
        chain_tail t[CHAIN_MAX_LANES];
        for (int l = 0; l < lanes; l++) {
          uint8_t salt[16], s[52];
          rng_bytes(&rng, salt, 16), rng_bytes(&rng, s, 32);
          uint32_t index;
          rng_bytes(&rng, (uint8_t *)&index, 4);
          chain_tail_init(&t[l], salt, index);
          for (int w = 0; w < 8; w++) st[l][w] = one[l][w] = load_be32(s + 4 * w);
          memcpy(s + 32, salt, 16), store_be32(s + 48, index);
          for (uint64_t j = 0; j < steps; j++) sha256(s, s, 52);  // F_i(s) = SHA256(s || salt || be32(i))
          for (int w = 0; w < 8; w++) want[l][w] = load_be32(s + 4 * w);
          be->run(one[l], &t[l], steps);
        }
        be->run_lanes(st, t, lanes, steps);
        CHECK(!memcmp(st, want, sizeof st[0] * lanes), "%s run_lanes, %d lanes, %llu steps", be->name, lanes,
              (unsigned long long)steps);
        CHECK(!memcmp(one, want, sizeof one[0] * lanes), "%s run, %llu steps", be->name, (unsigned long long)steps);
      }
    }
  }
}

// ---------------------------------------------------------------- round trips

typedef struct {
  cs_puzzle p;
  uint8_t key[32];
  uint8_t *env;
  size_t elen;
} sealed;

static int make(sealed *s, uint32_t n, uint64_t m, unsigned b, const uint8_t *msg, size_t len) {
  uint8_t nonce[16];
  rng_bytes(&rng, nonce, 16);
  int err = cs_generate(&s->p, s->key, n, m, b, &rng, NULL);
  if (err) return err;
  s->elen = cs_envelope_size(&s->p, len);
  s->env = malloc(s->elen);
  return cs_seal(&s->p, s->key, nonce, msg, len, s->env);
}

static void unmake(sealed *s) {
  cs_puzzle_free(&s->p);
  free(s->env);
}

static void test_round_trips(void) {
  const uint32_t ns[] = {1, 2, 3, 7, 16};
  const uint64_t ms[] = {1, 2, 10, 257};
  const unsigned bs[] = {1, 8, 12, 32};
  const size_t lens[] = {0, 1, 31, 32, 33, 1000};
  const chain_backend *all[4];
  int nb = chain_backends(all, 4);
  uint8_t msg[1000], out[1000];
  rng_bytes(&rng, msg, sizeof msg);
  int cases = 0;
  for (size_t a = 0; a < 5; a++)
    for (size_t c = 0; c < 4; c++)
      for (size_t d = 0; d < 4; d++) {
        size_t len = lens[(a + c + d) % 6];
        sealed s;
        CHECK(!make(&s, ns[a], ms[c], bs[d], msg, len), "make");
        CHECK(s.elen == CS_PUZZLE_HEADER + ns[a] * bs[d] + CS_ENVELOPE_OVERHEAD + len, "envelope size");
        cs_envelope e;
        CHECK(!cs_envelope_decode(&e, s.env, s.elen), "decode n=%u m=%llu b=%u", ns[a], (unsigned long long)ms[c],
              bs[d]);
        for (int bi = 0; bi < nb; bi++) {
          uint8_t key[32];
          CHECK(!cs_solve(&e.puzzle, key, NULL, all[bi], 3, NULL, NULL), "solve with %s", all[bi]->name);
          CHECK(!memcmp(key, s.key, 32), "solved key, %s", all[bi]->name);
        }
        memset(out, 0, sizeof out);
        CHECK(!cs_open(&e, s.key, out) && !memcmp(out, msg, len), "open");
        cs_envelope_free(&e);
        unmake(&s);
        cases++;
      }
  CHECK(cases == 80, "grid size");
}

// The puzzle depends only on its inputs: not on threads or backend.
static void test_determinism(void) {
  uint8_t salt[16], x[40 * 12];
  rng_bytes(&rng, salt, 16), rng_bytes(&rng, x, sizeof x);
  const chain_backend *all[4];
  int nb = chain_backends(all, 4);
  cs_puzzle ref;
  uint8_t ref_key[32], ref_y[40 * 32], ref_enc[CS_PUZZLE_HEADER + 40 * 12];
  cs_gen_opts o = {.threads = 1, .backend = all[nb - 1], .y_out = ref_y};
  CHECK(!cs_generate_from(&ref, ref_key, 40, 33, 12, salt, x, &o), "reference build");
  cs_puzzle_encode(&ref, ref_enc);
  const int threads[] = {1, 2, 3, 7, 64, 0};
  for (int bi = 0; bi < nb; bi++)
    for (size_t t = 0; t < sizeof threads / sizeof threads[0]; t++) {
      cs_puzzle p;
      uint8_t key[32], y[40 * 32], enc[sizeof ref_enc];
      cs_gen_opts oo = {.threads = threads[t], .backend = all[bi], .y_out = y};
      CHECK(!cs_generate_from(&p, key, 40, 33, 12, salt, x, &oo), "build");
      cs_puzzle_encode(&p, enc);
      CHECK(!memcmp(enc, ref_enc, sizeof enc) && !memcmp(key, ref_key, 32) && !memcmp(y, ref_y, sizeof y),
            "%s with %d threads matches the portable single-thread build", all[bi]->name, threads[t]);
      cs_puzzle_free(&p);
    }
  // Links: x_1 in the clear, then z_i = TH(mask, ctx || y_i)[0:b] xor x_{i+1}.
  int ok = !memcmp(ref.links, x, 12);
  uint8_t ctx[32], mk[32];
  cs_puzzle_ctx(&ref, ctx);
  for (int i = 1; i < 40; i++) {
    th(mk, "chainseal/v1/mask", ctx, 32, ref_y + 32 * (i - 1), 32, NULL, 0, NULL, 0);
    for (int k = 0; k < 12; k++) ok &= ref.links[12 * i + k] == (mk[k] ^ x[12 * i + k]);
  }
  CHECK(ok, "links are x_1, then TH(mask, ctx || y_i)[0:b] xor x_{i+1}");
  cs_puzzle_free(&ref);
}

// ---------------------------------------------------------------- failures

static void test_failures(void) {
  uint8_t msg[50], out[50], key[32];
  rng_bytes(&rng, msg, sizeof msg);
  sealed s;
  CHECK(!make(&s, 3, 20, 12, msg, sizeof msg), "make");
  cs_envelope e;
  CHECK(!cs_envelope_decode(&e, s.env, s.elen), "decode");

  memcpy(key, s.key, 32), key[31] ^= 1;
  memset(out, 0xa5, sizeof out);
  CHECK(cs_open(&e, key, out) == CS_ECOMMIT, "wrong key refused");
  CHECK(cs_seal(&s.p, key, (uint8_t[16]){0}, msg, 1, s.env) == CS_ECOMMIT, "seal with a wrong key refused");
  CHECK(cs_seal(&s.p, s.key, (uint8_t[16]){0}, msg, CS_MAX_MSG + 1, NULL) == CS_ERANGE, "message too long");
  int untouched = 1;
  for (size_t i = 0; i < sizeof out; i++) untouched &= out[i] == 0xa5;
  CHECK(untouched, "no plaintext written on failure");
  cs_envelope_free(&e);

  // A changed tag: the key still matches the commitment, so this is CS_ETAG.
  s.env[s.elen - 1] ^= 1;
  CHECK(!cs_envelope_decode(&e, s.env, s.elen), "decode with a bad tag");
  CHECK(cs_open(&e, s.key, out) == CS_ETAG, "bad tag refused");
  untouched = 1;
  for (size_t i = 0; i < sizeof out; i++) untouched &= out[i] == 0xa5;
  CHECK(untouched, "no plaintext written on a bad tag");
  cs_envelope_free(&e);

  // A malformed puzzle (a link changed after building) solves to a key that
  // does not match the commitment.
  s.p.links[12 + 3] ^= 0x40;
  CHECK(cs_solve(&s.p, key, NULL, NULL, 0, NULL, NULL) == CS_EPUZZLE, "malformed puzzle detected");
  unmake(&s);

  // Parameter ranges.
  cs_puzzle p;
  const struct {
    uint32_t n;
    uint64_t m;
    unsigned b;
  } bad[] = {{0, 1, 12}, {CS_MAX_N + 1, 1, 12}, {1, 0, 12}, {1, CS_MAX_M + 1, 12}, {1, 1, 0}, {1, 1, 33}, {CS_MAX_N, CS_MAX_WORK / CS_MAX_N + 1, 12}};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
    CHECK(cs_generate(&p, key, bad[i].n, bad[i].m, bad[i].b, &rng, NULL) == CS_ERANGE, "range case %zu", i);
  CHECK(cs_params_ok(CS_MAX_N, CS_MAX_WORK / CS_MAX_N, CS_MAX_B) && cs_params_ok(1, CS_MAX_M, 1) && cs_params_ok(1, 1, 1),
        "range limits allowed");
}

// ---------------------------------------------------------------- checkpoints and secrets

typedef struct {
  uint32_t i;
  uint64_t j;
} stop_at;

static int stop_when(void *arg, const cs_cursor *c) {
  const stop_at *s = arg;
  return c->i == s->i && c->j >= s->j;
}

static void test_checkpoints(void) {
  cs_puzzle p, other;
  uint8_t key[32], k2[32], other_key[32], buf[CS_CHECKPOINT_SIZE];
  CHECK(!cs_generate(&p, key, 4, 1000, 12, &rng, NULL), "build");
  CHECK(!cs_generate(&other, other_key, 4, 1000, 12, &rng, NULL), "build another");
  const stop_at stops[] = {{1, 1}, {1, 500}, {2, 1000}, {3, 7}, {4, 999}, {4, 1000}};
  for (size_t t = 0; t < sizeof stops / sizeof stops[0]; t++) {
    cs_cursor cur = {0}, back;
    CHECK(cs_solve(&p, k2, &cur, NULL, 7, stop_when, (void *)&stops[t]) == CS_ESTOPPED, "stopped");
    CHECK(cur.i == stops[t].i, "stopped in chain %u", stops[t].i);
    cs_checkpoint_encode(&p, &cur, buf);
    CHECK(!cs_checkpoint_decode(&p, &back, buf, sizeof buf), "decode checkpoint");
    CHECK(back.i == cur.i && back.j == cur.j && !memcmp(back.st, cur.st, 32) && !memcmp(back.acc, cur.acc, 32),
          "checkpoint round trip");
    CHECK(cs_checkpoint_decode(&other, &back, buf, sizeof buf) == CS_EMISMATCH, "other puzzle refused");
    CHECK(cs_checkpoint_decode(&p, &back, buf, sizeof buf - 1) == CS_EFORMAT, "short checkpoint");
    memset(k2, 0, 32);
    CHECK(!cs_solve(&p, k2, &back, NULL, 0, NULL, NULL) && !memcmp(k2, key, 32), "resume from %u/%llu",
          stops[t].i, (unsigned long long)stops[t].j);
  }
  // A finished cursor keeps a_{n-1}: solving again from it, directly or through a
  // checkpoint, gives the same key.
  for (uint32_t n = 1; n <= 3; n++) {
    cs_puzzle q;
    uint8_t qk[32], got[32];
    cs_cursor done = {0}, back;
    CHECK(!cs_generate(&q, qk, n, 5, 12, &rng, NULL), "build n = %u", n);
    CHECK(!cs_solve(&q, got, &done, NULL, 0, NULL, NULL) && !memcmp(got, qk, 32), "solve n = %u", n);
    CHECK(done.i == n && done.j == 5, "finished cursor at (n, m)");
    CHECK(!cs_solve(&q, got, &done, NULL, 0, NULL, NULL) && !memcmp(got, qk, 32), "solve again, n = %u", n);
    cs_checkpoint_encode(&q, &done, buf);
    CHECK(!cs_checkpoint_decode(&q, &back, buf, sizeof buf), "decode finished checkpoint");
    CHECK(!cs_solve(&q, got, &back, NULL, 0, NULL, NULL) && !memcmp(got, qk, 32), "resume finished, n = %u", n);
    cs_puzzle_free(&q);
  }
  // A checkpoint whose accumulator is wrong solves to a key that fails the commitment.
  {
    const stop_at at = {3, 7};
    cs_cursor cur = {0}, back;
    CHECK(cs_solve(&p, k2, &cur, NULL, 7, stop_when, (void *)&at) == CS_ESTOPPED, "stopped");
    cs_checkpoint_encode(&p, &cur, buf);
    buf[CS_CHECKPOINT_SIZE - 1] ^= 1;
    CHECK(!cs_checkpoint_decode(&p, &back, buf, sizeof buf), "decode");
    CHECK(cs_solve(&p, k2, &back, NULL, 0, NULL, NULL) == CS_EPUZZLE, "a wrong accumulator is caught");
  }
  cs_cursor cur;
  cs_cursor_start(&p, &cur);
  cs_checkpoint_encode(&p, &cur, buf);
  store_be32(buf + 40, 5);
  CHECK(cs_checkpoint_decode(&p, &cur, buf, sizeof buf) == CS_ERANGE, "i > n");
  store_be32(buf + 40, 1), store_be64(buf + 44, 1001);
  CHECK(cs_checkpoint_decode(&p, &cur, buf, sizeof buf) == CS_ERANGE, "j > m");
  store_be64(buf + 44, 0), buf[7] = 1;
  CHECK(cs_checkpoint_decode(&p, &cur, buf, sizeof buf) == CS_EFORMAT, "reserved byte");

  // Format checks that need no puzzle.
  uint8_t id[32], want[32];
  uint32_t i;
  uint64_t j;
  buf[7] = 0;
  cs_puzzle_id(&p, want);
  CHECK(!cs_checkpoint_peek(buf, sizeof buf, id, &i, &j) && !memcmp(id, want, 32) && i == 1 && !j, "peek");
  buf[4] = 2;
  CHECK(cs_checkpoint_peek(buf, sizeof buf, id, &i, &j) == CS_EFORMAT, "peek: version");
  buf[4] = 1, buf[5] = 1;
  CHECK(cs_checkpoint_peek(buf, sizeof buf, id, &i, &j) == CS_EFORMAT, "peek: reserved byte");
  buf[5] = 0, store_be32(buf + 40, 0);
  CHECK(cs_checkpoint_peek(buf, sizeof buf, id, &i, &j) == CS_ERANGE, "peek: i = 0");
  CHECK(cs_checkpoint_decode(&p, &cur, buf, sizeof buf) == CS_ERANGE, "i = 0");
  store_be32(buf + 40, 4097), store_be64(buf + 44, CS_MAX_M);
  CHECK(cs_checkpoint_peek(buf, sizeof buf, id, &i, &j) == CS_ERANGE, "peek: i*j above 2^60");
  store_be32(buf + 40, 4096);
  CHECK(cs_checkpoint_peek(buf, sizeof buf, id, &i, &j) == CS_OK && i == 4096 && j == CS_MAX_M, "peek: i*j = 2^60");
  store_be32(buf + 40, 1), store_be64(buf + 44, 0);
  CHECK(cs_checkpoint_peek(buf, sizeof buf + 1, id, &i, &j) == CS_EFORMAT, "peek: long checkpoint");

  uint8_t *sec = malloc(cs_secret_size(&p));
  cs_secret_encode(&p, key, sec);
  cs_puzzle q;
  CHECK(!cs_secret_decode(&q, k2, sec, cs_secret_size(&p)) && !memcmp(k2, key, 32), "secret round trip");
  cs_puzzle_free(&q);
  sec[8] ^= 1;
  CHECK(cs_secret_decode(&q, k2, sec, cs_secret_size(&p)) == CS_ECOMMIT, "secret with a wrong key");
  free(sec);
  cs_puzzle_free(&p), cs_puzzle_free(&other);
}

// ---------------------------------------------------------------- the guessing attack

static void test_guess(void) {
  uint8_t salt[16], x[3], key[32], gk[32], y[3 * 32], ends[3 * 32];
  rng_bytes(&rng, salt, 16), rng_bytes(&rng, x, 3);
  cs_puzzle p;
  cs_gen_opts o = {.y_out = ends};
  CHECK(!cs_generate_from(&p, key, 3, 10, 1, salt, x, &o), "build");
  for (uint32_t i = 1; i <= 3; i++) {
    cs_run_chain(&p, i, &x[i - 1], NULL, y + 32 * (i - 1));
    CHECK(!memcmp(y + 32 * (i - 1), ends + 32 * (i - 1), 32), "chain %u alone", i);
  }
  CHECK(cs_key_from_ends(&p, y, gk) && !memcmp(gk, key, 32), "key from the ends");
  // Guessing x_3 opens the puzzle only together with the true ends of chains 1 and 2.
  int wins = 0, winner = -1, alone = 0;
  for (int g = 0; g < 256; g++) {
    uint8_t guess = (uint8_t)g;
    cs_run_chain(&p, 3, &guess, NULL, y + 64);
    if (cs_key_from_ends(&p, y, gk)) {
      wins++, winner = g;
      CHECK(!memcmp(gk, key, 32), "key");
    }
    uint8_t wrong[3 * 32] = {0};
    memcpy(wrong + 64, y + 64, 32);
    alone += cs_key_from_ends(&p, wrong, gk);
  }
  CHECK(wins == 1 && winner == x[2], "exactly the true last link opens a 1-byte-link puzzle");
  CHECK(alone == 0, "the last chain alone opens nothing");
  // With b = 32 the right x_2 gives the whole mask z_1 xor x_2, but not y_1 (audit R6-1).
  {
    uint8_t x2[64], ys[64], k32[32], ends2[64];
    rng_bytes(&rng, x2, 64);
    cs_puzzle q;
    cs_gen_opts o2 = {.y_out = ends2};
    CHECK(!cs_generate_from(&q, k32, 2, 5, 32, salt, x2, &o2), "build b = 32");
    for (int k = 0; k < 32; k++) ys[k] = q.links[32 + k] ^ x2[32 + k];
    cs_run_chain(&q, 2, x2 + 32, NULL, ys + 32);
    CHECK(!cs_key_from_ends(&q, ys, gk), "the mask does not stand in for y_1");
    memcpy(ys, ends2, 32);
    CHECK(cs_key_from_ends(&q, ys, gk) && !memcmp(gk, k32, 32), "the true y_1 does");
    cs_puzzle_free(&q);
  }
  // Every chain end enters the key.
  for (int i = 0; i < 3; i++) {
    memcpy(y, ends, sizeof y);
    y[32 * i + 31] ^= 1;
    CHECK(!cs_key_from_ends(&p, y, gk), "changing y_%d changes the key", i + 1);
  }
  cs_puzzle_free(&p);
}

// ---------------------------------------------------------------- mutation fuzzing

static uint32_t rnd(uint32_t bound) {
  uint32_t v;
  rng_bytes(&rng, (uint8_t *)&v, 4);
  return v % bound;
}

static void test_fuzz(int rounds) {
  uint8_t msg[40], out[64];
  rng_bytes(&rng, msg, sizeof msg);
  sealed s;
  CHECK(!make(&s, 3, 20, 12, msg, sizeof msg), "make");
  uint8_t *buf = malloc(s.elen + 300);  // room for the extensions and the garbage below
  int accepted = 0, decoded = 0;
  for (int r = 0; r < rounds; r++) {
    size_t len = s.elen;
    memcpy(buf, s.env, len);
    int edits = 1 + (int)rnd(3);
    for (int k = 0; k < edits; k++) {
      switch (rnd(4)) {
        case 0: buf[rnd((uint32_t)len)] ^= (uint8_t)(1u << rnd(8)); break;
        case 1: buf[rnd((uint32_t)len)] = (uint8_t)rnd(256); break;
        case 2: len = rnd((uint32_t)len + 1); break;
        default:
          if (len < s.elen + 64) buf[len++] = (uint8_t)rnd(256);
      }
      if (len == 0) break;
    }
    if (len == s.elen && !memcmp(buf, s.env, len)) continue;  // no change
    // Exercise every decoder on the mutated bytes (ASan checks the reads).
    cs_envelope e;
    cs_puzzle p;
    cs_cursor c;
    uint8_t key[32];
    if (!cs_puzzle_decode(&p, buf, len)) cs_puzzle_free(&p);
    if (!cs_secret_decode(&p, key, buf, len)) cs_puzzle_free(&p);
    cs_checkpoint_decode(&s.p, &c, buf, len);
    if (!cs_envelope_decode(&e, buf, len)) {
      decoded++;
      if (!cs_open(&e, s.key, out)) accepted++;
      cs_envelope_free(&e);
    }
  }
  CHECK(accepted == 0, "%d of %d mutated envelopes accepted", accepted, rounds);
  CHECK(decoded > 0, "some mutations still decode, so open was exercised");

  // Random garbage with valid magics.
  static const char *magics[] = {"CSPZ", "CSEN", "CSSK", "CSCK"};
  for (int r = 0; r < rounds; r++) {
    size_t len = rnd(300);
    rng_bytes(&rng, buf, len);
    if (len >= 5) memcpy(buf, magics[rnd(4)], 4), buf[4] = 1;
    if (len >= 8 && rnd(2)) buf[5] = (uint8_t)rnd(33), buf[6] = buf[7] = 0;
    cs_envelope e;
    cs_puzzle p;
    cs_cursor c;
    uint8_t key[32];
    if (!cs_puzzle_decode(&p, buf, len)) cs_puzzle_free(&p);
    if (!cs_secret_decode(&p, key, buf, len)) cs_puzzle_free(&p);
    if (!cs_envelope_decode(&e, buf, len)) {
      CHECK(cs_open(&e, s.key, out) != CS_OK, "garbage envelope opened");
      cs_envelope_free(&e);
    }
    cs_checkpoint_decode(&s.p, &c, buf, len);
  }
  free(buf);
  unmake(&s);
}

// Mutations of valid puzzle, secret and checkpoint encodings. A decoder must
// reject every truncation and extension, and whatever it accepts must encode
// back to the same bytes: one value, one encoding.
enum { PUZZLE, SECRET, CHECKPOINT };

static int decodes_canonically(int kind, const cs_puzzle *of, const uint8_t *in, size_t len, int *ok) {
  cs_puzzle p;
  cs_cursor c;
  uint8_t key[32], *again = malloc(len + 1);
  int err;
  if (kind == PUZZLE) {
    if (!(err = cs_puzzle_decode(&p, in, len))) cs_puzzle_encode(&p, again), cs_puzzle_free(&p);
  } else if (kind == SECRET) {
    if (!(err = cs_secret_decode(&p, key, in, len))) cs_secret_encode(&p, key, again), cs_puzzle_free(&p);
  } else {
    if (!(err = cs_checkpoint_decode(of, &c, in, len))) cs_checkpoint_encode(of, &c, again);
  }
  *ok = err || !memcmp(again, in, len);
  free(again);
  return !err;
}

static void test_fuzz_decoders(int rounds) {
  cs_puzzle p;
  uint8_t key[32], k2[32];
  CHECK(!cs_generate(&p, key, 3, 20, 12, &rng, NULL), "build");
  stop_at at = {2, 7};
  cs_cursor cur = {0};
  CHECK(cs_solve(&p, k2, &cur, NULL, 1, stop_when, &at) == CS_ESTOPPED, "stop");
  size_t lens[3] = {cs_puzzle_size(p.n, p.b), cs_secret_size(&p), CS_CHECKPOINT_SIZE};
  uint8_t *seeds[3], *buf = malloc(lens[1] + 2);
  for (int k = 0; k < 3; k++) seeds[k] = malloc(lens[k]);
  cs_puzzle_encode(&p, seeds[PUZZLE]);
  cs_secret_encode(&p, key, seeds[SECRET]);
  cs_checkpoint_encode(&p, &cur, seeds[CHECKPOINT]);
  static const char *names[] = {"puzzle", "secret", "checkpoint"};
  for (int k = 0; k < 3; k++) {
    int ok, short_ok = 1, canon = 1, accepted = 0;
    CHECK(decodes_canonically(k, &p, seeds[k], lens[k], &ok) && ok, "%s seed decodes", names[k]);
    for (size_t len = 0; len < lens[k]; len++) short_ok &= !decodes_canonically(k, &p, seeds[k], len, &ok);
    CHECK(short_ok, "every truncated %s is rejected", names[k]);
    memcpy(buf, seeds[k], lens[k]), buf[lens[k]] = 0;
    CHECK(!decodes_canonically(k, &p, buf, lens[k] + 1, &ok), "an extended %s is rejected", names[k]);
    for (int r = 0; r < rounds; r++) {
      memcpy(buf, seeds[k], lens[k]);
      for (int e = 1 + (int)rnd(3); e > 0; e--) buf[rnd((uint32_t)lens[k])] ^= (uint8_t)(1 + rnd(255));
      accepted += decodes_canonically(k, &p, buf, lens[k], &ok);
      canon &= ok;
    }
    CHECK(canon, "mutated %ss that decode re-encode to the same bytes", names[k]);
    CHECK(accepted > 0 && accepted < rounds, "%s mutations: %d of %d decode", names[k], accepted, rounds);
  }
  for (int k = 0; k < 3; k++) free(seeds[k]);
  free(buf);
  cs_puzzle_free(&p);
}

int main(int argc, char **argv) {
  int rounds = argc > 1 ? atoi(argv[1]) : 20000;
  rng_test(&rng, "chainseal unit tests", 20);
  test_sha256();
  test_hmac();
  test_th();
  test_backends();
  test_round_trips();
  test_determinism();
  test_failures();
  test_checkpoints();
  test_guess();
  test_fuzz(rounds);
  test_fuzz_decoders(rounds / 4);
  const chain_backend *all[4];
  int k = chain_backends(all, 4);
  printf("unit tests: %d checks, %d failures (backends:", checks, failures);
  for (int i = 0; i < k; i++) printf(" %s", all[i]->name);
  printf(")\n");
  return failures ? 1 : 0;
}
