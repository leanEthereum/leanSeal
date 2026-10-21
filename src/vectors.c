// Deterministic test vectors (tests/vectors.json), for checking another
// implementation against this one. All randomness comes from rng_test().
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "tool.h"

static const struct {
  uint32_t n;
  uint64_t m;
  unsigned b;
  size_t msglen;
} CASES[] = {
    {1, 1, 1, 0}, {1, 5, 12, 1}, {2, 3, 12, 21}, {3, 10, 32, 32}, {5, 100, 12, 33}, {8, 1000, 7, 100}, {16, 64, 12, 64},
};
#define NCASES (sizeof CASES / sizeof CASES[0])

static void hex_field(const char *name, const uint8_t *data, size_t len, const char *after) {
  char *hex = malloc(2 * len + 1);
  hex_encode(hex, data, len);
  printf("\"%s\": \"%s\"%s", name, hex, after);
  free(hex);
}

static void hex_list(const char *name, const uint8_t *data, size_t count, size_t width, const char *after) {
  char hex[65];
  printf("\"%s\": [", name);
  for (size_t i = 0; i < count; i++) {
    hex_encode(hex, data + i * width, width);
    printf("%s\"%s\"", i ? ", " : "", hex);
  }
  printf("]%s", after);
}

typedef struct {
  uint32_t i;
  uint64_t j;
} stop_at;

static int stop_when(void *arg, const cs_cursor *c) {
  const stop_at *s = arg;
  return c->i == s->i && c->j == s->j;
}

typedef struct {
  cs_puzzle p;
  uint8_t key[32];
  uint8_t *puzzle, *envelope, *secret, ckpt[CS_CHECKPOINT_SIZE];
  size_t plen, elen, slen;
} built;

static built B[sizeof CASES / sizeof CASES[0]];

// Whether this implementation rejects an invalid input as SPEC.md section 10 requires.
static int rejects(const char *kind, int c, const uint8_t *data, size_t len) {
  cs_puzzle p;
  uint8_t key[32];
  if (!strcmp(kind, "puzzle") || !strcmp(kind, "secret")) {
    int err = kind[0] == 'p' ? cs_puzzle_decode(&p, data, len) : cs_secret_decode(&p, key, data, len);
    if (!err) cs_puzzle_free(&p);
    return err != CS_OK;
  }
  if (!strcmp(kind, "envelope")) {
    cs_envelope e;
    if (cs_envelope_decode(&e, data, len)) return 1;
    uint8_t *msg = malloc(e.ct_len + 1);
    int err = cs_open(&e, B[c].key, msg);
    free(msg);
    cs_envelope_free(&e);
    return err != CS_OK;
  }
  cs_cursor cur;
  return cs_checkpoint_decode(&B[c].p, &cur, data, len) != CS_OK;
}

static int first_invalid = 1, accepted_invalid = 0;
static void invalid(const char *kind, int c, const char *why, const uint8_t *data, size_t len) {
  printf("%s    {\"kind\": \"%s\", \"case\": %d, \"why\": \"%s\", ", first_invalid ? "" : ",\n", kind, c, why);
  hex_field("hex", data, len, "}");
  first_invalid = 0;
  if (!rejects(kind, c, data, len)) fprintf(stderr, "vectors: invalid %s accepted: %s\n", kind, why), accepted_invalid++;
}

// Copy `src`, apply one edit, and emit it as an invalid input.
static void mutate(const char *kind, int c, const char *why, const uint8_t *src, size_t len, size_t at, int set,
                   uint8_t value, ptrdiff_t resize) {
  size_t n = (size_t)((ptrdiff_t)len + resize);
  uint8_t *buf = calloc(n + 1, 1);
  memcpy(buf, src, n < len ? n : len);
  if (set >= 0 && at < n) buf[at] = set ? value : (uint8_t)(buf[at] ^ value);
  invalid(kind, c, why, buf, n);
  free(buf);
}
#define FLIP(kind, c, why, src, len, at) mutate(kind, c, why, src, len, at, 0, 1, 0)
#define SET(kind, c, why, src, len, at, v) mutate(kind, c, why, src, len, at, 1, v, 0)
#define RESIZE(kind, c, why, src, len, d) mutate(kind, c, why, src, len, 0, -1, 0, d)

static void set_be(uint8_t *buf, size_t at, uint64_t v, int bytes) {
  for (int k = bytes - 1; k >= 0; k--, v >>= 8) buf[at + k] = (uint8_t)v;
}

int cmd_vectors(int argc, char **argv) {
  (void)argc, (void)argv;
  printf("{\n  \"spec\": \"chainseal v1\",\n  \"cases\": [\n");
  for (size_t k = 0; k < NCASES; k++) {
    uint32_t n = CASES[k].n;
    uint64_t m = CASES[k].m;
    unsigned b = CASES[k].b;
    size_t ml = CASES[k].msglen;
    char seed[64];
    snprintf(seed, sizeof seed, "chainseal/v1 vector %zu", k);
    cs_rng rng;
    rng_test(&rng, seed, strlen(seed));
    uint8_t salt[16], nonce[16], *x = malloc((size_t)n * b), *y = malloc(32 * (size_t)n), *s = malloc(32 * (size_t)n);
    uint8_t *msg = malloc(ml + 1);
    rng_bytes(&rng, salt, 16), rng_bytes(&rng, x, (size_t)n * b), rng_bytes(&rng, nonce, 16), rng_bytes(&rng, msg, ml);
    built *o = &B[k];
    cs_gen_opts opts = {.threads = 1, .y_out = y};
    if (cs_generate_from(&o->p, o->key, n, m, b, salt, x, &opts)) return 1;
    for (uint32_t i = 1; i <= n; i++) cs_chain_start(&o->p, i, x + (size_t)(i - 1) * b, s + 32 * (i - 1));
    o->plen = cs_puzzle_size(n, b), o->elen = cs_envelope_size(&o->p, ml), o->slen = cs_secret_size(&o->p);
    o->puzzle = malloc(o->plen), o->envelope = malloc(o->elen), o->secret = malloc(o->slen);
    cs_puzzle_encode(&o->p, o->puzzle);
    cs_secret_encode(&o->p, o->key, o->secret);
    if (cs_seal(&o->p, o->key, nonce, msg, ml, o->envelope)) return 1;

    stop_at at = {(n + 1) / 2, m / 2 ? m / 2 : 1};
    cs_cursor cur = {0};
    uint8_t solved[32], id[32];
    if (cs_solve(&o->p, solved, &cur, NULL, 1, stop_when, &at) != CS_ESTOPPED) return 1;
    cs_checkpoint_encode(&o->p, &cur, o->ckpt);
    if (cs_solve(&o->p, solved, &cur, NULL, 0, NULL, NULL) || memcmp(solved, o->key, 32)) return 1;
    cs_puzzle_id(&o->p, id);
    uint8_t state[32];
    {
      cs_cursor again;
      cs_checkpoint_decode(&o->p, &again, o->ckpt, CS_CHECKPOINT_SIZE);
      for (int w = 0; w < 8; w++) store_be32(state + 4 * w, again.st[w]);
    }

    printf("    {\"n\": %u, \"m\": %llu, \"b\": %u,\n      ", n, (unsigned long long)m, b);
    hex_field("salt", salt, 16, ",\n      ");
    hex_list("x", x, n, b, ",\n      ");
    hex_list("start", s, n, 32, ",\n      ");
    hex_list("y", y, n, 32, ",\n      ");
    hex_field("key", o->key, 32, ",\n      ");
    hex_field("commit", o->p.commit, 32, ",\n      ");
    hex_field("puzzle", o->puzzle, o->plen, ",\n      ");
    hex_field("puzzle_id", id, 32, ",\n      ");
    hex_field("secret", o->secret, o->slen, ",\n      ");
    hex_field("nonce", nonce, 16, ",\n      ");
    hex_field("message", msg, ml, ",\n      ");
    hex_field("envelope", o->envelope, o->elen, ",\n      ");
    printf("\"checkpoint\": {\"i\": %u, \"j\": %llu, ", at.i, (unsigned long long)at.j);
    hex_field("state", state, 32, ", ");
    hex_field("hex", o->ckpt, CS_CHECKPOINT_SIZE, "}}");
    printf("%s\n", k + 1 < NCASES ? "," : "");
    free(x), free(y), free(s), free(msg);
  }

  printf("  ],\n  \"invalid\": [\n");
  const int c = 2;  // n = 2, m = 3, b = 12, 21-byte message
  const built *o = &B[c];
  const uint8_t *P = o->puzzle, *E = o->envelope, *S = o->secret, *K = o->ckpt;
  size_t pl = o->plen, el = o->elen, sl = o->slen, kl = CS_CHECKPOINT_SIZE, ct = 8 + pl + 20;
  uint8_t *buf = malloc(el + 64);

  FLIP("puzzle", c, "bad magic", P, pl, 0);
  SET("puzzle", c, "version 2", P, pl, 4, 2);
  SET("puzzle", c, "b = 0", P, pl, 5, 0);
  SET("puzzle", c, "b = 33", P, pl, 5, 33);
  SET("puzzle", c, "reserved byte 6 set", P, pl, 6, 1);
  SET("puzzle", c, "reserved byte 7 set", P, pl, 7, 0x80);
  memcpy(buf, P, pl), set_be(buf, 8, 0, 4), invalid("puzzle", c, "n = 0", buf, pl);
  memcpy(buf, P, pl), set_be(buf, 8, (1u << 20) + 1, 4), invalid("puzzle", c, "n = 2^20 + 1", buf, pl);
  memcpy(buf, P, pl), set_be(buf, 8, 3, 4), invalid("puzzle", c, "n = 3, links for n = 2", buf, pl);
  memcpy(buf, P, pl), set_be(buf, 12, 0, 8), invalid("puzzle", c, "m = 0", buf, pl);
  memcpy(buf, P, pl), set_be(buf, 12, (1ull << 48) + 1, 8), invalid("puzzle", c, "m = 2^48 + 1", buf, pl);
  RESIZE("puzzle", c, "one byte short", P, pl, -1);
  RESIZE("puzzle", c, "one trailing byte", P, pl, 1);
  RESIZE("puzzle", c, "header only", P, pl, -(ptrdiff_t)(pl - CS_PUZZLE_HEADER));
  RESIZE("puzzle", c, "empty", P, pl, -(ptrdiff_t)pl);
  {  // from case 0 (b = 1): every field in range, but n*m above 2^60
    const uint32_t big_n = 4097;
    size_t len = cs_puzzle_size(big_n, 1);
    uint8_t *big = calloc(len, 1);
    memcpy(big, B[0].puzzle, CS_PUZZLE_HEADER);
    set_be(big, 8, big_n, 4), set_be(big, 12, 1ull << 48, 8);
    invalid("puzzle", 0, "n*m = 4097 * 2^48, above 2^60", big, len);
    free(big);
  }

  FLIP("envelope", c, "bad magic", E, el, 0);
  SET("envelope", c, "version 2", E, el, 4, 2);
  SET("envelope", c, "reserved byte 5 set", E, el, 5, 1);
  SET("envelope", c, "reserved byte 7 set", E, el, 7, 1);
  SET("envelope", c, "inner puzzle b = 33", E, el, 8 + 5, 33);
  FLIP("envelope", c, "inner puzzle bad magic", E, el, 8);
  memcpy(buf, E, el), set_be(buf, ct - 4, 22, 4), invalid("envelope", c, "length field one too large", buf, el);
  memcpy(buf, E, el), set_be(buf, ct - 4, 20, 4), invalid("envelope", c, "length field one too small", buf, el);
  memcpy(buf, E, el), set_be(buf, ct - 4, (1u << 24) + 1, 4), invalid("envelope", c, "length 2^24 + 1", buf, el);
  RESIZE("envelope", c, "one byte short", E, el, -1);
  RESIZE("envelope", c, "one trailing byte", E, el, 1);
  FLIP("envelope", c, "tag modified", E, el, el - 1);
  FLIP("envelope", c, "ciphertext modified", E, el, ct);
  FLIP("envelope", c, "nonce modified", E, el, ct - 20);
  FLIP("envelope", c, "link z_1 modified", E, el, 8 + CS_PUZZLE_HEADER + 12);
  FLIP("envelope", c, "link x_1 modified", E, el, 8 + CS_PUZZLE_HEADER);
  FLIP("envelope", c, "commitment modified", E, el, 8 + 36);
  FLIP("envelope", c, "salt modified", E, el, 8 + 20);
  FLIP("envelope", c, "m modified", E, el, 8 + 19);

  FLIP("secret", c, "bad magic", S, sl, 0);
  SET("secret", c, "version 2", S, sl, 4, 2);
  SET("secret", c, "reserved byte 6 set", S, sl, 6, 1);
  FLIP("secret", c, "key does not match the commitment", S, sl, 8);
  FLIP("secret", c, "commitment does not match the key", S, sl, 40 + 36);
  RESIZE("secret", c, "one byte short", S, sl, -1);
  RESIZE("secret", c, "one trailing byte", S, sl, 1);

  FLIP("checkpoint", c, "bad magic", K, kl, 0);
  SET("checkpoint", c, "version 2", K, kl, 4, 2);
  SET("checkpoint", c, "reserved byte 5 set", K, kl, 5, 1);
  FLIP("checkpoint", c, "different puzzle id", K, kl, 8);
  memcpy(buf, K, kl), set_be(buf, 40, 0, 4), invalid("checkpoint", c, "i = 0", buf, kl);
  memcpy(buf, K, kl), set_be(buf, 40, 3, 4), invalid("checkpoint", c, "i = n + 1", buf, kl);
  memcpy(buf, K, kl), set_be(buf, 44, 4, 8), invalid("checkpoint", c, "j = m + 1", buf, kl);
  RESIZE("checkpoint", c, "one byte short", K, kl, -1);
  RESIZE("checkpoint", c, "one trailing byte", K, kl, 1);
  printf("\n  ]\n}\n");

  free(buf);
  for (size_t k = 0; k < NCASES; k++) {
    cs_puzzle_free(&B[k].p);
    free(B[k].puzzle), free(B[k].envelope), free(B[k].secret);
  }
  return accepted_invalid ? 1 : 0;
}
