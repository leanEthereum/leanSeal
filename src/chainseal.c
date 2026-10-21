#include "chainseal.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <pthread/qos.h>
#endif

#include "sha256.h"

static const uint8_t MAGIC_PUZZLE[4] = {'C', 'S', 'P', 'Z'}, MAGIC_ENVELOPE[4] = {'C', 'S', 'E', 'N'},
                     MAGIC_SECRET[4] = {'C', 'S', 'S', 'K'}, MAGIC_CHECKPOINT[4] = {'C', 'S', 'C', 'K'};
#define VERSION 1

const char *cs_strerror(int err) {
  switch (err) {
    case CS_OK: return "ok";
    case CS_EFORMAT: return "malformed input";
    case CS_ERANGE: return "parameter out of range";
    case CS_ECOMMIT: return "key does not match the puzzle's commitment";
    case CS_ETAG: return "authentication failed: the envelope was modified or the key is wrong";
    case CS_EPUZZLE: return "puzzle is malformed: solving it does not yield the committed key";
    case CS_EMISMATCH: return "checkpoint belongs to a different puzzle";
    case CS_ENOMEM: return "out of memory";
    case CS_ERNG: return "random number generator failed";
    case CS_ESTOPPED: return "stopped";
  }
  return "unknown error";
}

static void words_to_bytes(uint8_t out[32], const uint32_t w[8]) {
  for (int k = 0; k < 8; k++) store_be32(out + 4 * k, w[k]);
}
static void bytes_to_words(uint32_t w[8], const uint8_t in[32]) {
  for (int k = 0; k < 8; k++) w[k] = load_be32(in + 4 * k);
}

// ---------------------------------------------------------------- puzzles

int cs_params_ok(uint32_t n, uint64_t m, unsigned b) {
  return n >= 1 && n <= CS_MAX_N && m >= 1 && m <= CS_MAX_M && m <= CS_MAX_WORK / n && b >= 1 && b <= CS_MAX_B;
}

size_t cs_puzzle_size(uint32_t n, unsigned b) { return CS_PUZZLE_HEADER + (size_t)n * b; }

void cs_puzzle_ctx(const cs_puzzle *p, uint8_t ctx[32]) {
  ctx[0] = VERSION, ctx[1] = p->b, ctx[2] = 0, ctx[3] = 0;
  store_be32(ctx + 4, p->n);
  store_be64(ctx + 8, p->m);
  memcpy(ctx + 16, p->salt, 16);
}

void cs_puzzle_encode(const cs_puzzle *p, uint8_t *out) {
  memcpy(out, MAGIC_PUZZLE, 4);
  cs_puzzle_ctx(p, out + 4);
  memcpy(out + 36, p->commit, 32);
  memcpy(out + 68, p->links, (size_t)p->n * p->b);
}

// Reads the fixed header; on success *size is the full encoded length.
static int puzzle_header(cs_puzzle *p, const uint8_t *in, size_t len, size_t *size) {
  if (len < CS_PUZZLE_HEADER) return CS_EFORMAT;
  if (memcmp(in, MAGIC_PUZZLE, 4) || in[4] != VERSION || in[6] || in[7]) return CS_EFORMAT;
  p->b = in[5];
  p->n = load_be32(in + 8);
  p->m = load_be64(in + 12);
  if (!cs_params_ok(p->n, p->m, p->b)) return CS_ERANGE;
  memcpy(p->salt, in + 20, 16);
  memcpy(p->commit, in + 36, 32);
  p->links = NULL;
  *size = cs_puzzle_size(p->n, p->b);
  return CS_OK;
}

int cs_puzzle_decode(cs_puzzle *p, const uint8_t *in, size_t len) {
  size_t size;
  int err = puzzle_header(p, in, len, &size);
  if (err) return err;
  if (len != size) return CS_EFORMAT;
  size_t nb = (size_t)p->n * p->b;
  if (!(p->links = malloc(nb))) return CS_ENOMEM;
  memcpy(p->links, in + CS_PUZZLE_HEADER, nb);
  return CS_OK;
}

void cs_puzzle_free(cs_puzzle *p) {
  free(p->links);
  p->links = NULL;
}

void cs_puzzle_id(const cs_puzzle *p, uint8_t id[32]) {
  uint8_t head[36];
  memcpy(head, MAGIC_PUZZLE, 4);
  cs_puzzle_ctx(p, head + 4);
  th(id, "chainseal/v1/puzzle-id", head, 36, p->commit, 32, p->links, (size_t)p->n * p->b, NULL, 0);
}

static void derive_key(const cs_puzzle *p, const uint8_t y_n[32], uint8_t key[32]) {
  uint8_t ctx[32];
  cs_puzzle_ctx(p, ctx);
  th(key, "chainseal/v1/key", ctx, 32, y_n, 32, NULL, 0, NULL, 0);
}

static void commitment(const cs_puzzle *p, const uint8_t key[32], uint8_t c[32]) {
  uint8_t ctx[32];
  cs_puzzle_ctx(p, ctx);
  th(c, "chainseal/v1/commit", ctx, 32, key, 32, NULL, 0, NULL, 0);
}

int cs_check_key(const cs_puzzle *p, const uint8_t key[32]) {
  uint8_t c[32];
  commitment(p, key, c);
  return ct_equal(c, p->commit, 32);
}

void cs_chain_start(const cs_puzzle *p, uint32_t i, const uint8_t *x, uint8_t s[32]) {
  uint8_t ctx[32], ib[4];
  cs_puzzle_ctx(p, ctx);
  store_be32(ib, i);
  th(s, "chainseal/v1/start", ctx, 32, ib, 4, x, p->b, NULL, 0);
}

static void chain_start(const cs_puzzle *p, uint32_t i, const uint8_t *x, uint32_t st[8]) {
  uint8_t s[32];
  cs_chain_start(p, i, x, s);
  bytes_to_words(st, s);
}

// ---------------------------------------------------------------- generation

typedef struct {
  const cs_puzzle *p;
  const chain_backend *be;
  const uint8_t *x;
  uint32_t (*y)[8];
  atomic_uint next;       // next unclaimed chain, 0-based
  _Atomic uint64_t done;  // chain steps finished, for progress reports
  atomic_int running;     // workers not yet finished
} gen_job;

#define GEN_CHUNK (1u << 22)

static void *gen_worker(void *arg) {
  gen_job *j = arg;
#ifdef __APPLE__
  // Let the scheduler use performance and efficiency cores alike.
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
  const uint32_t n = j->p->n;
  const uint64_t m = j->p->m;
  const int L = j->be->lanes;
  for (;;) {
    uint32_t c = atomic_fetch_add(&j->next, (unsigned)L);
    if (c >= n) break;
    int lanes = n - c < (uint32_t)L ? (int)(n - c) : L;
    chain_tail tails[CHAIN_MAX_LANES];
    for (int l = 0; l < lanes; l++) {
      uint32_t i = c + l + 1;
      chain_tail_init(&tails[l], j->p->salt, i);
      chain_start(j->p, i, j->x + (size_t)(i - 1) * j->p->b, j->y[i - 1]);
    }
    for (uint64_t k = 0; k < m;) {
      uint64_t steps = m - k < GEN_CHUNK ? m - k : GEN_CHUNK;
      j->be->run_lanes(j->y + c, tails, lanes, steps);
      k += steps;
      atomic_fetch_add(&j->done, steps * (uint64_t)lanes);
    }
  }
  atomic_fetch_sub(&j->running, 1);
  return NULL;
}

static int cpu_count(void) {
  long k = sysconf(_SC_NPROCESSORS_ONLN);
  return k > 0 ? (int)k : 1;
}

int cs_generate_from(cs_puzzle *p, uint8_t key[32], uint32_t n, uint64_t m, unsigned b, const uint8_t salt[16],
                     const uint8_t *x, const cs_gen_opts *o) {
  if (!cs_params_ok(n, m, b)) return CS_ERANGE;
  const cs_gen_opts none = {0};
  if (!o) o = &none;
  p->n = n, p->m = m, p->b = (uint8_t)b;
  memcpy(p->salt, salt, 16);
  uint32_t(*y)[8] = malloc((size_t)n * sizeof *y);
  if (!(p->links = malloc((size_t)n * b)) || !y) {
    free(p->links), free(y);
    p->links = NULL;
    return CS_ENOMEM;
  }
  gen_job job = {.p = p, .be = o->backend ? o->backend : chain_best(), .x = x, .y = y};
  int threads = o->threads > 0 ? o->threads : cpu_count();
  uint32_t groups = (n + job.be->lanes - 1) / job.be->lanes;
  if ((uint32_t)threads > groups) threads = (int)groups;
  atomic_init(&job.next, 0);
  atomic_init(&job.done, 0);
  atomic_init(&job.running, threads);
  pthread_t *tid = calloc((size_t)threads, sizeof *tid);
  int started = 0;
  if (tid)
    for (; started < threads; started++)
      if (pthread_create(&tid[started], NULL, gen_worker, &job)) break;
  if (started == 0) {  // no threads available: do it here
    atomic_store(&job.running, 1);
    gen_worker(&job);
  } else {
    atomic_fetch_sub(&job.running, threads - started);
    const struct timespec tick = {0, 100 * 1000 * 1000};
    if (o->progress)
      while (atomic_load(&job.running) > 0) {
        o->progress(o->progress_arg, atomic_load(&job.done), (uint64_t)n * m);
        nanosleep(&tick, NULL);
      }
  }
  for (int t = 0; t < started; t++) pthread_join(tid[t], NULL);
  free(tid);
  if (o->progress) o->progress(o->progress_arg, (uint64_t)n * m, (uint64_t)n * m);

  uint8_t yb[32];
  memcpy(p->links, x, b);
  for (uint32_t i = 1; i < n; i++) {  // z_i = y_i[0:b] xor x_{i+1}
    words_to_bytes(yb, y[i - 1]);
    for (unsigned k = 0; k < b; k++) p->links[(size_t)i * b + k] = yb[k] ^ x[(size_t)i * b + k];
  }
  words_to_bytes(yb, y[n - 1]);
  derive_key(p, yb, key);
  commitment(p, key, p->commit);
  if (o->x_out) memcpy(o->x_out, x, (size_t)n * b);
  if (o->y_out)
    for (uint32_t i = 0; i < n; i++) words_to_bytes(o->y_out + 32 * (size_t)i, y[i]);
  secure_zero(yb, sizeof yb);
  secure_zero(y, (size_t)n * sizeof *y);
  free(y);
  return CS_OK;
}

int cs_generate(cs_puzzle *p, uint8_t key[32], uint32_t n, uint64_t m, unsigned b, cs_rng *rng,
                const cs_gen_opts *o) {
  if (!cs_params_ok(n, m, b)) return CS_ERANGE;
  uint8_t salt[16], *x = malloc((size_t)n * b);
  if (!x) return CS_ENOMEM;
  int err = CS_ERNG;
  if (!rng_bytes(rng, salt, 16) && !rng_bytes(rng, x, (size_t)n * b))
    err = cs_generate_from(p, key, n, m, b, salt, x, o);
  secure_zero(x, (size_t)n * b);
  free(x);
  return err;
}

// ---------------------------------------------------------------- solving

int cs_guess_last_link(const cs_puzzle *p, const uint8_t *x_n, const chain_backend *be, uint8_t key[32]) {
  if (!be) be = chain_best();
  uint32_t st[8];
  uint8_t yb[32];
  chain_tail t;
  chain_start(p, p->n, x_n, st);
  chain_tail_init(&t, p->salt, p->n);
  be->run(st, &t, p->m);
  words_to_bytes(yb, st);
  derive_key(p, yb, key);
  return cs_check_key(p, key);
}

void cs_cursor_start(const cs_puzzle *p, cs_cursor *c) {
  c->i = 1, c->j = 0;
  chain_start(p, 1, p->links, c->st);
}

int cs_solve(const cs_puzzle *p, uint8_t key[32], cs_cursor *cur, const chain_backend *be, uint64_t every,
             cs_progress_fn fn, void *arg) {
  if (!be) be = chain_best();
  cs_cursor c;
  if (cur && cur->i)
    c = *cur;
  else
    cs_cursor_start(p, &c);
  if (c.i < 1 || c.i > p->n || c.j > p->m) return CS_ERANGE;
  uint8_t yb[32], x[CS_MAX_B];
  chain_tail tail;
  chain_tail_init(&tail, p->salt, c.i);
  for (;;) {
    while (c.j < p->m) {
      uint64_t steps = p->m - c.j;
      if (every && steps > every) steps = every;
      be->run(c.st, &tail, steps);
      c.j += steps;
      if (fn && fn(arg, &c)) {
        if (cur) *cur = c;
        return CS_ESTOPPED;
      }
    }
    if (c.i == p->n) break;
    words_to_bytes(yb, c.st);  // unhide x_{i+1} = y_i[0:b] xor z_i
    for (unsigned k = 0; k < p->b; k++) x[k] = yb[k] ^ p->links[(size_t)c.i * p->b + k];
    c.i++, c.j = 0;
    chain_start(p, c.i, x, c.st);
    chain_tail_init(&tail, p->salt, c.i);
  }
  words_to_bytes(yb, c.st);
  derive_key(p, yb, key);
  if (cur) *cur = c;
  secure_zero(yb, sizeof yb), secure_zero(x, sizeof x), secure_zero(&c, sizeof c);
  return cs_check_key(p, key) ? CS_OK : CS_EPUZZLE;
}

void cs_checkpoint_encode(const cs_puzzle *p, const cs_cursor *c, uint8_t out[CS_CHECKPOINT_SIZE]) {
  memcpy(out, MAGIC_CHECKPOINT, 4);
  out[4] = VERSION, out[5] = out[6] = out[7] = 0;
  cs_puzzle_id(p, out + 8);
  store_be32(out + 40, c->i);
  store_be64(out + 44, c->j);
  words_to_bytes(out + 52, c->st);
}

int cs_checkpoint_peek(const uint8_t *in, size_t len, uint8_t id[32], uint32_t *i, uint64_t *j) {
  if (len != CS_CHECKPOINT_SIZE || memcmp(in, MAGIC_CHECKPOINT, 4) || in[4] != VERSION || in[5] || in[6] || in[7])
    return CS_EFORMAT;
  memcpy(id, in + 8, 32);
  *i = load_be32(in + 40);
  *j = load_be64(in + 44);
  return *i < 1 || *i > CS_MAX_N || *j > CS_MAX_M ? CS_ERANGE : CS_OK;
}

int cs_checkpoint_decode(const cs_puzzle *p, cs_cursor *c, const uint8_t *in, size_t len) {
  uint8_t id[32], want[32];
  int err = cs_checkpoint_peek(in, len, id, &c->i, &c->j);
  if (err == CS_EFORMAT) return err;
  cs_puzzle_id(p, want);
  if (memcmp(id, want, 32)) return CS_EMISMATCH;
  if (err || c->i > p->n || c->j > p->m) return CS_ERANGE;
  bytes_to_words(c->st, in + 52);
  return CS_OK;
}

// ---------------------------------------------------------------- secrets

size_t cs_secret_size(const cs_puzzle *p) { return CS_SECRET_HEADER + cs_puzzle_size(p->n, p->b); }

void cs_secret_encode(const cs_puzzle *p, const uint8_t key[32], uint8_t *out) {
  memcpy(out, MAGIC_SECRET, 4);
  out[4] = VERSION, out[5] = out[6] = out[7] = 0;
  memcpy(out + 8, key, 32);
  cs_puzzle_encode(p, out + CS_SECRET_HEADER);
}

int cs_secret_decode(cs_puzzle *p, uint8_t key[32], const uint8_t *in, size_t len) {
  if (len < CS_SECRET_HEADER || memcmp(in, MAGIC_SECRET, 4) || in[4] != VERSION || in[5] || in[6] || in[7])
    return CS_EFORMAT;
  int err = cs_puzzle_decode(p, in + CS_SECRET_HEADER, len - CS_SECRET_HEADER);
  if (err) return err;
  memcpy(key, in + 8, 32);
  if (!cs_check_key(p, key)) {
    cs_puzzle_free(p);
    secure_zero(key, 32);
    return CS_ECOMMIT;
  }
  return CS_OK;
}

// ---------------------------------------------------------------- envelopes

size_t cs_envelope_size(const cs_puzzle *p, size_t msglen) {
  return 8 + cs_puzzle_size(p->n, p->b) + 16 + 4 + msglen + 32;
}

static void subkeys(const uint8_t key[32], const uint8_t nonce[16], uint8_t k_enc[32], uint8_t k_mac[32]) {
  th(k_enc, "chainseal/v1/enc", key, 32, nonce, 16, NULL, 0, NULL, 0);
  th(k_mac, "chainseal/v1/mac", key, 32, nonce, 16, NULL, 0, NULL, 0);
}

// out = in xor keystream(k_enc); in and out may alias.
static void keystream_xor(const uint8_t k_enc[32], const uint8_t *in, uint8_t *out, size_t len) {
  uint8_t ctr[8], block[32];
  for (uint64_t j = 0; len > 0; j++) {
    store_be64(ctr, j);
    hmac_sha256(block, k_enc, 32, ctr, 8);
    size_t take = len < 32 ? len : 32;
    for (size_t k = 0; k < take; k++) out[k] = in[k] ^ block[k];
    in += take, out += take, len -= take;
  }
  secure_zero(block, sizeof block);
}

int cs_seal(const cs_puzzle *p, const uint8_t key[32], const uint8_t nonce[16], const uint8_t *msg, size_t len,
            uint8_t *out) {
  if (len > CS_MAX_MSG) return CS_ERANGE;
  if (!cs_check_key(p, key)) return CS_ECOMMIT;
  size_t plen = cs_puzzle_size(p->n, p->b), at = 8 + plen;
  memcpy(out, MAGIC_ENVELOPE, 4);
  out[4] = VERSION, out[5] = out[6] = out[7] = 0;
  cs_puzzle_encode(p, out + 8);
  memcpy(out + at, nonce, 16);
  store_be32(out + at + 16, (uint32_t)len);
  uint8_t k_enc[32], k_mac[32];
  subkeys(key, nonce, k_enc, k_mac);
  keystream_xor(k_enc, msg, out + at + 20, len);
  hmac_sha256(out + at + 20 + len, k_mac, 32, out, at + 20 + len);
  secure_zero(k_enc, 32), secure_zero(k_mac, 32);
  return CS_OK;
}

int cs_envelope_decode(cs_envelope *e, const uint8_t *in, size_t len) {
  memset(e, 0, sizeof *e);
  if (len < 8 || memcmp(in, MAGIC_ENVELOPE, 4) || in[4] != VERSION || in[5] || in[6] || in[7]) return CS_EFORMAT;
  size_t plen;
  int err = puzzle_header(&e->puzzle, in + 8, len - 8, &plen);
  if (err) return err;
  size_t at = 8 + plen;
  if (len < at + 20 + 32) return CS_EFORMAT;
  uint32_t L = load_be32(in + at + 16);
  if (L > CS_MAX_MSG) return CS_ERANGE;
  if (len != at + 20 + (size_t)L + 32) return CS_EFORMAT;
  if ((err = cs_puzzle_decode(&e->puzzle, in + 8, plen))) return err;
  e->data = in, e->len = len;
  e->nonce = in + at, e->ct_len = L, e->ct = in + at + 20, e->tag = in + at + 20 + L;
  return CS_OK;
}

void cs_envelope_free(cs_envelope *e) { cs_puzzle_free(&e->puzzle); }

int cs_open(const cs_envelope *e, const uint8_t key[32], uint8_t *msg_out) {
  if (!cs_check_key(&e->puzzle, key)) return CS_ECOMMIT;
  uint8_t k_enc[32], k_mac[32], tag[32];
  subkeys(key, e->nonce, k_enc, k_mac);
  hmac_sha256(tag, k_mac, 32, e->data, e->len - 32);
  int ok = ct_equal(tag, e->tag, 32);
  if (ok) keystream_xor(k_enc, e->ct, msg_out, e->ct_len);
  secure_zero(k_enc, 32), secure_zero(k_mac, 32);
  return ok ? CS_OK : CS_ETAG;
}
