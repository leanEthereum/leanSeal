// chainseal: time-lock encryption from SHA-256 chains. See SPEC.md.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include "chain.h"
#include "rng.h"

#define CS_MAX_N (1u << 20)
#define CS_MAX_M (1ull << 48)
#define CS_MAX_WORK (1ull << 60)  // bound on n*m, so step counts fit in 64 bits
#define CS_MAX_B 32u
#define CS_MAX_MSG (1u << 24)
#define CS_PUZZLE_HEADER 68u
#define CS_ENVELOPE_OVERHEAD 60u  // envelope bytes beyond the puzzle and the message
#define CS_SECRET_HEADER 40u
#define CS_CHECKPOINT_SIZE 116u

enum {
  CS_OK = 0,
  CS_EFORMAT,    // malformed encoding
  CS_ERANGE,     // parameter out of range
  CS_ECOMMIT,    // key does not match the commitment
  CS_ETAG,       // authentication tag mismatch
  CS_EPUZZLE,    // solved to the end, but the result does not match the commitment
  CS_EMISMATCH,  // checkpoint belongs to a different puzzle
  CS_ENOMEM,
  CS_ERNG,
  CS_ESTOPPED,   // solving stopped by the progress callback
};
const char *cs_strerror(int err);

typedef struct {
  uint32_t n;
  uint64_t m;
  uint8_t b;
  uint8_t salt[16];
  uint8_t commit[32];
  uint8_t *links;  // n*b bytes: x_1, then z_1 .. z_{n-1}
} cs_puzzle;

int cs_params_ok(uint32_t n, uint64_t m, unsigned b);
size_t cs_puzzle_size(uint32_t n, unsigned b);
void cs_puzzle_ctx(const cs_puzzle *p, uint8_t ctx[32]);
void cs_puzzle_encode(const cs_puzzle *p, uint8_t *out);  // cs_puzzle_size bytes
int cs_puzzle_decode(cs_puzzle *p, const uint8_t *in, size_t len);
void cs_puzzle_free(cs_puzzle *p);
void cs_puzzle_id(const cs_puzzle *p, uint8_t id[32]);
int cs_check_key(const cs_puzzle *p, const uint8_t key[32]);  // 1 if the key matches the commitment
// The start value s_i of chain i from its link x_i (SPEC.md section 4).
void cs_chain_start(const cs_puzzle *p, uint32_t i, const uint8_t *x, uint8_t s[32]);

// ---- generation
typedef struct {
  int threads;                   // 0: all online CPUs
  const chain_backend *backend;  // NULL: chain_best()
  uint8_t *x_out;                // optional, n*b bytes: the links (test vectors only)
  uint8_t *y_out;                // optional, n*32 bytes: the chain ends (test vectors only)
  // Optional; called about every 100 ms from the calling thread while workers run.
  void (*progress)(void *arg, uint64_t done, uint64_t total);
  void *progress_arg;
} cs_gen_opts;

int cs_generate(cs_puzzle *p, uint8_t key[32], uint32_t n, uint64_t m, unsigned b, cs_rng *rng,
                const cs_gen_opts *o);
// The same with the randomness given: salt and the n links x_1..x_n.
int cs_generate_from(cs_puzzle *p, uint8_t key[32], uint32_t n, uint64_t m, unsigned b, const uint8_t salt[16],
                     const uint8_t *x, const cs_gen_opts *o);

// ---- solving
typedef struct {
  uint32_t i;      // current chain, 1..n
  uint64_t j;      // steps of chain i done, 0..m
  uint32_t st[8];  // state after j steps
  uint8_t acc[32]; // a_{i-1}, the hash of the ends of chains 1..i-1 (SPEC.md section 4)
} cs_cursor;

// Called every `every` steps and at the end of every chain; return nonzero to stop.
typedef int (*cs_progress_fn)(void *arg, const cs_cursor *c);

void cs_cursor_start(const cs_puzzle *p, cs_cursor *c);
// Solve from *cur (or from the start if cur is NULL). On CS_ESTOPPED, *cur holds the
// position to resume from. Returns CS_EPUZZLE, with the derived key in `key`, when
// the chains end in a key that does not match the commitment.
int cs_solve(const cs_puzzle *p, uint8_t key[32], cs_cursor *cur, const chain_backend *be, uint64_t every,
             cs_progress_fn fn, void *arg);

// Run chain i alone from a link x_i, known or guessed, and return its end y_i.
// Guessing ahead (SPEC.md section 8) runs chains from guessed links this way.
void cs_run_chain(const cs_puzzle *p, uint32_t i, const uint8_t *x, const chain_backend *be, uint8_t y[32]);
// The key from all n chain ends y (n*32 bytes). Returns 1 if it matches the commitment.
int cs_key_from_ends(const cs_puzzle *p, const uint8_t *y, uint8_t key[32]);

void cs_checkpoint_encode(const cs_puzzle *p, const cs_cursor *c, uint8_t out[CS_CHECKPOINT_SIZE]);
int cs_checkpoint_decode(const cs_puzzle *p, cs_cursor *c, const uint8_t *in, size_t len);
// Check a checkpoint's format without its puzzle and read its puzzle id and position.
int cs_checkpoint_peek(const uint8_t *in, size_t len, uint8_t id[32], uint32_t *i, uint64_t *j);

// ---- secrets: a puzzle built in advance, with its key
size_t cs_secret_size(const cs_puzzle *p);
void cs_secret_encode(const cs_puzzle *p, const uint8_t key[32], uint8_t *out);
int cs_secret_decode(cs_puzzle *p, uint8_t key[32], const uint8_t *in, size_t len);

// ---- envelopes
typedef struct {
  cs_puzzle puzzle;
  const uint8_t *data;  // the whole envelope
  size_t len;
  const uint8_t *nonce, *ct, *tag;
  uint32_t ct_len;
} cs_envelope;

size_t cs_envelope_size(const cs_puzzle *p, size_t msglen);
int cs_seal(const cs_puzzle *p, const uint8_t key[32], const uint8_t nonce[16], const uint8_t *msg, size_t len,
            uint8_t *out);
// Pointers in *e point into `in`, which must outlive *e.
int cs_envelope_decode(cs_envelope *e, const uint8_t *in, size_t len);
void cs_envelope_free(cs_envelope *e);
// Checks the key against the commitment, then the tag, then writes ct_len bytes.
int cs_open(const cs_envelope *e, const uint8_t key[32], uint8_t *msg_out);
