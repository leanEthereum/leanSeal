#include "rng.h"

#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#if defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#endif

void rng_os(cs_rng *r) {
  memset(r, 0, sizeof *r);
}

void rng_test(cs_rng *r, const void *seed, size_t len) {
  memset(r, 0, sizeof *r);
  r->deterministic = 1;
  sha256(r->seed, seed, len);
}

static int os_bytes(uint8_t *out, size_t len) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  arc4random_buf(out, len);
  return 0;
#elif defined(__linux__)
  while (len > 0) {
    ssize_t got = getrandom(out, len, 0);
    if (got < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    out += got, len -= (size_t)got;
  }
  return 0;
#else
#error "no OS random source for this platform"
#endif
}

int rng_bytes(cs_rng *r, uint8_t *out, size_t len) {
  if (!r->deterministic) return os_bytes(out, len);
  while (len > 0) {
    uint8_t ctr[8], block[32];
    store_be64(ctr, r->counter++);
    th(block, "chainseal/test-rng", r->seed, 32, ctr, 8, NULL, 0, NULL, 0);
    size_t take = len < 32 ? len : 32;
    memcpy(out, block, take);
    out += take, len -= take;
  }
  return 0;
}
