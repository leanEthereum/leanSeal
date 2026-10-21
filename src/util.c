#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <pthread/qos.h>
#endif

#include "tool.h"

double now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + ts.tv_nsec * 1e-9;
}

void sleep_for(double seconds) {
  struct timespec ts = {(time_t)seconds, (long)((seconds - floor(seconds)) * 1e9)};
  nanosleep(&ts, NULL);
}

int online_cpus(void) {
  long k = sysconf(_SC_NPROCESSORS_ONLN);
  return k > 0 ? (int)k : 1;
}

void set_fast_qos(void) {
#ifdef __APPLE__
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
}

#define MAX_FILE (64u << 20)

int read_file(const char *path, uint8_t **out, size_t *len) {
  FILE *f = strcmp(path, "-") ? fopen(path, "rb") : stdin;
  if (!f) return -1;
  size_t cap = 1 << 16, n = 0;
  uint8_t *buf = malloc(cap);
  while (buf) {
    if (n == cap) {
      uint8_t *bigger = cap < MAX_FILE ? realloc(buf, cap * 2) : NULL;
      if (!bigger) {
        if (cap >= MAX_FILE) errno = EFBIG;
        free(buf), buf = NULL;
        break;
      }
      buf = bigger, cap *= 2;
    }
    size_t got = fread(buf + n, 1, cap - n, f);
    n += got;
    if (got == 0) {
      if (ferror(f)) free(buf), buf = NULL;
      break;
    }
  }
  if (f != stdin) fclose(f);
  if (!buf) return -1;
  *out = buf, *len = n;
  return 0;
}

int write_file(const char *path, const uint8_t *data, size_t len, int private_) {
  if (!strcmp(path, "-")) return fwrite(data, 1, len, stdout) == len && fflush(stdout) == 0 ? 0 : -1;
  char tmp[4096];
  if (snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof tmp) {
    errno = ENAMETOOLONG;
    return -1;
  }
  int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, private_ ? 0600 : 0644);
  if (fd < 0) return -1;
  for (size_t off = 0; off < len;) {
    ssize_t w = write(fd, data + off, len - off);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) goto fail;
    off += (size_t)w;
  }
  if (fsync(fd) || close(fd)) {
    fd = -1;
    goto fail;
  }
  if (rename(tmp, path)) {
    fd = -1;
    goto fail;
  }
  return 0;
fail:;
  int saved = errno;
  if (fd >= 0) close(fd);
  unlink(tmp);
  errno = saved;
  return -1;
}

void hex_encode(char *out, const uint8_t *in, size_t len) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) out[2 * i] = digits[in[i] >> 4], out[2 * i + 1] = digits[in[i] & 15];
  out[2 * len] = 0;
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int hex_decode(uint8_t *out, size_t len, const char *in) {
  size_t n = strlen(in);
  while (n > 0 && (in[n - 1] == '\n' || in[n - 1] == '\r' || in[n - 1] == ' ')) n--;
  if (n != 2 * len) return -1;
  for (size_t i = 0; i < len; i++) {
    int hi = hexval(in[2 * i]), lo = hexval(in[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)(hi << 4 | lo);
  }
  return 0;
}

int parse_u64(const char *s, uint64_t *out) {
  char *end;
  if (s[0] == '2' && s[1] == '^') {
    unsigned long e = strtoul(s + 2, &end, 10);
    if (end == s + 2 || *end || e > 63) return -1;
    *out = 1ull << e;
    return 0;
  }
  errno = 0;
  if (strspn(s, "0123456789") == strlen(s) && *s) {
    unsigned long long v = strtoull(s, &end, 10);
    if (errno) return -1;
    *out = v;
    return 0;
  }
  double d = strtod(s, &end);  // 1e6, 3.2e7
  if (end == s || *end || !(d >= 0) || d >= 18446744073709551616.0 || d != floor(d)) return -1;
  *out = (uint64_t)d;
  return 0;
}

int parse_seconds(const char *s, double *out) {
  char *end;
  double d = strtod(s, &end);
  if (end == s || !(d > 0) || !isfinite(d)) return -1;
  if (!strcmp(end, "") || !strcmp(end, "s")) *out = d;
  else if (!strcmp(end, "ms")) *out = d / 1e3;
  else if (!strcmp(end, "m") || !strcmp(end, "min")) *out = d * 60;
  else if (!strcmp(end, "h")) *out = d * 3600;
  else if (!strcmp(end, "d")) *out = d * 86400;
  else return -1;
  return isfinite(*out) ? 0 : -1;
}

const char *fmt_duration(char buf[32], double t) {
  if (t < 1e-3) snprintf(buf, 32, "%.0f us", t * 1e6);
  else if (t < 1) snprintf(buf, 32, "%.0f ms", t * 1e3);
  else if (t < 100) snprintf(buf, 32, "%.1f s", t);
  else if (t < 3600) snprintf(buf, 32, "%d min %02d s", (int)(t / 60), (int)fmod(t, 60));
  else if (t < 172800) snprintf(buf, 32, "%d h %02d min", (int)(t / 3600), (int)fmod(t / 60, 60));
  else snprintf(buf, 32, "%.1f days", t / 86400);
  return buf;
}

const char *fmt_si(char buf[32], double x) {
  static const char *units[] = {"", " k", " M", " G", " T", " P", " E"};
  int u = 0;
  while (fabs(x) >= 1000 && u < 6) x /= 1000, u++;
  snprintf(buf, 32, u ? "%.1f%s" : "%.0f%s", x, units[u]);
  return buf;
}
