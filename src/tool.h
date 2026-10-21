// Helpers for the command-line tool. Not part of the library.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "chainseal.h"

enum { EXIT_USAGE = 2, EXIT_AUTH = 3, EXIT_STOPPED = 130 };

double now(void);  // monotonic, in seconds
void sleep_for(double seconds);
int online_cpus(void);
void set_fast_qos(void);  // ask macOS for a performance core; no-op elsewhere

// "-" is stdin / stdout. Files are capped at 64 MiB. write_file replaces the
// file atomically; `private_` creates it readable by the owner only.
int read_file(const char *path, uint8_t **out, size_t *len);
int write_file(const char *path, const uint8_t *data, size_t len, int private_);

void hex_encode(char *out, const uint8_t *in, size_t len);  // out has 2*len+1 bytes
int hex_decode(uint8_t *out, size_t len, const char *in);   // 0 if `in` is exactly 2*len hex digits
int parse_u64(const char *s, uint64_t *out);                // 1000, 1e6, 2^25
int parse_seconds(const char *s, double *out);              // 90, 1.5, 90s, 10m, 2h

const char *fmt_duration(char buf[32], double seconds);
const char *fmt_si(char buf[32], double x);  // 412.3 M

double measure_latency_ns(const chain_backend *be, double seconds);
int cmd_bench(int argc, char **argv);
int cmd_vectors(int argc, char **argv);
