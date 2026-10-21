// chainseal command-line tool.
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "chainseal.h"
#include "sha256.h"
#include "tool.h"

static const char USAGE[] =
    "usage: chainseal <command> [options]\n"
    "\n"
    "Sender:\n"
    "  gen -o SECRET (-m STEPS | -d DELAY) [-n CHAINS] [-b BYTES]\n"
    "        build a puzzle in advance and keep it, with its key, in SECRET\n"
    "  encrypt -o ENVELOPE (-s SECRET | -m STEPS | -d DELAY) [-i MESSAGE] [--secret-out FILE]\n"
    "        encrypt MESSAGE (default stdin) under a stored or freshly built puzzle\n"
    "  key SECRET            print the key, to open an envelope early\n"
    "\n"
    "Receiver:\n"
    "  solve FILE...         solve puzzles (envelopes or bare puzzles), one thread each,\n"
    "                        saving progress to FILE.ckpt; print each key\n"
    "  open ENVELOPE (-k KEY | -s SECRET | --solve) [-o MESSAGE]\n"
    "        check the key and the tag, then write the message (default stdout)\n"
    "  info FILE             describe a puzzle, envelope, secret or checkpoint\n"
    "\n"
    "Measurement:\n"
    "  bench [latency | throughput | build | attack | all]\n"
    "  selftest              check every backend against plain SHA-256, then a round trip\n"
    "  vectors               print the test vectors as JSON\n"
    "\n"
    "Puzzle options:\n"
    "  -n, --chains N        chains (default 64); match the sender's parallelism\n"
    "  -m, --steps M         hash steps per chain, e.g. 2^28\n"
    "  -d, --delay T         or: choose m for a delay of T (90, 10m, 2h) ...\n"
    "      --step-ns L       ... against a solver taking L ns per step (default: this machine)\n"
    "  -b, --link-bytes B    link width (default 12; see SPEC.md section 8)\n"
    "  -j, --threads J       build threads (default: all cores)\n"
    "  -q, --quiet\n"
    "\n"
    "Backends: set CHAINSEAL_BACKEND=portable|armv8-sha2|x86-sha-ni to override.\n";

static int usage_error(const char *msg) {
  if (msg) fprintf(stderr, "chainseal: %s\n", msg);
  fprintf(stderr, "run 'chainseal help' for usage\n");
  return EXIT_USAGE;
}

static int fail(const char *what, int err) {
  fprintf(stderr, "chainseal: %s: %s\n", what, cs_strerror(err));
  return err == CS_ECOMMIT || err == CS_ETAG ? EXIT_AUTH : 1;
}

static int fail_errno(const char *path) {
  fprintf(stderr, "chainseal: %s: %s\n", path, strerror(errno));
  return 1;
}

// Set by SIGINT and SIGTERM and by the main thread, read by solver threads.
// Lock-free atomics are safe to store from a signal handler.
static atomic_int g_stop;
static void on_signal(int sig) {
  (void)sig;
  atomic_store(&g_stop, 1);
}

// ---------------------------------------------------------------- building puzzles

typedef struct {
  uint32_t n;
  uint64_t m;
  unsigned b;
  double delay, step_ns;
  int threads, quiet;
} params;

#define PARAM_SHORT "n:m:d:b:j:q"
#define PARAM_LONG                                                                                    \
  {"chains", required_argument, 0, 'n'}, {"steps", required_argument, 0, 'm'},                        \
      {"delay", required_argument, 0, 'd'}, {"step-ns", required_argument, 0, 'L'},                   \
      {"link-bytes", required_argument, 0, 'b'}, {"threads", required_argument, 0, 'j'},              \
      {"quiet", no_argument, 0, 'q'}

// Returns 1 if c was a puzzle option, 0 if not, -1 on a bad value.
static int param_opt(params *P, int c, const char *arg) {
  uint64_t v;
  switch (c) {
    case 'n': return parse_u64(arg, &v) || v < 1 || v > CS_MAX_N ? -1 : (P->n = (uint32_t)v, 1);
    case 'm': return parse_u64(arg, &v) || v < 1 || v > CS_MAX_M ? -1 : (P->m = v, 1);
    case 'b': return parse_u64(arg, &v) || v < 1 || v > CS_MAX_B ? -1 : (P->b = (unsigned)v, 1);
    case 'j': return parse_u64(arg, &v) || v < 1 || v > 4096 ? -1 : (P->threads = (int)v, 1);
    case 'd': return parse_seconds(arg, &P->delay) ? -1 : 1;
    case 'L': {
      char *end;
      P->step_ns = strtod(arg, &end);
      return *end || !(P->step_ns > 0) || !isfinite(P->step_ns) ? -1 : 1;
    }
    case 'q': P->quiet = 1; return 1;
  }
  return 0;
}

static void gen_progress(void *arg, uint64_t done, uint64_t total) {
  double *t0 = arg;
  double el = now() - *t0;
  char a[32], b[32];
  fprintf(stderr, "\r  building: %5.1f%%  %s steps/s  %s ", 100.0 * done / total, fmt_si(a, el > 0 ? done / el : 0),
          fmt_duration(b, el));
}

// Build a fresh puzzle. Returns an exit code.
static int build(params *P, cs_puzzle *p, uint8_t key[32]) {
  const chain_backend *be = chain_best();
  int measured = 0;
  if (!P->m) {
    if (!(P->delay > 0)) return usage_error("give the work per chain (-m STEPS) or a delay (-d SECONDS)");
    if (!(P->step_ns > 0)) P->step_ns = measure_latency_ns(be, 0.3), measured = 1;
    // Divide the two times first: an overflow becomes inf and is rejected, and an
    // underflow only happens when one chain step already covers the delay.
    double m = ceil(P->delay / P->step_ns * 1e9 / P->n);
    if (!(m <= (double)CS_MAX_M)) return fail("delay", CS_ERANGE);
    P->m = m < 1 ? 1 : (uint64_t)m;
  }
  cs_rng rng;
  rng_os(&rng);
  double t0 = now();
  cs_gen_opts o = {.threads = P->threads, .backend = be};
  if (!P->quiet && isatty(2)) o.progress = gen_progress, o.progress_arg = &t0;
  int err = cs_generate(p, key, P->n, P->m, P->b, &rng, &o);
  double dt = now() - t0;
  if (o.progress) fprintf(stderr, "\n");
  if (err) return fail("building the puzzle", err);
  if (!P->quiet) {
    if (!(P->step_ns > 0)) P->step_ns = measure_latency_ns(be, 0.2), measured = 1;
    double work = (double)P->n * P->m;
    char a[32], b[32], c[32], d[32];
    fprintf(stderr,
            "puzzle: n = %u chains, m = %llu steps each, b = %u-byte links, %zu bytes\n"
            "built in %s on %d threads (%s), %s steps/s\n"
            "solving takes n*m = %s steps: %s at %.1f ns/step%s\n",
            P->n, (unsigned long long)P->m, P->b, cs_puzzle_size(P->n, P->b), fmt_duration(a, dt),
            P->threads ? P->threads : online_cpus(), be->name, fmt_si(b, work / dt), fmt_si(c, work),
            fmt_duration(d, work * P->step_ns * 1e-9), P->step_ns, measured ? " (one chain on this machine)" : "");
    if (P->b < 11)
      fprintf(stderr,
              "warning: %u-byte links can be guessed; SPEC.md section 8 recommends 12 bytes\n", P->b);
  }
  return 0;
}

static int load_secret(const char *path, cs_puzzle *p, uint8_t key[32]) {
  uint8_t *data;
  size_t len;
  if (read_file(path, &data, &len)) return fail_errno(path);
  int err = cs_secret_decode(p, key, data, len);
  secure_zero(data, len);
  free(data);
  return err ? fail(path, err) : 0;
}

static int save_secret(const char *path, const cs_puzzle *p, const uint8_t key[32]) {
  size_t len = cs_secret_size(p);
  uint8_t *buf = malloc(len);
  if (!buf) return fail(path, CS_ENOMEM);
  cs_secret_encode(p, key, buf);
  int rc = write_file(path, buf, len, 1) ? fail_errno(path) : 0;
  secure_zero(buf, len);
  free(buf);
  return rc;
}

static int cmd_gen(int argc, char **argv) {
  params P = {.n = 64, .b = 12};
  const char *out = NULL;
  static const struct option longopts[] = {PARAM_LONG, {"out", required_argument, 0, 'o'}, {0}};
  for (int c; (c = getopt_long(argc, argv, PARAM_SHORT "o:", longopts, NULL)) != -1;) {
    if (c == 'o') out = optarg;
    else if (param_opt(&P, c, optarg) != 1) return usage_error(NULL);
  }
  if (!out || optind != argc) return usage_error("gen needs -o SECRET and no other arguments");
  cs_puzzle p;
  uint8_t key[32];
  int rc = build(&P, &p, key);
  if (rc) return rc;
  rc = save_secret(out, &p, key);
  if (!rc && !P.quiet) fprintf(stderr, "wrote %s (keep it private until you use it)\n", out);
  secure_zero(key, 32);
  cs_puzzle_free(&p);
  return rc;
}

static int cmd_encrypt(int argc, char **argv) {
  params P = {.n = 64, .b = 12};
  const char *out = NULL, *in = NULL, *secret = NULL, *secret_out = NULL;
  static const struct option longopts[] = {PARAM_LONG,
                                           {"out", required_argument, 0, 'o'},
                                           {"in", required_argument, 0, 'i'},
                                           {"secret", required_argument, 0, 's'},
                                           {"secret-out", required_argument, 0, 'S'},
                                           {0}};
  for (int c; (c = getopt_long(argc, argv, PARAM_SHORT "o:i:s:", longopts, NULL)) != -1;) {
    if (c == 'o') out = optarg;
    else if (c == 'i') in = optarg;
    else if (c == 's') secret = optarg;
    else if (c == 'S') secret_out = optarg;
    else if (param_opt(&P, c, optarg) != 1) return usage_error(NULL);
  }
  if (!in && optind < argc) in = argv[optind++];
  if (!out || optind != argc) return usage_error("encrypt needs -o ENVELOPE and at most one message file");
  if (secret && (P.m || P.delay > 0 || secret_out)) return usage_error("-s uses a stored puzzle: no -m, -d or --secret-out");

  uint8_t *msg;
  size_t len;
  if (read_file(in ? in : "-", &msg, &len)) return fail_errno(in ? in : "stdin");
  if (len > CS_MAX_MSG) {
    free(msg);
    return fail(in ? in : "stdin", CS_ERANGE);
  }
  cs_puzzle p;
  uint8_t key[32], nonce[16];
  int rc = secret ? load_secret(secret, &p, key) : build(&P, &p, key);
  if (rc) {
    free(msg);
    return rc;
  }
  cs_rng rng;
  rng_os(&rng);
  size_t elen = cs_envelope_size(&p, len);
  uint8_t *env = malloc(elen);
  int err = !env ? CS_ENOMEM : rng_bytes(&rng, nonce, 16) ? CS_ERNG : cs_seal(&p, key, nonce, msg, len, env);
  if (err) rc = fail("encrypting", err);
  else if (write_file(out, env, elen, 0)) rc = fail_errno(out);
  else if (secret_out) rc = save_secret(secret_out, &p, key);
  if (!rc && !P.quiet)
    fprintf(stderr, "wrote %s: %zu bytes (puzzle %zu + message %zu + %u)\n", out, elen,
            cs_puzzle_size(p.n, p.b), len, CS_ENVELOPE_OVERHEAD);
  secure_zero(key, 32);
  secure_zero(msg, len);
  free(msg), free(env);
  cs_puzzle_free(&p);
  return rc;
}

static int cmd_key(int argc, char **argv) {
  if (argc != 2) return usage_error("key takes one SECRET file");
  cs_puzzle p;
  uint8_t key[32];
  int rc = load_secret(argv[1], &p, key);
  if (rc) return rc;
  char hex[65];
  hex_encode(hex, key, 32);
  printf("%s\n", hex);
  secure_zero(key, 32), secure_zero(hex, sizeof hex);
  cs_puzzle_free(&p);
  return 0;
}

// ---------------------------------------------------------------- solving

#define SOLVE_EVERY (1u << 20)
#define CHECKPOINT_SECONDS 10.0

typedef struct {
  const char *path;
  uint8_t *data;
  size_t len;
  cs_envelope env;  // when the file is an envelope
  cs_puzzle bare;   // when it is a bare puzzle
  const cs_puzzle *p;
  char ckpt[4096];  // empty: no checkpoints
  cs_cursor cur;
  uint64_t start_done;      // steps already done when this run began
  _Atomic uint64_t done;    // steps done, for progress
  atomic_int finished;
  int solved;  // the key is valid
  double t0, t1, last_save;
  int err;
  uint8_t key[32];
} solve_job;

static uint64_t cursor_done(const cs_puzzle *p, const cs_cursor *c) { return (uint64_t)(c->i - 1) * p->m + c->j; }

static int save_checkpoint(solve_job *s, const cs_cursor *c) {
  uint8_t buf[CS_CHECKPOINT_SIZE];
  cs_checkpoint_encode(s->p, c, buf);
  return write_file(s->ckpt, buf, sizeof buf, 1);
}

// For tests: CHAINSEAL_TEST_STOP_AFTER=STEPS stops every solve after about
// that many steps, as if interrupted, and CHAINSEAL_TEST_READY=FILE creates
// FILE once a solve will save a checkpoint on SIGINT.
static uint64_t g_stop_after;
static const char *g_ready_file;

static int solve_progress(void *arg, const cs_cursor *c) {
  solve_job *s = arg;
  atomic_store(&s->done, cursor_done(s->p, c));
  if (g_stop_after && atomic_load(&s->done) - s->start_done >= g_stop_after) atomic_store(&g_stop, 1);
  if (s->ckpt[0] && now() - s->last_save >= CHECKPOINT_SECONDS) {
    save_checkpoint(s, c);  // best effort; failures surface when stopping
    s->last_save = now();
  }
  return atomic_load(&g_stop);
}

static void *solve_thread(void *arg) {
  solve_job *s = arg;
  set_fast_qos();
  s->t0 = s->last_save = now();
  s->err = cs_solve(s->p, s->key, &s->cur, NULL, SOLVE_EVERY, solve_progress, s);
  s->solved = !s->err;
  s->t1 = now();
  atomic_store(&s->finished, 1);
  return NULL;
}

// Load an envelope or bare puzzle and its checkpoint. Returns an exit code.
static int solve_open(solve_job *s, const char *path, int checkpoints) {
  memset(s, 0, sizeof *s);
  s->path = path;
  if (read_file(path, &s->data, &s->len)) return fail_errno(path);
  int err;
  if (s->len >= 4 && !memcmp(s->data, "CSEN", 4)) {
    if ((err = cs_envelope_decode(&s->env, s->data, s->len))) return fail(path, err);
    s->p = &s->env.puzzle;
  } else {
    if ((err = cs_puzzle_decode(&s->bare, s->data, s->len))) return fail(path, err);
    s->p = &s->bare;
  }
  cs_cursor_start(s->p, &s->cur);
  if (checkpoints && snprintf(s->ckpt, sizeof s->ckpt, "%s.ckpt", path) < (int)sizeof s->ckpt) {
    uint8_t *ck;
    size_t cklen;
    if (!read_file(s->ckpt, &ck, &cklen)) {
      err = cs_checkpoint_decode(s->p, &s->cur, ck, cklen);
      free(ck);
      if (err == CS_EMISMATCH) {
        fprintf(stderr, "chainseal: %s belongs to a different puzzle; remove it or pass --no-checkpoint\n", s->ckpt);
        return 1;
      }
      if (err) return fail(s->ckpt, err);
      char a[32];
      fprintf(stderr, "%s: resuming at chain %u of %u, %s steps done\n", path, s->cur.i, s->p->n,
              fmt_si(a, (double)cursor_done(s->p, &s->cur)));
    } else if (errno != ENOENT) {
      return fail_errno(s->ckpt);
    }
  } else {
    s->ckpt[0] = 0;
  }
  s->start_done = cursor_done(s->p, &s->cur);
  atomic_init(&s->done, s->start_done);
  atomic_init(&s->finished, 0);
  return 0;
}

static void solve_close(solve_job *s) {
  secure_zero(s->key, 32);
  secure_zero(&s->cur, sizeof s->cur);
  if (s->p == &s->env.puzzle) cs_envelope_free(&s->env);
  else cs_puzzle_free(&s->bare);
  free(s->data);
}

static void print_progress(solve_job *jobs, int k, double t0) {
  double done = 0, total = 0, fresh = 0;  // summed over puzzles: may exceed 64 bits
  int running = 0;
  for (int i = 0; i < k; i++) {
    uint64_t d = atomic_load(&jobs[i].done);
    done += (double)d, fresh += (double)(d - jobs[i].start_done), total += (double)jobs[i].p->n * jobs[i].p->m;
    running += !atomic_load(&jobs[i].finished);
  }
  double el = now() - t0, rate = el > 0 ? fresh / el : 0;
  char a[32], b[32], c[32];
  if (k == 1) {
    const solve_job *s = &jobs[0];
    uint32_t chain = (uint32_t)(done / s->p->m) + 1;
    if (chain > s->p->n) chain = s->p->n;
    double left = rate > 0 ? (total - done) / rate : 0;
    fprintf(stderr, "\r  chain %u/%u  %5.1f%%  %s steps/s (%.1f ns/step)  %s, about %s left ", chain, s->p->n,
            100.0 * done / total, fmt_si(a, rate), rate > 0 ? 1e9 / rate : 0, fmt_duration(b, el),
            fmt_duration(c, left));
  } else {
    fprintf(stderr, "\r  %d of %d puzzles running  %5.1f%%  %s steps/s in all  %s ", running, k,
            100.0 * done / total, fmt_si(a, rate), fmt_duration(b, el));
  }
}

// Solve k jobs in parallel. Returns an exit code.
static int solve_all(solve_job *jobs, int k, int quiet) {
  struct sigaction sa = {0};
  sa.sa_handler = on_signal;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  if (g_ready_file) {
    int fd = open(g_ready_file, O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) close(fd);
  }
  pthread_t *tid = calloc((size_t)k, sizeof *tid);
  if (!tid) return fail("solve", CS_ENOMEM);
  int started = 0;
  for (; started < k; started++)
    if (pthread_create(&tid[started], NULL, solve_thread, &jobs[started])) break;
  if (started < k) {
    atomic_store(&g_stop, 1);
    fprintf(stderr, "chainseal: could not start %d solver threads\n", k);
  }
  double t0 = now(), last = 0;
  int show = !quiet && isatty(2);
  for (;;) {
    int all = 1;
    for (int i = 0; i < started; i++) all &= atomic_load(&jobs[i].finished);
    if (all) break;
    if (show && now() - last >= 0.5) print_progress(jobs, k, t0), last = now();
    sleep_for(0.05);
  }
  for (int i = 0; i < started; i++) pthread_join(tid[i], NULL);
  free(tid);
  if (show) print_progress(jobs, k, t0), fprintf(stderr, "\n");

  int rc = started < k ? 1 : 0;
  for (int i = 0; i < started; i++) {
    solve_job *s = &jobs[i];
    char a[32];
    double el = s->t1 - s->t0, steps = (double)(atomic_load(&s->done) - s->start_done);
    if (s->err == CS_ESTOPPED) {
      if (s->ckpt[0] && save_checkpoint(s, &s->cur)) rc = fail_errno(s->ckpt);
      else if (s->ckpt[0]) fprintf(stderr, "%s: stopped; progress saved to %s\n", s->path, s->ckpt);
      else fprintf(stderr, "%s: stopped\n", s->path);
      if (!rc) rc = EXIT_STOPPED;
    } else if (s->err) {
      rc = fail(s->path, s->err);
    } else {
      if (!quiet)
        fprintf(stderr, "%s: solved in %s, %.2f ns/step\n", s->path, fmt_duration(a, el),
                steps > 0 ? el * 1e9 / steps : 0);
    }
  }
  return rc;
}

static int cmd_solve(int argc, char **argv) {
  int checkpoints = 1, quiet = 0;
  static const struct option longopts[] = {
      {"no-checkpoint", no_argument, 0, 'N'}, {"quiet", no_argument, 0, 'q'}, {0}};
  for (int c; (c = getopt_long(argc, argv, "q", longopts, NULL)) != -1;) {
    if (c == 'N') checkpoints = 0;
    else if (c == 'q') quiet = 1;
    else return usage_error(NULL);
  }
  int k = argc - optind;
  if (k < 1) return usage_error("solve needs at least one file");
  solve_job *jobs = calloc((size_t)k, sizeof *jobs);
  if (!jobs) return fail("solve", CS_ENOMEM);
  int rc = 0, opened = 0;
  for (; opened < k && !rc; opened++) rc = solve_open(&jobs[opened], argv[optind + opened], checkpoints);
  if (!rc) rc = solve_all(jobs, k, quiet);
  // Print every key that was found, even if another job failed, and only
  // then remove its checkpoint.
  for (int i = 0; i < opened; i++) {
    if (jobs[i].solved) {
      char hex[65];
      hex_encode(hex, jobs[i].key, 32);
      if (printf("%s  %s\n", hex, jobs[i].path) < 0 || fflush(stdout)) rc = fail_errno("stdout");
      else if (jobs[i].ckpt[0]) unlink(jobs[i].ckpt);
      secure_zero(hex, sizeof hex);
    }
    solve_close(&jobs[i]);
  }
  free(jobs);
  return rc;
}

// ---------------------------------------------------------------- opening

static int read_key(const char *arg, uint8_t key[32]) {
  if (!hex_decode(key, 32, arg)) return 0;
  uint8_t *data;
  size_t len;
  if (read_file(arg, &data, &len)) return usage_error("-k takes 64 hex digits or a file holding them");
  char text[80] = {0};
  memcpy(text, data, len < sizeof text - 1 ? len : sizeof text - 1);
  secure_zero(data, len);
  free(data);
  int bad = len >= sizeof text || hex_decode(key, 32, text);
  secure_zero(text, sizeof text);
  return bad ? usage_error("-k takes 64 hex digits or a file holding them") : 0;
}

static int cmd_open(int argc, char **argv) {
  const char *out = "-", *keyarg = NULL, *secret = NULL;
  int solve = 0, checkpoints = 1, quiet = 0;
  static const struct option longopts[] = {{"out", required_argument, 0, 'o'},
                                           {"key", required_argument, 0, 'k'},
                                           {"secret", required_argument, 0, 's'},
                                           {"solve", no_argument, 0, 'X'},
                                           {"no-checkpoint", no_argument, 0, 'N'},
                                           {"quiet", no_argument, 0, 'q'},
                                           {0}};
  for (int c; (c = getopt_long(argc, argv, "o:k:s:q", longopts, NULL)) != -1;) {
    if (c == 'o') out = optarg;
    else if (c == 'k') keyarg = optarg;
    else if (c == 's') secret = optarg;
    else if (c == 'X') solve = 1;
    else if (c == 'N') checkpoints = 0;
    else if (c == 'q') quiet = 1;
    else return usage_error(NULL);
  }
  if (optind != argc - 1 || (!!keyarg + !!secret + solve) != 1)
    return usage_error("open takes one ENVELOPE and exactly one of -k KEY, -s SECRET, --solve");
  solve_job s;
  int rc = solve_open(&s, argv[optind], solve && checkpoints);
  if (!rc && s.p != &s.env.puzzle) {
    fprintf(stderr, "chainseal: %s is a bare puzzle, not an envelope\n", s.path);
    rc = 1;
  }
  if (!rc && s.ckpt[0] && strcmp(out, "-") && same_path(out, s.ckpt))
    rc = usage_error("the output file is the checkpoint file; choose another -o or use --no-checkpoint");
  if (!rc) {
    if (solve) {
      rc = solve_all(&s, 1, quiet);
    } else if (keyarg) {
      rc = read_key(keyarg, s.key);
    } else {
      cs_puzzle sp;
      rc = load_secret(secret, &sp, s.key);
      if (!rc) cs_puzzle_free(&sp);
    }
  }
  if (!rc) {
    uint8_t *msg = malloc(s.env.ct_len ? s.env.ct_len : 1);
    int err = msg ? cs_open(&s.env, s.key, msg) : CS_ENOMEM;
    if (err) rc = fail(s.path, err);
    else if (write_file(out, msg, s.env.ct_len, 0)) rc = fail_errno(out);
    // On a case-insensitive filesystem the check above can miss an alias, so
    // compare the files themselves now that the output exists.
    else if (solve && s.ckpt[0] && (!strcmp(out, "-") || !same_path(out, s.ckpt))) unlink(s.ckpt);
    if (msg) secure_zero(msg, s.env.ct_len), free(msg);
  }
  if (s.data) solve_close(&s);
  return rc;
}

// ---------------------------------------------------------------- info

static void print_puzzle(const cs_puzzle *p) {
  char hex[65], a[32], b[32];
  uint8_t id[32];
  double work = (double)p->n * p->m;
  double ns = measure_latency_ns(chain_best(), 0.1);
  hex_encode(hex, p->salt, 16);
  printf("  chains n       %u\n  steps/chain m  %llu\n  link bytes b   %u\n  salt           %s\n", p->n,
         (unsigned long long)p->m, p->b, hex);
  hex_encode(hex, p->commit, 32);
  printf("  commitment     %s\n", hex);
  cs_puzzle_id(p, id);
  hex_encode(hex, id, 32);
  printf("  puzzle id      %s\n  puzzle size    %zu bytes\n", hex, cs_puzzle_size(p->n, p->b));
  printf("  work n*m       %s steps: %s here at %.1f ns/step\n", fmt_si(a, work), fmt_duration(b, work * ns * 1e-9),
         ns);
  printf("  last-link guess  each costs m steps, succeeds with chance 2^-%u\n", 8 * p->b);
}

static int cmd_info(int argc, char **argv) {
  if (argc != 2) return usage_error("info takes one file");
  uint8_t *data;
  size_t len;
  if (read_file(argv[1], &data, &len)) return fail_errno(argv[1]);
  int err = CS_EFORMAT;
  if (len >= 4 && !memcmp(data, "CSPZ", 4)) {
    cs_puzzle p;
    if (!(err = cs_puzzle_decode(&p, data, len))) printf("%s: puzzle\n", argv[1]), print_puzzle(&p), cs_puzzle_free(&p);
  } else if (len >= 4 && !memcmp(data, "CSEN", 4)) {
    cs_envelope e;
    if (!(err = cs_envelope_decode(&e, data, len))) {
      char hex[33];
      hex_encode(hex, e.nonce, 16);
      printf("%s: envelope, %zu bytes\n  message        %u bytes\n  nonce          %s\n", argv[1], len, e.ct_len, hex);
      print_puzzle(&e.puzzle);
      cs_envelope_free(&e);
    }
  } else if (len >= 4 && !memcmp(data, "CSSK", 4)) {
    cs_puzzle p;
    uint8_t key[32];
    if (!(err = cs_secret_decode(&p, key, data, len))) {
      printf("%s: secret (puzzle with its key; the key matches the commitment)\n", argv[1]);
      print_puzzle(&p);
      cs_puzzle_free(&p);
      secure_zero(key, 32);
    }
  } else if (len >= 4 && !memcmp(data, "CSCK", 4)) {
    uint8_t id[32];
    uint32_t i;
    uint64_t j;
    if (!(err = cs_checkpoint_peek(data, len, id, &i, &j))) {
      char hex[65];
      hex_encode(hex, id, 32);
      printf("%s: checkpoint\n  puzzle id      %s\n  chain i        %u\n  steps done j   %llu\n", argv[1], hex, i,
             (unsigned long long)j);
    }
  }
  secure_zero(data, len);
  free(data);
  return err ? fail(argv[1], err) : 0;
}

// ---------------------------------------------------------------- selftest

static int cmd_selftest(int argc, char **argv) {
  (void)argc, (void)argv;
  const chain_backend *all[4];
  int k = chain_backends(all, 4), bad = 0;
  cs_rng rng;
  rng_test(&rng, "selftest", 8);
  for (int b = 0; b < k; b++) {
    for (int lanes = 1; lanes <= all[b]->lanes; lanes++) {
      for (uint64_t steps = 1; steps <= 65; steps += 16) {
        uint32_t st[CHAIN_MAX_LANES][8], want[CHAIN_MAX_LANES][8];
        chain_tail t[CHAIN_MAX_LANES];
        uint8_t in[52];
        for (int l = 0; l < lanes; l++) {
          uint8_t salt[16], s[32];
          rng_bytes(&rng, salt, 16), rng_bytes(&rng, s, 32);
          uint32_t index = (uint32_t)(l * 977 + steps);
          chain_tail_init(&t[l], salt, index);
          for (int w = 0; w < 8; w++) st[l][w] = load_be32(s + 4 * w);
          memcpy(in, s, 32), memcpy(in + 32, salt, 16), store_be32(in + 48, index);
          for (uint64_t j = 0; j < steps; j++) sha256(in, in, 52);  // in[0:32] is the state
          for (int w = 0; w < 8; w++) want[l][w] = load_be32(in + 4 * w);
        }
        all[b]->run_lanes(st, t, lanes, steps);
        if (memcmp(st, want, sizeof(st[0]) * lanes)) bad++;
      }
    }
    printf("backend %-12s %s\n", all[b]->name, bad ? "MISMATCH" : "ok");
    if (bad) return 1;
  }
  cs_puzzle p;
  cs_envelope e;
  uint8_t key[32], key2[32], nonce[16] = {1}, env[512], msg[16];
  int err = cs_generate(&p, key, 5, 1000, 12, &rng, NULL);
  if (!err) err = cs_seal(&p, key, nonce, (const uint8_t *)"selftest message", 16, env);
  if (!err) err = cs_solve(&p, key2, NULL, NULL, 0, NULL, NULL);
  if (!err) err = cs_envelope_decode(&e, env, cs_envelope_size(&p, 16));
  if (!err) err = cs_open(&e, key2, msg), cs_envelope_free(&e);
  if (!err && memcmp(msg, "selftest message", 16)) err = CS_ETAG;
  cs_puzzle_free(&p);
  printf("round trip           %s\n", err ? cs_strerror(err) : "ok");
  return err ? 1 : 0;
}

// ---------------------------------------------------------------- main

int main(int argc, char **argv) {
  static const struct {
    const char *name;
    int (*fn)(int, char **);
  } commands[] = {{"gen", cmd_gen},   {"encrypt", cmd_encrypt},   {"key", cmd_key},     {"solve", cmd_solve},
                  {"open", cmd_open}, {"info", cmd_info},         {"bench", cmd_bench}, {"selftest", cmd_selftest},
                  {"vectors", cmd_vectors}};
  set_fast_qos();
  const char *stop_after = getenv("CHAINSEAL_TEST_STOP_AFTER");
  if (stop_after && parse_u64(stop_after, &g_stop_after)) return usage_error("bad CHAINSEAL_TEST_STOP_AFTER");
  g_ready_file = getenv("CHAINSEAL_TEST_READY");
  const char *forced = getenv("CHAINSEAL_BACKEND");
  if (forced && !chain_find(forced)) {
    fprintf(stderr, "chainseal: CHAINSEAL_BACKEND=%s is not available on this machine; available:", forced);
    const chain_backend *all[4];
    for (int i = 0, k = chain_backends(all, 4); i < k; i++) fprintf(stderr, " %s", all[i]->name);
    fprintf(stderr, "\n");
    return EXIT_USAGE;
  }
  if (argc < 2) return usage_error(NULL);
  if (!strcmp(argv[1], "help") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
    fputs(USAGE, stdout);
    return 0;
  }
  for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++)
    if (!strcmp(argv[1], commands[i].name)) return commands[i].fn(argc - 1, argv + 1);
  return usage_error("unknown command");
}
