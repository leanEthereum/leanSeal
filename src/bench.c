// Measurements: chain latency, parallel throughput, build time against n, and
// a toy run of the last-link guessing attack.
#include <getopt.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include "sha256.h"
#include "tool.h"

double measure_latency_ns(const chain_backend *be, double seconds) {
  uint32_t st[8] = {0};
  uint8_t salt[16] = {0};
  chain_tail t;
  chain_tail_init(&t, salt, 1);
  for (uint64_t steps = 1 << 12;;) {
    double t0 = now();
    be->run(st, &t, steps);
    double dt = now() - t0;
    if (dt >= seconds) return dt * 1e9 / steps;
    double grow = dt > 0 ? 1.1 * seconds / dt : 16;
    steps = (uint64_t)(steps * (grow > 16 ? 16 : grow < 1.5 ? 1.5 : grow));
  }
}

static int cmp_double(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return (x > y) - (x < y);
}

static void header(void) {
  struct utsname u;
  char model[256] = "";
  FILE *f = popen("sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2",
                  "r");
  if (f) {
    if (fgets(model, sizeof model, f)) model[strcspn(model, "\n")] = 0;
    pclose(f);
  }
  uname(&u);
  printf("# host %s %s, %d cpus, cpu:%s\n", u.sysname, u.machine, online_cpus(), model);
}

static int bench_latency(double seconds) {
  const chain_backend *all[4];
  int k = chain_backends(all, 4);
  printf("## latency: one chain, steps one after another\n");
  printf("%-12s %10s %10s %12s\n", "backend", "ns/step", "best", "M steps/s");
  for (int i = 0; i < k; i++) {
    double r[5];
    for (int t = 0; t < 5; t++) r[t] = measure_latency_ns(all[i], seconds / 5);
    qsort(r, 5, sizeof r[0], cmp_double);
    printf("%-12s %10.2f %10.2f %12.1f\n", all[i]->name, r[2], r[0], 1e3 / r[2]);
  }
  return 0;
}

typedef struct {
  const chain_backend *be;
  int lanes;
  atomic_int *stop;
  uint64_t steps;  // out: lane-steps done
} tp_job;

static void *tp_worker(void *arg) {
  tp_job *j = arg;
  set_fast_qos();
  uint32_t st[CHAIN_MAX_LANES][8] = {{0}};
  chain_tail t[CHAIN_MAX_LANES];
  uint8_t salt[16] = {0};
  for (int l = 0; l < j->lanes; l++) chain_tail_init(&t[l], salt, (uint32_t)l + 1);
  while (!atomic_load(j->stop)) {
    j->be->run_lanes(st, t, j->lanes, 1 << 14);
    j->steps += (uint64_t)j->lanes << 14;
  }
  return NULL;
}

// Aggregate chain steps per second with `threads` threads of `lanes` chains each.
static double throughput(const chain_backend *be, int threads, int lanes, double seconds) {
  atomic_int stop;
  atomic_init(&stop, 0);
  tp_job *jobs = calloc((size_t)threads, sizeof *jobs);
  pthread_t *tid = calloc((size_t)threads, sizeof *tid);
  double t0 = now();
  for (int i = 0; i < threads; i++) {
    jobs[i] = (tp_job){be, lanes, &stop, 0};
    pthread_create(&tid[i], NULL, tp_worker, &jobs[i]);
  }
  sleep_for(seconds);
  atomic_store(&stop, 1);
  uint64_t total = 0;
  for (int i = 0; i < threads; i++) pthread_join(tid[i], NULL), total += jobs[i].steps;
  double dt = now() - t0;
  free(jobs), free(tid);
  return total / dt;
}

static int bench_throughput(int threads, double seconds) {
  const chain_backend *be = chain_best();
  printf("## throughput: independent chains in parallel (%s)\n", be->name);
  printf("%8s %6s %14s %16s\n", "threads", "lanes", "M steps/s", "per thread");
  for (int lanes = 1; lanes <= be->lanes; lanes++) {
    double r = throughput(be, 1, lanes, seconds / 4);
    printf("%8d %6d %14.1f %16.1f\n", 1, lanes, r / 1e6, r / 1e6);
  }
  int counts[] = {2, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128};
  for (size_t i = 0; i < sizeof counts / sizeof counts[0] && counts[i] < threads; i++) {
    double r = throughput(be, counts[i], be->lanes, seconds / 4);
    printf("%8d %6d %14.1f %16.1f\n", counts[i], be->lanes, r / 1e6, r / 1e6 / counts[i]);
  }
  double r = throughput(be, threads, be->lanes, seconds);
  printf("%8d %6d %14.1f %16.1f   <- all cores\n", threads, be->lanes, r / 1e6, r / 1e6 / threads);
  return 0;
}

// Build time against the number of chains, for a fixed total work n*m.
static int bench_build(uint64_t work, int threads, unsigned b) {
  const chain_backend *be = chain_best();
  double ns = measure_latency_ns(be, 0.5);
  char a[32];
  printf("## build: total work n*m = %s steps, %d threads, %s, %.2f ns/step for one chain\n", fmt_si(a, (double)work),
         threads, be->name, ns);
  printf("%6s %12s %10s %12s %12s %10s %8s\n", "n", "m", "build s", "M steps/s", "solve s", "ratio", "bytes");
  cs_rng rng;
  rng_os(&rng);
  for (uint32_t n = 1; n <= 4096 && n <= work; n *= 2) {
    cs_puzzle p;
    uint8_t key[32];
    uint64_t m = work / n;
    cs_gen_opts o = {.threads = threads, .backend = be};
    double t0 = now();
    int err = cs_generate(&p, key, n, m, b, &rng, &o);
    double dt = now() - t0;
    if (err) return fprintf(stderr, "chainseal: %s\n", cs_strerror(err)), 1;
    double solve = (double)n * m * ns * 1e-9;
    printf("%6u %12llu %10.3f %12.1f %12.3f %10.2f %8zu\n", n, (unsigned long long)m, dt, (double)n * m / dt / 1e6,
           solve, solve / dt, cs_puzzle_size(n, b));
    fflush(stdout);
    cs_puzzle_free(&p);
  }
  return 0;
}

// Guessing ahead at toy sizes. The attacker solves chains 1..n-1 in sequence
// and meanwhile runs chain n from guesses of x_n; a right guess saves one chain.
// With b small enough to try a fixed fraction of all values, compare the
// success rate with the bound.
static int bench_attack(unsigned b, uint32_t n, uint64_t m, int trials, double fraction) {
  if (b > 3) return fprintf(stderr, "chainseal: attack needs -b 1, 2 or 3\n"), 1;
  uint64_t space = 1ull << (8 * b), budget = (uint64_t)(fraction * space);
  cs_rng rng;
  rng_os(&rng);
  uint8_t *y = malloc((size_t)n * 32);
  if (!y) return 1;
  int wins = 0;
  double t0 = now();
  for (int t = 0; t < trials; t++) {
    cs_puzzle p;
    uint8_t key[32], guess_key[32], g[4], x[4], mk[32];
    if (cs_generate(&p, key, n, m, b, &rng, NULL)) return free(y), 1;
    memcpy(x, p.links, b);
    for (uint32_t i = 1; i < n; i++) {  // the honest part: chains 1..n-1
      cs_run_chain(&p, i, x, NULL, y + 32 * (size_t)(i - 1));
      cs_chain_mask(&p, y + 32 * (size_t)(i - 1), mk);
      for (unsigned k = 0; k < b; k++) x[k] = mk[k] ^ p.links[(size_t)i * b + k];
    }
    uint32_t start;
    rng_bytes(&rng, (uint8_t *)&start, 4);
    for (uint64_t k = 0; k < budget; k++) {
      uint32_t v = (uint32_t)((start + k) & (space - 1));
      for (unsigned i = 0; i < b; i++) g[i] = (uint8_t)(v >> (8 * (b - 1 - i)));
      cs_run_chain(&p, n, g, NULL, y + 32 * (size_t)(n - 1));
      if (cs_key_from_ends(&p, y, guess_key)) {
        wins += !memcmp(key, guess_key, 32);
        break;
      }
    }
    cs_puzzle_free(&p);
  }
  free(y);
  double dt = now() - t0;
  double expect = (double)budget / space, sd = sqrt(trials * expect * (1 - expect));
  printf("## guessing ahead by one chain, b = %u (2^%u values), n = %u, m = %llu\n", b, 8 * b, n,
         (unsigned long long)m);
  printf("budget per puzzle   %llu guesses = %.3f of all values, %llu steps (honest solve: %llu)\n",
         (unsigned long long)budget, expect, (unsigned long long)(budget * m), (unsigned long long)(n * m));
  printf("opened early        %d of %d puzzles = %.3f; bound Q/(m*2^(8b)) = %.3f, expected %.1f +- %.1f\n", wins,
         trials, (double)wins / trials, expect, trials * expect, sd);
  printf("time                %.2f s\n", dt);
  return fabs(wins - trials * expect) <= 4 * sd + 1 ? 0 : 1;
}

int cmd_bench(int argc, char **argv) {
  double seconds = 2;
  int threads = online_cpus();
  uint64_t work = 1ull << 28, m = 16, n = 4, trials = 20000;
  unsigned b = 12, attack_b = 1;
  double fraction = 0.25;
  static const struct option longopts[] = {{"seconds", required_argument, 0, 's'},
                                           {"threads", required_argument, 0, 'j'},
                                           {"work", required_argument, 0, 'w'},
                                           {"link-bytes", required_argument, 0, 'b'},
                                           {"steps", required_argument, 0, 'm'},
                                           {"chains", required_argument, 0, 'n'},
                                           {"trials", required_argument, 0, 't'},
                                           {"fraction", required_argument, 0, 'f'},
                                           {0}};
  for (int c; (c = getopt_long(argc, argv, "s:j:w:b:m:n:t:f:", longopts, NULL)) != -1;) {
    uint64_t v = 0;
    char *end = NULL;
    int bad = 0;
    switch (c) {
      case 's': bad = parse_seconds(optarg, &seconds); break;
      case 'j': bad = parse_u64(optarg, &v) || v < 1 || v > 4096, threads = (int)v; break;
      case 'w': bad = parse_u64(optarg, &work) || work < 1; break;
      case 'b': bad = parse_u64(optarg, &v) || v < 1 || v > CS_MAX_B, b = attack_b = (unsigned)v; break;
      case 'm': bad = parse_u64(optarg, &m) || m < 1; break;
      case 'n': bad = parse_u64(optarg, &n) || n < 1 || n > CS_MAX_N; break;
      case 't': bad = parse_u64(optarg, &trials) || trials < 1 || trials > 1000000; break;
      case 'f': fraction = strtod(optarg, &end), bad = *end || !(fraction > 0 && fraction <= 1); break;
      default: bad = 1;
    }
    if (bad) return fprintf(stderr, "chainseal: bad bench option\n"), EXIT_USAGE;
  }
  const char *what = optind < argc ? argv[optind] : "all";
  int all = !strcmp(what, "all"), rc = 0, known = all;
  header();
  if (all || !strcmp(what, "latency")) known = 1, rc |= bench_latency(seconds);
  if (all || !strcmp(what, "throughput")) known = 1, rc |= bench_throughput(threads, seconds);
  if (all || !strcmp(what, "build")) known = 1, rc |= bench_build(work, threads, b);
  if (all || !strcmp(what, "attack")) known = 1, rc |= bench_attack(attack_b, (uint32_t)n, m, (int)trials, fraction);
  if (!known) return fprintf(stderr, "chainseal: bench latency|throughput|build|attack|all\n"), EXIT_USAGE;
  return rc;
}
