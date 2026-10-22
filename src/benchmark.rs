//! Benchmark measurements, separated from command-line formatting.
use crate::{
    backend::{Backend, Tail},
    hash::bytes_to_words,
    *,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
/// Measure sequential chain latency, growing the batch until it spans seconds.
pub fn latency_ns(backend: Backend, seconds: f64) -> f64 {
    let mut st = [0; 8];
    let tail = Tail::new(&[0; 16], 1);
    let mut steps = 1 << 12;
    loop {
        let t0 = Instant::now();
        backend.run(std::hint::black_box(&mut st), &tail, steps);
        std::hint::black_box(st);
        let dt = t0.elapsed().as_secs_f64();
        if dt >= seconds {
            return dt * 1e9 / steps as f64;
        }
        let grow = if dt > 0. { 1.1 * seconds / dt } else { 16. };
        steps = (steps as f64 * grow.clamp(1.5, 16.)) as u64;
    }
}
/// Five-sample latency, returning median and best in nanoseconds.
pub fn latency_samples(backend: Backend, seconds: f64) -> (f64, f64) {
    let mut r = [0.; 5];
    for v in &mut r {
        *v = latency_ns(backend, seconds / 5.);
    }
    r.sort_by(f64::total_cmp);
    (r[2], r[0])
}
/// Aggregate independent chain steps per second.
pub fn throughput(
    backend: Backend,
    threads: usize,
    lanes: usize,
    seconds: f64,
) -> std::io::Result<f64> {
    let stop = AtomicBool::new(false);
    let t0 = Instant::now();
    let total = std::thread::scope(|scope| {
        let mut jobs = Vec::new();
        for _ in 0..threads {
            let stop = &stop;
            match crate::thread::spawn(scope, move || {
                crate::backend::fast_qos();
                let mut st = vec![[0; 8]; lanes];
                let tails: Vec<_> = (1..=lanes).map(|i| Tail::new(&[0; 16], i as u32)).collect();
                let mut total = 0;
                while !stop.load(Ordering::Relaxed) {
                    backend.run_lanes(std::hint::black_box(&mut st), &tails, 1 << 14);
                    total += (lanes as u64) << 14;
                }
                std::hint::black_box(st);
                total
            }) {
                Ok(job) => jobs.push(job),
                Err(e) => {
                    stop.store(true, Ordering::Relaxed);
                    for job in jobs {
                        let _ = job.join();
                    }
                    return Err(e);
                }
            }
        }
        std::thread::sleep(Duration::from_secs_f64(seconds));
        stop.store(true, Ordering::Relaxed);
        Ok(jobs.into_iter().map(|h| h.join().unwrap_or(0)).sum::<u64>())
    })?;
    Ok(total as f64 / t0.elapsed().as_secs_f64())
}
/// One build measurement.
pub struct BuildRow {
    /// Number of chains.
    pub n: u32,
    /// Steps per chain.
    pub m: u64,
    /// Build duration.
    pub seconds: f64,
    /// Serialized puzzle size.
    pub bytes: usize,
}
/// Measure building with a fixed total work and number of chains.
pub fn build(work: u64, n: u32, threads: usize, b: u8, backend: Backend) -> Result<BuildRow> {
    let m = work / u64::from(n);
    let t = Instant::now();
    let (p, _) = generate(
        n,
        m,
        b,
        &GenOptions {
            threads,
            backend: Some(backend),
            progress: None,
        },
    )?;
    Ok(BuildRow {
        n,
        m,
        seconds: t.elapsed().as_secs_f64(),
        bytes: 68 + p.links.len(),
    })
}
/// Results of the toy last-link guessing experiment.
pub struct AttackResult {
    /// Guesses per puzzle.
    pub budget: u64,
    /// Fraction of the link space tested, which is this strategy's expected success rate.
    pub expected: f64,
    /// Puzzles whose key was recovered by one of the guesses.
    pub wins: u64,
    /// Binomial standard deviation.
    pub sd: f64,
    /// Elapsed seconds.
    pub seconds: f64,
}
/// Run the toy experiment that guesses the last link (SPEC section 8).
///
/// It counts how often a candidate set of last links contains the right one,
/// which measures the success of this one guessing strategy. It does not run
/// the guesses as a parallel schedule or time them, so it does not show that a
/// puzzle opens early or test the bound of SPEC section 8.
pub fn attack(
    b: u8,
    n: u32,
    m: u64,
    trials: u64,
    fraction: f64,
    backend: Backend,
) -> Result<AttackResult> {
    if b > 3 || !params_ok(n, m, b) {
        return Err(Error::Range);
    }
    let space = 1u64 << (8 * b);
    let budget = (fraction * space as f64) as u64;
    let mut wins = 0;
    let t0 = Instant::now();
    for _ in 0..trials {
        let (p, key) = generate(n, m, b, &GenOptions::default())?;
        let mut y = vec![[0; 32]; n as usize];
        let mut x = p.links[..b as usize].to_vec();
        for i in 1..n {
            y[i as usize - 1] = p.run_chain(i, &x, backend)?;
            let mask = p.chain_mask(&y[i as usize - 1]);
            for k in 0..b as usize {
                x[k] = mask[k] ^ p.links[i as usize * b as usize + k];
            }
        }
        let mut random = [0; 4];
        getrandom::getrandom(&mut random).map_err(|_| Error::Rng)?;
        let start = u32::from_ne_bytes(random);
        for k in 0..budget {
            let v = (u64::from(start) + k) & (space - 1);
            let g = v.to_be_bytes();
            y[n as usize - 1] = p.run_chain(n, &g[8 - b as usize..], backend)?;
            if p.key_from_ends(&y) == Ok(key) {
                wins += 1;
                break;
            }
        }
    }
    let expected = budget as f64 / space as f64;
    Ok(AttackResult {
        budget,
        expected,
        wins,
        sd: (trials as f64 * expected * (1. - expected)).sqrt(),
        seconds: t0.elapsed().as_secs_f64(),
    })
}
/// Check every backend against ordinary SHA-256 with deterministic random states.
pub fn selftest() -> Result<Vec<(&'static str, bool)>> {
    selftest_with(|be, st, tails, steps| be.run_lanes(st, tails, steps))
}
fn selftest_with(
    mut run: impl FnMut(Backend, &mut [[u32; 8]], &[Tail], u64),
) -> Result<Vec<(&'static str, bool)>> {
    let mut rng = crate::rng::TestRng::new(b"selftest");
    let mut result = Vec::new();
    for be in Backend::available() {
        for lanes in 1..=be.lanes() {
            for steps in (1..=65).step_by(16) {
                let mut st = vec![[0; 8]; lanes];
                let mut tails = Vec::new();
                let mut want = Vec::new();
                for (l, s) in st.iter_mut().enumerate() {
                    let mut salt = [0; 16];
                    let mut state = [0; 32];
                    rng.fill(&mut salt);
                    rng.fill(&mut state);
                    let index = (l * 977 + steps) as u32;
                    tails.push(Tail::new(&salt, index));
                    *s = bytes_to_words(state);
                    let mut input = [0; 52];
                    input[..32].copy_from_slice(&state);
                    input[32..48].copy_from_slice(&salt);
                    input[48..].copy_from_slice(&index.to_be_bytes());
                    for _ in 0..steps {
                        let h = crate::hash::sha256(&input);
                        input[..32].copy_from_slice(&h);
                    }
                    want.push(bytes_to_words(crate::array(&input[..32])?));
                }
                run(be, &mut st, &tails, steps as u64);
                if st != want {
                    result.push((be.name(), false));
                    return Ok(result);
                }
            }
        }
        result.push((be.name(), true));
    }
    let mut salt = [0; 16];
    let mut x = [0; 80];
    rng.fill(&mut salt);
    rng.fill(&mut x);
    let (p, key, _) = generate_from(5, 1000, 16, salt, &x, &GenOptions::default())?;
    let mut cur = p.cursor();
    let got = p.solve(&mut cur, Backend::best()?, 0, |_| false)?;
    let env = seal(&p, &key, &[1; 16], b"selftest message")?;
    if Envelope::decode(&env)?.open(&got)? != b"selftest message" {
        return Err(Error::Tag);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn throughput_spawn_failure_stops_started_workers() {
        for started in 0..3 {
            let result =
                crate::thread::fail_after(started, || throughput(Backend::PORTABLE, 3, 1, 0.001));
            assert!(result.is_err());
        }
        assert!(throughput(Backend::PORTABLE, 1, 1, 0.001).unwrap() > 0.);
    }
    #[test]
    fn selftest_stops_at_first_mismatch() {
        let mut calls = 0;
        let result = selftest_with(|be, st, tails, steps| {
            calls += 1;
            be.run_lanes(st, tails, steps);
            st[0][0] ^= 1;
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(result, vec![(Backend::available()[0].name(), false)]);
    }
}
