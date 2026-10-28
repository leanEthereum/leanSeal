//! File handling and concurrent resumable solves shared by command-line clients.
use crate::{backend::Backend, *};
use std::os::fd::AsFd;
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt},
};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};

/// Runtime failures with an associated path or operation.
#[derive(Debug)]
pub struct Failure {
    /// Operation or path that failed.
    pub what: String,
    /// Format/cryptographic error, when applicable.
    pub code: Option<Error>,
    /// Human-readable operating system failure.
    pub message: String,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.what, self.message)
    }
}
impl std::error::Error for Failure {}
impl Failure {
    /// Wrap a library failure.
    pub fn code(what: impl AsRef<std::ffi::OsStr>, code: Error) -> Self {
        Self {
            what: Path::new(what.as_ref()).display().to_string(),
            code: Some(code),
            message: code.to_string(),
        }
    }
    /// Wrap an operating system failure.
    pub fn io(what: impl AsRef<std::ffi::OsStr>, err: io::Error) -> Self {
        Self {
            what: Path::new(what.as_ref()).display().to_string(),
            code: None,
            message: {
                let text = err.to_string();
                let suffix = err.raw_os_error().map(|n| format!(" (os error {n})"));
                suffix
                    .as_ref()
                    .and_then(|s| text.strip_suffix(s))
                    .unwrap_or(&text)
                    .to_owned()
            },
        }
    }
    /// Command-line exit status for this failure.
    pub fn exit_code(&self) -> i32 {
        match self.code {
            Some(Error::Commit | Error::Tag) => 3,
            Some(Error::Stopped) => 130,
            _ => 1,
        }
    }
}
/// Read a bounded file or standard input ("-").
pub fn read_file(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    let mut out = Vec::new();
    let mut reader: Box<dyn Read> = if path == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(path)?)
    };
    reader.by_ref().take((64 << 20) + 1).read_to_end(&mut out)?;
    if out.len() >= 64 << 20 {
        return Err(io::Error::from_raw_os_error(27));
    }
    Ok(out)
}
/// Write through a new temporary file, fsync, and rename. Secrets use mode 0600.
pub fn write_file(path: impl AsRef<Path>, data: &[u8], private: bool) -> io::Result<()> {
    let path = path.as_ref();
    if path == Path::new("-") {
        let mut o = io::stdout().lock();
        o.write_all(data)?;
        return o.flush();
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    if tmp.as_os_str().len() >= 4096 {
        return Err(io::Error::from_raw_os_error(if cfg!(target_os = "macos") {
            63
        } else {
            36
        }));
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if private { 0o600 } else { 0o644 })
        .open(&tmp)?;
    let result = (|| {
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
/// Load a secret and check its key.
pub fn load_secret(path: impl AsRef<Path>) -> std::result::Result<(Puzzle, [u8; 32]), Failure> {
    let path = path.as_ref();
    let mut d = read_file(path).map_err(|e| Failure::io(path, e))?;
    let r = secret_decode(&d).map_err(|e| Failure::code(path, e));
    crate::secret::wipe(&mut d);
    r
}
/// Save a secret with private permissions.
pub fn save_secret(
    path: impl AsRef<Path>,
    p: &Puzzle,
    key: &[u8; 32],
) -> std::result::Result<(), Failure> {
    let path = path.as_ref();
    let mut d = secret_encode(p, key).map_err(|e| Failure::code(path, e))?;
    let r = write_file(path, &d, true).map_err(|e| Failure::io(path, e));
    crate::secret::wipe(&mut d);
    r
}
fn resolve(p: &Path) -> PathBuf {
    let parent = p
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf())
        .join(p.file_name().unwrap_or(p.as_os_str()))
}
/// Compare output (a path or "-") against another file, including redirected stdout and hard links.
pub fn is_output(out: impl AsRef<Path>, path: impl AsRef<Path>) -> bool {
    let out = out.as_ref();
    let path = path.as_ref();
    let a = if out == Path::new("-") {
        io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .and_then(|fd| fs::File::from(fd).metadata())
    } else {
        fs::metadata(out)
    };
    if let (Ok(a), Ok(b)) = (a, fs::metadata(path)) {
        return a.dev() == b.dev() && a.ino() == b.ino();
    }
    out != Path::new("-")
        && resolve(out).as_os_str().as_bytes() == resolve(path).as_os_str().as_bytes()
}
/// Lowercase hexadecimal encoding.
pub fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}
/// Decode a fixed-size hexadecimal key, allowing trailing whitespace.
pub fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let s = text.trim_end_matches(['\r', '\n', ' ']).as_bytes();
    if s.len() != 2 * N {
        return Err(Error::Format);
    }
    let mut out = [0; N];
    fn digit(b: u8) -> Result<u8> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(Error::Format),
        }
    }
    for (v, pair) in out.iter_mut().zip(s.chunks_exact(2)) {
        *v = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(out)
}
/// Format a count with decimal prefixes (k, M, G, ...).
pub fn fmt_si(mut x: f64) -> String {
    let units = ["", " k", " M", " G", " T", " P", " E"];
    let mut u = 0;
    while x.abs() >= 1000. && u < 6 {
        x /= 1000.;
        u += 1;
    }
    if u == 0 {
        format!("{x:.0}")
    } else {
        format!("{x:.1}{}", units[u])
    }
}
/// Format elapsed time in the units the tool prints.
pub fn fmt_duration(t: f64) -> String {
    if t < 1e-3 {
        format!("{:.0} us", t * 1e6)
    } else if t < 1. {
        format!("{:.0} ms", t * 1e3)
    } else if t < 100. {
        format!("{t:.1} s")
    } else if t < 3600. {
        format!("{:.0} min {:02.0} s", (t / 60.).floor(), (t % 60.).floor())
    } else if t < 172800. {
        format!(
            "{:.0} h {:02.0} min",
            (t / 3600.).floor(),
            ((t / 60.) % 60.).floor()
        )
    } else {
        format!("{:.1} days", t / 86400.)
    }
}
/// A loaded solve, including a possible checkpoint.
pub struct SolveJob {
    /// Source path.
    pub path: PathBuf,
    /// Original bytes (envelope or bare puzzle).
    pub data: Vec<u8>,
    /// Puzzle being solved.
    pub puzzle: Puzzle,
    /// Whether the source is an envelope.
    pub envelope: bool,
    /// Checkpoint path when enabled.
    pub checkpoint: Option<PathBuf>,
    /// Current cursor.
    pub cursor: Cursor,
    /// Steps completed before this run.
    pub start_done: u64,
    /// Whether a checkpoint was loaded.
    pub resumed: bool,
    /// Result key or error after running.
    pub result: Option<Result<[u8; 32]>>,
    /// Time spent in the solver.
    pub elapsed: f64,
    /// Checkpoint write failure on stop.
    pub save_error: Option<io::Error>,
    done: AtomicU64,
    finished: AtomicBool,
}
impl SolveJob {
    /// Load a puzzle/envelope and, optionally, its checkpoint.
    pub fn load(path: impl AsRef<Path>, checkpoints: bool) -> std::result::Result<Self, Failure> {
        let path = path.as_ref();
        let data = read_file(path).map_err(|e| Failure::io(path, e))?;
        let envelope = data.starts_with(b"LSEN");
        let puzzle = if envelope {
            Envelope::decode(&data).map(|e| e.puzzle)
        } else {
            Puzzle::decode(&data)
        }
        .map_err(|e| Failure::code(path, e))?;
        let checkpoint = if checkpoints && path.as_os_str().len() + 5 < 4096 {
            let mut ck = path.as_os_str().to_os_string();
            ck.push(".ckpt");
            Some(PathBuf::from(ck))
        } else {
            None
        };
        let mut cursor = puzzle.cursor();
        let mut resumed = false;
        if let Some(ck) = &checkpoint {
            match read_file(ck) {
                Ok(d) => {
                    cursor = Cursor::decode(&puzzle, &d).map_err(|e| Failure::code(ck, e))?;
                    resumed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(Failure::io(ck, e)),
            }
        }
        let start_done = cursor.done(&puzzle);
        Ok(Self {
            path: path.into(),
            data,
            puzzle,
            envelope,
            checkpoint,
            cursor,
            start_done,
            resumed,
            result: None,
            elapsed: 0.,
            save_error: None,
            done: AtomicU64::new(start_done),
            finished: AtomicBool::new(false),
        })
    }
    /// Progress count suitable for concurrent UI reads.
    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }
}
/// Concurrent progress snapshot.
pub struct SolveProgress {
    /// Completed steps across all jobs.
    pub done: f64,
    /// Newly completed steps.
    pub fresh: f64,
    /// Total work.
    pub total: f64,
    /// Jobs still running.
    pub running: usize,
    /// Elapsed seconds.
    pub elapsed: f64,
}
/// Solve one job per scoped thread, with periodic checkpoints. Setting `stop`
/// stops every job and checkpoints it; the caller owns the flag, for example
/// to set it from a signal handler installed before `ready` is created.
/// The callback runs on the caller's thread.
pub fn solve_jobs(
    jobs: &mut [SolveJob],
    backend: Backend,
    stop: &AtomicBool,
    stop_after: u64,
    ready: Option<&Path>,
    mut progress: impl FnMut(&SolveProgress),
) -> io::Result<()> {
    if let Some(path) = ready {
        let _ = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path);
    }
    struct Output {
        cur: Cursor,
        result: Result<[u8; 32]>,
        elapsed: f64,
        save_error: Option<io::Error>,
    }
    let mut spawn_failed = false;
    let outputs = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let begin = Instant::now();
        for job in jobs.iter() {
            match crate::thread::spawn(scope, move || {
                crate::backend::fast_qos();
                let t0 = Instant::now();
                let mut last = Instant::now();
                let mut cur = job.cursor.clone();
                let result = job.puzzle.solve(&mut cur, backend, 1 << 20, |c| {
                    let done = c.done(&job.puzzle);
                    job.done.store(done, Ordering::Relaxed);
                    if stop_after > 0 && done - job.start_done >= stop_after {
                        stop.store(true, Ordering::Relaxed);
                    }
                    if last.elapsed().as_secs_f64() >= 10. {
                        if let Some(path) = &job.checkpoint {
                            if let Ok(data) = c.encode(&job.puzzle) {
                                let _ = write_file(path, &data, true);
                            }
                        }
                        last = Instant::now();
                    }
                    stop.load(Ordering::Relaxed)
                });
                job.done.store(cur.done(&job.puzzle), Ordering::Relaxed);
                let save_error = if result == Err(Error::Stopped) {
                    job.checkpoint
                        .as_ref()
                        .and_then(|path| match cur.encode(&job.puzzle) {
                            Ok(data) => write_file(path, &data, true).err(),
                            Err(e) => Some(io::Error::other(e)),
                        })
                } else {
                    None
                };
                job.finished.store(true, Ordering::Release);
                Output {
                    cur,
                    result,
                    elapsed: t0.elapsed().as_secs_f64(),
                    save_error,
                }
            }) {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    spawn_failed = true;
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
        let started = handles.len();
        let mut last = Instant::now() - Duration::from_secs(1);
        loop {
            let running = jobs[..started]
                .iter()
                .filter(|j| !j.finished.load(Ordering::Acquire))
                .count();
            if running == 0 || last.elapsed().as_secs_f64() >= 0.5 {
                let done = jobs.iter().map(|j| j.done() as f64).sum();
                progress(&SolveProgress {
                    done,
                    fresh: jobs.iter().map(|j| (j.done() - j.start_done) as f64).sum(),
                    total: jobs
                        .iter()
                        .map(|j| j.puzzle.n as f64 * j.puzzle.m as f64)
                        .sum(),
                    running,
                    elapsed: begin.elapsed().as_secs_f64(),
                });
                last = Instant::now();
            }
            if running == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .map_err(|_| io::Error::other("solver thread failed"))
            })
            .collect::<io::Result<Vec<_>>>()
    })?;
    for (job, out) in jobs.iter_mut().zip(outputs) {
        job.cursor = out.cur;
        job.result = Some(out.result);
        job.elapsed = out.elapsed;
        job.save_error = out.save_error;
    }
    if spawn_failed {
        // Save every cursor after joining: this includes all work since the last
        // periodic save, completed workers, and jobs that never started.
        for job in jobs.iter_mut() {
            job.save_error =
                job.checkpoint
                    .as_ref()
                    .and_then(|path| match job.cursor.encode(&job.puzzle) {
                        Ok(data) => write_file(path, &data, true).err(),
                        Err(e) => Some(io::Error::other(e)),
                    });
        }
        return Err(io::Error::other(format!(
            "could not start {} solver threads",
            jobs.len()
        )));
    }
    Ok(())
}
/// Ask the OS to run this thread on a performance core (macOS only).
pub fn fast_qos() {
    crate::backend::fast_qos();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn solver_spawn_failure_saves_all_current_cursors(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        struct Temp(PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let dir = Temp(std::env::temp_dir().join(format!(
            "leanseal-spawn-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random)
        )));
        fs::create_dir(&dir.0)?;
        let be = Backend::PORTABLE;
        let (p, key, _) = generate_from(
            3,
            100,
            12,
            [7; 16],
            &[11; 36],
            &GenOptions {
                threads: 1,
                backend: Some(be),
                progress: None,
            },
        )?;
        for started in 0..3 {
            let mut jobs = Vec::new();
            for i in 0..3 {
                let path = dir.0.join(format!("puzzle-{started}-{i}"));
                fs::write(&path, p.encode()?)?;
                let mut job = SolveJob::load(&path, true)?;
                assert_eq!(
                    p.solve(&mut job.cursor, be, 2, |_| true),
                    Err(Error::Stopped)
                );
                fs::write(job.checkpoint.as_ref().unwrap(), job.cursor.encode(&p)?)?;
                jobs.push(SolveJob::load(&path, true)?);
            }
            let failure = crate::thread::fail_after(started, || {
                solve_jobs(&mut jobs, be, &AtomicBool::new(false), 0, None, |_| {})
            })
            .unwrap_err();
            assert_eq!(failure.to_string(), "could not start 3 solver threads");
            for (i, job) in jobs.iter().enumerate() {
                assert!(job.save_error.is_none());
                let mut restored =
                    Cursor::decode(&p, &fs::read(job.checkpoint.as_ref().unwrap())?)?;
                assert_eq!(restored, job.cursor);
                assert_eq!(restored.done(&p), job.done());
                if i < started {
                    assert!(restored.done(&p) > job.start_done);
                } else {
                    assert_eq!(restored.done(&p), job.start_done);
                }
                assert_eq!(p.solve(&mut restored, be, 0, |_| false)?, key);
            }
        }
        Ok(())
    }
}
