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
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
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
    pub fn code(what: impl Into<String>, code: Error) -> Self {
        Self {
            what: what.into(),
            code: Some(code),
            message: code.to_string(),
        }
    }
    /// Wrap an operating system failure.
    pub fn io(what: impl Into<String>, err: io::Error) -> Self {
        Self {
            what: what.into(),
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
    /// Matching C command-line exit status.
    pub fn exit_code(&self) -> i32 {
        match self.code {
            Some(Error::Commit | Error::Tag) => 3,
            Some(Error::Stopped) => 130,
            _ => 1,
        }
    }
}
/// Read a bounded file or standard input ("-").
pub fn read_file(path: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut reader: Box<dyn Read> = if path == "-" {
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
pub fn write_file(path: &str, data: &[u8], private: bool) -> io::Result<()> {
    if path == "-" {
        let mut o = io::stdout().lock();
        o.write_all(data)?;
        return o.flush();
    }
    let tmp = format!("{path}.tmp.{}", std::process::id());
    if tmp.len() >= 4096 {
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
pub fn load_secret(path: &str) -> std::result::Result<(Puzzle, [u8; 32]), Failure> {
    let mut d = read_file(path).map_err(|e| Failure::io(path, e))?;
    let r = secret_decode(&d).map_err(|e| Failure::code(path, e));
    d.fill(0);
    r
}
/// Save a secret with private permissions.
pub fn save_secret(path: &str, p: &Puzzle, key: &[u8; 32]) -> std::result::Result<(), Failure> {
    let mut d = secret_encode(p, key).map_err(|e| Failure::code(path, e))?;
    let r = write_file(path, &d, true).map_err(|e| Failure::io(path, e));
    d.fill(0);
    r
}
fn resolve(path: &str) -> PathBuf {
    let p = Path::new(path);
    let parent = p
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf())
        .join(p.file_name().unwrap_or(p.as_os_str()))
}
/// Compare output against a checkpoint, including redirected stdout and hard links.
pub fn is_output(out: &str, path: &str) -> bool {
    let a = if out == "-" {
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
    out != "-" && resolve(out).as_os_str().as_bytes() == resolve(path).as_os_str().as_bytes()
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
/// Decode a fixed-size hexadecimal key, allowing the C tool's trailing whitespace.
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
/// Format a count using the C tool's decimal prefixes.
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
/// Format elapsed time using the C tool's units.
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
    pub path: String,
    /// Original bytes (envelope or bare puzzle).
    pub data: Vec<u8>,
    /// Puzzle being solved.
    pub puzzle: Puzzle,
    /// Whether the source is an envelope.
    pub envelope: bool,
    /// Checkpoint path when enabled.
    pub checkpoint: Option<String>,
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
    pub fn load(path: &str, checkpoints: bool) -> std::result::Result<Self, Failure> {
        let data = read_file(path).map_err(|e| Failure::io(path, e))?;
        let envelope = data.starts_with(b"CSEN");
        let puzzle = if envelope {
            Envelope::decode(&data).map(|e| e.puzzle)
        } else {
            Puzzle::decode(&data)
        }
        .map_err(|e| Failure::code(path, e))?;
        let checkpoint = if checkpoints && path.len() + 5 < 4096 {
            Some(format!("{path}.ckpt"))
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
/// Solve one job per scoped thread, handling signals and periodic checkpoints.
/// The callback runs on the caller's thread.
pub fn solve_jobs(
    jobs: &mut [SolveJob],
    backend: Backend,
    stop_after: u64,
    ready: Option<&str>,
    mut progress: impl FnMut(&SolveProgress),
) -> io::Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    crate::signal::install(stop.clone())?;
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
    let outputs = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let begin = Instant::now();
        for job in jobs.iter() {
            let stop = &stop;
            handles.push(scope.spawn(move || {
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
            }));
        }
        let mut last = Instant::now() - Duration::from_secs(1);
        loop {
            let running = jobs
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
    Ok(())
}
/// Apply the same scheduler hint as the C command.
pub fn fast_qos() {
    crate::backend::fast_qos();
}
