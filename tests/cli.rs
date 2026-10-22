use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Result<Temp, std::io::Error> {
    let mut random = [0; 8];
    getrandom::getrandom(&mut random).map_err(|e| std::io::Error::other(e.to_string()))?;
    let p = std::env::temp_dir().join(format!(
        "chainseal-rust-test-{}-{}",
        std::process::id(),
        u64::from_ne_bytes(random)
    ));
    fs::create_dir(&p)?;
    Ok(Temp(p))
}
fn command(t: &Temp) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_chainseal"));
    c.current_dir(&t.0)
        .env_remove("CHAINSEAL_TEST_STOP_AFTER")
        .env_remove("CHAINSEAL_TEST_READY");
    c
}
#[test]
fn cli_checkpoint_stop_resume_and_signals() -> TestResult {
    let t = temp()?;
    assert!(command(&t)
        .args([
            "encrypt",
            "-q",
            "-n",
            "4",
            "-m",
            "2^22",
            "-o",
            "env",
            "--secret-out",
            "secret"
        ])
        .stdin(Stdio::null())
        .status()?
        .success());
    assert_eq!(
        fs::metadata(t.0.join("secret"))?.permissions().mode() & 0o777,
        0o600
    );
    let stopped = command(&t)
        .args(["solve", "-q", "env"])
        .env("CHAINSEAL_TEST_STOP_AFTER", "2^21")
        .output()?;
    assert_eq!(stopped.status.code(), Some(130));
    assert_eq!(fs::metadata(t.0.join("env.ckpt"))?.len(), 116);
    let resumed = command(&t).args(["solve", "-q", "env"]).output()?;
    assert!(resumed.status.success());
    assert!(String::from_utf8_lossy(&resumed.stderr).contains("resuming"));
    let key = command(&t).args(["key", "secret"]).output()?;
    assert!(key.status.success());
    assert!(resumed
        .stdout
        .starts_with(key.stdout.strip_suffix(b"\n").ok_or("key newline")?));
    assert!(!t.0.join("env.ckpt").exists());
    let mut env = fs::read(t.0.join("env"))?;
    env[20..28].copy_from_slice(&(1u64 << 40).to_be_bytes());
    fs::write(t.0.join("endless"), &env)?;
    for signal in ["-INT", "-TERM"] {
        let _ = fs::remove_file(t.0.join("ready"));
        let mut child = command(&t)
            .args(["solve", "-q", "endless"])
            .env("CHAINSEAL_TEST_READY", "ready")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let start = Instant::now();
        while !t.0.join("ready").exists() && start.elapsed() < Duration::from_secs(10) {
            thread::sleep(Duration::from_millis(10));
        }
        if !t.0.join("ready").exists() {
            child.kill()?;
            let _ = child.wait();
            return Err("signal handler never became ready".into());
        }
        assert!(Command::new("kill")
            .args([signal, &child.id().to_string()])
            .status()?
            .success());
        loop {
            if let Some(status) = child.try_wait()? {
                assert_eq!(status.code(), Some(130));
                break;
            }
            if start.elapsed() > Duration::from_secs(10) {
                child.kill()?;
                let _ = child.wait();
                return Err("signal stop timed out".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::metadata(t.0.join("endless.ckpt"))?.len(), 116);
    }
    Ok(())
}

#[test]
fn cli_c_numeric_syntax_and_backend_override() -> TestResult {
    let t = temp()?;
    for steps in ["2", "2^1", "2e0", "0x2", "0X1p+1"] {
        let out = command(&t)
            .env("CHAINSEAL_BACKEND", "portable")
            .args(["gen", "-q", "-n", "1", "-m", steps, "-o", "-"])
            .output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let (p, _) = chainseal::secret_decode(&out.stdout)?;
        assert_eq!((p.m(), p.b()), (2, 16));
    }
    for (delay, step_ns, want) in [
        ("0x1.00000000000008p0", "1e9", 1),
        ("0x1.00000000000008001p0", "1e9", 2),
        ("0x0.0000000000001p-1022", "3e-315", 2),
        ("0x1d", "1e9", 29),
        ("0x1p0ms", "1e6", 1),
    ] {
        let out = command(&t)
            .args([
                "gen",
                "-q",
                "-n",
                "1",
                "-d",
                delay,
                "--step-ns",
                step_ns,
                "-o",
                "-",
            ])
            .output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(chainseal::secret_decode(&out.stdout)?.0.m(), want);
    }
    let unavailable = command(&t)
        .env("CHAINSEAL_BACKEND", "unavailable")
        .arg("help")
        .output()?;
    assert_eq!(unavailable.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("is not available"));
    Ok(())
}
