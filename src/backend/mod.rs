//! Runtime-selected SHA-256 chain engines.
use crate::hash::{compress, IV};
#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "x86_64")]
mod x86;

/// Fixed salt words and chain index.
#[derive(Clone, Copy, Debug)]
pub struct Tail(pub(crate) [u32; 5]);
impl Tail {
    /// Prepare the constant words of a 52-byte chain message.
    pub fn new(salt: &[u8; 16], index: u32) -> Self {
        let mut w = [0; 5];
        for (v, b) in w.iter_mut().zip(salt.chunks_exact(4)) {
            *v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        w[4] = index;
        Self(w)
    }
}
/// An available chain engine. Construction checks CPU features.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backend(Kind);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Portable,
    #[cfg(target_arch = "aarch64")]
    Arm,
    #[cfg(target_arch = "x86_64")]
    X86,
}
impl Backend {
    /// Portable engine, available everywhere.
    pub const PORTABLE: Self = Self(Kind::Portable);
    /// Supported engines in preference order.
    pub fn available() -> Vec<Self> {
        let mut v = Vec::new();
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("sha2") {
            v.push(Self(Kind::Arm));
        }
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
        {
            v.push(Self(Kind::X86));
        }
        v.push(Self::PORTABLE);
        v
    }
    /// Find a supported engine by its command-line name.
    pub fn find(name: &str) -> Option<Self> {
        Self::available().into_iter().find(|b| b.name() == name)
    }
    /// Select the environment override, or the fastest supported engine.
    pub fn best() -> crate::Result<Self> {
        match std::env::var("CHAINSEAL_BACKEND") {
            Ok(name) => Self::find(&name).ok_or(crate::Error::Backend),
            Err(std::env::VarError::NotPresent) => Ok(Self::available()[0]),
            Err(std::env::VarError::NotUnicode(_)) => Err(crate::Error::Backend),
        }
    }
    /// Stable command-line name.
    pub fn name(self) -> &'static str {
        match self.0 {
            Kind::Portable => "portable",
            #[cfg(target_arch = "aarch64")]
            Kind::Arm => "armv8-sha2",
            #[cfg(target_arch = "x86_64")]
            Kind::X86 => "x86-sha-ni",
        }
    }
    /// Preferred number of independent chains per worker.
    pub fn lanes(self) -> usize {
        if self == Self::PORTABLE {
            1
        } else {
            2
        }
    }
    /// Iterate one chain.
    pub fn run(self, state: &mut [u32; 8], tail: &Tail, steps: u64) {
        self.run_lanes(
            std::slice::from_mut(state),
            std::slice::from_ref(tail),
            steps,
        );
    }
    /// Iterate independent chains, interleaving pairs on hardware engines.
    pub fn run_lanes(self, states: &mut [[u32; 8]], tails: &[Tail], steps: u64) {
        // The slice API permits arbitrary lane counts; unmatched lanes are untouched.
        for (st, t) in states.chunks_mut(2).zip(tails.chunks(2)) {
            let len = st.len().min(t.len());
            let st = &mut st[..len];
            let t = &t[..len];
            match self.0 {
                Kind::Portable => {
                    for (s, t) in st.iter_mut().zip(t) {
                        for _ in 0..steps {
                            let mut w = [0; 64];
                            w[..8].copy_from_slice(s);
                            w[8..13].copy_from_slice(&t.0);
                            w[13] = 0x80000000;
                            w[15] = 416;
                            let mut h = IV;
                            compress(&mut h, w);
                            *s = h;
                        }
                    }
                }
                #[cfg(target_arch = "aarch64")]
                Kind::Arm => arm::run(st, t, steps),
                #[cfg(target_arch = "x86_64")]
                Kind::X86 => x86::run(st, t, steps),
            }
        }
    }
}

// Keep the platform call beside the architecture intrinsics, so signal handling
// itself and all protocol/file code remain entirely safe Rust.
pub(crate) fn fast_qos() {
    #[cfg(target_arch = "aarch64")]
    arm::fast_qos();
    #[cfg(target_arch = "x86_64")]
    x86::fast_qos();
}
