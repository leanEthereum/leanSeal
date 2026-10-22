//! SHA-256, HMAC-SHA256 and labelled hashing.
pub(crate) const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
pub(crate) const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub(crate) fn compress(h: &mut [u32; 8], mut w: [u32; 64]) {
    for i in 16..64 {
        let a = w[i - 15];
        let b = w[i - 2];
        w[i] = w[i - 16]
            .wrapping_add(a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3))
            .wrapping_add(w[i - 7])
            .wrapping_add(b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10));
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut z] = *h;
    for i in 0..64 {
        let t1 = z
            .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
        z = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (v, x) in h.iter_mut().zip([a, b, c, d, e, f, g, z]) {
        *v = v.wrapping_add(x);
    }
}

/// Incremental SHA-256 state.
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    fill: usize,
    len: u64,
}
impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}
impl Sha256 {
    /// Start a hash.
    pub fn new() -> Self {
        Self {
            h: IV,
            buf: [0; 64],
            fill: 0,
            len: 0,
        }
    }
    /// Append bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (64 - self.fill).min(data.len());
            self.buf[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill == 64 {
                let mut w = [0; 64];
                for (v, b) in w.iter_mut().zip(self.buf.chunks_exact(4)) {
                    *v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                }
                compress(&mut self.h, w);
                self.fill = 0;
            }
        }
    }
    /// Finish and return the digest.
    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        let mut pad = [0; 72];
        pad[0] = 128;
        let n = if self.fill < 56 {
            56 - self.fill
        } else {
            120 - self.fill
        };
        pad[n..n + 8].copy_from_slice(&bits.to_be_bytes());
        self.update(&pad[..n + 8]);
        words_to_bytes(self.h)
    }
}
/// SHA-256 digest of bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}
/// HMAC-SHA256 with an arbitrary length key.
pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut pad = k;
    for v in &mut pad {
        *v ^= 0x36;
    }
    let mut h = Sha256::new();
    h.update(&pad);
    h.update(msg);
    let inner = h.finish();
    for (v, k) in pad.iter_mut().zip(k) {
        *v = k ^ 0x5c;
    }
    let mut h = Sha256::new();
    h.update(&pad);
    h.update(&inner);
    h.finish()
}
/// Prefix-free labelled hash. Labels must fit in one byte.
pub fn labelled_hash(label: &str, parts: &[&[u8]]) -> crate::Result<[u8; 32]> {
    if label.len() > 255 {
        return Err(crate::Error::Range);
    }
    let mut h = Sha256::new();
    h.update(&[label.len() as u8]);
    h.update(label.as_bytes());
    for part in parts {
        h.update(part);
    }
    Ok(h.finish())
}
pub(crate) fn th(label: &str, parts: &[&[u8]]) -> [u8; 32] {
    // All internal labels are fixed ASCII strings shorter than 256 bytes.
    let mut h = Sha256::new();
    h.update(&[label.len() as u8]);
    h.update(label.as_bytes());
    for part in parts {
        h.update(part);
    }
    h.finish()
}
/// Compare equal length byte strings without data-dependent early exit.
pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}
/// Convert SHA-256 state words to their big-endian byte encoding.
pub fn words_to_bytes(w: [u32; 8]) -> [u8; 32] {
    let mut b = [0; 32];
    for (o, v) in b.chunks_exact_mut(4).zip(w) {
        o.copy_from_slice(&v.to_be_bytes());
    }
    b
}
/// Convert a SHA-256 digest to state words.
pub fn bytes_to_words(b: [u8; 32]) -> [u32; 8] {
    let mut w = [0; 8];
    for (v, b) in w.iter_mut().zip(b.chunks_exact(4)) {
        *v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    }
    w
}
