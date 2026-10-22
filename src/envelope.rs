use crate::hash::{ct_equal, hmac, th};
use crate::secret::Secret;
use crate::{array, bytes, Error, Puzzle, Result, MAX_MSG};
/// Encode a secret containing a puzzle and its verified key.
pub fn secret_encode(p: &Puzzle, key: &[u8; 32]) -> Result<Vec<u8>> {
    let enc = p.encode()?;
    let mut v = bytes(40 + enc.len())?;
    v[..8].copy_from_slice(b"CSSK\x01\0\0\0");
    v[8..40].copy_from_slice(key);
    v[40..].copy_from_slice(&enc);
    Ok(v)
}
/// Decode a secret, including its key commitment check.
pub fn secret_decode(data: &[u8]) -> Result<(Puzzle, [u8; 32])> {
    if data.len() < 40 || &data[..8] != b"CSSK\x01\0\0\0" {
        return Err(Error::Format);
    }
    let p = Puzzle::decode(&data[40..])?;
    let k = array(&data[8..40])?;
    if !p.check_key(&k) {
        return Err(Error::Commit);
    }
    Ok((p, k))
}
fn stream(key: &[u8; 32], input: &[u8]) -> Result<Vec<u8>> {
    let mut out = bytes(input.len())?;
    for (i, (src, dst)) in input.chunks(32).zip(out.chunks_mut(32)).enumerate() {
        let block = hmac(key, &(i as u64).to_be_bytes());
        for ((v, x), k) in dst.iter_mut().zip(src).zip(block) {
            *v = x ^ k;
        }
    }
    Ok(out)
}
/// Seal a plaintext using an explicit nonce.
pub fn seal(p: &Puzzle, key: &[u8; 32], nonce: &[u8; 16], message: &[u8]) -> Result<Vec<u8>> {
    if message.len() > MAX_MSG {
        return Err(Error::Range);
    }
    if !p.check_key(key) {
        return Err(Error::Commit);
    }
    let kenc = Secret(th("chainseal/v1/enc", &[key, nonce]));
    let kmac = Secret(th("chainseal/v1/mac", &[key, nonce]));
    let enc = p.encode()?;
    let mut v = bytes(8 + enc.len() + 20 + message.len() + 32)?;
    v[..8].copy_from_slice(b"CSEN\x01\0\0\0");
    v[8..8 + enc.len()].copy_from_slice(&enc);
    let at = 8 + enc.len();
    v[at..at + 16].copy_from_slice(nonce);
    v[at + 16..at + 20].copy_from_slice(&(message.len() as u32).to_be_bytes());
    let end = at + 20 + message.len();
    v[at + 20..end].copy_from_slice(&stream(&kenc, message)?);
    let tag = hmac(&kmac[..], &v[..end]);
    v[end..].copy_from_slice(&tag);
    Ok(v)
}
/// Decoded envelope borrowing the authenticated encoding.
#[derive(Debug)]
pub struct Envelope<'a> {
    /// Owned puzzle.
    pub puzzle: Puzzle,
    /// Encryption nonce.
    pub nonce: [u8; 16],
    data: &'a [u8],
    ct: &'a [u8],
    tag: &'a [u8],
}
impl<'a> Envelope<'a> {
    /// Validate envelope structure and its puzzle.
    pub fn decode(data: &'a [u8]) -> Result<Self> {
        if data.len() < 8 || &data[..8] != b"CSEN\x01\0\0\0" {
            return Err(Error::Format);
        }
        let plen = Puzzle::encoded_len_from_header(&data[8..])?;
        let at = 8 + plen;
        if data.len() < at + 52 {
            return Err(Error::Format);
        }
        let len = u32::from_be_bytes(array(&data[at + 16..at + 20])?) as usize;
        if len > MAX_MSG {
            return Err(Error::Range);
        }
        if data.len() != at + 52 + len {
            return Err(Error::Format);
        }
        Ok(Self {
            puzzle: Puzzle::decode(&data[8..at])?,
            nonce: array(&data[at..at + 16])?,
            data,
            ct: &data[at + 20..at + 20 + len],
            tag: &data[at + 20 + len..],
        })
    }
    /// Ciphertext length in bytes.
    pub fn message_len(&self) -> usize {
        self.ct.len()
    }
    /// Check the key and tag before releasing any plaintext.
    pub fn open(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        if !self.puzzle.check_key(key) {
            return Err(Error::Commit);
        }
        let kenc = Secret(th("chainseal/v1/enc", &[key, &self.nonce]));
        let kmac = Secret(th("chainseal/v1/mac", &[key, &self.nonce]));
        if !ct_equal(
            &hmac(&kmac[..], &self.data[..self.data.len() - 32]),
            self.tag,
        ) {
            return Err(Error::Tag);
        }
        stream(&kenc, self.ct)
    }
}
