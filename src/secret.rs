//! Best-effort safe erasure of owned secret buffers.
use std::ops::{Deref, DerefMut};

pub(crate) fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

pub(crate) trait Erase {
    fn erase(&mut self);
}
impl<const N: usize> Erase for [u8; N] {
    fn erase(&mut self) {
        wipe(self);
    }
}
impl Erase for Vec<u8> {
    fn erase(&mut self) {
        wipe(self);
    }
}
impl Erase for &mut [u8] {
    fn erase(&mut self) {
        wipe(self);
    }
}
impl<const N: usize> Erase for [u32; N] {
    fn erase(&mut self) {
        self.fill(0);
        std::hint::black_box(self);
    }
}
impl<const N: usize> Erase for [[u32; 8]; N] {
    fn erase(&mut self) {
        for state in self {
            state.erase();
        }
    }
}
impl Erase for Vec<[u8; 32]> {
    fn erase(&mut self) {
        for end in self {
            wipe(end);
        }
    }
}

pub(crate) struct Secret<T: Erase>(pub T);
impl<T: Erase> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.erase();
    }
}
impl<T: Erase> Deref for Secret<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Erase> DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn erases_buffer_and_drop_guard() {
        let mut data = [17; 32];
        wipe(&mut data);
        assert_eq!(data, [0; 32]);
        data.fill(19);
        {
            let _guard = Secret(&mut data[..]);
        }
        assert_eq!(data, [0; 32]);
        let mut words = [42u32; 8];
        words.erase();
        assert_eq!(words, [0; 8]);
        let mut ends = vec![[42; 32]; 3];
        ends.erase();
        assert_eq!(ends, vec![[0; 32]; 3]);
    }
}
