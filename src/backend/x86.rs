#![allow(unsafe_code)]
use super::Tail;
use crate::hash::{IV, K};
use std::arch::x86_64::*;

pub(super) fn run(st: &mut [[u32; 8]], t: &[Tail], steps: u64) {
    // Backend construction checked SHA, SSE4.1 and SSSE3; matching slices, at most two lanes.
    unsafe {
        if st.len() == 2 {
            run_impl::<2>(st, t, steps)
        } else if st.len() == 1 {
            run_impl::<1>(st, t, steps)
        }
    }
}
#[target_feature(enable = "sha,sse4.1,ssse3")]
#[inline(never)]
unsafe fn run_impl<const L: usize>(st: &mut [[u32; 8]], tails: &[Tail], steps: u64) {
    let a = _mm_shuffle_epi32::<0xB1>(_mm_loadu_si128(IV.as_ptr().cast()));
    let e = _mm_shuffle_epi32::<0x1B>(_mm_loadu_si128(IV.as_ptr().add(4).cast()));
    let iv0 = _mm_alignr_epi8::<8>(a, e);
    let iv1 = _mm_blend_epi16::<0xF0>(e, a);
    let mut lo = [iv0; L];
    let mut hi = [iv0; L];
    let mut t2 = [iv0; L];
    let mut t3 = [iv0; L];
    for l in 0..L {
        lo[l] = _mm_loadu_si128(st[l].as_ptr().cast());
        hi[l] = _mm_loadu_si128(st[l].as_ptr().add(4).cast());
        t2[l] = _mm_loadu_si128(tails[l].0.as_ptr().cast());
        t3[l] = _mm_setr_epi32(tails[l].0[4] as i32, 0x80000000u32 as i32, 0, 416);
    }
    for _ in 0..steps {
        let mut m0 = lo;
        let mut m1 = hi;
        let mut m2 = t2;
        let mut m3 = t3;
        let mut s0 = [iv0; L];
        let mut s1 = [iv1; L];
        let mut wk;
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m0[l], _mm_loadu_si128(K.as_ptr().add(0).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m1[l], _mm_loadu_si128(K.as_ptr().add(4).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m0[l] = _mm_sha256msg1_epu32(m0[l], m1[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m2[l], _mm_loadu_si128(K.as_ptr().add(8).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m1[l] = _mm_sha256msg1_epu32(m1[l], m2[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m3[l], _mm_loadu_si128(K.as_ptr().add(12).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m0[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m0[l], _mm_alignr_epi8::<4>(m3[l], m2[l])),
                m3[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m2[l] = _mm_sha256msg1_epu32(m2[l], m3[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m0[l], _mm_loadu_si128(K.as_ptr().add(16).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m1[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m1[l], _mm_alignr_epi8::<4>(m0[l], m3[l])),
                m0[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m3[l] = _mm_sha256msg1_epu32(m3[l], m0[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m1[l], _mm_loadu_si128(K.as_ptr().add(20).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m2[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m2[l], _mm_alignr_epi8::<4>(m1[l], m0[l])),
                m1[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m0[l] = _mm_sha256msg1_epu32(m0[l], m1[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m2[l], _mm_loadu_si128(K.as_ptr().add(24).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m3[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m3[l], _mm_alignr_epi8::<4>(m2[l], m1[l])),
                m2[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m1[l] = _mm_sha256msg1_epu32(m1[l], m2[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m3[l], _mm_loadu_si128(K.as_ptr().add(28).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m0[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m0[l], _mm_alignr_epi8::<4>(m3[l], m2[l])),
                m3[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m2[l] = _mm_sha256msg1_epu32(m2[l], m3[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m0[l], _mm_loadu_si128(K.as_ptr().add(32).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m1[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m1[l], _mm_alignr_epi8::<4>(m0[l], m3[l])),
                m0[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m3[l] = _mm_sha256msg1_epu32(m3[l], m0[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m1[l], _mm_loadu_si128(K.as_ptr().add(36).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m2[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m2[l], _mm_alignr_epi8::<4>(m1[l], m0[l])),
                m1[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m0[l] = _mm_sha256msg1_epu32(m0[l], m1[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m2[l], _mm_loadu_si128(K.as_ptr().add(40).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m3[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m3[l], _mm_alignr_epi8::<4>(m2[l], m1[l])),
                m2[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m1[l] = _mm_sha256msg1_epu32(m1[l], m2[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m3[l], _mm_loadu_si128(K.as_ptr().add(44).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m0[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m0[l], _mm_alignr_epi8::<4>(m3[l], m2[l])),
                m3[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m2[l] = _mm_sha256msg1_epu32(m2[l], m3[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m0[l], _mm_loadu_si128(K.as_ptr().add(48).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m1[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m1[l], _mm_alignr_epi8::<4>(m0[l], m3[l])),
                m0[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            m3[l] = _mm_sha256msg1_epu32(m3[l], m0[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m1[l], _mm_loadu_si128(K.as_ptr().add(52).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m2[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m2[l], _mm_alignr_epi8::<4>(m1[l], m0[l])),
                m1[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m2[l], _mm_loadu_si128(K.as_ptr().add(56).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            m3[l] = _mm_sha256msg2_epu32(
                _mm_add_epi32(m3[l], _mm_alignr_epi8::<4>(m2[l], m1[l])),
                m2[l],
            );
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        wk = [iv0; L];
        for l in 0..L {
            wk[l] = _mm_add_epi32(m3[l], _mm_loadu_si128(K.as_ptr().add(60).cast()));
            s1[l] = _mm_sha256rnds2_epu32(s1[l], s0[l], wk[l]);
        }
        for l in 0..L {
            wk[l] = _mm_shuffle_epi32::<0x0E>(wk[l]);
            s0[l] = _mm_sha256rnds2_epu32(s0[l], s1[l], wk[l]);
        }
        for l in 0..L {
            let feba = _mm_shuffle_epi32::<0x1B>(_mm_add_epi32(s0[l], iv0));
            let dchg = _mm_shuffle_epi32::<0xB1>(_mm_add_epi32(s1[l], iv1));
            lo[l] = _mm_blend_epi16::<0xF0>(feba, dchg);
            hi[l] = _mm_alignr_epi8::<8>(dchg, feba);
        }
    }
    for l in 0..L {
        _mm_storeu_si128(st[l].as_mut_ptr().cast(), lo[l]);
        _mm_storeu_si128(st[l].as_mut_ptr().add(4).cast(), hi[l]);
    }
}

pub(super) fn fast_qos() {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn pthread_set_qos_class_self_np(class: u32, priority: i32) -> i32;
        }
        // Requests the user-interactive QoS class; no pointers or owned resources.
        unsafe {
            pthread_set_qos_class_self_np(0x21, 0);
        }
    }
}
