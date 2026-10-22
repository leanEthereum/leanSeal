#![allow(unsafe_code)]
use super::Tail;
use crate::hash::{IV, K};
use std::arch::aarch64::*;

pub(super) fn run(st: &mut [[u32; 8]], t: &[Tail], steps: u64) {
    // Backend construction checked SHA2; slices have matching lengths of one or two.
    unsafe {
        if st.len() == 2 {
            run_impl::<2>(st, t, steps)
        } else if st.len() == 1 {
            run_impl::<1>(st, t, steps)
        }
    }
}
#[target_feature(enable = "sha2")]
#[inline(never)]
unsafe fn run_impl<const L: usize>(st: &mut [[u32; 8]], tails: &[Tail], steps: u64) {
    // Keep table loads as loads from a common base, like the C engine.
    // Folding each four-word group into a separate vector constant increases
    // register pressure and spills in the two-chain loop on Apple cores.
    let constants = std::hint::black_box(&K);
    let iv = std::hint::black_box(&IV);
    let iv0 = vld1q_u32(iv.as_ptr());
    let iv1 = vld1q_u32(iv.as_ptr().add(4));
    let mut lo = [iv0; L];
    let mut hi = [iv1; L];
    let mut t2 = [iv0; L];
    let mut t3 = [iv0; L];
    for l in 0..L {
        lo[l] = vld1q_u32(st[l].as_ptr());
        hi[l] = vld1q_u32(st[l].as_ptr().add(4));
        t2[l] = vld1q_u32(tails[l].0.as_ptr());
        t3[l] = vld1q_u32([tails[l].0[4], 0x80000000, 0, 416].as_ptr());
    }
    for _ in 0..steps {
        let mut m0 = lo;
        let mut m1 = hi;
        let mut m2 = t2;
        let mut m3 = t3;
        let mut s0 = [iv0; L];
        let mut s1 = [iv1; L];
        for l in 0..L {
            let wk = vaddq_u32(m0[l], vld1q_u32(constants.as_ptr().add(0)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m0[l] = vsha256su1q_u32(vsha256su0q_u32(m0[l], m1[l]), m2[l], m3[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m1[l], vld1q_u32(constants.as_ptr().add(4)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m1[l] = vsha256su1q_u32(vsha256su0q_u32(m1[l], m2[l]), m3[l], m0[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m2[l], vld1q_u32(constants.as_ptr().add(8)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m2[l] = vsha256su1q_u32(vsha256su0q_u32(m2[l], m3[l]), m0[l], m1[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m3[l], vld1q_u32(constants.as_ptr().add(12)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m3[l] = vsha256su1q_u32(vsha256su0q_u32(m3[l], m0[l]), m1[l], m2[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m0[l], vld1q_u32(constants.as_ptr().add(16)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m0[l] = vsha256su1q_u32(vsha256su0q_u32(m0[l], m1[l]), m2[l], m3[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m1[l], vld1q_u32(constants.as_ptr().add(20)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m1[l] = vsha256su1q_u32(vsha256su0q_u32(m1[l], m2[l]), m3[l], m0[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m2[l], vld1q_u32(constants.as_ptr().add(24)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m2[l] = vsha256su1q_u32(vsha256su0q_u32(m2[l], m3[l]), m0[l], m1[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m3[l], vld1q_u32(constants.as_ptr().add(28)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m3[l] = vsha256su1q_u32(vsha256su0q_u32(m3[l], m0[l]), m1[l], m2[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m0[l], vld1q_u32(constants.as_ptr().add(32)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m0[l] = vsha256su1q_u32(vsha256su0q_u32(m0[l], m1[l]), m2[l], m3[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m1[l], vld1q_u32(constants.as_ptr().add(36)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m1[l] = vsha256su1q_u32(vsha256su0q_u32(m1[l], m2[l]), m3[l], m0[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m2[l], vld1q_u32(constants.as_ptr().add(40)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m2[l] = vsha256su1q_u32(vsha256su0q_u32(m2[l], m3[l]), m0[l], m1[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m3[l], vld1q_u32(constants.as_ptr().add(44)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            m3[l] = vsha256su1q_u32(vsha256su0q_u32(m3[l], m0[l]), m1[l], m2[l]);
        }
        for l in 0..L {
            let wk = vaddq_u32(m0[l], vld1q_u32(constants.as_ptr().add(48)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            let wk = vaddq_u32(m1[l], vld1q_u32(constants.as_ptr().add(52)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            let wk = vaddq_u32(m2[l], vld1q_u32(constants.as_ptr().add(56)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            let wk = vaddq_u32(m3[l], vld1q_u32(constants.as_ptr().add(60)));
            let prev = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], prev, wk);
        }
        for l in 0..L {
            lo[l] = vaddq_u32(s0[l], iv0);
            hi[l] = vaddq_u32(s1[l], iv1);
        }
    }
    for l in 0..L {
        vst1q_u32(st[l].as_mut_ptr(), lo[l]);
        vst1q_u32(st[l].as_mut_ptr().add(4), hi[l]);
    }
}

pub(super) fn fast_qos() {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn pthread_set_qos_class_self_np(class: u32, priority: i32) -> i32;
        }
        // Matches the C worker's scheduling request; no pointers or owned resources.
        unsafe {
            pthread_set_qos_class_self_np(0x21, 0);
        }
    }
}
