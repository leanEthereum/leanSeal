//! A global allocator that records the peak heap growth of a closure.
//!
//! Counting is per thread and only active inside [`measure`], so parallel
//! tests and the fuzzer's own allocations do not interfere.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// The system allocator, with per-thread peak accounting.
pub struct Counting;

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

fn grow(n: usize) {
    let _ = ACTIVE.try_with(|a| {
        if a.get() {
            let live = LIVE.with(|l| {
                let v = l.get().saturating_add(n);
                l.set(v);
                v
            });
            PEAK.with(|p| p.set(p.get().max(live)));
        }
    });
}

fn shrink(n: usize) {
    // Freeing memory allocated before `measure` saturates at zero, which can
    // only overstate later growth.
    let _ = ACTIVE.try_with(|a| {
        if a.get() {
            LIVE.with(|l| l.set(l.get().saturating_sub(n)));
        }
    });
}

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        shrink(layout.size());
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Both blocks may be live during the copy.
        grow(new_size);
        let p = System.realloc(ptr, layout, new_size);
        shrink(layout.size());
        p
    }
}

/// Run `f` and return its result with the peak number of bytes it held.
pub fn measure<R>(f: impl FnOnce() -> R) -> (R, usize) {
    assert!(!ACTIVE.with(Cell::get), "measure does not nest");
    LIVE.with(|l| l.set(0));
    PEAK.with(|p| p.set(0));
    ACTIVE.with(|a| a.set(true));
    let r = f();
    ACTIVE.with(|a| a.set(false));
    (r, PEAK.with(Cell::get))
}

/// Whether [`Counting`] is this binary's global allocator.
pub fn installed() -> bool {
    measure(|| std::hint::black_box(Vec::<u8>::with_capacity(4096))).1 >= 4096
}
