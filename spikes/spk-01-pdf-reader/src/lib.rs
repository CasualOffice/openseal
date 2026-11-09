//! SPK-01 spike helpers: a counting, capped global allocator so a hostile input cannot
//! push the machine into swap (the disk is nearly full), and a report of the peak heap.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Heap cap for a probe run. Above it the allocator returns null and std aborts with
/// "memory allocation of N bytes failed", which the harness classifies as `alloc-cap`.
pub const HEAP_CAP: usize = 3 << 30;

pub struct Capped;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let now = CUR.fetch_add(l.size(), Ordering::Relaxed) + l.size();
        if now > HEAP_CAP {
            CUR.fetch_sub(l.size(), Ordering::Relaxed);
            return std::ptr::null_mut();
        }
        PEAK.fetch_max(now, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        CUR.fetch_sub(l.size(), Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > l.size() {
            let grow = new - l.size();
            let now = CUR.fetch_add(grow, Ordering::Relaxed) + grow;
            if now > HEAP_CAP {
                CUR.fetch_sub(grow, Ordering::Relaxed);
                return std::ptr::null_mut();
            }
            PEAK.fetch_max(now, Ordering::Relaxed);
        } else {
            CUR.fetch_sub(l.size() - new, Ordering::Relaxed);
        }
        System.realloc(p, l, new)
    }
}

pub fn peak_heap() -> usize {
    PEAK.load(Ordering::Relaxed)
}
