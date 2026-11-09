//! SPK-01 WASM size probe: parse a PDF handed in from JS and count its pages.

/// Reserve `len` bytes in linear memory for the host to copy the PDF into.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len);
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Page count, or -1 on any error.
#[no_mangle]
pub extern "C" fn count_pages(ptr: *const u8, len: usize) -> i64 {
    // SAFETY: the host wrote `len` bytes at `ptr`, obtained from `alloc`.
    let b: &[u8] = unsafe { std::slice::from_raw_parts(ptr, len) };
    match lopdf::Document::load_mem(b) { Ok(d) => d.get_pages().len() as i64, Err(_) => -1 }
}
