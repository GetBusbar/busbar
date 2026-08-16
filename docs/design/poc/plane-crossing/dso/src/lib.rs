// A minimal plugin-side DSO: the bare cross-DSO call, and a pointer-offset read
// performed ON THE PLUGIN SIDE of a real dynamic-library boundary.

/// The bare crossing: one PLT/stub indirection and an add. This is the floor —
/// the cost of "a linked library is not slower than native".
#[no_mangle]
pub extern "C" fn zc_noop(x: u64) -> u64 {
    x.wrapping_add(1)
}

/// A real host->plugin crossing that hands over ptr+len and reads five
/// length-prefixed fields by offset. Models the zero-copy access pattern
/// ACROSS an actual DSO boundary rather than within one translation unit.
///
/// # Safety
/// `ptr`/`len` must describe a live readable buffer; `offs`/`n_offs` likewise.
#[no_mangle]
pub unsafe extern "C" fn zc_read_offsets(
    ptr: *const u8,
    len: usize,
    offs: *const usize,
    n_offs: usize,
) -> u64 {
    let buf = std::slice::from_raw_parts(ptr, len);
    let offs = std::slice::from_raw_parts(offs, n_offs);
    let mut acc = 0u64;
    for &off in offs {
        let l = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let f = &buf[off + 4..off + 4 + l];
        acc = acc.wrapping_add(f.len() as u64).wrapping_add(f[0] as u64);
    }
    acc
}
