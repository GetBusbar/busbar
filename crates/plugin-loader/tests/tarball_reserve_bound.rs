// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regression test for the tarball member reservation bound: `tarball::read_entry_bounded` must
//! not reserve an allocation sized off a tar header's DECLARED (self-reported, unverified-at-that-
//! point) size. A malformed/truncated archive whose header lies about a large size must not force
//! a large up-front `Vec::with_capacity` reservation.
//!
//! This is a separate integration test binary specifically so it can install its own
//! `#[global_allocator]`: `busbar-plugin-loader` has no `[[bin]]` target and pulls in no crate that
//! sets a global allocator, so a test-local one here is safe. (The `busbar` bin crate already sets
//! jemalloc as ITS global allocator in `main.rs` — a second global allocator in the same binary
//! would be a hard compile error, which is why this idiom lives here and not there.)

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static PEAK_SINGLE_ALLOC: Cell<usize> = const { Cell::new(0) };
}

/// Counts the largest single allocation `layout.size()` requested on the calling thread. No
/// `realloc` override: growth steps a `Vec` takes as it grows past its initial reservation route
/// through `alloc` (new, bigger layout) + copy + `dealloc` (old layout), so they're still counted
/// here as ordinary allocations — exactly the amplification this test is checking for.
struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        PEAK_SINGLE_ALLOC.with(|p| {
            if layout.size() > p.get() {
                p.set(layout.size());
            }
        });
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn peak_single_alloc() -> usize {
    PEAK_SINGLE_ALLOC.with(|p| p.get())
}

fn reset_peak() {
    PEAK_SINGLE_ALLOC.with(|p| p.set(0));
}

/// A raw (unpadded) 512-byte GNU tar header for a regular file member with the given name and
/// DECLARED size. The caller controls how many actual data bytes follow in the stream — for the
/// lying-header case below, far fewer than `size`.
fn raw_header(name: &str, size: u64) -> [u8; 512] {
    let mut h = tar::Header::new_gnu();
    h.set_path(name).expect("path fits in header");
    h.set_size(size);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_cksum();
    *h.as_bytes()
}

fn pad_to_512(buf: &mut Vec<u8>, unpadded_len: usize) {
    let rem = unpadded_len % 512;
    if rem != 0 {
        buf.extend(std::iter::repeat_n(0u8, 512 - rem));
    }
}

fn gzip(raw: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(raw).unwrap();
    enc.finish().unwrap()
}

/// Hand-craft a tarball (not via `tar::Builder`, which won't let you lie about member sizes):
/// a valid small `manifest.json` entry, followed by a library-member header that DECLARES 200 MiB
/// (safely under the loader's 256 MiB `MAX_LIB_BYTES` cap, so the existing declared-size rejection
/// does not fire before the allocation ever happens) but is backed by only a handful of real bytes
/// — a truncated/lying entry, the shape a corrupted or hostile tarball would take.
fn lying_size_tarball() -> Vec<u8> {
    let manifest_json = br#"{"name":"x","alias":"x","kind":"store","version":"1.0.0","publisher":"x","abi_version":1,"sha256":"","signature":"","description":"","homepage":"","license":"Apache-2.0","needs":[]}"#;

    let mut raw = Vec::new();
    raw.extend_from_slice(&raw_header("manifest.json", manifest_json.len() as u64));
    raw.extend_from_slice(manifest_json);
    pad_to_512(&mut raw, manifest_json.len());

    const LYING_SIZE: u64 = 200 * 1024 * 1024; // under MAX_LIB_BYTES (256 MiB)
    raw.extend_from_slice(&raw_header("lib.so", LYING_SIZE));
    // Only a few real bytes follow, then the stream simply ends — no padding, no more data.
    raw.extend_from_slice(b"only a few real bytes, not 200 MiB");

    gzip(&raw)
}

/// RED on the unfixed code (a `Vec::with_capacity(size as usize)` reserves ~200 MiB up front for a
/// header that never delivers that much data); GREEN after capping the reservation independent of
/// the declared size.
#[test]
fn truncated_lying_header_does_not_force_a_large_reservation() {
    reset_peak();
    let bytes = lying_size_tarball();

    // Don't assert on Ok/Err: whether the `tar` crate surfaces the truncation as an error or
    // returns short data is an implementation detail of that crate, not of our fix.
    let result = std::panic::catch_unwind(|| busbar_plugin_loader::tarball::unpack(&bytes));
    let result = result.expect("unpack must not panic on a truncated/lying entry");

    if let Ok(unpacked) = &result {
        // If it somehow succeeded, it must not have materialized anywhere near 200 MiB of library
        // bytes either (a truncated entry cannot legitimately produce that much data).
        assert!(
            unpacked.lib_bytes.len() < 4 * 1024 * 1024,
            "unexpectedly large lib_bytes: {}",
            unpacked.lib_bytes.len()
        );
    }

    let peak = peak_single_alloc();
    assert!(
        peak < 4 * 1024 * 1024,
        "peak single allocation was {peak} bytes (~{} MiB) — the reservation was sized off the \
         header's declared (unverified) size instead of being ceilinged",
        peak / (1024 * 1024)
    );
}

/// Sanity/non-regression companion: a REAL multi-MB library, packaged the normal way and unpacked,
/// must still round-trip byte-for-byte. Proves the amortized-growth path introduced by capping the
/// initial reservation doesn't corrupt real data for legitimately large members.
#[test]
fn real_multi_mb_library_round_trips_byte_for_byte() {
    use busbar_plugin_sign::{sign, SigningKey};

    let key = SigningKey::from_bytes(&[9u8; 32]);
    // A few MB of non-trivial (non-all-zero) content so a silent truncation or corruption would be
    // caught by the byte-for-byte comparison, not masked by padding zeros.
    let lib_bytes: Vec<u8> = (0..(6 * 1024 * 1024usize))
        .map(|i| (i % 251) as u8)
        .collect();

    let manifest = busbar_plugin_sign::Manifest {
        name: "busbar-store-biglib".into(),
        alias: "biglib".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "busbar".into(),
        abi_version: busbar_plugin_abi::ABI_VERSION,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: "Apache-2.0".into(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
    };
    let manifest = sign(&key, manifest, &lib_bytes);

    let tarball =
        busbar_plugin_loader::tarball::package(&manifest, "libbigplugin.so", &lib_bytes).unwrap();
    let unpacked = busbar_plugin_loader::tarball::unpack(&tarball).unwrap();

    assert_eq!(unpacked.manifest, manifest);
    assert_eq!(unpacked.lib_name, "libbigplugin.so");
    assert_eq!(unpacked.lib_bytes.len(), lib_bytes.len());
    assert_eq!(unpacked.lib_bytes, lib_bytes);
}
