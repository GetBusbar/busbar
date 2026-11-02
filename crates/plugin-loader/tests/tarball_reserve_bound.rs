// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static PEAK_SINGLE_ALLOC: Cell<usize> = const { Cell::new(0) };
}

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

fn lying_size_tarball() -> Vec<u8> {
    let manifest_json = br#"{"name":"x","alias":"x","kind":"store","version":"1.0.0","publisher":"x","abi_version":1,"sha256":"","signature":"","description":"","homepage":"","license":"Apache-2.0","needs":[]}"#;

    let mut raw = Vec::new();
    raw.extend_from_slice(&raw_header("manifest.json", manifest_json.len() as u64));
    raw.extend_from_slice(manifest_json);
    pad_to_512(&mut raw, manifest_json.len());

    const LYING_SIZE: u64 = 200 * 1024 * 1024;
    raw.extend_from_slice(&raw_header("lib.so", LYING_SIZE));

    raw.extend_from_slice(b"only a few real bytes, not 200 MiB");

    gzip(&raw)
}

#[test]
fn truncated_lying_header_does_not_force_a_large_reservation() {
    reset_peak();
    let bytes = lying_size_tarball();

    let result = std::panic::catch_unwind(|| busbar_plugin_loader::tarball::unpack(&bytes));
    let result = result.expect("unpack must not panic on a truncated/lying entry");

    if let Ok(unpacked) = &result {
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

#[test]
fn real_multi_mb_library_round_trips_byte_for_byte() {
    use busbar_plugin_loader::sign::{sign, SigningKey};

    let key = SigningKey::from_bytes(&[9u8; 32]);

    let lib_bytes: Vec<u8> = (0..(6 * 1024 * 1024usize))
        .map(|i| (i % 251) as u8)
        .collect();

    let manifest = busbar_plugin_loader::sign::Manifest {
        name: "busbar-store-biglib".into(),
        alias: "biglib".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "busbar".into(),
        abi_version: busbar_contract::abi::store::ABI_VERSION,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: "Apache-2.0".into(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
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
