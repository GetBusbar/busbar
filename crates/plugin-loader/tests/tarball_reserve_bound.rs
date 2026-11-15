// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::sdk::test_support::watch::Watch;

/// The reviewed allocator probe: unarmed it is the system allocator; `armed_here` counts this
/// thread's allocations and the largest single one.
#[global_allocator]
static ALLOC: Watch = Watch::new();

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
    let bytes = lying_size_tarball();

    let mut caught = None;
    let freed = ALLOC.armed_here(b"", || {
        caught = Some(std::panic::catch_unwind(|| {
            busbar_plugin_loader::tarball::unpack(&bytes)
        }));
    });
    let result = caught
        .expect("the armed scope ran")
        .expect("unpack must not panic on a truncated/lying entry");

    if let Ok(unpacked) = &result {
        assert!(
            unpacked.lib_bytes.len() < 4 * 1024 * 1024,
            "unexpectedly large lib_bytes: {}",
            unpacked.lib_bytes.len()
        );
    }

    let peak = freed.largest_alloc;
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
