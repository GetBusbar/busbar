// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/tarball.rs`.

use super::*;
use busbar_plugin_sign::{sign, SigningKey};

fn manifest() -> Manifest {
    Manifest {
        name: "busbar-store-valkey-plugin".into(),
        alias: "valkey".into(),
        kind: "store".into(),
        version: "1.5.0".into(),
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
        host: None,
    }
}

#[test]
fn package_then_unpack_roundtrips() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let lib = b"\x7fELF pretend library";
    let m = sign(&key, manifest(), lib);
    let tarball = package(&m, "libbusbar_store_valkey.so", lib).unwrap();
    let up = unpack(&tarball).unwrap();
    assert_eq!(up.manifest, m);
    assert_eq!(up.lib_name, "libbusbar_store_valkey.so");
    assert_eq!(up.lib_bytes, lib);
}

#[test]
fn garbage_is_refused() {
    assert!(unpack(b"not a tarball at all").is_err());
    assert!(unpack(&[]).is_err());
}

#[test]
fn missing_manifest_or_lib_is_refused() {
    // Only a library, no manifest.
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut t = tar::Builder::new(gz);
    let mut h = tar::Header::new_gnu();
    h.set_size(3);
    h.set_mode(0o644);
    h.set_cksum();
    t.append_data(&mut h, "lib.so", &b"abc"[..]).unwrap();
    let bytes = t.into_inner().unwrap().finish().unwrap();
    let err = unpack(&bytes).unwrap_err();
    assert!(err.contains("no manifest.json"), "got {err}");

    // Only a manifest, no library.
    let m = manifest();
    let json = serde_json::to_vec(&m).unwrap();
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut t = tar::Builder::new(gz);
    let mut h = tar::Header::new_gnu();
    h.set_size(json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    t.append_data(&mut h, MANIFEST_FILE, json.as_slice())
        .unwrap();
    let bytes = t.into_inner().unwrap().finish().unwrap();
    let err = unpack(&bytes).unwrap_err();
    assert!(err.contains("no library member"), "got {err}");
}

#[test]
fn extra_members_and_traversal_are_refused() {
    // Three regular files: manifest + two libraries.
    let m = manifest();
    let t1 = package(&m, "lib.so", b"abc").unwrap();
    // Rebuild with an extra member by unpacking the raw tar and appending.
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut t = tar::Builder::new(gz);
    let json = serde_json::to_vec(&m).unwrap();
    for (name, data) in [
        (MANIFEST_FILE, json.as_slice()),
        ("lib.so", &b"abc"[..]),
        ("evil.so", &b"def"[..]),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, name, data).unwrap();
    }
    let bytes = t.into_inner().unwrap().finish().unwrap();
    let err = unpack(&bytes).unwrap_err();
    assert!(err.contains("more than one library"), "got {err}");
    drop(t1);

    // Parent-reference path. `tar::Builder::append_data` itself refuses `..`, so write the
    // hostile name into the raw 512-byte header directly (what an attacker's tool would emit).
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut t = tar::Builder::new(gz);
    let mut h = tar::Header::new_gnu();
    h.set_size(3);
    h.set_mode(0o644);
    {
        let name = b"../escape.so";
        h.as_mut_bytes()[..name.len()].copy_from_slice(name);
    }
    h.set_cksum();
    t.append(&h, &b"abc"[..]).unwrap();
    let bytes = t.into_inner().unwrap().finish().unwrap();
    let err = unpack(&bytes).unwrap_err();
    assert!(err.contains("unsafe path"), "got {err}");
}

#[test]
fn oversized_manifest_member_is_refused() {
    // A "manifest.json" bigger than the cap is refused by DECLARED size before reading.
    let big = vec![b'x'; (MAX_MANIFEST_BYTES + 1) as usize];
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut t = tar::Builder::new(gz);
    let mut h = tar::Header::new_gnu();
    h.set_size(big.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    t.append_data(&mut h, MANIFEST_FILE, big.as_slice())
        .unwrap();
    let bytes = t.into_inner().unwrap().finish().unwrap();
    let err = unpack(&bytes).unwrap_err();
    assert!(
        err.contains("exceeding the") && err.contains("byte cap"),
        "must name it as the specific declared/read-size cap violation, not just any error \
             containing \"cap\": got {err}"
    );
}

#[test]
fn tarball_extension_matcher() {
    assert!(is_plugin_tarball(
        "busbar-store-valkey-1.5.0-aarch64.tar.gz"
    ));
    assert!(is_plugin_tarball("x.tgz"));
    assert!(!is_plugin_tarball("x.so"));
    assert!(!is_plugin_tarball("x.tar"));
    assert!(!is_plugin_tarball("x.zip"));
}

// The three size-cap constants are each a computed literal (multiplication / addition); assert
// their CONCRETE values directly rather than re-deriving them symbolically in the test (which
// would just re-run the same arithmetic and trivially agree with a mutated constant too).
#[test]
fn size_cap_constants_have_the_documented_concrete_values() {
    assert_eq!(MAX_MANIFEST_BYTES, 1_048_576, "1 MiB");
    assert_eq!(MAX_LIB_BYTES, 268_435_456, "256 MiB");
    assert_eq!(
        MAX_TARBALL_FILE_BYTES, 269_484_032,
        "MAX_LIB_BYTES + MAX_MANIFEST_BYTES"
    );
    assert_eq!(MEMBER_RESERVE_CEILING, 65_536, "64 KiB");
}

#[test]
fn manifest_member_at_exactly_the_cap_is_accepted_one_byte_over_is_refused() {
    // A manifest whose bytes deserialize is padded with trailing whitespace up to the exact
    // cap, then cap+1, to exercise `read_entry_bounded`'s `size > cap` boundary in both
    // directions (a `>` mutated to `==`/`>=` would wrongly refuse the exact-cap case).
    // Pad by inflating the `description` field so the member stays valid JSON at exactly the
    // cap (rather than appending raw bytes, which would break JSON parsing).
    let mut m_padded = manifest();
    let base_len = serde_json::to_vec(&m_padded).unwrap().len() as u64;
    let pad_needed = (MAX_MANIFEST_BYTES - base_len) as usize;
    m_padded.description = "x".repeat(pad_needed);
    let mut exact = serde_json::to_vec(&m_padded).unwrap();
    // `description`'s serialized length isn't 1:1 with `pad_needed` bytes of `x` once escaped
    // (plain ASCII `x` needs no JSON escaping, so it is 1:1) — assert the construction is
    // exact before trusting the boundary test built on it.
    assert_eq!(exact.len() as u64, MAX_MANIFEST_BYTES);

    let build = |manifest_bytes: &[u8]| -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut t = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(manifest_bytes.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, MANIFEST_FILE, manifest_bytes)
            .unwrap();
        let mut hlib = tar::Header::new_gnu();
        hlib.set_size(3);
        hlib.set_mode(0o644);
        hlib.set_cksum();
        t.append_data(&mut hlib, "lib.so", &b"abc"[..]).unwrap();
        t.into_inner().unwrap().finish().unwrap()
    };

    let bytes = build(&exact);
    let up = unpack(&bytes).expect("a manifest of exactly MAX_MANIFEST_BYTES must be accepted");
    assert_eq!(up.manifest.description.len(), pad_needed);

    // One byte over the cap: refused (already covered for declared-size by
    // `oversized_manifest_member_is_refused`, kept here only as the paired boundary case).
    exact.push(b' ');
    let bytes = build(&exact);
    let err = unpack(&bytes).unwrap_err();
    assert!(
        err.contains("exceeding the") && err.contains("byte cap"),
        "must name it as the specific declared/read-size cap violation, not just any error \
             containing \"cap\": got {err}"
    );
}
