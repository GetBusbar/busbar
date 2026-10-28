// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/fetch.rs`.

use super::*;

fn tmpdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let mut rnd = [0u8; 8];
    let _ = getrandom::fill(&mut rnd);
    p.push(format!(
        "busbar-fetch-test-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn spec(url: &str, sha: Option<&str>, file: &str) -> FetchSpec {
    FetchSpec {
        url: url.into(),
        sha256: sha.map(str::to_string),
        filename: file.into(),
    }
}

/// A pre-placed tarball hashing to the pin ⇒ Cached, and the (bogus, would-panic) downloader is
/// NEVER called.
#[test]
fn cached_by_pin_skips_network() {
    let dir = tmpdir();
    let body = b"the-real-signed-tarball";
    std::fs::write(dir.join("plugin.tar.gz"), body).unwrap();
    let pin = sha256_hex(body);

    let never = |_: &str| -> Result<Vec<u8>, String> { panic!("network must not be touched") };
    let out = fetch_plugins(
        &dir,
        &[spec("https://x/plugin.tar.gz", Some(&pin), "plugin.tar.gz")],
        true,
        &never,
    )
    .unwrap();
    assert_eq!(
        out,
        vec![FetchOutcome::Cached {
            filename: "plugin.tar.gz".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Served bytes ≠ pin ⇒ error, and `dir` is unchanged (no file written).
#[test]
fn hash_mismatch_never_writes() {
    let dir = tmpdir();
    let pin = sha256_hex(b"expected");
    let dl = |_: &str| Ok(b"WRONG-BYTES".to_vec());
    let err = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
        true,
        &dl,
    )
    .unwrap_err();
    assert!(err[0].contains("mismatch"), "{err:?}");
    assert!(
        !dir.join("p.tar.gz").exists(),
        "no file must be written on mismatch"
    );
    // No leftover temp files either.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(leftovers.is_empty(), "dir must be unchanged: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An unreachable spec: boot (fatal=true) ⇒ Err; reload (fatal=false) ⇒ Ok + Warned.
#[test]
fn boot_miss_fatal_reload_miss_warns() {
    let dir = tmpdir();
    let dead = |_: &str| -> Result<Vec<u8>, String> { Err("connection refused".into()) };
    let s = [spec(
        "https://unreachable/p.tar.gz",
        Some("deadbeef"),
        "p.tar.gz",
    )];

    assert!(
        fetch_plugins(&dir, &s, true, &dead).is_err(),
        "boot miss must be fatal"
    );

    let out = fetch_plugins(&dir, &s, false, &dead).unwrap();
    assert!(
        matches!(out.as_slice(), [FetchOutcome::Warned { .. }]),
        "reload miss must warn: {out:?}"
    );
    assert!(!dir.join("p.tar.gz").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Plugin#2 regression: a `filename` that is not a single path component (a `../../` traversal or an
/// absolute path) is REFUSED before any `dir.join`, so it can never escape `plugins.dir` at either
/// the cache-probe or the durable-write join. At boot it is fatal; the downloader is never touched
/// and nothing is written anywhere.
#[test]
fn traversal_filename_is_refused_at_both_sites() {
    let dir = tmpdir();
    let body = b"payload";
    let pin = sha256_hex(body);
    // A downloader that WOULD succeed — so if the guard were absent, the escaping path would be
    // written. It must never be called, and nothing must land.
    let dl = |_: &str| Ok(body.to_vec());

    for evil in [
        "../../evil",
        "../evil.tar.gz",
        "sub/evil.tar.gz",
        "/etc/evil",
        ".",
        "",
    ] {
        // Pinned: exercises the cache-probe join AND the verify-then-write join.
        let err = fetch_plugins(
            &dir,
            &[spec("https://x/p.tar.gz", Some(&pin), evil)],
            true,
            &dl,
        )
        .unwrap_err();
        assert!(
            err[0].contains("unsafe target filename"),
            "filename {evil:?} must be refused as unsafe, got {err:?}"
        );
    }

    // The escaping targets a `../` guard would have created must not exist, and `dir` stays empty.
    assert!(!dir.parent().unwrap().join("evil").exists());
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(leftovers.is_empty(), "dir must be untouched: {leftovers:?}");

    // A plain single-component filename still works (the guard is not over-broad).
    let out = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "good.tar.gz")],
        true,
        &dl,
    )
    .unwrap();
    assert_eq!(
        out,
        vec![FetchOutcome::Fetched {
            filename: "good.tar.gz".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A verified download is written atomically and readable back byte-for-byte.
#[test]
fn verified_download_is_written() {
    let dir = tmpdir();
    let body = b"fresh-tarball-bytes";
    let pin = sha256_hex(body);
    let dl = |_: &str| Ok(body.to_vec());
    let out = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
        true,
        &dl,
    )
    .unwrap();
    assert_eq!(
        out,
        vec![FetchOutcome::Fetched {
            filename: "p.tar.gz".into()
        }]
    );
    assert_eq!(std::fs::read(dir.join("p.tar.gz")).unwrap(), body);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sealed first-party tarball whose keys document expired at `expires` (Unix seconds).
fn sealed_tarball(expires: u64) -> Vec<u8> {
    use crate::release_trust::tests::{
        entry, keys_doc, seal_keys, seal_targets, targets_doc, TestSigner,
    };
    let (root, signer) = (TestSigner::p256(), TestSigner::p256());
    let lib = b"lib";
    let m = crate::sign::Manifest {
        name: "busbar-store-x".into(),
        alias: "x".into(),
        kind: "store".into(),
        version: "1.6.0".into(),
        publisher: "busbar".into(),
        abi_version: 1,
        sha256: sha256_hex(lib),
        ..Default::default()
    };
    let listed = sha256_hex(&crate::sign::canonical_manifest_bytes(&m));
    let mut keys = keys_doc(&[&signer]);
    keys.expires = expires;
    let mut targets = targets_doc(vec![entry(
        &m.name,
        &m.version,
        crate::release_trust::PLUGIN_TARGET,
        &listed,
    )]);
    targets.expires = expires;
    let m = crate::sign::Manifest {
        signature: crate::release_trust::wire::write_seal(
            &seal_keys(&keys, &[&root]),
            &seal_targets(&targets, &[&signer]),
        )
        .unwrap(),
        ..m
    };
    crate::tarball::package(&m, "lib.so", lib).unwrap()
}

/// FETCH is install time (TUF's semantics): a downloaded sealed tarball whose keys document has
/// expired is refused and never written, naming the audit code.
#[test]
fn a_fetched_tarball_whose_seal_has_expired_is_refused_and_not_written() {
    let dir = tmpdir();
    let body = sealed_tarball(1_600_000_000); // 2020
    let dl = |_: &str| Ok(body.clone());
    let err = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
        true,
        &dl,
    )
    .unwrap_err();
    assert!(err[0].contains("keys-expired"), "{err:?}");
    assert!(
        !dir.join("p.tar.gz").exists(),
        "an expired download is never written"
    );
    let fresh = sealed_tarball(crate::release_trust::now() + 86_400);
    let dl = |_: &str| Ok(fresh.clone());
    fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
        true,
        &dl,
    )
    .expect("a fresh seal is written");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An INSTALLED (cached, pinned) tarball is not re-judged for expiry: boot keeps it.
#[test]
fn an_installed_tarball_whose_seal_has_since_expired_is_kept() {
    let dir = tmpdir();
    let body = sealed_tarball(1_600_000_000);
    std::fs::write(dir.join("p.tar.gz"), &body).unwrap();
    let pin = sha256_hex(&body);
    let never = |_: &str| -> Result<Vec<u8>, String> { panic!("network must not be touched") };
    let out = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
        true,
        &never,
    )
    .unwrap();
    assert_eq!(
        out,
        vec![FetchOutcome::Cached {
            filename: "p.tar.gz".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}
