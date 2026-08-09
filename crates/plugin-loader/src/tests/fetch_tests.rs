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
