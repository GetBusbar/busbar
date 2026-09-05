//! `cargo xtask denylist --selftest` — proves the denylist logic itself, against synthetic pure
//! crates checked into `xtask/fixtures/`, independent of whatever today's real crate graph looks
//! like. Three fixtures:
//!
//! * `xtask-fixture-clean` — a pure crate with no banned dependency and no banned own-src path.
//!   Must be GREEN.
//! * `xtask-fixture-dirty-dep` — a pure crate that depends directly on `libc` (one of section
//!   1.2's named banned crates). Must be RED, naming `libc`.
//! * `xtask-fixture-dirty-src` — a pure crate with no unusual dependency at all, whose own
//!   `src/lib.rs` calls `std::fs::read` in production code (and, to prove the test-code
//!   exclusion, `std::env::var` inside a `#[cfg(test)] mod`). Must be RED on `std::fs` only —
//!   proving the own-src scan catches an unannounced std path AND that test code is excluded
//!   exactly as section 1.2's I/O-kind carve-out implies.
//!
//! Each fixture is its own tiny standalone Cargo workspace (`[workspace]` with no members other
//! than itself) so `cargo metadata --manifest-path` resolves it without touching the real
//! workspace's Cargo.lock.

use std::path::PathBuf;

use crate::denylist::{self, PureCrate};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn check(
    label: &str,
    fixture_name: &str,
    manifest_name: &str,
    expect_offenders: &[&str],
    fails: &mut Vec<String>,
) {
    let root = workspace_root();
    let banned = denylist::load_banned_lists(&root);
    let fragments = denylist::load_test_fragments_pub(&root);
    let dir = fixtures_dir().join(fixture_name);
    let manifest = dir.join("Cargo.toml");
    if !manifest.exists() {
        fails.push(format!("{label}: fixture manifest missing at {}", manifest.display()));
        return;
    }
    let pc = PureCrate { name: manifest_name.to_string(), dir: dir.clone(), kind: "plane".to_string() };
    let hits = denylist::run_on(&manifest, vec![pc], &banned, &fragments);

    if expect_offenders.is_empty() {
        if hits.is_empty() {
            println!("  GREEN  {label}: 0 hits, as expected");
        } else {
            let names: Vec<_> = hits.iter().map(|h| h.offender.clone()).collect();
            fails.push(format!("{label}: expected 0 hits, got {}: {}", hits.len(), names.join(", ")));
        }
        return;
    }

    let mut missing = Vec::new();
    for want in expect_offenders {
        if !hits.iter().any(|h| h.offender.contains(want)) {
            missing.push(*want);
        }
    }
    if missing.is_empty() {
        let names: Vec<_> = hits.iter().map(|h| h.offender.clone()).collect();
        println!("  RED    {label}: hit(s) [{}] include every expected offender {:?}", names.join(", "), expect_offenders);
    } else {
        fails.push(format!(
            "{label}: expected offender(s) {:?} among the hits, missing {:?} (got: {})",
            expect_offenders,
            missing,
            hits.iter().map(|h| h.offender.clone()).collect::<Vec<_>>().join(", ")
        ));
    }
}

pub fn run() -> bool {
    println!("xtask denylist --selftest");
    let mut fails = Vec::new();

    check("clean pure crate", "clean-pure", "xtask-fixture-clean", &[], &mut fails);
    check("pure crate with a banned direct dependency", "dirty-dep", "xtask-fixture-dirty-dep", &["libc"], &mut fails);
    check(
        "pure crate with a banned own-src path",
        "dirty-src",
        "xtask-fixture-dirty-src",
        &["std::fs"],
        &mut fails,
    );
    check_test_code_excluded(&mut fails);

    if fails.is_empty() {
        println!("\nxtask denylist --selftest: ALL GREEN");
        true
    } else {
        println!("\nxtask denylist --selftest FAILED:");
        for f in &fails {
            println!("  - {f}");
        }
        false
    }
}

/// The `dirty-src` fixture also has `std::env::var` inside a `#[cfg(test)] mod`; this must NOT be
/// reported (mirroring the FAST-tier lint's test-code exclusion), so the fixture's hit list must
/// name `std::fs` and nothing about `std::env`.
fn check_test_code_excluded(fails: &mut Vec<String>) {
    let root = workspace_root();
    let banned = denylist::load_banned_lists(&root);
    let fragments = denylist::load_test_fragments_pub(&root);
    let dir = fixtures_dir().join("dirty-src");
    let manifest = dir.join("Cargo.toml");
    let pc = PureCrate {
        name: "xtask-fixture-dirty-src".to_string(),
        dir: dir.clone(),
        kind: "plane".to_string(),
    };
    let hits = denylist::run_on(&manifest, vec![pc], &banned, &fragments);
    if hits.iter().any(|h| h.offender.contains("std::env")) {
        fails.push(
            "test-code exclusion: dirty-src's #[cfg(test)] mod's std::env::var was reported \
             (should be excluded as test code)"
                .to_string(),
        );
    } else {
        println!("  GREEN  test-code exclusion: #[cfg(test)] mod's std::env::var was NOT reported");
    }
}
