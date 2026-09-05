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
//! * `xtask-fixture-via-only` — a pure crate whose ONLY path to `libc` runs through a local `mid`
//!   crate (`xtask-fixture-via-mid`). RED on `libc` with no allow-list entry; GREEN with a
//!   `dep = "libc", via = "xtask-fixture-via-mid"` waiver, proving `via` fully covers a crate
//!   when no path bypasses it.
//! * `xtask-fixture-via-bypass` — the same shape PLUS a second, direct dependency on `libc`. The
//!   SAME `via = "xtask-fixture-via-mid"` waiver must leave it RED, proving a bypassing path
//!   defeats the narrowing rather than being silently forgiven alongside the covered one.
//!
//! Each fixture is its own tiny standalone Cargo workspace (`[workspace]` with no members other
//! than itself, or itself plus a local `mid` path-dependency) so `cargo metadata --manifest-path`
//! resolves it without touching the real workspace's Cargo.lock.

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
    let pc = PureCrate {
        name: manifest_name.to_string(),
        dir: dir.clone(),
        kind: "plane".to_string(),
        report_name: manifest_name.to_string(),
    };
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
    check_via_only(&mut fails);
    check_via_bypass(&mut fails);

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
        report_name: "xtask-fixture-dirty-src".to_string(),
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

/// `xtask-fixture-via-only` reaches `libc` ONLY through `xtask-fixture-via-mid`: RED with no
/// allow-list entry, fully GREEN with a `via`-narrowed `dep = "libc"` waiver naming that crate.
fn check_via_only(fails: &mut Vec<String>) {
    let root = workspace_root();
    let banned = denylist::load_banned_lists(&root);
    let fragments = denylist::load_test_fragments_pub(&root);
    let dir = fixtures_dir().join("via-only");
    let manifest = dir.join("Cargo.toml");
    if !manifest.exists() {
        fails.push(format!("via-only: fixture manifest missing at {}", manifest.display()));
        return;
    }
    let pc = || PureCrate {
        name: "xtask-fixture-via-only".to_string(),
        dir: dir.clone(),
        kind: "plane".to_string(),
        report_name: "xtask-fixture-via-only".to_string(),
    };

    let red_hits = denylist::run_on(&manifest, vec![pc()], &banned, &fragments);
    if !red_hits.iter().any(|h| h.offender == "libc") {
        fails.push(format!(
            "via-only: expected a `libc` hit with no allow-list entry, got: {}",
            red_hits.iter().map(|h| h.offender.clone()).collect::<Vec<_>>().join(", ")
        ));
        return;
    }
    println!("  RED    via-only: `libc` hit with no allow-list entry, as expected");

    let allow = vec![("xtask-fixture-via-only", "libc", Some("xtask-fixture-via-mid"))];
    let green_hits =
        denylist::run_on_with_allow(&manifest, vec![pc()], &banned, &fragments, allow);
    if green_hits.iter().any(|h| h.offender == "libc") {
        fails.push(format!(
            "via-only: expected 0 `libc` hits with the via-narrowed waiver applied, got: {}",
            green_hits.iter().map(|h| h.offender.clone()).collect::<Vec<_>>().join(", ")
        ));
    } else {
        println!("  GREEN  via-only: `libc` fully waived by `via = \"xtask-fixture-via-mid\"`");
    }
}

/// `xtask-fixture-via-bypass` reaches `libc` through `xtask-fixture-via-mid` AND directly. The
/// same `via`-narrowed waiver used for `via-only` must leave this fixture RED on `libc`.
fn check_via_bypass(fails: &mut Vec<String>) {
    let root = workspace_root();
    let banned = denylist::load_banned_lists(&root);
    let fragments = denylist::load_test_fragments_pub(&root);
    let dir = fixtures_dir().join("via-bypass");
    let manifest = dir.join("Cargo.toml");
    if !manifest.exists() {
        fails.push(format!("via-bypass: fixture manifest missing at {}", manifest.display()));
        return;
    }
    let pc = PureCrate {
        name: "xtask-fixture-via-bypass".to_string(),
        dir: dir.clone(),
        kind: "plane".to_string(),
        report_name: "xtask-fixture-via-bypass".to_string(),
    };

    let allow = vec![("xtask-fixture-via-bypass", "libc", Some("xtask-fixture-via-mid"))];
    let hits = denylist::run_on_with_allow(&manifest, vec![pc], &banned, &fragments, allow);
    if hits.iter().any(|h| h.offender == "libc") {
        println!(
            "  RED    via-bypass: `libc` stays red under the via-narrowed waiver (a direct path \
             bypasses `via`), as expected"
        );
    } else {
        fails.push(
            "via-bypass: expected `libc` to stay red under the via-narrowed waiver (a direct \
             dependency bypasses `via`), but it was fully waived"
                .to_string(),
        );
    }
}
