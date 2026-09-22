//! `cargo xtask conformance check --selftest` — the RED/GREEN proofs for the turnstile-facing
//! admission command. Mirrors `gates::conformance_sync::selftest`'s shape (a GREEN control, then one
//! plant per failure mode) but drives the plain functions in [`super`] directly: this command
//! answers a CLI question against explicit `--suite`/`--sha`/`--manifest` flags rather than a fixed
//! `Gate::run`, so there is no `Gate` to hand a generic `prove_rows_red` harness.

use serde_json::json;

use crate::ctx::{Ctx, Overlay};
use crate::ledger::{Row, Status};

use super::{check_musts, check_one_suite, DEFAULT_MANIFEST_PATH};

const SHA: &str = "cafef00dcafef00dcafef00dcafef00dcafef00";
const OTHER_SHA: &str = "0000000000000000000000000000000000000000";

/// Two suites: `alpha` is a fresh pass at [`SHA`]; `beta` has not run. Enough to exercise every
/// admission path without needing the real registry/manifest.
fn base_manifest() -> serde_json::Value {
    json!({
        "schema": "busbar.conformance.manifest/1",
        "release": "1.6.0",
        "commit": SHA,
        "generated_at": "2026-09-19T14:05:00Z",
        "suites": [
            {
                "suite": "alpha",
                "standard": "Alpha Standard",
                "plan": "alpha plan",
                "tier": "conformant",
                "public": true,
                "status": "pass",
                "claim": "Conformant — passes alpha plan",
                "commit": SHA,
                "evidence": "https://example.invalid/alpha",
                "verified_at": "2026-09-19T14:05:00Z"
            },
            {
                "suite": "beta",
                "standard": "Beta Standard",
                "plan": "beta plan",
                "tier": "conformant",
                "public": true,
                "status": "not-run",
                "claim": null,
                "reason": "planned 1.6.0 — beta leg not yet green"
            }
        ]
    })
}

fn planted(cx: &Ctx, manifest: &serde_json::Value) -> Ctx {
    let mut ov = Overlay::new();
    ov.set(
        DEFAULT_MANIFEST_PATH,
        serde_json::to_string_pretty(manifest).unwrap(),
    );
    cx.with_overlay(ov)
}

struct Case {
    name: &'static str,
    proven: bool,
}

/// A case is PROVEN when the row lands on the expected status and its title+detail together name
/// why — a case that merely lands on the right status with an unrelated message would prove
/// nothing about the specific hazard it names.
fn expect(name: &'static str, row: Row, want: Status, must_contain: &str) -> Case {
    let message = format!("{} {}", row.title, row.detail);
    let proven = row.status == want && message.contains(must_contain);
    if !proven {
        eprintln!(
            "  NOT PROVEN: {name}\n    got:    status={:?} title={:?} detail={:?}\n    wanted: \
             status={:?} title+detail containing {:?}",
            row.status, row.title, row.detail, want, must_contain
        );
    }
    Case { name, proven }
}

pub fn run(cx: &Ctx) -> i32 {
    println!("xtask conformance check --selftest");
    let mut cases = Vec::new();

    let planted_cx = planted(cx, &base_manifest());

    // ── GREEN control: a fresh pass is admitted.
    cases.push(expect(
        "fresh-pass suite is admitted (GREEN)",
        check_one_suite(&planted_cx, DEFAULT_MANIFEST_PATH, "alpha", SHA),
        Status::Pass,
        "fresh pass",
    ));

    // ── RED: unknown suite id — deny-safe, never a silent pass on a name nobody registered.
    cases.push(expect(
        "unknown suite id is refused (RED)",
        check_one_suite(&planted_cx, DEFAULT_MANIFEST_PATH, "not-a-suite", SHA),
        Status::Fail,
        "not a registered suite",
    ));

    // ── RED: a pass carried over from an older sha — CONFORMANCE-SYNC-DESIGN.md §5.2.
    cases.push(expect(
        "a pass carried over from an older sha is STALE (RED)",
        check_one_suite(&planted_cx, DEFAULT_MANIFEST_PATH, "alpha", OTHER_SHA),
        Status::Fail,
        "STALE",
    ));

    // ── RED: a non-pass status (here, not-run).
    cases.push(expect(
        "a not-run suite is refused (RED)",
        check_one_suite(&planted_cx, DEFAULT_MANIFEST_PATH, "beta", SHA),
        Status::Fail,
        "not a fresh pass",
    ));

    // ── RED: a MISSING manifest — nothing to admit from, so nothing is admitted.
    let mut ov = Overlay::new();
    ov.remove(DEFAULT_MANIFEST_PATH);
    let no_manifest_cx = cx.with_overlay(ov);
    cases.push(expect(
        "a missing manifest is refused (RED), never a silent pass",
        check_one_suite(&no_manifest_cx, DEFAULT_MANIFEST_PATH, "alpha", SHA),
        Status::Fail,
        "could not be loaded",
    ));

    // ── RED: an unparseable manifest.
    let mut ov = Overlay::new();
    ov.set(DEFAULT_MANIFEST_PATH, "{ not json");
    let bad_json_cx = cx.with_overlay(ov);
    cases.push(expect(
        "an unparseable manifest is refused (RED)",
        check_one_suite(&bad_json_cx, DEFAULT_MANIFEST_PATH, "alpha", SHA),
        Status::Fail,
        "could not be loaded",
    ));

    // ── `--musts` GREEN: every registered suite is a fresh pass.
    let mut all_pass = base_manifest();
    if let Some(arr) = all_pass.get_mut("suites").and_then(|v| v.as_array_mut()) {
        for s in arr.iter_mut() {
            s["status"] = json!("pass");
            s["commit"] = json!(SHA);
        }
    }
    let all_pass_cx = planted(cx, &all_pass);
    let musts_rows = check_musts(&all_pass_cx, DEFAULT_MANIFEST_PATH, SHA);
    let musts_green = musts_rows.len() == 2 && musts_rows.iter().all(|r| r.status == Status::Pass);
    if !musts_green {
        eprintln!("  NOT PROVEN: --musts GREEN control: rows = {musts_rows:?}");
    }
    cases.push(Case {
        name: "--musts admits when every registered suite is a fresh pass (GREEN)",
        proven: musts_green,
    });

    // ── `--musts` RED: the single call turnstile makes denies the moment any MUST suite is not a
    //    fresh pass — here `beta` is not-run.
    let musts_rows_mixed = check_musts(&planted_cx, DEFAULT_MANIFEST_PATH, SHA);
    let musts_red = musts_rows_mixed.iter().any(|r| r.status == Status::Fail)
        && musts_rows_mixed
            .iter()
            .any(|r| r.id == "conformance-check:beta" && r.status == Status::Fail);
    if !musts_red {
        eprintln!("  NOT PROVEN: --musts RED control: rows = {musts_rows_mixed:?}");
    }
    cases.push(Case {
        name: "--musts denies when any registered suite is not fresh-pass (RED)",
        proven: musts_red,
    });

    let mut failed = Vec::new();
    for c in &cases {
        println!(
            "  {:<11} {}",
            if c.proven { "PROVEN" } else { "NOT PROVEN" },
            c.name
        );
        if !c.proven {
            failed.push(c.name);
        }
    }
    if failed.is_empty() {
        println!(
            "xtask conformance check --selftest: {} case(s), the command is proven able to admit \
             AND deny",
            cases.len()
        );
        0
    } else {
        eprintln!(
            "xtask conformance check --selftest FAILED: {}",
            failed.join(", ")
        );
        1
    }
}
