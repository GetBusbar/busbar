//! `cargo xtask conformance check --selftest` — the RED/GREEN proofs for the CI-facing
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

/// A manifest over `ids` (every row a fresh pass at [`SHA`] except `not_run`), plus one fresh-pass
/// row for each of `extra`.
fn registered_manifest(ids: &[String], not_run: Option<&str>, extra: &[&str]) -> serde_json::Value {
    let row = |id: &str| {
        if Some(id) == not_run {
            json!({"suite": id, "status": "not-run", "reason": "planted: this leg did not run"})
        } else {
            json!({"suite": id, "status": "pass", "commit": SHA})
        }
    };
    let suites: Vec<serde_json::Value> = ids
        .iter()
        .map(String::as_str)
        .chain(extra.iter().copied())
        .map(row)
        .collect();
    json!({
        "schema": "busbar.conformance.manifest/1",
        "release": "1.6.0",
        "commit": SHA,
        "generated_at": "2026-09-19T14:05:00Z",
        "suites": suites
    })
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

    // ── RED: a pass carried over from an older sha: a pass is honoured only on its own commit.
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

    // The `--musts` cases run over the REAL registry's suite ids: the MUST set is the registry's,
    // so a manifest of made-up names proves nothing about it.
    let ids: Vec<String> = crate::gates::conformance_sync::render::parse_registry(cx)
        .map(|suites| suites.into_iter().map(|s| s.id).collect())
        .unwrap_or_default();
    if ids.len() < 2 {
        eprintln!(
            "  NOT PROVEN: the registry yields {} suite id(s); the --musts cases need two",
            ids.len()
        );
    }
    let all_pass = registered_manifest(&ids, None, &[]);

    // ── `--musts` GREEN: every registered suite is a fresh pass.
    let all_pass_cx = planted(cx, &all_pass);
    let musts_rows = check_musts(&all_pass_cx, DEFAULT_MANIFEST_PATH, SHA);
    let musts_green = ids.len() >= 2
        && musts_rows.len() == ids.len()
        && musts_rows.iter().all(|r| r.status == Status::Pass);
    if !musts_green {
        eprintln!("  NOT PROVEN: --musts GREEN control: rows = {musts_rows:?}");
    }
    cases.push(Case {
        name: "--musts admits when every registered suite is a fresh pass (GREEN)",
        proven: musts_green,
    });

    // ── `--musts` RED: the single call the `conformance` check makes denies the moment any MUST
    //    suite is not a fresh pass — here the first registered suite is not-run.
    let first = ids.first().cloned().unwrap_or_default();
    let mixed_cx = planted(cx, &registered_manifest(&ids, Some(&first), &[]));
    let musts_rows_mixed = check_musts(&mixed_cx, DEFAULT_MANIFEST_PATH, SHA);
    let musts_red = musts_rows_mixed
        .iter()
        .any(|r| r.id == format!("conformance-check:{first}") && r.status == Status::Fail);
    if !musts_red {
        eprintln!("  NOT PROVEN: --musts RED control: rows = {musts_rows_mixed:?}");
    }
    cases.push(Case {
        name: "--musts denies when any registered suite is not fresh-pass (RED)",
        proven: musts_red,
    });

    // ── `--musts` RED: a manifest that DROPS a registered suite cannot shrink the MUST set into a
    //    green. Every row it does carry is a fresh pass; the missing one is the refusal.
    let last = ids.last().cloned().unwrap_or_default();
    let dropped: Vec<String> = ids.iter().filter(|i| **i != last).cloned().collect();
    let dropped_cx = planted(cx, &registered_manifest(&dropped, None, &[]));
    let dropped_rows = check_musts(&dropped_cx, DEFAULT_MANIFEST_PATH, SHA);
    let dropped_red = dropped_rows.iter().any(|r| {
        r.id == format!("conformance-check:{last}")
            && r.status == Status::Fail
            && format!("{} {}", r.title, r.detail).contains("absent from the manifest")
    });
    if !dropped_red {
        eprintln!("  NOT PROVEN: --musts dropped-suite RED: rows = {dropped_rows:?}");
    }
    cases.push(Case {
        name: "--musts denies a manifest that drops a registered suite (RED, registry denominator)",
        proven: dropped_red,
    });

    // ── `--musts` RED: a manifest row the registry does not name is no MUST anybody owes; it is
    //    refused rather than counted, so a renamed suite cannot stand in for the registered one.
    let extra_cx = planted(cx, &registered_manifest(&ids, None, &["not-a-suite"]));
    let extra_rows = check_musts(&extra_cx, DEFAULT_MANIFEST_PATH, SHA);
    let extra_red = extra_rows.iter().any(|r| {
        r.id == "conformance-check:not-a-suite"
            && r.status == Status::Fail
            && format!("{} {}", r.title, r.detail).contains("not a registered suite")
    });
    if !extra_red {
        eprintln!("  NOT PROVEN: --musts extra-suite RED: rows = {extra_rows:?}");
    }
    cases.push(Case {
        name: "--musts denies a manifest row the registry does not name (RED)",
        proven: extra_red,
    });

    // ── `--musts` RED: the MUST set has a floor derived from the planes the build ships. The same
    //    all-pass manifest is DENIED once the registry leaves a shipped plane (decisions) with no
    //    suite: deleting a plane's suite block cannot shrink the requirement into a green.
    let registry = cx
        .read(crate::gates::conformance_sync::render::REGISTRY_PATH)
        .unwrap_or_default();
    let mut ov = Overlay::new();
    ov.set(
        DEFAULT_MANIFEST_PATH,
        serde_json::to_string_pretty(&all_pass).unwrap(),
    );
    ov.set(
        crate::gates::conformance_sync::render::REGISTRY_PATH,
        registry.replace("plane = \"decisions\"\n", ""),
    );
    let floor_rows = check_musts(&cx.with_overlay(ov), DEFAULT_MANIFEST_PATH, SHA);
    let floor_red = registry.contains("plane = \"decisions\"\n")
        && floor_rows.len() == 1
        && floor_rows[0].id == "conformance-check:registry"
        && floor_rows[0].status == Status::Fail
        && floor_rows[0].detail.contains("decisions");
    if !floor_red {
        eprintln!("  NOT PROVEN: --musts plane-floor RED: rows = {floor_rows:?}");
    }
    cases.push(Case {
        name: "--musts denies when a shipped plane has no registered suite (RED, derived floor)",
        proven: floor_red,
    });

    // ── `--musts` RED: the MUST set has an ARMED floor too (`SUITE_FLOOR`, Law 9). A registry with
    //    the block of a suite that judges no plane (ws) cut out leaves every plane covered, and the
    //    same all-pass manifest minus that row is still DENIED: no suite leaves the MUST set.
    let without_ws = registry
        .split("\n[[suite]]\n")
        .filter(|block| !block.starts_with("id = \"ws\"\n"))
        .collect::<Vec<_>>()
        .join("\n[[suite]]\n");
    let mut ov = Overlay::new();
    ov.set(
        DEFAULT_MANIFEST_PATH,
        serde_json::to_string_pretty(&registered_manifest(
            &ids.iter()
                .filter(|i| *i != "ws")
                .cloned()
                .collect::<Vec<_>>(),
            None,
            &[],
        ))
        .unwrap(),
    );
    ov.set(
        crate::gates::conformance_sync::render::REGISTRY_PATH,
        without_ws.clone(),
    );
    let armed_rows = check_musts(&cx.with_overlay(ov), DEFAULT_MANIFEST_PATH, SHA);
    let armed_red = without_ws != registry
        && armed_rows.len() == 1
        && armed_rows[0].id == "conformance-check:registry"
        && armed_rows[0].status == Status::Fail
        && armed_rows[0]
            .detail
            .contains("the armed suite(s) ws are absent");
    if !armed_red {
        eprintln!("  NOT PROVEN: --musts armed-floor RED: rows = {armed_rows:?}");
    }
    cases.push(Case {
        name: "--musts denies when an armed suite's block is deleted (RED, armed floor)",
        proven: armed_red,
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
