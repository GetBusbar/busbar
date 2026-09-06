// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE METER-STEP REACHABILITY GATE — the mechanical proof that every billing plane actually
//! traverses the core Meter step (the canonical path's `Meter` verb: record/debit spend to the
//! principal's ledger), instead of reimplementing or skipping it.
//!
//! Why this gate exists: neutrality/doctrine gates prove the core mentions no plane — a SYNTACTIC
//! property. They are structurally blind to a plane that is perfectly neutral yet never bills,
//! because it built its own detached metering apparatus and left it unwired. That is exactly how a
//! plane can price at $0 in the shipped binary while every existing gate stays green. This gate
//! closes that blind spot: it scans each billing plane's PRODUCTION source (tests excluded) and
//! fails RED unless the plane reaches the core Meter seam at least once.
//!
//! The core Meter seam (the attributed metering entry points on the host / governance state — the
//! ONE billing path every plane must use, never a plane-private ledger):
//!   - `meter_charge`   (EngineHost: attributed charge over a dispatch scope)
//!   - `meter_ledger`   (EngineHost: ledger a delivery's usage against the key's budget chain)
//!   - `meter_series`   (EngineHost: record raw consumption into the per-key metering series)
//!   - `record_metering`/`record_usage` (governance-state accrual the above drive)
//!
//! A plane that calls NONE of these in production has no way to put spend on the ledger — it bills
//! nobody. This gate makes that a build failure, named by plane.
//!
//! ## Two paths, the same question
//!
//! The scan above is the LEGACY path's answer: the plane crate serves the request and reaches the
//! host's metering entry points itself. Over the composition root the plane holds no host at all —
//! it contributes one method per Teller step and the loop calls them in order — so the Meter step
//! lives in that plane's leg under `crates/busbar/src/root/units_*.rs`. A leg can pass every
//! neutrality and isomorphism gate in the tree and still proceed with an EMPTY usage report, which
//! is the identical blind spot one path over. [`every_billing_plane_reaches_the_usage_seam_on_its_teller_meter_step`]
//! closes it: every billing plane's leg must carry a Meter step AND reach the one usage seam.

use std::path::{Path, PathBuf};

/// Every plane that performs billable work and therefore MUST reach the core Meter seam. Keyed by
/// the plane's crate directory name under `crates/`.
const BILLING_PLANE_CRATES: &[&str] = &["busbar-llm", "busbar-mcp", "busbar-a2a", "busbar-voice"];

/// The core Meter-seam call tokens. A production line containing any of these (outside a comment)
/// counts as reaching the one billing path.
const METER_SEAM_TOKENS: &[&str] = &[
    "meter_charge(",
    "meter_ledger(",
    "meter_series(",
    "record_metering(",
    "record_usage(",
];

fn crates_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/busbar; its parent is the crates/ tree.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/busbar has a parent (crates/)")
        .to_path_buf()
}

/// Collect every `.rs` file under `dir` that is PRODUCTION source (not a test file), skipping any
/// `target/` build dir. Test files are excluded because a plane's tests may drive the seam via a
/// mock — the point is whether the SHIPPED source reaches it.
fn production_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == "tests" {
                continue;
            }
            production_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let p = path.to_string_lossy().replace('\\', "/");
            let is_test =
                p.ends_with("_tests.rs") || p.ends_with("/tests.rs") || p.contains("/test_support");
            if !is_test {
                out.push(path);
            }
        }
    }
}

/// Whether `line` contains a Meter-seam call token outside a line/doc comment.
fn has_meter_seam_call(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return false;
    }
    let code = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    METER_SEAM_TOKENS.iter().any(|tok| code.contains(tok))
}

/// The count of production Meter-seam reaches in a plane crate's `src/` tree.
fn meter_seam_reaches(crate_dir: &Path) -> usize {
    let mut files = Vec::new();
    production_rs_files(&crate_dir.join("src"), &mut files);
    let mut n = 0usize;
    for path in &files {
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in src.lines() {
            if has_meter_seam_call(line) {
                n += 1;
            }
        }
    }
    n
}

#[test]
fn every_billing_plane_reaches_the_core_meter_seam_in_production() {
    let root = crates_root();
    let mut offenders: Vec<String> = Vec::new();
    for plane in BILLING_PLANE_CRATES {
        let dir = root.join(plane);
        assert!(
            dir.join("src").is_dir(),
            "plane crate src not found: {} — this gate is scanning the wrong tree",
            dir.display()
        );
        let reaches = meter_seam_reaches(&dir);
        if reaches == 0 {
            offenders.push(format!(
                "{plane}: 0 calls to the core Meter seam ({}) in production source — it cannot put \
                 spend on any principal's ledger; it bills nobody",
                METER_SEAM_TOKENS.join(" / "),
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "a billing plane does NOT traverse the core Meter step in the shipped binary — it must \
         record spend through the ONE core metering seam (never a plane-private ledger):\n{}",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// THE SAME QUESTION OVER THE TELLER PATH.
//
// The gate above scans the PLANE CRATE, which is the legacy path's answer: the plane crate serves
// the request and reaches the host's metering entry points itself. Over the composition root the
// plane does not hold the host at all — it contributes one method per Teller step
// (`busbar_substrate::teller::TellerPlane`) and the loop calls them in order, so the Meter step is
// `fn meter(&mut self, token: &UnitToken<Meter>, usage: &UsageToken, …) -> Decision<Meter>` in that
// plane's leg under `crates/busbar/src/root/`.
//
// A leg can satisfy every neutrality and isomorphism gate in the tree and still hand back a
// `Decision::proceed` with an EMPTY usage report — the loop would run, the audit step would seal a
// terminal, and the principal would be charged nothing. That is the identical blind spot the legacy
// gate closes, one path over, and it is the one that matters now that the planes are being switched
// onto the root. So: every billing plane's leg must reach the ONE usage seam on its Meter step.
// ---------------------------------------------------------------------------

/// Billing plane crate -> the composition root's leg file that runs it through the Teller loop.
/// Admin is deliberately absent: `root-admin` answers to ZERO ledger columns in
/// `qa/capability-equality.json` (an admin request is unpriced), so it is owed no Meter reach and a
/// row here would be a claim the ledger contradicts.
const BILLING_PLANE_ROOT_LEGS: &[(&str, &str)] = &[
    ("busbar-llm", "units_llm.rs"),
    ("busbar-mcp", "units_mcp.rs"),
    ("busbar-a2a", "units_a2a.rs"),
    ("busbar-voice", "units_voice.rs"),
];

/// The ONE usage seam every Teller Meter step folds through, in the three spellings the tree
/// actually uses: the usage unit's own entry point, the report constructor it returns, and the
/// per-leg fold helper that wraps it. A leg reaching NONE of these reports no lines, and a Meter
/// step that reports no lines charges nobody.
const TELLER_USAGE_SEAM_TOKENS: &[&str] =
    &["busbar_unit_usage::meter(", "Usage::report(", "fold_usage("];

/// Whether `line` reaches a Teller usage seam outside a line/doc comment.
fn has_teller_usage_seam(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return false;
    }
    let code = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    TELLER_USAGE_SEAM_TOKENS
        .iter()
        .any(|tok| code.contains(tok))
}

/// The count of usage-seam reaches in a file's production text.
fn usage_seam_reaches_in(path: &Path) -> usize {
    let Ok(src) = std::fs::read_to_string(path) else {
        return 0;
    };
    src.lines().filter(|l| has_teller_usage_seam(l)).count()
}

/// The count of usage-seam reaches in a plane crate's own Teller-waist unit tree (`src/unit/`).
/// A leg is allowed EXACTLY ONE hop: `units_llm.rs`'s Meter step is `self.walk.meter(token, usage)`,
/// which lands in `busbar-llm/src/unit/meter.rs`. That is still the one usage seam, reached through
/// the plane's own waist rather than restated in the root — what is forbidden is reaching NOTHING.
fn usage_seam_reaches_in_plane_waist(crate_dir: &Path) -> usize {
    let mut files = Vec::new();
    production_rs_files(&crate_dir.join("src").join("unit"), &mut files);
    files.iter().map(|p| usage_seam_reaches_in(p)).sum()
}

#[test]
fn every_billing_plane_reaches_the_usage_seam_on_its_teller_meter_step() {
    let root = crates_root();
    let leg_dir = root.join("busbar").join("src").join("root");
    let mut offenders: Vec<String> = Vec::new();

    for (plane, leg) in BILLING_PLANE_ROOT_LEGS {
        let leg_path = leg_dir.join(leg);
        assert!(
            leg_path.is_file(),
            "billing plane `{plane}` names root leg {} , which does not exist — this gate is \
             scanning the wrong tree",
            leg_path.display()
        );
        let src = std::fs::read_to_string(&leg_path).expect("the leg file is readable");

        // (1) The leg must CARRY the Teller Meter step at all. A leg with no `fn meter` contributes
        //     no Meter method to the loop, and the loop cannot call a step that is not there.
        if !src.contains("fn meter(") {
            offenders.push(format!(
                "{plane}: root leg {leg} has NO `fn meter(` — it contributes no Meter step to the \
                 Teller loop, so nothing it serves over the root is ever priced"
            ));
            continue;
        }

        // (2) The step must reach the one usage seam — in the leg itself, or one hop into the
        //     plane's own Teller waist.
        let direct = usage_seam_reaches_in(&leg_path);
        let waist = usage_seam_reaches_in_plane_waist(&root.join(plane));
        if direct == 0 && waist == 0 {
            offenders.push(format!(
                "{plane}: root leg {leg} carries a Meter step but reaches the usage seam ({}) \
                 NEITHER in the leg NOR in {plane}/src/unit/. A Meter step that reports no lines \
                 proceeds with an empty usage report — the loop runs, the audit seals, and the \
                 principal is charged nothing",
                TELLER_USAGE_SEAM_TOKENS.join(" / "),
            ));
            continue;
        }
        println!("  {plane:<13} {leg:<15} usage seam: {direct} in leg, {waist} in plane waist");
    }

    assert!(
        offenders.is_empty(),
        "a billing plane does NOT reach the usage seam on its Teller Meter step — over the \
         composition root the plane holds no host, so the ONLY place spend can be put on the \
         principal's ledger is the loop's Meter step:\n{}",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// SELF-TEST: both gates are proven to FIRE. A gate that cannot fail is worse than none.
// ---------------------------------------------------------------------------

#[test]
fn selftest_the_seam_scanners_discriminate() {
    // The legacy scanner: a real call counts, the same token in a comment does not.
    assert!(has_meter_seam_call("        host.meter_charge(&scope, n);"));
    assert!(!has_meter_seam_call(
        "        // host.meter_charge(&scope, n);"
    ));
    assert!(!has_meter_seam_call(
        "        let x = 1; // meter_ledger(y)"
    ));
    assert!(!has_meter_seam_call("        let x = record_metering;")); // no call parens

    // The Teller scanner: same discrimination over the usage seam's own tokens.
    assert!(has_teller_usage_seam(
        "        match busbar_unit_usage::meter(&retained, &kernel, p, &d, usage) {"
    ));
    assert!(has_teller_usage_seam("        Usage::report(usage, lines)"));
    assert!(!has_teller_usage_seam(
        "        //! the metering step calls Usage::report(…) here"
    ));
    assert!(!has_teller_usage_seam("        let usage = 1;"));
}
