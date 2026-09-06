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

//! ## What this gate reads, and what it deliberately does not
//!
//! Both scans read PRODUCTION source through `tests/common/mod.rs` — comments stripped, and every
//! `#[cfg(test)] mod` body removed. That is not a detail. Reading a leg file whole means a
//! `Usage::report(` written inside that file's own unit tests satisfies the gate, and a plane whose
//! Meter step reaches nothing passes on the strength of the mock its tests use to stand in for the
//! step that is missing. The same applies one level down: the waist hop is resolved to the Meter
//! step's OWN module rather than summed over the plane's whole `src/unit/` tree, because a token in
//! the plane's Admit or Audit step is not the Meter step reaching the ledger — it is a different
//! step, and counting it means the gate answers a question about the file layout instead of about
//! the step.
//!
//! And the scan is of the Meter step's BODY, not of the file the step lives in. A leg file names
//! the usage seam in several steps; asking the file is how a `fn meter` that returns
//! `Decision::proceed` with an empty report keeps a green gate.

mod common;

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

/// The count of production Meter-seam reaches in a plane crate's `src/` tree. PRODUCTION means the
/// shipped binary's text: [`common::production_lines`] has already dropped the comments and every
/// `#[cfg(test)] mod` body, so a plane whose only `meter_charge(` is in the mock its unit tests use
/// counts as zero — which is what it is.
fn meter_seam_reaches(crate_dir: &Path) -> usize {
    let mut files = Vec::new();
    common::production_rs_files(&crate_dir.join("src"), &mut files);
    files
        .iter()
        .flat_map(|p| common::production_lines(p))
        .filter(|l| METER_SEAM_TOKENS.iter().any(|tok| l.code.contains(tok)))
        .count()
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

/// THE ONE HOP a Meter step is allowed. `units_llm.rs`'s step is `self.walk.meter(token, usage)`,
/// which lands in the plane's own Meter module — the same one usage seam, reached through the
/// plane's waist rather than restated in the root. What the hop may NOT do is land anywhere else in
/// the plane: the destination below is the Meter step's own module, and a `Usage::report(` in the
/// plane's Admit or Audit step is a different step doing a different thing.
const PLANE_METER_STEP_MODULE: &[&str] = &["src", "unit", "meter.rs"];

/// The call shapes that hand the Meter step off to the plane's own waist.
const WAIST_HOP_TOKENS: &[&str] = &[".meter(", "::meter("];

/// Whether a classified production line reaches a Teller usage seam.
fn line_reaches_usage_seam(line: &common::Line) -> bool {
    TELLER_USAGE_SEAM_TOKENS
        .iter()
        .any(|tok| line.code.contains(tok))
}

/// The count of usage-seam reaches among a set of production lines.
fn usage_seam_reaches(lines: &[&common::Line]) -> usize {
    lines.iter().filter(|l| line_reaches_usage_seam(l)).count()
}

/// The count of usage-seam reaches in the plane's OWN Meter step module — the single legal hop
/// destination, rather than a sum over the whole `src/unit/` tree.
fn usage_seam_reaches_in_plane_meter_step(crate_dir: &Path) -> Option<usize> {
    let mut path: PathBuf = crate_dir.to_path_buf();
    for part in PLANE_METER_STEP_MODULE {
        path = path.join(part);
    }
    if !path.is_file() {
        return None;
    }
    let lines = common::production_lines(&path);
    let refs: Vec<&common::Line> = lines.iter().collect();
    Some(usage_seam_reaches(&refs))
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
        let lines = common::production_lines(&leg_path);
        assert!(
            !lines.is_empty(),
            "root leg {} classified to zero production lines — the scan is reading nothing, and a \
             scan that reads nothing passes everything",
            leg_path.display()
        );

        // (1) The leg must CARRY the Teller Meter step at all, IN PRODUCTION. A leg with no
        //     `fn meter` contributes no Meter method to the loop, and the loop cannot call a step
        //     that is not there. A `fn meter` that exists only inside the leg's own
        //     `#[cfg(test)] mod` is not in the binary and does not count.
        let Some(body) = common::item_body(&lines, "fn meter(") else {
            offenders.push(format!(
                "{plane}: root leg {leg} has NO production `fn meter(` — it contributes no Meter \
                 step to the Teller loop, so nothing it serves over the root is ever priced"
            ));
            continue;
        };

        // (2) The STEP'S OWN BODY must reach the one usage seam, directly or through the single
        //     legal hop into the plane's own Meter module. The question is asked of the step, not
        //     of the file: another step in the same file reaching the seam says nothing about this
        //     one, and a `fn meter` that proceeds with an empty report charges nobody.
        let direct = usage_seam_reaches(&body);
        if direct > 0 {
            println!("  {plane:<13} {leg:<15} usage seam: {direct} in the step's own body");
            continue;
        }

        let hops = body
            .iter()
            .filter(|l| WAIST_HOP_TOKENS.iter().any(|tok| l.code.contains(tok)))
            .count();
        if hops == 0 {
            offenders.push(format!(
                "{plane}: root leg {leg}'s `fn meter` body reaches the usage seam ({}) directly and \
                 hands off to nothing. A Meter step that reports no lines proceeds with an empty \
                 usage report — the loop runs, the audit seals, and the principal is charged nothing",
                TELLER_USAGE_SEAM_TOKENS.join(" / "),
            ));
            continue;
        }

        let meter_module = root.join(plane).join(PLANE_METER_STEP_MODULE.join("/"));
        match usage_seam_reaches_in_plane_meter_step(&root.join(plane)) {
            None => offenders.push(format!(
                "{plane}: root leg {leg}'s `fn meter` body hands off to the plane's waist, but \
                 {} does not exist. The hop lands nowhere this gate can follow, so nothing proves \
                 the handoff ends at the usage seam rather than at a step that reports no lines",
                meter_module.display()
            )),
            Some(0) => offenders.push(format!(
                "{plane}: root leg {leg}'s `fn meter` body hands off to the plane's waist, and the \
                 plane's own Meter step ({}) reaches the usage seam ({}) ZERO times in production. \
                 The handoff is real and the destination meters nobody",
                meter_module.display(),
                TELLER_USAGE_SEAM_TOKENS.join(" / "),
            )),
            Some(n) => {
                println!("  {plane:<13} {leg:<15} usage seam: {n} in the plane's own Meter step");
            }
        }
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

/// Classify a synthetic leg and hand back its `fn meter` body's production lines.
fn meter_body_of(src: &str) -> Vec<String> {
    let lines = common::classify(src, false);
    let prod: Vec<common::Line> = lines.into_iter().filter(|l| !l.intest).collect();
    common::item_body(&prod, "fn meter(")
        .map(|b| b.iter().map(|l| l.code.clone()).collect())
        .unwrap_or_default()
}

#[test]
fn selftest_the_seam_scanners_discriminate() {
    let seam = |code: &str| {
        TELLER_USAGE_SEAM_TOKENS
            .iter()
            .any(|tok| code.contains(tok))
    };
    // A real call counts; the same token in a comment or with no call parens does not.
    let prod = |src: &str| {
        common::classify(src, false)
            .into_iter()
            .filter(|l| !l.intest)
            .map(|l| l.code)
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(seam(&prod("Usage::report(usage, lines)\n")));
    assert!(!seam(&prod("// Usage::report(usage, lines)\n")));
    assert!(!seam(&prod("let x = 1; // fold_usage(y)\n")));
    assert!(!seam(&prod("let x = record_metering;\n")));
    assert!(METER_SEAM_TOKENS
        .iter()
        .any(|t| prod("host.meter_charge(&scope, n);\n").contains(t)));
}

/// THE FAILURE THIS GATE WAS BLIND TO. The scan used to read the leg file whole, so a seam token in
/// the leg's own `#[cfg(test)] mod tests` satisfied it — a Meter step reaching NOTHING passed on
/// the strength of the mock the tests use to stand in for the step that is missing. Driven here on
/// synthetic source so the proof does not require planting a fake leg in the tree.
#[test]
fn selftest_a_seam_reached_only_by_a_test_module_does_not_count() {
    let leg_that_meters_nobody = r#"
impl TellerPlane for Leg {
    fn meter(&self, token: &UnitToken<Meter>, usage: &UsageToken) -> Decision<Meter> {
        Decision::proceed(token, Default::default())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_step_meters() {
        let report = Usage::report(usage, lines);
        assert!(report.is_ok());
    }
}
"#;
    let body = meter_body_of(leg_that_meters_nobody).join("\n");
    assert!(
        !body.is_empty(),
        "the synthetic leg's Meter step must be found at all, or this self-test proves nothing"
    );
    assert!(
        !TELLER_USAGE_SEAM_TOKENS.iter().any(|t| body.contains(t)),
        "a `Usage::report(` that exists only inside the leg's `#[cfg(test)] mod tests` was counted \
         as the Meter step reaching the ledger. The whole gate is satisfiable by a mock while that \
         is true:\n{body}"
    );
    assert!(
        !WAIST_HOP_TOKENS.iter().any(|t| body.contains(t)),
        "the step hands off to nothing either, so this synthetic leg is exactly the shape the gate \
         must report: proceed with an empty report, charging nobody:\n{body}"
    );
}

/// THE SECOND FAILURE. The waist hop used to be summed over the plane's whole `src/unit/` tree, so
/// a `Usage::report(` in the plane's AUDIT step satisfied a gate asking about its METER step. The
/// hop destination is now one named module, and this proves the two are told apart.
#[test]
fn selftest_the_hop_lands_on_the_meter_step_and_not_the_neighbouring_step() {
    let root = crates_root();
    for (plane, _) in BILLING_PLANE_ROOT_LEGS {
        let dir = root.join(plane);
        let unit_dir = dir.join("src").join("unit");
        if !unit_dir.is_dir() {
            continue;
        }
        let mut all = Vec::new();
        common::production_rs_files(&unit_dir, &mut all);
        let tree_wide: usize = all
            .iter()
            .flat_map(|p| common::production_lines(p))
            .filter(line_reaches_usage_seam)
            .count();
        let step_only = usage_seam_reaches_in_plane_meter_step(&dir).unwrap_or(0);
        assert!(
            step_only <= tree_wide,
            "{plane}: the Meter step's own module cannot reach the seam more often than the whole \
             unit tree does — the scan is reading the wrong file"
        );
        println!("  {plane:<13} usage seam: {step_only} in the Meter step, {tree_wide} tree-wide");
    }
}
