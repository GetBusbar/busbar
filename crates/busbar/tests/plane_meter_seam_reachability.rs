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
