// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `record-op-source` (DES-264 §4.1): every `busbar.recordop1` receipt identity reaching a
//! receipt-writing entry point is a held class-M op minted by `RecordOps`, or the class-D op of
//! `principal_transition::operation`. The types carry the guarantee (`Op` is built only from a
//! `HeldOp` or a `DerivedOp`); this rule refuses the ways around them in production code:
//! - a `DerivedOp` or `Op::Derived` built anywhere but those two owners;
//! - a scoped request's `op` (field or assignment) built from raw bytes: `door::op_id()`, an
//!   `OpId(..)`/`OpId::from_parts`, an attempt id's `.operation`, or a digest slice.

use std::path::Path;

use super::{rel, rust_files, Outcome};

/// The only production files that may build a class-D identity.
const OWNERS: [&str; 2] = [
    "crates/busbar-kernel/src/persistence/record_ops.rs",
    "crates/busbar-kernel/src/off_path/governance/principal_transition.rs",
];

/// Constructions of a class-D identity.
const DERIVED: [&str; 2] = ["DerivedOp::principal_transition(", "Op::Derived("];

/// Raw byte sources an op must never be built from.
const RAW: [&str; 5] = [
    "door::op_id(",
    "OpId(",
    "OpId::from_parts(",
    "digest[",
    "next_id()",
];

/// Markers of a file that hands a request to a receipt-writing entry point.
const ENTRY_POINTS: [&str; 4] = [
    "conditional_native",
    ".conditional(",
    "prepare_delete_exact",
    "scoped::",
];

/// Whether a repo-relative path is test code, which the rule does not cover.
fn test_path(path: &str) -> bool {
    path.contains("/tests/")
        || path.ends_with("_tests.rs")
        || path.ends_with("/tests.rs")
        || path.ends_with("/test_backend.rs")
        || path.contains("/store_kit")
}

/// The findings for one production file's text.
pub(crate) fn findings(path: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let owner = OWNERS.contains(&path);
    // The raw-op rule covers files that reach a receipt entry point (other `op` fields, such as
    // a logical1 debt row's, are not receipt identities).
    let reaches = ENTRY_POINTS.iter().any(|entry| text.contains(entry));
    for (index, line) in text.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        if !owner {
            for site in DERIVED {
                if code.contains(site) {
                    out.push(format!(
                        "{path}:{}: `{site}` outside principal_transition::operation (DES-264 §4.1)",
                        index + 1
                    ));
                }
            }
        }
        let op = reaches && (code.starts_with("op:") || code.contains(".op ="));
        if op {
            if let Some(raw) = RAW.iter().find(|raw| code.contains(*raw)) {
                out.push(format!(
                    "{path}:{}: a receipt op built from raw bytes (`{raw}`); mint it with CoreStore::record_op (DES-264 §4.1)",
                    index + 1
                ));
            }
        }
    }
    out
}

pub(crate) fn record_op_source(root: &Path) -> Outcome {
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files)?;
    let mut out = Vec::new();
    for file in files {
        let path = rel(root, &file);
        if test_path(&path) {
            continue;
        }
        let text = std::fs::read_to_string(&file).map_err(|e| format!("{path}: {e}"))?;
        out.extend(findings(&path, &text));
    }
    Ok(out)
}
