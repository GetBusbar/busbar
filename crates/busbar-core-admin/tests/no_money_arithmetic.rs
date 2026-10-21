// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATOR SURFACE NAMES NO MONEY FIGURE OF ITS OWN (THE DESIGN §7, BUSBAR-1.6.0.md
//! l.1001-1003: "The operator surface names no figure of its own: an admin view that shows money
//! reads it through the ledger's read-time view types").
//!
//! Every money figure an admin read serves is the ledger's: a row's spend is the one function's
//! (`cost::price_in_view` through the row pricers), and what the reads build from those figures —
//! a rollup's total, a class's summed cost, a budget's headroom — is the ledger's read-time
//! arithmetic too (`busbar_kernel::cost::sum_spend`, `busbar_kernel::cost::budget_remaining`). So
//! the crate's shipped source does no arithmetic on a money figure: a scan (tests excluded,
//! comments skipped) fails, naming `file:line`, on a line that names a money figure (`spend_micros`,
//! `spend_cents`, `.cost`) beside an arithmetic call or compound assignment.

use std::path::{Path, PathBuf};

const MONEY: &[&str] = &["spend_micros", "spend_cents", ".cost"];
const ARITHMETIC: &[&str] = &[
    ".checked_add(",
    ".checked_sub(",
    ".checked_mul(",
    ".saturating_add(",
    ".saturating_sub(",
    ".saturating_mul(",
    ".wrapping_add(",
    ".wrapping_sub(",
    "+=",
    "-=",
];

/// Whether a shipped-source line does arithmetic on a money figure.
fn offends(line: &str) -> bool {
    let code = line.trim_start();
    if code.starts_with("//") {
        return false;
    }
    MONEY.iter().any(|m| code.contains(m)) && ARITHMETIC.iter().any(|a| code.contains(a))
}

/// Shipped source, as opposed to a fixture or a test.
fn is_shipped_source(path: &Path) -> bool {
    let rel = path.to_string_lossy().replace('\\', "/");
    !rel.contains("/tests/")
        && !rel.ends_with("/tests.rs")
        && !rel.ends_with("_test.rs")
        && !rel.ends_with("_tests.rs")
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the crate's src tree is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            walk(&path, files);
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
}

/// RED while `GET /usage` summed its rollups (`b.spend_micros.checked_add(row_spend)`, the
/// `others` bucket's `saturating_add`s, the class costs' `checked_add`) and `GET /groups/{name}/usage`
/// computed `cap.saturating_sub(usage.spend_cents)` itself.
#[test]
fn the_admin_reads_do_no_arithmetic_on_a_money_figure() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    let shipped: Vec<&PathBuf> = files.iter().filter(|p| is_shipped_source(p)).collect();
    assert!(
        shipped
            .iter()
            .any(|p| p.ends_with("src/v1/service_operations.rs")),
        "the scan never reached the file that serves the usage reads: {shipped:?}"
    );
    let mut offenders = Vec::new();
    for path in shipped {
        let text = std::fs::read_to_string(path).expect("a source file reads");
        for (n, line) in text.lines().enumerate() {
            if offends(line) {
                offenders.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "an admin read computes a money figure of its own (§7): {offenders:#?}"
    );
}

/// The scan sees each shape it forbids and not the counts beside them or prose.
#[test]
fn the_money_scan_sees_what_it_forbids_and_nothing_else() {
    assert!(offends(
        "b.spend_micros = match b.spend_micros.checked_add(row_spend) {"
    ));
    assert!(offends("e.cost = e.cost.saturating_add(u.cost);"));
    assert!(offends(
        ".map(|cap| cap.saturating_sub(usage.spend_cents).max(0)),"
    ));
    assert!(!offends(
        "b.requests = b.requests.saturating_add(r.requests);"
    ));
    assert!(!offends(
        "b.spend_micros = busbar_kernel::cost::sum_spend(b.spend_micros, row_spend)"
    ));
    assert!(!offends(
        "// b.spend_micros.checked_add(row_spend) is the ledger's"
    ));
}
