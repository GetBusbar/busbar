// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MONEY REFUSES AT THE DOOR, AND ENDS NOTHING THAT IS ALREADY RUNNING.
//!
//! The design binding this file exists for says that on a 1.5.5-shaped deployment an ADMITTED
//! `http`/`sse` unit is never ended for money: there is no `Aborted(Kernel { OverBudget })` and no
//! `Aborted(Kernel { OverdraftCeiling })`, the overdraft ceiling is unbounded, and
//! `OverdraftCeiling` and `StaleSlice` are never refusal reasons. Value has already been delivered
//! by the time a mid-unit shortfall is visible, so the unit runs to its end and the excess is
//! POSTED as an overdraft — the shortfall reduces the next window instead of cutting this one.
//!
//! Every clause is a claim that a SHAPE DOES NOT OCCUR. Behavioural tests cannot settle that: they
//! show the shapes that DO occur on the paths they walk, and a money abort added tomorrow on a path
//! nobody drove would go on not occurring in exactly the same way. What settles it is the shipped
//! VOCABULARY — the set of reasons the tree is capable of constructing in each position. So the
//! scans below read the production source and answer, per position, which reasons are built there:
//!
//!   * `Abort::Kernel { reason: … }` — the only abort a kernel can raise;
//!   * `Refusal::new(ReasonCode::…)` — the only way a reason becomes a refusal;
//!   * `Overdraft::Ceiling` — the verdict the ceiling clause is about.
//!
//! Each scan is answered against the whole of `crates/`, excluding tests, and each carries its own
//! non-vacuity assertion: a scan that found nothing would otherwise pass every "is not in the set"
//! question ever asked of it.
//!
//! The behavioural half of the binding is proven where the behaviour is:
//! `busbar-llm/src/unit/admit.rs::over_budget_refuses_with_no_charge_and_nothing_to_refund` (an
//! over-budget request is a `Decision::refuse` at `StepName::Admit`, charging nothing) and
//! `busbar-llm/src/unit/meter.rs::a_spend_past_the_reservation_is_carried_out_as_an_overdraft` (a
//! unit that overspends after admission carries the excess out rather than ending).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The reasons the design calls MONEY reasons — the ones this binding says never end a unit.
const MONEY_REASONS: &[&str] = &[
    "OverBudget",
    "OverdraftCeiling",
    "StaleSlice",
    "GroupFrozen",
    "Unpriced",
];

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("crates/ must exist")
}

/// Every production `.rs` under `crates/`: no `tests/` directory, no `tests.rs`, no `*_test(s).rs`.
/// The same scope discipline the house source-scanning oracles use.
fn production_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if path.is_dir() {
            if name == "tests" || name == "target" {
                continue;
            }
            production_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && name != "tests.rs"
            && !name.ends_with("_test.rs")
            && !name.ends_with("_tests.rs")
        {
            out.push(path);
        }
    }
}

fn production_sources() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    production_rs(&crates_root(), &mut files);
    assert!(
        files.len() > 300,
        "the scan must reach the whole tree; it found {} files",
        files.len()
    );
    files
        .into_iter()
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|s| (p, s)))
        .collect()
}

/// Every `ReasonCode::<Name>` that follows `marker` in production source, with the file it is in.
///
/// `marker` is the opening of the position being asked about, so the answer is the set of reasons
/// the tree can put IN that position. A `match` arm that merely READS a reason binds a name
/// (`Abort::Kernel { reason } =>`) and never writes `reason: ReasonCode::…`, so a rendering or
/// classification site is not mistaken for a construction.
fn reasons_after(marker: &str) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for (path, text) in production_sources() {
        let file = path
            .strip_prefix(crates_root())
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        // Whitespace-normalised, so a construction rustfmt broke across four lines reads the same
        // as one written on a single line.
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut rest = text.as_str();
        while let Some(at) = rest.find(marker) {
            rest = &rest[at + marker.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                found.insert((file.clone(), name));
            }
        }
    }
    found
}

/// The kernel's abort vocabulary is `ClientGone` and `Drain`, and no money reason is in it.
///
/// These are the two ends a kernel raises on its own initiative: the client went away, and the node
/// is draining. Neither is about money. The day a third is added, this names it.
#[test]
fn no_abort_the_shipped_kernel_can_raise_carries_a_money_reason() {
    let built = reasons_after("Abort::Kernel { reason: ReasonCode::");
    let reasons: BTreeSet<&str> = built.iter().map(|(_, r)| r.as_str()).collect();

    assert_eq!(
        reasons,
        BTreeSet::from(["ClientGone", "Drain"]),
        "the shipped abort vocabulary; sites: {built:?}"
    );
    for money in MONEY_REASONS {
        assert!(
            !reasons.contains(money),
            "a shipped abort is constructed with the money reason {money}: {:?}",
            built.iter().filter(|(_, r)| r == money).collect::<Vec<_>>()
        );
    }
}

/// `OverdraftCeiling` and `StaleSlice` are refusal reasons nothing in the tree ever refuses with.
///
/// The scan is on the one construction that turns a reason into a refusal. `OverBudget` IS in the
/// answer — that is the non-vacuity, and it is also the binding's positive half: over-budget is a
/// refusal, taken at a door, and never an end for a unit that is already running.
#[test]
fn overdraft_ceiling_and_stale_slice_are_refusal_reasons_nothing_refuses_with() {
    let refusals = reasons_after("Refusal::new(ReasonCode::");
    let reasons: BTreeSet<&str> = refusals.iter().map(|(_, r)| r.as_str()).collect();

    assert!(
        reasons.contains("OverBudget"),
        "non-vacuity: over-budget IS a refusal in the shipped tree, and the scan must see it"
    );
    for never in ["OverdraftCeiling", "StaleSlice"] {
        assert!(
            !reasons.contains(never),
            "{never} is constructed as a refusal at {:?}",
            refusals
                .iter()
                .filter(|(_, r)| r == never)
                .collect::<Vec<_>>()
        );
    }
}

/// The ceiling verdict is named in one file: the module that defines the rule.
///
/// `Overdraft::Ceiling` is what `slice::overdraft(_, at_ceiling)` answers when a bucket is at its
/// ceiling. Nothing outside the rule's own module names that verdict, so no shipped path branches
/// on it and no shipped path can end a unit by it: the ceiling is unbounded in force, and the
/// operator verb that would once have set one (`KernelVerb::SetOverdraftCeiling`) is not in the
/// vocabulary at all — 1.6.0's money model deleted it with the other four correction verbs, so the
/// "flag-only" scan below now answers "no such name anywhere", which is the same claim proven
/// harder. The scan stays: it is what catches the verb, or a payload for it, coming back.
#[test]
fn the_overdraft_ceiling_is_a_verdict_no_shipped_path_branches_on() {
    let mut namers = BTreeSet::new();
    for (path, text) in production_sources() {
        if text.contains("Overdraft::Ceiling") {
            namers.insert(
                path.strip_prefix(crates_root())
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    assert_eq!(
        namers,
        BTreeSet::from(["busbar-kernel/src/slice.rs".to_string()]),
        "only the rule's own module may name the ceiling verdict"
    );

    // And the verb that would arm one carries no value anywhere in the tree.
    let mut with_a_value = Vec::new();
    for (path, text) in production_sources() {
        for line in text.lines() {
            if line.contains("SetOverdraftCeiling") && line.contains('(') {
                with_a_value.push(format!("{}: {}", path.display(), line.trim()));
            }
        }
    }
    assert!(
        with_a_value.is_empty(),
        "SetOverdraftCeiling is flag-only; something gave it a payload: {with_a_value:?}"
    );
}
