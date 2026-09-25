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
//!   * `Refusal::new(…)` — the only way a reason becomes a refusal, censused at EVERY site: a reason
//!     written at the site under any path and any line breaks, and a reason carried in an expression,
//!     which is answered by reading where reason values come from;
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

mod common;

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

/// One production file, as the scans below read it: every line that is a `//` comment dropped, and
/// then EVERY whitespace character removed.
///
/// Removed, not collapsed. Collapsing a run of whitespace to one space (what this file used to do)
/// is what BROKE the match it claimed to fix: rustfmt breaks `Refusal::new(ReasonCode::X)` into
/// `Refusal::new(` / `ReasonCode::X,` / `)` on three lines once the line is long, the collapse left
/// `Refusal::new( ReasonCode::X, )`, and a marker spelled with no space after the paren could not
/// cross the one the collapse put there — so every broken construction was invisible (item 263).
/// With every whitespace character gone, the one-line and the rustfmt-broken spelling are the same
/// string. Comment lines are dropped first so a doc comment that QUOTES a construction is not
/// counted as one.
fn squeezed(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// What a construction site puts in the reason position.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Reason {
    /// A `ReasonCode::<Name>` written at the site, under any path prefix
    /// (`busbar_contract::caps::ReasonCode::NoDestination` is `NoDestination`).
    Named(String),
    /// An expression the reason is carried in — a variable, a field, a call. Its value is decided
    /// elsewhere, which is why [`every_value_a_computed_refusal_could_carry_excludes_the_ceiling_and_the_stale_slice`]
    /// exists.
    Computed(String),
}

/// `ReasonCode::<Name>` under any path prefix, and nothing after it.
fn named_reason(expr: &str) -> Option<String> {
    let at = expr.rfind("ReasonCode::")?;
    let prefix = &expr[..at];
    let path_ok = prefix.is_empty()
        || (prefix.ends_with("::")
            && prefix
                .split("::")
                .filter(|seg| !seg.is_empty())
                .all(|seg| seg.chars().all(|c| c.is_alphanumeric() || c == '_')));
    let name = &expr[at + "ReasonCode::".len()..];
    (path_ok && !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .then(|| name.to_string())
}

/// The text between `open` (just past an opening delimiter) and its matching close, split at the
/// top-level commas. `None` when the delimiters never balance.
fn top_level_args(text: &str, open: usize) -> Option<(Vec<&str>, usize)> {
    let bytes = text.as_bytes();
    let (mut depth, mut from, mut args) = (1usize, open, Vec::new());
    let mut at = open;
    while at < bytes.len() {
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    if at > from {
                        args.push(&text[from..at]);
                    }
                    return Some((args, at + 1));
                }
            }
            b',' if depth == 1 => {
                args.push(&text[from..at]);
                from = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    None
}

/// Every `Refusal::new(…)` in one squeezed file, with what its reason position holds.
///
/// The census is EVERY occurrence of the constructor, not the ones a marker happens to match: a
/// site whose reason is written as a `ReasonCode` is [`Reason::Named`] whatever path prefix it wears
/// and however rustfmt broke it, and a site whose reason is carried in an expression is
/// [`Reason::Computed`] rather than invisible. The admin crate's two-argument spelling
/// (`Refusal::new(RefusalStep::X, ReasonCode::Y)`) reads its reason from the argument after the step.
fn refusal_sites_in(squeezed: &str) -> Vec<Reason> {
    const OPEN: &str = "Refusal::new(";
    let mut out = Vec::new();
    let mut rest = 0;
    while let Some(found) = squeezed[rest..].find(OPEN) {
        let open = rest + found + OPEN.len();
        let (args, end) = top_level_args(squeezed, open)
            .unwrap_or_else(|| panic!("an unbalanced `Refusal::new(` at byte {open}"));
        let reason = args
            .iter()
            .find(|a| !a.starts_with("RefusalStep::"))
            .copied()
            .unwrap_or("");
        out.push(match named_reason(reason) {
            Some(name) => Reason::Named(name),
            None => Reason::Computed(reason.to_string()),
        });
        rest = end;
    }
    out
}

/// Every `Abort::Kernel { reason: … }` CONSTRUCTION in one squeezed file. A read of the variant
/// binds the name (`Abort::Kernel { reason } =>`) and has no `:` after it, so it is not a site.
fn abort_sites_in(squeezed: &str) -> Vec<Reason> {
    const OPEN: &str = "Abort::Kernel{";
    let mut out = Vec::new();
    let mut rest = 0;
    while let Some(found) = squeezed[rest..].find(OPEN) {
        let open = rest + found + OPEN.len();
        let (fields, end) = top_level_args(squeezed, open)
            .unwrap_or_else(|| panic!("an unbalanced `Abort::Kernel {{` at byte {open}"));
        for field in fields {
            if let Some(expr) = field.strip_prefix("reason:") {
                out.push(match named_reason(expr) {
                    Some(name) => Reason::Named(name),
                    None => Reason::Computed(expr.to_string()),
                });
            }
        }
        rest = end;
    }
    out
}

/// The production tree, squeezed, with each file's path relative to `crates/`.
fn squeezed_sources() -> Vec<(String, String)> {
    production_sources()
        .into_iter()
        .map(|(path, text)| {
            let file = path
                .strip_prefix(crates_root())
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            (file, squeezed(&text))
        })
        .collect()
}

/// Every site `sites_in` finds across the production tree, with the file it is in.
fn census(sites_in: fn(&str) -> Vec<Reason>) -> Vec<(String, Reason)> {
    squeezed_sources()
        .into_iter()
        .flat_map(|(file, text)| {
            sites_in(&text)
                .into_iter()
                .map(move |reason| (file.clone(), reason))
        })
        .collect()
}

/// The named reasons in a census.
fn named(sites: &[(String, Reason)]) -> BTreeSet<&str> {
    sites
        .iter()
        .filter_map(|(_, r)| match r {
            Reason::Named(n) => Some(n.as_str()),
            Reason::Computed(_) => None,
        })
        .collect()
}

/// The kernel's abort vocabulary is `ClientGone` and `Drain`, and no money reason is in it.
///
/// These are the two ends a kernel raises on its own initiative: the client went away, and the node
/// is draining. Neither is about money. The day a third is added, this names it — and an abort whose
/// reason is carried in a variable is refused outright, because its vocabulary is not on the page.
#[test]
fn no_abort_the_shipped_kernel_can_raise_carries_a_money_reason() {
    let built = census(abort_sites_in);
    let computed: Vec<&(String, Reason)> = built
        .iter()
        .filter(|(_, r)| matches!(r, Reason::Computed(_)))
        .collect();
    assert!(
        computed.is_empty(),
        "an abort whose reason is not written at the site cannot be answered by reading: {computed:?}"
    );
    let reasons = named(&built);

    assert_eq!(
        reasons,
        BTreeSet::from(["ClientGone", "Drain"]),
        "the shipped abort vocabulary; sites: {built:?}"
    );
    for money in MONEY_REASONS {
        assert!(
            !reasons.contains(money),
            "a shipped abort is constructed with the money reason {money}: {:?}",
            built
                .iter()
                .filter(|(_, r)| *r == Reason::Named(money.to_string()))
                .collect::<Vec<_>>()
        );
    }
}

/// THE CENSUS FLOOR, armed at today's measured number: seventy-seven `Refusal::new(` constructions
/// in production source. The scan this file used to run matched fifty-seven of them (item 258); a floor
/// under the census is what stops a scanner regression from quietly shrinking the population every
/// "nothing refuses with" claim below is asserted over.
///
/// The floor sits AT the population, with no headroom: one lost site is red. It was armed at one
/// hundred, the population grew to one hundred and one, and the strike under the owner ruling of
/// 2026-09-08 deleted `posture::check_approve` and
/// `posture::check_set_dual_control_required` — the removed `approve` / `set_dual_control` verbs'
/// own checks, zero production callers — taking their three `RefusalStep::Approve` sites
/// (`SelfApproval`, `PayloadMismatch`, `InsufficientApprovers`) with them. None is a money reason and
/// none was served. The population was ninety-eight since. K2c (DEAD-UNITS) then deleted
/// `root/units_mcp.rs` — the pre-unification mcp unit bindings no chain from `fn main()` reaches; the
/// plane is served through the kernel-loop rider and meters inside its own `drive` — taking its four
/// sites with it: two `HandoffMismatch` (arrival), one `DecodeFailed` and the one carried `*reason`
/// (decode; pinned below until then). None is a money reason and none was served. The population was
/// ninety-four. K2c then deleted `root/units_a2a.rs` — the pre-unification a2a unit bindings, built
/// only at their own constructor and in their tests; the plane is served through the same rider and
/// ledgers its payload bytes inside its own `drive` — taking its seventeen sites with it: six
/// `NoDestination`, three `DecodeFailed`, three `ScopeDenied`, one each of `OverBudget`,
/// `DurabilityUnavailable`, `Revoked` and `MeterDisputed`, and the one carried
/// `refusal.kind.reason()` (pinned below until then). The `OverBudget` was a door refusal on a unit
/// no request reached; the served admission refuses over-budget itself. The population is
/// seventy-seven since; the floor is re-armed there. A population that falls because code was DELETED
/// re-arms this floor in the same commit as the deletion, naming the sites; a population that falls
/// with no deletion is the scanner regression this floor exists to catch.
const MIN_REFUSAL_SITES: usize = 77;

/// THE SITES WHOSE REASON IS CARRIED, NOT WRITTEN — pinned, file by file, at today's measurement.
///
/// A refusal whose reason is an expression cannot be answered by reading the site; it is answered
/// by [`every_value_a_computed_refusal_could_carry_excludes_the_ceiling_and_the_stale_slice`], which
/// reads where reason VALUES come from instead. The pin is what makes a new carried site a reviewed
/// event rather than an invisible one: it goes red here until somebody has looked at it.
fn computed_refusal_sites() -> Vec<(String, String)> {
    common::fixture_lines("computed_refusal_sites.txt")
        .into_iter()
        .map(|l| {
            let (file, expr) = l.split_once('\t').unwrap_or_else(|| {
                panic!("computed_refusal_sites.txt: `{l}` is not <file>TAB<expr>")
            });
            (file.trim().to_string(), expr.trim().to_string())
        })
        .collect()
}

/// `OverdraftCeiling` and `StaleSlice` are refusal reasons nothing in the tree ever refuses with.
///
/// The scan is on the one construction that turns a reason into a refusal, and it is a CENSUS: every
/// `Refusal::new(` in production source is a site, named or carried, and the two add up to the whole.
/// `OverBudget` IS in the named answer — that is the non-vacuity, and it is also the binding's
/// positive half: over-budget is a refusal, taken at a door, and never an end for a unit that is
/// already running.
#[test]
fn overdraft_ceiling_and_stale_slice_are_refusal_reasons_nothing_refuses_with() {
    let refusals = census(refusal_sites_in);
    let every_constructor: usize = squeezed_sources()
        .iter()
        .map(|(_, text)| text.matches("Refusal::new(").count())
        .sum();
    assert_eq!(
        refusals.len(),
        every_constructor,
        "the census must classify every `Refusal::new(` in production source, named or carried"
    );
    assert!(
        refusals.len() >= MIN_REFUSAL_SITES,
        "the census found {} refusal constructions (floor {MIN_REFUSAL_SITES}); a scan that lost \
         sites answers 'nothing refuses with' over a partial population",
        refusals.len()
    );

    let mut computed: Vec<(&str, &str)> = refusals
        .iter()
        .filter_map(|(file, r)| match r {
            Reason::Computed(expr) => Some((file.as_str(), expr.as_str())),
            Reason::Named(_) => None,
        })
        .collect();
    computed.sort_unstable();
    let pinned_owned = computed_refusal_sites();
    let mut pinned: Vec<(&str, &str)> = pinned_owned
        .iter()
        .map(|(f, e)| (f.as_str(), e.as_str()))
        .collect();
    pinned.sort_unstable();
    assert_eq!(
        computed, pinned,
        "the refusal sites whose reason is carried in an expression moved; a new one is a site this \
         file cannot answer by reading, so it is reviewed and pinned rather than passed"
    );

    let reasons = named(&refusals);
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
                .filter(|(_, r)| *r == Reason::Named(never.to_string()))
                .collect::<Vec<_>>()
        );
    }
}

/// The carried half of the claim: a refusal whose reason is an expression can only carry a
/// `OverdraftCeiling` or a `StaleSlice` if something in production PRODUCES one as a value.
///
/// So this reads every mention of the two variants (under any enum and any path) and separates the
/// ones in a PATTERN — an arm or an alternation, which reads a reason and makes none — from the ones
/// in value position. There is exactly one value today: `SliceError::reason` answers
/// `ReasonCode::StaleSlice` for a stale epoch. That function is reached only through a `SliceError`,
/// which only a `SliceStore` hands out, and the only production file that touches either outside
/// the defining module is the store adapter that IMPLEMENTS the trait and never asks an error its
/// reason. The one other place a reason value is read back out of nothing — the cancel token's
/// `ReasonCode::ALL.get(index)` — decodes an index its own `trip` stored from a reason it was handed,
/// so it can return no reason that was not already a value.
#[test]
fn every_value_a_computed_refusal_could_carry_excludes_the_ceiling_and_the_stale_slice() {
    let sources = squeezed_sources();
    let mut values: BTreeSet<(String, String)> = BTreeSet::new();
    for (file, text) in &sources {
        for name in ["OverdraftCeiling", "StaleSlice"] {
            let needle = format!("::{name}");
            let mut rest = 0;
            while let Some(found) = text[rest..].find(&needle) {
                let at = rest + found;
                let end = at + needle.len();
                rest = end;
                let after = &text[end..];
                if after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    continue; // a longer name, e.g. `SetOverdraftCeiling`'s neighbours
                }
                let path_start = text[..at]
                    .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                    .map_or(0, |i| i + 1);
                let before = &text[..path_start];
                let in_pattern =
                    before.ends_with('|') || after.starts_with('|') || after.starts_with("=>");
                if !in_pattern {
                    values.insert((file.clone(), text[path_start..end].to_string()));
                }
            }
        }
    }
    assert_eq!(
        values,
        BTreeSet::from([(
            "busbar-contract/src/slice.rs".to_string(),
            "ReasonCode::StaleSlice".to_string()
        )]),
        "a production value of the ceiling or stale-slice reason appeared; a carried refusal could \
         now be one of them"
    );

    let slice_reach: BTreeSet<&str> = sources
        .iter()
        .filter(|(_, text)| {
            text.contains("SliceError")
                || text.contains("SliceStore")
                || text.contains("slice_store(")
        })
        .map(|(file, _)| file.as_str())
        .collect();
    assert_eq!(
        slice_reach,
        BTreeSet::from([
            "busbar-contract/src/slice.rs",
            "plugin-loader/src/store_adapter.rs"
        ]),
        "something outside the slice module and its one implementor now reaches a SliceError, \
         and SliceError::reason is the tree's one StaleSlice value"
    );
    for (file, text) in &sources {
        if slice_reach.contains(file.as_str()) {
            assert!(
                !text.contains(".reason()") && !text.contains("Refusal::new("),
                "{file} reaches a SliceError and also asks a reason or builds a refusal"
            );
        }
    }

    let decoders: BTreeSet<&str> = sources
        .iter()
        .filter(|(_, text)| text.contains("ReasonCode::ALL"))
        .map(|(file, _)| file.as_str())
        .collect();
    assert_eq!(
        decoders,
        BTreeSet::from(["busbar-kernel/src/inflight.rs"]),
        "a new reader of the whole reason vocabulary can hand out any reason, the two included"
    );
}

/// THE SCANNER, ON THE SPELLINGS IT USED TO MISS. rustfmt breaks a long construction across lines
/// and some sites spell the enum by its full path; both are the same construction as the one-line
/// spelling and must read as one. The one-line spelling is here too, as the control.
#[test]
fn the_census_reads_a_broken_or_path_qualified_construction_as_the_same_site() {
    for spelling in [
        "Refusal::new(ReasonCode::OverdraftCeiling)",
        "Refusal::new(\n    ReasonCode::OverdraftCeiling,\n)",
        "Refusal::new(\n    busbar_contract::caps::ReasonCode::OverdraftCeiling,\n)",
        "Refusal::new(RefusalStep::Admit, ReasonCode::OverdraftCeiling)",
        "Refusal::new(\n    RefusalStep::Admit,\n    ReasonCode::OverdraftCeiling,\n)",
    ] {
        assert_eq!(
            refusal_sites_in(&squeezed(spelling)),
            vec![Reason::Named("OverdraftCeiling".to_string())],
            "{spelling:?}"
        );
    }
    assert_eq!(
        refusal_sites_in(&squeezed("Refusal::new(refusal.reason())")),
        vec![Reason::Computed("refusal.reason()".to_string())],
        "a carried reason is a site, not an absence"
    );
    assert_eq!(
        refusal_sites_in(&squeezed("// Refusal::new(ReasonCode::StaleSlice)\n")),
        Vec::<Reason>::new(),
        "a comment that quotes a construction is not one"
    );
    assert_eq!(
        abort_sites_in(&squeezed(
            "Abort::Kernel {\n    reason: busbar_contract::caps::ReasonCode::Drain,\n}\nAbort::Kernel { reason } => reason,"
        )),
        vec![Reason::Named("Drain".to_string())],
        "a construction is a site under any prefix and a read of the variant is not"
    );
}

/// The ceiling verdict is named in one file: the module that defines the rule.
///
/// `Overdraft::Ceiling` is what `slice::overdraft(_, at_ceiling)` answers when a bucket is at its
/// ceiling. Nothing outside the rule's own module names that verdict, so no shipped path branches
/// on it and no shipped path can end a unit by it: the ceiling is unbounded in force, and the
/// operator verb that would set one (`KernelVerb::SetOverdraftCeiling`) is carried in the
/// vocabulary with no dispatch arm behind it — flag-only, exactly as the binding says.
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
        // The rule's own module is `busbar-contract/src/slice.rs` since b544c8bbf moved the slice
        // ABI types out of the kernel (#38, to break the core-absorption cycle). The PROPERTY is
        // unchanged and is what this pin is about: exactly ONE file — the module that defines
        // `overdraft()` — names the verdict it returns.
        BTreeSet::from(["busbar-contract/src/slice.rs".to_string()]),
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
