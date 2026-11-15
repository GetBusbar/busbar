// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A8 and A7, THE FROZEN ESCAPE HATCHES (CORE-ARCHITECTURE-DIET §3.1 and §5, W0.2).
//!
//! A8: production `unsafe` lives only at the interim sites in `arch/escapes.json`, each naming
//! the MR that deletes or moves it, plus the two whole-crate entries that W4.3 deletes. Every
//! other crate root carries `deny` or `forbid(unsafe_code)`, and every module that carries
//! `#![forbid(unsafe_code)]` today keeps it. A7 (with core-diet): an `allow`/`expect` of
//! `dead_code` or an `unused*` lint in production code never grows past today's per-file count.
//! The lists only shrink: against the merge base no entry may be added or raised, except under an
//! `admitted` owner ruling, which is valid for the one merge that carries the change.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::scan::{self, Parsed};

const ESCAPES: &str = "crates/busbar-kernel/tests/arch/escapes.json";

#[derive(Deserialize)]
struct Escapes {
    version: u32,
    unsafe_code: UnsafeCode,
    /// File → `allow`/`expect` attributes naming `dead_code` or `unused*`.
    dead_code: BTreeMap<String, usize>,
    /// File → the owner ruling that admits its site or forbid-list removal for one merge. An
    /// admission is valid only while the merge base lacks the change; once the change is in the
    /// base the entry must go, so an admission never outlives the merge that carries it.
    #[serde(default)]
    admitted: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct UnsafeCode {
    /// Crate → the MR that deletes it.
    whole_crates: BTreeMap<String, String>,
    sites: BTreeMap<String, Site>,
    forbid: BTreeSet<String>,
}

#[derive(Deserialize)]
struct Site {
    keywords: usize,
    allows: usize,
    /// The MR that deletes or moves the site.
    by: String,
}

struct Measured {
    keywords: usize,
    allows: usize,
    dead_code: usize,
    forbid: bool,
}

#[test]
fn unsafe_and_dead_code_escapes_stay_at_their_frozen_sites() {
    let mut workspace = scan::load();
    let root = workspace.root.clone();
    let text = std::fs::read_to_string(root.join(ESCAPES)).expect(ESCAPES);
    let escapes: Escapes = sonic_rs::from_str(&text).expect(ESCAPES);
    assert_eq!(escapes.version, 1, "{ESCAPES}: unknown version");
    workspace.walk(&BTreeSet::new());

    let mut measured: BTreeMap<String, Measured> = BTreeMap::new();
    let mut whole: BTreeSet<String> = BTreeSet::new();
    for (path, reached) in workspace
        .files
        .iter()
        .filter(|(_, reached)| reached.production)
    {
        let package = &workspace.packages[reached.package].name;
        let relative = workspace.relative(path);
        if escapes.unsafe_code.whole_crates.contains_key(package) {
            whole.insert(relative.clone());
        }
        let source = std::fs::read_to_string(path).expect("read reached file");
        let file = Parsed::new(&source);
        measured.insert(
            relative,
            Measured {
                keywords: file.unsafe_keywords(),
                allows: file.unsafe_allows(),
                dead_code: file.dead_code_allows(),
                forbid: file.inner_lint("forbid"),
            },
        );
    }

    let mut failures = Vec::new();
    for (name, by) in &escapes.unsafe_code.whole_crates {
        if !workspace
            .packages
            .iter()
            .any(|package| &package.name == name)
        {
            failures.push(format!(
                "whole-crate entry {name} (deleted by {by}) names no member; remove it"
            ));
        }
    }

    // A8: every production `unsafe` keyword and `allow(unsafe_code)` is at a listed site.
    for (file, counts) in &measured {
        if whole.contains(file) || (counts.keywords == 0 && counts.allows == 0) {
            continue;
        }
        match escapes.unsafe_code.sites.get(file) {
            None => failures.push(format!(
                "unsafe: {file} has {} `unsafe` and {} `allow(unsafe_code)` in production code; \
                 production unsafe lives only at the frozen sites (plugins::bind, edge::sys, \
                 boot::mallctl and the interim entries)",
                counts.keywords, counts.allows
            )),
            Some(site) if counts.keywords > site.keywords || counts.allows > site.allows => {
                failures.push(format!(
                    "unsafe: {file} grew to {} `unsafe` and {} `allow(unsafe_code)` (frozen at \
                     {} and {} until {})",
                    counts.keywords, counts.allows, site.keywords, site.allows, site.by
                ))
            }
            Some(_) => {}
        }
    }
    for file in escapes.unsafe_code.sites.keys() {
        if !measured.contains_key(file) {
            failures.push(format!(
                "unsafe: the site {file} is no longer production code; remove its entry"
            ));
        }
    }

    // A8: modules that forbid unsafe keep forbidding it.
    for file in &escapes.unsafe_code.forbid {
        if !measured.get(file).is_some_and(|counts| counts.forbid) {
            failures.push(format!(
                "forbid: {file} must keep `#![forbid(unsafe_code)]` (if the file moved, move \
                 the entry with it)"
            ));
        }
    }
    let listed: BTreeSet<&String> = escapes.unsafe_code.forbid.iter().collect();
    for (file, counts) in &measured {
        if counts.forbid && !listed.contains(file) {
            failures.push(format!(
                "forbid: {file} forbids unsafe code; add it to the frozen forbid list"
            ));
        }
    }

    // A8: every production crate root denies unsafe code, outside the whole-crate entries.
    for package in &workspace.packages {
        if escapes.unsafe_code.whole_crates.contains_key(&package.name) {
            continue;
        }
        for target in package.production_roots() {
            let source = std::fs::read_to_string(target).expect("read crate root");
            let file = Parsed::new(&source);
            if !file.inner_lint("deny") && !file.inner_lint("forbid") {
                failures.push(format!(
                    "unsafe: the crate root {} carries neither `#![deny(unsafe_code)]` nor \
                     `#![forbid(unsafe_code)]`",
                    workspace.relative(target)
                ));
            }
        }
    }

    // A7: dead-code escapes never grow.
    for (file, counts) in &measured {
        let frozen = escapes.dead_code.get(file).copied().unwrap_or(0);
        if counts.dead_code > frozen {
            failures.push(format!(
                "dead code: {file} has {} `allow`/`expect` of dead_code or unused* in production \
                 code (frozen at {frozen}); delete the dead item instead (203)",
                counts.dead_code
            ));
        }
    }

    // The lists only shrink.
    match super::base_revision(&root) {
        None => failures.push("no base revision: the frozen lists need Git history".to_string()),
        Some(base) => {
            if let Some(text) = super::file_at(&root, &base, ESCAPES) {
                let before: Escapes = sonic_rs::from_str(&text).expect("base escapes");
                shrink_only(&escapes, &before, &measured, &mut failures);
                admissions_expire(&escapes, &before, &mut failures);
            }
        }
    }

    if !failures.is_empty() {
        let mut report = String::from("measured production escapes (keywords, allows, dead):\n");
        for (file, counts) in &measured {
            if counts.keywords + counts.allows + counts.dead_code > 0 || counts.forbid {
                report.push_str(&format!(
                    "  {file}: {} {} {}{}\n",
                    counts.keywords,
                    counts.allows,
                    counts.dead_code,
                    if counts.forbid { " forbid" } else { "" }
                ));
            }
        }
        panic!("{report}\n{}", failures.join("\n"));
    }
}

fn shrink_only(
    now: &Escapes,
    before: &Escapes,
    measured: &BTreeMap<String, Measured>,
    failures: &mut Vec<String>,
) {
    for name in now.unsafe_code.whole_crates.keys() {
        if !before.unsafe_code.whole_crates.contains_key(name) {
            failures.push(format!("unsafe: whole-crate entry {name} was added"));
        }
    }
    for (file, site) in &now.unsafe_code.sites {
        let raised = before
            .unsafe_code
            .sites
            .get(file)
            .is_none_or(|old| site.keywords > old.keywords || site.allows > old.allows);
        if raised && admitted(now, file, failures) {
            continue;
        }
        if raised {
            failures.push(format!(
                "unsafe: the site {file} was added or raised; entries can only be removed"
            ));
        }
    }
    for file in &before.unsafe_code.forbid {
        if !now.unsafe_code.forbid.contains(file)
            && measured.contains_key(file)
            && !admitted(now, file, failures)
        {
            failures.push(format!(
                "forbid: {file} left the forbid list; a forbid is never lifted"
            ));
        }
    }
    for (file, count) in &now.dead_code {
        if *count > before.dead_code.get(file).copied().unwrap_or(0) {
            failures.push(format!(
                "dead code: the frozen count for {file} rose; it can only fall"
            ));
        }
    }
}

/// Whether `file` carries an owner admission; an empty ruling is itself a failure.
fn admitted(now: &Escapes, file: &str, failures: &mut Vec<String>) -> bool {
    match now.admitted.get(file) {
        None => false,
        Some(ruling) if ruling.trim().is_empty() => {
            failures.push(format!("admitted: {file} names no owner ruling"));
            false
        }
        Some(_) => true,
    }
}

/// Every admission must still be needed: the base lacks the site, a raise, or the forbid entry.
fn admissions_expire(now: &Escapes, before: &Escapes, failures: &mut Vec<String>) {
    for file in now.admitted.keys() {
        let site_added = now.unsafe_code.sites.get(file).is_some_and(|site| {
            before
                .unsafe_code
                .sites
                .get(file)
                .is_none_or(|old| site.keywords > old.keywords || site.allows > old.allows)
        });
        let forbid_lifted =
            before.unsafe_code.forbid.contains(file) && !now.unsafe_code.forbid.contains(file);
        if !site_added && !forbid_lifted {
            failures.push(format!(
                "admitted: {file} is already in the merge base; remove its admission"
            ));
        }
    }
}
