// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARCHITECTURE CHECKS (CORE-ARCHITECTURE-DIET). This file holds A5, THE LOC BUDGET (§7;
//! owner decision 200); `arch/escapes.rs` holds A8 and A7.
//!
//! Core's production lines, counted one way only (`diet-metrics-v2`: Cargo targets, `mod`,
//! `#[path]` and `include!` followed, code only `cfg(test)` or the dev-only `test-support` feature
//! compiles and doc attributes excluded, comments and
//! blank lines never counted), must stay within `arch/loc-budget.json`, and the budgets only
//! ratchet down. The fixed rules live in `arch/loc-bar.json` (owner approval to change); the
//! dependency-set guard (§5) lives in `arch/layering.json`. Every failure message names the
//! number to use. The check parses sources only; it never builds core.

mod arch;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use arch::scan;
use serde::Deserialize;

const BAR: &str = "crates/busbar-kernel/tests/arch/loc-bar.json";
const BUDGET: &str = "crates/busbar-kernel/tests/arch/loc-budget.json";
const LAYERING: &str = "crates/busbar-kernel/tests/arch/layering.json";

#[derive(Deserialize)]
struct Bar {
    version: u32,
    counting: String,
    bar: u64,
    locked: bool,
    slack_pct: u64,
    slack_min: u64,
    #[serde(default)]
    test_only: Vec<String>,
    #[serde(default)]
    decisions: Vec<String>,
    #[serde(default)]
    bridges: Vec<Bridge>,
}

#[derive(Deserialize)]
struct Bridge {
    id: String,
    decision: String,
    crates: Vec<String>,
    max: u64,
    /// The sum of all crate budgets at the merge base of the MR that opened the bridge.
    base_sum: u64,
    repays: Vec<String>,
}

#[derive(Deserialize)]
struct Budgets {
    version: u32,
    /// `crate` or `crate::module::path` → its budget.
    budgets: BTreeMap<String, Entry>,
    #[serde(default)]
    generated: Vec<String>,
}

#[derive(Deserialize)]
struct Entry {
    budget: u64,
    #[serde(default)]
    from: Vec<String>,
    #[serde(default)]
    raised_by: Option<String>,
    #[serde(default)]
    bridge: Option<String>,
}

#[derive(Deserialize)]
struct Layering {
    version: u32,
    lib: String,
    lib_workspace_deps: Vec<String>,
    #[serde(default)]
    allowed_additions: Vec<String>,
}

fn parse<T: for<'de> Deserialize<'de>>(name: &str, text: &str) -> T {
    sonic_rs::from_str(text).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn read(root: &Path, name: &str) -> String {
    std::fs::read_to_string(root.join(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn crate_sum(budgets: &Budgets) -> u64 {
    budgets
        .budgets
        .iter()
        .filter(|(key, _)| !key.contains("::"))
        .map(|(_, entry)| entry.budget)
        .sum()
}

#[test]
fn production_lines_stay_within_their_ratcheting_budgets() {
    let mut workspace = scan::load();
    let root = workspace.root.clone();
    let bar: Bar = parse(BAR, &read(&root, BAR));
    let budgets: Budgets = parse(BUDGET, &read(&root, BUDGET));
    let layering: Layering = parse(LAYERING, &read(&root, LAYERING));
    let mut failures = Vec::new();

    assert_eq!(bar.version, 1, "{BAR}: unknown version");
    assert_eq!(budgets.version, 1, "{BUDGET}: unknown version");
    assert_eq!(layering.version, 1, "{LAYERING}: unknown version");
    if bar.counting != scan::METHOD {
        failures.push(format!(
            "method drift: {BAR} counting is {:?}; this check counts {:?}",
            bar.counting,
            scan::METHOD
        ));
    }

    let test_only: BTreeSet<String> = bar.test_only.iter().cloned().collect();
    workspace.walk(&test_only);
    let (lines, generated) = workspace.count();

    // Measured lines per crate and per budgeted module.
    let mut measured: BTreeMap<String, u64> = BTreeMap::new();
    for package in &workspace.packages {
        if !test_only.contains(&package.name) {
            measured.insert(package.name.clone(), 0);
        }
    }
    let module_keys: Vec<(String, String, Vec<String>)> = budgets
        .budgets
        .keys()
        .filter_map(|key| {
            let mut parts = key.split("::");
            let krate = parts.next()?.to_string();
            let path: Vec<String> = parts.map(str::to_string).collect();
            (!path.is_empty()).then(|| (key.clone(), krate, path))
        })
        .collect();
    for (key, _, _) in &module_keys {
        measured.insert(key.clone(), 0);
    }
    for (path, count) in &lines {
        let reached = &workspace.files[path];
        let name = &workspace.packages[reached.package].name;
        if test_only.contains(name) {
            continue;
        }
        *measured.entry(name.clone()).or_default() += *count as u64;
        for (key, krate, module) in &module_keys {
            if krate == name && reached.module.starts_with(module) {
                *measured.entry(key.clone()).or_default() += *count as u64;
            }
        }
    }

    // Rule 5: every production member has a budget, and every budget names a member.
    for name in measured.keys().filter(|key| !key.contains("::")) {
        if !budgets.budgets.contains_key(name) {
            failures.push(format!(
                "new crate: {name} has no budget; it is born at its measured size {} through a \
                 transfer (`from`), an owner raise or a bridge",
                measured[name]
            ));
        }
    }
    for key in budgets.budgets.keys() {
        let krate = key.split("::").next().unwrap_or(key);
        if !measured.contains_key(krate) {
            failures.push(format!(
                "stale budget: {key} names no production workspace member; delete it (a fold \
                 names it in the receiving entry's `from`)"
            ));
        }
    }

    // Test-only crates are dev-dependencies only.
    for package in &workspace.packages {
        for dependency in &package.dependencies {
            if test_only.contains(&dependency.name) && dependency.kind.as_deref() != Some("dev") {
                failures.push(format!(
                    "{} takes the test-only crate {} as a non-dev dependency",
                    package.name, dependency.name
                ));
            }
        }
    }

    // Rules 1 and 2: within budget, and no more than the slack above it.
    for (key, entry) in &budgets.budgets {
        let Some(&count) = measured.get(key) else {
            continue;
        };
        if count > entry.budget {
            failures.push(format!(
                "over budget: {key} measures {count} production lines against its budget of {}",
                entry.budget
            ));
        }
        if entry.budget * 100 > count * (100 + bar.slack_pct)
            && entry.budget > count + bar.slack_min
        {
            failures.push(format!(
                "slack: {key} measures {count} but its budget is {}; lower the budget to {count} \
                 so freed lines cannot be refilled",
                entry.budget
            ));
        }
    }

    // Rule 6: no unreachable source file.
    for path in workspace.unreachable() {
        failures.push(format!(
            "unreachable file: {} is under src/ but no Cargo target reaches it; delete it",
            workspace.relative(&path)
        ));
    }

    // Rule 7: no generated production code outside the frozen list.
    let sites: BTreeSet<String> = generated
        .iter()
        .map(|site| format!("{}:{}", workspace.relative(&site.file), site.line))
        .collect();
    for site in &sites {
        if !budgets.generated.contains(site) {
            failures.push(format!(
                "generated code: {site} includes a non-literal path in production code; check \
                 the table in as source"
            ));
        }
    }
    for site in &budgets.generated {
        if !sites.contains(site) {
            failures.push(format!(
                "generated list: {site} is no longer a generated include; remove it from {BUDGET}"
            ));
        }
    }

    // The dependency-set guard (§5): the lib's workspace dependencies, written down exactly.
    let lib_deps: BTreeSet<String> = workspace
        .packages
        .iter()
        .find(|package| package.name == layering.lib)
        .map(|lib| {
            lib.dependencies
                .iter()
                .filter(|dependency| dependency.kind.is_none())
                .filter(|dependency| {
                    workspace
                        .packages
                        .iter()
                        .any(|package| package.name == dependency.name)
                })
                .map(|dependency| dependency.name.clone())
                .collect()
        })
        .unwrap_or_default();
    let declared: BTreeSet<String> = layering.lib_workspace_deps.iter().cloned().collect();
    if lib_deps != declared {
        failures.push(format!(
            "{LAYERING}: lib_workspace_deps must be exactly {lib_deps:?}"
        ));
    }

    let open = |bridge: &Bridge| {
        bridge
            .repays
            .iter()
            .any(|crate_name| measured.contains_key(crate_name))
    };
    let sum = crate_sum(&budgets);
    for bridge in &bar.bridges {
        if !bar.decisions.contains(&bridge.decision) {
            failures.push(format!(
                "bridge {} cites {} which is not an owner decision in {BAR}",
                bridge.id, bridge.decision
            ));
        }
        if !open(bridge) && sum > bridge.base_sum {
            failures.push(format!(
                "bridge {} is closed but the budget sum {sum} is above {} from before it opened",
                bridge.id, bridge.base_sum
            ));
        }
    }
    if bar.locked {
        if sum > bar.bar {
            failures.push(format!(
                "locked: the budget sum {sum} is above the bar {}",
                bar.bar
            ));
        }
        if bar.bridges.iter().any(open) {
            failures.push("locked: no bridge may be open".to_string());
        }
    }

    // Rules 3 and 4, and the frozen lists, against the merge base.
    match arch::base_revision(&root) {
        None => failures.push(
            "no base revision: the ratchet needs Git history (set BUSBAR_LOC_BASE)".to_string(),
        ),
        Some(base) => {
            println!("ratchet base: {base}");
            let base_bar: Option<Bar> =
                arch::file_at(&root, &base, BAR).map(|text| parse(BAR, &text));
            let base_budgets: Option<Budgets> =
                arch::file_at(&root, &base, BUDGET).map(|text| parse(BUDGET, &text));
            let base_layering: Option<Layering> =
                arch::file_at(&root, &base, LAYERING).map(|text| parse(LAYERING, &text));
            if let Some(base_bar) = &base_bar {
                if base_bar.bar != bar.bar {
                    failures.push(format!("the bar never changes: it was {}", base_bar.bar));
                }
                if base_bar.locked && !bar.locked {
                    failures.push("locked can never go back to false".to_string());
                }
            }
            if let Some(base_layering) = &base_layering {
                for added in lib_deps
                    .iter()
                    .filter(|name| !base_layering.lib_workspace_deps.contains(*name))
                {
                    if !layering.allowed_additions.contains(added) {
                        failures.push(format!(
                            "dependency-set guard: {} gained the workspace dependency {added}, \
                             which is not in {LAYERING} allowed_additions",
                            layering.lib
                        ));
                    }
                }
            }
            if let Some(base_budgets) = &base_budgets {
                ratchet(&bar, &budgets, base_budgets, &open, &mut failures);
            }
        }
    }

    if !failures.is_empty() {
        let mut report = String::from("measured production lines:\n");
        for (key, count) in &measured {
            report.push_str(&format!("  {key}: {count}\n"));
        }
        report.push_str(&format!(
            "  total: {}\n",
            measured
                .iter()
                .filter(|(key, _)| !key.contains("::"))
                .map(|(_, count)| count)
                .sum::<u64>()
        ));
        report.push_str("generated sites:\n");
        for site in &sites {
            report.push_str(&format!("  {site}\n"));
        }
        panic!("{report}\n{}", failures.join("\n"));
    }
}

/// Rules 3 and 4: a budget rises only by a transfer, an owner raise or an open bridge, and the
/// sum of all budgets never rises except by an owner raise or within an open bridge's cap.
fn ratchet(
    bar: &Bar,
    budgets: &Budgets,
    base: &Budgets,
    open: &dyn Fn(&Bridge) -> bool,
    failures: &mut Vec<String>,
) {
    let before = |key: &str| base.budgets.get(key).map_or(0, |entry| entry.budget);
    let after = |key: &str| budgets.budgets.get(key).map_or(0, |entry| entry.budget);
    let mut owner_raised = 0;
    let mut bridged = Vec::new();
    for (key, entry) in &budgets.budgets {
        let raise = entry.budget.saturating_sub(before(key));
        if raise == 0 {
            continue;
        }
        let krate = key.split("::").next().unwrap_or(key);
        let freed: u64 = entry
            .from
            .iter()
            .map(|source| before(source).saturating_sub(after(source)))
            .sum();
        if !entry.from.is_empty() && freed >= raise {
            continue;
        }
        if let Some(decision) = &entry.raised_by {
            if bar.decisions.contains(decision) {
                owner_raised += raise;
                continue;
            }
        }
        if let Some(id) = &entry.bridge {
            if let Some(bridge) = bar.bridges.iter().find(|bridge| &bridge.id == id) {
                if open(bridge) && bridge.crates.iter().any(|name| name == krate) {
                    bridged.push(bridge);
                    continue;
                }
            }
        }
        failures.push(format!(
            "raise: {key} rose from {} to {} without a transfer (`from` naming entries that fell \
             by at least {raise}), an owner raise (`raised_by` an owner decision in {BAR}) or an \
             open bridge",
            before(key),
            entry.budget
        ));
    }
    let sum_before = crate_sum(base);
    let sum_after = crate_sum(budgets);
    if sum_after > sum_before + owner_raised {
        let within_bridge = bridged
            .iter()
            .any(|bridge| sum_after <= bridge.base_sum + bridge.max);
        if !within_bridge {
            failures.push(format!(
                "sum: the budgets sum to {sum_after}, above {sum_before} at the merge base"
            ));
        }
    }
    for site in &budgets.generated {
        if !base.generated.contains(site) {
            failures.push(format!(
                "generated list: {site} was added; entries can only be removed"
            ));
        }
    }
}
