//! `cargo xtask gate plugin-closure-deps` — A PLUGIN DEPENDS ON `busbar-contract` AND NOTHING ELSE
//! OF BUSBAR'S (M0 ABI-SPEC).
//!
//! A plugin is a plugin whether it is compiled in or dropped in, and it talks to core only over
//! its kind's memory ABI. So its closure holds exactly one busbar crate, `busbar-contract`. What
//! third-party crate a plugin links, and which OS facilities it reaches directly, are its own
//! business — OWNER RULING 2026-09-28 (PLUGIN LIBRARIES): a plugin may use whatever third-party
//! libraries it needs to do its job. The two walls that remain are enforced elsewhere, by kind:
//! `busbar-contract`-only closure is this gate's own row below; a PURE kind (plane, hook, auth)
//! doing no I/O of its own is `source-denylist`'s row, scoped to those kinds only, and never to a
//! transport (carrier) crate, which is the one kind whose job IS to own the wire.
//!
//! * **`busbar-deps`** — a busbar crate other than `busbar-contract` reached through the plugin's
//!   shipped workspace edges (its own and those of every workspace crate it reaches).
//!
//! Plugin crates are the workspace members named for a plugin kind ([`one_abi::is_plugin_crate`]).
//! Sibling plugin repositories are not read by this gate; M5 (ZERODEP) owns them.
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/plugin-closure-deps.toml`.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Member, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_BUSBAR: &str = "plugin-closure-deps:busbar-deps";

/// The one busbar crate a plugin may depend on.
const CONTRACT: &str = "busbar-contract";

pub const SPEC: Spec = Spec {
    gate: "plugin-closure-deps",
    ledger: "qa/plugin-closure-deps.toml",
    rules: &[(
        ROW_BUSBAR,
        "a plugin's closure holds no busbar crate but busbar-contract",
    )],
    header: "# plugin-closure-deps: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # A plugin depends on busbar-contract and nothing else of busbar's. Each row is one\n\
             # the tree carries today; `file` is the plugin's manifest. Strike a row in the commit\n\
             # that drains it; never add one.\n\
             # Regenerate with `cargo xtask gate plugin-closure-deps --write`.\n",
};

fn is_busbar(name: &str, members: &BTreeSet<&str>) -> bool {
    name.starts_with("busbar") || members.contains(name)
}

/// Every workspace member a plugin reaches through shipped edges, the plugin excluded, and the
/// member each was first reached from.
fn reached<'m>(
    start: &'m Member,
    by_name: &BTreeMap<&str, &'m Member>,
) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut todo: Vec<(&Member, String)> = vec![(start, start.name.clone())];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    while let Some((m, _)) = todo.pop() {
        if !seen.insert(m.name.clone()) {
            continue;
        }
        for d in m.decls.iter().filter(|d| d.table.shipped()) {
            if let Some(next) = by_name.get(d.pkg.as_str()) {
                out.entry(d.pkg.clone()).or_insert_with(|| m.name.clone());
                todo.push((next, m.name.clone()));
            }
        }
    }
    out
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let members = match one_abi::members(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let names: BTreeSet<&str> = members.iter().map(|m| m.name.as_str()).collect();
    let by_name: BTreeMap<&str, &Member> = members.iter().map(|m| (m.name.as_str(), m)).collect();
    let plugins: Vec<&Member> = members
        .iter()
        .filter(|m| one_abi::is_plugin_crate(&m.name))
        .collect();
    if plugins.len() < 5 {
        errors.push(format!(
            "the workspace names {} plugin crate(s); the scan has gone blind",
            plugins.len()
        ));
    }
    for p in plugins {
        let manifest = p.manifest_rel();
        let reach = reached(p, &by_name);
        for (name, via) in &reach {
            if is_busbar(name, &names) && name != CONTRACT {
                let how = if via == &p.name {
                    name.clone()
                } else {
                    format!("{name} (via {via})")
                };
                findings.push(Finding::new(ROW_BUSBAR, &manifest, how, 0));
            }
        }
    }
    (findings, errors)
}

pub struct PluginClosureDepsGate;

impl Gate for PluginClosureDepsGate {
    fn name(&self) -> &'static str {
        SPEC.gate
    }

    fn owed(&self) -> Vec<String> {
        SPEC.owed()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let (findings, errors) = scan(cx);
        one_abi::verdict(cx, &SPEC, findings, errors)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        // THE PLANTS GO INTO THE ONE PLUGIN CRATE THAT DEPENDS ON busbar-contract ALONE TODAY, so a
        // plant's finding is the only new one.
        let manifest = "crates/busbar-transport-stdio/Cargo.toml";
        let with_dep = |dep: &str| {
            let text = cx.read(manifest).unwrap_or_default();
            let text = text.replacen("[dependencies]\n", &format!("[dependencies]\n{dep}\n"), 1);
            let mut ov = Overlay::new();
            ov.set(manifest, text);
            ov
        };
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![(
                ROW_BUSBAR,
                "a plugin depending on the kernel is RED, naming the kernel",
                with_dep("busbar-kernel-wal = { path = \"../busbar-kernel-wal\" }"),
                vec![manifest, "busbar-kernel-wal"],
            )],
        );
        // OWNER RULING 2026-09-28 (PLUGIN LIBRARIES): a plugin's own third-party library choice is
        // no longer this gate's business, so a plugin naming a runtime, logger or subscriber crate
        // — even one this gate used to deny by name — must stay green on the one row this gate
        // still keeps.
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a plugin depending on hyper stays green: this gate checks only busbar-contract",
            &[ROW_BUSBAR],
            with_dep("hyper = { workspace = true }"),
        ));
        report
    }
}
