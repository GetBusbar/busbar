//! `cargo xtask gate plugin-closure-deps` — A PLUGIN DEPENDS ON `busbar-contract` AND NOTHING ELSE
//! OF BUSBAR'S, AND OWNS NO RUNTIME (M0 ABI-SPEC).
//!
//! A plugin is a plugin whether it is compiled in or dropped in, and it talks to core only over
//! its kind's memory ABI. So its closure holds exactly one busbar crate, `busbar-contract`; and
//! because a dropped-in plugin runs with no runtime entered and no subscriber installed, it owns
//! no executor, no logger and no OS resource of its own — slow I/O goes through the host.
//!
//! * **`busbar-deps`** — a busbar crate other than `busbar-contract` reached through the plugin's
//!   shipped workspace edges (its own and those of every workspace crate it reaches).
//! * **`runtime-deps`** — a denied registry crate in that closure: `tokio`, `hyper`,
//!   `hyper-util`, `async-std`, `smol`, `tracing`, `tracing-subscriber`, `log`, `env_logger`,
//!   `metrics`. A `tracing`/`log` call in a linked plugin reaches the kernel's subscriber and in a
//!   dropped one reaches nothing — the two builds differ.
//! * **`std-io`** — `std::thread`, `std::net`, `std::fs`, `std::env` or `set_var` in a plugin's
//!   production source.
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
pub const ROW_RUNTIME: &str = "plugin-closure-deps:runtime-deps";
pub const ROW_STD_IO: &str = "plugin-closure-deps:std-io";

/// The one busbar crate a plugin may depend on.
const CONTRACT: &str = "busbar-contract";

/// Registry crates no plugin closure may hold.
pub const DENIED: &[&str] = &[
    "tokio",
    "hyper",
    "hyper-util",
    "async-std",
    "smol",
    "tracing",
    "tracing-subscriber",
    "log",
    "env_logger",
    "metrics",
];

/// OS resources a plugin reaches only through the host.
const STD_IO: &[&str] = &["std::thread", "std::net", "std::fs", "std::env", "set_var"];

pub const SPEC: Spec = Spec {
    gate: "plugin-closure-deps",
    ledger: "qa/plugin-closure-deps.toml",
    rules: &[
        (
            ROW_BUSBAR,
            "a plugin's closure holds no busbar crate but busbar-contract",
        ),
        (
            ROW_RUNTIME,
            "a plugin's closure holds no runtime, logger or recorder",
        ),
        (
            ROW_STD_IO,
            "a plugin's source reaches no thread, socket, file or env of its own",
        ),
    ],
    header: "# plugin-closure-deps: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # A plugin depends on busbar-contract and nothing else of busbar's, holds no runtime,\n\
             # logger or recorder, and reaches no thread, socket, file or env of its own. Each row\n\
             # is one the tree carries today; `file` is the plugin's manifest or source file.\n\
             # Strike a row in the commit that drains it; never add one.\n\
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
        // The plugin's own edges and the edges of every workspace crate it reaches.
        let mut closure: Vec<&Member> = vec![p];
        for name in reach.keys() {
            if let Some(m) = by_name.get(name.as_str()) {
                closure.push(m);
            }
        }
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
        let mut denied: BTreeMap<String, String> = BTreeMap::new();
        for m in &closure {
            for d in m.decls.iter().filter(|d| d.table.shipped()) {
                if DENIED.contains(&d.pkg.as_str()) {
                    denied
                        .entry(d.pkg.clone())
                        .or_insert_with(|| m.name.clone());
                }
            }
        }
        for (dep, via) in denied {
            let how = if via == p.name {
                dep
            } else {
                format!("{dep} (via {via})")
            };
            findings.push(Finding::new(ROW_RUNTIME, &manifest, how, 0));
        }
        let files = match one_abi::rs_files(cx, &p.dir) {
            Ok(f) => f,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        for f in &files {
            let rel = f.rel_str();
            for sl in one_abi::production(&f.text) {
                for n in STD_IO {
                    if sl.counted.contains(n) {
                        findings.push(Finding::new(ROW_STD_IO, &rel, *n, sl.no));
                    }
                }
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
        let src = "crates/busbar-transport-stdio/src/planted_closure.rs";
        let with_dep = |dep: &str| {
            let text = cx.read(manifest).unwrap_or_default();
            let text = text.replacen("[dependencies]\n", &format!("[dependencies]\n{dep}\n"), 1);
            let mut ov = Overlay::new();
            ov.set(manifest, text);
            ov
        };
        let mut io = Overlay::new();
        io.set(
            src,
            "pub fn planted() { let _ = std::thread::spawn(|| ()); }\n",
        );
        one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_BUSBAR,
                    "a plugin depending on the kernel is RED, naming the kernel",
                    with_dep("busbar-kernel-wal = { path = \"../busbar-kernel-wal\" }"),
                    vec![manifest, "busbar-kernel-wal"],
                ),
                (
                    ROW_RUNTIME,
                    "a plugin depending on a logger is RED, naming it",
                    with_dep("env_logger = \"0.11\""),
                    vec![manifest, "env_logger"],
                ),
                (
                    ROW_STD_IO,
                    "a plugin spawning its own thread is RED",
                    io,
                    vec![src, "std::thread"],
                ),
            ],
        )
    }
}
