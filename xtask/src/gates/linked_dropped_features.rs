//! `cargo xtask gate linked-dropped-features` — A LINKED PLUGIN IS BUILT WITH THE SAME FEATURES AS
//! ITS DROPPED-IN BUILD (M0 ABI-SPEC).
//!
//! Compiled in = dropped in: the same plugin, the same table. Cargo's feature unification breaks
//! that quietly. A plugin linked into the `busbar` binary is compiled with the UNION of every
//! feature any crate in the binary asks of it — and of every registry crate it shares with them —
//! while its dropped-in cdylib is compiled alone, with its own defaults. Two builds, two plugins.
//!
//! For every plugin crate the binary links ([`one_abi::binary_closure`]):
//!
//! * **`own-features`** — a feature of the plugin itself switched on in one build and not the
//!   other: the edges that link it ask for features (or turn defaults off) its cdylib does not.
//! * **`unified-deps`** — a registry crate the plugin depends on, with a feature switched on in the
//!   linked build only because another crate in the binary asks for it.
//!
//! This reads the manifests (edge `features`, `default-features`, `[workspace.dependencies]`
//! inheritance and the `[features]` table), not Cargo's resolver: a feature a registry crate's
//! own features switch on transitively is not seen. M5 re-measures with the resolver.
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/linked-dropped-features.toml`.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Member, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;
use crate::manifest;

pub const ROW_OWN: &str = "linked-dropped-features:own-features";
pub const ROW_UNIFIED: &str = "linked-dropped-features:unified-deps";

pub const SPEC: Spec = Spec {
    gate: "linked-dropped-features",
    ledger: "qa/linked-dropped-features.toml",
    rules: &[
        (
            ROW_OWN,
            "a linked plugin's own features equal its dropped-in build's",
        ),
        (
            ROW_UNIFIED,
            "a linked plugin's registry deps carry no feature the binary unifies in",
        ),
    ],
    header: "# linked-dropped-features: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # A plugin linked into the binary is built with the features its dropped-in cdylib\n\
             # is built with. Each row is a plugin manifest and one feature that differs today.\n\
             # Strike a row in the commit that drains it; never add one.\n\
             # Regenerate with `cargo xtask gate linked-dropped-features --write`.\n",
};

/// One dependency edge as a manifest states it, with what it asks for.
#[derive(Debug, Clone, Default)]
struct Ask {
    pkg: String,
    features: BTreeSet<String>,
    default: bool,
    workspace: bool,
}

/// Is `section` a SHIPPED dependency table?
fn shipped_table(section: &str) -> bool {
    let last = section.rsplit('.').next().unwrap_or("");
    last == "dependencies" || last == "build-dependencies"
}

fn strings_in(s: &str) -> BTreeSet<String> {
    s.split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, v)| v.to_string())
        .collect()
}

/// The value of `key = …` inside an inline table body, up to the next top-level `,` or `}`.
fn inline_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(i) = body[from..].find(key) {
        let at = from + i;
        from = at + key.len();
        let before = body[..at].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            continue;
        }
        let rest = body[at + key.len()..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with('[') {
            let end = rest.find(']').map_or(rest.len(), |e| e + 1);
            return Some(&rest[..end]);
        }
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        return Some(rest[..end].trim());
    }
    None
}

fn ask_of(key: &str, body: &str) -> Ask {
    let mut a = Ask {
        pkg: key.to_string(),
        default: true,
        ..Ask::default()
    };
    if let Some(p) = inline_value(body, "package") {
        a.pkg = p.trim_matches('"').to_string();
    }
    if let Some(f) = inline_value(body, "features") {
        a.features = strings_in(f);
    }
    if inline_value(body, "default-features") == Some("false")
        || inline_value(body, "default_features") == Some("false")
    {
        a.default = false;
    }
    a.workspace = inline_value(body, "workspace") == Some("true");
    a
}

/// Every dependency a manifest's tables named by `want` ask for. Handles `key = "1"`,
/// `key = { … }` (across lines) and the `[dependencies.key]` table form.
fn asks(text: &str, want: fn(&str) -> bool) -> Vec<Ask> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut pending: Option<(String, String)> = None;
    let mut table_dep: Option<(String, String)> = None;
    let flush_table = |t: &mut Option<(String, String)>, out: &mut Vec<Ask>| {
        if let Some((k, body)) = t.take() {
            out.push(ask_of(&k, &body));
        }
    };
    for raw in text.lines() {
        let line = raw.split(" #").next().unwrap_or("");
        let t = line.trim();
        if let Some((k, mut body)) = pending.take() {
            body.push(' ');
            body.push_str(t);
            if body.matches('{').count() <= body.matches('}').count() {
                out.push(ask_of(&k, &body));
            } else {
                pending = Some((k, body));
            }
            continue;
        }
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if let Some(h) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            flush_table(&mut table_dep, &mut out);
            let h = h.replace(['\'', '"'], "");
            // `[dependencies.tokio]`
            if let Some((sec, key)) = h.rsplit_once('.') {
                if want(sec) && !want(&h) {
                    table_dep = Some((key.to_string(), String::new()));
                    section = String::new();
                    continue;
                }
            }
            section = h;
            continue;
        }
        if let Some((_, body)) = table_dep.as_mut() {
            body.push_str(t);
            body.push_str(", ");
            continue;
        }
        if !want(&section) {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let k = k.trim().trim_matches('"').to_string();
        let v = v.trim();
        if v.starts_with('{') && v.matches('{').count() > v.matches('}').count() {
            pending = Some((k, v.to_string()));
        } else {
            out.push(ask_of(&k, v));
        }
    }
    flush_table(&mut table_dep, &mut out);
    out
}

/// A plugin's own features a set of seeds switches on, through its `[features]` table.
fn expand(table: &BTreeMap<String, Vec<String>>, seeds: &BTreeSet<String>) -> BTreeSet<String> {
    let mut on: BTreeSet<String> = BTreeSet::new();
    let mut todo: Vec<String> = seeds.iter().cloned().collect();
    while let Some(f) = todo.pop() {
        if !table.contains_key(&f) || !on.insert(f.clone()) {
            continue;
        }
        for item in &table[&f] {
            if !item.contains(':') && !item.contains('/') {
                todo.push(item.clone());
            }
        }
    }
    on
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let members = match one_abi::members(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let root = cx.read("Cargo.toml").unwrap_or_default();
    let ws: BTreeMap<String, Ask> = asks(&root, |s| s == "workspace.dependencies")
        .into_iter()
        .map(|a| (a.pkg.clone(), a))
        .collect();
    let resolve = |mut a: Ask| {
        if a.workspace {
            if let Some(w) = ws.get(&a.pkg) {
                a.features.extend(w.features.iter().cloned());
                a.default = a.default && w.default;
            }
        }
        a
    };
    let names: BTreeSet<&str> = members.iter().map(|m| m.name.as_str()).collect();
    let closure = one_abi::binary_closure(&members);
    let edges: BTreeMap<&str, Vec<Ask>> = members
        .iter()
        .filter(|m| closure.contains(&m.name))
        .map(|m| {
            (
                m.name.as_str(),
                asks(&m.manifest, shipped_table)
                    .into_iter()
                    .map(resolve)
                    .collect(),
            )
        })
        .collect();
    let linked: Vec<&Member> = members
        .iter()
        .filter(|m| closure.contains(&m.name) && one_abi::is_plugin_crate(&m.name))
        .collect();
    if linked.len() < 3 {
        errors.push(format!(
            "the binary links {} plugin crate(s); the scan has gone blind",
            linked.len()
        ));
    }
    for p in linked {
        let file = p.manifest_rel();
        let table = manifest::feature_table(&p.manifest);
        // THE LINKED BUILD: every edge onto the plugin from a non-plugin crate of the binary.
        let mut seeds: BTreeSet<String> = BTreeSet::new();
        for (from, list) in &edges {
            if one_abi::is_plugin_crate(from) {
                continue;
            }
            for a in list.iter().filter(|a| a.pkg == p.name) {
                seeds.extend(a.features.iter().cloned());
                if a.default {
                    seeds.insert("default".to_string());
                }
            }
        }
        let linked_on = expand(&table, &seeds);
        let dropped_on = expand(&table, &BTreeSet::from(["default".to_string()]));
        for f in linked_on.difference(&dropped_on) {
            findings.push(Finding::new(ROW_OWN, &file, format!("linked-only {f}"), 0));
        }
        for f in dropped_on.difference(&linked_on) {
            findings.push(Finding::new(ROW_OWN, &file, format!("dropped-only {f}"), 0));
        }
        // THE UNIFIED DEPS: what the binary asks of a registry crate the plugin also asks for.
        let own: Vec<Ask> = edges.get(p.name.as_str()).cloned().unwrap_or_default();
        for mine in own.iter().filter(|a| !names.contains(a.pkg.as_str())) {
            let mut asked: BTreeSet<String> = mine.features.clone();
            if mine.default {
                asked.insert("default".to_string());
            }
            let mut union: BTreeSet<String> = BTreeSet::new();
            for list in edges.values() {
                for a in list.iter().filter(|a| a.pkg == mine.pkg) {
                    union.extend(a.features.iter().cloned());
                    if a.default {
                        union.insert("default".to_string());
                    }
                }
            }
            for f in union.difference(&asked) {
                findings.push(Finding::new(
                    ROW_UNIFIED,
                    &file,
                    format!("{}/{f}", mine.pkg),
                    0,
                ));
            }
        }
    }
    (findings, errors)
}

pub struct LinkedDroppedFeaturesGate;

impl Gate for LinkedDroppedFeaturesGate {
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
        let bin = "crates/busbar/Cargo.toml";
        let plugin = "crates/busbar-transport-http/Cargo.toml";
        let edge = "busbar-transport-http = { path = \"../busbar-transport-http\" }";
        let own = {
            let b = cx.read(bin).unwrap_or_default().replacen(
                edge,
                "busbar-transport-http = { path = \"../busbar-transport-http\", features = [\"planted-linked\"] }",
                1,
            );
            let p = cx.read(plugin).unwrap_or_default();
            let p = if p.contains("[features]\n") {
                p.replacen("[features]\n", "[features]\nplanted-linked = []\n", 1)
            } else {
                format!("{p}\n[features]\nplanted-linked = []\n")
            };
            let mut ov = Overlay::new();
            ov.set(bin, b);
            ov.set(plugin, p);
            ov
        };
        let unified = {
            let b = cx.read(bin).unwrap_or_default().replacen(
                "[dependencies]\n",
                "[dependencies]\nfutures = { workspace = true, features = [\"planted-unified\"] }\n",
                1,
            );
            let mut ov = Overlay::new();
            ov.set(bin, b);
            ov
        };
        one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_OWN,
                    "the binary asking a plugin for a feature its cdylib lacks is RED",
                    own,
                    vec![plugin, "linked-only planted-linked"],
                ),
                (
                    ROW_UNIFIED,
                    "the binary unifying a feature into a plugin's registry dep is RED",
                    unified,
                    vec![plugin, "futures/planted-unified"],
                ),
            ],
        )
    }
}
