//! `cargo xtask gate one-memory-abi` — PLUGINS SPEAK THE MEMORY ABI ONLY (M0 ABI-SPEC).
//!
//! > "Plugins speak Memory ABI ONLY." — OWNER, 2026-09-27
//!
//! One door per plugin, one call shape, no COLD/JSON lane. What this gate measures, workspace-wide
//! over production code:
//!
//! * **`exported-symbol`** — every `#[no_mangle]` / `#[unsafe(no_mangle)]` / `#[export_name]`
//!   item whose symbol is not `busbar_plugin_door`. A plugin exports exactly one symbol.
//! * **`cold-lane`** — every reference to the COLD/JSON lane outside its own home
//!   (`abi/cold/`): `abi::cold`, `busbar_call`, `ColdEntry`.
//! * **`spawn-blocking`** — `spawn_blocking` in the loader or in a dispatcher file: waiting never
//!   blocks, so the one loading path and the one dispatcher own no blocking thread.
//! * **`c-unwind`** — every `extern "C-unwind"`: unwinding across a foreign cdylib is undefined
//!   behaviour, so a slot is `extern "C"` and a panic that escapes it aborts.
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/one-memory-abi.toml` (see
//! [`super::one_abi`]). M6 (cold delete) and M3 (the kind tables) drain it.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;
use crate::scan::ScopeLine;

pub const ROW_EXPORTED: &str = "one-memory-abi:exported-symbol";
pub const ROW_COLD: &str = "one-memory-abi:cold-lane";
pub const ROW_SPAWN_BLOCKING: &str = "one-memory-abi:spawn-blocking";
pub const ROW_C_UNWIND: &str = "one-memory-abi:c-unwind";

/// The one symbol a plugin exports.
pub const DOOR_SYMBOL: &str = "busbar_plugin_door";
/// The cold lane's own home; references inside it are the lane itself, deleted whole in M6.
const COLD_HOME: &str = "crates/busbar-contract/src/abi/cold/";
/// The cold lane's names.
const COLD_NEEDLES: &[&str] = &["abi::cold", "busbar_call", "ColdEntry"];

pub const SPEC: Spec = Spec {
    gate: "one-memory-abi",
    ledger: "qa/one-memory-abi.toml",
    rules: &[
        (
            ROW_EXPORTED,
            "the only exported symbol is busbar_plugin_door",
        ),
        (
            ROW_COLD,
            "no reference to the COLD/JSON lane outside abi/cold/",
        ),
        (
            ROW_SPAWN_BLOCKING,
            "no spawn_blocking in the loader or a dispatcher",
        ),
        (
            ROW_C_UNWIND,
            "no extern \"C-unwind\": slots are extern \"C\"",
        ),
    ],
    header: "# one-memory-abi: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # Plugins speak the memory ABI only: one exported symbol, no COLD/JSON lane, no\n\
             # blocking thread in the loader or dispatcher, extern \"C\" slots. Each row is one\n\
             # the tree carries today. Strike a row in the commit that drains it; never add one.\n\
             # Regenerate with `cargo xtask gate one-memory-abi --write`.\n",
};

/// The symbol an export attribute on line `idx` gives the item it applies to: its
/// `export_name`, else the next `fn`/`static` name within a few lines.
fn exported_symbol(lines: &[ScopeLine], idx: usize) -> String {
    let raw = &lines[idx].raw;
    if let Some(p) = raw.find("export_name") {
        if let Some(q) = raw[p..].find('"') {
            let rest = &raw[p + q + 1..];
            return rest.split('"').next().unwrap_or("?").to_string();
        }
    }
    for sl in lines.iter().skip(idx).take(8) {
        let words: Vec<&str> = sl
            .counted
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
            .filter(|w| !w.is_empty())
            .collect();
        for w in words.windows(2) {
            if w[0] == "fn" || w[0] == "static" {
                return w[1].to_string();
            }
        }
    }
    "?".to_string()
}

fn is_export_attr(counted: &str) -> bool {
    let t = counted.trim_start();
    t.starts_with("#[no_mangle]")
        || t.starts_with("#[unsafe(no_mangle)]")
        || t.starts_with("#[export_name")
        || t.starts_with("#[unsafe(export_name")
}

fn is_dispatcher(rel: &str) -> bool {
    rel.starts_with("crates/plugin-loader/") || rel.contains("/dispatch")
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let members = match one_abi::members(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let mut files = 0usize;
    for m in members.iter().filter(|m| m.dir.starts_with("crates/")) {
        let list = match one_abi::rs_files(cx, &m.dir) {
            Ok(l) => l,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        files += list.len();
        for f in &list {
            let rel = f.rel_str();
            let all = crate::scan::test_scope(&f.text);
            for (idx, sl) in all.iter().enumerate() {
                if sl.gated || sl.is_comment {
                    continue;
                }
                if is_export_attr(&sl.counted) {
                    let sym = exported_symbol(&all, idx);
                    if sym != DOOR_SYMBOL {
                        findings.push(Finding::new(ROW_EXPORTED, &rel, sym, sl.no));
                    }
                }
                if !rel.starts_with(COLD_HOME) {
                    for n in COLD_NEEDLES {
                        if sl.counted.contains(n) {
                            findings.push(Finding::new(ROW_COLD, &rel, *n, sl.no));
                        }
                    }
                }
                if is_dispatcher(&rel) && one_abi::has_word(&sl.counted, "spawn_blocking") {
                    findings.push(Finding::new(
                        ROW_SPAWN_BLOCKING,
                        &rel,
                        "spawn_blocking",
                        sl.no,
                    ));
                }
                if sl.raw.contains("\"C-unwind\"") && sl.counted.contains("extern") {
                    findings.push(Finding::new(
                        ROW_C_UNWIND,
                        &rel,
                        "extern \"C-unwind\"",
                        sl.no,
                    ));
                }
            }
        }
    }
    if files < 500 {
        errors.push(format!(
            "the workspace read as {files} production file(s); the scan has gone blind"
        ));
    }
    (findings, errors)
}

pub struct OneMemoryAbiGate;

impl Gate for OneMemoryAbiGate {
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
        let file = "crates/busbar-kernel/src/planted_one_abi.rs";
        let loader = "crates/plugin-loader/src/planted_one_abi.rs";
        let plant = |rel: &str, body: &str| {
            let mut ov = Overlay::new();
            ov.set(rel, body.to_string());
            ov
        };
        let door_only = {
            let mut ov = Overlay::new();
            ov.set(
                file,
                "#[no_mangle]\npub extern \"C\" fn busbar_plugin_door() {}\n",
            );
            ov
        };
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_EXPORTED,
                    "a second exported symbol is RED, naming it",
                    plant(
                        file,
                        "#[unsafe(no_mangle)]\npub extern \"C\" fn busbar_planted_call() {}\n",
                    ),
                    vec![file, "busbar_planted_call"],
                ),
                (
                    ROW_COLD,
                    "a cold-lane reference outside abi/cold/ is RED",
                    plant(file, "use busbar_contract::abi::cold::Planted;\n"),
                    vec![file, "abi::cold"],
                ),
                (
                    ROW_SPAWN_BLOCKING,
                    "spawn_blocking in the loader is RED",
                    plant(
                        loader,
                        "pub fn planted() { tokio::task::spawn_blocking(|| ()); }\n",
                    ),
                    vec![loader, "spawn_blocking"],
                ),
                (
                    ROW_C_UNWIND,
                    "an extern \"C-unwind\" slot is RED",
                    plant(file, "pub extern \"C-unwind\" fn planted_slot() {}\n"),
                    vec![file, "C-unwind"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "exporting busbar_plugin_door is the one export that is not a finding",
            &[ROW_EXPORTED],
            door_only,
        ));
        report
    }
}
