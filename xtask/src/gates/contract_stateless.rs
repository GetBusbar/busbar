//! `cargo xtask gate contract-stateless` — THE CONTRACT CRATE HOLDS NO STATE (M0 ABI-SPEC).
//!
//! `busbar-contract` is the ABI a plugin is built against, linked into the kernel AND into every
//! dropped-in plugin image. A `static` in it is two statics the moment a plugin is dropped in —
//! one per image — so a registry, a once-cell or a thread-local there behaves one way compiled in
//! and another way dropped in. Services reach a plugin only through the host tables handed at
//! `open`. So the contract has no `static`, `OnceLock`, `LazyLock`, `OnceCell` or `thread_local!`
//! outside test code.
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/contract-stateless.toml` (see
//! [`super::one_abi`]); the rows are the work list of the step that moves the registries into the
//! kernel.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_STATIC: &str = "contract-stateless:static";
pub const ROW_ONCE: &str = "contract-stateless:once-cell";
pub const ROW_THREAD_LOCAL: &str = "contract-stateless:thread-local";

const CONTRACT_SRC: &str = "crates/busbar-contract";

/// Where the door macro's per-thread capture slot lives: the ledger's one `[[sanctioned]]` site
/// pair (ARCHITECT ruling 2026-10-14; SPEC l.1297-1300).
const CAPTURE_HOME: &str = "crates/busbar-contract/src/abi/sdk/door.rs";

pub const SPEC: Spec = Spec {
    gate: "contract-stateless",
    ledger: "qa/contract-stateless.toml",
    rules: &[
        (ROW_STATIC, "no `static` item in busbar-contract"),
        (
            ROW_ONCE,
            "no OnceLock / LazyLock / OnceCell / Lazy in busbar-contract",
        ),
        (ROW_THREAD_LOCAL, "no thread_local! in busbar-contract"),
    ],
    header: "# contract-stateless: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # busbar-contract holds no static, once-cell or thread-local outside test code: each\n\
             # row is one the tree carries today. Strike a row in the commit that drains it;\n\
             # never add one. Regenerate with `cargo xtask gate contract-stateless --write`.\n",
};

/// The once-cell spellings, each read as a word.
const ONCE: &[&str] = &["OnceLock", "LazyLock", "OnceCell", "Lazy"];

/// The name a `static` item declares on this (blanked) line, if it declares one. `'static` is a
/// lifetime and never counts.
fn static_item(counted: &str) -> Option<String> {
    let mut from = 0;
    while let Some(i) = counted[from..].find("static") {
        let at = from + i;
        from = at + 6;
        let before = counted[..at].chars().next_back();
        if before.is_some_and(|c| c == '\'' || c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let rest = counted[at + 6..].trim_start();
        if !counted[at + 6..].starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.strip_prefix("mut ").map_or(rest, str::trim_start);
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        let after = rest[name.len()..].trim_start();
        if !name.is_empty() && after.starts_with(':') && !after.starts_with("::") {
            return Some(name);
        }
    }
    None
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let files = match one_abi::rs_files(cx, CONTRACT_SRC) {
        Ok(f) => f,
        Err(e) => return (findings, vec![e]),
    };
    if files.len() < 20 {
        return (
            findings,
            vec![format!(
                "{CONTRACT_SRC}/src read as {} file(s); the scan has gone blind",
                files.len()
            )],
        );
    }
    for f in &files {
        let rel = f.rel_str();
        for sl in one_abi::production(&f.text) {
            if let Some(name) = static_item(&sl.counted) {
                findings.push(Finding::new(ROW_STATIC, &rel, name, sl.no));
            }
            for w in ONCE {
                if one_abi::has_word(&sl.counted, w) {
                    findings.push(Finding::new(ROW_ONCE, &rel, *w, sl.no));
                }
            }
            if sl.counted.contains("thread_local!") {
                findings.push(Finding::new(ROW_THREAD_LOCAL, &rel, "thread_local!", sl.no));
            }
        }
    }
    (findings, Vec::new())
}

pub struct ContractStatelessGate;

impl Gate for ContractStatelessGate {
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
        let file = "crates/busbar-contract/src/abi/mechanism/planted_state.rs";
        let plant = |body: &str| {
            let mut ov = Overlay::new();
            ov.set(file, body.to_string());
            ov
        };
        let tests_only = {
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-contract/src/abi/mechanism/planted_test_state.rs",
                "#[cfg(test)]\nmod t {\n    static PLANTED_TEST_ONLY: u8 = 0;\n}\n",
            );
            ov
        };
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_STATIC,
                    "a static in the contract is RED, naming it",
                    plant("pub static PLANTED_REGISTRY: u8 = 0;\n"),
                    vec![file, "PLANTED_REGISTRY"],
                ),
                (
                    ROW_ONCE,
                    "a OnceLock in the contract is RED",
                    plant("pub struct Planted(std::sync::OnceLock<u8>);\n"),
                    vec![file, "OnceLock"],
                ),
                (
                    ROW_THREAD_LOCAL,
                    "a thread_local! in the contract is RED",
                    plant("thread_local! { }\n"),
                    vec![file, "thread_local!"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a static inside #[cfg(test)] is not state the contract ships",
            &[ROW_STATIC],
            tests_only,
        ));
        // THE ONE SANCTIONED PER-THREAD SLOT (the plugin-logging capture, SPEC l.1297-1300)
        // excuses exactly itself: a SECOND thread_local! beside it, in the very file it lives in,
        // is NEW and red; and a sanction whose site left the tree is STALE.
        let second = {
            let mut ov = Overlay::new();
            let text = cx.read(CAPTURE_HOME).unwrap_or_default();
            ov.set(
                CAPTURE_HOME,
                format!("{text}\nthread_local! {{ static PLANTED_SECOND: u8 = 0; }}\n"),
            );
            ov
        };
        report.push(crate::gates::prove_rows_red(
            cx,
            self,
            "a second thread_local! beside the sanctioned capture slot is RED",
            &[ROW_THREAD_LOCAL],
            second,
            &[CAPTURE_HOME, "thread_local!"],
        ));
        let gone = {
            let mut ov = Overlay::new();
            let ledger = cx.read(SPEC.ledger).unwrap_or_default();
            ov.set(
                SPEC.ledger,
                format!(
                    "{ledger}\n[[sanctioned]]\nrule = \"{ROW_ONCE}\"\nfile = \"{CAPTURE_HOME}\"\nitem = \"OnceCell\"\ncite = \"planted\"\ndrain = \"planted\"\n"
                ),
            );
            ov
        };
        let ledger_row = SPEC.ledger_row();
        report.push(crate::gates::prove_rows_red(
            cx,
            self,
            "a sanctioned site the tree does not carry is STALE",
            &[ledger_row.as_str()],
            gone,
            &["STALE sanctioned", "OnceCell"],
        ));
        report
    }
}
