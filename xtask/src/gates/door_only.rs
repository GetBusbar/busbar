//! `cargo xtask gate door-only` — THE KERNEL REACHES A PLUGIN ONLY THROUGH ITS DOOR (M0 ABI-SPEC).
//!
//! > "compiled or dropped in is just a convenience for customer; NOTHING CHANGES about the plugin
//! > itself and how it works." — OWNER, 2026-09-27
//!
//! A compiled-in plugin is a row holding the same `door` a dropped-in one exports, and the kernel
//! calls both through the same table: it never holds a plugin crate's Rust types and never calls
//! its Rust functions. Over the WHOLE BINARY CLOSURE — every non-plugin workspace crate the `busbar`
//! binary links, the binary included, `busbar-contract` aside (its own gate is
//! `contract-stateless`):
//!
//! * **`plugin-path`** — a Rust path into a plugin crate (`busbar_plane_llm::…`) other than
//!   `<crate>::door`.
//! * **`static-seam`** — a `static` whose type holds a function pointer, a `Fn` trait or a trait
//!   object: a seam another crate installs Rust code into, bypassing every door. Exactly two are
//!   exempt, the oauth2 and admin cleanliness seams the owner ruled core
//!   ([`EXEMPT_SEAMS`]); a third is a finding.
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/door-only.toml`.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_PATH: &str = "door-only:plugin-path";
pub const ROW_SEAM: &str = "door-only:static-seam";

/// The two static fn-pointer seams the owner ruled core (oauth2 and admin), and no others.
pub const EXEMPT_SEAMS: &[&str] = &[
    "crates/busbar-kernel/src/oauth_as/seam.rs",
    "crates/busbar-kernel/src/admin/seam.rs",
];

pub const SPEC: Spec = Spec {
    gate: "door-only",
    ledger: "qa/door-only.toml",
    rules: &[
        (
            ROW_PATH,
            "the binary closure names no plugin crate's Rust item but its door",
        ),
        (
            ROW_SEAM,
            "the binary closure installs no static fn-pointer seam (oauth2 and admin exempt)",
        ),
    ],
    header: "# door-only: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # The binary closure reaches a plugin only through its door, and installs no static\n\
             # fn-pointer seam but the two ruled core (oauth_as/seam.rs, admin/seam.rs). Each row\n\
             # is one the tree carries today. Strike a row in the commit that drains it; never\n\
             # add one. Regenerate with `cargo xtask gate door-only --write`.\n",
};

/// The name and declared type of a `static` item on this blanked line, if it declares one.
fn static_decl(counted: &str) -> Option<(String, String)> {
    let mut from = 0;
    while let Some(i) = counted[from..].find("static") {
        let at = from + i;
        from = at + 6;
        let before = counted[..at].chars().next_back();
        if before.is_some_and(|c| c == '\'' || c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        if !counted[at + 6..].starts_with(char::is_whitespace) {
            continue;
        }
        let rest = counted[at + 6..].trim_start();
        let rest = rest.strip_prefix("mut ").map_or(rest, str::trim_start);
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = rest[name.len()..].trim_start();
        if name.is_empty() || !after.starts_with(':') || after.starts_with("::") {
            continue;
        }
        let ty: String = after[1..]
            .chars()
            .take_while(|c| *c != '=' && *c != ';')
            .collect();
        return Some((name, ty));
    }
    None
}

/// Does a static's declared type hold code: a fn pointer, a `Fn` trait or a trait object?
fn holds_code(ty: &str) -> bool {
    one_abi::has_word(ty, "fn")
        || one_abi::has_word(ty, "Fn")
        || one_abi::has_word(ty, "FnMut")
        || one_abi::has_word(ty, "FnOnce")
        || one_abi::has_word(ty, "dyn")
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let members = match one_abi::members(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let closure = one_abi::binary_closure(&members);
    let plugin_idents: Vec<String> = members
        .iter()
        .filter(|m| one_abi::is_plugin_crate(&m.name))
        .map(|m| m.name.replace('-', "_"))
        .collect();
    let scope: Vec<_> = members
        .iter()
        .filter(|m| {
            closure.contains(&m.name)
                && !one_abi::is_plugin_crate(&m.name)
                && m.name != "busbar-contract"
        })
        .collect();
    if scope.len() < 10 {
        errors.push(format!(
            "the binary closure read as {} crate(s); the scan has gone blind",
            scope.len()
        ));
    }
    for m in scope {
        let files = match one_abi::rs_files(cx, &m.dir) {
            Ok(f) => f,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        for f in &files {
            let rel = f.rel_str();
            // A multi-line static's type runs onto the next lines; read up to its `=` or `;`.
            let lines = one_abi::production(&f.text);
            for (idx, sl) in lines.iter().enumerate() {
                for p in &plugin_idents {
                    let needle = format!("{p}::");
                    let mut from = 0;
                    while let Some(i) = sl.counted[from..].find(&needle) {
                        let at = from + i;
                        from = at + needle.len();
                        let before = sl.counted[..at].chars().next_back();
                        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                            continue;
                        }
                        let tail: String = sl.counted[at + needle.len()..]
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        if tail != "door" {
                            findings.push(Finding::new(ROW_PATH, &rel, p.clone(), sl.no));
                        }
                    }
                }
                if EXEMPT_SEAMS.contains(&rel.as_str()) {
                    continue;
                }
                if let Some((name, mut ty)) = static_decl(&sl.counted) {
                    for more in lines.iter().skip(idx + 1).take(6) {
                        if ty.contains('=') || sl.counted.contains('=') || sl.counted.contains(';')
                        {
                            break;
                        }
                        ty.push(' ');
                        ty.push_str(
                            &more
                                .counted
                                .chars()
                                .take_while(|c| *c != '=' && *c != ';')
                                .collect::<String>(),
                        );
                        if more.counted.contains('=') || more.counted.contains(';') {
                            break;
                        }
                    }
                    if holds_code(&ty) {
                        findings.push(Finding::new(ROW_SEAM, &rel, name, sl.no));
                    }
                }
            }
        }
    }
    (findings, errors)
}

pub struct DoorOnlyGate;

impl Gate for DoorOnlyGate {
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
        // THE PLUGIN THE PLANT NAMES IS ONE THE WORKSPACE HOLDS. The plant named
        // `busbar_transport_tcp` until that transport left for its own repo (66853bf6e1); the scan
        // only knows the plugin crates that are members, so a path into a departed one is no
        // finding and the red arm proved nothing. The plugins leave this tree one by one, so the
        // plant takes whichever plugin member the census holds first.
        let plugin: &'static str = match one_abi::members(cx).map(|ms| {
            ms.into_iter()
                .find(|m| one_abi::is_plugin_crate(&m.name))
                .map(|m| m.name.replace('-', "_"))
        }) {
            Ok(Some(ident)) => Box::leak(ident.into_boxed_str()),
            Ok(None) => {
                let mut report = Report::new();
                report.note_infra_failure(
                    "door-only selftest: the workspace holds no plugin crate to plant a path into",
                );
                return report;
            }
            Err(e) => {
                let mut report = Report::new();
                report.note_infra_failure(format!("door-only selftest: {e}"));
                return report;
            }
        };
        let file = "crates/busbar-kernel/src/planted_door_only.rs";
        let mut path = Overlay::new();
        path.set(
            file,
            format!("pub fn planted() {{ {plugin}::carrier::Planted::go(); }}\n"),
        );
        let mut seam = Overlay::new();
        seam.set(
            file,
            "pub static PLANTED_SEAM: std::sync::OnceLock<fn() -> u8> = std::sync::OnceLock::new();\n",
        );
        let mut door = Overlay::new();
        door.set(
            file,
            format!("pub const ROW: fn() = {plugin}::door;\npub static NAME: &str = \"x\";\n"),
        );
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_PATH,
                    "the kernel naming a plugin's Rust item is RED, naming the crate",
                    path,
                    vec![file, plugin],
                ),
                (
                    ROW_SEAM,
                    "a static fn-pointer seam in the kernel is RED, naming it",
                    seam,
                    vec![file, "PLANTED_SEAM"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a row holding <crate>::door, and a static holding data, are not findings",
            &[ROW_PATH, ROW_SEAM],
            door,
        ));
        report
    }
}
