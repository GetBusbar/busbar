//! `cargo xtask gate door-cells-rig` — A DOOR PLANE'S ROOT CELLS REACH THE ROOT THROUGH ITS RIG ALONE.
//!
//! Each linked plane door's own root cells (its crate's `tests/root/mod.rs`, ARCHITECT ruling on
//! #464) compile into the composition root's serve module through `$OUT_DIR/door_cells.rs`, and a
//! pinned plane's cells live in another repository. A cell that names a root internal by its path
//! (a struct literal of a root type, a root builder's argument list, an installer by its path)
//! breaks at the pin on every root refactor. The root holds one stable surface for them instead,
//! `crates/busbar/src/root/tests/door_rig.rs` (mounted as `root::serve::door_rig`): a cell names the
//! root through `super::door_rig` alone, and the kernel's and the contract's public surfaces
//! directly. What a cell needs and the rig lacks is added to the rig, never reached for past it.
//!
//! One row over every door plane's cells, the files `DOOR_CELLS_FILES` cites
//! ([`crate::libtest_path::door_cells`]: every `plane-door` row of the root's
//! `[package.metadata.busbar.linked]`, a pinned plane read from the checkout `Cargo.lock` pins, laid
//! at its census mount, and an in-tree one at its path):
//!
//! * **`root-path`** — a `crate::` path (or `crate as …`), or a `super::` path that climbs out of
//!   the cells file into the serve module (or past it) and does not name `door_rig` next. A
//!   `super::` that stays inside the cells file (an inline `mod` reaching its own parent) is no
//!   finding. Comments and string literals are blanked first ([`crate::scan::blank_code`]).
//!
//! A cells file that does not read is RED (`:ledger`): the gate never judges a door it could not
//! see. The sites the pinned cells still carry are the COUNTED drain-only ledger
//! `qa/door-cells-rig.toml` (Law 9: a count only goes down); they drain when the root repins the
//! a2a plane at its cells-on-the-rig change (busbar-plane-a2a #44), which strikes every row in the
//! same commit.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_ROOT_PATH: &str = "door-cells-rig:root-path";

/// The composition root's crate root, whose manifest names the door planes.
const ROOT_FILE: &str = "crates/busbar/src/main.rs";

/// The one root module a door plane's cells may name, as `super::door_rig` from the cells file.
const RIG: &str = "door_rig";

pub const SPEC: Spec = Spec {
    gate: "door-cells-rig",
    ledger: "qa/door-cells-rig.toml",
    rules: &[(
        ROW_ROOT_PATH,
        "a door plane's root cells name the composition root through super::door_rig alone",
    )],
    header: "# door-cells-rig: DRAIN-ONLY ledger (ARCHITECT ruling on #464; Law 9, BUSBAR-1.6.0.md).\n\
             # A door plane's own root cells (its crate's tests/root/mod.rs, compiled into\n\
             # root::serve) name the composition root through super::door_rig alone. Each row is a\n\
             # root path a pinned plane's cells still name, COUNTED (one per line); the a2a rows\n\
             # drain when the root repins busbar-plane-a2a at its cells-on-the-rig change\n\
             # (busbar-plane-a2a #44), which strikes them in the same commit. Never add a row or\n\
             # raise a count. Regenerate with `cargo xtask gate door-cells-rig --write`.\n",
};

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The identifier starting at `at`, and the index after it.
fn word(b: &[char], at: usize) -> (String, usize) {
    let mut k = at;
    while k < b.len() && is_ident(b[k]) {
        k += 1;
    }
    (b[at..k].iter().collect(), k)
}

fn starts(b: &[char], at: usize, s: &str) -> bool {
    s.chars()
        .enumerate()
        .all(|(n, c)| b.get(at + n).copied() == Some(c))
}

fn skip_blanks(b: &[char], mut at: usize) -> usize {
    while at < b.len() && (b[at] == ' ' || b[at] == '\t' || b[at] == '\r') {
        at += 1;
    }
    at
}

/// The path's segments from `at` (just past a `::`): identifiers joined by `::`, a trailing group
/// read as `{..}` and a glob as `*`.
fn segments(b: &[char], mut at: usize) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let (w, after) = word(b, at);
        if !w.is_empty() {
            out.push(w);
            at = after;
        } else if b.get(at) == Some(&'{') {
            out.push("{..}".to_string());
            break;
        } else if b.get(at) == Some(&'*') {
            out.push("*".to_string());
            break;
        } else {
            break;
        }
        if starts(b, at, "::") {
            at += 2;
        } else {
            break;
        }
    }
    out
}

/// EVERY ROOT PATH A CELLS FILE NAMES: `(line, path)`, one per path per line, over the file with its
/// comments and literals blanked. Inline `mod` blocks are tracked so a `super::` is resolved from
/// the module it is written in: `k` supers from `d` inline modules deep stay in the file while
/// `k <= d`, reach the serve module at `k == d + 1` (where only `door_rig` may follow) and climb
/// past it beyond.
pub fn root_paths(src: &str) -> Vec<(usize, String)> {
    let mut lex = crate::scan::LexState::default();
    let blanked: Vec<String> = src
        .lines()
        .map(|l| crate::scan::blank_code(l, &mut lex))
        .collect();
    let b: Vec<char> = blanked.join("\n").chars().collect();
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut push = |line: usize, path: String| {
        if !out.iter().any(|(l, p)| *l == line && *p == path) {
            out.push((line, path));
        }
    };
    let (mut depth, mut line) = (0usize, 1usize);
    // The brace depth inside each open inline module.
    let mut mods: Vec<usize> = Vec::new();
    let mut pending_mod = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            '\n' => line += 1,
            '{' => {
                depth += 1;
                if pending_mod {
                    mods.push(depth);
                    pending_mod = false;
                }
            }
            '}' => {
                if mods.last() == Some(&depth) {
                    mods.pop();
                }
                depth = depth.saturating_sub(1);
            }
            ';' => pending_mod = false,
            _ if is_ident(c) && (i == 0 || !is_ident(b[i - 1])) => {
                let (w, after) = word(&b, i);
                match w.as_str() {
                    "mod" => {
                        let at = skip_blanks(&b, after);
                        let (name, mut k) = word(&b, at);
                        if !name.is_empty() {
                            while k < b.len() && b[k].is_whitespace() {
                                k += 1;
                            }
                            if b.get(k) == Some(&'{') {
                                pending_mod = true;
                            }
                        }
                    }
                    "crate" => {
                        let at = skip_blanks(&b, after);
                        if starts(&b, at, "::") {
                            let mut path = vec!["crate".to_string()];
                            path.extend(segments(&b, at + 2));
                            push(line, path.join("::"));
                        } else if word(&b, at).0 == "as" {
                            push(line, "crate".to_string());
                        }
                    }
                    "super" => {
                        let mut supers = 1usize;
                        let mut at = after;
                        while starts(&b, at, "::") {
                            let (next, past) = word(&b, at + 2);
                            if next != "super" {
                                break;
                            }
                            supers += 1;
                            at = past;
                        }
                        let inside = mods.len();
                        if supers > inside {
                            let climbed = vec!["super".to_string(); supers];
                            if starts(&b, at, "::") {
                                let rest = segments(&b, at + 2);
                                let to_rig = supers == inside + 1
                                    && rest.first().map(String::as_str) == Some(RIG);
                                if !to_rig {
                                    push(line, [climbed, rest].concat().join("::"));
                                }
                            } else if word(&b, skip_blanks(&b, at)).0 == "as" {
                                push(line, climbed.join("::"));
                            }
                        }
                        i = at;
                        continue;
                    }
                    _ => {}
                }
                i = after;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let cells = crate::libtest_path::door_cells(&|rel: &str| cx.read(rel).ok(), ROOT_FILE);
    if cells.is_empty() {
        errors.push(format!(
            "{ROOT_FILE}'s manifest names no plane-door row with cells; the scan has gone blind"
        ));
    }
    for (_, file) in &cells {
        match cx.read(file) {
            Ok(text) => {
                for (line, path) in root_paths(&text) {
                    findings.push(Finding::new(ROW_ROOT_PATH, file, path, line));
                }
            }
            Err(e) => errors.push(format!(
                "{file}: a door plane's root cells do not read ({e}); a door the gate cannot see is \
                 never judged clean"
            )),
        }
    }
    (findings, errors)
}

pub struct DoorCellsRigGate;

impl Gate for DoorCellsRigGate {
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
        // THE PLANTS GO INTO A DOOR'S CELLS THE TREE HOLDS: the first cells file the root's
        // manifest names that reads, so the plant is read exactly where the gate reads.
        let file: &'static str =
            match crate::libtest_path::door_cells(&|rel: &str| cx.read(rel).ok(), ROOT_FILE)
                .into_iter()
                .map(|(_, f)| f)
                .find(|f| cx.read(f).is_ok())
            {
                Some(f) => Box::leak(f.into_boxed_str()),
                None => {
                    let mut report = Report::new();
                    report.note_infra_failure(
                        "door-cells-rig selftest: the root names no door plane's cells that read",
                    );
                    return report;
                }
            };
        let text = cx.read(file).unwrap_or_default();
        let plant = |extra: &str| {
            let mut ov = Overlay::new();
            ov.set(file, format!("{text}\n{extra}"));
            ov
        };
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_ROOT_PATH,
                    "a cell naming a root struct by its crate:: path is RED, naming it",
                    plant("fn planted(e: &crate::root::serve::DoorEgress<'_>) { let _ = e; }\n"),
                    vec![file, "crate::root::serve::DoorEgress"],
                ),
                (
                    ROW_ROOT_PATH,
                    "a cell reaching the serve module past the rig through super:: is RED, naming it",
                    plant("use super::DoorEgress;\n"),
                    vec![file, "super::DoorEgress"],
                ),
                (
                    ROW_ROOT_PATH,
                    "an inline module climbing out of the cells file past the rig is RED, naming it",
                    plant("mod planted_inner {\n    use super::super::compose_planes;\n}\n"),
                    vec![file, "super::super::compose_planes"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "the rig's own paths, an inline module's own super::, and a root path in a comment or a \
             string are not findings",
            &[ROW_ROOT_PATH],
            plant(
                "use super::door_rig::EgressRig;\n\
                 use super::door_rig as rig;\n\
                 mod planted_inner {\n    use super::*;\n    use super::rig::ProcessRig;\n    \
                 use super::super::door_rig::DoorCompose;\n}\n\
                 // crate::root::serve::DoorEgress\n\
                 const PLANTED: &str = \"crate::root::serve::DoorEgress super::HookStage\";\n\
                 pub(crate) fn planted_vis() {}\n\
                 pub(super) fn planted_up() {}\n",
            ),
        ));
        report
    }
}
