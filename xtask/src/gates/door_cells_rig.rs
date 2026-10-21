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
//! The gate reads every door plane's cells, the files `DOOR_CELLS_FILES` cites
//! ([`crate::libtest_path::door_cells`]: every `plane-door` row of the root's
//! `[package.metadata.busbar.linked]`, a pinned plane read from the checkout `Cargo.lock` pins, laid
//! at its census mount, and an in-tree one at its path). Each file is read as ONE TOKEN STREAM, its
//! comments and literals blanked first ([`crate::scan::blank_code`]) and every blank and newline
//! dropped, so `crate ::x`, `super\n::x` and `super :: super :: x` read as the paths they are. Three
//! rows:
//!
//! * **`root-path`** — a `crate::` path, `crate as …` or `extern crate self` (the crate under an
//!   alias), at any depth; or a `super::` path that climbs out of the cells file into the serve
//!   module (or past it) and does not name `door_rig` next. A `super::` that stays inside the cells
//!   file (an inline `mod` reaching its own parent) is no finding: inline modules are tracked, so
//!   `k` supers from `d` modules deep stay in the file while `k <= d`.
//! * **`unseen-source`** — a file-backed `mod x;`, a `path = …` attribute or an `include!(…)`: code
//!   the root compiles into the cells that this gate does not read. The gate never judges a door it
//!   could not see.
//! * **`cells-path`** — the file read is not the one the plane's crate states: its `build.rs` prints
//!   `cargo::metadata=cells=` as `CARGO_MANIFEST_DIR` joined with `tests/root/mod.rs` and nothing
//!   else, which is the file the root's build compiles (`DEP_BUSBAR_DOOR_CELLS_<CRATE>_CELLS`).
//!
//! A cells file that does not read is RED (`:ledger`). The sites the pinned cells still carry are
//! the COUNTED drain-only ledger `qa/door-cells-rig.toml` (Law 9: a count only goes down); they
//! drain when the root repins the a2a plane at its cells-on-the-rig change (busbar-plane-a2a #44),
//! which strikes every row in the same commit.
//!
//! KNOWN LIMIT: the reader is a token scan, not a macro expander. A hostile `macro_rules!` whose
//! body carries unbalanced-looking braces or a `mod … {` can shift the inline-module depth the
//! scan tracks, so a `super::` after it may read as staying inside the cells file. A cells file is
//! reviewed source in a plane's own repository, and no cell today defines such a macro.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_ROOT_PATH: &str = "door-cells-rig:root-path";
pub const ROW_UNSEEN: &str = "door-cells-rig:unseen-source";
pub const ROW_CELLS_PATH: &str = "door-cells-rig:cells-path";

/// The composition root's crate root, whose manifest names the door planes.
const ROOT_FILE: &str = "crates/busbar/src/main.rs";

/// The one root module a door plane's cells may name, as `super::door_rig` from the cells file.
const RIG: &str = "door_rig";

/// Where a plane crate's cells live, relative to its crate directory.
const CELLS_REL: &str = "tests/root/mod.rs";

/// The metadata line a plane crate's `build.rs` states its cells under.
const CELLS_METADATA: &str = "cargo::metadata=cells=";

pub const SPEC: Spec = Spec {
    gate: "door-cells-rig",
    ledger: "qa/door-cells-rig.toml",
    rules: &[
        (
            ROW_ROOT_PATH,
            "a door plane's root cells name the composition root through super::door_rig alone",
        ),
        (
            ROW_UNSEEN,
            "a door plane's root cells pull in no source the gate does not read (mod x;, path =, \
             include!)",
        ),
        (
            ROW_CELLS_PATH,
            "the cells file the gate reads is the one the plane's build.rs states",
        ),
    ],
    header: "# door-cells-rig: DRAIN-ONLY ledger (ARCHITECT ruling on #464; Law 9, BUSBAR-1.6.0.md).\n\
             # A door plane's own root cells (its crate's tests/root/mod.rs, compiled into\n\
             # root::serve) name the composition root through super::door_rig alone. Each row is a\n\
             # root path a pinned plane's cells still name, COUNTED (one per line); the a2a rows\n\
             # drain when the root repins busbar-plane-a2a at its cells-on-the-rig change\n\
             # (busbar-plane-a2a #44), which strikes them in the same commit. Never add a row or\n\
             # raise a count. Regenerate with `cargo xtask gate door-cells-rig --write`.\n",
};

/// One token of a blanked cells file, with its 1-based line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    /// `::`
    Sep,
    Punct(char),
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// THE ONE READER: the file's comments and literals blanked, then every blank and newline
/// dropped, so no path reader below ever sees whitespace.
fn tokens(src: &str) -> Vec<(Tok, usize)> {
    let mut lex = crate::scan::LexState::default();
    let mut out = Vec::new();
    for (n, raw) in src.lines().enumerate() {
        let line = n + 1;
        let b: Vec<char> = crate::scan::blank_code(raw, &mut lex).chars().collect();
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            if c.is_whitespace() {
                i += 1;
            } else if is_ident(c) {
                let start = i;
                while i < b.len() && is_ident(b[i]) {
                    i += 1;
                }
                out.push((Tok::Ident(b[start..i].iter().collect()), line));
            } else if c == ':' && b.get(i + 1) == Some(&':') {
                out.push((Tok::Sep, line));
                i += 2;
            } else {
                out.push((Tok::Punct(c), line));
                i += 1;
            }
        }
    }
    out
}

struct Stream {
    t: Vec<(Tok, usize)>,
}

impl Stream {
    fn ident(&self, at: usize) -> Option<&str> {
        match self.t.get(at) {
            Some((Tok::Ident(w), _)) => Some(w.as_str()),
            _ => None,
        }
    }

    fn is_ident(&self, at: usize, word: &str) -> bool {
        self.ident(at) == Some(word)
    }

    fn is_sep(&self, at: usize) -> bool {
        matches!(self.t.get(at), Some((Tok::Sep, _)))
    }

    fn is_punct(&self, at: usize, c: char) -> bool {
        matches!(self.t.get(at), Some((Tok::Punct(p), _)) if *p == c)
    }

    /// The path's segments from `at` (just past a `::`): identifiers joined by `::`, a trailing
    /// group read as `{..}` and a glob as `*`.
    fn segments(&self, mut at: usize) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            if let Some(w) = self.ident(at) {
                out.push(w.to_string());
                at += 1;
            } else if self.is_punct(at, '{') {
                out.push("{..}".to_string());
                break;
            } else if self.is_punct(at, '*') {
                out.push("*".to_string());
                break;
            } else {
                break;
            }
            if self.is_sep(at) {
                at += 1;
            } else {
                break;
            }
        }
        out
    }
}

/// EVERY FINDING IN ONE CELLS FILE: `(line, row, item)`, one per item per line.
pub fn cell_findings(src: &str) -> Vec<(usize, &'static str, String)> {
    let s = Stream { t: tokens(src) };
    let mut out: Vec<(usize, &'static str, String)> = Vec::new();
    let mut push = |line: usize, row: &'static str, item: String| {
        if !out
            .iter()
            .any(|(l, r, i)| *l == line && *r == row && *i == item)
        {
            out.push((line, row, item));
        }
    };
    let mut depth = 0usize;
    // The brace depth inside each open inline module.
    let mut mods: Vec<usize> = Vec::new();
    let mut pending_mod = false;
    let mut i = 0;
    while i < s.t.len() {
        let line = s.t[i].1;
        match &s.t[i].0 {
            Tok::Punct('{') => {
                depth += 1;
                if pending_mod {
                    mods.push(depth);
                    pending_mod = false;
                }
            }
            Tok::Punct('}') => {
                if mods.last() == Some(&depth) {
                    mods.pop();
                }
                depth = depth.saturating_sub(1);
            }
            Tok::Punct(';') => pending_mod = false,
            // An attribute (`#[..]` or `#![..]`): a `path = …` anywhere in it, `cfg_attr` included.
            Tok::Punct('#') => {
                let mut j = i + 1;
                if s.is_punct(j, '!') {
                    j += 1;
                }
                if s.is_punct(j, '[') {
                    let mut open = 0usize;
                    while j < s.t.len() {
                        if s.is_punct(j, '[') {
                            open += 1;
                        } else if s.is_punct(j, ']') {
                            open -= 1;
                            if open == 0 {
                                break;
                            }
                        } else if s.is_ident(j, "path") && s.is_punct(j + 1, '=') {
                            push(s.t[j].1, ROW_UNSEEN, "#[path]".to_string());
                        }
                        j += 1;
                    }
                }
            }
            Tok::Ident(w) => match w.as_str() {
                "mod" => {
                    if let Some(name) = s.ident(i + 1) {
                        if s.is_punct(i + 2, ';') {
                            push(line, ROW_UNSEEN, format!("mod {name};"));
                        } else if s.is_punct(i + 2, '{') {
                            pending_mod = true;
                        }
                    }
                }
                "include" if s.is_punct(i + 1, '!') => {
                    push(line, ROW_UNSEEN, "include!".to_string());
                }
                "extern" if s.is_ident(i + 1, "crate") && s.is_ident(i + 2, "self") => {
                    push(line, ROW_ROOT_PATH, "extern crate self".to_string());
                    i += 3;
                    continue;
                }
                "crate" => {
                    if s.is_sep(i + 1) {
                        let mut path = vec!["crate".to_string()];
                        path.extend(s.segments(i + 2));
                        push(line, ROW_ROOT_PATH, path.join("::"));
                    } else if s.is_ident(i + 1, "as") {
                        push(line, ROW_ROOT_PATH, "crate".to_string());
                    }
                }
                // `super` stands only at a path's start, or after `self::`.
                "super"
                    if !(i >= 1 && s.is_sep(i - 1)) || (i >= 2 && s.is_ident(i - 2, "self")) =>
                {
                    let mut supers = 1usize;
                    let mut at = i + 1;
                    while s.is_sep(at) && s.is_ident(at + 1, "super") {
                        supers += 1;
                        at += 2;
                    }
                    let inside = mods.len();
                    if supers > inside {
                        let climbed = vec!["super".to_string(); supers];
                        if s.is_sep(at) {
                            let rest = s.segments(at + 1);
                            let to_rig = supers == inside + 1
                                && rest.first().map(String::as_str) == Some(RIG);
                            if !to_rig {
                                push(line, ROW_ROOT_PATH, [climbed, rest].concat().join("::"));
                            }
                        } else if s.is_ident(at, "as") {
                            push(line, ROW_ROOT_PATH, climbed.join("::"));
                        }
                    }
                    i = at;
                    continue;
                }
                _ => {}
            },
            _ => {}
        }
        i += 1;
    }
    out
}

/// What is wrong with the cells path a plane crate's `build.rs` states, if anything: it must print
/// [`CELLS_METADATA`] once, as `CARGO_MANIFEST_DIR` joined with [`CELLS_REL`] alone.
pub fn stated_cells_problem(build: &str) -> Option<String> {
    let code: String = crate::scan::production_lines(build)
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    let stated: Vec<&str> = code.split(CELLS_METADATA).skip(1).collect();
    let [statement] = stated.as_slice() else {
        return Some(format!(
            "build.rs states {} cells path(s), not one",
            stated.len()
        ));
    };
    let statement: String = statement
        .split(';')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let at_manifest = statement.contains("var(\"CARGO_MANIFEST_DIR\")");
    let one_join = statement.matches(".join(").count() == 1;
    let at_cells = statement.contains(&format!(".join(\"{CELLS_REL}\")"));
    (!(at_manifest && one_join && at_cells))
        .then(|| "build.rs states another cells path than the one the gate reads".to_string())
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
                for (line, row, item) in cell_findings(&text) {
                    findings.push(Finding::new(row, file, item, line));
                }
            }
            Err(e) => errors.push(format!(
                "{file}: a door plane's root cells do not read ({e}); a door the gate cannot see is \
                 never judged clean"
            )),
        }
        let Some(dir) = file.strip_suffix(&format!("/{CELLS_REL}")) else {
            findings.push(Finding::new(
                ROW_CELLS_PATH,
                file,
                "the cells file is not at its crate's tests/root/mod.rs",
                0,
            ));
            continue;
        };
        let build = format!("{dir}/build.rs");
        match cx.read(&build) {
            Ok(text) => {
                if let Some(problem) = stated_cells_problem(&text) {
                    findings.push(Finding::new(ROW_CELLS_PATH, &build, problem, 0));
                }
            }
            Err(_) => findings.push(Finding::new(
                ROW_CELLS_PATH,
                &build,
                "no build.rs states the cells path",
                0,
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
        let build: &'static str = Box::leak(
            format!(
                "{}/build.rs",
                file.strip_suffix(&format!("/{CELLS_REL}")).unwrap_or(file)
            )
            .into_boxed_str(),
        );
        let text = cx.read(file).unwrap_or_default();
        let plant = |extra: &str| {
            let mut ov = Overlay::new();
            ov.set(file, format!("{text}\n{extra}"));
            ov
        };
        let mut moved = Overlay::new();
        moved.set(
            build,
            cx.read(build)
                .unwrap_or_default()
                .replace(&format!("\"{CELLS_REL}\""), "\"tests/root/elsewhere.rs\""),
        );
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
                (
                    ROW_ROOT_PATH,
                    "a blank before a super path's :: hides nothing (`super ::X`)",
                    plant("use super ::StreamFramers;\n"),
                    vec![file, "super::StreamFramers"],
                ),
                (
                    ROW_ROOT_PATH,
                    "a newline between super and :: hides nothing",
                    plant("use super\n::HookStage;\n"),
                    vec![file, "super::HookStage"],
                ),
                (
                    ROW_ROOT_PATH,
                    "a spaced super chain from an inline module hides nothing (`super :: super :: y`)",
                    plant("mod planted_spaced {\n    use super :: super :: LateServices;\n}\n"),
                    vec![file, "super::super::LateServices"],
                ),
                (
                    ROW_ROOT_PATH,
                    "a newline between crate and :: hides nothing",
                    plant("use crate\n    ::root::serve::Served;\n"),
                    vec![file, "crate::root::serve::Served"],
                ),
                (
                    ROW_ROOT_PATH,
                    "extern crate self under an alias is the crate by another name, and RED",
                    plant(
                        "extern crate self as planted_me;\n\
                         fn planted_alias() { planted_me::root::planted(); }\n",
                    ),
                    vec![file, "extern crate self"],
                ),
                (
                    ROW_ROOT_PATH,
                    "extern crate self inside an inline module is RED as well",
                    plant("mod planted_nested {\n    extern crate self as planted_deep;\n}\n"),
                    vec![file, "extern crate self"],
                ),
                (
                    ROW_UNSEEN,
                    "a file-backed mod in a cells file is RED: the gate does not read it",
                    plant("mod planted_file;\n"),
                    vec![file, "mod planted_file;"],
                ),
                (
                    ROW_UNSEEN,
                    "a path attribute in a cells file is RED: the gate does not read its file",
                    plant("#[cfg_attr(test, path = \"elsewhere.rs\")]\nmod planted_at {}\n"),
                    vec![file, "#[path]"],
                ),
                (
                    ROW_UNSEEN,
                    "an include! in a cells file is RED: the gate does not read what it pulls in",
                    plant("include!(\"elsewhere.rs\");\n"),
                    vec![file, "include!"],
                ),
                (
                    ROW_CELLS_PATH,
                    "a plane whose build.rs states other cells than the file the gate reads is RED",
                    moved,
                    vec![build, "another cells path"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "the rig's own paths, an inline module's own super::, and a root path in a comment or a \
             string are not findings",
            &[ROW_ROOT_PATH, ROW_UNSEEN, ROW_CELLS_PATH],
            plant(
                "use super::door_rig::EgressRig;\n\
                 use super :: door_rig as rig;\n\
                 mod planted_inner {\n    use super::*;\n    use super::rig::ProcessRig;\n    \
                 use super::super::door_rig::DoorCompose;\n    use self::super::rig::DoorStore;\n}\n\
                 // crate::root::serve::DoorEgress mod planted; include!(x)\n\
                 const PLANTED: &str = \"crate::root::serve::DoorEgress super::HookStage mod x;\";\n\
                 pub(crate) fn planted_vis() {}\n\
                 pub(super) fn planted_up() {}\n\
                 extern crate std as planted_std;\n",
            ),
        ));
        report
    }
}
