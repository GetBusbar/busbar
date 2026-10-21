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
//! comments and literals blanked first ([`crate::scan::blank_code`]) and every ASCII blank and
//! newline dropped, so `crate ::x`, `super\n::x` and `super :: super :: x` read as the paths they are.
//!
//! FAIL CLOSED: a spelling the gate cannot read is refused, never passed. Four rows:
//!
//! * **`root-path`** — a `crate::` path, `crate as …` or `extern crate self` (the crate under an
//!   alias), at any depth; a `super::` path that climbs out of the cells file into the serve module
//!   (or past it) and does not name `door_rig` next; a bare `super` or `crate` not followed by `::`
//!   (a token a macro could paste into a path) other than the visibilities `pub(crate)`,
//!   `pub(super)` and `pub(in …)`; and a `use` declaration that does not parse as a plain use tree
//!   (a raw identifier, say). A `use` tree's groups are resolved by joining each leaf to its prefix
//!   (`super::{super::X}` is `super::super::X`). A `super::` that stays inside the cells file (an
//!   inline `mod` reaching its own parent) is no finding: inline modules are tracked, so `k` supers
//!   from `d` modules deep stay in the file while `k <= d`. A bare `self` is a method receiver or a
//!   value; it names the cells module itself, never the root, and climbs only through a `super`
//!   token, which is refused bare.
//! * **`unseen-source`** — code the root compiles into the cells that this gate does not read: a
//!   `mod` that is not a plain identifier opening an inline block (`mod x;`, `mod r#x`, `mod $x`), a
//!   `path = …` attribute (`cfg_attr` included), and any `include` token (`include!(…)`, an
//!   `include as …` alias, `include` handed to a macro).
//! * **`opaque-code`** — code the token reader cannot judge: a non-ASCII character outside a literal
//!   or comment (U+200E and U+200F are whitespace to rustc and to no ASCII reader), and
//!   `macro_rules!` (a macro body can paste `super` or `crate` into a path, shift the module depth
//!   the gate tracks, or carry a hygiene-scoped `use`).
//! * **`cells-path`** — the file read is not the one the plane's crate states: its `build.rs` must
//!   hold exactly the one canonical statement [`CELLS_STATEMENT`] (`CARGO_MANIFEST_DIR` joined with
//!   `tests/root/mod.rs`), the file the root's build compiles (`DEP_BUSBAR_DOOR_CELLS_<CRATE>_CELLS`),
//!   and name `cells` nowhere else in its code (no second `cargo::metadata=cells=` and no legacy
//!   `cargo:cells=`).
//!
//! A cells file that does not read is RED (`:ledger`). The sites the pinned cells still carry are
//! the COUNTED drain-only ledger `qa/door-cells-rig.toml` (Law 9: a count only goes down); they
//! drain when the root repins the a2a plane at its cells-on-the-rig change (busbar-plane-a2a #44),
//! which strikes every row in the same commit.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_ROOT_PATH: &str = "door-cells-rig:root-path";
pub const ROW_UNSEEN: &str = "door-cells-rig:unseen-source";
pub const ROW_OPAQUE: &str = "door-cells-rig:opaque-code";
pub const ROW_CELLS_PATH: &str = "door-cells-rig:cells-path";

/// The composition root's crate root, whose manifest names the door planes.
const ROOT_FILE: &str = "crates/busbar/src/main.rs";

/// The one root module a door plane's cells may name, as `super::door_rig` from the cells file.
const RIG: &str = "door_rig";

/// Where a plane crate's cells live, relative to its crate directory.
// qa-names: tests/root/mod.rs -- xtask/src/gates/door_cells_rig.rs -- CRATE-RELATIVE, not a repo path: it is joined to each door plane crate's directory (crates/<crate>/tests/root/mod.rs), so there is no such file at the repo root by design
const CELLS_REL: &str = "tests/root/mod.rs";

/// THE ONE STATEMENT a plane crate's `build.rs` states its cells with, blanks removed.
pub const CELLS_STATEMENT: &str = "println!(\"cargo::metadata=cells={}\",PathBuf::from(std::env::\
                                   var(\"CARGO_MANIFEST_DIR\")?).join(\"tests/root/mod.rs\").\
                                   display());";

/// The cells-path finding's item when the canonical statement holds and a `cargo:` key is built
/// from a format argument (`cargo_key_unreadable`), so that rule is proven red on its own.
const UNREADABLE_CARGO_KEY: &str = "build.rs sets a cargo: key built from a format argument";

/// The cells-path finding's item.
const ANOTHER_CELLS_PATH: &str =
    "build.rs states another cells path than the one canonical statement the gate reads";

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
             include)",
        ),
        (
            ROW_OPAQUE,
            "a door plane's root cells hold no code the gate cannot read (non-ASCII, macro_rules!)",
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

/// One token of a blanked cells file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    /// `::`
    Sep,
    /// Any other character, a non-ASCII one included.
    Punct(char),
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// One leaf of a `use` tree: its segments joined to every prefix above it, and the token its first
/// `super` or `crate` was written at (where its finding is named from).
struct Leaf {
    segs: Vec<String>,
    anchor: Option<usize>,
}

/// THE ONE READER: the file's comments and literals blanked, then every ASCII blank and newline
/// dropped, so no path reader below ever sees whitespace. Each token carries its 1-based line.
struct Stream {
    t: Vec<(Tok, usize)>,
}

impl Stream {
    fn new(src: &str) -> Stream {
        let mut lex = crate::scan::LexState::default();
        let mut t = Vec::new();
        for (n, raw) in src.lines().enumerate() {
            let line = n + 1;
            let b: Vec<char> = crate::scan::blank_code(raw, &mut lex).chars().collect();
            let mut i = 0;
            while i < b.len() {
                let c = b[i];
                if c.is_ascii_whitespace() {
                    i += 1;
                } else if is_ident_char(c) {
                    let start = i;
                    while i < b.len() && is_ident_char(b[i]) {
                        i += 1;
                    }
                    t.push((Tok::Ident(b[start..i].iter().collect()), line));
                } else if c == ':' && b.get(i + 1) == Some(&':') {
                    t.push((Tok::Sep, line));
                    i += 2;
                } else {
                    t.push((Tok::Punct(c), line));
                    i += 1;
                }
            }
        }
        Stream { t }
    }

    fn line(&self, at: usize) -> usize {
        self.t.get(at).map_or(0, |(_, l)| *l)
    }

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

    /// The path's segments from `at`: identifiers joined by `::`, a trailing group read as `{..}`
    /// and a glob as `*`.
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

    /// Is the keyword at `at` a visibility: `pub(<kw>)` or `pub(in <kw>)`?
    fn visibility(&self, at: usize) -> bool {
        self.is_punct(at + 1, ')')
            && ((at >= 2 && self.is_punct(at - 1, '(') && self.is_ident(at - 2, "pub"))
                || (at >= 3
                    && self.is_ident(at - 1, "in")
                    && self.is_punct(at - 2, '(')
                    && self.is_ident(at - 3, "pub")))
    }

    /// The `use` tree at `at` under `prefix`: where it ends and its leaves, each joined to its
    /// prefix. `None` when it is not a plain use tree (a raw identifier, a macro fragment).
    fn use_tree(
        &self,
        mut at: usize,
        prefix: &[String],
        mut anchor: Option<usize>,
    ) -> Option<(usize, Vec<Leaf>)> {
        let mut segs = prefix.to_vec();
        if self.is_sep(at) {
            segs.push(String::new());
            at += 1;
        }
        loop {
            if let Some(w) = self.ident(at) {
                if anchor.is_none() && (w == "super" || w == "crate") {
                    anchor = Some(at);
                }
                segs.push(w.to_string());
                at += 1;
                if self.is_sep(at) {
                    at += 1;
                    continue;
                }
                if self.is_ident(at, "as") {
                    self.ident(at + 1)?;
                    return Some((at + 2, vec![Leaf { segs, anchor }]));
                }
                return Some((at, vec![Leaf { segs, anchor }]));
            }
            if self.is_punct(at, '*') {
                segs.push("*".to_string());
                return Some((at + 1, vec![Leaf { segs, anchor }]));
            }
            if !self.is_punct(at, '{') {
                return None;
            }
            at += 1;
            let mut leaves = Vec::new();
            loop {
                if self.is_punct(at, '}') {
                    return Some((at + 1, leaves));
                }
                let (next, more) = self.use_tree(at, &segs, anchor)?;
                leaves.extend(more);
                at = next;
                if self.is_punct(at, ',') {
                    at += 1;
                } else if self.is_punct(at, '}') {
                    return Some((at + 1, leaves));
                } else {
                    return None;
                }
            }
        }
    }
}

/// Does a `use` leaf, resolved from `inside` inline modules deep, reach the root past the rig?
fn leaf_escapes(segs: &[String], inside: usize) -> bool {
    let s: Vec<&str> = segs
        .iter()
        .map(String::as_str)
        .filter(|x| !x.is_empty() && *x != "self")
        .collect();
    let k = s.iter().take_while(|x| **x == "super").count();
    s.contains(&"crate")
        || s[k..].contains(&"super")
        || (k > inside && !(k == inside + 1 && s.get(k) == Some(&RIG)))
}

/// EVERY FINDING IN ONE CELLS FILE: `(line, row, item)`, one per item per line.
pub fn cell_findings(src: &str) -> Vec<(usize, &'static str, String)> {
    let s = Stream::new(src);
    let n = s.t.len();
    let mut out: Vec<(usize, &'static str, String)> = Vec::new();
    let mut push = |line: usize, row: &'static str, item: String| {
        if !out
            .iter()
            .any(|(l, r, i)| *l == line && *r == row && *i == item)
        {
            out.push((line, row, item));
        }
    };

    // EVERY TOKEN, whatever it sits in (a `use` tree, an attribute, a macro's arguments).
    for (i, (tok, line)) in s.t.iter().enumerate() {
        match tok {
            Tok::Punct(c) if !c.is_ascii() => {
                push(
                    *line,
                    ROW_OPAQUE,
                    format!("non-ASCII U+{:04X}", u32::from(*c)),
                );
            }
            Tok::Ident(w) if w == "macro_rules" => {
                push(*line, ROW_OPAQUE, "macro_rules!".to_string());
            }
            Tok::Ident(w) if w == "include" => {
                let call = s.is_punct(i + 1, '!') && s.is_punct(i + 2, '(');
                let item = if call { "include!" } else { "include" };
                push(*line, ROW_UNSEEN, item.to_string());
            }
            // An attribute (`#[..]` or `#![..]`): a `path = …` anywhere in it, `cfg_attr` included.
            Tok::Punct('#') => {
                let mut j = i + 1;
                if s.is_punct(j, '!') {
                    j += 1;
                }
                if s.is_punct(j, '[') {
                    let mut open = 0usize;
                    while j < n {
                        if s.is_punct(j, '[') {
                            open += 1;
                        } else if s.is_punct(j, ']') {
                            open -= 1;
                            if open == 0 {
                                break;
                            }
                        } else if s.is_ident(j, "path") && s.is_punct(j + 1, '=') {
                            push(s.line(j), ROW_UNSEEN, "#[path]".to_string());
                        }
                        j += 1;
                    }
                }
            }
            _ => {}
        }
    }

    // THE STRUCTURE: inline modules, `use` trees and paths.
    let mut depth = 0usize;
    // The brace depth inside each open inline module.
    let mut mods: Vec<usize> = Vec::new();
    let mut pending_mod = false;
    let mut i = 0;
    while i < n {
        let line = s.line(i);
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
            Tok::Ident(w) => match w.as_str() {
                "mod" => match (
                    s.ident(i + 1),
                    s.is_punct(i + 2, '{'),
                    s.is_punct(i + 2, ';'),
                ) {
                    (Some(_), true, _) => pending_mod = true,
                    (Some(name), _, true) => push(line, ROW_UNSEEN, format!("mod {name};")),
                    _ => push(line, ROW_UNSEEN, "mod (unreadable)".to_string()),
                },
                "extern" if s.is_ident(i + 1, "crate") => {
                    if s.is_ident(i + 2, "self") {
                        push(line, ROW_ROOT_PATH, "extern crate self".to_string());
                    }
                    i += 3;
                    continue;
                }
                "use" => match s.use_tree(i + 1, &[], None) {
                    Some((end, leaves)) if s.is_punct(end, ';') => {
                        for leaf in leaves.iter().filter(|l| leaf_escapes(&l.segs, mods.len())) {
                            let at = leaf.anchor.unwrap_or(i + 1);
                            push(s.line(at), ROW_ROOT_PATH, s.segments(at).join("::"));
                        }
                        i = end;
                        continue;
                    }
                    _ => push(line, ROW_ROOT_PATH, "use (unreadable)".to_string()),
                },
                "crate" => {
                    if s.is_sep(i + 1) {
                        push(line, ROW_ROOT_PATH, s.segments(i).join("::"));
                    } else if !s.visibility(i) {
                        push(line, ROW_ROOT_PATH, "crate".to_string());
                    }
                }
                "super" => {
                    // `super` stands only at a path's start, or after `self::`.
                    if i >= 1 && s.is_sep(i - 1) && !(i >= 2 && s.is_ident(i - 2, "self")) {
                        push(line, ROW_ROOT_PATH, "super".to_string());
                        i += 1;
                        continue;
                    }
                    let mut supers = 1usize;
                    let mut at = i + 1;
                    while s.is_sep(at) && s.is_ident(at + 1, "super") {
                        supers += 1;
                        at += 2;
                    }
                    let inside = mods.len();
                    let climbed = vec!["super".to_string(); supers];
                    if s.is_sep(at) {
                        if supers > inside {
                            let rest = s.segments(at + 1);
                            let to_rig = supers == inside + 1
                                && rest.first().map(String::as_str) == Some(RIG);
                            if !to_rig {
                                push(line, ROW_ROOT_PATH, [climbed, rest].concat().join("::"));
                            }
                        }
                    } else if !(supers == 1 && s.visibility(i)) {
                        push(line, ROW_ROOT_PATH, climbed.join("::"));
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

/// What is wrong with the cells path a plane crate's `build.rs` states, if anything. Its code
/// (comments stripped, blanks removed) holds [`CELLS_STATEMENT`] exactly once, as a top-level
/// statement of `fn main` (`runs_in_main`); names `cells` nowhere else (no second or legacy
/// `cargo:cells=` line); and sets no `cargo:` key it builds at run time (`cargo_key_unreadable`).
pub fn stated_cells_problem(build: &str) -> Option<String> {
    let code: String = crate::scan::production_lines(build)
        .into_iter()
        .flat_map(|(_, l)| l.chars().filter(|c| !c.is_whitespace()).collect::<Vec<_>>())
        .collect();
    let stated: Vec<usize> = code
        .match_indices(CELLS_STATEMENT)
        .map(|(at, _)| at)
        .collect();
    let canonical = matches!(stated.as_slice(), [at] if runs_in_main(&code, *at));
    if !canonical || code.matches("cells").count() != 1 {
        return Some(ANOTHER_CELLS_PATH.to_string());
    }
    cargo_key_unreadable(&code).then(|| UNREADABLE_CARGO_KEY.to_string())
}

/// Does the statement at `at` run as a top-level statement of `fn main`: inside its body at depth
/// one (not in an `if`, a closure or a block), right after a statement boundary (`{`, `;` or `}`,
/// so no attribute or expression stands before it)? `code` is blank-free, its comments stripped;
/// braces inside string literals are not counted.
fn runs_in_main(code: &str, at: usize) -> bool {
    let Some(open) = code
        .find("fnmain(")
        .and_then(|main| code[main..].find('{').map(|o| main + o))
    else {
        return false;
    };
    if at <= open {
        return false;
    }
    let b = code.as_bytes();
    let (mut depth, mut in_str, mut escaped) = (0i32, false, false);
    for &c in &b[open..at] {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 1 && matches!(b[at - 1], b'{' | b';' | b'}')
}

/// Does any `cargo:` directive set a key the gate cannot read: one built by a format argument
/// (`"cargo:{}=…"`), or a directive with no literal key at all?
fn cargo_key_unreadable(code: &str) -> bool {
    code.match_indices("\"cargo:").any(|(at, _)| {
        let rest = &code[at + 7..];
        let rest = rest.strip_prefix(':').unwrap_or(rest);
        let rest = rest.strip_prefix("metadata=").unwrap_or(rest);
        let key = rest.split('=').next().unwrap_or("");
        key.contains('{') || key.contains('"')
    })
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
        let build_text = cx.read(build).unwrap_or_default();
        let rebuild = |edited: String| {
            let mut ov = Overlay::new();
            ov.set(build, edited);
            ov
        };
        let cells_lit = format!("\"{CELLS_REL}\"");
        let cases: Vec<(&'static str, &'static str, &'static str, &'static str)> = vec![
            (
                ROW_ROOT_PATH,
                "a cell naming a root struct by its crate:: path is RED, naming it",
                "fn planted(e: &crate::root::serve::DoorEgress<'_>) { let _ = e; }\n",
                "crate::root::serve::DoorEgress",
            ),
            (
                ROW_ROOT_PATH,
                "a cell reaching the serve module past the rig through super:: is RED, naming it",
                "use super::DoorEgress;\n",
                "super::DoorEgress",
            ),
            (
                ROW_ROOT_PATH,
                "an inline module climbing out of the cells file past the rig is RED, naming it",
                "mod planted_inner {\n    use super::super::compose_planes;\n}\n",
                "super::super::compose_planes",
            ),
            (
                ROW_ROOT_PATH,
                "a blank before a super path's :: hides nothing (`super ::X`)",
                "use super ::StreamFramers;\n",
                "super::StreamFramers",
            ),
            (
                ROW_ROOT_PATH,
                "a newline between super and :: hides nothing",
                "use super\n::HookStage;\n",
                "super::HookStage",
            ),
            (
                ROW_ROOT_PATH,
                "a spaced super chain from an inline module hides nothing (`super :: super :: y`)",
                "mod planted_spaced {\n    use super :: super :: LateServices;\n}\n",
                "super::super::LateServices",
            ),
            (
                ROW_ROOT_PATH,
                "a newline between crate and :: hides nothing",
                "use crate\n    ::root::serve::Served;\n",
                "crate::root::serve::Served",
            ),
            (
                ROW_ROOT_PATH,
                "extern crate self under an alias is the crate by another name, and RED",
                "extern crate self as planted_me;\n\
                 fn planted_alias() { planted_me::root::planted(); }\n",
                "extern crate self",
            ),
            (
                ROW_ROOT_PATH,
                "extern crate self inside an inline module is RED as well",
                "mod planted_nested {\n    extern crate self as planted_deep;\n}\n",
                "extern crate self",
            ),
            (
                ROW_ROOT_PATH,
                "a use group joins its prefix: super::{super::X} from an inline module is RED",
                "mod planted_group {\n    use super::{super::DoorEgress};\n}\n",
                "super::{..}",
            ),
            (
                ROW_ROOT_PATH,
                "a bare super handed to a macro is RED (it pastes into a path)",
                "fn planted_tt() { let _ = planted_up!(super); }\n",
                "super",
            ),
            (
                ROW_ROOT_PATH,
                "a bare crate handed to a macro is RED (it pastes into a path)",
                "type PlantedT = planted_up!(crate);\n",
                "crate",
            ),
            (
                ROW_ROOT_PATH,
                "a raw identifier in a use declaration is RED: the tree does not read",
                "use self::r#planted::X;\n",
                "use (unreadable)",
            ),
            (
                ROW_UNSEEN,
                "a file-backed mod in a cells file is RED: the gate does not read it",
                "mod planted_file;\n",
                "mod planted_file;",
            ),
            (
                ROW_UNSEEN,
                "a raw-identifier mod in a cells file is RED: the gate does not read it",
                "mod r#planted_evil;\n",
                "mod (unreadable)",
            ),
            (
                ROW_UNSEEN,
                "mod r#helpers; (a raw-identifier file-backed mod) is RED",
                "mod r#helpers;\n",
                "mod (unreadable)",
            ),
            (
                ROW_UNSEEN,
                "a mod whose name a macro pastes in is RED: the gate does not read it",
                "planted_m! { mod $planted; }\n",
                "mod (unreadable)",
            ),
            (
                ROW_UNSEEN,
                "a path attribute in a cells file is RED: the gate does not read its file",
                "#[cfg_attr(test, path = \"elsewhere.rs\")]\nmod planted_at {}\n",
                "#[path]",
            ),
            (
                ROW_UNSEEN,
                "an include! in a cells file is RED: the gate does not read what it pulls in",
                "include!(\"elsewhere.rs\");\n",
                "include!",
            ),
            (
                ROW_UNSEEN,
                "include under an alias is RED (use core::include as …)",
                "use core::include as planted_inc;\nplanted_inc!(\"elsewhere.rs\");\n",
                "include",
            ),
            (
                ROW_UNSEEN,
                "include aliased from std is RED (use std::include as …)",
                "use std::include as planted_std_inc;\nplanted_std_inc!(\"elsewhere.rs\");\n",
                "include",
            ),
            (
                ROW_UNSEEN,
                "include imported under its own name is RED (use core::include;)",
                "use core::include;\n",
                "include",
            ),
            (
                ROW_UNSEEN,
                "include handed to a macro is RED",
                "planted_i!(include);\n",
                "include",
            ),
            (
                ROW_OPAQUE,
                "a left-to-right mark (rustc whitespace) between super and :: is RED",
                "use super\u{200E}::DoorEgress;\n",
                "U+200E",
            ),
            (
                ROW_OPAQUE,
                "a right-to-left mark (rustc whitespace) between crate and :: is RED",
                "use crate\u{200F}::root::serve::Served;\n",
                "U+200F",
            ),
            (
                ROW_OPAQUE,
                "macro_rules! in a cells file is RED (a body can paste super into a path)",
                "macro_rules! planted_up { ($a:tt) => { $a::DoorEgress } }\n",
                "macro_rules!",
            ),
            (
                ROW_OPAQUE,
                "a macro_use module's hygiene-scoped use is RED through its macro_rules!",
                "#[macro_use]\nmod planted_a {\n    macro_rules! planted_up { () => { use super::DoorEgress; } }\n}\nplanted_up!();\n",
                "macro_rules!",
            ),
        ];
        let mut plants: Vec<(&'static str, &'static str, Overlay, Vec<&'static str>)> = cases
            .into_iter()
            .map(|(row, name, extra, item)| (row, name, plant(extra), vec![file, item]))
            .collect();
        plants.push((
            ROW_CELLS_PATH,
            "a plane whose build.rs states other cells than the file the gate reads is RED",
            rebuild(build_text.replace(&cells_lit, "\"tests/root/elsewhere.rs\"")),
            vec![build, "another cells path"],
        ));
        plants.push((
            ROW_CELLS_PATH,
            "a canonical-looking cells statement moved off by with_file_name is RED",
            rebuild(build_text.replace(
                &format!(".join({cells_lit})"),
                &format!(".join({cells_lit}).with_file_name(\"other.rs\")"),
            )),
            vec![build, "another cells path"],
        ));
        plants.push((
            ROW_CELLS_PATH,
            "a second, legacy cargo:cells= line beside the canonical one is RED",
            rebuild(format!(
                "{build_text}\nfn planted_legacy() {{\n    println!(\"cargo:cells=/elsewhere.rs\");\n}}\n"
            )),
            vec![build, "another cells path"],
        ));
        plants.push((
            ROW_CELLS_PATH,
            "a format suffix on the canonical cells statement is RED",
            rebuild(build_text.replace("cells={}\"", "cells={}.bak\"")),
            vec![build, "another cells path"],
        ));
        // The canonical statement, unchanged, inside `if false { }`: it never runs.
        let never_runs = build_text
            .find("\"cargo::metadata=cells=")
            .and_then(|lit| {
                let start = build_text[..lit].rfind("println!")?;
                let end = lit + build_text[lit..].find(");")? + 2;
                Some(format!(
                    "{}if false {{ {} }}{}",
                    &build_text[..start],
                    &build_text[start..end],
                    &build_text[end..]
                ))
            })
            .unwrap_or_else(|| build_text.clone());
        plants.push((
            ROW_CELLS_PATH,
            "the canonical cells statement inside `if false {}` is RED: it never runs",
            rebuild(never_runs),
            vec![build, "another cells path"],
        ));
        // The canonical statement untouched and `cells` still named once: only the format-built key
        // is wrong, so the red is `cargo_key_unreadable`'s alone (its own item).
        plants.push((
            ROW_CELLS_PATH,
            "a cargo: key built from a format argument beside the canonical statement is RED",
            rebuild(format!(
                "{build_text}\nfn planted_key() {{\n    let key = concat!(\"ce\", \"lls\");\n    \
                 println!(\"cargo::metadata={{}}=/elsewhere.rs\", key);\n}}\n"
            )),
            vec![build, UNREADABLE_CARGO_KEY],
        ));
        let mut report = one_abi::selftest(cx, self, &SPEC, plants);
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "the rig's own paths, an inline module's own super::, a method's self, visibilities, \
             and a root path in a comment or a string are not findings",
            &[ROW_ROOT_PATH, ROW_UNSEEN, ROW_OPAQUE, ROW_CELLS_PATH],
            plant(
                "use super::door_rig::EgressRig;\n\
                 use super :: door_rig as rig;\n\
                 use super::{door_rig::{DoorStore, ProcessRig}};\n\
                 mod planted_inner {\n    use super::*;\n    use super::rig::ProcessRig;\n    \
                 use super::super::door_rig::DoorCompose;\n    use self::super::rig::DoorStore;\n}\n\
                 // crate::root::serve::DoorEgress mod planted; include!(x) macro_rules! \u{200E}\n\
                 const PLANTED: &str = \"crate::root::serve::DoorEgress super::HookStage mod x; \u{200F}\";\n\
                 pub(crate) fn planted_vis() {}\n\
                 pub(super) fn planted_up() {}\n\
                 pub(in super) fn planted_in() {}\n\
                 extern crate std as planted_std;\n\
                 struct PlantedS { inner: u8 }\n\
                 impl PlantedS { fn planted(&self) -> u8 { self.inner } }\n",
            ),
        ));
        report
    }
}
