//! `teller-steps` — THE TELLER STEP MATRIX: one cell per Teller step per plane, and a second,
//! independent verdict per cell taken over the composition root's own legs.
//!
//! Ported from `scripts/teller-steps-check.py`. Five rules, five owed rows, and the shape of each
//! is the shape the Python enforced — including the three floors that are the whole reason the
//! check is not a formality:
//!
//! * **every plane carries every declared step.** A matrix that dropped a step would be green with
//!   fewer cells, which is the cheapest possible way to close a gap.
//! * **every root leg proves at least one step.** A leg with no watched cell is a leg nobody drove,
//!   and it reads exactly like a leg that passed.
//! * **a claim may not outlive its evidence.** A named rig cell must be owned by something in the
//!   tree, and a named loop cell must exist as an `fn` in the leg's own file — the two ways a
//!   renamed test leaves a green row pointing at nothing.
//!
//! Plus `MIN_ROOT_NOTE`: every root verdict, proven OR gap, owes a one-line argument of at least 60
//! characters. A label is not an argument, and `"not yet"` was the shape that rule was written
//! against.
//!
//! THE STEP ORDER IS THE FILE'S KEY ORDER. `list(steps)` in the Python is the render sequence, so
//! this module reads the matrix through [`crate::json_lite`], which keeps it, and never through a
//! reader that sorts.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Edit, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::json_lite::{self, Json};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;

pub const LEDGER_REL: &str = "qa/teller-steps.json";
const ROOT_DIR: &str = "crates/busbar/src/root/";
const MANIFEST_REL: &str = "crates/busbar/Cargo.toml";

/// A root verdict owes an ARGUMENT, not a label. Sixty characters is the width `"not yet"` fails
/// and a sentence someone could disagree with passes. It is a `const` here with no environment
/// override on purpose: the only way to lower a floor is a reviewable source edit.
///
/// A CHARACTER COUNT IS NOT A CONTENT CHECK, and on its own this one was the whole rule. Sixty
/// characters is cleared by `"aaaaaaaa…"`, by `"not yet not yet not yet not yet not yet not yet"`,
/// and — the shape that actually happens — by ONE boilerplate sentence pasted into all fifty cells,
/// which reads as fifty arguments and is one. Each of those is a label wearing a sentence's length.
/// [`note_problem`] below adds the three cheap properties that separate an argument from padding,
/// and every floor here is a `const` for the same reviewable-edit reason.
const MIN_ROOT_NOTE: usize = 60;

/// An argument is made of words. The committed matrix's thinnest note runs fourteen.
const MIN_ROOT_NOTE_WORDS: usize = 8;

/// …and of DIFFERENT words: repeating one phrase to reach a length is the cheapest way to clear a
/// count. The committed matrix's thinnest note carries twelve distinct words.
const MIN_ROOT_NOTE_DISTINCT_WORDS: usize = 7;

/// No character may run longer than this. Padding to a length is a run; English is not. The
/// committed matrix's longest run is two (`ll`, `ss`, …).
const MAX_ROOT_NOTE_CHAR_RUN: usize = 4;

/// The content half of the note rule: what a note must be BEYOND long enough. Returns the sentence
/// naming the defect, or `None` when the note argues something.
///
/// Uniqueness is NOT here — it is a property of the note against every OTHER note in the matrix,
/// so it is checked by the caller, which is the only place that can see them all.
fn note_problem(note: &str) -> Option<String> {
    if note.chars().count() < MIN_ROOT_NOTE {
        return Some(format!(
            "every root verdict owes a one-line argument (>= {MIN_ROOT_NOTE} chars), a proof as \
             much as a gap"
        ));
    }
    let words: Vec<String> = note
        .split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect();
    if words.len() < MIN_ROOT_NOTE_WORDS {
        return Some(format!(
            "an argument is made of words, and this one has {} (>= {MIN_ROOT_NOTE_WORDS} owed). A \
             character count alone is cleared by padding",
            words.len()
        ));
    }
    let distinct: BTreeSet<&str> = words.iter().map(String::as_str).collect();
    if distinct.len() < MIN_ROOT_NOTE_DISTINCT_WORDS {
        return Some(format!(
            "{} distinct word(s) across {} (>= {MIN_ROOT_NOTE_DISTINCT_WORDS} owed): repeating one \
             phrase to reach a length is a label, not an argument",
            distinct.len(),
            words.len()
        ));
    }
    let mut run = 0usize;
    let mut prev = None;
    for c in note.chars() {
        run = if Some(c) == prev { run + 1 } else { 1 };
        if run > MAX_ROOT_NOTE_CHAR_RUN {
            return Some(format!(
                "the character {c:?} runs {run} times: padding to a length is a run, English is not"
            ));
        }
        prev = Some(c);
    }
    None
}

const STATUSES: [&str; 3] = ["mapped", "new", "none"];
const ROOT_STATES: [&str; 2] = ["none", "proven"];

pub const ROW_MATRIX: &str = "teller-steps:matrix";
pub const ROW_RIG: &str = "teller-steps:rig-cells";
pub const ROW_ROOT_COLUMN: &str = "teller-steps:root-column";
pub const ROW_ROOT_LEGS: &str = "teller-steps:root-legs";
pub const ROW_GATING: &str = "teller-steps:gating-gaps";

// -------------------------------------------------------------------------------------------
// The matrix
// -------------------------------------------------------------------------------------------

/// The matrix as the checks read it. `steps` and each plane row keep their file order because the
/// render is order-sensitive and the Python's is the file's.
pub struct Matrix {
    doc: Json,
}

impl Matrix {
    pub fn steps(&self) -> &Json {
        self.doc.get("steps")
    }

    pub fn matrix(&self) -> &Json {
        self.doc.get("matrix")
    }

    pub fn root_legs(&self) -> &Json {
        self.doc.get("root_legs")
    }

    /// The declared step order — the file's key order, which is the render sequence.
    pub fn step_order(&self) -> Vec<String> {
        self.steps()
            .as_object()
            .map(|o| o.keys().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// The plane rows, SORTED — `sorted(matrix)` in the Python, and the order every message and
    /// every rendered line comes out in.
    pub fn planes(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .matrix()
            .as_object()
            .map(|o| o.keys().map(str::to_string).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    fn cell(&self, plane: &str, step: &str) -> &Json {
        self.matrix().get(plane).get(step)
    }
}

/// Parse and STRUCTURALLY validate the matrix, in the Python's order and with its messages.
///
/// The order is load-bearing: `matrix.{plane} is missing step(s) …` must fire before any per-cell
/// rule, because a matrix that dropped a step has fewer cells for every later rule to judge and
/// would otherwise read as a cleaner matrix rather than a shorter one.
pub fn load(cx: &Ctx) -> Result<Matrix, String> {
    let text = cx
        .read(LEDGER_REL)
        .map_err(|e| format!("{LEDGER_REL}: {e}"))?;
    let doc = json_lite::parse(&text).map_err(|e| format!("{LEDGER_REL}: {e}"))?;

    let steps = doc.get("steps");
    if !steps.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        return Err(format!("{LEDGER_REL}: no non-empty 'steps' object"));
    }
    let matrix = doc.get("matrix");
    if !matrix.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        return Err(format!("{LEDGER_REL}: no non-empty 'matrix' object"));
    }

    let steps_obj = steps.as_object().expect("checked above");
    for step in steps_obj.keys() {
        if !steps
            .get(step)
            .as_object()
            .is_some_and(|o| o.contains_key("gating"))
        {
            return Err(format!(
                "{LEDGER_REL}: steps.{step} has no 'gating' boolean"
            ));
        }
    }

    let declared: BTreeSet<String> = steps_obj.keys().map(str::to_string).collect();
    let mut planes: Vec<&str> = matrix.as_object().expect("checked above").keys().collect();
    planes.sort_unstable();

    for plane in planes {
        let row = matrix.get(plane);
        let Some(row_obj) = row.as_object() else {
            return Err(format!("{LEDGER_REL}: matrix.{plane} is not an object"));
        };
        let present: BTreeSet<String> = row_obj.keys().map(str::to_string).collect();
        let missing: Vec<&String> = declared.difference(&present).collect();
        if !missing.is_empty() {
            return Err(format!(
                "{LEDGER_REL}: matrix.{plane} is missing step(s) {}",
                py_list(missing.into_iter().map(String::as_str))
            ));
        }
        for step in row_obj.keys() {
            if !declared.contains(step) {
                return Err(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step} names an undeclared step"
                ));
            }
            let cell = row.get(step);
            let (Some(cell_id), Some(status)) =
                (cell.get("cell").as_str(), cell.get("status").as_str())
            else {
                return Err(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step} has no cell/status"
                ));
            };
            if !STATUSES.contains(&status) {
                return Err(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step}.status {} is not one of {}",
                    json_lite::py_repr(status),
                    py_list(STATUSES)
                ));
            }
            // A GAP IS A GAP IN BOTH COLUMNS. `cell == "none"` and `status == "none"` must agree,
            // or one of the two spellings is a gap the other column reports as covered.
            if (cell_id == "none") != (status == "none") {
                return Err(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step} cell/status disagree on whether this is \
                     a gap (cell={} status={})",
                    json_lite::py_repr(cell_id),
                    json_lite::py_repr(status)
                ));
            }
        }
    }

    Ok(Matrix { doc })
}

/// Python's `sorted(list)` repr, which is what several of these messages interpolate.
fn py_list<'a, I: IntoIterator<Item = &'a str>>(items: I) -> String {
    let mut v: Vec<&str> = items.into_iter().collect();
    v.sort_unstable();
    format!(
        "[{}]",
        v.into_iter()
            .map(json_lite::py_repr)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

// -------------------------------------------------------------------------------------------
// The rig column: a claim may not outlive its evidence
// -------------------------------------------------------------------------------------------

/// The h2 subject-script namespaces, and the source trees the battery/supplement namespaces are
/// declared in. Data, in one place, so a renamed rig directory is one edit.
const H2_DIRS: [(&str, &str); 2] = [
    ("mcp.rig", "scripts/mcp-subject"),
    ("a2a.battery", "scripts/a2a-subject"),
];
const SOURCE_DIRS: [(&str, &str); 2] = [
    ("mcp.battery", "testing/mcp-conformance/src/suites"),
    ("a2a.supplement", "testing/a2a-supplement/a2asup"),
];

/// Which file in the tree OWNS a named rig cell, or `None` — the "nothing owns this any more"
/// answer that makes the claim red.
pub fn resolve_cell(cx: &Ctx, cell_id: &str) -> Option<String> {
    if oracle_cell_ids(cx).contains(cell_id) {
        return Some("testing/shadow-oracle/cells.json".to_string());
    }
    let (namespace, rest) = cell_id.split_once('|')?;
    if rest.is_empty() {
        return None;
    }

    // THE H2 ARM RETURNS EARLY WHETHER OR NOT IT RESOLVES. A `mcp.rig|h2-…` id whose subject
    // script vanished must not fall through into the later arms and be adopted by a substring
    // match somewhere else — that is exactly how a deleted script keeps a green row.
    if let Some((_, dir)) = H2_DIRS.iter().find(|(ns, _)| *ns == namespace) {
        if rest.starts_with("h2-") {
            let path = format!("{dir}/{rest}.sh");
            return cx.exists(&path).then_some(path);
        }
    }

    if namespace == "voice.rig" {
        let path = format!("testing/voice-conformance/legs/{rest}.sh");
        if cx.exists(&path) {
            return Some(path);
        }
    }

    if let Some((_, base)) = SOURCE_DIRS.iter().find(|(ns, _)| *ns == namespace) {
        if let Some(owner) = declared_in_source(cx, base, rest) {
            return Some(owner);
        }
    }

    if rig_baseline_ids(cx).contains(cell_id) {
        return Some("testing/shadow-oracle/rigs-baseline.json".to_string());
    }
    None
}

/// The characters a scenario id is made of. Anything else is a boundary, and a match that is not
/// bounded on both sides is a match on a DIFFERENT id that merely starts or ends the same way.
fn is_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '|' | '/')
}

/// Does `text` DECLARE `needle` — i.e. does the id occur as a whole token, not as a fragment of a
/// longer one?
///
/// THE PLAIN SUBSTRING THIS REPLACES WAS THE BUG, and it was inherited from the Python's
/// `rest in text`. A scenario id is a hyphenated word, and ids in a suite are near-neighbours by
/// construction: `stream`, `stream-abort`, `stream-abort-mid-frame`. Under a naked `contains`,
/// EVERY id that is a prefix — or an infix, or a suffix — of a surviving one resolves to the
/// surviving one's file. So deleting `stream-abort` while `stream-abort-mid-frame` stays leaves the
/// matrix's cell for the deleted scenario resolving green, owned by a file that declares something
/// else entirely. That is the precise failure this whole rule exists to catch ("a claim may not
/// outlive its evidence"), passing because of how the check was spelled.
///
/// Token-exactness is the fix: the id must be bounded on both sides by a character no id can
/// contain — a quote, a bracket, whitespace, a comma, an equals sign, end of file. That is exactly
/// how these ids are actually written down (as string literals and table keys), so nothing that
/// genuinely declares an id stops matching, and a longer id that merely CONTAINS this one no longer
/// answers for it.
fn declares_id(text: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let nlen = needle.len();
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(needle) {
        let start = from + rel;
        let end = start + nlen;
        let before_ok = start == 0 || !text[..start].chars().next_back().is_some_and(is_id_char);
        let after_ok = end >= bytes.len() || !text[end..].chars().next().is_some_and(is_id_char);
        if before_ok && after_ok {
            return true;
        }
        // Advance by ONE character, not by the match length: overlapping occurrences are real, and
        // skipping past a rejected match can step over the bounded one that follows it.
        from = start + text[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// The first file under `base`, in sorted path order, that DECLARES `needle` as a whole token.
fn declared_in_source(cx: &Ctx, base: &str, needle: &str) -> Option<String> {
    let mut paths: Vec<String> = Vec::new();
    collect_paths(&cx.abs(base), cx.root(), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .find(|rel| cx.read(rel).is_ok_and(|t| declares_id(&t, needle)))
}

/// Path components that are BUILD OUTPUT, never a declaration site. A `__pycache__/*.pyc` carries
/// every id its source did, so a scenario deleted from the `.py` still resolves — to a compiled
/// copy of the file it was deleted from. An id is owned by a source file or by nothing.
const NOT_A_DECLARATION_SITE: [&str; 4] = ["__pycache__", ".git", "target", "node_modules"];

fn collect_paths(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.filter_map(Result::ok) {
        let path = entry.path();
        let skip = path.file_name().is_some_and(|n| {
            NOT_A_DECLARATION_SITE
                .iter()
                .any(|bad| n.to_string_lossy() == *bad)
        });
        if skip {
            continue;
        }
        if path.is_dir() {
            collect_paths(&path, root, out);
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Ids read out of a JSON list-of-objects keyed by `id`. An unreadable file yields an EMPTY set,
/// matching the Python — and the emptiness is never itself a pass, because a cell that resolves
/// nowhere is red.
fn json_ids(cx: &Ctx, rel: &str, list_key: &str) -> BTreeSet<String> {
    cx.read(rel)
        .ok()
        .and_then(|t| json_lite::parse(&t).ok())
        .and_then(|d| d.get(list_key).as_array().map(<[Json]>::to_vec))
        .map(|cells| {
            cells
                .iter()
                .filter_map(|c| c.get("id").as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn oracle_cell_ids(cx: &Ctx) -> BTreeSet<String> {
    json_ids(cx, "testing/shadow-oracle/cells.json", "cells")
}

fn rig_baseline_ids(cx: &Ctx) -> BTreeSet<String> {
    cx.read("testing/shadow-oracle/rigs-baseline.json")
        .ok()
        .and_then(|t| json_lite::parse(&t).ok())
        .and_then(|d| d.get("rows").as_object().cloned())
        .map(|o| o.keys().map(str::to_string).collect())
        .unwrap_or_default()
}

pub fn check_rig_column(cx: &Ctx, m: &Matrix) -> Vec<String> {
    let mut out = Vec::new();
    for plane in m.planes() {
        for step in m.step_order() {
            let cell = m.cell(&plane, &step);
            let cell_id = cell.str_or("cell", "");
            if cell_id == "none" {
                continue;
            }
            if resolve_cell(cx, &cell_id).is_none() {
                out.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step} names rig cell {}, which NOTHING in the \
                     tree owns -- no oracle cell of that id, no h2 subject script, no voice leg, \
                     no suite source declaring it and no row in rigs-baseline.json. The scenario \
                     was renamed or deleted; a claim that outlives its evidence is the drift this \
                     check exists to stop",
                    json_lite::py_repr(&cell_id)
                ));
            }
        }
    }
    out
}

// -------------------------------------------------------------------------------------------
// The root column: the second, independent verdict
// -------------------------------------------------------------------------------------------

/// The root column's problems, split into the two rows they belong to: the per-cell verdicts and
/// the per-leg floors. Splitting them is not cosmetic — "this cell's proof was renamed away" and
/// "this leg drove nothing at all" are different failures and a reader that collapses them cannot
/// tell a broken claim from an absent one.
#[derive(Default)]
pub struct RootProblems {
    pub column: Vec<String>,
    pub legs: Vec<String>,
}

pub fn check_root_column(cx: &Ctx, m: &Matrix) -> RootProblems {
    let mut p = RootProblems::default();
    let legs = m.root_legs();
    let Some(legs_obj) = legs.as_object().filter(|o| !o.is_empty()) else {
        p.legs
            .push(format!("{LEDGER_REL}: no non-empty 'root_legs' object"));
        return p;
    };

    let planes: BTreeSet<String> = m.planes().into_iter().collect();
    let mut leg_of_plane: BTreeMap<String, String> = BTreeMap::new();
    let mut leg_file: BTreeMap<String, String> = BTreeMap::new();
    for leg in legs_obj.keys() {
        let entry = legs.get(leg);
        let plane = entry.str_or("plane", "");
        let file = entry.str_or("file", "");
        if !planes.contains(&plane) {
            p.legs.push(format!(
                "{LEDGER_REL}: root leg {} names plane {}, which is not a row of the matrix",
                json_lite::py_repr(leg),
                json_lite::py_repr(&plane)
            ));
            continue;
        }
        if !file.starts_with(ROOT_DIR) {
            p.legs.push(format!(
                "{LEDGER_REL}: root leg {} names file {}, which is not under {ROOT_DIR} -- a \
                 leg's evidence lives in the composition root",
                json_lite::py_repr(leg),
                json_lite::py_repr(&file)
            ));
            continue;
        }
        if !cx.exists(&file) {
            p.legs.push(format!(
                "{LEDGER_REL}: root leg {} names {file}, which does not exist",
                json_lite::py_repr(leg)
            ));
            continue;
        }
        leg_of_plane.insert(plane, leg.to_string());
        leg_file.insert(leg.to_string(), file);
    }

    // A PLANE WITH NO LEG IS A LOOP NOBODY IS JUDGING, and it reads exactly like a plane whose leg
    // is green.
    let unowned: Vec<&str> = planes
        .iter()
        .filter(|pl| !leg_of_plane.contains_key(*pl))
        .map(String::as_str)
        .collect();
    if !unowned.is_empty() {
        p.legs.push(format!(
            "{LEDGER_REL}: plane(s) {} are answered by NO root leg -- a plane with no leg is a \
             loop nobody is judging",
            py_list(unowned)
        ));
    }

    let mut proven_per_leg: BTreeMap<String, usize> =
        leg_file.keys().map(|l| (l.clone(), 0usize)).collect();

    // note text -> the `plane.step` that argued it first, for the reuse check below.
    let mut seen_notes: BTreeMap<String, String> = BTreeMap::new();

    for plane in m.planes() {
        let Some(leg) = leg_of_plane.get(&plane) else {
            continue;
        };
        let file = &leg_file[leg];
        for step in m.step_order() {
            let r = m.cell(&plane, &step).get("root");
            if r.as_object().is_none() {
                p.column.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step} carries no 'root' verdict -- an absent \
                     second verdict is indistinguishable from an oversight"
                ));
                continue;
            }
            let state = r.str_or("state", "");
            if !ROOT_STATES.contains(&state.as_str()) {
                p.column.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step}.root.state {} is not one of {}",
                    json_lite::py_repr_json(r.get("state")),
                    py_list(ROOT_STATES)
                ));
                continue;
            }
            let named_leg = r.str_or("leg", "");
            if &named_leg != leg {
                p.column.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step}.root names leg {}, but plane {} runs \
                     through {}",
                    json_lite::py_repr_json(r.get("leg")),
                    json_lite::py_repr(&plane),
                    json_lite::py_repr(leg)
                ));
                continue;
            }
            let note = r.get("note").as_str().unwrap_or("").trim().to_string();
            if let Some(why) = note_problem(&note) {
                p.column.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step}.root has note {}: {why}",
                    json_lite::py_repr(&note)
                ));
                continue;
            }
            // THE ARGUMENT MUST BE THIS CELL'S. One sentence pasted into every cell clears every
            // length and shape floor above while saying nothing about any particular verdict --
            // fifty identical arguments are one argument and forty-nine labels. The first cell to
            // use a note keeps it; each later reuse is named against the cell it was taken from.
            if let Some(first) = seen_notes.get(&note) {
                p.column.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step}.root reuses the note already argued at \
                     matrix.{first} verbatim: a note copied between cells is boilerplate, not an \
                     argument about this cell's verdict"
                ));
                continue;
            }
            seen_notes.insert(note.clone(), format!("{plane}.{step}"));
            if state == "none" {
                continue;
            }
            let test = r.str_or("test", "");
            let prefix = format!("{file}::");
            let Some(func) = test.strip_prefix(&prefix) else {
                p.column.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step}.root is proven by {}, which does not \
                     live in {}'s own file {file} -- a leg is proven by its own cells",
                    json_lite::py_repr(&test),
                    json_lite::py_repr(leg)
                ));
                continue;
            };
            // THE NAMED CELL MUST STILL EXIST. A renamed `fn` leaves a row claiming a proof the
            // binary cannot run, which is the same green as a proof that passed.
            let body = cx.read(file).unwrap_or_default();
            if !body.contains(&format!("fn {func}(")) {
                p.column.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step}.root is proven by {test}, but no `fn \
                     {func}(` exists there. The named loop cell is gone or renamed; a claim that \
                     outlives its evidence is the drift this check exists to stop"
                ));
                continue;
            }
            *proven_per_leg.entry(leg.clone()).or_default() += 1;
        }
    }

    // THE FLOOR. A leg that proves zero steps drove nothing, and zero findings is the passing
    // answer to every question nobody asked.
    let empty: Vec<&str> = proven_per_leg
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(l, _)| l.as_str())
        .collect();
    if !empty.is_empty() {
        p.legs.push(format!(
            "{LEDGER_REL}: root leg(s) {} prove ZERO steps over the loop. A leg with no watched \
             cell is a leg nobody drove",
            py_list(empty)
        ));
    }
    p
}

// -------------------------------------------------------------------------------------------
// The shipped-leg bar, and the render
// -------------------------------------------------------------------------------------------

/// The `root-*` features the binary SHIPS, read out of the manifest's own `default` line.
///
/// A deliberate one-line parse rather than a TOML load, and kept that way: the subject of the rule
/// is what a human wrote on that line, and a general parser that normalises the document answers a
/// different question.
pub fn default_root_legs(text: &str) -> Result<BTreeSet<String>, String> {
    let mut in_features = false;
    for line in text.lines() {
        let stripped = line.trim();
        if stripped.starts_with('[') {
            in_features = stripped == "[features]";
            continue;
        }
        if !in_features || !stripped.starts_with("default") {
            continue;
        }
        let Some((head, rest)) = stripped.split_once('=') else {
            continue;
        };
        if head.trim() != "default" {
            continue;
        }
        let (Some(open), Some(close)) = (rest.find('['), rest.rfind(']')) else {
            return Err(format!(
                "{MANIFEST_REL}: `default` is not a single-line array"
            ));
        };
        return Ok(rest[open + 1..close]
            .split(',')
            .map(|f| f.trim().trim_matches('"').to_string())
            .filter(|f| f.starts_with("root-"))
            .collect());
    }
    Err(format!(
        "{MANIFEST_REL}: no `default` line under [features]"
    ))
}

/// The gating plane×step cells on a SHIPPED leg that nothing drives over the loop. A default leg
/// is the shipped path for its plane; a gating step nobody drives over it is a half-answer.
pub fn root_legs_gating(m: &Matrix, shipped: &BTreeSet<String>) -> (usize, Vec<String>) {
    let mut considered = 0usize;
    let mut red = Vec::new();
    for plane in m.planes() {
        for step in m.step_order() {
            if !m.steps().get(&step).get("gating").truthy() {
                continue;
            }
            let r = m.cell(&plane, &step).get("root");
            let leg = r.str_or("leg", "");
            if !shipped.contains(&leg) {
                continue;
            }
            considered += 1;
            if r.str_or("state", "") != "proven" {
                red.push(format!("{plane}.{step} ({leg})"));
            }
        }
    }
    red.sort();
    (considered, red)
}

/// The gating cells that are still `"none"` — what `--check` is RED on.
pub fn gating_gaps(m: &Matrix) -> Vec<String> {
    let mut out = Vec::new();
    for plane in m.planes() {
        for step in m.step_order() {
            let cell = m.cell(&plane, &step);
            let is_gap = cell.str_or("status", "") == "none";
            if is_gap && m.steps().get(&step).get("gating").truthy() {
                out.push(format!("{plane}.{step}"));
            }
        }
    }
    out
}

/// The human matrix, byte-identical to the Python's — column widths 13 / 6 / 46 / 5, two-space
/// indent, and `info` padded to the width of `gating` so the bracket column lines up.
pub fn render(m: &Matrix) -> String {
    let mut lines = Vec::new();
    for plane in m.planes() {
        lines.push(format!("plane {plane}:"));
        for step in m.step_order() {
            let entry = m.cell(&plane, &step);
            let status = entry.str_or("status", "");
            let mark = if status == "none" {
                "NONE".to_string()
            } else {
                status.to_uppercase()
            };
            let tag = if m.steps().get(&step).get("gating").truthy() {
                "gating"
            } else {
                "info  "
            };
            let root = entry.get("root");
            let proven = root.str_or("state", "") == "proven";
            let rmark = if proven { "LOOP" } else { "NONE" };
            let rcell = if proven {
                root.str_or("test", "")
                    .rsplit("::")
                    .next()
                    .unwrap_or("")
                    .to_string()
            } else {
                "--".to_string()
            };
            let cell = entry.str_or("cell", "");
            lines.push(format!(
                "  [{tag}] {step:<13} {mark:<6} {cell:<46} {rmark:<5} {rcell}"
            ));
        }
    }
    lines.join("\n")
}

/// The `ROOT-STEPS:` line. `scripts/verify-1.6.0-done.sh` greps this prefix out of stdout, so it
/// is a CONSUMED CONTRACT, not decoration — the prefix and the counts on it must not move.
pub fn root_line(m: &Matrix) -> String {
    let mut total = 0usize;
    let mut proven = 0usize;
    let mut gaps: Vec<String> = Vec::new();
    let mut per_leg: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for plane in m.planes() {
        for step in m.step_order() {
            let r = m.cell(&plane, &step).get("root");
            let leg = r.get("leg").as_str().unwrap_or("?").to_string();
            total += 1;
            let e = per_leg.entry(leg).or_default();
            if r.str_or("state", "") == "proven" {
                proven += 1;
                e.0 += 1;
            } else {
                gaps.push(format!("{plane}.{step}"));
                e.1 += 1;
            }
        }
    }
    let mut lines = vec![format!(
        "ROOT-STEPS: {} of {total} plane x step cell(s) are still \"none\" over the composition \
         root's legs ({proven} driven through run_unit) -- this line names where:",
        gaps.len()
    )];
    if !gaps.is_empty() {
        lines.push(format!("  {}", gaps.join(", ")));
    }
    lines.push(format!(
        "  per leg: {}",
        per_leg
            .iter()
            .map(|(leg, (n, g))| format!("{leg} {n} proven / {g} none"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    lines.push(
        "  (run them: cargo xtask teller-steps --root-legs -- builds the binary crate with all \
         five legs on and executes every named loop cell)"
            .to_string(),
    );
    lines.join("\n")
}

// -------------------------------------------------------------------------------------------
// The runner arms — `cargo xtask teller-steps [...]`
// -------------------------------------------------------------------------------------------

/// The five root legs the `--root-legs` arm compiles the binary crate with.
const ROOT_FEATURES: &str = "root-admin,root-mcp,root-a2a,root-voice,root-llm";

const ARM_USAGE: &str = "\
usage:
  cargo xtask teller-steps                       print the matrix and the ROOT-STEPS line
  cargo xtask teller-steps --root-legs           RUN every named loop cell the matrix cites
  cargo xtask teller-steps --root-legs-gating    the shipped legs owe every gating step

There is deliberately no `--rig-legs` arm. Driving the oracle's rig ledger means RUNNING the
oracle's code, which `cargo xtask gate segregation` forbids the gate runner from doing — a runner
that executes its own subject is a runner whose verdict moves when the subject does. That arm
stayed in scripts/verify-1.6.0-done.sh, where the caller drives the oracle directly.";

/// `cargo xtask teller-steps …` — the arms that RUN something, and the human render whose
/// `ROOT-STEPS:` prefix `scripts/verify-1.6.0-done.sh` greps out of stdout.
///
/// UNKNOWN FLAGS ARE AN ARGUMENT ERROR HERE, where the Python fell through into its default
/// `--check` path. A runner that silently answers a question nobody asked is a runner whose green
/// says nothing about the flag that was typed.
pub fn run_arm(cx: &Ctx, args: &[String]) -> i32 {
    let mut root_legs = false;
    let mut gating = false;
    for a in args {
        match a.as_str() {
            "--root-legs" => root_legs = true,
            "--root-legs-gating" => gating = true,
            // `--check` was the Python's default path and CI still spells it; it stays an accepted
            // spelling of "print the matrix" rather than becoming an error on the same day.
            "--check" => {}
            other => {
                eprintln!("xtask teller-steps: unknown flag `{other}`");
                eprintln!("{ARM_USAGE}");
                return 2;
            }
        }
    }

    if root_legs || gating {
        let mut rc = 0;
        if root_legs {
            rc |= run_root_legs(cx);
        }
        if gating {
            if root_legs {
                println!();
            }
            rc |= run_root_legs_gating(cx);
        }
        return rc;
    }

    let m = match load(cx) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("FAIL: {LEDGER_REL} is not a valid teller-steps matrix: {e}");
            return 1;
        }
    };
    println!("{}", render(&m));
    println!();
    println!("{}", root_line(&m));
    println!();
    let gaps = gating_gaps(&m);
    if gaps.is_empty() {
        println!("GREEN: every gating plane x step cell in {LEDGER_REL} names a real scenario.");
        0
    } else {
        println!(
            "RED: {} gating plane x step cell(s) are still \"none\": {}",
            gaps.len(),
            gaps.join(", ")
        );
        1
    }
}

/// The shipped-leg bar: a default leg is the shipped path for its plane, so a gating step nobody
/// drives over it is a half-answer, not a queue entry.
fn run_root_legs_gating(cx: &Ctx) -> i32 {
    let m = match load(cx) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ROOT-GATING: cannot read the bar's two inputs: {e}");
            return 1;
        }
    };
    let shipped = match cx.read(MANIFEST_REL).and_then(|t| default_root_legs(&t)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ROOT-GATING: cannot read the bar's two inputs: {e}");
            return 1;
        }
    };
    let (considered, red) = root_legs_gating(&m, &shipped);
    let legs = if shipped.is_empty() {
        "(none)".to_string()
    } else {
        shipped.iter().cloned().collect::<Vec<_>>().join(", ")
    };
    println!(
        "ROOT-GATING: the shipped legs are {legs}; {considered} gating plane x step cell(s) are \
         theirs to drive."
    );
    if red.is_empty() {
        println!("GREEN: every gating step on every shipped root leg is driven over the loop.");
        return 0;
    }
    println!("  not driven: {}", red.join(", "));
    println!(
        "RED: {} gating step(s) on a leg the binary SHIPS have no cell over the loop. A default \
         leg is the shipped path for its plane; a gating step nobody drives over it is a \
         half-answer, not a queue entry.",
        red.len()
    );
    1
}

/// The `(leg, file, fn)` triples the matrix claims are proven over the loop.
fn root_cells(m: &Matrix) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for plane in m.planes() {
        for step in m.step_order() {
            let r = m.cell(&plane, &step).get("root");
            if r.str_or("state", "") != "proven" {
                continue;
            }
            let test = r.str_or("test", "");
            if let Some((file, func)) = test.split_once("::") {
                out.push((r.str_or("leg", "?"), file.to_string(), func.to_string()));
            }
        }
    }
    out
}

/// RUN every named loop cell, with all five legs compiled in.
///
/// Three floors, each of which the shell version needed: naming NO cell is a refusal, a build that
/// does not carry a named cell is a refusal, and a run that executed a DIFFERENT NUMBER of cells
/// than were named is a refusal. The last is the one that matters — a libtest filter selecting
/// nothing exits 0 printing "0 passed".
fn run_root_legs(cx: &Ctx) -> i32 {
    let m = match load(cx) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ROOT-STEPS: {LEDGER_REL} is not a valid matrix: {e}");
            return 1;
        }
    };
    let cells = root_cells(&m);
    if cells.is_empty() {
        eprintln!("ROOT-STEPS: NO root cell was named to run");
        return 1;
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let base: Vec<String> = [
        "test",
        "-p",
        "busbar",
        "--features",
        ROOT_FEATURES,
        "--bin",
        "busbar",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();

    let mut list_argv = base.clone();
    list_argv.extend(["--".to_string(), "--list".to_string()]);
    let listing = match cx.run_checked(&cargo, &list_argv) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ROOT-STEPS: the five-leg build did not compile:");
            eprintln!("{e}");
            return 1;
        }
    };
    let known: BTreeSet<&str> = listing
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .collect();

    // `crates/busbar/src/root/units_llm.rs::the_fn` is the ledger's spelling; libtest's is
    // `root::units_llm::tests::the_fn`. Deriving one from the other rather than storing both is
    // what keeps the two from drifting apart.
    let mut wanted: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut per_leg: BTreeMap<String, usize> = BTreeMap::new();
    for (leg, file, func) in &cells {
        let path = file
            .split("src/")
            .nth(1)
            .and_then(|s| s.strip_suffix(".rs"))
            .map(|s| format!("{}::tests::{func}", s.replace('/', "::")))
            .unwrap_or_default();
        if path.is_empty() || !known.contains(path.as_str()) {
            unknown.push(format!("  {leg}: {file}::{func} (looked for {path})"));
        } else if !wanted.contains(&path) {
            wanted.push(path);
        }
        *per_leg.entry(leg.clone()).or_default() += 1;
    }
    if !unknown.is_empty() {
        eprintln!(
            "ROOT-STEPS: the five-leg build does NOT carry these named loop cells -- the ledger \
             claims a proof this binary cannot run:"
        );
        for u in &unknown {
            eprintln!("{u}");
        }
        return 1;
    }

    let mut run_argv = base;
    run_argv.push("--".to_string());
    run_argv.push("--exact".to_string());
    run_argv.extend(wanted.iter().cloned());
    let out = match cx.run_checked(&cargo, &run_argv) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ROOT-STEPS: the root-leg cells did not pass:");
            eprintln!("{e}");
            return 1;
        }
    };
    let Some((passed, failed)) = parse_libtest_tally(&out) else {
        eprintln!("ROOT-STEPS: the root-leg cells did not pass:");
        eprintln!("{out}");
        return 1;
    };
    if failed != 0 || passed != wanted.len() {
        eprintln!(
            "ROOT-STEPS: expected {} named loop cell(s) to run and pass; the harness reported \
             {passed} passed / {failed} failed. A run that executed a different set is not the \
             run the ledger claims.",
            wanted.len()
        );
        return 1;
    }
    println!(
        "ROOT-STEPS: {passed} named loop cell(s) RAN and passed with --features {ROOT_FEATURES}"
    );
    for (leg, n) in &per_leg {
        println!("  {leg}: {n} cell(s)");
    }
    0
}

/// `N passed; M failed` out of a libtest summary line.
fn parse_libtest_tally(text: &str) -> Option<(usize, usize)> {
    for line in text.lines() {
        let Some(i) = line.find(" passed; ") else {
            continue;
        };
        let passed = line[..i].rsplit(' ').next()?.parse().ok()?;
        let rest = &line[i + " passed; ".len()..];
        let failed = rest.split(' ').next()?.parse().ok()?;
        return Some((passed, failed));
    }
    None
}

// -------------------------------------------------------------------------------------------
// The gate
// -------------------------------------------------------------------------------------------

pub struct TellerStepsGate;

/// WHAT THE GATE FOUND, separated from HOW IT IS SPELLED.
///
/// [`Gate::run`] fills this from the tree and [`translate`] fills it from the legacy script's own
/// output; both then hand it to [`rows_from`]. That is what makes the parity comparison worth
/// anything: with one row constructor, the only thing that can differ between the two sides is the
/// finding, and the finding is the only thing about the tree.
#[derive(Default)]
pub struct Findings {
    /// The denominator. A matrix with fewer cells is a shorter matrix, not a cleaner one, so the
    /// count is carried in the row detail where a diff can see it move.
    pub cells: usize,
    pub legs: usize,
    pub matrix: Vec<String>,
    pub rig: Vec<String>,
    pub root_column: Vec<String>,
    pub root_legs: Vec<String>,
    pub gating: Vec<String>,
}

/// THE MATRIX DID NOT PARSE, so no rule below it ran. Every rule carries the refusal — the one
/// naming it, and the four that were never evaluated — because an unreadable matrix is the single
/// input whose absence would otherwise make every other rule vacuously green.
pub fn did_not_load(detail: &str) -> Findings {
    let owner = owner_of(detail);
    let carry = format!("{detail} — a rule that did not run is not a rule that passed");
    let pick = |id: &str| {
        vec![if id == owner {
            detail.to_string()
        } else {
            carry.clone()
        }]
    };
    Findings {
        cells: 0,
        legs: 0,
        matrix: pick(ROW_MATRIX),
        rig: pick(ROW_RIG),
        root_column: pick(ROW_ROOT_COLUMN),
        root_legs: pick(ROW_ROOT_LEGS),
        gating: pick(ROW_GATING),
    }
}

fn one_row(
    problems: &[String],
    id: &str,
    title_ok: &str,
    title_bad: &str,
    ok_detail: String,
) -> Row {
    if problems.is_empty() {
        Row::pass(id, title_ok, ok_detail)
    } else {
        Row::fail(id, title_bad, problems.join(" | "))
    }
}

/// The one row constructor. Both the Rust gate and the legacy translator reach the ledger through
/// here and nowhere else.
pub fn rows_from(f: &Findings) -> Vec<Row> {
    let cells = f.cells;
    vec![
        one_row(
            &f.matrix,
            ROW_MATRIX,
            "every plane carries every declared step, and no cell disagrees with itself",
            "the Teller step matrix is not a valid matrix",
            format!("{cells} cell(s)"),
        ),
        one_row(
            &f.rig,
            ROW_RIG,
            "every rig cell the matrix names is owned by something in the tree",
            "a rig cell the matrix names is owned by NOTHING in the tree",
            format!("{cells} cell(s) resolved"),
        ),
        one_row(
            &f.root_column,
            ROW_ROOT_COLUMN,
            "every cell carries a root verdict whose named loop cell still exists",
            "a root verdict is absent, mis-attributed, unargued, or names a loop cell that is gone",
            format!("{cells} verdict(s) read"),
        ),
        one_row(
            &f.root_legs,
            ROW_ROOT_LEGS,
            "every plane is answered by a root leg, and every leg proves at least one step",
            "a plane is answered by no leg, or a leg proves ZERO steps over the loop",
            format!("{} leg(s)", f.legs),
        ),
        one_row(
            &f.gating,
            ROW_GATING,
            "every gating plane x step cell names a real scenario",
            "a gating plane x step cell is still \"none\"",
            format!("0 of {cells} gating cell(s) are \"none\""),
        ),
    ]
}

impl Gate for TellerStepsGate {
    fn name(&self) -> &'static str {
        "teller-steps"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_MATRIX.to_string(),
            ROW_RIG.to_string(),
            ROW_ROOT_COLUMN.to_string(),
            ROW_ROOT_LEGS.to_string(),
            ROW_GATING.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let m = match load(cx) {
            Ok(m) => m,
            Err(e) => return Verdict::of(rows_from(&did_not_load(&e))),
        };

        let root = check_root_column(cx, &m);
        Verdict::of(rows_from(&Findings {
            cells: m.planes().len() * m.step_order().len(),
            legs: m.root_legs().as_object().map_or(0, json_lite::Obj::len),
            matrix: Vec::new(),
            rig: check_rig_column(cx, &m),
            root_column: root.column,
            root_legs: root.legs,
            gating: gating_gaps(&m),
        }))
    }

    /// The legacy `--check` prints prose and exits 0 or 1; there is no ledger to read. This reads
    /// its OWN OUTPUT into the rows it amounts to, through the same constructors [`Gate::run`]
    /// uses, so the only thing that can differ between the two sides is the finding — which is the
    /// only thing worth comparing.
    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        if run.code.is_none() && run.stdout.is_empty() && run.stderr.is_empty() {
            return Some(Ok(Vec::new()));
        }
        Some(translate(run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed matrix is green under every rule",
            &[
                ROW_MATRIX,
                ROW_RIG,
                ROW_ROOT_COLUMN,
                ROW_ROOT_LEGS,
                ROW_GATING,
            ],
        ));

        let base = match cx.read(LEDGER_REL) {
            Ok(t) => t,
            Err(e) => {
                report.note_infra_failure(format!("{LEDGER_REL}: {e}"));
                return report;
            }
        };
        let doc = match json_lite::parse(&base) {
            Ok(d) => d,
            Err(e) => {
                report.note_infra_failure(format!("{LEDGER_REL}: {e}"));
                return report;
            }
        };

        // A REAL note from a DIFFERENT cell, for the boilerplate-reuse plant below. Lifted out of
        // the committed matrix rather than invented, so the plant is a note that already clears
        // every length and shape floor -- which is the entire point of the reuse rule.
        let borrowed_note = doc
            .get("matrix")
            .get("mcp")
            .as_object()
            .and_then(|steps| {
                steps
                    .iter()
                    .find_map(|(_, cell)| cell.get("root").get("note").as_str().map(str::to_string))
            })
            .unwrap_or_default();

        // Every plant is a MUTATION OF THE REAL COMMITTED MATRIX, not a synthetic fixture, so a
        // rule that stopped covering the real file's shape cannot pass its own selftest.
        let plants: Vec<Plantable> = vec![
            (
                "a plane missing a declared step",
                ROW_MATRIX,
                "missing step(s)",
                Box::new(|p: &mut Plant| p.drop_step("llm", "meter")),
            ),
            (
                "a cell whose status disagrees with its own gap",
                ROW_MATRIX,
                "cell/status disagree",
                Box::new(|p: &mut Plant| {
                    p.set_cell_field("llm", "meter", "status", Json::Str("none".into()));
                }),
            ),
            (
                "a rig cell id nothing in the tree owns any more",
                ROW_RIG,
                "NOTHING in the tree owns",
                Box::new(|p: &mut Plant| {
                    p.set_cell_field(
                        "llm",
                        "meter",
                        "cell",
                        Json::Str("teller|a-scenario-that-was-renamed-away".into()),
                    );
                }),
            ),
            (
                "an h2 rig cell whose subject script vanished",
                ROW_RIG,
                "NOTHING in the tree owns",
                Box::new(|p: &mut Plant| {
                    p.set_cell_field(
                        "mcp",
                        "route",
                        "cell",
                        Json::Str("mcp.rig|h2-a-step-with-no-script".into()),
                    );
                }),
            ),
            (
                "a root proof whose named loop cell was renamed away",
                ROW_ROOT_COLUMN,
                "no `fn a_fn_that_was_renamed_away(` exists there",
                Box::new(|p: &mut Plant| {
                    p.set_root_field(
                        "llm",
                        "meter",
                        "test",
                        Json::Str(format!(
                            "{ROOT_DIR}tests/units_llm.rs::a_fn_that_was_renamed_away"
                        )),
                    );
                }),
            ),
            (
                "root evidence taken from another leg's file",
                ROW_ROOT_COLUMN,
                "but plane 'llm' runs through 'root-llm'",
                Box::new(|p: &mut Plant| {
                    p.set_root_field("llm", "meter", "leg", Json::Str("root-mcp".into()));
                }),
            ),
            (
                "a root verdict with a label instead of an argument",
                ROW_ROOT_COLUMN,
                "owes a one-line argument",
                Box::new(|p: &mut Plant| {
                    p.set_root_field("llm", "meter", "note", Json::Str("not yet".into()));
                }),
            ),
            // ── THE NOTE RULE WAS A CHARACTER COUNT. These three are the labels that cleared it. ──
            (
                "a root note padded to length by repeating one phrase",
                ROW_ROOT_COLUMN,
                "distinct word",
                Box::new(|p: &mut Plant| {
                    // 63 characters, sixteen words, TWO distinct: clears MIN_ROOT_NOTE outright,
                    // and is the exact label ("not yet") the char-count floor was written against,
                    // simply repeated until it was long enough.
                    p.set_root_field(
                        "llm",
                        "meter",
                        "note",
                        Json::Str(
                            "not yet not yet not yet not yet not yet not yet not yet not yet"
                                .into(),
                        ),
                    );
                }),
            ),
            (
                "a root note padded to length with a character run",
                ROW_ROOT_COLUMN,
                "padding to a length is a run",
                Box::new(|p: &mut Plant| {
                    p.set_root_field(
                        "llm",
                        "meter",
                        "note",
                        Json::Str(format!(
                            "the root leg proves this step and here is the argument {}",
                            "a".repeat(40)
                        )),
                    );
                }),
            ),
            (
                "a root note copied verbatim from another cell",
                ROW_ROOT_COLUMN,
                "reuses the note already argued at",
                Box::new(move |p: &mut Plant| {
                    p.set_root_field("llm", "meter", "note", Json::Str(borrowed_note.clone()));
                }),
            ),
            // ── THE RIG-CELL RESOLVER MATCHED A NAKED SUBSTRING. ──────────────────────────────
            // `ADV.MALFORMED` is a strict PREFIX of the real, still-declared `ADV.MALFORMED-JSON`.
            // Under the plain `contains` this replaces, the deleted id resolved to the surviving
            // id's file and the cell stayed green — a claim outliving its evidence, which is the
            // one thing this row exists to refuse. Token-exactness is what makes this plant red.
            (
                "a rig cell id that is only a PREFIX of a scenario that still exists",
                ROW_RIG,
                "NOTHING in the tree owns",
                Box::new(|p: &mut Plant| {
                    p.set_cell_field(
                        "mcp",
                        "decode",
                        "cell",
                        Json::Str("mcp.battery|ADV.MALFORMED".into()),
                    );
                }),
            ),
            (
                "a rig cell id that is only a SUFFIX of a scenario that still exists",
                ROW_RIG,
                "NOTHING in the tree owns",
                Box::new(|p: &mut Plant| {
                    p.set_cell_field(
                        "a2a",
                        "authenticate",
                        "cell",
                        Json::Str("a2a.supplement|SERVER-002".into()),
                    );
                }),
            ),
            (
                "a plane no root leg answers to",
                ROW_ROOT_LEGS,
                "answered by NO root leg",
                Box::new(|p: &mut Plant| p.drop_leg("root-voice")),
            ),
            (
                "a gating cell that is still a gap",
                ROW_GATING,
                "llm.meter",
                Box::new(|p: &mut Plant| {
                    p.set_cell_field("llm", "meter", "cell", Json::Str("none".into()));
                    p.set_cell_field("llm", "meter", "status", Json::Str("none".into()));
                }),
            ),
        ];

        for (label, covers, naming, mutate) in plants {
            let mut plant = Plant { doc: doc.clone() };
            mutate(&mut plant);
            let mut ov = Overlay::new();
            let text = format!("{}\n", json_lite::dump_python(&plant.doc));
            if let Err(e) = Edit::Replace(text).apply(cx, LEDGER_REL, &mut ov) {
                report.note_infra_failure(format!("{label}: {e}"));
                continue;
            }
            // THE PLANT MUST BE NAMED. `naming` is the substring the report has to carry — "the
            // gate went red" says nothing about whether it went red for the planted reason, and
            // eight of these nine plants are one JSON key apart from each other.
            report.push(prove_red(cx, self, label, &[covers], ov, &[naming]));
        }

        report
    }
}

/// One planted violation: its label, the owed row it exercises, the substring its report must NAME,
/// and the edit that plants it into a copy of the real committed matrix.
type Plantable = (
    &'static str,
    &'static str,
    &'static str,
    Box<dyn Fn(&mut Plant)>,
);

/// A mutable copy of the committed matrix, for planting.
struct Plant {
    doc: Json,
}

impl Plant {
    fn cell_mut(&mut self, plane: &str, step: &str) -> Option<&mut json_lite::Obj> {
        match self
            .doc
            .as_object_mut()?
            .get_mut("matrix")?
            .as_object_mut()?
            .get_mut(plane)?
            .as_object_mut()?
            .get_mut(step)?
        {
            Json::Object(o) => Some(o),
            _ => None,
        }
    }

    fn set_cell_field(&mut self, plane: &str, step: &str, key: &str, v: Json) {
        if let Some(c) = self.cell_mut(plane, step) {
            c.insert(key, v);
        }
    }

    fn set_root_field(&mut self, plane: &str, step: &str, key: &str, v: Json) {
        if let Some(Json::Object(r)) = self.cell_mut(plane, step).and_then(|c| c.get_mut("root")) {
            r.insert(key, v);
        }
    }

    fn drop_step(&mut self, plane: &str, step: &str) {
        if let Some(Json::Object(row)) = self
            .doc
            .as_object_mut()
            .and_then(|d| d.get_mut("matrix"))
            .and_then(Json::as_object_mut)
            .and_then(|m| m.get_mut(plane))
        {
            row.remove(step);
        }
    }

    fn drop_leg(&mut self, leg: &str) {
        if let Some(Json::Object(legs)) = self
            .doc
            .as_object_mut()
            .and_then(|d| d.get_mut("root_legs"))
        {
            legs.remove(leg);
        }
    }
}

/// Read the legacy `--check`'s own prose into the rows it amounts to.
///
/// The mapping is the script's own: a `FAIL:` line is a structural refusal and belongs to whichever
/// rule raised it; a `RED:` line is the gating-gap rule; `GREEN:` is every rule passing. A run that
/// says nothing recognisable is an ERROR, not zero rows — a translator that cannot see the finding
/// the script exited on is not parsing the script.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let all: Vec<&str> = run.lines().collect();

    // THE DENOMINATOR COMES OUT OF THE SCRIPT'S OWN LINE, not out of a constant here. `ROOT-STEPS:
    // 0 of 50 plane x step cell(s)` is the script's own cell count, so a legacy that saw a
    // different-sized matrix than the Rust gate did shows up as a row diff rather than as two
    // agreeing greens over two different matrices.
    let mut f = Findings::default();
    if let Some(line) = all.iter().find(|l| l.starts_with("ROOT-STEPS: ")) {
        if let Some(total) = line
            .split_whitespace()
            .skip_while(|w| *w != "of")
            .nth(1)
            .and_then(|w| w.parse::<usize>().ok())
        {
            f.cells = total;
        }
        // `per leg: root-a2a 10 proven / 0 none, …` — one comma-separated entry per leg.
        if let Some(per) = all
            .iter()
            .find_map(|l| l.trim_start().strip_prefix("per leg: "))
        {
            f.legs = per.split(',').filter(|s| !s.trim().is_empty()).count();
        }
    }

    if let Some(fail) = all.iter().find(|l| l.starts_with("FAIL: ")) {
        let detail = fail
            .split_once(" is not a valid teller-steps matrix: ")
            .map_or_else(|| (*fail).to_string(), |(_, d)| d.to_string());
        // The matrix did not load, so the Rust gate reports every dependent rule as "did not run".
        // The translator must say exactly the same thing, or a structural refusal would read as
        // four passing rules on one side and four failing ones on the other.
        return Ok(rows_from(&did_not_load(&detail)));
    }

    if let Some(red) = all.iter().find(|l| l.starts_with("RED: ")) {
        f.gating.push((*red).to_string());
        return Ok(rows_from(&f));
    }

    if all.iter().any(|l| l.starts_with("GREEN: ")) {
        return Ok(rows_from(&f));
    }

    Err(format!(
        "parity: `{}` printed neither a FAIL:, a RED: nor a GREEN: line. A translator that cannot \
         see the verdict the script reached is not parsing the script. stdout: {}",
        run.argv.join(" "),
        run.stdout.trim()
    ))
}

/// Which rule a structural refusal belongs to, by the message the script raised it with.
fn owner_of(detail: &str) -> &'static str {
    if detail.contains("NOTHING in the tree owns") {
        ROW_RIG
    } else if detail.contains("root_legs")
        || detail.contains("answered by NO root leg")
        || detail.contains("prove ZERO steps")
        || detail.contains("root leg ")
    {
        ROW_ROOT_LEGS
    } else if detail.contains(".root") {
        ROW_ROOT_COLUMN
    } else {
        ROW_MATRIX
    }
}
