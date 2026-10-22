//! `teller-steps` — THE TELLER STEP MATRIX: one cell per Teller step per plane, and a second,
//! independent verdict per cell taken over the composition root's own legs.
//!
//! Ported from `scripts/teller-steps-check.py`. Five rules, five owed rows (a sixth, the run rule
//! over the capability-equality ledger, has no Python ancestor), and the shape of each
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
//! * **a proof must RUN** (Law 10). A named loop cell — this matrix's, and the capability-equality
//!   ledger's root column ([`ROW_EQUALITY_CELLS`]) — must be a test CI's build compiles and runs:
//!   every cfg on its module's way enabled in the `test` check's build, a test attribute, no
//!   `#[ignore]` ([`crate::ci_cfg`]). A fn that exists under a cfg no build enables is a proof that
//!   never runs, which fourteen root-llm cells were once no linked row carried the `node` axis.
//! * **the roster is the tree's, not the file's** ([`check_roster`]). "Every plane carries every
//!   declared step" is true of whatever lists the file wrote, so both lists are DERIVED: the steps
//!   from the kernel's own `StepName::ALL` (set and order), the rows from the `PlaneMeta` KEY every
//!   plane-kind crate states. A plane with no row, a kernel step the matrix lacks, and a matrix
//!   step or row the tree does not declare are each red by name.
//! * **a cleanliness crate's coverage is re-pointed, never retired** (BUSBAR-1.6.0.md l.3987). A
//!   compiled-in cleanliness crate (spec Part 2 #26) is not a plane and states no `PlaneMeta`, so
//!   its steps cannot ride the plane roster; they live under `cleanliness_rows`, one row per entry
//!   of the gate's own [`CLEANLINESS_ROWS`] list, and every rule below judges those rows exactly as
//!   it judges a plane row: every cell, every cited loop test, `--root-legs` and the gating bar.
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
use crate::gates::{kind_isolation, prove_green, prove_red, Gate, Report};
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
/// The capability-equality ledger's two columns, judged by the same run rule as this matrix's
/// (Law 10, status row 178): its root column, and each cell's own test wherever it cites the
/// composition root's build. Its enforcing cargo test (`crates/busbar/tests/capability_equality.rs`)
/// reads only the source, so whether CI's build compiles a cited cell is asked here, where the
/// module tree is read.
pub const ROW_EQUALITY_CELLS: &str = "teller-steps:equality-root-cells";

/// The capability-equality ledger whose root column [`ROW_EQUALITY_CELLS`] judges.
pub const EQUALITY_REL: &str = "qa/capability-equality.json";

/// The ledger key the cleanliness rows live under, beside `matrix`.
pub const CLEANLINESS_KEY: &str = "cleanliness_rows";

/// THE CLEANLINESS ROWS THE GATE OWES, as a FIXED list: `(row, crate, manifest)`. A cleanliness
/// crate (spec Part 2 #26: compiled-in, one-way dep on the kernel, no plugin face) is not a plane
/// and must never state a `PlaneMeta` again just to be counted, so its row cannot be derived from
/// the plane roster. It is named here instead, and a reviewable edit to this list is the only way
/// to add or drop one. Each entry must carry a row; each row must be an entry; and the row is then
/// judged under every rule a plane row is (spec l.3987: coverage "is re-pointed, never retired").
pub const CLEANLINESS_ROWS: [(&str, &str, &str); 1] = [(
    "admin",
    "busbar-core-admin",
    "crates/busbar-core-admin/Cargo.toml",
)];

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

    /// The cleanliness rows (`cleanliness_rows`), `Null` when the ledger carries none.
    pub fn cleanliness(&self) -> &Json {
        self.doc.get(CLEANLINESS_KEY)
    }

    /// Is `row` a cleanliness row rather than a plane row?
    pub fn is_cleanliness(&self, row: &str) -> bool {
        self.cleanliness()
            .as_object()
            .is_some_and(|o| o.contains_key(row))
    }

    /// Where `row` lives in the ledger, as a message names it: `matrix.<row>` or
    /// `cleanliness_rows.<row>`.
    pub fn at(&self, row: &str) -> String {
        if self.is_cleanliness(row) {
            format!("{CLEANLINESS_KEY}.{row}")
        } else {
            format!("matrix.{row}")
        }
    }

    /// The PLANE rows only, sorted — what the `PlaneMeta` roster is held to.
    pub fn plane_rows(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .matrix()
            .as_object()
            .map(|o| o.keys().map(str::to_string).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    /// The cleanliness rows only, sorted.
    pub fn cleanliness_rows(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .cleanliness()
            .as_object()
            .map(|o| o.keys().map(str::to_string).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    /// The declared step order — the file's key order, which is the render sequence.
    pub fn step_order(&self) -> Vec<String> {
        self.steps()
            .as_object()
            .map(|o| o.keys().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// EVERY JUDGED ROW, SORTED: the plane rows (`sorted(matrix)` in the Python) and the
    /// cleanliness rows together, and the order every message and every rendered line comes out
    /// in. Every rule iterates this, which is what holds a cleanliness row to the plane rows' rules
    /// without a second copy of any of them. Only the `PlaneMeta` roster reads [`Self::plane_rows`].
    pub fn planes(&self) -> Vec<String> {
        let mut v = self.plane_rows();
        v.extend(self.cleanliness_rows());
        v.sort();
        v
    }

    fn cell(&self, plane: &str, step: &str) -> &Json {
        if self.is_cleanliness(plane) {
            self.cleanliness().get(plane).get(step)
        } else {
            self.matrix().get(plane).get(step)
        }
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
    let mut planes: Vec<(&str, &str)> = matrix
        .as_object()
        .expect("checked above")
        .keys()
        .map(|k| ("matrix", k))
        .collect();
    planes.sort_unstable();

    // THE CLEANLINESS ROWS ARE STRUCTURALLY THE SAME AS A PLANE ROW and are validated by the same
    // loop. A row under both keys would be judged twice under one name, so that is a refusal.
    let cleanliness = doc.get(CLEANLINESS_KEY);
    if !matches!(cleanliness, Json::Null) {
        let Some(c) = cleanliness.as_object() else {
            return Err(format!(
                "{LEDGER_REL}: '{CLEANLINESS_KEY}' is not an object of rows"
            ));
        };
        let mut rows: Vec<&str> = c.keys().collect();
        rows.sort_unstable();
        for row in rows {
            if matrix.get(row).as_object().is_some() {
                return Err(format!(
                    "{LEDGER_REL}: {CLEANLINESS_KEY}.{row} is also matrix.{row} -- one row under \
                     two keys is judged twice under one name"
                ));
            }
            planes.push((CLEANLINESS_KEY, row));
        }
    }

    for (section, plane) in planes {
        let row = doc.get(section).get(plane);
        let Some(row_obj) = row.as_object() else {
            return Err(format!("{LEDGER_REL}: {section}.{plane} is not an object"));
        };
        let present: BTreeSet<String> = row_obj.keys().map(str::to_string).collect();
        let missing: Vec<&String> = declared.difference(&present).collect();
        if !missing.is_empty() {
            return Err(format!(
                "{LEDGER_REL}: {section}.{plane} is missing step(s) {}",
                py_list(missing.into_iter().map(String::as_str))
            ));
        }
        for step in row_obj.keys() {
            if !declared.contains(step) {
                return Err(format!(
                    "{LEDGER_REL}: {section}.{plane}.{step} names an undeclared step"
                ));
            }
            let cell = row.get(step);
            let (Some(cell_id), Some(status)) =
                (cell.get("cell").as_str(), cell.get("status").as_str())
            else {
                return Err(format!(
                    "{LEDGER_REL}: {section}.{plane}.{step} has no cell/status"
                ));
            };
            if !STATUSES.contains(&status) {
                return Err(format!(
                    "{LEDGER_REL}: {section}.{plane}.{step}.status {} is not one of {}",
                    json_lite::py_repr(status),
                    py_list(STATUSES)
                ));
            }
            // A GAP IS A GAP IN BOTH COLUMNS. `cell == "none"` and `status == "none"` must agree,
            // or one of the two spellings is a gap the other column reports as covered.
            if (cell_id == "none") != (status == "none") {
                return Err(format!(
                    "{LEDGER_REL}: {section}.{plane}.{step} cell/status disagree on whether this is \
                     a gap (cell={} status={})",
                    json_lite::py_repr(cell_id),
                    json_lite::py_repr(status)
                ));
            }
        }
    }

    Ok(Matrix { doc })
}

// -------------------------------------------------------------------------------------------
// The roster: the matrix's steps and planes, held to what the tree declares
// -------------------------------------------------------------------------------------------

/// WHERE THE LOOP'S STEPS ARE DECLARED. The kernel's teller (`crates/busbar-kernel/src/teller.rs`)
/// does not restate them: it imports the step markers and `StepName` from the contract, whose
/// `StepName::ALL` (step.rs:67, the enum at step.rs:42) is "every step, in the order the loop runs
/// them". The spec's list is THE DESIGN §1 (docs/design/BUSBAR-1.6.0.md:153-154) and its #72 row
/// (:2266), which cites this file.
pub const KERNEL_STEPS_REL: &str = "crates/busbar-contract/src/caps/step.rs";

/// The Teller's steps IN LOOP ORDER, read off the kernel's own declaration: the variants of
/// `StepName::ALL`, each spelled as its `as_str` arm spells it (`StepName::Arrival => "arrival"`).
///
/// A file that no longer carries either shape is an `Err`, never an empty roster: an empty roster
/// is the passing answer to "does the matrix lack a step the kernel has".
pub fn kernel_steps(cx: &Ctx) -> Result<Vec<String>, String> {
    let text = cx
        .read(KERNEL_STEPS_REL)
        .map_err(|e| format!("{KERNEL_STEPS_REL}: {e}"))?;
    // Comments are not declarations: strip every `//` tail before reading either shape.
    let code: String = text
        .lines()
        .map(|l| l.split_once("//").map_or(l, |(c, _)| c))
        .collect::<Vec<_>>()
        .join("\n");
    let no_all = || {
        format!(
            "{KERNEL_STEPS_REL}: no `pub const ALL: [StepName; N] = [...];` -- the kernel's step \
             order cannot be read, so the matrix's steps are held to nothing"
        )
    };
    let at = code.find("pub const ALL: [StepName;").ok_or_else(no_all)?;
    let rest = &code[at..];
    let open = rest.find("= [").ok_or_else(no_all)? + "= [".len();
    let close = rest[open..].find("];").ok_or_else(no_all)?;
    let mut steps = Vec::new();
    for item in rest[open..open + close]
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let variant = item.strip_prefix("StepName::").ok_or_else(|| {
            format!("{KERNEL_STEPS_REL}: StepName::ALL carries {item:?}, which is not a StepName")
        })?;
        let arm = format!("StepName::{variant} => \"");
        let name = code
            .find(&arm)
            .map(|i| &code[i + arm.len()..])
            .and_then(|tail| tail.split_once('"'))
            .map(|(name, _)| name.to_string())
            .ok_or_else(|| {
                format!(
                    "{KERNEL_STEPS_REL}: StepName::{variant} has no `as_str` arm spelling it -- \
                     the step's runtime name cannot be read"
                )
            })?;
        steps.push(name);
    }
    if steps.is_empty() {
        return Err(no_all());
    }
    Ok(steps)
}

/// THE MATRIX'S ROSTER, HELD TO THE TREE. The matrix used to be checked only against itself:
/// "every plane carries every declared step" is true of whatever plane list and step list the file
/// wrote. So both lists are now derived and compared, and every difference is named:
///
/// * the STEPS are the kernel's ([`kernel_steps`]) as a set AND in order. A step the kernel runs
///   that the matrix lacks is a step no plane is measured on; a step the matrix carries that the
///   kernel does not declare is a cell about nothing.
/// * the ROWS are the planes the tree declares: every plane-kind crate (the kind census,
///   [`kind_isolation::plane_meta_declarations`]) must state a `PlaneMeta` KEY, and every key it
///   states must be a row. A row must in turn be a key SOME crate's `impl PlaneMeta` states, which
///   refuses a row for a plane nothing declares any more.
/// * the CLEANLINESS ROWS are the gate's own [`CLEANLINESS_ROWS`] list, never the plane roster: a
///   listed crate with no row is coverage retired rather than re-pointed, a row the list does not
///   name is a row about nothing the gate owes, a listed crate whose manifest is gone is a row for
///   a crate the tree no longer has, and a cleanliness row some crate's `impl PlaneMeta` declares
///   is a plane, whose row belongs in `matrix`.
pub fn check_roster(cx: &Ctx, m: &Matrix) -> Vec<String> {
    let mut out = Vec::new();
    let order = m.step_order();
    match kernel_steps(cx) {
        Err(e) => out.push(e),
        Ok(kernel) => {
            for s in kernel.iter().filter(|s| !order.contains(s)) {
                out.push(format!(
                    "{LEDGER_REL}: the kernel declares step {} ({KERNEL_STEPS_REL} \
                     StepName::ALL), which the matrix's 'steps' lacks -- a step no plane is \
                     measured on",
                    json_lite::py_repr(s)
                ));
            }
            for s in order.iter().filter(|s| !kernel.contains(s)) {
                out.push(format!(
                    "{LEDGER_REL}: steps.{s} is a step the kernel does not declare \
                     ({KERNEL_STEPS_REL} StepName::ALL runs {}) -- a cell about no step",
                    py_seq(&kernel)
                ));
            }
            let same_set = kernel.len() == order.len() && kernel.iter().all(|s| order.contains(s));
            if same_set && kernel != order {
                out.push(format!(
                    "{LEDGER_REL}: 'steps' runs {}, but the kernel's loop runs {} \
                     ({KERNEL_STEPS_REL} StepName::ALL) -- the matrix's order is the render \
                     sequence and must be the loop's",
                    py_seq(&order),
                    py_seq(&kernel)
                ));
            }
        }
    }

    let rows: BTreeSet<String> = m.plane_rows().into_iter().collect();
    let clean: BTreeSet<String> = m.cleanliness_rows().into_iter().collect();
    for (row, krate, manifest) in CLEANLINESS_ROWS {
        if !clean.contains(row) {
            out.push(format!(
                "{LEDGER_REL}: cleanliness crate {krate} carries no {CLEANLINESS_KEY}.{row} -- its \
                 Teller steps are measured nowhere, and coverage is re-pointed, never retired \
                 (BUSBAR-1.6.0.md l.3987)"
            ));
        }
        if !cx.exists(manifest) {
            out.push(format!(
                "{LEDGER_REL}: {CLEANLINESS_KEY}.{row} is owed by cleanliness crate {krate}, whose \
                 manifest {manifest} does not exist -- a row for a crate the tree does not have"
            ));
        }
    }
    for row in clean
        .iter()
        .filter(|r| !CLEANLINESS_ROWS.iter().any(|(c, _, _)| *c == r.as_str()))
    {
        out.push(format!(
            "{LEDGER_REL}: {CLEANLINESS_KEY}.{row} names no cleanliness crate the gate's \
             CLEANLINESS_ROWS list owes -- a row about nothing the gate judges"
        ));
    }
    match kind_isolation::plane_meta_declarations(cx) {
        Err(e) => out.push(format!(
            "{LEDGER_REL}: the plane roster cannot be derived: {e}"
        )),
        Ok(decls) => {
            if !decls.iter().any(|d| d.plane_kind) {
                out.push(format!(
                    "{LEDGER_REL}: the kind census finds NO plane-kind crate, so no row is held \
                     to a plane -- an empty roster is the passing answer to every row check"
                ));
            }
            let declared: BTreeSet<&str> = decls
                .iter()
                .flat_map(|d| d.keys.iter().map(String::as_str))
                .collect();
            for d in decls.iter().filter(|d| d.plane_kind) {
                if d.keys.is_empty() {
                    out.push(format!(
                        "{LEDGER_REL}: plane crate {} states no `impl PlaneMeta` KEY, so the \
                         matrix cannot be held to it",
                        d.krate
                    ));
                }
                for key in d.keys.iter().filter(|k| !rows.contains(*k)) {
                    out.push(format!(
                        "{LEDGER_REL}: plane crate {} declares plane {}, which carries no matrix \
                         row -- a plane with no row is a plane no step is measured on",
                        d.krate,
                        json_lite::py_repr(key)
                    ));
                }
            }
            for row in rows.iter().filter(|r| !declared.contains(r.as_str())) {
                out.push(format!(
                    "{LEDGER_REL}: matrix.{row} is a plane no crate declares (no `impl \
                     PlaneMeta` states KEY {}) -- a row for a plane the tree does not have",
                    json_lite::py_repr(row)
                ));
            }
            for row in clean.iter().filter(|r| declared.contains(r.as_str())) {
                out.push(format!(
                    "{LEDGER_REL}: {CLEANLINESS_KEY}.{row} is a key some crate's `impl PlaneMeta` \
                     declares -- a plane's row belongs in 'matrix', and a cleanliness crate states \
                     no PlaneMeta"
                ));
            }
        }
    }
    out
}

/// A sequence in Python's list repr, IN ITS OWN ORDER (unlike [`py_list`], which sorts).
fn py_seq(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| json_lite::py_repr(s))
            .collect::<Vec<_>>()
            .join(", ")
    )
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
/// The rigs whose scenarios are named checks of ONE source file (the jev rig is Rust, run by
/// `cargo xtask conformance record --suite jev`; it writes no per-scenario ledger row the
/// rigs-baseline could carry). A cell `<namespace>|<check>` is owned by the file only while the
/// file DECLARES the check's name as a whole token.
const FILE_RIGS: [(&str, &str); 1] = [("jev.rig", "xtask/src/conformance_record/jev.rs")];
const SOURCE_DIRS: [(&str, &str); 2] = [
    ("mcp.battery", "testing/mcp-conformance/src/suites"),
    ("a2a.supplement", "testing/a2a-supplement/a2asup"),
];

/// Which file in the tree OWNS a named rig cell, or `None` — the "nothing owns this any more"
/// answer that makes the claim red.
pub fn resolve_cell(cx: &Ctx, cell_id: &str) -> Option<String> {
    CellOwners::new(cx).resolve(cell_id)
}

/// THE RIG COLUMN'S EVIDENCE, READ ONCE PER RUN AND NOT ONCE PER CELL.
///
/// [`resolve_cell`] used to re-read its evidence for every cell it was asked about: it parsed
/// `testing/shadow-oracle/cells.json` (1.4 MB) and `rigs-baseline.json` afresh, and re-listed each
/// suite directory with `read_dir`, sixty times per gate run — once per cell of the matrix. A
/// self-test case is a gate run over a tree one plant away from the last, so the `teller-steps`
/// battery parsed the oracle's cell list some 1 400 times and went over its work-unit budget
/// (25 754 of 25 237 on ModernCI, 2026-10-18) doing it. Nothing a run reads changes between two
/// cells of the same run, so the owners are read here once and every cell is put to the same
/// answer, in the same arm order, as before. The oracle's id set is a pure function of the file's
/// bytes, so it is also memoised on them ([`oracle_ids_of`]): a plant that edits `cells.json` is
/// read fresh, and every other case re-uses the reading.
struct CellOwners<'c> {
    cx: &'c Ctx,
    /// The oracle's cell ids ([`oracle_cell_ids`]), read on first use.
    oracle: std::cell::OnceCell<std::sync::Arc<BTreeSet<String>>>,
    /// `rigs-baseline.json`'s row keys ([`rig_baseline_ids`]), read on first use.
    baseline: std::cell::OnceCell<BTreeSet<String>>,
    /// Each [`SOURCE_DIRS`] base's sorted file list ([`collect_paths`]), listed on first use.
    listed: std::cell::RefCell<BTreeMap<&'static str, std::rc::Rc<Vec<String>>>>,
}

impl<'c> CellOwners<'c> {
    fn new(cx: &'c Ctx) -> CellOwners<'c> {
        CellOwners {
            cx,
            oracle: std::cell::OnceCell::new(),
            baseline: std::cell::OnceCell::new(),
            listed: std::cell::RefCell::new(BTreeMap::new()),
        }
    }

    /// Which file in the tree OWNS `cell_id` — [`resolve_cell`]'s answer, arm for arm.
    fn resolve(&self, cell_id: &str) -> Option<String> {
        let cx = self.cx;
        if self
            .oracle
            .get_or_init(|| oracle_cell_ids(cx))
            .contains(cell_id)
        {
            return Some(ORACLE_CELLS_REL.to_string());
        }
        let (namespace, rest) = cell_id.split_once('|')?;
        if rest.is_empty() {
            return None;
        }

        // THE H2 ARM RETURNS EARLY WHETHER OR NOT IT RESOLVES. A `mcp.rig|h2-…` id whose subject
        // script vanished must not fall through into the arms below and be adopted by a substring
        // match somewhere else — that is exactly how a deleted script keeps a green row.
        if let Some((_, dir)) = H2_DIRS.iter().find(|(ns, _)| *ns == namespace) {
            if rest.starts_with("h2-") {
                let path = format!("{dir}/{rest}.sh");
                return cx.exists(&path).then_some(path);
            }
        }

        // THE FILE ARM RETURNS EARLY TOO, for the H2 arm's reason: a check renamed out of its rig's
        // file must not be adopted by another arm's search somewhere else.
        if let Some((_, file)) = FILE_RIGS.iter().find(|(ns, _)| *ns == namespace) {
            return cx
                .read(file)
                .is_ok_and(|t| declares_id(&t, rest))
                .then(|| (*file).to_string());
        }

        if namespace == "voice.rig" {
            let path = format!("testing/voice-conformance/legs/{rest}.sh");
            if cx.exists(&path) {
                return Some(path);
            }
        }

        if let Some((_, base)) = SOURCE_DIRS.iter().find(|(ns, _)| *ns == namespace) {
            if let Some(owner) = self.declared_in_source(base, rest) {
                return Some(owner);
            }
        }

        if self
            .baseline
            .get_or_init(|| rig_baseline_ids(cx))
            .contains(cell_id)
        {
            return Some("testing/shadow-oracle/rigs-baseline.json".to_string());
        }
        None
    }

    /// The first file under `base`, in sorted path order, that DECLARES `needle` as a whole token.
    /// The listing is taken once per base per run; each file is still read through the context, so
    /// a plant's bytes are the ones searched.
    fn declared_in_source(&self, base: &'static str, needle: &str) -> Option<String> {
        let paths = std::rc::Rc::clone(
            self.listed
                .borrow_mut()
                .entry(base)
                .or_insert_with(|| std::rc::Rc::new(source_paths(self.cx, base))),
        );
        paths
            .iter()
            .find(|rel| {
                self.cx
                    .read(rel.as_str())
                    .is_ok_and(|t| declares_id(&t, needle))
            })
            .cloned()
    }
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

/// Every file under `base`, in sorted path order — the candidates [`CellOwners`] searches.
fn source_paths(cx: &Ctx, base: &str) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    collect_paths(&cx.abs(base), cx.root(), &mut paths);
    paths.sort();
    paths
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

/// Ids read out of a JSON document's list-of-objects keyed by `id`. An unreadable or unparseable
/// file yields an EMPTY set, matching the Python — and the emptiness is never itself a pass,
/// because a cell that resolves nowhere is red.
fn ids_in(text: &str, list_key: &str) -> BTreeSet<String> {
    json_lite::parse(text)
        .ok()
        .and_then(|d| d.get(list_key).as_array().map(<[Json]>::to_vec))
        .map(|cells| {
            cells
                .iter()
                .filter_map(|c| c.get("id").as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

const ORACLE_CELLS_REL: &str = "testing/shadow-oracle/cells.json";

fn oracle_cell_ids(cx: &Ctx) -> std::sync::Arc<BTreeSet<String>> {
    match cx.read(ORACLE_CELLS_REL) {
        Ok(text) => oracle_ids_of(&text),
        Err(_) => std::sync::Arc::new(BTreeSet::new()),
    }
}

/// The oracle's cell ids read out of `text` — [`ids_in`] over `cells.json`'s bytes — MEMOISED ON
/// THOSE BYTES. The reading is a pure function of them, so a case that plants a different
/// `cells.json` is read fresh and every case that does not shares one parse.
fn oracle_ids_of(text: &str) -> std::sync::Arc<BTreeSet<String>> {
    use std::hash::{Hash, Hasher};
    use std::sync::{Arc, Mutex, OnceLock};
    type Cell = Arc<OnceLock<Arc<BTreeSet<String>>>>;
    type Memo = Mutex<BTreeMap<(usize, u64, u64), Cell>>;
    static MEMO: OnceLock<Memo> = OnceLock::new();
    let mut a = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut a);
    let mut b = std::collections::hash_map::DefaultHasher::new();
    (text.len(), text).hash(&mut b);
    0x7e1_u32.hash(&mut b);
    let key = (text.len(), a.finish(), b.finish());
    // The cell is handed out under the lock and FILLED OUTSIDE it, so concurrent cases that need the
    // same bytes take one parse between them instead of one each.
    let cell = MEMO
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(key)
        .or_default()
        .clone();
    cell.get_or_init(|| Arc::new(ids_in(text, "cells"))).clone()
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
    let owners = CellOwners::new(cx);
    for plane in m.planes() {
        for step in m.step_order() {
            let cell = m.cell(&plane, &step);
            let cell_id = cell.str_or("cell", "");
            if cell_id == "none" {
                continue;
            }
            if owners.resolve(&cell_id).is_none() {
                out.push(format!(
                    "{LEDGER_REL}: {}.{step} names rig cell {}, which NOTHING in the \
                     tree owns -- no oracle cell of that id, no h2 subject script, no voice leg, \
                     no jev rig check, no suite source declaring it and no row in \
                     rigs-baseline.json. The scenario \
                     was renamed or deleted; a claim that outlives its evidence is the drift this \
                     check exists to stop",
                    m.at(&plane),
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
    check_root_column_in(cx, m, &CiView::of(cx))
}

/// WHAT RUNS IN CI: the composition root's module tree, read off the source with every cfg on the
/// way to each file, and the build CI's `test` check compiles it in ([`crate::ci_cfg`]). Read once
/// per gate run and handed to both root columns. A cited file the root's tree does not reach is
/// looked for in the test targets of the crate that compiles it (the root's own integration-test
/// targets, then any other workspace member's lib, bin and test targets), each read once and kept.
pub struct CiView {
    tree: crate::libtest_path::ModuleTree,
    ci: Result<crate::ci_cfg::CiBuild, String>,
    /// target root file -> its module tree, read on first use.
    targets: std::sync::Mutex<BTreeMap<String, ModuleTreeRef>>,
}

type ModuleTreeRef = std::sync::Arc<crate::libtest_path::ModuleTree>;

impl CiView {
    pub fn of(cx: &Ctx) -> CiView {
        CiView {
            tree: crate::libtest_path::module_tree(&|rel: &str| cx.read(rel).ok(), BUSBAR_MAIN),
            ci: cx
                .read(MANIFEST_REL)
                .and_then(|t| crate::ci_cfg::CiBuild::of_manifest(&t))
                .map_err(|e| format!("{MANIFEST_REL}: {e}")),
            targets: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// `Ok` when `file::func` is a test CI's build compiles and runs; else why not.
    fn runs(&self, file: &str, func: &str) -> Result<(), String> {
        let ci = self.ci.as_ref().map_err(|e| {
            format!("CI's test build could not be derived, so no cell is shown to run ({e})")
        })?;
        crate::libtest_path::resolve_cell(&self.tree, file, func).and_then(|c| ci.runs(&c))
    }

    /// THE VERDICT FOR ANY CITATION: `None` when `file` is outside this workspace (a pinned
    /// plugin's own repo, whose tests that repo's CI builds), else whether CI's `test` check
    /// (`cargo nextest run --workspace`) compiles and runs `file::func`:
    /// - a file the composition root's binary reaches (door cells included) is judged in that build;
    /// - else, in each target that reaches it, under the build of the crate that target belongs
    ///   to: the file's own crate's lib, bin and the integration-test target its path spells, then
    ///   (when none of those runs it) every test target of that crate and the composition root's
    ///   targets that include a plane crate's driver-proofs cases. A target whose
    ///   `required-features` its crate's build lacks is never built. One target that runs it is
    ///   enough;
    /// - a file of a workspace crate no target reaches is a refusal, never skipped.
    fn judge(&self, cx: &Ctx, file: &str, func: &str) -> Option<Result<(), String>> {
        if self.tree.paths.contains_key(file) {
            return Some(self.runs(file, func));
        }
        let member = workspace_member_of(cx, file)?;
        let mut why = Vec::new();
        for full in [false, true] {
            for target in target_candidates(cx, &member, file, full) {
                let tree = self.tree_at(cx, &target);
                if !tree.paths.contains_key(file) {
                    continue;
                }
                match self.runs_in_target(cx, &target, &tree, file, func) {
                    Ok(()) => return Some(Ok(())),
                    Err(e) => {
                        let e = format!("in {target}: {e}");
                        if !why.contains(&e) {
                            why.push(e);
                        }
                    }
                }
            }
        }
        if !why.is_empty() {
            return Some(Err(why.join("; ")));
        }
        if file.starts_with(BUSBAR_SRC) {
            // Reached by no `mod` from the root: `runs` names that refusal.
            return Some(self.runs(file, func));
        }
        Some(Err(format!(
            "{file} is reached by no target of {member} (its lib, bin or test targets), nor by \
             the composition root's, so no test in it runs"
        )))
    }

    /// `file::func` in `target` (a root file `tree` was read from), under the build of the crate
    /// `target` belongs to: the composition root's derived build, or another member's
    /// ([`crate::ci_cfg::CiBuild::of_member_manifest`]).
    fn runs_in_target(
        &self,
        cx: &Ctx,
        target: &str,
        tree: &crate::libtest_path::ModuleTree,
        file: &str,
        func: &str,
    ) -> Result<(), String> {
        let krate = workspace_member_of(cx, target).unwrap_or_else(|| BUSBAR_DIR.to_string());
        let manifest_rel = format!("{krate}/Cargo.toml");
        let manifest = cx.read(&manifest_rel).unwrap_or_default();
        let build = if krate == BUSBAR_DIR {
            self.ci.clone().map_err(|e| {
                format!("CI's test build could not be derived, so no cell is shown to run ({e})")
            })?
        } else {
            crate::ci_cfg::CiBuild::of_member_manifest(&manifest)
        };
        let off: Vec<String> = required_features(&manifest, &krate, target)
            .into_iter()
            .filter(|f| !build.features.contains(f))
            .collect();
        if !off.is_empty() {
            return Err(format!(
                "its test target {target} requires feature(s) {} ({manifest_rel} \
                 `required-features`), which {} does not enable, so cargo never builds it",
                py_list(off.iter().map(String::as_str)),
                crate::ci_cfg::CI_TEST_BUILD
            ));
        }
        crate::libtest_path::resolve_cell(tree, file, func).and_then(|c| build.runs(&c))
    }

    /// The module tree rooted at `target`, read once per view.
    fn tree_at(&self, cx: &Ctx, target: &str) -> ModuleTreeRef {
        let mut cache = self
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache
            .entry(target.to_string())
            .or_insert_with(|| {
                std::sync::Arc::new(crate::libtest_path::module_tree(
                    &|rel: &str| cx.read(rel).ok(),
                    target,
                ))
            })
            .clone()
    }
}

/// The targets that may compile `file`, a file of the workspace member at `krate`, each an existing
/// root file. Not `full`: the cheap ones, the member's lib and bin (the composition root's bin is
/// [`CiView::tree`] itself) and the integration-test target `file`'s path spells. `full`: every
/// test target of the member ([`target_roots`]), and the composition root's targets that include a
/// plane crate's driver-proofs cases (`tests/on_driver/`, compiled only there).
fn target_candidates(cx: &Ctx, krate: &str, file: &str, full: bool) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    if full {
        out.extend(target_roots(cx, krate));
        if krate != BUSBAR_DIR {
            out.extend(target_roots(cx, BUSBAR_DIR).into_iter().filter(|r| {
                cx.read(r)
                    .is_ok_and(|t| t.contains(crate::libtest_path::DRIVER_PROOFS_FILE))
            }));
        }
    } else {
        if krate != BUSBAR_DIR {
            let manifest = cx.read(format!("{krate}/Cargo.toml")).unwrap_or_default();
            let lib = crate::toml_lite::parse_text(&manifest)
                .table("lib")
                .get_one("path")
                .map_or_else(|| "src/lib.rs".to_string(), str::to_string);
            out.insert(format!("{krate}/{}", lib.trim_start_matches("./")));
            out.insert(format!("{krate}/src/main.rs"));
        }
        out.extend(target_root_of(krate, file));
    }
    out.into_iter().filter(|r| cx.exists(r)).collect()
}

/// The root files of the workspace member at `krate`'s integration-test targets, as its manifest
/// and its `tests/` directory state them: every `[[test]]` path, every `tests/<x>.rs` and
/// `tests/<x>/main.rs`. Whether each exists is the caller's question.
fn target_roots(cx: &Ctx, krate: &str) -> BTreeSet<String> {
    let manifest = cx.read(format!("{krate}/Cargo.toml")).unwrap_or_default();
    let mut roots: BTreeSet<String> = BTreeSet::new();
    for t in crate::toml_lite::parse_text(&manifest).array_table("test") {
        if let Some(p) = t.get_one("path") {
            roots.insert(format!("{krate}/{}", p.trim_start_matches("./")));
        }
    }
    let tests_dir = format!("{krate}/tests");
    if let Ok(rd) = std::fs::read_dir(cx.abs(&tests_dir)) {
        for e in rd.filter_map(Result::ok) {
            let name = e.file_name().to_string_lossy().to_string();
            if e.path().is_dir() {
                roots.insert(format!("{tests_dir}/{name}/main.rs"));
            } else if name.ends_with(".rs") {
                roots.insert(format!("{tests_dir}/{name}"));
            }
        }
    }
    roots
}

/// A workspace member's test file a capability-equality cell's own column cites (the kernel's
/// breaker cells), which the selftest extends with a cell CI's build is not shown to compile.
const MEMBER_CELL_FILE: &str = "crates/busbar-kernel/src/tests/breaker_tests.rs";
/// A file in that member no `mod` and no target reaches, planted by the selftest.
// qa-names: crates/busbar-kernel/src/tests/a_file_no_mod_reaches.rs -- xtask/src/gates/teller_steps.rs -- a PLANT: the selftest writes this file into an overlay to show a cited cell no target reaches is refused; its absence from the tree is the point
const MEMBER_UNREACHED_FILE: &str = "crates/busbar-kernel/src/tests/a_file_no_mod_reaches.rs";

/// The composition root's crate directory.
const BUSBAR_DIR: &str = "crates/busbar";
/// The composition root's own sources: every test under here is compiled, if at all, by the build
/// [`CiView`] models.
const BUSBAR_SRC: &str = "crates/busbar/src/";
/// The composition root's integration-test targets, one per `<name>.rs` directly under here.
const BUSBAR_TESTS: &str = "crates/busbar/tests/";
/// The workspace manifest whose `[workspace] members` CI's `--workspace` run builds.
const WORKSPACE_MANIFEST: &str = "Cargo.toml";

/// The workspace member (its directory, as `[workspace] members` spells it) whose tree holds
/// `file`; `None` for a file outside every member (a pinned plugin's own repo).
fn workspace_member_of(cx: &Ctx, file: &str) -> Option<String> {
    let doc = crate::toml_lite::parse_text(&cx.read(WORKSPACE_MANIFEST).ok()?);
    doc.table("workspace")
        .get_list("members")
        .into_iter()
        .filter(|m| file.starts_with(&format!("{m}/")))
        .max_by_key(String::len)
}

/// The integration-test target cargo compiles `file` as, spelled from its path alone: `file` itself
/// when it is `<crate>/tests/<name>.rs`, else `<crate>/tests/<dir>/main.rs` for a file under
/// `<crate>/tests/<dir>/` (whether that target exists is the caller's question).
fn target_root_of(krate: &str, file: &str) -> Option<String> {
    let rest = file.strip_prefix(&format!("{krate}/tests/"))?;
    match rest.split_once('/') {
        None => rest.ends_with(".rs").then(|| file.to_string()),
        Some((dir, _)) => Some(format!("{krate}/tests/{dir}/main.rs")),
    }
}

/// Points the first `proven` cell of a capability-equality document at `cited` in its own column;
/// `false` when no cell is proven.
fn plant_own_test(eq: &mut Json, cited: &str) -> bool {
    let Some(Json::Array(cells)) = eq.as_object_mut().and_then(|d| d.get_mut("cells")) else {
        return false;
    };
    for c in cells.iter_mut() {
        if c.str_or("state", "") != "proven" {
            continue;
        }
        if let Some(o) = c.as_object_mut() {
            o.insert("test", Json::Str(cited.to_string()));
            return true;
        }
    }
    false
}

/// The `required-features` of the `[[test]]` table in `manifest` (the manifest of the crate at
/// `krate`) whose `path` is `target` (stated relative to the crate: `tests/x.rs`); empty when no
/// such table states any.
fn required_features(manifest: &str, krate: &str, target: &str) -> Vec<String> {
    let rel = target.strip_prefix(&format!("{krate}/")).unwrap_or(target);
    crate::toml_lite::parse_text(manifest)
        .array_table("test")
        .into_iter()
        .filter(|t| t.get_one("path").map(|p| p.trim_start_matches("./")) == Some(rel))
        .flat_map(|t| t.get_list("required-features"))
        .collect()
}

fn check_root_column_in(cx: &Ctx, m: &Matrix, view: &CiView) -> RootProblems {
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
    // A door plane's own root cells (its crate's `tests/root/mod.rs`, a
    // `plane-door` row of `[package.metadata.busbar.linked]`) compile into the root's serve module, so a leg's
    // evidence may live there: the cells are written in the plane's own words in the plane's crate.
    let door_cells: BTreeSet<String> =
        crate::libtest_path::door_cells(&|rel: &str| cx.read(rel).ok(), BUSBAR_MAIN)
            .into_iter()
            .map(|(_, file)| file)
            .collect();
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
        if !file.starts_with(ROOT_DIR) && !door_cells.contains(&file) {
            p.legs.push(format!(
                "{LEDGER_REL}: root leg {} names file {}, which is not under {ROOT_DIR} and is no \
                 door plane's own root cells -- a leg's evidence lives in the composition root",
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
        let at = m.at(&plane);
        for step in m.step_order() {
            let r = m.cell(&plane, &step).get("root");
            if r.as_object().is_none() {
                p.column.push(format!(
                    "{LEDGER_REL}: {at}.{step} carries no 'root' verdict -- an absent \
                     second verdict is indistinguishable from an oversight"
                ));
                continue;
            }
            let state = r.str_or("state", "");
            if !ROOT_STATES.contains(&state.as_str()) {
                p.column.push(format!(
                    "{LEDGER_REL}: {at}.{step}.root.state {} is not one of {}",
                    json_lite::py_repr_json(r.get("state")),
                    py_list(ROOT_STATES)
                ));
                continue;
            }
            let named_leg = r.str_or("leg", "");
            if &named_leg != leg {
                p.column.push(format!(
                    "{LEDGER_REL}: {at}.{step}.root names leg {}, but plane {} runs \
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
                    "{LEDGER_REL}: {at}.{step}.root has note {}: {why}",
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
                    "{LEDGER_REL}: {at}.{step}.root reuses the note already argued at \
                     {first} verbatim: a note copied between cells is boilerplate, not an \
                     argument about this cell's verdict"
                ));
                continue;
            }
            seen_notes.insert(note.clone(), format!("{at}.{step}"));
            if state == "none" {
                continue;
            }
            let test = r.str_or("test", "");
            let prefix = format!("{file}::");
            let Some(func) = test.strip_prefix(&prefix) else {
                p.column.push(format!(
                    "{LEDGER_REL}: {at}.{step}.root is proven by {}, which does not \
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
                    "{LEDGER_REL}: {at}.{step}.root is proven by {test}, but no `fn \
                     {func}(` exists there. The named loop cell is gone or renamed; a claim that \
                     outlives its evidence is the drift this check exists to stop"
                ));
                continue;
            }
            // THE NAMED CELL MUST RUN (Law 10). A fn that exists in a module no CI build compiles,
            // or that the harness skips, is a proof that never runs: the same green as one that
            // passed, which is what fourteen root-llm cells were once their node-axis row went.
            if let Err(why) = view.runs(file, func) {
                p.column.push(format!(
                    "{LEDGER_REL}: matrix.{plane}.{step}.root is proven by {test}, which no CI step \
                     runs: {why}. A proof may not point at a test that never runs"
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

/// THE CAPABILITY-EQUALITY LEDGER, BY THE SAME RUN RULE: every `proven` cell of [`EQUALITY_REL`]
/// names a test CI's build compiles and runs, in BOTH its columns. The root column always lives in
/// the composition root; the cell's own column is judged wherever it cites a file of this
/// workspace ([`CiView::judge`]): the root's binary or test targets, or another member crate's lib,
/// bin or test targets, each under the build CI's `--workspace` run compiles it in.
/// `audit-chain`x`llm` once cited a node-axis cell that compiles under `cfg(linked_axis_node)`,
/// which no CI build enables. A citation into a pinned plugin's own repo is that repo's CI's to
/// run, not this workspace's. Shape, ownership and
/// existence are the cargo gate's (`crates/busbar/tests/capability_equality.rs`); what this adds is
/// the question a source read there cannot answer, whether the cited fn is in the build that runs.
pub fn check_equality_cells(cx: &Ctx, view: &CiView) -> Vec<String> {
    let doc = match cx.read(EQUALITY_REL).and_then(|t| json_lite::parse(&t)) {
        Ok(d) => d,
        Err(e) => return vec![format!("{EQUALITY_REL}: {e}")],
    };
    let mut out = Vec::new();
    let mut proven = 0usize;
    let mut judged_own = 0usize;
    for cell in doc.get("cells").as_array().unwrap_or(&[]) {
        let id = format!(
            "{}x{}",
            cell.str_or("capability", "?"),
            cell.str_or("plane", "?")
        );
        // The cell's own column.
        if cell.str_or("state", "") == "proven" {
            let test = cell.str_or("test", "");
            if let Some((file, func)) = test.split_once("::") {
                if let Some(verdict) = view.judge(cx, file, func) {
                    judged_own += 1;
                    if let Err(why) = verdict {
                        out.push(format!(
                            "{EQUALITY_REL}: cell {id} is proven by {test}, which no CI step \
                             runs: {why}. A proof may not point at a test that never runs"
                        ));
                    }
                }
            }
        }
        // The root column.
        let r = cell.get("root");
        if r.str_or("state", "") != "proven" {
            continue;
        }
        proven += 1;
        let test = r.str_or("test", "");
        let Some((file, func)) = test.split_once("::") else {
            out.push(format!(
                "{EQUALITY_REL}: cell {id} is proven over the loop by {}, which names no \
                 `<file>::<fn>`",
                json_lite::py_repr(&test)
            ));
            continue;
        };
        if let Err(why) = view.runs(file, func) {
            out.push(format!(
                "{EQUALITY_REL}: cell {id} is proven over the loop by {test}, which no CI step \
                 runs: {why}. A proof may not point at a test that never runs"
            ));
        }
    }
    // Zero findings over zero cells is no verdict.
    if proven == 0 {
        out.push(format!(
            "{EQUALITY_REL}: no root cell is proven, so there is nothing to show runs -- an empty \
             column is not a column that passed"
        ));
    }
    if judged_own == 0 {
        out.push(format!(
            "{EQUALITY_REL}: no proven cell's own test is in this workspace's build, so \
             nothing in that column is shown to run -- a column judged over nothing is not a \
             column that passed"
        ));
    }
    out
}

// -------------------------------------------------------------------------------------------
// The shipped-leg bar, and the render
// -------------------------------------------------------------------------------------------

/// The features the binary SHIPS, read out of the manifest's own `default` line.
///
/// A deliberate one-line parse rather than a TOML load, and kept that way: the subject of the rule
/// is what a human wrote on that line, and a general parser that normalises the document answers a
/// different question.
pub fn default_features(text: &str) -> Result<BTreeSet<String>, String> {
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
            .filter(|f| !f.is_empty())
            .collect());
    }
    Err(format!(
        "{MANIFEST_REL}: no `default` line under [features]"
    ))
}

/// The root legs the binary SHIPS: every leg whose feature is on the manifest's `default` line. A
/// leg's feature is its `feature` member when it names one — the mcp, a2a and streaming legs are the
/// kernel-loop rider those planes are served through, gated by the feature that links the plane (`plane-mcp`,
/// `plane-a2a`, `plane-streaming`), the decision leg is the plane's door served by the root's serve path
/// (`plane-decisions`), and the llm leg is the root's node, compiled with the plane that rides
/// the `node` axis (`plane-llm`) — and otherwise the leg's own name (`root-admin`).
pub fn shipped_legs(m: &Matrix, default: &BTreeSet<String>) -> BTreeSet<String> {
    let legs = m.root_legs();
    legs.as_object()
        .map(|o| {
            o.keys()
                .filter(|leg| default.contains(&legs.get(leg).str_or("feature", leg)))
                .map(|leg| leg.to_string())
                .collect()
        })
        .unwrap_or_default()
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

/// The matrix's list of gating gaps OWED BY NAME: `"<plane>.<step>": "<owner>"`.
pub const OWED_KEY: &str = "owed_gaps";

/// The gating row's verdict: its problems, and the gaps it carries as owed (`plane.step (owner)`).
#[derive(Default)]
pub struct Gating {
    pub problems: Vec<String>,
    pub owed: Vec<String>,
}

/// THE GATING GAPS, HELD TO THE LIST THAT OWES THEM. A gating cell that is `"none"` is red unless
/// the matrix's [`OWED_KEY`] names it with an owner, and the list must be EXACTLY the measured gaps:
/// a gap nobody owes is red (a new gap is never absorbed), and an owed entry that is no longer a
/// gap is red until it is struck (the list only shrinks, and a closed gap cannot keep a slot open
/// for the next one). The owed gaps stay in the row's detail by name, so the floor is visible on
/// every green run.
pub fn check_gating(m: &Matrix) -> Gating {
    let gaps = gating_gaps(m);
    let owed_obj = m.doc.get(OWED_KEY);
    let mut g = Gating::default();
    let mut owed: BTreeMap<String, String> = BTreeMap::new();
    if let Some(o) = owed_obj.as_object() {
        for (cell, owner) in o.iter() {
            match owner.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                Some(owner) => {
                    owed.insert(cell.to_string(), owner.to_string());
                }
                None => g.problems.push(format!(
                    "{LEDGER_REL}: {OWED_KEY}.{cell} names no owner -- a gap owed by nobody is \
                     a gap hidden, not a gap owed"
                )),
            }
        }
    } else if !matches!(owed_obj, Json::Null) {
        g.problems.push(format!(
            "{LEDGER_REL}: '{OWED_KEY}' is not an object of \"<plane>.<step>\": \"<owner>\""
        ));
    }
    for gap in &gaps {
        match owed.get(gap) {
            Some(owner) => g.owed.push(format!("{gap} ({owner})")),
            None => g.problems.push(format!(
                "{gap} is a gating gap no '{OWED_KEY}' entry owes -- a new gap is red, never \
                 absorbed"
            )),
        }
    }
    for cell in owed.keys().filter(|c| !gaps.contains(c)) {
        g.problems.push(format!(
            "{LEDGER_REL}: {OWED_KEY}.{cell} is owed but is no longer a gating gap -- a closed \
             gap must be struck from the list"
        ));
    }
    g
}

/// The human matrix, byte-identical to the Python's — column widths 13 / 6 / 46 / 5, two-space
/// indent, and `info` padded to the width of `gating` so the bracket column lines up.
pub fn render(m: &Matrix) -> String {
    let mut lines = Vec::new();
    for plane in m.planes() {
        if m.is_cleanliness(&plane) {
            lines.push(format!("cleanliness {plane}:"));
        } else {
            lines.push(format!("plane {plane}:"));
        }
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
        "  (run them: cargo xtask teller-steps --root-legs -- builds the binary crate with every \
         leg on and executes every named loop cell)"
            .to_string(),
    );
    lines.join("\n")
}

// -------------------------------------------------------------------------------------------
// The runner arms — `cargo xtask teller-steps [...]`
// -------------------------------------------------------------------------------------------

/// The features that compile the root legs, which the `--root-legs` arm builds the binary crate
/// with: the admin leg's own feature, for the mcp, a2a and streaming legs (the kernel-loop rider those
/// planes are served through) the feature that links the plane, for the decision leg the feature that
/// links its door (`plane-decisions`; its cells are `root/serve.rs`'s `door_tests`), and for the llm
/// leg the feature that links the plane riding the `node` axis, which compiles the root's node
/// (`root/plane_node.rs`).
const ROOT_FEATURES: &str =
    "root-admin,plane-mcp,plane-a2a,plane-streaming,plane-decisions,plane-llm";

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
    // THE ROSTER, one `ROSTER:` line per difference between the matrix and what the tree
    // declares. The legacy adapter ([`translate`]) reads these lines back into the matrix row, so
    // the arm and the gate report the same finding.
    let roster = check_roster(cx, &m);
    for problem in &roster {
        println!("{ROSTER_PREFIX}{problem}");
    }
    let gating = check_gating(&m);
    for owed in &gating.owed {
        println!("{OWED_PREFIX}{owed}");
    }
    let rc = if gating.problems.is_empty() {
        println!(
            "GREEN: every gating plane x step cell in {LEDGER_REL} names a real scenario or is a \
             gap owed by name."
        );
        0
    } else {
        println!("RED: {}", gating.problems.join(" | "));
        1
    };
    if roster.is_empty() {
        rc
    } else {
        1
    }
}

/// The prefix of the arm's roster lines, which [`translate`] reads back.
const ROSTER_PREFIX: &str = "ROSTER: ";

/// The prefix of the arm's owed-gap lines, which [`translate`] reads back.
const OWED_PREFIX: &str = "OWED: ";

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
    let shipped = match cx.read(MANIFEST_REL).and_then(|t| default_features(&t)) {
        Ok(d) => shipped_legs(&m, &d),
        Err(e) => {
            eprintln!("ROOT-GATING: cannot read the bar's two inputs: {e}");
            return 1;
        }
    };
    let (lines, rc) = root_legs_gating_verdict(&m, &shipped);
    for line in lines {
        println!("{line}");
    }
    rc
}

/// The shipped legs that leave the bar nothing to judge (TODO l.1503-1515, Law 8): no leg ships at
/// all, or a shipped leg owns no gating plane x step cell. Over either, an empty `red` is a GREEN
/// over an empty set, so the bar refuses instead of passing.
pub fn empty_denominators(m: &Matrix, shipped: &BTreeSet<String>) -> Vec<String> {
    if shipped.is_empty() {
        return vec![format!(
            "no root leg ships: {MANIFEST_REL}'s `default` line turns on no leg's feature"
        )];
    }
    let gating: Vec<String> = m
        .step_order()
        .into_iter()
        .filter(|step| m.steps().get(step).get("gating").truthy())
        .collect();
    shipped
        .iter()
        .filter(|leg| {
            !m.planes().iter().any(|plane| {
                gating
                    .iter()
                    .any(|step| m.cell(plane, step).get("root").str_or("leg", "") == leg.as_str())
            })
        })
        .map(|leg| format!("the shipped leg `{leg}` owns no gating plane x step cell"))
        .collect()
}

/// The shipped-leg bar's verdict: the lines it prints and its exit code. It states its denominator,
/// REFUSES an empty one, then judges every gating cell on a shipped leg.
pub fn root_legs_gating_verdict(m: &Matrix, shipped: &BTreeSet<String>) -> (Vec<String>, i32) {
    let (considered, red) = root_legs_gating(m, shipped);
    let legs = if shipped.is_empty() {
        "(none)".to_string()
    } else {
        shipped.iter().cloned().collect::<Vec<_>>().join(", ")
    };
    let mut lines = vec![format!(
        "ROOT-GATING: the shipped legs are {legs}; {considered} gating plane x step cell(s) are \
         theirs to drive."
    )];
    let empty = empty_denominators(m, shipped);
    if !empty.is_empty() || considered == 0 {
        lines.push(format!("  nothing to judge: {}", empty.join("; ")));
        lines.push(
            "RED: the shipped-leg bar has no denominator. A bar that judges zero cells is not \
             green; it measured nothing."
                .to_string(),
        );
        return (lines, 1);
    }
    if red.is_empty() {
        lines.push(
            "GREEN: every gating step on every shipped root leg is driven over the loop."
                .to_string(),
        );
        return (lines, 0);
    }
    lines.push(format!("  not driven: {}", red.join(", ")));
    lines.push(format!(
        "RED: {} gating step(s) on a leg the binary SHIPS have no cell over the loop. A default \
         leg is the shipped path for its plane; a gating step nobody drives over it is a \
         half-answer, not a queue entry.",
        red.len()
    ));
    (lines, 1)
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

/// The binary crate whose test harness runs the root legs: its module tree starts here.
const BUSBAR_MAIN: &str = "crates/busbar/src/main.rs";

/// RUN every named loop cell, with every leg compiled in.
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
            eprintln!("ROOT-STEPS: the every-leg build did not compile:");
            eprintln!("{e}");
            return 1;
        }
    };
    let known: BTreeSet<&str> = listing
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .collect();

    // `crates/busbar/src/root/plane_node.rs::the_fn` is the ledger's spelling; libtest's is the
    // module path the crate builds for it. That path is READ OFF THE SOURCE
    // ([`crate::libtest_path`]): the module tree from `src/main.rs` through every `mod` declaration
    // and `#[path]` attribute, then the inline modules the fn sits in. It used to be guessed from the
    // file's NAME (`.../tests/<stem>.rs` -> `<impl>::tests`), which is wrong for a body carried
    // under another module name (`serve.rs`: `#[path = "tests/serve_tests.rs"] mod door_tests`) or
    // nested in an inline module (`mod agent_door { .. }`): every such cell was reported absent. A
    // file or fn the tree reaches two ways is a refusal naming both, never a guess.
    let tree = crate::libtest_path::module_tree(&|rel: &str| cx.read(rel).ok(), BUSBAR_MAIN);
    let mut wanted: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut per_leg: BTreeMap<String, usize> = BTreeMap::new();
    for (leg, file, func) in &cells {
        let path = match crate::libtest_path::resolve(&tree, file, func) {
            Ok(p) => p,
            Err(why) => {
                unknown.push(format!("  {leg}: {file}::{func} ({why})"));
                *per_leg.entry(leg.clone()).or_default() += 1;
                continue;
            }
        };
        if path.is_empty() || !known.contains(path.as_str()) {
            unknown.push(format!("  {leg}: {file}::{func} (looked for {path})"));
        } else if !wanted.contains(&path) {
            wanted.push(path);
        }
        *per_leg.entry(leg.clone()).or_default() += 1;
    }
    if !unknown.is_empty() {
        eprintln!(
            "ROOT-STEPS: the every-leg build does NOT carry these named loop cells -- the ledger \
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
    /// The gating gaps owed by name (`plane.step (owner)`), carried in the gating row's detail.
    pub owed: Vec<String>,
    /// [`EQUALITY_REL`]'s root cells that no CI step runs.
    pub equality_cells: Vec<String>,
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
        owed: Vec::new(),
        equality_cells: pick(ROW_EQUALITY_CELLS),
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
            "the steps are the kernel's in loop order, the rows are the declared planes, every \
             plane carries every step, and no cell disagrees with itself",
            "the Teller step matrix is not a valid matrix, or its roster is not the tree's",
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
            "every cell carries a root verdict whose named loop cell exists and runs in CI",
            "a root verdict is absent, mis-attributed, unargued, or names a loop cell that is gone \
             or that no CI step runs",
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
            "every gating plane x step cell names a real scenario, or is a gap owed by name",
            "a gating plane x step cell is a gap nobody owes, or an owed gap was closed and not struck",
            if f.owed.is_empty() {
                format!("0 of {cells} gating cell(s) are \"none\"")
            } else {
                format!(
                    "{} of {cells} gating cell(s) are \"none\", each owed by name: {}",
                    f.owed.len(),
                    f.owed.join(", ")
                )
            },
        ),
        one_row(
            &f.equality_cells,
            ROW_EQUALITY_CELLS,
            "every proven root cell of the capability-equality ledger is a test CI's build compiles \
             and runs",
            "a proven root cell of the capability-equality ledger names a test no CI step runs",
            format!("{EQUALITY_REL} root column read"),
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
            ROW_EQUALITY_CELLS.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let m = match load(cx) {
            Ok(m) => m,
            Err(e) => return Verdict::of(rows_from(&did_not_load(&e))),
        };

        let view = CiView::of(cx);
        let root = check_root_column_in(cx, &m, &view);
        let gating = check_gating(&m);
        Verdict::of(rows_from(&Findings {
            cells: m.planes().len() * m.step_order().len(),
            legs: m.root_legs().as_object().map_or(0, json_lite::Obj::len),
            matrix: check_roster(cx, &m),
            rig: check_rig_column(cx, &m),
            root_column: root.column,
            root_legs: root.legs,
            gating: gating.problems,
            owed: gating.owed,
            equality_cells: check_equality_cells(cx, &view),
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
                ROW_EQUALITY_CELLS,
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

        // The llm leg's own file, as the committed matrix names it: the root-column plants cite
        // cells there, so a plant is about the rule it names and not about which file the leg is.
        let llm_leg_file = doc
            .get("root_legs")
            .get("root-llm")
            .str_or("file", &format!("{ROOT_DIR}tests/serve_tests.rs"));
        let renamed_away = format!("{llm_leg_file}::a_fn_that_was_renamed_away");

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
                "a jev rig cell whose check its rig no longer declares",
                ROW_RIG,
                "NOTHING in the tree owns",
                Box::new(|p: &mut Plant| {
                    p.set_cell_field(
                        "decision",
                        "route",
                        "cell",
                        Json::Str("jev.rig|h2-a-check-that-was-renamed-away".into()),
                    );
                }),
            ),
            (
                "a root proof whose named loop cell was renamed away",
                ROW_ROOT_COLUMN,
                "no `fn a_fn_that_was_renamed_away(` exists there",
                Box::new(move |p: &mut Plant| {
                    p.set_root_field("llm", "meter", "test", Json::Str(renamed_away.clone()));
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
                Box::new(|p: &mut Plant| p.drop_leg("root-streaming")),
            ),
            (
                "an owed gap that was closed and not struck",
                ROW_GATING,
                "owed_gaps.decision.verify is owed but is no longer a gating gap",
                // The committed matrix owes nothing on this cell any more (the jev rig closed it),
                // so the plant re-adds the struck entry beside the closed cell.
                Box::new(|p: &mut Plant| p.owe("decision.verify", "DECISIONS-FIX")),
            ),
            // ── THE ROSTER WAS THE FILE'S OWN. These are the two lists checked against the tree. ──
            (
                "a kernel step missing from the matrix",
                ROW_MATRIX,
                "which the matrix's 'steps' lacks",
                Box::new(|p: &mut Plant| p.drop_step_everywhere("meter")),
            ),
            (
                "a matrix row for a plane no crate declares",
                ROW_MATRIX,
                "matrix.ghost is a plane no crate declares",
                Box::new(|p: &mut Plant| p.copy_row("llm", "ghost")),
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
            // ── A CLEANLINESS ROW IS JUDGED BY THE PLANE ROWS' RULES (spec l.3987). ──────────────
            (
                "a cleanliness row whose cited loop test does not exist",
                ROW_ROOT_COLUMN,
                "cleanliness_rows.admin.meter.root is proven by",
                Box::new(|p: &mut Plant| {
                    p.set_root_field(
                        "admin",
                        "meter",
                        "test",
                        Json::Str(format!(
                            "{ROOT_DIR}units_admin/tests/units_admin.rs::a_fn_that_was_renamed_away"
                        )),
                    );
                }),
            ),
            (
                "a cleanliness row's gating step with no cell",
                ROW_GATING,
                "admin.audit",
                Box::new(|p: &mut Plant| {
                    p.set_cell_field("admin", "audit", "cell", Json::Str("none".into()));
                    p.set_cell_field("admin", "audit", "status", Json::Str("none".into()));
                }),
            ),
            (
                "a cleanliness row the gate's list does not owe",
                ROW_MATRIX,
                "cleanliness_rows.ghost names no cleanliness crate",
                Box::new(|p: &mut Plant| p.copy_row("admin", "ghost")),
            ),
        ];

        // THE GREEN BASE EVERY PLANT IS PROVEN FROM. A root cell whose named loop cell is gone
        // from its file keeps `root-column` red on the unplanted tree, and a row that is already
        // red cannot be shown to turn red: every root-column plant below would report an
        // impossible proof. The base gives each such cell a stub `fn` of the name it cites, in an
        // overlay, so the row starts green and only the plant can move it. The real tree is not
        // healed by this: the control case above still reads it unplanted and stays red until the
        // matrix names a cell that exists.
        let base = missing_root_cells(cx, &doc);
        let base_cx = cx.with_overlay(base.clone());

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
            report.push(prove_red(
                &base_cx,
                self,
                label,
                &[covers],
                base.layered(&ov),
                &[naming],
            ));
        }

        // ── THE CELL MUST RUN (Law 10, status row 178). The `fn <name>(` match accepted any fn
        // that EXISTS; each plant below is a fn that exists in the llm leg's own file and that no
        // CI step runs, cited by a cell. The first two are the shape fourteen root-llm cells had
        // once no linked row carried the `node` axis: a cfg no CI build enables. ──
        let leg_body = base_cx.read(&llm_leg_file).unwrap_or_default();
        let run_plants: [(&str, &str, &str, &str); 4] = [
            (
                "a root cell under a cfg no CI build enables",
                "\n#[cfg(linked_axis_node)]\n#[tokio::test]\nasync fn a_cell_no_ci_build_compiles() {}\n",
                "a_cell_no_ci_build_compiles",
                "linked_axis_node",
            ),
            (
                "a root cell in a module no CI build carries",
                "\n#[cfg(all(test, linked_axis_node))]\nmod gone_with_its_axis {\n    \
                 #[tokio::test]\n    async fn a_cell_in_a_module_no_build_carries() {}\n}\n",
                "a_cell_in_a_module_no_build_carries",
                "linked_axis_node",
            ),
            (
                "a root cell CI's test run skips",
                "\n#[tokio::test]\n#[ignore]\nasync fn a_cell_the_run_skips() {}\n",
                "a_cell_the_run_skips",
                "ignore",
            ),
            (
                "a root cell that is a helper the harness never runs",
                "\nfn a_helper_no_harness_runs() {}\n",
                "a_helper_no_harness_runs",
                "no test attribute",
            ),
        ];
        for (label, cell, func, naming) in run_plants {
            let mut plant = Plant { doc: doc.clone() };
            plant.set_root_field(
                "llm",
                "meter",
                "test",
                Json::Str(format!("{llm_leg_file}::{func}")),
            );
            let mut ov = Overlay::new();
            ov.set(&llm_leg_file, format!("{leg_body}{cell}"));
            let text = format!("{}\n", json_lite::dump_python(&plant.doc));
            if let Err(e) = Edit::Replace(text).apply(cx, LEDGER_REL, &mut ov) {
                report.note_infra_failure(format!("{label}: {e}"));
                continue;
            }
            report.push(prove_red(
                &base_cx,
                self,
                label,
                &[ROW_ROOT_COLUMN],
                base.layered(&ov),
                &[naming],
            ));
        }

        // THE SAME RULE OVER THE CAPABILITY-EQUALITY LEDGER: one of its proven root cells pointed
        // at a cell under a cfg no CI build enables.
        match base_cx
            .read(EQUALITY_REL)
            .and_then(|t| json_lite::parse(&t))
        {
            Ok(mut eq) => {
                let cited = format!("{llm_leg_file}::a_cell_no_ci_build_compiles");
                let mut planted = false;
                if let Some(Json::Array(cells)) =
                    eq.as_object_mut().and_then(|d| d.get_mut("cells"))
                {
                    for c in cells.iter_mut() {
                        if c.get("root").str_or("state", "") != "proven" {
                            continue;
                        }
                        if let Some(Json::Object(r)) =
                            c.as_object_mut().and_then(|o| o.get_mut("root"))
                        {
                            r.insert("test", Json::Str(cited.clone()));
                            planted = true;
                            break;
                        }
                    }
                }
                if planted {
                    let mut ov = Overlay::new();
                    ov.set(&llm_leg_file, format!("{leg_body}{}", run_plants[0].1));
                    ov.set(EQUALITY_REL, format!("{}\n", json_lite::dump_python(&eq)));
                    report.push(prove_red(
                        &base_cx,
                        self,
                        "a capability-equality root cell under a cfg no CI build enables",
                        &[ROW_EQUALITY_CELLS],
                        base.layered(&ov),
                        &["linked_axis_node"],
                    ));
                } else {
                    report.note_infra_failure(format!(
                        "{EQUALITY_REL}: no proven root cell to plant the run rule's RED on"
                    ));
                }
            }
            Err(e) => report.note_infra_failure(format!("{EQUALITY_REL}: {e}")),
        }

        // THE SAME RULE OVER THE CAPABILITY-EQUALITY LEDGER'S OWN COLUMN: a proven cell's own
        // `test` pointed at a cell under a cfg no CI build enables (the shape `audit-chain`x`llm`
        // once had, a node-axis cell), and at a cell in an integration-test target cargo builds
        // only under a feature CI's test build lacks.
        let manifest = base_cx.read(MANIFEST_REL).unwrap_or_default();
        let target = format!("{BUSBAR_TESTS}a_target_no_ci_build_has.rs");
        // (label, cited `file::fn`, the files it plants, the word its refusal must name)
        type OwnPlant = (&'static str, String, Vec<(String, String)>, &'static str);
        let member_body = base_cx.read(MEMBER_CELL_FILE).unwrap_or_default();
        let own_plants: [OwnPlant; 4] = [
            (
                "a capability-equality cell's own test under a cfg no CI build enables",
                format!("{llm_leg_file}::a_cell_no_ci_build_compiles"),
                vec![(
                    llm_leg_file.clone(),
                    format!("{leg_body}{}", run_plants[0].1),
                )],
                "linked_axis_node",
            ),
            (
                "a capability-equality cell's own test in a target CI's build never builds",
                format!("{target}::a_cell_in_a_target_no_build_has"),
                vec![
                    (
                        target.clone(),
                        "#[test]\nfn a_cell_in_a_target_no_build_has() {}\n".to_string(),
                    ),
                    (
                        MANIFEST_REL.to_string(),
                        format!(
                            "{manifest}\n[[test]]\nname = \"a_target_no_ci_build_has\"\n\
                             path = \"tests/a_target_no_ci_build_has.rs\"\n\
                             required-features = [\"a-feature-ci-never-enables\"]\n"
                        ),
                    ),
                ],
                "required-features",
            ),
            // ANOTHER WORKSPACE MEMBER (row 178): its own tests are judged in its own build too,
            // where a feature outside its default and self-dev closure is not shown on.
            (
                "a capability-equality cell's own test in another workspace crate under a feature \
                 its CI build is not shown to enable",
                format!("{MEMBER_CELL_FILE}::a_member_cell_no_ci_build_is_shown_to_compile"),
                vec![(
                    MEMBER_CELL_FILE.to_string(),
                    format!(
                        "{member_body}\n#[cfg(feature = \"a-feature-ci-never-enables\")]\n#[test]\n\
                         fn a_member_cell_no_ci_build_is_shown_to_compile() {{}}\n"
                    ),
                )],
                "a-feature-ci-never-enables",
            ),
            (
                "a capability-equality cell's own test in a workspace crate file no target reaches",
                format!("{MEMBER_UNREACHED_FILE}::a_member_cell_no_mod_reaches"),
                vec![(
                    MEMBER_UNREACHED_FILE.to_string(),
                    "#[test]\nfn a_member_cell_no_mod_reaches() {}\n".to_string(),
                )],
                "reached by no target",
            ),
        ];
        if member_body.is_empty() {
            report.note_infra_failure(format!(
                "{MEMBER_CELL_FILE}: unreadable, so the member-crate plant has nothing to extend"
            ));
        }
        for (label, cited, files, naming) in own_plants {
            let eq = base_cx
                .read(EQUALITY_REL)
                .and_then(|t| json_lite::parse(&t))
                .map(|mut eq| (plant_own_test(&mut eq, &cited), eq));
            match eq {
                Ok((true, eq)) => {
                    let mut ov = Overlay::new();
                    for (rel, text) in files {
                        ov.set(rel, text);
                    }
                    ov.set(EQUALITY_REL, format!("{}\n", json_lite::dump_python(&eq)));
                    report.push(prove_red(
                        &base_cx,
                        self,
                        label,
                        &[ROW_EQUALITY_CELLS],
                        base.layered(&ov),
                        &["is proven by", naming],
                    ));
                }
                Ok((false, _)) => report.note_infra_failure(format!(
                    "{EQUALITY_REL}: no proven cell to plant the run rule's RED on ({label})"
                )),
                Err(e) => report.note_infra_failure(format!("{EQUALITY_REL}: {e}")),
            }
        }

        // THE TREE'S SIDE OF THE ROSTER: plants in the declarations the roster is derived from,
        // with the committed matrix untouched. A gate that read its roster off the matrix again
        // would stay green under every one of them.
        let step_rs = cx.read(KERNEL_STEPS_REL).unwrap_or_default();
        let tree_plants: Vec<TreePlant> = vec![
            (
                "a plane crate with no matrix row",
                "busbar-plane-shadow declares plane 'shadow', which carries no matrix row",
                vec![
                    (
                        "crates/busbar-plane-shadow/Cargo.toml",
                        "[package]\nname = \"busbar-plane-shadow\"\nversion = \"0.0.0\"\n"
                            .to_string(),
                    ),
                    (
                        "crates/busbar-plane-shadow/src/meta.rs",
                        "pub struct ShadowPlane;\n\nimpl PlaneMeta for ShadowPlane {\n    \
                         const KEY: &'static str = \"shadow\";\n}\n"
                            .to_string(),
                    ),
                ],
            ),
            (
                "a matrix step the kernel does not declare",
                "steps.meter is a step the kernel does not declare",
                vec![(
                    KERNEL_STEPS_REL,
                    step_rs.replacen("        StepName::Meter,\n", "", 1),
                )],
            ),
            (
                "the kernel's steps in another order than the matrix's",
                "but the kernel's loop runs",
                vec![(
                    KERNEL_STEPS_REL,
                    step_rs.replacen(
                        "        StepName::Route,\n        StepName::Meter,\n",
                        "        StepName::Meter,\n        StepName::Route,\n",
                        1,
                    ),
                )],
            ),
        ];
        for (label, naming, files) in tree_plants {
            let mut ov = Overlay::new();
            for (rel, text) in files {
                ov.set(rel, text);
            }
            report.push(prove_red(
                &base_cx,
                self,
                label,
                &[ROW_MATRIX],
                base.layered(&ov),
                &[naming],
            ));
        }

        report
    }
}

/// A FIXTURE OVERLAY THAT GIVES EVERY STALE ROOT CITATION A CELL TO RESOLVE TO: for each matrix
/// cell whose `root.test` names `file::func` and whose `file` declares no `fn func(`, a stub
/// `fn func() {}` is appended to that file. Empty when every citation resolves, which is the
/// ordinary state of the tree.
fn missing_root_cells(cx: &Ctx, doc: &Json) -> Overlay {
    let mut stubs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for planes in ["matrix", CLEANLINESS_KEY]
        .into_iter()
        .filter_map(|section| doc.get(section).as_object())
    {
        for (_, steps) in planes.iter() {
            let Some(steps) = steps.as_object() else {
                continue;
            };
            for (_, cell) in steps.iter() {
                let Some(test) = cell.get("root").get("test").as_str() else {
                    continue;
                };
                let Some((file, func)) = test.split_once("::") else {
                    continue;
                };
                let body = cx.read(file).unwrap_or_default();
                if body.is_empty() || body.contains(&format!("fn {func}(")) {
                    continue;
                }
                stubs
                    .entry(file.to_string())
                    .or_default()
                    .push(func.to_string());
            }
        }
    }
    let mut ov = Overlay::new();
    for (file, funcs) in stubs {
        let mut body = cx.read(&file).unwrap_or_default();
        for func in funcs {
            body.push_str(&format!("\n#[test]\nfn {func}() {{}}\n"));
        }
        ov.set(&file, body);
    }
    ov
}

/// One planted violation in the TREE the roster is derived from: its label, the substring its report
/// must NAME, and the files the plant writes over the real tree.
type TreePlant = (&'static str, &'static str, Vec<(&'static str, String)>);

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
    /// The section a row lives in: `cleanliness_rows` when it is a cleanliness row, else `matrix`.
    fn section_of(&self, plane: &str) -> &'static str {
        if self
            .doc
            .get(CLEANLINESS_KEY)
            .as_object()
            .is_some_and(|o| o.contains_key(plane))
        {
            CLEANLINESS_KEY
        } else {
            "matrix"
        }
    }

    fn cell_mut(&mut self, plane: &str, step: &str) -> Option<&mut json_lite::Obj> {
        let section = self.section_of(plane);
        match self
            .doc
            .as_object_mut()?
            .get_mut(section)?
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
        let section = self.section_of(plane);
        if let Some(Json::Object(row)) = self
            .doc
            .as_object_mut()
            .and_then(|d| d.get_mut(section))
            .and_then(Json::as_object_mut)
            .and_then(|m| m.get_mut(plane))
        {
            row.remove(step);
        }
    }

    /// Drop `step` from the declared steps AND from every row, plane and cleanliness alike, so the
    /// matrix is internally whole and only the kernel's roster can see what it lost.
    fn drop_step_everywhere(&mut self, step: &str) {
        let Some(doc) = self.doc.as_object_mut() else {
            return;
        };
        if let Some(Json::Object(steps)) = doc.get_mut("steps") {
            steps.remove(step);
        }
        for section in ["matrix", CLEANLINESS_KEY] {
            if let Some(Json::Object(rows)) = doc.get_mut(section) {
                let planes: Vec<String> = rows.keys().map(str::to_string).collect();
                for plane in planes {
                    if let Some(Json::Object(row)) = rows.get_mut(&plane) {
                        row.remove(step);
                    }
                }
            }
        }
    }

    /// Add a row `to` that is a copy of row `from`, in the section `from` lives in.
    fn copy_row(&mut self, from: &str, to: &str) {
        let section = self.section_of(from);
        if let Some(Json::Object(rows)) = self.doc.as_object_mut().and_then(|d| d.get_mut(section))
        {
            if let Some(row) = rows.get(from).cloned() {
                rows.insert(to, row);
            }
        }
    }

    /// Name `cell` in the owed-gaps list, owed by `owner`, creating the list if it is gone.
    fn owe(&mut self, cell: &str, owner: &str) {
        let Some(doc) = self.doc.as_object_mut() else {
            return;
        };
        if !matches!(doc.get_mut(OWED_KEY), Some(Json::Object(_))) {
            doc.insert(OWED_KEY, Json::Object(json_lite::Obj::default()));
        }
        if let Some(Json::Object(owed)) = doc.get_mut(OWED_KEY) {
            owed.insert(cell, Json::Str(owner.into()));
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

    // The owed gaps are the gating row's detail, one line each.
    f.owed = all
        .iter()
        .filter_map(|l| l.strip_prefix(OWED_PREFIX))
        .map(str::to_string)
        .collect();

    // The roster's differences are the matrix row's findings, one line each.
    f.matrix = all
        .iter()
        .filter_map(|l| l.strip_prefix(ROSTER_PREFIX))
        .map(str::to_string)
        .collect();

    if let Some(red) = all.iter().find(|l| l.starts_with("RED: ")) {
        f.gating
            .push(red.strip_prefix("RED: ").unwrap_or(red).to_string());
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

#[cfg(test)]
mod root_gating_tests {
    use super::*;

    /// One plane, one gating step and one non-gating step; the gating cell on `root-x`.
    fn matrix() -> Matrix {
        Matrix {
            doc: json_lite::parse(
                r#"{"steps": {"admit": {"gating": true}, "note": {"gating": false}},
                    "matrix": {"p": {"admit": {"root": {"leg": "root-x", "state": "proven"}},
                                     "note": {"root": {"leg": "root-y", "state": "none"}}}},
                    "root_legs": {"root-x": {}, "root-y": {}}}"#,
            )
            .expect("the planted matrix parses"),
        }
    }

    fn legs(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// TODO l.1503-1515: with no shipped leg the bar printed its `(none)` denominator, found no
    /// red cell among zero, and printed GREEN with exit 0. It refuses.
    #[test]
    fn no_shipped_leg_is_red_not_green() {
        let (lines, rc) = root_legs_gating_verdict(&matrix(), &legs(&[]));
        assert_eq!(rc, 1, "{lines:?}");
        assert!(lines.iter().any(|l| l.starts_with("RED: ")), "{lines:?}");
        assert!(!lines.iter().any(|l| l.starts_with("GREEN: ")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("no root leg ships")),
            "{lines:?}"
        );
    }

    /// A shipped leg that owns only non-gating cells is judged over nothing: refused, named.
    #[test]
    fn a_shipped_leg_with_no_gating_cell_is_red() {
        let (lines, rc) = root_legs_gating_verdict(&matrix(), &legs(&["root-x", "root-y"]));
        assert_eq!(rc, 1, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("the shipped leg `root-y` owns no gating")),
            "{lines:?}"
        );
    }

    /// A cleanliness row is held to the shipped-leg bar exactly as a plane row: a gating step on a
    /// shipped leg with no cell over the loop is red, named by the row.
    #[test]
    fn a_cleanliness_rows_gating_step_with_no_loop_cell_is_red() {
        let m = Matrix {
            doc: json_lite::parse(
                r#"{"steps": {"admit": {"gating": true}},
                    "matrix": {"p": {"admit": {"root": {"leg": "root-x", "state": "proven"}}}},
                    "cleanliness_rows": {"c": {"admit": {"root": {"leg": "root-c", "state": "none"}}}},
                    "root_legs": {"root-x": {}, "root-c": {}}}"#,
            )
            .expect("the planted matrix parses"),
        };
        let (lines, rc) = root_legs_gating_verdict(&m, &legs(&["root-x", "root-c"]));
        assert_eq!(rc, 1, "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("c.admit (root-c)")),
            "{lines:?}"
        );
    }

    /// The control: a shipped leg whose gating cell is proven is GREEN, so the refusal is the
    /// empty denominator's and not every verdict's.
    #[test]
    fn a_shipped_leg_with_a_proven_gating_cell_is_green() {
        let (lines, rc) = root_legs_gating_verdict(&matrix(), &legs(&["root-x"]));
        assert_eq!(rc, 0, "{lines:?}");
        assert!(lines.iter().any(|l| l.starts_with("GREEN: ")), "{lines:?}");
    }
}

#[cfg(test)]
mod cell_owner_tests {
    use super::*;

    /// THE REFERENCE: [`resolve_cell`] as it was before [`CellOwners`], re-reading every piece of
    /// evidence for every cell it is asked about. Kept here, and only here, so the memoised reading
    /// has something to be held to.
    fn resolve_cell_rereading(cx: &Ctx, cell_id: &str) -> Option<String> {
        if ids_in(&cx.read(ORACLE_CELLS_REL).unwrap_or_default(), "cells").contains(cell_id) {
            return Some(ORACLE_CELLS_REL.to_string());
        }
        let (namespace, rest) = cell_id.split_once('|')?;
        if rest.is_empty() {
            return None;
        }
        if let Some((_, dir)) = H2_DIRS.iter().find(|(ns, _)| *ns == namespace) {
            if rest.starts_with("h2-") {
                let path = format!("{dir}/{rest}.sh");
                return cx.exists(&path).then_some(path);
            }
        }
        if let Some((_, file)) = FILE_RIGS.iter().find(|(ns, _)| *ns == namespace) {
            return cx
                .read(file)
                .is_ok_and(|t| declares_id(&t, rest))
                .then(|| (*file).to_string());
        }
        if namespace == "voice.rig" {
            let path = format!("testing/voice-conformance/legs/{rest}.sh");
            if cx.exists(&path) {
                return Some(path);
            }
        }
        if let Some((_, base)) = SOURCE_DIRS.iter().find(|(ns, _)| *ns == namespace) {
            let mut paths: Vec<String> = Vec::new();
            collect_paths(&cx.abs(base), cx.root(), &mut paths);
            paths.sort();
            if let Some(owner) = paths
                .into_iter()
                .find(|rel| cx.read(rel).is_ok_and(|t| declares_id(&t, rest)))
            {
                return Some(owner);
            }
        }
        if rig_baseline_ids(cx).contains(cell_id) {
            return Some("testing/shadow-oracle/rigs-baseline.json".to_string());
        }
        None
    }

    /// THE MEMOISED OWNERS ARE THE PER-CELL RE-READ'S, on the real tree and on planted ones: every
    /// cell the committed matrix names plus the ids the self-test plants, asked of one
    /// [`CellOwners`] per tree (so every answer after the first is served warm) and of the
    /// reference that re-reads per cell. The `cells.json` plant is asked AFTER the real tree filled
    /// the oracle memo, so a memo that answered from the wrong bytes would show here.
    #[test]
    fn the_memoised_cell_owners_are_the_per_cell_reread_on_planted_trees() {
        let base = Ctx::workspace().expect("the workspace opens");
        let m = load(&base).expect("the committed matrix loads");
        let mut ids: Vec<String> = Vec::new();
        for plane in m.planes() {
            for step in m.step_order() {
                ids.push(m.cell(&plane, &step).str_or("cell", ""));
            }
        }
        ids.extend(
            [
                "teller|a-scenario-that-was-renamed-away",
                "mcp.rig|h2-a-step-with-no-script",
                "jev.rig|h2-a-check-that-was-renamed-away",
                "mcp.battery|ADV.MALFORMED",
                "a2a.supplement|SERVER-002",
                "teller|planted-oracle-cell",
                "voice.rig|a-leg-with-no-script",
                "no-namespace",
                "mcp.battery|",
            ]
            .map(str::to_string),
        );
        let planted_oracle = {
            let mut ov = Overlay::new();
            ov.set(
                ORACLE_CELLS_REL,
                "{\"cells\": [{\"id\": \"teller|planted-oracle-cell\"}]}\n",
            );
            ov
        };
        let no_jev = {
            let mut ov = Overlay::new();
            ov.set(FILE_RIGS[0].1, String::new());
            ov
        };
        for (i, ov) in [Overlay::new(), planted_oracle, no_jev]
            .into_iter()
            .enumerate()
        {
            let cx = base.with_overlay(ov);
            let owners = CellOwners::new(&cx);
            let mut resolved = 0usize;
            for id in &ids {
                let want = resolve_cell_rereading(&cx, id);
                assert_eq!(
                    owners.resolve(id),
                    want,
                    "plant {i}: the memoised owner of {id:?} is not the re-read's"
                );
                assert_eq!(
                    resolve_cell(&cx, id),
                    want,
                    "plant {i}: resolve_cell's owner of {id:?} is not the re-read's"
                );
                resolved += usize::from(want.is_some());
            }
            assert!(
                resolved > 0,
                "plant {i}: no id resolved, so nothing was compared"
            );
        }
    }
}

#[cfg(test)]
mod equality_target_tests {
    use super::*;

    const MANIFEST: &str = "[package]\nname = \"busbar\"\n\n[[test]]\nname = \"gated\"\n\
                            path = \"tests/gated.rs\"\nrequired-features = [\"a\", \"b\"]\n\n\
                            [[test]]\nname = \"free\"\npath = \"tests/free.rs\"\n\n\
                            [features]\ndefault = []\n";

    #[test]
    fn a_target_states_its_required_features_and_only_its_own() {
        assert_eq!(
            required_features(MANIFEST, "crates/busbar", "crates/busbar/tests/gated.rs"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(
            required_features(MANIFEST, "crates/busbar", "crates/busbar/tests/free.rs").is_empty()
        );
        assert!(
            required_features(MANIFEST, "crates/busbar", "crates/busbar/tests/absent.rs")
                .is_empty()
        );
    }

    #[test]
    fn a_files_target_is_spelled_from_its_path_under_its_crates_tests() {
        assert_eq!(
            target_root_of("crates/busbar", "crates/busbar/tests/plane_integration.rs").as_deref(),
            Some("crates/busbar/tests/plane_integration.rs")
        );
        assert_eq!(
            target_root_of("crates/busbar", "crates/busbar/tests/linked/mod.rs").as_deref(),
            Some("crates/busbar/tests/linked/main.rs")
        );
        assert_eq!(
            target_root_of("crates/busbar-kernel", "crates/busbar-kernel/tests/x.rs").as_deref(),
            Some("crates/busbar-kernel/tests/x.rs")
        );
        assert_eq!(
            target_root_of("crates/busbar", "crates/busbar-kernel/tests/x.rs"),
            None
        );
        assert_eq!(
            target_root_of("crates/busbar", "crates/busbar/src/root/tests/x.rs"),
            None
        );
    }
}
