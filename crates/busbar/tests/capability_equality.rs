// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EQUALITY GATE. Every cell of `core capability x protocol plane` is `proven` (naming a test
//! that this gate verifies exists), `missing` (the pinned work queue), or `not-applicable` (with a
//! one-line argument) -- and a matrix that drifts from that pin FAILS THE BUILD.
//!
//! Owner's ruling, recorded repeatedly and slipped repeatedly, which is the whole reason this is a
//! gate and not another paragraph:
//!
//! > *"breakers, hooks, auditing -- list all the core functionality. outside should ONLY BE Auth,
//! > Store, Protocols, i.e. Plugins. Any plugin gets all functionality. LLM == MCP == A2A -- just
//! > different protocols not different pathway through engine at all."*
//!
//! And, on being told this was already recorded: *"its been recorded before hence my concern.
//! i keep repeating."* Prose here has a measured half-life of days; the mechanisms that have held
//! are machine gates (PLANE_LEDGER, `pinned_missing_set_is_exact`, the hygiene lints). This file is
//! that mechanism for the equality doctrine, modelled on
//! `crates/busbar/tests/method_coverage.rs` -- the house oracle pattern.
//!
//! ## The three states, and what each one costs
//!
//! | state | claim | enforced how |
//! |---|---|---|
//! | `proven` | a named test exercises the capability ON that plane | the file must exist, the fn must be in it, and the file must live in a test location. A proven cell whose test vanishes or is renamed is RED. |
//! | `missing` | the capability does not reach the plane, or nothing proves it does | allowed, pinned, and NAMED on every umbrella run (`scripts/capability-equality-summary.py`, wired into `scripts/full-gate.sh`). Closing a cell without flipping the pin leaves the queue lying, and the review that lands the closing test is expected to flip it in the same commit. |
//! | `not-applicable` | the plane is not owed this capability | only WITH an argument long enough to actually argue. N/A is a claim, not an escape; an unexplained absent cell is the failure mode this gate exists to prevent, so there is no way to express one. |
//!
//! The matrix is EXACT: every capability x plane pair appears exactly once, no hole, no duplicate,
//! no cell naming a capability or plane the header does not declare. That is the "computed ==
//! pinned" half -- the cross product is computed from the declared axes and the pinned cells must
//! tile it.
//!
//! ## Why it is allowed to be red-in-the-ledger and green-in-CI
//!
//! Same honest-ledger pattern as `qa/method-coverage.missing`: the missing set IS the work queue
//! for wiring the non-LLM planes into the core capabilities (the breaker/failover audit,
//! `design/breaker-all-planes-audit.md`, is the evidence base). Green means "the pin matches
//! reality"; it never means "no gap". The gap is printed, by name, on every full-gate run.
//!
//! **Never weaken this gate to make it green. Never delete a capability to shrink the queue.**
//!
//! ## The ROOT LEG column — the same matrix, judged a second time over the loop
//!
//! Every plane now also runs through the composition root, behind `root-llm` / `root-mcp` /
//! `root-a2a` / `root-voice` / `root-admin`. A capability proven where the plane crate serves it and
//! unwitnessed where the root drives it is the same silent half-answer this file exists to refuse,
//! so the ledger carries a SECOND verdict per cell (`root`) and this gate runs the matrix ONCE PER
//! LEG: for each declared leg, every cell in that leg's ledger columns is checked against the leg's
//! own file.
//!
//! ### Why cfg-gated tests and not a test that boots the release binary
//!
//! Two options were on the table, and the boot one cannot answer the question:
//!
//! * The five root features carry **no config key, no environment variable and no boot line** (see
//!   `crates/busbar/Cargo.toml`: a deployment "cannot tell from the logs which way it was built").
//!   A booted binary therefore cannot be asked which legs it carries, let alone which
//!   capability × plane cell held on one. Booting proves the binary starts; it does not prove a
//!   cell.
//! * The evidence for a leg lives in the binary crate's own `#[cfg(test)] mod tests` inside
//!   `src/root/units_*.rs`, compiled only when that leg's feature is on. Cargo features reach an
//!   integration test target too, so a `#[cfg(all(feature = "root-llm", …))]` test here runs in
//!   EXACTLY the build where the legs exist — and is absent, rather than lying, in a build where
//!   they do not.
//!
//! So: the structural half of the root column (every cell carries one; a `proven` root cell names a
//! fn that exists in its leg's own file; a `none` carries a real argument; `not-applicable` moves
//! with the cell's own state) is checked on EVERY build, and the leg-by-leg half
//! ([`the_root_leg_matrix_runs_once_per_leg`]) is cfg-gated on all five features.
//!
//! What a Rust test cannot do is RUN another crate's tests, so "the evidence passes over the loop"
//! is closed one level up: `scripts/capability-equality-summary.py --root-legs` builds the binary
//! crate with all five legs on and executes every named root cell, refusing a run in which a named
//! cell did not execute. `scripts/verify-1.6.0-done.sh`'s EQUALITY group calls it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The doctrine's plane list, verbatim: three protocols, and the two bidirectional ones counted in
/// both directions. A matrix missing a plane is not a smaller matrix, it is a different claim.
const PLANES: [&str; 7] = [
    "llm",
    "mcp-client",
    "mcp-server",
    "a2a-client",
    "a2a-server",
    "voice-client",
    "voice-server",
];

/// M0 TOTALITY CROSS-CHECK — a SEPARATE axis from the pinned directional `PLANES` above.
///
/// `PLANES` is the owner's doctrine, pinned verbatim in
/// [`the_gates_own_constants_are_the_doctrines`]; it is deliberately NOT derived from the workspace
/// (the two bidirectional protocols are counted in both directions, so the axis is 5 wide over 3
/// protocols). This map runs the OTHER direction: it names, per workspace PLANE CRATE, the ledger
/// columns that crate answers to. The cross-check below fails loudly if any plane crate the tree
/// carries maps to ZERO columns — a plane that reaches the workspace and then answers to nothing is
/// tracked by no cell, the silent hole the whole file exists to refuse.
///
/// `voice` (busbar-voice, Plane 4) is armed: it answers to two REAL directional ledger columns —
/// `voice-client` (the dialed provider WSS + telephony media egress) and `voice-server` (the inbound
/// session-open front door: browser sideband WS + telephony media webhook) — exactly as the two
/// bidirectional protocols do. Every mapped column must be a real declared ledger plane.
const PLANE_CRATE_LEDGER_COLUMNS: &[(&str, &[&str])] = &[
    ("llm", &["llm"]),
    ("mcp", &["mcp-client", "mcp-server"]),
    ("a2a", &["a2a-client", "a2a-server"]),
    ("voice", &["voice-client", "voice-server"]),
];

/// Floor on the capability axis. Sized below today's real number (13) so an ordinary addition does
/// not trip it, and well above zero so a file that quietly lost its rows cannot report equality of
/// nothing.
const MIN_CAPABILITIES: usize = 12;

/// Floor on proven cells. A matrix where nothing is proven is a matrix nobody filled from the tree;
/// today's honest count is well above this.
const MIN_PROVEN: usize = 20;

/// An n/a "argument" shorter than this is a label, not an argument.
const MIN_NA_REASON: usize = 60;

/// THE FIVE ROOT LEGS, verbatim — one per `root-*` feature the composition root carries. Pinned
/// here for the same reason [`PLANES`] is: a leg that quietly left the list would take its whole
/// column of root verdicts with it.
const ROOT_LEGS: [&str; 5] = ["root-a2a", "root-admin", "root-llm", "root-mcp", "root-voice"];

/// Every root leg's file lives here, and evidence for a leg that lived anywhere else would not be
/// that leg's evidence.
const ROOT_DIR: &str = "crates/busbar/src/root/";

/// A root `none` reason shorter than this is a label. Same doctrine as [`MIN_NA_REASON`]: R-16 says
/// name the gap, and a name is a sentence a reviewer can disagree with.
const MIN_ROOT_REASON: usize = 60;

/// A leg answering to ZERO ledger columns is a real claim (admin carries no protocol and no
/// upstream target, so it owns no cell in this matrix) — but it is the kind of claim that hides an
/// omission, so it costs a longer argument than an ordinary `none`.
const MIN_ZERO_COLUMN_ARGUMENT: usize = 120;

/// Floor on root-proven cells. Today's honest count is well above this; a ledger that lost the
/// column would report loop-equality of nothing.
const MIN_ROOT_PROVEN: usize = 25;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// What the verifier concluded. `missing` keeps the ids so the caller can print the queue.
#[derive(Debug, Default, PartialEq, Eq)]
struct Summary {
    proven: usize,
    missing: Vec<String>,
    not_applicable: usize,
    per_plane_missing: BTreeMap<String, usize>,
}

/// THE ONE VERDICT. Both the real gate and the self-tests below drive this exact function -- a
/// self-test that exercised a copy would prove the copy (the same reason `structure-lint.sh
/// --selftest` runs the real `scan_rule`).
///
/// `required_planes` / `min_capabilities` are parameters so the self-tests can plant a small
/// fixture matrix; [`the_gates_own_constants_are_the_doctrines`] pins the real constants.
fn verify(
    doc: &serde_json::Value,
    root: &Path,
    required_planes: &[&str],
    min_capabilities: usize,
) -> Result<Summary, String> {
    let capabilities: BTreeSet<String> = doc["capabilities"]
        .as_object()
        .ok_or("`capabilities` must be an object of name -> one-line definition")?
        .keys()
        .cloned()
        .collect();
    let planes: BTreeSet<String> = doc["planes"]
        .as_object()
        .ok_or("`planes` must be an object of name -> one-line definition")?
        .keys()
        .cloned()
        .collect();

    if capabilities.len() < min_capabilities {
        return Err(format!(
            "only {} capabilities declared (floor {min_capabilities}). This gate refuses to pass \
             vacuously -- a matrix that lost its rows would report equality of nothing.",
            capabilities.len()
        ));
    }
    for p in required_planes {
        if !planes.contains(*p) {
            return Err(format!(
                "plane `{p}` is not declared. The doctrine's planes are {required_planes:?}; a \
                 matrix missing one is not a smaller matrix, it is a different claim."
            ));
        }
    }
    for p in &planes {
        if !required_planes.contains(&p.as_str()) {
            return Err(format!(
                "plane `{p}` is declared but is not one of the doctrine's planes \
                 {required_planes:?}. Add it to the doctrine (this test) and fill its whole \
                 column, or delete it."
            ));
        }
    }
    for (name, def) in doc["capabilities"].as_object().unwrap() {
        if def.as_str().is_none_or(|d| d.trim().len() < 20) {
            return Err(format!(
                "capability `{name}` has no real one-line definition; an undefined capability \
                 cannot be argued about, only gestured at."
            ));
        }
    }

    let cells = doc["cells"].as_array().ok_or("`cells` must be an array")?;

    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut out = Summary::default();
    for p in &planes {
        out.per_plane_missing.insert(p.clone(), 0);
    }

    for cell in cells {
        let cap = cell["capability"]
            .as_str()
            .ok_or("a cell has no `capability`")?;
        let plane = cell["plane"].as_str().ok_or("a cell has no `plane`")?;
        let id = format!("{cap}\u{d7}{plane}"); // U+00D7 MULTIPLICATION SIGN, the matrix's own glyph
        if !capabilities.contains(cap) {
            return Err(format!(
                "cell `{id}` names capability `{cap}` which is not declared in `capabilities`. \
                 An undeclared row is how a capability gets tracked nowhere."
            ));
        }
        if !planes.contains(plane) {
            return Err(format!(
                "cell `{id}` names plane `{plane}` which is not declared in `planes`."
            ));
        }
        if !seen.insert((cap.to_string(), plane.to_string())) {
            return Err(format!(
                "cell `{id}` appears twice. Two answers for one cell is no answer."
            ));
        }
        match cell["state"].as_str() {
            Some("proven") => {
                let test = cell["test"].as_str().ok_or_else(|| {
                    format!(
                        "cell `{id}` is `proven` but names no `test`. Proven means an instrument \
                         was watched; name it as `<repo-relative file>::<test fn>`."
                    )
                })?;
                let (file, func) = test.split_once("::").ok_or_else(|| {
                    format!("cell `{id}`: `test` must be `<repo-relative file>::<test fn>`, got {test:?}")
                })?;
                if !(file.contains("/tests/") || file.ends_with("_tests.rs")) {
                    return Err(format!(
                        "cell `{id}`: {file} is not a test location (`.../tests/...` or \
                         `*_tests.rs`). Evidence must be a test, not a pointer at production code."
                    ));
                }
                let path = root.join(file);
                let src = std::fs::read_to_string(&path).map_err(|e| {
                    format!(
                        "cell `{id}` is `proven` by {test}, but {file} cannot be read ({e}). \
                         A proven cell whose evidence vanished has REGRESSED: either restore the \
                         test or flip the cell to `missing` -- in the same commit, so the queue \
                         tells the truth."
                    )
                })?;
                let sig = format!("fn {func}(");
                if !src.contains(&sig) {
                    return Err(format!(
                        "cell `{id}` is `proven` by {test}, but no `fn {func}(` exists in {file}. \
                         The named instrument is gone or renamed; a claim that outlives its \
                         evidence is exactly the drift this gate exists to stop. Restore or rename \
                         the reference, or flip the cell to `missing`."
                    ));
                }
                out.proven += 1;
            }
            Some("missing") => {
                out.missing.push(id.clone());
                *out.per_plane_missing.get_mut(plane).unwrap() += 1;
            }
            Some("not-applicable") => {
                let reason = cell["reason"].as_str().unwrap_or("");
                if reason.trim().len() < MIN_NA_REASON {
                    return Err(format!(
                        "cell `{id}` is `not-applicable` with reason {reason:?}. N/A is a CLAIM, \
                         not an escape -- it needs a one-line argument (>= {MIN_NA_REASON} chars) a \
                         reviewer could disagree with. An unexplained absent cell is \
                         indistinguishable from an oversight, which is the failure mode."
                    ));
                }
                out.not_applicable += 1;
            }
            other => {
                return Err(format!(
                    "cell `{id}` has state {other:?}. A cell is `proven`, `missing`, or \
                     `not-applicable`; there is no fourth state, deliberately."
                ));
            }
        }
    }

    // The cross product is EXACT: the pinned cells must tile computed capabilities x planes.
    for cap in &capabilities {
        for plane in &planes {
            if !seen.contains(&(cap.clone(), plane.clone())) {
                return Err(format!(
                    "cell `{cap}\u{d7}{plane}` is ABSENT from the matrix. An absent cell and a \
                     considered-and-inapplicable cell look identical on the page; that is the \
                     silent omission this gate exists to catch. Add it as `proven`, `missing`, or \
                     `not-applicable` with an argument."
                ));
            }
        }
    }
    out.missing.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// THE ROOT LEG COLUMN — the same matrix, judged a second time over the loop.
// ---------------------------------------------------------------------------

/// What the root-leg verifier concluded, per leg and in total.
#[derive(Debug, Default, PartialEq, Eq)]
struct RootSummary {
    /// leg -> (proven, none, not-applicable) over the cells in that leg's columns.
    per_leg: BTreeMap<String, (usize, usize, usize)>,
    /// The `(capability, plane)` ids whose root verdict is `none`, in ledger order.
    none: Vec<String>,
    proven: usize,
}

/// One named instrument, checked the way [`verify`] checks the legacy column: the file must be
/// readable and the fn must be in it, so a root cell cannot outlive its evidence either.
fn named_fn_exists(root: &Path, id: &str, test: &str) -> Result<(), String> {
    let (file, func) = test.split_once("::").ok_or_else(|| {
        format!("root cell `{id}`: `test` must be `<repo-relative file>::<test fn>`, got {test:?}")
    })?;
    let src = std::fs::read_to_string(root.join(file)).map_err(|e| {
        format!(
            "root cell `{id}` is `proven` by {test}, but {file} cannot be read ({e}). A root \
             verdict whose evidence vanished has REGRESSED: restore the cell or flip the root \
             verdict to `none` with the reason, in the same commit."
        )
    })?;
    if !src.contains(&format!("fn {func}(")) {
        return Err(format!(
            "root cell `{id}` is `proven` by {test}, but no `fn {func}(` exists in {file}. The \
             named loop cell is gone or renamed; a claim that outlives its evidence is the drift \
             this gate exists to stop."
        ));
    }
    Ok(())
}

/// THE ONE ROOT VERDICT, driven by the real gate and by the fixture self-tests alike.
///
/// It runs the matrix ONCE PER LEG: `root_legs` declares each leg's file and the ledger columns it
/// answers to, and every cell in those columns must carry a root verdict naming that leg.
fn verify_root(
    doc: &serde_json::Value,
    root: &Path,
    required_legs: &[&str],
    min_root_proven: usize,
) -> Result<RootSummary, String> {
    let legs_obj = doc["root_legs"]
        .as_object()
        .ok_or("`root_legs` must be an object of `root-<leg>` -> {file, columns, note}")?;
    let declared_planes: BTreeSet<String> = doc["planes"]
        .as_object()
        .ok_or("`planes` must be an object")?
        .keys()
        .cloned()
        .collect();

    let named: BTreeSet<&str> = legs_obj.keys().map(String::as_str).collect();
    let wanted: BTreeSet<&str> = required_legs.iter().copied().collect();
    if named != wanted {
        return Err(format!(
            "`root_legs` declares {named:?}; the composition root's legs are {wanted:?}. A leg that \
             left the list would take its whole column of root verdicts with it."
        ));
    }

    // leg -> its ledger columns; and the reverse, so a cell can be routed to its one leg.
    let mut leg_columns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut plane_leg: BTreeMap<String, String> = BTreeMap::new();
    let mut leg_file: BTreeMap<String, String> = BTreeMap::new();
    for (leg, meta) in legs_obj {
        let file = meta["file"]
            .as_str()
            .ok_or_else(|| format!("root leg `{leg}` names no `file`"))?;
        if !file.starts_with(ROOT_DIR) {
            return Err(format!(
                "root leg `{leg}` names file {file:?}, which is not under {ROOT_DIR}. A leg's \
                 evidence lives in the composition root or it is not that leg's evidence."
            ));
        }
        if !root.join(file).is_file() {
            return Err(format!(
                "root leg `{leg}` names {file}, which does not exist."
            ));
        }
        let note = meta["note"].as_str().unwrap_or("");
        let columns: Vec<String> = meta["columns"]
            .as_array()
            .ok_or_else(|| format!("root leg `{leg}` has no `columns` array"))?
            .iter()
            .map(|c| {
                c.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("root leg `{leg}`: a `columns` entry is not a string"))
            })
            .collect::<Result<_, _>>()?;
        let floor = if columns.is_empty() {
            MIN_ZERO_COLUMN_ARGUMENT
        } else {
            MIN_ROOT_REASON
        };
        if note.trim().len() < floor {
            return Err(format!(
                "root leg `{leg}` has note {note:?}: a leg needs a one-line argument (>= {floor} \
                 chars) for what it covers. A leg answering to ZERO columns costs the longer one, \
                 because that is the shape an omission hides in."
            ));
        }
        for col in &columns {
            if !declared_planes.contains(col) {
                return Err(format!(
                    "root leg `{leg}` answers to column `{col}`, which is not a declared ledger \
                     plane {declared_planes:?}."
                ));
            }
            if let Some(other) = plane_leg.insert(col.clone(), leg.clone()) {
                return Err(format!(
                    "column `{col}` is claimed by both `{other}` and `{leg}`; a plane runs through \
                     one leg, so two claims is no claim."
                ));
            }
        }
        leg_columns.insert(leg.clone(), columns);
        leg_file.insert(leg.clone(), file.to_string());
    }

    // TOTALITY: every declared ledger plane is answered by exactly one leg. A column no leg owns is
    // a plane whose loop nobody is judging — the silent hole, one axis over.
    let unowned: Vec<&String> = declared_planes
        .iter()
        .filter(|p| !plane_leg.contains_key(*p))
        .collect();
    if !unowned.is_empty() {
        return Err(format!(
            "ledger plane(s) {unowned:?} are answered by NO root leg. Every plane runs through the \
             composition root; a column with no leg is a loop nobody is judging."
        ));
    }

    let mut out = RootSummary::default();
    for leg in legs_obj.keys() {
        out.per_leg.insert(leg.clone(), (0, 0, 0));
    }

    for cell in doc["cells"].as_array().ok_or("`cells` must be an array")? {
        let cap = cell["capability"].as_str().unwrap_or("?");
        let plane = cell["plane"].as_str().unwrap_or("?");
        let id = format!("{cap}\u{d7}{plane}");
        let leg_of_plane = plane_leg.get(plane).ok_or_else(|| {
            format!("cell `{id}` names plane `{plane}`, which no root leg answers to.")
        })?;
        let r = cell["root"].as_object().ok_or_else(|| {
            format!(
                "cell `{id}` carries no `root` verdict. Every cell is judged twice -- once where \
                 the plane crate serves it and once over the loop -- and an absent second verdict \
                 is indistinguishable from an oversight."
            )
        })?;
        let leg = r
            .get("leg")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("cell `{id}`'s root verdict names no `leg`"))?;
        if leg != leg_of_plane {
            return Err(format!(
                "cell `{id}`'s root verdict names leg `{leg}`, but plane `{plane}` runs through \
                 `{leg_of_plane}`. Evidence from another leg is evidence about another loop."
            ));
        }
        let tally = out.per_leg.get_mut(leg).unwrap();
        let na = cell["state"].as_str() == Some("not-applicable");
        match r.get("state").and_then(serde_json::Value::as_str) {
            Some("proven") => {
                if na {
                    return Err(format!(
                        "cell `{id}` is `not-applicable` on the legacy path but `proven` over the \
                         loop. The two verdicts must move together: a plane not owed a capability \
                         is not owed it through the root either."
                    ));
                }
                let test = r
                    .get("test")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        format!(
                            "cell `{id}`'s root verdict is `proven` but names no `test`. Proven \
                             means a loop cell was watched; name it."
                        )
                    })?;
                let want = leg_file.get(leg).unwrap();
                if !test.starts_with(&format!("{want}::")) {
                    return Err(format!(
                        "cell `{id}`'s root evidence {test:?} does not live in `{leg}`'s own file \
                         {want}. A leg is proven by its own cells."
                    ));
                }
                named_fn_exists(root, &id, test)?;
                tally.0 += 1;
                out.proven += 1;
            }
            Some("none") => {
                if na {
                    return Err(format!(
                        "cell `{id}` is `not-applicable` on the legacy path but `none` over the \
                         loop. A plane not owed a capability is owed no loop cell for it either -- \
                         say `not-applicable` on both, or neither."
                    ));
                }
                let reason = r
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if reason.trim().len() < MIN_ROOT_REASON {
                    return Err(format!(
                        "cell `{id}`'s root verdict is `none` with reason {reason:?}. R-16: name \
                         the gap, never paper it -- a gap needs a one-line argument (>= \
                         {MIN_ROOT_REASON} chars) saying what the leg does instead."
                    ));
                }
                out.none.push(id.clone());
                tally.1 += 1;
            }
            Some("not-applicable") => {
                if !na {
                    return Err(format!(
                        "cell `{id}` is `{}` on the legacy path but `not-applicable` over the \
                         loop. `not-applicable` is a statement about the PLANE, not about the \
                         path; it cannot be true on one and false on the other.",
                        cell["state"].as_str().unwrap_or("?")
                    ));
                }
                tally.2 += 1;
            }
            other => {
                return Err(format!(
                    "cell `{id}`'s root verdict has state {other:?}. A root verdict is `proven`, \
                     `none`, or `not-applicable`; there is no fourth state, deliberately."
                ));
            }
        }
    }

    // A leg that answers to columns and proves NOTHING on any of them is a leg nobody drove.
    for (leg, cols) in &leg_columns {
        if cols.is_empty() {
            continue;
        }
        if out.per_leg[leg].0 == 0 {
            return Err(format!(
                "root leg `{leg}` answers to {cols:?} and proves ZERO cells over the loop. A leg \
                 with no watched cell is a leg nobody drove."
            ));
        }
    }
    if out.proven < min_root_proven {
        return Err(format!(
            "only {} root-proven cells (floor {min_root_proven}). A ledger that lost the root \
             column would report loop-equality of nothing.",
            out.proven
        ));
    }
    Ok(out)
}

fn real_doc() -> serde_json::Value {
    let p = repo_root().join("qa/capability-equality.json");
    serde_json::from_str(
        &std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display())),
    )
    .expect("qa/capability-equality.json parses")
}

// ---------------------------------------------------------------------------
// 1. The gate: the pinned matrix is exact, honest, and every proof exists.
// ---------------------------------------------------------------------------

#[test]
fn pinned_equality_matrix_is_exact_and_every_proof_exists() {
    let summary = verify(&real_doc(), &repo_root(), &PLANES, MIN_CAPABILITIES)
        .unwrap_or_else(|e| panic!("qa/capability-equality.json: {e}"));

    assert!(
        summary.proven >= MIN_PROVEN,
        "only {} proven cells (floor {MIN_PROVEN}). A matrix where almost nothing is proven was \
         not filled from the tree; fill it honestly, cell by cell.",
        summary.proven
    );

    // The named gap -- same honest-ledger shape as qa/method-coverage.missing. Green while the pin
    // matches reality; the umbrella (scripts/full-gate.sh) prints this list on every run.
    println!(
        "EQUALITY: {} cells missing ({} proven, {} n/a) -- {}",
        summary.missing.len(),
        summary.proven,
        summary.not_applicable,
        summary.missing.join(", ")
    );
}

/// THE ROOT COLUMN, STRUCTURALLY — on every build, whatever features are on. The verdicts are DATA
/// and the files they name are on disk either way, so this half needs no leg compiled; what it
/// refuses is a cell with no second verdict, a `proven` root cell whose loop cell vanished, a `none`
/// with no argument, and an n/a that disagrees with itself across the two paths.
#[test]
fn every_cell_carries_a_root_leg_verdict_and_every_root_proof_exists() {
    let s = verify_root(&real_doc(), &repo_root(), &ROOT_LEGS, MIN_ROOT_PROVEN)
        .unwrap_or_else(|e| panic!("qa/capability-equality.json root column: {e}"));
    println!(
        "ROOT-EQUALITY: {} cells proven over the loop, {} still \"none\" -- {}",
        s.proven,
        s.none.len(),
        s.none.join(", ")
    );
}

/// THE MATRIX, ONCE PER LEG, WITH THE FEATURES ON.
///
/// cfg-gated on all five `root-*` features rather than written as a boot test, for the reason in
/// this file's header: the legs carry no config key, no environment variable and no boot line, so a
/// booted binary cannot be asked which legs it has. A build without the features does not run this
/// -- it is absent, which is honest -- and the command the tracker pins turns all five on.
#[cfg(all(
    feature = "root-llm",
    feature = "root-mcp",
    feature = "root-a2a",
    feature = "root-voice",
    feature = "root-admin"
))]
#[test]
fn the_root_leg_matrix_runs_once_per_leg() {
    let doc = real_doc();
    let s = verify_root(&doc, &repo_root(), &ROOT_LEGS, MIN_ROOT_PROVEN)
        .unwrap_or_else(|e| panic!("qa/capability-equality.json root column: {e}"));

    // Once per leg: every declared leg is tallied, and the tallies sum to the whole matrix.
    let cells = doc["cells"].as_array().expect("`cells` is an array").len();
    let mut total = 0;
    for leg in ROOT_LEGS {
        let (proven, none, na) = s
            .per_leg
            .get(leg)
            .copied()
            .unwrap_or_else(|| panic!("leg `{leg}` was not run over the matrix"));
        total += proven + none + na;
        println!("  leg {leg:<11} {proven} proven, {none} none, {na} n/a");
    }
    assert_eq!(
        total, cells,
        "the per-leg tallies must account for every cell exactly once; a cell counted by no leg is \
         a cell no leg is judging"
    );
}

/// The constants above ARE the doctrine; a refactor that widened `verify`'s parameters must not be
/// able to quietly narrow what the real gate demands.
#[test]
fn the_gates_own_constants_are_the_doctrines() {
    assert_eq!(
        PLANES,
        [
            "llm",
            "mcp-client",
            "mcp-server",
            "a2a-client",
            "a2a-server",
            "voice-client",
            "voice-server"
        ],
        "the plane list is the owner's ruling (LLM == MCP == A2A == VOICE, both directions of the \
         bidirectional three); changing it is a doctrine change, not a refactor"
    );
    const {
        assert!(MIN_CAPABILITIES >= 12 && MIN_PROVEN >= 20 && MIN_NA_REASON >= 60);
    }
    assert_eq!(
        ROOT_LEGS,
        ["root-a2a", "root-admin", "root-llm", "root-mcp", "root-voice"],
        "the five root legs are the composition root's own; changing the list is a doctrine change"
    );
    const {
        assert!(
            MIN_ROOT_REASON >= 60 && MIN_ROOT_PROVEN >= 25 && MIN_ZERO_COLUMN_ARGUMENT >= 120
        );
    }
}

/// Read the ONE list of plane keys (`scripts/plane-keys.sh`, the same source the shell gates read)
/// so this test enumerates the workspace plane crates from the tree's single source, not a second
/// hand-kept copy. A plane added there is enumerated here with no edit.
fn plane_keys_from_single_source(root: &Path) -> Vec<String> {
    let p = root.join("scripts/plane-keys.sh");
    let src = std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read the single source of plane keys {}: {e}",
            p.display()
        )
    });
    for line in src.lines() {
        if let Some(rest) = line.trim().strip_prefix("PLANE_KEYS=") {
            return rest
                .trim()
                .trim_matches('"')
                .split_whitespace()
                .map(str::to_string)
                .collect();
        }
    }
    panic!("scripts/plane-keys.sh declares no `PLANE_KEYS=...` line");
}

/// M0 TOTALITY CROSS-CHECK. Enumerate the workspace PLANE CRATES from the single source and assert
/// each maps to >= 1 ledger column. This is the reverse of the pinned matrix: the matrix proves no
/// declared cell is a lie; this proves no plane crate the tree carries is tracked by NOTHING. Voice
/// arriving as a skeleton with no directional column is exactly the hole it catches — pinned here to
/// its pending column so the check is honest-green today and RED the moment a plane crate joins the
/// workspace with no row in `PLANE_CRATE_LEDGER_COLUMNS`.
#[test]
fn every_workspace_plane_crate_maps_to_at_least_one_ledger_column() {
    let root = repo_root();
    let ledger_columns: BTreeSet<String> = real_doc()["planes"]
        .as_object()
        .expect("`planes` is an object")
        .keys()
        .cloned()
        .collect();
    let map: BTreeMap<&str, &[&str]> = PLANE_CRATE_LEDGER_COLUMNS.iter().copied().collect();

    let mut unmapped: Vec<String> = Vec::new();
    for key in plane_keys_from_single_source(&root) {
        // The single source names this plane; the crate must exist, or source and tree disagree.
        let crate_dir = root.join(format!("crates/busbar-{key}"));
        assert!(
            crate_dir.is_dir(),
            "scripts/plane-keys.sh names plane `{key}` but crates/busbar-{key} does not exist; the \
             single source and the tree disagree — fix one."
        );
        match map.get(key.as_str()) {
            Some(cols) if !cols.is_empty() => {
                // Every mapped column must be a real declared ledger plane (voice is armed: its
                // voice-client / voice-server columns are real ledger planes like the other two).
                for &col in *cols {
                    assert!(
                        ledger_columns.contains(col),
                        "plane crate busbar-{key} maps to column `{col}`, which is not a declared \
                         ledger plane {ledger_columns:?}. Fix the map or the ledger."
                    );
                }
            }
            _ => unmapped.push(key),
        }
    }
    assert!(
        unmapped.is_empty(),
        "workspace plane crate(s) {unmapped:?} map to ZERO ledger columns. A plane crate that \
         reaches the workspace and answers to no column is tracked by nothing — add its columns to \
         PLANE_CRATE_LEDGER_COLUMNS (voice is pinned to its own pending column as the pattern)."
    );

    println!(
        "TOTALITY: {} workspace plane crate(s) all map to >= 1 ledger column",
        PLANE_CRATE_LEDGER_COLUMNS.len()
    );
}

// ---------------------------------------------------------------------------
// 2. SELF-TEST: the gate is proven to FIRE, on fixtures, through the REAL `verify`.
//    House rule: a gate that cannot fail is worse than none.
// ---------------------------------------------------------------------------

/// A small well-formed matrix (2 capabilities x 2 planes) whose one proven cell points at a fixture
/// test file this helper plants on disk. Each red case below breaks exactly one thing.
fn fixture(root: &Path) -> serde_json::Value {
    let tests_dir = root.join("crates/x/tests");
    std::fs::create_dir_all(&tests_dir).expect("fixture tests dir");
    std::fs::write(
        tests_dir.join("real_tests.rs"),
        "#[test]\nfn the_named_instrument() {}\n",
    )
    .expect("fixture test file");
    serde_json::json!({
        "capabilities": {
            "cap-a": "a capability defined at argument length for the fixture",
            "cap-b": "another capability defined at argument length for the fixture"
        },
        "planes": { "p1": "first fixture plane", "p2": "second fixture plane" },
        "cells": [
            { "capability": "cap-a", "plane": "p1", "state": "proven",
              "test": "crates/x/tests/real_tests.rs::the_named_instrument" },
            { "capability": "cap-a", "plane": "p2", "state": "missing" },
            { "capability": "cap-b", "plane": "p1", "state": "not-applicable",
              "reason": "a fixture argument that is long enough to be an actual argument a reviewer could disagree with" },
            { "capability": "cap-b", "plane": "p2", "state": "missing" }
        ]
    })
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-capability-equality-selftest-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("selftest scratch dir");
    d
}

#[test]
fn selftest_green_fixture_passes_and_counts_honestly() {
    let root = scratch("green");
    let s = verify(&fixture(&root), &root, &["p1", "p2"], 2).expect("the green fixture verifies");
    assert_eq!(s.proven, 1);
    assert_eq!(s.missing, vec!["cap-a\u{d7}p2", "cap-b\u{d7}p2"]);
    assert_eq!(s.not_applicable, 1);
    assert_eq!(s.per_plane_missing["p2"], 2);
    let _ = std::fs::remove_dir_all(&root);
}

/// (a) A proven cell whose named test VANISHES must turn the gate red -- this is the regression
/// case, and it is the single most important firing mode: a claim outliving its evidence.
#[test]
fn selftest_a_proven_cell_whose_named_test_vanished_is_red() {
    // The fn is renamed out from under the claim.
    let root = scratch("vanish-fn");
    let doc = fixture(&root);
    std::fs::write(
        root.join("crates/x/tests/real_tests.rs"),
        "#[test]\nfn renamed_out_from_under_the_claim() {}\n",
    )
    .unwrap();
    let err = verify(&doc, &root, &["p1", "p2"], 2).expect_err("a vanished test fn must be red");
    assert!(
        err.contains("the_named_instrument") && err.contains("gone or renamed"),
        "the error must name the vanished instrument; got: {err}"
    );

    // The whole file is deleted.
    let root2 = scratch("vanish-file");
    let doc2 = fixture(&root2);
    std::fs::remove_file(root2.join("crates/x/tests/real_tests.rs")).unwrap();
    let err2 =
        verify(&doc2, &root2, &["p1", "p2"], 2).expect_err("a deleted test file must be red");
    assert!(
        err2.contains("REGRESSED"),
        "the error must say the cell regressed; got: {err2}"
    );

    // And evidence pointing at NON-test code is refused even if it exists.
    let root3 = scratch("not-a-test");
    let mut doc3 = fixture(&root3);
    std::fs::create_dir_all(root3.join("crates/x/src")).unwrap();
    std::fs::write(
        root3.join("crates/x/src/lib.rs"),
        "pub fn the_named_instrument() {}\n",
    )
    .unwrap();
    doc3["cells"][0]["test"] = "crates/x/src/lib.rs::the_named_instrument".into();
    let err3 = verify(&doc3, &root3, &["p1", "p2"], 2)
        .expect_err("production code is not evidence of a watched instrument");
    assert!(err3.contains("not a test location"), "got: {err3}");

    for r in [root, root2, root3] {
        let _ = std::fs::remove_dir_all(&r);
    }
}

/// (b) A pinned file that disagrees with the computed cross product -- a hole, a duplicate, or a
/// cell naming an undeclared axis -- must be red. An absent cell and a considered cell look
/// identical on the page; only the computation tells them apart.
#[test]
fn selftest_b_pin_disagreeing_with_computed_cross_product_is_red() {
    // A HOLE: one cell silently absent.
    let root = scratch("hole");
    let mut doc = fixture(&root);
    doc["cells"].as_array_mut().unwrap().pop();
    let err = verify(&doc, &root, &["p1", "p2"], 2).expect_err("a hole in the matrix must be red");
    assert!(
        err.contains("cap-b\u{d7}p2") && err.contains("ABSENT"),
        "the error must name the absent cell; got: {err}"
    );

    // A DUPLICATE: two answers for one cell.
    let root2 = scratch("dup");
    let mut doc2 = fixture(&root2);
    let dup = doc2["cells"][1].clone();
    doc2["cells"].as_array_mut().unwrap().push(dup);
    let err2 = verify(&doc2, &root2, &["p1", "p2"], 2).expect_err("a duplicate cell must be red");
    assert!(err2.contains("appears twice"), "got: {err2}");

    // AN UNDECLARED PLANE: a cell for a column the header does not own.
    let root3 = scratch("undeclared");
    let mut doc3 = fixture(&root3);
    doc3["cells"][1]["plane"] = "p9".into();
    let err3 =
        verify(&doc3, &root3, &["p1", "p2"], 2).expect_err("an undeclared plane must be red");
    assert!(err3.contains("p9"), "got: {err3}");

    // A FOURTH STATE: `partially` is not a state, here or in method-coverage.
    let root4 = scratch("fourth-state");
    let mut doc4 = fixture(&root4);
    doc4["cells"][1]["state"] = "partially".into();
    let err4 = verify(&doc4, &root4, &["p1", "p2"], 2).expect_err("a fourth state must be red");
    assert!(err4.contains("no fourth state"), "got: {err4}");

    for r in [root, root2, root3, root4] {
        let _ = std::fs::remove_dir_all(&r);
    }
}

/// (c) An n/a cell with no argument (or a token one) must be red. N/A is a claim.
#[test]
fn selftest_c_na_cell_without_an_argument_is_red() {
    let root = scratch("na-empty");
    let mut doc = fixture(&root);
    doc["cells"][2]["reason"] = "".into();
    let err = verify(&doc, &root, &["p1", "p2"], 2).expect_err("an argument-free n/a must be red");
    assert!(err.contains("not an escape"), "got: {err}");

    let root2 = scratch("na-token");
    let mut doc2 = fixture(&root2);
    doc2["cells"][2]["reason"] = "does not apply".into();
    let err2 = verify(&doc2, &root2, &["p1", "p2"], 2).expect_err("a token n/a label must be red");
    assert!(err2.contains("not an escape"), "got: {err2}");

    // And an n/a with a REAL argument still passes -- the gate must move in both directions or it
    // is decorative.
    let root3 = scratch("na-ok");
    let doc3 = fixture(&root3);
    verify(&doc3, &root3, &["p1", "p2"], 2).expect("a properly argued n/a is legitimate");

    for r in [root, root2, root3] {
        let _ = std::fs::remove_dir_all(&r);
    }
}

// ---------------------------------------------------------------------------
// 3. SELF-TEST for the ROOT LEG column, through the REAL `verify_root`.
// ---------------------------------------------------------------------------

const ARG: &str =
    "a fixture argument long enough to be an argument a reviewer could actually disagree with here";
const LONG_ARG: &str = "a fixture argument for a leg that answers to zero ledger columns, which is a \
                        real claim about the plane rather than an omission, and therefore costs a \
                        longer sentence than an ordinary gap does";

/// Two legs over two planes, one leg per plane, with a planted root file per leg. `leg-a` proves its
/// one non-n/a cell; `leg-b` proves one and names one honest gap.
fn root_fixture(root: &Path) -> serde_json::Value {
    let dir = root.join(ROOT_DIR);
    std::fs::create_dir_all(&dir).expect("fixture root dir");
    for f in ["units_a.rs", "units_b.rs"] {
        std::fs::write(dir.join(f), "#[test]\nfn the_loop_cell() {}\n").expect("fixture leg file");
    }
    serde_json::json!({
        "capabilities": { "cap-a": ARG, "cap-b": ARG },
        "planes": { "p1": "first fixture plane", "p2": "second fixture plane" },
        "root_legs": {
            "leg-a": { "file": "crates/busbar/src/root/units_a.rs", "columns": ["p1"], "note": ARG },
            "leg-b": { "file": "crates/busbar/src/root/units_b.rs", "columns": ["p2"], "note": ARG }
        },
        "cells": [
            { "capability": "cap-a", "plane": "p1", "state": "proven", "test": "x",
              "root": { "state": "proven", "leg": "leg-a",
                        "test": "crates/busbar/src/root/units_a.rs::the_loop_cell" } },
            { "capability": "cap-a", "plane": "p2", "state": "proven", "test": "x",
              "root": { "state": "proven", "leg": "leg-b",
                        "test": "crates/busbar/src/root/units_b.rs::the_loop_cell" } },
            { "capability": "cap-b", "plane": "p1", "state": "not-applicable", "reason": ARG,
              "root": { "state": "not-applicable", "leg": "leg-a" } },
            { "capability": "cap-b", "plane": "p2", "state": "proven", "test": "x",
              "root": { "state": "none", "leg": "leg-b", "reason": ARG } }
        ]
    })
}

const FIXTURE_LEGS: [&str; 2] = ["leg-a", "leg-b"];

#[test]
fn selftest_root_green_fixture_passes_and_tallies_per_leg() {
    let root = scratch("root-green");
    let s = verify_root(&root_fixture(&root), &root, &FIXTURE_LEGS, 2)
        .expect("the green root fixture verifies");
    assert_eq!(s.proven, 2);
    assert_eq!(s.none, vec!["cap-b\u{d7}p2"]);
    assert_eq!(s.per_leg["leg-a"], (1, 0, 1));
    assert_eq!(s.per_leg["leg-b"], (1, 1, 0));
    let _ = std::fs::remove_dir_all(&root);
}

/// The regression case, again: a root cell whose named loop cell vanished, and a root cell whose
/// evidence came from ANOTHER leg's file. Both are claims about a loop nobody drove.
#[test]
fn selftest_root_evidence_that_vanished_or_came_from_another_leg_is_red() {
    let root = scratch("root-vanish");
    let doc = root_fixture(&root);
    std::fs::write(
        root.join(ROOT_DIR).join("units_a.rs"),
        "#[test]\nfn renamed_out_from_under_the_claim() {}\n",
    )
    .unwrap();
    let err = verify_root(&doc, &root, &FIXTURE_LEGS, 1).expect_err("a vanished loop cell is red");
    assert!(
        err.contains("the_loop_cell") && err.contains("gone or renamed"),
        "got: {err}"
    );

    let root2 = scratch("root-wrong-leg");
    let mut doc2 = root_fixture(&root2);
    doc2["cells"][0]["root"]["test"] = "crates/busbar/src/root/units_b.rs::the_loop_cell".into();
    let err2 = verify_root(&doc2, &root2, &FIXTURE_LEGS, 1)
        .expect_err("evidence from another leg's file is red");
    assert!(err2.contains("proven by its own cells"), "got: {err2}");

    for r in [root, root2] {
        let _ = std::fs::remove_dir_all(&r);
    }
}

/// A cell with NO second verdict, and a `none` with no argument. R-16: name the gap, never paper it
/// -- and an absent verdict papers it by saying nothing at all.
#[test]
fn selftest_a_missing_root_verdict_or_an_unargued_gap_is_red() {
    let root = scratch("root-absent");
    let mut doc = root_fixture(&root);
    doc["cells"][0].as_object_mut().unwrap().remove("root");
    let err = verify_root(&doc, &root, &FIXTURE_LEGS, 1).expect_err("an absent root verdict is red");
    assert!(err.contains("carries no `root` verdict"), "got: {err}");

    let root2 = scratch("root-token");
    let mut doc2 = root_fixture(&root2);
    doc2["cells"][3]["root"]["reason"] = "not yet".into();
    let err2 =
        verify_root(&doc2, &root2, &FIXTURE_LEGS, 1).expect_err("an unargued root gap is red");
    assert!(err2.contains("never paper it"), "got: {err2}");

    for r in [root, root2] {
        let _ = std::fs::remove_dir_all(&r);
    }
}

/// The two verdicts must move together, and every column must be answered by exactly one leg.
#[test]
fn selftest_root_verdict_disagreeing_with_the_cell_or_an_unowned_column_is_red() {
    // n/a on one path, proven on the other.
    let root = scratch("root-disagree");
    let mut doc = root_fixture(&root);
    doc["cells"][2]["root"] = serde_json::json!({
        "state": "proven", "leg": "leg-a",
        "test": "crates/busbar/src/root/units_a.rs::the_loop_cell"
    });
    let err = verify_root(&doc, &root, &FIXTURE_LEGS, 1)
        .expect_err("an n/a cell proven over the loop is red");
    assert!(err.contains("move together"), "got: {err}");

    // A ledger plane no leg answers to.
    let root2 = scratch("root-unowned");
    let mut doc2 = root_fixture(&root2);
    doc2["root_legs"]["leg-b"]["columns"] = serde_json::json!([]);
    doc2["root_legs"]["leg-b"]["note"] = LONG_ARG.into();
    let err2 =
        verify_root(&doc2, &root2, &FIXTURE_LEGS, 1).expect_err("a column no leg answers to is red");
    assert!(err2.contains("answered by NO root leg"), "got: {err2}");

    // A leg that answers to a column and proves nothing on it.
    let root3 = scratch("root-undriven");
    let mut doc3 = root_fixture(&root3);
    doc3["cells"][1]["root"] = serde_json::json!({ "state": "none", "leg": "leg-b", "reason": ARG });
    let err3 = verify_root(&doc3, &root3, &FIXTURE_LEGS, 1)
        .expect_err("a leg with no watched cell is red");
    assert!(err3.contains("nobody drove"), "got: {err3}");

    // A leg list that lost a leg.
    let root4 = scratch("root-legs");
    let doc4 = root_fixture(&root4);
    let err4 = verify_root(&doc4, &root4, &["leg-a"], 1).expect_err("a dropped leg is red");
    assert!(err4.contains("would take its whole column"), "got: {err4}");

    for r in [root, root2, root3, root4] {
        let _ = std::fs::remove_dir_all(&r);
    }
}
