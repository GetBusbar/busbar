//! THE CONFIG-STABILITY GATE — the config grammar is FROZEN after 1.5.3, additive-only forever.
//!
//! `scripts/config-stability-gate.sh` + `scripts/config-schema.py`, as one registered gate. Two
//! rules, the same two the shell had, plus the three refusals that were scattered through its
//! control flow and are rows here because a refusal nobody reconciles is a refusal that can go
//! quiet:
//!
//! | row | the refusal |
//! |---|---|
//! | `config-schema:tracked-sources` | the TRACKED SOURCE SET resolved and every source in it was read. A vanished source, a plane whose grammar has no home or two homes, a duplicate bare type name, a lift list naming a key no struct carries, an unsupported `rename_all` — each stops the gate here. A source that silently drops out of the set silently un-freezes its grammar, which is the whole failure this gate exists to prevent, so it is never a narrower scan. |
//! | `config-schema:snapshot-drift` | the committed `config-schema.snapshot.json` byte-equals a fresh render. `--write` REWRITES it instead of diffing it — the same derivation either way, so the two arms cannot disagree about what the answer is; the flag only decides whether it is compared or committed. |
//! | `config-schema:baseline` | the baseline ref RESOLVES **and** carries the snapshot, and the snapshot it carries has types in it. All three used to be bypasses. |
//! | `config-schema:additive-only` | every delta from the baseline to the fresh render is additive (or waived). Field removed/retyped/newly-required, enum variant dropped, a hand-written impl's refusal added *or removed* = RED. |
//! | `config-schema:waivers` | the waiver register parses, names exact paths with reasons, and carries no STALE entry — a waiver matching nothing is standing permission to break that path later. |
//!
//! ## THE BASELINE IS A GIT REF, NEVER THE WORKING TREE
//!
//! That is the one design decision the whole gate rests on. The drift guard compares the committed
//! snapshot against a fresh render, so a config change that forgets to regenerate is caught — but
//! regenerating is a one-line command, and if the additive check also read the working tree then
//! running it would *launder the break*: the snapshot and the render would agree, and the removal
//! would be invisible. Reading the baseline from history is what makes "refresh the snapshot" an
//! honest act rather than a bypass. [`Ctx::git_show`] is the only door to it.
//!
//! ## THE DECLARED BOOTSTRAP IS NOT A PASS, AND IT IS STILL NOT RED
//!
//! `CONFIG_SCHEMA_BOOTSTRAP=1` is the shell's one-run escape from having no baseline at all, and it
//! is kept exactly as the shell had it — exit 0, with the skipped check ANNOUNCED in the row's own
//! title and detail. Making it RED here would have been a stricter gate smuggled in under a port
//! whose job is to prove the two halves agree; it is a change to argue for on its own, not one to
//! land inside a parity proof. `scripts/verify-1.6.0-done.sh` is what refuses a DONE run that sets
//! it, and that assertion is unchanged.

pub mod classify;
pub mod scan;
pub mod schema;

use std::collections::BTreeMap;

use serde_json::Value;

use crate::ctx::Ctx;
use crate::gates::{Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_TRACKED_SOURCES: &str = "config-schema:tracked-sources";
pub const ROW_SNAPSHOT_DRIFT: &str = "config-schema:snapshot-drift";
pub const ROW_BASELINE: &str = "config-schema:baseline";
pub const ROW_ADDITIVE_ONLY: &str = "config-schema:additive-only";
pub const ROW_WAIVERS: &str = "config-schema:waivers";

pub const OWED: &[&str] = &[
    ROW_TRACKED_SOURCES,
    ROW_SNAPSHOT_DRIFT,
    ROW_BASELINE,
    ROW_ADDITIVE_ONLY,
    ROW_WAIVERS,
];

/// The default baseline ref. `CONFIG_SCHEMA_BASELINE_REF` overrides it, through [`crate::ctx::Env`]
/// rather than out of the process environment, so a runner can see the gate reading it.
pub const DEFAULT_BASELINE_REF: &str = "HEAD";

/// The regen command, spelled once so every row that suggests it suggests the same thing.
const REGEN: &str = "cargo xtask gate config-schema --write";

/// The FLOOR under the tracked source set. The set is a fixed list of eleven entries today, two of
/// them directories; a render built from a handful of files is a render that lost most of the
/// config grammar, and "no delta" is the passing answer to every question this gate asks. The floor
/// is deliberately far below today's count — it catches a collapse, not a refactor.
const MIN_TRACKED_FILES: usize = 8;

/// The FLOOR under a baseline's type map. See [`row_baseline`].
const MIN_BASELINE_TYPES: usize = 1;

// ── the rows ─────────────────────────────────────────────────────────────────────────────────────

fn unproven(id: &str, why: &str) -> Row {
    Row::skip(
        id,
        "unproven — the check above this one refused",
        why.to_string(),
    )
}

/// Every owed row except `first`, as SKIP. A refusal at the top of the derivation makes every row
/// under it DID NOT RUN; reporting them as passes is the false green the whole harness exists to
/// refuse.
fn refuse(first: &str, why: String) -> Verdict {
    let mut rows = vec![Row::fail(
        first,
        "the tracked source set was refused",
        why.clone(),
    )];
    for id in OWED {
        if *id != first {
            rows.push(unproven(id, &why));
        }
    }
    Verdict::of(rows)
}

fn row_tracked_sources(files: usize, types: usize) -> Row {
    Row::pass(
        ROW_TRACKED_SOURCES,
        "the tracked source set resolved and every source in it was read",
        format!("{files} tracked source file(s), {types} type(s) fingerprinted"),
    )
}

fn row_drift(state: DriftState) -> Row {
    match state {
        DriftState::Written(n) => Row::pass(
            ROW_SNAPSHOT_DRIFT,
            "the committed snapshot IS the fresh render (rewritten by --write)",
            format!("{} rewritten, {n} type(s)", schema::SNAPSHOT),
        ),
        DriftState::Clean(n) => Row::pass(
            ROW_SNAPSHOT_DRIFT,
            "the committed snapshot byte-equals a fresh render of the config surface",
            format!("{} is current, {n} type(s)", schema::SNAPSHOT),
        ),
        DriftState::Missing => Row::fail(
            ROW_SNAPSHOT_DRIFT,
            "the committed snapshot is MISSING",
            format!(
                "{} does not exist. The drift guard has nothing to compare against, so nothing \
                 about the config surface was measured. Seed it with:  {REGEN}",
                schema::SNAPSHOT
            ),
        ),
        DriftState::Stale { first_diff } => Row::fail(
            ROW_SNAPSHOT_DRIFT,
            "the committed snapshot is STALE",
            format!(
                "{} does not match the config source — the surface changed and the snapshot was \
                 not regenerated. {first_diff}  Regenerate (a reviewed, intentional change) with:  \
                 {REGEN}. Regenerating does NOT launder a break: the additive check below reads the \
                 committed baseline, not your working tree.",
                schema::SNAPSHOT
            ),
        ),
        DriftState::Unwritable(e) => Row::fail(
            ROW_SNAPSHOT_DRIFT,
            "the committed snapshot could not be written",
            format!("{} could not be written: {e}", schema::SNAPSHOT),
        ),
    }
}

enum DriftState {
    Written(usize),
    Clean(usize),
    Missing,
    Stale { first_diff: String },
    Unwritable(String),
}

/// The first line the two renders disagree on, so a stale snapshot says WHERE rather than only
/// THAT. The shell printed sixty lines of `diff -u`; one located line is what a reader acts on.
fn first_difference(committed: &str, fresh: &str) -> String {
    for (i, (a, b)) in committed.lines().zip(fresh.lines()).enumerate() {
        if a != b {
            return format!(
                "first difference at line {}: committed {:?} vs fresh {:?}.",
                i + 1,
                a.trim(),
                b.trim()
            );
        }
    }
    format!(
        "the two agree for {} line(s) and then differ in length (committed {} line(s), fresh {}).",
        committed.lines().count().min(fresh.lines().count()),
        committed.lines().count(),
        fresh.lines().count()
    )
}

/// THE BASELINE ARM, AND THE THREE BYPASSES IT CLOSES.
///
/// 1. A ref that does NOT RESOLVE. Point the gate at a typo and every breaking change sails through
///    green, so an unresolvable ref is a hard error and never a skip. In CI it almost always means
///    the checkout was shallow — `actions/checkout` with `fetch-depth: 0`.
/// 2. A ref that resolves and carries NO SNAPSHOT. This was the identical bypass one branch later:
///    any commit from before the snapshot landed grants it, and so does an orphan branch or an old
///    tag. The additive check is the WHOLE gate, and a run that did not perform it has measured
///    nothing — it must not be able to say PASS.
/// 3. **A baseline that carries an EMPTY TYPE MAP** — the hole this port closes. The classifier
///    reads `baseline["types"]`, and against an empty one every single type in the fresh render is
///    a `new type/section added`, which is ADDITIVE, which is GREEN. So a baseline snapshot that
///    was truncated, hand-emptied, or written by a generator that crashed after the header is a
///    silent, total bypass of the additive rule that looks exactly like a clean run. An empty
///    baseline is not a baseline.
fn row_baseline(state: &BaselineState) -> Row {
    match state {
        BaselineState::Ok { r, types } => Row::pass(
            ROW_BASELINE,
            "the additive-only baseline was read from a git ref, not the working tree",
            format!("baseline '{r}' carries {} with {types} type(s)", schema::SNAPSHOT),
        ),
        BaselineState::Bootstrap { r } => Row::pass(
            ROW_BASELINE,
            "DECLARED BOOTSTRAP — the additive check DID NOT RUN and nothing was measured",
            format!(
                "CONFIG_SCHEMA_BOOTSTRAP=1: baseline '{r}' carries no {}, so the additive-only \
                 check did not run this run. This is a declared bootstrap, not a pass — it proves \
                 nothing about whether the config surface changed compatibly.",
                schema::SNAPSHOT
            ),
        ),
        BaselineState::Unresolvable { r } => Row::fail(
            ROW_BASELINE,
            "the baseline ref does NOT resolve",
            format!(
                "baseline ref '{r}' does not resolve — refusing to run. The additive check is the \
                 whole gate; silently skipping it would be a free bypass. In CI this almost always \
                 means the checkout was shallow — use actions/checkout with fetch-depth: 0 (and for \
                 a PR, fetch the base branch). Locally, set CONFIG_SCHEMA_BASELINE_REF to a ref \
                 that exists (default: {DEFAULT_BASELINE_REF})."
            ),
        ),
        BaselineState::NoSnapshot { r } => Row::fail(
            ROW_BASELINE,
            "the baseline ref resolves but carries NO snapshot",
            format!(
                "baseline ref '{r}' resolves but carries NO {}. The additive check is the whole \
                 gate, and it did not run — so nothing was measured. A ref that resolves without \
                 the snapshot is the same free bypass as a ref that does not resolve at all: any \
                 commit from before the snapshot landed grants it. Pointing the gate somewhere else \
                 is not a fix. The ONE legitimate case is declared, not inferred: \
                 CONFIG_SCHEMA_BOOTSTRAP=1.",
                schema::SNAPSHOT
            ),
        ),
        BaselineState::Unparseable { r, why } => Row::fail(
            ROW_BASELINE,
            "the baseline snapshot is not readable JSON",
            format!("baseline '{r}' carries a {} that does not parse: {why}", schema::SNAPSHOT),
        ),
        BaselineState::Empty { r, types } => Row::fail(
            ROW_BASELINE,
            "the baseline carries an EMPTY type map — every delta would read as additive",
            format!(
                "baseline '{r}' carries {} with {types} type(s), under the floor of \
                 {MIN_BASELINE_TYPES}. The classifier reads the baseline's type map, and against an \
                 empty one EVERY type in the fresh render is a `new type/section added` — which is \
                 ADDITIVE, which is GREEN. A truncated or hand-emptied baseline is therefore a \
                 total, silent bypass of the additive rule that looks exactly like a clean run. An \
                 empty baseline is not a baseline.",
                schema::SNAPSHOT
            ),
        ),
    }
}

enum BaselineState {
    Ok { r: String, types: usize },
    Bootstrap { r: String },
    Unresolvable { r: String },
    NoSnapshot { r: String },
    Unparseable { r: String, why: String },
    Empty { r: String, types: usize },
}

fn row_additive(outcome: &classify::Outcome) -> Row {
    if outcome.breaking.is_empty() {
        let mut detail = format!(
            "{} additive delta(s), {} relocation(s), {} waived break(s)",
            outcome.additive.len(),
            outcome.relocated.len(),
            outcome.waived.len()
        );
        // A RELOCATION is printed on its own line every run, loudly: it is a third verdict, not a
        // pass, and a reviewer must be able to see the move and ask whether it was intended.
        for f in &outcome.relocated {
            detail.push_str(&format!("  |  RELOCATED {}: {}", f.path, f.reason));
        }
        for (f, why) in &outcome.waived {
            detail.push_str(&format!("  |  WAIVED {} <- {why}", f.path));
        }
        return Row::pass(
            ROW_ADDITIVE_ONLY,
            "every config-surface delta is additive (or an exact-path waived break)",
            detail,
        );
    }
    let mut detail = format!("{} non-additive delta(s): ", outcome.breaking.len());
    for f in &outcome.breaking {
        detail.push_str(&format!("{} — {}  |  ", f.path, f.reason));
    }
    detail.push_str(classify::FROZEN_MSG);
    Row::fail(ROW_ADDITIVE_ONLY, "NON-ADDITIVE config change", detail)
}

fn row_waivers(state: &WaiverState) -> Row {
    match state {
        WaiverState::Ok { n } => Row::pass(
            ROW_WAIVERS,
            "the waiver register is well-formed and every entry is still doing work",
            format!("{} carries {n} waiver(s), none stale", schema::WAIVERS),
        ),
        WaiverState::Malformed { why } => {
            Row::fail(ROW_WAIVERS, "the waiver register is malformed", why.clone())
        }
        WaiverState::Stale { keys } => Row::fail(
            ROW_WAIVERS,
            "the waiver register carries a STALE waiver",
            format!(
                "these waiver(s) excuse a break that no longer exists: {}. Delete them — a \
                 lingering waiver silently pre-authorizes a future break at that exact path, which \
                 is standing permission nobody re-reviews.",
                keys.join(", ")
            ),
        ),
    }
}

enum WaiverState {
    Ok { n: usize },
    Malformed { why: String },
    Stale { keys: Vec<String> },
}

/// How many types a fingerprint document declares.
fn type_count(doc: &Value) -> usize {
    doc.get("types")
        .and_then(Value::as_object)
        .map(serde_json::Map::len)
        .unwrap_or(0)
}

// ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────

pub struct ConfigSchemaGate;

impl Gate for ConfigSchemaGate {
    fn name(&self) -> &'static str {
        "config-schema"
    }

    fn owed(&self) -> Vec<String> {
        OWED.iter().map(|s| (*s).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        // ── THE TRACKED SOURCE SET. Every refusal in the extractor lands here, and every row
        //    below it is SKIP rather than PASS: a render nobody managed to build measures nothing.
        let paths = match schema::sources(cx) {
            Ok(p) => p,
            Err(why) => return refuse(ROW_TRACKED_SOURCES, why),
        };
        let files = match schema::resolve_sources(cx, &paths) {
            Ok(f) => f,
            Err(why) => return refuse(ROW_TRACKED_SOURCES, why),
        };
        if files.len() < MIN_TRACKED_FILES {
            return refuse(
                ROW_TRACKED_SOURCES,
                format!(
                    "the tracked source set resolved to only {} file(s), under its floor of \
                     {MIN_TRACKED_FILES}. A render built from a handful of files has lost most of \
                     the config grammar, and `no delta` is the passing answer to every question \
                     this gate asks — a shrunken scan reads exactly like a clean tree.",
                    files.len()
                ),
            );
        }
        let mut read = Vec::with_capacity(files.len());
        for path in &files {
            match cx.read(path) {
                Ok(text) => read.push((path.clone(), text)),
                Err(why) => return refuse(ROW_TRACKED_SOURCES, why),
            }
        }
        let fresh = match schema::extract(&read) {
            Ok(v) => v,
            Err(why) => return refuse(ROW_TRACKED_SOURCES, why),
        };
        let fresh_text = schema::canonical(&fresh);
        let n_types = type_count(&fresh);

        let mut rows = vec![row_tracked_sources(files.len(), n_types)];

        // ── THE DRIFT GUARD. One derivation, two arms: write it, or diff it.
        rows.push(row_drift(if cx.env().write {
            match std::fs::write(cx.abs(schema::SNAPSHOT), &fresh_text) {
                Ok(()) => DriftState::Written(n_types),
                Err(e) => DriftState::Unwritable(e.to_string()),
            }
        } else {
            match cx.read(schema::SNAPSHOT) {
                Err(_) => DriftState::Missing,
                Ok(committed) if committed != fresh_text => DriftState::Stale {
                    first_diff: first_difference(&committed, &fresh_text),
                },
                Ok(_) => DriftState::Clean(n_types),
            }
        }));

        // ── THE WAIVER REGISTER, parsed before it is applied. An absent file is an empty register,
        //    which is the documented default and the state this file should stay in.
        let waiver_text = cx.read(schema::WAIVERS).unwrap_or_default();
        let waivers = match classify::load_waivers(schema::WAIVERS, &waiver_text) {
            Ok(w) => w,
            Err(why) => {
                rows.push(row_waivers(&WaiverState::Malformed { why: why.clone() }));
                rows.push(unproven(
                    ROW_BASELINE,
                    "the waiver register is malformed, so no break could be judged against it",
                ));
                rows.push(unproven(
                    ROW_ADDITIVE_ONLY,
                    "the waiver register is malformed, so no break could be judged against it",
                ));
                return Verdict::of(rows);
            }
        };

        // ── THE BASELINE, FROM A GIT REF AND NEVER THE WORKING TREE.
        let r = cx
            .env()
            .config_baseline_ref
            .clone()
            .unwrap_or_else(|| DEFAULT_BASELINE_REF.to_string());
        let (state, baseline) = read_baseline(cx, &r);
        rows.push(row_baseline(&state));

        match baseline {
            Some(baseline) => {
                let outcome = classify::judge(classify::classify(&baseline, &fresh), &waivers);
                rows.push(row_additive(&outcome));
                rows.push(row_waivers(&if outcome.stale.is_empty() {
                    WaiverState::Ok { n: waivers.len() }
                } else {
                    WaiverState::Stale {
                        keys: outcome.stale.clone(),
                    }
                }));
            }
            None => {
                // No baseline: the additive check did not run. Under the DECLARED bootstrap that is
                // announced and tolerated; otherwise the baseline row above is already FAIL and
                // this one must not claim to have measured anything.
                let why = match &state {
                    BaselineState::Bootstrap { .. } => {
                        "the declared bootstrap: there was no baseline to classify against"
                    }
                    _ => "the baseline was refused above, so no delta could be classified",
                };
                rows.push(unproven(ROW_ADDITIVE_ONLY, why));
                // The waiver register is still judged on its own terms — it parsed, and a STALE
                // entry cannot be detected without a classification, so this says only what it
                // knows.
                rows.push(unproven(
                    ROW_WAIVERS,
                    "no classification ran, so no waiver could be shown to be doing work",
                ));
            }
        }

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        selftest::run(self, cx)
    }
}

/// Resolve the baseline ref and read the snapshot it carries. Returns the row state and, when there
/// is one, the parsed baseline the classifier gets.
fn read_baseline(cx: &Ctx, r: &str) -> (BaselineState, Option<Value>) {
    if !cx.git_ref_resolves(r) {
        return (BaselineState::Unresolvable { r: r.to_string() }, None);
    }
    let Ok(text) = cx.git_show(r, schema::SNAPSHOT) else {
        return if cx.env().config_bootstrap {
            (BaselineState::Bootstrap { r: r.to_string() }, None)
        } else {
            (BaselineState::NoSnapshot { r: r.to_string() }, None)
        };
    };
    let doc: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return (
                BaselineState::Unparseable {
                    r: r.to_string(),
                    why: e.to_string(),
                },
                None,
            )
        }
    };
    let types = type_count(&doc);
    if types < MIN_BASELINE_TYPES {
        return (
            BaselineState::Empty {
                r: r.to_string(),
                types,
            },
            None,
        );
    }
    (
        BaselineState::Ok {
            r: r.to_string(),
            types,
        },
        Some(doc),
    )
}

/// The waiver register as the gate reads it, exposed for the self-test.
pub fn waivers_of(cx: &Ctx) -> Result<BTreeMap<String, String>, String> {
    classify::load_waivers(
        schema::WAIVERS,
        &cx.read(schema::WAIVERS).unwrap_or_default(),
    )
}

mod selftest;
