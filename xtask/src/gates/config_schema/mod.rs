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
//! ## THE BASELINE IS A RELEASED TAG — NOT THE WORKING TREE, AND NOT `HEAD` EITHER
//!
//! That is the one design decision the whole gate rests on, and until the 1.6.0 denominator audit
//! it was only half made. The drift guard compares the committed snapshot against a fresh render,
//! so a config change that forgets to regenerate is caught — but regenerating is a one-line
//! command, and if the additive check also read the working tree then running it would *launder the
//! break*: the snapshot and the render would agree, and the removal would be invisible. Reading the
//! baseline from history is what makes "refresh the snapshot" an honest act rather than a bypass.
//! [`Ctx::git_show`] is the only door to it.
//!
//! **`HEAD` IS THE WORKING TREE WEARING A REF'S CLOTHES.** The default was `"HEAD"`, which the
//! drift row above has *just finished proving* byte-equal to the fresh render — so the additive
//! check compared the tree against itself and the delta was empty by construction, on every run.
//! It was not a weak baseline; it was the absence of one, and the gate had been green on that basis
//! for the whole release. [`DEFAULT_BASELINE_REF`] carries the repair and the reasoning for which
//! ref replaces it; [`SNAPSHOT_HOMES`] carries the one mechanical consequence, which is that a
//! baseline older than the last relocation must be read at the path it used *then*.
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
pub mod declared;
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

/// THE DEFAULT BASELINE: **the freeze point itself**, `v1.5.3`.
///
/// `CONFIG_SCHEMA_BASELINE_REF` overrides it, through [`crate::ctx::Env`] rather than out of the
/// process environment, so a runner can see the gate reading it.
///
/// ## IT WAS `HEAD`, AND `HEAD` IS THE TREE BEING JUDGED
///
/// This constant read `"HEAD"` until the 1.6.0 denominator audit
/// (`docs/design/1.6.0-denominator.md` §8.2) went looking. `HEAD` is not a baseline; it is the
/// commit under test. The additive check then compared the fresh render against the snapshot
/// committed in that same tree — and the drift row above has already proven those two byte-equal,
/// so the delta was **empty by construction, on every run, forever**. The gate reported green
/// because it had measured nothing, and `.github/workflows/ci.yml` said so in its own comment:
/// *"On a push, HEAD is the baseline (no-op delta)."* The PR arm was no better over a long-lived
/// branch: the base branch already contains everything the branch has merged, so **a chain of
/// per-PR additive checks cannot prove the cumulative diff is additive — each step's baseline is
/// the previous step's output.**
///
/// ## WHICH QUESTION THIS GATE ANSWERS, AND THEREFORE WHICH BASELINE IS RIGHT
///
/// The rule is not "has this branch drifted since yesterday." It is the one written on the
/// artefact's own `_meta` line and repeated in [`classify::FROZEN_MSG`]: *"FROZEN at 1.5.3,
/// additive-only **forever**"* — a claim about the **published** grammar, i.e. that **every
/// `config.yaml` an operator has ever shipped still parses**. A question about the published
/// contract can only be answered against the published contract.
///
/// So the baseline is a RELEASED TAG, and specifically the **earliest** one that carries the
/// fingerprint, which is the freeze point the rule names:
///
/// * `v1.5.3` is where the fingerprint was first committed — `v1.5.2` and earlier carry no
///   snapshot at all, so no older baseline exists to have.
/// * It is external and unmodifiable: tagged 2026-08-08, twelve days before `v1.5.5` and well
///   before the 1.6.0 window opened. Nothing in this release can edit it.
/// * **A freeze point is a CONSTANT, not a pointer.** This is the decisive property and the reason
///   it is not "the latest release tag". A baseline that ratchets forward at each release lets this
///   release's removals become the next release's baseline — the same circularity, merely slower.
///   `additive-only forever` is only literally true if the yardstick never moves.
/// * Choosing it costs nothing over `v1.5.5`: the snapshot is **byte-identical at `v1.5.3`,
///   `v1.5.4` and `v1.5.5`** (sha256 `09291129a4ec…`, 75 types / 247 fields at all three), so the
///   freeze demonstrably held across the released line and the two candidates give the same answer.
///   `v1.5.3` is chosen because it is the one the rule names, not because it is stricter.
///
/// **A stale baseline here cannot become a bypass.** The usual objection to a pinned ref is that it
/// rots silently; that failure mode needs the pin to move *forward*. This one only ever gets older
/// relative to the tree, which makes the check strictly stronger over time, never weaker. If the
/// ref does not resolve — a shallow clone with no tags — [`row_baseline`] is RED and never a skip.
pub const DEFAULT_BASELINE_REF: &str = "v1.5.3";

/// EVERY HOME THE COMMITTED FINGERPRINT HAS EVER HAD, newest first.
///
/// A baseline older than the last time the file moved is read with `git show <ref>:<path>`, and at
/// that ref the path is whatever it was THEN. The fingerprint has been relocated twice —
/// `crates/busbar/` → `crates/busbar-core/` → `crates/busbar-kernel/` — so asking `v1.5.3` for
/// today's path gets "no such file", which [`row_baseline`] correctly refuses as a baseline
/// carrying no snapshot. Refusing there would make an honest external baseline *unusable* and push
/// the gate straight back to a ref that happens to share today's layout, i.e. back to `HEAD`.
///
/// **THIS IS AN ENUMERATION, NOT A FALLBACK.** The distinction matters, because a silent fallback
/// to a degenerate baseline is the same defect this constant exists to repair, merely wearing a
/// guard. So: every home is PROBED, the row NAMES the one that answered, zero homes is RED
/// ([`BaselineState::NoSnapshot`]), and **two homes at one ref is also RED**
/// ([`BaselineState::AmbiguousHome`]) rather than "take the first" — picking a winner between two
/// live fingerprints would freeze one home's grammar and quietly un-freeze the other's, which is
/// the same coverage hole [`schema::plane_dir`] already refuses for the plane grammars.
///
/// The first entry IS [`schema::SNAPSHOT`], by construction rather than by copy, so the census can
/// never fall out of step with the path the gate actually renders to.
pub const SNAPSHOT_HOMES: &[&str] = &[
    // today, since the W4 core-absorption folded `busbar-core` into `busbar-kernel`.
    schema::SNAPSHOT,
    // the intermediate home, while the config module lived in `busbar-core`.
    "crates/busbar-core/src/config/config-schema.snapshot.json",
    // the original home and the one the RELEASED TAGS carry: v1.5.3, v1.5.4, v1.5.5.
    "crates/busbar/src/config/config-schema.snapshot.json",
];

/// The regen command, spelled once so every row that suggests it suggests the same thing.
const REGEN: &str = "cargo xtask gate config-schema --write";

/// The FLOOR under the tracked source set. The set is eleven entries today: eight fixed paths, the
/// two plane grammar directories `plane_dir` resolves, and one grammar directory per core-kind
/// crate that [`schema::core_roots`] censuses — so the count RISES as the config layer is carved
/// out of `busbar-core`, and can never fall below what one core crate contributed. A render built
/// from a handful of files is a render that lost most of the
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
        BaselineState::Ok { r, path, types } => Row::pass(
            ROW_BASELINE,
            "the additive-only baseline was read from a RELEASED TAG, not the tree being judged",
            format!(
                "baseline '{r}' carries {path} with {types} type(s). The default is the freeze \
                 point the rule names ({DEFAULT_BASELINE_REF}); it is external to this release and \
                 it does not move, so the delta below is measured against something this work did \
                 not write."
            ),
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
            "the baseline ref resolves but carries NO snapshot at any of its known homes",
            format!(
                "baseline ref '{r}' resolves but carries no config-schema fingerprint at any of \
                 the {} home(s) it has ever had: {}. The additive check is the whole gate, and it \
                 did not run — so nothing was measured. A ref that resolves without the snapshot \
                 is the same free bypass as a ref that does not resolve at all: any commit from \
                 before the snapshot landed grants it (it first appears at {DEFAULT_BASELINE_REF}). \
                 Pointing the gate somewhere else is not a fix. If the file has MOVED AGAIN, add \
                 the new home to SNAPSHOT_HOMES — that census is what lets an older tag be read at \
                 the path it used then. The ONE legitimate case is declared, not inferred: \
                 CONFIG_SCHEMA_BOOTSTRAP=1.",
                SNAPSHOT_HOMES.len(),
                SNAPSHOT_HOMES.join(", ")
            ),
        ),
        BaselineState::AmbiguousHome { r, paths } => Row::fail(
            ROW_BASELINE,
            "the baseline ref carries the fingerprint at MORE THAN ONE home",
            format!(
                "baseline ref '{r}' carries a config-schema fingerprint at {} homes at once: {}. \
                 The gate will not pick a winner. Judging against one of them would freeze that \
                 home's grammar and leave the other's silently un-frozen — a coverage hole that \
                 reads exactly like a clean run, which is the same refusal the plane-grammar \
                 resolver already makes for zero homes and two. Delete the stale copy, or name \
                 which one is the fingerprint.",
                paths.len(),
                paths.join(", ")
            ),
        ),
        BaselineState::Unparseable { r, path, why } => Row::fail(
            ROW_BASELINE,
            "the baseline snapshot is not readable JSON",
            format!("baseline '{r}' carries a {path} that does not parse: {why}"),
        ),
        BaselineState::Empty { r, path, types } => Row::fail(
            ROW_BASELINE,
            "the baseline carries an EMPTY type map — every delta would read as additive",
            format!(
                "baseline '{r}' carries {path} with {types} type(s), under the floor of \
                 {MIN_BASELINE_TYPES}. The classifier reads the baseline's type map, and against an \
                 empty one EVERY type in the fresh render is a `new type/section added` — which is \
                 ADDITIVE, which is GREEN. A truncated or hand-emptied baseline is therefore a \
                 total, silent bypass of the additive rule that looks exactly like a clean run. An \
                 empty baseline is not a baseline."
            ),
        ),
    }
}

enum BaselineState {
    Ok {
        r: String,
        path: String,
        types: usize,
    },
    Bootstrap {
        r: String,
    },
    Unresolvable {
        r: String,
    },
    NoSnapshot {
        r: String,
    },
    AmbiguousHome {
        r: String,
        paths: Vec<String>,
    },
    Unparseable {
        r: String,
        path: String,
        why: String,
    },
    Empty {
        r: String,
        path: String,
        types: usize,
    },
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
        let fresh =
            match declared::read(cx).and_then(|declared| schema::extract_with(&read, &declared)) {
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
                let home = match &state {
                    BaselineState::Ok { path, .. } => path.as_str(),
                    _ => schema::SNAPSHOT,
                };
                let see = see_through(cx, &r, home, &baseline, &fresh, &read);
                let outcome =
                    classify::judge(classify::classify_with(&baseline, &fresh, &see), &waivers);
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
///
/// THE REF IS ASKED FOR EVERY HOME THE FINGERPRINT HAS EVER HAD, and the answer is a census rather
/// than a first-match: see [`SNAPSHOT_HOMES`] for why zero and two are both hard errors and why
/// "take the first" is the defect wearing a guard.
fn read_baseline(cx: &Ctx, r: &str) -> (BaselineState, Option<Value>) {
    if !cx.git_ref_resolves(r) {
        return (BaselineState::Unresolvable { r: r.to_string() }, None);
    }
    let mut found: Vec<(String, String)> = Vec::new();
    for home in SNAPSHOT_HOMES {
        if let Ok(text) = cx.git_show(r, home) {
            found.push(((*home).to_string(), text));
        }
    }
    if found.len() > 1 {
        return (
            BaselineState::AmbiguousHome {
                r: r.to_string(),
                paths: found.into_iter().map(|(p, _)| p).collect(),
            },
            None,
        );
    }
    let Some((path, text)) = found.pop() else {
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
                    path,
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
                path,
                types,
            },
            None,
        );
    }
    (
        BaselineState::Ok {
            r: r.to_string(),
            path,
            types,
        },
        Some(doc),
    )
}

/// WHAT THE CLASSIFIER READS BESIDE THE TWO FINGERPRINTS — see [`classify::SeeThrough`].
///
/// THE REFUSAL HALF READS THE BASELINE REF'S SOURCE, BECAUSE ITS SNAPSHOT CANNOT ANSWER. Every
/// hand-written impl whose fresh `manual-de X` node records `refused` but whose baseline node does
/// not (absent, or rendered before the arm existed — which is every node of `v1.5.3`) is measured
/// from the source the baseline ref carried, by the same rule as the working tree's. The baseline's
/// source is looked for in two places, both read through [`Ctx::git_show`] and so from history,
/// never the working tree:
///
/// * the tracked files as they are named TODAY, at the baseline ref — a file that has not moved is
///   found where it is, and one that has ([`schema::MOVED_SOURCES`]: `SecretRef`'s, now
///   `crates/busbar-contract/src/secret_ref.rs`) under the name it had at the baseline;
/// * every `*.rs` directly inside the directory that held the baseline's own snapshot — the config
///   module the baseline froze, which is where a type that has since MOVED lived then.
///
/// A type whose hand-written impl is found in neither place (or in two) did not exist at the
/// baseline in any form this can measure, and is left to the "new type" verdict it already gets.
fn see_through(
    cx: &Ctx,
    r: &str,
    baseline_home: &str,
    baseline: &Value,
    fresh: &Value,
    read: &[(String, String)],
) -> classify::SeeThrough {
    let mut see = classify::SeeThrough {
        forwards: schema::forwards(read),
        ..Default::default()
    };
    let empty = serde_json::Map::new();
    let bt = baseline
        .get("types")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let ft = fresh
        .get("types")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let need: Vec<&str> = ft
        .iter()
        .filter(|(_, v)| v.get("refused").is_some())
        .filter_map(|(k, _)| k.strip_prefix("manual-de "))
        .filter(|x| {
            bt.get(&format!("manual-de {x}"))
                .and_then(|b| b.get("refused"))
                .is_none()
        })
        .collect();
    if need.is_empty() {
        return see;
    }
    let mut paths: Vec<String> = read
        .iter()
        .filter(|(_, t)| need.iter().any(|x| t.contains(&format!("for {x}"))))
        .map(|(p, _)| p.clone())
        .collect();
    let moved: Vec<String> = schema::MOVED_SOURCES
        .iter()
        .filter(|(now, _)| paths.iter().any(|p| p == now))
        .map(|(_, then)| (*then).to_string())
        .collect();
    paths.extend(moved);
    if let Some((dir, _)) = baseline_home.rsplit_once('/') {
        // `git show <ref>:<dir>` lists a tree: a `tree …` header, a blank line, then one entry per
        // line with a trailing `/` on a subdirectory.
        if let Ok(listing) = cx.git_show(r, dir) {
            for entry in listing.lines().skip_while(|l| !l.is_empty()).skip(1) {
                if entry.ends_with(".rs") && !entry.contains('/') {
                    paths.push(format!("{dir}/{entry}"));
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    let base_src: Vec<(String, String)> = paths
        .into_iter()
        .filter_map(|p| cx.git_show(r, &p).ok().map(|t| (p, t)))
        .collect();
    let base_eff = schema::effective_refusals(&base_src);
    let fresh_eff = schema::effective_refusals(read);
    for x in need {
        if let (Some(Some(b)), Some(Some(f))) = (base_eff.get(x), fresh_eff.get(x)) {
            see.refusals
                .insert(format!("manual-de {x}"), (b.clone(), f.clone()));
        }
    }
    see
}

/// The waiver register as the gate reads it, exposed for the self-test.
pub fn waivers_of(cx: &Ctx) -> Result<BTreeMap<String, String>, String> {
    classify::load_waivers(
        schema::WAIVERS,
        &cx.read(schema::WAIVERS).unwrap_or_default(),
    )
}

mod selftest;
