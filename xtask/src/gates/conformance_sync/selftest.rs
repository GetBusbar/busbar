//! THE GATE'S OWN RED PROOFS — driven through [`Gate::run`], the only handle a selftest gets.
//!
//! The controls come first: the real seeded tree must be GREEN in every row, or every RED below
//! proves only that the gate is broken. Then each row is planted RED in turn. Two cases carry the
//! design's headline claim (§0, task step 5): flip a suite's verdict to fail and the manifest render
//! drops it (manifest-drift), regenerate the manifest without it and the README badge disappears
//! (readme-drift); a not-run suite whose claim someone pastes in by hand is caught (no-orphan-claim);
//! and a pass carried over from an older sha is caught (freshness).

use serde_json::{json, Value};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_rows_green, prove_rows_red, Gate, Report};

use super::render::{
    parse_registry, BADGE_BEGIN, BADGE_END, MANIFEST_PATH, README_PATH, RELEASE_COMMIT_KEY,
    VERDICT_DIR,
};
use super::{
    ROW_COVERAGE, ROW_FRESHNESS, ROW_MANIFEST_DRIFT, ROW_NO_ORPHAN, ROW_README_DRIFT, ROW_REGISTRY,
};

/// The suite whose verdict is mutated to plant the failure cases. It is green in the seed, so a
/// mutation of it is a delta of exactly the size the case describes.
const ANCHOR: &str = "mcp";
/// A not-run suite, for the orphan-claim plant: claiming it is claiming something not proven.
const NOT_RUN_LABEL: &str = "WebSocket";
const NOT_RUN_WORD: &str = "conformant";

/// The floor under this suite's own case count. A suite that runs zero cases reports zero failures,
/// which is the false green the gate exists to be immune to.
const CASE_FLOOR: usize = 18;

/// The release commit the freshness FIXTURE is judged against. Not a real sha on purpose: the
/// fixture says "the checkout under judgement is this commit, and every verdict is about it".
const FIXTURE_RELEASE: &str = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1";
/// A second commit, for the plants that move the release commit or one verdict off the fixture's.
const OTHER_COMMIT: &str = "0000000000000000000000000000000000000000";

/// THE FRESHNESS FIXTURE BASE: every registered suite's verdict rewritten to be about
/// [`FIXTURE_RELEASE`] (the anchor suite's written outright, so the base is armed whatever the tree
/// holds), and the release commit planted as that same sha.
///
/// WHY A FIXTURE AND NOT THE REAL TREE. A red proof needs a row that is green before the plant. The
/// freshness row judges every armed pass against the commit of the checkout under judgement. On any
/// commit but the one the suites ran on, the real tree is RED on that row — that is the rule
/// working (every commit invalidates every conformance pass), and
/// it stays RED on `cargo xtask gate conformance-sync`. Measured from the real tree, every
/// freshness red proof would be PROOF IMPOSSIBLE. Measured from this base, the unplanted row is
/// honestly green (the fixture control proves it) and each plant is the base with exactly one
/// mutation. This fixes the PROOF, not the tree.
fn freshness_base(cx: &Ctx) -> Overlay {
    let mut ov = Overlay::new();
    ov.set_command(RELEASE_COMMIT_KEY, FIXTURE_RELEASE);
    for suite in parse_registry(cx).unwrap_or_default() {
        let path = format!("{VERDICT_DIR}/{}.json", suite.id);
        let Ok(text) = cx.read(&path) else { continue };
        let Ok(mut v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if let Some(obj) = v.as_object_mut() {
            obj.insert("commit".into(), json!(FIXTURE_RELEASE));
        }
        ov.set(path, serde_json::to_string_pretty(&v).unwrap());
    }
    ov.set(
        format!("{VERDICT_DIR}/{ANCHOR}.json"),
        serde_json::to_string_pretty(&anchor_verdict(FIXTURE_RELEASE)).unwrap(),
    );
    ov
}

/// The context whose UNPLANTED state is [`freshness_base`]. [`Ctx::with_overlay`] replaces rather
/// than layers, so every plant proven on it carries the whole base plus its one mutation.
fn on_fresh(cx: &Ctx) -> Ctx {
    cx.with_overlay(freshness_base(cx))
}

/// A registry fixture: one line of `[[suite]]` tables from `(id, tier, extra-omit)` triples. `omit`
/// names a field to leave out, for the missing-field case.
fn registry_of(entries: &[(&str, &str, Option<&str>)]) -> String {
    let mut out = String::from("# selftest fixture registry\n");
    for (id, tier, omit) in entries {
        out.push_str("\n[[suite]]\n");
        let field = |key: &str, val: &str| -> String {
            if *omit == Some(key) {
                String::new()
            } else {
                format!("{key} = \"{val}\"\n")
            }
        };
        out.push_str(&field("id", id));
        out.push_str(&field("standard", "Some Standard"));
        out.push_str(&field("plan", "some plan"));
        out.push_str(&field("label", "Some"));
        out.push_str(&field("tier", tier));
        out.push_str(&field("verdict", "conformance-verdict-some"));
        out.push_str("public = \"true\"\n");
    }
    out
}

fn overlay_registry(text: String) -> Overlay {
    let mut ov = Overlay::new();
    ov.set("conformance/registry.toml", text);
    ov
}

/// A full, armed, passing verdict for the anchor suite, with `commit` overridden — the shape a real
/// verdict has, so a mutation of it is what a real re-run (or a stale carry-over) looks like.
fn anchor_verdict(commit: &str) -> Value {
    json!({
        "schema": "busbar.conformance.verdict/1",
        "suite": ANCHOR,
        "standard": "Model Context Protocol",
        "plan": "official modelcontextprotocol TCK + in-house battery",
        "spec_version": "2025-06-18",
        "status": "pass",
        "armed": true,
        "commit": commit,
        "run_id": "https://github.com/GetBusbar/busbar/actions/runs/0",
        "evidence": "https://github.com/GetBusbar/busbar/actions/runs/0",
        "generated_at": "2026-09-19T14:05:00Z"
    })
}

pub fn run<'a>(gate: &'a dyn Gate, cx: &'a Ctx) -> Report<'a> {
    let mut report = Report::new();

    // ── THE CONTROLS. The seeded tree is green in every row but freshness, whose green depends on
    //    the commit under judgement (see [`freshness_base`]); freshness has its own control on the
    //    fixture it is proven from.
    report.push(prove_rows_green(
        cx,
        gate,
        "control: the seeded tree is green in every commit-independent conformance-sync row",
        &[
            ROW_REGISTRY,
            ROW_MANIFEST_DRIFT,
            ROW_COVERAGE,
            ROW_README_DRIFT,
            ROW_NO_ORPHAN,
        ],
        Overlay::new(),
    ));
    // The plant IS the fixture base: an empty overlay would replace the base, not keep it.
    report.push(prove_rows_green(
        cx,
        gate,
        "control: the freshness fixture (every verdict about the release commit) is green",
        &[ROW_FRESHNESS],
        freshness_base(cx),
    ));
    let fresh = on_fresh(cx);

    // ══ :registry ════════════════════════════════════════════════════════════════════════════════
    report.push(prove_rows_red(
        cx,
        gate,
        "registry: a tier outside the fixed enum is REFUSED",
        &[ROW_REGISTRY],
        overlay_registry(registry_of(&[("mcp", "vendor-blessed", None)])),
        &["unknown tier"],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "registry: a DUPLICATE suite id is REFUSED",
        &[ROW_REGISTRY],
        overlay_registry(registry_of(&[
            ("mcp", "conformant", None),
            ("mcp", "conformant", None),
        ])),
        &["duplicate"],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "registry: a suite missing its standard is REFUSED",
        &[ROW_REGISTRY],
        overlay_registry(registry_of(&[("mcp", "conformant", Some("standard"))])),
        &["missing `standard`"],
    ));

    // ══ :manifest-drift ══════════════════════════════════════════════════════════════════════════
    let mut ov = Overlay::new();
    ov.set(
        MANIFEST_PATH,
        cx.read(MANIFEST_PATH).unwrap_or_default() + "\n",
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "manifest-drift: a committed manifest that is not the fresh render is STALE",
        &[ROW_MANIFEST_DRIFT],
        ov,
        &["is STALE"],
    ));

    let mut ov = Overlay::new();
    ov.remove(MANIFEST_PATH);
    report.push(prove_rows_red(
        cx,
        gate,
        "manifest-drift: a MISSING committed manifest is RED — nothing to compare against",
        &[ROW_MANIFEST_DRIFT],
        ov,
        &["MISSING"],
    ));

    // FLIP A SUITE TO FAIL → the fresh render drops it, so the committed manifest is STALE. The
    // render dropping the green is the fail-closed property (§5.1): a red suite cannot keep its
    // manifest entry.
    let mut ov = Overlay::new();
    ov.set(format!("{VERDICT_DIR}/{ANCHOR}.json"), {
        let mut v = anchor_verdict("dc7bb3233bf9cf73f02b7d0afd59cbce05d022b6");
        v["status"] = json!("fail");
        serde_json::to_string_pretty(&v).unwrap()
    });
    report.push(prove_rows_red(
        cx,
        gate,
        "manifest-drift: flipping a suite's verdict to FAIL drops it from the render (STALE)",
        &[ROW_MANIFEST_DRIFT],
        ov,
        &["is STALE"],
    ));

    // ══ :coverage ════════════════════════════════════════════════════════════════════════════════
    report.push(prove_rows_red(
        cx,
        gate,
        "coverage: a suite that VANISHED from the committed manifest is RED, not un-claimed",
        &[ROW_COVERAGE],
        manifest_without(cx, ANCHOR),
        &["ABSENT"],
    ));

    // ══ :readme-drift ════════════════════════════════════════════════════════════════════════════
    let mut ov = Overlay::new();
    ov.set(
        README_PATH,
        cx.read(README_PATH)
            .unwrap_or_default()
            .replacen("2ea44f", "ff0000", 1),
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "readme-drift: a hand-edit inside the badge markers is STALE",
        &[ROW_README_DRIFT],
        ov,
        &["is STALE"],
    ));

    let mut ov = Overlay::new();
    ov.set(README_PATH, readme_without_markers(cx));
    report.push(prove_rows_red(
        cx,
        gate,
        "readme-drift: a README with no badge markers is RED — the badges are unguarded",
        &[ROW_README_DRIFT],
        ov,
        &["no BEGIN/END"],
    ));

    // REGENERATE THE MANIFEST WITHOUT A SUITE → its badge disappears from a fresh render, so a
    // README still showing it is STALE. This is "the render drops its badge" at the README layer.
    report.push(prove_rows_red(
        cx,
        gate,
        "readme-drift: a suite dropped from the manifest drops its badge (README STALE)",
        &[ROW_README_DRIFT],
        manifest_with_anchor_not_run(cx),
        &["is STALE"],
    ));

    // ══ :freshness ═══════════════════════════════════════════════════════════════════════════════
    // Every case is measured from the fixture base, whose freshness row is green by construction.
    //
    // A pass carried over from an older sha: the anchor's verdict claims green on a commit that is
    // not the release commit, while every other suite's is about it. Staleness fails closed.
    let mut ov = freshness_base(cx);
    ov.set(
        format!("{VERDICT_DIR}/{ANCHOR}.json"),
        serde_json::to_string_pretty(&anchor_verdict(OTHER_COMMIT)).unwrap(),
    );
    report.push(prove_rows_red(
        &fresh,
        gate,
        "freshness: a pass on a commit that is not the release commit is STALE",
        &[ROW_FRESHNESS],
        ov,
        &["STALE", ANCHOR],
    ));

    // ITEM 165: EVERY verdict agrees — on a commit that is not the one under judgement. An anchor
    // elected from the verdicts agrees with them by construction and calls this fresh; the release
    // commit is resolved from outside them, so the whole majority is STALE.
    let mut ov = freshness_base(cx);
    ov.set_command(RELEASE_COMMIT_KEY, OTHER_COMMIT);
    report.push(prove_rows_red(
        &fresh,
        gate,
        "freshness: every verdict agreeing on an OLDER commit is still STALE — the anchor is not \
         elected by the verdicts it judges",
        &[ROW_FRESHNESS],
        ov,
        &["STALE", ANCHOR],
    ));

    // A release commit that cannot be resolved is RED, never a vacuous "nothing is stale".
    let mut ov = freshness_base(cx);
    ov.set_command(RELEASE_COMMIT_KEY, "");
    report.push(prove_rows_red(
        &fresh,
        gate,
        "freshness: an unresolvable release commit is RED, not a pass against nothing",
        &[ROW_FRESHNESS],
        ov,
        &["could not be resolved"],
    ));

    // ══ :no-orphan-claim ═════════════════════════════════════════════════════════════════════════
    // A NOT-RUN suite's claim pasted into the README by hand, outside the markers. It is backed by no
    // green manifest entry, so it is RED — the belt to the render's braces (§5.1).
    let mut ov = Overlay::new();
    ov.set(
        README_PATH,
        format!(
            "{}\n\nWe are {NOT_RUN_LABEL} {NOT_RUN_WORD}!\n",
            cx.read(README_PATH).unwrap_or_default()
        ),
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "no-orphan-claim: a not-run suite's claim pasted outside the markers has no backing entry",
        &[ROW_NO_ORPHAN],
        ov,
        &["no backing manifest entry"],
    ));

    // ITEM 188: a claim for a standard NO registry names. The registered-token scan cannot see it
    // by construction; the claim vocabulary does.
    let mut ov = Overlay::new();
    ov.set(
        README_PATH,
        format!(
            "{}\n\nbusbar is SOC 2 certified.\n",
            cx.read(README_PATH).unwrap_or_default()
        ),
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "no-orphan-claim: a claim for a standard in NO registry is an unbacked claim",
        &[ROW_NO_ORPHAN],
        ov,
        &["SOC 2 certified", "no registered suite backs it"],
    ));

    // …and the vocabulary is WORDS, not substrings: TLS `certificate` prose is not a claim.
    let mut ov = Overlay::new();
    ov.set(
        README_PATH,
        format!(
            "{}\n\nTLS certificates are rotated without a restart.\n",
            cx.read(README_PATH).unwrap_or_default()
        ),
    );
    report.push(prove_rows_green(
        cx,
        gate,
        "no-orphan-claim: `certificate` prose outside the markers is not a claim",
        &[ROW_NO_ORPHAN],
        ov,
    ));

    if report.cases().len() < CASE_FLOOR {
        report.note_infra_failure(format!(
            "the conformance-sync self-test executed only {} case(s), under its floor of \
             {CASE_FLOOR}. Coverage was deleted, or the suite exited early — either way this is NOT \
             a pass.",
            report.cases().len()
        ));
    }

    report
}

/// The committed manifest with one suite's entry removed — the "a suite vanished" plant.
fn manifest_without(cx: &Ctx, id: &str) -> Overlay {
    let mut v: Value =
        serde_json::from_str(&cx.read(MANIFEST_PATH).unwrap_or_default()).unwrap_or(json!({}));
    if let Some(arr) = v.get_mut("suites").and_then(Value::as_array_mut) {
        arr.retain(|s| s.get("suite").and_then(Value::as_str) != Some(id));
    }
    let mut ov = Overlay::new();
    ov.set(MANIFEST_PATH, serde_json::to_string_pretty(&v).unwrap());
    ov
}

/// The committed manifest with the anchor suite forced to not-run (claim null) — as if it had been
/// regenerated after the suite went red. Its badge must then disappear from the README render.
fn manifest_with_anchor_not_run(cx: &Ctx) -> Overlay {
    let mut v: Value =
        serde_json::from_str(&cx.read(MANIFEST_PATH).unwrap_or_default()).unwrap_or(json!({}));
    if let Some(arr) = v.get_mut("suites").and_then(Value::as_array_mut) {
        for s in arr {
            if s.get("suite").and_then(Value::as_str) == Some(ANCHOR) {
                if let Some(obj) = s.as_object_mut() {
                    obj.insert("status".into(), json!("not-run"));
                    obj.insert("claim".into(), Value::Null);
                }
            }
        }
    }
    let mut ov = Overlay::new();
    ov.set(MANIFEST_PATH, serde_json::to_string_pretty(&v).unwrap());
    ov
}

/// The committed README with the whole marked span excised — no markers at all.
fn readme_without_markers(cx: &Ctx) -> String {
    let readme = cx.read(README_PATH).unwrap_or_default();
    match (readme.find(BADGE_BEGIN), readme.find(BADGE_END)) {
        (Some(b), Some(e)) if e >= b => {
            let end = e + BADGE_END.len();
            format!("{}{}", &readme[..b], &readme[end..])
        }
        _ => readme,
    }
}
