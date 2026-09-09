//! THE DESIGN BINDINGS GATE'S RED PROOFS.
//!
//! Every case plants into the LEDGER, not into the tree, because the ledger is what this gate
//! judges: a citation is a claim about the tree, and the failure this instrument exists for is a
//! claim that stayed green after the thing it named went away. So a plant is a rewritten
//! `qa/design-bindings.json` in an overlay — one bogus ref, one vanished cell, one cell the golden
//! never recorded, one gate nobody invokes — and the gate must name each by its ref.
//!
//! Two cases plant something else, because two of this gate's refusals are not about a citation:
//! the VACUOUS one (an empty binding table leaves every owed binding unrecorded, which the derived
//! owed set refuses before any citation is read) and REGEN-CLEAN (a ledger with a binding removed
//! is refused, because `--strict` judges the rows in the cache and a stale cache hides a binding
//! added to Appendix B).

use crate::ctx::{Ctx, Overlay};
use crate::gates::design_bindings::json::{self, J};
use crate::gates::design_bindings::{build, DesignBindingsGate, ROW_REGEN};
use crate::gates::{prove_red, prove_rows_green, Case, Expect, Gate, Report};
use crate::jobj;

/// The binding id every fixture that needs a PASSING row beside a failing one reuses. It is a REAL
/// owed id on purpose: a control under an id the gate does not owe would be reconciled away as a
/// stray row and would prove nothing about a binding the ledger actually carries.
const CONTROL: &str = "PB-1";

/// A ledger holding exactly the bindings given, in the shape `build` emits.
fn ledger(bindings: Vec<J>) -> String {
    let doc = jobj! {
        "_comment" => J::Arr(vec![]),
        "counts" => jobj! {},
        "bindings" => J::Arr(bindings),
    };
    build::to_json_text(&doc)
}

fn binding(id: &str, surface: &str, status: &str, checks: Vec<J>) -> J {
    jobj! {
        "id" => json::s(id),
        "surface" => json::s(surface),
        "binding" => json::s("x"),
        "inventory" => json::s("x"),
        "status" => json::s(status),
        "checks" => J::Arr(checks),
    }
}

fn check(kind: &str, r: &str) -> J {
    jobj! {
        "kind" => json::s(kind),
        "ref" => json::s(r),
        "status" => json::s("mapped"),
    }
}

/// One real, unambiguous test fn name out of this tree, so a fixture is proven against the actual
/// crates rather than against a name somebody hoped existed.
fn a_real_test(cx: &Ctx) -> Option<String> {
    let inputs = DesignBindingsGate::inputs(cx).ok()?;
    inputs
        .ctx
        .idx
        .iter()
        .find(|(_, files)| files.len() == 1)
        .map(|(name, _)| name.clone())
}

/// A cell id the golden RECORDED, and one it did not — the second is what makes the
/// "cited but never compared" case non-vacuous.
fn cells(cx: &Ctx) -> Option<(String, String)> {
    let inputs = DesignBindingsGate::inputs(cx).ok()?;
    let recorded = inputs
        .ctx
        .cell_ids
        .iter()
        .find(|id| inputs.ctx.recorded.contains(*id))?
        .clone();
    let skipped = inputs
        .ctx
        .cell_ids
        .iter()
        .find(|id| !inputs.ctx.recorded.contains(*id))?
        .clone();
    Some((recorded, skipped))
}

pub fn run(gate: &dyn Gate, cx: &Ctx) -> Report {
    let mut r = Report::new();
    let owed: Vec<String> = gate.owed();
    let all: Vec<&str> = owed.iter().map(String::as_str).collect();
    if !all.contains(&CONTROL) {
        r.note_infra_failure(format!(
            "`{CONTROL}` is no longer a binding this gate owes, so the case that plants it as a \
             passing control is planting a row the reconciliation drops"
        ));
        return r;
    }

    // The tree as it stands: the committed ledger is what Appendix B derives, and the gate says so.
    let verdict = crate::gates::execute(gate, cx);
    let regen_ok = verdict
        .rows
        .iter()
        .any(|row| row.id == ROW_REGEN && row.status == crate::ledger::Status::Pass);
    r.push(Case {
        name: "REGEN-CLEAN holds on the committed ledger".to_string(),
        covers: vec![ROW_REGEN.to_string()],
        expected: Expect::Green,
        got: if regen_ok {
            Expect::Green
        } else {
            Expect::Red {
                naming: verdict
                    .rows
                    .iter()
                    .filter(|row| row.id == ROW_REGEN)
                    .map(|row| row.detail.clone())
                    .collect(),
            }
        },
    });

    let Some(real_fn) = a_real_test(cx) else {
        r.note_infra_failure(
            "no unambiguous test fn was found in crates/, so every fixture below would be a \
             fixture about nothing",
        );
        return r;
    };
    let Some((recorded, skipped)) = cells(cx) else {
        r.note_infra_failure(
            "the cell corpus yielded no recorded/unrecorded pair, so the oracle cases would pass \
             vacuously",
        );
        return r;
    };

    // (a) one bogus test ref among good ones: exactly that binding is FAIL, the good one PASSes.
    //
    // THE CONTROL IS THE POINT OF THIS CASE, and it is why the case's `covers` is not the whole
    // owed set the way every other case's is. `CONTROL` is planted with refs that RESOLVE, so its
    // row passes — that is the half of the claim which says the gate reds on the bogus ref rather
    // than on any rewritten ledger. `prove_red` requires EVERY covered id to be red, so naming the
    // control among them would fail the case for the gate behaving; the control is proven the
    // other way round, by [`prove_rows_green`] over the same plant, and its RED proof is carried
    // by case (b), which rewrites it away like every other owed binding.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![
            binding(
                CONTROL,
                "good",
                "mapped",
                vec![check("test", &real_fn), check("oracle-cell", &recorded)],
            ),
            binding(
                "PB-2",
                "bogus",
                "mapped",
                vec![check(
                    "test",
                    "this_test_fn_does_not_exist_anywhere_selftest",
                )],
            ),
        ]),
    );
    let bogus_covers: Vec<&str> = all.iter().copied().filter(|id| *id != CONTROL).collect();
    r.push(prove_red(
        cx,
        gate,
        "a test ref naming a fn no file declares",
        &bogus_covers,
        ov.clone(),
        &["this_test_fn_does_not_exist_anywhere_selftest"],
    ));
    r.push(prove_rows_green(
        cx,
        gate,
        "the binding beside it, whose refs all resolve, still passes",
        &[CONTROL],
        ov,
    ));

    // (b) a vanished cell id, and (b2) a cell the golden never recorded. Both are FAIL, and the
    //     second is the one an existence-only check would have called proof.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![
            binding(
                "PB-3",
                "cell",
                "mapped",
                vec![check("oracle-cell", "no.such.family|nope|nope")],
            ),
            binding(
                "PB-4",
                "skipped cell",
                "mapped",
                vec![check("oracle-cell", &skipped)],
            ),
        ]),
    );
    r.push(prove_red(
        cx,
        gate,
        "a vanished oracle cell, and one the pinned golden never recorded",
        &all,
        ov,
        &["no.such.family|nope|nope", "the golden never recorded it"],
    ));

    // (b4) a citation naming a gate the runner does not answer to resolves to a module that is not
    //      there, and that is a FAIL exactly as a vanished script is.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![binding(
            "PB-5",
            "bogus xtask gate",
            "mapped",
            vec![check("lint", "xtask/src/gates/no_such_gate.rs")],
        )]),
    );
    r.push(prove_red(
        cx,
        gate,
        "a citation naming a gate the runner does not answer to",
        &all,
        ov,
        &["xtask/src/gates/no_such_gate.rs"],
    ));

    // (j) A GATE NOBODY RUNS PROVES NOTHING. `qa/segments.toml` is a real file that no workflow
    //     invokes as a script, so citing it as a gate is exactly the shape this refuses.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![binding(
            "PB-6",
            "a data file cited as a gate",
            "mapped",
            vec![check("gate", "qa/segments.toml")],
        )]),
    );
    r.push(prove_red(
        cx,
        gate,
        "a file that exists on disk but that nothing invokes",
        &all,
        ov,
        &["nothing under .github/workflows invokes it"],
    ));

    // (b6) THE FAMILY ARMS, both of them. `oracle-family` is the looser citation — it claims a
    //      whole family of cells rather than one — and it has two ways to settle nothing: a family
    //      the cell table does not carry, and a family whose cells the pinned golden never
    //      recorded. Only the second is interesting, and it is the one an existence-only reading
    //      would have called proof; neither was planted.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![binding(
            "PB-9",
            "a family the cell table does not carry",
            "mapped",
            vec![check("oracle-family", "no-such-family-at-all-selftest")],
        )]),
    );
    r.push(prove_red(
        cx,
        gate,
        "an oracle-family citation naming a family with no cells",
        &all,
        ov,
        &["oracle-family:no-such-family-at-all-selftest"],
    ));

    // (l) A BARE NAME TWO FILES BOTH DECLARE NAMES NO TEST. Delete the one the curation read and
    //     the citation stays green on its namesake, which is the failure this ledger is for.
    if let Some(ambiguous) = DesignBindingsGate::inputs(cx).ok().and_then(|i| {
        i.ctx
            .idx
            .iter()
            .find(|(_, f)| f.len() > 1)
            .map(|(n, _)| n.clone())
    }) {
        let mut ov = Overlay::new();
        ov.set(
            build::OUT_JSON_REL,
            ledger(vec![binding(
                "PB-7",
                "an ambiguous bare test name",
                "mapped",
                vec![check("test", &ambiguous)],
            )]),
        );
        r.push(prove_red(
            cx,
            gate,
            "a bare test name two files both declare",
            &all,
            ov,
            &["cite it as path.rs::name"],
        ));
    } else {
        r.push(Case {
            name: "a bare test name two files both declare".to_string(),
            covers: vec![],
            expected: Expect::Red { naming: vec![] },
            got: Expect::Skipped,
        });
    }

    // (c) AN EMPTY BINDING TABLE IS THE VACUOUS RED, and it is refused by the DERIVED OWED SET
    //     rather than by the zero-rows arm.
    //
    //     The distinction is worth writing down, because the obvious expectation is wrong here.
    //     `Reconcile`'s zero-rows refusal fires only when a gate records NOTHING, and this gate
    //     always records something: REGEN-CLEAN is emitted on every run, including over a ledger
    //     with no bindings in it. So the row set is never empty and that arm is unreachable.
    //
    //     What catches the plant is the stronger property: the owed set comes from the COMMITTED
    //     ledger, so emptying the table in an overlay leaves all 103 bindings owed and none of them
    //     recorded — every one DID NOT RUN, which is not a pass. That is the refusal asserted here,
    //     by the words the reconciliation actually prints.
    let mut ov = Overlay::new();
    ov.set(build::OUT_JSON_REL, ledger(vec![]));
    r.push(prove_red(
        cx,
        gate,
        "an empty binding table leaves every owed binding unrecorded",
        &all,
        ov,
        &["owed but no row was recorded"],
    ));

    // (h) REGEN-CLEAN's other arm: a ledger with one binding removed is REFUSED. Without this,
    //     a binding added to Appendix B and never re-derived is absent from everything the strict
    //     form reads — unmapped, unproven, and green.
    let mut ov = Overlay::new();
    if let Ok(text) = cx.read(build::OUT_JSON_REL) {
        if let Ok(mut doc) = json::parse(&text) {
            if let Some(J::Arr(bs)) = doc.get("bindings").cloned() {
                doc.set("bindings", J::Arr(bs[1..].to_vec()));
                ov.set(build::OUT_JSON_REL, build::to_json_text(&doc));
            }
        }
    }
    r.push(prove_red(
        cx,
        gate,
        "a committed ledger with one binding removed is not what Appendix B derives",
        &[ROW_REGEN],
        ov,
        &["is NOT what Appendix B derives"],
    ));

    r
}
