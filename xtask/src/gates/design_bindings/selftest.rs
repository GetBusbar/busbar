//! THE DESIGN BINDINGS GATE'S RED PROOFS.
//!
//! Every case plants into the LEDGER, not into the tree, because the ledger is what this gate
//! judges: a citation is a claim about the tree, and the failure this instrument exists for is a
//! claim that stayed green after the thing it named went away. So a plant is a rewritten
//! `qa/design-bindings.json` in an overlay — one bogus ref, one vanished cell, one cell the golden
//! never recorded, one gate nobody invokes — and the gate must name each by its ref.
//!
//! Some cases plant something else, because not every refusal here is about a citation: the VACUOUS
//! one (an empty binding table leaves every owed binding unrecorded, which the derived owed set
//! refuses before any citation is read), REGEN-CLEAN both ways (a ledger with a binding removed is
//! refused, because `--strict` judges the rows in the cache and a stale cache hides a binding added
//! to Appendix B; and a derivation that could not be MADE is not a clean regen), and the ledger
//! itself being unreadable.
//!
//! TWO PLANTS ARE NOT LEDGER REWRITES AND SAY SO AT THE CALL SITE. [`super::NOTE_TABLE_KEY`] stands
//! in for the shipped note table, which is empty on HEAD and therefore unreachable by any ledger a
//! case could write; and `a_real_test_in_the_wrong_file` builds its ref out of two entries of the
//! real test index, so the fixture is a citation that is wrong in exactly one way rather than a
//! name nothing anywhere declares.

use crate::ctx::{Ctx, Overlay};
use crate::gates::design_bindings::json::{self, J};
use crate::gates::design_bindings::{build, DesignBindingsGate, NOTE_TABLE_KEY, ROW_REGEN};
use crate::gates::{prove_red, prove_rows_green, prove_rows_red, Case, Expect, Gate, Report};
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
    check_with_status(kind, r, "mapped")
}

/// The same, under a status of the caller's choosing. A check that is not `mapped` is not a
/// citation this gate reads, which is what makes a binding carrying only those a NAMED GAP.
fn check_with_status(kind: &str, r: &str, status: &str) -> J {
    jobj! {
        "kind" => json::s(kind),
        "ref" => json::s(r),
        "status" => json::s(status),
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

/// A REAL, UNAMBIGUOUS TEST FN NAME PAIRED WITH A FILE THAT DOES NOT DECLARE IT.
///
/// Both halves are read out of the index, so the fixture is a `path.rs::name` ref whose name really
/// is a test somewhere and whose file really is a file full of tests -- just not that one. A ref
/// naming a fn that exists nowhere would be caught by the bare-name arm as well, and would prove
/// nothing about the arm that resolves the PATH.
fn a_real_test_in_the_wrong_file(cx: &Ctx) -> Option<String> {
    let inputs = DesignBindingsGate::inputs(cx).ok()?;
    let singles: Vec<(&String, &String)> = inputs
        .ctx
        .idx
        .iter()
        .filter(|(_, f)| f.len() == 1)
        .filter_map(|(n, f)| f.iter().next().map(|file| (n, file)))
        .collect();
    let (name, home) = singles.first()?;
    let elsewhere = singles.iter().find(|(_, f)| f != home)?.1;
    Some(format!("{elsewhere}::{name}"))
}

/// AN ORACLE FAMILY THE CELL TABLE CARRIES AND THE PINNED GOLDEN NEVER RECORDED A CELL OF.
///
/// This is the family-level twin of the "in cells.json, but the golden never recorded it" cell, and
/// it is the arm an existence-only reading of a citation would have called proof: the family is
/// right there in the corpus, and not one of its cells was ever compared.
fn a_family_the_golden_never_recorded(cx: &Ctx) -> Option<String> {
    let inputs = DesignBindingsGate::inputs(cx).ok()?;
    inputs
        .ctx
        .fam_cells
        .iter()
        .find(|(_, ids)| !ids.is_empty() && !ids.iter().any(|i| inputs.ctx.recorded.contains(i)))
        .map(|(fam, _)| fam.clone())
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

pub fn run<'a>(gate: &'a dyn Gate, cx: &'a Ctx) -> Report<'a> {
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

    r.append(broken_citation_cases(gate, cx, &all, &real_fn));
    r.append(binding_verdict_cases(gate, cx, &all, &real_fn));
    r.append(instrument_cases(gate, cx));
    r
}

/// THE WAYS ONE CITATION SETTLES NOTHING that had no plant. Each is a single check on a single
/// binding, so the row that reds is the row the case is about and the reason it prints is the arm
/// under test.
fn broken_citation_cases<'a>(
    gate: &'a dyn Gate,
    cx: &'a Ctx,
    all: &[&str],
    real_fn: &str,
) -> Report<'a> {
    let mut r = Report::new();

    // A CITATION THAT CLAIMS `mapped` AND NAMES NOTHING. Until this case the empty ref was dropped
    // before it was judged, which read the blank as an absent citation -- a named gap, SKIP,
    // allowed -- rather than as the broken one it is.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![binding(
            "PB-2",
            "a citation with no ref",
            "mapped",
            vec![check("test", "")],
        )]),
    );
    r.push(prove_red(
        cx,
        gate,
        "a check that claims to be mapped and names nothing settles nothing",
        all,
        ov,
        &["no ref -- a check with nothing to compare against"],
    ));

    // A `path.rs::name` REF WHOSE FILE DOES NOT DECLARE THAT FN. The qualified form exists because
    // a bare name is ambiguous; if the path half were unjudged, qualifying a ref would WEAKEN it.
    match a_real_test_in_the_wrong_file(cx) {
        Some(wrong) => {
            let mut ov = Overlay::new();
            ov.set(
                build::OUT_JSON_REL,
                ledger(vec![binding(
                    "PB-3",
                    "a qualified ref pointing at the wrong file",
                    "mapped",
                    vec![check("test", &wrong)],
                )]),
            );
            r.push(prove_red(
                cx,
                gate,
                "a path.rs::name ref whose file declares no test fn by that name",
                all,
                ov,
                &["no test fn by that name is declared in that file"],
            ));
        }
        None => r.note_infra_failure(
            "no two files each declaring one unambiguous test fn were found, so the arm that \
             resolves the PATH half of a `path.rs::name` ref is unproven",
        ),
    }

    // A CHECK OF A KIND THIS GATE DOES NOT KNOW. The kinds are a closed set and the fall-through is
    // the only thing standing between "we cite a `vibes` check" and a green row.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![binding(
            "PB-4",
            "a check of a kind nothing knows how to read",
            "mapped",
            vec![check("vibes", "the general feeling in the room")],
        )]),
    );
    r.push(prove_red(
        cx,
        gate,
        "a check of an unknown kind settles nothing, whatever it names",
        all,
        ov,
        &["unknown check kind"],
    ));

    // AN ORACLE FAMILY WHOSE CELLS EXIST AND WHOSE GOLDEN RECORDED NONE OF THEM. The absent-family
    // arm beside it was already planted; this one -- the one an existence check calls proof -- was
    // not, and it is the looser citation's version of the failure the whole file exists for.
    match a_family_the_golden_never_recorded(cx) {
        Some(fam) => {
            let mut ov = Overlay::new();
            ov.set(
                build::OUT_JSON_REL,
                ledger(vec![binding(
                    "PB-5",
                    "a family the golden never recorded",
                    "mapped",
                    vec![check("oracle-family", &fam)],
                )]),
            );
            r.push(prove_red(
                cx,
                gate,
                "an oracle-family whose cells exist but whose golden recorded none of them",
                all,
                ov,
                &["cells exist, but the golden recorded none of them"],
            ));
        }
        None => r.note_infra_failure(
            "every family in the cell corpus has at least one recorded cell, so the arm that \
             refuses a family the golden never compared is unproven here",
        ),
    }

    let _ = real_fn;
    r
}

/// THE THREE VERDICTS A BINDING CAN EARN that no plant reached: every citation broken, the ledger's
/// own note, and the named gap.
fn binding_verdict_cases<'a>(
    gate: &'a dyn Gate,
    cx: &'a Ctx,
    all: &[&str],
    real_fn: &str,
) -> Report<'a> {
    let mut r = Report::new();

    // EVERY CITATION BROKEN IS `unproven`, NOT `partly proven`. The two arms print different words
    // and only the partly-proven one was planted; with this arm switched off a binding all of whose
    // citations had rotted fell through to the partly-proven arm with an EMPTY broken list -- which
    // is to say, to a row that says a referenced check settles nothing and names none.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![binding(
            "PB-6",
            "two citations, both rotted",
            "mapped",
            vec![
                check("test", "no_such_test_fn_a_selftest"),
                check("test", "no_such_test_fn_b_selftest"),
            ],
        )]),
    );
    r.push(prove_red(
        cx,
        gate,
        "a binding whose every cited check settles nothing is UNPROVEN, not partly proven",
        all,
        ov,
        &["nothing this binding cites compares anything today"],
    ));

    // THE LEDGER'S OWN NOTE. The shipped table is empty, so the table is planted rather than the
    // ledger: the binding's citation RESOLVES and its row would otherwise be a PASS, which is the
    // whole point -- the note is what refuses it.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![binding(
            "PB-7",
            "a binding the note calls unproven",
            "mapped",
            vec![check("test", real_fn)],
        )]),
    );
    ov.set_command(
        NOTE_TABLE_KEY,
        "PB-7\tthe surface this binding names does not exist in crates/ yet; the test fn the ref \
         resolves to belongs to another subsystem and happens to match by name",
    );
    r.push(prove_red(
        cx,
        gate,
        "a binding the ledger's own note calls UNPROVEN is refused, resolving citation and all",
        all,
        ov,
        &["UNPROVEN, by the ledger's own note"],
    ));

    // A NAMED GAP IS A NAMED GAP, and it is `unmapped` -- SKIP, with the suggested check in the
    // detail column -- rather than one more `unproven`. `CONTROL` is a binding the committed ledger
    // records as MAPPED, so it is not in this gate's skip allowlist and its SKIP is refused: the
    // case reads that refusal, which carries the row's own `unmapped:` detail.
    let mut ov = Overlay::new();
    ov.set(
        build::OUT_JSON_REL,
        ledger(vec![binding(
            CONTROL,
            "a gap nobody has closed",
            "unmapped",
            vec![check_with_status("test", real_fn, "suggested")],
        )]),
    );
    r.push(prove_rows_red(
        cx,
        gate,
        "a binding with no mapped check is a NAMED gap, and a gap the ledger does not record is \
         refused",
        &[CONTROL],
        ov,
        &["unmapped: "],
    ));

    r
}

/// THE TWO REFUSALS THAT ARE NOT ABOUT A CITATION: the instrument could not read its ledger, and
/// the derivation it compares that ledger against could not be made.
fn instrument_cases<'a>(gate: &'a dyn Gate, cx: &'a Ctx) -> Report<'a> {
    let mut r = Report::new();

    // A LEDGER THAT CANNOT BE READ IS NOT A LEDGER WITH NO BINDINGS IN IT. Every owed row goes
    // unrecorded, and the one row the gate does emit says why.
    let mut ov = Overlay::new();
    ov.remove(build::OUT_JSON_REL);
    r.push(prove_rows_red(
        cx,
        gate,
        "the bindings ledger being unreadable is refused, not read as no bindings",
        &["design-bindings:ledger-unreadable"],
        ov,
        &["the design bindings ledger could not be read"],
    ));

    // AND THE DERIVATION ITSELF FAILING IS NOT A CLEAN REGEN. Appendix B is the source the committed
    // ledger is compared against; with it unreadable there is no comparison to pass, and the arm
    // that says so was the one arm of REGEN-CLEAN with no plant.
    let mut ov = Overlay::new();
    ov.remove(build::ARCH_REL);
    r.push(prove_rows_red(
        cx,
        gate,
        "the derivation from Appendix B failing is refused, never read as a clean regen",
        &[ROW_REGEN],
        ov,
        &["the derivation from Appendix B FAILED"],
    ));

    r
}
