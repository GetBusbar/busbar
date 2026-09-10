//! `audit-ledger` — IS THE INSTRUMENT SOUND?
//!
//! This gate and `cargo xtask ledger --check` are ONE computation
//! ([`crate::audit_cmd::check`]) — two implementations of "is this register trustworthy" is exactly
//! how a register comes to read red one way and green the other. What differs is WHICH OF THE SEVEN
//! RULES EACH ONE IS THE JUDGE OF, and the split is not convenience:
//!
//! * **The gate owns the five rules about the REGISTER.** Does it carry every scope the tree
//!   implies; is every entry readable; is every result a result; does every record's hash match the
//!   tree at the commit it claims to have read; does every HIGH/MEDIUM fix carry a confirming round
//!   from somebody other than the fixer. These
//!   are questions about whether the instrument can be believed, and the answer is yes today. They
//!   belong on a gate because a `no` is a regression somebody just introduced.
//!
//! * **`--check` owns the two rules about the AUDIT.** Is coverage complete, and is any scope still
//!   open at HIGH/MEDIUM. Those are RED ON HEAD and red BY DESIGN — 42 scopes are open and the
//!   audit is in flight — so they are the release-time DONE claim
//!   (`scripts/verify-1.6.0-done.sh`), which is where they have always been called from and where a
//!   red means "not finished yet" rather than "somebody broke something".
//!
//! Folding the second pair into `cargo xtask gate --all` would make the umbrella red for a fact
//! nobody is expected to fix this week, and a red that is always red is a red people learn to skip.
//! `--check` still judges all seven, so nothing stopped being enforced — it is enforced at the
//! moment it means something.
//!
//! The selftest plants each violation into a COPY OF THE REAL REGISTER and requires the gate to
//! name it — a synthetic fixture would prove the rules against a register shape the tree does not
//! have.

use crate::audit::{self, Git};
use crate::audit_cmd::{self, CheckFindings};
use crate::ctx::{Ctx, Edit, Overlay};
use crate::gates::{prove_green, prove_rows_green, prove_rows_red, Gate, Report};
use crate::json_lite::{self, Json};
use crate::ledger::{Row, Verdict};

/// The two rules `--check` owns and the gate does not. They are RED ON HEAD by design; see the
/// module note. `--check` prints them, `verify-1.6.0-done.sh` judges them.
pub const ROW_COVERAGE: &str = "audit-ledger:coverage";
pub const ROW_OPEN: &str = "audit-ledger:open-high-medium";

pub const ROW_MISSING: &str = "audit-ledger:missing-scopes";
pub const ROW_READABLE: &str = "audit-ledger:readable";
pub const ROW_INVALID: &str = "audit-ledger:invalid-result";
pub const ROW_STAMPED: &str = "audit-ledger:hash-matches-commit";
/// THE COMMIT A RECORD NAMES IS ONE THIS REPOSITORY STILL CARRIES.
///
/// [`ROW_STAMPED`] proves a record's `tree_hash` is what its commit's tree actually held, and it
/// proves it by asking git to produce that tree today. That proof is only as durable as the commit:
/// one reachable from no branch, no tag and no pin is one `git gc` away from not being producible
/// at all, and every round stamped against it becomes a number nobody can recompute. The register
/// is the tree's audit history, and a history citing commits the repository is free to discard is a
/// history of nothing.
pub const ROW_REACHABLE: &str = "audit-ledger:audited-at-reachable";
pub const ROW_OWED: &str = "audit-ledger:fix-owes-confirmation";

pub struct AuditLedgerGate;

fn row(problems: &[String], id: &str, ok: &str, bad: &str, ok_detail: String) -> Row {
    if problems.is_empty() {
        Row::pass(id, ok, ok_detail)
    } else {
        Row::fail(id, bad, problems.join(" | "))
    }
}

/// The SIX rows the gate owns. The two `--check`-only rules are deliberately absent; see the
/// module note.
pub fn rows_from(f: &CheckFindings) -> Vec<Row> {
    vec![
        row(
            &f.missing,
            ROW_MISSING,
            "the register carries every scope the tree implies",
            "the tree implies scope(s) the register does not carry",
            format!("{} scope(s)", f.scopes),
        ),
        row(
            &f.problems,
            ROW_READABLE,
            "every register entry is readable",
            "a register entry the instrument cannot read",
            format!("{} scope(s)", f.scopes),
        ),
        row(
            &f.invalid,
            ROW_INVALID,
            "every recorded result is one of the four known results",
            "a recorded result is not a result",
            format!("{} scope(s)", f.scopes),
        ),
        row(
            &f.stamped,
            ROW_STAMPED,
            "every record's hash is the tree at the commit it claims to have read",
            "a record's hash is not the tree at the commit it claims to have read",
            format!("{} scope(s)", f.scopes),
        ),
        row(
            &f.unreachable,
            ROW_REACHABLE,
            "every commit a record names is one this repository still carries",
            "a record names a commit reachable from neither HEAD nor an audit pin",
            format!("{} scope(s)", f.scopes),
        ),
        row(
            &f.owed,
            ROW_OWED,
            "every HIGH/MEDIUM finding stamped fixed carries a confirming round",
            "a HIGH/MEDIUM finding is stamped fixed with no confirming round",
            format!("{} scope(s)", f.scopes),
        ),
    ]
}

impl Gate for AuditLedgerGate {
    fn name(&self) -> &'static str {
        "audit-ledger"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_MISSING.to_string(),
            ROW_READABLE.to_string(),
            ROW_INVALID.to_string(),
            ROW_STAMPED.to_string(),
            ROW_REACHABLE.to_string(),
            ROW_OWED.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        // The register may be OVERLAID by a selftest plant, so it is materialised into scratch and
        // read from there rather than from the working tree. Everything else the check reads comes
        // from git, which an overlay cannot fake — and should not: the universe of tracked files is
        // the one input this instrument must not be able to shrink.
        let register = match materialize_register(cx) {
            Ok(p) => p,
            Err(e) => {
                return Verdict::of(
                    self.owed()
                        .iter()
                        .map(|id| {
                            Row::fail(
                                id,
                                "the register could not be read",
                                format!("{e} — a rule that did not run is not a rule that passed"),
                            )
                        })
                        .collect(),
                )
            }
        };
        let git = Git::new(cx.root());
        match audit_cmd::check(&git, &register) {
            Ok(f) => Verdict::of(rows_from(&f)),
            Err(e) => Verdict::of(
                self.owed()
                    .iter()
                    .map(|id| {
                        Row::fail(
                            id,
                            "the register could not be judged",
                            format!("{e} — a rule that did not run is not a rule that passed"),
                        )
                    })
                    .collect(),
            ),
        }
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed register is sound under every rule the gate owns",
            &[
                ROW_MISSING,
                ROW_READABLE,
                ROW_INVALID,
                ROW_STAMPED,
                ROW_OWED,
            ],
        ));

        let doc = match cx
            .read(audit::REGISTER_REL)
            .and_then(|t| json_lite::parse(&t))
        {
            Ok(d) => d,
            Err(e) => {
                report.note_infra_failure(format!("{}: {e}", audit::REGISTER_REL));
                return report;
            }
        };

        type Plant = (&'static str, &'static str, &'static str, fn(&mut Json));
        let plants: Vec<Plant> = vec![
            (
                "the tree implies a scope the register does not carry",
                ROW_MISSING,
                "does not carry",
                |d: &mut Json| drop_scope(d, "xtask/src"),
            ),
            (
                "a result outside the four known results",
                ROW_INVALID,
                "not a result",
                |d: &mut Json| set_first_record(d, "result", Json::Str("passed".to_string())),
            ),
            (
                "a counts entry that is not a count",
                ROW_READABLE,
                "is not a count",
                |d: &mut Json| {
                    let mut c = json_lite::Obj::new();
                    c.insert("HIGH", Json::Int(-1));
                    set_first_record(d, "counts", Json::Object(c));
                },
            ),
            (
                "an unknown severity in counts",
                ROW_READABLE,
                "unknown severity",
                |d: &mut Json| {
                    let mut c = json_lite::Obj::new();
                    c.insert("CRITICAL", Json::Int(1));
                    set_first_record(d, "counts", Json::Object(c));
                },
            ),
            (
                "a top-level record that has drifted from the round it came from",
                ROW_READABLE,
                "must BE the last round",
                |d: &mut Json| set_first(d, "auditor", Json::Str("somebody else".to_string())),
            ),
        ];

        for (label, covers, naming, mutate) in plants {
            let mut planted = doc.clone();
            mutate(&mut planted);
            let mut ov = Overlay::new();
            let text = format!("{}\n", json_lite::dump_python(&planted));
            if let Err(e) = Edit::Replace(text).apply(cx, audit::REGISTER_REL, &mut ov) {
                report.note_infra_failure(format!("{label}: {e}"));
                continue;
            }
            report.push(prove_rows_red(cx, self, label, &[covers], ov, &[naming]));
        }

        // The two remaining rules need a REAL COMMIT to hash against, so they are planted as a
        // recorded round on the first scope, at HEAD, at the register's own shape.
        let Ok(head) = Git::new(cx.root()).head() else {
            report.note_infra_failure(
                "could not read HEAD, so the two rules whose subject is a recorded round are \
                 unproven here rather than passing",
            );
            return report;
        };

        // A HIGH finding stamped fixed, with the fix stamped at the same commit the round read.
        // Nobody has confirmed the fixed tree, and the fixer saying so is not a confirmation.
        let mut planted = doc.clone();
        stamp_first(
            cx,
            &mut planted,
            &head,
            "findings",
            "HIGH",
            "selftest",
            true,
        );
        plant_rows(
            cx,
            self,
            &mut report,
            &planted,
            "a HIGH finding stamped fixed with nobody confirming it",
            ROW_OWED,
            &["no confirming round"],
        );

        // THE SAME HOLE ONE SEVERITY DOWN. A MEDIUM that closes itself closes itself just as
        // completely as a HIGH, and until this the owed rule only ever looked at HIGH.
        let mut planted = doc.clone();
        stamp_first(
            cx,
            &mut planted,
            &head,
            "findings",
            "MEDIUM",
            "selftest",
            true,
        );
        plant_rows(
            cx,
            self,
            &mut report,
            &planted,
            "a MEDIUM finding stamped fixed with nobody confirming it",
            ROW_OWED,
            &["no confirming round"],
        );

        // THE FIXER CONFIRMING HIMSELF UNDER A DIFFERENT SPELLING. `alice` stamps the fix and
        // `Alice ` records the confirming zero round: one reader, two spellings, and before
        // `auditor_identity` the second one counted as somebody else. The contrast case below is
        // byte-identical except for the name, so what it isolates is the identity and nothing else.
        let good = hash_first_at(cx, &doc, &head);
        for (who, label, expect_red) in [
            (
                "Alice ",
                "a HIGH fix confirmed only by the fixer under a different spelling",
                true,
            ),
            (
                "bob",
                "a HIGH fix confirmed by somebody who is genuinely somebody else",
                false,
            ),
        ] {
            let mut planted = doc.clone();
            stamp_first(cx, &mut planted, &head, "findings", "HIGH", "alice", true);
            append_round(&mut planted, 2, "zero", who, &head, good.clone());
            let mut ov = Overlay::new();
            let text = format!("{}\n", json_lite::dump_python(&planted));
            match Edit::Replace(text).apply(cx, audit::REGISTER_REL, &mut ov) {
                Err(e) => report.note_infra_failure(format!("{label}: {e}")),
                Ok(()) if expect_red => report.push(prove_rows_red(
                    cx,
                    self,
                    label,
                    &[ROW_OWED],
                    ov,
                    &["no confirming round"],
                )),
                Ok(()) => report.push(prove_rows_green(cx, self, label, &[ROW_OWED], ov)),
            }
        }

        // A round that NAMES a commit but stores a hash that is not the scope's hash there. That is
        // a round stamped against a tree it did not read, and every later reading of it reads
        // nothing. It is the only rule whose subject is the record rather than the finding.
        let mut planted = doc.clone();
        stamp_first(
            cx,
            &mut planted,
            &head,
            "in_progress",
            "",
            "selftest",
            false,
        );
        set_first_record(&mut planted, "tree_hash", Json::Str("0".repeat(64)));
        plant_rows(
            cx,
            self,
            &mut report,
            &planted,
            "a round stamped against a tree it did not read",
            ROW_STAMPED,
            &["not the tree at the commit"],
        );

        // THE SAME FORGERY INSIDE THE ROUNDS LIST. `clean` is computed from the rounds, so a round
        // nobody re-hashes is a round anybody can append — and until the check walked every round,
        // only the top-level record was ever asked to prove its hash.
        let mut planted = doc.clone();
        stamp_first(cx, &mut planted, &head, "zero", "", "selftest", false);
        append_round(
            &mut planted,
            2,
            "zero",
            "a stranger",
            &head,
            Json::Str("0".repeat(64)),
        );
        plant_rows(
            cx,
            self,
            &mut report,
            &planted,
            "an appended round stamped against a tree it did not read",
            ROW_STAMPED,
            &["not the tree at the commit", "round["],
        );

        // A COMMIT GIT CANNOT PRODUCE IS NOT A COMMIT THAT MATCHED. The rule whose whole purpose is
        // catching a stamp against an unread tree must not go quiet exactly when the named tree is
        // the one that cannot be produced at all.
        let mut planted = doc.clone();
        stamp_first(cx, &mut planted, &head, "zero", "", "selftest", false);
        set_first_record(&mut planted, "audited_at", Json::Str("0".repeat(40)));
        plant_rows(
            cx,
            self,
            &mut report,
            &planted,
            "a record naming a commit this repository cannot resolve",
            ROW_STAMPED,
            &["cannot be resolved"],
        );

        // …AND THE SAME PLANT IS THE REACHABILITY ROW'S RED, because it goes down the same path.
        // The rule asks `merge-base --is-ancestor` FIRST and only then asks whether the commit
        // resolves at all, so a commit git cannot produce and a commit on no branch reach this row
        // through one code path and differ only in the sentence it prints. That is deliberate: a
        // plant that could only exercise the unresolvable arm would leave the arm that actually
        // catches drift — a real commit on no ref — proven by nothing, and the honest way to avoid
        // that is to give both arms the same body rather than to write an object into the
        // developer's repository to plant against.
        plant_rows(
            cx,
            self,
            &mut report,
            &planted,
            "a record naming a commit no branch, tag or audit pin reaches",
            ROW_REACHABLE,
            &[
                "reachable from neither HEAD nor an audit pin",
                "does not resolve in this repository",
            ],
        );

        report
    }
}

/// Overlay a planted register and require THE COVERED ROW to go red naming every string given.
fn plant_rows<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    report: &mut Report<'a>,
    doc: &Json,
    label: &str,
    covers: &str,
    naming: &[&str],
) {
    let mut ov = Overlay::new();
    let text = format!("{}\n", json_lite::dump_python(doc));
    match Edit::Replace(text).apply(cx, audit::REGISTER_REL, &mut ov) {
        Ok(()) => report.push(prove_rows_red(cx, gate, label, &[covers], ov, naming)),
        Err(e) => report.note_infra_failure(format!("{label}: {e}")),
    }
}

/// Write the (possibly overlaid) register into scratch so the check reads the planted bytes.
fn materialize_register(cx: &Ctx) -> Result<std::path::PathBuf, String> {
    let text = cx.read(audit::REGISTER_REL)?;
    let dest = cx.scratch().join(format!(
        "audit-register-{}-{:?}.json",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&dest, text).map_err(|e| format!("{}: {e}", dest.display()))?;
    Ok(dest)
}

fn scopes_mut(doc: &mut Json) -> Option<&mut Vec<Json>> {
    match doc.as_object_mut()?.get_mut("scopes")? {
        Json::Array(a) => Some(a),
        _ => None,
    }
}

fn drop_scope(doc: &mut Json, id: &str) {
    if let Some(scopes) = scopes_mut(doc) {
        scopes.retain(|s| s.get("id").as_str() != Some(id));
    }
}

fn set_first(doc: &mut Json, key: &str, v: Json) {
    if let Some(scopes) = scopes_mut(doc) {
        if let Some(Json::Object(o)) = scopes.first_mut() {
            o.insert(key, v);
        }
    }
}

fn rounds_mut(doc: &mut Json) -> Option<&mut Vec<Json>> {
    match scopes_mut(doc)?
        .first_mut()?
        .as_object_mut()?
        .get_mut("rounds")?
    {
        Json::Array(a) => Some(a),
        _ => None,
    }
}

/// Set a record key on the first scope AND on its last round, keeping the two copies in agreement.
///
/// The register requires the top-level record to BE the last round, so editing only the scope trips
/// THAT rule as well as whichever one the plant is aiming at — and a case that goes red for two
/// reasons proves neither. Only [`audit::RECORD_KEYS`] are mirrored; `fixed_at` is a stamp on the
/// scope, not part of the record, and has no round to agree with.
fn set_first_record(doc: &mut Json, key: &str, v: Json) {
    set_first(doc, key, v.clone());
    if audit::RECORD_KEYS.contains(&key) {
        if let Some(Json::Object(o)) = rounds_mut(doc).and_then(|rs| rs.last_mut()) {
            o.insert(key, v);
        }
    }
}

/// Append a round to the first scope, spelling every record key out. The caller decides whether it
/// agrees with the top-level record — a round that does not is exactly the forgery being planted.
fn append_round(doc: &mut Json, round: i64, result: &str, auditor: &str, at: &str, hash: Json) {
    let mut o = json_lite::Obj::new();
    o.insert("round", Json::Int(round));
    o.insert("result", Json::Str(result.to_string()));
    o.insert("auditor", Json::Str(auditor.to_string()));
    o.insert("audited_at", Json::Str(at.to_string()));
    o.insert("tree_hash", hash);
    o.insert("counts", Json::Object(json_lite::Obj::new()));
    o.insert("report", Json::Str("selftest".to_string()));
    if let Some(rs) = rounds_mut(doc) {
        rs.push(Json::Object(o));
    }
}

/// The first scope's REAL tree hash at `at` — what an honest record there would carry.
fn hash_first_at(cx: &Ctx, doc: &Json, at: &str) -> Json {
    let Some(first) = doc.get("scopes").as_array().and_then(<[Json]>::first) else {
        return Json::Null;
    };
    match Git::new(cx.root()).files_at(at) {
        Ok(all) => audit::tree_hash(first, &all).map_or(Json::Null, Json::Str),
        Err(_) => Json::Null,
    }
}

fn stamp_first(
    cx: &Ctx,
    doc: &mut Json,
    at: &str,
    result: &str,
    severity: &str,
    auditor: &str,
    fixed: bool,
) {
    set_first_record(doc, "result", Json::Str(result.to_string()));
    set_first_record(doc, "audited_at", Json::Str(at.to_string()));
    set_first_record(doc, "round", Json::Int(1));
    set_first_record(doc, "auditor", Json::Str(auditor.to_string()));
    set_first_record(doc, "report", Json::Str("selftest".to_string()));
    let mut c = json_lite::Obj::new();
    if !severity.is_empty() {
        c.insert(severity, Json::Int(1));
    }
    set_first_record(doc, "counts", Json::Object(c));
    set_first(
        doc,
        "fixed_at",
        if fixed {
            Json::Str(at.to_string())
        } else {
            Json::Null
        },
    );
    // The recorded hash must be the scope's REAL hash at `at`, or the hash-vs-commit rule fires
    // instead of the rule this plant is aiming at — and a selftest that goes red for the wrong
    // reason proves the wrong rule. The caller that wants THAT rule overwrites this afterwards.
    let h = hash_first_at(cx, doc, at);
    set_first_record(doc, "tree_hash", h);
    // A scope carrying rounds from BEFORE the plant still carries their old hashes, and the
    // per-round hash rule reads every one of them. They are honest records of older trees, so they
    // are left alone; the cases below are narrowed to the row each one is about.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::{execute, verify_report};

    /// THE FIVE ROWS THE GATE OWNS ARE GREEN ON THE TREE IT SHIPS WITH. Every RED case below only
    /// proves the gate can fail; without this one, a gate that is simply broken would look proven.
    #[test]
    fn the_gate_is_green_on_the_committed_register() {
        let cx = Ctx::workspace().expect("workspace context");
        let verdict = execute(&AuditLedgerGate, &cx);
        assert!(
            !verdict.red,
            "audit-ledger is red on the register it ships with: {:?}",
            verdict.problems
        );
    }

    /// EVERY OWED ROW IS PROVEN RED-ABLE, and every planted case named the offender it planted. This
    /// is what stops a rule from being deleted with the selftest still green.
    #[test]
    fn the_selftest_proves_every_owed_row() {
        let cx = Ctx::workspace().expect("workspace context");
        let report = AuditLedgerGate.selftest(&cx);
        if let Err(failures) = verify_report(&AuditLedgerGate, &report) {
            panic!("audit-ledger selftest did not prove itself: {failures:#?}");
        }
    }

    /// `record --report` REFUSES THE CLASS OF LEAK THIS BRANCH JUST CLEANED OUT OF THE REGISTER.
    /// A RED case for [`crate::audit_cmd::hygiene_refusal`], run through the real CLI entry point
    /// against a SCRATCH COPY of the register (never the working tree — this gate never writes to
    /// it) so the proof is that `ledger record` itself refuses, not just the helper function.
    #[test]
    fn record_refuses_a_public_hygiene_violation() {
        let cx = Ctx::workspace().expect("workspace context");
        let src = cx.root().join(audit::REGISTER_REL);
        let scratch = cx.scratch().join("hygiene-refusal-selftest.json");
        std::fs::copy(&src, &scratch).expect("copy the register into scratch");
        let before = std::fs::read_to_string(&scratch).expect("read the scratch copy");

        let args: Vec<String> = [
            "record",
            "--ledger",
            scratch.to_str().expect("scratch path is UTF-8"),
            "--scope",
            "xtask/src",
            "--round",
            "1",
            "--result",
            "zero",
            "--report",
            // public-hygiene-lint: allow — RED fixture quoting the exact class `record` refuses
            "gate/audits/codeaudit-fake-r9.md",
            "--auditor",
            "selftest",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let code = crate::audit_cmd::main(cx.root(), &args);
        assert_eq!(
            code, 2,
            "`ledger record` must refuse a --report citing an audit-round artifact"
        );

        let after = std::fs::read_to_string(&scratch).expect("read the scratch copy after refusal");
        assert_eq!(
            before, after,
            "a refused record must not write the register — the scratch copy changed"
        );
    }
}
