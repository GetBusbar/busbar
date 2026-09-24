//! `cargo xtask gate ship-ready` — THE SHIP CRITERION, AS A ROW THAT CAN GO RED.
//!
//! The ship criterion used to be a checklist that nothing enforced: the ship twin is zero
//! everywhere, no ceiling carries slack, no ceiling rose, the standing-red list is empty. A
//! checklist is a promise that someone will read it. Nothing in the tree could tell whether any
//! line of it was true, and nothing went red when a line stopped being true — which is the same as
//! not having the criterion at all.
//!
//! So it is a gate. Four rows, each of which is one line of the old checklist, each of which can be
//! red on its own:
//!
//! | row | the claim |
//! | --- | --- |
//! | [`ROW_SHIP_TWIN`] | `kind-isolation-ship` is green: every kind's ship twin measures zero |
//! | [`ROW_SLACK`] | `ceiling-slack` is green: every ceiling equals the thing it measures |
//! | [`ROW_ROSE`] | `ceiling-rose` is green: no number in a qa ceilings file went up on this branch |
//! | [`ROW_STANDING`] | the standing-red list is EMPTY, for a `qa`/`main` posture |
//!
//! The `gate-mutants` job used to be a fifth row here, read from the GitHub
//! checks API. Per owner ruling it is now MANUAL-ONLY and entirely OPTIONAL — it tests the tests,
//! it does not gate a release — so ship-ready no longer owes or reads a mutation verdict, and
//! branch protection no longer requires the `gate-mutants` check.
//!
//! ## THE POSTURE
//!
//! Three of the four rows are claims about the tree and hold everywhere. [`ROW_STANDING`] is not:
//! the standing-red list is a DEV-LINE CONVENIENCE, a set of construction rows that are known-red,
//! written down, and deliberately not blocking the integration line while they are drained. That is
//! a reasonable thing to have on a working branch and an unreasonable thing to promote. So this row
//! reads a posture — `XTASK_SHIP_TARGET`, else the branch name — and is red for a `qa` or `main`
//! target while the list is non-empty, and green-with-the-list-printed otherwise. The row is never
//! silent about what is on the list, because a convenience nobody re-reads is how a temporary
//! exemption becomes the architecture.

use crate::ctx::Ctx;
use crate::gates::construction::ceilings;
use crate::gates::{Case, Expect, Gate, Report, CONSTRUCTION_STANDING_REDS};
use crate::ledger::{Row, Status, Verdict};

pub const ROW_SHIP_TWIN: &str = "ship-ready:ship-twin";
pub const ROW_SLACK: &str = "ship-ready:ceiling-slack";
pub const ROW_ROSE: &str = "ship-ready:ceiling-rose";
pub const ROW_STANDING: &str = "ship-ready:standing-reds";

const OWED: &[&str] = &[ROW_SHIP_TWIN, ROW_SLACK, ROW_ROSE, ROW_STANDING];

/// The postures under which the standing-red list is refused. A promotion carries none of the
/// dev line's written-down conveniences.
const SHIPPING_TARGETS: &[&str] = &["qa", "main"];

pub struct ShipReadyGate;

/// WHAT THE POSTURE IS FOR THIS RUN, AND WHETHER IT IS KNOWN AT ALL.
///
/// THIS USED TO BE A `String` ENDING IN `unwrap_or_default()`, WHICH IS A FAIL-OPEN. A git failure
/// — no repository, a broken index, `git` not on PATH, a checkout with no branch — produced `""`;
/// `is_shipping("")` is false; and the false arm of [`standing_row`] is the PASS arm. So the one
/// row in this gate whose entire job is to REFUSE a promotion answered "this is the dev line, carry
/// on" to a question it had not been able to ask. A release gate that passes because git errored is
/// pointed the wrong way.
///
/// `HEAD` and the empty string are folded in here for the same reason: `git rev-parse --abbrev-ref
/// HEAD` answers `HEAD` on a detached checkout, which is git saying it cannot name a branch, not
/// git naming a branch called HEAD. Reading it as a dev-line name is the same fail-open one step
/// removed. CI sets `XTASK_SHIP_TARGET` explicitly (`ci.yml`, `${{ github.ref_name }}`), which is
/// the supported way to say what a detached checkout is a checkout OF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Posture {
    /// The target, named: `XTASK_SHIP_TARGET` when set and non-empty, else the branch git reports.
    Named(String),
    /// Nothing named the target and git could not either. **This is not a dev line** — it is the
    /// absence of an answer, and it is treated as such. Carries the sentence that explains it.
    Unknown(String),
}

impl Posture {
    /// How the posture reads in a row's detail.
    fn label(&self) -> String {
        match self {
            Posture::Named(t) => format!("`{t}`"),
            Posture::Unknown(_) => "UNKNOWN".to_string(),
        }
    }
}

/// The posture for this run. Named separately so the self-test can drive every arm of it without a
/// checkout.
pub fn posture(cx: &Ctx) -> Posture {
    if let Ok(t) = std::env::var("XTASK_SHIP_TARGET") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Posture::Named(t);
        }
    }
    posture_of_branch_output(cx.git(&["rev-parse", "--abbrev-ref", "HEAD"]))
}

/// The branch half of [`posture`], separated from the command that produces it so every arm — a
/// failure, silence, a detached HEAD, a real branch — is drivable in the self-test without a
/// throwaway checkout. An arm nothing can reach is an arm nothing proves.
fn posture_of_branch_output(out: Result<String, String>) -> Posture {
    match out {
        Err(e) => Posture::Unknown(format!(
            "git could not say what this checkout is on ({e}) and XTASK_SHIP_TARGET is not set"
        )),
        Ok(s) => match s.trim() {
            "" => Posture::Unknown(
                "git named no branch (empty output) and XTASK_SHIP_TARGET is not set".to_string(),
            ),
            "HEAD" => Posture::Unknown(
                "this checkout is DETACHED, so `git rev-parse --abbrev-ref HEAD` answers `HEAD` \
                 rather than a branch, and XTASK_SHIP_TARGET is not set"
                    .to_string(),
            ),
            t => Posture::Named(t.to_string()),
        },
    }
}

fn is_shipping(target: &str) -> bool {
    SHIPPING_TARGETS.contains(&target)
}

/// THE STANDING-RED ROW. Red for a shipping posture while anything is standing red, and it prints
/// what is standing red either way: the whole hazard of a written-down exemption is that it stops
/// being read.
///
/// WHAT IS STANDING RED IS READ OFF THE CONSTRUCTION GATE'S VERDICT, NOT OFF THE LIST (item 221).
/// This row used to decide "nothing is standing red" from whether `CONSTRUCTION_STANDING_REDS` was
/// an empty slice, while `run()` held the construction gate's actual verdict five lines later. So
/// striking the names from the list without draining one row made the list empty, and the row
/// certified a shipping line whose tree broke every one of those rules — retiring the record was
/// the very thing it read. The list now only ANNOTATES: a red construction row is standing red
/// whether or not anybody wrote its name down, and a row the construction gate could not run (a
/// reconciliation problem) is standing red too, because a rule that did not run is not a rule
/// that holds.
fn standing_row(target: &Posture, listed: &[&str], construction: &Verdict) -> Row {
    let mut standing: Vec<String> = construction
        .rows
        .iter()
        .filter(|r| r.status != Status::Pass)
        .map(|r| r.id.clone())
        .collect();
    standing.extend(
        construction
            .problems
            .iter()
            .map(|p| format!("(did not run) {p}")),
    );
    standing.sort();
    standing.dedup();
    let unlisted: Vec<&str> = standing
        .iter()
        .map(String::as_str)
        .filter(|id| !listed.contains(id))
        .collect();
    let listed_txt = if listed.is_empty() {
        "(empty)".to_string()
    } else {
        listed.join(", ")
    };
    let red_txt = if unlisted.is_empty() {
        standing.join(", ")
    } else {
        format!(
            "{} — of which {} NOT on the written-down list: {}",
            standing.join(", "),
            unlisted.len(),
            unlisted.join(", ")
        )
    };
    // THE VERDICT FIRST, THE POSTURE SECOND. The claim this row makes is about what the
    // construction gate reports red; the posture only decides whether standing reds are excused.
    // A tree with none satisfies the criterion under every posture, including one nobody could
    // read, so it is green there and says which.
    if standing.is_empty() {
        return Row::pass(
            ROW_STANDING,
            "nothing is standing red",
            format!(
                "target {}: the construction gate reports no red row ({} row(s) read); the \
                 written-down standing-red list is {listed_txt}.",
                target.label(),
                construction.rows.len()
            ),
        );
    }
    match target {
        // FAIL CLOSED. Not knowing whether this is a shipping line is not the same as knowing it
        // is not one, and only one of those two may excuse a written-down breakage.
        Posture::Unknown(why) => Row::fail(
            ROW_STANDING,
            "the posture could not be read, so nothing may be excused against it",
            format!(
                "{why}. {} construction row(s) are standing red — {red_txt} — and the exemption \
                 that covers them is a DEV-LINE one. A run that cannot tell whether it is on the \
                 dev line must not help itself to the dev line's conveniences: that is how a \
                 release gate comes to pass because git errored. Set XTASK_SHIP_TARGET to the line \
                 this checkout is for.",
                standing.len()
            ),
        ),
        Posture::Named(t) if !is_shipping(t) => Row::pass(
            ROW_STANDING,
            "the standing-red list is a dev-line convenience, and this is the dev line",
            format!(
                "target `{t}` is not a shipping line, so the {} standing red(s) still stand: \
                 {red_txt}. Written-down list: {listed_txt}. None of them survives a promotion — \
                 run this gate with XTASK_SHIP_TARGET=qa to see what a promotion would refuse.",
                standing.len()
            ),
        ),
        Posture::Named(t) => Row::fail(
            ROW_STANDING,
            "a shipping line inherits no standing reds",
            format!(
                "target `{t}` is a shipping line and {} construction row(s) are still standing \
                 red: {red_txt}. A standing red is a rule this tree BREAKS, written down so the \
                 dev line can keep moving while it is drained. Promoting it does not drain it — it \
                 promotes the breakage and retires the record of it. Drain each row, or do not ship.",
                standing.len()
            ),
        ),
    }
}

/// A construction verdict whose red rows are exactly `ids` — the self-test's and the unit tests'
/// stand-in for running the construction gate.
fn red_verdict(ids: &[&str]) -> Verdict {
    Verdict::of(
        ids.iter()
            .map(|id| Row::fail(*id, "standing red", "planted"))
            .chain(std::iter::once(Row::pass("some-green-row", "t", "d")))
            .collect(),
    )
}

/// THE CEILING ROWS. Both are construction-gate rows; this gate does not re-implement either
/// rule, it runs the gate that owns them and reads the two verdicts it is about. Re-implementing a
/// rule in a second place is how two gates come to disagree and both stay green.
fn ceiling_rows(construction: &Verdict) -> Vec<Row> {
    [
        (ROW_SLACK, ceilings::ROW_SLACK),
        (ROW_ROSE, ceilings::ROW_ROSE),
    ]
    .iter()
    .map(
        |(mine, theirs)| match construction.rows.iter().find(|r| r.id == *theirs) {
            None => Row::fail(
                *mine,
                "the construction gate emitted no such row",
                format!(
                    "`{theirs}` is not in the construction gate's verdict. A ship criterion whose \
                     evidence row has been renamed or deleted is a criterion nothing measures, and \
                     it must be red rather than absent."
                ),
            ),
            Some(r) if r.status == Status::Pass => {
                Row::pass(*mine, format!("`{theirs}` is green"), r.detail.clone())
            }
            Some(r) => Row::fail(
                *mine,
                format!("`{theirs}` is not green"),
                format!("{}: {}", r.title, r.detail),
            ),
        },
    )
    .collect()
}

/// THE SHIP-TWIN ROW. `kind-isolation-ship` is the twin that measures the ship criterion for every
/// plugin kind; ship-ready is green on it only when the twin has no failing row at all.
fn ship_twin_row(ship: &Verdict) -> Row {
    let bad: Vec<String> = ship
        .rows
        .iter()
        .filter(|r| r.status != Status::Pass)
        .map(|r| format!("{} ({})", r.id, r.title))
        .collect();
    if ship.rows.is_empty() {
        return Row::fail(
            ROW_SHIP_TWIN,
            "the ship twin produced no rows",
            "`kind-isolation-ship` returned an empty verdict. A twin that measured nothing is not \
             a twin that measured zero."
                .to_string(),
        );
    }
    if bad.is_empty() {
        return Row::pass(
            ROW_SHIP_TWIN,
            "the ship twin is zero everywhere",
            format!(
                "`kind-isolation-ship`: {} row(s), all green.",
                ship.rows.len()
            ),
        );
    }
    Row::fail(
        ROW_SHIP_TWIN,
        "the ship twin is not zero",
        format!(
            "`kind-isolation-ship` is not green: {}. Each of these is a kind whose ship criterion \
             this tree does not meet yet.",
            bad.join("; ")
        ),
    )
}

impl Gate for ShipReadyGate {
    fn name(&self) -> &'static str {
        "ship-ready"
    }

    fn owed(&self) -> Vec<String> {
        OWED.iter().map(|s| (*s).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let target = posture(cx);

        // The two gates that OWN the evidence, run once each. Their `--selftest` is the expensive
        // half; a single `run()` over the tree is not, which is what makes reading them here
        // affordable rather than a second implementation of the same rules.
        let construction = crate::gates::execute(
            &crate::gates::construction::ConstructionGate as &dyn Gate,
            cx,
        );
        let mut rows = vec![standing_row(
            &target,
            CONSTRUCTION_STANDING_REDS,
            &construction,
        )];
        rows.extend(ceiling_rows(&construction));

        let ship_gate = crate::gates::kind_isolation::KindIsolationGate::ship();
        let ship = crate::gates::execute(&ship_gate as &dyn Gate, cx);
        rows.push(ship_twin_row(&ship));

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::default();

        // -- THE STANDING-RED ROW, both directions, on the real list and on planted ones. The
        //    posture is the whole subject of this row, so each posture gets its own case: proving
        //    "some posture refuses the list" would pass with `main` unhandled.
        for target in ["qa", "main"] {
            report.push(unit_case(
                format!("a `{target}` target refuses a non-empty standing-red list"),
                &[ROW_STANDING],
                Expect::Red {
                    naming: vec!["standing red".to_string(), "plane-no-money".to_string()],
                },
                standing_row(
                    &Posture::Named(target.to_string()),
                    &["plane-no-money", "one-pick-site"],
                    &red_verdict(&["plane-no-money", "one-pick-site"]),
                ),
            ));
            report.push(unit_case(
                format!("a `{target}` target with an EMPTY list is green"),
                &[ROW_STANDING],
                Expect::Green,
                standing_row(&Posture::Named(target.to_string()), &[], &red_verdict(&[])),
            ));
        }
        // -- ITEM 221: THE LIST EMPTIED, THE TREE STILL RED. Striking the names without draining
        //    a row must not turn a shipping line green: the row reads the construction verdict.
        for target in ["qa", "main"] {
            report.push(unit_case(
                format!(
                    "a `{target}` target with an EMPTY list over a RED construction verdict is red"
                ),
                &[ROW_STANDING],
                Expect::Red {
                    naming: vec![
                        "one-pick-site".to_string(),
                        "NOT on the written-down list".to_string(),
                    ],
                },
                standing_row(
                    &Posture::Named(target.to_string()),
                    &[],
                    &red_verdict(&["one-pick-site"]),
                ),
            ));
        }
        report.push(unit_case(
            "the dev line keeps its standing reds, and the row PRINTS them",
            &[ROW_STANDING],
            Expect::Green,
            standing_row(
                &Posture::Named("dev".to_string()),
                &["plane-no-money"],
                &red_verdict(&["plane-no-money"]),
            ),
        ));

        // -- THE FAIL-OPEN, MADE A CASE. `posture()` used to end in `unwrap_or_default()`: a git
        //    failure became `""`, `is_shipping("")` is false, and the false arm is the PASS arm —
        //    so the row whose whole job is to refuse a promotion passed BECAUSE it could not tell
        //    what it was looking at. An unreadable posture is now its own arm and it is RED.
        report.push(unit_case(
            "an UNREADABLE posture refuses the standing-red list rather than excusing it",
            &[ROW_STANDING],
            Expect::Red {
                naming: vec![
                    "could not be read".to_string(),
                    "plane-no-money".to_string(),
                ],
            },
            standing_row(
                &Posture::Unknown("git exited 128: not a git repository".to_string()),
                &["plane-no-money"],
                &red_verdict(&["plane-no-money"]),
            ),
        ));
        report.push(unit_case(
            "an unreadable posture over an EMPTY list is still green — the criterion is met",
            &[ROW_STANDING],
            Expect::Green,
            standing_row(
                &Posture::Unknown("git exited 128: not a git repository".to_string()),
                &[],
                &red_verdict(&[]),
            ),
        ));
        // A DETACHED checkout is git declining to name a branch, not a branch named `HEAD`.
        report.push(unit_case(
            "a DETACHED checkout is an unknown posture, not a dev-line one",
            &[ROW_STANDING],
            Expect::Red {
                naming: vec!["DETACHED".to_string()],
            },
            standing_row(
                &posture_of_branch_output(Ok("HEAD\n".to_string())),
                &["plane-no-money"],
                &red_verdict(&["plane-no-money"]),
            ),
        ));
        report.push(unit_case(
            "a real branch name IS a dev-line posture",
            &[ROW_STANDING],
            Expect::Green,
            standing_row(
                &posture_of_branch_output(Ok("consolidated/1.6.0\n".to_string())),
                &["plane-no-money"],
                &red_verdict(&["plane-no-money"]),
            ),
        ));
        // THE MATCHED PAIR, IN ONE PLACE. `Posture::Named("")` is EXACTLY what the old
        // `unwrap_or_default()` handed to this row on a git failure, and it takes the dev-line
        // PASS arm — so the case below is green and is the BEFORE half, kept as evidence. The
        // same failure now arrives as `Posture::Unknown` and is red. Nothing about the list
        // changed between the two; only whether the posture was allowed to be a guess.
        report.push(unit_case(
            "the OLD fail-open shape (an EMPTY target name) still reads as a dev line — which is \
             why it had to stop being reachable",
            &[ROW_STANDING],
            Expect::Green,
            standing_row(
                &Posture::Named(String::new()),
                &["plane-no-money"],
                &red_verdict(&["plane-no-money"]),
            ),
        ));
        report.push(unit_case(
            "a git FAILURE is an unknown posture",
            &[ROW_STANDING],
            Expect::Red {
                naming: vec!["could not say".to_string()],
            },
            standing_row(
                &posture_of_branch_output(Err("git rev-parse exited 128".to_string())),
                &["plane-no-money"],
                &red_verdict(&["plane-no-money"]),
            ),
        ));

        // -- THE CEILING ROWS. A missing evidence row is the failure that matters: a rename in the
        //    construction gate must red this gate rather than silently satisfy it.
        let slack_pass = Row::pass(ceilings::ROW_SLACK, "t", "d");
        let rose_pass = Row::pass(ceilings::ROW_ROSE, "t", "d");
        report.push(rows_case(
            "both ceiling rows green is green here",
            &[ROW_SLACK, ROW_ROSE],
            Expect::Green,
            ceiling_rows(&Verdict::of(vec![slack_pass.clone(), rose_pass.clone()])),
        ));
        report.push(rows_case(
            "a ceiling left above the count it measures is red",
            &[ROW_SLACK],
            Expect::Red {
                naming: vec![ceilings::ROW_SLACK.to_string()],
            },
            ceiling_rows(&Verdict::of(vec![
                Row::fail(
                    ceilings::ROW_SLACK,
                    "slack",
                    "a ceiling above its measurement",
                ),
                rose_pass.clone(),
            ])),
        ));
        report.push(rows_case(
            "a ceiling that rose on this branch is red",
            &[ROW_ROSE],
            Expect::Red {
                naming: vec![ceilings::ROW_ROSE.to_string()],
            },
            ceiling_rows(&Verdict::of(vec![
                slack_pass.clone(),
                Row::fail(ceilings::ROW_ROSE, "rose", "a number went up"),
            ])),
        ));
        report.push(rows_case(
            "an evidence row the construction gate no longer emits is RED, not absent",
            &[ROW_SLACK, ROW_ROSE],
            Expect::Red {
                naming: vec!["emitted no such row".to_string()],
            },
            ceiling_rows(&Verdict::of(vec![Row::pass("something-else", "t", "d")])),
        ));

        // -- THE SHIP TWIN. Zero rows is the vacuous-green shape and is proven separately from a
        //    twin that genuinely has a failing row.
        report.push(unit_case(
            "a ship twin with a failing row is red, and names it",
            &[ROW_SHIP_TWIN],
            Expect::Red {
                naming: vec!["kind-isolation-ship:shape".to_string()],
            },
            ship_twin_row(&Verdict::of(vec![Row::fail(
                "kind-isolation-ship:shape",
                "two entry impls",
                "d",
            )])),
        ));
        report.push(unit_case(
            "a ship twin that produced NO rows is red, not green-by-silence",
            &[ROW_SHIP_TWIN],
            Expect::Red {
                naming: vec!["measured nothing".to_string()],
            },
            ship_twin_row(&Verdict::of(Vec::new())),
        ));
        report.push(unit_case(
            "a ship twin whose every row is green is green",
            &[ROW_SHIP_TWIN],
            Expect::Green,
            ship_twin_row(&Verdict::of(vec![Row::pass(
                "kind-isolation-ship:shape",
                "t",
                "d",
            )])),
        ));

        // -- THE GATE RUNS END TO END AND OWES WHAT IT SAYS IT OWES.
        //
        //    This gate is NOT green on the integration line and is not supposed to be: the ship
        //    twin is red on HEAD by design and the standing-red list is not empty. So an
        //    end-to-end case cannot assert a COLOUR without asserting today's redness, and a case
        //    that has to be rewritten every time the tree gets closer to shipping is not a case.
        //    What it asserts instead is the property a deleted row would break: `run()` reaches the
        //    end, and every owed row is actually emitted.
        let ran = self.run(cx);
        let missing: Vec<&str> = OWED
            .iter()
            .copied()
            .filter(|id| !ran.rows.iter().any(|r| r.id == *id))
            .collect();
        report.push(Case {
            name: "run() reaches the end and emits every owed row".to_string(),
            covers: Vec::new(),
            expected: Expect::Green,
            got: if missing.is_empty() {
                Expect::Green
            } else {
                Expect::Red {
                    naming: vec![format!("owed row(s) never emitted: {missing:?}")],
                }
            },
        });
        report
    }
}

/// Wrap one already-computed Row as a self-test case. The rows above are pure functions of their
/// inputs, so they are driven directly rather than through an overlay: an overlay that plants a
/// construction verdict would be proving the overlay.
fn unit_case(name: impl Into<String>, covers: &[&str], expected: Expect, got: Row) -> Case {
    rows_case(name, covers, expected, vec![got])
}

fn rows_case(name: impl Into<String>, covers: &[&str], expected: Expect, got: Vec<Row>) -> Case {
    let red: Vec<String> = got
        .iter()
        .filter(|r| r.status != Status::Pass)
        .map(|r| format!("{} {} {}", r.id, r.title, r.detail))
        .collect();
    Case {
        name: name.into(),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected,
        got: if red.is_empty() {
            Expect::Green
        } else {
            Expect::Red { naming: red }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ITEM 221: an EMPTY standing-red list does not make a shipping line green while the
    /// construction verdict is red — the row reads the verdict it is handed, not the Rust slice.
    #[test]
    fn an_emptied_list_over_a_red_construction_verdict_refuses_a_shipping_line() {
        for target in ["qa", "main"] {
            let row = standing_row(
                &Posture::Named(target.to_string()),
                &[],
                &red_verdict(&["one-pick-site", "request-path-fn-size"]),
            );
            assert_eq!(row.status, Status::Fail, "{target}: {}", row.detail);
            assert!(row.detail.contains("one-pick-site"), "{}", row.detail);
            assert!(
                row.detail.contains("request-path-fn-size"),
                "{}",
                row.detail
            );
        }
        // A construction rule that did not run is standing red too.
        let mut v = red_verdict(&[]);
        v.problems.push("one-pick-site: DID NOT RUN".to_string());
        let row = standing_row(&Posture::Named("qa".to_string()), &[], &v);
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        // And a clean verdict with an empty list is the criterion met.
        let row = standing_row(&Posture::Named("qa".to_string()), &[], &red_verdict(&[]));
        assert_eq!(row.status, Status::Pass, "{}", row.detail);
    }
}
