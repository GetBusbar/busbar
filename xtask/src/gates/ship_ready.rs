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

/// What the posture is for this run: the explicit target if one is set, otherwise the branch this
/// tree is on. Named separately so the self-test can drive every branch of it without a checkout.
pub fn posture(cx: &Ctx) -> String {
    if let Ok(t) = std::env::var("XTASK_SHIP_TARGET") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    cx.git(&["rev-parse", "--abbrev-ref", "HEAD"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn is_shipping(target: &str) -> bool {
    SHIPPING_TARGETS.contains(&target)
}

/// THE STANDING-RED ROW. Red for a shipping posture while anything is on the list, and it prints
/// the list either way: the whole hazard of a written-down exemption is that it stops being read.
fn standing_row(target: &str, standing: &[&str]) -> Row {
    let listed = if standing.is_empty() {
        "(empty)".to_string()
    } else {
        standing.join(", ")
    };
    if !is_shipping(target) {
        return Row::pass(
            ROW_STANDING,
            "the standing-red list is a dev-line convenience, and this is the dev line",
            format!(
                "target `{target}` is not a shipping line, so the {} standing red(s) still stand: \
                 {listed}. Each one is a construction row that is KNOWN red and deliberately not \
                 blocking. None of them survives a promotion — run this gate with \
                 XTASK_SHIP_TARGET=qa to see what a promotion would refuse.",
                standing.len()
            ),
        );
    }
    if standing.is_empty() {
        return Row::pass(
            ROW_STANDING,
            "nothing is standing red on a shipping line",
            format!("target `{target}`: the standing-red list is empty."),
        );
    }
    Row::fail(
        ROW_STANDING,
        "a shipping line inherits no standing reds",
        format!(
            "target `{target}` is a shipping line and {} construction row(s) are still standing \
             red: {listed}. A standing red is a rule this tree BREAKS, written down so the dev \
             line can keep moving while it is drained. Promoting it does not drain it — it \
             promotes the breakage and retires the record of it. Drain each row, or do not ship.",
            standing.len()
        ),
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
        let mut rows = vec![standing_row(&target, CONSTRUCTION_STANDING_REDS)];

        // The two gates that OWN the evidence, run once each. Their `--selftest` is the expensive
        // half; a single `run()` over the tree is not, which is what makes reading them here
        // affordable rather than a second implementation of the same rules.
        let construction = crate::gates::execute(
            &crate::gates::construction::ConstructionGate as &dyn Gate,
            cx,
        );
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
                standing_row(target, &["plane-no-money", "one-pick-site"]),
            ));
            report.push(unit_case(
                format!("a `{target}` target with an EMPTY list is green"),
                &[ROW_STANDING],
                Expect::Green,
                standing_row(target, &[]),
            ));
        }
        report.push(unit_case(
            "the dev line keeps its standing reds, and the row PRINTS them",
            &[ROW_STANDING],
            Expect::Green,
            standing_row("dev", &["plane-no-money"]),
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
