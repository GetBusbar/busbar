//! `cargo xtask gate ship-ready` — THE SHIP CRITERION, AS A ROW THAT CAN GO RED.
//!
//! The ship criterion used to be a checklist in a design document: the ship twin is zero
//! everywhere, no ceiling carries slack, no ceiling rose, the standing-red list is empty, the
//! mutation job caught everything. A checklist is a promise that someone will read it. Nothing in
//! the tree could tell whether any line of it was true, and nothing went red when a line stopped
//! being true — which is the same as not having the criterion at all.
//!
//! So it is a gate. Five rows, each of which is one line of the old checklist, each of which can be
//! red on its own:
//!
//! | row | the claim |
//! | --- | --- |
//! | [`ROW_SHIP_TWIN`] | `kind-isolation-ship` is green: every kind's ship twin measures zero |
//! | [`ROW_SLACK`] | `ceiling-slack` is green: every ceiling equals the thing it measures |
//! | [`ROW_ROSE`] | `ceiling-rose` is green: no number in a qa ceilings file went up on this branch |
//! | [`ROW_STANDING`] | the standing-red list is EMPTY, for a `qa`/`main` posture |
//! | [`ROW_MUTANTS`] | the `gate-mutants` check for this commit is green |
//!
//! ## THE POSTURE
//!
//! Four of the five rows are claims about the tree and hold everywhere. [`ROW_STANDING`] is not:
//! the standing-red list is a DEV-LINE CONVENIENCE, a set of construction rows that are known-red,
//! written down, and deliberately not blocking the integration line while they are drained. That is
//! a reasonable thing to have on a working branch and an unreasonable thing to promote. So this row
//! reads a posture — `XTASK_SHIP_TARGET`, else the branch name — and is red for a `qa` or `main`
//! target while the list is non-empty, and green-with-the-list-printed otherwise. The row is never
//! silent about what is on the list, because a convenience nobody re-reads is how a temporary
//! exemption becomes the architecture.
//!
//! ## WHY THE MUTATION VERDICT IS READ FROM GITHUB AND NOT FROM A FILE IN THE TREE
//!
//! The obvious design is for the mutation job to commit `qa/gate-mutants.json` — `{tree, surviving,
//! run_url}` — and for this row to read it. That design cannot work, and the reason is worth
//! stating plainly because it is the same reason for every "proof carried in the tree":
//!
//! A COMMITTED FILE IS A CLAIM THE CLAIMANT WROTE. Anyone who can push to the branch can write
//! `"surviving": 0` next to their own tree hash, and nothing in the repository can tell that file
//! apart from the one the job wrote — same branch, same author permissions, no signature to check.
//! The gate would then be asking the person being gated whether they passed. Worse, it fails in the
//! quiet direction: the forgery is a one-line edit and the gate goes green.
//!
//! The GitHub check for a commit is a record only GitHub can write. It is keyed to the commit SHA,
//! it cannot be produced by editing the tree, and re-running it requires actually re-running it. So
//! [`ROW_MUTANTS`] asks the checks API, over `gh`, for the conclusion of the `gate-mutants` check on
//! this commit — and an answer it cannot get is RED, never green. A gate that cannot reach its
//! evidence has not been satisfied; it has been prevented from asking.
//!
//! `mutants.out/` is still uploaded by the job as a run artefact, and the run URL is still printed
//! here — as a POINTER for a human, never as the verdict.

use std::process::Command;

use crate::ctx::{Ctx, Overlay};
use crate::gates::construction::ceilings;
use crate::gates::{Case, Expect, Gate, Report, CONSTRUCTION_STANDING_REDS};
use crate::ledger::{Row, Status, Verdict};

pub const ROW_SHIP_TWIN: &str = "ship-ready:ship-twin";
pub const ROW_SLACK: &str = "ship-ready:ceiling-slack";
pub const ROW_ROSE: &str = "ship-ready:ceiling-rose";
pub const ROW_STANDING: &str = "ship-ready:standing-reds";
pub const ROW_MUTANTS: &str = "ship-ready:gate-mutants";

const OWED: &[&str] = &[
    ROW_SHIP_TWIN,
    ROW_SLACK,
    ROW_ROSE,
    ROW_STANDING,
    ROW_MUTANTS,
];

/// The check GitHub reports for `.github/workflows/gate-mutants.yml`'s required summary job. It is
/// the job's `name:`, which is what both the checks API and branch protection match on.
pub const MUTANTS_CHECK: &str = "gate-mutants";

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

/// Which repository the checks API is asked about. Overridable only so the self-test can point the
/// real reader at a repository that does not exist and prove the unreachable branch is RED.
fn repo_of(_cx: &Ctx) -> String {
    std::env::var("XTASK_SHIP_REPO")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "GetBusbar/busbar".to_string())
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

/// One answer from the checks API, reduced to what this row needs. `None` for `conclusion` is a
/// check that exists and has not finished — which is not a green one.
struct CheckAnswer {
    conclusion: Option<String>,
    url: String,
    sha: String,
}

/// ASK GITHUB. See the module comment for why this is a network read and not a file read.
///
/// One sha, one answer. WHICH shas may be asked is [`verdict_candidates`]'s question, and it is a
/// question with a hole in it that this comment used to describe as a feature — see there.
fn ask_github(cx: &Ctx, repo: &str, sha: &str) -> Result<Option<CheckAnswer>, String> {
    let out = Command::new("gh")
        .current_dir(cx.root())
        .args([
            "api",
            &format!("repos/{repo}/commits/{sha}/check-runs"),
            "--jq",
            &format!(
                r#".check_runs[] | select(.name == "{MUTANTS_CHECK}") | "\(.conclusion // "pending")\t\(.html_url)""#
            ),
        ])
        .output()
        .map_err(|e| format!("could not run `gh`: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`gh api repos/{repo}/commits/{sha}/check-runs` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // The newest check-run for the name is the last line GitHub returns for it.
    let Some(line) = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .next_back()
    else {
        return Ok(None);
    };
    let (concl, url) = line.split_once('\t').unwrap_or((line.as_str(), ""));
    Ok(Some(CheckAnswer {
        conclusion: match concl {
            "pending" | "" => None,
            other => Some(other.to_string()),
        },
        url: url.to_string(),
        sha: sha.to_string(),
    }))
}

/// The script that owns the mutation job's scope, and the shell function inside it that IS the
/// list. `scripts/gate-mutants.sh` says of that list, in its own words, "this list is the single
/// source of truth: the workflow does not repeat it, it calls `--scope`" — so this row does not
/// repeat it either. It reads it.
const MUTANTS_SCRIPT: &str = "scripts/gate-mutants.sh";
const SCOPE_FN: &str = "gm_scope_paths()";

/// THE PATHS THE MUTATION JOB IS SCOPED TO, read out of the script that owns them.
///
/// A COPY OF THE LIST IN RUST WOULD BE THE SECOND SOURCE OF TRUTH the script's own comment refuses
/// to have. A path added to the job's scope and not to the copy would be a path this row still
/// believes the branch cannot have touched, which is exactly the fallback below going quiet again
/// — one file at a time, invisibly, as the scope grows.
///
/// A SCRIPT THAT CANNOT BE READ IS AN ERROR, never an empty list: empty reads as "this branch
/// changed nothing the job measures", which is the permissive answer to every question below.
fn mutants_scope(cx: &Ctx) -> Result<Vec<String>, String> {
    let text = cx.read(MUTANTS_SCRIPT)?;
    let Some((_, rest)) = text.split_once(SCOPE_FN) else {
        return Err(format!(
            "{MUTANTS_SCRIPT} carries no `{SCOPE_FN}`, so the paths the mutation job is scoped to \
             cannot be read out of the script that owns them"
        ));
    };
    let Some((_, body)) = rest.split_once("<<'PATHS'\n") else {
        return Err(format!(
            "`{SCOPE_FN}` in {MUTANTS_SCRIPT} no longer prints a `PATHS` heredoc, so its list \
             cannot be read"
        ));
    };
    let out: Vec<String> = body
        .lines()
        .take_while(|l| l.trim() != "PATHS")
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if out.is_empty() {
        return Err(format!(
            "`{SCOPE_FN}` in {MUTANTS_SCRIPT} lists no path at all. An empty scope reads as \"this \
             branch changed nothing the mutation job measures\", which is the answer that makes \
             every other commit's verdict acceptable for this one"
        ));
    }
    Ok(out)
}

/// WHAT THIS BRANCH CHANGED that the mutation job would have measured — the job's own `gm_scope`,
/// asked of the same base every other ratchet in this binary uses.
fn picks(cx: &Ctx, base: &str, scope: &[String]) -> Result<Vec<String>, String> {
    let mut args: Vec<&str> = vec!["diff", "--name-only", base, "HEAD", "--"];
    args.extend(scope.iter().map(String::as_str));
    Ok(cx
        .git_lines(&args)?
        .into_iter()
        .filter(|l| !l.trim().is_empty())
        .collect())
}

/// WHICH COMMITS MAY ANSWER FOR THIS TREE, in the order they are asked.
///
/// THE HOLE THIS FUNCTION EXISTS TO CLOSE. The row used to ask HEAD and then, whatever the branch
/// contained, fall back to the base — and take the base's `success` as the tip's verdict. The
/// rationale written beside it was true of one case and applied to all of them: "a commit that
/// only moved documentation carries no `gate-mutants` run of its own, and the standing verdict for
/// the branch point is the honest answer for it". For a branch that moved documentation, yes. For
/// a branch that rewrote `xtask/src/gates`, the base is a commit that carries NONE OF THE PICKS —
/// its green says nothing whatever about the gate code being shipped, and an unpushed tip full of
/// new gate code inherited it silently. That is a PASS with no evidence under it, which is the one
/// thing this whole gate exists not to print.
///
/// So the fallback keeps exactly the case its rationale describes and loses the rest: the base may
/// answer for the tip only when the branch changed NOTHING in the mutation job's scope, because
/// then the gate code at the tip and the gate code at the base are the same gate code and the
/// verdict really is about it.
fn verdict_candidates(head: &str, base: &str, picks: &[String]) -> Vec<String> {
    let mut out = vec![head.to_string()];
    if picks.is_empty() && !base.is_empty() && base != head {
        out.push(base.to_string());
    }
    out
}

fn mutants_row(cx: &Ctx, repo: &str) -> Row {
    let head = cx
        .git(&["rev-parse", "HEAD"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if head.is_empty() {
        return Row::fail(
            ROW_MUTANTS,
            "this tree has no HEAD to ask about",
            "`git rev-parse HEAD` said nothing, so there is no commit to look the mutation \
             verdict up against."
                .to_string(),
        );
    }
    // THE BASE COMES FROM THE ONE RESOLVER. This row used to compute its own merge-base, in its
    // own words, beside `ceilings::base_ref` computing the same thing in different ones — so a run
    // pointed at a base (`BUSBAR_GATE_BASE_REF`) moved every ceiling ratchet and left this row
    // still asking about the integration line. Two answers to "what is the base" in one binary is
    // two ratchets disagreeing about what they ratchet from while both stay green.
    let base = ceilings::base_ref(cx).unwrap_or_default();

    // READ BEFORE ANYTHING IS ASKED OF GITHUB, because the answer decides WHO may be asked. A run
    // that cannot tell what this branch changed cannot tell whose verdict is about it.
    let picked = match mutants_scope(cx).and_then(|scope| picks(cx, &base, &scope)) {
        Ok(p) => p,
        Err(why) => {
            return Row::fail(
                ROW_MUTANTS,
                "what this branch changed could not be read",
                format!(
                    "{why}. Which commit's `{MUTANTS_CHECK}` verdict is about THIS tree depends on \
                     what this tree changed in the job's scope; a run that cannot read the scope \
                     cannot say, and cannot be told yes."
                ),
            );
        }
    };

    let mut tried: Vec<String> = Vec::new();
    for sha in verdict_candidates(&head, &base, &picked)
        .into_iter()
        .filter(|s| !s.is_empty())
    {
        match ask_github(cx, repo, &sha) {
            Err(why) => {
                // A GATE THAT CANNOT REACH ITS EVIDENCE HAS NOT BEEN SATISFIED. This is the one
                // branch where the temptation to be lenient is strongest and where leniency is
                // exactly the hole: "no token here" would make the row green on every laptop.
                return Row::fail(
                    ROW_MUTANTS,
                    "the mutation verdict could not be read",
                    format!(
                        "{why}. The `{MUTANTS_CHECK}` verdict is read from the GitHub checks API \
                         because that is the one record of it a push cannot forge; a run that \
                         cannot ask has not been told yes. Authenticate `gh`, or run this gate \
                         where CI runs it."
                    ),
                );
            }
            Ok(None) => tried.push(sha),
            Ok(Some(a)) => {
                return match a.conclusion.as_deref() {
                    Some("success") => Row::pass(
                        ROW_MUTANTS,
                        "every mutant in the changed gate code was caught",
                        format!("`{MUTANTS_CHECK}` success on {} -- {}", &a.sha[..12.min(a.sha.len())], a.url),
                    ),
                    Some(other) => Row::fail(
                        ROW_MUTANTS,
                        "the mutation job is not green",
                        format!(
                            "`{MUTANTS_CHECK}` is `{other}` on {} -- {}. A surviving mutant is gate \
                             code this branch changed that no self-test case holds down.",
                            &a.sha[..12.min(a.sha.len())],
                            a.url
                        ),
                    ),
                    None => Row::fail(
                        ROW_MUTANTS,
                        "the mutation job has not finished",
                        format!(
                            "`{MUTANTS_CHECK}` is still running on {} -- {}. Not finished is not \
                             green.",
                            &a.sha[..12.min(a.sha.len())],
                            a.url
                        ),
                    ),
                };
            }
        }
    }
    let carried = if picked.is_empty() {
        "This branch changed nothing in the mutation job's scope, so the base's standing verdict \
         would have answered for it — and there is not one."
            .to_string()
    } else {
        format!(
            "This branch changed {} file(s) in the job's scope ({}), so NO ancestor's verdict is \
             about this tree: an ancestor carries none of those picks.",
            picked.len(),
            picked.join(", ")
        )
    };
    Row::fail(
        ROW_MUTANTS,
        "no mutation verdict exists for this commit",
        format!(
            "no `{MUTANTS_CHECK}` check on {}. The job reports on every push, so no check means \
             the commit was never pushed, or the workflow is not on this branch. Either way \
             nothing has measured whether this tree's gates still bite. {carried}",
            tried.join(" or ")
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

        rows.push(mutants_row(cx, &repo_of(cx)));
        Verdict::of(rows)
    }

    fn selftest(&self, cx: &Ctx) -> Report {
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

        // -- THE MUTATION VERDICT. Driven against the REAL reader, with `gh` pointed at a repo
        //    that does not exist: an unreachable evidence source must be RED. This is the branch a
        //    lenient implementation would have made green on every laptop, and it covers no row it
        //    has not earned.
        report.push(unit_case(
            "a mutation verdict this run cannot READ is red, never green",
            &[ROW_MUTANTS],
            Expect::Red {
                naming: vec!["could not be read".to_string()],
            },
            mutants_row(cx, "GetBusbar/no-such-repository-ever-0000"),
        ));

        // -- WHOSE VERDICT IS ABOUT THIS TREE. The audit's claim, as a fixture: a tip that
        //    carries gate-code picks used to inherit its merge-base's green, and the base carries
        //    none of those picks. The rule is now a pure function of (head, base, picks) and each
        //    of its two arms is a case, because the arm that is right for a documentation-only
        //    push is the arm that was wrong for every other one.
        for (name, picks, want, why) in [
            (
                "a tip carrying picks in the job's scope may NOT inherit an ancestor's verdict",
                vec!["xtask/src/gates/construction/ceilings.rs".to_string()],
                vec!["deadbeef".to_string()],
                "the base carries none of this branch's picks",
            ),
            (
                "a tip that changed nothing in the job's scope may read the base's standing verdict",
                Vec::new(),
                vec!["deadbeef".to_string(), "cafef00d".to_string()],
                "the gate code at the tip IS the gate code at the base",
            ),
        ] {
            let got = verdict_candidates("deadbeef", "cafef00d", &picks);
            report.push(Case {
                name: name.to_string(),
                covers: vec![ROW_MUTANTS.to_string()],
                expected: Expect::Green,
                got: if got == want {
                    Expect::Green
                } else {
                    Expect::Red {
                        naming: vec![format!(
                            "picks {picks:?} may be answered for by {got:?}, and only {want:?} \
                             answers for them: {why}"
                        )],
                    }
                },
            });
        }

        // -- THE SCOPE IS READ, NEVER COPIED. An empty or unreadable scope reads as "this branch
        //    changed nothing the job measures", which is the answer that hands every ancestor's
        //    verdict to every tip — so it is RED, and it is red before `gh` is reached, which is
        //    what lets this case run with no network and no token.
        for (name, planted, naming) in [
            (
                "a gate-mutants script with no scope function reddens the row, never widens it",
                "#!/usr/bin/env bash\necho hello\n".to_string(),
                "carries no `gm_scope_paths()`",
            ),
            (
                "a gate-mutants script whose scope list is EMPTY is refused, not read as \"nothing changed\"",
                format!("#!/usr/bin/env bash\n{SCOPE_FN} {{\n  cat <<'PATHS'\nPATHS\n}}\n"),
                "lists no path at all",
            ),
        ] {
            let mut ov = Overlay::new();
            ov.set(MUTANTS_SCRIPT, planted);
            report.push(unit_case(
                name,
                &[ROW_MUTANTS],
                Expect::Red {
                    naming: vec![naming.to_string()],
                },
                mutants_row(&cx.with_overlay(ov), "GetBusbar/no-such-repository-ever-0000"),
            ));
        }

        // -- AND THE REAL SCRIPT'S LIST IS READABLE. The two refusals above prove the reader
        //    refuses; this proves it reads, against the file that owns the list — so a heredoc
        //    reformatted in the script turns this red rather than quietly emptying the scope.
        report.push(Case {
            name: "the mutation job's scope is read out of scripts/gate-mutants.sh itself".into(),
            covers: Vec::new(),
            expected: Expect::Green,
            got: match mutants_scope(cx) {
                Ok(paths) if paths.iter().any(|p| p == "xtask/src/gates") => Expect::Green,
                Ok(paths) => Expect::Red {
                    naming: vec![format!(
                        "{MUTANTS_SCRIPT} scope read as {paths:?}, which does not name the gate \
                         sources — the reader and the script have come apart"
                    )],
                },
                Err(e) => Expect::Red {
                    naming: vec![format!("{MUTANTS_SCRIPT} scope could not be read: {e}")],
                },
            },
        });

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
