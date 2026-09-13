//! `cargo xtask gate qa-gate-dispatch` — THE DISPATCHER THAT ACTUALLY FIRES MUST BE THE ONE ANYONE
//! READ.
//!
//! WHY THIS GATE EXISTS
//! --------------------
//! `workflow_run` ALWAYS loads the workflow file from the DEFAULT branch. Whatever
//! `.github/workflows/qa-gate.yml` looks like on `main` is what auto-fires after a push to `qa`,
//! regardless of what the promoted commit carries. That has already cost this tree once: the
//! auto-fired gate ran ONE job while the whole segmentation umbrella sat unused on `qa`, and it
//! failed SILENTLY — the run went green, it had simply done far less than anyone believed.
//!
//! The dispatcher design solves most of it: `qa-gate.yml` checks out the TRIGGERING SHA and invokes
//! `scripts/qa-gate-run.sh` from that checkout, so gate LOGIC rides the commit it gates. What
//! cannot ride the commit is everything GitHub must read before a checkout exists — `on:`,
//! `concurrency`, `permissions`, `env`, `runs-on`, `timeout-minutes`, the `needs`/`if` graph and
//! the `strategy.matrix` expression. Those come from the default branch, always.
//!
//! WHAT IS COMPARED, AND WHAT DELIBERATELY IS NOT
//! ---------------------------------------------
//! The PARSED STRUCTURE, not the bytes. Comments and formatting are dropped by
//! [`crate::yaml_lite::parse_structure`] and may drift freely. That distinction is the only reason
//! this gate can exist: a byte-identical requirement would deadlock, because the default branch
//! only moves at a release, so any workflow edit would be red until the very release the edit is
//! meant to gate. Structural identity means a prose change costs nothing while a change to the run
//! graph fails immediately — the same split as between what rides the commit and what does not.
//!
//! WHICH QUESTION IS ASKED, AND WHERE
//! ---------------------------------
//! Structural identity fixed the prose deadlock and left a bigger one standing. Comparing against
//! the default branch on EVERY branch is a question a development branch cannot answer: the only
//! way to satisfy it is to push the workflow to the default branch, a release-path action. An
//! integration branch carrying a legitimate dispatcher change is then red for its entire life, by
//! construction, with a remedy no one on that branch is allowed to take — and a gate that cannot be
//! satisfied from where it runs stops being read.
//!
//! So the question is asked where it can be answered, in two arms and four rows:
//!
//! 1. [`ROW_WORKFLOW`] — `.github/workflows/qa-gate.yml` exists and parses into a non-empty job
//!    graph. Zero jobs is a NAMED failure, distinct from "compared and found no differences":
//!    an empty document satisfies every comparison vacuously.
//! 2. [`ROW_DECLARED_READABLE`] — `.github/workflows/qa-gate.dispatcher.json`, the shape this
//!    branch DECLARES, exists and parses. An unreadable declared shape is UNKNOWN, and unknown is
//!    not green.
//! 3. [`ROW_DECLARED_CURRENT`] — the workflow matches that declared shape. THIS ARM RUNS ON EVERY
//!    BRANCH: it needs no network and no fetched remote, which is the whole point of it. Any change
//!    to the run graph is caught at the commit that makes it, with the declared file in the diff
//!    for a reviewer to read.
//! 4. [`ROW_DEFAULT_BRANCH`] — on `qa` and `main` ADDITIONALLY, the copy on [`DEFAULT_BRANCH_REF`],
//!    the one `workflow_run` actually loads, matches too. This is the original question, kept whole
//!    and unrelaxed, asked at the two branches where the promotion is the point.
//!
//! THE ROW THAT MUST NOT DISAPPEAR
//! ------------------------------
//! Rule 4 is branch-dependent, and a check that quietly vanishes on most branches is precisely the
//! defect this gate was fixed for. So it emits a row on EVERY branch, always. On a development
//! branch that row is a PASS whose detail names the branch it saw and states that the promoted copy
//! is compared on `qa` and `main` — the reader is told which arm ran, never left to infer it from
//! silence.
//!
//! It is deliberately not a SKIP. [`crate::ledger::Reconcile`] makes every SKIP red unless the id is
//! on a narrow allowlist, and [`crate::gates::execute`] — what `cargo xtask gate` and every
//! `prove_red`/`prove_green` call — carries no allowlist at all. A SKIP here would therefore make
//! this gate red on every branch that is not `qa` or `main`, which is the branch-cannot-answer
//! deadlock restated in the ledger instead of in the comparison. The distinction the SKIP would
//! have carried is carried by the row's title and detail instead, where a human reads it.
//!
//! FAILS CLOSED
//! ------------
//! If the default branch's copy cannot be read on a branch where it IS asked, that is a FAILURE,
//! not a pass and not a skip. A lint that goes green when it cannot see is worse than no lint,
//! because it is consulted and wrong.

use serde_json::{Map, Value};

use crate::ctx::{Ctx, Edit, Overlay};
use crate::gates::{prove_green, prove_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::yaml_lite;

/// The dispatcher itself.
pub const WORKFLOW: &str = ".github/workflows/qa-gate.yml";

/// The shape THIS BRANCH declares — the projection promoted along with the workflow. JSON rather
/// than YAML because it is a DERIVED artifact nobody should hand-edit: `--write` produces it and
/// the gate compares against it, the same regen-drift shape the other generated artifacts use.
pub const DECLARED: &str = ".github/workflows/qa-gate.dispatcher.json";

/// The ref whose copy `workflow_run` actually loads.
pub const DEFAULT_BRANCH_REF: &str = "origin/main";

/// The branches on which the dispatcher that fires IS the one on the default branch, so the
/// comparison against [`DEFAULT_BRANCH_REF`] is the question actually being asked.
pub const PROMOTION_BRANCHES: &[&str] = &["qa", "main"];

pub const ROW_WORKFLOW: &str = "qa-gate-dispatch:workflow-parses";
pub const ROW_DECLARED_READABLE: &str = "qa-gate-dispatch:declared-shape-readable";
pub const ROW_DECLARED_CURRENT: &str = "qa-gate-dispatch:declared-shape-current";
pub const ROW_DEFAULT_BRANCH: &str = "qa-gate-dispatch:default-branch-copy";

/// What the diff paths call the other side. The two arms compare against different things, and a
/// message naming the wrong one sends the reader to the wrong file.
fn other_declared() -> String {
    format!("the declared shape ({DECLARED})")
}

pub struct QaGateDispatchGate {
    /// The branch to judge as. `None` reads it from the environment, then from the working tree.
    branch: Option<String>,
    /// The ref the promoted copy is read from. A field rather than a constant so a self-test can
    /// point it at a ref that CANNOT exist and prove the fails-closed arm with real `git`, rather
    /// than asserting it.
    default_ref: String,
    /// The promoted copy, injected. `None` reads [`Self::default_ref`] with `git`. A self-test that
    /// needed a fetched remote could not prove the promotion arm at all and would quietly stop
    /// covering it, which is the failure this gate was written about.
    remote: Option<String>,
}

impl Default for QaGateDispatchGate {
    fn default() -> Self {
        QaGateDispatchGate::new()
    }
}

impl QaGateDispatchGate {
    /// The registered gate: judge the branch this actually is, read the promoted copy with `git`.
    pub fn new() -> QaGateDispatchGate {
        QaGateDispatchGate {
            branch: None,
            default_ref: DEFAULT_BRANCH_REF.to_string(),
            remote: None,
        }
    }

    /// A gate that judges as `branch`, reading the promoted copy from `default_ref` unless `remote`
    /// supplies it. Reached only through [`Gate::run`], exactly like the registered gate — the
    /// self-test never gets a second path to the predicate.
    pub fn judging_as(branch: &str, default_ref: &str, remote: Option<&str>) -> QaGateDispatchGate {
        QaGateDispatchGate {
            branch: Some(branch.to_string()),
            default_ref: default_ref.to_string(),
            remote: remote.map(str::to_string),
        }
    }

    /// The branch this run is on, as CI knows it, falling back to the working tree.
    ///
    /// `GITHUB_REF_NAME` is what the workflow is actually running as and is exact; under a
    /// `workflow_run` the checked-out HEAD is not. An UNKNOWN branch is treated as a development
    /// branch, which is the SAFE direction: the development arm is the one that is always
    /// answerable, and the promotion arm must not be asked of someone who is not promoting.
    fn branch(&self, cx: &Ctx) -> String {
        if let Some(b) = &self.branch {
            return b.clone();
        }
        if let Some(b) = std::env::var("GITHUB_REF_NAME")
            .ok()
            .filter(|b| !b.is_empty())
        {
            return b;
        }
        cx.git(&["rev-parse", "--abbrev-ref", "HEAD"])
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "(unknown)".to_string())
    }

    /// Regenerate the declared shape from the workflow this branch carries.
    ///
    /// An EXPLICIT method, never a fallback inside [`Gate::run`]. A gate that repaired its own
    /// subject when it found drift would report green over a change nobody reviewed and would
    /// rewrite the very file the diff is supposed to show.
    pub fn write_declared(&self, cx: &Ctx) -> Result<String, String> {
        let text = cx.read(WORKFLOW)?;
        let shape = yaml_lite::parse_structure(&text)
            .map_err(|e| format!("{WORKFLOW} is not parseable YAML: {e}"))?;
        let json = canonical(&shape);
        let dest = cx.abs(DECLARED);
        std::fs::write(&dest, &json).map_err(|e| format!("{}: {e}", dest.display()))?;
        Ok(format!("wrote {DECLARED} from {WORKFLOW}"))
    }

    /// The workflow as the structure the runner executes, or the reason it is unknown.
    fn workflow_structure(&self, cx: &Ctx) -> Result<Value, String> {
        let text = cx
            .read(WORKFLOW)
            .map_err(|_| format!("{WORKFLOW} does not exist in this checkout"))?;
        let value = yaml_lite::parse_structure(&text)
            .map_err(|e| format!("{WORKFLOW} is not parseable YAML: {e}"))?;
        // ZERO IS NEVER CLEAN. A document that parsed to no jobs compares equal to another document
        // that parsed to no jobs, so a workflow whose `jobs:` key was emptied or renamed away would
        // sail through both arms while running nothing at all.
        let jobs = value.get("jobs").and_then(Value::as_object);
        match jobs {
            Some(j) if !j.is_empty() => Ok(value),
            _ => Err(format!(
                "{WORKFLOW} declares no jobs: a dispatcher with an empty job graph runs nothing, \
                 and it compares clean against every other empty job graph"
            )),
        }
    }

    fn rows(&self, cx: &Ctx) -> Vec<Row> {
        let mut rows = Vec::new();

        let here = match self.workflow_structure(cx) {
            Ok(v) => {
                let names = job_names(&v);
                rows.push(Row::pass(
                    ROW_WORKFLOW,
                    "the dispatcher parses into a job graph",
                    format!("{} job(s): {}", names.len(), names.join(", ")),
                ));
                v
            }
            Err(why) => {
                rows.push(Row::fail(
                    ROW_WORKFLOW,
                    "the dispatcher could not be read as a job graph",
                    why.clone(),
                ));
                rows.push(unevaluated(ROW_DECLARED_READABLE, &why));
                rows.push(unevaluated(ROW_DECLARED_CURRENT, &why));
                rows.push(unevaluated(ROW_DEFAULT_BRANCH, &why));
                return rows;
            }
        };

        let declared = match self.declared_shape(cx) {
            Ok(v) => {
                rows.push(Row::pass(
                    ROW_DECLARED_READABLE,
                    "the declared shape is readable",
                    format!("{DECLARED}, the projection every branch is measured against"),
                ));
                v
            }
            Err(why) => {
                rows.push(Row::fail(
                    ROW_DECLARED_READABLE,
                    "the declared shape could not be read",
                    why.clone(),
                ));
                rows.push(unevaluated(ROW_DECLARED_CURRENT, &why));
                rows.push(self.promoted_copy_row(cx, &here));
                return rows;
            }
        };

        rows.push(self.declared_current_row(&here, &declared));
        rows.push(self.promoted_copy_row(cx, &here));
        rows
    }

    fn declared_shape(&self, cx: &Ctx) -> Result<Value, String> {
        let text = cx.read(DECLARED).map_err(|_| {
            format!(
                "{DECLARED} does not exist. It is the shape this branch declares for the \
                 dispatcher and the thing every branch is measured against; regenerate it and \
                 commit it in the same change as the workflow."
            )
        })?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{DECLARED} is not parseable JSON: {e}. Unknown is not green."))?;
        match value.as_object() {
            Some(m) if !m.is_empty() => Ok(value),
            _ => Err(format!(
                "{DECLARED} declares nothing: an empty shape compares equal to every workflow and \
                 measures none of them"
            )),
        }
    }

    /// ARM 1 — the declared shape. Every branch, `qa` and `main` included.
    fn declared_current_row(&self, here: &Value, declared: &Value) -> Row {
        // Both sides go through the SAME canonicalisation the writer uses, so a value with no JSON
        // spelling cannot read as drift on every run while the two files agree perfectly.
        let mine: Value = match serde_json::from_str(&canonical(here)) {
            Ok(v) => v,
            Err(e) => {
                return Row::fail(
                    ROW_DECLARED_CURRENT,
                    "the dispatcher's own shape could not be canonicalised",
                    format!("{e} — an uncomparable side is unproven, not equal"),
                )
            }
        };
        let drift = diff_paths(&mine, declared, "", &other_declared());
        if drift.is_empty() {
            return Row::pass(
                ROW_DECLARED_CURRENT,
                "the dispatcher matches the shape this branch declares",
                format!(
                    "{WORKFLOW} == {DECLARED}; comments and formatting may differ, and that is fine"
                ),
            );
        }
        Row::fail(
            ROW_DECLARED_CURRENT,
            format!("{WORKFLOW} does not match the shape this branch declares in {DECLARED}"),
            format!(
                "{} — the declared shape is what will be promoted with this branch and what a \
                 reviewer reads to see that the run graph moved. Regenerate it \
                 (`QaGateDispatchGate::write_declared`) in the same commit as the workflow change.",
                drift.join(" | ")
            ),
        )
    }

    /// ARM 2 — the promoted copy. Asked only where the promotion is the point; REPORTED everywhere.
    fn promoted_copy_row(&self, cx: &Ctx, here: &Value) -> Row {
        let branch = self.branch(cx);
        if !PROMOTION_BRANCHES.contains(&branch.as_str()) {
            return Row::pass(
                ROW_DEFAULT_BRANCH,
                "the promoted copy is compared where the promotion happens",
                format!(
                    "branch is `{branch}`, so the comparison against {DEFAULT_BRANCH_REF} — the \
                     copy `workflow_run` actually loads — is asked on {}, where it is answerable \
                     and where it decides whether a release is gated by the graph anyone believes. \
                     The declared-shape arm above ran here and catches a run-graph change at the \
                     commit that makes it.",
                    PROMOTION_BRANCHES.join(" and ")
                ),
            );
        }

        let remote_text = match &self.remote {
            Some(t) => Ok(t.clone()),
            None => cx.git(&["show", &format!("{}:{}", self.default_ref, WORKFLOW)]),
        };
        let remote_text = match remote_text {
            Ok(t) => t,
            Err(e) => {
                return Row::fail(
                    ROW_DEFAULT_BRANCH,
                    format!("could not read {WORKFLOW} from {}", self.default_ref),
                    format!(
                        "{e} — so it is UNKNOWN whether the dispatcher that will actually fire \
                         matches this commit's. Unknown is not green: fetch the default branch and \
                         re-run, and do not skip this check.",
                    ),
                )
            }
        };
        let there = match yaml_lite::parse_structure(&remote_text) {
            Ok(v) => v,
            Err(e) => {
                return Row::fail(
                    ROW_DEFAULT_BRANCH,
                    format!("{}'s {WORKFLOW} is not parseable YAML", self.default_ref),
                    format!("{e} — an unparseable promoted copy is unknown, not equal"),
                )
            }
        };

        let differences = diff_paths(here, &there, "", &self.default_ref);
        if differences.is_empty() {
            return Row::pass(
                ROW_DEFAULT_BRANCH,
                "the dispatcher matches the copy the default branch will fire",
                format!(
                    "branch is `{branch}`; {WORKFLOW} == {}:{WORKFLOW}, comments and formatting \
                     aside",
                    self.default_ref
                ),
            );
        }
        Row::fail(
            ROW_DEFAULT_BRANCH,
            format!(
                "the qa-gate DISPATCHER on this commit differs STRUCTURALLY from the one on {}",
                self.default_ref
            ),
            format!(
                "{} — `workflow_run` always loads the workflow file from the DEFAULT branch, so \
                 the gate that actually fires after a push to `qa` is the one on {}, NOT the one in \
                 this commit. Until these agree, a qa-gate improvement cannot gate the release that \
                 ships it, and the run goes GREEN having done less than anyone thinks. This is \
                 branch `{branch}`, where the promotion IS the point: fix it by promoting this file \
                 to the default branch, not by relaxing this check. Gate LOGIC belongs in \
                 scripts/qa-gate-run.sh, which rides the commit and is exempt from this problem \
                 entirely.",
                differences.join(" | "),
                self.default_ref
            ),
        )
    }
}

/// An owed row whose rule could not be reached. A row is still EMITTED, because an owed id with no
/// row reads as DID NOT RUN and would bury the real failure under a reconciliation complaint.
fn unevaluated(id: &str, because: &str) -> Row {
    Row::fail(
        id,
        "not evaluated",
        format!("{because} — a rule that could not be reached is unproven, not satisfied"),
    )
}

fn job_names(value: &Value) -> Vec<String> {
    value
        .get("jobs")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

impl Gate for QaGateDispatchGate {
    fn name(&self) -> &'static str {
        "qa-gate-dispatch"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_WORKFLOW.to_string(),
            ROW_DECLARED_READABLE.to_string(),
            ROW_DECLARED_CURRENT.to_string(),
            ROW_DEFAULT_BRANCH.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(self.rows(cx))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        report.push(prove_green(
            cx,
            self,
            "the tree's dispatcher matches the shape it declares",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        report.push(plant(
            cx,
            self,
            "the dispatcher file is gone",
            &[ROW_WORKFLOW],
            WORKFLOW,
            Edit::Delete,
            &["does not exist in this checkout"],
        ));

        report.push(plant(
            cx,
            self,
            "the dispatcher declares no jobs",
            &[ROW_WORKFLOW],
            WORKFLOW,
            Edit::Replace("name: qa-gate\non:\n  workflow_dispatch: {}\njobs:\n".to_string()),
            &["declares no jobs"],
        ));

        report.push(plant(
            cx,
            self,
            "the declared shape is gone",
            &[ROW_DECLARED_READABLE],
            DECLARED,
            Edit::Delete,
            &["does not exist"],
        ));

        report.push(plant(
            cx,
            self,
            "the declared shape is not JSON",
            &[ROW_DECLARED_READABLE],
            DECLARED,
            Edit::Replace("{ this is not json".to_string()),
            &["is not parseable JSON"],
        ));

        // The declared-shape arm, planted as a change to the RUN GRAPH — the class of edit that
        // must fail at the commit that makes it rather than at the next release.
        report.push(match graph_change(cx, WORKFLOW) {
            Some(changed) => {
                let mut ov = Overlay::new();
                ov.set(WORKFLOW, changed);
                prove_red(
                    cx,
                    self,
                    "a needs: edge is removed from the dispatcher",
                    &[ROW_DECLARED_CURRENT],
                    ov,
                    &[
                        "jobs.slow.needs",
                        "does not match the shape this branch declares",
                    ],
                )
            }
            None => unplantable(
                "a needs: edge is removed from the dispatcher",
                &[ROW_DECLARED_CURRENT],
                &["jobs.slow.needs"],
            )
            .into(),
        });

        // BOTH ARMS OF THE BRANCH SPLIT. The cases above prove the COMPARISON discriminates; they
        // say nothing about WHICH comparison a given branch gets, which is the thing this gate got
        // wrong. So the promotion arm is driven with a fixture whose promoted copy is injected: a
        // self-test that needed the network could not prove the `qa` arm at all.
        let base = FIXTURE_BASE.to_string();
        let changed = base.replace("needs: [build, fast]", "needs: [build]");
        match yaml_lite::parse_structure(&changed) {
            Ok(shape) => {
                let mut ov = Overlay::new();
                ov.set(WORKFLOW, changed.clone());
                ov.set(DECLARED, canonical(&shape));
                // The gate is built FOR THIS CASE — a promotion arm the registry does not carry —
                // so the case owns it rather than borrowing a temporary that dies at this `;`.
                let arm = QaGateDispatchGate::judging_as("qa", DEFAULT_BRANCH_REF, Some(&base));
                report.push(crate::gates::CasePlan::new(move || {
                    prove_red(
                        cx,
                        &arm,
                        "on qa an unpromoted run-graph change is red against the default branch",
                        &[ROW_DEFAULT_BRANCH],
                        ov,
                        &[
                            "differs STRUCTURALLY from the one on origin/main",
                            "jobs.slow.needs",
                        ],
                    )
                    .take()
                }));
            }
            Err(e) => report.note_infra_failure(format!(
                "the promotion-arm fixture did not parse, so the qa arm is unproven here: {e}"
            )),
        }

        // FAILS CLOSED, proven with real `git` rather than asserted: a ref that cannot exist is
        // unreadable, and an unreadable promoted copy on a promotion branch is a named failure.
        let unreadable_default = QaGateDispatchGate::judging_as(
            "main",
            "refs/heads/no-such-ref-for-the-qa-gate-dispatch-selftest",
            None,
        );
        report.push(crate::gates::CasePlan::new(move || {
            prove_red(
                cx,
                &unreadable_default,
                "on main an unreadable default branch is a failure, never a pass",
                &[ROW_DEFAULT_BRANCH],
                Overlay::new(),
                &["could not read", "Unknown is not green"],
            )
            .take()
        }));

        report
    }

    /// The planted trees `--parity` drives the legacy script and this gate over together.
    ///
    /// WHICH ARM PARITY CAN REACH, AND WHY IT IS ONLY ONE.
    ///
    /// The harness materializes an overlaid view of named paths into a scratch directory and points
    /// the legacy script at it with `--root`. Two consequences fall straight out of that, and both
    /// are properties of this gate's subject rather than gaps to be papered over:
    ///
    /// * [`ROW_DEFAULT_BRANCH`] IS NOT COVERED. The legacy reads the promoted copy with
    ///   `git show origin/main:…`, and a scratch directory is not a repository. Manufacturing one
    ///   there would be building a fake default branch to satisfy a comparison whose entire point is
    ///   that the real one is what fires — and an unfetched `origin/main` must stay the named
    ///   failure it is. The arm keeps its two selftest cases, which prove it end to end with an
    ///   injected copy and with real `git` against a ref that cannot exist.
    /// * ONLY THE LEGACY'S EXIT-1 PATHS ARE PROBEABLE. Its "could not run" paths — a missing
    ///   workflow, a missing or unparseable declared shape — exit 2, and the harness refuses an exit
    ///   above 1 as neither the script's green nor its red. Those are exactly the rows
    ///   [`ROW_WORKFLOW`] and [`ROW_DECLARED_READABLE`] cover, so they too stay proven by selftest
    ///   rather than by parity. That refusal is right: reading an undocumented exit code as a
    ///   verdict is how a crashed gate reports a clean tree.
    ///
    /// What is left is [`ROW_DECLARED_CURRENT`] — the arm that runs on every branch and the one that
    /// catches a run-graph change at the commit that makes it. Three shapes of structural drift are
    /// planted, plus the property that makes this lint viable at all: a prose-only edit must move
    /// NEITHER implementation, because a byte comparison would deadlock every comment change until
    /// the next release.
    ///
    /// No probe can reach [`Self::write_declared`]. `run` reads and never writes, and the only paths
    /// any probe touches are the two materialized into the harness's scratch tree.
    fn parity_probes(&self, cx: &Ctx) -> Vec<crate::gates::ParityProbe> {
        let Ok(text) = cx.read(WORKFLOW) else {
            // The subject is absent, so there is nothing to plant INTO. An empty probe list is
            // refused by the harness, which is the right answer: parity is unproven here.
            return Vec::new();
        };

        let mut probes = Vec::new();
        let mut push = |label: &str, planted: String, expect_rule: Option<&str>| {
            let mut overlay = Overlay::new();
            overlay.set(WORKFLOW, planted);
            probes.push(crate::gates::ParityProbe {
                label: label.to_string(),
                overlay,
                materialize: vec![WORKFLOW.to_string(), DECLARED.to_string()],
                expect_rule: expect_rule.map(str::to_string),
                // The legacy's own sentence for the declared-shape arm. Deliberately the sentence
                // and not the gate's name: the script's `--write` hint contains the script's own
                // filename, so matching on that would have passed for every probe while proving
                // nothing about WHICH rule fired. The other arm's message reads "differs
                // STRUCTURALLY from the one on origin/main", so the two cannot be confused.
                legacy_names: expect_rule
                    .map(|_| "does not match the shape this branch declares in".to_string()),
                divergence: None,
            });
        };

        // A prose edit changes no structure, so both implementations must stay GREEN. This is the
        // discriminating half: an implementation that compared bytes would pass every probe below
        // and fail this one.
        push(
            "a comment-only edit to the dispatcher",
            format!("# a comment that changes nothing GitHub executes\n{text}"),
            None,
        );

        // Three different parts of the run graph, so parity is not asserted over one key. A gate
        // that only noticed `needs:` would agree with the legacy on every probe but the others.
        for (label, needle, replacement) in [
            (
                "a needs: edge is removed from the run graph",
                "needs: [build, fast]",
                "needs: [build]",
            ),
            (
                "the trigger's workflow list changes",
                "workflows: [\"CI\"]",
                "workflows: [\"CI\", \"Other\"]",
            ),
            (
                "a job's timeout is removed",
                "\n    timeout-minutes: 15\n",
                "\n",
            ),
        ] {
            if !text.contains(needle) {
                continue;
            }
            push(
                label,
                text.replacen(needle, replacement, 1),
                Some(ROW_DECLARED_CURRENT),
            );
        }

        probes
    }
}

/// The hermetic dispatcher used by the promotion-arm cases. Small on purpose: the arm being proven
/// is WHICH comparison a branch gets, and a fixture large enough to be interesting would only add
/// ways for the case to go red for a reason other than the one it names.
const FIXTURE_BASE: &str = "\
name: qa-gate
on:
  workflow_run:
    workflows: [\"CI\"]
    branches: [qa]
    types: [completed]
concurrency:
  group: qa-gate-fixture
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - run: echo build
  slow:
    needs: [build, fast]
    runs-on: ubuntu-latest
    steps:
      - run: echo slow
";

/// The real dispatcher with one `needs:` edge removed, or `None` if this tree no longer spells the
/// edge that way — in which case the case is UNPLANTABLE and says so, rather than passing.
fn graph_change(cx: &Ctx, path: &str) -> Option<String> {
    let text = cx.read(path).ok()?;
    let needle = "needs: [build, fast]";
    if !text.contains(needle) {
        return None;
    }
    Some(text.replacen(needle, "needs: [build]", 1))
}

fn plant<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    path: &str,
    edit: Edit,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    let mut ov = Overlay::new();
    if edit.apply(cx, path, &mut ov).is_err() {
        return unplantable(name, covers, naming).into();
    }
    prove_red(cx, gate, name, covers, ov, naming)
}

/// NOTHING TO PLANT — the rule's subject is absent from this tree — is a VISIBLE case in the
/// report, counted as unproven. Never a silent green.
fn unplantable(name: &str, covers: &[&str], naming: &[&str]) -> Case {
    Case {
        name: name.to_string(),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected: Expect::Red {
            naming: naming.iter().map(|s| (*s).to_string()).collect(),
        },
        got: Expect::Skipped,
    }
}

// ---------------------------------------------------------------------------------------------
// THE DECLARED SHAPE'S ON-DISK FORM.
//
// Sorted keys, two-space indent, ASCII-only, one trailing newline. The formatting is not a taste:
// the committed file is what a reviewer diffs, so a regeneration that reordered keys or re-encoded
// a character would produce a diff nobody can read and would make `--write` unusable as a
// no-op-when-current operation.
// ---------------------------------------------------------------------------------------------

/// The declared shape's on-disk form.
pub fn canonical(shape: &Value) -> String {
    let mut out = String::new();
    write_value(shape, 0, &mut out);
    out.push('\n');
    out
}

fn write_value(value: &Value, level: usize, out: &mut String) {
    match value {
        Value::Object(map) => write_object(map, level, out),
        Value::Array(items) => write_array(items, level, out),
        Value::String(s) => write_string(s, out),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::Null => out.push_str("null"),
    }
}

fn write_object(map: &Map<String, Value>, level: usize, out: &mut String) {
    if map.is_empty() {
        out.push_str("{}");
        return;
    }
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    out.push_str("{\n");
    for (n, key) in keys.iter().enumerate() {
        if n > 0 {
            out.push_str(",\n");
        }
        indent(level + 1, out);
        write_string(key, out);
        out.push_str(": ");
        write_value(&map[*key], level + 1, out);
    }
    out.push('\n');
    indent(level, out);
    out.push('}');
}

fn write_array(items: &[Value], level: usize, out: &mut String) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (n, item) in items.iter().enumerate() {
        if n > 0 {
            out.push_str(",\n");
        }
        indent(level + 1, out);
        write_value(item, level + 1, out);
    }
    out.push('\n');
    indent(level, out);
    out.push(']');
}

fn indent(level: usize, out: &mut String) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// A JSON string, ASCII-only. Everything outside printable ASCII is escaped, so the committed file
/// is byte-stable across locales and editors and an invisible character cannot hide in a run graph.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let v = cp - 0x1_0000;
                    out.push_str(&format!("\\u{:04x}", 0xD800 + (v >> 10)));
                    out.push_str(&format!("\\u{:04x}", 0xDC00 + (v & 0x3FF)));
                }
            }
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------------------------
// THE COMPARISON.
// ---------------------------------------------------------------------------------------------

/// Every path at which two structures disagree, as dotted keys.
///
/// Reported as PATHS rather than as a text diff because the useful question is WHICH part of the
/// run graph moved — `on.workflow_run.workflows` and a `needs:` edge are very different problems,
/// and a unified diff of re-serialised documents buries that under formatting noise.
fn diff_paths(a: &Value, b: &Value, path: &str, other: &str) -> Vec<String> {
    if kind(a) != kind(b) {
        return vec![format!(
            "{}: type {} vs {}",
            if path.is_empty() { "(root)" } else { path },
            kind(a),
            kind(b)
        )];
    }

    if let (Value::Object(x), Value::Object(y)) = (a, b) {
        let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
        keys.sort();
        keys.dedup();
        let mut out = Vec::new();
        for key in keys {
            let here = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            match (x.get(key), y.get(key)) {
                (None, _) => out.push(format!(
                    "{here}: missing on this commit, present in {other}"
                )),
                (_, None) => out.push(format!(
                    "{here}: present on this commit, missing in {other}"
                )),
                (Some(l), Some(r)) => out.extend(diff_paths(l, r, &here, other)),
            }
        }
        return out;
    }

    if let (Value::Array(x), Value::Array(y)) = (a, b) {
        if x.len() != y.len() {
            return vec![format!(
                "{path}: {} entries here vs {} in {other}",
                x.len(),
                y.len()
            )];
        }
        let mut out = Vec::new();
        for (i, (l, r)) in x.iter().zip(y.iter()).enumerate() {
            out.extend(diff_paths(l, r, &format!("{path}[{i}]"), other));
        }
        return out;
    }

    if a == b {
        Vec::new()
    } else {
        vec![format!(
            "{path}: {} here vs {} in {other}",
            render(a),
            render(b)
        )]
    }
}

/// The type name a difference is reported by. A boolean and a number are DIFFERENT kinds even
/// where one could be read as the other: `timeout-minutes: 0` and `timeout-minutes: false` are not
/// the same run graph.
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Object(_) => "dict",
        Value::Array(_) => "list",
        Value::String(_) => "str",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if n.is_f64() {
                "float"
            } else {
                "int"
            }
        }
        Value::Null => "NoneType",
    }
}

/// A scalar as a difference message spells it: quoted if it is a string, so `"90"` and `90` cannot
/// read as the same value in a report a human is meant to act on.
fn render(v: &Value) -> String {
    match v {
        Value::String(s) => {
            let quote = if s.contains('\'') && !s.contains('"') {
                '"'
            } else {
                '\''
            };
            let mut out = String::new();
            out.push(quote);
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    c => out.push(c),
                }
            }
            out.push(quote);
            out
        }
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates;

    fn cx() -> Ctx {
        Ctx::workspace().expect("the workspace context must open")
    }

    #[test]
    fn the_real_tree_is_green_through_the_runner() {
        let gate = QaGateDispatchGate::new();
        let verdict = gates::execute(&gate, &cx());
        assert!(
            !verdict.red,
            "qa-gate-dispatch is red on this tree: {:?}",
            verdict.problems
        );
        assert_eq!(verdict.rows.len(), gate.owed().len());
    }

    #[test]
    fn the_selftest_proves_every_owed_row_can_still_be_red() {
        let gate = QaGateDispatchGate::new();
        let cx = cx();
        let report = gate.selftest(&cx);
        if let Err(errs) = gates::verify_report(&gate, &report) {
            panic!("qa-gate-dispatch selftest: {errs:#?}");
        }
        assert_eq!(
            report.skipped(),
            0,
            "every case must have had something to plant"
        );
    }

    /// The probes must actually plant something, and each must move the gate the way it claims.
    /// The harness proves the two IMPLEMENTATIONS agree; this proves the probe list is not a set of
    /// plants that leave this side green, which would make the agreement vacuous on our half.
    #[test]
    fn every_parity_probe_moves_this_gate_the_way_it_declares() {
        let cx = cx();
        let gate = QaGateDispatchGate::new();
        let probes = gate.parity_probes(&cx);
        assert_eq!(probes.len(), 4, "the probe list lost an entry");
        for probe in &probes {
            assert!(
                probe.materialize.contains(&WORKFLOW.to_string())
                    && probe.materialize.contains(&DECLARED.to_string()),
                "{}: a path the legacy is not shown is a path it reads out of the real repository",
                probe.label
            );
            let verdict = gates::execute(&gate, &cx.with_overlay(probe.overlay.clone()));
            match &probe.expect_rule {
                Some(rule) => {
                    assert!(verdict.red, "{}: expected RED", probe.label);
                    assert!(
                        verdict
                            .problems
                            .iter()
                            .any(|p| p.starts_with(rule.as_str())),
                        "{}: went red without naming {rule} ({:?})",
                        probe.label,
                        verdict.problems
                    );
                }
                None => assert!(
                    !verdict.red,
                    "{}: expected green, got {:?}",
                    probe.label, verdict.problems
                ),
            }
        }
    }

    /// THE WRITER IS THE FILE. If regenerating the declared shape produced different bytes, every
    /// `--write` would show a diff nobody made and the artifact would stop being reviewable.
    #[test]
    fn the_writer_reproduces_the_committed_declared_shape_byte_for_byte() {
        let cx = cx();
        let workflow = cx.read(WORKFLOW).expect("the dispatcher must be readable");
        let committed = cx
            .read(DECLARED)
            .expect("the declared shape must be readable");
        let shape = yaml_lite::parse_structure(&workflow).expect("the dispatcher must parse");
        let regenerated = canonical(&shape);
        assert_eq!(
            regenerated, committed,
            "regenerating {DECLARED} from {WORKFLOW} did not reproduce the committed bytes"
        );
    }

    #[test]
    fn a_matching_dispatcher_is_green_on_a_promotion_branch_too() {
        let shape = yaml_lite::parse_structure(FIXTURE_BASE).unwrap();
        let mut ov = Overlay::new();
        ov.set(WORKFLOW, FIXTURE_BASE);
        ov.set(DECLARED, canonical(&shape));
        let gate = QaGateDispatchGate::judging_as("qa", DEFAULT_BRANCH_REF, Some(FIXTURE_BASE));
        let verdict = gates::execute(&gate, &cx().with_overlay(ov));
        assert!(
            !verdict.red,
            "a dispatcher matching BOTH its declared shape and the default branch must be green \
             on qa: {:?}",
            verdict.problems
        );
    }

    /// The deadlock this gate's shape exists to break: a development branch whose dispatcher
    /// matches its OWN declared shape is green even though the default branch has not been
    /// promoted yet.
    #[test]
    fn a_development_branch_is_green_against_an_unpromoted_default_branch() {
        let changed = FIXTURE_BASE.replace("needs: [build, fast]", "needs: [build]");
        let shape = yaml_lite::parse_structure(&changed).unwrap();
        let mut ov = Overlay::new();
        ov.set(WORKFLOW, changed);
        ov.set(DECLARED, canonical(&shape));
        let gate = QaGateDispatchGate::judging_as(
            "integration/some-branch",
            DEFAULT_BRANCH_REF,
            Some(FIXTURE_BASE),
        );
        let verdict = gates::execute(&gate, &cx().with_overlay(ov));
        assert!(!verdict.red, "{:?}", verdict.problems);
    }

    /// The other half of the same split: the promotion arm is never merely absent. A row is emitted
    /// on every branch, and on a development branch it says which arm ran and why.
    #[test]
    fn the_promotion_arm_reports_a_row_on_a_branch_that_cannot_answer_it() {
        let gate =
            QaGateDispatchGate::judging_as("integration/some-branch", DEFAULT_BRANCH_REF, None);
        let verdict = gates::execute(&gate, &cx());
        let row = verdict
            .rows
            .iter()
            .find(|r| r.id == ROW_DEFAULT_BRANCH)
            .expect("the promotion arm must emit a row on every branch");
        assert_eq!(row.status, crate::ledger::Status::Pass);
        assert!(row.detail.contains("integration/some-branch"), "{row:?}");
        assert!(row.detail.contains(DEFAULT_BRANCH_REF), "{row:?}");
    }

    #[test]
    fn a_run_graph_change_is_caught_on_a_development_branch() {
        let changed = FIXTURE_BASE.replace("needs: [build, fast]", "needs: [build]");
        let shape = yaml_lite::parse_structure(FIXTURE_BASE).unwrap();
        let mut ov = Overlay::new();
        ov.set(WORKFLOW, changed);
        ov.set(DECLARED, canonical(&shape));
        let gate = QaGateDispatchGate::judging_as(
            "integration/some-branch",
            DEFAULT_BRANCH_REF,
            Some(FIXTURE_BASE),
        );
        let verdict = gates::execute(&gate, &cx().with_overlay(ov));
        assert!(verdict.red);
        assert!(verdict
            .problems
            .iter()
            .any(|p| p.contains(ROW_DECLARED_CURRENT)));
    }

    #[test]
    fn a_comment_only_change_is_not_a_difference() {
        let base = yaml_lite::parse_structure(FIXTURE_BASE).unwrap();
        let commented =
            yaml_lite::parse_structure(&format!("# a fresh comment\n{FIXTURE_BASE}")).unwrap();
        assert!(diff_paths(&base, &commented, "", "the other side").is_empty());
    }

    #[test]
    fn the_difference_paths_name_what_moved() {
        let base = yaml_lite::parse_structure(FIXTURE_BASE).unwrap();
        for (changed, want) in [
            ("needs: [build, fast]", "jobs.slow.needs"),
            ("branches: [qa]", "on.workflow_run.branches"),
            ("    timeout-minutes: 90\n", "jobs.build"),
        ] {
            let text = if changed.ends_with('\n') {
                FIXTURE_BASE.replace(changed, "")
            } else {
                FIXTURE_BASE.replace(changed, "needs: [build]")
            };
            let other = yaml_lite::parse_structure(&text).unwrap();
            let diff = diff_paths(&base, &other, "", "the other side");
            assert!(
                diff.iter().any(|d| d.starts_with(want)),
                "{changed:?} should have been reported under {want}, got {diff:?}"
            );
        }
    }

    #[test]
    fn a_whole_job_removed_is_a_difference() {
        let base = yaml_lite::parse_structure(FIXTURE_BASE).unwrap();
        let trimmed = FIXTURE_BASE.split("  slow:").next().unwrap().to_string();
        let other = yaml_lite::parse_structure(&trimmed).unwrap();
        let diff = diff_paths(&base, &other, "", "the other side");
        assert!(diff.iter().any(|d| d.contains("jobs.slow")), "{diff:?}");
    }

    #[test]
    fn non_ascii_is_escaped_the_way_the_committed_file_spells_it() {
        let mut map = Map::new();
        map.insert("k".to_string(), Value::from("qa\u{2192}main"));
        assert_eq!(
            canonical(&Value::Object(map)),
            "{\n  \"k\": \"qa\\u2192main\"\n}\n"
        );
    }

    #[test]
    fn empty_collections_and_scalars_round_trip() {
        let v: Value = serde_json::from_str(r#"{"a":{},"b":[],"c":0,"d":true,"e":null}"#).unwrap();
        assert_eq!(
            canonical(&v),
            "{\n  \"a\": {},\n  \"b\": [],\n  \"c\": 0,\n  \"d\": true,\n  \"e\": null\n}\n"
        );
    }
}
