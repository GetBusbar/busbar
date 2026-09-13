//! `cargo xtask gate ci-umbrella` — EVERY JOB IN `ci.yml` IS GATED BY THE UMBRELLA, OR DECLARED
//! NON-GATING IN WRITING. The Rust successor to `scripts/ci-umbrella-lint.py`.
//!
//! WHY THIS EXISTS. `ci-umbrella` is the single required check: it is the job branch protection
//! points at, and its `needs:` list is the whole of what "CI is green" means. That list is
//! maintained BY HAND, one entry per job, in a file where jobs are added by people thinking about
//! the new job and not about the umbrella. The failure is silent and total: add an enforcement job,
//! forget the `needs:` line, and the umbrella reports GREEN on a run in which that job failed —
//! because a job that is not in `needs` is not a job the umbrella has ever heard of. That is not
//! hypothetical: `deletion-test-matrix`, the gate proving the neutral crates still compile with a
//! plane removed, sat outside `needs` for its whole life.
//!
//! So membership is DERIVED and ASSERTED rather than remembered. The declarations that permit a
//! deliberate exclusion are COMMENTS —
//!
//! ```text
//! # non-gating:  <job-key> -- <reason, at least 30 characters>
//! # report-only: <job-key> -- <reason, at least 30 characters>
//! ```
//!
//! — which is why this gate reads the workflow BOTH as a parsed document (jobs, `needs:`, the
//! umbrella's `env.RESULTS` ledger, each job's `if:` guard) and as TEXT. A YAML parser drops
//! comments, and the comments are half the contract.
//!
//! THE RULES, each its own ledger row:
//!
//! 1. [`ROW_WORKFLOW`] — `.github/workflows/ci.yml` is readable and parses to a workflow with jobs.
//!    An unreadable file must never read as a clean one.
//! 2. [`ROW_UMBRELLA`] — the `ci-umbrella` job exists. No umbrella is not a pass.
//! 3. [`ROW_MEMBERSHIP`] — every job is in the umbrella's `needs`, or declared `# non-gating:`.
//! 4. [`ROW_SCORED`] — every job in `needs` has a RESULTS row, or is declared `# report-only:`
//!    (waited for and printed, deliberately not counted).
//! 5. [`ROW_DECL_LIVE`] — a declaration names a job that exists. A stale exemption outlives the job
//!    it excused and silently excuses the next one to take the name.
//! 6. [`ROW_DECL_REASON`] — a declaration carries a reason of at least [`MIN_REASON`] characters.
//!    An exemption without a reason becomes permanent by accident.
//! 7. [`ROW_ROW_SHAPE`] — every RESULTS line is `jobkey|tier|${{ needs.<job>.result }}`.
//! 8. [`ROW_LABEL`] — a RESULTS row's label and the job it reads agree, so the printed name is the
//!    measured one.
//! 9. [`ROW_REF_JOB`] — a RESULTS row scores a job that exists.
//! 10. [`ROW_REF_NEEDS`] — a RESULTS row scores a job that is in `needs`. `needs.X.result` for an X
//!     that is not a dependency evaluates to the empty string, which is neither "success" nor a
//!     recognised skip.
//! 11. [`ROW_TIER`] — TIER IFF FULL-TIER GUARD. A RESULTS row's tier is `full` exactly when the job
//!     it scores carries the full-tier `if:` guard the umbrella's own `FULL_TIER` expression
//!     mirrors. The tier column is not a label: the umbrella forgives `skipped` only for a `full`
//!     row on a fast-tier run. A guarded job labelled `fast` reddens every fast-tier run for doing
//!     what it was told; an unguarded job labelled `full` has its real skip forgiven, which is the
//!     required check quietly not requiring it.
//! 12. [`ROW_JOBS_FLOOR`], 13. [`ROW_NEEDS_FLOOR`], 14. [`ROW_RESULTS_FLOOR`] — THE FLOORS.
//!     A reader that matched nothing reports a clean file; a `needs` list that shrank is a required
//!     check that stopped requiring things; an unread ledger scores nothing and prints GREEN. Each
//!     floor is a `const` here with no environment override, and each is proven to bite ON ITS OWN
//!     in [`Gate::selftest`] — proving them together proves only that at least one fired, and the
//!     jobs floor alone fires on every stub small enough to write by hand.

use std::collections::BTreeSet;

use crate::ctx::{Ctx, Edit, Overlay};
use crate::gates::{prove_green, prove_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::yaml_lite;

pub const WORKFLOW: &str = ".github/workflows/ci.yml";
pub const UMBRELLA: &str = "ci-umbrella";

pub const ROW_WORKFLOW: &str = "ci-umbrella:workflow-readable";
pub const ROW_UMBRELLA: &str = "ci-umbrella:umbrella-job-present";
pub const ROW_MEMBERSHIP: &str = "ci-umbrella:membership";
pub const ROW_SCORED: &str = "ci-umbrella:needs-scored";
pub const ROW_DECL_LIVE: &str = "ci-umbrella:declaration-names-a-live-job";
pub const ROW_DECL_REASON: &str = "ci-umbrella:declaration-reason";
pub const ROW_ROW_SHAPE: &str = "ci-umbrella:results-row-shape";
pub const ROW_LABEL: &str = "ci-umbrella:results-label-matches-job";
pub const ROW_REF_JOB: &str = "ci-umbrella:results-scores-a-real-job";
pub const ROW_REF_NEEDS: &str = "ci-umbrella:results-scores-a-dependency";
pub const ROW_TIER: &str = "ci-umbrella:results-tier-matches-guard";
pub const ROW_JOBS_FLOOR: &str = "ci-umbrella:jobs-floor";
pub const ROW_NEEDS_FLOOR: &str = "ci-umbrella:needs-floor";
pub const ROW_RESULTS_FLOOR: &str = "ci-umbrella:results-floor";

/// The floors, each well below today's real count. They exist so a reader that matched nothing
/// fails loudly rather than passes vacuously. Deliberately NOT overridable from the environment: a
/// floor a caller can lower is a floor a caller can turn off, and the self-test below drives each
/// one by planting a workflow that is genuinely too small, never by moving the number.
const MIN_JOBS: usize = 20;
const MIN_NEEDS: usize = 15;
const MIN_RESULTS: usize = 15;
/// The shortest exemption reason that is a reason rather than a shrug.
const MIN_REASON: usize = 30;

pub struct CiUmbrellaGate;

/// One `# non-gating:` / `# report-only:` declaration comment.
#[derive(Debug, Clone)]
struct Declaration {
    kind: &'static str,
    job: String,
    reason: String,
}

/// One line of the umbrella's `RESULTS` ledger. `parsed` is `None` when the line does not have the
/// `jobkey|tier|${{ needs.<job>.result }}` shape — an unparsed line is a row that scores nothing,
/// so it is kept and named rather than dropped.
#[derive(Debug, Clone)]
struct ResultRow {
    raw: String,
    parsed: Option<(String, String, String)>,
}

impl Gate for CiUmbrellaGate {
    fn name(&self) -> &'static str {
        "ci-umbrella"
    }

    fn owed(&self) -> Vec<String> {
        OWED.iter().map(|s| (*s).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let text = match cx.read(WORKFLOW) {
            Ok(t) => t,
            Err(e) => {
                return Verdict::of(all_fail(
                    "ci.yml could not be read",
                    format!("{e} — a workflow nobody could read is not a workflow with no jobs"),
                ))
            }
        };
        let wf = match yaml_lite::parse_workflow(&text) {
            Ok(w) => w,
            Err(e) => {
                return Verdict::of(all_fail(
                    "ci.yml has no readable `jobs:` mapping",
                    format!("{e} — refusing to report a clean file from an unread one"),
                ))
            }
        };

        let mut rows = vec![Row::pass(
            ROW_WORKFLOW,
            "ci.yml parses to a workflow with jobs",
            format!("{WORKFLOW}: {} job(s)", wf.jobs().len()),
        )];

        let jobs: Vec<String> = wf.job_names();
        rows.push(rule_jobs_floor(&jobs));

        let decls = declarations(&text);
        rows.push(rule_decl_live(&decls, &jobs));
        rows.push(rule_decl_reason(&decls));

        let non_gating: BTreeSet<String> = decls
            .iter()
            .filter(|d| d.kind == "non-gating")
            .map(|d| d.job.clone())
            .collect();
        let report_only: BTreeSet<String> = decls
            .iter()
            .filter(|d| d.kind == "report-only")
            .map(|d| d.job.clone())
            .collect();

        let Some(umbrella) = wf.job(UMBRELLA) else {
            rows.push(Row::fail(
                ROW_UMBRELLA,
                format!("there is no `{UMBRELLA}` job"),
                "the single required check is gone: nothing branch protection points at waits for \
                 anything, and every job's red reports GREEN",
            ));
            rows.extend(fail_umbrella_dependent(format!(
                "there is no `{UMBRELLA}` job to read this from"
            )));
            return Verdict::of(rows);
        };
        rows.push(Row::pass(
            ROW_UMBRELLA,
            format!("the `{UMBRELLA}` job is present"),
            "the single required check exists and can be read",
        ));

        let needs: BTreeSet<String> = umbrella.needs.iter().cloned().collect();
        rows.push(rule_needs_floor(&needs));
        rows.push(rule_membership(&jobs, &needs, &non_gating));

        let results = results_rows(umbrella);
        rows.push(rule_results_floor(&results));
        rows.push(rule_row_shape(&results));
        rows.push(rule_label(&results));
        rows.push(rule_ref_job(&results, &jobs));
        rows.push(rule_ref_needs(&results, &jobs, &needs));
        rows.push(rule_tier(&results, &wf));
        rows.push(rule_scored(&results, &needs, &report_only));

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the tree's own ci.yml is wired to its umbrella",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // AN UNREADABLE WORKFLOW IS NOT A CLEAN ONE.
        report.push(plant(
            cx,
            self,
            "ci.yml is empty",
            &[ROW_WORKFLOW],
            Edit::Replace(String::new()),
            &["empty workflow"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "the umbrella job is renamed away",
            &[ROW_UMBRELLA],
            &format!("\n  {UMBRELLA}:\n"),
            "\n  not-the-umbrella:\n",
            &[&format!("there is no `{UMBRELLA}` job")],
        ));

        // THE HISTORICAL DEFECT, RE-PLANTED: a job the umbrella never waits for.
        report.push(plant(
            cx,
            self,
            "a job outside needs, undeclared",
            &[ROW_MEMBERSHIP],
            Edit::Append(
                "\n  planted-ungated-job:\n    runs-on: ubuntu-latest\n    steps:\n      - run: \
                 true\n"
                    .to_string(),
            ),
            &["planted-ungated-job"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "a needs entry with no RESULTS row",
            &[ROW_SCORED],
            "        teller-steps|full|${{ needs.teller-steps.result }}\n",
            "",
            &["teller-steps", "has no RESULTS row"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "an exemption for a job that no longer exists",
            &[ROW_DECL_LIVE],
            "# non-gating: coverage --",
            "# non-gating: coverage-ghost --",
            &["coverage-ghost", "names a job that does not exist"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "an exemption with no reason",
            &[ROW_DECL_REASON],
            "# non-gating: coverage -- a REPORTING job (it uploads to Codecov and asserts no \
             threshold here);",
            "# non-gating: coverage -- brief",
            &["5-character reason"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "a RESULTS line that is not jobkey|tier|result",
            &[ROW_ROW_SHAPE],
            "gate-tier|fast|${{ needs.gate-tier.result }}",
            "gate-tier|${{ needs.gate-tier.result }}",
            &["is not `jobkey|tier|"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "a label that scores a different job",
            &[ROW_LABEL],
            "structure-lint|fast|${{ needs.structure-lint.result }}",
            "structure-lint|fast|${{ needs.check.result }}",
            &["structure-lint", "the label and the job it scores disagree"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "a RESULTS row that scores a job that does not exist",
            &[ROW_REF_JOB],
            "design-bindings|fast|${{ needs.design-bindings.result }}",
            "design-bindings|fast|${{ needs.ghost-job.result }}",
            &["ghost-job", "is not a job in"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "a RESULTS row for a job the umbrella does not wait for",
            &[ROW_REF_NEEDS],
            "design-bindings|fast|${{ needs.design-bindings.result }}",
            "design-bindings|fast|${{ needs.design-bindings.result }}\n        \
             proof-manifest|fast|${{ needs.proof-manifest.result }}",
            &["proof-manifest", "is NOT in"],
        ));

        report.push(plant_subst(
            cx,
            self,
            "a full-tier-guarded job scored as fast tier",
            &[ROW_TIER],
            "windows|full|${{ needs.windows.result }}",
            "windows|fast|${{ needs.windows.result }}",
            &["windows", "carries the full-tier guard"],
        ));

        // THE THREE FLOORS, EACH DRIVEN ALONE. Each case plants a workflow that is genuinely under
        // ONE floor and is checked by THAT floor's own message, so a floor that stopped biting is
        // named rather than covered for by its neighbour.
        report.push(prove_red(
            cx,
            self,
            "the JOBS floor bites on its own",
            &[ROW_JOBS_FLOOR],
            overlay_of(synthetic(MIN_JOBS - 1, MIN_NEEDS, MIN_RESULTS)),
            &[&format!(
                "only {} job(s) parsed (floor {MIN_JOBS})",
                MIN_JOBS - 1
            )],
        ));
        // The needs floor cannot be planted without also shortening the ledger: a RESULTS row must
        // score a dependency, so 14 dependencies can carry at most 14 rows. The case is therefore
        // discriminated by the needs floor's OWN message, which the results floor never prints.
        report.push(prove_red(
            cx,
            self,
            "the NEEDS floor bites on its own",
            &[ROW_NEEDS_FLOOR],
            overlay_of(synthetic(MIN_JOBS, MIN_NEEDS - 1, MIN_NEEDS - 1)),
            &[&format!(
                "lists {} job(s) (floor {MIN_NEEDS})",
                MIN_NEEDS - 1
            )],
        ));
        report.push(prove_red(
            cx,
            self,
            "the RESULTS floor bites on its own",
            &[ROW_RESULTS_FLOOR],
            overlay_of(synthetic(MIN_JOBS, MIN_NEEDS, MIN_RESULTS - 1)),
            &[&format!(
                "ledger has {} row(s) (floor {MIN_RESULTS})",
                MIN_RESULTS - 1
            )],
        ));

        report
    }

    /// THE SAME PLANTS, DRIVEN THROUGH BOTH IMPLEMENTATIONS.
    ///
    /// Every probe below is the overlay one self-test case already builds, so the tree the parity
    /// harness compares over is the tree the gate is proven on and not a second description of it.
    /// The legacy lint is pointed at the planted tree with `--root`, and reads exactly one file, so
    /// `materialize` is exactly that file.
    ///
    /// ON THE RULE NAME. `expect_rule` is checked against the LEGACY SCRIPT'S OUTPUT as well as the
    /// gate's problems, and `ci-umbrella-lint.py` prints prose findings and never a row id — it has
    /// no ledger at all, which is why this gate's ids are new rather than inherited. So these
    /// probes prove the two agree on the VERDICT for each planted violation, and the rule-name half
    /// of the harness's contract cannot be met by a legacy lint that names no rules. That is
    /// reported rather than dodged: the ids stay the gate's real owed ids.
    fn parity_probes(&self, cx: &Ctx) -> Vec<crate::gates::ParityProbe> {
        let mut out = Vec::new();
        // Each probe carries the LEGACY's own wording for the same rule. The Python prints prose
        // and never a row id, so without this the comparison would degrade into "both went red
        // somehow" -- which two implementations can do for two different reasons.
        let mut push = |label: &str, rule: &str, legacy: &str, overlay: Result<Overlay, String>| {
            if let Ok(overlay) = overlay {
                out.push(
                    crate::gates::ParityProbe::red(
                        label,
                        overlay,
                        vec![WORKFLOW.to_string()],
                        rule,
                    )
                    .named_by(legacy),
                );
            }
        };

        push(
            "ci.yml is empty",
            ROW_WORKFLOW,
            "has no `jobs:` mapping -- refusing to report a clean file from an unread one",
            Ok(overlay_of(String::new())),
        );
        push(
            "the umbrella job is renamed away",
            ROW_UMBRELLA,
            "the single required check is gone",
            subst_overlay(cx, &format!("\n  {UMBRELLA}:\n"), "\n  not-the-umbrella:\n"),
        );
        push(
            "a job outside needs, undeclared",
            ROW_MEMBERSHIP,
            "is not declared non-gating",
            cx.read(WORKFLOW).map(|text| {
                overlay_of(format!(
                    "{text}\n  planted-ungated-job:\n    runs-on: ubuntu-latest\n    steps:\n      \
                     - run: true\n"
                ))
            }),
        );
        push(
            "a needs entry with no RESULTS row",
            ROW_SCORED,
            "but has no RESULTS row",
            subst_overlay(
                cx,
                "        teller-steps|full|${{ needs.teller-steps.result }}\n",
                "",
            ),
        );
        push(
            "an exemption for a job that no longer exists",
            ROW_DECL_LIVE,
            "names a job that does not exist in ci.yml",
            subst_overlay(
                cx,
                "# non-gating: coverage --",
                "# non-gating: coverage-ghost --",
            ),
        );
        push(
            "an exemption with no reason",
            ROW_DECL_REASON,
            "-character reason (floor",
            subst_overlay(
                cx,
                "# non-gating: coverage -- a REPORTING job (it uploads to Codecov and asserts no \
                 threshold here);",
                "# non-gating: coverage -- brief",
            ),
        );
        push(
            "a RESULTS line that is not jobkey|tier|result",
            ROW_ROW_SHAPE,
            "RESULTS row is not `jobkey|tier|",
            subst_overlay(
                cx,
                "gate-tier|fast|${{ needs.gate-tier.result }}",
                "gate-tier|${{ needs.gate-tier.result }}",
            ),
        );
        push(
            "a label that scores a different job",
            ROW_LABEL,
            "the label and the job it scores disagree",
            subst_overlay(
                cx,
                "structure-lint|fast|${{ needs.structure-lint.result }}",
                "structure-lint|fast|${{ needs.check.result }}",
            ),
        );
        push(
            "a RESULTS row that scores a job that does not exist",
            ROW_REF_JOB,
            "which is not a job in ci.yml.",
            subst_overlay(
                cx,
                "design-bindings|fast|${{ needs.design-bindings.result }}",
                "design-bindings|fast|${{ needs.ghost-job.result }}",
            ),
        );
        push(
            "a RESULTS row for a job the umbrella does not wait for",
            ROW_REF_NEEDS,
            "is the empty string there, not a verdict",
            subst_overlay(
                cx,
                "design-bindings|fast|${{ needs.design-bindings.result }}",
                "design-bindings|fast|${{ needs.design-bindings.result }}\n        \
                 proof-manifest|fast|${{ needs.proof-manifest.result }}",
            ),
        );
        push(
            "the JOBS floor bites on its own",
            ROW_JOBS_FLOOR,
            "job(s) parsed (floor",
            Ok(overlay_of(synthetic(MIN_JOBS - 1, MIN_NEEDS, MIN_RESULTS))),
        );
        push(
            "the NEEDS floor bites on its own",
            ROW_NEEDS_FLOOR,
            "job(s) (floor",
            Ok(overlay_of(synthetic(
                MIN_JOBS,
                MIN_NEEDS - 1,
                MIN_NEEDS - 1,
            ))),
        );
        push(
            "the RESULTS floor bites on its own",
            ROW_RESULTS_FLOOR,
            "row(s) (floor",
            Ok(overlay_of(synthetic(MIN_JOBS, MIN_NEEDS, MIN_RESULTS - 1))),
        );

        // THE TIER RULE HAS NO LEGACY HALF. The conversion introduced it: `ci-umbrella-lint.py`
        // asserts only that a RESULTS row carries `fast` or `full`, never that the tier agrees with
        // the job's guard. A probe for it would assert that the legacy script reds on something it
        // was never taught, which is a false parity failure rather than a finding — so the rule is
        // proven by [`Gate::selftest`] alone and named here as the one rule parity cannot cover.
        out
    }
}

/// Every row id this gate can emit, in the order it emits them.
const OWED: &[&str] = &[
    ROW_WORKFLOW,
    ROW_UMBRELLA,
    ROW_MEMBERSHIP,
    ROW_SCORED,
    ROW_DECL_LIVE,
    ROW_DECL_REASON,
    ROW_ROW_SHAPE,
    ROW_LABEL,
    ROW_REF_JOB,
    ROW_REF_NEEDS,
    ROW_TIER,
    ROW_JOBS_FLOOR,
    ROW_NEEDS_FLOOR,
    ROW_RESULTS_FLOOR,
];

/// The rows that can only be decided by reading the umbrella job itself.
const UMBRELLA_DEPENDENT: &[&str] = &[
    ROW_MEMBERSHIP,
    ROW_SCORED,
    ROW_ROW_SHAPE,
    ROW_LABEL,
    ROW_REF_JOB,
    ROW_REF_NEEDS,
    ROW_TIER,
    ROW_NEEDS_FLOOR,
    ROW_RESULTS_FLOOR,
];

/// Every owed row as a FAIL. The gate owes a row for every rule on every run: a rule that could not
/// be evaluated DID NOT RUN, and a check that did not run is not a check that passed.
fn all_fail(title: impl Into<String>, detail: impl Into<String>) -> Vec<Row> {
    let (title, detail) = (title.into(), detail.into());
    OWED.iter()
        .map(|id| Row::fail(*id, title.clone(), detail.clone()))
        .collect()
}

fn fail_umbrella_dependent(detail: String) -> Vec<Row> {
    UMBRELLA_DEPENDENT
        .iter()
        .map(|id| {
            Row::fail(
                *id,
                "the umbrella's wiring could not be read",
                detail.clone(),
            )
        })
        .collect()
}

// ── the readers ─────────────────────────────────────────────────────────────────────────────────

/// Every `# non-gating:` / `# report-only:` declaration in the file, wherever it sits. These are
/// COMMENTS: they survive no YAML parse, so they are read from the text, and the shape is the one
/// the Python's `DECL_RE` accepted — `# <kind>: <job-key> <-- | — | - | :> <reason>`.
fn declarations(text: &str) -> Vec<Declaration> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some((kind, rest)) = ["non-gating", "report-only"]
            .iter()
            .find_map(|k| rest.strip_prefix(k).map(|r| (*k, r)))
        else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim_start();
        let job_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'))
            .unwrap_or(rest.len());
        let (job, rest) = rest.split_at(job_len);
        if job.is_empty() {
            continue;
        }
        // The separator, in the four spellings the declaration grammar accepts. `--` is tried
        // before `-` so a `--` never reads as a `-` followed by a reason starting with `-`.
        let rest = rest.trim_start();
        let Some(reason) = ["--", "—", "-", ":"]
            .iter()
            .find_map(|sep| rest.strip_prefix(sep))
        else {
            continue;
        };
        let reason = reason.trim();
        if reason.is_empty() {
            continue;
        }
        out.push(Declaration {
            kind,
            job: job.to_string(),
            reason: reason.to_string(),
        });
    }
    out
}

/// The umbrella's `RESULTS` ledger, one entry per non-blank line.
fn results_rows(umbrella: &yaml_lite::Job) -> Vec<ResultRow> {
    let raw = umbrella.env.get("RESULTS").cloned().unwrap_or_default();
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| ResultRow {
            raw: l.trim().to_string(),
            parsed: parse_result_row(l.trim()),
        })
        .collect()
}

/// `jobkey|tier|${{ needs.<job>.result }}`, and nothing looser. The tier is `fast` or `full`
/// because those are the only two the umbrella's own reader understands.
fn parse_result_row(line: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() != 3 {
        return None;
    }
    let job = parts[0].trim();
    let tier = parts[1].trim();
    if !is_job_key(job) || !(tier == "fast" || tier == "full") {
        return None;
    }
    let expr = parts[2].trim();
    let inner = expr.strip_prefix("${{")?.strip_suffix("}}")?.trim();
    let referenced = inner.strip_prefix("needs.")?.strip_suffix(".result")?;
    if !is_job_key(referenced) {
        return None;
    }
    Some((job.to_string(), tier.to_string(), referenced.to_string()))
}

fn is_job_key(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Whether a job carries the FULL-TIER GUARD: the `if:` expression the umbrella's `FULL_TIER` env
/// mirrors — everything except a push, plus pushes to the three promotion branches.
fn is_full_tier_guarded(cond: Option<&String>) -> bool {
    let Some(cond) = cond else { return false };
    let flat = cond.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.contains("github.event_name != 'push'") && flat.contains("refs/heads/main")
}

// ── the rules ───────────────────────────────────────────────────────────────────────────────────

fn rule_jobs_floor(jobs: &[String]) -> Row {
    if jobs.len() >= MIN_JOBS {
        Row::pass(
            ROW_JOBS_FLOOR,
            "the reader parsed a plausible number of jobs",
            format!("{} job(s), floor {MIN_JOBS}", jobs.len()),
        )
    } else {
        Row::fail(
            ROW_JOBS_FLOOR,
            format!("only {} job(s) parsed (floor {MIN_JOBS})", jobs.len()),
            "a reader that sees almost no jobs reports almost no omissions; that is not a pass",
        )
    }
}

fn rule_needs_floor(needs: &BTreeSet<String>) -> Row {
    if needs.len() >= MIN_NEEDS {
        Row::pass(
            ROW_NEEDS_FLOOR,
            "the umbrella waits for a plausible number of jobs",
            format!("{} dependencies, floor {MIN_NEEDS}", needs.len()),
        )
    } else {
        Row::fail(
            ROW_NEEDS_FLOOR,
            format!(
                "`{UMBRELLA}.needs` lists {} job(s) (floor {MIN_NEEDS})",
                needs.len()
            ),
            "a short needs list is how a required check stops requiring things",
        )
    }
}

fn rule_results_floor(results: &[ResultRow]) -> Row {
    if results.len() >= MIN_RESULTS {
        Row::pass(
            ROW_RESULTS_FLOOR,
            "the umbrella's RESULTS ledger scores a plausible number of jobs",
            format!("{} row(s), floor {MIN_RESULTS}", results.len()),
        )
    } else {
        Row::fail(
            ROW_RESULTS_FLOOR,
            format!(
                "the umbrella's RESULTS ledger has {} row(s) (floor {MIN_RESULTS})",
                results.len()
            ),
            "an unread ledger scores nothing and prints GREEN",
        )
    }
}

fn rule_membership(
    jobs: &[String],
    needs: &BTreeSet<String>,
    non_gating: &BTreeSet<String>,
) -> Row {
    let offenders: Vec<&String> = jobs
        .iter()
        .filter(|j| j.as_str() != UMBRELLA && !needs.contains(*j) && !non_gating.contains(*j))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_MEMBERSHIP,
            "every job is gated by the umbrella or declared non-gating",
            format!(
                "{} job(s); {} deliberate exclusion(s), each with a reason",
                jobs.len(),
                non_gating.len()
            ),
        )
    } else {
        Row::fail(
            ROW_MEMBERSHIP,
            "a job is neither in the umbrella's needs nor declared non-gating",
            format!(
                "{} — the umbrella does not wait for it and cannot see it fail, so a red there \
                 reports GREEN on the required check. Add it to `needs` (and to RESULTS), or write \
                 `# non-gating: <job> -- <why it must not gate>` in ci.yml.",
                offenders
                    .iter()
                    .map(|j| j.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    }
}

fn rule_scored(
    results: &[ResultRow],
    needs: &BTreeSet<String>,
    report_only: &BTreeSet<String>,
) -> Row {
    let scored: BTreeSet<&str> = results
        .iter()
        .filter_map(|r| r.parsed.as_ref())
        .map(|(job, _, _)| job.as_str())
        .collect();
    let offenders: Vec<&String> = needs
        .iter()
        .filter(|j| !scored.contains(j.as_str()) && !report_only.contains(*j))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_SCORED,
            "every job the umbrella waits for is scored, or declared report-only",
            format!("{} scored, {} report-only", scored.len(), report_only.len()),
        )
    } else {
        Row::fail(
            ROW_SCORED,
            "a job the umbrella waits for has no RESULTS row",
            format!(
                "{} — the umbrella waits for it and then does not score it. Add the row, or write \
                 `# report-only: <job> -- <why it is printed and not counted>`.",
                offenders
                    .iter()
                    .map(|j| j.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    }
}

fn rule_decl_live(decls: &[Declaration], jobs: &[String]) -> Row {
    let offenders: Vec<String> = decls
        .iter()
        .filter(|d| !jobs.iter().any(|j| j == &d.job))
        .map(|d| format!("# {}: {}", d.kind, d.job))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_DECL_LIVE,
            "every exemption names a job that exists",
            format!("{} declaration(s)", decls.len()),
        )
    } else {
        Row::fail(
            ROW_DECL_LIVE,
            "an exemption names a job that does not exist in ci.yml",
            format!(
                "{} — a stale exemption outlives the job it excused and silently excuses the next \
                 one to take the name",
                offenders.join(", ")
            ),
        )
    }
}

fn rule_decl_reason(decls: &[Declaration]) -> Row {
    let offenders: Vec<String> = decls
        .iter()
        .filter(|d| d.reason.chars().count() < MIN_REASON)
        .map(|d| {
            format!(
                "`# {}: {}` carries a {}-character reason (floor {MIN_REASON})",
                d.kind,
                d.job,
                d.reason.chars().count()
            )
        })
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_DECL_REASON,
            "every exemption carries a reason",
            format!(
                "{} declaration(s), each at least {MIN_REASON} characters",
                decls.len()
            ),
        )
    } else {
        Row::fail(
            ROW_DECL_REASON,
            "an exemption carries no real reason",
            format!(
                "{} — an exemption without a reason becomes permanent by accident",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_row_shape(results: &[ResultRow]) -> Row {
    let offenders: Vec<&str> = results
        .iter()
        .filter(|r| r.parsed.is_none())
        .map(|r| r.raw.as_str())
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_ROW_SHAPE,
            "every RESULTS row has the jobkey|tier|result shape",
            format!("{} row(s)", results.len()),
        )
    } else {
        Row::fail(
            ROW_ROW_SHAPE,
            "a RESULTS row is not `jobkey|tier|${{ needs.<job>.result }}`",
            format!(
                "{} — a row the umbrella's own reader cannot split scores nothing, and an unscored \
                 row prints as a job that passed",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_label(results: &[ResultRow]) -> Row {
    let offenders: Vec<String> = results
        .iter()
        .filter_map(|r| r.parsed.as_ref())
        .filter(|(job, _, referenced)| job != referenced)
        .map(|(job, _, referenced)| format!("`{job}` reads `needs.{referenced}.result`"))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_LABEL,
            "every RESULTS row prints the job it measures",
            format!("{} row(s)", results.len()),
        )
    } else {
        Row::fail(
            ROW_LABEL,
            "a RESULTS row's label and the job it scores disagree",
            format!(
                "{} — the label and the job it scores disagree, so the printed name is not the \
                 measured one",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_ref_job(results: &[ResultRow], jobs: &[String]) -> Row {
    let offenders: Vec<String> = results
        .iter()
        .filter_map(|r| r.parsed.as_ref())
        .filter(|(_, _, referenced)| !jobs.iter().any(|j| j == referenced))
        .map(|(job, _, referenced)| format!("`{job}` scores `{referenced}`"))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_REF_JOB,
            "every RESULTS row scores a job that exists",
            format!("{} row(s)", results.len()),
        )
    } else {
        Row::fail(
            ROW_REF_JOB,
            "a RESULTS row scores a job that is not a job in ci.yml",
            format!(
                "{} — which is not a job in ci.yml, so the row measures nothing at all",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_ref_needs(results: &[ResultRow], jobs: &[String], needs: &BTreeSet<String>) -> Row {
    // A row that scores a job which does not exist is reported by `rule_ref_job` and NOT here: two
    // rows for one defect is two people fixing it, and the missing job is the larger fact.
    let offenders: Vec<String> = results
        .iter()
        .filter_map(|r| r.parsed.as_ref())
        .filter(|(_, _, referenced)| jobs.iter().any(|j| j == referenced))
        .filter(|(_, _, referenced)| !needs.contains(referenced.as_str()))
        .map(|(job, _, referenced)| format!("`{job}` scores `{referenced}`"))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_REF_NEEDS,
            "every RESULTS row scores a job the umbrella waits for",
            format!("{} dependencies", needs.len()),
        )
    } else {
        Row::fail(
            ROW_REF_NEEDS,
            "a RESULTS row scores a job that is NOT in the umbrella's needs",
            format!(
                "{} — which is NOT in `{UMBRELLA}.needs`, so `needs.<job>.result` is the empty \
                 string there, not a verdict",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_tier(results: &[ResultRow], wf: &yaml_lite::Workflow) -> Row {
    let mut offenders = Vec::new();
    for (job, tier, referenced) in results.iter().filter_map(|r| r.parsed.as_ref()) {
        let Some(target) = wf.job(referenced) else {
            continue;
        };
        let guarded = is_full_tier_guarded(target.cond.as_ref());
        match (tier.as_str(), guarded) {
            ("full", false) => offenders.push(format!(
                "`{job}` is scored as full tier but `{referenced}` carries no full-tier guard, so \
                 a real skip of it is forgiven on a fast-tier run"
            )),
            ("fast", true) => offenders.push(format!(
                "`{job}` is scored as fast tier but `{referenced}` carries the full-tier guard, so \
                 the run reddens whenever that job legitimately does not run"
            )),
            _ => {}
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_TIER,
            "every RESULTS row's tier matches its job's full-tier guard",
            "the umbrella forgives `skipped` only for a full-tier row on a fast-tier run, so the \
             tier column has to be the guard and not a label",
        )
    } else {
        Row::fail(
            ROW_TIER,
            "a RESULTS row's tier disagrees with its job's full-tier guard",
            offenders.join(" | "),
        )
    }
}

// ── the plants ──────────────────────────────────────────────────────────────────────────────────

/// NOTHING TO PLANT is a VISIBLE case, counted as unproven — never a silent green.
fn unplantable(name: &str, covers: &[&str], naming: &[&str], why: String) -> Case {
    Case {
        name: format!("{name} ({why})"),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected: Expect::Red {
            naming: naming.iter().map(|s| (*s).to_string()).collect(),
        },
        got: Expect::Skipped,
    }
}

fn plant<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    edit: Edit,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    let mut ov = Overlay::new();
    if let Err(e) = edit.apply(cx, WORKFLOW, &mut ov) {
        return unplantable(name, covers, naming, e).into();
    }
    prove_red(cx, gate, name, covers, ov, naming)
}

/// The same, for a plant expressed as ONE substitution into the real `ci.yml`. A needle that is no
/// longer in the file is an unplantable case, never a quiet no-op: a plant that planted nothing
/// leaves its case green and proves the opposite of what it claims.
fn plant_subst<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    needle: &str,
    with: &str,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    match subst_overlay(cx, needle, with) {
        Ok(ov) => prove_red(cx, gate, name, covers, ov, naming),
        Err(e) => unplantable(name, covers, naming, e).into(),
    }
}

/// The overlay ONE substitution into the real `ci.yml` produces. Shared by [`Gate::selftest`] and
/// [`Gate::parity_probes`] so a probe and its self-test case are the same planted tree, not two
/// descriptions of one that drift apart.
fn subst_overlay(cx: &Ctx, needle: &str, with: &str) -> Result<Overlay, String> {
    let text = cx.read(WORKFLOW)?;
    if !text.contains(needle) {
        return Err(format!("`{needle}` is not in {WORKFLOW} to plant over"));
    }
    let mut ov = Overlay::new();
    ov.set(WORKFLOW, text.replacen(needle, with, 1));
    Ok(ov)
}

fn overlay_of(text: String) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(WORKFLOW, text);
    ov
}

/// A workflow with `jobs` jobs (the umbrella included), the umbrella waiting for `needs` of them
/// and scoring `results` of those. Everything else about it is correct — the jobs it does not wait
/// for are declared non-gating with a reason, the dependencies it does not score are declared
/// report-only — so the ONLY thing a case built from it can be red about is the one dimension it
/// shrank. That is what makes each floor's proof its own rather than its neighbour's.
fn synthetic(jobs: usize, needs: usize, results: usize) -> String {
    let others: Vec<String> = (1..jobs).map(|n| format!("job{n:02}")).collect();
    let waited: Vec<&String> = others.iter().take(needs).collect();
    let mut out = String::from("name: CI\non: [push]\njobs:\n");
    for job in &others {
        out.push_str(&format!(
            "  {job}:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
        ));
    }
    out.push_str(&format!("  {UMBRELLA}:\n"));
    for job in others.iter().skip(needs) {
        out.push_str(&format!(
            "    # non-gating: {job} -- a synthetic reporting job that asserts nothing at all\n"
        ));
    }
    for job in waited.iter().skip(results) {
        out.push_str(&format!(
            "    # report-only: {job} -- printed by the umbrella and deliberately not counted\n"
        ));
    }
    out.push_str("    needs:\n");
    for job in &waited {
        out.push_str(&format!("      - {job}\n"));
    }
    out.push_str("    runs-on: ubuntu-latest\n    env:\n      RESULTS: |\n");
    for job in waited.iter().take(results) {
        out.push_str(&format!(
            "        {job}|fast|${{{{ needs.{job}.result }}}}\n"
        ));
    }
    out.push_str("    steps:\n      - run: true\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::{execute, verify_report};

    #[test]
    fn the_tree_is_green_through_the_runner() {
        let cx = Ctx::workspace().expect("workspace context");
        let verdict = execute(&CiUmbrellaGate, &cx);
        assert!(
            !verdict.red,
            "ci-umbrella is red on the tree it ships with: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn the_selftest_proves_every_owed_row() {
        let cx = Ctx::workspace().expect("workspace context");
        let report = CiUmbrellaGate.selftest(&cx);
        if let Err(failures) = verify_report(&CiUmbrellaGate, &report) {
            panic!("ci-umbrella selftest did not prove itself: {failures:#?}");
        }
    }

    #[test]
    fn a_synthetic_workflow_at_the_floors_is_accepted() {
        // The generator is the fixture every floor case is built from. If it produced a workflow
        // that is red for some OTHER reason, all three floor cases would pass on the wrong red.
        let cx = Ctx::workspace().expect("workspace context");
        let planted = cx.with_overlay(overlay_of(synthetic(MIN_JOBS, MIN_NEEDS, MIN_RESULTS)));
        let verdict = execute(&CiUmbrellaGate, &planted);
        assert!(
            !verdict.red,
            "the floor fixture is red for a reason that is not a floor: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn a_declaration_needs_a_job_and_a_reason() {
        let decls = declarations(
            "# non-gating: coverage -- a reporting job that asserts nothing at all here\n\
             #   coverage policy lives in codecov.yml, which this line is a continuation of\n\
             # report-only: construction-gate — red by design while the work is in flight\n\
             # nothing: at-all -- not a declaration kind this grammar knows\n",
        );
        assert_eq!(decls.len(), 2, "got {decls:?}");
        assert_eq!(decls[0].kind, "non-gating");
        assert_eq!(decls[0].job, "coverage");
        assert_eq!(decls[1].job, "construction-gate");
    }

    #[test]
    fn a_results_row_is_read_only_in_its_exact_shape() {
        assert_eq!(
            parse_result_row("windows|full|${{ needs.windows.result }}"),
            Some((
                "windows".to_string(),
                "full".to_string(),
                "windows".to_string()
            ))
        );
        assert!(parse_result_row("windows|${{ needs.windows.result }}").is_none());
        assert!(parse_result_row("windows|nightly|${{ needs.windows.result }}").is_none());
        assert!(parse_result_row("windows|full|${{ needs.windows.outcome }}").is_none());
    }
}
