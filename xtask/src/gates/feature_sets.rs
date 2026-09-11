//! `cargo xtask gate feature-sets` — EVERY NON-DEFAULT CARGO FEATURE IN THIS WORKSPACE IS BUILT BY
//! A CI JOB THAT NAMES IT, OR IS DECLARED COVERED IN WRITING.
//!
//! A cargo feature nothing builds is a feature that is already broken and nobody knows. The code
//! behind `#[cfg(feature = "…")]` is not compiled, so it is not type-checked, so it does not have
//! to be valid Rust; it rots at the speed the rest of the tree moves and the first person to turn
//! the feature on pays the whole bill at once. That is the defect this gate exists for, and it is
//! not hypothetical: the root binary's duplex-serve leg was default-OFF, named by NO job, and it
//! stopped compiling for DAYS without one red run. Every other non-default feature in the tree had
//! exactly that exposure, because nothing anywhere compared the feature list with the CI matrix.
//!
//! THE SHAPE OF THE CONTRACT is `ci-umbrella`'s, deliberately: membership is DERIVED from the tree
//! and ASSERTED against the workflow, and a deliberate exclusion is possible only IN WRITING.
//!
//! ```text
//! # feature-covered: <pkg>/<feature> -- <job-key> -- <reason, at least MIN_REASON characters>
//! ```
//!
//! A feature added to any crate tomorrow is RED until somebody writes down which job builds it.
//!
//! THE RULES, each its own ledger row:
//!
//! 1. [`ROW_MANIFESTS`] — the root manifest and every member manifest were read. A reader that lost
//!    its input has an empty feature list, and an empty feature list is covered by anything.
//! 2. [`ROW_FEATURE_FLOOR`] — at least [`FEATURE_FLOOR`] non-default features were discovered. Zero
//!    is never clean: "every feature is covered" is vacuously true over no features.
//! 3. [`ROW_MATRIX`] — `ci.yml` carries the [`JOB`] job and at least [`MATRIX_FLOOR`] matrix rows
//!    naming features. A matrix that emptied out is a job that builds nothing, reported as a job.
//! 4. [`ROW_COVERED`] — every non-default feature is in that matrix or carries a declaration.
//! 5. [`ROW_DECL_LIVE`] — a declaration names a feature that still exists and is still non-default.
//!    A stale exemption outlives the feature it excused and silently excuses the next one to take
//!    the name; a declaration for a feature that became default-on is an exemption nobody needs.
//! 6. [`ROW_DECL_JOB`] — the job a declaration names is a job in `ci.yml`. A reference to a job that
//!    was renamed away is a coverage claim nobody can check.
//! 7. [`ROW_DECL_REASON`] — a declaration carries a reason of at least [`MIN_REASON`] characters. An
//!    exemption without a reason becomes permanent by accident.
//!
//! WHAT THIS DOES NOT HOLD, stated so it is not mistaken for held: rule 4 accepts a declaration on
//! its word. It does not resolve the named job's own feature set, so a declaration that says
//! `check` builds a feature by dev-dependency unification stays green after the dev-dependency that
//! did the unifying is deleted. Closing that needs a `cargo tree -f '{p}|{f}'` per declared leg,
//! compared against the claim. It belongs in this gate, as an eighth row. It is not here.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::manifest;

pub const ROOT_MANIFEST: &str = "Cargo.toml";
pub const WORKFLOW: &str = ".github/workflows/ci.yml";
/// The job whose matrix is the coverage.
pub const JOB: &str = "feature-sets";
/// The declaration prefix. Matched on the trimmed line, so the YAML indentation is free to move.
pub const DECL: &str = "# feature-covered:";
/// The separator between a declaration's three fields.
pub const SEP: &str = " -- ";

pub const ROW_MANIFESTS: &str = "feature-sets:manifests-read";
pub const ROW_FEATURE_FLOOR: &str = "feature-sets:feature-floor";
pub const ROW_MATRIX: &str = "feature-sets:matrix-present";
pub const ROW_COVERED: &str = "feature-sets:every-non-default-feature-is-built";
pub const ROW_DECL_LIVE: &str = "feature-sets:declaration-names-a-live-feature";
pub const ROW_DECL_JOB: &str = "feature-sets:declaration-names-a-live-job";
pub const ROW_DECL_REASON: &str = "feature-sets:declaration-reason";
/// The SECOND axis this gate holds: an executable scenario the tree carries and no job runs is the
/// same defect as a feature no job builds. See [`RIG_DIRS`].
pub const ROW_RIGS_RUN: &str = "feature-sets:every-h2-rig-is-run-by-a-named-step";

/// The discovery floor under the non-default feature count. Measured at 46 on the 1.6.0 integration
/// tree. Deliberately NOT overridable from the environment: a floor a caller can lower is a floor a
/// caller can turn off, and the self-test drives it by planting a workspace that is genuinely too
/// small, never by moving the number.
pub const FEATURE_FLOOR: usize = 30;
/// The floor under the matrix. One row, because the case this floor exists for is a reader that
/// matched NOTHING — and a floor set at today's row count would turn every deliberate matrix edit
/// into a gate edit, which is how floors get lowered for convenience.
pub const MATRIX_FLOOR: usize = 1;
/// The shortest exemption reason that is a reason rather than a shrug. `ci-umbrella`'s number.
pub const MIN_REASON: usize = 30;

/// WHERE THE EXECUTABLE RIG SCENARIOS LIVE. `qa/teller-steps.json` cites these scripts as the proof
/// of a Teller step, and `teller-steps` asserts each cell names a real one — but naming a file is
/// not running it. Twelve of them sat in the tree, cited as proof, executed by no job in any
/// workflow.
pub const RIG_DIRS: &[&str] = &["scripts/mcp-subject", "scripts/a2a-subject"];
/// The prefix that makes a script a scenario.
pub const RIG_PREFIX: &str = "h2-";
/// The shared helper every scenario sources. It is a library, not a scenario, and running it
/// directly asserts nothing — so it is excluded BY NAME rather than by a pattern that could quietly
/// grow to swallow a real scenario.
pub const RIG_NOT_A_SCENARIO: &[&str] = &["h2-lib.sh"];
/// The discovery floor under the rig count. Measured at 12 on the 1.6.0 integration tree. Same
/// reasoning as every other floor here: a walk that found nothing reports every rig covered.
pub const RIG_FLOOR: usize = 10;

/// One crate's feature table, reduced to what this gate reads.
#[derive(Debug, Clone)]
struct CrateFeatures {
    pkg: String,
    /// Every `[features]` key except `default` itself, with its value list.
    features: BTreeMap<String, Vec<String>>,
    /// The keys reachable from `default` WITHIN this crate. Cross-crate forwards are somebody
    /// else's `default` and are classified in that crate's own row.
    default_on: BTreeSet<String>,
}

/// One `# feature-covered:` line.
#[derive(Debug, Clone)]
struct Decl {
    feature: String,
    job: String,
    reason: String,
}

// ---------------------------------------------------------------------------------------------
// readers
// ---------------------------------------------------------------------------------------------

/// The `[package] name` of a manifest.
fn package_name(text: &str) -> Option<String> {
    let mut in_package = false;
    for raw in text.lines() {
        let t = raw.trim();
        if let Some(header) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_package = header.trim() == "package";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = t.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v.trim().trim_matches(['"', '\'']).to_string());
            }
        }
    }
    None
}

/// The `[features]` table of a manifest: `key = ["a", "b/c"]`, values possibly spread over lines.
///
/// Repeated `[features]` headers ACCUMULATE rather than replace. Real cargo rejects a duplicate
/// table, so this never happens in a shipped manifest; it is how the self-test adds one feature to
/// a real crate without replacing that crate's whole manifest and thereby planting three violations
/// where it meant to plant one.
fn feature_table(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut inside = false;
    let mut collecting: Option<(String, Vec<String>)> = None;
    for raw in text.lines() {
        let line = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        };
        let t = line.trim();
        if let Some((key, values)) = collecting.as_mut() {
            push_values(t, values);
            if t.contains(']') {
                out.entry(key.clone()).or_default().append(values);
                collecting = None;
            }
            continue;
        }
        if let Some(header) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            inside = header.trim() == "features";
            continue;
        }
        if !inside {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let key = k.trim().trim_matches(['"', '\'']).to_string();
        if key.is_empty() {
            continue;
        }
        let mut values = Vec::new();
        push_values(v, &mut values);
        if v.contains(']') {
            out.entry(key).or_default().extend(values);
        } else {
            collecting = Some((key, values));
        }
    }
    out
}

/// The quoted strings on one line of a feature's value list.
fn push_values(segment: &str, out: &mut Vec<String>) {
    let mut rest = segment;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        let v = after[..close].trim();
        if !v.is_empty() {
            out.push(v.to_string());
        }
        rest = &after[close + 1..];
    }
}

/// The keys reachable from `default` inside one crate's own table.
fn default_closure(features: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = features.get("default").cloned().unwrap_or_default();
    while let Some(f) = stack.pop() {
        if f == "default" || !features.contains_key(&f) || !seen.insert(f.clone()) {
            continue;
        }
        stack.extend(features[&f].iter().cloned());
    }
    seen
}

/// Read every workspace member's feature table. Every way this can go wrong is an `Err` carrying
/// its own sentence: none of them may be reachable as "an empty feature list".
fn load_crates(cx: &Ctx) -> Result<Vec<CrateFeatures>, String> {
    let root = cx.read(ROOT_MANIFEST).map_err(|e| {
        format!(
            "{ROOT_MANIFEST} is unreadable ({e}) — a reader with no workspace has no features, and \
             no features are covered by anything"
        )
    })?;
    let members = manifest::workspace_members(&root);
    if members.is_empty() {
        return Err(format!(
            "{ROOT_MANIFEST} names no `[workspace] members` — the key was renamed or the manifest \
             changed shape, which reads as zero crates and therefore as zero uncovered features"
        ));
    }
    let mut out = Vec::with_capacity(members.len());
    for member in &members {
        let rel = format!("{member}/Cargo.toml");
        let text = cx.read(&rel).map_err(|e| {
            format!("{rel} is unreadable ({e}) — a member this gate cannot read is a member whose features it cannot check, so it is refused rather than skipped")
        })?;
        let Some(pkg) = package_name(&text) else {
            return Err(format!(
                "{rel} carries no `[package] name` — a crate this gate cannot name is a crate whose \
                 features it cannot report"
            ));
        };
        let mut features = feature_table(&text);
        let default_on = default_closure(&features);
        features.remove("default");
        out.push(CrateFeatures {
            pkg,
            features,
            default_on,
        });
    }
    Ok(out)
}

/// `pkg/feature` for every feature NOT reachable from its own crate's `default`.
fn non_default(crates: &[CrateFeatures]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for c in crates {
        for key in c.features.keys() {
            if !c.default_on.contains(key) {
                out.insert(format!("{}/{key}", c.pkg));
            }
        }
    }
    out
}

/// Every `pkg/feature` the tree declares, default-on ones included — the set a DECLARATION is
/// checked against for liveness.
fn all_features(crates: &[CrateFeatures]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for c in crates {
        for key in c.features.keys() {
            out.insert(format!("{}/{key}", c.pkg));
        }
    }
    out
}

/// The `feature-sets` job's matrix feature values, and every `# feature-covered:` declaration.
///
/// The job block is delimited by indentation: a job key is two spaces and a name, so the block runs
/// to the next line matching that shape. The declarations are read from the WHOLE file, because a
/// declaration is a comment and a YAML parser drops comments — the same reason `ci-umbrella` reads
/// its workflow twice.
fn read_workflow(text: &str) -> (Vec<String>, Vec<Decl>, BTreeSet<String>) {
    let mut jobs = BTreeSet::new();
    let mut matrix = Vec::new();
    let mut in_job = false;
    for raw in text.lines() {
        if let Some(name) = job_key(raw) {
            in_job = name == JOB;
            jobs.insert(name);
            continue;
        }
        if in_job {
            if let Some(v) = raw.trim().strip_prefix("features:") {
                let v = v.trim().trim_matches(['"', '\'']).trim();
                if !v.is_empty() {
                    matrix.push(v.to_string());
                }
            }
        }
    }
    let decls = text.lines().filter_map(|l| parse_decl(l.trim())).collect();
    (matrix, decls, jobs)
}

/// `  some-job:` — exactly two spaces, a key, a colon, nothing else.
fn job_key(raw: &str) -> Option<String> {
    let rest = raw.strip_prefix("  ")?;
    if rest.starts_with(' ') || rest.starts_with('#') {
        return None;
    }
    let key = rest.strip_suffix(':')?;
    if key.is_empty() || key.contains(' ') || key.contains(':') {
        return None;
    }
    Some(key.to_string())
}

/// `# feature-covered: pkg/feat -- job -- reason`. A line that carries the prefix and does not have
/// this shape is NOT silently skipped: it is returned with the empty fields it parsed to, so the
/// job and reason rules report it.
fn parse_decl(t: &str) -> Option<Decl> {
    let rest = t.strip_prefix(DECL)?.trim();
    let mut parts = rest.splitn(3, SEP);
    Some(Decl {
        feature: parts.next().unwrap_or_default().trim().to_string(),
        job: parts.next().unwrap_or_default().trim().to_string(),
        reason: parts.next().unwrap_or_default().trim().to_string(),
    })
}

/// The individual features one matrix `features:` value turns on.
fn split_features(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Every executable rig scenario the tree carries, as a repo-relative path.
///
/// Derived by listing, never by a hand-maintained constant: a scenario added tomorrow is discovered
/// tomorrow, which is the whole point — a list somebody has to remember to extend is the mechanism
/// that let twelve of these go unrun.
fn rig_scripts(cx: &Ctx) -> Vec<String> {
    let spec = crate::ctx::WalkSpec::new(RIG_DIRS.iter().copied()).ext("sh");
    let Ok(paths) = cx.list(&spec) else {
        return Vec::new();
    };
    let mut out: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|rel| {
            let name = rel.rsplit('/').next().unwrap_or(rel);
            name.starts_with(RIG_PREFIX) && !RIG_NOT_A_SCENARIO.contains(&name)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The rig row: every scenario is NAMED by a step of the workflow, and enough of them were found for
/// that to mean anything.
///
/// "Named" is a literal path match against the workflow text on purpose. A
/// `for f in scripts/*-subject/h2-*.sh` loop would run them all and name none, and a glob expands on
/// the runner where nobody reads the expansion — so a scenario added tomorrow would be covered by a
/// loop that never listed it and no diff would show the difference. A step per scenario is a line a
/// reviewer can count against the directory listing.
fn rig_row(rigs: &[String], workflow: &str) -> Row {
    if rigs.len() < RIG_FLOOR {
        return Row::fail(
            ROW_RIGS_RUN,
            "the rig scenario walk collapsed below its discovery floor",
            format!(
                "only {} scenario(s) were found under {:?} (floor {RIG_FLOOR}). A walk that found \
                 nothing reports every rig covered.",
                rigs.len(),
                RIG_DIRS
            ),
        );
    }
    let unrun: Vec<&str> = rigs
        .iter()
        .filter(|r| !workflow.contains(r.as_str()))
        .map(String::as_str)
        .collect();
    if unrun.is_empty() {
        Row::pass(
            ROW_RIGS_RUN,
            "every H2 rig scenario is run by a step that names it",
            format!("{} scenario(s) across {:?}", rigs.len(), RIG_DIRS),
        )
    } else {
        Row::fail(
            ROW_RIGS_RUN,
            "an executable rig scenario is run by no step of this workflow",
            format!(
                "{} — qa/teller-steps.json cites scenarios like these as the proof of a Teller \
                 step, and `teller-steps` asserts the cell names a real file. Naming a file is not \
                 running it: add a step to {WORKFLOW} that names this path.",
                unrun.join(" | ")
            ),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------------------------

pub struct FeatureSetsGate;

/// The rows every rule below `ROW_MANIFESTS` answers on when there was nothing to read.
fn unproven(why: &str) -> Verdict {
    let detail = format!("unproven: the workspace feature list did not load — {why}");
    Verdict::of(vec![
        Row::fail(ROW_MANIFESTS, "the workspace manifests did not load", why),
        Row::fail(
            ROW_FEATURE_FLOOR,
            "the feature count is unknown",
            detail.clone(),
        ),
        Row::fail(ROW_MATRIX, "no matrix was compared", detail.clone()),
        Row::fail(ROW_COVERED, "no feature was checked", detail.clone()),
        Row::fail(ROW_DECL_LIVE, "no declaration was checked", detail.clone()),
        Row::fail(ROW_DECL_JOB, "no declaration was checked", detail.clone()),
        Row::fail(
            ROW_DECL_REASON,
            "no declaration was checked",
            detail.clone(),
        ),
        Row::fail(ROW_RIGS_RUN, "no rig scenario was checked", detail),
    ])
}

impl Gate for FeatureSetsGate {
    fn name(&self) -> &'static str {
        "feature-sets"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_MANIFESTS.to_string(),
            ROW_FEATURE_FLOOR.to_string(),
            ROW_MATRIX.to_string(),
            ROW_COVERED.to_string(),
            ROW_DECL_LIVE.to_string(),
            ROW_DECL_JOB.to_string(),
            ROW_DECL_REASON.to_string(),
            ROW_RIGS_RUN.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let crates = match load_crates(cx) {
            Ok(c) => c,
            Err(why) => return unproven(&why),
        };
        let workflow = match cx.read(WORKFLOW) {
            Ok(t) => t,
            Err(e) => {
                return unproven(&format!(
                    "{WORKFLOW} is unreadable ({e}) — an unread workflow names no job and no \
                     matrix, and a feature list compared against nothing is covered by nothing"
                ))
            }
        };

        let nd = non_default(&crates);
        let all = all_features(&crates);
        let (matrix, decls, jobs) = read_workflow(&workflow);

        let mut rows = vec![Row::pass(
            ROW_MANIFESTS,
            "every workspace member manifest was read",
            format!(
                "{} crate(s), {} declared feature(s), {} non-default",
                crates.len(),
                all.len(),
                nd.len()
            ),
        )];

        rows.push(if nd.len() < FEATURE_FLOOR {
            Row::fail(
                ROW_FEATURE_FLOOR,
                "the feature set collapsed below its discovery floor",
                format!(
                    "only {} non-default feature(s) were discovered (floor {FEATURE_FLOOR}). A \
                     feature list that collapsed has nothing left to be uncovered, so 'every \
                     feature is built' is vacuously true over it.",
                    nd.len()
                ),
            )
        } else {
            Row::pass(
                ROW_FEATURE_FLOOR,
                "enough non-default features were discovered for the coverage check to mean something",
                format!("{} non-default feature(s) (floor {FEATURE_FLOOR})", nd.len()),
            )
        });

        rows.push(if matrix.len() < MATRIX_FLOOR {
            Row::fail(
                ROW_MATRIX,
                "the CI feature matrix is missing or empty",
                format!(
                    "`{JOB}` in {WORKFLOW} contributed {} matrix row(s) naming features (floor \
                     {MATRIX_FLOOR}). A matrix that emptied out builds nothing, and a coverage \
                     check against an empty matrix passes only the features nobody needs.",
                    matrix.len()
                ),
            )
        } else {
            Row::pass(
                ROW_MATRIX,
                "the CI feature matrix is present and names features",
                format!("{} matrix row(s) in `{JOB}`", matrix.len()),
            )
        });

        // COVERED — in the matrix, or declared. The declaration's own validity is rules 5-7; a
        // declaration that is stale still discharges rule 4, so exactly one row goes red per defect.
        let mut built: BTreeSet<&str> = BTreeSet::new();
        for value in &matrix {
            built.extend(split_features(value));
        }
        let declared: BTreeSet<&str> = decls.iter().map(|d| d.feature.as_str()).collect();
        let uncovered: Vec<&String> = nd
            .iter()
            .filter(|f| !built.contains(f.as_str()) && !declared.contains(f.as_str()))
            .collect();
        rows.push(if uncovered.is_empty() {
            Row::pass(
                ROW_COVERED,
                "every non-default feature is built by a job that names it, or declared",
                format!(
                    "{} non-default feature(s): {} in the `{JOB}` matrix, {} declared",
                    nd.len(),
                    nd.iter().filter(|f| built.contains(f.as_str())).count(),
                    nd.iter().filter(|f| declared.contains(f.as_str())).count(),
                ),
            )
        } else {
            Row::fail(
                ROW_COVERED,
                "a non-default feature is built by no CI job and declared by nobody",
                format!(
                    "{} — nothing compiles the code behind it, so it is not type-checked, so it \
                     does not have to be valid Rust. Add it to the `{JOB}` matrix in {WORKFLOW}, or \
                     write a `{DECL}` line naming the job that already builds it.",
                    uncovered
                        .iter()
                        .map(|f| f.as_str())
                        .collect::<Vec<_>>()
                        .join(" | ")
                ),
            )
        });

        let mut dead = Vec::new();
        let mut promoted = Vec::new();
        let mut bad_job = Vec::new();
        let mut thin = Vec::new();
        for d in &decls {
            if !all.contains(&d.feature) {
                dead.push(format!("`{}`", d.feature));
            } else if !nd.contains(&d.feature) {
                promoted.push(format!("`{}`", d.feature));
            }
            if !jobs.contains(&d.job) {
                bad_job.push(format!("`{}` names job `{}`", d.feature, d.job));
            }
            if d.reason.len() < MIN_REASON {
                thin.push(format!(
                    "`{}` ({} char reason)",
                    d.feature,
                    d.reason.chars().count()
                ));
            }
        }

        rows.push(if dead.is_empty() && promoted.is_empty() {
            Row::pass(
                ROW_DECL_LIVE,
                "every coverage declaration names a feature that exists and is still non-default",
                format!("{} declaration(s)", decls.len()),
            )
        } else {
            let mut detail = String::new();
            if !dead.is_empty() {
                detail.push_str(&format!(
                    "no crate declares {} — a stale exemption outlives the feature it excused and \
                     then silently excuses the next one to take the name. ",
                    dead.join(", ")
                ));
            }
            if !promoted.is_empty() {
                detail.push_str(&format!(
                    "{} became default-on and needs no exemption; leaving one hides the day it goes \
                     back off.",
                    promoted.join(", ")
                ));
            }
            Row::fail(
                ROW_DECL_LIVE,
                "a coverage declaration names a feature that is not there to cover",
                detail.trim_end().to_string(),
            )
        });

        rows.push(if bad_job.is_empty() {
            Row::pass(
                ROW_DECL_JOB,
                "every coverage declaration names a job that exists",
                format!("{} job(s) in {WORKFLOW}", jobs.len()),
            )
        } else {
            Row::fail(
                ROW_DECL_JOB,
                "a coverage declaration names a job this workflow does not have",
                format!(
                    "{} — a coverage claim pointing at a job that was renamed away is a claim \
                     nobody can check.",
                    bad_job.join(" | ")
                ),
            )
        });

        rows.push(if thin.is_empty() {
            Row::pass(
                ROW_DECL_REASON,
                "every coverage declaration carries a reason",
                format!(
                    "{} declaration(s), minimum {MIN_REASON} characters",
                    decls.len()
                ),
            )
        } else {
            Row::fail(
                ROW_DECL_REASON,
                "a coverage declaration carries no reason worth the name",
                format!(
                    "{} — minimum {MIN_REASON}. An exemption without a reason becomes permanent by \
                     accident.",
                    thin.join(" | ")
                ),
            )
        });

        rows.push(rig_row(&rig_scripts(cx), &workflow));

        Verdict::of(rows)
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every non-default feature in this tree is built by a job that names it or declared",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));
        for plant in plants(cx) {
            report.push(plant.case(cx, self));
        }
        report
    }
}

// ---------------------------------------------------------------------------------------------
// the plants
// ---------------------------------------------------------------------------------------------

struct Plant {
    label: &'static str,
    rule: &'static str,
    naming: Vec<String>,
    overlay: Option<Overlay>,
}

impl Plant {
    fn case(self, cx: &Ctx, gate: &dyn Gate) -> Case {
        let Some(overlay) = self.overlay else {
            // NOTHING TO PLANT is a visible, counted case — never a silent green.
            return Case {
                name: self.label.to_string(),
                covers: vec![self.rule.to_string()],
                expected: Expect::Red {
                    naming: self.naming.clone(),
                },
                got: Expect::Skipped,
            };
        };
        let naming: Vec<&str> = self.naming.iter().map(String::as_str).collect();
        prove_red(cx, gate, self.label, &[self.rule], overlay, &naming)
    }
}

/// The feature name planted into a real crate — deliberately one no manifest, workflow or source
/// file in this tree mentions.
const PLANTED_FEATURE: &str = "xtask-feature-sets-selftest-uncovered";

/// The first workspace member that declares NO `[features]` table. Appending one to it is valid
/// TOML and changes exactly one fact, which is what a discriminating plant needs.
fn featureless_member(cx: &Ctx) -> Option<(String, String)> {
    let root = cx.read(ROOT_MANIFEST).ok()?;
    for member in manifest::workspace_members(&root) {
        let rel = format!("{member}/Cargo.toml");
        let Ok(text) = cx.read(&rel) else { continue };
        if feature_table(&text).is_empty() {
            return Some((rel, text));
        }
    }
    None
}

fn plants(cx: &Ctx) -> Vec<Plant> {
    let workflow = cx.read(WORKFLOW).ok();

    // THE DEFECT THIS GATE IS NAMED FOR, RE-PLANTED: a crate grows a feature and no CI job names
    // it. This is the red-first case — it is the shape of the duplex-serve leg that stopped
    // compiling for days.
    let uncovered = featureless_member(cx).map(|(rel, text)| {
        let mut ov = Overlay::new();
        ov.set(
            &rel,
            format!("{text}\n[features]\n{PLANTED_FEATURE} = []\n"),
        );
        ov
    });

    // A DECLARATION THAT OUTLIVED ITS FEATURE.
    let dead_decl = workflow.as_ref().map(|t| {
        let mut ov = Overlay::new();
        ov.set(
            WORKFLOW,
            format!(
                "{t}\n  {DECL} busbar-gone/ghost-feature{SEP}check{SEP}a crate that no longer \
                 exists, declared as covered anyway\n"
            ),
        );
        ov
    });

    // A DECLARATION POINTING AT A JOB THAT WAS RENAMED AWAY. The feature is real and already
    // covered, so rules 4 and 5 stay green and only rule 6 can move.
    let dead_job = workflow.as_ref().map(|t| {
        let mut ov = Overlay::new();
        ov.set(
            WORKFLOW,
            format!(
                "{t}\n  {DECL} busbar-core/loom-model{SEP}no-such-job{SEP}a job key that this \
                 workflow does not define, declared anyway\n"
            ),
        );
        ov
    });

    // A DECLARATION WITH A SHRUG FOR A REASON.
    let thin_reason = workflow.as_ref().map(|t| {
        let mut ov = Overlay::new();
        ov.set(
            WORKFLOW,
            format!("{t}\n  {DECL} busbar-core/loom-model{SEP}check{SEP}because\n"),
        );
        ov
    });

    // THE MATRIX THAT EMPTIED OUT, with every feature it built moved to a declaration so that ONLY
    // the floor can go red. A floor proven alongside its neighbours is a floor that could be
    // deleted with the self-test still green.
    let empty_matrix = workflow.as_ref().map(|t| emptied_matrix(t));

    // A WORKSPACE WITH NOTHING IN IT. The root manifest still parses and still names a member; that
    // member simply declares no features, so the coverage check is vacuously true and only the
    // floor may move. The declarations go with it: every one of them names a feature that the
    // collapsed workspace no longer declares, and a plant that reddens rule 5 as well as rule 2 is
    // a plant that proves neither alone.
    let tiny_workspace =
        featureless_member(cx)
            .zip(workflow.as_ref())
            .map(|((rel, _), workflow_text)| {
                let member = rel.trim_end_matches("/Cargo.toml").to_string();
                let mut ov = Overlay::new();
                ov.set(
                    ROOT_MANIFEST,
                    format!("[workspace]\nresolver = \"2\"\nmembers = [\"{member}\"]\n"),
                );
                ov.set(WORKFLOW, without_declarations(workflow_text));
                ov
            });

    // A RIG SCENARIO NO STEP RUNS — the second defect this gate is named for, re-planted: the
    // scenario is in the tree and cited by the matrix as proof, and the step that ran it is gone.
    let unrun_rig = workflow
        .as_ref()
        .zip(rig_scripts(cx).first().cloned())
        .map(|(t, rig)| {
            let mut ov = Overlay::new();
            ov.set(
                WORKFLOW,
                t.lines()
                    .filter(|l| !l.contains(rig.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
            ov
        });

    // THE ROOT MANIFEST GONE. Everything below rule 1 is UNPROVEN, never passed.
    let mut no_root = Overlay::new();
    no_root.remove(ROOT_MANIFEST);

    vec![
        Plant {
            label: "a crate grows a feature no CI job builds and nobody declared",
            rule: ROW_COVERED,
            naming: vec![PLANTED_FEATURE.to_string()],
            overlay: uncovered,
        },
        Plant {
            label: "a coverage declaration outlived the feature it excused",
            rule: ROW_DECL_LIVE,
            naming: vec!["busbar-gone/ghost-feature".to_string()],
            overlay: dead_decl,
        },
        Plant {
            label: "a coverage declaration names a job that was renamed away",
            rule: ROW_DECL_JOB,
            naming: vec!["no-such-job".to_string()],
            overlay: dead_job,
        },
        Plant {
            label: "a coverage declaration carries a shrug for a reason",
            rule: ROW_DECL_REASON,
            naming: vec![format!("minimum {MIN_REASON}")],
            overlay: thin_reason,
        },
        Plant {
            label: "the CI feature matrix emptied out while every feature stayed declared",
            rule: ROW_MATRIX,
            naming: vec![format!("floor {MATRIX_FLOOR}")],
            overlay: empty_matrix,
        },
        Plant {
            label: "the workspace collapsed to a crate with no features at all",
            rule: ROW_FEATURE_FLOOR,
            naming: vec![format!("floor {FEATURE_FLOOR}")],
            overlay: tiny_workspace,
        },
        Plant {
            label: "a rig scenario the tree carries is run by no step of the workflow",
            rule: ROW_RIGS_RUN,
            naming: vec!["run by no step".to_string()],
            overlay: unrun_rig,
        },
        Plant {
            label: "the root manifest is unreadable",
            rule: ROW_MANIFESTS,
            naming: vec!["is unreadable".to_string()],
            overlay: Some(no_root),
        },
    ]
}

/// The workflow with every `# feature-covered:` line removed.
fn without_declarations(text: &str) -> String {
    text.lines()
        .filter(|l| parse_decl(l.trim()).is_none())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strip every `features:` line out of the `feature-sets` job and re-declare what it built, so the
/// matrix floor is the only rule that can move.
fn emptied_matrix(text: &str) -> Overlay {
    let mut out: Vec<String> = Vec::new();
    let mut decls: Vec<String> = Vec::new();
    let mut in_job = false;
    for raw in text.lines() {
        if let Some(name) = job_key(raw) {
            in_job = name == JOB;
        }
        if in_job {
            if let Some(v) = raw.trim().strip_prefix("features:") {
                for f in split_features(v.trim().trim_matches(['"', '\''])) {
                    decls.push(format!(
                        "  {DECL} {f}{SEP}check{SEP}the matrix row that named it was removed by \
                         this planted fixture"
                    ));
                }
                continue;
            }
        }
        out.push(raw.to_string());
    }
    out.extend(decls);
    let mut ov = Overlay::new();
    ov.set(WORKFLOW, out.join("\n"));
    ov
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> Ctx {
        Ctx::workspace().expect("workspace context")
    }

    #[test]
    fn the_feature_table_reader_handles_the_shapes_this_tree_writes() {
        let t = "[package]\nname = \"x\"\n\n[features]\ndefault = [\"a\"]\na = [\"b\"]\nb = []\n\
                 wide = [\n  \"dep:serde\",\n  \"other/thing\",\n]\n# c = [\"commented-out\"]\n\n\
                 [dependencies]\nserde = \"1\"\n";
        let f = feature_table(t);
        assert_eq!(package_name(t).as_deref(), Some("x"));
        assert_eq!(
            f.keys().cloned().collect::<Vec<_>>(),
            vec!["a", "b", "default", "wide"]
        );
        assert_eq!(f["wide"], vec!["dep:serde", "other/thing"]);
        // `default` reaches `a`, and `a` reaches `b`. `wide` is reached by nothing.
        let d = default_closure(&f);
        assert!(d.contains("a") && d.contains("b"));
        assert!(!d.contains("wide"));
    }

    #[test]
    fn a_declaration_parses_into_its_three_fields_and_a_job_key_is_two_spaces_deep() {
        let d = parse_decl(&format!("{DECL} busbar/x{SEP}check{SEP}a reason")).expect("parses");
        assert_eq!((d.feature.as_str(), d.job.as_str()), ("busbar/x", "check"));
        assert_eq!(d.reason, "a reason");
        assert_eq!(job_key("  check:").as_deref(), Some("check"));
        assert_eq!(job_key("    steps:"), None);
        assert_eq!(job_key("  # comment:"), None);
        assert_eq!(job_key("on:"), None);
    }

    /// The ids that went non-PASS under one planted overlay.
    fn failed_ids(ov: Overlay) -> Vec<String> {
        let planted = cx().with_overlay(ov);
        crate::gates::execute(&FeatureSetsGate, &planted)
            .rows
            .iter()
            .filter(|r| r.status != crate::ledger::Status::Pass)
            .map(|r| r.id.clone())
            .collect()
    }

    /// EVERY PLANT MUST REDDEN ITS OWN ROW AND NOTHING ELSE — except the root-manifest plant, whose
    /// whole point is that everything below it is unproven. A rule proven only alongside its
    /// neighbours is a rule that could be deleted with the self-test still green.
    #[test]
    fn each_plant_reddens_exactly_its_own_row() {
        for p in plants(&cx()) {
            if p.rule == ROW_MANIFESTS {
                continue;
            }
            let ov = p
                .overlay
                .unwrap_or_else(|| panic!("nothing to plant: {}", p.label));
            assert_eq!(
                failed_ids(ov),
                vec![p.rule.to_string()],
                "plant `{}` did not redden exactly `{}`",
                p.label,
                p.rule
            );
        }
    }

    /// THE RIG FLOOR BITES ON ITS OWN. It cannot be reached by an overlay -- the scenarios are files
    /// on disk and a plant that "removes" ten of them is planting the walk, not the tree -- so it is
    /// driven directly. A walk that found nothing must not report every rig covered.
    #[test]
    fn the_rig_floor_refuses_a_walk_that_found_almost_nothing() {
        let thin: Vec<String> = (0..RIG_FLOOR - 1)
            .map(|i| format!("scripts/mcp-subject/h2-{i}.sh"))
            .collect();
        let row = rig_row(&thin, "");
        assert_ne!(row.status, crate::ledger::Status::Pass);
        assert!(
            row.detail.contains(&format!("floor {RIG_FLOOR}")),
            "{row:?}"
        );
        // ...and a full list whose every member the workflow names is clean.
        let full: Vec<String> = (0..RIG_FLOOR)
            .map(|i| format!("scripts/mcp-subject/h2-{i}.sh"))
            .collect();
        let text = full.join("\n");
        assert_eq!(
            rig_row(&full, &text).status,
            crate::ledger::Status::Pass,
            "the floor must not reject a list that is big enough and fully named"
        );
    }

    #[test]
    fn the_gate_is_green_on_the_workspace() {
        let verdict = crate::gates::execute(&FeatureSetsGate, &cx());
        assert!(
            !verdict.red,
            "feature-sets is RED on the real tree: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn the_selftest_proves_every_owed_row() {
        let cx = cx();
        let report = FeatureSetsGate.selftest(&cx);
        crate::gates::verify_report(&FeatureSetsGate, &report)
            .unwrap_or_else(|errs| panic!("feature-sets selftest: {errs:#?}"));
        assert_eq!(report.skipped(), 0, "a case had nothing to plant");
    }
}
