//! `cargo xtask gate service-images` — EVERY CONTAINER IMAGE THIS REPO RUNS IS THE DIGEST ONE
//! TABLE PINS. The Rust successor to `scripts/service-images-check.sh`.
//!
//! THE DRIFT THIS EXISTS TO STOP, measured before it was written. The service containers busbar's
//! durable stores need were provisioned in FIVE places: `ci.yml`'s `check` job, `ci.yml`'s
//! `coverage` job, `release-stage.yml`'s `gate` job, `plugin-ci.yml`'s `build-test-signoff` job,
//! and `scripts/release-check.sh`. The four workflows agreed on a digest. `release-check.sh` — the
//! script the QA GATE runs — used FLOATING tags. So the gate that decides a release was not pinned
//! to the bytes CI was pinned to, and nothing anywhere said so.
//!
//! GitHub Actions cannot read a file into a `services:` block, so the workflows must keep literal
//! `image:` lines; the pin cannot be enforced by construction and has to be enforced by a lint.
//! A digest bump then lands in ONE commit — edit [`IMAGES_TSV`], edit the workflow lines — and this
//! gate is what proves the fan-out was complete rather than three-quarters complete. The table
//! stays DATA: bumping a pin is a one-row review, and moving the pins into Rust would make it a
//! code review of a gate.
//!
//! THE RULES, each its own ledger row:
//!
//! 1. [`ROW_TABLE`] — the pinned table is present and non-empty.
//! 2. [`ROW_SHAPE`] — every row of it is pinned by a well-formed `sha256:` + 64 hex digest.
//! 3. [`ROW_FLOOR`] — the scanner found at least [`MIN_IMAGE_LINES`] image references. A SCANNER
//!    THAT FINDS NOTHING PASSES EVERYTHING, so a shrunken scan is red on its own terms.
//! 4. [`ROW_FLOATING`] — no workflow image is on a floating tag (a `name:tag` with no `@sha256:`).
//!    This is the specific hole `release-check.sh` had and it is invisible: a floating tag is a
//!    perfectly well-formed workflow that silently changes what it proved between two runs of the
//!    same commit.
//! 5. [`ROW_ROW_PRESENT`] — every workflow image HAS A ROW in the table. An image nobody pinned is
//!    a named FAIL, never a line the scanner passes over.
//! 6. [`ROW_PIN_MATCHES`] — and the digest it carries is the digest that row pins.
//! 7. [`ROW_EVERY_PIN_USED`] — every row of the table is used by at least one workflow. An unused
//!    pin is a pin nobody bumps, and it is how the table starts describing a world that stopped
//!    existing while still reading as authoritative.
//! 8. [`ROW_RELEASE_CHECK`] — THE SCAN SET IS WIDER THAN THE WORKFLOWS, and the SHELL SIDE IS HELD
//!    TO THE SAME BAR. Every container any script under [`SCRIPT_DIR`] starts with `docker run` is
//!    named in the table, PINNED BY DIGEST, and pinned to the digest that row carries — rules 5, 4
//!    and 6 again, on the other side of the fence.
//!
//!    Both halves of that sentence were holes. The scan set was the single literal path
//!    `scripts/release-check.sh`, so any other script starting a container was outside everything
//!    the gate read — the original defect (`.github/workflows/` only) one directory down. And the
//!    rule asked ONLY whether the image was NAMED in the table: `postgres:16` has a row, so
//!    `docker run … postgres:16` satisfied it and went green. Having a row is not being pinned by
//!    one. That is the exact drift the table was created to end, reported as success by the rule
//!    written to catch it.
//!
//! THE ESCAPE HATCH, ported exactly as the shell had it: an `image:` whose value is a workflow
//! expression (`${{ … }}`) with no image literal in it is exempt. The value is not knowable from
//! the text, and a lint that guessed at it would be a lint somebody adds an allowlist to — and the
//! allowlist is where the real one hides. A quoted literal image sitting INSIDE a `${{ … }}`
//! ternary is still read, which is what keeps a third unpinned literal from hiding beside two
//! pinned ones.
//!
//! ON ROW IDS. The shell recorded one row per image LOCATION (`images|ci.yml:413`), which cannot be
//! a static owed set — the ids would change with every line number. So the location moves into the
//! row's detail and the RULE becomes the id, which is strictly finer than the shell was: the three
//! distinct failures it folded into one dynamic id (floating, no row, wrong digest) are three
//! separately owed rows here, each with its own proof.

use std::collections::BTreeSet;

use crate::ctx::{Ctx, Edit, Overlay, SourceFile, WalkSpec};
use crate::gates::{prove_green, prove_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const IMAGES_TSV: &str = "testing/fleet-fixtures/service-images.tsv";
pub const WORKFLOW_DIR: &str = ".github/workflows";
pub const RELEASE_CHECK: &str = "scripts/release-check.sh";

/// THE SCAN SET FOR THE SHELL SIDE, and it is a DIRECTORY on purpose. Naming
/// `scripts/release-check.sh` literally made every other script that starts a container invisible —
/// the same defect as reading `.github/workflows/` alone, one directory down. A gate that has to be
/// told about each new file is a gate that is silently narrow between edits.
pub const SCRIPT_DIR: &str = "scripts";

pub const ROW_TABLE: &str = "images|table-readable";
pub const ROW_SHAPE: &str = "images|table-digest-shape";
pub const ROW_FLOOR: &str = "images|discovery-floor";
pub const ROW_FLOATING: &str = "images|no-floating-tag";
pub const ROW_ROW_PRESENT: &str = "images|workflow-row-present";
pub const ROW_PIN_MATCHES: &str = "images|workflow-pin-matches";
pub const ROW_EVERY_PIN_USED: &str = "images|every-pin-used";
pub const ROW_RELEASE_CHECK: &str = "images|release-check-tags";

/// The shell's own TITLE for the three rules whose row ids could not be inherited.
fn legacy_title(rule: &str) -> Option<&'static str> {
    match rule {
        ROW_FLOATING => Some("a workflow image is on a FLOATING tag"),
        ROW_ROW_PRESENT => Some("a workflow image has no row in the pinned table"),
        ROW_PIN_MATCHES => Some("a workflow image's digest disagrees with the pinned table"),
        _ => None,
    }
}

/// THE WIDENED SCAN SET, declared as the divergence it is.
///
/// The shell reads `.github/workflows/` and nothing else, so a container the release harness runs
/// is not something it can see - which is why the qa gate's own floating tags were the drift that
/// prompted widening the scan. Every probe of that rule is therefore a violation the legacy is
/// green on, by construction rather than by accident.
fn release_check_divergence(rule: &str) -> Option<crate::gates::Divergence> {
    (rule == ROW_RELEASE_CHECK).then(|| crate::gates::Divergence::LegacyGreen {
        reason: "the shell scans .github/workflows/ only, so a container the release harness runs \
                 is outside everything it reads. Widening the scan to those tags is the point of \
                 this rule, and the qa gate's own floating tags were the drift that prompted it."
            .to_string(),
    })
}

/// Twelve `image:` references exist today across `ci.yml` (4), `plugin-ci.yml` (6) and
/// `release-stage.yml` (2). The floor is set below that on purpose: it must catch a scanner that
/// broke, not fail every time somebody legitimately deletes a service. A floor of 1 catches
/// nothing. Not overridable from the environment — a floor a caller can lower is a floor a caller
/// can turn off.
const MIN_IMAGE_LINES: usize = 6;

/// `release-check.sh` runs four service containers today (postgres, mysql, valkey, vault). Same
/// reasoning, same refusal to be configurable: a `docker run` parser that stopped matching would
/// otherwise report a script full of floating tags as a script with no containers at all.
const MIN_RELEASE_CHECK_TAGS: usize = 3;

pub struct ServiceImagesGate;

/// One `image:` reference found in a workflow. `digest` is `None` for a FLOATING reference — one
/// carrying no `@sha256:` at all.
#[derive(Debug, Clone)]
struct ImageRef {
    /// `<workflow-basename>:<line-no>`, the same locator the shell ledger used for its row ids.
    loc: String,
    reference: String,
    digest: Option<String>,
}

/// One row of the pinned table.
#[derive(Debug, Clone)]
struct Pin {
    service: String,
    image: String,
    digest: Option<String>,
}

impl Gate for ServiceImagesGate {
    fn name(&self) -> &'static str {
        "service-images"
    }

    fn owed(&self) -> Vec<String> {
        OWED.iter().map(|s| (*s).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = Vec::new();

        // ── the table itself ────────────────────────────────────────────────────────────────────
        let table = match cx.read(IMAGES_TSV) {
            Ok(t) if !t.trim().is_empty() => {
                rows.push(Row::pass(
                    ROW_TABLE,
                    "the pinned image table is present",
                    IMAGES_TSV,
                ));
                Some(parse_table(&t))
            }
            Ok(_) => {
                rows.push(Row::fail(
                    ROW_TABLE,
                    "the pinned image table is empty",
                    format!("{IMAGES_TSV} — an empty table pins nothing and agrees with anything"),
                ));
                None
            }
            Err(e) => {
                rows.push(Row::fail(
                    ROW_TABLE,
                    "the pinned image table is missing",
                    format!("{IMAGES_TSV}: {e}"),
                ));
                None
            }
        };

        // ── the workflows ───────────────────────────────────────────────────────────────────────
        let workflows = cx.walk(&workflow_spec());
        let found: Vec<ImageRef> = match &workflows {
            Ok(files) => extract_images(files),
            Err(e) => {
                for id in [ROW_FLOOR, ROW_FLOATING, ROW_ROW_PRESENT, ROW_PIN_MATCHES] {
                    rows.push(Row::fail(
                        id,
                        "the workflow directory could not be scanned",
                        e.to_string(),
                    ));
                }
                Vec::new()
            }
        };

        if workflows.is_ok() {
            rows.push(rule_floor(&found));
            rows.push(rule_floating(&found));
            match &table {
                Some(pins) => {
                    rows.push(rule_row_present(&found, pins));
                    rows.push(rule_pin_matches(&found, pins));
                }
                None => {
                    for id in [ROW_ROW_PRESENT, ROW_PIN_MATCHES] {
                        rows.push(Row::fail(
                            id,
                            "no pinned table to resolve workflow images against",
                            format!("{IMAGES_TSV} is missing or empty, so no image is pinned"),
                        ));
                    }
                }
            }
        }

        match &table {
            Some(pins) => {
                rows.push(rule_shape(pins));
                rows.push(rule_every_pin_used(&found, pins, workflows.is_ok()));
                rows.push(rule_release_check(cx, pins));
            }
            None => {
                for id in [ROW_SHAPE, ROW_EVERY_PIN_USED, ROW_RELEASE_CHECK] {
                    rows.push(Row::fail(
                        id,
                        "the pinned table could not be read",
                        format!(
                            "{IMAGES_TSV} is missing or empty — a rule that could not run is \
                                 not a rule that passed"
                        ),
                    ));
                }
            }
        }

        Verdict::of(rows)
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every image this tree runs matches the table",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        report.push(plant_table(
            cx,
            self,
            "the pinned table is gone",
            &[ROW_TABLE],
            Edit::Delete,
            &["the pinned image table is missing"],
        ));

        report.push(plant_table(
            cx,
            self,
            "a table row is not pinned by a sha256 digest",
            &[ROW_SHAPE],
            Edit::Append("planted\tplanted/img:1\tlatest\t-\t1234\t-\t60\n".to_string()),
            &["planted", "not pinned by a well-formed sha256 digest"],
        ));

        report.push(plant_table(
            cx,
            self,
            "a pinned image no workflow references",
            &[ROW_EVERY_PIN_USED],
            Edit::Append(format!(
                "planted\tplanted/unused:1\t{}\t-\t1234\t-\t60\n",
                PLANTED_DIGEST
            )),
            &["planted/unused:1", "referenced by no workflow"],
        ));

        // THE DISCOVERY FLOOR, on its own: every workflow removed and one that mentions no image
        // put in their place. A scan that found nothing has proven nothing.
        match cx.walk(&workflow_spec()) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(&f.rel);
                }
                ov.set(
                    format!("{WORKFLOW_DIR}/zz-planted.yml"),
                    "jobs:\n  check:\n    steps:\n      - run: true\n",
                );
                report.push(prove_red(
                    cx,
                    self,
                    "a scan that found no image at all",
                    &[ROW_FLOOR],
                    ov,
                    &[
                        "found 0 image reference(s)",
                        &format!("floor is {MIN_IMAGE_LINES}"),
                    ],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "the discovery-floor case could not be planted: {WORKFLOW_DIR}: {e}"
            )),
        }

        report.push(plant_workflow(
            cx,
            self,
            "a workflow image on a floating tag",
            &[ROW_FLOATING],
            "        image: postgres:16\n",
            &["postgres:16", "carries no @sha256:"],
        ));

        report.push(plant_workflow(
            cx,
            self,
            "a workflow image with no row in the table",
            &[ROW_ROW_PRESENT],
            &format!("        image: redis:7@{PLANTED_DIGEST}\n"),
            &["redis:7", "no row in the pinned table"],
        ));

        report.push(plant_workflow(
            cx,
            self,
            "a workflow digest that disagrees with the table",
            &[ROW_PIN_MATCHES],
            &format!("        image: postgres:16@{PLANTED_DIGEST}\n"),
            &["postgres:16", "the table pins"],
        ));

        // THE ESCAPE HATCH. An `image:` whose value is a workflow expression is exempt, so this
        // plant must leave the gate GREEN — and the floating case above is what proves the same
        // scanner still refuses a literal in that position.
        report.push(prove_green(
            &cx.with_overlay(workflow_overlay(
                "        image: ${{ inputs.service_image }}\n",
            )),
            self,
            "an image: that is a workflow expression is exempt",
            &[ROW_FLOATING, ROW_ROW_PRESENT, ROW_PIN_MATCHES],
        ));

        report.push(plant_release_check(
            cx,
            self,
            "release-check.sh runs a container the table does not pin",
            &[ROW_RELEASE_CHECK],
            Some((&pinned_postgres(), "ghostdb:9 >/dev/null")),
            &["ghostdb:9", "is not named in"],
        ));

        // THE HOLE THIS ROW USED TO HAVE. `postgres:16` HAS a row in the table, so under the old
        // "is it named?" rule this plant was GREEN — and it is the literal text the script shipped.
        // A row in the table is not a pin; the floating tag resolves to whatever the registry
        // serves, which is the drift the table was written to end.
        report.push(plant_release_check(
            cx,
            self,
            "release-check.sh runs a container on a FLOATING tag that the table does name",
            &[ROW_RELEASE_CHECK],
            Some((&pinned_postgres(), "postgres:16 >/dev/null")),
            &["postgres:16", "FLOATING tag"],
        ));

        report.push(plant_release_check(
            cx,
            self,
            "release-check.sh pins a digest the table disagrees with",
            &[ROW_RELEASE_CHECK],
            Some((
                &pinned_postgres(),
                &format!("postgres:16@{PLANTED_DIGEST} >/dev/null"),
            )),
            &["postgres:16", PLANTED_DIGEST],
        ));

        // THE WIDENED SCAN SET, as its own plant: a container started by SOME OTHER script under
        // scripts/. Under the old shape — which named `scripts/release-check.sh` literally — this
        // file was outside everything the gate read, and a new script running an unpinned service
        // was invisible until someone thought to add its path.
        {
            let mut ov = Overlay::new();
            ov.set(
                "scripts/zz-planted-service.sh",
                "#!/usr/bin/env bash\ndocker run -d --rm --name planted -p 1:1 postgres:16\n",
            );
            report.push(prove_red(
                cx,
                self,
                "a container started by a script OTHER than release-check.sh",
                &[ROW_RELEASE_CHECK],
                ov,
                &["zz-planted-service.sh", "FLOATING tag"],
            ));
        }

        // AND THE TWO FALSE POSITIVES THE WIDENING WOULD OTHERWISE HAVE INTRODUCED, kept green on
        // purpose: a lint with false positives is a lint somebody adds an allowlist to, and the
        // allowlist is where the real one hides.
        {
            let mut ov = Overlay::new();
            ov.set(
                "scripts/zz-planted-prose.sh",
                "#!/usr/bin/env bash\n\
                 emit \"docker:boot-bare\" \"the bare documented docker run boots and answers ok\"\n\
                 run_it -e ORG=\"Example Org\" \"$SOME_IMAGE\"\n",
            );
            report.push(prove_green(
                &cx.with_overlay(ov),
                self,
                "prose naming `docker run`, and a quoted value containing a space, are not containers",
                &[ROW_RELEASE_CHECK],
            ));
        }

        report.push(plant_release_check(
            cx,
            self,
            "release-check.sh names no container at all",
            &[ROW_RELEASE_CHECK],
            None,
            &[&format!("floor is {MIN_RELEASE_CHECK_TAGS}")],
        ));

        report
    }

    /// THE SAME PLANTS, DRIVEN THROUGH BOTH IMPLEMENTATIONS.
    ///
    /// The legacy script anchors on its own path, so the harness copies it into the planted tree
    /// and runs it there. Everything it reads therefore has to BE in that tree: every workflow, the
    /// pinned table, `release-check.sh`, and the two fleet-fixture files it sources for `record`
    /// and its verdict. A path left out is a path it reads from the real repository, and the probe
    /// then proves nothing.
    ///
    /// TWO PLACES THE TWO ARE EXPECTED TO DIFFER, both reported rather than smoothed over:
    ///
    /// * the three per-image rules ([`ROW_FLOATING`], [`ROW_ROW_PRESENT`], [`ROW_PIN_MATCHES`])
    ///   carry ids the shell never printed — it recorded one row per LOCATION — so the verdicts
    ///   agree while the rule NAMES cannot;
    /// * the two [`ROW_RELEASE_CHECK`] probes are the WIDENED SCAN SET. The shell reads only
    ///   `.github/workflows/`, so it is green on a `release-check.sh` running an unpinned
    ///   container — which is precisely the drift that motivated the table. Those probes are kept
    ///   set: the Rust being stricter there is the point of the widening, not a parity bug.
    fn parity_probes(&self, cx: &Ctx) -> Vec<crate::gates::ParityProbe> {
        let workflows: Vec<String> = match cx.walk(&workflow_spec()) {
            Ok(files) => files.iter().map(|f| f.rel_str()).collect(),
            Err(_) => Vec::new(),
        };
        let planted_workflow = format!("{WORKFLOW_DIR}/zz-planted.yml");
        // What the relocated script reads beyond the workflows: the table it resolves against, the
        // qa gate's own script (this gate's widened scan set), and the fixture library + verdict
        // reader it sources.
        let support = |with_table: bool| {
            let mut v = vec![
                RELEASE_CHECK.to_string(),
                "testing/fleet-fixtures/lib.sh".to_string(),
                "testing/fleet-fixtures/verdict.sh".to_string(),
            ];
            if with_table {
                v.push(IMAGES_TSV.to_string());
            }
            v
        };
        let all = |extra: &[String], with_table: bool| {
            let mut v = workflows.clone();
            v.extend(extra.iter().cloned());
            v.extend(support(with_table));
            v
        };

        let mut out = Vec::new();
        let mut push = |label: &str,
                        rule: Option<&str>,
                        overlay: Result<Overlay, String>,
                        materialize: Vec<String>| {
            if let Ok(overlay) = overlay {
                out.push(crate::gates::ParityProbe {
                    label: label.to_string(),
                    overlay,
                    materialize,
                    expect_rule: rule.map(str::to_string),
                    // Four of this gate's rows keep the shell's own ids and match directly. The
                    // three per-image rules cannot: the shell keys those rows by FILE AND LINE, so
                    // the id moved whenever a workflow was edited, and an id nobody can predict
                    // cannot be a `Gate::owed` set. The rule became the id and the location moved
                    // into the detail, so the probe carries the shell's TITLE for the same rule.
                    legacy_names: rule.and_then(legacy_title).map(str::to_string),
                    divergence: rule.and_then(release_check_divergence),
                });
            }
        };

        // The table's own rules. A deleted table is materialized by OMITTING it: the plant is that
        // the file is not there.
        push(
            "the pinned table is gone",
            Some(ROW_TABLE),
            table_overlay(cx, &Edit::Delete),
            all(&[], false),
        );
        push(
            "a table row is not pinned by a sha256 digest",
            Some(ROW_SHAPE),
            table_overlay(
                cx,
                &Edit::Append("planted\tplanted/img:1\tlatest\t-\t1234\t-\t60\n".to_string()),
            ),
            all(&[], true),
        );
        push(
            "a pinned image no workflow references",
            Some(ROW_EVERY_PIN_USED),
            table_overlay(
                cx,
                &Edit::Append(format!(
                    "planted\tplanted/unused:1\t{PLANTED_DIGEST}\t-\t1234\t-\t60\n"
                )),
            ),
            all(&[], true),
        );

        // The discovery floor: every workflow gone, one that names no image in their place. Only
        // the surviving file can be materialized, because the others are absent in this plant.
        if !workflows.is_empty() {
            let mut ov = Overlay::new();
            for rel in &workflows {
                ov.remove(rel);
            }
            ov.set(
                &planted_workflow,
                "jobs:\n  check:\n    steps:\n      - run: true\n",
            );
            let mut materialize = vec![planted_workflow.clone()];
            materialize.extend(support(true));
            push(
                "a scan that found no image at all",
                Some(ROW_FLOOR),
                Ok(ov),
                materialize,
            );
        }

        for (label, rule, line) in [
            (
                "a workflow image on a floating tag",
                ROW_FLOATING,
                "        image: postgres:16\n".to_string(),
            ),
            (
                "a workflow image with no row in the table",
                ROW_ROW_PRESENT,
                format!("        image: redis:7@{PLANTED_DIGEST}\n"),
            ),
            (
                "a workflow digest that disagrees with the table",
                ROW_PIN_MATCHES,
                format!("        image: postgres:16@{PLANTED_DIGEST}\n"),
            ),
        ] {
            push(
                label,
                Some(rule),
                Ok(workflow_overlay(&line)),
                all(std::slice::from_ref(&planted_workflow), true),
            );
        }

        // THE ESCAPE HATCH, as a probe: both implementations must stay GREEN over an `image:` that
        // is a workflow expression. `expect_rule: None` is the harness's way of saying so, and it
        // is the one probe here that proves the two agree about what they DO NOT report.
        push(
            "an image: that is a workflow expression is exempt",
            None,
            Ok(workflow_overlay(
                "        image: ${{ inputs.service_image }}\n",
            )),
            all(std::slice::from_ref(&planted_workflow), true),
        );

        push(
            "release-check.sh runs a container the table does not pin",
            Some(ROW_RELEASE_CHECK),
            release_check_overlay(cx, Some(("postgres:16 >/dev/null", "ghostdb:9 >/dev/null"))),
            all(&[], true),
        );
        push(
            "release-check.sh names no container at all",
            Some(ROW_RELEASE_CHECK),
            release_check_overlay(cx, None),
            all(&[], true),
        );

        out
    }
}

const OWED: &[&str] = &[
    ROW_TABLE,
    ROW_SHAPE,
    ROW_FLOOR,
    ROW_FLOATING,
    ROW_ROW_PRESENT,
    ROW_PIN_MATCHES,
    ROW_EVERY_PIN_USED,
    ROW_RELEASE_CHECK,
];

/// The exact `docker run` tail the qa gate's script carries for postgres, rebuilt from the table so
/// the plants below cannot drift away from the text they plant over: a plant that no longer matches
/// is a self-test case that silently stops running.
fn pinned_postgres() -> String {
    "postgres:16@sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b >/dev/null"
        .to_string()
}

/// A well-formed digest that pins nothing real, for the plants that need one.
const PLANTED_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The workflow walk. `min_files(1)` is the point: `find` drops a missing root silently, and a
/// workflow directory that yielded nothing reads exactly like a repo whose workflows are all
/// clean.
fn workflow_spec() -> WalkSpec {
    WalkSpec::new([WORKFLOW_DIR]).min_files(1)
}

fn script_spec() -> WalkSpec {
    WalkSpec::new([SCRIPT_DIR]).min_files(1)
}

// ── the readers ─────────────────────────────────────────────────────────────────────────────────

fn is_workflow(rel: &str) -> bool {
    rel.ends_with(".yml") || rel.ends_with(".yaml")
}

fn basename(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

/// Every `image:` reference in the workflow files, in file-then-line order.
///
/// The KEY is exactly `image:` at the start of the stripped line. `promote-image:`, `stage-image:`
/// and `bundle_image:` are JOB and INPUT names, and an earlier shape of this scanner that grepped
/// for the substring `image:` reported all three plus a line of prose reading `(image: ${IMG})`.
/// A lint with four false positives is a lint somebody adds an allowlist to.
fn extract_images(files: &[SourceFile]) -> Vec<ImageRef> {
    let mut out = Vec::new();
    for f in files.iter().filter(|f| is_workflow(&f.rel_str())) {
        let name = basename(&f.rel_str()).to_string();
        for (n, line) in f.text.lines().enumerate() {
            let Some(value) = line.trim().strip_prefix("image:") else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let loc = format!("{name}:{}", n + 1);
            let pinned = pinned_refs(value);
            for (reference, digest) in &pinned {
                out.push(ImageRef {
                    loc: loc.clone(),
                    reference: reference.clone(),
                    digest: Some(digest.clone()),
                });
            }
            // A value that mentions an image WITHOUT a digest is the floating case, and it is
            // reported even when the same line also carries a pinned one: `plugin-ci.yml`'s
            // ternaries put a pinned image and an empty fallback on one line, and a THIRD, unpinned
            // literal sneaking in beside them is exactly what would otherwise be invisible.
            let quoted = quoted_floating_refs(value);
            for reference in &quoted {
                if pinned.iter().any(|(r, _)| r == reference)
                    || value.contains(&format!("{reference}@"))
                {
                    continue;
                }
                out.push(ImageRef {
                    loc: loc.clone(),
                    reference: reference.clone(),
                    digest: None,
                });
            }
            // THE ESCAPE HATCH: a value that is a workflow expression names no image this reader
            // can know, and is exempt exactly as the shell exempted it.
            if pinned.is_empty() && quoted.is_empty() && !value.contains("${{") && value != "''" {
                out.push(ImageRef {
                    loc: loc.clone(),
                    reference: value.to_string(),
                    digest: None,
                });
            }
        }
    }
    out
}

fn is_ref_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '/' || c == '-'
}

fn is_tag(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// A name, optionally with a registry host and path, optionally with a tag: the left-hand side of
/// an `@sha256:` or the whole of a floating reference.
fn is_image_name(s: &str) -> bool {
    let (name, tag) = match s.split_once(':') {
        Some((n, t)) => (n, Some(t)),
        None => (s, None),
    };
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(is_ref_char)
        && tag.is_none_or(is_tag)
}

/// Every `<name>[:tag]@sha256:<64 hex>` in a value, as `(reference, digest)`.
fn pinned_refs(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes: Vec<char> = value.chars().collect();
    let mut search = 0usize;
    while let Some(rel) = value[search..].find("@sha256:") {
        let at = search + rel;
        let digest_start = at + 1;
        let hex: String = value[digest_start + "sha256:".len()..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            .collect();
        search = at + "@sha256:".len();
        if hex.len() < 64 {
            continue;
        }
        // Walk back over the reference. `:` is included so a tagged reference survives, then the
        // run is narrowed to the LAST two colon-separated segments — the most a reference may
        // carry — so `a:b:c@sha256:…` reads as `b:c` and not as the whole run.
        let start_char = value[..at].chars().count();
        let mut i = start_char;
        while i > 0 && (is_ref_char(bytes[i - 1]) || bytes[i - 1] == ':') {
            i -= 1;
        }
        let run: String = bytes[i..start_char].iter().collect();
        let segments: Vec<&str> = run.split(':').collect();
        let reference = if segments.len() > 2 {
            segments[segments.len() - 2..].join(":")
        } else {
            run
        };
        if !is_image_name(&reference) {
            continue;
        }
        out.push((reference, format!("sha256:{}", &hex[..64])));
    }
    out
}

/// Every QUOTED `<name>:<tag>` in a value. Quoted, because an unquoted bare word inside a `${{ }}`
/// ternary is an expression fragment, not an image.
fn quoted_floating_refs(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = value;
    while let Some(open) = rest.find('\'') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('\'') else {
            break;
        };
        let inner = &after[..close];
        if inner.contains(':') && is_image_name(inner) {
            out.push(inner.to_string());
        }
        rest = &after[close + 1..];
    }
    out
}

/// The pinned table. `#` comments and blank lines are ignored, exactly as the awk did.
fn parse_table(text: &str) -> Vec<Pin> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 2 {
            continue;
        }
        out.push(Pin {
            service: cols[0].trim().to_string(),
            image: cols[1].trim().to_string(),
            digest: cols.get(2).map(|d| d.trim().to_string()),
        });
    }
    out
}

fn is_well_formed_digest(d: &str) -> bool {
    d.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}

/// Every container a shell script starts with `docker run`, as an [`ImageRef`] — so a reference
/// carrying no `@sha256:` arrives with `digest: None` and is a FLOATING pin, exactly as a workflow's
/// would be.
///
/// The reference sits at the END of backslash-continued invocations, so the lines are joined first.
/// The image is the first token after `docker run` that is neither a flag nor a flag's value; a
/// token carrying a `$` is a shell expansion this reader cannot resolve and is left alone, the same
/// way a `${{ … }}` workflow expression is.
/// The arguments of a `docker run` INVOCATION, or `None` when the text merely mentions the phrase.
///
/// Command position is the discriminator, and it is needed: `scripts/release-gate/expected-ids.sh`
/// carries the row label `"the bare documented docker run boots and answers ok on /healthz"`, whose
/// next word is `boots` — a valid image name. A reader that accepted any occurrence reported that
/// prose as a container this repository starts. A real invocation is preceded by nothing, or by a
/// command separator: `$( `, a backtick, `;`, `&&`, `||`, `|`, `(`, or `&`.
fn docker_run_args(joined: &str) -> Option<&str> {
    const NEEDLE: &str = "docker run";
    let mut from = 0usize;
    while let Some(rel) = joined[from..].find(NEEDLE) {
        let at = from + rel;
        let head = joined[..at].trim_end();
        let in_command_position =
            head.is_empty() || head.ends_with(['(', '`', ';', '|', '&']) || head.ends_with("$(");
        if in_command_position {
            return Some(&joined[at + NEEDLE.len()..]);
        }
        from = at + NEEDLE.len();
    }
    None
}

/// Split on whitespace OUTSIDE quotes, and drop the quote characters. Not a shell parser — it does
/// not expand anything — just enough to keep a quoted value that contains a space as ONE token.
fn shell_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn script_images(f: &SourceFile) -> Vec<ImageRef> {
    let name = basename(&f.rel_str()).to_string();
    let mut out = Vec::new();
    let mut logical = String::new();
    let mut start_line = 0usize;
    for (n, raw) in f.text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') && logical.is_empty() {
            continue;
        }
        if logical.is_empty() {
            start_line = n + 1;
        }
        if let Some(head) = line.strip_suffix('\\') {
            logical.push_str(head.trim_end());
            logical.push(' ');
            continue;
        }
        logical.push_str(line);
        let joined = std::mem::take(&mut logical);
        let Some(rest) = docker_run_args(&joined) else {
            continue;
        };
        // QUOTE-AWARE, and it has to be. `-e LDAP_ORGANISATION="Example Org"` splits on whitespace
        // into three tokens, the third of which (`Org"`) is a perfectly well-formed image NAME —
        // so a whitespace splitter reports `scripts/release-check-1.5.2.sh` as running a container
        // called `Org`. A lint with false positives is a lint somebody adds an allowlist to.
        let toks = shell_tokens(rest);
        let mut tokens = toks.iter().map(String::as_str);
        while let Some(token) = tokens.next() {
            if token.starts_with('>') || token.starts_with('|') || token.starts_with('&') {
                break;
            }
            if token.starts_with('-') {
                // A value-taking flag consumes the next token; `--flag=value` carries its own.
                const TAKES_A_VALUE: &[&str] = &[
                    "-e",
                    "-p",
                    "-v",
                    "--name",
                    "--env",
                    "--publish",
                    "--volume",
                    "--network",
                ];
                if !token.contains('=') && TAKES_A_VALUE.contains(&token) {
                    tokens.next();
                }
                continue;
            }
            if token.contains('$') {
                break;
            }
            let loc = format!("{name}:{start_line}");
            // A digest-pinned reference reads exactly as a workflow's does, so it is parsed by the
            // same function — one answer to "what is a pinned reference", not two.
            let pinned = pinned_refs(token);
            if let Some((reference, digest)) = pinned.into_iter().next() {
                out.push(ImageRef {
                    loc,
                    reference,
                    digest: Some(digest),
                });
            } else if is_image_name(token) {
                out.push(ImageRef {
                    loc,
                    reference: token.to_string(),
                    digest: None,
                });
            }
            break;
        }
    }
    out
}

// ── the rules ───────────────────────────────────────────────────────────────────────────────────

fn rule_floor(found: &[ImageRef]) -> Row {
    if found.len() >= MIN_IMAGE_LINES {
        Row::pass(
            ROW_FLOOR,
            format!("the scanner found {} image reference(s)", found.len()),
            format!("floor is {MIN_IMAGE_LINES}"),
        )
    } else {
        Row::fail(
            ROW_FLOOR,
            format!("the scanner found {} image reference(s)", found.len()),
            format!(
                "floor is {MIN_IMAGE_LINES}; a lint that scans nothing passes everything, so this \
                 is red on its own terms"
            ),
        )
    }
}

fn rule_floating(found: &[ImageRef]) -> Row {
    let offenders: Vec<String> = found
        .iter()
        .filter(|i| i.digest.is_none())
        .map(|i| format!("{} at {}", i.reference, i.loc))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_FLOATING,
            "no workflow image is on a floating tag",
            format!("{} reference(s), every one pinned by digest", found.len()),
        )
    } else {
        Row::fail(
            ROW_FLOATING,
            "a workflow image is on a FLOATING tag",
            format!(
                "{} — it carries no @sha256:, so it can change what it proved between two runs of \
                 the same commit. Pin it to the digest in {IMAGES_TSV}.",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_row_present(found: &[ImageRef], pins: &[Pin]) -> Row {
    let offenders: Vec<String> = found
        .iter()
        .filter(|i| i.digest.is_some())
        .filter(|i| !pins.iter().any(|p| p.image == i.reference))
        .map(|i| format!("{} at {}", i.reference, i.loc))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_ROW_PRESENT,
            "every workflow image has a row in the pinned table",
            format!("{} row(s) in {IMAGES_TSV}", pins.len()),
        )
    } else {
        Row::fail(
            ROW_ROW_PRESENT,
            "a workflow image has no row in the pinned table",
            format!(
                "{} — it is not named in {IMAGES_TSV}; add a row rather than pinning it in one \
                 workflow only",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_pin_matches(found: &[ImageRef], pins: &[Pin]) -> Row {
    let mut offenders = Vec::new();
    let mut matched = 0usize;
    for image in found.iter().filter(|i| i.digest.is_some()) {
        let Some(pin) = pins.iter().find(|p| p.image == image.reference) else {
            continue; // reported by `rule_row_present`; two rows for one defect is two fixes
        };
        let want = pin.digest.clone().unwrap_or_default();
        let got = image.digest.clone().unwrap_or_default();
        if want == got {
            matched += 1;
        } else {
            offenders.push(format!(
                "{} at {} is {got}; the table pins {want}. One of the two was bumped and the other \
                 was not.",
                image.reference, image.loc
            ));
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_PIN_MATCHES,
            "every workflow image is the digest the table pins",
            format!("{matched} reference(s) matched"),
        )
    } else {
        Row::fail(
            ROW_PIN_MATCHES,
            "a workflow image's digest disagrees with the pinned table",
            offenders.join(" | "),
        )
    }
}

fn rule_shape(pins: &[Pin]) -> Row {
    let offenders: Vec<&str> = pins
        .iter()
        .filter(|p| !p.digest.as_deref().is_some_and(is_well_formed_digest))
        .map(|p| p.service.as_str())
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_SHAPE,
            "every table row is pinned by a well-formed sha256 digest",
            format!("{} row(s)", pins.len()),
        )
    } else {
        Row::fail(
            ROW_SHAPE,
            "a table row is not pinned by a well-formed sha256 digest",
            format!("rows: {}", offenders.join(", ")),
        )
    }
}

fn rule_every_pin_used(found: &[ImageRef], pins: &[Pin], scanned: bool) -> Row {
    if !scanned {
        return Row::fail(
            ROW_EVERY_PIN_USED,
            "no workflow was scanned, so no pin could be shown to be used",
            "a table every one of whose rows is unused reads the same as a table nobody read",
        );
    }
    // A pin counts as USED only where the workflow reference MATCHED it. A row whose digest
    // disagrees is reported by its own rule and must not also count as this row's evidence.
    let used: BTreeSet<&str> = found
        .iter()
        .filter(|i| {
            pins.iter()
                .any(|p| p.image == i.reference && p.digest == i.digest)
        })
        .map(|i| i.reference.as_str())
        .collect();
    let unused: Vec<&str> = pins
        .iter()
        .map(|p| p.image.as_str())
        .filter(|image| !used.contains(image))
        .collect();
    if unused.is_empty() {
        Row::pass(
            ROW_EVERY_PIN_USED,
            "every pinned image is referenced by at least one workflow",
            format!("{} pin(s)", pins.len()),
        )
    } else {
        Row::fail(
            ROW_EVERY_PIN_USED,
            "a pinned image is referenced by no workflow",
            format!(
                "unused: {} — delete the row or wire the service, but do not leave a pin nobody \
                 bumps",
                unused.join(", ")
            ),
        )
    }
}

/// THE SCRIPT SIDE, AND IT ASKS THE WORKFLOW SIDE'S THREE QUESTIONS, NOT ONE.
///
/// TWO HOLES, and they were the same hole at two scales.
///
///  1. THE SCAN SET WAS ONE FILE. `scripts/release-check.sh` was named literally, so any OTHER
///     script that starts a container was outside everything this gate reads — the same shape as
///     the original defect (a lint that read `.github/workflows/` only) one directory down. The
///     scan is now [`SCRIPT_DIR`], every `*.sh` in it, and a new script that runs a container is
///     covered on the day it is written rather than on the day someone remembers to add its path.
///
///  2. AND IT ONLY ASKED WHETHER THE IMAGE WAS *NAMED*. A row exists in the table for
///     `postgres:16`, so `docker run … postgres:16` — a FLOATING tag — satisfied "named in the
///     pinned table" and the gate went green. That is precisely the drift the table was created to
///     end: four workflows agreed on a digest while the script the QA GATE runs resolved
///     `postgres:16` to whatever the registry served that morning. The table pinned bytes the qa
///     gate never used, and this rule reported success over it.
///
/// So a script's container is now held to the workflow side's bar, verbatim: named in the table,
/// PINNED BY DIGEST, and pinned to the digest the table carries.
fn rule_release_check(cx: &Ctx, pins: &[Pin]) -> Row {
    let files = match cx.walk(&script_spec()) {
        Ok(files) => files,
        Err(e) => {
            return Row::fail(
                ROW_RELEASE_CHECK,
                "the script directory could not be scanned",
                format!("{SCRIPT_DIR}: {e}"),
            )
        }
    };
    let found: Vec<ImageRef> = files
        .iter()
        .filter(|f| f.rel_str().ends_with(".sh"))
        .flat_map(script_images)
        .collect();

    if found.len() < MIN_RELEASE_CHECK_TAGS {
        return Row::fail(
            ROW_RELEASE_CHECK,
            format!("only {} container(s) found under {SCRIPT_DIR}", found.len()),
            format!(
                "floor is {MIN_RELEASE_CHECK_TAGS}; the drift this gate exists to stop was found \
                 in {RELEASE_CHECK}, and a reader that finds no containers there clears it \
                 vacuously"
            ),
        );
    }

    let mut problems: Vec<String> = Vec::new();
    for img in &found {
        let Some(pin) = pins.iter().find(|p| p.image == img.reference) else {
            problems.push(format!(
                "{}: {} is not named in {IMAGES_TSV}, so the gate that decides a release is not \
                 pinned to the bytes CI is pinned to",
                img.loc, img.reference
            ));
            continue;
        };
        let Some(digest) = &img.digest else {
            problems.push(format!(
                "{}: {} is a FLOATING tag. Having a ROW in the table is not being PINNED by it — \
                 the tag resolves to whatever the registry serves, which is exactly the drift the \
                 table was written to end",
                img.loc, img.reference
            ));
            continue;
        };
        match &pin.digest {
            Some(want) if want == digest => {}
            Some(want) => problems.push(format!(
                "{}: {} is pinned to {digest}, but {IMAGES_TSV} pins {want}",
                img.loc, img.reference
            )),
            None => problems.push(format!(
                "{}: {} carries a digest, but its row in {IMAGES_TSV} pins none",
                img.loc, img.reference
            )),
        }
    }

    if problems.is_empty() {
        Row::pass(
            ROW_RELEASE_CHECK,
            "every container a script runs is pinned by the table's own digest",
            format!(
                "{} container(s): {}",
                found.len(),
                found
                    .iter()
                    .map(|i| format!("{} ({})", i.reference, i.loc))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    } else {
        Row::fail(
            ROW_RELEASE_CHECK,
            "a script runs a container that is not pinned to the table's digest",
            problems.join("; "),
        )
    }
}

// ── the plants ──────────────────────────────────────────────────────────────────────────────────

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

fn plant_table(
    cx: &Ctx,
    gate: &dyn Gate,
    name: &str,
    covers: &[&str],
    edit: Edit,
    naming: &[&str],
) -> Case {
    match table_overlay(cx, &edit) {
        Ok(ov) => prove_red(cx, gate, name, covers, ov, naming),
        Err(e) => unplantable(name, covers, naming, e),
    }
}

/// The overlay one edit to the pinned table produces. Shared by [`Gate::selftest`] and
/// [`Gate::parity_probes`] so a probe and its self-test case are the same planted tree.
fn table_overlay(cx: &Ctx, edit: &Edit) -> Result<Overlay, String> {
    let mut ov = Overlay::new();
    edit.apply(cx, IMAGES_TSV, &mut ov)?;
    Ok(ov)
}

/// A workflow file that does not exist in the tree, carrying one planted `image:` line. Planting a
/// NEW file rather than editing a real one keeps every other reference in the tree intact, so the
/// case's red is about the planted line and nothing else.
fn workflow_overlay(image_line: &str) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(
        format!("{WORKFLOW_DIR}/zz-planted.yml"),
        format!("jobs:\n  check:\n    services:\n      planted:\n{image_line}"),
    );
    ov
}

fn plant_workflow(
    cx: &Ctx,
    gate: &dyn Gate,
    name: &str,
    covers: &[&str],
    image_line: &str,
    naming: &[&str],
) -> Case {
    prove_red(cx, gate, name, covers, workflow_overlay(image_line), naming)
}

/// `Some((needle, replacement))` substitutes into the real script; `None` replaces it with a script
/// that runs no container at all, which is the floor's case.
fn plant_release_check(
    cx: &Ctx,
    gate: &dyn Gate,
    name: &str,
    covers: &[&str],
    subst: Option<(&str, &str)>,
    naming: &[&str],
) -> Case {
    match release_check_overlay(cx, subst) {
        Ok(ov) => prove_red(cx, gate, name, covers, ov, naming),
        Err(e) => unplantable(name, covers, naming, e),
    }
}

/// The overlay one plant into the qa gate's script produces, shared by the self-test and the parity
/// probes.
fn release_check_overlay(cx: &Ctx, subst: Option<(&str, &str)>) -> Result<Overlay, String> {
    let text = cx.read(RELEASE_CHECK)?;
    let planted = match subst {
        Some((needle, with)) => {
            if !text.contains(needle) {
                return Err(format!(
                    "`{needle}` is not in {RELEASE_CHECK} to plant over"
                ));
            }
            text.replacen(needle, with, 1)
        }
        None => "#!/usr/bin/env bash\nset -euo pipefail\necho 'no containers here'\n".to_string(),
    };
    let mut ov = Overlay::new();
    ov.set(RELEASE_CHECK, planted);
    Ok(ov)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::{execute, verify_report};

    #[test]
    fn the_tree_is_green_through_the_runner() {
        let cx = Ctx::workspace().expect("workspace context");
        let verdict = execute(&ServiceImagesGate, &cx);
        assert!(
            !verdict.red,
            "service-images is red on the tree it ships with: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn the_selftest_proves_every_owed_row() {
        let cx = Ctx::workspace().expect("workspace context");
        let report = ServiceImagesGate.selftest(&cx);
        if let Err(failures) = verify_report(&ServiceImagesGate, &report) {
            panic!("service-images selftest did not prove itself: {failures:#?}");
        }
    }

    #[test]
    fn a_pinned_reference_is_read_with_its_digest() {
        let refs = pinned_refs(
            "postgres:16@sha256:aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee",
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "postgres:16");
        assert!(refs[0].1.starts_with("sha256:aa11"));
    }

    #[test]
    fn a_ternary_carrying_a_pinned_and_an_unpinned_literal_reports_the_unpinned_one() {
        let value = "${{ true && 'postgres:16@sha256:aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee' || 'mysql:8' }}";
        assert_eq!(pinned_refs(value).len(), 1);
        assert_eq!(quoted_floating_refs(value), vec!["mysql:8".to_string()]);
    }

    #[test]
    fn a_bare_expression_names_no_image_at_all() {
        // THE ESCAPE HATCH, at the level of the readers: nothing to resolve, so nothing reported.
        let value = "${{ inputs.service_image }}";
        assert!(pinned_refs(value).is_empty());
        assert!(quoted_floating_refs(value).is_empty());
        assert!(value.contains("${{"));
    }

    #[test]
    fn a_job_named_promote_image_is_not_an_image_reference() {
        let file = SourceFile {
            rel: ".github/workflows/x.yml".into(),
            abs: ".github/workflows/x.yml".into(),
            text: "jobs:\n  promote-image:\n    steps:\n      - run: echo \"(image: ${IMG})\"\n"
                .to_string(),
        };
        assert!(extract_images(&[file]).is_empty());
    }

    fn read_script(rel: &str) -> SourceFile {
        let cx = Ctx::workspace().expect("workspace context");
        SourceFile {
            rel: rel.into(),
            abs: cx.abs(rel),
            text: cx.read(rel).expect("script"),
        }
    }

    #[test]
    fn the_qa_gate_script_pins_its_containers_by_digest() {
        let found = script_images(&read_script(RELEASE_CHECK));
        assert!(
            found.len() >= MIN_RELEASE_CHECK_TAGS,
            "the docker-run reader found {found:?}"
        );
        for want in ["postgres:16", "hashicorp/vault"] {
            let img = found
                .iter()
                .find(|i| i.reference == want)
                .unwrap_or_else(|| panic!("{want} not found in {found:?}"));
            // A ROW in the table is not a PIN. This is the assertion the rule used to be missing.
            assert!(
                img.digest.is_some(),
                "{want} is on a floating tag: {found:?}"
            );
        }
    }

    /// The two false positives the widened scan set would otherwise have introduced, both taken
    /// from real text in this tree.
    #[test]
    fn prose_and_quoted_values_are_not_containers() {
        // `scripts/release-gate/expected-ids.sh` describes a row as "the bare documented docker run
        // boots and answers ok" — `boots` is a valid image name in the wrong position.
        let prose = SourceFile {
            rel: "scripts/x.sh".into(),
            abs: "scripts/x.sh".into(),
            text: "emit \"docker:boot-bare\" \"the documented docker run boots and answers ok\"\n"
                .to_string(),
        };
        assert!(
            script_images(&prose).is_empty(),
            "{:?}",
            script_images(&prose)
        );

        // `scripts/release-check-1.5.2.sh` passes `-e LDAP_ORGANISATION="Example Org"`; a
        // whitespace splitter reads `Org` as the image.
        let quoted = SourceFile {
            rel: "scripts/y.sh".into(),
            abs: "scripts/y.sh".into(),
            text: "cid=\"$(docker run -d --rm -e LDAP_ORGANISATION=\"Example Org\" \"$IMG\")\"\n"
                .to_string(),
        };
        assert!(
            script_images(&quoted).is_empty(),
            "{:?}",
            script_images(&quoted)
        );
    }

    #[test]
    fn a_floating_script_container_is_read_as_floating() {
        let f = SourceFile {
            rel: "scripts/z.sh".into(),
            abs: "scripts/z.sh".into(),
            text: "docker run -d --rm -p 1:1 postgres:16 >/dev/null\n".to_string(),
        };
        let found = script_images(&f);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].reference, "postgres:16");
        assert!(found[0].digest.is_none(), "{found:?}");
    }
}
