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
//! 8. [`ROW_RELEASE_CHECK`] — THE SCAN SET IS WIDER THAN THE WORKFLOWS. The container references
//!    `scripts/release-check.sh` names in its own `docker run` lines are held to the SAME two
//!    demands rules 4 and 6 make of a workflow's `image:` line: each carries an `@sha256:`, and it
//!    is the digest this table pins for that image. Asking only whether the tag NAMES a row is the
//!    question the original drift answers yes to — `postgres:16` was in the table and was still a
//!    floating reference — so the name test alone reads the four tags it exists to ban as clean.
//!    That script is where the drift was found, and a lint that reads only `.github/workflows/`
//!    would have declared the tree clean on the day the hole was open.
//!
//! 9. [`ROW_SCRIPTS`] — THE SCAN SET IS DISCOVERED, NOT LISTED (items 182, 220). Every tracked
//!    `*.sh` under [`SCRIPT_ROOTS`] that runs a container (`docker run`/`docker create`/`podman
//!    run`) is read, and each reference it runs is held to rule 8's demands. Rule 8 read one named
//!    script, so the qa gate's own `bash scripts/release-check-1.5.2.sh` hop and the shadow
//!    oracle's store provisioner ran floating tags with this gate green. A shell VARIABLE is not
//!    an escape: `IMG="postgres:16"` … `docker run "$IMG"` is resolved through the file's own
//!    assignments (a `${X:-default}` resolves to the default that runs when nothing overrides it);
//!    only a value computed at run time (`$(…)`, a variable the file never assigns) is exempt, the
//!    same way a `${{ … }}` workflow expression is. Images published by this project
//!    ([`FIRST_PARTY`]) are the product under test in a release check, not a pinned service.
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
use crate::gates::{prove_green, prove_red, prove_rows_green, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const IMAGES_TSV: &str = "testing/fleet-fixtures/service-images.tsv";
pub const WORKFLOW_DIR: &str = ".github/workflows";
pub const RELEASE_CHECK: &str = "scripts/release-check.sh";

pub const ROW_TABLE: &str = "images|table-readable";
pub const ROW_SHAPE: &str = "images|table-digest-shape";
pub const ROW_FLOOR: &str = "images|discovery-floor";
pub const ROW_FLOATING: &str = "images|no-floating-tag";
pub const ROW_ROW_PRESENT: &str = "images|workflow-row-present";
pub const ROW_PIN_MATCHES: &str = "images|workflow-pin-matches";
pub const ROW_EVERY_PIN_USED: &str = "images|every-pin-used";
pub const ROW_RELEASE_CHECK: &str = "images|release-check-tags";
pub const ROW_SCRIPTS: &str = "images|script-containers";

/// Where container-running scripts live. Every `*.sh` under these that runs a container is in the
/// [`ROW_SCRIPTS`] scan set; nothing is listed by name.
pub const SCRIPT_ROOTS: &[&str] = &["scripts", "testing"];

/// Image namespaces this project PUBLISHES. A release check that boots `getbusbar/busbar@<digest>`
/// or the published `:latest` bundle is verifying the product, not running a service dependency;
/// those references are not rows of the service table and are not judged against it.
pub const FIRST_PARTY: &[&str] = &["getbusbar/", "docker.io/getbusbar/", "ghcr.io/getbusbar/"];

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
/// otherwise report a script full of floating tags as a script with no containers at all. The floor
/// is the measured four (item 182): at three, moving one reference behind a variable the reader
/// skipped still cleared it.
const MIN_RELEASE_CHECK_TAGS: usize = 4;

/// Third-party container references judged across the discovered scripts OTHER than
/// `release-check.sh` (which has its own row and floor). Measured 6 when [`ROW_SCRIPTS`] was armed
/// (`release-check-1.5.2.sh` 2, `oracle-box-store-services.sh` 3, `ws-conformance/scripts/run.sh`
/// one); the floor sits below that so retiring the 1.5.2 harness does not trip it, while a reader
/// that stopped matching finds zero.
const MIN_SCRIPT_REFS: usize = 3;

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
                rows.push(rule_scripts(cx, pins));
            }
            None => {
                for id in [
                    ROW_SHAPE,
                    ROW_EVERY_PIN_USED,
                    ROW_RELEASE_CHECK,
                    ROW_SCRIPTS,
                ] {
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

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
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
        // Narrowed to the three workflow rows it is about: the exemption is a claim about how a
        // workflow `image:` is read, and it must not be held hostage to a script row's standing red.
        report.push(prove_rows_green(
            cx,
            self,
            "an image: that is a workflow expression is exempt",
            &[ROW_FLOATING, ROW_ROW_PRESENT, ROW_PIN_MATCHES],
            workflow_overlay("        image: ${{ inputs.service_image }}\n"),
        ));

        match a_pinned_reference(cx) {
            Ok(reference) => {
                let image = reference
                    .split('@')
                    .next()
                    .unwrap_or(&reference)
                    .to_string();
                let unknown = format!("ghostdb:9@{PLANTED_DIGEST}");
                report.push(plant_release_check(
                    cx,
                    self,
                    "release-check.sh runs a container the table does not pin",
                    &[ROW_RELEASE_CHECK],
                    Some((&reference, &unknown)),
                    &["ghostdb:9", "no row in"],
                ));

                // THE FLOATING TAG ITSELF — the drift this rule was written for, and the one shape
                // a rule that only asks "is this name in the table?" is green over: the name IS in
                // the table, and the reference still resolves to whatever the registry serves
                // today.
                report.push(plant_release_check(
                    cx,
                    self,
                    "release-check.sh runs a container by a floating tag the table pins by digest",
                    &[ROW_RELEASE_CHECK],
                    Some((&reference, &image)),
                    &[&image, "carries no @sha256:"],
                ));
            }
            Err(e) => report.note_infra_failure(format!("service-images selftest: {e}")),
        }

        // ITEM 182: A VARIABLE IS NOT AN ESCAPE. The finding's own shape: one of the four pinned
        // references moved behind `VAULT_IMAGE=` as a floating tag. The reader skipped `$`-tokens,
        // the three that remained cleared a floor of 3, and the row stayed green.
        match a_pinned_reference(cx) {
            Ok(reference) => {
                let image = reference
                    .split('@')
                    .next()
                    .unwrap_or(&reference)
                    .to_string();
                let planted = cx.read(RELEASE_CHECK).map(|t| {
                    let moved = t.replacen(&reference, "\"$PLANTED_SVC_IMAGE\"", 1);
                    format!("PLANTED_SVC_IMAGE=\"{image}\"\n{moved}")
                });
                match planted {
                    Ok(text) => {
                        let mut ov = Overlay::new();
                        ov.set(RELEASE_CHECK, text);
                        report.push(prove_red(
                            cx,
                            self,
                            "release-check.sh runs a floating tag spelled as a shell variable",
                            &[ROW_RELEASE_CHECK],
                            ov,
                            &[&image, "carries no @sha256:"],
                        ));
                    }
                    Err(e) => report.note_infra_failure(format!("service-images selftest: {e}")),
                }
            }
            Err(e) => report.note_infra_failure(format!("service-images selftest: {e}")),
        }

        // ITEM 220: A SCRIPT NOBODY LISTED. A new provisioning script runs a floating tag through
        // a `${X:-default}` variable; before discovery, nothing read it.
        {
            let mut ov = Overlay::new();
            ov.set(
                "testing/planted/planted-services.sh",
                "#!/usr/bin/env bash\nIMG=\"${PLANTED_IMG:-postgres:16}\"\n\
                 docker run -d --rm --name planted \\\n  -p 5432:5432 \"$IMG\" >/dev/null\n",
            );
            report.push(prove_red(
                cx,
                self,
                "a script outside release-check.sh runs a floating tag",
                &[ROW_SCRIPTS],
                ov,
                &["planted-services.sh", "postgres:16", "carries no @sha256:"],
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

        let unknown = format!("ghostdb:9@{PLANTED_DIGEST}");
        push(
            "release-check.sh runs a container the table does not pin",
            Some(ROW_RELEASE_CHECK),
            a_pinned_reference(cx).and_then(|r| release_check_overlay(cx, Some((&r, &unknown)))),
            all(&[], true),
        );
        push(
            "release-check.sh runs a container by a floating tag the table pins by digest",
            Some(ROW_RELEASE_CHECK),
            a_pinned_reference(cx).and_then(|r| {
                let image = r.split('@').next().unwrap_or(&r).to_string();
                release_check_overlay(cx, Some((&r, &image)))
            }),
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
    ROW_SCRIPTS,
];

/// A well-formed digest that pins nothing real, for the plants that need one.
const PLANTED_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The workflow walk. `min_files(1)` is the point: `find` drops a missing root silently, and a
/// workflow directory that yielded nothing reads exactly like a repo whose workflows are all
/// clean.
fn workflow_spec() -> WalkSpec {
    WalkSpec::new([WORKFLOW_DIR]).min_files(1)
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

/// A whole container reference as a shell command writes it: `<name>[:tag]` with an OPTIONAL
/// `@sha256:<64 hex>` pin, split into the two halves the release-check rule judges separately.
///
/// `is_image_name` alone cannot read a pinned reference — it splits at the first `:` and the tag
/// half then carries the whole digest — so a reader built on it drops exactly the references that
/// are correctly pinned and keeps the floating ones. That is anti-monotone: fixing the script
/// would have emptied the scan set and tripped its floor.
fn split_reference(s: &str) -> Option<(&str, Option<&str>)> {
    match s.split_once('@') {
        None => is_image_name(s).then_some((s, None)),
        Some((name, digest)) => {
            let hex = digest.strip_prefix("sha256:")?;
            (is_image_name(name)
                && hex.len() == 64
                && hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
            .then_some((name, Some(digest)))
        }
    }
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

/// Every container tag `scripts/release-check.sh` names in a `docker run` — see [`container_refs`].
fn release_check_tags(text: &str) -> Vec<String> {
    container_refs(text).into_iter().map(|(_, r)| r).collect()
}

/// The shell assignments a script makes, `NAME=value` (optionally `export`/`local`/`readonly`),
/// every value kept: a variable assigned twice is judged on every literal it can hold.
fn shell_assignments(text: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for raw in text.lines() {
        let mut t = raw.trim();
        if t.starts_with('#') {
            continue;
        }
        for kw in ["export ", "local ", "readonly ", "declare "] {
            if let Some(rest) = t.strip_prefix(kw) {
                t = rest.trim_start();
            }
        }
        let Some(eq) = t.find('=') else { continue };
        let name = &t[..eq];
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || name.starts_with(|c: char| c.is_ascii_digit())
        {
            continue;
        }
        let value = shell_word(&t[eq + 1..]);
        out.entry(name.to_string()).or_default().push(value);
    }
    out
}

/// The first shell word of `s` with its quotes removed — enough of the quoting rules to read an
/// assignment's value (`"x"`, `'x'`, bare `x`, a trailing `# comment`).
fn shell_word(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    let mut depth = 0i32; // inside `${…}` / `$(…)`, whitespace does not end the word
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                for d in chars.by_ref() {
                    if d == '"' {
                        break;
                    }
                    out.push(d);
                }
            }
            '\'' => {
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    out.push(d);
                }
            }
            '{' | '(' => {
                depth += 1;
                out.push(c);
            }
            '}' | ')' => {
                depth -= 1;
                out.push(c);
            }
            c if c.is_whitespace() && depth <= 0 => break,
            ';' if depth <= 0 => break,
            _ => out.push(c),
        }
    }
    out
}

/// Resolve every `$NAME` / `${NAME}` / `${NAME:-default}` in `word` through the script's own
/// assignments. Returns every fully-literal value the word can take; an empty result means the
/// value is computed at run time (`$(…)`, a name the file never assigns and gives no default) and
/// this reader cannot know it.
fn resolve_word(
    word: &str,
    vars: &std::collections::BTreeMap<String, Vec<String>>,
    depth: usize,
) -> Vec<String> {
    if depth > 6 {
        return Vec::new();
    }
    let Some(at) = word.find('$') else {
        return vec![word.to_string()];
    };
    let (head, rest) = word.split_at(at);
    let rest = &rest[1..];
    let (name, default, tail): (&str, Option<&str>, &str) =
        if let Some(inner) = rest.strip_prefix('{') {
            let Some(close) = inner.find('}') else {
                return Vec::new();
            };
            let body = &inner[..close];
            let tail = &inner[close + 1..];
            match body.find(":-").or_else(|| body.find('-')) {
                Some(i) if i > 0 => {
                    let skip = if body[i..].starts_with(":-") { 2 } else { 1 };
                    (&body[..i], Some(&body[i + skip..]), tail)
                }
                _ => (body, None, tail),
            }
        } else {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (&rest[..end], None, &rest[end..])
        };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Vec::new(); // `$(`, `$?`, `$1` … — computed
    }
    let values: Vec<String> = match vars.get(name) {
        Some(vs) => vs
            .iter()
            .flat_map(|v| resolve_word(v, vars, depth + 1))
            .collect(),
        None => match default {
            Some(d) => resolve_word(d, vars, depth + 1),
            None => Vec::new(),
        },
    };
    let mut out = Vec::new();
    for v in values.into_iter().filter(|v| !v.is_empty()) {
        for t in resolve_word(tail, vars, depth + 1) {
            out.push(format!("{head}{v}{t}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Every container reference a shell script runs, as `(line, reference)`.
///
/// The tags sit at the END of backslash-continued invocations, so the lines are joined first. The
/// image is the first token after `docker run` / `docker create` / `podman run` that is neither a
/// flag nor a flag's value. A token spelled as a shell variable is RESOLVED through the script's
/// own assignments (item 182 — it used to be skipped, so `docker run "$VAULT_IMAGE"` over
/// `VAULT_IMAGE="hashicorp/vault"` was a floating reference the reader never saw); only a value
/// computed at run time is left alone, the same way a `${{ … }}` workflow expression is.
fn container_refs(text: &str) -> Vec<(usize, String)> {
    const OPENERS: &[&str] = &["docker run", "docker create", "podman run"];
    // A value-taking flag consumes the next token; `--flag=value` carries its own.
    const TAKES_A_VALUE: &[&str] = &[
        "-e",
        "-p",
        "-v",
        "-w",
        "-u",
        "-l",
        "-m",
        "-h",
        "--name",
        "--env",
        "--env-file",
        "--publish",
        "--volume",
        "--network",
        "--entrypoint",
        "--workdir",
        "--user",
        "--add-host",
        "--mount",
        "--label",
        "--platform",
        "--hostname",
        "--cap-add",
        "--cap-drop",
        "--restart",
        "--memory",
        "--cpus",
        "--pull",
        "--ulimit",
        "--tmpfs",
        "--shm-size",
        "--log-driver",
        "--health-cmd",
    ];
    let vars = shell_assignments(text);
    let mut out = Vec::new();
    let mut logical = String::new();
    let mut start = 0usize;
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') && logical.is_empty() {
            continue;
        }
        if logical.is_empty() {
            start = idx + 1;
        }
        if let Some(head) = line.strip_suffix('\\') {
            logical.push_str(head.trim_end());
            logical.push(' ');
            continue;
        }
        logical.push_str(line);
        let joined = std::mem::take(&mut logical);
        let Some(rest) = opener_at_command_position(&joined, OPENERS) else {
            continue;
        };
        let tokens = shell_tokens(rest);
        let mut tokens = tokens.iter();
        while let Some(token) = tokens.next() {
            if token.starts_with('-') {
                if !token.contains('=') && TAKES_A_VALUE.contains(&token.as_str()) {
                    tokens.next();
                }
                continue;
            }
            for candidate in resolve_word(token, &vars, 0) {
                if split_reference(&candidate).is_some() {
                    out.push((start, candidate));
                }
            }
            break;
        }
    }
    out
}

/// The text after the first container-run opener that sits in COMMAND position — at the start of
/// the line or after `$(`, `(`, `;`, `|`, `&&`, `then`, `do`, `!`. `docker run` inside a sentence
/// (`emit "…the documented docker run boots…"`) is prose, not an invocation.
fn opener_at_command_position<'t>(line: &'t str, openers: &[&str]) -> Option<&'t str> {
    let mut best: Option<(usize, usize)> = None;
    for o in openers {
        let mut from = 0;
        while let Some(rel) = line[from..].find(o) {
            let i = from + rel;
            let before = line[..i].trim_end();
            let command_position = before.is_empty()
                || ["$(", "(", ";", "|", "&", "then", "do", "!", "`", "{"]
                    .iter()
                    .any(|p| before.ends_with(p));
            if command_position && best.is_none_or(|(b, _)| i < b) {
                best = Some((i, o.len()));
                break;
            }
            from = i + o.len();
        }
    }
    best.map(|(i, n)| &line[i + n..])
}

/// The shell words of one command, quotes removed and `${…}` / `$(…)` kept whole, stopping at the
/// end of the command (an unmatched `)`, or a top-level `;`, `|`, `&`, `>`, `<`). Whitespace
/// splitting read `-e LDAP_ORGANISATION="Example Org"` as two words and judged `Org` as an image.
fn shell_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut have = false;
    let mut depth = 0i32;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {
                have = true;
                for d in chars.by_ref() {
                    if d == c {
                        break;
                    }
                    cur.push(d);
                }
            }
            '$' if matches!(chars.peek(), Some('{') | Some('(')) => {
                have = true;
                cur.push(c);
                depth += 1;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '}' | ')' if depth > 0 => {
                depth -= 1;
                cur.push(c);
            }
            ')' | ';' | '|' | '&' | '>' | '<' if depth == 0 => break,
            c if c.is_whitespace() && depth == 0 => {
                if have {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            _ => {
                have = true;
                cur.push(c);
            }
        }
    }
    if have {
        out.push(cur);
    }
    out
}

/// Whether a reference is an image this project publishes (see [`FIRST_PARTY`]).
fn is_first_party(reference: &str) -> bool {
    FIRST_PARTY.iter().any(|ns| reference.starts_with(ns))
}

/// What is wrong with one container reference a script runs, judged against the table exactly as a
/// workflow `image:` is: it must carry a digest, name a row, and carry THAT row's digest.
fn judge_reference(tag: &str, pins: &[Pin]) -> Option<String> {
    let Some((image, digest)) = split_reference(tag) else {
        return Some(format!(
            "{tag} — not a container reference this reader can judge"
        ));
    };
    let Some(pin) = pins.iter().find(|p| p.image == image) else {
        return Some(match digest {
            None => format!(
                "{tag} — carries no @sha256: AND no row in {IMAGES_TSV} names `{image}`: a \
                 FLOATING reference nothing pins"
            ),
            Some(_) => format!(
                "{tag} — no row in {IMAGES_TSV} names `{image}`, so the gate that decides a \
                 release is not pinned to the bytes CI is pinned to"
            ),
        });
    };
    match (digest, pin.digest.as_deref()) {
        (None, _) => Some(format!(
            "{tag} — carries no @sha256:, so it is a FLOATING reference: it can resolve to \
             different bytes on two runs of the same commit, which is the drift this rule was \
             written for"
        )),
        (Some(d), Some(pinned)) if d != pinned => Some(format!(
            "{tag} — the table pins {pinned} for `{image}`, so the qa gate and CI are running \
             two different images under one name"
        )),
        (Some(_), None) => Some(format!(
            "{tag} — the row for `{image}` in {IMAGES_TSV} carries no digest, so there is \
             nothing to agree with"
        )),
        (Some(_), Some(_)) => None,
    }
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

fn rule_release_check(cx: &Ctx, pins: &[Pin]) -> Row {
    let text = match cx.read(RELEASE_CHECK) {
        Ok(t) => t,
        Err(e) => {
            return Row::fail(
                ROW_RELEASE_CHECK,
                "the qa gate's own script could not be read",
                format!("{RELEASE_CHECK}: {e}"),
            )
        }
    };
    let tags = release_check_tags(&text);
    if tags.len() < MIN_RELEASE_CHECK_TAGS {
        return Row::fail(
            ROW_RELEASE_CHECK,
            format!(
                "only {} container tag(s) found in {RELEASE_CHECK}",
                tags.len()
            ),
            format!(
                "floor is {MIN_RELEASE_CHECK_TAGS}; the drift this gate exists to stop was found \
                 in this script, and a reader that finds no containers in it clears it vacuously"
            ),
        );
    }
    // THE REFERENCE IS JUDGED, NOT ITS NAME. Asking only whether the tag NAMES a table row is the
    // question the drift already answers yes to: `postgres:16` is in the table, and `postgres:16`
    // is exactly the floating reference this rule exists to ban. So each reference must carry the
    // digest, and it must carry the SAME digest the table pins — the identical demand
    // `ROW_FLOATING` and `ROW_PIN_MATCHES` make of a workflow's `image:` line.
    let offenders: Vec<String> = tags
        .iter()
        .filter_map(|tag| judge_reference(tag, pins))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_RELEASE_CHECK,
            "every container the qa gate's script runs is pinned to the digest the table pins",
            format!(
                "{} reference(s): {}",
                tags.len(),
                tags.iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    } else {
        Row::fail(
            ROW_RELEASE_CHECK,
            "the qa gate's script runs a container that is not pinned to the table's bytes",
            offenders.join(" | "),
        )
    }
}

/// The discovered scan set: every `*.sh` under [`SCRIPT_ROOTS`] other than [`RELEASE_CHECK`] that
/// runs a container.
fn container_scripts(cx: &Ctx) -> Result<Vec<SourceFile>, String> {
    let files = cx
        .walk(&WalkSpec::new(SCRIPT_ROOTS.iter().copied()).ext("sh"))
        .map_err(|e| e.to_string())?;
    Ok(files
        .into_iter()
        .filter(|f| f.rel_str() != RELEASE_CHECK && !container_refs(&f.text).is_empty())
        .collect())
}

fn rule_scripts(cx: &Ctx, pins: &[Pin]) -> Row {
    let scripts = match container_scripts(cx) {
        Ok(s) => s,
        Err(e) => {
            return Row::fail(
                ROW_SCRIPTS,
                "the container-running scripts could not be discovered",
                format!("{SCRIPT_ROOTS:?}: {e}"),
            )
        }
    };
    let mut judged = 0usize;
    let mut offenders = Vec::new();
    for f in &scripts {
        for (line, tag) in container_refs(&f.text) {
            if is_first_party(&tag) {
                continue;
            }
            judged += 1;
            if let Some(why) = judge_reference(&tag, pins) {
                offenders.push(format!("{}:{line}: {why}", f.rel_str()));
            }
        }
    }
    if judged < MIN_SCRIPT_REFS {
        return Row::fail(
            ROW_SCRIPTS,
            format!("only {judged} third-party container reference(s) found across the scripts"),
            format!(
                "floor is {MIN_SCRIPT_REFS}; a reader that finds no containers in {SCRIPT_ROOTS:?} \
                 clears every script vacuously"
            ),
        );
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_SCRIPTS,
            "every container a tracked script runs is pinned to the digest the table pins",
            format!(
                "{judged} third-party reference(s) across {} script(s)",
                scripts.len()
            ),
        )
    } else {
        Row::fail(
            ROW_SCRIPTS,
            "a tracked script runs a container that is not pinned to the table's bytes",
            offenders.join(" | "),
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

fn plant_table<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    edit: Edit,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    match table_overlay(cx, &edit) {
        Ok(ov) => prove_red(cx, gate, name, covers, ov, naming),
        Err(e) => unplantable(name, covers, naming, e).into(),
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

fn plant_workflow<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    image_line: &str,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    prove_red(cx, gate, name, covers, workflow_overlay(image_line), naming)
}

/// `Some((needle, replacement))` substitutes into the real script; `None` replaces it with a script
/// that runs no container at all, which is the floor's case.
fn plant_release_check<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    subst: Option<(&str, &str)>,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    match release_check_overlay(cx, subst) {
        Ok(ov) => prove_red(cx, gate, name, covers, ov, naming),
        Err(e) => unplantable(name, covers, naming, e).into(),
    }
}

/// A pinned reference the qa gate's script really runs, read out of the script itself.
///
/// The plants below rewrite a reference; naming one as a literal here would mean a digest bump in
/// the table becoming an unplantable selftest, and a selftest that cannot plant proves nothing
/// about the rule it names. So the needle is discovered the same way the rule discovers it.
fn a_pinned_reference(cx: &Ctx) -> Result<String, String> {
    let text = cx.read(RELEASE_CHECK)?;
    release_check_tags(&text)
        .into_iter()
        .find(|t| matches!(split_reference(t), Some((_, Some(_)))))
        .ok_or_else(|| {
            format!("{RELEASE_CHECK} runs no digest-pinned container to plant over").to_string()
        })
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

    /// ITEM 182: a reference spelled as a shell variable is resolved through the script's own
    /// assignments, a `${X:-default}` resolves to its default, and a computed value stays exempt.
    #[test]
    fn a_shell_variable_image_is_resolved_not_skipped() {
        let text = "VAULT_IMAGE=\"hashicorp/vault\"\n\
                    PG=\"${ORACLE_PG_IMAGE:-postgres:16}\"\n\
                    ref=\"$(svc_ref pg)\"\n\
                    docker run -d --rm --cap-add=IPC_LOCK \\\n  \"$VAULT_IMAGE\" >/dev/null\n\
                    cid=\"$(docker run -d -p 1:2 \"$PG\")\"\n\
                    docker run -d \"$ref\"\n";
        let refs: Vec<String> = container_refs(text).into_iter().map(|(_, r)| r).collect();
        assert_eq!(
            refs,
            vec!["hashicorp/vault".to_string(), "postgres:16".to_string()]
        );
    }

    /// ITEM 220: a container-running script outside release-check.sh is in the scan set, and its
    /// floating tag is NAMED by the scripts row.
    #[test]
    fn a_floating_container_in_any_script_is_named() {
        let cx = Ctx::workspace().expect("workspace context");
        let mut ov = Overlay::new();
        ov.set(
            "testing/planted/planted-services.sh",
            "#!/usr/bin/env bash\nIMG=\"${PLANTED_IMG:-redis:7}\"\ndocker run -d \"$IMG\"\n",
        );
        let verdict = execute(&ServiceImagesGate, &cx.with_overlay(ov));
        assert!(
            verdict
                .rows
                .iter()
                .any(|r| r.status != crate::ledger::Status::Pass
                    && r.detail.contains("planted-services.sh")
                    && r.detail.contains("redis:7")),
            "no row named the planted floating container: {:?}",
            verdict.rows
        );
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

    #[test]
    fn the_qa_gate_script_names_its_containers() {
        let cx = Ctx::workspace().expect("workspace context");
        let text = cx.read(RELEASE_CHECK).expect("release-check.sh");
        let tags = release_check_tags(&text);
        assert!(
            tags.len() >= MIN_RELEASE_CHECK_TAGS,
            "the docker-run reader found {tags:?}"
        );
        // THE WHOLE REFERENCE, digest and all. The reader used to stop at the image name, which is
        // the same reader bug the rule had: `is_image_name` splits at the first `:`, so a pinned
        // `postgres:16@sha256:…` failed its tag test and was dropped — the correctly pinned lines
        // were exactly the ones that fell out of the scan set.
        assert!(
            tags.iter()
                .any(|t| t.starts_with("postgres:16@sha256:")
                    && t.len() == "postgres:16@".len() + 71),
            "{tags:?}"
        );
        assert!(
            tags.iter()
                .any(|t| t.starts_with("hashicorp/vault@sha256:")),
            "{tags:?}"
        );
        // ...and every one of them carries a digest: the tags this rule was written for were all
        // floating, and a reader that still returns a bare name has lost the thing being judged.
        assert!(
            tags.iter()
                .all(|t| matches!(split_reference(t), Some((_, Some(_))))),
            "{tags:?}"
        );
    }
}
