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
//! 8. [`ROW_RELEASE_CHECK`] — THE SCAN SET IS WIDER THAN THE WORKFLOWS. The container tags
//!    `scripts/release-check.sh` names in its own `docker run` lines resolve to rows in the SAME
//!    table. That script is where the drift was found, and a lint that reads only
//!    `.github/workflows/` would have declared the tree clean on the day the hole was open.
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

pub const ROW_TABLE: &str = "images|table-readable";
pub const ROW_SHAPE: &str = "images|table-digest-shape";
pub const ROW_FLOOR: &str = "images|discovery-floor";
pub const ROW_FLOATING: &str = "images|no-floating-tag";
pub const ROW_ROW_PRESENT: &str = "images|workflow-row-present";
pub const ROW_PIN_MATCHES: &str = "images|workflow-pin-matches";
pub const ROW_EVERY_PIN_USED: &str = "images|every-pin-used";
pub const ROW_RELEASE_CHECK: &str = "images|release-check-tags";

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
            Some(("postgres:16 >/dev/null", "ghostdb:9 >/dev/null")),
            &["ghostdb:9", "is not named in"],
        ));

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

/// Every container tag `scripts/release-check.sh` names in a `docker run`.
///
/// The tags sit at the END of backslash-continued invocations, so the lines are joined first. The
/// image is the first token after `docker run` that is neither a flag nor a flag's value; a token
/// carrying a `$` is a shell expansion this reader cannot resolve and is left alone, the same way
/// a `${{ … }}` workflow expression is.
fn release_check_tags(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut logical = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') && logical.is_empty() {
            continue;
        }
        if let Some(head) = line.strip_suffix('\\') {
            logical.push_str(head.trim_end());
            logical.push(' ');
            continue;
        }
        logical.push_str(line);
        let joined = std::mem::take(&mut logical);
        let Some(rest) = joined.split_once("docker run").map(|(_, r)| r) else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
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
            let token = token.trim_matches(['"', '\'']);
            if !token.contains('$') && is_image_name(token) {
                out.push(token.to_string());
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
    let offenders: Vec<&String> = tags
        .iter()
        .filter(|tag| !pins.iter().any(|p| &&p.image == tag))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_RELEASE_CHECK,
            "every container the qa gate's script runs is named in the pinned table",
            format!(
                "{} tag(s): {}",
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
            "the qa gate's script runs a container the pinned table does not name",
            format!(
                "{} — it is not named in {IMAGES_TSV}, so the gate that decides a release is not \
                 pinned to the bytes CI is pinned to",
                offenders
                    .iter()
                    .map(|t| t.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
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
    let mut ov = Overlay::new();
    if let Err(e) = edit.apply(cx, IMAGES_TSV, &mut ov) {
        return unplantable(name, covers, naming, e);
    }
    prove_red(cx, gate, name, covers, ov, naming)
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
    let text = match cx.read(RELEASE_CHECK) {
        Ok(t) => t,
        Err(e) => return unplantable(name, covers, naming, e),
    };
    let planted = match subst {
        Some((needle, with)) => {
            if !text.contains(needle) {
                return unplantable(
                    name,
                    covers,
                    naming,
                    format!("`{needle}` is not in {RELEASE_CHECK} to plant over"),
                );
            }
            text.replacen(needle, with, 1)
        }
        None => "#!/usr/bin/env bash\nset -euo pipefail\necho 'no containers here'\n".to_string(),
    };
    let mut ov = Overlay::new();
    ov.set(RELEASE_CHECK, planted);
    prove_red(cx, gate, name, covers, ov, naming)
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

    #[test]
    fn the_qa_gate_script_names_its_containers() {
        let cx = Ctx::workspace().expect("workspace context");
        let text = cx.read(RELEASE_CHECK).expect("release-check.sh");
        let tags = release_check_tags(&text);
        assert!(
            tags.len() >= MIN_RELEASE_CHECK_TAGS,
            "the docker-run reader found {tags:?}"
        );
        assert!(tags.iter().any(|t| t == "postgres:16"), "{tags:?}");
        assert!(tags.iter().any(|t| t == "hashicorp/vault"), "{tags:?}");
    }
}
