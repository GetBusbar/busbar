//! `cargo xtask gate changelog` — THE NEWEST ENTRY IN `CHANGELOG.md` CARRIES A VERSION AND A DATE.
//!
//! WHAT THIS GUARDS, AND WHY IT IS A GATE RATHER THAN A CONVENTION. The top of `CHANGELOG.md` is
//! the first thing a human reads and the only thing the marketing site publishes. It has gone out
//! without a version number and without a date more than once, and the request to fix it has been
//! made more than once — which is the definition of something that needs a gate rather than another
//! reminder. A fix somebody has to keep asking for is not a fix.
//!
//! THE FAILURE THAT MOTIVATED IT, precisely, because it was not what anyone assumed. The site's
//! sync step strips `## [Unreleased]` before publishing and rewrites a dated heading into a version
//! heading plus a styled date line. It did that with a regex terminated by an anchor JavaScript
//! does not have, which degraded to a literal letter and, case-insensitively, matched a lowercase
//! one in the prose. The strip therefore ended at the first such letter in the staged notes, cut
//! mid-word, and left the remainder of the section on the published page as a HEADLESS blob sitting
//! above the newest real release: no heading, so no version and no date, and no rewriter ever
//! looked at it. It only fired when the staged section was non-empty, which is why the default
//! branch looked correct while the development branch was broken for weeks.
//!
//! That bug lives in the site repo and is fixed there. This gate guards the OTHER half — the source
//! file's own shape — because the site can only publish what this file gives it, and every
//! downstream renderer keys off the exact heading spelling below.
//!
//! THE CANONICAL SHAPE of a SHIPPED entry, and there is exactly one:
//!
//! ```text
//! ## [1.5.1], 2026-08-02
//! ```
//!
//! And of a version that is NAMED but has not shipped — the state every branch is in for the length
//! of a release cycle — exactly one more:
//!
//! ```text
//! ## [1.6.0], unreleased
//! ```
//!
//! The literal word, never a date-shaped placeholder. A version in flight has a number long before
//! it has a ship date: the number is in the manifest from the first commit of the cycle, and the
//! date is not knowable until the day it is tagged. Without a spelling for that state every branch
//! had to choose between an invented date (a lie that renders as a shipped release on a public
//! page) and a heading the lint refuses; both were taken at different times, and the second is what
//! made this gate red on every branch for a whole release cycle. A gate nobody can be green against
//! is a gate nobody reads.
//!
//! What keeps that from being a hole is [`ChangelogGate::require_dated_top`], the release-time arm:
//! the release path asks for a real ship date and nothing else does. It is a NAMED METHOD on the
//! gate and not a boolean read from the environment, because the one strict/loose pair in the shell
//! that was environment-overridable is the cautionary case — a floor that can be lowered from a
//! `run:` line is a floor whose value is whatever the last caller felt like.
//!
//! THE OTHER ARM the release path passes is [`ChangelogGate::require_version`]: the version being
//! tagged must be the NEWEST entry in this file. The release body extraction is deliberately
//! fail-soft — it warns and falls back to generated commit titles when no section for the version
//! exists — so a version could be tagged, published, fanned out to every downstream repo and pinned
//! by users with a release body that never said what changed.
//!
//! Every rule owns one ledger row, keyed by the rule id this gate has always printed, and every row
//! id has its own RED case in [`Gate::selftest`]. A rule that cannot be shown to fire is not a rule.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

/// The parse floor. A file with no `## ` heading at all is not a clean changelog; it is an empty
/// file or a broken parser, and a broken parser reports every changelog clean.
pub const ROW_SHAPE: &str = "SHAPE";
pub const ROW_CANONICAL: &str = "CANONICAL-HEADING";
pub const ROW_UNRELEASED_FIRST: &str = "UNRELEASED-FIRST";
pub const ROW_TOP_ENTRY_DATED: &str = "TOP-ENTRY-DATED";
pub const ROW_NO_DUPLICATE_VERSION: &str = "NO-DUPLICATE-VERSION";
pub const ROW_DESCENDING: &str = "DESCENDING";
pub const ROW_NO_FUTURE_DATE: &str = "NO-FUTURE-DATE";
/// Emitted only by the release arm; see [`ChangelogGate::require_dated_top`].
pub const ROW_RELEASE_TOP_DATED: &str = "RELEASE-TOP-DATED";
/// Emitted only by the release arm; see [`ChangelogGate::require_version`].
pub const ROW_VERSION_HAS_NOTES: &str = "VERSION-HAS-NOTES";

/// The staging heading, permitted once and only at the very top.
const UNRELEASED: &str = "## [Unreleased]";
/// The headings that are deliberately not releases. Anything else that looks like a heading and is
/// not canonical is a violation, so a malformed heading cannot be skipped by accident.
const NON_RELEASE: &[&str] = &[UNRELEASED, "## [Early development]"];

/// The changelog grammar, as a gate.
pub struct ChangelogGate {
    /// The file under judgement, relative to the workspace root.
    pub file: String,
    /// The release-time arm: an undated top entry is refused. See [`ChangelogGate::require_dated_top`].
    pub require_dated_top: bool,
    /// The release-time arm: this version must be the newest entry. Implies the arm above, exactly
    /// as the legacy command line did — the caller that is shipping is the caller that owes a date.
    pub require_version: Option<String>,
    /// Today, UTC, as `YYYY-MM-DD`. A field rather than a call inside the rule so a test can pin it
    /// and so the clock is read once per run instead of once per heading.
    pub today: String,
}

impl Default for ChangelogGate {
    fn default() -> ChangelogGate {
        ChangelogGate {
            file: "CHANGELOG.md".to_string(),
            require_dated_top: false,
            require_version: None,
            today: today_utc(),
        }
    }
}

impl ChangelogGate {
    /// The ordinary arm every branch runs: the shape rules, and a named-but-undated top entry is
    /// legal.
    pub fn new() -> ChangelogGate {
        ChangelogGate::default()
    }

    /// THE RELEASE ARM. A named-but-undated top entry is the honest state of a branch mid-cycle and
    /// a lie on a published release: the tag exists, the artifacts exist, and the changelog page
    /// would show the shipped version with no ship date. The two facts differ only in WHEN they are
    /// asked, so this is an arm rather than a second spelling — every branch runs without it, the
    /// release path runs with it, fail-closed, because the remedy is to type the date.
    pub fn require_dated_top(mut self) -> ChangelogGate {
        self.require_dated_top = true;
        self
    }

    /// THE OTHER RELEASE ARM: the version about to be tagged must be the NEWEST entry in the file.
    /// Newest, not merely present — an entry buried below a higher version means the version in the
    /// manifest is not the one this file thinks shipped last, and one of the two is wrong.
    pub fn require_version(mut self, version: impl Into<String>) -> ChangelogGate {
        self.require_version = Some(version.into());
        self
    }

    /// Pin today, for a test that must not move when the calendar does.
    pub fn with_today(mut self, today: impl Into<String>) -> ChangelogGate {
        self.today = today.into();
        self
    }

    /// `--require-version` implies `--require-dated-top`: the release path is exactly the caller
    /// that may not ship an undated top entry. The two stay separately spellable so a caller can
    /// ask for the date alone.
    fn dated_top_required(&self) -> bool {
        self.require_dated_top || self.require_version.is_some()
    }
}

/// THE VERSION BEING TAGGED, and the ways it can lack notes: the case name, the version the
/// release arm is asked for, and the string the report must name. A `const` rather than a literal
/// inside the selftest because each row builds a gate of its own, and those gates are built above
/// the report that holds the cases naming them.
const VERSION_CASES: &[(&str, &str, &str)] = &[
    (
        "the version being released has no section at all",
        "1.5.5",
        "has NO `## [1.5.5]",
    ),
    (
        "the version being released is not the newest entry",
        "1.5.3",
        "BELOW 1.5.4",
    ),
];

impl Gate for ChangelogGate {
    fn name(&self) -> &'static str {
        "changelog"
    }

    fn owed(&self) -> Vec<String> {
        let mut owed = vec![
            ROW_SHAPE.to_string(),
            ROW_CANONICAL.to_string(),
            ROW_UNRELEASED_FIRST.to_string(),
            ROW_TOP_ENTRY_DATED.to_string(),
            ROW_NO_DUPLICATE_VERSION.to_string(),
            ROW_DESCENDING.to_string(),
            ROW_NO_FUTURE_DATE.to_string(),
        ];
        if self.dated_top_required() {
            owed.push(ROW_RELEASE_TOP_DATED.to_string());
        }
        if self.require_version.is_some() {
            owed.push(ROW_VERSION_HAS_NOTES.to_string());
        }
        owed
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let text = match cx.read(&self.file) {
            Ok(t) => t,
            Err(e) => {
                // AN UNREADABLE CHANGELOG IS NOT A CLEAN ONE. Every owed row fails by name rather
                // than one row failing and the rest reading as "did not run" noise beside it.
                return Verdict::of(self.every_row_fails(
                    format!("{} is unreadable", self.file),
                    format!("{e} — an unreadable changelog is not a clean one"),
                ));
            }
        };

        let heads = parse(&text);
        if heads.is_empty() {
            // ZERO IS NOT CLEAN. Every rule below is vacuous over a file with no headings, so a
            // parser that stopped matching would answer green to all of them at once.
            let mut rows = self.every_row_fails(
                "no version headings were parsed at all",
                format!(
                    "{}: either the file is empty or the parser is broken, and a broken parser \
                     reports a clean changelog",
                    self.file
                ),
            );
            rows.retain(|r| r.id != ROW_SHAPE);
            rows.insert(
                0,
                Row::fail(
                    ROW_SHAPE,
                    "no `## ` version headings found at all",
                    format!(
                        "{}: either the file is empty or the parser is broken, and a broken parser \
                         reports a clean changelog",
                        self.file
                    ),
                ),
            );
            return Verdict::of(rows);
        }

        // Entries carrying a VERSION, shipped or not: what the ordering and duplicate rules judge.
        let entries: Vec<&Heading> = heads
            .iter()
            .filter(|h| matches!(h.kind, Kind::Release | Kind::Staged))
            .collect();
        // Entries carrying a DATE. A staged entry has none, so no date rule may reach it — the
        // alternative is inventing one, which is the failure this whole gate exists over.
        let releases: Vec<&Heading> = heads
            .iter()
            .filter(|h| matches!(h.kind, Kind::Release))
            .collect();

        let mut rows = vec![
            Row::pass(
                ROW_SHAPE,
                "the changelog parsed into headings",
                format!(
                    "{} heading(s), {} released entr(ies), {} named but not yet dated",
                    heads.len(),
                    releases.len(),
                    entries.len() - releases.len()
                ),
            ),
            rule_canonical(&heads),
            rule_unreleased_first(&heads),
            rule_top_entry_dated(&heads),
            rule_no_duplicate_version(&entries),
            rule_descending(&entries, &releases),
            rule_no_future_date(&releases, &self.today),
        ];
        if self.dated_top_required() {
            rows.push(rule_release_top_dated(&entries));
        }
        if let Some(version) = &self.require_version {
            rows.push(rule_version_has_notes(&entries, version));
        }
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        // EVERY GATE THIS SELFTEST BUILDS IS BUILT HERE, ABOVE THE REPORT. The release arms are
        // `ChangelogGate` with a flag the registry does not carry, so the cases that prove them
        // name a gate this function owns; a case is taken on whichever thread reaches it, so the
        // gate it names has to outlive the report that holds the case, and declaration order is
        // what says so.
        let branch = ChangelogGate::new().with_today(self.today.clone());
        let release = ChangelogGate::new()
            .with_today(self.today.clone())
            .require_dated_top();
        let versioned: Vec<(&str, &str, ChangelogGate)> = VERSION_CASES
            .iter()
            .map(|(name, version, naming)| {
                (
                    *name,
                    *naming,
                    ChangelogGate::new()
                        .with_today(self.today.clone())
                        .require_version(*version),
                )
            })
            .collect();
        let newest_not_a_release = ChangelogGate::new()
            .with_today(self.today.clone())
            .require_version("1.5.4");
        let mut report = Report::new();
        let owed: Vec<String> = branch.owed();
        let owed_refs: Vec<&str> = owed.iter().map(String::as_str).collect();

        // The unplanted tree, judged by the arm every branch runs. Without this every RED below
        // proves only that the gate is broken.
        report.push(prove_green(
            cx,
            &branch,
            "the real changelog passes the branch arm",
            &owed_refs,
        ));

        // And the known-good fixture, so a rule that is red on a correct file is caught here rather
        // than by whoever writes the next release notes.
        report.push(prove_green(
            &cx.with_overlay(plant(GOOD)),
            &branch,
            "the known-good fixture passes (no false positive)",
            &owed_refs,
        ));

        report.push(prove_red(
            cx,
            &branch,
            "a dash separator instead of the canonical comma",
            &[ROW_CANONICAL],
            plant(&GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4] - 2026-08-14")),
            &[ROW_CANONICAL, "## [1.5.4] - 2026-08-14"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "a date-shaped placeholder instead of the literal word",
            &[ROW_CANONICAL],
            plant(&GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4], TBD")),
            &[ROW_CANONICAL, "## [1.5.4], TBD"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "the newest entry stamped with a version but NO date",
            &[ROW_TOP_ENTRY_DATED],
            plant(&GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4]")),
            &[ROW_TOP_ENTRY_DATED, "## [1.5.4]"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "the newest entry with neither a version nor a date",
            &[ROW_TOP_ENTRY_DATED],
            plant(&GOOD.replace("## [1.5.4], 2026-08-14", "## [Next release]")),
            &[ROW_TOP_ENTRY_DATED, "## [Next release]"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "an Unreleased block buried below a shipped release",
            &[ROW_UNRELEASED_FIRST],
            plant(&GOOD.replace("## [Unreleased]\n", "").replace(
                "## [1.5.3], 2026-08-08",
                "## [Unreleased]\n\n## [1.5.3], 2026-08-08",
            )),
            &[ROW_UNRELEASED_FIRST, "line 12"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "one version number used by two entries",
            &[ROW_NO_DUPLICATE_VERSION],
            plant(&GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.4], 2026-08-08")),
            &[ROW_NO_DUPLICATE_VERSION, "1.5.4"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "a newer version listed below an older one",
            &[ROW_DESCENDING],
            plant(&GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.5], 2026-08-08")),
            &[ROW_DESCENDING, "1.5.5 is not older than 1.5.4"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "a date that increases as you read down the file",
            &[ROW_DESCENDING],
            plant(&GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.3], 2026-08-20")),
            &[ROW_DESCENDING, "dated 2026-08-20"],
        ));

        // A staged entry is still an ENTRY: the ordering rule must reach it, or `, unreleased`
        // becomes a way to park a misordered version where no rule looks.
        report.push(prove_red(
            cx,
            &branch,
            "the ordering rule still reaches a named-but-undated entry",
            &[ROW_DESCENDING],
            plant(&staged().replace("## [1.5.3], 2026-08-08", "## [1.5.6], 2026-08-08")),
            &[ROW_DESCENDING, "1.5.6 is not older than 1.5.4"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "a release dated in the future",
            &[ROW_NO_FUTURE_DATE],
            plant(&GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4], 2099-01-01")),
            &[ROW_NO_FUTURE_DATE, "2099-01-01"],
        ));

        report.push(prove_red(
            cx,
            &branch,
            "an empty changelog names no version anywhere",
            &[ROW_SHAPE],
            plant("# Changelog\n\nnothing has ever shipped.\n"),
            &[ROW_SHAPE, "no `## ` version headings found at all"],
        ));

        // -- BOTH SIDES OF THE NAMED-BUT-UNDATED SPELLING, each proven ---------------------------
        //
        // The branch side is the case above: an undated top entry passes the ordinary run (the
        // known-good green covers the shape, and this one covers the spelling). If it ever goes red
        // the gate is back to being red for a whole release cycle, which is how it stopped being
        // read the first time.
        report.push(prove_green(
            &cx.with_overlay(plant(&staged())),
            &branch,
            "a named-but-undated top entry passes on a branch",
            &[ROW_RELEASE_TOP_DATED],
        ));

        report.push(prove_red(
            cx,
            &release,
            "an undated top entry at release time",
            &[ROW_RELEASE_TOP_DATED],
            plant(&staged()),
            &[ROW_RELEASE_TOP_DATED, "names a version but no ship date"],
        ));
        // The twin that differs only in the thing the rule is about.
        report.push(prove_green(
            &cx.with_overlay(plant(GOOD)),
            &release,
            "a dated top entry passes at release time",
            &[ROW_RELEASE_TOP_DATED],
        ));

        // -- THE VERSION BEING TAGGED, three ways it can lack notes, and the twin -----------------
        for (name, naming, gate) in &versioned {
            report.push(prove_red(
                cx,
                gate,
                *name,
                &[ROW_VERSION_HAS_NOTES],
                plant(GOOD),
                &[ROW_VERSION_HAS_NOTES, naming],
            ));
        }
        report.push(prove_red(
            cx,
            &newest_not_a_release,
            "a file whose newest heading is not a release at all",
            &[ROW_VERSION_HAS_NOTES],
            plant(&GOOD.replace("## [1.5.4], 2026-08-14", "## [Unreleased] but stale")),
            &[ROW_VERSION_HAS_NOTES, "Newest entry is 1.5.3"],
        ));
        report.push(prove_green(
            &cx.with_overlay(plant(GOOD)),
            &newest_not_a_release,
            "the newest entry IS the version being released",
            &[ROW_VERSION_HAS_NOTES],
        ));

        report.sealed()
    }

    /// THE PARITY PROBES, one per rule the ordinary (branch) invocation of the legacy lint can
    /// report. They are the SAME overlays the selftest plants — a probe that plants something the
    /// selftest does not would be proving a rule nothing else proves.
    ///
    /// The legacy script prints its rule id and this gate uses that id as its row id, so one string
    /// identifies the rule on both sides and `expect_rule` compares them directly.
    ///
    /// The two release arms have no probes here on purpose: parity runs ONE legacy invocation, and
    /// the one being compared is the ordinary run every branch makes. `--require-dated-top` and
    /// `--require-version` would each need their own invocation of both implementations, so they
    /// are proven by the selftest and remain unproven by parity.
    fn parity_probes(&self, _cx: &Ctx) -> Vec<crate::gates::ParityProbe> {
        let probe = |label: &str, text: String, rule: &str| crate::gates::ParityProbe {
            label: label.to_string(),
            overlay: plant(&text),
            materialize: vec!["CHANGELOG.md".to_string()],
            expect_rule: Some(rule.to_string()),
            legacy_names: None,
            divergence: None,
        };
        vec![
            probe(
                "a dash separator instead of the canonical comma",
                GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4] - 2026-08-14"),
                ROW_CANONICAL,
            ),
            probe(
                "a date-shaped placeholder instead of the literal word",
                GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4], TBD"),
                ROW_CANONICAL,
            ),
            probe(
                "the newest entry stamped with a version but NO date",
                GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4]"),
                ROW_TOP_ENTRY_DATED,
            ),
            probe(
                "the newest entry with neither a version nor a date",
                GOOD.replace("## [1.5.4], 2026-08-14", "## [Next release]"),
                ROW_TOP_ENTRY_DATED,
            ),
            probe(
                "an Unreleased block buried below a shipped release",
                GOOD.replace("## [Unreleased]\n", "").replace(
                    "## [1.5.3], 2026-08-08",
                    "## [Unreleased]\n\n## [1.5.3], 2026-08-08",
                ),
                ROW_UNRELEASED_FIRST,
            ),
            probe(
                "one version number used by two entries",
                GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.4], 2026-08-08"),
                ROW_NO_DUPLICATE_VERSION,
            ),
            probe(
                "a newer version listed below an older one",
                GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.5], 2026-08-08"),
                ROW_DESCENDING,
            ),
            probe(
                "a date that increases as you read down the file",
                GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.3], 2026-08-20"),
                ROW_DESCENDING,
            ),
            probe(
                "the ordering rule still reaches a named-but-undated entry",
                staged().replace("## [1.5.3], 2026-08-08", "## [1.5.6], 2026-08-08"),
                ROW_DESCENDING,
            ),
            probe(
                "a release dated in the future",
                GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4], 2099-01-01"),
                ROW_NO_FUTURE_DATE,
            ),
            probe(
                "an empty changelog names no version anywhere",
                "# Changelog\n\nnothing has ever shipped.\n".to_string(),
                ROW_SHAPE,
            ),
            // A DOCUMENTED DELTA, probed rather than hidden. A shape-valid date naming a day that
            // does not exist is a named failure here and an unhandled exception in the legacy — it
            // exits 1 with a traceback, which the harness reads as red for the right verdict and
            // the wrong reason. The verdicts agree; the naming does not, and that is the finding.
            probe(
                "a date that is shaped right and names no real day",
                GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4], 2026-02-30"),
                ROW_NO_FUTURE_DATE,
            )
            .diverges(crate::gates::Divergence::LegacyCrashes {
                reason:
                    "the legacy raises out of date parsing and exits 1 with a traceback, so it \
                         reaches the right verdict by dying rather than by reporting a rule. This \
                         gate names the day that does not exist."
                        .to_string(),
            }),
        ]
    }
}

impl ChangelogGate {
    /// Every owed row, failed with one reason. Used where the gate could not read or could not
    /// parse: each rule below it is unproven, and unproven is not a pass.
    fn every_row_fails(&self, title: impl Into<String>, detail: impl Into<String>) -> Vec<Row> {
        let title = title.into();
        let detail = detail.into();
        self.owed()
            .into_iter()
            .map(|id| Row::fail(id, title.clone(), detail.clone()))
            .collect()
    }
}

// ── the fixtures the selftest plants ────────────────────────────────────────────────────────────

/// A correct file: staged notes on top, then two shipped entries, newest first.
const GOOD: &str = "\
# Changelog

## [Unreleased]

### Added

- Something staged.

## [1.5.4], 2026-08-14

- A shipped thing.

## [1.5.3], 2026-08-08

- An older shipped thing.
";

/// The same file with its top entry NAMED but not yet dated. Green on a branch, red on the release
/// path — the same bytes, judged by who is asking.
fn staged() -> String {
    GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4], unreleased")
}

fn plant(text: &str) -> Overlay {
    let mut ov = Overlay::new();
    ov.set("CHANGELOG.md", text);
    ov
}

// ── the grammar ─────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `## [Unreleased]` or `## [Early development]` — deliberately not a release.
    NonRelease,
    /// `## [X.Y.Z], YYYY-MM-DD`.
    Release,
    /// `## [X.Y.Z], unreleased` — a version named before it has a ship date.
    Staged,
    /// A level-2 heading that is none of the above.
    Malformed,
}

#[derive(Debug, Clone)]
struct Heading {
    lineno: usize,
    raw: String,
    kind: Kind,
    ver: Option<String>,
    date: Option<String>,
}

/// Every level-2 heading, classified. A heading that is NEARLY right is worse than one that is
/// obviously wrong — the site's rewriter has an optional date group, so a bare version publishes
/// silently as a version with no date rather than failing — so anything that is not exactly one of
/// the accepted spellings is [`Kind::Malformed`] here and named by a rule below.
fn parse(text: &str) -> Vec<Heading> {
    let mut out = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        if !line.starts_with("## ") {
            continue;
        }
        let raw = line.trim_end().to_string();
        let lineno = i + 1;
        if NON_RELEASE.contains(&raw.as_str()) {
            out.push(Heading {
                lineno,
                raw,
                kind: Kind::NonRelease,
                ver: None,
                date: None,
            });
            continue;
        }
        let parts = heading_parts(&raw).map(|(v, t)| (v.to_string(), t.to_string()));
        match parts {
            Some((ver, tail)) if is_version(&ver) && is_iso_shape(&tail) => out.push(Heading {
                lineno,
                raw,
                kind: Kind::Release,
                ver: Some(ver),
                date: Some(tail),
            }),
            // Carries its version so the ordering and duplicate rules still see it; carries no
            // date, so every date rule skips it rather than inventing one.
            Some((ver, tail)) if is_version(&ver) && tail == "unreleased" => out.push(Heading {
                lineno,
                raw,
                kind: Kind::Staged,
                ver: Some(ver),
                date: None,
            }),
            _ => out.push(Heading {
                lineno,
                raw,
                kind: Kind::Malformed,
                ver: None,
                date: None,
            }),
        }
    }
    out
}

/// `## [<left>], <right>` split into its two halves, or `None` if the heading is not that shape.
fn heading_parts(raw: &str) -> Option<(&str, &str)> {
    raw.strip_prefix("## [")?.split_once("], ")
}

/// `X.Y.Z` with an optional dotted/dashed alphanumeric pre-release.
fn is_version(s: &str) -> bool {
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    match pre {
        None => true,
        Some(p) => {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        }
    }
}

/// `YYYY-MM-DD` by SHAPE only. Whether those digits name a day that exists is a separate rule with
/// its own row, so an impossible date is a named failure rather than a heading that quietly stops
/// being a release entry.
fn is_iso_shape(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
}

/// Whether `YYYY-MM-DD` names a day that exists.
fn is_real_date(s: &str) -> bool {
    let (y, m, d) = match split_date(s) {
        Some(t) => t,
        None => return false,
    };
    if !(1..=12).contains(&m) {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let last = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if leap => 29,
        _ => 28,
    };
    (1..=last).contains(&d)
}

fn split_date(s: &str) -> Option<(i64, u32, u32)> {
    if !is_iso_shape(s) {
        return None;
    }
    Some((
        s[0..4].parse().ok()?,
        s[5..7].parse().ok()?,
        s[8..10].parse().ok()?,
    ))
}

/// Sort key with correct pre-release ordering: a pre-release sorts BELOW the version it leads to,
/// and a numeric identifier sorts below an alphanumeric one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SemverKey {
    nums: Vec<u64>,
    /// 0 for a pre-release, 1 for a plain version, so `1.0.0-rc.7` sorts below `1.0.0`.
    rank: u8,
    pre: Vec<PreId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PreId {
    Num(u64),
    Alnum(String),
}

fn semver_key(ver: &str) -> SemverKey {
    let (core, pre) = match ver.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (ver, None),
    };
    let nums = core.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    match pre {
        None => SemverKey {
            nums,
            rank: 1,
            pre: Vec::new(),
        },
        Some(p) => SemverKey {
            nums,
            rank: 0,
            pre: p
                .split('.')
                .map(|part| match part.parse::<u64>() {
                    Ok(n) if part.chars().all(|c| c.is_ascii_digit()) => PreId::Num(n),
                    _ => PreId::Alnum(part.to_string()),
                })
                .collect(),
        },
    }
}

// ── the rules, one row each ─────────────────────────────────────────────────────────────────────

fn rule_canonical(heads: &[Heading]) -> Row {
    let offenders: Vec<String> = heads
        .iter()
        .filter(|h| h.kind == Kind::Malformed)
        .map(|h| format!("line {}: `{}`", h.lineno, h.raw))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_CANONICAL,
            "every heading is one of the accepted spellings",
            format!("{} heading(s) read", heads.len()),
        )
    } else {
        Row::fail(
            ROW_CANONICAL,
            "a heading is not a valid entry heading",
            format!(
                "{} — every released entry reads exactly `## [X.Y.Z], YYYY-MM-DD`; a version named \
                 but not shipped reads `## [X.Y.Z], unreleased`, the literal word and never a \
                 date-shaped placeholder. The only other headings allowed are `{}`.",
                offenders.join(" | "),
                NON_RELEASE.join("` and `")
            ),
        )
    }
}

fn rule_unreleased_first(heads: &[Heading]) -> Row {
    let offenders: Vec<String> = heads
        .iter()
        .enumerate()
        .filter(|(idx, h)| h.raw == UNRELEASED && *idx != 0)
        .map(|(_, h)| format!("line {}", h.lineno))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_UNRELEASED_FIRST,
            "staged notes are at the top of the file or absent",
            format!("`{UNRELEASED}` is the first heading or does not appear"),
        )
    } else {
        Row::fail(
            ROW_UNRELEASED_FIRST,
            "staged notes appear below a released entry",
            format!(
                "{} — `{UNRELEASED}` belongs at the very top of the file or nowhere; buried, it \
                 publishes in the middle of shipped history",
                offenders.join(", ")
            ),
        )
    }
}

/// The newest entry is what the published page shows first. It must carry a version; whether it may
/// carry the word instead of a date is [`ROW_RELEASE_TOP_DATED`]'s question, asked by the release
/// arm alone.
fn rule_top_entry_dated(heads: &[Heading]) -> Row {
    let first = heads
        .iter()
        .position(|h| matches!(h.kind, Kind::Release | Kind::Staged));
    let Some(first) = first else {
        return Row::fail(
            ROW_TOP_ENTRY_DATED,
            "the file contains no released entry at all",
            "every heading is staged or early-development. The published changelog would have no \
             version and no date anywhere on it."
                .to_string(),
        );
    };
    let offenders: Vec<String> = heads[..first]
        .iter()
        .filter(|h| h.kind == Kind::Malformed)
        .map(|h| format!("line {}: `{}`", h.lineno, h.raw))
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_TOP_ENTRY_DATED,
            "the topmost entry carries a usable version",
            format!("`{}` at line {}", heads[first].raw, heads[first].lineno),
        )
    } else {
        Row::fail(
            ROW_TOP_ENTRY_DATED,
            "the topmost entry carries no usable version",
            format!(
                "{} — this is the heading the changelog page shows first. Write it as \
                 `## [X.Y.Z], YYYY-MM-DD`, or `## [X.Y.Z], unreleased` while the ship date is not \
                 yet a fact.",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_release_top_dated(entries: &[&Heading]) -> Row {
    match entries.first() {
        Some(top) if top.kind == Kind::Staged => Row::fail(
            ROW_RELEASE_TOP_DATED,
            "the newest entry names a version but no ship date, on the release path",
            format!(
                "line {}: `{}` names a version but no ship date, and this is the RELEASE path. The \
                 undated spelling is for a branch mid-cycle; a release being staged has a date, and \
                 the public page renders the top entry as shipped. Stamp it `## [{}], YYYY-MM-DD` \
                 and push again.",
                top.lineno,
                top.raw,
                top.ver.clone().unwrap_or_default()
            ),
        ),
        Some(top) => Row::pass(
            ROW_RELEASE_TOP_DATED,
            "the newest entry carries a real ship date",
            format!("`{}` at line {}", top.raw, top.lineno),
        ),
        None => Row::fail(
            ROW_RELEASE_TOP_DATED,
            "there is no newest entry to date",
            "the file names no version at all, so the release path has nothing to stamp".to_string(),
        ),
    }
}

fn rule_no_duplicate_version(entries: &[&Heading]) -> Row {
    let mut seen: Vec<(&str, usize)> = Vec::new();
    let mut offenders = Vec::new();
    for e in entries {
        let v = e.ver.as_deref().unwrap_or("");
        if let Some((_, first)) = seen.iter().find(|(s, _)| *s == v) {
            offenders.push(format!(
                "line {}: version {v} was already used at line {first}",
                e.lineno
            ));
        } else {
            seen.push((v, e.lineno));
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_NO_DUPLICATE_VERSION,
            "no version number is used twice",
            format!("{} versioned entr(ies)", entries.len()),
        )
    } else {
        Row::fail(
            ROW_NO_DUPLICATE_VERSION,
            "one version number is used by two entries",
            format!(
                "{} — two entries with one version number make the release ambiguous",
                offenders.join(" | ")
            ),
        )
    }
}

/// Version ordering covers EVERY entry, the named-but-undated included: an entry in the wrong place
/// is the same defect whether or not it has shipped. Date ordering is a separate walk over the
/// dated entries only.
fn rule_descending(entries: &[&Heading], releases: &[&Heading]) -> Row {
    let mut offenders = Vec::new();
    for pair in entries.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let (va, vb) = (
            a.ver.as_deref().unwrap_or(""),
            b.ver.as_deref().unwrap_or(""),
        );
        if semver_key(va) <= semver_key(vb) {
            offenders.push(format!(
                "line {}: version {vb} is not older than {va} above it at line {}",
                b.lineno, a.lineno
            ));
        }
    }
    for pair in releases.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let (da, db) = (
            a.date.as_deref().unwrap_or(""),
            b.date.as_deref().unwrap_or(""),
        );
        if da < db {
            offenders.push(format!(
                "line {}: {} is dated {db}, which is AFTER {} above it ({da})",
                b.lineno,
                b.ver.clone().unwrap_or_default(),
                a.ver.clone().unwrap_or_default()
            ));
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_DESCENDING,
            "the file reads newest-first, by version and by date",
            format!(
                "{} versioned entr(ies), {} of them dated",
                entries.len(),
                releases.len()
            ),
        )
    } else {
        Row::fail(
            ROW_DESCENDING,
            "an entry is out of order",
            format!(
                "{} — the changelog reads newest-first; an entry added in the wrong place shows a \
                 superseded release as the current one",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_no_future_date(releases: &[&Heading], today: &str) -> Row {
    let mut offenders = Vec::new();
    for r in releases {
        let d = r.date.as_deref().unwrap_or("");
        if !is_real_date(d) {
            offenders.push(format!(
                "line {}: {} is dated {d}, which is not a day that exists",
                r.lineno,
                r.ver.clone().unwrap_or_default()
            ));
        } else if d > today {
            offenders.push(format!(
                "line {}: {} is dated {d}, which is in the future (today is {today} UTC)",
                r.lineno,
                r.ver.clone().unwrap_or_default()
            ));
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_NO_FUTURE_DATE,
            "every release date is a real day, on or before today",
            format!("{} dated entr(ies) against {today} UTC", releases.len()),
        )
    } else {
        Row::fail(
            ROW_NO_FUTURE_DATE,
            "a release is dated in the future, or on a day that does not exist",
            format!(
                "{} — a release cannot have shipped on a date that has not happened; this renders \
                 as a future ship date on the public changelog",
                offenders.join(" | ")
            ),
        )
    }
}

/// A named-but-undated entry COUNTS as having notes: it is the version's section, written. Whether
/// it may ship undated is [`ROW_RELEASE_TOP_DATED`]'s question, asked by the same arm, and answering
/// it here as well would give one defect two names.
fn rule_version_has_notes(entries: &[&Heading], version: &str) -> Row {
    let Some(top) = entries.first() else {
        return Row::fail(
            ROW_VERSION_HAS_NOTES,
            "the version being tagged has no notes",
            format!(
                "{version} is about to be tagged and the changelog contains no released entry at \
                 all. Write the notes under `{UNRELEASED}` and roll them over before staging."
            ),
        );
    };
    let top_v = top.ver.clone().unwrap_or_default();
    let top_d = top.date.clone().unwrap_or_else(|| "unreleased".to_string());
    if top_v == version {
        return Row::pass(
            ROW_VERSION_HAS_NOTES,
            "the newest entry is the version being released",
            format!("`{}` at line {}", top.raw, top.lineno),
        );
    }
    match entries.iter().find(|e| e.ver.as_deref() == Some(version)) {
        None => Row::fail(
            ROW_VERSION_HAS_NOTES,
            "the version being released has no section",
            format!(
                "the changelog has NO `## [{version}], YYYY-MM-DD` section, but {version} is the \
                 version this run would tag and publish. The release body extraction is fail-soft, \
                 so this would ship a release whose notes are auto-generated commit titles and \
                 whose changelog page never mentions the version. Newest entry is {top_v} ({top_d})."
            ),
        ),
        Some(found) => Row::fail(
            ROW_VERSION_HAS_NOTES,
            "the version being released is not the newest entry",
            format!(
                "{version} is the version being released but its entry is at line {}, BELOW \
                 {top_v} ({top_d}). The newest entry must be the version being tagged, or the file \
                 says a different release is the current one.",
                found.lineno
            ),
        ),
    }
}

// ── the clock ───────────────────────────────────────────────────────────────────────────────────

/// Today in UTC, as `YYYY-MM-DD`. A clock that cannot be read yields the epoch, which dates every
/// real entry in the future and reds the gate — fail-closed, because a date rule with no today is
/// unproven rather than satisfied.
fn today_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since the epoch to a civil date, by the standard shift-the-era algorithm — no date crate,
/// for the same reason there is no `cargo_metadata` crate here.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::{execute, verify_report};

    fn cx() -> Ctx {
        Ctx::workspace().expect("the workspace opens")
    }

    fn gate() -> ChangelogGate {
        ChangelogGate::new().with_today("2026-08-16")
    }

    #[test]
    fn the_real_tree_is_green_through_the_runner() {
        let verdict = execute(&ChangelogGate::new(), &cx());
        assert!(
            !verdict.red,
            "the tree's own CHANGELOG.md must pass the branch arm: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn the_selftest_report_is_accepted_by_the_framework() {
        let gate = gate();
        let cx = cx();
        let report = gate.selftest(&cx);
        if let Err(errs) = verify_report(&gate, &report) {
            panic!("selftest report refused: {errs:#?}");
        }
    }

    #[test]
    fn the_release_arms_carry_their_own_owed_rows_and_prove_themselves() {
        let gate = ChangelogGate::new()
            .with_today("2026-08-16")
            .require_version("1.6.0");
        assert!(gate.owed().iter().any(|o| o == ROW_RELEASE_TOP_DATED));
        assert!(gate.owed().iter().any(|o| o == ROW_VERSION_HAS_NOTES));
        let cx = cx();
        let report = gate.selftest(&cx);
        if let Err(errs) = verify_report(&gate, &report) {
            panic!("selftest report refused: {errs:#?}");
        }
    }

    #[test]
    fn a_prerelease_sorts_below_the_version_it_leads_to() {
        assert!(semver_key("1.0.0-rc.7") < semver_key("1.0.0"));
        assert!(semver_key("1.0.0-rc.2") < semver_key("1.0.0-rc.10"));
        assert!(semver_key("1.0.0-alpha") < semver_key("1.0.0-rc"));
        assert!(semver_key("1.5.4") > semver_key("1.5.3"));
    }

    #[test]
    fn the_accepted_spellings_and_nothing_else() {
        let heads = parse(
            "## [Unreleased]\n## [1.6.0], unreleased\n## [1.5.4], 2026-08-14\n## [1.5.4]\n\
             ## [1.5.4], TBD\n## [1.5.4], 2026-13-01\n",
        );
        let kinds: Vec<Kind> = heads.iter().map(|h| h.kind).collect();
        assert_eq!(
            kinds,
            vec![
                Kind::NonRelease,
                Kind::Staged,
                Kind::Release,
                Kind::Malformed,
                Kind::Malformed,
                // shape-valid, calendar-invalid: a date rule names it, the grammar does not hide it
                Kind::Release,
            ]
        );
    }

    #[test]
    fn an_impossible_day_is_named_rather_than_silently_skipped() {
        let ov = plant(&GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4], 2026-02-30"));
        let verdict = execute(&gate(), &cx().with_overlay(ov));
        assert!(verdict.red);
        assert!(verdict
            .rows
            .iter()
            .any(|r| r.id == ROW_NO_FUTURE_DATE && r.detail.contains("not a day that exists")));
    }

    #[test]
    fn an_unreadable_changelog_fails_every_owed_row() {
        let mut ov = Overlay::new();
        ov.remove("CHANGELOG.md");
        let g = gate();
        let verdict = execute(&g, &cx().with_overlay(ov));
        assert!(verdict.red);
        for id in g.owed() {
            assert!(
                verdict
                    .rows
                    .iter()
                    .any(|r| r.id == id && r.status == crate::ledger::Status::Fail),
                "{id} must FAIL when the file cannot be read, never go missing"
            );
        }
    }

    #[test]
    fn a_file_that_names_no_version_cannot_have_the_release_notes() {
        // Headings, but not one of them a version: every version rule below must say so rather
        // than find nothing to judge and answer green.
        let ov = plant("# Changelog\n\n## [Unreleased]\n\n- staged.\n");
        let g = ChangelogGate::new()
            .with_today("2026-08-16")
            .require_version("1.6.0");
        let verdict = execute(&g, &cx().with_overlay(ov));
        assert!(verdict.red);
        assert!(verdict.rows.iter().any(
            |r| r.id == ROW_VERSION_HAS_NOTES && r.detail.contains("no released entry at all")
        ));
        assert!(verdict
            .rows
            .iter()
            .any(|r| r.id == ROW_RELEASE_TOP_DATED && r.detail.contains("nothing to stamp")));
    }

    #[test]
    fn the_civil_calendar_matches_known_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_666), (2026, 8, 1));
    }
}
