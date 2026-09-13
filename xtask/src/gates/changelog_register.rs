//! `cargo xtask gate changelog-register` — EVERY ACCEPTED DIFFERENCE NAMES ITS OWN CHANGELOG LINE.
//!
//! The shadow oracle runs the published binary and this tree against the same config, the same
//! requests and the same plugins, and every difference it finds is either fixed or ACCEPTED by the
//! owner in a register. The owner rule for an accepted difference is the same whether it is a break
//! or an improvement: it is accepted with sign-off, NAMED IN THE CHANGELOG. The oracle's own differ
//! already refuses a register entry that accepts an observable difference without a `changelog`
//! field; this gate closes the other half of that contract — that the named line was actually
//! WRITTEN, not merely declared — so the release notes cannot drift silently out of sync with what
//! the owner accepted.
//!
//! THREE OUTCOMES PER ENTRY, and the middle one is the point:
//!
//! * the entry names a line and that line is present, verbatim, in the newest release section;
//! * the entry owes no line and SAYS SO IN THE OPEN — an explicit null plus a written reason. A
//!   waiver is an argument a reviewer can disagree with, never an omission, which is the whole
//!   difference between "we decided this needs no line" and "nobody wrote one";
//! * anything else fails: no `changelog` key at all, a blank one, a null with no reason, a line
//!   that is not in the file, or — for a `breaking` entry — a waiver at all, because a break the
//!   owner accepted is user-visible by definition and always owes a line.
//!
//! THE SEARCH IS ANCHORED TO THE NEWEST SECTION, and once it was not. The check asked whether a
//! line appeared ANYWHERE in the file, as an unanchored substring over an append-only history of a
//! dozen releases — so the register was satisfied by prose written for an old version that happens
//! to contain the same words, and an entry could count as "named in the changelog" while the
//! section this release actually publishes said nothing about it. An accepted difference is named
//! in the notes THIS release ships; no older section can discharge it.
//!
//! MATCHING IS WHITESPACE-NORMALISED AND NOTHING ELSE. A markdown line wrapped across two source
//! lines still matches; no word is added, removed or reordered.
//!
//! ZERO IS NOT CLEAN, and this gate is where that rule earns its keep. The owed set is one JSON key
//! in a file this gate does not own — the register belongs to the oracle, and a differ refactor
//! that renames the key would empty the owed set silently. `changelog: no entries found` and `this
//! gate has stopped reading its input` produced identical output and both exited 0. So a register
//! that is missing, unparseable, keyed differently, holding something that is not a list, or
//! holding an EMPTY list is a named failure of its own row — never "no missing lines, therefore
//! green". A denominator of zero satisfies every ban vacuously.
//!
//! The register is read AS DATA, with `serde_json`, exactly as the oracle's golden ledger is. The
//! oracle's code is never invoked from here, and the segregation gate's data allowlist is what says
//! so out loud.

use serde_json::Value;

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

/// The register itself resolved: readable, parseable, keyed as expected, and holding at least one
/// entry. Every other row below is vacuous without it.
pub const ROW_REGISTER: &str = "changelog-register:register-resolved";
/// The changelog offers a newest `## [x.y.z]` section for the search to anchor to.
pub const ROW_SECTION: &str = "changelog-register:newest-section";
/// Every entry declares its intent: a line, or an explicit waiver with a written reason.
pub const ROW_DECLARED: &str = "changelog-register:entry-declares-a-line";
/// Every named line is present, verbatim, in that newest section.
pub const ROW_PRESENT: &str = "changelog-register:line-present-verbatim";
/// A `breaking` entry may never waive.
pub const ROW_BREAKING: &str = "changelog-register:breaking-never-waives";
/// Emitted only by the release arm; see [`ChangelogRegisterGate::require_version`].
pub const ROW_VERSION: &str = "changelog-register:release-section-is-the-version";

/// The oracle's accepted-differences register, read as data.
pub const DEFAULT_REGISTER: &str = "testing/shadow-oracle/accepted-differences.json";
/// The one JSON key the owed set comes from.
const ACCEPTED_KEY: &str = "accepted";

pub struct ChangelogRegisterGate {
    pub register: String,
    pub changelog: String,
    /// The release-time arm. See [`ChangelogRegisterGate::require_version`].
    pub require_version: Option<String>,
}

impl Default for ChangelogRegisterGate {
    fn default() -> ChangelogRegisterGate {
        ChangelogRegisterGate {
            register: DEFAULT_REGISTER.to_string(),
            changelog: "CHANGELOG.md".to_string(),
            require_version: None,
        }
    }
}

impl ChangelogRegisterGate {
    pub fn new() -> ChangelogRegisterGate {
        ChangelogRegisterGate::default()
    }

    /// THE RELEASE ARM, and it is what makes the anchor above mean anything at release time. Every
    /// other rule here judges entries against "the newest section", whichever version that happens
    /// to be. On a branch that is the right question. On the release path it is not: if the newest
    /// section is still the PREVIOUS release, every accepted difference for the version being
    /// tagged would be discharged by the last release's prose and the gate would go green over
    /// notes that never mentioned any of them. So the release path names the version it is tagging
    /// — the same version it hands `changelog --require-version` — and the section the search
    /// anchors to must be that one. A named method, not an environment variable: the one
    /// strict/loose pair in the shell that was overridable from a `run:` line is the cautionary
    /// case for every pair since.
    pub fn require_version(mut self, version: impl Into<String>) -> ChangelogRegisterGate {
        self.require_version = Some(version.into());
        self
    }
}

impl Gate for ChangelogRegisterGate {
    fn name(&self) -> &'static str {
        "changelog-register"
    }

    fn owed(&self) -> Vec<String> {
        let mut owed = vec![
            ROW_REGISTER.to_string(),
            ROW_SECTION.to_string(),
            ROW_DECLARED.to_string(),
            ROW_PRESENT.to_string(),
            ROW_BREAKING.to_string(),
        ];
        if self.require_version.is_some() {
            owed.push(ROW_VERSION.to_string());
        }
        owed
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let entries = match self.read_entries(cx) {
            Ok(e) => e,
            Err(detail) => {
                let mut rows = self.every_row_fails(
                    "the register did not resolve",
                    "unproven: the owed set could not be read, and an owed set of zero satisfies \
                     every rule below vacuously",
                );
                rows.retain(|r| r.id != ROW_REGISTER);
                rows.insert(
                    0,
                    Row::fail(ROW_REGISTER, "the register did not resolve", detail),
                );
                return Verdict::of(rows);
            }
        };

        let text = match cx.read(&self.changelog) {
            Ok(t) => t,
            Err(e) => {
                let mut rows = self.every_row_fails(
                    format!("{} is unreadable", self.changelog),
                    format!("{e} — an unreadable changelog names nothing"),
                );
                rows.retain(|r| r.id != ROW_REGISTER);
                rows.insert(0, self.register_pass(&entries));
                return Verdict::of(rows);
            }
        };

        let Some(section) = newest_section(&text) else {
            let mut rows = self.every_row_fails(
                "the changelog offers no section to anchor to",
                "unproven: with no section, an unanchored search over the whole file would be \
                 satisfied by any older release's prose",
            );
            rows.retain(|r| r.id != ROW_REGISTER && r.id != ROW_SECTION);
            rows.insert(0, self.register_pass(&entries));
            rows.insert(
                1,
                Row::fail(
                    ROW_SECTION,
                    "the changelog has no `## [x.y.z]` section heading",
                    format!(
                        "{}: there is no release section to search, and an unanchored search over \
                         the whole file would be satisfied by any older release's prose",
                        self.changelog
                    ),
                ),
            );
            return Verdict::of(rows);
        };

        let mut rows = vec![
            self.register_pass(&entries),
            Row::pass(
                ROW_SECTION,
                "the newest release section resolved",
                format!(
                    "`## [{}]` in {}, {} character(s) of notes",
                    section.version,
                    self.changelog,
                    section.body.len()
                ),
            ),
            rule_declared(&entries),
            rule_breaking(&entries),
            rule_present(&entries, &section),
        ];
        if let Some(version) = &self.require_version {
            rows.push(rule_release_section(&section, version));
        }
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        // BOTH ARMS' GATES ARE BUILT ABOVE THE REPORT. A case is taken on whichever thread reaches
        // it, so a gate this function builds has to outlive the report that holds the case naming
        // it, and declaration order is what says so.
        let gate = ChangelogRegisterGate::new();
        let release = ChangelogRegisterGate::new().require_version("1.7.0");
        let mut report = Report::new();
        let owed = gate.owed();
        let owed_refs: Vec<&str> = owed.iter().map(String::as_str).collect();

        // The unplanted tree. Without it every RED below proves only that the gate is broken.
        report.push(prove_green(
            cx,
            &gate,
            "the real register is fully named in the real changelog",
            &owed_refs,
        ));

        // A named line present in the newest section, both kinds, plus a wrapped line: the green
        // twin every RED below is measured against.
        report.push(prove_green(
            &cx.with_overlay(plant(
                &register(&[
                    r#"{"id":"X-1","kind":"improvement","changelog":"the grass is now greener"}"#,
                    r#"{"id":"X-2","kind":"breaking","changelog":"the sky is now a lovely green"}"#,
                ]),
                "## [1.6.0], unreleased\n\n- the grass is now greener\n- the sky is now a lovely\n  green\n",
            )),
            &gate,
            "improvement and breaking entries named, one of them line-wrapped",
            &[ROW_PRESENT, ROW_DECLARED, ROW_BREAKING],
        ));

        report.push(prove_red(
            cx,
            &gate,
            "a named line missing from the changelog",
            &[ROW_PRESENT],
            plant(
                &register(&[
                    r#"{"id":"X-2","kind":"breaking","changelog":"the sky is now green"}"#,
                    r#"{"id":"X-6","kind":"improvement","changelog":"never written"}"#,
                ]),
                "## [1.6.0]\n\n- the grass is now greener\n",
            ),
            &[ROW_PRESENT, "X-2", "X-6"],
        ));

        // THE ANCHOR. Both lines are in the file, verbatim — in the section of a release that
        // shipped a year ago. Unanchored this passed, and deleting the line from the current
        // section changed nothing.
        report.push(prove_red(
            cx,
            &gate,
            "lines present only in an older release section",
            &[ROW_PRESENT],
            plant(
                &register(&[
                    r#"{"id":"X-1","kind":"improvement","changelog":"the grass is now greener"}"#,
                ]),
                "## [1.6.0], unreleased\n\n- an unrelated note\n\n## [1.5.0], 2026-08-01\n\n\
                 - the grass is now greener\n",
            ),
            &[ROW_PRESENT, "X-1"],
        ));

        report.push(prove_red(
            cx,
            &gate,
            "an entry with no changelog key at all",
            &[ROW_DECLARED],
            plant(
                &register(&[
                    r#"{"id":"X-7","kind":"improvement","rationale":"silent"}"#,
                    r#"{"id":"X-3","kind":"breaking"}"#,
                ]),
                GOOD_CHANGELOG,
            ),
            &[ROW_DECLARED, "X-7", "X-3"],
        ));

        report.push(prove_red(
            cx,
            &gate,
            "a waiver with no reason written beside it",
            &[ROW_DECLARED],
            plant(
                &register(&[r#"{"id":"X-8","kind":"improvement","changelog":null}"#]),
                GOOD_CHANGELOG,
            ),
            &[ROW_DECLARED, "X-8", "no `changelog_reason`"],
        ));

        report.push(prove_red(
            cx,
            &gate,
            "an entry whose changelog field is blank",
            &[ROW_DECLARED],
            plant(
                &register(&[r#"{"id":"X-10","kind":"improvement","changelog":"   "}"#]),
                GOOD_CHANGELOG,
            ),
            &[ROW_DECLARED, "X-10"],
        ));

        report.push(prove_red(
            cx,
            &gate,
            "a breaking entry trying to waive its line",
            &[ROW_BREAKING],
            plant(
                &register(&[r#"{"id":"X-9","kind":"breaking","changelog":null,
                        "changelog_reason":"we would rather not say"}"#]),
                GOOD_CHANGELOG,
            ),
            &[ROW_BREAKING, "X-9"],
        ));

        // -- ZERO IS NOT CLEAN, four ways ---------------------------------------------------------
        report.push(prove_red(
            cx,
            &gate,
            "a register that parsed to zero entries",
            &[ROW_REGISTER],
            plant(&register(&[]), GOOD_CHANGELOG),
            &[ROW_REGISTER, "zero entries"],
        ));

        report.push(prove_red(
            cx,
            &gate,
            "a register whose owed-set key has been renamed",
            &[ROW_REGISTER],
            plant(
                r#"{"differences":[{"id":"X-6","kind":"breaking","changelog":"nobody checks this"}]}"#,
                GOOD_CHANGELOG,
            ),
            &[ROW_REGISTER, "no `accepted` key"],
        ));

        report.push(prove_red(
            cx,
            &gate,
            "an accepted key that is not a list",
            &[ROW_REGISTER],
            plant(
                r#"{"accepted":{"X-7":{"kind":"breaking"}}}"#,
                GOOD_CHANGELOG,
            ),
            &[ROW_REGISTER, "not a list"],
        ));

        let mut gone = Overlay::new();
        gone.remove(DEFAULT_REGISTER);
        report.push(prove_red(
            cx,
            &gate,
            "a register file that is not there at all",
            &[ROW_REGISTER],
            gone,
            &[ROW_REGISTER, "could not be read"],
        ));

        report.push(prove_red(
            cx,
            &gate,
            "a changelog with no release section to anchor to",
            &[ROW_SECTION],
            plant(
                &register(&[
                    r#"{"id":"X-1","kind":"improvement","changelog":"the grass is now greener"}"#,
                ]),
                "- the grass is now greener\n",
            ),
            &[ROW_SECTION, "no `## [x.y.z]` section heading"],
        ));

        // -- THE RELEASE ARM, red and green ------------------------------------------------------
        report.push(prove_red(
            cx,
            &release,
            "the newest section is not the version being released",
            &[ROW_VERSION],
            plant(
                &register(&[
                    r#"{"id":"X-1","kind":"improvement","changelog":"the grass is now greener"}"#,
                ]),
                "## [1.6.0], unreleased\n\n- the grass is now greener\n",
            ),
            &[ROW_VERSION, "1.7.0", "1.6.0"],
        ));
        report.push(prove_green(
            &cx.with_overlay(plant(
                &register(&[
                    r#"{"id":"X-1","kind":"improvement","changelog":"the grass is now greener"}"#,
                ]),
                "## [1.7.0], 2026-09-01\n\n- the grass is now greener\n",
            )),
            &release,
            "the newest section IS the version being released",
            &[ROW_VERSION],
        ));

        report.sealed()
    }

    /// THE PARITY PROBES, and one thing about them has to be said plainly rather than smoothed
    /// over: THE TWO SIDES NAME THE SAME RULES DIFFERENTLY. The legacy prints one line per REGISTER
    /// ENTRY, keyed by that entry's id; this gate emits one row per RULE, keyed by a rule id, so
    /// the entry ids move into the row's detail. `expect_rule` is therefore satisfied on this side
    /// and not on the legacy's, and each probe below records the legacy substring that identifies
    /// the same rule so the split can be documented rather than discovered later.
    ///
    /// The alternative — dropping `expect_rule` — is worse, not weaker: the harness reads a probe
    /// with no rule as one that must be GREEN on both sides, so a violation probe would assert the
    /// opposite of what it plants.
    ///
    /// Two probes are DOCUMENTED DELTAS where this gate is deliberately stricter, and they are here
    /// precisely so the difference is measured: a register that parsed to zero entries, and a
    /// register whose key was renamed. The legacy exits 0 on the first of those.
    ///
    /// The release arm has no probe: the legacy script has no counterpart flag, so there is nothing
    /// to compare and inventing an invocation for it would prove only that this gate agrees with
    /// itself.
    fn parity_probes(&self, _cx: &Ctx) -> Vec<crate::gates::ParityProbe> {
        let materialize = vec![
            DEFAULT_REGISTER.to_string(),
            "CHANGELOG.md".to_string(),
            // The wrapper invokes the Python by RELATIVE path from its own directory, so the
            // Python has to be in the planted tree too; without it the wrapper exits 2 and the
            // harness refuses the run rather than reporting a green nobody produced.
            "scripts/changelog-register-check.py".to_string(),
        ];
        // The legacy prints one line per REGISTER ENTRY, keyed by that entry's id; this gate owes
        // one row per RULE, because an id that moves with a data file cannot be a `Gate::owed` set.
        // Each probe therefore carries the legacy's own wording, so the comparison stays about the
        // same rule across that rename instead of decaying into "both went red somehow".
        let probe = |label: &str, reg: String, changelog: &str, rule: &str, legacy: &str| {
            crate::gates::ParityProbe::red(label, plant(&reg, changelog), materialize.clone(), rule)
                .named_by(legacy)
        };
        let named = r#"{"id":"X-1","kind":"improvement","changelog":"the grass is now greener"}"#;
        vec![
            // legacy names it: `FAIL    X-2  changelog line not found verbatim`
            probe(
                "a named line missing from the changelog",
                register(&[
                    r#"{"id":"X-2","kind":"breaking","changelog":"the sky is now green"}"#,
                    r#"{"id":"X-6","kind":"improvement","changelog":"never written"}"#,
                ]),
                "## [1.6.0]\n\n- the grass is now greener\n",
                ROW_PRESENT,
                "changelog line not found verbatim in the",
            ),
            // legacy names it: the same `not found verbatim in the 1.6.0 section` line, which is
            // what makes the anchor visible on both sides.
            probe(
                "lines present only in an older release section",
                register(&[named]),
                "## [1.6.0], unreleased\n\n- an unrelated note\n\n## [1.5.0], 2026-08-01\n\n\
                 - the grass is now greener\n",
                ROW_PRESENT,
                "changelog line not found verbatim in the",
            ),
            // legacy names it: `carries no `changelog` key at all`
            probe(
                "an entry with no changelog key at all",
                register(&[
                    r#"{"id":"X-7","kind":"improvement","rationale":"silent"}"#,
                    r#"{"id":"X-3","kind":"breaking"}"#,
                ]),
                GOOD_CHANGELOG,
                ROW_DECLARED,
                "carries no `changelog` key at all",
            ),
            // legacy names it: `no `changelog_reason` says why no line is owed`
            probe(
                "a waiver with no reason written beside it",
                register(&[r#"{"id":"X-8","kind":"improvement","changelog":null}"#]),
                GOOD_CHANGELOG,
                ROW_DECLARED,
                "no `changelog_reason` says why no line is owed",
            ),
            // legacy names it: `kind=breaking may not waive its CHANGELOG line`
            probe(
                "a breaking entry trying to waive its line",
                register(&[r#"{"id":"X-9","kind":"breaking","changelog":null,
                        "changelog_reason":"we would rather not say"}"#]),
                GOOD_CHANGELOG,
                ROW_BREAKING,
                "kind=breaking may not waive its CHANGELOG line",
            ),
            // legacy names it: `has no `accepted` key`
            probe(
                "a register whose owed-set key has been renamed",
                r#"{"differences":[{"id":"X-6","kind":"breaking","changelog":"unchecked"}]}"#
                    .to_string(),
                GOOD_CHANGELOG,
                ROW_REGISTER,
                "has no `accepted` key",
            ),
            // legacy names it: ``accepted` is dict, not a list`
            probe(
                "an accepted key that is not a list",
                r#"{"accepted":{"X-7":{"kind":"breaking"}}}"#.to_string(),
                GOOD_CHANGELOG,
                ROW_REGISTER,
                "`accepted` is dict, not a list",
            ),
            // legacy names it: `has no `## [x.y.z]` section heading`
            probe(
                "a changelog with no release section to anchor to",
                register(&[named]),
                "- the grass is now greener\n",
                ROW_SECTION,
                "has no `## [x.y.z]` section heading",
            ),
            // THE DELTA. The legacy calls an empty register `0 register entries -- nothing owed`
            // and exits 0; this gate calls it a gate with no input. The probe exists to measure
            // that, not to pass it.
            probe(
                "a register that parsed to zero entries",
                register(&[]),
                GOOD_CHANGELOG,
                ROW_REGISTER,
                "",
            )
            .diverges(crate::gates::Divergence::LegacyGreen {
                reason:
                    "the legacy reads an empty accepted list as nothing owed and exits 0, so a \
                         renamed key or a truncated write is indistinguishable from a clean \
                         register. Zero rows against a non-empty owed set is this crate's oldest \
                         refusal and it applies to the register's own input too."
                        .to_string(),
            }),
        ]
    }
}

impl ChangelogRegisterGate {
    fn every_row_fails(&self, title: impl Into<String>, detail: impl Into<String>) -> Vec<Row> {
        let title = title.into();
        let detail = detail.into();
        self.owed()
            .into_iter()
            .map(|id| Row::fail(id, title.clone(), detail.clone()))
            .collect()
    }

    fn register_pass(&self, entries: &[Entry]) -> Row {
        Row::pass(
            ROW_REGISTER,
            "the register resolved and holds entries to judge",
            format!(
                "{}: {} accepted difference(s) under `{ACCEPTED_KEY}`",
                self.register,
                entries.len()
            ),
        )
    }

    /// The owed set, as data. Every way this can fail to produce entries is an error string, never
    /// an empty list — the two readings this gate exists to keep apart.
    fn read_entries(&self, cx: &Ctx) -> Result<Vec<Entry>, String> {
        let text = cx.read(&self.register).map_err(|e| {
            format!("{} could not be read: {e} — an unreadable register owes nothing, which is the reading this gate refuses", self.register)
        })?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} did not parse as JSON: {e}", self.register))?;
        let Some(map) = value.as_object() else {
            return Err(format!(
                "{} is not a JSON object, so it carries no `{ACCEPTED_KEY}` key",
                self.register
            ));
        };
        let Some(accepted) = map.get(ACCEPTED_KEY) else {
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            return Err(format!(
                "{} has no `{ACCEPTED_KEY}` key (top level: {}) — this gate reads the register by \
                 that one key, so an absent key silently empties the owed set and would report \
                 green over every accepted difference in the file, breaking ones included",
                self.register,
                keys.join(", ")
            ));
        };
        let Some(list) = accepted.as_array() else {
            return Err(format!(
                "{}: `{ACCEPTED_KEY}` is not a list — nothing can be enumerated from it",
                self.register
            ));
        };
        if list.is_empty() {
            return Err(format!(
                "{}: `{ACCEPTED_KEY}` holds zero entries. A denominator of zero satisfies every \
                 rule below vacuously, so an empty register is a gate with no input rather than a \
                 clean one; delete the gate deliberately or keep the register honest",
                self.register
            ));
        }
        Ok(list.iter().map(Entry::of).collect())
    }
}

/// One accepted difference, reduced to what this gate judges.
#[derive(Debug, Clone)]
struct Entry {
    id: String,
    kind: String,
    /// What the `changelog` field says: absent, an explicit waiver, or a line.
    declares: Declares,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Declares {
    /// No `changelog` key at all — the shape the register carried before the rule existed.
    Absent,
    /// An explicit null: this difference owes no line, and says so.
    Waived,
    /// A line, verbatim.
    Line(String),
    /// Present but unusable: blank, or not a string.
    Unusable(String),
}

impl Entry {
    fn of(value: &Value) -> Entry {
        let s = |k: &str| {
            value
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let id = match value.get("id").and_then(Value::as_str) {
            Some(id) => id.to_string(),
            None => "<unnamed>".to_string(),
        };
        let kind = match value.get("kind").and_then(Value::as_str) {
            Some(k) => k.to_string(),
            None => "<no kind>".to_string(),
        };
        let declares = match value.get("changelog") {
            None => Declares::Absent,
            Some(Value::Null) => Declares::Waived,
            Some(Value::String(line)) if !line.trim().is_empty() => Declares::Line(line.clone()),
            Some(other) => Declares::Unusable(other.to_string()),
        };
        Entry {
            id,
            kind,
            declares,
            reason: s("changelog_reason"),
        }
    }
}

/// The newest release section of the changelog: the topmost `## [x.y.z]` heading and everything
/// down to the next one.
struct Section {
    version: String,
    body: String,
}

fn newest_section(text: &str) -> Option<Section> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut heads = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| section_version(l).map(|v| (i, v)));
    let (start, version) = heads.next()?;
    let end = heads.next().map(|(i, _)| i).unwrap_or(lines.len());
    Some(Section {
        version,
        body: lines[start..end].join("\n"),
    })
}

/// `## [x.y.z]` at the head of a line, whatever follows the bracket — a dated heading and a
/// named-but-undated one are both sections.
fn section_version(line: &str) -> Option<String> {
    let rest = line.strip_prefix("## [")?;
    let (ver, _) = rest.split_once(']')?;
    let parts: Vec<&str> = ver.split('.').collect();
    if parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        Some(ver.to_string())
    } else {
        None
    }
}

/// Collapse every whitespace run — markdown's line wraps included — to a single space. No word is
/// added, removed or reordered: this is the only latitude the verbatim rule gives.
fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ── the rules, one row each ─────────────────────────────────────────────────────────────────────

fn rule_declared(entries: &[Entry]) -> Row {
    let mut offenders = Vec::new();
    for e in entries {
        match &e.declares {
            Declares::Absent => offenders.push(format!(
                "{}: kind={} but the entry carries no `changelog` key at all — an accepted \
                 difference owes either a named line or an explicit waiver",
                e.id, e.kind
            )),
            Declares::Waived if e.reason.trim().is_empty() => offenders.push(format!(
                "{}: `changelog` is null but no `changelog_reason` says why no line is owed — a \
                 null is a decision, not an omission",
                e.id
            )),
            Declares::Unusable(what) => offenders.push(format!(
                "{}: `changelog` is empty or not a string: {what}",
                e.id
            )),
            _ => {}
        }
    }
    let waived = entries
        .iter()
        .filter(|e| e.declares == Declares::Waived)
        .count();
    if offenders.is_empty() {
        Row::pass(
            ROW_DECLARED,
            "every accepted difference declares a line or an explicit waiver",
            format!(
                "{} entr(ies), {waived} of them explicitly waived with a written reason",
                entries.len()
            ),
        )
    } else {
        Row::fail(
            ROW_DECLARED,
            "an accepted difference declares neither a line nor a waiver",
            offenders.join(" | "),
        )
    }
}

fn rule_breaking(entries: &[Entry]) -> Row {
    let offenders: Vec<String> = entries
        .iter()
        .filter(|e| e.kind == "breaking" && e.declares == Declares::Waived)
        .map(|e| format!("{}: kind=breaking may not waive its changelog line", e.id))
        .collect();
    let breaking = entries.iter().filter(|e| e.kind == "breaking").count();
    if offenders.is_empty() {
        Row::pass(
            ROW_BREAKING,
            "no accepted break waives its changelog line",
            format!("{breaking} breaking entr(ies), none waived"),
        )
    } else {
        Row::fail(
            ROW_BREAKING,
            "an accepted break waives its changelog line",
            format!(
                "{} — an accepted break is user-visible by definition and always owes a line",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_present(entries: &[Entry], section: &Section) -> Row {
    let haystack = normalize(&section.body);
    let mut offenders = Vec::new();
    let mut named = 0usize;
    for e in entries {
        let Declares::Line(line) = &e.declares else {
            continue;
        };
        if haystack.contains(&normalize(line)) {
            named += 1;
        } else {
            offenders.push(format!(
                "{}: changelog line not found verbatim in the {} section: `{line}`",
                e.id, section.version
            ));
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_PRESENT,
            "every named line is present verbatim in the newest section",
            format!(
                "{named} of {} accepted difference(s) named in the {} section",
                entries.len(),
                section.version
            ),
        )
    } else {
        Row::fail(
            ROW_PRESENT,
            "an accepted difference names a line the changelog does not carry",
            format!(
                "{} — the line drifted or was never written, and an older release's prose cannot \
                 discharge it",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_release_section(section: &Section, version: &str) -> Row {
    if section.version == version {
        Row::pass(
            ROW_VERSION,
            "the newest section is the version being released",
            format!(
                "`## [{}]` is the anchor every line is searched in",
                section.version
            ),
        )
    } else {
        Row::fail(
            ROW_VERSION,
            "the newest section is not the version being released",
            format!(
                "{version} is the version this run would tag, but the newest section is \
                 {}. Every accepted difference would then be judged against the previous \
                 release's notes, which is the search this gate anchors precisely to avoid.",
                section.version
            ),
        )
    }
}

// ── the fixtures the selftest plants ────────────────────────────────────────────────────────────

const GOOD_CHANGELOG: &str = "## [1.6.0], unreleased\n\n- the grass is now greener\n";

/// A register document around the entry literals a case cares about.
fn register(entries: &[&str]) -> String {
    format!("{{\"accepted\":[{}]}}", entries.join(","))
}

fn plant(register_json: &str, changelog: &str) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(DEFAULT_REGISTER, register_json);
    ov.set("CHANGELOG.md", changelog);
    ov
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::{execute, verify_report};

    fn cx() -> Ctx {
        Ctx::workspace().expect("the workspace opens")
    }

    #[test]
    fn the_real_tree_is_green_through_the_runner() {
        let verdict = execute(&ChangelogRegisterGate::new(), &cx());
        assert!(
            !verdict.red,
            "every accepted difference must be named in the changelog: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn the_selftest_report_is_accepted_by_the_framework() {
        let gate = ChangelogRegisterGate::new();
        let cx = cx();
        let report = gate.selftest(&cx);
        if let Err(errs) = verify_report(&gate, &report) {
            panic!("selftest report refused: {errs:#?}");
        }
    }

    #[test]
    fn the_release_arm_carries_its_own_owed_row_and_proves_itself() {
        let gate = ChangelogRegisterGate::new().require_version("1.6.0");
        assert!(gate.owed().iter().any(|o| o == ROW_VERSION));
        let cx = cx();
        let report = gate.selftest(&cx);
        if let Err(errs) = verify_report(&gate, &report) {
            panic!("selftest report refused: {errs:#?}");
        }
    }

    #[test]
    fn an_empty_register_is_a_named_failure_not_a_vacuous_pass() {
        let ov = plant(&register(&[]), GOOD_CHANGELOG);
        let verdict = execute(&ChangelogRegisterGate::new(), &cx().with_overlay(ov));
        assert!(verdict.red);
        let row = verdict
            .rows
            .iter()
            .find(|r| r.id == ROW_REGISTER)
            .expect("the register row is owed");
        assert!(row.detail.contains("zero entries"), "{}", row.detail);
    }

    #[test]
    fn a_wrapped_line_still_matches_and_a_reordered_one_does_not() {
        let section = newest_section("## [1.6.0]\n\n- the sky is now a lovely\n  green\n")
            .expect("a section");
        assert_eq!(section.version, "1.6.0");
        assert!(normalize(&section.body).contains(&normalize("the sky is now a lovely green")));
        assert!(!normalize(&section.body).contains(&normalize("the sky is now green a lovely")));
    }

    #[test]
    fn the_anchor_is_the_newest_section_and_nothing_below_it() {
        let section = newest_section(
            "# Changelog\n\n## [1.6.0], unreleased\n\n- new prose\n\n## [1.5.0], 2026-08-01\n\n\
             - old prose\n",
        )
        .expect("a section");
        assert_eq!(section.version, "1.6.0");
        assert!(section.body.contains("new prose"));
        assert!(
            !section.body.contains("old prose"),
            "an older release's prose cannot discharge this release's entries"
        );
    }
}
