//! THE TWO RULES ABOUT THE CEILINGS THEMSELVES — `ceiling-rose` and `ceiling-slack`.
//!
//! Every other rule in this gate measures the TREE against a number in `qa/construction.toml`.
//! Nothing measured the NUMBER. Both halves of that gap were proven on this base:
//!
//! * A landing may raise a ceiling and stay green. `legacy-reach.ceiling` 92 -> 200 is a one-line
//!   edit; the row that reads it says "ratchet 92, may only go down" in its own detail and then
//!   passes at 200, because "may only go down" was prose in a message and the number was a freely
//!   edited integer. `ports-only-tests.max_per_crate.busbar-llm` 20 -> 50 turned the one standing
//!   FAIL in this gate into a PASS the same way. [`ceiling_rose`] is the answer: every integer in
//!   the two ceilings files is compared against the same integer at the branch's BASE, and any
//!   increase is refused.
//! * A ceiling with slack is a ceiling that has already been abolished. `loc-ceilings:union` sat at
//!   23 465 against 56 000 — 32 535 lines of room nobody voted for — so the row could not report a
//!   regression until the tree had grown by half again. [`ceiling_slack`] is the answer: a ceiling
//!   EQUALS today's measurement or the gate is red, and `--write` re-pins it, DOWNWARD ONLY.
//!
//! WHY `--write` NEVER RAISES. A ceiling that rises is the landing that grew the coupling, and the
//! whole point of `ceiling-rose` is that such a rise is reviewed rather than absorbed. A `--write`
//! that raised would be `ceiling-rose`'s own bypass, one flag away, in the same binary. So the
//! re-pin is monotone: a row measuring BELOW its ceiling is re-pinned to what it measures, and a
//! row measuring ABOVE its ceiling is left exactly where it is and stays RED until somebody drains
//! it or the owner moves the number by hand, in a diff.
//!
//! WHERE THE NUMBER LIVES IS DERIVED, NOT TABLED. [`pins`] builds the row-id -> `(table, key)` map
//! from the ceilings file itself — the kernel-file rows from `rules.loc-ceilings.kernel_files`, the
//! per-crate rows from `gate.plane_crates`, the reach rows from `rules.legacy-reach.prefixes` — so
//! a kernel file, a plane or a retiring crate added to the data brings its pin with it, and a pin
//! for a row that no longer exists is refused by the same reconciliation every other row is.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::gates::construction::model::{plain, CRow, Cfg};
use crate::gates::construction::{CEILINGS, SURFACE};

/// The other ceilings file this gate watches. It is not read by any construction rule — it is the
/// `kind-isolation:matrix` allowance — and it is watched HERE because `ceiling-rose` is one claim
/// about one property ("no number in a qa ceilings file went up on this branch") and splitting it
/// across two gates would give a landing that edits both a row in each and a reader neither.
pub const KIND_CEILINGS: &str = "qa/kind-isolation.toml";

/// The line the branch is measured against. The merge-base with it is the BASE.
pub const INTEGRATION_REF: &str = "origin/integration/oracle-phase0";

pub const ROW_ROSE: &str = "ceiling-rose";
pub const ROW_SLACK: &str = "ceiling-slack";

/// One ceiling: the row it governs, and the exact place in the ceilings file the number is written.
#[derive(Debug, Clone)]
pub struct Pin {
    pub row: String,
    /// The TOML table path, as [`crate::toml_doc::Document::table`] spells it.
    pub table: String,
    pub key: String,
}

impl Pin {
    fn new(row: impl Into<String>, table: impl Into<String>, key: impl Into<String>) -> Pin {
        Pin {
            row: row.into(),
            table: table.into(),
            key: key.into(),
        }
    }
}

/// Every ceiling this gate ratchets, derived from the ceilings file.
///
/// The rows deliberately NOT here are the ones whose threshold is a POLICY rather than a
/// measurement: `max_extra_sites = 0`, `max_hits = 0`, `max_lines = 200`. Zero is not slack — a
/// rule that permits nothing is already exact — and a function-length limit is a rule about the
/// shape of a function, not a ratchet over what the tree happens to contain today. Re-pinning
/// those to today's measurement would turn every one of them from a rule into a high-water mark.
pub fn pins(cfg: &Cfg) -> Vec<Pin> {
    let mut out = vec![
        Pin::new(
            "loc-ceilings:kernel",
            "rules.loc-ceilings",
            "kernel_ceiling",
        ),
        Pin::new(
            "loc-ceilings:caps-contract",
            "rules.loc-ceilings",
            "caps_contract_ceiling",
        ),
        Pin::new(
            "loc-ceilings:unit-total",
            "rules.loc-ceilings",
            "unit_total_ceiling",
        ),
        Pin::new(
            "loc-ceilings:unit-verbs",
            "rules.loc-ceilings",
            "verbs_ceiling",
        ),
        Pin::new("loc-ceilings:union", "rules.loc-ceilings", "union_ceiling"),
        Pin::new("legacy-reach", "rules.legacy-reach", "ceiling"),
    ];
    for (key, _) in cfg.doc.children("rules.loc-ceilings.kernel_files") {
        out.push(Pin::new(
            format!("loc-ceilings:kernel:{key}"),
            format!("rules.loc-ceilings.kernel_files.{key}"),
            "ceiling",
        ));
    }
    for (key, _) in cfg.doc.children("rules.legacy-reach.prefixes") {
        out.push(Pin::new(
            format!("legacy-reach:{key}"),
            format!("rules.legacy-reach.prefixes.{key}"),
            "figure",
        ));
    }
    for (id, key, ..) in SURFACE {
        out.push(Pin::new(
            format!("surface-ceiling:{id}"),
            "gate.surface_ceilings",
            key,
        ));
    }
    for crate_name in cfg
        .gate()
        .map(|g| g.list_of("plane_crates"))
        .unwrap_or_default()
    {
        out.push(Pin::new(
            format!("ports-only:{crate_name}"),
            "rules.ports-only.max_per_crate",
            crate_name.clone(),
        ));
        out.push(Pin::new(
            format!("ports-only-tests:{crate_name}"),
            "rules.ports-only-tests.max_per_crate",
            crate_name,
        ));
    }
    out
}

// ── ceiling-slack ────────────────────────────────────────────────────────────────────────────────

/// A ceiling EQUALS what it measures, or it is slack somebody can spend without a diff.
///
/// The row is computed from the OTHER ROWS' measurements rather than by re-measuring, so it cannot
/// disagree with the rule it is about: the number it compares is the number that row printed.
///
/// One measurement is not slack and is excluded by name: a row measuring ABOVE its ceiling — that
/// is the row's own FAIL, not slack, and this rule saying so a second time would be one finding
/// printed twice.
///
/// A VACUOUS row USED TO BE EXCLUDED TOO, on the reasoning that re-pinning to the count of nothing
/// would write a ceiling of 0 for a crate that is not here. That reasoning had it backwards: it
/// meant a rule whose subject went missing kept the ceiling it earned when the subject existed,
/// ready to absorb the subject's return at any size, while the rule itself printed PASS. An absent
/// subject is now RED where the row is built (see `measure`'s scan-set floor), so there is nothing
/// left to exempt — and a ceiling over a subject that is not there is slack like any other.
pub fn ceiling_slack(cfg: &Cfg, rows: &[CRow]) -> Vec<CRow> {
    let (slack, _) = slack_findings(cfg, rows);
    let detail = if slack.is_empty() {
        "every ratcheted ceiling equals what it measures".to_string()
    } else {
        format!(
            "{} ceiling(s) with slack — a ceiling above its measurement is room nobody voted for; \
             `cargo xtask gate construction --write` re-pins them (downward only): {}",
            slack.len(),
            slack
                .iter()
                .map(|s| s.line())
                .collect::<Vec<_>>()
                .join("; ")
        )
    };
    vec![plain(
        ROW_SLACK,
        slack.is_empty(),
        "every ratcheted ceiling is pinned to today's measurement",
        detail,
        slack.len() as i64,
        0,
        slack.iter().map(|s| s.line()).collect(),
    )]
}

/// One ceiling with room under it.
#[derive(Debug, Clone)]
pub struct Slack {
    pub pin: Pin,
    pub measured: i64,
    pub ceiling: i64,
}

impl Slack {
    fn line(&self) -> String {
        format!(
            "{} measures {} against ceiling {} ({}.{} = {}, slack {})",
            self.pin.row,
            self.measured,
            self.ceiling,
            self.pin.table,
            self.pin.key,
            self.ceiling,
            self.ceiling - self.measured
        )
    }
}

/// The slack list, plus the pins whose row never appeared — a pin naming no row is a stale entry in
/// exactly the way a waiver naming no hit is, and the caller reports it.
fn slack_findings(cfg: &Cfg, rows: &[CRow]) -> (Vec<Slack>, Vec<String>) {
    let by_id: BTreeMap<&str, &CRow> = rows.iter().map(|r| (r.id.as_str(), r)).collect();
    let (mut slack, mut orphan) = (Vec::new(), Vec::new());
    for pin in pins(cfg) {
        let Some(row) = by_id.get(pin.row.as_str()) else {
            orphan.push(pin.row.clone());
            continue;
        };
        // A VACUOUS ROW IS NO LONGER EXEMPT. It used to be skipped here, which meant a rule whose
        // subject had gone missing kept its ceiling AND reported no slack under it — the ceiling
        // stayed at the number it had when the subject existed, ready to absorb the subject coming
        // back at any size. `measure()` now scores an absent subject RED (see its scan-set floor),
        // and this row holds its ceiling to what it measures like every other.
        if row.current < 0 || row.current >= row.threshold {
            continue;
        }
        slack.push(Slack {
            pin,
            measured: row.current,
            ceiling: row.threshold,
        });
    }
    (slack, orphan)
}

/// `cargo xtask gate construction --write`: re-pin every slack ceiling to what it measures, and
/// strike every declared raise the base already carries.
///
/// DOWNWARD ONLY, and the monotonicity is the whole safety property — see the module header. The
/// strike is the other half of the same property: an entry the base carries excuses nothing any
/// more (see [`raises`]), so removing it changes no verdict and leaves nothing behind that a later
/// raise of the same ceiling could shelter under.
pub fn rewrite(cx: &Ctx) -> Result<String, String> {
    let cfg = super::ConstructionGate::cfg(cx)?;
    let (rows, problems) = super::ConstructionGate::measure(cx)?;
    if !problems.is_empty() {
        return Err(format!(
            "the gate could not measure every rule, so the re-pin would write a ceiling for a row \
             nobody measured: {}",
            problems.join("; ")
        ));
    }
    let (slack, orphan) = slack_findings(&cfg, &rows);
    if !orphan.is_empty() {
        return Err(format!(
            "these ceilings name a row this run did not emit, so their value cannot be re-pinned \
             from a measurement: {}",
            orphan.join(", ")
        ));
    }
    let (mut out, struck) = struck_text(cx)?;
    if slack.is_empty() && struck.is_empty() {
        return Ok(
            "every ratcheted ceiling already equals what it measures, and no declared raise has \
             expired; nothing to write"
                .to_string(),
        );
    }
    let path = cx.abs(CEILINGS);
    let mut done = Vec::new();
    for s in &slack {
        out = set_int(&out, &s.pin.table, &s.pin.key, s.measured).ok_or_else(|| {
            format!(
                "{CEILINGS} has no `{}` under [{}] to re-pin",
                s.pin.key, s.pin.table
            )
        })?;
        done.push(format!("{}: {} -> {}", s.pin.row, s.ceiling, s.measured));
    }
    for r in &struck {
        done.push(format!(
            "struck [[{RAISES}]] #{}: {} +{} — the base already carries it",
            r.ordinal, r.key, r.by
        ));
    }
    std::fs::write(&path, &out).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!(
        "re-pinned {} ceiling(s) (downward only) and struck {} expired declared raise(s) in \
         {CEILINGS}:\n  {}",
        slack.len(),
        struck.len(),
        done.join("\n  ")
    ))
}

/// Rewrite `table.key`'s integer, in place, preserving every byte around it.
///
/// A line editor rather than a serializer, because the ceilings file is 1 000 lines of the owner's
/// prose and a round-trip through a writer this crate does not have would reformat all of it — a
/// diff nobody can review is a re-pin nobody can check.
pub fn set_int(text: &str, table: &str, key: &str, value: i64) -> Option<String> {
    let mut cur = String::new();
    let mut out: Vec<String> = Vec::new();
    let mut hit = false;
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('[') && t.ends_with(']') {
            cur = t[1..t.len() - 1].trim().to_string();
            out.push(raw.to_string());
            continue;
        }
        if !hit && cur == table {
            if let Some((k, _)) = t.split_once('=') {
                if k.trim() == key && !t.starts_with('#') {
                    let indent: String = raw.chars().take_while(|c| c.is_whitespace()).collect();
                    out.push(format!("{indent}{key} = {value}"));
                    hit = true;
                    continue;
                }
            }
        }
        out.push(raw.to_string());
    }
    if !hit {
        return None;
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    Some(s)
}

// ── ceiling-rose ─────────────────────────────────────────────────────────────────────────────────

/// THE BASE THIS BRANCH IS MEASURED AGAINST.
///
/// The merge-base with the integration line, because that is the commit the branch's own edits are
/// diffed from; and `HEAD~1` when the merge-base IS `HEAD`, which is the case on the integration
/// line itself, where "what this branch changed" is what the last commit changed.
pub fn base_ref(cx: &Ctx) -> Result<String, String> {
    let head = cx.git(&["rev-parse", "HEAD"])?.trim().to_string();
    if cx.git_ref_resolves(INTEGRATION_REF) {
        if let Ok(mb) = cx.git(&["merge-base", "HEAD", INTEGRATION_REF]) {
            let mb = mb.trim().to_string();
            if !mb.is_empty() && mb != head {
                return Ok(mb);
            }
        }
    }
    cx.git(&["rev-parse", "HEAD~1"])
        .map(|s| s.trim().to_string())
}

/// No ceiling in either qa ceilings file is higher than it was at the base.
///
/// EVERY NUMBER IS A CEILING HERE, and that is deliberate rather than lazy. The alternative is a
/// list of which keys count, and a list is exactly the thing the next rule to be added forgets to
/// join — the `[[cell]] count` rows in `qa/kind-isolation.toml` are hundreds of numbers that no
/// hand-kept list would have covered. The owner's ruling is "I'd rather it false-fail than not": a
/// number that legitimately rises reddens this row and is unredded by the review that should have
/// accompanied it, which is the transaction this rule exists to force.
///
/// "NUMBER" RATHER THAN "INTEGER" IS THE LOAD-BEARING WORD, and this comment used to get it wrong.
/// The kind-isolation counts are all written as quoted strings (`count = "122"`), so for as long as
/// [`ints_of`] read TOML integers only, this row measured NOTHING in that file while its own doc
/// comment named those numbers as the reason it scans everything. See [`ints_of`].
///
/// A base that cannot be established is RED, never green. "The branch has no history here" is the
/// state a shallow clone is in, and a ratchet that switches itself off on the runner where it is
/// cheapest to switch off is not a ratchet.
///
/// THE ONE WAY THROUGH IS A DECLARED RAISE, and it is a transaction rather than a hole — see
/// [`raises`] for the shape and [`Declared`] for how an entry lives, expires and is refused. The
/// verdict over a ceiling that rose is: the LIVE entries for that ceiling sum to EXACTLY the rise,
/// or the row is red and says which side is short.
pub fn ceiling_rose(cx: &Ctx) -> Vec<CRow> {
    let base = match base_ref(cx) {
        Ok(b) => b,
        Err(e) => {
            return vec![plain(
                ROW_ROSE,
                false,
                ROSE_TITLE,
                format!(
                    "no base commit could be established, so no ceiling could be compared \
                     against one ({e}). A ratchet that cannot read its own history reports \
                     nothing, and reporting nothing is not passing."
                ),
                -1,
                0,
                vec![],
            )]
        }
    };
    let short = &base[..8.min(base.len())];
    let declared = raises(cx, &base);
    let mut risen: Vec<String> = declared.refused.clone();
    let mut allowed: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    // Every LIVE entry whose ceiling rose is judged, one way or the other, by the loop below; what
    // is left afterwards is an entry describing a rise that did not happen.
    let mut judged: BTreeSet<usize> = BTreeSet::new();

    for file in [CEILINGS, KIND_CEILINGS] {
        let now = match cx.read(file) {
            Ok(t) => t,
            Err(e) => {
                unreadable.push(format!("{file} on this tree: {e}"));
                continue;
            }
        };
        let was = match cx.git_show(&base, file) {
            Ok(t) => t,
            // A file the base did not carry is a file this branch ADDED; every number in it is new
            // and none of them rose.
            Err(_) => continue,
        };
        let (now, was) = match (ints_of(&now), ints_of(&was)) {
            (Ok(a), Ok(b)) => (a, b),
            (a, b) => {
                for (which, r) in [("this tree", a), ("the base", b)] {
                    if let Err(e) = r {
                        unreadable.push(format!("{file} at {which}: {e}"));
                    }
                }
                continue;
            }
        };
        for (path, before) in &was {
            let Some(after) = now.get(path) else { continue };
            if after <= before {
                continue;
            }
            let rise = after - before;
            let key = format!("{file}:{path}");
            let live: Vec<(usize, &Raise)> = declared
                .live
                .iter()
                .enumerate()
                .filter(|(_, r)| r.key == key)
                .collect();
            judged.extend(live.iter().map(|(i, _)| *i));
            let sum: i64 = live.iter().map(|(_, r)| r.by).sum();
            let entries = live
                .iter()
                .map(|(_, r)| r.line())
                .collect::<Vec<_>>()
                .join(", ");
            if live.is_empty() {
                risen.push(format!("{file} {path}: {before} -> {after}"));
            } else if sum == rise {
                allowed.push(format!("{file} {path}: {before} -> {after} ({entries})"));
            } else if sum > rise {
                // OVER-DECLARED. A raise declares exactly what its face measured; a `by` above the
                // rise is room the face did not spend, which is slack with a reason attached.
                risen.push(format!(
                    "{file} {path}: {before} -> {after} rose by {rise}, but its declared raises \
                     sum to {sum} ({entries}) — over-declared. A `by` is the lines the face \
                     MEASURED, not room for it: lower it to what this tree actually rose by"
                ));
            } else {
                risen.push(format!(
                    "{file} {path}: {before} -> {after} rose by {rise}, and its declared raises \
                     cover only {sum} ({entries}); the remaining {} is undeclared",
                    rise - sum
                ));
            }
        }
    }
    // A LIVE DECLARATION THAT DESCRIBES NO RISE ON THIS BRANCH IS A WAIVER THAT OUTLIVED WHAT IT
    // EXCUSED — the base does not carry it, and the ceiling it names did not move. Somebody deleted
    // the face and left the entry, or the key is misspelt.
    for (i, r) in declared.live.iter().enumerate() {
        if !judged.contains(&i) {
            risen.push(format!(
                "{}: a declared raise of +{} that is not a rise at the base {short}. The base does \
                 not carry this entry and the ceiling it names did not move on this branch: either \
                 the face it was declared for is gone — strike the entry — or the key names no \
                 ceiling that rose ({})",
                r.key,
                r.by,
                r.because_short()
            ));
        }
    }

    let ok = risen.is_empty() && unreadable.is_empty();
    // A CARRIED ENTRY IS A WARNING, NEVER A RED. The entry did its job — the base holds the figure
    // it declared — and the only thing left to do about it is to strike it, which `--write` does.
    // Red here would be a red every face pays one batch after it lands, since the strike cannot
    // ride in the same batch as the face.
    let carried = if declared.carried.is_empty() {
        String::new()
    } else {
        format!(
            "; WARN {} declared raise(s) already carried by the base {short} — `cargo xtask gate \
             construction --write` strikes them: {}",
            declared.carried.len(),
            declared
                .carried
                .iter()
                .map(|r| format!("{} {}", r.key, r.line()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let detail = if ok && allowed.is_empty() {
        format!(
            "no ceiling in {CEILINGS} or {KIND_CEILINGS} is higher than it is at the base \
             {short}{carried}"
        )
    } else if ok {
        format!(
            "no undeclared ceiling is higher than it is at the base {short}; {} declared \
             raise(s): {}{carried}",
            allowed.len(),
            allowed.join("; ")
        )
    } else if !unreadable.is_empty() {
        format!(
            "a ceilings file could not be compared against the base {short}, so no claim about it \
             can be made: {}",
            unreadable.join("; ")
        )
    } else {
        format!(
            "{} ceiling(s) ROSE since the base {short}, or a declared raise is refused. A ceiling \
             only goes down: raise one and the row that reads it stops reporting the coupling it \
             was written to report. Drain the measurement instead, or declare the raise with the \
             face that measured it: {}{carried}",
            risen.len(),
            risen.join("; ")
        )
    };
    let mut offenders = risen.clone();
    offenders.extend(unreadable.clone());
    vec![plain(
        ROW_ROSE,
        ok,
        ROSE_TITLE,
        detail,
        (risen.len() + unreadable.len()) as i64,
        0,
        offenders,
    )]
}

const ROSE_TITLE: &str = "no ceiling in a qa ceilings file is higher than it is at the base";

/// A declaration shorter than this is a shrug, not a reason.
const MIN_REASON: usize = 80;

/// The array of tables the raises are declared in.
pub const RAISES: &str = "gate.ceiling_raises";

/// THE SHAPE A DECLARED RAISE HAS, printed by every refusal that is about the shape.
pub const RAISE_SHAPE: &str = "[[gate.ceiling_raises]]\n\
    key = \"rules.loc-ceilings.caps_contract_ceiling\"\n\
    by = 10\n\
    because = \"<the face, and the lines it measured — at least 80 characters>\"\n\
    # optional: file = \"qa/kind-isolation.toml\" (default qa/construction.toml); \
    commit = \"<sha>\"";

/// ONE DECLARED RAISE: which ceiling, by how much, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raise {
    /// `<file>:<dotted path>`, the same label [`ceiling_rose`] compares under.
    pub key: String,
    pub by: i64,
    pub because: String,
    /// The face's commit, when the author knows it. Informational: an entry riding IN the face's
    /// commit cannot name that commit's own hash, so nothing is keyed on it.
    pub commit: Option<String>,
    /// Which `[[gate.ceiling_raises]]` this is, counting from 1, so a refusal can point at it.
    pub ordinal: usize,
}

impl Raise {
    fn line(&self) -> String {
        format!("#{} +{} ({})", self.ordinal, self.by, self.because_short())
    }

    /// The reason, cut to a report-sized excerpt.
    fn because_short(&self) -> String {
        const MAX: usize = 60;
        if self.because.chars().count() <= MAX {
            return self.because.clone();
        }
        let head: String = self.because.chars().take(MAX).collect();
        format!("{}…", head.trim_end())
    }

    /// What makes two entries THE SAME ENTRY — the base carrying one of these is the base carrying
    /// this one.
    fn identity(&self) -> (&str, i64, &str) {
        (&self.key, self.by, &self.because)
    }
}

/// THE DECLARED RAISES, PARTITIONED BY WHAT THE BASE ALREADY CARRIES.
///
/// * `live` — entries the base's copy of the ceilings file does NOT contain: they were written on
///   this branch and they must describe rises on this branch, exactly;
/// * `carried` — entries the base's copy DOES contain: their commit landed, the base holds the
///   figure they declared, and the only thing left to do is strike them. Never red; `--write`
///   strikes them (see [`expired`]);
/// * `refused` — entries of a shape this reader will not honour, each with the shape it should
///   have had, so a landing cannot get through by writing a declaration this row does not read.
#[derive(Debug, Clone, Default)]
pub struct Declared {
    pub live: Vec<Raise>,
    pub carried: Vec<Raise>,
    pub refused: Vec<String>,
}

/// The declared raises, read from this tree's ceilings file and partitioned against the base's.
///
/// WHY A RAISE CAN BE DECLARED AT ALL. A ratchet with no route through it is a ratchet somebody
/// edits the rule to get past, and there are raises that are legitimate and cannot be avoided: the
/// FIRST gating figure of a row that was not gating before, and a face landed under a ceiling that
/// measures the very lines the face is made of. The commit that lands such a thing cannot also be
/// the commit that reports a regression, because nothing was ever held.
///
/// So the raise is DECLARED, and the declaration is a DELTA rather than a pair of numbers: it names
/// the exact dotted path and how many lines the face measured, and carries a reason long enough to
/// be one. Two faces declared off the same base each carry their own entry, the entries sum, and
/// the tree is green when the rise equals the sum — a `from`/`to` pair could not say this, because
/// the second face's `from` was never the base's figure and TOML has one header per key.
///
/// AND IT EXPIRES BY ITSELF. An entry rides in the commit that needs it; the moment that commit is
/// in the base, the base's copy of this file carries the entry too, and an entry the base carries
/// is one whose rise the base already holds. Such an entry is reported as a warning and STRUCK by
/// `--write`, never red — the strike cannot ride in the same batch as the face, so a red here would
/// be a red every face pays one batch later. An entry the base does NOT carry, naming a ceiling
/// that did not rise, is the other thing: a face that was deleted and left its declaration behind,
/// and that is red.
///
/// THE KEY IS A ROW'S IDENTITY, never its ordinal: for a row of `qa/kind-isolation.toml` that is
/// `cell.<crate>.<kind>.count`, and an ordinal key is refused rather than resolved, because
/// striking one `[[cell]]` renumbers every later row and re-targets it. See [`IDENTITIES`].
pub fn raises(cx: &Ctx, base: &str) -> Declared {
    let Ok(text) = cx.read(CEILINGS) else {
        return Declared::default();
    };
    let (entries, refused) = raises_in(&text);
    let at_base = cx
        .git_show(base, CEILINGS)
        .ok()
        .map(|t| raises_in(&t).0)
        .unwrap_or_default();
    let mut out = partition(entries, at_base);
    out.refused = refused;
    out
}

/// This tree's entries split into the ones the base already carries and the ones it does not.
/// The base's entries are read for ONE purpose — to say which of this tree's it carries — so an
/// entry of a refused shape at the base is nothing here rather than a second refusal, and a base
/// carrying an entry twice covers two identical entries here, not every one of them.
fn partition(entries: Vec<Raise>, mut at_base: Vec<Raise>) -> Declared {
    let mut out = Declared::default();
    for r in entries {
        match at_base.iter().position(|b| b.identity() == r.identity()) {
            Some(i) => {
                at_base.swap_remove(i);
                out.carried.push(r);
            }
            None => out.live.push(r),
        }
    }
    out
}

/// Every declared raise in one ceilings-file text, plus the refusals: the `from`/`to` form this
/// table used to have, and any entry that does not spell a ceiling, a delta and a face.
pub fn raises_in(text: &str) -> (Vec<Raise>, Vec<String>) {
    let mut out = Vec::new();
    let mut refused = Vec::new();
    let Ok(doc) = crate::toml_doc::parse_str(text) else {
        return (out, refused);
    };
    // THE OLD SHAPE IS REFUSED BY NAME. `[gate.ceiling_raises."<key>"]` with `from`/`to` named a
    // pair of numbers, so two faces off one base could not both be declared and an entry never
    // expired on its own. It is not migrated silently: a landing that carried the old shape was
    // making a claim this reader no longer reads, and the author is told the shape that does.
    let prefix = format!("{RAISES}.");
    for (path, _) in doc.tables() {
        let Some(rest) = path.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let head = rest.split('.').next().unwrap_or(rest);
        if head.is_empty() || !head.chars().all(|c| c.is_ascii_digit()) {
            refused.push(format!(
                "[{RAISES}.\"{rest}\"]: a declared raise in the retired `from`/`to` shape, which \
                 names a pair of numbers and so can neither sum with a second face's nor expire \
                 by itself. Declare one delta per face:\n{RAISE_SHAPE}"
            ));
        }
    }
    for (i, t) in doc.array_of_tables(RAISES).into_iter().enumerate() {
        let ordinal = i + 1;
        let at = format!("[[{RAISES}]] #{ordinal}");
        if t.get("from").is_some() || t.get("to").is_some() {
            refused.push(format!(
                "{at}: carries `from`/`to`, the retired shape. A raise is a delta, `by`, so that \
                 two faces off one base sum and a landed entry expires:\n{RAISE_SHAPE}"
            ));
            continue;
        }
        let (Some(key), Some(by)) = (t.str_of("key"), t.int_of("by")) else {
            refused.push(format!(
                "{at}: a declared raise names a `key` and a `by`, and this one does not:\n\
                 {RAISE_SHAPE}"
            ));
            continue;
        };
        if by <= 0 {
            refused.push(format!(
                "{at} ({key}): `by = {by}` is not a raise. A ceiling that goes DOWN is re-pinned \
                 by `--write` with no declaration at all"
            ));
            continue;
        }
        let because = t.str_of("because").unwrap_or("").trim().to_string();
        if because.chars().count() < MIN_REASON {
            refused.push(format!(
                "{at} ({key}): a {}-character `because` names no face. A declared raise names \
                 the face it lands and the lines that face measured, in at least {MIN_REASON} \
                 characters:\n{RAISE_SHAPE}",
                because.chars().count()
            ));
            continue;
        }
        let file = t.str_of("file").unwrap_or(CEILINGS);
        // AN ORDINAL KEY IS REFUSED OUTRIGHT, whatever it happens to line up with. A declaration
        // is a transaction about ONE ceiling, and `cell.178.count` does not name a ceiling — it
        // names a slot, which the next `[[cell]]` struck above it hands to a different crate.
        if let Some((name, fields)) = ordinal_form(key) {
            refused.push(format!(
                "{at} ({key}): a declared raise keyed by ORDINAL. Striking one `[[{name}]]` \
                 renumbers every later row, so this entry re-targets whichever row slides into \
                 that position. Key it by identity: `{name}.<{}>.count`",
                fields.join(">.<")
            ));
            continue;
        }
        out.push(Raise {
            key: format!("{file}:{key}"),
            by,
            because,
            commit: t.str_of("commit").map(str::to_string),
            ordinal,
        });
    }
    (out, refused)
}

/// THE ENTRIES `--write` STRIKES: every declared raise the base already carries. See [`raises`].
pub fn expired(cx: &Ctx) -> Result<Vec<Raise>, String> {
    let base = base_ref(cx)?;
    Ok(raises(cx, &base).carried)
}

/// The ceilings-file text with the `ordinal`th `[[gate.ceiling_raises]]` (counting from 1)
/// struck: the header, the comment lines directly above it, and everything up to the next header.
/// A line editor for the same reason [`set_int`] is one — the file is the owner's prose, and a
/// strike a reviewer can read is one that removes one block and touches nothing else.
pub fn strike(text: &str, ordinal: usize) -> Option<String> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let header = format!("[[{RAISES}]]");
    let start = lines
        .iter()
        .enumerate()
        .filter(|(_, raw)| raw.trim() == header)
        .nth(ordinal.checked_sub(1)?)
        .map(|(i, _)| i)?;
    let mut end = start + 1;
    while end < lines.len() && !lines[end].trim_start().starts_with('[') {
        end += 1;
    }
    // The comment lines directly above a header describe THAT entry and go with it; a blank line
    // breaks that attachment. So the next header's comments are handed back, and this one's are
    // taken.
    while end > start + 1 && end < lines.len() && lines[end - 1].trim_start().starts_with('#') {
        end -= 1;
    }
    let mut from = start;
    while from > 0 && lines[from - 1].trim_start().starts_with('#') {
        from -= 1;
    }
    let mut out = String::with_capacity(text.len());
    out.extend(lines[..from].iter().copied());
    out.extend(lines[end..].iter().copied());
    Some(out)
}

/// The ceilings-file text with every expired entry struck, and the entries struck — the same
/// derivation [`rewrite`] commits, exposed so the self-test can prove it without writing a file.
pub fn struck_text(cx: &Ctx) -> Result<(String, Vec<Raise>), String> {
    let expired = expired(cx)?;
    let mut out = cx.read(CEILINGS)?;
    // Highest ordinal first, so each strike leaves the ordinals below it where they were.
    let mut order: Vec<&Raise> = expired.iter().collect();
    order.sort_by_key(|r| std::cmp::Reverse(r.ordinal));
    for r in order {
        out = strike(&out, r.ordinal).ok_or_else(|| {
            format!(
                "{CEILINGS} has no [[{RAISES}]] #{} to strike (declared raise {})",
                r.ordinal, r.key
            )
        })?;
    }
    Ok((out, expired))
}

/// THE ARRAY-OF-TABLES ROWS WHOSE NAME IS THEIR IDENTITY, and the fields that spell it.
///
/// `qa/kind-isolation.toml` is an array of tables, so [`crate::toml_doc`] spells every count in it
/// by POSITION — `cell.178.count`. A position is not a name. Strike one `[[cell]]` and every later
/// row renumbers by one, and two things go wrong at once, silently:
///
/// * [`ceiling_rose`] compares `cell.178.count` on this tree against `cell.178.count` at the base —
///   two DIFFERENT cells — so a strike manufactures rises and hides real ones; and
/// * a `[gate.ceiling_raises."cell.178.count"]` entry re-targets whichever cell slid into slot 178,
///   which is a declared raise pointing at a ceiling nobody declared it for.
///
/// A DELETION IS EXACTLY THE EDIT THAT RENUMBERS, and a deletion is the landing this whole ratchet
/// exists to make cheap. So a row of one of these tables is relabelled by the fields that NAME it:
/// `cell.178.count` becomes `cell.busbar.api.count`, which is the same string on both sides of a
/// strike, and a declaration keyed that way follows its cell rather than its slot.
///
/// A table not named here keeps its dotted path, and so does a row missing any of the fields that
/// would name it: an unrecognised shape falls back to the ordinal rather than vanishing from the
/// comparison, because a ceiling this reader cannot name is still a ceiling.
const IDENTITIES: &[(&str, &[&str])] = &[
    ("cell", &["crate", "kind"]),
    ("dep", &["from", "to", "half"]),
    ("face", &["crate", "face"]),
];

/// The identity label for one array-of-tables row, or `None` when the row is not one [`IDENTITIES`]
/// names — in which case the caller keeps the ordinal path.
fn identity_of(path: &str, table: &crate::toml_doc::Table) -> Option<String> {
    let (name, ord) = path.split_once('.')?;
    if ord.is_empty() || !ord.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let fields = IDENTITIES.iter().find(|(n, _)| *n == name)?.1;
    let mut out = String::from(name);
    for f in fields {
        // A FIELD CARRYING A DOT WOULD MAKE THE LABEL AMBIGUOUS against the dotted path it becomes,
        // so such a row keeps its ordinal. No crate, kind, face or half in this tree spells one.
        let v = table
            .str_of(f)
            .filter(|v| !v.is_empty() && !v.contains('.'))?;
        out.push('.');
        out.push_str(v);
    }
    Some(out)
}

/// Is this declared-raise key an ORDINAL path into one of [`IDENTITIES`]' tables? If so, the form
/// it should have been written in.
fn ordinal_form(key: &str) -> Option<&'static (&'static str, &'static [&'static str])> {
    let path = key.split_once(':').map_or(key, |(_, p)| p);
    let (name, rest) = path.split_once('.')?;
    let ord = rest.split('.').next()?;
    if ord.is_empty() || !ord.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    IDENTITIES.iter().find(|(n, _)| *n == name)
}

/// Every integer in a TOML document, by dotted path — WHETHER IT IS WRITTEN AS A TOML INTEGER OR
/// AS A QUOTED STRING. The reader this crate has refuses a document it does not understand, which
/// is the behaviour wanted here too: a ceilings file that cannot be parsed is a comparison that
/// cannot be made.
///
/// A ROW OF `qa/kind-isolation.toml` IS NAMED BY ITS IDENTITY, NEVER BY ITS ORDINAL — see
/// [`IDENTITIES`]. A dotted path through an array of tables is a POSITION, and a position is not a
/// name.
///
/// THE STRING FALLBACK IS NOT A CONVENIENCE. Every one of the `[[cell]] count` numbers in
/// `qa/kind-isolation.toml` is written `count = "122"`, and an integer-only reader scores that file
/// at zero ceilings: the whole file was re-pinnable by hand with this row printing PASS. How a
/// number is spelled is a matter of the file's own style, and a ratchet that a change of quoting
/// switches off is not a ratchet.
///
/// THE DECLARATIONS THEMSELVES ARE NOT CEILINGS, and are the one table left out. A
/// `[[gate.ceiling_raises]]` row carries an integer, `by`, and is an array row this reader cannot
/// name (its `key` is dotted, so no identity could label it) — so it would be read by POSITION,
/// and striking an earlier entry ahead of a later one would read as slot 0's `by` rising: a rise
/// manufactured by the very strike `--write` performs. The rule about those numbers is
/// [`ceiling_rose`]'s sum, not this comparison.
fn ints_of(text: &str) -> Result<BTreeMap<String, i64>, String> {
    let doc = crate::toml_doc::parse_str(text)?;
    let mut out = BTreeMap::new();
    let raises = format!("{RAISES}.");
    for (path, table) in doc.tables() {
        if path == RAISES || path.starts_with(raises.as_str()) {
            continue;
        }
        let label = identity_of(path, table).unwrap_or_else(|| path.to_string());
        for key in table.keys() {
            if let Some(v) = table
                .int_of(key)
                .or_else(|| table.str_of(key).and_then(|s| s.trim().parse::<i64>().ok()))
            {
                let dotted = if label.is_empty() {
                    key.clone()
                } else {
                    format!("{label}.{key}")
                };
                out.insert(dotted, v);
            }
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "# a comment\n[gate.surface_ceilings]\ngrammar = 500\n\n[rules.x]\nn = 1\n";

    #[test]
    fn every_integer_is_read_by_its_dotted_path() {
        let ints = ints_of(DOC).expect("the fixture parses");
        assert_eq!(ints.get("gate.surface_ceilings.grammar"), Some(&500));
        assert_eq!(ints.get("rules.x.n"), Some(&1));
    }

    /// THE `qa/kind-isolation.toml` SHAPE. Every `[[cell]] count` in that file is a quoted string,
    /// and for as long as this reader took TOML integers only, `ceiling-rose` scored that entire
    /// file at zero ceilings — a hand re-pin of any cell passed unremarked. How a number is spelled
    /// is the file's own style; it is not a switch that turns the ratchet off.
    #[test]
    fn a_count_written_as_a_quoted_string_is_still_a_ceiling() {
        let doc = "[[cell]]\ncrate = \"busbar\"\nkind = \"api\"\ncount = \"122\"\n";
        let ints = ints_of(doc).expect("the fixture parses");
        assert_eq!(ints.get("cell.busbar.api.count"), Some(&122));
        // The neighbouring strings are words, not numbers, and must not become ceilings.
        assert_eq!(ints.get("cell.busbar.api.crate"), None);
        assert_eq!(ints.get("cell.busbar.api.kind"), None);
    }

    /// A three-cell ledger, in the shape `qa/kind-isolation.toml` has.
    fn cells(rows: &[(&str, &str, i64)]) -> String {
        rows.iter()
            .map(|(k, kd, n)| {
                format!("[[cell]]\ncrate = \"{k}\"\nkind = \"{kd}\"\ncount = \"{n}\"\n")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// THE STRIKE THAT USED TO RE-TARGET EVERY LATER ROW. A `[[cell]]` deleted from the middle
    /// renumbers every cell below it, so an ordinal path names a DIFFERENT cell either side of the
    /// deletion — and a deletion is the landing this ratchet exists to make cheap. Keyed by
    /// identity, the ceiling of `busbar-llm × plane` is the same string before and after.
    #[test]
    fn striking_a_cell_does_not_re_target_the_cells_below_it() {
        let before = cells(&[
            ("busbar", "api", 122),
            ("busbar", "caps", 302),
            ("busbar-llm", "plane", 47),
        ]);
        let after = cells(&[("busbar", "api", 122), ("busbar-llm", "plane", 47)]);
        let (a, b) = (
            ints_of(&before).expect("the fixture parses"),
            ints_of(&after).expect("the fixture parses"),
        );
        assert_eq!(a.get("cell.busbar-llm.plane.count"), Some(&47));
        assert_eq!(b.get("cell.busbar-llm.plane.count"), Some(&47));
        // The struck row leaves the comparison entirely rather than handing its number on.
        assert_eq!(b.get("cell.busbar.caps.count"), None);
        // …and no ordinal survives to be keyed against.
        assert!(a.keys().all(|k| !k.starts_with("cell.0.")));
    }

    /// The `[[dep]]` and `[[face]]` rows carry counts too, and renumber the same way.
    #[test]
    fn every_countable_row_of_the_kind_ledger_is_named_by_its_identity() {
        let doc = "[[dep]]\nfrom = \"a\"\nto = \"b\"\nhalf = \"shipped\"\ncount = \"3\"\n\n\
                   [[face]]\ncrate = \"busbar\"\nface = \"Plane\"\ncount = \"2\"\n";
        let ints = ints_of(doc).expect("the fixture parses");
        assert_eq!(ints.get("dep.a.b.shipped.count"), Some(&3));
        assert_eq!(ints.get("face.busbar.Plane.count"), Some(&2));
    }

    /// A row missing the fields that would name it keeps its ordinal: a shape this reader does not
    /// recognise must not drop out of the comparison, because a ceiling it cannot name is still a
    /// ceiling. Same for a table `IDENTITIES` says nothing about.
    #[test]
    fn a_row_this_reader_cannot_name_keeps_its_ordinal_rather_than_vanishing() {
        let ints = ints_of("[[cell]]\ncrate = \"busbar\"\ncount = \"9\"\n").expect("parses");
        assert_eq!(ints.get("cell.0.count"), Some(&9));
        let ints = ints_of("[[question]]\nat = \"x\"\nn = 4\n").expect("parses");
        assert_eq!(ints.get("question.0.n"), Some(&4));
    }

    /// An ORDINAL declared-raise key is recognised as one so `ceiling-rose` can refuse it by name,
    /// and an identity key is not mistaken for one.
    #[test]
    fn an_ordinal_declared_raise_key_is_recognised_as_ordinal() {
        assert_eq!(
            ordinal_form("qa/kind-isolation.toml:cell.178.count").map(|(n, _)| *n),
            Some("cell")
        );
        assert!(ordinal_form("qa/kind-isolation.toml:cell.busbar.api.count").is_none());
        assert!(ordinal_form("qa/construction.toml:rules.legacy-reach.ceiling").is_none());
        // A table with no identity is not renumbered by a strike this rule can see, so an ordinal
        // into it is not this refusal's business.
        assert!(ordinal_form("qa/kind-isolation.toml:question.3.n").is_none());
    }

    /// A string that is not a number is not a ceiling, and must not make the file unreadable
    /// either: `ints_of` returning `Err` would take the whole comparison down with it.
    #[test]
    fn a_string_that_is_not_a_number_is_simply_not_a_ceiling() {
        let ints = ints_of("[t]\nword = \"none\"\nspaced = \" 7 \"\n").expect("the fixture parses");
        assert_eq!(ints.get("t.word"), None);
        assert_eq!(ints.get("t.spaced"), Some(&7));
    }

    /// The re-pin edits ONE line and leaves every other byte — the prose around a ceiling is what
    /// makes the diff reviewable.
    #[test]
    fn a_re_pin_changes_one_line_and_nothing_else() {
        let out = set_int(DOC, "gate.surface_ceilings", "grammar", 388).expect("the key is there");
        assert_eq!(
            out,
            "# a comment\n[gate.surface_ceilings]\ngrammar = 388\n\n[rules.x]\nn = 1\n"
        );
    }

    /// A key in a table this pin does not name is not the key: `n` under `[rules.x]` must not be
    /// found by a pin that names `[rules.y]`.
    #[test]
    fn a_pin_that_names_no_key_writes_nothing() {
        assert!(set_int(DOC, "rules.y", "n", 9).is_none());
        assert!(set_int(DOC, "rules.x", "missing", 9).is_none());
    }

    /// A reason long enough to be one, for the declared-raise fixtures below.
    const BECAUSE: &str = "governance virtual-key face: KeyFacts + VirtualKeyDirectory, measured \
                           at the lines this fixture declares — a reason of the length one needs";

    fn entry(key: &str, by: i64, because: &str) -> String {
        format!("\n[[gate.ceiling_raises]]\nkey = \"{key}\"\nby = {by}\nbecause = \"{because}\"\n")
    }

    /// TWO FACES OFF ONE BASE, ONE KEY. The array shape is the whole point: a `[gate.ceiling_raises
    /// ."<key>"]` header can be written once per key, so the second face had nowhere to declare.
    #[test]
    fn several_deltas_may_be_declared_for_one_key() {
        let text = format!(
            "{DOC}{}{}",
            entry("rules.x.n", 10, BECAUSE),
            entry("rules.x.n", 5, BECAUSE)
        );
        let (raises, refused) = raises_in(&text);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(
            raises.iter().map(|r| (r.ordinal, r.by)).collect::<Vec<_>>(),
            vec![(1, 10), (2, 5)]
        );
        assert!(raises
            .iter()
            .all(|r| r.key == "qa/construction.toml:rules.x.n"));
    }

    /// THE RETIRED `from`/`to` SHAPE IS REFUSED BY NAME, in both places it could be written, and
    /// the refusal prints the shape that is read now — a landing told "no" without being told what
    /// "yes" looks like is a landing that edits the rule.
    #[test]
    fn the_from_to_shape_is_refused_and_the_array_shape_is_printed() {
        let old = format!(
            "{DOC}\n[gate.ceiling_raises.\"rules.x.n\"]\nfrom = 1\nto = 2\nbecause = \"{BECAUSE}\"\n"
        );
        let (raises, refused) = raises_in(&old);
        assert!(raises.is_empty());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("retired `from`/`to` shape"));
        assert!(refused[0].contains(RAISE_SHAPE));

        let mixed = format!(
            "{DOC}\n[[gate.ceiling_raises]]\nkey = \"rules.x.n\"\nfrom = 1\nto = 2\n\
             because = \"{BECAUSE}\"\n"
        );
        let (raises, refused) = raises_in(&mixed);
        assert!(raises.is_empty());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("carries `from`/`to`"));
        assert!(refused[0].contains("by = 10"));
    }

    /// An entry that names no face, no delta, or a delta that is not a raise, excuses nothing and
    /// says why — and is NOT counted as a live entry the rise could sum against.
    #[test]
    fn an_entry_naming_no_face_or_no_delta_is_refused() {
        let text = format!(
            "{DOC}{}{}\n[[gate.ceiling_raises]]\nkey = \"rules.x.n\"\nbecause = \"{BECAUSE}\"\n",
            entry("rules.x.n", 3, "too short"),
            entry("rules.x.n", 0, BECAUSE),
        );
        let (raises, refused) = raises_in(&text);
        assert!(raises.is_empty(), "{raises:?}");
        assert_eq!(refused.len(), 3, "{refused:?}");
        assert!(refused[0].contains("names no face"));
        assert!(refused[1].contains("`by = 0` is not a raise"));
        assert!(refused[2].contains("names a `key` and a `by`"));
    }

    /// An ORDINAL key is refused at the reader, so no arm of `ceiling-rose` ever sees it as live.
    #[test]
    fn an_ordinal_key_is_refused_at_the_reader() {
        let text = format!(
            "{DOC}\n[[gate.ceiling_raises]]\nkey = \"cell.178.count\"\n\
             file = \"qa/kind-isolation.toml\"\nby = 1\nbecause = \"{BECAUSE}\"\n"
        );
        let (raises, refused) = raises_in(&text);
        assert!(raises.is_empty());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("keyed by ORDINAL"));
        assert!(refused[0].contains("`cell.<crate>.<kind>.count`"));
    }

    /// SELF-EXPIRY IS "THE BASE CARRIES THE ENTRY". The partition is a multiset match on the
    /// entry's identity — key, delta, reason — so a base carrying one such entry covers one here,
    /// and the entry this branch added on top of it stays live.
    #[test]
    fn an_entry_the_base_carries_is_carried_and_the_rest_stay_live() {
        let a = |ord| Raise {
            key: "qa/construction.toml:rules.x.n".into(),
            by: 10,
            because: BECAUSE.into(),
            commit: None,
            ordinal: ord,
        };
        let b = Raise { by: 5, ..a(3) };
        let now = vec![a(1), a(2), b.clone()];
        let base = vec![a(1)];
        let d = partition(now, base);
        assert_eq!(
            d.carried.iter().map(|r| r.ordinal).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            d.live.iter().map(|r| r.ordinal).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(d.live[1], b);
        // Nothing at the base means everything is live: a branch that added the table from
        // nothing declared every entry in it.
        let d = partition(vec![a(1)], vec![]);
        assert!(d.carried.is_empty());
        assert_eq!(d.live.len(), 1);
    }

    /// The strike removes ONE entry — its header, its lines, and the comment directly above it —
    /// and leaves every other byte, so the strike `--write` commits is a diff a reviewer can read.
    #[test]
    fn a_strike_removes_one_entry_and_its_comment_and_nothing_else() {
        let text = format!(
            "{DOC}\n# face A\n[[gate.ceiling_raises]]\nkey = \"rules.x.n\"\nby = 10\n\
             because = \"{BECAUSE}\"\n\n# face B\n[[gate.ceiling_raises]]\nkey = \"rules.x.n\"\n\
             by = 5\nbecause = \"{BECAUSE}\"\n\n[rules.y]\nm = 2\n"
        );
        let out = strike(&text, 1).expect("the first entry is there");
        assert_eq!(
            out,
            format!(
                "{DOC}\n# face B\n[[gate.ceiling_raises]]\nkey = \"rules.x.n\"\nby = 5\n\
                 because = \"{BECAUSE}\"\n\n[rules.y]\nm = 2\n"
            )
        );
        let out = strike(&text, 2).expect("the second entry is there");
        assert_eq!(
            out,
            format!(
                "{DOC}\n# face A\n[[gate.ceiling_raises]]\nkey = \"rules.x.n\"\nby = 10\n\
                 because = \"{BECAUSE}\"\n\n[rules.y]\nm = 2\n"
            )
        );
        assert!(strike(&text, 3).is_none());
        assert!(strike(&text, 0).is_none());
    }

    /// THE DECLARATIONS ARE NOT CEILINGS. `[[gate.ceiling_raises]]` rows carry an integer, `by`,
    /// and this reader labels an array row it cannot name by POSITION — so with the table in the
    /// comparison, striking an earlier entry (by = 19) ahead of a later one (by = 205) read as slot
    /// 0 rising 19 -> 205: a rise manufactured by the strike this mechanism exists to perform, and
    /// `key` is dotted, so no identity could ever have named the row. The table is left out.
    #[test]
    fn striking_an_earlier_delta_does_not_raise_a_later_ones_by() {
        let before = format!(
            "{DOC}{}{}",
            entry("rules.x.n", 19, BECAUSE),
            entry("rules.x.n", 205, BECAUSE)
        );
        let after = format!("{DOC}{}", entry("rules.x.n", 205, BECAUSE));
        let (a, b) = (
            ints_of(&before).expect("the fixture parses"),
            ints_of(&after).expect("the fixture parses"),
        );
        assert!(
            a.keys().all(|k| !k.starts_with("gate.ceiling_raises")),
            "{a:?}"
        );
        assert!(
            b.keys().all(|k| !k.starts_with("gate.ceiling_raises")),
            "{b:?}"
        );
        // The real ceilings beside the table are still read.
        assert_eq!(a.get("gate.surface_ceilings.grammar"), Some(&500));
        assert_eq!(b.get("rules.x.n"), Some(&1));
    }
}
