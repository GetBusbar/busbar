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
    let (mut out, struck, migrated) = struck_text(cx)?;
    if slack.is_empty() && struck.is_empty() && migrated.is_empty() {
        return Ok(
            "every ratcheted ceiling already equals what it measures, and no declared raise has \
             expired or is still in the retired shape; nothing to write"
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
            "struck {}: {} +{} — the base already carries it",
            match &r.pair {
                Some(key) => format!("[{RAISES}.\"{key}\"]"),
                None => format!("[[{RAISES}]] #{}", r.ordinal),
            },
            r.key,
            r.by
        ));
    }
    for r in &migrated {
        done.push(format!(
            "migrated [{RAISES}.\"{}\"] into [[{RAISES}]]: {} +{} — the same declaration, in the \
             shape that sums and expires",
            r.pair.as_deref().unwrap_or(""),
            r.key,
            r.by
        ));
    }
    std::fs::write(&path, &out).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!(
        "re-pinned {} ceiling(s) (downward only), struck {} expired declared raise(s) and \
         migrated {} out of the retired shape in {CEILINGS}:\n  {}",
        slack.len(),
        struck.len(),
        migrated.len(),
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
    let mints = mints_in(&cx.read(KIND_CEILINGS).unwrap_or_default());
    let mut risen: Vec<String> = declared.refused.clone();
    let mut allowed: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    let mut expired: Vec<String> = Vec::new();
    // Every LIVE entry whose ceiling rose is judged, one way or the other, by the loop below; what
    // is left afterwards is an entry describing a rise that did not happen.
    let mut judged: BTreeSet<usize> = BTreeSet::new();

    let (rose, unread, unadmitted) = rose(cx, &base, &mints);
    unreadable.extend(unread);
    risen.extend(unadmitted);
    for (key, (before, after, minted)) in &rose {
        let (file, path) = key.split_once(':').unwrap_or(("", key.as_str()));
        let rise = after - before;
        let live: Vec<(usize, &Raise)> = declared
            .live
            .iter()
            .enumerate()
            .filter(|(_, r)| &r.key == key)
            .collect();
        judged.extend(live.iter().map(|(i, _)| *i));
        let sum: i64 = live.iter().map(|(_, r)| r.by).sum();
        let entries = live
            .iter()
            .map(|(_, r)| r.line())
            .collect::<Vec<_>>()
            .join(", ");
        if live.is_empty() && *minted {
            risen.push(format!(
                "{file} {path}: {before} -> {after}. This ceiling is not at the base {short} — \
                 this branch MINTED it, and a key with no `before` is the one raise this row could \
                 not see until it was given one. Its `before` is {before}; the {rise} above that \
                 is undeclared"
            ));
        } else if live.is_empty() {
            risen.push(format!("{file} {path}: {before} -> {after}"));
        } else if sum == rise {
            allowed.push(format!("{file} {path}: {before} -> {after} ({entries})"));
        } else if sum > rise {
            // OVER-DECLARED. A raise declares exactly what its face measured; a `by` above the
            // rise is room the face did not spend, which is slack with a reason attached.
            risen.push(format!(
                "{file} {path}: {before} -> {after} rose by {rise}, but its declared raises sum \
                 to {sum} ({entries}) — over-declared. A `by` is the lines the face MEASURED, not \
                 room for it: lower it to what this tree actually rose by"
            ));
        } else {
            risen.push(format!(
                "{file} {path}: {before} -> {after} rose by {rise}, and its declared raises cover \
                 only {sum} ({entries}); the remaining {} is undeclared",
                rise - sum
            ));
        }
    }
    // A LIVE DECLARATION THAT DESCRIBES NO RISE ON THIS BRANCH HAS EXPIRED, and expiry is a WARNING.
    //
    // IT USED TO BE RED, on the reading that such an entry is a deleted face's leftover. Measured
    // against the live queue that reading is wrong far more often than it is right: 53 entries
    // across 23 lines name a key whose figure at the branch head is at or BELOW the tip's, because
    // the core-drain lines drained `busbar-core × plane` and `busbar-core × control` underneath a
    // stack that was measured on a higher base. Every one of those declarations was honest when it
    // was written and describes no rise by the time it lands, and reddening them punishes a line
    // for a drain that landed beneath it.
    //
    // AND THE RED WAS NEVER LOAD-BEARING. The thing it guarded against — a leftover sheltering the
    // next raise of the same ceiling — cannot happen, because the entries SUM and the sum must
    // equal the rise EXACTLY: a leftover riding under a later rise makes the sum over-declared,
    // which is its own red, by name. So an entry that excuses nothing is reported as expired,
    // beside the entries the base already carries, and `--write` strikes it.
    for (i, r) in declared.live.iter().enumerate() {
        if !judged.contains(&i) {
            expired.push(format!(
                "{} +{} ({}): a declared raise that is not a rise at the base {short} — either its \
                 face landed, or the ceiling it names FELL beneath this branch. It excuses nothing \
                 and sums with nothing",
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
    // A RETIRED-SHAPE ENTRY IS A WARNING WHILE THE TRANSITION IS OPEN, for the same reason a
    // carried entry is: the entry says a true thing about this tree, and the only thing wrong
    // with it is how it is spelled. See [`raises_in`] for the commit that closes this.
    let warned = if declared.warned.is_empty() {
        String::new()
    } else {
        format!(
            "; WARN {} declared raise(s) still in the retired `from`/`to` header, read as deltas \
             — `cargo xtask gate construction --write` migrates them: {}",
            declared.warned.len(),
            declared.warned.join("; ")
        )
    };
    let spent = if expired.is_empty() {
        String::new()
    } else {
        format!(
            "; WARN {} declared raise(s) EXPIRED — they describe no rise at the base and \
             `cargo xtask gate construction --write` strikes them: {}",
            expired.len(),
            expired.join("; ")
        )
    };
    let carried = format!("{carried}{warned}{spent}");
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

/// EVERY CEILING THAT ROSE ON THIS BRANCH: `<file>:<path>` -> (`before`, `after`, minted).
///
/// Extracted from [`ceiling_rose`] because `--write` needs the same answer: an entry naming a key
/// that is NOT in this map has expired, and a strike derived from a second reading of the same
/// comparison is a strike that can disagree with the row that reported it.
///
/// Also answered: the files that could not be compared, and the keys the base does not carry that
/// no `[[minted]]` row admits (see [`minted_before`]).
#[allow(clippy::type_complexity)]
fn rose(
    cx: &Ctx,
    base: &str,
    mints: &Mints,
) -> (BTreeMap<String, (i64, i64, bool)>, Vec<String>, Vec<String>) {
    let (mut out, mut unreadable, mut unadmitted) = (BTreeMap::new(), Vec::new(), Vec::new());
    for file in [CEILINGS, KIND_CEILINGS] {
        let now = match cx.read(file) {
            Ok(t) => t,
            Err(e) => {
                unreadable.push(format!("{file} on this tree: {e}"));
                continue;
            }
        };
        let was = match cx.git_show(base, file) {
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
        for (path, after) in &now {
            // A KEY THE BASE DOES NOT CARRY IS A CEILING MINTED ON THIS BRANCH, and until now this
            // comparison walked the BASE's keys and never saw one. See [`minted_before`]: its
            // `before` is what a `[[minted]]` / `[[minted_kind]]` row admits it at, or nothing.
            let minted = !was.contains_key(path);
            let before = match was.get(path) {
                Some(b) => *b,
                None => match minted_before(mints, file, path) {
                    Ok(b) => b,
                    Err(why) => {
                        unadmitted.push(format!("{file} {path} = {after}: {why}"));
                        continue;
                    }
                },
            };
            if *after > before {
                out.insert(format!("{file}:{path}"), (before, *after, minted));
            }
        }
    }
    (out, unreadable, unadmitted)
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
    /// Zero for an entry read from the retired header, which has no position in the array.
    pub ordinal: usize,
    /// THE RETIRED HEADER THIS ENTRY WAS READ FROM, when it was read from one: the dotted key
    /// inside `[gate.ceiling_raises."<key>"]`. See [`raises_in`] — during the transition such an
    /// entry is READ (as the delta `to - from`) and warned about, and `--write` migrates it into
    /// the array shape. `None` is the array shape, which is the shape everything ends up in.
    pub pair: Option<String>,
    /// THE ORDINAL KEY THIS ENTRY WAS WRITTEN WITH, when [`Ordinals`] resolved one into `key`.
    /// `--write` rewrites the entry with the identity, which is what stops a slot from being
    /// re-targeted by the next strike.
    pub written_key: Option<String>,
}

impl Raise {
    fn line(&self) -> String {
        match &self.pair {
            Some(key) => format!("[\"{key}\"] +{} ({})", self.by, self.because_short()),
            None => format!("#{} +{} ({})", self.ordinal, self.by, self.because_short()),
        }
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
    ///
    /// THE SHAPE IS NOT PART OF THE IDENTITY, and that is what makes the migration safe: an entry
    /// the base carries as `[gate.ceiling_raises."k"] from/to` and this tree carries as
    /// `[[gate.ceiling_raises]] key/by` is ONE entry, read once, so `--write` may rewrite the
    /// shape in a commit of its own without the rewrite reading as a second face's declaration.
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
///   have had, so a landing cannot get through by writing a declaration this row does not read;
/// * `warned` — entries READ in the retired `from`/`to` header, one line each. They are `live` or
///   `carried` like any other; the warning is about the SHAPE, and it is a warning rather than a
///   refusal only until the transition closes. See [`raises_in`].
#[derive(Debug, Clone, Default)]
pub struct Declared {
    pub live: Vec<Raise>,
    pub carried: Vec<Raise>,
    pub refused: Vec<String>,
    pub warned: Vec<String>,
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
    // THE ORDINAL MAP IS READ FROM THE BASE, never from this tree. An ordinal names a POSITION,
    // and the only position a declaration written on this branch can have meant is the one the
    // base's file had when the author counted it — this branch is free to strike a row above it.
    let ords = Ordinals::at(cx, base);
    let (entries, refused, warned) = raises_in_at(&text, &ords);
    let at_base = cx
        .git_show(base, CEILINGS)
        .ok()
        .map(|t| raises_in_at(&t, &ords).0)
        .unwrap_or_default();
    let mut out = partition(entries, at_base);
    out.refused = refused;
    out.warned = warned;
    out
}

/// ROW ORDINALS AS THEY STOOD AT THE BASE: `<file>` -> `<table>.<n>` -> `<table>.<identity>`.
///
/// A declaration keyed `cell.193.count` names slot 193 of an array of tables, and slot 193 is
/// whichever crate happens to be sitting there. T0-E refused such a key outright, and that is the
/// right end state — but 204 of the 295 declarations waiting in the queue are written that way,
/// and refusing them is refusing two thirds of the transition it is the point of this reader to
/// carry. So an ordinal key is RESOLVED, against the base's row order, into the identity it named
/// when it was written, and warned about; the cutoff commit named in [`raises_in`] closes this arm
/// with the other one.
///
/// RESOLVED AGAINST THE BASE AND NOWHERE ELSE. Resolving against this tree would let a branch that
/// strikes a row silently re-target a declaration at its neighbour, which is the whole defect the
/// refusal was written for.
#[derive(Debug, Clone, Default)]
pub struct Ordinals {
    by_file: BTreeMap<String, BTreeMap<String, String>>,
}

impl Ordinals {
    /// The row order of both ceilings files at `base`.
    pub fn at(cx: &Ctx, base: &str) -> Self {
        let mut by_file = BTreeMap::new();
        for file in [CEILINGS, KIND_CEILINGS] {
            if let Ok(text) = cx.git_show(base, file) {
                by_file.insert(file.to_string(), Self::of(&text));
            }
        }
        Self { by_file }
    }

    /// One file's `<table>.<n>` -> `<table>.<identity>` map.
    fn of(text: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let Ok(doc) = crate::toml_doc::parse_str(text) else {
            return out;
        };
        for (name, _) in IDENTITIES {
            for (i, t) in doc.array_of_tables(name).into_iter().enumerate() {
                let at = format!("{name}.{i}");
                if let Some(id) = identity_of(&at, t) {
                    out.insert(at, id);
                }
            }
        }
        out
    }

    /// `cell.193.count` in `file`, as the identity it named at the base — or `None` when the base
    /// has no such row, which is a declaration pointing at a slot that never existed.
    fn resolve(&self, file: &str, key: &str) -> Option<String> {
        let (name, rest) = key.split_once('.')?;
        let (ord, tail) = rest.split_once('.')?;
        let id = self.by_file.get(file)?.get(&format!("{name}.{ord}"))?;
        Some(format!("{id}.{tail}"))
    }
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

/// Every declared raise in one ceilings-file text, the refusals, and the transition warnings.
///
/// BOTH SHAPES ARE READ WHILE THE QUEUE DRAINS. The array of deltas is the shape, and it is the
/// shape for the reasons the module header gives — a pair of numbers cannot sum with a second
/// face's and cannot expire by itself. But the lines waiting to land were cut against a tree whose
/// reader took `[gate.ceiling_raises."<key>"] from/to` and nothing else, and a reader that refuses
/// them turns a queue of already-measured faces red one line at a time for a reason that is about
/// the SHAPE of a declaration rather than about a single line of the tree. So the retired header is
/// READ, as the delta it always was — `to - from`, keyed by the same identity — and WARNED about,
/// in the same place a carried entry is warned about, and `--write` migrates it.
///
/// THE CONTENT RULES ARE THE SAME FOR BOTH SHAPES: at least [`MIN_REASON`] characters of reason, a
/// delta that is a raise, and a key that is a row's IDENTITY and never its ordinal. The transition
/// is about how a declaration is spelled, not about what it has to say.
///
/// AND IT CLOSES ON A NAMED COMMIT, NOT A DATE A GATE READS. The warning is not a second supported
/// shape — it is a ramp with an end written on it, and the end is a landing, not a clock: nothing
/// in this gate reads `now()` or compares against a stored date, so nothing reds when a date passes.
/// The transition closes when the closing line lands, and it is queued to land on 2026-09-18. When
/// it does, the commit **`gate ceiling-rose: the from/to transition closes — the retired header is
/// refused again`** deletes [`read_pair`]'s acceptance arm (the block above reading the retired
/// header as a delta) and restores the refusal below it. Until then a from/to entry is a warning;
/// after the closing line lands, a refusal, and nothing else changes. See
/// `docs/ci/gate-integrity.md`'s construction-rows section for the full statement of what that
/// commit deletes.
pub fn raises_in(text: &str) -> (Vec<Raise>, Vec<String>, Vec<String>) {
    raises_in_at(text, &Ordinals::default())
}

/// [`raises_in`], with the base's row order so an ORDINAL key can be resolved into the identity it
/// named. Without one (the unit tests, and any reader with no base) an ordinal key is refused, as
/// it was before the transition opened.
pub fn raises_in_at(text: &str, ords: &Ordinals) -> (Vec<Raise>, Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let mut refused = Vec::new();
    let mut warned = Vec::new();
    let Ok(doc) = crate::toml_doc::parse_str(text) else {
        return (out, refused, warned);
    };
    let prefix = format!("{RAISES}.");
    for (path, t) in doc.tables() {
        let Some(rest) = path.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let head = rest.split('.').next().unwrap_or(rest);
        if head.is_empty() || !head.chars().all(|c| c.is_ascii_digit()) {
            match read_pair(rest, t, ords) {
                Ok((r, mut warnings)) => {
                    warned.append(&mut warnings);
                    out.push(r);
                }
                Err(why) => refused.push(why),
            }
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
        match judged(&at, key, by, t, ordinal, None, ords) {
            Ok((r, mut w)) => {
                warned.append(&mut w);
                out.push(r);
            }
            Err(why) => refused.push(why),
        }
    }
    (out, refused, warned)
}

/// One entry in the retired `[gate.ceiling_raises."<key>"]` header, read as the delta `to - from`.
///
/// A header with neither `from` nor `to` is not that shape at all and is refused as the shapeless
/// thing it is; a `to` at or below its `from` is a FALL, which needs no declaration of any kind.
fn read_pair(
    key: &str,
    t: &crate::toml_doc::Table,
    ords: &Ordinals,
) -> Result<(Raise, Vec<String>), String> {
    let at = format!("[{RAISES}.\"{key}\"]");
    let (Some(from), Some(to)) = (t.int_of("from"), t.int_of("to")) else {
        return Err(format!(
            "{at}: a declared raise names a `key` and a `by`, and this one does not:\n{RAISE_SHAPE}"
        ));
    };
    // THE PAIR IS READ AS THE DELTA IT ALWAYS WAS, `to - from`, WITHOUT ASKING WHAT `from` IS.
    //
    // THE CHAIN FORM depends on exactly that. Four queued lines (P3, P4, P5 and the K14 rows) write
    // `from = <the predecessor's tip>` rather than the landing base's figure, so a reader that
    // checked `from == before` — which the retired one did, exactly — reds every chained entry
    // whose predecessor has not landed yet. As deltas they simply SUM, which is what the array
    // shape was introduced to make possible and what this reader gets for free by ignoring `from`.
    let (r, mut warnings) = judged(&at, key, to - from, t, 0, Some(key.to_string()), ords)?;
    warnings.insert(
        0,
        format!(
            "{at} {from} -> {to}: the retired `from`/`to` header, read as the delta +{} it always \
             was. It cannot sum with a second face's declaration and it does not expire on its \
             own, so `cargo xtask gate construction --write` MIGRATES it into the shape that \
             does:\n{RAISE_SHAPE}",
            r.by
        ),
    );
    Ok((r, warnings))
}

/// THE RULES A DECLARATION HAS TO MEET, whichever shape it is written in: a delta that raises, a
/// reason long enough to be one, and a key that names a row rather than a slot.
#[allow(clippy::too_many_arguments)]
fn judged(
    at: &str,
    key: &str,
    by: i64,
    t: &crate::toml_doc::Table,
    ordinal: usize,
    pair: Option<String>,
    ords: &Ordinals,
) -> Result<(Raise, Vec<String>), String> {
    if by <= 0 {
        return Err(format!(
            "{at} ({key}): `by = {by}` is not a raise. A ceiling that goes DOWN is re-pinned by \
             `--write` with no declaration at all"
        ));
    }
    let because = t.str_of("because").unwrap_or("").trim().to_string();
    if because.chars().count() < MIN_REASON {
        return Err(format!(
            "{at} ({key}): a {}-character `because` names no face. A declared raise names the \
             face it lands and the lines that face measured, in at least {MIN_REASON} \
             characters:\n{RAISE_SHAPE}",
            because.chars().count()
        ));
    }
    let file = t.str_of("file").unwrap_or(CEILINGS);
    // AN ORDINAL KEY NAMES A SLOT AND NOT A CEILING — `cell.178.count` is whichever crate sits at
    // position 178, and the next `[[cell]]` struck above it hands that slot to a different one. It
    // is RESOLVED against the base's row order while the transition is open (see [`Ordinals`]) and
    // warned about, because two thirds of the declarations waiting in the queue are written that
    // way; with no base to resolve against, it is refused, as it will be again once the closing
    // line lands (queued for 2026-09-18, see `raises_in`'s doc comment above `read_pair`) — that
    // same commit deletes this resolution arm alongside `read_pair`'s from/to acceptance.
    let mut warnings = Vec::new();
    let mut written_key = None;
    let key = match ordinal_form(key) {
        None => key.to_string(),
        Some((name, fields)) => match ords.resolve(file, key) {
            Some(id) => {
                warnings.push(format!(
                    "{at} ({key}): a declared raise keyed by ORDINAL, resolved against the base's \
                     row order to `{id}`. Striking one `[[{name}]]` renumbers every later row, so \
                     a slot is not a ceiling: `cargo xtask gate construction --write` migrates \
                     this entry and writes the identity key"
                ));
                written_key = Some(key.to_string());
                id
            }
            None => {
                return Err(format!(
                    "{at} ({key}): a declared raise keyed by ORDINAL, and the base carries no \
                     `[[{name}]]` at that position to resolve it against. Striking one \
                     `[[{name}]]` renumbers every later row, so this entry re-targets whichever \
                     row slides into that position. Key it by identity: `{name}.<{}>.count`",
                    fields.join(">.<")
                ))
            }
        },
    };
    Ok((
        Raise {
            key: format!("{file}:{key}"),
            by,
            because,
            commit: t.str_of("commit").map(str::to_string),
            ordinal,
            pair,
            written_key,
        },
        warnings,
    ))
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
    splice(text, &format!("[[{RAISES}]]"), ordinal, "")
}

/// The ceilings-file text with the retired `[gate.ceiling_raises."<key>"]` header STRUCK — the
/// same block edit [`strike`] performs, over the other header. Used when the base already carries
/// the entry, so nothing has to be written in its place.
pub fn strike_pair(text: &str, key: &str) -> Option<String> {
    splice(text, &format!("[{RAISES}.\"{key}\"]"), 1, "")
}

/// The ceilings-file text with the retired `[gate.ceiling_raises."<key>"]` header REPLACED by the
/// same declaration in the array shape — the migration `--write` performs while the transition is
/// open. The entry says the same thing afterwards: same key, same delta (`to - from`), same
/// reason, so [`Raise::identity`] is unchanged and the base still carries it when its face lands.
pub fn migrate_pair(text: &str, r: &Raise) -> Option<String> {
    let header = r.pair.as_deref()?;
    splice(text, &format!("[{RAISES}.\"{header}\"]"), 1, &block_of(r))
}

/// The `ordinal`th array entry rewritten with the IDENTITY key this reader resolved its ordinal to.
/// Same entry, same delta, same reason — `--write` is where a declaration keyed by a slot stops
/// being one, so that the next `[[cell]]` struck above it cannot re-target it.
pub fn rekey(text: &str, r: &Raise) -> Option<String> {
    r.written_key.as_ref()?;
    splice(text, &format!("[[{RAISES}]]"), r.ordinal, &block_of(r))
}

/// One entry in the shape this file keeps: the array row, identity-keyed, with `file` written only
/// when it is not the default.
fn block_of(r: &Raise) -> String {
    let (file, key) = r.key.split_once(':').unwrap_or((CEILINGS, r.key.as_str()));
    let mut block = format!("[[{RAISES}]]\nkey = \"{key}\"\n");
    if file != CEILINGS {
        block.push_str(&format!("file = \"{file}\"\n"));
    }
    block.push_str(&format!("by = {}\nbecause = \"{}\"\n", r.by, r.because));
    if let Some(c) = &r.commit {
        block.push_str(&format!("commit = \"{c}\"\n"));
    }
    block
}

/// The `nth` block (counting from 1) whose header line is exactly `header`, replaced by `with`.
/// `with` empty is a strike. One block editor for both headers, so the comment rules below are
/// the same rules in both shapes.
fn splice(text: &str, header: &str, nth: usize, with: &str) -> Option<String> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let start = lines
        .iter()
        .enumerate()
        .filter(|(_, raw)| raw.trim() == header)
        .nth(nth.checked_sub(1)?)
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
    let mut out = String::with_capacity(text.len() + with.len());
    out.extend(lines[..from].iter().copied());
    out.push_str(with);
    out.extend(lines[end..].iter().copied());
    Some(out)
}

/// The ceilings-file text with every expired entry struck, and the entries struck — the same
/// derivation [`rewrite`] commits, exposed so the self-test can prove it without writing a file.
pub fn struck_text(cx: &Ctx) -> Result<(String, Vec<Raise>, Vec<Raise>), String> {
    let base = base_ref(cx)?;
    let declared = raises(cx, &base);
    let mints = mints_in(&cx.read(KIND_CEILINGS).unwrap_or_default());
    let (rose, _, _) = rose(cx, &base, &mints);
    // WHAT `--write` STRIKES: every entry the base already carries (its face landed), and every
    // live entry naming a ceiling that did not rise (it has EXPIRED — see [`ceiling_rose`]'s
    // expiry arm, where the same comparison reports it as a warning rather than a red).
    let mut expired = declared.carried;
    let (spent, live): (Vec<Raise>, Vec<Raise>) = declared
        .live
        .into_iter()
        .partition(|r| !rose.contains_key(&r.key));
    expired.extend(spent);
    // AND WHAT IT REWRITES: every live entry still in the retired header, and every live entry
    // whose key was an ORDINAL this reader resolved. Both keep their key, delta and reason; what
    // changes is the spelling, which is the whole of the transition.
    let migrated: Vec<Raise> = live
        .into_iter()
        .filter(|r| r.pair.is_some() || r.written_key.is_some())
        .collect();
    let mut out = cx.read(CEILINGS)?;
    // THE ARRAY EDITS GO HIGHEST ORDINAL FIRST, because each one changes the positions above it
    // and none of them changes a position below. The retired-header entries have no position and
    // are found by their key, so they are done afterwards, together.
    let mut arrays: Vec<&Raise> = expired
        .iter()
        .chain(migrated.iter())
        .filter(|r| r.pair.is_none())
        .collect();
    arrays.sort_by_key(|r| std::cmp::Reverse(r.ordinal));
    for r in arrays {
        let strike_it = expired.iter().any(|e| std::ptr::eq(e, r));
        out = if strike_it {
            strike(&out, r.ordinal).ok_or_else(|| {
                format!(
                    "{CEILINGS} has no [[{RAISES}]] #{} to strike (declared raise {})",
                    r.ordinal, r.key
                )
            })?
        } else {
            rekey(&out, r).ok_or_else(|| {
                format!(
                    "{CEILINGS} has no [[{RAISES}]] #{} to re-key (declared raise {})",
                    r.ordinal, r.key
                )
            })?
        };
    }
    for r in expired.iter().filter(|r| r.pair.is_some()) {
        let key = r.pair.as_deref().unwrap_or("");
        out = strike_pair(&out, key)
            .ok_or_else(|| format!("{CEILINGS} has no [{RAISES}.\"{key}\"] header to strike"))?;
    }
    for r in migrated.iter().filter(|r| r.pair.is_some()) {
        out = migrate_pair(&out, r).ok_or_else(|| {
            format!(
                "{CEILINGS} has no [{RAISES}.\"{}\"] header to migrate",
                r.pair.as_deref().unwrap_or("")
            )
        })?;
    }
    Ok((out, expired, migrated))
}

/// THE TABLES WHOSE INTEGERS ARE NOT CEILINGS. See [`ints_of`]: `[[minted]] cells`,
/// `[[minted_kind]] cells`/`edges` and both rows' `ceiling` are numbers ABOUT the ceilings, and a
/// comparison that read them as ceilings would refuse the very admission it was asked to honour.
const NOT_CEILINGS: &[&str] = &["minted", "minted_kind"];

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

/// WHAT A `[[minted]]` / `[[minted_kind]]` ROW ADMITS A CEILING AT.
///
/// THE HOLE THIS CLOSES, measured. [`ceiling_rose`] used to walk the BASE's keys, so a key the base
/// does not carry was never compared to anything, at any size. A `[[cell]]` row minted on a branch
/// could therefore be born at any figure and grow without limit for the rest of that branch, and
/// two landings did exactly that in the open: `cell.busbar.dialect.count` 651 -> 653 and
/// `cell.busbar.export.count` 39 -> 63 -> 64, both hand-edited UP, both naming the hole in their
/// own commit messages because no instrument could see them. `kind-isolation`'s mint door admits
/// the row's EXISTENCE; nothing admitted its FIGURE.
///
/// SO THE DOOR CARRIES A CEILING. A `[[minted]]` row already says which crate, at which commit and
/// how many cells; it now also says `ceiling` — THE HIGHEST FIGURE ANY ROW IT ADMITS MAY CARRY.
/// That figure is the minted key's `before`, and everything above it is an ordinary rise judged by
/// the ordinary `[[gate.ceiling_raises]]` sum. `[[minted_kind]]` carries the same field for the
/// column it opens. One number per admission, on the row that already exists, checked against the
/// same tree the rest of this module is checked against.
///
/// A ROW OF THE LEDGER MUST BE COVERED. `qa/kind-isolation.toml`'s rows are the coupling matrix,
/// and a cell of it born at 651 with no admission is a 651-hit coupling nobody voted for; there is
/// no honest `0 -> 651` declaration to write, which is exactly why the bulk admission exists. So a
/// minted ledger key with no covering row — or with one that carries no `ceiling` — is RED, and
/// the message names the row that would admit it.
///
/// A NEW CEILING IN `qa/construction.toml` IS DIFFERENT and is left to the ordinary mechanism: that
/// file is the owner's rule table, a new rule arrives with its own figure, and the figure is small
/// enough to declare outright. Its `before` is 0, so the whole of it is a declared raise — which is
/// what "the FIRST gating figure of a row that was not gating before" has always meant here.
fn minted_before(mints: &Mints, file: &str, path: &str) -> Result<i64, String> {
    if file != KIND_CEILINGS {
        return Ok(0);
    }
    let (table, rest) = path.split_once('.').unwrap_or((path, ""));
    let names: Vec<&str> = rest.split('.').collect();
    // Which crate(s) and which kind the key is about, read off the identity label [`IDENTITIES`]
    // builds. A key this reader cannot name is a key it cannot admit, and it says so.
    let (crates, kind): (Vec<&str>, Option<&str>) = match (table, names.as_slice()) {
        ("cell", [krate, kind, ..]) => (vec![*krate], Some(*kind)),
        ("face", [krate, ..]) => (vec![*krate], None),
        ("dep", [from, to, ..]) => (vec![*from, *to], None),
        _ => (vec![], None),
    };
    // THE CRATE'S OWN ADMISSION TAKES THE ROW FIRST, then the column's — the same order
    // `kind-isolation`'s own mint door reads them in, so the two doors never disagree about which
    // row admitted what.
    for name in &crates {
        if let Some(m) = mints.crates.get(*name) {
            return m.ceiling.ok_or_else(|| {
                format!(
                    "a ceiling MINTED on this branch under `[[minted]] crate = \"{name}\"`, which \
                     carries no `ceiling`. A row admits the EXISTENCE of a ledger row; the figure \
                     it is born at is the other half, and without it a minted cell may be born at \
                     any size. Add `ceiling = \"<the highest figure any row this admits carries>\"`"
                )
            });
        }
    }
    if let Some(k) = kind {
        if let Some(m) = mints.kinds.get(k) {
            return m.ceiling.ok_or_else(|| {
                format!(
                    "a ceiling MINTED on this branch under `[[minted_kind]] kind = \"{k}\"`, which \
                     carries no `ceiling`. A column admission opens every cell of a kind at once, \
                     so the figure those cells are born at is the whole of what it costs. Add \
                     `ceiling = \"<the highest figure any cell of this column carries>\"`"
                )
            });
        }
    }
    Err(format!(
        "a ceiling MINTED on this branch — {KIND_CEILINGS} at the base carries no such key — and no \
         `[[minted]]` or `[[minted_kind]]` row of {KIND_CEILINGS} admits it. A row that did not \
         exist is a 0 -> N raise wearing the clothes of a first measurement, and this file's rows \
         are the coupling matrix itself: there is no honest `0 -> N` declaration to write for one. \
         Admit it with the row that admits its crate (or its kind's column), carrying the `ceiling` \
         it is born at"
    ))
}

/// One `[[minted]]` or `[[minted_kind]]` row, as THIS module needs it: the ceiling it admits at.
/// `kind-isolation` reads the same rows for everything else about them; what is read here is the
/// one field that says how high the rows it admits may be.
#[derive(Debug, Clone, Default)]
pub struct Mint {
    pub ceiling: Option<i64>,
}

/// The admissions of one ledger text, by crate and by kind.
#[derive(Debug, Clone, Default)]
pub struct Mints {
    pub crates: BTreeMap<String, Mint>,
    pub kinds: BTreeMap<String, Mint>,
}

/// The `[[minted]]` and `[[minted_kind]]` rows of one ledger text.
///
/// Read here with the document reader rather than through `kind-isolation`'s line parser, because
/// this row is about the CEILINGS and must be readable from the ceilings module without either gate
/// depending on the other. The figure is taken as an integer OR as a quoted one, for the reason
/// [`ints_of`] gives: every count in that file is written `"122"`, and a reader that takes only
/// bare integers reads this file as carrying no numbers at all.
pub fn mints_in(text: &str) -> Mints {
    let mut out = Mints::default();
    let Ok(doc) = crate::toml_doc::parse_str(text) else {
        return out;
    };
    let read = |t: &crate::toml_doc::Table| Mint {
        ceiling: t.int_of("ceiling").or_else(|| {
            t.str_of("ceiling")
                .and_then(|s| s.trim().parse::<i64>().ok())
        }),
    };
    for t in doc.array_of_tables("minted") {
        if let Some(k) = t.str_of("crate") {
            out.crates.insert(k.to_string(), read(t));
        }
    }
    for t in doc.array_of_tables("minted_kind") {
        if let Some(k) = t.str_of("kind") {
            out.kinds.insert(k.to_string(), read(t));
        }
    }
    out
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
        // AND NEITHER ARE THE ADMISSIONS. `[[minted]]` and `[[minted_kind]]` carry `cells`,
        // `edges` and — since the minted-ceiling door — `ceiling`, and every one of those is a
        // number ABOUT ceilings rather than a ceiling. Read as ceilings they are keys the base
        // never carried, which is precisely what the door refuses: the door would red its own
        // admission, measured, the first time one was written.
        if NOT_CEILINGS
            .iter()
            .any(|t| path == *t || path.starts_with(&format!("{t}.")))
        {
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
        let (raises, refused, warned) = raises_in(&text);
        assert!(refused.is_empty(), "{refused:?}");
        assert!(warned.is_empty(), "{warned:?}");
        assert_eq!(
            raises.iter().map(|r| (r.ordinal, r.by)).collect::<Vec<_>>(),
            vec![(1, 10), (2, 5)]
        );
        assert!(raises
            .iter()
            .all(|r| r.key == "qa/construction.toml:rules.x.n"));
    }

    /// THE RETIRED HEADER IS READ WHILE THE TRANSITION IS OPEN, as the delta `to - from` it
    /// always was, and WARNED about rather than refused — a queue of lines cut against the reader
    /// that took only that shape must be able to land. The array shape written with `from`/`to`
    /// is a different thing entirely: it is neither shape, and it stays refused.
    #[test]
    fn the_retired_from_to_header_is_read_as_a_delta_and_warned_about() {
        let old = format!(
            "{DOC}\n[gate.ceiling_raises.\"rules.x.n\"]\nfrom = 1\nto = 9\nbecause = \"{BECAUSE}\"\n"
        );
        let (raises, refused, warned) = raises_in(&old);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(raises.len(), 1, "{raises:?}");
        assert_eq!(raises[0].by, 8);
        assert_eq!(raises[0].key, "qa/construction.toml:rules.x.n");
        assert_eq!(raises[0].pair.as_deref(), Some("rules.x.n"));
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(warned[0].contains("retired `from`/`to` header"));
        assert!(warned[0].contains("1 -> 9"));
        assert!(warned[0].contains(RAISE_SHAPE));

        // A `to` at or below its `from` is a FALL, and a fall is re-pinned with no declaration.
        let fall = format!(
            "{DOC}\n[gate.ceiling_raises.\"rules.x.n\"]\nfrom = 9\nto = 9\nbecause = \"{BECAUSE}\"\n"
        );
        let (raises, refused, _) = raises_in(&fall);
        assert!(raises.is_empty());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("is not a raise"));

        // THE ARRAY SHAPE WITH `from`/`to` IS NEITHER SHAPE and is still refused by name.
        let mixed = format!(
            "{DOC}\n[[gate.ceiling_raises]]\nkey = \"rules.x.n\"\nfrom = 1\nto = 2\n\
             because = \"{BECAUSE}\"\n"
        );
        let (raises, refused, warned) = raises_in(&mixed);
        assert!(raises.is_empty());
        assert!(warned.is_empty(), "{warned:?}");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("carries `from`/`to`"));
        assert!(refused[0].contains("by = 10"));
    }

    /// THE TWO SHAPES MIX IN ONE TREE AND SUM AGAINST ONE RISE. This is the transition's whole
    /// point: a line cut in the retired header lands beside a line cut in the array shape, and
    /// `ceiling-rose` adds their deltas exactly as it adds two array entries'.
    #[test]
    fn both_shapes_are_read_in_one_tree_and_key_the_same_ceiling() {
        let text = format!(
            "{DOC}{}\n[gate.ceiling_raises.\"rules.x.n\"]\nfrom = 100\nto = 105\n\
             because = \"{BECAUSE}\"\n",
            entry("rules.x.n", 10, BECAUSE)
        );
        let (raises, refused, warned) = raises_in(&text);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert_eq!(raises.len(), 2, "{raises:?}");
        // One key, whichever shape spells it, so the deltas sum against one rise.
        assert!(raises
            .iter()
            .all(|r| r.key == "qa/construction.toml:rules.x.n"));
        assert_eq!(raises.iter().map(|r| r.by).sum::<i64>(), 15);
    }

    /// MIGRATION PRESERVES THE IDENTITY. `--write` rewrites the header into the array shape and
    /// the entry says the same thing afterwards — same key, same delta, same reason — so the base
    /// still carries it when the face lands and it expires on the ordinary terms.
    #[test]
    fn migrating_a_retired_header_keeps_the_entry_identical() {
        let text = format!(
            "{DOC}\n# face A\n[gate.ceiling_raises.\"cell.busbar.export.count\"]\n\
             file = \"qa/kind-isolation.toml\"\nfrom = 39\nto = 64\nbecause = \"{BECAUSE}\"\n\
             \n[rules.y]\nm = 2\n"
        );
        let (raises, _, _) = raises_in(&text);
        assert_eq!(raises.len(), 1, "{raises:?}");
        let out = migrate_pair(&text, &raises[0]).expect("the header is there");
        assert!(!out.contains("from = 39"), "{out}");
        assert!(out.contains("[[gate.ceiling_raises]]"), "{out}");
        assert!(out.contains("file = \"qa/kind-isolation.toml\""), "{out}");
        assert!(out.contains("[rules.y]"), "{out}");
        let (after, refused, warned) = raises_in(&out);
        assert!(
            refused.is_empty() && warned.is_empty(),
            "{refused:?} {warned:?}"
        );
        assert_eq!(after.len(), 1);
        assert_eq!(
            (after[0].key.clone(), after[0].by, after[0].because.clone()),
            (
                raises[0].key.clone(),
                raises[0].by,
                raises[0].because.clone()
            )
        );
        // And a struck header leaves every other byte where it was.
        let struck = strike_pair(&text, "cell.busbar.export.count").expect("the header is there");
        assert_eq!(struck, format!("{DOC}\n[rules.y]\nm = 2\n"));
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
        let (raises, refused, _) = raises_in(&text);
        assert!(raises.is_empty(), "{raises:?}");
        assert_eq!(refused.len(), 3, "{refused:?}");
        assert!(refused[0].contains("names no face"));
        assert!(refused[1].contains("`by = 0` is not a raise"));
        assert!(refused[2].contains("names a `key` and a `by`"));
    }

    /// AN ORDINAL KEY IS RESOLVED AGAINST THE BASE'S ROW ORDER while the transition is open, and
    /// refused when there is no base to resolve it against. 204 of the 295 declarations waiting in
    /// the queue are keyed `cell.<n>.count`; refusing them refuses two thirds of the transition.
    #[test]
    fn an_ordinal_key_is_resolved_against_the_bases_row_order() {
        let text = format!(
            "{DOC}\n[[gate.ceiling_raises]]\nkey = \"cell.1.count\"\n\
             file = \"qa/kind-isolation.toml\"\nby = 1\nbecause = \"{BECAUSE}\"\n"
        );
        // With no base, the key names a slot and nothing can say which row that was.
        let (raises, refused, _) = raises_in(&text);
        assert!(raises.is_empty());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("keyed by ORDINAL"));
        assert!(refused[0].contains("`cell.<crate>.<kind>.count`"));

        // With one, it is the row that stood there — the SECOND, because the labels are the
        // document reader's own zero-based positions.
        let ords = Ordinals {
            by_file: [(
                KIND_CEILINGS.to_string(),
                Ordinals::of(
                    "[[cell]]\ncrate = \"busbar\"\nkind = \"api\"\ncount = \"120\"\n\n\
                     [[cell]]\ncrate = \"busbar-core\"\nkind = \"plane\"\ncount = \"3067\"\n",
                ),
            )]
            .into_iter()
            .collect(),
        };
        let (raises, refused, warned) = raises_in_at(&text, &ords);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(raises.len(), 1, "{raises:?}");
        assert_eq!(
            raises[0].key,
            "qa/kind-isolation.toml:cell.busbar-core.plane.count"
        );
        assert_eq!(raises[0].written_key.as_deref(), Some("cell.1.count"));
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(warned[0].contains("keyed by ORDINAL, resolved"));
        // And `--write` writes the identity, never the slot it was handed.
        let out = rekey(&text, &raises[0]).expect("the entry is there");
        assert!(out.contains("cell.busbar-core.plane.count"), "{out}");
        assert!(!out.contains("cell.1.count"), "{out}");
    }

    /// THE CHAIN FORM. P3, P4, P5 and the K14 rows write `from = <the predecessor's tip>` rather
    /// than the landing base's figure — sound only if every predecessor has landed, which is what
    /// their holds buy. Read as DELTAS the chain needs no such reasoning: the entries simply sum.
    #[test]
    fn a_chain_of_retired_headers_sums_to_the_whole_rise() {
        let text = format!(
            "{DOC}\n[gate.ceiling_raises.\"rules.x.n\"]\nfrom = 5595\nto = 5631\n\
             because = \"{BECAUSE}\"\n"
        );
        let (raises, refused, _) = raises_in(&text);
        assert!(refused.is_empty(), "{refused:?}");
        // 5595 is the predecessor's tip and is never compared against anything: the entry is +36.
        assert_eq!(raises[0].by, 36);
    }

    /// THE ENTRIES THE QUEUE IS ACTUALLY HOLDING, replayed verbatim. PROBE-1 (queue line 165),
    /// P1 (491) and S1b (562) carry NO hold at all: they can pop at any moment, they were written
    /// against the reader that took only the retired header, and a parser that reds them is a
    /// parser that breaks three live lines the hour it lands.
    #[test]
    fn the_three_unheld_lines_entries_are_read() {
        let pair = |key: &str, from: i64, to: i64| {
            format!(
                "\n[gate.ceiling_raises.\"{key}\"]\nfrom = {from}\nto = {to}\n\
                 because = \"{BECAUSE}\"\n"
            )
        };
        for (line, entries, want) in [
            (
                "PROBE-1",
                format!(
                    "{}{}",
                    pair("gate.surface_ceilings.contract_caps", 3478, 3483),
                    pair("rules.loc-ceilings.union_ceiling", 23465, 23470)
                ),
                vec![5, 5],
            ),
            (
                "S1b",
                format!(
                    "{}{}{}",
                    pair("gate.surface_ceilings.contract_caps", 3478, 3543),
                    pair("rules.loc-ceilings.caps_contract_ceiling", 3480, 3545),
                    pair("rules.loc-ceilings.union_ceiling", 23465, 23477)
                ),
                vec![65, 65, 12],
            ),
            (
                "P1",
                format!(
                    "{}{}",
                    pair("gate.surface_ceilings.contract_caps", 3478, 3603),
                    pair("rules.loc-ceilings.caps_contract_ceiling", 3480, 3605)
                ),
                vec![125, 125],
            ),
        ] {
            let (raises, refused, warned) = raises_in(&format!("{DOC}{entries}"));
            assert!(refused.is_empty(), "{line}: {refused:?}");
            assert_eq!(warned.len(), want.len(), "{line}: {warned:?}");
            let mut got: Vec<i64> = raises.iter().map(|r| r.by).collect();
            let mut want = want;
            got.sort_unstable();
            want.sort_unstable();
            assert_eq!(got, want, "{line}");
        }
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
            pair: None,
            written_key: None,
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

    /// AND NEITHER ARE THE ADMISSIONS. A `[[minted]]` row carries `cells` and `ceiling`, and a
    /// `[[minted_kind]]` row `cells`, `edges` and `ceiling` — numbers ABOUT ceilings. Read as
    /// ceilings they are keys the base never carried, so the minted door would refuse the very
    /// admission it was written to honour. Measured: the first self-test case to write one reported
    /// `minted.0.ceiling = 120` and `minted.0.cells = 1` as two undeclared minted rises.
    #[test]
    fn a_minted_rows_own_numbers_are_not_ceilings() {
        let text = format!(
            "{DOC}\n[[minted]]\ncrate = \"busbar-export-file\"\ncommit = \"planted\"\n\
             cells = \"4\"\nceiling = \"39\"\n\n\
             [[minted_kind]]\nkind = \"dialect\"\ncommit = \"planted\"\ncells = \"26\"\n\
             edges = \"15\"\nceiling = \"651\"\n"
        );
        let ints = ints_of(&text).expect("the fixture parses");
        assert!(
            ints.keys().all(|k| !k.starts_with("minted")),
            "the admissions are read as ceilings: {ints:?}"
        );
        // The real ceilings beside them are still read.
        assert_eq!(ints.get("gate.surface_ceilings.grammar"), Some(&500));
        // And the door still reads the admission itself.
        let mints = mints_in(&text);
        assert_eq!(
            mints
                .crates
                .get("busbar-export-file")
                .and_then(|m| m.ceiling),
            Some(39)
        );
        assert_eq!(
            mints.kinds.get("dialect").and_then(|m| m.ceiling),
            Some(651)
        );
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
