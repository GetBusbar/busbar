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

/// THE BASE IS NOT A HARDCODED BRANCH NAME ANY MORE, AND THAT IS THE WHOLE POINT.
///
/// This constant used to be one. It was `origin/integration/oracle-phase0`, which was renamed to
/// `delete/integration/oracle-phase0` and stopped resolving; [`base_ref`] treated "does not
/// resolve" as "fall back to `HEAD~1`" and every row that read it silently measured one commit
/// instead of a branch. The repair was to name a different fixed branch, `origin/predev`, on the
/// reasoning that it is "the ref every in-flight branch forks from and lands back on". That
/// reasoning is sound for a FORK-AND-LAND branch and it was wrong here, measurably:
///
/// * `origin/predev` last moved three days before this was written and had DIVERGED — 88 commits on
///   it that HEAD does not carry — so `merge-base(HEAD, origin/predev)` was a fork point 178
///   commits and four days in the past.
/// * The branch the work is actually on, `consolidated/1.6.0`, is not a fork of predev that will be
///   merged back as a unit. It is a SHARED LINE that roughly eighteen agents commit directly onto.
///   So `merge-base..HEAD` was not "this change" — it was four days of the whole team's work, and
///   `ceiling-rose` reported every ceiling any of them had moved as an undeclared raise of the
///   commit in front of it.
/// * Worse, the `[gate.ceiling_raises]` transaction stopped working. Its own doc ([`raises`]) says
///   a declaration "EXPIRES BY ITSELF, because the moment its commit lands the base carries the new
///   number". Against a base that never advances, nothing ever expires and every raise must be
///   declared from a four-day-old number instead of the one it actually moved.
///
/// So the base is DERIVED FROM THE CHECKOUT: the remote tip of the line `HEAD` is on, and `HEAD~1`
/// when `HEAD` already is that tip. That is the ref that cannot go stale, because it is not a name
/// anybody has to remember to update — rename the branch and the derivation renames with it, which
/// is the failure mode this constant has now had twice. See [`base_ref`].
///
/// [`BASE_ENV`] overrides it for a caller that genuinely knows better (CI measuring a merge target,
/// a self-test pointing at a planted ref). An override that does not resolve is RED like any other
/// base that cannot be established — it is not a way to turn the ratchet off.
pub const BASE_ENV: &str = "XTASK_CEILING_BASE";

pub const ROW_ROSE: &str = "ceiling-rose";

/// The overlay command key a self-test plants to pin [`base_ref`]'s answer. See there.
pub const BASE_PIN_KEY: &str = "construction-ceiling-base";
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
    /// The ceiling's dotted path, `<table>.<key>` — what a named reservation is keyed by.
    pub fn path(&self) -> String {
        format!("{}.{}", self.table, self.key)
    }

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
///
/// AN ORPHAN PIN IS RED HERE TOO (item 232). A pin whose row this run did not emit is a ceiling
/// nobody measured: it cannot be slack-checked, `--write` refuses to re-pin it, and it sits in the
/// ceilings file ready to absorb its subject's return at any size. [`slack_findings`] has always
/// computed that list and said "the caller reports it"; this caller discarded it, so only the
/// `--write` path ever saw it. It is reported and scored, beside the slack.
pub fn ceiling_slack(cfg: &Cfg, rows: &[CRow]) -> Vec<CRow> {
    let (slack, mut orphan) = slack_findings(cfg, rows);
    orphan.extend(reservation_problems(cfg));
    let mut parts = Vec::new();
    if !slack.is_empty() {
        parts.push(format!(
            "{} ceiling(s) with slack — a ceiling above its measurement is room nobody voted for; \
             `cargo xtask gate construction --write` re-pins them (downward only): {}",
            slack.len(),
            slack
                .iter()
                .map(|s| s.line())
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if !orphan.is_empty() {
        parts.push(format!(
            "{} ceiling(s) or reservation(s) are not a measured, named room — point each at its row \
             or strike it: {}",
            orphan.len(),
            orphan.join(", ")
        ));
    }
    let detail = if parts.is_empty() {
        "every ratcheted ceiling equals what it measures".to_string()
    } else {
        parts.join("; ")
    };
    let mut offenders: Vec<String> = slack.iter().map(|s| s.line()).collect();
    offenders.extend(
        orphan
            .iter()
            .map(|o| format!("{o}: not a measured, named room")),
    );
    vec![plain(
        ROW_SLACK,
        offenders.is_empty(),
        "every ratcheted ceiling is pinned to today's measurement",
        detail,
        offenders.len() as i64,
        0,
        offenders,
    )]
}

/// One ceiling with room under it.
#[derive(Debug, Clone)]
pub struct Slack {
    pub pin: Pin,
    pub measured: i64,
    /// Headroom a named reservation holds open under this ceiling (0 when none is declared).
    pub reserved: i64,
    pub ceiling: i64,
}

impl Slack {
    fn line(&self) -> String {
        let held = if self.reserved > 0 {
            format!(", {} of it reserved by name", self.reserved)
        } else {
            String::new()
        };
        format!(
            "{} measures {} against ceiling {} ({}.{} = {}, slack {}{held})",
            self.pin.row,
            self.measured,
            self.ceiling,
            self.pin.table,
            self.pin.key,
            self.ceiling,
            self.ceiling - self.measured - self.reserved
        )
    }
}

/// The slack list, plus the pins whose row never appeared — a pin naming no row is a stale entry in
/// exactly the way a waiver naming no hit is, and the caller reports it.
fn slack_findings(cfg: &Cfg, rows: &[CRow]) -> (Vec<Slack>, Vec<String>) {
    let by_id: BTreeMap<&str, &CRow> = rows.iter().map(|r| (r.id.as_str(), r)).collect();
    let (mut slack, mut orphan) = (Vec::new(), Vec::new());
    let held: BTreeMap<String, i64> = reservations(cfg)
        .into_iter()
        .filter(|(_, r)| r.is_named())
        .map(|(path, r)| (path, r.lines))
        .collect();
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
        let reserved = held.get(&pin.path()).copied().unwrap_or(0);
        if row.current < 0 || row.current + reserved >= row.threshold {
            continue;
        }
        slack.push(Slack {
            pin,
            measured: row.current,
            reserved,
            ceiling: row.threshold,
        });
    }
    (slack, orphan)
}

/// `cargo xtask gate construction --write`: re-pin every slack ceiling to what it measures.
///
/// DOWNWARD ONLY, and the monotonicity is the whole safety property — see the module header.
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
    if slack.is_empty() {
        return Ok(
            "every ratcheted ceiling already equals what it measures; nothing to re-pin"
                .to_string(),
        );
    }
    let path = cx.abs(CEILINGS);
    let text = cx.read(CEILINGS)?;
    let mut out = text.clone();
    let mut done = Vec::new();
    for s in &slack {
        out =
            set_int(&out, &s.pin.table, &s.pin.key, s.measured + s.reserved).ok_or_else(|| {
                format!(
                    "{CEILINGS} has no `{}` under [{}] to re-pin",
                    s.pin.key, s.pin.table
                )
            })?;
        done.push(format!("{}: {} -> {}", s.pin.row, s.ceiling, s.measured));
    }
    std::fs::write(&path, &out).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!(
        "re-pinned {} ceiling(s) in {CEILINGS} (downward only):\n  {}",
        done.len(),
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

/// Add `items` to the list `table.key`, in place, creating the key directly under the table's header
/// when it is absent. The entries go in right after the list's opening `[`, so a one-line list, a
/// multi-line list and an empty `[]` all stay valid TOML. `None` when the table has no header line.
///
/// Written for the construction self-test's GREEN FIXTURE (item 89), which records today's debt in
/// the rule's own review lists INSIDE AN OVERLAY so a case can ask about a site the debt does not
/// touch. Nothing writes this to the committed file.
pub fn add_to_list(text: &str, table: &str, key: &str, items: &[String]) -> Option<String> {
    let quoted = items
        .iter()
        .map(|i| format!("\"{}\"", i.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(", ");
    let mut cur = String::new();
    let mut out: Vec<String> = Vec::new();
    let (mut header_at, mut done) = (None, false);
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('[') && t.ends_with(']') {
            cur = t[1..t.len() - 1].trim().to_string();
            out.push(raw.to_string());
            if cur == table && header_at.is_none() {
                header_at = Some(out.len());
            }
            continue;
        }
        if !done && cur == table && !t.starts_with('#') {
            if let Some((k, v)) = t.split_once('=') {
                if k.trim().trim_matches('"') == key && v.trim_start().starts_with('[') {
                    let at = raw.find('[').unwrap_or(raw.len());
                    let (head, tail) = raw.split_at(at + 1);
                    out.push(format!("{head} {quoted},{tail}"));
                    done = true;
                    continue;
                }
            }
        }
        out.push(raw.to_string());
    }
    if !done {
        let at = header_at?;
        out.insert(at, format!("{key} = [{quoted}]"));
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    Some(s)
}

/// The header prefix of every `[gate.ceiling_raises."<dotted path>"]` declaration table.
pub const RAISES_PREFIX: &str = "gate.ceiling_raises.";

/// The header prefix of every `[gate.ceiling_reservations."<dotted path>"]` table.
pub const RESERVATIONS_PREFIX: &str = "gate.ceiling_reservations.";

/// ONE NAMED RESERVATION: headroom a ruling holds open under one ceiling, for a change that is
/// ruled and not yet landed.
///
/// `ceiling-slack` holds every ceiling to its measurement, and room above the measurement is room
/// nobody voted for. A reservation is room somebody DID vote for: it names the ceiling it sits
/// under by its exact dotted path, states how many units it holds, and carries the ruling that
/// grants it. The gate subtracts it before judging slack, so a ceiling equal to its measurement
/// plus its reservation is pinned, and any gap beyond the reservation is still slack. The number
/// is itself a ratcheted figure in this file (`ceiling-rose` reads it like any other), so a
/// reservation can shrink as the reserved change spends it and never grow without a declared raise.
#[derive(Debug, Clone)]
pub struct Reservation {
    pub lines: i64,
    pub because: String,
}

impl Reservation {
    /// A reservation counts only when it holds a positive amount and says why at the length a
    /// reason needs; anything less is an unexplained gap wearing a label.
    fn is_named(&self) -> bool {
        self.lines > 0 && self.because.len() >= MIN_REASON
    }
}

/// The named reservations, keyed by the dotted path of the ceiling each sits under.
pub fn reservations(cfg: &Cfg) -> BTreeMap<String, Reservation> {
    cfg.doc
        .tables()
        .into_iter()
        .filter_map(|(p, t)| {
            let key = p.strip_prefix(RESERVATIONS_PREFIX)?;
            Some((
                key.trim_matches('"').to_string(),
                Reservation {
                    lines: t.int_of("lines").unwrap_or(0),
                    because: t.str_of("because").unwrap_or("").trim().to_string(),
                },
            ))
        })
        .collect()
}

/// Every reservation that is not a measured, named room: one that holds nothing or gives no reason
/// long enough to be one, or one that sits under no ratcheted ceiling. Each is RED on
/// `ceiling-slack`, since a reservation the gate cannot tie to a pin and a ruling would otherwise
/// excuse slack for nobody.
fn reservation_problems(cfg: &Cfg) -> Vec<String> {
    let paths: BTreeSet<String> = pins(cfg).iter().map(Pin::path).collect();
    reservations(cfg)
        .into_iter()
        .filter_map(|(path, r)| {
            if !paths.contains(&path) {
                Some(format!(
                    "reservation `{RESERVATIONS_PREFIX}\"{path}\"` sits under no ratcheted ceiling"
                ))
            } else if !r.is_named() {
                Some(format!(
                    "reservation `{RESERVATIONS_PREFIX}\"{path}\"` must hold a positive `lines` and \
                     a `because` of at least {MIN_REASON} characters naming its ruling"
                ))
            } else {
                None
            }
        })
        .collect()
}

/// The text with every table whose header starts with `prefix` removed, header to next header.
/// The self-test's green fixture uses it to take `[gate.ceiling_raises.*]` out of a ceilings file
/// whose base is planted as that same file: a declaration over a base with no raise is stale by
/// design, so the fixture that makes the base equal to the tree carries none.
pub fn strip_tables(text: &str, prefix: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut skipping = false;
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('[') && t.ends_with(']') {
            skipping = t[1..].starts_with(prefix);
        }
        if !skipping {
            out.push(raw);
        }
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    s
}

// ── ceiling-rose ─────────────────────────────────────────────────────────────────────────────────

/// THE BASE, AND THE DERIVATION THAT PRODUCED IT.
///
/// `how` is not decoration. The bug this type exists to prevent was never a base that was WRONG in
/// a way anybody could see — it was a base that was UNSAID. `ceiling-rose` printed "the base
/// dc7bb323" and nothing anywhere printed which ref that came from or how far back it was, so a
/// ref that had stopped resolving, and later a ref that had gone four days stale, both read exactly
/// like a working gate. Every row that establishes a base now states the derivation in its own
/// detail, so "measuring the wrong thing" is a sentence a reader can disagree with.
#[derive(Debug, Clone)]
pub struct Base {
    /// The commit itself.
    pub sha: String,
    /// How it was arrived at, in words, for the row detail.
    pub how: String,
}

impl Base {
    /// The abbreviated sha every finding quotes.
    pub fn short(&self) -> &str {
        &self.sha[..8.min(self.sha.len())]
    }
}

impl std::fmt::Display for Base {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.sha)
    }
}

/// THE BASE THIS RUN IS MEASURED AGAINST: the remote tip of the line `HEAD` is on, or `HEAD~1` when
/// `HEAD` already is that tip.
///
/// WHY THE LINE'S OWN REMOTE TIP AND NOT A NAMED UPSTREAM. See [`BASE_ENV`] for the history; the
/// short form is that `merge-base(HEAD, <some fixed branch>)` answers "where did this branch fork"
/// and that is only the right question when HEAD is a fork. Every place this gate actually runs, it
/// is not: CI runs it on a pushed branch, and the agents run it on a shared integration line they
/// commit directly onto. In both, the unit of judgement is the COMMIT — which is exactly what
/// `[gate.ceiling_raises]` already says it is ("in the same commit as the change", expiring by
/// itself the moment that commit lands) — and the commits under judgement are precisely the ones
/// this checkout has that the line's remote tip does not.
///
/// THE FOUR WAYS THIS RETURNS RED, none of which used to be red:
/// 1. `HEAD` is detached and no [`BASE_ENV`] was given, so there is no line to take a tip from.
/// 2. The ref does not resolve — a rename, an unfetched remote, a shallow clone. This is the
///    original failure: it used to fall through to `HEAD~1` and measure one commit forever.
/// 3. `git merge-base` prints nothing: unrelated histories.
/// 4. THE REF HAS DIVERGED FROM `HEAD` — the merge-base is neither `HEAD` nor the ref's own tip, so
///    the ref carries commits `HEAD` does not and the merge-base is a fork point in the past. This
///    is the second failure, and it is the generalisation of the first: a base that RESOLVES can
///    still be unestablishable. `origin/predev` was 88 commits ahead of a 178-commit-old fork
///    point, and the gate reported four days of the whole team's ceiling movement as the work of
///    the commit in front of it. "Cannot be established" has to mean this too, or the next stale
///    ref is as silent as the last one.
///
/// Only case (4)'s complement — the merge-base IS the ref's tip, or IS `HEAD` — is a base, and in
/// both the span it names is a contiguous run of commits every one of which is on this line.
pub fn base_ref(cx: &Ctx) -> Result<Base, String> {
    // A SELF-TEST'S PINNED BASE. Every other input to this derivation is live git: `HEAD`, the
    // line's remote tip, the merge-base. On a shared checkout that other writers commit onto, a
    // self-test that takes minutes sees `HEAD~1` move under it, so the base a fixture planted
    // `git-show:<sha>:<file>` for at the start is not the base a case asks about at the end — and
    // the case reports a race as a rule's verdict. The fixture pins the sha it planted against. An
    // EMPTY value is "not pinned", so a case can plant the unpinned derivation back (the case that
    // proves an unresolvable ref is refused needs the live arm). No real run carries an overlay.
    if let Some(sha) = cx.overlay_command(BASE_PIN_KEY) {
        if !sha.trim().is_empty() {
            return Ok(Base {
                sha: sha.trim().to_string(),
                how: "pinned by the self-test's fixture".to_string(),
            });
        }
    }
    let head = cx.git(&["rev-parse", "HEAD"])?.trim().to_string();
    let (r, why) = base_line(cx)?;
    if !cx.git_ref_resolves(&r) {
        return Err(format!(
            "the base ref '{r}' does not resolve in this checkout -- fetch it, push this line, or \
             set {BASE_ENV}. A base that cannot be established is RED, never a silent fall-back to \
             the last commit"
        ));
    }
    let mb = cx
        .git(&["merge-base", "HEAD", &r])
        .map_err(|e| format!("'{r}' resolves but HEAD has no merge-base with it: {e}"))?
        .trim()
        .to_string();
    if mb.is_empty() {
        return Err(format!(
            "'{r}' resolves but `git merge-base` printed nothing -- unrelated histories, most \
             likely"
        ));
    }
    if mb == head {
        // HEAD IS the tip of its own line: "what is under judgement here" is the last commit.
        let sha = cx.git(&["rev-parse", "HEAD~1"])?.trim().to_string();
        return Ok(Base {
            sha,
            how: format!("HEAD~1, because HEAD is at or behind {r} ({why})"),
        });
    }
    let tip = cx
        .git(&["rev-parse", &format!("{r}^{{commit}}")])?
        .trim()
        .to_string();
    if mb != tip {
        let (ahead, behind) = (
            cx.git(&["rev-list", "--count", &format!("{mb}..{head}")])
                .unwrap_or_default()
                .trim()
                .to_string(),
            cx.git(&["rev-list", "--count", &format!("{mb}..{tip}")])
                .unwrap_or_default()
                .trim()
                .to_string(),
        );
        return Err(format!(
            "'{r}' has DIVERGED from HEAD: their merge-base {} is {ahead} commit(s) behind HEAD \
             and {behind} commit(s) behind '{r}', so it is a fork point in the past rather than \
             this line's base. Measuring against it would report every ceiling anyone moved in \
             those {ahead} commits as this change's own raise. Rebase onto '{r}', fetch it, or set \
             {BASE_ENV}. A base that cannot be established is RED, never a silent fall-back",
            &mb[..8.min(mb.len())]
        ));
    }
    let ahead = cx
        .git(&["rev-list", "--count", &format!("{mb}..{head}")])
        .unwrap_or_default()
        .trim()
        .to_string();
    Ok(Base {
        sha: mb,
        how: format!("{why}, {ahead} commit(s) behind HEAD"),
    })
}

/// THE REF [`base_ref`] WILL MEASURE AGAINST, and the words for how it was chosen — resolved or
/// not, merge-based or not.
///
/// Separate from [`base_ref`] so the self-test can ask which ref this checkout would use and then
/// plant THAT ref as unresolvable. The alternative is a case that hardcodes a branch name, which is
/// the same mistake as the constant this function replaced: it would prove the arm on the machine
/// it was written on and quietly stop exercising it everywhere else.
pub fn base_line(cx: &Ctx) -> Result<(String, String), String> {
    if let Some(r) = base_override() {
        let why = format!("{BASE_ENV}={r}");
        return Ok((r, why));
    }
    let branch = cx
        .git(&["symbolic-ref", "--quiet", "--short", "HEAD"])
        .map_err(|_| {
            format!(
                "HEAD is detached, so there is no line to take a remote tip from and no base can \
                 be derived. Set {BASE_ENV} to the commit this checkout should be measured \
                 against. A base that cannot be established is RED, never a silent fall-back to \
                 the last commit."
            )
        })?
        .trim()
        .to_string();
    let r = format!("origin/{branch}");
    let why = format!("the remote tip of the line HEAD is on, {r}");
    Ok((r, why))
}

/// [`BASE_ENV`], trimmed, with an empty value read as absent.
///
/// A direct `std::env::var` rather than a field on [`Ctx`]'s environment struct because this is an
/// ESCAPE HATCH for a caller who knows better, not a mode the gate has: nothing in the ordinary run
/// sets it, and an override that does not resolve is refused by [`base_ref`] like any other base.
fn base_override() -> Option<String> {
    std::env::var(BASE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
    let declared = raises(cx);
    let mut risen: Vec<String> = Vec::new();
    let mut allowed: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    // Every compared number's base value, keyed `<file>:<path>`, so a declaration that describes no
    // rise on this branch can be told apart: one whose raise the base already carries has LANDED,
    // and one that matches neither the base nor the tree never described a real edit.
    let mut at_base: BTreeMap<String, i64> = BTreeMap::new();
    let mut expired: Vec<String> = Vec::new();
    for file in [CEILINGS, KIND_CEILINGS] {
        let now = match cx.read(file) {
            Ok(t) => t,
            Err(e) => {
                unreadable.push(format!("{file} on this tree: {e}"));
                continue;
            }
        };
        let was = match cx.git_show(&base.sha, file) {
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
            at_base.insert(format!("{file}:{path}"), *before);
            let Some(after) = now.get(path) else { continue };
            if after <= before {
                continue;
            }
            // A DECLARED RAISE IS THE ONE WAY THROUGH, and it is a transaction rather than a hole:
            // the declaration names the exact path and BOTH numbers, carries a reason, and expires
            // by itself — once the commit lands, the base carries the new number, the rise this
            // row sees is gone, and the entry describes nothing and is refused as stale. See
            // [`raises`].
            match declared.get(&format!("{file}:{path}")) {
                Some(r) if r.from == *before && r.to == *after && r.because.len() >= MIN_REASON => {
                    used.insert(format!("{file}:{path}"));
                    allowed.push(format!(
                        "{file} {path}: {before} -> {after} ({})",
                        r.because
                    ));
                }
                Some(r) => {
                    used.insert(format!("{file}:{path}"));
                    risen.push(format!(
                        "{file} {path}: {before} -> {after}, declared as {}->{} with a {}-character reason. A raise is allowed by a declaration that describes THIS raise and gives a reason, or by nothing",
                        r.from,
                        r.to,
                        r.because.len()
                    ));
                }
                None => risen.push(format!("{file} {path}: {before} -> {after}")),
            }
        }
    }
    // A DECLARATION THAT DESCRIBES NO RAISE ON THIS BRANCH IS A WAIVER THAT OUTLIVED WHAT IT
    // EXCUSED, and that is how this mechanism cannot silt up: the entry is struck by the commit
    // after the one that needed it, or the row says so.
    //
    // EXCEPT ONE THAT HAS LANDED. The base is the commit before the tip, so a raise declared in its
    // own commit is carried by the base from the very next commit on, and every later tip used to go
    // RED on it until somebody landed the strike. A declaration whose `to` IS the base's value
    // describes a raise already in history: it passes, and is named so it can be struck at leisure.
    // One whose ceiling never moved, or whose `to` matches neither the base nor the tree, stays RED.
    for (key, r) in &declared {
        if !used.contains(key) && at_base.get(key) == Some(&r.to) {
            expired.push(format!(
                "{key}: the declared raise {} -> {} is already carried by the base (landed); \
                 strike it at leisure",
                r.from, r.to
            ));
        } else if !used.contains(key) {
            risen.push(format!(
                "{key}: a declared raise {} -> {} that is not a raise at the base {}. Either the                  commit that needed it has landed — strike the entry — or it names a ceiling that                  never moved.",
                r.from,
                r.to,
                base.short()
            ));
        }
    }

    let short = base.short();
    let ok = risen.is_empty() && unreadable.is_empty();
    let landed = if expired.is_empty() {
        String::new()
    } else {
        format!(
            "; {} expired declaration(s): {}",
            expired.len(),
            expired.join("; ")
        )
    };
    let detail = if ok && allowed.is_empty() {
        format!(
            "no ceiling in {CEILINGS} or {KIND_CEILINGS} is higher than it is at the base \
             {short}{landed}"
        )
    } else if ok {
        format!(
            "no undeclared ceiling is higher than it is at the base {short}; {} declared raise(s):              {}{landed}",
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
            "{} ceiling(s) ROSE since the base {short}. A ceiling only goes down: raise one and \
             the row that reads it stops reporting the coupling it was written to report. Drain \
             the measurement instead, or move the number in a commit of its own that says why: {}",
            risen.len(),
            risen.join("; ")
        )
    };
    // THE DERIVATION IS PART OF THE FINDING, always, pass or fail. A base this row does not name
    // is a base nobody audits, and this row has now twice spent weeks comparing against a commit
    // that was not the one it claimed to be measuring — once because the ref had been renamed away,
    // once because it had gone stale. Printing "the base dc7bb323" told a reader nothing; printing
    // where dc7bb323 came from and how far back it is, is the sentence a reader can call wrong.
    let detail = format!("{detail}. Base {short} derived as: {}", base.how);
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

/// ONE DECLARED RAISE: the exact numbers, and why.
#[derive(Debug, Clone)]
pub struct Raise {
    pub from: i64,
    pub to: i64,
    pub because: String,
}

/// The declared raises, keyed `<file>:<dotted path>`.
///
/// WHY A RAISE CAN BE DECLARED AT ALL. A ratchet with no route through it is a ratchet somebody
/// edits the rule to get past, and there is one raise that is legitimate and cannot be avoided:
/// the FIRST gating figure of a row that was not gating before. `legacy-reach:busbar_substrate`
/// was `informational()` — PASS whatever it measured — and the tree moved underneath it while it
/// said nothing. The commit that makes such a row gate cannot also be the commit that reports a
/// regression, because nothing was ever held.
///
/// So the raise is DECLARED, and the declaration is not a waiver: it names the file, the exact
/// dotted path and BOTH numbers, so it describes one edit and not a direction; it carries a reason
/// long enough to be one; and it EXPIRES BY ITSELF, because the moment its commit lands the base
/// carries the new number, the rise disappears, and an entry that describes no rise is refused as
/// stale. It cannot be left behind, and it cannot cover the next raise of the same ceiling.
pub fn raises(cx: &Ctx) -> BTreeMap<String, Raise> {
    let mut out = BTreeMap::new();
    let Ok(text) = cx.read(CEILINGS) else {
        return out;
    };
    let Ok(doc) = crate::toml_doc::parse_str(&text) else {
        return out;
    };
    // `Document::children` cannot answer this: the entry's key IS a dotted path, so a header like
    // `[gate.ceiling_raises."rules.legacy-reach.prefixes.busbar_substrate.figure"]` registers a
    // table whose remainder contains dots, which `children` filters out as a deeper sub-table.
    let prefix = RAISES_PREFIX;
    for (key, t) in doc
        .tables()
        .into_iter()
        .filter_map(|(p, t)| p.strip_prefix(prefix).map(|k| (k.to_string(), t)))
    {
        let (Some(from), Some(to)) = (t.int_of("from"), t.int_of("to")) else {
            continue;
        };
        let file = t.str_of("file").unwrap_or(CEILINGS).to_string();
        out.insert(
            format!("{file}:{key}"),
            Raise {
                from,
                to,
                because: t.str_of("because").unwrap_or("").trim().to_string(),
            },
        );
    }
    out
}

/// Every integer in a TOML document, by dotted path — WHETHER IT IS WRITTEN AS A TOML INTEGER OR
/// AS A QUOTED STRING. The reader this crate has refuses a document it does not understand, which
/// is the behaviour wanted here too: a ceilings file that cannot be parsed is a comparison that
/// cannot be made.
///
/// THE STRING FALLBACK IS NOT A CONVENIENCE. Every one of the `[[cell]] count` numbers in
/// `qa/kind-isolation.toml` is written `count = "122"`, and an integer-only reader scores that file
/// at zero ceilings: the whole file was re-pinnable by hand with this row printing PASS. How a
/// number is spelled is a matter of the file's own style, and a ratchet that a change of quoting
/// switches off is not a ratchet.
/// AN `[[array]]` ENTRY IS KEYED BY WHAT IT IS, NEVER BY WHERE IT SITS, and that is the second bug
/// this reader had.
///
/// `[[cell]]` entries register as `cell.0`, `cell.1`, …, so the path a count was filed under was
/// its ORDINAL. Delete a row from the middle of `qa/kind-isolation.toml` and every row after it
/// slides down one — and this function then compared each surviving row against whatever unrelated
/// row used to occupy its new index. Measured on the tree this comment was written on: 70 rows had
/// been struck, and `ceiling-rose` reported 117 raises, of which ZERO were raises. `cell.100` was
/// `busbar-llm`/`timing` = 12 at the base and `busbar-mcp`/`transport` = 1104 in the tree, and the
/// row dutifully reported "12 -> 1104". Every one of the 117 was a comparison between two different
/// crates. That is not a false positive in a rule, it is a rule reading a different file than it
/// thinks it is, and it drowned the six findings that were real.
///
/// THE IDENTITY IS DERIVED, NOT TABLED. An entry's identity is its own non-numeric string fields —
/// for `[[cell]]` that is `crate` and `kind`, which is exactly the pair that names the cell, but
/// nothing here knows the word "cell". A table of "which keys identify which array" is the thing
/// the next array added to a ceilings file would forget to join, and this row's whole design is
/// that it reads every number in the file without being told where they are.
///
/// IT FALLS BACK TO THE ORDINAL, DELIBERATELY, in the two cases where an identity would be a
/// FICTION: an entry with no non-numeric string field at all, and an identity that is not unique
/// within its array. In both, two entries would collapse onto one key and the last one parsed would
/// silently win — which is the same class of bug as the one being fixed. The ordinal is at least
/// honest about being positional. Both sides of the comparison run this identical rule, so a
/// document that falls back on one side and not the other simply yields no common key, and a
/// ceiling with no counterpart is skipped rather than guessed at.
///
/// WHAT THIS MEANS FOR A DELETED ROW: nothing is reported. The base's key has no counterpart in the
/// tree, [`ceiling_rose`] skips it, and a struck row can no longer manufacture a raise in the rows
/// beneath it. A row that is genuinely raised — same crate, same kind, bigger count — is still
/// caught, which is the only thing this rule ever claimed to catch.
fn array_identity(doc: &crate::toml_doc::Document, path: &str) -> Option<String> {
    let (base, idx) = path.rsplit_once('.')?;
    let i: usize = idx.parse().ok()?;
    let n = doc.array_len(base);
    if i >= n {
        return None;
    }
    let ident = |t: &crate::toml_doc::Table| -> Option<String> {
        let mut parts: Vec<String> = t
            .keys()
            .iter()
            .filter(|k| t.int_of(k).is_none())
            .filter_map(|k| {
                let s = t.str_of(k)?;
                // A NUMBER SPELLED AS A STRING IS A CEILING, NOT A NAME — the whole reason this
                // reader reads quoted numbers at all. It must not also become part of the identity,
                // or raising a count would change the key the count is filed under and the raise
                // would vanish instead of being reported.
                (s.trim().parse::<i64>().is_err()).then(|| format!("{k}={s}"))
            })
            .collect();
        (!parts.is_empty()).then(|| {
            parts.sort();
            parts.join(",")
        })
    };
    let mine = ident(doc.table(path)?)?;
    let unique = (0..n)
        .filter(|j| *j != i)
        .filter_map(|j| doc.table(&format!("{base}.{j}")))
        .all(|t| ident(t).as_deref() != Some(mine.as_str()));
    unique.then(|| format!("{base}[{mine}]"))
}

/// Every integer in a TOML document, by dotted path — WHETHER IT IS WRITTEN AS A TOML INTEGER OR
/// AS A QUOTED STRING. The reader this crate has refuses a document it does not understand, which
/// is the behaviour wanted here too: a ceilings file that cannot be parsed is a comparison that
/// cannot be made.
///
/// THE STRING FALLBACK IS NOT A CONVENIENCE. Every one of the `[[cell]] count` numbers in
/// `qa/kind-isolation.toml` is written `count = "122"`, and an integer-only reader scores that file
/// at zero ceilings: the whole file was re-pinnable by hand with this row printing PASS. How a
/// number is spelled is a matter of the file's own style, and a ratchet that a change of quoting
/// switches off is not a ratchet.
///
/// THE PATH OF AN `[[array]]` ENTRY IS ITS IDENTITY, NOT ITS INDEX — see [`array_identity`] for the
/// 117 raises that were not raises.
///
/// A DECLARATION IS NOT A CEILING. The `from` / `to` of a `[gate.ceiling_raises."<path>"]` entry
/// are numbers in this file, and they used to be read as ceilings like every other number: the
/// commit that replaces a landed declaration with the next re-arm of the same ceiling (7414 -> 7418
/// over 5652 -> 7414) moves both numbers UP, and `ceiling-rose` refused the re-declaration itself
/// as two undeclared rises. The declaration tables are taken out before anything is read, so the
/// numbers compared are the ceilings and only the ceilings; [`raises`] reads the declarations.
fn ints_of(text: &str) -> Result<BTreeMap<String, i64>, String> {
    let text = strip_tables(text, RAISES_PREFIX);
    let doc = crate::toml_doc::parse_str(&text)?;
    let mut out = BTreeMap::new();
    for (path, table) in doc.tables() {
        let keyed = array_identity(&doc, path).unwrap_or_else(|| path.to_string());
        for key in table.keys() {
            if let Some(v) = table
                .int_of(key)
                .or_else(|| table.str_of(key).and_then(|s| s.trim().parse::<i64>().ok()))
            {
                let dotted = if keyed.is_empty() {
                    key.clone()
                } else {
                    format!("{keyed}.{key}")
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
    use crate::ledger::Status;

    /// ITEM 232: A PIN WHOSE ROW THE RUN DID NOT EMIT IS RED ON `ceiling-slack`, not only on
    /// `--write`. The same run with every pinned row present at its ceiling is GREEN, so the red
    /// is the orphan and nothing else.
    #[test]
    fn ceiling_slack_reports_a_pin_whose_row_never_appeared() {
        let cx = crate::ctx::Ctx::workspace().expect("workspace");
        let cfg = super::super::ConstructionGate::cfg(&cx).expect("ceilings");
        let all = pins(&cfg);
        assert!(all.len() > 1, "the control needs pins");
        let at_ceiling: Vec<CRow> = all
            .iter()
            .map(|p| plain(p.row.clone(), true, "t", "d", 3, 3, vec![]))
            .collect();
        let green = ceiling_slack(&cfg, &at_ceiling);
        assert_eq!(green[0].status, Status::Pass, "{}", green[0].detail);

        let orphaned = &all[0].row;
        let missing_one: Vec<CRow> = at_ceiling
            .into_iter()
            .filter(|r| &r.id != orphaned)
            .collect();
        let red = ceiling_slack(&cfg, &missing_one);
        assert_eq!(red[0].status, Status::Fail, "{}", red[0].detail);
        assert!(
            red[0].detail.contains(orphaned.as_str()),
            "{}",
            red[0].detail
        );
    }

    /// Every pin's row at its ceiling, except the kernel's, which measures `kernel` under 100.
    fn rows_with_kernel_at(cfg: &Cfg, kernel: i64) -> Vec<CRow> {
        pins(cfg)
            .iter()
            .map(|p| match p.row.as_str() {
                "loc-ceilings:kernel" => plain(p.row.clone(), true, "t", "d", kernel, 100, vec![]),
                _ => plain(p.row.clone(), true, "t", "d", 3, 3, vec![]),
            })
            .collect()
    }

    fn cfg_of(doc: &str) -> Cfg {
        Cfg {
            doc: crate::toml_doc::parse_str(doc).expect("the fixture parses"),
        }
    }

    const RULED: &str =
        "the kernel change this ruling reserves room for is ruled and not yet landed, \
                         so its lines are held open by name";

    /// A NAMED RESERVATION IS SUBTRACTED BEFORE SLACK IS JUDGED, AND ONLY ITS OWN AMOUNT. A ceiling
    /// at measurement plus reservation is pinned (GREEN); the same ceiling one unit further up is an
    /// unnamed gap (RED); with no reservation, the reserved amount is slack like any other (RED).
    #[test]
    fn a_named_reservation_is_subtracted_and_an_unnamed_gap_still_fails() {
        let reserved = cfg_of(&format!(
            "[gate.ceiling_reservations.\"rules.loc-ceilings.kernel_ceiling\"]\nlines = 10\n\
             because = \"{RULED}\"\n"
        ));
        let green = ceiling_slack(&reserved, &rows_with_kernel_at(&reserved, 90));
        assert_eq!(green[0].status, Status::Pass, "{}", green[0].detail);

        let red = ceiling_slack(&reserved, &rows_with_kernel_at(&reserved, 89));
        assert_eq!(red[0].status, Status::Fail, "{}", red[0].detail);
        assert!(
            red[0].detail.contains("slack 1, 10 of it reserved"),
            "{}",
            red[0].detail
        );

        let bare = cfg_of("[rules.x]\nn = 1\n");
        let unnamed = ceiling_slack(&bare, &rows_with_kernel_at(&bare, 90));
        assert_eq!(unnamed[0].status, Status::Fail, "{}", unnamed[0].detail);
        assert!(
            unnamed[0].detail.contains("slack 10"),
            "{}",
            unnamed[0].detail
        );
    }

    /// A RESERVATION THAT DOES NOT SAY WHY, HOLDS NOTHING, OR SITS UNDER NO CEILING EXCUSES NOTHING
    /// and is itself RED: a label on a gap is not a ruling.
    #[test]
    fn a_reservation_without_its_ruling_or_its_ceiling_is_refused() {
        for doc in [
            "[gate.ceiling_reservations.\"rules.loc-ceilings.kernel_ceiling\"]\nlines = 10\n\
             because = \"K2g\"\n"
                .to_string(),
            format!(
                "[gate.ceiling_reservations.\"rules.loc-ceilings.kernel_ceiling\"]\nlines = 0\n\
                 because = \"{RULED}\"\n"
            ),
            format!(
                "[gate.ceiling_reservations.\"rules.nowhere.ceiling\"]\nlines = 10\n\
                 because = \"{RULED}\"\n"
            ),
        ] {
            let cfg = cfg_of(&doc);
            let at_ceiling: Vec<CRow> = pins(&cfg)
                .iter()
                .map(|p| plain(p.row.clone(), true, "t", "d", 3, 3, vec![]))
                .collect();
            let red = ceiling_slack(&cfg, &at_ceiling);
            assert_eq!(red[0].status, Status::Fail, "{doc}: {}", red[0].detail);
            assert!(red[0].detail.contains("reservation"), "{}", red[0].detail);
        }
    }

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
        assert_eq!(
            ints.get("cell[crate=busbar,kind=api].count"),
            Some(&122),
            "an array entry is keyed by what it is"
        );
        // The neighbouring strings are words, not numbers, and must not become ceilings.
        assert_eq!(ints.get("cell[crate=busbar,kind=api].crate"), None);
        assert_eq!(ints.get("cell[crate=busbar,kind=api].kind"), None);
    }

    /// THE 117 RAISES THAT WERE NOT RAISES. Striking one row from an array used to slide every row
    /// below it down one index, and the reader compared each survivor against whatever unrelated
    /// entry had previously occupied its new ordinal — `busbar-llm`/`timing` = 12 against
    /// `busbar-mcp`/`transport` = 1104, reported as "12 -> 1104".
    #[test]
    fn striking_an_array_row_does_not_renumber_the_rows_beneath_it() {
        let row = |c: &str, n: i64| {
            format!("[[cell]]\ncrate = \"{c}\"\nkind = \"api\"\ncount = \"{n}\"\n")
        };
        let was = ints_of(&format!("{}{}{}", row("a", 1), row("b", 2), row("c", 3)))
            .expect("the fixture parses");
        // `b` is struck; `c` slides from index 2 to index 1 and NOTHING about `c` changed.
        let now = ints_of(&format!("{}{}", row("a", 1), row("c", 3))).expect("the fixture parses");
        for (path, before) in &was {
            if let Some(after) = now.get(path) {
                assert_eq!(after, before, "{path} must not appear to have moved");
            }
        }
        // The struck row's key is simply absent, which `ceiling_rose` skips.
        assert!(!now.contains_key("cell[crate=b,kind=api].count"));
        // …and `c` is still found, under the same key, at the same number.
        assert_eq!(now.get("cell[crate=c,kind=api].count"), Some(&3));
    }

    /// A GENUINE RAISE OF AN ARRAY ROW IS STILL CAUGHT — the identity is the entry's NAMES, and the
    /// count is deliberately not part of it, or raising a count would re-key the row and the raise
    /// would vanish instead of being reported.
    #[test]
    fn a_count_that_actually_rose_is_still_reported() {
        let was = ints_of("[[cell]]\ncrate = \"a\"\nkind = \"api\"\ncount = \"1\"\n").unwrap();
        let now = ints_of("[[cell]]\ncrate = \"a\"\nkind = \"api\"\ncount = \"9\"\n").unwrap();
        let k = "cell[crate=a,kind=api].count";
        assert_eq!((was.get(k), now.get(k)), (Some(&1), Some(&9)));
    }

    /// AN IDENTITY THAT IS NOT UNIQUE IS A FICTION, and the ordinal — honest about being positional
    /// — is used instead. Two entries collapsing onto one key would let the last one parsed win,
    /// which is the same class of bug as the one identity keying fixes.
    #[test]
    fn a_duplicate_identity_falls_back_to_the_ordinal() {
        let ints = ints_of("[[c]]\nname = \"x\"\nn = 1\n\n[[c]]\nname = \"x\"\nn = 2\n").unwrap();
        assert_eq!(ints.get("c.0.n"), Some(&1));
        assert_eq!(ints.get("c.1.n"), Some(&2));
        assert_eq!(ints.get("c[name=x].n"), None);
    }

    /// An entry with NO non-numeric string field has no identity to be keyed by, and keeps its
    /// ordinal rather than being given one that does not exist.
    #[test]
    fn an_entry_with_no_names_keeps_its_ordinal() {
        let ints = ints_of("[[c]]\nn = 1\n\n[[c]]\nn = 2\n").unwrap();
        assert_eq!(ints.get("c.0.n"), Some(&1));
        assert_eq!(ints.get("c.1.n"), Some(&2));
    }

    /// An ordinary `[table.0]` that is NOT an array-of-tables entry must not be mistaken for one.
    #[test]
    fn a_plain_table_whose_last_segment_is_a_number_is_left_alone() {
        let ints = ints_of("[t.0]\nname = \"x\"\nn = 5\n").unwrap();
        assert_eq!(ints.get("t.0.n"), Some(&5));
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

    /// The self-test fixture's two text editors: an entry lands in the named table's list (made
    /// when absent, prepended when present), the result still parses, and a stripped table takes
    /// its body with it and nothing else.
    #[test]
    fn the_fixture_editors_add_to_a_list_and_strip_a_table() {
        let doc = "[a]\nk = [\n  \"x\",\n]\n[b]\nn = 1\n[gate.ceiling_raises.\"c[k=v].n\"]\nfrom = 1\nto = 2\n[d]\nm = 3\n";
        let added = add_to_list(doc, "a", "k", &["y".to_string()]).expect("table a");
        let made = add_to_list(&added, "b", "new-key", &["z".to_string()]).expect("table b");
        let parsed = crate::toml_doc::parse_str(&made).expect("still TOML");
        assert_eq!(parsed.table("a").expect("a").list_of("k"), vec!["y", "x"]);
        assert_eq!(parsed.table("b").expect("b").list_of("new-key"), vec!["z"]);
        assert!(add_to_list(doc, "nope", "k", &[]).is_none());
        let stripped = strip_tables(doc, "gate.ceiling_raises.");
        assert!(!stripped.contains("from = 1"), "{stripped}");
        assert!(stripped.contains("[d]\nm = 3"), "{stripped}");
        assert!(stripped.contains("[b]\nn = 1"), "{stripped}");
    }

    /// A DECLARATION IS NOT A CEILING: the `from` / `to` of a `[gate.ceiling_raises.*]` entry are
    /// not read as numbers `ceiling-rose` compares, and a ceiling in the table after one still is.
    #[test]
    fn a_declarations_numbers_are_not_ceilings() {
        let doc = "[rules.x]\nceiling = 7\n[gate.ceiling_raises.\"rules.x.ceiling\"]\nfrom = 5652\nto = 7414\n[rules.y]\nceiling = 3\n";
        let ints = ints_of(doc).expect("the fixture parses");
        assert_eq!(ints.get("rules.x.ceiling"), Some(&7), "{ints:?}");
        assert_eq!(ints.get("rules.y.ceiling"), Some(&3), "{ints:?}");
        assert!(
            ints.keys().all(|k| !k.starts_with(RAISES_PREFIX)),
            "a declaration's numbers were read as ceilings: {ints:?}"
        );
    }
}
