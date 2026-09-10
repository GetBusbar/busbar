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
        out = set_int(&out, &s.pin.table, &s.pin.key, s.measured).ok_or_else(|| {
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

    // AN ORDINAL KEY IS REFUSED OUTRIGHT, whatever it happens to line up with today. A declaration
    // is a transaction about ONE ceiling, and `cell.178.count` does not name a ceiling — it names a
    // slot, which the next `[[cell]]` struck above it hands to a different crate entirely. The
    // entry is marked used so this is the ONE thing said about it: "stale" would be a second, less
    // true sentence about the same line. See [`IDENTITIES`].
    for (key, r) in &declared {
        let Some((name, fields)) = ordinal_form(key) else {
            continue;
        };
        used.insert(key.clone());
        risen.push(format!(
            "{key}: a declared raise {} -> {} keyed by ORDINAL. Striking one `[[{name}]]` \
             renumbers every later row, so this entry re-targets whichever row slides into that \
             position. Key it by identity: `{name}.<{}>.count`.",
            r.from,
            r.to,
            fields.join(">.<")
        ));
    }

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
    for (key, r) in &declared {
        if !used.contains(key) {
            risen.push(format!(
                "{key}: a declared raise {} -> {} that is not a raise at the base {}. Either the                  commit that needed it has landed — strike the entry — or it names a ceiling that                  never moved.",
                r.from,
                r.to,
                &base[..8.min(base.len())]
            ));
        }
    }

    let short = &base[..8.min(base.len())];
    let ok = risen.is_empty() && unreadable.is_empty();
    let detail = if ok && allowed.is_empty() {
        format!(
            "no ceiling in {CEILINGS} or {KIND_CEILINGS} is higher than it is at the base {short}"
        )
    } else if ok {
        format!(
            "no undeclared ceiling is higher than it is at the base {short}; {} declared raise(s):              {}",
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

/// The declared raises, keyed `<file>:<dotted path>` — and for a row of `qa/kind-isolation.toml`
/// the dotted path is the row's IDENTITY, `cell.<crate>.<kind>.count`, never its ordinal
/// `cell.178.count`. An ordinal entry is refused by [`ceiling_rose`] rather than resolved, because
/// striking one `[[cell]]` renumbers every later row and re-targets it. See [`IDENTITIES`].
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
    let prefix = "gate.ceiling_raises.";
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
fn ints_of(text: &str) -> Result<BTreeMap<String, i64>, String> {
    let doc = crate::toml_doc::parse_str(text)?;
    let mut out = BTreeMap::new();
    for (path, table) in doc.tables() {
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
}
