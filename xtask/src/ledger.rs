//! THE LEDGER. Rows in the TSV `scripts/release-gate/lib.sh::record` writes and both
//! `scripts/release-gate/gate.sh` and `testing/fleet-fixtures/verdict.sh` read.
//!
//! ## The column count, stated exactly, because it used to be stated wrongly
//!
//! `record` writes SIX columns: `id`, `status`, `title`, `detail`, then the VERSION the row is about
//! and the STAGED QA SHA it was produced against. The last two are not decoration —
//! `gate.sh` counts only rows whose fifth column names the release under test, because ledgers
//! arrive as artefacts merged into one directory and nothing else binds a row to the release.
//!
//! This module READS all six and WRITES four, and both halves are deliberate:
//!
//! * [`parse_rows`] splits on every tab and takes column four as the detail, so a row written by
//!   the shell reads back as the row the shell meant. It used to `splitn(4, …)`, which welded
//!   `detail<TAB>ver<TAB>sha` into the detail — and [`crate::parity`] then compared THAT against a
//!   Rust gate's clean detail, so every ledger-path parity run was comparing two different shapes.
//! * [`Row::tsv`] writes four, because a `Row` carries no version: it does not know which release it
//!   is about, and inventing one would be worse than omitting it. [`write_leg`] has no production
//!   caller, so nothing in this crate contributes rows to a ledger `gate.sh` counts. A Rust gate
//!   that ever needs to WRITE a leg the shell will count must be given the version at its call
//!   site — never read from the environment, which is how the shell's own version column came to
//!   need the refusal `gate.sh` carries.
//!
//! The three refusals the shell readers carry are refusals in the TYPE here, not conventions:
//!
//! * **zero rows is not clean.** An empty row set against a non-empty owed set is RED, by name,
//!   before any other logic runs.
//! * **an owed id with no row DID NOT RUN**, which is not a pass.
//! * **duplicate rows for one id resolve by AGREEMENT, never by position.** `gate.sh` on this base
//!   takes the first row for an id, so a PASS followed by a retry's FAIL let the PASS stand.
//!   Agreement passes; disagreement is [`Resolution::Conflict`] and RED.
//!
//! Plus the two the shell learned the hard way: every SKIP is RED unless its id is explicitly
//! allowlisted, and a row nobody owes is RED rather than a line the reader ignores while exiting 0.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        }
    }

    pub fn parse(s: &str) -> Option<Status> {
        match s {
            "PASS" => Some(Status::Pass),
            "FAIL" => Some(Status::Fail),
            "SKIP" => Some(Status::Skip),
            _ => None,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One ledger row: `<id>\t<PASS|FAIL|SKIP>\t<title>\t<detail>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    pub status: Status,
    pub title: String,
    pub detail: String,
}

impl Row {
    pub fn new(
        status: Status,
        id: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Row {
        Row {
            id: id.into(),
            status,
            title: title.into(),
            detail: detail.into(),
        }
    }

    pub fn pass(id: impl Into<String>, title: impl Into<String>, detail: impl Into<String>) -> Row {
        Row::new(Status::Pass, id, title, detail)
    }

    pub fn fail(id: impl Into<String>, title: impl Into<String>, detail: impl Into<String>) -> Row {
        Row::new(Status::Fail, id, title, detail)
    }

    pub fn skip(id: impl Into<String>, title: impl Into<String>, detail: impl Into<String>) -> Row {
        Row::new(Status::Skip, id, title, detail)
    }

    /// The wire form. `\t` and `\n` are flattened to spaces in `title`/`detail`, the same
    /// `tr '\t\n' '  '` `record()` does, so a row can never split itself into two.
    pub fn tsv(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            flatten(&self.id),
            self.status,
            flatten(&self.title),
            flatten(&self.detail)
        )
    }
}

fn flatten(s: &str) -> String {
    s.replace(['\t', '\n'], " ")
}

/// Parse a leg's TSV. Blank lines are skipped; a line whose column 2 is not a status is an error,
/// because a ledger the reader cannot understand must not read as an empty one.
///
/// COLUMN FOUR IS THE WHOLE DETAIL AND NOTHING ELSE. `record` writes SIX columns — the version and
/// the staged qa sha follow the detail, and `gate.sh` filters a merged artefact directory on the
/// fifth — so a `splitn(4, …)` welded `detail\tver\tsha` into the detail of every row read back from
/// a real ledger, which is what [`crate::parity`] then compared against a Rust gate's clean detail.
/// Splitting on every tab is exact rather than lenient: both writers strip tabs out of the free-text
/// fields, so nothing of the detail can be hiding past the split.
pub fn parse_rows(text: &str) -> Result<Vec<Row>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let id = cols.next().unwrap_or_default();
        let status = cols.next().unwrap_or_default();
        let title = cols.next().unwrap_or_default();
        let detail = cols.next().unwrap_or_default();
        let Some(status) = Status::parse(status) else {
            return Err(format!(
                "ledger line {}: column 2 is `{status}`, not PASS/FAIL/SKIP",
                i + 1
            ));
        };
        out.push(Row::new(status, id, title, detail));
    }
    Ok(out)
}

/// Append rows to a leg file, creating it if absent. Never truncates: a leg is written by several
/// steps and truncation is how a later step erases an earlier step's failure.
pub fn write_leg(path: &Path, rows: &[Row]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    for row in rows {
        writeln!(f, "{}", row.tsv())?;
    }
    Ok(())
}

/// Empty a leg file BEFORE the run that is supposed to write it, so the file-exists guard is
/// honest. Without this a gate that died before writing leaves the previous healthy run's ledger
/// sitting there and the caller reads a green that nothing produced.
pub fn truncate_leg(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"")
}

/// Read a leg back. A MISSING file is an error, never zero rows — "the gate never ran" and "the
/// gate ran and found nothing" are the two readings this whole module exists to keep apart.
pub fn read_leg(path: &Path) -> Result<Vec<Row>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("ledger {}: {e}", path.display()))?;
    parse_rows(&text)
}

/// Truncate, run, read back — the sequence any gate that still shells out must follow. Doing it
/// for the caller is the point: the staleness above is unrepresentable for an in-process gate and
/// must not be reintroduced by one that is not converted yet.
pub fn read_leg_after<F, E>(path: &Path, run: F) -> Result<Vec<Row>, String>
where
    F: FnOnce(&Path) -> Result<(), E>,
    E: fmt::Display,
{
    truncate_leg(path).map_err(|e| format!("ledger {}: {e}", path.display()))?;
    run(path).map_err(|e| e.to_string())?;
    read_leg(path)
}

/// How a set of rows for one id resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Pass,
    Fail,
    Skip,
    /// Two rows for one id disagreed. Never silently resolved by position.
    Conflict,
}

/// A gate's verdict: the rows it produced, whether it is RED, and why.
#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub rows: Vec<Row>,
    pub red: bool,
    /// One line per reason the verdict is RED, each naming its subject.
    pub problems: Vec<String>,
    resolutions: BTreeMap<String, Resolution>,
}

impl Verdict {
    /// Rows with no reconciliation yet — what a [`crate::gates::Gate::run`] returns. The runner
    /// reconciles it against the gate's declared owed set; a gate never marks itself green.
    pub fn of(rows: Vec<Row>) -> Verdict {
        let mut v = Verdict {
            red: rows.iter().any(|r| r.status != Status::Pass),
            rows,
            problems: Vec::new(),
            resolutions: BTreeMap::new(),
        };
        v.resolutions = fold(&v.rows);
        v
    }

    pub fn resolve(&self, id: &str) -> Option<Resolution> {
        self.resolutions.get(id).copied()
    }
}

fn fold(rows: &[Row]) -> BTreeMap<String, Resolution> {
    let mut by_id: BTreeMap<String, BTreeSet<Status>> = BTreeMap::new();
    for row in rows {
        by_id.entry(row.id.clone()).or_default().insert(row.status);
    }
    by_id
        .into_iter()
        .map(|(id, statuses)| {
            let r = if statuses.len() > 1 {
                Resolution::Conflict
            } else {
                match statuses.iter().next().copied() {
                    Some(Status::Pass) => Resolution::Pass,
                    Some(Status::Fail) => Resolution::Fail,
                    Some(Status::Skip) => Resolution::Skip,
                    None => Resolution::Conflict,
                }
            };
            (id, r)
        })
        .collect()
}

/// Reconciles a row set against the owed set. The owed set is DERIVED from the gate registry
/// (`Gate::owed`), never maintained beside the rules — a rule cannot emit a row without being
/// owed, and an owed row cannot silently stop being emitted.
#[derive(Debug, Clone, Default)]
pub struct Reconcile {
    owed: BTreeSet<String>,
    skip_allow: BTreeSet<String>,
}

impl Reconcile {
    pub fn new<I, S>(owed: I) -> Reconcile
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Reconcile {
            owed: owed.into_iter().map(Into::into).collect(),
            skip_allow: BTreeSet::new(),
        }
    }

    /// The narrow skip allowlist. `verdict.sh` has none — every SKIP is RED — and
    /// `release-gate/gate.sh` has exactly four ids. It stays data on the gate that needs it and is
    /// never a wider default.
    pub fn allow_skip<I, S>(mut self, ids: I) -> Reconcile
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.skip_allow.extend(ids.into_iter().map(Into::into));
        self
    }

    pub fn verdict(&self, rows: Vec<Row>) -> Verdict {
        let mut problems = Vec::new();

        // ZERO ROWS FIRST, by name, before any other logic — exactly where both shell readers put
        // it, because every later check is vacuous over an empty ledger.
        if rows.is_empty() && !self.owed.is_empty() {
            problems.push(format!(
                "zero rows: nothing was recorded, but {} check(s) are owed ({}). A check that did \
                 not run is not a check that passed.",
                self.owed.len(),
                self.owed.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }

        let resolutions = fold(&rows);

        for id in &self.owed {
            match resolutions.get(id) {
                None => problems.push(format!(
                    "{id}: owed but no row was recorded — DID NOT RUN, which is not a pass"
                )),
                Some(Resolution::Fail) => problems.push(format!("{id}: FAIL")),
                Some(Resolution::Conflict) => problems.push(format!(
                    "{id}: CONFLICT — two rows for one id disagreed; a later FAIL never hides \
                     behind an earlier PASS"
                )),
                Some(Resolution::Skip) if !self.skip_allow.contains(id) => problems.push(format!(
                    "{id}: SKIP and not allowlisted — a check that could not run is unreachable \
                     for users too"
                )),
                Some(_) => {}
            }
        }

        for id in resolutions.keys() {
            if !self.owed.contains(id) {
                problems.push(format!(
                    "{id}: a row nobody owes. Nothing diffs it, so a FAIL here would be written \
                     into the ledger and exited 0 through. Declare it in the gate's owed set or \
                     stop emitting it."
                ));
            }
        }

        Verdict {
            red: !problems.is_empty(),
            rows,
            problems,
            resolutions,
        }
    }
}
