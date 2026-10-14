//! A ROW'S CELLS ON THE TSV WIRE: `cargo xtask gate --format=tsv` prints each cell of a row whose
//! detail is a list of coded findings as its own indented line under the row.
//!
//! WHY. busbar-release judges a ledger row PER CELL (BUSBAR-1.6.0.md Law 9, "arm at today's
//! number"; its `baseline::cells`): a cell standing red at the base and not grown is the base's
//! debt, a new red cell or one whose figure rose is the candidate's. A generic CI that compares
//! failing row ids between a change and its target sees one id, `kind-isolation:law0`, for every
//! cell of that row, so a second cell going red inside an already-red row is invisible to it. One
//! line per cell gives such a reader a failing id per cell, the same unit busbar-release judges.
//!
//! THE LINE: a leading tab, then `<row-id>/<cell>`, the cell's `PASS`/`FAIL`, its
//! `<figure>/<ceiling>` (`-` for a side the finding does not state), and the cell's finding(s):
//!
//! ```text
//! kind-isolation:law0\tFAIL\t<title>\t<detail>
//! \tkind-isolation:law0/busbar×plane\tFAIL\t828/826\tlaw0-rise busbar × plane 828 hit(s) ...
//! ```
//!
//! `<cell>` is the key busbar-release's `baseline::cells` files the finding under (the words after
//! the code up to the first count, `busbar × plane`) with its spaces removed, so the id is one
//! token. THE LEADING TAB is what keeps every existing reader where it was: busbar-release's
//! `gate::parse_tsv_rows` reads column 1 as the row id and drops a line whose id is empty, so its
//! rows, and the JSON report built from them, are byte-identical with or without the cell lines; a
//! reader that trims the line reads the cell as a row. The row line itself is unchanged.
//!
//! WHERE THE CELLS COME FROM. A gate that measured the row cell by cell attaches the cells to the
//! row ([`Row::cells`], `kind-isolation:law0`: every neutral crate × axis, the at-ceiling ones
//! PASS). Any other FAIL row is decomposed by [`findings`], the port of busbar-release's own
//! `baseline::findings` / `finding_parts`, so the rows decomposed are exactly the rows it
//! decomposes and every cell is keyed as it keys it. A PASS or SKIP row, a FAIL row that is not a
//! list of coded findings, and one whose findings all fall in one unnamed cell (the row itself),
//! keeps its single line.

use std::collections::BTreeMap;

use crate::ledger::{flatten, Cell, Row, Status};

/// The `--format=tsv` text of `rows`: each row's [`Row::tsv`] line, followed by its cell lines.
#[must_use]
pub fn render(rows: &[Row]) -> String {
    let mut out = String::new();
    for row in rows {
        out.push_str(&row.tsv());
        out.push('\n');
        for line in cell_lines(row) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// The cell lines printed under `row` (none for a row that keeps its single line).
#[must_use]
pub fn cell_lines(row: &Row) -> Vec<String> {
    cells_of(row)
        .iter()
        .map(|c| {
            format!(
                "\t{}/{}\t{}\t{}/{}\t{}",
                flatten(&row.id),
                c.key.split_whitespace().collect::<String>(),
                c.status,
                c.figure.map_or_else(|| "-".to_string(), |n| n.to_string()),
                c.ceiling.map_or_else(|| "-".to_string(), |n| n.to_string()),
                flatten(&c.detail)
            )
        })
        .collect()
}

/// The cells of `row`: those its gate measured, else, for a FAIL row whose detail is a list of
/// coded findings, one FAIL cell per key its findings are filed under.
#[must_use]
pub fn cells_of(row: &Row) -> Vec<Cell> {
    if row.status != Status::Fail {
        return Vec::new();
    }
    if !row.cells.is_empty() {
        return row.cells.clone();
    }
    let Some(found) = findings(&flatten(&row.detail)) else {
        return Vec::new();
    };
    let mut by_key: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in found {
        by_key.entry(finding_parts(&f).1).or_default().push(f);
    }
    // ONE UNNAMED CELL IS THE ROW ITSELF (`busbar-kernel 29590 (ceiling 29284)` opens with a
    // code-shaped word and a count): a `<row-id>/` line would repeat the row line under no name.
    if by_key.len() == 1 && by_key.contains_key("") {
        return Vec::new();
    }
    by_key
        .into_iter()
        .map(|(key, mut found)| {
            found.sort();
            // The cell's figure is its highest finding's (busbar-release `baseline::grown` reads
            // the max), and the ceiling the one that finding states.
            let top = found
                .iter()
                .max_by_key(|f| finding_parts(f).2)
                .cloned()
                .unwrap_or_default();
            Cell {
                key,
                status: Status::Fail,
                figure: finding_parts(&top).2,
                ceiling: ceiling_of(&top),
                detail: found.join(" | "),
            }
        })
        .collect()
}

/// The coded findings of a FLATTENED row detail, `<head>: <finding> | <finding> ...`, each finding
/// opening with its code (`law0-rise busbar × vendor 90 hit(s) against a ceiling of 89: ...`).
/// `None` when the detail is not such a list. A ` | ` not followed by a code continues the finding
/// before it. A verbatim port of busbar-release `baseline::findings`.
#[must_use]
pub fn findings(detail: &str) -> Option<Vec<String>> {
    let opens = |s: &str| {
        s.split_once(' ').is_some_and(|(code, _)| {
            code.contains(|c: char| c.is_ascii_lowercase())
                && code
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
    };
    // The head (`3 hit(s) off the [[law0]] ceilings, 2 finding(s) ...`) is the text before the
    // first `: `, unless the detail opens with a finding itself.
    let body = if opens(detail) {
        detail
    } else {
        detail.split_once(": ").map_or(detail, |(_, b)| b)
    };
    let mut out: Vec<String> = Vec::new();
    for piece in body.split(" | ") {
        if opens(piece) {
            out.push(piece.to_string());
        } else {
            let prev = out.last_mut()?;
            prev.push_str(" | ");
            prev.push_str(piece);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// A finding's code, its cell (the words after the code up to its first count, `busbar × vendor`),
/// and that count (its figure, `None` when it states none). A verbatim port of busbar-release
/// `baseline::finding_parts`.
#[must_use]
pub fn finding_parts(f: &str) -> (&str, String, Option<u64>) {
    let mut words = f.split_whitespace();
    let code = words.next().unwrap_or("");
    let mut cell = Vec::new();
    let mut figure = None;
    for w in words {
        if let Ok(n) = w.parse::<u64>() {
            figure = Some(n);
            break;
        }
        cell.push(w);
    }
    (code, cell.join(" "), figure)
}

/// The ceiling a finding states: the number after `ceiling` (`against a ceiling of 826`,
/// `(ceiling 29284)`), `None` when it states none (`law0-new`: no row yet).
#[must_use]
pub fn ceiling_of(f: &str) -> Option<u64> {
    let mut words = f
        .split_whitespace()
        .skip_while(|w| w.trim_start_matches('(') != "ceiling");
    words.next()?;
    let mut next = words.next()?;
    if next == "of" {
        next = words.next()?;
    }
    next.trim_end_matches(|c: char| !c.is_ascii_digit())
        .parse()
        .ok()
}

#[cfg(test)]
#[path = "tests/cells_tests.rs"]
pub(crate) mod tests;
