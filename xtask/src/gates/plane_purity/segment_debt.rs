//! THE SEGMENT-DEBT LIST — `qa/segment-debt.toml`, the dialect names the neutral crates write as
//! identifier SEGMENTS (`PROTO_GEMINI`, `gemini_path`, `anthropic_adaptive_thinking`).
//!
//! The scanner's whole-word rule treats `_` as part of a word, so a dialect written as a segment was
//! invisible to every gate until [`super::scanner::segment_ci`]. The hits that rule found the day it
//! landed are DEBT: named here, row by row, owned by the neutrality lane, and DRAIN-ONLY. A listed
//! segment-only hit is excluded from the DIALECT counts every gate keeps (so no ceiling moves), an
//! UNLISTED one counts as a normal DIALECT hit and is refused by `plane-purity:segment-debt`, and a
//! row whose line no longer exists is stale and refused too — the list can only shrink.
//!
//! A row matches a hit on FILE and TEXT, never on line: line numbers drift with every edit above
//! them and the text is the key. `line` is informational. Matching is ROW BY ROW: each live
//! segment-only hit consumes one unconsumed row of the same file and text, so N identical lines
//! need N identical rows, a hit with no row left is new (RED), and a row no hit consumed is stale.

use crate::ctx::Ctx;

use super::scanner::Hit;

/// The debt list. Owner-edited data; the gate never rewrites it.
pub const SEGMENT_DEBT_TOML: &str = "qa/segment-debt.toml";

/// One `[[segment-debt]]` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Debt {
    pub file: String,
    /// Informational only: where the line sat when the row was written.
    pub line: usize,
    /// The trimmed source line, exactly as [`Hit::code`] holds it.
    pub text: String,
    pub dialect: String,
    pub owner: String,
}

impl Debt {
    pub fn site(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
}

/// Read `text` as the debt list. A row missing a field, or carrying one of the wrong shape, is a
/// refusal naming the row: a half-read list is a list that silently lists less.
pub fn parse(text: &str) -> Result<Vec<Debt>, String> {
    let doc = crate::toml_doc::parse_str(text).map_err(|e| format!("{SEGMENT_DEBT_TOML}: {e}"))?;
    let mut out = Vec::new();
    for (i, t) in doc.array_of_tables("segment-debt").into_iter().enumerate() {
        let field = |k: &str| {
            t.str_of(k).map(str::to_string).ok_or_else(|| {
                format!("{SEGMENT_DEBT_TOML}: [[segment-debt]] row {i} has no string `{k}`")
            })
        };
        let line = t
            .int_of("line")
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| {
                format!("{SEGMENT_DEBT_TOML}: [[segment-debt]] row {i} has no integer `line`")
            })?;
        out.push(Debt {
            file: field("file")?,
            line,
            text: field("text")?,
            dialect: field("dialect")?,
            owner: field("owner")?,
        });
    }
    Ok(out)
}

/// The list as the tree carries it. An ABSENT file is an empty list, not an error: with no list
/// nothing is excluded, so every segment hit counts and the direction of failure is RED.
pub fn load(cx: &Ctx) -> Result<Vec<Debt>, String> {
    if !cx.exists(SEGMENT_DEBT_TOML) {
        return Ok(Vec::new());
    }
    parse(&cx.read(SEGMENT_DEBT_TOML)?)
}

/// The list written back out in the shape [`parse`] reads. Used by the self-test to lay a row onto
/// the committed list; the gate itself never writes it.
pub fn render(rows: &[Debt]) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::new();
    for d in rows {
        out.push_str(&format!(
            "[[segment-debt]]\nfile = \"{}\"\nline = {}\ntext = \"{}\"\ndialect = \"{}\"\nowner = \"{}\"\n\n",
            esc(&d.file),
            d.line,
            esc(&d.text),
            esc(&d.dialect),
            esc(&d.owner)
        ));
    }
    out
}

/// ROW BY ROW: one segment-only hit consumes ONE unconsumed row with the same file and text, and
/// answers whether it found one. Identical lines therefore need identical duplicate rows, so a new
/// identical line is a hit no row is left for.
pub fn consume(debt: &[Debt], consumed: &mut [bool], file: &str, text: &str) -> bool {
    match debt
        .iter()
        .enumerate()
        .position(|(i, d)| !consumed[i] && d.file == file && d.text == text)
    {
        Some(i) => {
            consumed[i] = true;
            true
        }
        None => false,
    }
}

/// Drop the listed segment-only hits from `hits`, consuming one row per hit in `consumed`. What is
/// returned is what every count downstream sees: whole-word hits untouched, listed debt gone, an
/// unlisted segment-only hit kept (and counted as the DIALECT hit it is). A row left unconsumed
/// after every list is drained is stale.
pub fn drain_listed(debt: &[Debt], consumed: &mut [bool], hits: Vec<Hit>) -> Vec<Hit> {
    hits.into_iter()
        .filter(|h| !(h.segment && consume(debt, consumed, &h.file, &h.code)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_round_trips_through_render_and_parse() {
        let rows = vec![Debt {
            file: "crates/x/src/a.rs".into(),
            line: 7,
            text: "const A: &str = \"PROTO_GEMINI\"; // a \\ b".into(),
            dialect: "gemini".into(),
            owner: "kernel-neutrality lane".into(),
        }];
        assert_eq!(parse(&render(&rows)).unwrap(), rows);
    }

    #[test]
    fn a_row_with_a_missing_field_is_refused() {
        assert!(parse("[[segment-debt]]\nfile = \"a\"\nline = 1\n").is_err());
    }
}
