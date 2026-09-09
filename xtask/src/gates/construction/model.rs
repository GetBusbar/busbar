//! The construction gate's row shape, its config accessors, and the small set of idioms every
//! rule shares.
//!
//! THE PRINTED SHAPES ARE PART OF THE CONTRACT. A row's `detail` column is compared byte for byte
//! against the Python's by `cargo xtask gate construction --parity`, and several rules print a
//! Python container straight into that column (`f"{sorted(allowed)}"`, `f"{seen}"`). So
//! [`py_list`] and [`py_dict`] reproduce `repr()` exactly rather than picking a nicer Rust
//! spelling: a difference there is a parity RED that says nothing about the tree, which is the one
//! kind of noise the parity harness exists to keep out of a conversion.

use crate::ledger::{Row, Status};
use crate::rx::{self, Regex};
use crate::toml_doc::{Document, Table};

/// The prefix `rules.py` puts on a detail whose subject does not exist in the tree yet.
pub const VACUOUS: &str = "vacuous: ";

/// One measured invariant. `current`/`threshold`/`offenders` are what the report and the
/// self-test read; the ledger sees only the first four fields.
#[derive(Debug, Clone)]
pub struct CRow {
    pub id: String,
    pub status: Status,
    pub title: String,
    pub detail: String,
    pub current: i64,
    pub threshold: i64,
    pub offenders: Vec<String>,
    pub informational: bool,
}

impl CRow {
    pub fn to_row(&self) -> Row {
        Row::new(self.status, &self.id, &self.title, &self.detail)
    }
}

/// A GATING ROW: what it measured is compared, and a false comparison is a FAIL.
///
/// THE `ok` ARGUMENT AND THE `informational` FLAG NO LONGER MEET. They used to be two parameters of
/// one constructor, and the constructor read `if ok || informational { Pass }` — so a rule written
/// with `informational: true` and a real comparison had that comparison silently discarded, and the
/// rule was a comment with the shape of a gate. `legacy-reach:<key>` was exactly that for as long as
/// it existed: `current <= figure` evaluated every run and reached nothing. There is now no way to
/// spell it. A row that compares something is built HERE and gates on the answer; a row that
/// reports without judging is built by [`informational`], which takes no comparison at all.
#[allow(clippy::too_many_arguments)]
pub fn plain(
    id: impl Into<String>,
    ok: bool,
    title: impl Into<String>,
    detail: impl Into<String>,
    current: i64,
    threshold: i64,
    offenders: Vec<String>,
) -> CRow {
    CRow {
        id: id.into(),
        status: if ok { Status::Pass } else { Status::Fail },
        title: title.into(),
        detail: detail.into(),
        current,
        threshold,
        offenders,
        informational: false,
    }
}

/// A REPORTING ROW: it measures, it prints, it never judges. Its title is prefixed `WARN ` — the
/// prefix is in the ledger text, so it is not decoration this port may drop.
///
/// It takes no `ok`, which is the whole point: there is no comparison here for the constructor to
/// throw away, so "informational" is a property of the ROW rather than a modifier that quietly
/// unmakes the verdict the rule computed. A reporting row that should start gating becomes a
/// [`plain`] call with the comparison written out, in a diff a reviewer reads as what it is.
pub fn informational(
    id: impl Into<String>,
    title: impl Into<String>,
    detail: impl Into<String>,
    current: i64,
    threshold: i64,
    offenders: Vec<String>,
) -> CRow {
    CRow {
        id: id.into(),
        status: Status::Pass,
        title: format!("WARN {}", title.into()),
        detail: detail.into(),
        current,
        threshold,
        offenders,
        informational: true,
    }
}

/// Python's `repr()` of a list of strings, which several details print verbatim.
pub fn py_list<S: AsRef<str>>(items: &[S]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| format!("'{}'", s.as_ref()))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Python's `repr()` of a `dict[str, int]`, in insertion order.
pub fn py_dict(items: &[(String, usize)]) -> String {
    format!(
        "{{{}}}",
        items
            .iter()
            .map(|(k, v)| format!("'{k}': {v}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub fn sorted_unique(items: &[String]) -> Vec<String> {
    let mut out = items.to_vec();
    out.sort();
    out.dedup();
    out
}

/// A regex for `literal` as a whole token — no identifier character immediately before it.
pub fn word(literal: &str) -> String {
    format!("(?<![A-Za-z0-9_]){}", rx::escape(literal))
}

/// `^\s*(pub(\([a-z]+\))?\s+)?use\s` — a `use` line names a symbol, it does not call one.
pub fn use_line_rx() -> Regex {
    Regex::new(r"^\s*(pub(\([a-z]+\))?\s+)?use\s").expect("the `use` line pattern compiles")
}

/// The construction ceilings file, read once.
pub struct Cfg {
    pub doc: Document,
}

impl Cfg {
    pub fn rule(&self, name: &str) -> Result<&Table, String> {
        self.doc
            .table(&format!("rules.{name}"))
            .ok_or_else(|| format!("qa/construction.toml has no [rules.{name}] table"))
    }

    pub fn gate(&self) -> Result<&Table, String> {
        self.doc
            .table("gate")
            .ok_or_else(|| "qa/construction.toml has no [gate] table".to_string())
    }

    pub fn plane_crates(&self) -> Result<Vec<String>, String> {
        Ok(self.gate()?.list_of("plane_crates"))
    }

    pub fn test_path_fragments(&self) -> Result<Vec<String>, String> {
        Ok(self.gate()?.list_of("test_path_fragments"))
    }

    pub fn scan_roots(&self) -> Result<Vec<String>, String> {
        Ok(self.gate()?.list_of("scan_roots"))
    }

    /// The directory globs naming one plugin kind. A kind with no entry is no globs, never an
    /// error: the kind simply has no crate yet.
    pub fn kind_globs(&self, kind: &str) -> Vec<String> {
        self.doc
            .table("gate.plugin_kinds")
            .map(|t| t.list_of(kind))
            .unwrap_or_default()
    }
}

/// An integer a rule must have. A ceiling read as a default nobody wrote down is a ceiling that
/// silently moved, so a missing one is a refusal rather than a zero.
pub fn need_int(t: &Table, key: &str, rule: &str) -> Result<i64, String> {
    t.int_of(key)
        .ok_or_else(|| format!("[rules.{rule}] has no integer `{key}`"))
}

pub fn need_str<'a>(t: &'a Table, key: &str, rule: &str) -> Result<&'a str, String> {
    t.str_of(key)
        .ok_or_else(|| format!("[rules.{rule}] has no string `{key}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The detail column carries Python container reprs verbatim; a Rust-flavoured spelling is a
    /// parity RED about nothing.
    #[test]
    fn python_container_reprs_are_reproduced() {
        assert_eq!(
            py_list(&["finish", "finish_admitted"]),
            "['finish', 'finish_admitted']"
        );
        assert_eq!(py_list::<&str>(&[]), "[]");
        assert_eq!(
            py_dict(&[("busbar-llm".to_string(), 1), ("busbar-mcp".to_string(), 0)]),
            "{'busbar-llm': 1, 'busbar-mcp': 0}"
        );
        assert_eq!(py_dict(&[]), "{}");
    }

    /// An informational row is PASS whatever it measured, and says WARN in its title. It has no
    /// `ok` argument to discard, which is what makes "an informational row with a real comparison
    /// in it" unspellable rather than merely unusual.
    #[test]
    fn an_informational_row_never_fails_and_is_titled_warn() {
        let r = informational("x", "a thing", "detail", 9, 0, vec![]);
        assert_eq!(r.status, Status::Pass);
        assert_eq!(r.title, "WARN a thing");
        let g = plain("y", false, "a thing", "detail", 9, 0, vec![]);
        assert_eq!(g.status, Status::Fail);
        assert_eq!(g.title, "a thing");
    }

    #[test]
    fn word_is_a_whole_token_matcher() {
        let r = Regex::new(&word("run_unit")).expect("compiles");
        assert!(r.is_match_str("  run_unit("));
        assert!(!r.is_match_str("  rerun_unit("));
    }
}
