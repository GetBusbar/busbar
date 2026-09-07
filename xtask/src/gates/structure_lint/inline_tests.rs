//! INVARIANT 3: TESTS LIVE IN `foo/tests/<what>.rs`, ALWAYS.
//!
//! THE RULE, owner: "tests in their own file always", because it "keeps code file length honest and
//! easier to compare". That rationale is not decoration; it already corrupted an investigation. A
//! reviewer compared `config/overlay.rs` at 2,111 lines against `config/migrate.rs` at 2,379 and
//! drew a conclusion from the pair. The real implementation figure for `overlay.rs` was 607 lines;
//! the rest was inline test bodies. Two files whose stated sizes measure different things cannot be
//! compared, and nothing in the file tells you that.
//!
//! So an implementation file carries NO inline test body. The body lives in its own file and the
//! impl file keeps the one-line declaration that leaves it a direct child, which is what preserves
//! `use super::*` reaching private items:
//!
//! ```text
//! #[cfg(test)]
//! #[path = "tests/overlay_tests.rs"]
//! mod tests;
//! ```
//!
//! WHAT COUNTS AS A VIOLATION, precisely: a `#[cfg(test)]`-gated region containing a TEST-FUNCTION
//! attribute. "Gated" is answered by [`crate::scan::test_scope`] and by nothing else, so this rule
//! and the choke-point registry can never disagree about what test code is. Two shapes deliberately
//! do NOT trip it, because neither is a test: the `#[path]` declaration above (brace-less, so it
//! gates its own line and stops), and a `#[cfg(test)]` support module or helper that declares no
//! test (a log tap, a serialising mutex) — those are production-side hooks with no own-file to move
//! to. Files under a `tests/` directory are out of scope: they ARE the own-file.
//!
//! ## The allow marker must NAME ITS REASON
//!
//! A bare allow is the permission-to-ignore mechanism this project banned outright, so a marker
//! with no reason is not a weaker pass — it is its own violation, on its own row:
//!
//! ```text
//! // structure-lint: allow inline-test: <why this body cannot move>
//! ```
//!
//! It must sit in the comment block directly above the `#[cfg(test)]`; any code between detaches
//! it, and a reason shorter than [`MIN_REASON`] characters names nothing.

use crate::ere::Ere;
use crate::gates::structure_lint::corpus::Corpus;
use crate::gates::structure_lint::{row, Findings};
use crate::ledger::Row;

pub const ROW_INLINE_TEST: &str = "structure-lint:inline-tests";
pub const ROW_ALLOW_REASON: &str = "structure-lint:inline-test-allow-reason";

/// The test-function attributes, including the runtime-wrapped spellings. A `#[testing]` is not one
/// of them, which is what the terminator class at the end is for.
pub const INLINE_TEST_ATTR: &str = r"^[[:space:]]*#\[((tokio|async_std|actix_rt|serial_test)::)?(test|rstest|test_case|bench|proptest)[]([:space:]]";
pub const INLINE_ALLOW_RE: &str = r"structure-lint:[[:space:]]*allow[[:space:]]+inline-test";

/// A token like "yes" names nothing.
pub const MIN_REASON: usize = 12;

pub fn finding_inline(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: INLINE-TEST: an inline #[cfg(test)] test body in an implementation file — \
         move it to tests/<what>.rs and leave a #[path] declaration"
    )
}

pub fn finding_allow(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: ALLOW-WITHOUT-REASON: `structure-lint: allow inline-test` with no reason \
         after it — a bare allow is permission to ignore; name why this body cannot move"
    )
}

pub fn scan(corpus: &Corpus, f: &mut Findings) {
    let attr = Ere::new(INLINE_TEST_ATTR).expect("the inline-test attribute pattern compiles");
    let allow = Ere::new(INLINE_ALLOW_RE).expect("the allow-marker pattern compiles");

    for c in &corpus.files {
        let mut armed = false;
        let mut arm_line = 0usize;
        let mut emitted = false;
        // The marker that applies is the one on the line above, so it is tracked as it goes and
        // captured at the moment the region opens.
        let mut marker = false;
        let mut reason = String::new();
        let mut armed_marker = false;
        let mut armed_reason = String::new();

        for line in &c.lines {
            // (1) REGION BOOKKEEPING. The report points at the `#[cfg(test)]` that OPENED the
            //     region, which is the line a reader has to act on — not the individual test
            //     attribute inside it.
            if line.gated && !armed {
                armed = true;
                arm_line = line.no;
                emitted = false;
                armed_marker = marker;
                armed_reason = reason.clone();
            } else if !line.gated && armed {
                armed = false;
            }

            // (2) THE TRIGGER: a test-function attribute anywhere inside the gated region, once.
            if armed && !emitted && attr.is_match(&line.raw) {
                emitted = true;
                if !armed_marker {
                    f.inline_tests.push(finding_inline(&c.rel, arm_line));
                } else if armed_reason.is_empty() {
                    f.allow_reason.push(finding_allow(&c.rel, arm_line));
                }
            }

            // (3) MARKER ADJACENCY, evaluated AFTER the region test so the marker on the line above
            //     is the one that applies. Any line that is neither comment nor blank detaches it.
            if !line.gated {
                if allow.is_match(&line.raw) {
                    marker = true;
                    reason = reason_of(&allow, &line.raw);
                } else if !line.is_comment && !line.raw.trim().is_empty() {
                    marker = false;
                    reason.clear();
                }
            }
        }
    }
}

/// Everything after the marker, with the punctuation that introduces it trimmed off. Too short is
/// the same as absent.
fn reason_of(allow: &Ere, raw: &str) -> String {
    // `sub(/^.*<marker>/, "", reason)` — the greedy `^.*`, so the LAST marker on the line is the
    // one whose tail is the reason.
    let chars: Vec<char> = raw.chars().collect();
    let mut tail = None;
    for start in 0..chars.len() {
        let rest: String = chars[start..].iter().collect();
        if let Some((at, len)) = allow.find(&rest) {
            if at == 0 {
                tail = Some(chars[start + len..].iter().collect::<String>());
            }
        }
    }
    let Some(tail) = tail else {
        return String::new();
    };
    let trimmed = tail
        .trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == '.' || c == '-')
        .trim_end()
        .to_string();
    if trimmed.chars().count() < MIN_REASON {
        return String::new();
    }
    trimmed
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![
        row(
            ROW_INLINE_TEST,
            "no implementation file carries an inline test body",
            "an implementation file carries an inline test body, so its length measures two things",
            &f.inline_tests,
        ),
        row(
            ROW_ALLOW_REASON,
            "every inline-test allow names its reason",
            "a bare `allow inline-test` names no reason, which is permission to ignore",
            &f.allow_reason,
        ),
    ]
}
