//! INVARIANT 2: NO MONSTER IMPL FILES.
//!
//! Impl files target ~1,500 lines; [`MAX_LINES_IMPL`] forbids genuine MONSTERS — the thing that
//! makes a codebase unnavigable — rather than micromanaging cohesive units. Test files are exempt:
//! they are located by NAME (`foo/tests/<what>.rs`), not read top to bottom, so the navigability the
//! cap protects is already served by the `tests/` convention plus one module per file.
//!
//! ## The grandfathered list is data, and it only shrinks
//!
//! This rule ran for the first time against real content and immediately found files that were
//! already over the cap, none of them introduced by anything that landed the same day. Splitting a
//! 4,900-line hot file under release pressure is how a real regression gets introduced while
//! chasing a lint, so the debt is VISIBLE and TRACKED rather than hidden: a grandfathered file is
//! reported as grandfathered and does not fail the gate.
//!
//! SHRINKING THE LIST IS THE ONLY PERMITTED EDIT. A pull request that ADDS an entry for NEW code is
//! not a fix, it is evading the check.
//!
//! Entries FOLLOW THEIR FILE across a crate split, which is why they are written against
//! [`super::roots`] rather than as literals: the oversized `diagnostics/mod.rs` body moved to the
//! substrate, `mcp/method.rs` moved wholesale to `busbar-mcp`, and the grandfathered LLM engine body
//! moved to `busbar-llm` as `engine/pipeline.rs`. Not re-pointing them would report moved debt as a
//! fresh violation (a lint that lies) while leaving the real file uncovered.

use crate::ctx::{Ctx, WalkSpec};
use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{row, Findings, Tables};
use crate::ledger::Row;

pub const ROW_OVERSIZED: &str = "structure-lint:oversized";

pub const MAX_LINES_IMPL: usize = 2500;

const EXCLUDE_TESTS: &str = "/tests/";

/// PRE-EXISTING DEBT, GRANDFATHERED. `admin/v1/service.rs` is the one entry that is not a moved
/// file: it sat three lines under the cap and the 1.6.0 ABI-purity retype pushed it over, because
/// the admin read path had to stop naming the plane's own types and project the NEUTRAL view
/// instead — the unavoidable cost of the "everything crosses the ABI" mandate, not new behaviour.
/// Its shrink target is the module-level config-mutation builders; this entry comes off the list in
/// that commit.
pub fn grandfathered(a: &Addresses) -> Vec<String> {
    vec![
        format!("{}/admin/v1/json/handlers.rs", a.core),
        format!("{}/config/mod.rs", a.core),
        format!("{}/config/migrate.rs", a.core),
        "crates/busbar-llm/src/engine/pipeline.rs".to_string(),
        format!("{}/diagnostics/mod.rs", a.substrate_values),
        "crates/busbar-a2a/src/a2a/receive.rs".to_string(),
        "crates/busbar-mcp/src/mcp/method.rs".to_string(),
        format!("{}/admin/v1/service.rs", a.core),
    ]
}

pub fn finding(rel: &str, lines: usize) -> String {
    format!("OVERSIZED: {rel} ({lines} lines, over the {MAX_LINES_IMPL}-line cap)")
}

/// `wc -l`, not `lines().count()`: a file whose last line carries no newline is one line shorter to
/// `wc` than to a line iterator, and a cap is a comparison against a number somebody read off a
/// terminal.
fn wc_l(text: &str) -> usize {
    text.bytes().filter(|b| *b == b'\n').count()
}

pub fn scan(cx: &Ctx, t: &Tables, f: &mut Findings) {
    // A SEPARATE WALK from the candidate corpus, and deliberately: `benches/` is exempt from the
    // choke-point registry because a bench is harness code, but a 4,000-line bench is exactly as
    // unnavigable as a 4,000-line module.
    let Ok(files) = cx.walk(
        &WalkSpec::new([super::roots::CRATES])
            .ext("rs")
            .exclude([EXCLUDE_TESTS]),
    ) else {
        return;
    };
    for s in files {
        let n = wc_l(&s.text);
        if n <= MAX_LINES_IMPL {
            continue;
        }
        let rel = s.rel_str();
        if t.grandfathered.contains(&rel) {
            continue;
        }
        f.oversized.push(finding(&rel, n));
    }
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![row(
        ROW_OVERSIZED,
        "every impl file is under the cap, or on the grandfathered list that only shrinks",
        "an impl file is over the cap and is not pre-existing debt",
        &f.oversized,
    )]
}
