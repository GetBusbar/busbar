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

/// PRE-EXISTING DEBT, GRANDFATHERED. Most entries are MOVED files whose debt travelled with them:
/// the admin read path (`v1/json/handlers.rs`) was extracted out of the engine into its own admin
/// crate, and `config/mod.rs` / `config/migrate.rs` rode the `busbar-core` -> `busbar-kernel`
/// absorption, so they are named at their current homes rather than deleted.
///
/// AN ENTRY NAMING NO FILE IS THE SILENT FAILURE THIS LIST HAS. The handlers row read
/// `crates/busbar-admin/src/v1/json/handlers.rs` until the #37 fold put the two admin crates into
/// `busbar-core-admin`; a grandfather entry matching nothing does not red, it just stops
/// grandfathering, and the file it was written for came back as a NEW oversized finding under its
/// new name while the row that excused it sat there looking live.
///
/// The former `admin/v1/service.rs` entry came OFF this list when the extraction carried the
/// config-mutation-builder shrink with it and the file sat under the cap at 2491. It is NOT put
/// back here: that file is over the cap again today, and so is `busbar/src/main.rs` (no line count
/// is quoted, because a count written into a comment is the next thing to go stale — run the gate).
/// Those are live findings for their owners to shrink or to grandfather in a diff that argues for
/// it — repointing a stale row is not a licence to absorb the reds that row was never written for.
///
/// The last two entries are the same class as the retired `service.rs` one — a structural MANDATE
/// pushed an under-cap file over, not new behaviour:
///   * `busbar-kernel/src/plane_host/mod.rs` — the W4.b P2 substrate absorption folded
///     `busbar-substrate`'s 1608-line plane host into the kernel's, and the merged dispatch host is
///     3421. Splitting it means moving plane-dispatch code, which the absorption wave deliberately
///     does not touch; its shrink target is the per-plane vtable rows, carved to submodules once the
///     dispatch seam is otherwise stable.
///   * `busbar/src/root/units_admin/mod.rs` — the #36 drain of `busbar-unit-verbs` into
///     `busbar-admin` grew the composition-root admin wiring to 2606; its shrink target is the
///     per-verb install blocks, split to sibling modules once the drain lands in full.
pub fn grandfathered(a: &Addresses) -> Vec<String> {
    vec![
        "crates/busbar-core-admin/src/v1/json/handlers.rs".to_string(),
        format!("{}/config/mod.rs", a.core),
        format!("{}/config/migrate.rs", a.core),
        "crates/busbar-llm/src/engine/pipeline.rs".to_string(),
        format!("{}/diagnostics/mod.rs", a.substrate_values),
        "crates/busbar-a2a/src/a2a/receive.rs".to_string(),
        "crates/busbar-mcp/src/mcp/method.rs".to_string(),
        format!("{}/plane_host/mod.rs", a.core),
        "crates/busbar/src/root/units_admin/mod.rs".to_string(),
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
