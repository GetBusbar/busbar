//! Crate-level test suite for the admin surface's declarations.
//!
//! Inline (`#[cfg(test)] mod tests` from `mod.rs`) rather than an external `tests/` integration
//! crate, because the table-driven tests need this module's own `pub(crate)` verb table to state
//! their expectations without hand-duplicating it.
//!
//! WHAT IS NOT TESTED HERE ANY MORE, AND WHY. This file used to drive a `Plane` entry face:
//! `decode_ingress` over the pinned fixture's 66 operations, `encode_refusal`, `encode_response`'s
//! arena pass-through, and a determinism walk. The face is gone — a `Plane` is how TRAFFIC enters
//! the dispatch loop and the admin surface serves operators (#3/#5/#83 def 11) — and nothing
//! dispatched through it even while it existed: an admin request arrives on `admin_listen`, is
//! matched against `verbs::resolve`, and walks the loop as the admin units. So the coverage moved
//! to where the behaviour is:
//!
//! * the 66/34/32 fixture walk is `tests/verbs.rs`'s
//!   `every_1_5_5_fixture_operation_resolves_to_the_right_verb_and_scope`, which reads the same
//!   pinned document through `find_verb` — the lookup the live path runs;
//! * the frozen error envelope is `tests/refusal.rs`, through `envelope_of` — the function the
//!   administrative listener's every error answer is actually built with;
//! * the walk itself (a real verb, through the real mount, past the loop's steps, onto the audit
//!   chain) is `crates/busbar/src/root/units_admin/tests/admin_path_without_plane_face.rs`.

use crate::admin_codec::verbs::{self, VERB_COUNT};

// ── the closed table ───────────────────────────────────────────────────────────────────────────

/// The combined table (66 generated + 18 money-governance + 5 ledger views) has exactly the rows
/// its count declares, and no duplicate verb name.
#[test]
fn combined_table_has_unique_verb_names() {
    let all = verbs::table();
    assert_eq!(all.len(), VERB_COUNT);
    let mut names: Vec<&str> = all.iter().map(|e| e.verb).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(
        names.len(),
        before,
        "a verb name repeats in the combined table"
    );
}

// ── what the surface declares about itself ─────────────────────────────────────────────────────

// ── the entry face is gone, and this is what says so ───────────────────────────────────────────

// ── no section-sign or parity-binding literals anywhere in this crate ──────────────────────────
