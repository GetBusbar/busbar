// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SANITISER'S COMPLEXITY GUARDS — the half of markup-normalisation that is measured in time.
//!
//! Tool output and `resources/read` content are bytes an UPSTREAM chose. A scan that goes quadratic
//! on a shape the sender picks is a denial of service the sender can spell in a 200 KB body, so the
//! two adversarial shapes below carry a wall-clock bound as well as an output assertion.
//!
//! WHY THESE TWO LIVE OUT HERE AND THE REST OF THE SUITE LIVES IN `src/tests/`. They read a clock,
//! and this crate's purity oracle (`tests/purity.rs::the_plane_performs_no_input_or_output`) walks
//! `src/` and refuses one — rightly, because a plane that reads a clock can answer differently for
//! a reason no caller can see. Measuring what a pure function COSTS is not the plane reading a
//! clock; it is a harness reading one from outside. So the rule stays absolute and the guard stays
//! running, which is the arrangement a waiver would have destroyed.

use busbar_plane_mcp::sanitize::normalise;

/// AN UNTERMINATED `<` MUST NOT COST MORE THAN THE BYTES IT ARRIVED IN.
///
/// Tool output and `resources/read` content are bytes an upstream MCP server chose, and this is the
/// module that exists because of that. Re-scanning the whole tail for every `<letter` turns a 200 KB
/// body into billions of byte comparisons on a served request — cheap to send, expensive to receive.
/// The output assertion is the correctness half (nothing is dropped, nothing is rewritten); the
/// wall-clock bound is the half that fails the moment the scan goes quadratic again.
#[test]
fn unterminated_tags_are_kept_verbatim_without_rescanning_the_tail() {
    let hostile = "<a".repeat(100_000);
    let started = std::time::Instant::now();
    let out = normalise(&hostile);
    let elapsed = started.elapsed();
    assert_eq!(
        out, hostile,
        "with no `>` anywhere in the input, every `<` is a dangling `<`, i.e. ordinary text"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "normalising {} bytes of `>`-less input took {elapsed:?}: the tag scan is re-reading the \
         tail for every `<` instead of remembering that no `>` remains",
        hostile.len()
    );
}

/// NOR MAY THE RECONSTITUTION CHECK, WHICH IS THE OTHER SHAPE AN UPSTREAM GETS TO CHOOSE.
///
/// `<<<…a…>>>` is the adversarial input for the seam re-examination: every deletion hands the next
/// one a fresh pending `<`. Re-normalising the whole string to a fixpoint would answer correctly and
/// cost a pass per nesting level — quadratic on bytes the sender picked. Removing the opener and
/// jumping past its `>` costs one step per level instead, and the cursor never goes backwards, so
/// this stays inside the same wall-clock bound as the `>`-less case above.
#[test]
fn deep_reconstitution_nesting_does_not_reprocess_the_string_per_level() {
    let depth = 100_000;
    // `<<<a>a>a>` at scale: one opener per level, and each level's `>` is the one that closes the
    // opener the level below it just had exposed.
    let hostile = format!("{}a{}>", "<".repeat(depth), ">a".repeat(depth - 1));
    let started = std::time::Instant::now();
    let out = normalise(&hostile);
    let elapsed = started.elapsed();
    // The COLLAPSE ITSELF is asserted next door, in `src/tests/sanitize_tests.rs`'s
    // `deep_reconstitution_nesting_collapses_every_level`, which needs no clock and therefore stays
    // where the rest of the suite is. What is left here is the half that needs one.
    let _ = &out;
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "normalising {} bytes of {depth}-deep nesting took {elapsed:?}: the seam check is \
         re-running the whole scan once per nesting level",
        hostile.len()
    );
}
