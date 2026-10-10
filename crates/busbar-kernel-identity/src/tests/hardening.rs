// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The parts of the unit the ported suite never watched.
//!
//! Every test here was written because a deliberate change to production code — the wrong
//! comparison in a bound, a boolean accessor pinned to `true`, a conjunction turned into a
//! disjunction — left the existing suite entirely green. Each one names the specific change it
//! refuses, so the property is on record rather than left to be inferred from a passing run.

use super::{entry, Canned};
use crate::chain::AuthChain;
use crate::module::AuthOutcome;

// ---------------------------------------------------------------------------------------------
// The chain's own accessors and its cacheability gate.
// ---------------------------------------------------------------------------------------------

/// The two chain-shape accessors answer about the chain they were built over, in BOTH directions.
///
/// Read only in the affirmative, each is satisfied by a constant `true`; a caller deciding whether
/// to run the keys arm, or an operator report saying whether a chain has modules, would then get the
/// same answer for every chain that was ever configured.
#[test]
fn the_chain_shape_accessors_answer_in_both_directions() {
    let with_module = AuthChain::new(
        vec![entry("m", Box::new(Canned::new("m", AuthOutcome::Pass)))],
        false,
    );
    assert!(
        !with_module.has_no_modules(),
        "a chain with a module does not report an empty module list"
    );
    assert!(
        !with_module.keys_in_chain(),
        "a chain that did not name the keys arm does not report it"
    );
    assert!(!with_module.is_open(), "a chain with a module is not open");

    let keys_only = AuthChain::new(Vec::new(), true);
    assert!(
        keys_only.has_no_modules(),
        "the keys arm is not a boxed module, so a keys-only chain has none"
    );
    assert!(keys_only.keys_in_chain());
    assert!(
        !keys_only.is_open(),
        "the arm keeps the door shut even with an empty module list"
    );

    let empty = AuthChain::new(Vec::new(), false);
    assert!(empty.has_no_modules());
    assert!(!empty.keys_in_chain());
    assert!(empty.is_open());
}

/// The chain's `Debug` reports the two facts it says it reports, and never the modules themselves.
///
/// It is hand-written precisely so a boxed module cannot print whatever it likes into an operator's
/// log; a rendering that quietly produced nothing would take the two facts with it.
#[test]
fn the_chains_debug_rendering_carries_the_shape_it_promises() {
    let c = AuthChain::new(
        vec![
            entry("m1", Box::new(Canned::new("m1", AuthOutcome::Pass))),
            entry("m2", Box::new(Canned::new("m2", AuthOutcome::Pass))),
        ],
        true,
    );
    let rendered = format!("{c:?}");
    assert!(rendered.contains("AuthChain"), "{rendered}");
    assert!(rendered.contains("keys_in_chain"), "{rendered}");
    assert!(rendered.contains("true"), "{rendered}");
    assert!(rendered.contains("chain_len"), "{rendered}");
    assert!(rendered.contains('2'), "{rendered}");
}
