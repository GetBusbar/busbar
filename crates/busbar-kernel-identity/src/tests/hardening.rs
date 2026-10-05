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
use crate::challenge::{Challenge, ChallengeBounds};
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

// ---------------------------------------------------------------------------------------------
// The challenge budget.
// ---------------------------------------------------------------------------------------------

/// Each round of an exchange spends exactly the bytes it carried, and exactly one round.
///
/// The byte budget is the bound on how much an unauthenticated party may be talked to. The suite
/// watched the refusals at the edges — no rounds left, a round too large — but never that a round
/// that IS accepted debits the budget by what it actually cost, so any accounting that leaves more
/// budget than it should went unnoticed, and with it the unbounded conversation the bound exists to
/// prevent.
#[test]
fn every_accepted_round_spends_its_own_bytes_and_one_round() {
    let bounds = ChallengeBounds {
        max_rounds: 4,
        max_bytes: 100,
    };
    let c = Challenge::open(vec![0u8; 10], bounds);
    assert_eq!(c.rounds_left, 3, "opening spent one round");
    assert_eq!(c.bytes_left, 90, "opening spent its own ten bytes");

    let c = c.advance(vec![0u8; 30]).expect("within budget");
    assert_eq!(c.rounds_left, 2);
    assert_eq!(c.bytes_left, 60, "90 - 30, not 90 divided by anything");
    assert_eq!(c.bytes.len(), 30, "the round's bytes are what is carried");

    let c = c.advance(vec![0u8; 55]).expect("within budget");
    assert_eq!(c.rounds_left, 1);
    assert_eq!(c.bytes_left, 5);
    assert!(!c.exhausted(), "one round and five bytes still left");

    // The next round is refused on BYTES with a round still in hand, which is only reachable
    // because the byte budget was debited honestly above.
    assert!(
        c.clone().advance(vec![0u8; 6]).is_none(),
        "six bytes do not fit in five"
    );
    let c = c.advance(vec![0u8; 5]).expect("five exactly fit");
    assert_eq!(c.bytes_left, 0);
    assert!(c.exhausted(), "the byte budget is spent");
}
