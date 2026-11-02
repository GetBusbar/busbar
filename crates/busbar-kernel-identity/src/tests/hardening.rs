// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The parts of the unit the ported suite never watched.

use super::{entry, Canned};
use crate::chain::AuthChain;
use crate::module::AuthOutcome;

/// The two chain-shape accessors answer about the chain they were built over, in BOTH directions.

#[test]
fn the_chain_shape_accessors_answer_in_both_directions() {
    let with_module = AuthChain::new(
        vec![entry("m", Box::new(Canned::new("m", AuthOutcome::Pass)))],
        false,
    );
    assert!(
        !with_module.chain_names().is_empty(),
        "a chain with a module does not report an empty module list"
    );
    assert!(
        !with_module.keys_in_chain(),
        "a chain that did not name the keys arm does not report it"
    );
    assert!(!with_module.is_open(), "a chain with a module is not open");

    let keys_only = AuthChain::new(Vec::new(), true);
    assert!(
        keys_only.chain_names().is_empty(),
        "the keys arm is not a boxed module, so a keys-only chain has none"
    );
    assert!(keys_only.keys_in_chain());
    assert!(
        !keys_only.is_open(),
        "the arm keeps the door shut even with an empty module list"
    );

    let empty = AuthChain::new(Vec::new(), false);
    assert!(empty.chain_names().is_empty());
    assert!(!empty.keys_in_chain());
    assert!(empty.is_open());
}
