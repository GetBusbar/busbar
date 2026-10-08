// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport script is chosen by the declared role (`super::script_for`).

use super::script_for;
use busbar_contract::abi::transport::{ROLE_CARRIER, ROLE_FRAMER};

/// A framer runs the framer script; a carrier is refused BY NAME (the interim guard until
/// `p2-transport-carrier`); an unknown role fails. RED arms: the carrier and the unknown role.
#[test]
fn the_script_is_chosen_by_the_declared_role() {
    assert_eq!(script_for(ROLE_FRAMER), Ok(()));
    let carrier = script_for(ROLE_CARRIER).expect_err("RED: a carrier is refused");
    assert!(carrier.starts_with("CarrierScriptPending"), "{carrier}");
    assert!(carrier.contains("p2-transport-carrier"), "{carrier}");
    for role in [0, ROLE_CARRIER | ROLE_FRAMER, 7] {
        let e = script_for(role).expect_err("RED: an unknown role fails");
        assert!(e.starts_with("UnknownRole"), "{e}");
    }
}
