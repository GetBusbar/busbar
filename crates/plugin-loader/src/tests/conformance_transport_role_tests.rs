// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport suite picks its script by the role the door declares.

use super::{script_for, Script};
use busbar_contract::abi::transport::{ROLE_CARRIER, ROLE_FRAMER};

/// A framer runs the framer script and a carrier the carrier script; an unknown role fails
/// (RED arm).
#[test]
fn the_script_is_chosen_by_the_declared_role() {
    assert_eq!(script_for(ROLE_FRAMER), Ok(Script::Framer));
    assert_eq!(script_for(ROLE_CARRIER), Ok(Script::Carrier));
    for role in [0, ROLE_CARRIER | ROLE_FRAMER, 7] {
        let e = script_for(role).expect_err("RED: an unknown role fails");
        assert!(e.starts_with("UnknownRole"), "{e}");
    }
}
