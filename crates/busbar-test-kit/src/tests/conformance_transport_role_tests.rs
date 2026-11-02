// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{script_for, Script};
use busbar_contract::abi::transport::{ROLE_CARRIER, ROLE_FRAMER};

#[test]
fn the_script_is_chosen_by_the_declared_role() {
    assert_eq!(script_for(ROLE_FRAMER, false), Ok(Script::Framer));
    assert_eq!(script_for(ROLE_FRAMER, true), Ok(Script::Datagram));
    for datagram in [false, true] {
        assert_eq!(script_for(ROLE_CARRIER, datagram), Ok(Script::Carrier));
        for role in [0, ROLE_CARRIER | ROLE_FRAMER, 7] {
            let e = script_for(role, datagram).expect_err("RED: an unknown role fails");
            assert!(e.starts_with("UnknownRole"), "{e}");
        }
    }
}
