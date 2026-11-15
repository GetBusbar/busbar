// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A minted dial's two failures keep their two answers: a minting failure is a host fault, a refused dial is refused.

use super::*;
use crate::datagram::DialBegin;
use crate::framer::Refused;
use busbar_contract::abi::mechanism::call::Outcome;

fn refused(outcome: Outcome) -> Refused {
    Refused {
        outcome,
        error: "why".to_owned(),
    }
}

#[test]
fn a_dial_minting_failure_is_a_fault_and_a_dial_refusal_is_refused() {
    assert_eq!(
        dial_begin_error(DialBegin::Mint(refused(Outcome::Fault))),
        ConnError::Fault
    );
    assert_eq!(
        dial_begin_error(DialBegin::Dial(refused(Outcome::Refused))),
        ConnError::Refused
    );
    assert_eq!(
        dial_begin_error(DialBegin::Dial(refused(Outcome::Fault))),
        ConnError::Refused
    );
}
