// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TRANSPORT THAT STATES NO FAULT READING READS AS NONE (ARCHITECT breaker ruling, 2026-10-05).
//!
//! A transport built before the fault byte was named (a carrier such as tcp, whose pieces carry
//! no status at all) wrote that byte as alignment padding, always `0`, and its tail stops short of
//! the appended fault table, which the host then reads as absent. Both read as "no reading": the
//! byte is `FAULT_NONE`, and `FAULT_NONE` is no `WireFault`, which the breaker reads as the
//! caller's (it records nothing). Every stated reading round-trips; a byte no reading names is
//! none, never a guess.

use busbar_contract::abi::transport::{
    FramePiece, FAULT_CALLER, FAULT_HARD, FAULT_NONE, FAULT_TRANSIENT,
};
use busbar_contract::transport::wire::WireFault;

#[test]
fn an_unstated_fault_byte_reads_as_no_reading() {
    // The byte a transport that predates the reading writes: the zeroed padding.
    // SAFETY: `FramePiece` is plain C data; all-zero is a valid value of it.
    let piece: FramePiece = unsafe { std::mem::zeroed() };
    assert_eq!(piece.fault, FAULT_NONE);
    assert_eq!(WireFault::from_code(piece.fault), None);
}

#[test]
fn every_stated_reading_round_trips_and_an_unknown_byte_is_none() {
    assert_eq!(WireFault::from_code(FAULT_CALLER), Some(WireFault::Caller));
    assert_eq!(
        WireFault::from_code(FAULT_TRANSIENT),
        Some(WireFault::Transient)
    );
    assert_eq!(WireFault::from_code(FAULT_HARD), Some(WireFault::Hard));
    assert_eq!(WireFault::from_code(FAULT_HARD + 1), None);
    assert_eq!(WireFault::from_code(u8::MAX), None);
}
