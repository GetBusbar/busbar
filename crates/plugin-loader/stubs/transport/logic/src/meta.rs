// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself, as the kind's own file (`BUSBAR-1.6.0.md` THE

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::KindTailHead;
use busbar_contract::abi::transport::{
    TransportTail, FRAME_PIECE_SIZE, FRAMING_STREAM, ROLE_CARRIER,
};

/// The claim this entry answers for.
pub const KEY: &str = "tcp";

/// The absent string: a slot this transport states nothing in.
pub(crate) const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The transport kind's tail: the CARRIER of the host's byte stream (its role stated, busbar

pub(crate) const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_CARRIER,
    framing: FRAMING_STREAM,
    facts: 0,
    handshake_max_steps: 0,
    frame_piece_size: FRAME_PIECE_SIZE,
    _reserved: 0,
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: crate::claims::CLAIMS.as_ptr(),
    claim_rows_len: crate::claims::CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: std::ptr::null(),
    status_rows_len: 0,
    settings: std::ptr::null(),
    settings_len: 0,
    fault_rows: std::ptr::null(),
    fault_rows_len: 0,
};
