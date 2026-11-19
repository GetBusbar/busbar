// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed fault, status and limit numbers core uses for a far end and a connection.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::transport::status::MAX_NAMESPACE_BYTES;
pub use crate::abi::transport::{
    fields, slot, FACT_ACCEPTS, FAULT_HARD, FAULT_NONE, FAULT_RATE_LIMIT, FAULT_TRANSIENT,
    FRAMING_DATAGRAM, MAX_ADDR, PIECE_CODE_HANDOFF, PIECE_CONTINUED, PIECE_END, PIECE_END_OF_FRAME,
    PIECE_FIELDS, PIECE_HAS_CODE, PIECE_HAS_DECLARED_LEN, PIECE_HAS_RETRY_AFTER, PIECE_INTERIM,
    PIECE_STREAM_FAILED, PIECE_TEXT, PIECE_WRITABLE, READ_END_OF_FRAME, ROLE_CARRIER, ROLE_FRAMER,
    SIDE_DIAL, STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
    YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
};
