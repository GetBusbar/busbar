// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane vocabulary core keeps: refusal, route, audit, record, claim and cancel numbers and their pure readers.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::plane::check::{
    check_tail, entry_fact, entry_path_matches, raw_affix_matches, Bounds, EntryPredicate,
};
pub use crate::abi::plane::{
    cancel_bills_reported_units, class_of, slot, CollectionMode, RecordCollection, RefusalClass,
    RefusalCode, AUDIT_APPLIED, AUDIT_DEGRADED, AUDIT_REJECTED, CANCEL_ABORTED, CANCEL_FAILED,
    CANCEL_OK_PARTIAL, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, CHAIN_PIPE_SEPARATED,
    CLAIM_CATALOG, CLAIM_ENTRY, CLAIM_EXACT, CLAIM_OPEN, CLAIM_PATTERN, CLAIM_RAW_AFFIX,
    CLAIM_SIGNED_INGRESS, CLAIM_TICKET, DIALECT_PROVIDER, EMIT_DONE, EMIT_FINAL_STATUS,
    EMIT_MESSAGE_END, EMIT_TO_FAR_END, PIECE_CUT, PIECE_FIELDS, PIECE_FINAL, PIECE_HAS_STATUS,
    PIECE_LAST, PIECE_OUT_TEXT, PIECE_REFUSED, RECORD_AUDIT, RECORD_PUT, TAIL_FALLBACK,
    TAIL_PROBES, TAIL_REFUSED_PIECE, VERDICT_COUNT_REFUSED,
};
