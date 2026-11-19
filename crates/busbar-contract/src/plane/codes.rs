// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane vocabulary core keeps: refusal, route, audit, record, claim and cancel numbers and their pure readers.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::plane::check::{
    check_authenticated_route, check_billable_classes, check_claim_target, check_dialect_auth,
    check_pin_mechanisms, check_record_chains, check_record_retentions, check_refusal_statuses,
    check_route_cost, check_sections, check_tail, check_trust_keys, entry_fact, entry_path_matches,
    raw_affix_matches, Bounds, EntryPredicate, MAX_TURNS,
};
pub use crate::abi::plane::{
    cancel_bills_reported_units, class_of, reason_code, slot, CollectionMode, FieldList,
    RecordCollection, RefusalClass, RefusalCode, AUDIT_APPLIED, AUDIT_DEGRADED, AUDIT_NONE,
    AUDIT_REJECTED, CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL, CHAIN_DIGESTS_SCOPE,
    CHAIN_LENGTH_PREFIXED, CHAIN_PIPE_SEPARATED, CLAIM_CATALOG, CLAIM_ENTRY, CLAIM_EXACT,
    CLAIM_OPEN, CLAIM_PATTERN, CLAIM_PROBE, CLAIM_RAW_AFFIX, CLAIM_SIGNED_INGRESS, CLAIM_TICKET,
    DIALECT_PROVIDER, EMIT_DONE, EMIT_FINAL_STATUS, EMIT_MESSAGE_END, EMIT_TO_FAR_END, EXT_OWNED,
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, MAX_ROUTE_ENTRY_BYTES, PIECE_CUT, PIECE_FIELDS,
    PIECE_FINAL, PIECE_HAS_STATUS, PIECE_LAST, PIECE_OUT_TEXT, PIECE_REFUSED, PRINCIPAL_REQUIRED,
    RECORD_AUDIT, RECORD_PUT, REFUSAL_ANY_DIALECT, REFUSAL_ARRIVE, REFUSAL_GATE, REFUSAL_KERNEL,
    REFUSED_AFTER_ADMISSION, REFUSED_UNSUPPORTED_ACTION, ROUTE_AUTHENTICATED,
    ROUTE_CARRIES_OWN_TOKEN, ROUTE_COUNTED, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_ONCE, ROUTE_POOL,
    ROUTE_PUBLIC, ROUTE_SCOPE, ROUTE_SCOPE_LOCAL, ROUTE_SCOPE_SEPARATOR, ROUTE_SESSION,
    ROUTE_STREAM, TAIL_FALLBACK, TAIL_PROBES, TAIL_REFUSED_PIECE, VERDICT_COUNT_REFUSED,
    VERDICT_RETRY,
};
