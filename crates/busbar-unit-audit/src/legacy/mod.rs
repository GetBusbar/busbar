// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The previous release's admin mutation chain, kept and appended.
//!
//! Nothing in here is new work. It is the same mechanism, the same record, the same digest, the same
//! ring size and the same restore, moved into the unit that owns auditing so that there is one place
//! to look. The new fixed audit record lives beside it, in [`crate::record`], and the two never
//! merge: a digest that moved would report every deployed chain's history as tampered at its next
//! boot.

pub mod chain;
pub mod entry;

pub use chain::{
    digest, seal, sha256_hex, verify_chain, verify_window, Chain, ChainBreak, ChainBreakKind,
    ChainLabels, ChainedRecord, Digest, Framing,
};
pub use entry::{
    AuditEntry, AuditInput, AuditLog, Clock, DurableSeam, NoSeam, SystemClock, ADMIN_LOG,
    AUDIT_ACTIONS, MAX_AUDIT_ENTRIES, OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED,
};
