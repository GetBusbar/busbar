// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-audit — the audit unit
//!
//! Two streams of evidence live here, and the most important thing about them is that they do not
//! merge.
//!
//! ## The previous release's admin mutation chain, kept
//!
//! [`legacy`] holds it, moved rather than rewritten. Eight wire fields in the order they have always
//! been in, one further field carrying provenance that is skipped on the wire, a digest that is the
//! hexadecimal SHA-256 of the previous hash, sequence, timestamp, action, resource, outcome and
//! principal joined by vertical bars, a genesis previous hash that is the empty string, a ring of a
//! thousand entries, and a restore that verifies before it seeds. Thirty-three action names, listed
//! as one array so that "the set did not change" is something a test can say.
//!
//! It is kept because a digest that moved would not break a feature — it would make every chain in
//! every deployment fail to verify at the next boot, which is to say it would report the whole of
//! somebody's history as tampered. That is the one migration this crate may never do quietly, and
//! the golden vector in the tests is what stops it happening by accident.
//!
//! ## The new fixed audit record, beside it
//!
//! [`record`] holds it: one shape, for every plane, with no exceptions. A plane contributes exactly
//! two identifiers — what kind of operation this was and how it finished — and everything else is
//! the same whichever door the request came in through. An audit whose shape varies by protocol is
//! an audit nobody can compare two rows of.
//!
//! ## And the amendments
//!
//! [`amend`] holds the two classes of thing that happen after the fact: an ACCESS, written every
//! time a hook or an export plugin reads content, and an ADJUSTMENT, written every time a figure
//! that was already recorded changes. Both are new entries rather than edits, because a journal that
//! can be edited is not evidence.
//!
//! ## What never goes in
//!
//! Content. Not the request, not the response, not a fragment of either. The correlation label is
//! hashed on the way in and the label itself is dropped; there is no path through [`record`] that
//! keeps it. The reason is not squeamishness — the journal is a financial record exempt from
//! erasure, so anything written into it can never be taken out again, and a prompt in a record that
//! cannot be deleted is a promise nobody can keep.
//!
//! ## What a token buys here
//!
//! Sealing a record, or appending an amendment, takes the audit step's token. A plane can say what
//! it saw and a hook can say what it did; turning either into something on a chain is the audit
//! unit's act. Evidence anybody could add is evidence nobody can rely on.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod amend;
pub mod legacy;
pub mod record;

pub use amend::{
    amends, content_access, correction, Access, Adjust, AmendBody, AmendChain, AmendClass,
    Amendment, Reader,
};
pub use legacy::{
    AuditEntry, AuditInput, AuditLog, Chain, ChainBreak, ChainBreakKind, ChainedRecord, Clock,
    DurableSeam, NoSeam, SystemClock, ADMIN_LOG, AUDIT_ACTIONS, MAX_AUDIT_ENTRIES, OUTCOME_APPLIED,
    OUTCOME_DEGRADED, OUTCOME_REJECTED,
};
pub use record::{
    Amount, Audit, AuditBreak, AuditBreakKind, AuditChain, AuditInputs, AuditRecord, Controls,
    FinishClass, HookApplied, OpClassId, OutcomeFacts, QuantitySource, Subject, UsageLine, What,
};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
