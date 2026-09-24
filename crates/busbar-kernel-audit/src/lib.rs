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
//! been in, one further field carrying provenance that is skipped on the wire, a genesis previous
//! hash that is the empty string, a ring of a thousand entries, and a restore that verifies before it
//! seeds. Thirty-three action names, listed as one array so that "the set did not change" is
//! something a test can say.
//!
//! It is kept because a digest that moved would not break a feature — it would make every chain in
//! every deployment fail to verify at the next boot, which is to say it would report the whole of
//! somebody's history as tampered. That is the one migration this crate may never do quietly, and
//! the golden vector in the tests is what stops it happening by accident.
//!
//! What DID change: the digest used to be, unconditionally, those seven fields joined by vertical
//! bars — forgeable by any caller who controls a byte inside one of them (an upstream MCP tool name
//! landing in `resource` is the real path in). [`legacy::AuditEntry::scheme`] is a per-record tag
//! that says which framing an entry was actually sealed under: absent (every entry already on disk)
//! reads as the vertical-bar join those entries always used, and every entry sealed FRESH now takes
//! a length-prefixed framing that makes a field boundary unforgeable by anything a field contains. A
//! chain mixing both eras verifies end to end, each record checked under its own tag.
//!
//! ## The new fixed audit record, beside it
//!
//! [`record`] holds it: one shape, for every caller, with no exceptions. A caller contributes
//! exactly two identifiers — what kind of operation this was and how it finished — and everything
//! else is the same whichever door the request came in through. An audit whose shape varies by the
//! door it came in through is an audit nobody can compare two rows of.
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
//! ## And the signature, which is the half that cannot be added later
//!
//! [`sign`] mints an ed25519 signature over each record's digest, in the process that sealed it, at
//! the moment it sealed it. A chain of digests proves only that a file agrees with itself, and the
//! file is one the operator fully controls; the signature is what says a NODE produced it. It is
//! not retrofittable — a signature a receiver applies later proves that the receiver got those
//! bytes — so every record sealed before signing existed stays unprovable, whatever ships after.
//!
//! [`recipe`] publishes the exact field order that digest is taken over, and [`expose`] renders the
//! three reads an outside verifier pulls: the head, a range of records carrying every field their
//! digests ate, and the public keys. The node ANSWERS; it never phones home, holds no credential
//! and opens no outbound connection for any of this. Anchoring is somebody else's product, because
//! a node cannot anchor to itself.
//!
//! [`heads`] keeps the anchors, forever, independently of how long records are kept — a puller that
//! was offline while a window's records were pruned lost the records, which was the deal, and must
//! not also lose the window's anchor.
//!
//! ## What a token buys here
//!
//! Sealing a record, or appending an amendment, takes the audit step's token. A caller can say what
//! it saw and a hook can say what it did; turning either into something on a chain is the audit
//! unit's act. Evidence anybody could add is evidence nobody can rely on.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod amend;
pub mod expose;
pub mod heads;
pub mod legacy;
pub mod recipe;
pub mod record;
pub mod sign;

pub use amend::{
    amends, content_access, correction, Access, Adjust, AmendBody, AmendChain, AmendClass,
    Amendment, Reader,
};
pub use heads::{HeadHistory, SignedHead, HEAD_SAMPLE_SECONDS};
pub use legacy::{
    AuditEntry, AuditInput, AuditLog, Chain, ChainBreak, ChainBreakKind, ChainedRecord, Clock,
    DurableSeam, NoSeam, PositionsExhausted, ADMIN_LOG, AUDIT_ACTIONS,
    AUDIT_SCHEME_LENGTH_PREFIXED, AUDIT_SCHEME_PIPE, MAX_AUDIT_ENTRIES, OUTCOME_APPLIED,
    OUTCOME_DEGRADED, OUTCOME_REJECTED,
};
pub use recipe::{digest_fields, digest_over, DigestField, DigestValue, DIGEST_RECIPE};
pub use record::{
    Audit, AuditBreak, AuditBreakKind, AuditChain, AuditInputs, AuditRecord, Controls, FinishClass,
    HookApplied, OpClassId, OutcomeFacts, QuantitySource, Subject, Usage, UsageLine, What,
};
pub use sign::{
    AuditKeySet, AuditSigningKey, AuditVerifyingKey, KeyError, SIGNATURE_ALGORITHM,
    SIGNATURE_DOMAIN,
};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
