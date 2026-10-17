// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-audit — the audit unit
//!
//! The audit unit holds the fixed audit record every plane contributes to, the amendments that
//! follow it, and the signature over each record's digest — a digest that names the node that
//! sealed the record.
//!
//! ## The fixed audit record
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
//! file is one the operator fully controls; the signature is what says the deployment's key vouched
//! for the record at seal time, and the digest it covers names the node that sealed it
//! ([`record::AuditRecord::node`]). It is not retrofittable — a signature a receiver applies later proves that the receiver got those
//! bytes — so every record sealed before signing existed stays unprovable, whatever ships after.
//!
//! [`recipe`] publishes the exact field order that digest is taken over, and [`expose`] renders the
//! three reads an outside verifier pulls: the head, a range of records carrying every field their
//! digests ate, and the public keys. The node ANSWERS; it never phones home, holds no credential
//! and opens no outbound connection for any of this. Anchoring is somebody else's product, because
//! a node cannot anchor to itself.
//!
//! [`heads`] keeps the anchors — the heads a puller ties a window to — rebuilt from the sealed
//! records at every boot, so a restart loses none of them.
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
pub mod digest;
pub mod expose;
pub mod heads;
pub mod journal;
pub mod recipe;
pub mod record;
pub mod sign;

pub use amend::{
    content_access, correction, Access, Adjust, AmendBody, AmendChain, AmendClass, AmendJournal,
    Amendment, ClassCounts, CorrectionError, CorrectionRefused, CountCorrection, Reader,
    AMENDMENTS_RETAINED,
};
pub use heads::{HeadHistory, SignedHead, HEAD_SAMPLE_SECONDS};
pub use journal::{from_journal_body, journal_body, JOURNAL_TAG};
pub use recipe::{
    digest_fields, digest_over, DigestField, DigestValue, Recipe, DIGEST_RECIPE, DIGEST_RECIPE_V2,
};
pub use record::{
    Audit, AuditBreak, AuditBreakKind, AuditChain, AuditInputs, AuditRecord, Controls, FinishClass,
    HookApplied, OpClassId, OutcomeFacts, QuantitySource, Subject, Usage, UsageLine, What,
};
pub use sign::{
    checkpoint_preimage, AuditKeySet, AuditSigningKey, AuditVerifyingKey, KeyError,
    CHECKPOINT_SIGNATURE_DOMAIN, SIGNATURE_ALGORITHM, SIGNATURE_DOMAIN,
};

/// TEST ONLY: the minimum the kernel's own tests reach that is not public API. They live in the
/// kernel because they mint the tokens sealing takes; the items they drive stay `pub(crate)` here.
/// Compiled only under the `test-support` feature, which only the kernel's dev-dependency turns on;
/// never in a shipped build.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    use crate::{AuditRecord, HeadHistory};

    /// Take the head as it stands after one sealed record: delegates to the crate-private
    /// `HeadHistory::observe`, so a test can drive a history without sealing a record per step.
    pub fn observe(history: &mut HeadHistory, record: &AuditRecord) {
        history.observe(record);
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
