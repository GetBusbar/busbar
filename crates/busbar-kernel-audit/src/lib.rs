// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-audit — the audit unit

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
mod wiped;

pub use amend::{
    content_access, Access, Adjust, AmendBody, AmendChain, AmendClass, AmendJournal, AmendSink,
    Amendment, ClassCounts, NodeAmendments, Reader, AMENDMENTS_RETAINED,
};
pub use heads::{HeadHistory, SignedHead, HEAD_SAMPLE_SECONDS};
pub use journal::{from_journal_body, journal_body, FieldTooLong, JOURNAL_TAG};
pub use recipe::{
    digest_fields, digest_over, DigestField, DigestValue, Recipe, DIGEST_RECIPE, DIGEST_RECIPE_V2,
    DIGEST_RECIPE_V4,
};
pub use record::{
    Audit, AuditBreak, AuditBreakKind, AuditChain, AuditInputs, AuditRecord, Controls, FinishClass,
    HookApplied, HookHead, OpClassId, OutcomeFacts, QuantitySource, Subject, Usage, UsageLine,
    What,
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
    pub fn observe(history: &mut HeadHistory, record: &AuditRecord) {
        history.observe(record);
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
