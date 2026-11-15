// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! # busbar-kernel-audit — the audit unit

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod amend;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod digest;
// The cold module (LINT-RULES LR-167): rare text and framing the request-path modules beside it call
// out of line.
pub(crate) mod cold;
// The admin reads (head, range, key set): answered on an operator verb, never per request, so
// outside the request-path marker.
pub mod expose;
// The request-path modules' code that runs off the request path: once per configuration, restore or
// process lifecycle, never per request.
pub(crate) mod off_path;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod heads;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod journal;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod recipe;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod record;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod sign;

pub use amend::{
    content_access, Access, Adjust, AmendBody, AmendChain, AmendClass, AmendJournal, AmendSink,
    Amendment, ClassCounts, NodeAmendments, Reader, SubjectText, AMENDMENTS_RETAINED,
};
pub use heads::{HeadHistory, SignedHead, HEAD_SAMPLE_SECONDS};
pub use journal::{from_journal_body, journal_body, FieldTooLong, JOURNAL_TAG};
pub use recipe::{
    digest_over, digest_record, visit_fields, DigestField, DigestValue, FieldSink, Recipe,
    DIGEST_RECIPE, DIGEST_RECIPE_V2, DIGEST_RECIPE_V4, DIGEST_RECIPE_V6, DIGEST_RECIPE_V7,
};
pub use record::{
    attribution, Attempt, AttemptOutcome, Audit, AuditBreak, AuditBreakKind, AuditChain,
    AuditInputs, AuditRecord, Controls, FinishClass, HookApplied, HookHead, OpClassId,
    OutcomeFacts, QuantitySource, Subject, UnitFacts, UnitId, Usage, UsageLine, What,
    ATTEMPT_SLOTS, ATTRIBUTION_SEP,
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
