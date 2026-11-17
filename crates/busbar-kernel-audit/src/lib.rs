// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! # busbar-kernel-audit — the audit unit

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]
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
pub mod link;
// The notary key certificate line (certificate v2): linked by the Bootstrap signer, decoded for
// the range read and checked by verify.
pub mod notary_key;
// The page stamps and break notices (SEALING-FIX §3.1): built and signed by the notary and the
// Bootstrap signer threads, never per request.
pub mod restart;
pub mod stamp;
pub use restart::{span_ms, walk_tail, BackwardWalk, BreakAt, TailItem, WalkContext, WalkOutcome};
// The audit signing capabilities (SEALING-FIX §5.3): consumed once at boot, used on the signer
// threads only.
pub mod grant;
/// Common chain decoding and integrity checks, including certificate rows.
pub mod linked_record;
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
pub use grant::{
    BootstrapGrant, BootstrapSigner, GrantError, LiveSigner, Notary, NotaryGrant, StampSignError,
};
pub use heads::{HeadHistory, SignedHead, HEAD_SAMPLE_SECONDS};
pub use journal::{from_journal_body, journal_body, FieldTooLong, JOURNAL_TAG};
pub use link::{line_fingerprint, line_hasher, Fingerprint, LineAt, Linked, Prepared};
pub use notary_key::{
    notary_key_from_journal_body, NotaryKeyCertificate, NotaryKeyRecord, NOTARY_KEY_DOMAIN,
    NOTARY_KEY_JOURNAL_TAG, NOTARY_KEY_RECORD_DOMAIN,
};
pub use recipe::{
    digest_over, digest_record, visit_fields, DigestField, DigestValue, FieldSink, Recipe,
    DIGEST_RECIPE, DIGEST_RECIPE_V2, DIGEST_RECIPE_V4, DIGEST_RECIPE_V6, DIGEST_RECIPE_V7,
    LINK_RECIPE,
};
pub use record::{
    attribution, Attempt, AttemptOutcome, Audit, AuditBreak, AuditBreakKind, AuditChain,
    AuditInputs, AuditRecord, Controls, FinishClass, HookApplied, HookHead, OpClassId,
    OutcomeFacts, QuantitySource, RecordFacts, Subject, UnitFacts, UnitId, Usage, UsageLine, What,
    ATTEMPT_SLOTS, ATTRIBUTION_SEP, LABEL_SLOTS,
};
pub use sign::{
    checkpoint_preimage, AuditKeySet, AuditSigningKey, AuditVerifyingKey, KeyError,
    CHECKPOINT_SIGNATURE_DOMAIN, SIGNATURE_ALGORITHM, SIGNATURE_DOMAIN,
};
pub use stamp::{
    break_body, break_from_journal_body, stamp_body, stamp_from_journal_body, BreakNotice,
    BreakReason, CoverError, Stamp, StampError, StampKind, BREAK_DOMAIN, BREAK_JOURNAL_TAG,
    STAMP_DOMAIN, STAMP_JOURNAL_TAG,
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
