// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! # busbar-kernel-wal — the journal codec
//!
//! The fixed journal record, the hash chain over it, the length-prefixed body fields, and the
//! quarantine note a written journal can carry. The store journal seals and verifies with these.

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
pub mod journal;
// Reading a journal back (decode, the holes a chain may cross): recovery and verification, never
// per request, so outside the request-path marker.
mod off_path;
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
pub mod note;
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

pub use journal::{
    body_digest, decode_run, verify as verify_journal, BodyReader, BodyWriter, Entry, JournalBreak,
    JournalBreakKind, JournalRecord, RecordClass, JOURNAL_HEADER_BYTES,
};
pub use note::{Bridge, QuarantineNote, QUARANTINE_BODY_TAG};
pub use record::Record;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
