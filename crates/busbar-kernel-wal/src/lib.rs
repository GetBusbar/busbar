// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-wal — the journal codec
//!
//! The fixed journal record, the hash chain over it, the length-prefixed body fields, and the
//! quarantine note a written journal can carry. The store journal seals and verifies with these.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod journal;
pub mod note;
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
