// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// busbar:request-path
#![cfg_attr(
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
pub use record::{
    decode_frame, FrameError, FrameHeader, Record, FRAME_BYTES, FRAME_END_MARK, FRAME_HEADER_BYTES,
    FRAME_MAGIC, FRAME_PAYLOAD_BYTES, FRAME_TRAILER_BYTES, FRAME_VERSION,
};
pub use recover::{
    quarantine_in_place, recover_and_truncate, scan, Bridge, Hole, Quarantine, QuarantineKept,
    QuarantineNote, Recovered, TailVerdict, QUARANTINE_BODY_TAG,
};
pub use segment::{Segment, SegmentError, GROWTH_STEP_BYTES, SEGMENT_BYTES};
pub use ship::{NullShipper, ShipError, Shipper};
pub use wal::{BatchAck, Clock, Forgotten, Mode, OpenError, Wal};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
