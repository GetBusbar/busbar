// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-wal — the write-ahead log unit

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod backend;
pub mod journal;
pub mod record;
pub mod recover;
pub mod segment;
pub mod ship;
pub mod wal;

pub use backend::{
    DirectoryFactory, FileSegment, MemoryFactory, MemorySegment, QuarantinedBytes, SegmentBackend,
    SegmentFactory, SharedBytes,
};
pub use journal::{
    body_digest, decode_run, tail_of, verify as verify_journal, verify_bridged, BodyReader,
    BodyWriter, Entry, Journal, JournalAck, JournalBreak, JournalBreakKind, JournalRecord,
    Overflow, RecordClass, JOURNAL_HEADER_BYTES, JOURNAL_MAGIC, JOURNAL_VERSION,
    MEMORY_BUFFER_RECORDS,
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
pub use wal::{BatchAck, Clock, Mode, OpenError, Wal};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
