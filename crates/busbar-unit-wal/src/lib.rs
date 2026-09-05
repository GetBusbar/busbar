// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-wal — the write-ahead log unit
//!
//! A unit waits on this crate twice: once before it dials, and once before it ends. Everything here
//! exists to make those two waits mean something, and to make the failure of one of them impossible
//! to ignore.
//!
//! ## The four rules
//!
//! **Records are fixed-size frames.** Every frame is 512 bytes on the medium, header and payload
//! together. A body longer than one frame's payload area continues into further frames carrying the
//! same writer identity and an increasing part index. Nothing about finding the next frame depends
//! on a length field a reader might have read out of a half-written region.
//!
//! **A torn tail is cut at recovery to the last record that verifies.** Whole records, not whole
//! frames: a record whose last part was lost is absent, not short. The battery for this truncates a
//! written segment at every single byte offset, recovers, and asserts the result is the longest
//! complete prefix — there is no interesting subset of the offsets a crash can stop at, so none is
//! chosen.
//!
//! **A group commit is one write and one sync.** Records are framed into one buffer and put down
//! with a single positional write, then made durable with a single data sync. Whatever the batch
//! size, the wait is one sync.
//!
//! **A failed sync poisons the segment.** Permanently. Every byte after the last good commit is of
//! unknown state, and the only safe reading of unknown is absent. The caller is handed a
//! [`busbar_caps::DurabilityLost`] — which only a holder of the durability token can mint, so the
//! claim "a durable write was lost" is not something any other part of the system can invent — and
//! the batch that failed is written again, along with the one after it, on a fresh segment.
//!
//! ## The default is no disk at all
//!
//! [`Wal::memory_buffered`] is the default, and it is what a deployment that names no data directory
//! gets. There is no directory probe, no file, no preallocation and no boot warning. It is not a
//! degraded mode with the file writing switched off; a memory-buffered log holds no directory
//! factory, so there is no code path from it to a file system. The battery for this runs a whole
//! append-and-recover cycle with a temporary directory in view and asserts the directory is still
//! empty afterwards.
//!
//! In that mode the store is where durability comes from, so shipping is part of committing: a
//! batch the store refuses is a durability loss and is reported as one. With a data directory the
//! local log is the record, so a shipping failure is catch-up work and does not fail the commit.
//! Two postures, one code path, both said out loud.
//!
//! ## On unsafe code
//!
//! This crate is `#![forbid(unsafe_code)]`, which was not a foregone conclusion for an I/O crate.
//! The positional write is `std::os::unix::fs::FileExt::write_all_at` and the sync is
//! `std::fs::File::sync_data`, both safe; there is no memory-mapped writeback to justify, so no
//! reviewed allow-list is needed here and the stronger of the two lints applies.
//!
//! ## Where the money types come in
//!
//! Only one place, deliberately. The log does not know what a hold is, what a posting is, or what a
//! journal entry means; its records are opaque bytes with a writer's identity on them. The single
//! capability it participates in is the durability loss, and it participates in that because it is
//! the only part of the system entitled to observe one.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod backend;
pub mod record;
pub mod recover;
pub mod segment;
pub mod ship;
pub mod wal;

pub use backend::{
    DirectoryFactory, FileSegment, MemoryFactory, MemorySegment, SegmentBackend, SegmentFactory,
    SharedBytes,
};
pub use record::{
    decode_frame, FrameError, FrameHeader, Record, FRAME_BYTES, FRAME_HEADER_BYTES, FRAME_MAGIC,
    FRAME_PAYLOAD_BYTES, FRAME_VERSION,
};
pub use recover::{recover_and_truncate, scan, Recovered};
pub use segment::{Segment, SegmentError, GROWTH_STEP_BYTES, SEGMENT_BYTES};
pub use ship::{BufferShipper, NullShipper, ShipError, Shipper};
pub use wal::{BatchAck, Mode, OpenError, Wal};

/// The largest record the log will carry, header and payload together — the contract's own cap on a
/// journal record. A body larger than one frame's payload area is continued into further frames, so
/// this is a frame size rather than a limit on what a caller may write.
pub const MAX_RECORD_BYTES: usize = FRAME_BYTES;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
