// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Watchdog words: the per-thread busy word table and its scanner (IF §10.6). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H1 fills it.

/// Reserved entry indices for non-method entries (method bits are 0..=55).
pub const ENTRY_DESCRIBE: u8 = 56;
pub const ENTRY_OPEN: u8 = 57;
pub const ENTRY_RESUME: u8 = 58;
pub const ENTRY_CANCEL: u8 = 59;
pub const ENTRY_CLOSE: u8 = 60; /* round 31: 61 (ENTRY_MIGRATE) retired */

/// One `AtomicU64` per registered thread, Relaxed stores, no clock read (I5):
/// bits 0..=23 slot, bits 24..=31 entry index, bits 32..=63 the word's entry sequence (never 0 while busy).
/// 0 = idle. One word, so the scanner can never read a torn (slot, entry) pair.
/// Round 12: the word table (registration rule below). Allocated once by `init`, never grown or shrunk.
/// **Round 17 (I5, false sharing): each word owns its cache-line pair**, the same padding as `FreeHead` (§6.5):
/// a worker's two Relaxed stores per crossing never take a line another thread writes. `WATCH_CAP` drops to
/// 1,024 for that memory (1,024 × 128 B = 128 KiB), still 2x tokio's 512-thread blocking-pool maximum plus workers.
#[repr(C, align(128))]
pub struct WatchWord(pub core::sync::atomic::AtomicU64);
pub const WATCH_CAP: u32 = 1_024;

/// Called once by `Registry::new` before any entry (a second call is a no-op). Allocates `WATCH_CAP`
/// `WatchWord`s (128 KiB, one per 128-byte line pair), then, in a separate allocation the writers never store to
/// on the hot path, `WATCH_CAP` `last_seq` u32s and `WATCH_CAP / 64` occupancy bitmap words, all zeroed
/// (~132 KiB total). The bitmap and `last_seq` are touched only by claim/release (cold) and the scanner (reads).
pub fn init() {
    todo!()
}
/// Registers the calling thread on its first entry (cold, below), then two Relaxed stores.
pub fn enter(slot: u32, entry: u8) {
    let _ = (slot, entry);
    todo!()
}
pub fn leave() {
    todo!()
}
/// Live registrations (popcount of the occupancy bitmap). For C-WATCH-CHURN and `plugin_watch_threads`.
pub fn live() -> u32 {
    todo!()
}
/// For the loader's watchdog thread (scan every 100 ms; the only code here that reads a clock). It keeps,
/// per thread, the last word seen, the scan tick at which it first saw it and (round 14) the slot epoch it read
/// right after first seeing it (`ceiling(slot, entry).1`, one Acquire load). A word unchanged for
/// `ticks * 100 ms >= ceiling(slot, entry).0` is reported once as `(slot, epoch, entry, busy_ms)`. Ceilings are
/// therefore enforced to +100 ms.
/// **Round 14: the ceiling and the quarantine target come from the slot, not from an Instance.** `ceiling` is the
/// registry's `SlotTable::watch_view` (§11.2): `ceilings_us[entry]` (Relaxed) and `epoch` (Acquire) of the slot's
/// `SlotCell`, the row the registry wrote when it allocated the slot, so every entry kind (describe, migrate, open,
/// their resumes and cancels, kind methods, close) has its real ceiling, store-lane rows included (a store-sqlite
/// first `migrate` gets its declared 3,600 s, never the 5 s default). `report` is `SlotTable::hung` (§11.2), which
/// quarantines exactly the owner of that slot epoch. Both are plain fn pointers: `scan` reads no Instance.
/// Why the epoch is the owner's: the word is unchanged from first sight to report, so that one entry ran the whole
/// time, so its lease was held the whole time (a lease is released only after the last entry under it returns,
/// I10 (d)); the epoch read between those two loads is therefore the owner's (the epoch is bumped with Release
/// only when the slot is re-allocated, after the previous lease's last `leave`).
pub fn scan(
    ceiling: impl Fn(u32 /*slot*/, u8 /*entry*/) -> (u32 /*ceiling µs*/, u32 /*epoch*/),
    report: impl FnMut(u32 /*slot*/, u32 /*epoch*/, u8 /*entry*/, u64 /*busy_ms*/),
) {
    let _ = (ceiling, report);
    todo!()
}
/// The slot of the entry running on this thread (log attribution, §5), or None outside an entry. Round 24: reads
/// `entry.rs`'s `OWNER` cell (§10.7), never the watch claim or word, so it is Some in every entry, watched or not
/// ("Full table" below), and in a nested entry it names the nested entry's owner.
pub fn current_slot() -> Option<u32> {
    todo!()
}
