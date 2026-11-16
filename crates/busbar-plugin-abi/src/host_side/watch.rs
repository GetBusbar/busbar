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

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests that claim words run one at a time, so no other test thread takes a word they just freed.
    static SERIAL: Mutex<()> = Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// This thread's word, as the scanner reads it.
    fn my_word() -> u64 {
        let idx = CLAIM.with(|c| c.idx.get());
        table()
            .words
            .get(idx as usize)
            .map_or(0, |w| w.0.load(Ordering::Relaxed))
    }

    #[test]
    fn a_word_owns_its_line_pair() {
        assert_eq!(core::mem::align_of::<WatchWord>(), 128);
        assert_eq!(core::mem::size_of::<WatchWord>(), 128);
        init();
        init();
        assert_eq!(table().words.len(), WATCH_CAP as usize);
        assert_eq!(table().bitmap.len(), WATCH_CAP as usize / 64);
    }

    #[test]
    fn enter_writes_slot_entry_and_a_fresh_sequence_and_leave_idles() {
        let _serial = serial();
        init();
        std::thread::spawn(|| {
            enter(0x12_3456, ENTRY_OPEN);
            let word = my_word();
            assert_eq!(word & 0xFF_FFFF, 0x12_3456);
            assert_eq!((word >> 24) & 0xFF, u64::from(ENTRY_OPEN));
            let seq = word >> 32;
            assert_ne!(seq, 0);
            leave();
            assert_eq!(my_word(), 0);
            enter(1, 3);
            assert_eq!(
                my_word() >> 32,
                seq + 1,
                "every entry takes the next sequence"
            );
            leave();
        })
        .join()
        .expect("thread");
    }

    #[test]
    fn a_nested_entry_restores_the_enclosing_word() {
        let _serial = serial();
        init();
        std::thread::spawn(|| {
            enter(7, ENTRY_RESUME);
            let outer = my_word();
            enter(9, ENTRY_CANCEL);
            assert_eq!(my_word() & 0xFF_FFFF, 9);
            leave();
            assert_eq!(my_word(), outer, "the outer entry's word, unchanged");
            leave();
            assert_eq!(my_word(), 0);
        })
        .join()
        .expect("thread");
    }

    #[test]
    fn a_thread_exit_releases_its_word_and_keeps_the_sequence_with_the_index() {
        let _serial = serial();
        init();
        let (idx, seq) = std::thread::spawn(|| {
            enter(1, 1);
            leave();
            CLAIM.with(|c| (c.idx.get(), c.seq.get()))
        })
        .join()
        .expect("thread");
        assert_ne!(idx, u32::MAX);
        let i = idx as usize;
        let bit = table().bitmap[i / 64].load(Ordering::Acquire) & (1 << (i % 64));
        assert_eq!(bit, 0, "the claim bit is cleared at thread exit");
        assert_eq!(table().last_seq[i].load(Ordering::Relaxed), seq);
        assert_eq!(table().words[i].0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn current_slot_is_the_entry_owner() {
        assert_eq!(current_slot(), None);
        crate::host_side::entry::within(5, || assert_eq!(current_slot(), Some(5)));
        assert_eq!(current_slot(), None);
    }

    /// The scanner reports a word unchanged past its ceiling once, with the epoch it read at first sight;
    /// a new word restarts the count; a ceiling of 0 is never reported. One test, so no other scan races it.
    #[test]
    fn the_scanner_reports_a_hung_entry_once_with_its_first_epoch() {
        let _serial = serial();
        init();
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let (entered, ready) = std::sync::mpsc::channel::<()>();
        const SLOT: u32 = 0xAB_CDEF;
        let hung = std::thread::spawn(move || {
            enter(SLOT, 4);
            entered.send(()).expect("send");
            wait.recv().expect("recv");
            leave();
        });
        ready.recv().expect("entered");
        let epoch = core::cell::Cell::new(1u32);
        let mut reports = Vec::new();
        let ceiling = |slot: u32, _entry: u8| {
            if slot == SLOT {
                (250_000, epoch.get())
            } else {
                (0, 0)
            }
        };
        for tick in 0..6 {
            if tick == 1 {
                epoch.set(2); // a later epoch must not be blamed
            }
            scan(ceiling, |slot, epoch, entry, busy| {
                if slot == SLOT {
                    reports.push((epoch, entry, busy));
                }
            });
        }
        go.send(()).expect("release");
        hung.join().expect("thread");
        assert_eq!(
            reports,
            [(1, 4, 300)],
            "once, at the first tick past 250 ms, with the first epoch"
        );
    }
}
