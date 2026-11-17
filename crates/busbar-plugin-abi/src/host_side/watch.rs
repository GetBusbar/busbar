// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Watchdog words: the per-thread busy word table and its scanner (IF §10.6; W1-H1).
//!
//! A thread claims one word on its first entry (one `compare_exchange` on the occupancy bitmap, the only RMW
//! here outside thread exit) and releases it from a host-side TLS destructor. Every later `enter`/`leave` is
//! one Relaxed store each, plus thread-local loads and stores. Nested entries (C-NESTED) keep the enclosing
//! entry's word in a thread-local stack and `leave` stores it back, so the scanner sees the outer entry's word
//! unchanged (its time keeps counting) once the nested one returns. The scanner counts ticks (one per `scan`
//! call, every 100 ms) instead of reading a clock, so it is deterministic under test.

use core::cell::Cell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

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
    let _ = table();
}

/// The table and the scanner's state, allocated once.
struct Table {
    words: Box<[WatchWord]>,
    /// The sequence each index's last owner reached (read by the next owner of that index).
    last_seq: Box<[AtomicU32]>,
    /// One bit per word: claimed.
    bitmap: Box<[AtomicU64]>,
    /// The scanner's per-index memory and tick count (the watchdog thread alone takes it).
    scan: Mutex<Scanner>,
    /// Entries that ran unwatched because no word was free (`plugin_watch_full_total`).
    full: AtomicU64,
}

#[derive(Clone, Copy, Default)]
struct Seen {
    word: u64,
    first_tick: u64,
    epoch: u32,
    reported: bool,
}

struct Scanner {
    tick: u64,
    seen: Box<[Seen]>,
}

static TABLE: OnceLock<Table> = OnceLock::new();

fn table() -> &'static Table {
    TABLE.get_or_init(|| {
        let cap = WATCH_CAP as usize;
        Table {
            words: (0..cap).map(|_| WatchWord(AtomicU64::new(0))).collect(),
            last_seq: (0..cap).map(|_| AtomicU32::new(0)).collect(),
            bitmap: (0..cap / 64).map(|_| AtomicU64::new(0)).collect(),
            scan: Mutex::new(Scanner {
                tick: 0,
                seen: vec![Seen::default(); cap].into_boxed_slice(),
            }),
            full: AtomicU64::new(0),
        }
    })
}

/// Nested entries whose enclosing word is kept (deeper ones restore idle; busbar-ffi's ACTIVE bound).
const NEST: usize = 16;

/// This thread's claim: its word index (`u32::MAX` = unclaimed) and its sequence. Dropped at thread exit.
struct Claim {
    idx: Cell<u32>,
    seq: Cell<u32>,
    /// The word this thread last stored (what a nested entry's `leave` restores).
    word: Cell<u64>,
    depth: Cell<usize>,
    saved: [Cell<u64>; NEST],
}

impl Drop for Claim {
    fn drop(&mut self) {
        let idx = self.idx.get();
        if idx == u32::MAX {
            return;
        }
        let Some(table) = TABLE.get() else {
            return;
        };
        let i = idx as usize;
        if let Some(word) = table.words.get(i) {
            word.0.store(0, Ordering::Relaxed);
        }
        if let Some(last) = table.last_seq.get(i) {
            last.store(self.seq.get(), Ordering::Relaxed);
        }
        if let Some(bits) = table.bitmap.get(i / 64) {
            bits.fetch_and(!(1u64 << (i % 64)), Ordering::Release);
        }
    }
}

std::thread_local! {
    static CLAIM: Claim = const {
        Claim {
            idx: Cell::new(u32::MAX),
            seq: Cell::new(0),
            word: Cell::new(0),
            depth: Cell::new(0),
            saved: [const { Cell::new(0) }; NEST],
        }
    };
}

/// Claims a free word for this thread: one successful `compare_exchange` on a zero bit, scanning from a
/// per-thread start (the claim's own address), a lost race retrying on the next zero bit. None: the table is
/// full (the entry runs unwatched and the next entry retries).
fn claim(table: &Table, claim: &Claim) -> Option<u32> {
    let words = table.bitmap.len();
    if words == 0 {
        return None;
    }
    let hint = (core::ptr::from_ref(claim).addr() / 64) % words;
    for k in 0..words {
        let w = (hint + k) % words;
        let bits = table.bitmap.get(w)?;
        let mut cur = bits.load(Ordering::Relaxed);
        while cur != u64::MAX {
            let bit = (!cur).trailing_zeros();
            match bits.compare_exchange(cur, cur | (1 << bit), Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => {
                    let idx = u32::try_from(w * 64).ok()? + bit;
                    let last = table.last_seq.get(idx as usize)?.load(Ordering::Relaxed);
                    claim.seq.set(last);
                    claim.idx.set(idx);
                    return Some(idx);
                }
                Err(now) => cur = now,
            }
        }
    }
    table.full.fetch_add(1, Ordering::Relaxed);
    None
}

/// A native entry's exact enclosing watch state. Cancellation has no output frame and can nest
/// beyond the fixed output depth, so restoration cannot rely on the legacy `saved` array.
pub(crate) struct Entry {
    saved: Option<(u64, usize)>,
    _thread: core::marker::PhantomData<std::rc::Rc<()>>,
}

impl Entry {
    pub(crate) fn enter(slot: u32, entry: u8) -> Self {
        let scope = Self {
            saved: CLAIM
                .try_with(|claim| (claim.word.get(), claim.depth.get()))
                .ok(),
            _thread: core::marker::PhantomData,
        };
        enter(slot, entry);
        scope
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        let Some((word, depth)) = self.saved else {
            return;
        };
        let _ = CLAIM.try_with(|claim| {
            claim.word.set(word);
            claim.depth.set(depth);
            if let Some(published) = TABLE
                .get()
                .and_then(|table| table.words.get(claim.idx.get() as usize))
            {
                published.0.store(word, Ordering::Relaxed);
            }
        });
    }
}

/// Registers the calling thread on its first entry (cold, below), then two Relaxed stores.
pub fn enter(slot: u32, entry: u8) {
    let Some(table) = TABLE.get() else {
        return;
    };
    let _ = CLAIM.try_with(|c| {
        let depth = c.depth.get();
        if let Some(saved) = c.saved.get(depth) {
            saved.set(c.word.get());
        }
        c.depth.set(depth + 1);
        let mut idx = c.idx.get();
        if idx == u32::MAX {
            match claim(table, c) {
                Some(claimed) => idx = claimed,
                None => return,
            }
        }
        let mut seq = c.seq.get().wrapping_add(1);
        if seq == 0 {
            seq = 1;
        }
        c.seq.set(seq);
        let word =
            u64::from(slot & 0x00FF_FFFF) | (u64::from(entry) << 24) | (u64::from(seq) << 32);
        c.word.set(word);
        if let Some(w) = table.words.get(idx as usize) {
            w.0.store(word, Ordering::Relaxed);
        }
    });
}
pub fn leave() {
    let Some(table) = TABLE.get() else {
        return;
    };
    let _ = CLAIM.try_with(|c| {
        let depth = c.depth.get().saturating_sub(1);
        c.depth.set(depth);
        let restored = c.saved.get(depth).map_or(0, Cell::get);
        c.word.set(restored);
        if let Some(w) = table.words.get(c.idx.get() as usize) {
            w.0.store(restored, Ordering::Relaxed);
        }
    });
}
/// Live registrations (popcount of the occupancy bitmap). For C-WATCH-CHURN and `plugin_watch_threads`.
pub fn live() -> u32 {
    TABLE.get().map_or(0, |table| {
        table
            .bitmap
            .iter()
            .map(|bits| bits.load(Ordering::Relaxed).count_ones())
            .sum()
    })
}
/// Entries that ran unwatched because the table was full (`plugin_watch_full_total`). W1-H1: the registry's
/// watchdog thread turns a rise into the once-a-minute ERROR line §10.6 asks for (this module has no logger).
pub fn full_total() -> u64 {
    TABLE
        .get()
        .map_or(0, |table| table.full.load(Ordering::Relaxed))
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
///
/// W1-H1: one call is one 100 ms tick (`busy_ms` = ticks × 100), so the scan reads no clock at all. A ceiling
/// of 0 (a slot with no row) is never reported.
pub fn scan(
    ceiling: impl Fn(u32 /*slot*/, u8 /*entry*/) -> (u32 /*ceiling µs*/, u32 /*epoch*/),
    mut report: impl FnMut(
        u32, /*slot*/
        u32, /*epoch*/
        u8,  /*entry*/
        u64, /*busy_ms*/
    ),
) {
    let Some(table) = TABLE.get() else {
        return;
    };
    let mut scanner = table.scan.lock().unwrap_or_else(PoisonError::into_inner);
    scanner.tick += 1;
    let tick = scanner.tick;
    for (w, bits) in table.bitmap.iter().enumerate() {
        let claimed = bits.load(Ordering::Acquire);
        for bit in 0..64 {
            let i = w * 64 + bit;
            let Some(seen) = scanner.seen.get_mut(i) else {
                continue;
            };
            let word = match table.words.get(i) {
                Some(word) if claimed & (1 << bit) != 0 => word.0.load(Ordering::Relaxed),
                _ => 0,
            };
            if word == 0 {
                *seen = Seen::default();
                continue;
            }
            let slot = (word & 0x00FF_FFFF) as u32;
            let entry = ((word >> 24) & 0xFF) as u8;
            if word != seen.word {
                *seen = Seen {
                    word,
                    first_tick: tick,
                    epoch: ceiling(slot, entry).1,
                    reported: false,
                };
                continue;
            }
            if seen.reported {
                continue;
            }
            let busy_ms = (tick - seen.first_tick).saturating_mul(100);
            let (ceiling_us, _) = ceiling(slot, entry);
            if ceiling_us != 0 && busy_ms.saturating_mul(1_000) >= u64::from(ceiling_us) {
                seen.reported = true;
                report(slot, seen.epoch, entry, busy_ms);
            }
        }
    }
}
/// The slot of the entry running on this thread (log attribution, §5), or None outside an entry. Round 24: reads
/// `entry.rs`'s `OWNER` cell (§10.7), never the watch claim or word, so it is Some in every entry, watched or not
/// ("Full table" below), and in a nested entry it names the nested entry's owner.
pub fn current_slot() -> Option<u32> {
    crate::host_side::entry::owner()
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
    fn scoped_entries_restore_exact_words_and_depths_beyond_the_saved_array() {
        let _serial = serial();
        init();
        std::thread::spawn(|| {
            enter(7, ENTRY_RESUME);
            let outer = my_word();
            let index = CLAIM.with(|claim| claim.idx.get());
            let mut scopes = Vec::new();
            for _ in 0..NEST + 3 {
                let word = my_word();
                let depth = CLAIM.with(|claim| claim.depth.get());
                let scope = Entry::enter(9, ENTRY_CANCEL);
                assert!(
                    my_word() >> 32 > word >> 32,
                    "each nested entry advances the sequence"
                );
                scopes.push((scope, word, depth));
            }
            let deepest = my_word();
            let deepest_depth = CLAIM.with(|claim| claim.depth.get());
            let panicked = std::panic::catch_unwind(|| {
                let _scope = Entry::enter(11, ENTRY_CANCEL);
                panic!("unwind a nested no-output entry");
            });
            assert!(panicked.is_err());
            assert_eq!(
                my_word(),
                deepest,
                "unwind restores the exact word including its sequence"
            );
            assert_eq!(CLAIM.with(|claim| claim.depth.get()), deepest_depth);
            let sequence = CLAIM.with(|claim| claim.seq.get());
            while let Some((scope, word, depth)) = scopes.pop() {
                drop(scope);
                assert_eq!(my_word(), word);
                CLAIM.with(|claim| {
                    assert_eq!(claim.word.get(), word);
                    assert_eq!(claim.depth.get(), depth);
                    assert_eq!(
                        claim.seq.get(),
                        sequence,
                        "restoration never rewinds sequence allocation"
                    );
                    assert_eq!(claim.idx.get(), index, "the same thread retains its claim");
                });
            }
            assert_eq!(
                my_word(),
                outer,
                "a scoped entry restores its enclosing legacy entry"
            );
            leave();
            assert_eq!(my_word(), 0);
            assert_eq!(CLAIM.with(|claim| claim.depth.get()), 0);
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
