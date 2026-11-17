// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE Q24 WIPE PROOF (UNSAFE-MIN §4.4): plant a unique canary secret, run the code under test,
//! drop it, then scan this process's own memory (`/proc/self/maps` and `/proc/self/mem`, both
//! safe `std::fs`) and assert the canary is gone. It needs no `unsafe` and no custom allocator.
//!
//! It proves something only when the test binary runs on the shipped allocator with freed pages
//! left mapped, so a test using it:
//!
//! * declares `#[global_allocator] static A: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;`
//!   (or `stats_alloc::StatsAlloc<Jemalloc>` when it also counts), and
//! * runs with `_RJEM_MALLOC_CONF=dirty_decay_ms:-1,muzzy_decay_ms:-1` (the workspace's
//!   `.cargo/config.toml` sets it), so a freed block's bytes stay readable.
//!
//! A scan is trusted only after two controls pass, so "absent" can never be a blind scan:
//!
//! * a **live sentinel**, a heap block that stays alive, must be found (`/proc/self/mem` is readable
//!   on this runner, S8);
//! * a **positive control**, a block shaped like the canary payload, dropped WITHOUT wiping, must be
//!   found (the scan sees freed memory).
//!
//! The scan allocates nothing. jemalloc hands the most recently freed block of a size class to the
//! next allocation of that class, so any allocation between a drop and the read (the scan's own
//! buffers growing, a set node) can land on a freed block and overwrite the very bytes the scan is
//! about to look for. So [`WipeProof::new`] opens both files and makes every buffer the scan uses,
//! and plants the control in a block it holds, unwiped; the scan frees that block just before it
//! reads, so nothing the code under test allocates in between can reuse it, and nothing reuses it
//! (or a freed canary block) before the read.
//!
//! The canary is 32 random bytes placed at offset 32 of a payload far below jemalloc's small-size
//! limit; a match is any 16-byte window of it, so a partly overwritten secret still counts. The
//! patterns are held XOR-masked and compared masked, so the scan never builds the plaintext, and
//! hits inside the scan's own read buffer are not counted. Staging buffers are [`SecureVec`] and
//! are dropped before [`WipeProof::assert_absent`].
//!
//! Linux only (A23): elsewhere [`WipeProof::assert_absent`] checks nothing and the wipe counters and
//! mutants carry the proof.
//!
//! ```ignore
//! let proof = WipeProof::new();
//! {
//!     let secret = proof.payload();          // SecureVec holding the canary
//!     code_under_test(&secret);
//! }                                           // dropped before the scan
//! proof.assert_absent("code_under_test wipes its copies");
//! ```

use busbar_contract::secure::SecureVec;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

/// Bytes in a canary.
pub const CANARY_LEN: usize = 32;
/// The bytes of a canary a match must show (any window of this length).
pub const WINDOW: usize = 16;
/// Where the canary sits in a payload (at or past 16, clear of an allocator's free-list word).
pub const OFFSET: usize = 32;
/// A payload's length: small for jemalloc, with filler on both sides of the canary.
pub const PAYLOAD_LEN: usize = 128;
/// The filler around the canary.
const FILLER: u8 = 0xA5;

/// 32 random bytes held as `masked ^ mask`, so the plaintext is never at rest in this struct.
#[derive(Clone)]
struct Pattern {
    masked: [u8; CANARY_LEN],
    mask: [u8; CANARY_LEN],
}

impl Pattern {
    fn random() -> Self {
        let mut plain = [0_u8; CANARY_LEN];
        let mut mask = [0_u8; CANARY_LEN];
        fill_random(&mut plain);
        fill_random(&mut mask);
        let mut masked = [0_u8; CANARY_LEN];
        for ((m, p), k) in masked.iter_mut().zip(&plain).zip(&mask) {
            *m = p ^ k;
        }
        plain.fill(0);
        std::hint::black_box(&mut plain);
        Self { masked, mask }
    }

    /// One plaintext byte, unmasked on the way out so no whole copy is made.
    #[inline]
    fn byte(&self, at: usize) -> u8 {
        std::hint::black_box(self.masked[at]) ^ std::hint::black_box(self.mask[at])
    }

    /// Whether `seen` is plaintext byte `at`, compared masked.
    #[inline]
    #[cfg(target_os = "linux")]
    fn is(&self, at: usize, seen: u8) -> bool {
        seen ^ self.mask[at] == self.masked[at]
    }

    /// Filler, the canary at [`OFFSET`], filler: written into `out` (a [`PAYLOAD_LEN`] block).
    fn fill(&self, out: &mut [u8]) {
        out.fill(FILLER);
        for (at, slot) in out[OFFSET..OFFSET + CANARY_LEN].iter_mut().enumerate() {
            *slot = self.byte(at);
        }
    }

    /// A payload in a [`SecureVec`] staging buffer.
    fn payload(&self) -> SecureVec {
        let mut out = SecureVec::zeroed(PAYLOAD_LEN);
        self.fill(&mut out);
        out
    }

    /// A payload in a plain block, made in place (no staging copy that could take a freed block).
    fn block(&self) -> Vec<u8> {
        let mut out = vec![0_u8; PAYLOAD_LEN];
        self.fill(&mut out);
        out
    }
}

/// Fill `out` from the OS-seeded `RandomState` mixed with a clock and a counter. Unique per call;
/// not cryptographic, which a canary does not need.
fn fill_random(out: &mut [u8]) {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let state = RandomState::new();
    for chunk in out.chunks_mut(8) {
        let mut hasher = state.build_hasher();
        hasher.write_u64(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        let word = hasher.finish().to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
}

/// One wipe proof: a canary, a live sentinel, a positive control and the scanner that looks for them.
pub struct WipeProof {
    canary: Pattern,
    sentinel: Pattern,
    control: Pattern,
    /// The live sentinel block; it stays alive until the scan has read memory.
    live: Vec<u8>,
    /// The positive control's block, unwiped; the scan frees it just before it reads.
    unwiped: Vec<u8>,
    /// The files and buffers the scan uses, made before anything is planted.
    #[cfg(target_os = "linux")]
    scanner: std::io::Result<linux::Scanner>,
}

impl std::fmt::Debug for WipeProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WipeProof").finish_non_exhaustive()
    }
}

impl Default for WipeProof {
    fn default() -> Self {
        Self::new()
    }
}

impl WipeProof {
    /// Draw a canary, make the scan's files and buffers, plant the live sentinel and plant the
    /// (unwiped) control.
    #[must_use]
    pub fn new() -> Self {
        let canary = Pattern::random();
        let sentinel = Pattern::random();
        let control = Pattern::random();
        // First, so the scan never allocates after a block it must read is freed.
        #[cfg(target_os = "linux")]
        let scanner = linux::Scanner::open();
        let live = sentinel.block();
        let unwiped = control.block();
        Self {
            canary,
            sentinel,
            control,
            live,
            unwiped,
            #[cfg(target_os = "linux")]
            scanner,
        }
    }

    /// A staging buffer holding the canary (a [`PAYLOAD_LEN`]-byte payload, the canary at
    /// [`OFFSET`]). It is [`SecureVec`]: drop it before [`Self::assert_absent`].
    #[must_use]
    pub fn payload(&self) -> SecureVec {
        self.canary.payload()
    }

    /// Write the canary into `out` (which must be [`CANARY_LEN`] bytes), for code that takes the
    /// secret as a slice.
    ///
    /// # Panics
    /// If `out` is not [`CANARY_LEN`] bytes.
    pub fn write_canary(&self, out: &mut [u8]) {
        assert_eq!(out.len(), CANARY_LEN, "a canary is {CANARY_LEN} bytes");
        for (at, slot) in out.iter_mut().enumerate() {
            *slot = self.canary.byte(at);
        }
    }

    /// Scan this process's memory and panic unless the live sentinel and the positive control are
    /// found and the canary is not. On a target without `/proc/self/mem` it checks nothing.
    ///
    /// # Panics
    /// On a blind scan (sentinel or control missing: the message says which and how to fix it), or
    /// when the canary is still in memory.
    pub fn assert_absent(self, what: &str) {
        #[cfg(target_os = "linux")]
        {
            let found = self.scan(what);
            assert!(
                found[0] > 0,
                "{what}: the live sentinel was not found, so /proc/self/mem is not readable here \
                 and \"absent\" would prove nothing"
            );
            assert!(
                found[1] > 0,
                "{what}: the positive control (an unwiped, dropped block) was not found. Run on \
                 jemalloc with _RJEM_MALLOC_CONF=dirty_decay_ms:-1,muzzy_decay_ms:-1 so freed \
                 pages stay mapped"
            );
            assert_eq!(
                found[2], 0,
                "{what}: {} copies of the canary are still in process memory after the drop",
                found[2]
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                &self.sentinel,
                &self.control,
                &self.canary,
                &self.live,
                &self.unwiped,
                what,
            );
        }
    }

    /// The same scan, returning how many places still hold the canary (after the two controls
    /// pass), for a test that expects a leak and asserts it is found (RT10's red side).
    ///
    /// # Panics
    /// On a blind scan, as [`Self::assert_absent`].
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn canary_copies(self, what: &str) -> usize {
        let found = self.scan(what);
        assert!(found[0] > 0, "{what}: the live sentinel was not found");
        assert!(found[1] > 0, "{what}: the positive control was not found");
        found[2]
    }

    /// Free the control unwiped, then scan for the sentinel, the control and the canary, with no
    /// allocation between the free and the end of the read.
    #[cfg(target_os = "linux")]
    fn scan(self, what: &str) -> [usize; 3] {
        let Self {
            canary,
            sentinel,
            control,
            live,
            unwiped,
            scanner,
        } = self;
        let mut scanner = scanner
            .unwrap_or_else(|error| panic!("{what}: the memory scan could not run: {error}"));
        // `black_box`: the block's stores and its free are real, not optimised away.
        drop(std::hint::black_box(unwiped));
        let found = scanner.scan([&sentinel, &control, &canary]);
        drop(std::hint::black_box(live));
        found.unwrap_or_else(|error| panic!("{what}: the memory scan could not run: {error}"))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Pattern, CANARY_LEN, WINDOW};
    use std::fs::File;
    use std::io::{self, Read, Seek};
    use std::os::unix::fs::FileExt;

    /// Bytes matched per read (a match may start in the first `STEP` bytes of a read).
    const STEP: usize = 1 << 16;
    /// The most `/proc/self/maps` text one scan reads.
    const MAPS: usize = 4 << 20;
    /// Distinct places recorded per pattern; more are counted, not deduplicated.
    const PLACES: usize = 256;

    /// The scan's files and buffers, made once, before anything is planted: a scan allocates
    /// nothing, so it cannot take (and overwrite) a freed block it is about to read.
    pub(super) struct Scanner {
        maps: File,
        mem: File,
        text: Vec<u8>,
        buf: Vec<u8>,
        places: [Vec<u64>; 3],
    }

    impl Scanner {
        pub(super) fn open() -> io::Result<Self> {
            Ok(Self {
                maps: File::open("/proc/self/maps")?,
                mem: File::open("/proc/self/mem")?,
                text: vec![0; MAPS],
                buf: vec![0; STEP + WINDOW - 1],
                places: [
                    Vec::with_capacity(PLACES),
                    Vec::with_capacity(PLACES),
                    Vec::with_capacity(PLACES),
                ],
            })
        }

        /// How many distinct places hold each pattern in this process's writable memory: a place is
        /// where a 16-byte window of the pattern matches, normalised to where the pattern would
        /// start.
        pub(super) fn scan(&mut self, patterns: [&Pattern; 3]) -> io::Result<[usize; 3]> {
            self.maps.rewind()?;
            let mut n = 0;
            loop {
                let Some(rest) = self.text.get_mut(n..).filter(|rest| !rest.is_empty()) else {
                    return Err(io::Error::other(
                        "/proc/self/maps outgrew the scan's buffer",
                    ));
                };
                match self.maps.read(rest) {
                    Ok(0) => break,
                    Ok(k) => n += k,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }

            let buf_low = self.buf.as_ptr() as u64;
            let own = buf_low.saturating_sub(WINDOW as u64 - 1)..buf_low + self.buf.len() as u64;
            let mut tables = [[false; 256]; 3];
            for (pattern, starts) in patterns.iter().zip(&mut tables) {
                for at in 0..=CANARY_LEN - WINDOW {
                    starts[usize::from(pattern.byte(at))] = true;
                }
            }
            let mut extra = [0_usize; 3];
            for places in &mut self.places {
                places.clear();
            }

            let text = &self.text[..n];
            for line in text.split(|b| *b == b'\n') {
                let Some((low, high)) = writable(line) else {
                    continue;
                };
                let mut at = low;
                while at < high {
                    let want = usize::try_from(high - at)
                        .unwrap_or(usize::MAX)
                        .min(self.buf.len());
                    let Ok(read) = self.mem.read_at(&mut self.buf[..want], at) else {
                        break; // a guard page or a region that vanished: the rest is not memory
                    };
                    if read == 0 {
                        break;
                    }
                    let buf = &self.buf[..read];
                    let limit = read.saturating_sub(WINDOW - 1).min(STEP);
                    for (((pattern, starts), places), extra) in patterns
                        .iter()
                        .zip(&tables)
                        .zip(&mut self.places)
                        .zip(&mut extra)
                    {
                        for place in 0..limit {
                            if !starts[usize::from(buf[place])] {
                                continue;
                            }
                            let address = at + place as u64;
                            if own.contains(&address) {
                                continue; // the scan's own read buffer
                            }
                            for offset in 0..=CANARY_LEN - WINDOW {
                                if !(0..WINDOW).all(|k| pattern.is(offset + k, buf[place + k])) {
                                    continue;
                                }
                                let anchor = address - offset as u64;
                                if places.contains(&anchor) {
                                    continue;
                                }
                                if places.len() < places.capacity() {
                                    places.push(anchor);
                                } else {
                                    *extra += 1;
                                }
                            }
                        }
                    }
                    at += limit.max(1) as u64;
                }
            }
            let mut found = [0_usize; 3];
            for ((count, places), extra) in found.iter_mut().zip(&self.places).zip(extra) {
                *count = places.len() + extra;
            }
            Ok(found)
        }
    }

    /// The start and end of a `/proc/self/maps` line's mapping, when it is readable and writable
    /// (and not the kernel's `[vvar]` or `[vsyscall]` page).
    fn writable(line: &[u8]) -> Option<(u64, u64)> {
        if line.ends_with(b"[vvar]") || line.ends_with(b"[vsyscall]") {
            return None;
        }
        let mut fields = line.split(|b| *b == b' ');
        let range = fields.next()?;
        let perms = fields.next()?;
        if perms.get(..2) != Some(b"rw".as_slice()) {
            return None;
        }
        let dash = range.iter().position(|b| *b == b'-')?;
        let hex = |s: &[u8]| u64::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok();
        let (low, high) = (hex(range.get(..dash)?)?, hex(range.get(dash + 1..)?)?);
        (low < high).then_some((low, high))
    }
}
