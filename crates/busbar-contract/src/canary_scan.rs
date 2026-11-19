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
//!
//! Code that holds the secret as text takes [`WipeProof::text`] and [`WipeProof::text_payload`] (the
//! canary drawn from 64 ASCII characters). `WipeProof::short_text` makes a short one: a
//! [`SHORT_CANARY_LEN`]-character canary in a [`SHORT_PAYLOAD_LEN`]-byte payload, under the 30 bytes a
//! small-string type stores inline, its sentinel and control in blocks of the same size. A test that must also show the secret is still owned
//! part-way (a pending future, a shared owner not yet dropped) calls [`WipeProof::assert_held`]
//! there: the canary must still be found, so the later "absent" is the drop at the end, not an
//! early free.

use crate::secure::{SecureString, SecureVec};
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
/// A short payload's length: at most 30 bytes, so a small-string type stores it inline.
const SHORT_PAYLOAD_LEN: usize = 24;
/// Where a short canary sits in its payload: two filler bytes on each side.
const SHORT_OFFSET: usize = 2;
/// The filler around the canary.
const FILLER: u8 = 0xA5;
/// The filler around a text canary (ASCII, so the payload is a `String`).
const TEXT_FILLER: u8 = b'.';
/// The 64 characters a text canary is drawn from.
const TEXT: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
/// Alphanumeric-only canaries also survive URL/form encoding unchanged.
const ALPHANUMERIC: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Where a pattern sits: its payload's length and its offset there.
#[derive(Clone, Copy)]
struct Layout {
    payload: usize,
    offset: usize,
}

/// The [`PAYLOAD_LEN`] layout, the pattern at [`OFFSET`].
const LONG: Layout = Layout {
    payload: PAYLOAD_LEN,
    offset: OFFSET,
};

/// The [`SHORT_PAYLOAD_LEN`] layout, the pattern at [`SHORT_OFFSET`].
const SHORT: Layout = Layout {
    payload: SHORT_PAYLOAD_LEN,
    offset: SHORT_OFFSET,
};

/// `len` random bytes (at most [`CANARY_LEN`]) held as `masked ^ mask`, so the plaintext is never
/// at rest in this struct.
#[derive(Clone)]
struct Pattern {
    masked: [u8; CANARY_LEN],
    mask: [u8; CANARY_LEN],
    len: usize,
}

impl Pattern {
    fn random(len: usize) -> Self {
        Self::random_from(None, len)
    }

    fn random_from(alphabet: Option<&[u8]>, len: usize) -> Self {
        assert!(
            (WINDOW..=CANARY_LEN).contains(&len),
            "a pattern is {WINDOW} to {CANARY_LEN} bytes"
        );
        let mut draw = [0_u8; CANARY_LEN];
        let mut mask = [0_u8; CANARY_LEN];
        fill_random(&mut draw);
        fill_random(&mut mask);
        let mut masked = [0_u8; CANARY_LEN];
        for ((m, d), k) in masked.iter_mut().zip(&draw).zip(&mask) {
            let plain = alphabet.map_or(*d, |chars| chars[usize::from(*d) % chars.len()]);
            *m = plain ^ k;
        }
        draw.fill(0);
        std::hint::black_box(&mut draw);
        Self { masked, mask, len }
    }

    /// `len` characters drawn from [`TEXT`], so the canary can stand in a `String` (32 of them carry
    /// 192 random bits).
    fn random_text(len: usize) -> Self {
        Self::random_from(Some(TEXT), len)
    }

    /// Whether every canary byte is one of [`TEXT`] (the pattern was drawn by [`Self::random_text`]).
    fn is_text(&self) -> bool {
        (0..self.len).all(|at| TEXT.contains(&self.byte(at)))
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

    /// Filler, the pattern at `layout`'s offset, filler: written into `out` (a payload-sized block).
    fn fill(&self, out: &mut [u8], layout: Layout) {
        out.fill(FILLER);
        for (at, slot) in out[layout.offset..layout.offset + self.len]
            .iter_mut()
            .enumerate()
        {
            *slot = self.byte(at);
        }
    }

    /// A payload in a [`SecureVec`] staging buffer.
    fn payload(&self, layout: Layout) -> SecureVec {
        let mut out = SecureVec::zeroed(layout.payload);
        self.fill(&mut out, layout);
        out
    }

    /// A text payload (filler [`TEXT_FILLER`], the canary at `layout`'s offset) in a
    /// [`SecureString`] staging string. The pattern must be a text one ([`Self::random_text`]).
    fn text_payload(&self, layout: Layout) -> SecureString {
        let mut out = vec![TEXT_FILLER; layout.payload];
        for (at, slot) in out[layout.offset..layout.offset + self.len]
            .iter_mut()
            .enumerate()
        {
            *slot = self.byte(at);
        }
        // ASCII throughout (checked by the caller), so this keeps the same block: no copy is made.
        SecureString::from(String::from_utf8(out).expect("a text canary payload is ASCII"))
    }

    /// A payload in a plain block, made in place (no staging copy that could take a freed block).
    fn block(&self, layout: Layout) -> Vec<u8> {
        let mut out = vec![0_u8; layout.payload];
        self.fill(&mut out, layout);
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
    /// The payload size and canary offset every block of this proof uses.
    layout: Layout,
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
        Self::with_canary(Pattern::random(CANARY_LEN), LONG)
    }

    /// As [`Self::new`], with a text canary (32 characters of 64 ASCII ones), for code that holds
    /// the secret as a `String`: plant it with [`Self::text_payload`].
    #[must_use]
    pub fn text() -> Self {
        Self::with_canary(Pattern::random_text(CANARY_LEN), LONG)
    }

    /// An ASCII alphanumeric canary, unchanged by URL/form encoding, using the same masked scanner and
    /// controls as [`Self::new`]. Write it directly into guarded ASCII staging with [`Self::write_canary`].
    /// [`Self::payload`] still has binary filler and is not a UTF-8 payload.
    #[must_use]
    pub fn new_text() -> Self {
        Self::with_canary(Pattern::random_from(Some(ALPHANUMERIC), CANARY_LEN), LONG)
    }

    fn with_canary(canary: Pattern, layout: Layout) -> Self {
        let sentinel = Pattern::random(canary.len);
        let control = Pattern::random(canary.len);
        // First, so the scan never allocates after a block it must read is freed.
        #[cfg(target_os = "linux")]
        let scanner = linux::Scanner::open();
        let live = sentinel.block(layout);
        let unwiped = control.block(layout);
        Self {
            canary,
            layout,
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
        self.canary.payload(self.layout)
    }

    /// A staging string holding the text canary (a [`PAYLOAD_LEN`]-byte ASCII payload, the canary at
    /// [`OFFSET`]; for `Self::short_text`, [`SHORT_PAYLOAD_LEN`] bytes, the canary at
    /// [`SHORT_OFFSET`]). It is [`SecureString`]: clone the text into the code under test and drop
    /// this before [`Self::assert_absent`].
    ///
    /// # Panics
    /// If the canary contains non-text bytes; use [`Self::text`], `Self::short_text` or
    /// [`Self::new_text`].
    #[must_use]
    pub fn text_payload(&self) -> SecureString {
        assert!(
            self.canary.is_text(),
            "a text payload needs a proof made by WipeProof::text()"
        );
        self.canary.text_payload(self.layout)
    }

    /// Scan now, while the code under test must still own its copy of the canary (a pending future,
    /// a shared owner not yet dropped), and panic unless the live sentinel and the canary are found.
    /// The proof stays whole for the final [`Self::assert_absent`]. On a target without
    /// `/proc/self/mem` it checks nothing.
    ///
    /// # Panics
    /// On a blind scan (the sentinel missing), or when the canary is gone already: freed early, or
    /// never planted.
    pub fn assert_held(&mut self, what: &str) {
        #[cfg(target_os = "linux")]
        {
            let scanner = self
                .scanner
                .as_mut()
                .unwrap_or_else(|error| panic!("{what}: the memory scan could not run: {error}"));
            let found = scanner
                .scan([&self.sentinel, &self.control, &self.canary])
                .unwrap_or_else(|error| panic!("{what}: the memory scan could not run: {error}"));
            assert!(
                found[0] > 0,
                "{what}: the live sentinel was not found, so /proc/self/mem is not readable here \
                 and \"held\" would prove nothing"
            );
            assert!(
                found[2] > 0,
                "{what}: the canary is not in memory while its owner should still hold it (freed \
                 early, or never planted)"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = what;
        }
    }

    /// Write the canary into `out` (which must be the canary's length: [`CANARY_LEN`] bytes, or
    /// [`SHORT_CANARY_LEN`] for `Self::short_text`), for code that takes the secret as a slice.
    ///
    /// # Panics
    /// If `out` is not the canary's length.
    pub fn write_canary(&self, out: &mut [u8]) {
        let len = self.canary.len;
        assert_eq!(out.len(), len, "a canary is {len} bytes");
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
                &self.layout,
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
            layout: _,
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
    use super::{Pattern, WINDOW};
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
            // Which byte values occur anywhere in each pattern.
            let mut tables = [[false; 256]; 3];
            for (pattern, present) in patterns.iter().zip(&mut tables) {
                for at in 0..pattern.len {
                    present[usize::from(pattern.byte(at))] = true;
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
                    // A match is a window starting at some `place` in `0..limit` (all its bytes in
                    // `buf`). Every window of WINDOW bytes holds exactly one address that is a
                    // multiple of WINDOW, so only those bytes are probed: a probed byte equal to
                    // pattern byte `index` names the windows (pattern offsets) that could hold it
                    // there, and each is checked whole. The same windows and anchors as testing
                    // every place, at a WINDOW-th of the probes (a scan is about 1 s of an
                    // unoptimised test build otherwise, and a wipe test makes dozens).
                    let first =
                        usize::try_from((WINDOW as u64 - at % WINDOW as u64) % WINDOW as u64)
                            .unwrap_or(0);
                    let end = (limit + WINDOW - 1).min(read);
                    for (((pattern, present), places), extra) in patterns
                        .iter()
                        .zip(&tables)
                        .zip(&mut self.places)
                        .zip(&mut extra)
                    {
                        let mut probe = first;
                        while probe < end {
                            let seen = buf[probe];
                            if present[usize::from(seen)] {
                                for index in 0..pattern.len {
                                    if !pattern.is(index, seen) {
                                        continue;
                                    }
                                    // Offsets whose window covers pattern byte `index`.
                                    let lowest = index.saturating_sub(WINDOW - 1);
                                    let highest = index.min(pattern.len - WINDOW);
                                    for offset in lowest..=highest {
                                        let Some(place) = probe.checked_sub(index - offset) else {
                                            continue;
                                        };
                                        if place >= limit {
                                            continue; // the next read starts this window
                                        }
                                        let address = at + place as u64;
                                        if own.contains(&address) {
                                            continue; // the scan's own read buffer
                                        }
                                        if !(0..WINDOW)
                                            .all(|k| pattern.is(offset + k, buf[place + k]))
                                        {
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
                            probe += WINDOW;
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
