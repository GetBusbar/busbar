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
//! The canary is 32 random bytes placed at offset 32 of a payload far below jemalloc's small-size
//! limit; a match is any 16-byte window of it, so a partly overwritten secret still counts. The
//! patterns are held XOR-masked and compared byte by byte, so the scan never builds the plaintext,
//! and hits inside the scan's own read buffer are not counted. Staging buffers are [`Zeroizing`]
//! and are dropped before [`WipeProof::assert_absent`].
//!
//! Linux only (A23): elsewhere [`WipeProof::assert_absent`] checks nothing and the wipe counters and
//! mutants carry the proof.
//!
//! ```ignore
//! let proof = WipeProof::new();
//! {
//!     let secret = proof.payload();          // Zeroizing<Vec<u8>> holding the canary
//!     code_under_test(&secret);
//! }                                           // dropped before the scan
//! proof.assert_absent("code_under_test wipes its copies");
//! ```

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use zeroize::Zeroizing;

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

    #[inline]
    fn byte(&self, at: usize) -> u8 {
        self.masked[at] ^ self.mask[at]
    }

    /// A payload: filler, the canary at [`OFFSET`], filler.
    fn payload(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![FILLER; PAYLOAD_LEN]);
        for (at, slot) in out[OFFSET..OFFSET + CANARY_LEN].iter_mut().enumerate() {
            *slot = self.byte(at);
        }
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

/// One wipe proof: a canary, a live sentinel and a positive control (already planted and dropped).
pub struct WipeProof {
    canary: Pattern,
    sentinel: Pattern,
    control: Pattern,
    /// The live sentinel block; it stays alive until the scan.
    _live: Vec<u8>,
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
    /// Draw a canary, plant the live sentinel and plant then drop (without wiping) the control.
    #[must_use]
    pub fn new() -> Self {
        let canary = Pattern::random();
        let sentinel = Pattern::random();
        let control = Pattern::random();
        let live = sentinel.payload().to_vec();
        // The control is a plain `Vec`, dropped as is: its bytes stay in the freed block.
        let unwiped = control.payload().to_vec();
        drop(unwiped);
        Self {
            canary,
            sentinel,
            control,
            _live: live,
        }
    }

    /// A staging buffer holding the canary (a [`PAYLOAD_LEN`]-byte payload, the canary at
    /// [`OFFSET`]). It is [`Zeroizing`]: drop it before [`Self::assert_absent`].
    #[must_use]
    pub fn payload(&self) -> Zeroizing<Vec<u8>> {
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
            let found = match linux::scan(&[&self.sentinel, &self.control, &self.canary]) {
                Ok(found) => found,
                Err(error) => panic!("{what}: the memory scan could not run: {error}"),
            };
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
            let _ = (&self.sentinel, &self.control, &self.canary, what);
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
        let found = linux::scan(&[&self.sentinel, &self.control, &self.canary])
            .unwrap_or_else(|error| panic!("{what}: the memory scan could not run: {error}"));
        assert!(found[0] > 0, "{what}: the live sentinel was not found");
        assert!(found[1] > 0, "{what}: the positive control was not found");
        found[2]
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Pattern, CANARY_LEN, WINDOW};
    use std::collections::BTreeSet;
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    /// Bytes matched per read (a match may start in the first `STEP` bytes of a read).
    const STEP: usize = 1 << 16;

    /// How many distinct places hold each pattern in this process's writable memory: a place is
    /// where a 16-byte window of the pattern matches, normalised to where the pattern would start.
    pub(super) fn scan(patterns: &[&Pattern]) -> std::io::Result<Vec<usize>> {
        let maps = std::fs::read_to_string("/proc/self/maps")?;
        let mem = File::open("/proc/self/mem")?;
        let mut buf = vec![0_u8; STEP + WINDOW - 1];
        let buf_low = buf.as_ptr() as u64;
        let buf_high = buf_low + buf.len() as u64;
        let tables: Vec<[bool; 256]> = patterns
            .iter()
            .map(|pattern| {
                let mut starts = [false; 256];
                for at in 0..=CANARY_LEN - WINDOW {
                    starts[usize::from(pattern.byte(at))] = true;
                }
                starts
            })
            .collect();
        let mut anchors: Vec<BTreeSet<u64>> = patterns.iter().map(|_| BTreeSet::new()).collect();

        for line in maps.lines() {
            let Some((range, rest)) = line.split_once(' ') else {
                continue;
            };
            let perms = rest.split(' ').next().unwrap_or("");
            if !perms.starts_with("rw") || line.ends_with("[vvar]") || line.ends_with("[vsyscall]")
            {
                continue;
            }
            let Some((low, high)) = range.split_once('-') else {
                continue;
            };
            let (Ok(low), Ok(high)) = (u64::from_str_radix(low, 16), u64::from_str_radix(high, 16))
            else {
                continue;
            };
            let mut at = low;
            while at < high {
                let want = usize::try_from(high - at)
                    .unwrap_or(usize::MAX)
                    .min(buf.len());
                let Ok(read) = mem.read_at(&mut buf[..want], at) else {
                    break; // a guard page or a region that vanished: the rest is not memory
                };
                if read == 0 {
                    break;
                }
                let limit = read.saturating_sub(WINDOW - 1).min(STEP);
                for ((pattern, starts), found) in patterns.iter().zip(&tables).zip(&mut anchors) {
                    for place in 0..limit {
                        if !starts[usize::from(buf[place])] {
                            continue;
                        }
                        let address = at + place as u64;
                        if (buf_low..buf_high).contains(&address) {
                            continue; // the scan's own read buffer
                        }
                        for offset in 0..=CANARY_LEN - WINDOW {
                            if (0..WINDOW).all(|k| buf[place + k] == pattern.byte(offset + k)) {
                                found.insert(address - offset as u64);
                            }
                        }
                    }
                }
                at += limit.max(1) as u64;
            }
        }
        Ok(anchors.iter().map(BTreeSet::len).collect())
    }
}
