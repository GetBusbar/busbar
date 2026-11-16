// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANARY SCAN (owner ruling Q24; UNSAFE-MIN §4.4): the wipe proof of a secret-holding type,
//! with no `unsafe` and no custom allocator. A test plants a unique random canary through the
//! type's own constructor, exercises the path (growth past capacity included), drops the value,
//! then scans its own process memory: every readable and writable mapping `/proc/self/maps` lists,
//! read through `/proc/self/mem` with `std::fs`. The canary must be absent. A copy left in a freed
//! block, in an old block a realloc gave up, or in a stack slot is found.
//!
//! The scanner never holds the canary: it keeps a random mask and the masked canary, and compares
//! each window of memory masked. [`Canary::new`] opens both files and makes every buffer the scan
//! uses, so a scan allocates nothing that could reuse (and overwrite) a freed block it is about to
//! read. Hits inside the scan's own read buffer are not counted. Linux only: elsewhere
//! [`Canary::new`] answers [`std::io::ErrorKind::Unsupported`].
//!
//! ```ignore
//! use busbar_contract::abi::sdk::test_support::canary::Canary;
//!
//! let mut c = Canary::new()?;
//! let key = SecureVec::from(c.plant());   // the type's own constructor takes the only copy
//! key.grow_past_capacity();
//! drop(key);
//! c.assert_absent();                      // panics naming every address that still holds it
//! ```
#![forbid(unsafe_code)]

use std::fmt;
use std::io;

/// The canary's length in bytes.
pub const LEN: usize = 32;

/// One read of `/proc/self/mem`: the scan's buffer, made once.
#[cfg(target_os = "linux")]
const CHUNK: usize = 1 << 20;

/// The most `/proc/self/maps` text one scan reads.
#[cfg(target_os = "linux")]
const MAPS: usize = 4 << 20;

/// One unique random canary and the scanner that looks for it.
pub struct Canary {
    mask: [u8; LEN],
    masked: [u8; LEN],
    #[cfg(target_os = "linux")]
    os: Os,
}

impl fmt::Debug for Canary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Canary").finish_non_exhaustive()
    }
}

/// What one scan read and found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    /// The address of every copy of the canary found, in map order.
    pub hits: Vec<usize>,
    /// Readable and writable mappings scanned.
    pub regions: usize,
    /// Of those, mappings not read to their end (gone, or refused by the kernel).
    pub unreadable: usize,
    /// Bytes read.
    pub bytes: u64,
}

impl Canary {
    /// A fresh canary, with the files and buffers its scans use.
    ///
    /// # Errors
    /// Off Linux, [`io::ErrorKind::Unsupported`]; on Linux, when `/proc/self/maps` or
    /// `/proc/self/mem` cannot be opened, or no random bytes can be drawn.
    pub fn new() -> io::Result<Self> {
        let (mask, masked) = draw()?;
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                mask,
                masked,
                os: Os::open()?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (mask, masked);
            Err(unsupported())
        }
    }

    /// The canary, in a fresh `Vec` of [`LEN`] bytes: hand it to the type's own constructor, which
    /// then holds the only copy.
    #[must_use]
    pub fn plant(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(LEN);
        v.extend(self.bytes());
        v
    }

    /// Writes the canary into the first [`LEN`] bytes of `dst` (a buffer the type under test owns).
    ///
    /// # Panics
    /// When `dst` is shorter than [`LEN`].
    pub fn plant_into(&self, dst: &mut [u8]) {
        assert!(dst.len() >= LEN, "a canary needs {LEN} bytes");
        dst.iter_mut().zip(self.bytes()).for_each(|(d, b)| *d = b);
    }

    /// The canary's bytes, one at a time, so no whole copy is made on the way.
    fn bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.masked
            .iter()
            .zip(&self.mask)
            .map(|(s, m)| std::hint::black_box(*s) ^ std::hint::black_box(*m))
    }

    /// Scans every readable and writable mapping of this process for the canary.
    ///
    /// # Errors
    /// When `/proc/self/maps` cannot be read (or outgrows the scan's buffer); off Linux,
    /// [`io::ErrorKind::Unsupported`]. A mapping that cannot be read is counted in
    /// [`Scan::unreadable`], not an error.
    pub fn scan(&mut self) -> io::Result<Scan> {
        #[cfg(target_os = "linux")]
        {
            self.os.scan(&self.mask, &self.masked)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(unsupported())
        }
    }

    /// Scans, and panics unless the scan read memory and found no copy of the canary.
    ///
    /// # Panics
    /// When the scan fails, reads nothing, or finds the canary; the message names every address.
    #[track_caller]
    pub fn assert_absent(&mut self) {
        let scan = match self.scan() {
            Ok(scan) => scan,
            Err(e) => panic!("the canary scan could not read process memory: {e}"),
        };
        assert!(scan.bytes > 0, "the canary scan read no memory: {scan:?}");
        assert!(
            scan.hits.is_empty(),
            "the canary is still in process memory, {} cop(ies) at {:#x?} ({} mapping(s) scanned, {} unreadable)",
            scan.hits.len(),
            scan.hits,
            scan.regions,
            scan.unreadable
        );
    }
}

/// A random mask and the masked canary, neither of which is the canary: no byte of either is 0.
fn draw() -> io::Result<([u8; LEN], [u8; LEN])> {
    let mut mask = [0_u8; LEN];
    let mut masked = [0_u8; LEN];
    for _ in 0..64 {
        busbar_crypto::fill(&mut mask).map_err(|_| io::Error::other("no random bytes"))?;
        busbar_crypto::fill(&mut masked).map_err(|_| io::Error::other("no random bytes"))?;
        if !mask.contains(&0) && !masked.contains(&0) {
            return Ok((mask, masked));
        }
    }
    Err(io::Error::other(
        "the random source keeps answering zero bytes",
    ))
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the canary scan reads /proc/self/mem (Linux only)",
    )
}

/// The scan's files and buffers, made once by [`Canary::new`].
#[cfg(target_os = "linux")]
struct Os {
    maps: std::fs::File,
    mem: std::fs::File,
    text: Vec<u8>,
    chunk: Vec<u8>,
    hits: Vec<usize>,
}

#[cfg(target_os = "linux")]
impl Os {
    fn open() -> io::Result<Self> {
        Ok(Self {
            maps: std::fs::File::open("/proc/self/maps")?,
            mem: std::fs::File::open("/proc/self/mem")?,
            text: vec![0; MAPS],
            chunk: vec![0; CHUNK],
            hits: Vec::with_capacity(64),
        })
    }

    fn scan(&mut self, mask: &[u8; LEN], masked: &[u8; LEN]) -> io::Result<Scan> {
        use std::io::{Read, Seek};
        use std::os::unix::fs::FileExt;

        self.maps.rewind()?;
        let mut n = 0;
        loop {
            let rest = self.text.get_mut(n..).unwrap_or_default();
            if rest.is_empty() {
                return Err(io::Error::other(
                    "/proc/self/maps outgrew the scan's buffer",
                ));
            }
            match self.maps.read(rest) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        // The scan's own read buffer holds a copy of whatever it last read: never a hit.
        let own = self.chunk.as_ptr().addr();
        let own = own.saturating_sub(LEN - 1)..own.saturating_add(self.chunk.len());
        self.hits.clear();
        let (mut regions, mut unreadable, mut bytes) = (0, 0, 0_u64);
        let text = self.text.get(..n).unwrap_or_default();
        for (start, end) in text.split(|b| *b == b'\n').filter_map(writable) {
            regions += 1;
            let mut at = start;
            while at < end {
                let want = usize::try_from(end - at).map_or(CHUNK, |left| left.min(CHUNK));
                let Some(buf) = self.chunk.get_mut(..want) else {
                    break;
                };
                let got = match self.mem.read_at(buf, at) {
                    Ok(0) | Err(_) => {
                        unreadable += 1;
                        break;
                    }
                    Ok(got) => got,
                };
                bytes += got as u64;
                let read = self.chunk.get(..got).unwrap_or_default();
                for p in found(read, mask, masked) {
                    let Some(hit) = usize::try_from(at).ok().and_then(|a| a.checked_add(p)) else {
                        continue;
                    };
                    if !own.contains(&hit) {
                        self.hits.push(hit);
                    }
                }
                // The next read starts LEN - 1 bytes early, so a copy across the seam is seen once.
                at = if at + got as u64 >= end || got < LEN {
                    at + got as u64
                } else {
                    at + (got - (LEN - 1)) as u64
                };
            }
        }
        Ok(Scan {
            hits: std::mem::take(&mut self.hits),
            regions,
            unreadable,
            bytes,
        })
    }
}

/// The start and end of a `/proc/self/maps` line's mapping, when it is readable and writable.
#[cfg(target_os = "linux")]
fn writable(line: &[u8]) -> Option<(u64, u64)> {
    let mut fields = line.split(|b| *b == b' ');
    let range = fields.next()?;
    let perms = fields.next()?;
    if perms.get(..2) != Some(b"rw".as_slice()) {
        return None;
    }
    let dash = range.iter().position(|b| *b == b'-')?;
    let hex = |s: &[u8]| u64::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok();
    let (start, end) = (hex(range.get(..dash)?)?, hex(range.get(dash + 1..)?)?);
    (start < end).then_some((start, end))
}

/// The offset of every window of `read` that is the canary, compared masked.
#[cfg(target_os = "linux")]
fn found<'a>(
    read: &'a [u8],
    mask: &'a [u8; LEN],
    masked: &'a [u8; LEN],
) -> impl Iterator<Item = usize> + 'a {
    read.windows(LEN).enumerate().filter_map(move |(p, w)| {
        w.iter()
            .zip(mask)
            .zip(masked)
            .all(|((b, m), s)| b ^ m == *s)
            .then_some(p)
    })
}
