// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANARY SCAN (owner ruling Q24; UNSAFE-MIN §4.4): the wipe proof of a secret-holding type,
//! with no `unsafe` and no custom allocator. RED STAGE: the API only; the scan reads nothing yet.
#![forbid(unsafe_code)]

use std::fmt;
use std::io;

/// The canary's length in bytes.
pub const LEN: usize = 32;

/// One unique random canary and the scanner that looks for it.
pub struct Canary {
    mask: [u8; LEN],
    masked: [u8; LEN],
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
    /// A fresh canary.
    ///
    /// # Errors
    /// When no random bytes can be drawn.
    pub fn new() -> io::Result<Self> {
        let (mask, masked) = draw()?;
        Ok(Self { mask, masked })
    }

    /// The canary, in a fresh `Vec` of [`LEN`] bytes.
    #[must_use]
    pub fn plant(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(LEN);
        v.extend(self.bytes());
        v
    }

    /// Writes the canary into the first [`LEN`] bytes of `dst`.
    ///
    /// # Panics
    /// When `dst` is shorter than [`LEN`].
    pub fn plant_into(&self, dst: &mut [u8]) {
        assert!(dst.len() >= LEN, "a canary needs {LEN} bytes");
        dst.iter_mut().zip(self.bytes()).for_each(|(d, b)| *d = b);
    }

    fn bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.masked
            .iter()
            .zip(&self.mask)
            .map(|(s, m)| std::hint::black_box(*s) ^ std::hint::black_box(*m))
    }

    /// Scans process memory for the canary. RED STAGE: reads nothing.
    ///
    /// # Errors
    /// None yet.
    pub fn scan(&mut self) -> io::Result<Scan> {
        Ok(Scan::default())
    }

    /// Scans, and panics unless the scan read memory and found no copy of the canary.
    ///
    /// # Panics
    /// When the scan fails, reads nothing, or finds the canary.
    #[track_caller]
    pub fn assert_absent(&mut self) {
        let scan = match self.scan() {
            Ok(scan) => scan,
            Err(e) => panic!("the canary scan could not read process memory: {e}"),
        };
        assert!(scan.bytes > 0, "the canary scan read no memory: {scan:?}");
        assert!(
            scan.hits.is_empty(),
            "the canary is still in process memory: {scan:?}"
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
