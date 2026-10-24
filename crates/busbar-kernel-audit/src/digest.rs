// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DIGEST CANONICALISER every hash-chained record in the node frames through: the hex
//! SHA-256 helper, the two framings, and the one [`Digest`] builder that applies a framing to a
//! record's fields. The fixed audit record and the amendment chain frame length-prefixed here; the
//! kernel's own chains (the admin audit chain, the plane journals and their host-side prelude) take
//! this same builder, re-exported as `busbar_kernel::audit::{Digest, Framing}`, rather than a copy of
//! it.
//!
//! The admin audit chain's digest is a 1.5.5 byte: `sha256(prev_hash | seq | ts | …)`, joined by a
//! bar with integers in decimal. That is [`Framing::PipeSeparated`], kept byte for byte, because a
//! digest that changed would report a deployment's whole history as tampered at its next boot.

/// The lowercase hexadecimal digest the chain is built on.
pub fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// HOW A RECORD'S FIELDS ARE FRAMED INTO THE DIGEST INPUT.
///
/// A wire fact of chains that already exist on disk, not a preference. Changing the framing of an
/// existing stream would make every persisted chain in every deployment fail to verify at the next
/// boot. That is the one migration this module may never do silently, so the framing travels with
/// the record type instead of being unified away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Every field is prefixed with its big-endian eight-byte length, and integers are their
    /// eight-byte big-endian form. THE FRAMING A NEW RECORD TYPE MUST CHOOSE: length prefixes make
    /// the split between fields unforgeable regardless of what any field contains, so a caller who
    /// can choose one field's bytes cannot forge the same byte stream under a different split. A
    /// separator-joined digest is only safe while no field can contain the separator, which is a
    /// property of today's fields rather than of the code.
    LengthPrefixed,
    /// Fields joined by a vertical bar, integers in decimal. The framing of the admin audit chain
    /// and one plane stream's provenance chain, kept byte for byte because their records are
    /// already on disk.
    PipeSeparated,
}

/// THE ONE CANONICALISER. A record feeds its chained fields in through [`Digest::text`] and
/// [`Digest::num`] (and a pre-framed suffix through [`Digest::raw`]); the framing and the hash
/// function are not its business.
pub struct Digest {
    framing: Framing,
    buf: Vec<u8>,
    /// Pipe-separated only: whether a separator is owed before the next field.
    started: bool,
}

impl Digest {
    /// A canonicaliser in the given framing.
    pub fn new(framing: Framing) -> Self {
        Digest {
            framing,
            buf: Vec::new(),
            started: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        match self.framing {
            Framing::LengthPrefixed => {
                self.buf
                    .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
                self.buf.extend_from_slice(bytes);
            }
            Framing::PipeSeparated => {
                if self.started {
                    self.buf.push(b'|');
                }
                self.buf.extend_from_slice(bytes);
            }
        }
        self.started = true;
    }

    /// Feed one string field.
    pub fn text(&mut self, s: &str) -> &mut Self {
        self.push(s.as_bytes());
        self
    }

    /// Feed one integer field.
    pub fn num(&mut self, v: u64) -> &mut Self {
        match self.framing {
            Framing::LengthPrefixed => self.push(&v.to_be_bytes()),
            Framing::PipeSeparated => self.push(v.to_string().as_bytes()),
        }
        self
    }

    /// Feed ALREADY-FRAMED bytes verbatim — the join primitive the kernel's host-side journal
    /// cleave uses. A plane hands a pre-framed content SUFFIX and the host concatenates it after the
    /// framed prelude, so `sha256_hex(prelude ⧺ suffix)` equals the single-builder digest. It
    /// appends no length prefix and no separator of its own — the suffix already carries the leading
    /// bar a pipe-separated stream owes — and it still counts as a field for the next separator.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self.started = true;
        self
    }

    /// The framed bytes, unhashed — what a prelude framed by one builder is when a second builder
    /// takes it through [`Digest::raw`] (the kernel's `frame_prelude`).
    #[must_use]
    pub fn into_framed(self) -> Vec<u8> {
        self.buf
    }

    /// The digest of everything fed in so far.
    pub fn finish(self) -> String {
        sha256_hex(&self.buf)
    }
}
