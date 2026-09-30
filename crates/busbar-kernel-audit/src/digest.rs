// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The digest canonicaliser the audit records hash through: the hex SHA-256 helper, the two
//! framings, and the one [`Digest`] builder that applies a framing to a record's fields.
//!
//! Every byte this produces is already on somebody's disk, so the framing, the field order and the
//! hash are exactly as they were when the retired admin chain shared this crate. A digest that changed
//! would report a deployment's whole history as tampered at its next boot.

/// The lowercase hexadecimal digest the chain is built on.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(data)
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
    /// Fields joined by a vertical bar, integers in decimal. The framing of the admin audit chain,
    /// kept byte for byte because its records are already on disk.
    PipeSeparated,
}

/// THE ONE CANONICALISER. A record feeds its chained fields in through [`Digest::text`] and
/// [`Digest::num`]; the framing and the hash function are not its business.
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

    /// The digest of everything fed in so far.
    pub fn finish(self) -> String {
        sha256_hex(&self.buf)
    }

    /// The framed bytes, before hashing. Only a test that is checking the framing itself wants
    /// these.
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
}
