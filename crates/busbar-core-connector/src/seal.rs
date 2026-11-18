// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALED CREDENTIAL VALUES (TSEAL; the "plane never sees credential bytes" family): the bound

use busbar_contract::kept::Kept;
use busbar_contract::secure::SecureVec;
use foldhash::HashMap;

use crate::compose::Opening;

/// The refusal of an open whose sealed values would cross a connection the host does not secure:
pub const SEALED_IN_CLEAR: &str = "a sealed credential is never written in the clear: the open's \
     connection is not secured by the host, so its carrier would read the credential";

/// The refusal of an opening whose filler the framer did not render verbatim exactly once.
pub const SEAL_BROKEN: &str = "the framer did not render a sealed value verbatim exactly once; \
     nothing of the message was sent";

/// The filler's alphabet: legal in any field value and never transformed by a literal rendering.
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// One sealed value: the filler the framer was handed and the real bytes it stands for. A seal is
/// a slot of [`Seals`]: spliced or cleared, it is emptied (its value wiped) and filled again by the
/// connection's next seal in the storage it already has.
#[derive(Default)]
pub(crate) struct Seal {
    pub(crate) stream: u64,
    pub(crate) filler: Vec<u8>,
    pub(crate) value: SecureVec,
}

impl Kept for Seal {
    fn clear(&mut self) {
        self.stream = 0;
        self.filler.clear();
        self.value.clear();
    }
}

/// THE SEALS A CONNECTION HOLDS: those not yet spliced into its wire (the first `live` slots of
/// `held`, in the order they were sealed; the slots past them keep their storage for the next
/// seals), the connection's reused list of where each seal's filler stands, and how many seals
/// wait on each stream (kept current as a seal is held, spliced or cleared, so asking after a
/// stream is no scan).
#[derive(Default)]
pub(crate) struct Seals {
    held: Vec<Seal>,
    live: usize,
    positions: Vec<Option<usize>>,
    counts: HashMap<u64, usize>,
}

impl std::fmt::Debug for Seals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Seals({} pending)", self.live)
    }
}

pub(crate) use crate::off_path::seal::take_sealed_names;

/// Fill `bytes` with `len` bytes of filler, in its own storage. False when the host's random
/// source failed.
fn filler_into(bytes: &mut Vec<u8>, len: usize) -> bool {
    bytes.clear();
    bytes.resize(len, 0);
    if busbar_contract::crypto::fill(bytes).is_err() {
        return false;
    }
    for b in bytes.iter_mut() {
        *b = ALPHABET[usize::from(*b) % ALPHABET.len()];
    }
    true
}

/// The host's random source failed while a filler was made.
const RANDOM_FAILED: &str = "the host's random source failed";

fn released(counts: &mut HashMap<u64, usize>, stream: u64) {
    if let std::collections::hash_map::Entry::Occupied(mut held) = counts.entry(stream) {
        *held.get_mut() -= 1;
        if *held.get() == 0 {
            held.remove();
        }
    }
}

impl Seals {
    /// The next seal for `stream`, emptied, its filler made `len` long; `None` when the host's
    /// random source failed (nothing is held then). The slot is made only the first time a
    /// connection holds this many seals at once.
    fn hold(&mut self, stream: u64, len: usize) -> Option<&mut Seal> {
        if self.live == self.held.len() {
            self.held.push(Seal::default());
        }
        let seal = &mut self.held[self.live];
        seal.clear();
        if !filler_into(&mut seal.filler, len) {
            seal.clear();
            return None;
        }
        seal.stream = stream;
        self.live += 1;
        *self.counts.entry(stream).or_default() += 1;
        Some(seal)
    }

    /// Keep the live seals `keep` answers true for, in their order; every other one is emptied
    /// (its value wiped) and its slot kept for reuse.
    fn retain(&mut self, mut keep: impl FnMut(usize, &mut Seal) -> bool) {
        let mut kept = 0;
        for at in 0..self.live {
            if keep(at, &mut self.held[at]) {
                self.held.swap(kept, at);
                kept += 1;
            } else {
                let stream = self.held[at].stream;
                released(&mut self.counts, stream);
                self.held[at].clear();
            }
        }
        self.live = kept;
    }

    /// Remove the host's query metadata before framing and append it only to the wire target.
    pub(crate) fn seal_queries(
        &mut self,
        stream: u64,
        opening: &mut Option<Opening>,
        target: &mut Vec<u8>,
        sealing: bool,
        secured: bool,
    ) -> Result<bool, &'static str> {
        let Some((fields, _)) = opening.as_mut() else {
            return Ok(false);
        };
        let pairs = crate::off_path::seal::take_query_pairs(fields);
        if pairs.is_empty() {
            return Ok(false);
        }

        for pair in &pairs {
            let Some(at) = pair.iter().position(|b| *b == b'=') else {
                return Err(SEAL_BROKEN);
            };
            let encoded = |bytes: &[u8]| {
                let mut rest = bytes;
                while let Some((&b, tail)) = rest.split_first() {
                    if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                        rest = tail;
                    } else if b == b'%'
                        && tail.len() >= 2
                        && tail[..2].iter().all(u8::is_ascii_hexdigit)
                    {
                        rest = &tail[2..];
                    } else {
                        return false;
                    }
                }
                true
            };
            if !encoded(&pair[..at]) || !encoded(&pair[at + 1..]) {
                return Err(SEAL_BROKEN);
            }
            if sealing && !secured && at + 1 < pair.len() {
                return Err(SEALED_IN_CLEAR);
            }
        }

        target.reserve(pairs.iter().map(|pair| pair.len().saturating_add(1)).sum());
        // A fragment stays where it is while the pairs are appended after it; one in-place rotation
        // puts it back at the end, so no copy of it is allocated. The query state is read from the
        // part before the fragment, then follows what is appended.
        let end = target
            .iter()
            .position(|b| *b == b'#')
            .unwrap_or(target.len());
        let fragment = target.len() - end;
        let mut query = target[..end].contains(&b'?');
        let mut last = target[..end].last().copied();
        for pair in &pairs {
            let at = pair.iter().position(|b| *b == b'=').ok_or(SEAL_BROKEN)?;
            if !query {
                target.push(b'?');
                query = true;
            } else if !matches!(last, Some(b'?' | b'&')) {
                target.push(b'&');
            }
            target.extend_from_slice(&pair[..=at]);
            let value = &pair[at + 1..];
            if sealing && !value.is_empty() {
                let seal = self.hold(stream, value.len()).ok_or(RANDOM_FAILED)?;
                target.extend_from_slice(&seal.filler);
                seal.value.extend_from_slice(value);
            } else {
                target.extend_from_slice(value);
            }
            last = target.last().copied();
        }
        target[end..].rotate_left(fragment);
        Ok(true)
    }

    /// SEAL `opening`: the sealed-fields field is taken out; when `sealing` (the framer renders
    #[cfg(test)]
    pub(crate) fn seal(
        &mut self,
        opening: &mut Option<Opening>,
        sealing: bool,
        secured: bool,
    ) -> Result<(), &'static str> {
        let Some((fields, _)) = opening.as_mut() else {
            return Ok(());
        };
        let names = take_sealed_names(fields);
        self.seal_names(0, opening, &names, sealing, secured)
    }

    /// Seal the named fields after the connector retained their header classification.
    pub(crate) fn seal_names(
        &mut self,
        stream: u64,
        opening: &mut Option<Opening>,
        names: &[String],
        sealing: bool,
        secured: bool,
    ) -> Result<(), &'static str> {
        let Some((fields, _)) = opening.as_mut() else {
            return Ok(());
        };
        if names.is_empty() || !sealing {
            return Ok(());
        }
        let named = |n: &str| names.iter().any(|s| s.eq_ignore_ascii_case(n.trim()));
        if !fields.iter().any(|(n, v)| named(n) && !v.is_empty()) {
            return Ok(());
        }
        if !secured {
            return Err(SEALED_IN_CLEAR);
        }
        for (_, v) in fields.iter_mut().filter(|(n, v)| named(n) && !v.is_empty()) {
            let seal = self.hold(stream, v.len()).ok_or(RANDOM_FAILED)?;
            // The real bytes go into the seal's wiping buffer; the field's own bytes are then
            // written over with the filler (the same length), so the credential leaves the field
            // without a copy left behind in it.
            seal.value.extend_from_slice(v);
            v.copy_from_slice(&seal.filler);
        }
        Ok(())
    }

    /// Whether any seal waits to be spliced.
    pub(crate) fn pending(&self) -> bool {
        self.live != 0
    }

    pub(crate) fn pending_on(&self, stream: u64) -> bool {
        self.counts.contains_key(&stream)
    }

    pub(crate) fn streams(&self) -> Vec<u64> {
        crate::off_path::seal::pending_streams(&self.held[..self.live])
    }

    /// Clear every seal `stream` holds: each is emptied (its value wiped) and its slot kept.
    pub(crate) fn clear_on(&mut self, stream: u64) {
        self.retain(|_, seal| seal.stream != stream);
        self.counts.remove(&stream);
    }

    /// SPLICE every pending seal whose filler `wire` holds: the real bytes over the filler, in
    pub(crate) fn splice(&mut self, wire: &mut [u8]) -> Result<(), &'static str> {
        // The connection's reused list of where each seal's filler stands in `wire`.
        let mut positions = std::mem::take(&mut self.positions);
        positions.clear();
        for s in &self.held[..self.live] {
            let n = s.filler.len();
            let mut at = wire.windows(n).enumerate().filter(|(_, w)| *w == s.filler);
            match (at.next().map(|(i, _)| i), at.next()) {
                (Some(i), None) => positions.push(Some(i)),
                (Some(_), Some(_)) => {
                    self.positions = positions;
                    return Err(SEAL_BROKEN);
                }
                (None, _) => positions.push(None),
            }
        }
        // A spliced seal leaves (emptied, its slot kept); one whose filler is not in `wire` stays.
        self.retain(|at, seal| match positions[at] {
            Some(i) => {
                wire[i..i + seal.filler.len()].copy_from_slice(&seal.value);
                false
            }
            None => true,
        });
        self.positions = positions;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/seal_tests.rs"]
mod tests;
