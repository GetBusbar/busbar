// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALED CREDENTIAL VALUES (TSEAL; the "plane never sees credential bytes" family): the bound

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

/// One sealed value: the filler the framer was handed and the real bytes it stands for.
pub(crate) struct Seal {
    pub(crate) stream: u64,
    pub(crate) filler: Vec<u8>,
    pub(crate) value: SecureVec,
}

/// THE SEALS A CONNECTION HOLDS: those not yet spliced into its wire, the connection's reused list
/// of where each seal's filler stands, and how many seals wait on each stream (kept current as a
/// seal is held, spliced or cleared, so asking after a stream is no scan).
#[derive(Default)]
pub(crate) struct Seals(Vec<Seal>, Vec<Option<usize>>, HashMap<u64, usize>);

impl std::fmt::Debug for Seals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Seals({} pending)", self.0.len())
    }
}

pub(crate) use crate::off_path::seal::take_sealed_names;

fn filler(len: usize) -> Option<Vec<u8>> {
    let mut bytes = vec![0_u8; len];
    busbar_contract::crypto::fill(&mut bytes).ok()?;
    for b in &mut bytes {
        *b = ALPHABET[usize::from(*b) % ALPHABET.len()];
    }
    Some(bytes)
}

impl Seals {
    /// Hold `seal` until it is spliced or cleared.
    fn hold(&mut self, seal: Seal) {
        *self.2.entry(seal.stream).or_default() += 1;
        self.0.push(seal);
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
                let fill = filler(value.len()).ok_or("the host's random source failed")?;
                target.extend_from_slice(&fill);
                self.hold(Seal {
                    stream,
                    filler: fill,
                    value: SecureVec::from(value),
                });
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
            let fill = filler(v.len()).ok_or("the host's random source failed")?;
            let value = SecureVec::from(std::mem::replace(v, fill.clone()));
            self.hold(Seal {
                stream,
                filler: fill,
                value,
            });
        }
        Ok(())
    }

    /// Whether any seal waits to be spliced.
    pub(crate) fn pending(&self) -> bool {
        !self.0.is_empty()
    }

    pub(crate) fn pending_on(&self, stream: u64) -> bool {
        self.2.contains_key(&stream)
    }

    pub(crate) fn streams(&self) -> Vec<u64> {
        crate::off_path::seal::pending_streams(&self.0)
    }

    pub(crate) fn clear_on(&mut self, stream: u64) {
        self.2.remove(&stream);
        crate::off_path::seal::drop_stream(&mut self.0, stream);
    }

    /// SPLICE every pending seal whose filler `wire` holds: the real bytes over the filler, in
    pub(crate) fn splice(&mut self, wire: &mut [u8]) -> Result<(), &'static str> {
        // The connection's reused list of where each seal's filler stands in `wire`.
        let mut positions = std::mem::take(&mut self.1);
        positions.clear();
        for s in &self.0 {
            let n = s.filler.len();
            let mut at = wire.windows(n).enumerate().filter(|(_, w)| *w == s.filler);
            match (at.next().map(|(i, _)| i), at.next()) {
                (Some(i), None) => positions.push(Some(i)),
                (Some(_), Some(_)) => {
                    self.1 = positions;
                    return Err(SEAL_BROKEN);
                }
                (None, _) => positions.push(None),
            }
        }
        crate::off_path::seal::splice_found(&mut self.0, &positions, wire, &mut self.2);
        self.1 = positions;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/seal_tests.rs"]
mod tests;
