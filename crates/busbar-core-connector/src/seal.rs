// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALED CREDENTIAL VALUES (TSEAL; the "plane never sees credential bytes" family): the bound
//! auth's field values never cross to a framer that states it renders sealed values
//! (`abi::transport::EXT_SEALED_VALUES`). The opener names the fields whose values are credential
//! bytes ([`busbar_contract::conn::SEALED_FIELDS_FIELD`], the host's own field, taken out here and
//! never sent); each value is swapped, before the framer is handed anything, for FILLER of exactly
//! its length (random, in the field-value-safe alphabet `A-Za-z0-9`), and the real bytes are held
//! here, wiped when dropped. The framer renders the filler verbatim, exactly once, so every length
//! it writes is already right; the host SPLICES the real bytes over it in the framer's wire output
//! at the one place it is written into connection security, and wipes the spliced output once
//! written. A sealed value is never written in the clear: an open whose connection is not secured
//! by the host is refused before anything is framed ([`SEALED_IN_CLEAR`]), and an opening whose
//! filler the framer did not render exactly once is refused before its bytes leave
//! ([`SEAL_BROKEN`]).

use ring::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

use crate::compose::Opening;

/// The refusal of an open whose sealed values would cross a connection the host does not secure:
/// spliced there, the real bytes would reach the carrier plugin in the clear.
pub const SEALED_IN_CLEAR: &str = "a sealed credential is never written in the clear: the open's \
     connection is not secured by the host, so its carrier would read the credential";

/// The refusal of an opening whose filler the framer did not render verbatim exactly once.
pub const SEAL_BROKEN: &str = "the framer did not render a sealed value verbatim exactly once; \
     nothing of the message was sent";

/// The filler's alphabet: legal in any field value and never transformed by a literal rendering.
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// One sealed value: the filler the framer was handed and the real bytes it stands for.
struct Seal {
    stream: u64,
    filler: Vec<u8>,
    value: Zeroizing<Vec<u8>>,
}

/// THE SEALS A CONNECTION HOLDS: those not yet spliced into its wire.
#[derive(Default)]
pub(crate) struct Seals(Vec<Seal>);

impl std::fmt::Debug for Seals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Seals({} pending)", self.0.len())
    }
}

/// The names the opener's [`busbar_contract::conn::SEALED_FIELDS_FIELD`] states, taken out of
/// `fields` (every occurrence; the field is the host's and never sent).
pub(crate) fn take_sealed_names(fields: &mut Vec<(String, Vec<u8>)>) -> Vec<String> {
    let mut names = Vec::new();
    fields.retain(|(n, v)| {
        if busbar_contract::conn::is_sealed_fields_field(n.as_bytes()) {
            names.extend(
                String::from_utf8_lossy(v)
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty()),
            );
            false
        } else {
            true
        }
    });
    names
}

fn filler(len: usize) -> Option<Vec<u8>> {
    let mut bytes = vec![0_u8; len];
    SystemRandom::new().fill(&mut bytes).ok()?;
    for b in &mut bytes {
        *b = ALPHABET[usize::from(*b) % ALPHABET.len()];
    }
    Some(bytes)
}

impl Seals {
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
        let mut pairs = Vec::new();
        fields.retain_mut(|(name, value)| {
            if busbar_contract::conn::is_sealed_query_field(name.as_bytes()) {
                pairs.push(Zeroizing::new(std::mem::take(value)));
                false
            } else {
                true
            }
        });
        if pairs.is_empty() {
            return Ok(false);
        }
        // Validate before changing the target. Only the host's RFC3986 pair encoding is accepted.
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
        // Reserve before any credential is appended, so growth cannot free a prior secret copy.
        target.reserve(pairs.iter().map(|pair| pair.len().saturating_add(1)).sum());
        let fragment = target
            .iter()
            .position(|b| *b == b'#')
            .map(|at| target.split_off(at));
        for pair in &pairs {
            let at = pair.iter().position(|b| *b == b'=').ok_or(SEAL_BROKEN)?;
            if !target.contains(&b'?') {
                target.push(b'?');
            } else if !matches!(target.last(), Some(b'?' | b'&')) {
                target.push(b'&');
            }
            target.extend_from_slice(&pair[..=at]);
            let value = &pair[at + 1..];
            if sealing && !value.is_empty() {
                let fill = filler(value.len()).ok_or("the host's random source failed")?;
                target.extend_from_slice(&fill);
                self.0.push(Seal {
                    stream,
                    filler: fill,
                    value: Zeroizing::new(value.to_vec()),
                });
            } else {
                target.extend_from_slice(value);
            }
        }
        if let Some(fragment) = fragment {
            target.extend_from_slice(&fragment);
        }
        Ok(true)
    }

    /// SEAL `opening`: the sealed-fields field is taken out; when `sealing` (the framer renders
    /// sealed values), each named field's value becomes filler and its real bytes are held here.
    /// `secured` = the host secures the connection the opening rides.
    ///
    /// # Errors
    ///
    /// [`SEALED_IN_CLEAR`] for a sealed value on a connection the host does not secure; a failed
    /// random source.
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
            let value = Zeroizing::new(std::mem::replace(v, fill.clone()));
            self.0.push(Seal {
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
        self.0.iter().any(|seal| seal.stream == stream)
    }

    pub(crate) fn streams(&self) -> Vec<u64> {
        let mut streams = Vec::new();
        for seal in &self.0 {
            if !streams.contains(&seal.stream) {
                streams.push(seal.stream);
            }
        }
        streams
    }

    pub(crate) fn clear_on(&mut self, stream: u64) {
        self.0.retain(|seal| seal.stream != stream);
    }

    /// SPLICE every pending seal whose filler `wire` holds: the real bytes over the filler, in
    /// place. A seal found is done.
    ///
    /// # Errors
    ///
    /// [`SEAL_BROKEN`] when a filler appears more than once.
    pub(crate) fn splice(&mut self, wire: &mut [u8]) -> Result<(), &'static str> {
        let mut positions = Vec::with_capacity(self.0.len());
        for s in &self.0 {
            let n = s.filler.len();
            let mut at = wire.windows(n).enumerate().filter(|(_, w)| *w == s.filler);
            match (at.next().map(|(i, _)| i), at.next()) {
                (Some(i), None) => positions.push(Some(i)),
                (Some(_), Some(_)) => return Err(SEAL_BROKEN),
                (None, _) => positions.push(None),
            }
        }
        let mut positions = positions.into_iter();
        self.0.retain(|s| match positions.next().flatten() {
            Some(i) => {
                wire[i..i + s.filler.len()].copy_from_slice(&s.value);
                false
            }
            None => true,
        });
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/seal_tests.rs"]
mod tests;
