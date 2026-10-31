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
use zeroize::{Zeroize as _, Zeroizing};

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
    /// SEAL `opening`: the sealed-fields field is taken out; when `sealing` (the framer renders
    /// sealed values), each named field's value becomes filler and its real bytes are held here.
    /// `secured` = the host secures the connection the opening rides.
    ///
    /// # Errors
    ///
    /// [`SEALED_IN_CLEAR`] for a sealed value on a connection the host does not secure; a failed
    /// random source.
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

    /// SPLICE every pending seal whose filler `wire` holds: the real bytes over the filler, in
    /// place. A seal found is done.
    ///
    /// # Errors
    ///
    /// [`SEAL_BROKEN`] when a filler appears more than once.
    pub(crate) fn splice(&mut self, wire: &mut [u8]) -> Result<(), &'static str> {
        let mut broken = false;
        self.0.retain(|s| {
            let n = s.filler.len();
            let mut at = wire.windows(n).enumerate().filter(|(_, w)| *w == s.filler);
            match (at.next().map(|(i, _)| i), at.next()) {
                (Some(i), None) => {
                    wire[i..i + n].copy_from_slice(&s.value);
                    false
                }
                (Some(_), Some(_)) => {
                    broken = true;
                    true
                }
                (None, _) => true,
            }
        });
        if broken {
            return Err(SEAL_BROKEN);
        }
        Ok(())
    }

    /// Forget every pending seal (the connection failed): their real bytes are wiped.
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
}

/// Wipe `wire` once it was written: it may hold spliced credential bytes.
pub(crate) fn wipe(wire: &mut Vec<u8>) {
    wire.zeroize();
}

#[cfg(test)]
#[path = "tests/seal_tests.rs"]
mod tests;
