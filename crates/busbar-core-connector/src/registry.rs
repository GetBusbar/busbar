// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REGISTRY VIEW: which transport entry serves which scheme, and as which of its claims

use std::sync::Arc;

use foldhash::HashMap;

use crate::framer::FramerDoor;

/// One entry, as the view holds it.
#[derive(Clone)]
pub struct Entry {
    /// The entry's table.
    pub door: Arc<dyn FramerDoor>,
    /// The protocols its connections offer in the TLS handshake, most preferred first. Made once
    /// with the entry and shared (a reference count) by every declaration and dial that offers it.
    pub alpn: Arc<[Vec<u8>]>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("facts", self.door.facts())
            .finish_non_exhaustive()
    }
}

/// Which entry serves a scheme, and as which claim.
#[derive(Debug, Clone)]
pub struct Served<'a> {
    /// The entry.
    pub entry: &'a Entry,
    /// The index of the claim in the entry's claims (`0` = its own).
    pub claim: usize,
}

/// Why the view refused an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewRefusal {
    /// Two entries claim one scheme.
    ClaimedTwice {
        /// The scheme.
        scheme: String,
        /// The entry that claimed it first.
        first: String,
        /// The entry that claimed it again.
        second: String,
    },
    /// An entry composes over a claim no entry serves.
    UnservedLayer {
        /// The entry.
        entry: String,
        /// The layer it names.
        layer: String,
    },
    /// An entry states no claim.
    NoClaim {
        /// The entry.
        entry: String,
    },
}

impl std::fmt::Display for ViewRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimedTwice {
                scheme,
                first,
                second,
            } => write!(
                f,
                "transports `{first}` and `{second}` both claim the scheme `{scheme}`"
            ),
            Self::UnservedLayer { entry, layer } => write!(
                f,
                "transport `{entry}` composes over `{layer}`, which no transport serves"
            ),
            Self::NoClaim { entry } => write!(f, "transport `{entry}` states no claim"),
        }
    }
}

impl std::error::Error for ViewRefusal {}

/// The registry view.
#[derive(Debug, Clone, Default)]
pub struct Transports {
    entries: Vec<Entry>,
    /// Each claimed scheme: the index of the entry serving it, and of the claim in its claims. Built
    /// once with the view, so a dial's lookup never walks the entries.
    by_scheme: HashMap<&'static str, (usize, usize)>,
    /// The index of the address carrier ([`Self::address_carrier`]), found once with the view.
    carrier: Option<usize>,
}

impl Transports {
    /// The view over `entries`.
    pub fn new(entries: Vec<Entry>) -> Result<Self, ViewRefusal> {
        let mut by_scheme: HashMap<&'static str, (usize, usize)> = HashMap::default();
        for (at, e) in entries.iter().enumerate() {
            let facts = e.door.facts();
            if facts.claims.is_empty() {
                return Err(crate::cold::lines::no_claim(&facts.name));
            }
            for (claim, &scheme) in facts.claims.iter().enumerate() {
                match by_scheme.entry(scheme) {
                    std::collections::hash_map::Entry::Occupied(first) => {
                        let first = &entries[first.get().0].door.facts().name;
                        return Err(crate::cold::lines::claimed_twice(
                            scheme,
                            first,
                            &facts.name,
                        ));
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert((at, claim));
                    }
                }
            }
        }
        for e in &entries {
            let facts = e.door.facts();
            if let Some(layer) = facts
                .composes_over
                .iter()
                .find(|l| !by_scheme.contains_key(*l))
            {
                return Err(crate::cold::lines::unserved_layer(&facts.name, layer));
            }
        }
        let carrier = entries.iter().position(|e| {
            let f = e.door.facts();
            f.role == busbar_contract::abi::transport::ROLE_CARRIER && f.ported
        });
        Ok(Self {
            entries,
            by_scheme,
            carrier,
        })
    }

    /// The entry serving `scheme`, and as which claim.
    #[must_use]
    pub fn serving(&self, scheme: &str) -> Option<Served<'_>> {
        let &(at, claim) = self.by_scheme.get(scheme)?;
        Some(Served {
            entry: &self.entries[at],
            claim,
        })
    }

    /// The entry serving an outbound scheme, with its dialing capability declared.
    #[must_use]
    pub fn dialing(&self, scheme: &str) -> Option<Served<'_>> {
        self.serving(scheme)
            .filter(|served| served.entry.door.facts().supports_dial())
    }

    /// THE CARRIER OF A NETWORK ADDRESS: the first entry, in registration order, that is a CARRIER
    #[must_use]
    pub fn address_carrier(&self) -> Option<&Entry> {
        self.carrier.map(|at| &self.entries[at])
    }

    /// Every scheme, the entry serving it and its claim index, in registration order.
    #[cfg(test)]
    #[must_use]
    pub fn view(&self) -> Vec<(String, String, usize)> {
        self.entries
            .iter()
            .flat_map(|e| {
                let facts = e.door.facts();
                facts
                    .claims
                    .iter()
                    .enumerate()
                    .map(|(i, c)| ((*c).to_owned(), facts.name.clone(), i))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod tests;
