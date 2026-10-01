// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REGISTRY VIEW: which transport entry serves which scheme, and as which of its claims
//! (`BUSBAR-1.6.0.md` THE DESIGN, §5: one plugin is one entry, the schemes it serves are its claims;
//! two entries claiming one scheme refuse boot; no transport names another).
//!
//! Each entry comes with its registration: the protocols its connections offer in the TLS
//! handshake (the operator's settings, dealt at boot). Every layer an entry composes over must be
//! claimed by an entry here, or the view refuses it: a connection built over a layer nobody serves
//! would describe a stack that does not exist.

use std::sync::Arc;

use crate::framer::FramerDoor;

/// One entry, as the view holds it.
#[derive(Clone)]
pub struct Entry {
    /// The entry's table.
    pub door: Arc<dyn FramerDoor>,
    /// The protocols its connections offer in the TLS handshake, most preferred first.
    pub alpn: Vec<Vec<u8>>,
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
}

impl Transports {
    /// The view over `entries`.
    ///
    /// # Errors
    ///
    /// Two entries claim one scheme, an entry states no claim, or an entry composes over a claim
    /// no entry serves.
    pub fn new(entries: Vec<Entry>) -> Result<Self, ViewRefusal> {
        let view = Self { entries };
        let mut seen: Vec<(&str, &str)> = Vec::new();
        for e in &view.entries {
            let facts = e.door.facts();
            if facts.claims.is_empty() {
                return Err(ViewRefusal::NoClaim {
                    entry: facts.name.clone(),
                });
            }
            for scheme in &facts.claims {
                if let Some((_, first)) = seen.iter().find(|(s, _)| s == scheme) {
                    return Err(ViewRefusal::ClaimedTwice {
                        scheme: (*scheme).to_owned(),
                        first: (*first).to_owned(),
                        second: facts.name.clone(),
                    });
                }
                seen.push((scheme, &facts.name));
            }
        }
        for e in &view.entries {
            let facts = e.door.facts();
            if let Some(layer) = facts
                .composes_over
                .iter()
                .find(|l| !seen.iter().any(|(s, _)| s == *l))
            {
                return Err(ViewRefusal::UnservedLayer {
                    entry: facts.name.clone(),
                    layer: (*layer).to_owned(),
                });
            }
        }
        Ok(view)
    }

    /// The entry serving `scheme`, and as which claim.
    #[must_use]
    pub fn serving(&self, scheme: &str) -> Option<Served<'_>> {
        self.entries.iter().find_map(|entry| {
            let claim = entry
                .door
                .facts()
                .claims
                .iter()
                .position(|c| *c == scheme)?;
            Some(Served { entry, claim })
        })
    }

    /// Every scheme, the entry serving it and its claim index, in registration order.
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
