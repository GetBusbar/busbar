// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TRANSPORT ENTRY AS THE BOOT FOLD ADMITS IT: [`HostWire`] is the composition root's record of one
//! transport entry the connector serves over the host's sockets, built once per entry at boot
//! (the root's `root::doors::{build, served}`) and nothing more. Building one is the check
//! that the entry may be served at all: it states a claim (its registry key is its first), and it
//! names no transport it composes over (`BUSBAR-1.6.0.md` TRANSPORT-STACK (2): every entry states an
//! EMPTY `composes_over`, and the carrier is the connector's choice from the target's scheme).
//!
//! It carries no connection, dials nothing and holds no socket. Every connection an entry serves is
//! the connector's own: dialled by the connector's dial path or accepted by its listener
//! ([`crate::listen`]), and composed carrier -> \[TLS\] -> framer ([`crate::compose`]).

use crate::framer::FramerDoor;

/// One transport entry the boot fold admitted: its registry key, read off its door's facts.
pub struct HostWire {
    key: &'static str,
}

impl std::fmt::Debug for HostWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostWire").field("key", &self.key).finish()
    }
}

impl HostWire {
    /// The entry behind `door`, admitted to be served over the host's sockets. Its registry key is
    /// its first claim.
    ///
    /// # Errors
    ///
    /// The entry states no claim, or names another transport it composes over (no transport names
    /// another: the carrier is the connector's choice).
    pub fn new(door: &dyn FramerDoor) -> Result<Self, String> {
        let facts = door.facts();
        let Some(&key) = facts.claims.first() else {
            return Err(format!("transport `{}` states no claim", facts.name));
        };
        if !facts.composes_over.is_empty() {
            return Err(format!(
                "transport `{}` names a transport it composes over; no transport names another \
                 (the carrier is the connector's choice from the target's scheme)",
                facts.name
            ));
        }
        Ok(Self { key })
    }

    /// The entry's registry key: its first claim.
    #[must_use]
    pub fn key(&self) -> &'static str {
        self.key
    }
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod tests;
