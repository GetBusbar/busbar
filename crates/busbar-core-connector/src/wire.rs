// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TRANSPORT ENTRY AS THE BOOT FOLD ADMITS IT: [`HostWire`] is the composition root's record of one

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
