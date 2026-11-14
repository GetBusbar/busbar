// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE COMPOSITION RULE A SERVED TRANSPORT ENTRY KEEPS: it names no layer. The carrier is the
//! connector's choice from the target's scheme, so an entry that composes over another is refused
//! where the connector opens it.

use crate::framer::FramerDoor;

/// Refuse `door` if it names a transport it composes over.
pub fn unlayered(door: &dyn FramerDoor) -> Result<(), String> {
    let facts = door.facts();
    if !facts.composes_over.is_empty() {
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: a load-time refusal of a transport entry"
        )]
        return Err(format!(
            "transport `{}` names a transport it composes over; no transport names another \
             (the carrier is the connector's choice from the target's scheme)",
            facts.name
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod tests;
