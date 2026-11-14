// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim doors, each one port bound once when the listener's binds are configured.

use std::sync::Arc;

use busbar_core_connector::udp::ReadyPort;

use crate::root::serve::serve_datagram::{ClaimDoor, ClaimDoors};

impl ClaimDoors {
    /// Key a claim door under `claim`, once, when its port is bound or shared.
    pub fn insert(&mut self, claim: &str, door: Arc<ClaimDoor>) {
        self.0.insert(claim.to_owned(), door);
    }

    /// Bind one port per datagram claim the binds name.
    pub fn bind(
        binds: &[crate::root::loader::boot::InboundBind],
        framer_for: impl Fn(&str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>>,
    ) -> Result<Self, String> {
        let mut doors = ClaimDoors::default();
        for b in binds {
            if b.transport.is_empty()
                || !framer_for(&b.transport).is_some_and(|d| d.facts().datagram)
            {
                continue;
            }
            if doors.0.contains_key(&b.transport) {
                return Err(format!(
                    "{}: a second claim door for `{}`",
                    b.listen_setting(),
                    b.transport
                ));
            }
            let port = busbar_core_connector::udp::bind(&b.listen.to_string())
                .and_then(ReadyPort::open)
                .map_err(|e| {
                    format!("{}: {} cannot be bound: {e}", b.listen_setting(), b.listen)
                })?;
            doors.insert(&b.transport, ClaimDoor::serve(port));
        }
        Ok(doors)
    }
}
