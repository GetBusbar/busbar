// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Building a pool and its members: once, when the pool configuration is loaded.

use crate::pool::{Failover, Member, OnExhausted, Pool};
use crate::ports::DestinationId;
use crate::select::WeightedFloor;

/// A configured name as shared text: made here once, as the pool is built.
fn shared(name: String) -> busbar_contract::kept::Text {
    busbar_contract::kept::Text::from(std::sync::Arc::<str>::from(name))
}

impl Member {
    /// A member with only the two things every member has.
    #[must_use]
    pub fn new(destination: DestinationId, name: impl Into<String>, weight: u32) -> Self {
        Self {
            destination,
            name: shared(name.into()),
            weight,
            tier: 0,
            attempt_timeout_ms: None,
            context_max: None,
            lane: None,
            passthrough: false,
        }
    }
}

impl Pool {
    /// A pool of these members with every default.
    #[must_use]
    pub fn new(name: impl Into<String>, members: Vec<Member>) -> Self {
        Self {
            name: shared(name.into()),
            members,
            failover: Failover::default(),
            on_exhausted: OnExhausted::default(),
            floor: WeightedFloor::default(),
            admissible: None,
            queued: crate::pool::QueueDepth::default(),
        }
    }

    /// Set what bounds the walk and apply its blocklist, once. A blocklist that names no member of
    /// this pool leaves `admissible` empty, so nothing is held twice. Call it after the members are
    /// final.
    pub fn set_failover(&mut self, failover: Failover) {
        let names_a_member = self
            .members
            .iter()
            .any(|member| failover.exclusions.iter().any(|name| member.name == *name));
        self.admissible = names_a_member.then(|| {
            self.members
                .iter()
                .filter(|member| !failover.exclusions.iter().any(|name| member.name == *name))
                .cloned()
                .collect()
        });
        self.failover = failover;
    }
}
