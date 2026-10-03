// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AGENT CARDS THE PLANE HOLDS, in plugin-owned memory (ARCHITECT ruling B2): the mirror of the
//! `card` host records ([`crate::records::KIND_CARD`], keyed by agent id, operator scope), which the
//! card fetch writes on the plane's tick, never inside a request. A held card is valid to the
//! refresh generation it was held under: `arrive` does no I/O and reads only this memory, and a
//! card held under another generation is not read.

use std::sync::Arc;

use busbar_contract::abi::sdk::publish::Keyed;
use serde_json::Value;

/// The most cards held at once; past it, the smallest agent ids are dropped first.
pub const MAX_CARDS: usize = 4096;

/// The held cards, by agent id, each with the generation it was held under.
#[derive(Debug, Default)]
pub struct Cards {
    by_agent: Keyed<String, (u64, Arc<Value>)>,
}

impl Cards {
    /// No card held.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `card` for `agent` under `generation`, in place of any earlier one.
    pub fn hold(&self, agent: &str, generation: u64, card: Value) {
        self.by_agent.with_all(|m| {
            while m.len() >= MAX_CARDS && !m.contains_key(agent) {
                if m.pop_first().is_none() {
                    break;
                }
            }
            m.insert(agent.to_string(), (generation, Arc::new(card)));
        });
    }

    /// The card held for `agent` under `generation`; `None` when none is, or it was held under
    /// another generation.
    #[must_use]
    pub fn at(&self, agent: &str, generation: u64) -> Option<Arc<Value>> {
        self.by_agent
            .get(&agent.to_string())
            .filter(|(held, _)| *held == generation)
            .map(|(_, card)| card)
    }

    /// Drop every card held under `generation` (its retire).
    pub fn retire(&self, generation: u64) {
        self.by_agent
            .with_all(|m| m.retain(|_, (held, _)| *held != generation));
    }
}

#[cfg(test)]
#[path = "tests/cards_tests.rs"]
mod tests;
