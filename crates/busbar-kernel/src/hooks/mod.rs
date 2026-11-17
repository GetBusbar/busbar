// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the native hook bindings share of the hook vocabulary: the signal catalog and its
//! requested-signal mask, the pool strategy-word resolution, the bounded tap spawner and the
//! plugin text-cut report. The kernel opens no hook itself; the native bindings
//! ([`crate::plane_driver::native_hook_bindings`]) are the only hook path.

pub mod strategy;
pub mod taps;
pub mod text_cut;

pub use busbar_contract::signal::{Signal, SignalBag, SignalValue};

/// The per-generation, config-derived UNION of every hook's declared [`Signal`] set — a dense
/// bitmask ("which catalog entries does ANYTHING configured on this generation want"), consulted
/// with a single `AND`+compare BEFORE any compute fn runs ([`RequestedSignals::wants`]), never
/// call-then-discard. Each native hook call carries the mask of the signals its own definition
/// declares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestedSignals(u64);

impl RequestedSignals {
    #[inline]
    pub fn wants(self, s: Signal) -> bool {
        debug_assert!(
            s.bit() < 64,
            "Signal::bit() exceeded the u64 bitmask width; grow RequestedSignals to a bitset"
        );
        self.0 & (1u64 << s.bit()) != 0
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn insert(&mut self, s: Signal) {
        self.0 |= 1u64 << s.bit();
    }
}
