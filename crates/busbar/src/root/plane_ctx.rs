// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-UNIT CONTEXT A PLANE CALL IS GIVEN, built by the root and by nothing else.
//!
//! ## Why this file exists
//!
//! `busbar_contract::Ctx::new` says in its own documentation that "the kernel builds every one of
//! these", and until now nothing on any serving path did: every construction in the workspace was a
//! test's. A plane cannot be asked what bytes mean without one — `decode_ingress`, `encode_response`
//! and `encode_refusal` all take a `&Ctx`, and the arena they allocate their answers out of is on it
//! — so "no production `Ctx`" and "no plane is driven by the root" were the same sentence said twice.
//!
//! This module is the first half of removing that sentence. It builds a real one, out of the four
//! things a root actually has at the moment an arrival lands: the node's clock, the transport facts
//! the arrival published, an empty label set, and a per-unit arena carved out of a space that lives
//! on the calling task's stack for exactly the length of the call.
//!
//! ## The arena is the whole shape of the API
//!
//! `busbar_kernel::arena::UnitArena` borrows its `ArenaSpace` and hands out slices that borrow the
//! arena. That is what makes it a *real* allocator rather than the leaking test doubles that stood
//! in for one — and it is also why this module offers a scope function rather than a value. Nothing
//! a plane allocates can outlive the call, because the compiler has already proved the space it came
//! out of has not been dropped. A caller that wants a plane's bytes copies them out inside the
//! closure; there is no way to write the mistake.
//!
//! ## What is deliberately answered with nothing, and why that is the honest answer
//!
//! [`Ctx::config`] is a plugin's own configuration block, and an arrival does not carry one: what
//! resolves a plane's block is the deployment's configuration, read at boot, keyed by the plane's
//! registry key. A context built from an arrival has not been told which plane it is for, so
//! [`NoConfig`] answers `None` to every key rather than inventing a block. A plane that needs its
//! own configuration on the request path needs the root to hand it one at composition, which is a
//! seam this module does not have and must not fake.
//!
//! [`Ctx::session`] is `None` for the same kind of reason: a mounted document surface is one-shot,
//! and a session is what a duplex transport opens. A one-shot arrival handed a session view would be
//! handed somebody else's.

use busbar_contract::bounded::Labels;
use busbar_contract::transport::Arrival;
use busbar_contract::unit::{Clock, ConfigView, Ctx, TransportView};
use busbar_kernel::arena::{ArenaSpace, UnitArena};

/// A plugin's own configuration block, for a call that has not been told which plugin it is for.
///
/// Every key answers `None`. That is not a stub: the alternative is a context that hands a plane a
/// block belonging to some other plane, or an empty block a plane cannot tell from a configured one.
/// A `None` is a plane reading its own defaults, which is exactly what a plane with no configured
/// block is supposed to do.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoConfig;

impl ConfigView for NoConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }

    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }

    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
}

/// The transport stack under one arrival, as the plane reads it.
///
/// A borrow of the arrival and nothing else. The key and the chain are the transport's own words for
/// what carried the bytes, and the facts are the ones the mount published — reserved keys first, in
/// the order the mount published them, which is why the lookup below is a linear first-match walk
/// rather than a map: the ordering IS the precedence, and a map would lose it.
#[derive(Debug, Clone, Copy)]
pub struct ArrivalTransport<'a> {
    key: &'static str,
    chain: &'a [&'static str],
    facts: &'a [(&'a str, &'a str)],
}

impl<'a> ArrivalTransport<'a> {
    /// The view over one arrival's published facts.
    #[must_use]
    pub fn new(arrival: &Arrival<'a>) -> Self {
        ArrivalTransport {
            key: arrival.transport,
            chain: arrival.chain,
            facts: arrival.facts,
        }
    }
}

impl TransportView for ArrivalTransport<'_> {
    fn key(&self) -> &'static str {
        self.key
    }

    fn chain(&self) -> &[&'static str] {
        self.chain
    }

    fn fact(&self, key: &str) -> Option<&str> {
        // First match wins, which is what makes the mount's ordering load-bearing rather than
        // cosmetic: a declaration free to name a capture `path` cannot hand a plane something other
        // than the request target.
        self.facts.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
}

/// Build one unit's context and run `call` inside it.
///
/// The one production construction of `busbar_contract::Ctx`. The space is a local, so the 4 KiB and
/// the span table are on the calling task's stack for the length of one arrival and are gone when it
/// returns — no pool, no allocation, and nothing shared between two units.
///
/// The closure is the API rather than a returned value because the arena's borrows are: a plane's
/// answer is a slice OF the space, so a signature that handed one back would be a signature the
/// borrow checker refuses. Copy what you need out before returning.
pub fn with_ctx<R>(arrival: &Arrival<'_>, clock: Clock, call: impl FnOnce(&Ctx<'_>) -> R) -> R {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);
    let config = NoConfig;
    let transport = ArrivalTransport::new(arrival);
    let labels = Labels::new();
    let ctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
    call(&ctx)
}

#[cfg(test)]
#[path = "tests/plane_ctx.rs"]
mod tests;
