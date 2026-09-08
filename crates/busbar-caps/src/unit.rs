// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE trait a `busbar-unit-*` crate implements — the `unit` row of the plugin tree.
//!
//! # Why this is the whole seam
//!
//! `docs/design/PLUGIN-TREE.md` §2 says every plugin of every kind integrates with core the same
//! way: it DECLARES, it is CLAIMED, it is SEALED, and it is DRIVEN by the kernel loop and by
//! nothing else. Nine kinds reach that shape through one trait. The `unit` row did not: `impl Unit
//! for` appeared ZERO times in the tree, the fourteen `busbar-unit-*` crates each exposed an ad-hoc
//! step function under its own name, and the composition root wired each one by hand — so two
//! siblings of the kind were not the same shape, and no rule could say what a unit IS. [`Unit`] is
//! that one declaration.
//!
//! # Why it lives in `busbar-caps` and not in `busbar-contract`
//!
//! PLUGIN-TREE.md §1's unit row names `busbar-contract::unit` as the home. It cannot be: the answer
//! a unit gives is [`Decision<S>`](crate::decision::Decision) and the proof it is entitled to give
//! it is [`UnitToken<S>`](crate::token::UnitToken), and both live HERE — `busbar-caps` depends on
//! `busbar-contract`, never the reverse (the measured edge is `caps -> contract`). A `Unit` trait in
//! the contract would have to name types the contract sits below. PLUGIN-TREE.md's own precedence
//! rule settles it: "where the contract crates and this document disagree, the crates win". Both
//! crates sit under ONE surface ceiling (`surface-ceiling:contract+caps`), so the plugin author's
//! budget is unchanged by the choice.
//!
//! # Two roles, one shape — and why the tree really has two
//!
//! The loop has ten steps and the tree has fourteen unit crates, so they cannot be in bijection,
//! and the composition root's own table says so out loud (`crates/busbar/src/root/kernel.rs`:
//! "the breaker unit is consulted at Verify and recorded at Route without ever being a step of its
//! own"; "the WAL unit sits under the ledger on the durability path"; "the transport-key unit runs
//! at listen, dial and upgrade"). Seven crates OWN a step — auth, trust, scope, admission, egress,
//! usage, audit. Seven SERVE the unit that owns one — breaker, cost, egress-auth, ledger,
//! transport-key, verbs, wal.
//!
//! [`Unit::OWNS_ITS_STEP`] states which, and it is a `bool` on the one trait rather than a second
//! trait, because a second trait is exactly the one-off the ship criterion forbids. Both roles have
//! the same shape: asked at one step, handed everything they read, answering once.
//!
//! # What "sealed by token" means here, exactly
//!
//! [`Unit`] is NOT sealed on a private supertrait — a unit crate has to be able to implement it, so
//! sealing the trait would defeat the point. What is sealed is WHEN a unit may be asked and, for a
//! unit that owns its step, WHAT it may answer:
//!
//! - Every `decide` call is handed `&UnitToken<Self::Step>`. The loop mints that token for the
//!   length of one call and lends it by reference; no unit can hold, copy or forge one. So a unit
//!   is reachable only DURING its own step — that is true of both roles, and it is why a serving
//!   unit takes the token even where its own answer does not consume one.
//! - A unit with `OWNS_ITS_STEP = true` answers `Decision<Self::Step>`, and the only constructors
//!   of that type take the same token. It therefore cannot answer a step it was not asked.
//!
//! A serving unit's `Answer` is its own value — a priced posting, a sealed audit record, a journal
//! ack — because the step's `Facts` are the OWNING unit's to build and building them takes a token
//! (a hold takes the admit token, a destination takes the trust token) that a serving unit is
//! deliberately not lent. Widening `Answer` is what keeps that rule true; narrowing it to
//! `Decision` would have meant handing the breaker a trust token to say "the lane is open".
//!
//! # What a unit still may not do
//!
//! [`Unit::decide`] is synchronous and is handed everything it reads. It may not block, may not
//! perform I/O on the loop's thread, and may not read a wall clock — a step that needs the time is
//! handed it in [`Unit::Input`], which is why `busbar-unit-auth`'s request struct carries a
//! `now: u64` field rather than calling `SystemTime::now`. Route is the one step the loop AWAITS,
//! and it is awaited AROUND this call: the egress unit's `Answer` is the future, not its output.

use crate::step::{Step, StepName};
use crate::token::UnitToken;

/// One unit: the crate that is asked at exactly one step of the ten-step loop.
///
/// Every `busbar-unit-*` crate implements this exactly once, over the step function it already had.
/// Two siblings of the kind are then indistinguishable in shape — which is the ship criterion the
/// `kind-isolation:shape` row reads.
pub trait Unit {
    /// The one step of the loop this unit is asked at, as the type-level marker.
    ///
    /// This is the associated type that lets the loop PLACE the unit: a unit whose `Step` is
    /// [`Approve`](crate::step::Approve) is handed the approve token and no other, so if it owns
    /// its step it can build no other step's answer.
    type Step: Step;

    /// Everything this unit reads, borrowed for the length of the call.
    ///
    /// A generic associated type rather than a fixed struct: the seven owned steps are handed
    /// genuinely different facts (a credential and a clock reading; a principal and a candidate
    /// lane set; a hold slip), and flattening them into one struct would hand every unit the inputs
    /// of every other — the exact opposite of the capability rule this crate exists for.
    type Input<'a>
    where
        Self: 'a;

    /// What this unit hands back. `Decision<Self::Step>` exactly when [`Self::OWNS_ITS_STEP`].
    type Answer<'a>
    where
        Self: 'a;

    /// The step this unit is asked at, as a plain runtime name.
    ///
    /// Derived from [`Self::Step`] so it can never disagree with it; stated as a const so the loop
    /// can order and place units without naming their types.
    const STEP: StepName = <Self::Step as Step>::NAME;

    /// Whether this unit OWNS its step or SERVES the unit that owns it. See the module docs.
    const OWNS_ITS_STEP: bool;

    /// Answer once. Never panics, never blocks, never reads a clock.
    fn decide<'a>(
        &'a mut self,
        token: &'a UnitToken<Self::Step>,
        input: Self::Input<'a>,
    ) -> Self::Answer<'a>;
}
