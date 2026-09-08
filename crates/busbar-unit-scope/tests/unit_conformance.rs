// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `unit`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::unit_conformance`. This file is THE SAME
//! FILE, modulo this crate's own type and step, in every sibling of the kind — so a ruling added to
//! the battery reaches all fourteen crates on their next build instead of being hand-copied
//! fourteen times and drifting, which is exactly what `kind-isolation:testkit` found.
//!
//! Its own `tests/` file rather than a second inline `mod` in `src/lib.rs`, following
//! `crates/store-memory/tests/store_conformance.rs` — the one battery the tree already had.
//!
//! This crate is the kind's WORKED EXAMPLE for the answer half: it owns its step and its input is
//! two plain values, so it runs the whole battery. See the note in `every_input_is_answered`.

use busbar_caps::step::Approve;
use busbar_caps::{KernelSeal, StepName, Unit, UnitToken};
use busbar_plugin_testkit::unit_conformance as conf;
use busbar_unit_scope::unit::{ApproveInput, ScopeUnit};
use busbar_unit_scope::{Grants, Scope};

#[test]
fn the_kind_has_one_entry_and_it_names_its_own_step() {
    conf::assert_owns_one_step::<ScopeUnit>(StepName::Approve);
}

/// Every input of the step is answered — with a decision or a refusal, never a panic, never a
/// block, never a clock read.
///
/// Four inputs: what the caller holds crossed with what the operation needs, both rungs of a
/// two-rung chain. `Full` over `ReadOnly` proceeds and `ReadOnly` under `Full` refuses, so both
/// arms of the answer are exercised rather than only the happy one.
#[test]
fn every_input_is_answered() {
    let seal = KernelSeal::acquire_for_kernel();
    let token = UnitToken::<Approve>::mint(&seal);
    for held in [
        Grants::default(),
        Grants::of(Scope::ReadOnly),
        Grants::of(Scope::Full),
    ] {
        for needed in [Scope::ReadOnly, Scope::Full] {
            conf::assert_answers(StepName::Approve, || {
                ScopeUnit.decide(&token, ApproveInput { held, needed })
            });
        }
    }
}
