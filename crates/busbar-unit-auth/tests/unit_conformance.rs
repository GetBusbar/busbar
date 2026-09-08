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

use busbar_caps::step::Authenticate;
use busbar_caps::{KernelSeal, StepName, Unit, UnitToken};
use busbar_plugin_testkit::unit_conformance as conf;
use busbar_unit_auth::unit::AuthInput;
use busbar_unit_auth::{Auth, AuthChain, AuthRequest};

#[test]
fn the_kind_has_one_entry_and_it_names_its_own_step() {
    conf::assert_owns_one_step::<Auth>(StepName::Authenticate);
}

/// Every input of the step is answered — with a decision or a refusal, never a panic, never a
/// block, never a clock read.
///
/// The clock reading is an INPUT (`AuthRequest::now`), which is the whole reason this unit can be
/// asked the same question twice and answer it the same way; a unit that called `SystemTime::now`
/// would fail the determinism arm of the battery here rather than in production.
#[test]
fn every_input_is_answered() {
    let seal = KernelSeal::acquire_for_kernel();
    let token = UnitToken::<Authenticate>::mint(&seal);
    for candidate in [None, Some("not-a-credential")] {
        for scheme in [None, Some("bearer")] {
            conf::assert_answers(StepName::Authenticate, || {
                // A FRESH unit per call, which is what makes the battery's determinism arm mean
                // something: a unit that carried an answer over from the previous call would agree
                // with itself for the wrong reason.
                let mut unit = Auth::new(AuthChain::new(Vec::new(), false));
                let req = AuthRequest {
                    candidate,
                    scheme,
                    declared_schemes: &["bearer"],
                    expected_aud: None,
                    in_handshake: false,
                    now: 1_700_000_000,
                    new_unit: true,
                };
                unit.decide(
                    &token,
                    AuthInput {
                        req: &req,
                        cache: None,
                        keys: None,
                        revocations: None,
                        pending: None,
                    },
                )
            });
        }
    }
}
