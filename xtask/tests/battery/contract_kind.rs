// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// A BATTERY IS WRITTEN FOR THE KIND, NOT FOR TODAY'S CALLERS. Some arms below are owed by crates
// that cannot yet answer them, and an arm deleted for being uncalled today is a ruling deleted: the
// next crate to grow the fixture would have to re-derive it. `dead_code` is allowed HERE and
// nowhere else in this tree.
#![allow(dead_code)]

//! The shared batteries for the four kinds whose `busbar-contract` trait has ZERO implementors:
//! `auth`, `secret`, `hooks`, `export`.
//!
//! # Why a battery that is RED is the right answer here
//!
//! `docs/design/PLUGIN-TREE.md` §8 names six kinds that "have rules and gate rows but no crate
//! implementing their `busbar-core-contract` trait; the live plugins sit on the retiring
//! `busbar-api` ABI." Two of those six (store, and the transport row) have since moved. Four have
//! not: today `kinds::AuthScheme`, `kinds::Secret`, `kinds::Hook` and `kinds::Export` are
//! implemented **nowhere in the workspace except `busbar-contract`'s own object-safety fixtures**,
//! while `auth-admin-tokens`, `auth-static-plugin`, `secret-example-plugin`, `secret-ref`,
//! `hook-test-plugin`, `hooks-ranking` and `export-example-plugin` all sit on `busbar_api`.
//!
//! A battery that quietly skipped that would report a kind as conformant on the strength of a trait
//! nothing implements. So [`assert_contract_trait_implemented`] is RED, by construction, with the
//! reason named — and it goes green the day the kind's first crate is re-based, without anybody
//! remembering to come back and turn it on. That is the same ratchet the kind gate itself uses.
//!
//! What is NOT red is the half these crates can already answer: the universal config contract,
//! which `busbar-plugin-testkit` has held since 1.5 and which [`assert_universal_config`] wires so
//! a kind's block is one call rather than four.
//!
//! It is a module of the GATE RUNNER's test tree rather than of a shipped helper crate, because the
//! dependency has to run tooling -> plugin. See `tests/kind_conformance.rs`'s own header.

/// THE RED ROW: does this kind's `busbar-contract` trait have a shipping implementor at all?
///
/// `implementor` is the name of the type in THIS crate that implements the kind's
/// `busbar_contract::kinds` trait, or `None` where the crate still sits on the retiring
/// `busbar_api` ABI. `None` fails, and says why in the words a reader can act on.
///
/// The check is a value the caller states rather than a reflection over the crate, because a test
/// binary cannot enumerate its own trait impls — and stating it is the point: the day the re-base
/// lands, the same line that turned red is the line that turns green.
pub fn assert_contract_trait_implemented(
    kind: &str,
    contract_trait: &str,
    implementor: Option<&str>,
) {
    match implementor {
        Some(name) => assert!(
            !name.is_empty(),
            "kind `{kind}` named an empty implementor of `{contract_trait}`"
        ),
        None => panic!(
            "no implementor: kind `{kind}` has no crate implementing \
             `busbar_contract::kinds::{contract_trait}` — this crate is still on the retiring \
             `busbar_api` ABI. PLUGIN-TREE.md §8 prices the re-base; until it lands, the kind's \
             boundaries are policed around a trait nothing implements, and this battery says so \
             instead of passing."
        ),
    }
}

/// The universal config contract, for a kind whose crates expose the shared `open` seam.
///
/// One call instead of two in every conformance file, so a new universal check added to this crate
/// reaches every kind at once — which is the whole reason the batteries are shared.
///
/// **Not wired by any of the seven blocks today**, and that is the second half of the same finding:
/// none of `auth-admin-tokens`, `auth-static-plugin`, `secret-example-plugin`, `secret-ref`,
/// `hook-test-plugin`, `hooks-ranking` or `export-example-plugin` exposes an
/// `open(cfg) -> Result<_, String>` seam at all, so there is nothing for the universal battery to
/// be pointed at. It lands with the re-base, on the same line item.
pub fn assert_universal_config<T>(open: impl Fn(&str) -> Result<T, String> + Copy) {
    busbar_plugin_testkit::assert_empty_config_rejected(open);
    busbar_plugin_testkit::assert_malformed_json_rejected(open);
}
