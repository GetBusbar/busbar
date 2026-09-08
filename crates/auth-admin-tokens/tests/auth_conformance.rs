// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `auth`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::contract_kind_conformance`. This file is
//! THE SAME FILE, modulo the kind's name and trait, in every crate of the four kinds whose
//! `busbar-contract` trait has no implementor.
//!
//! # THIS TEST WOULD BE RED, AND IS `#[ignore]`d RATHER THAN DELETED
//!
//! `kinds::AuthScheme` is implemented NOWHERE in the workspace except `busbar-contract`'s own
//! object-safety fixtures; this crate sits on the retiring `busbar_api` ABI. `PLUGIN-TREE.md` §8
//! prices the re-base at ~250 lines and puts it on track R5. Until it lands, the `auth` kind's
//! boundaries are policed around a trait nothing implements.
//!
//! The assertion is kept INTACT and ignored, not weakened: a red `cargo test --workspace` blocks
//! every landing, so this debt is carried by the ship gate and by the ignore REASON — which names
//! the trait — rather than by a failing binary. The day this crate implements its kind's trait, the
//! `#[ignore]` comes off and the same line passes. Nothing else has to change.

use busbar_plugin_testkit::contract_kind_conformance as conf;

#[test]
#[ignore = "not yet on busbar-contract: AuthScheme has no implementor here; the kind-isolation:testkit row carries this red"]
fn the_kinds_contract_trait_has_an_implementor() {
    conf::assert_contract_trait_implemented("auth", "AuthScheme", None);
}
