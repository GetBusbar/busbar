// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `hooks`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::contract_kind_conformance`. This file is
//! THE SAME FILE, modulo the kind's name and trait, in every crate of the four kinds whose
//! `busbar-contract` trait has no implementor.
//!
//! # THIS TEST IS RED ON PURPOSE
//!
//! `kinds::Hook` is implemented NOWHERE in the workspace except `busbar-contract`'s own
//! object-safety fixtures; this crate sits on the retiring `busbar_api` ABI. `PLUGIN-TREE.md` §8
//! prices the re-base at ~200 lines on track R5, with the seats coming from the four-seat table.

use busbar_plugin_testkit::contract_kind_conformance as conf;

#[test]
fn the_kinds_contract_trait_has_an_implementor() {
    conf::assert_contract_trait_implemented("hooks", "Hook", None);
}
