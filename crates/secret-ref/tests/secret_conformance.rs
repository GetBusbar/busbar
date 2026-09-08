// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `secret`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::contract_kind_conformance`. This file is
//! THE SAME FILE, modulo the kind's name and trait, in every crate of the four kinds whose
//! `busbar-contract` trait has no implementor.
//!
//! # THIS TEST WOULD BE RED FOR TWO REASONS, AND IS `#[ignore]`d RATHER THAN DELETED
//!
//! First, `kinds::Secret` is implemented nowhere in the workspace. Second, and this crate is the
//! sharper case: it is a `SecretRef` TYPE crate with no `Secret` impl at all, classified into the
//! `secret` kind by a directory glob rather than by a declaration — the exact defect
//! `PLUGIN-TREE.md` §9 records against "kind by glob, not declaration", whose answer is to fold
//! `SecretRef` into `busbar-contract` and delete the crate.
//!
//! The assertion is kept INTACT and ignored, not weakened: a red `cargo test --workspace` blocks
//! every landing, so this debt is carried by the ship gate and by the ignore REASON rather than by
//! a failing binary. Either resolution — the re-base, or the fold — removes the `#[ignore]` or the
//! whole crate.

use busbar_plugin_testkit::contract_kind_conformance as conf;

#[test]
#[ignore = "not yet on busbar-contract: Secret has no implementor here; the kind-isolation:testkit row carries this red"]
fn the_kinds_contract_trait_has_an_implementor() {
    conf::assert_contract_trait_implemented("secret", "Secret", None);
}
