// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `secret`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::contract_kind_conformance`. This file is
//! THE SAME FILE, modulo the kind's name and trait, in every crate of the four kinds whose
//! `busbar-contract` trait has no implementor.
//!
//! # THIS TEST IS RED ON PURPOSE, AND FOR TWO REASONS HERE
//!
//! First, `kinds::Secret` is implemented nowhere in the workspace. Second, and this crate is the
//! sharper case: it is a `SecretRef` TYPE crate with no `Secret` impl at all, classified into the
//! `secret` kind by a directory glob rather than by a declaration — the exact defect
//! `PLUGIN-TREE.md` §9 records against "kind by glob, not declaration", whose answer is to fold
//! `SecretRef` into `busbar-contract` and delete the crate. Until one of those two things happens,
//! this row is red and says which.

use busbar_plugin_testkit::contract_kind_conformance as conf;

#[test]
fn the_kinds_contract_trait_has_an_implementor() {
    conf::assert_contract_trait_implemented("secret", "Secret", None);
}
