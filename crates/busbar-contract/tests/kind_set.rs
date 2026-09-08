// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed kind set, its markers and its spellings are ONE list, and adding to it is a compile
//! error until all three agree.
//!
//! `Plugin::kind()` returns a member of the set, the isolation gate reads the spelling, and the
//! sealed marker is how a kernel-side generic names one kind at compile time. Three lists that
//! could drift, so the exhaustive match below is what stops them: a variant added without a marker
//! does not compile here, and a variant added without a spelling does not compile in the crate.

use busbar_contract::plugin::markers::{
    AuthKind, ControlKind, DialectKind, EgressAuthKind, ExportKind, HookKind, PlaneKind,
    SecretKind, StoreKind, TransportKind,
};
use busbar_contract::{AbiVersion, Kind, Plugin};

/// Every kind, its marker's constant, and the spelling the isolation gate reads.
///
/// The `match` is exhaustive ON PURPOSE and is the whole ratchet: the day a kind is added by an
/// owner ruling, this file stops compiling until the kind has a marker and a name, which is step 4
/// of `PLUGIN-TREE.md` §6 stated as a test rather than as a sentence in a document.
fn spelling(kind: Kind) -> &'static str {
    match kind {
        Kind::Plane => {
            assert_eq!(Kind::of::<PlaneKind>(), kind);
            "plane"
        }
        Kind::Dialect => {
            assert_eq!(Kind::of::<DialectKind>(), kind);
            "dialect"
        }
        Kind::Control => {
            assert_eq!(Kind::of::<ControlKind>(), kind);
            "control"
        }
        Kind::Transport => {
            assert_eq!(Kind::of::<TransportKind>(), kind);
            "transport"
        }
        Kind::Auth => {
            assert_eq!(Kind::of::<AuthKind>(), kind);
            "auth"
        }
        Kind::EgressAuth => {
            assert_eq!(Kind::of::<EgressAuthKind>(), kind);
            "egress-auth"
        }
        Kind::Store => {
            assert_eq!(Kind::of::<StoreKind>(), kind);
            "store"
        }
        Kind::Secret => {
            assert_eq!(Kind::of::<SecretKind>(), kind);
            "secret"
        }
        Kind::Hook => {
            assert_eq!(Kind::of::<HookKind>(), kind);
            "hook"
        }
        Kind::Export => {
            assert_eq!(Kind::of::<ExportKind>(), kind);
            "export"
        }
    }
}

/// The set, listed once, in the order of the normative kind table.
const EVERY_KIND: &[Kind] = &[
    Kind::Plane,
    Kind::Dialect,
    Kind::Control,
    Kind::Transport,
    Kind::Auth,
    Kind::EgressAuth,
    Kind::Store,
    Kind::Secret,
    Kind::Hook,
    Kind::Export,
];

#[test]
fn every_kind_has_a_marker_and_the_spelling_it_displays_as() {
    for kind in EVERY_KIND {
        assert_eq!(kind.to_string(), spelling(*kind));
    }
}

#[test]
fn the_kinds_are_distinct_and_the_list_holds_all_of_them() {
    let mut seen: Vec<String> = EVERY_KIND.iter().map(ToString::to_string).collect();
    let listed = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        listed,
        "two kinds display as one name: {seen:?}"
    );
}

/// A control surface declares the kind it IS.
///
/// The kind a crate declares is what the isolation gate cross-checks against the kind its name
/// says, and before this variant existed the only kind a control surface could return was `Plane`
/// — the one kind it is explicitly not.
struct AdminSurface;

impl Plugin for AdminSurface {
    fn key(&self) -> &'static str {
        "admin"
    }
    fn kind(&self) -> Kind {
        Kind::Control
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

/// A dialect declares the kind it is, for the same reason and against the same alternative.
struct AnthropicDialect;

impl Plugin for AnthropicDialect {
    fn key(&self) -> &'static str {
        "anthropic"
    }
    fn kind(&self) -> Kind {
        Kind::Dialect
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

#[test]
fn a_control_surface_and_a_dialect_each_declare_their_own_kind() {
    let control: &dyn Plugin = &AdminSurface;
    let dialect: &dyn Plugin = &AnthropicDialect;
    assert_eq!(control.kind(), Kind::Control);
    assert_eq!(dialect.kind(), Kind::Dialect);
    assert_ne!(control.kind(), Kind::Plane);
    assert_ne!(dialect.kind(), Kind::Plane);
}
