// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-testkit/src/kinds.rs`.
//!
//! A battery is only worth calling if it FAILS on the thing it claims to catch, so every row below
//! is proven in both directions: a well-formed surface passes, and one that breaks exactly that row
//! panics with a message naming what it declared.

use crate::kinds::{control, dialect};
use busbar_contract::{AbiVersion, Kind, Plugin};

/// A well-formed plugin of any kind, parameterised by what it declares.
struct Decl {
    key: &'static str,
    kind: Kind,
    abi: u16,
}

impl Plugin for Decl {
    fn key(&self) -> &'static str {
        self.key
    }
    fn kind(&self) -> Kind {
        self.kind
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(self.abi)
    }
}

fn well_formed(kind: Kind) -> Decl {
    Decl {
        key: "fixture",
        kind,
        abi: 1,
    }
}

#[test]
fn a_well_formed_control_surface_passes_its_battery() {
    control(&well_formed(Kind::Control));
}

#[test]
fn a_well_formed_dialect_passes_its_battery() {
    dialect(&well_formed(Kind::Dialect));
}

/// THE ROW THE KIND EXISTS FOR. Before `Kind::Control` a control surface's only available
/// declaration was `Plane`; the battery is what says out loud that calling the control battery does
/// not make a plane a control surface.
#[test]
#[should_panic(expected = "this is the `control` battery and the plugin declares kind `plane`")]
fn a_plane_calling_the_control_battery_is_refused() {
    control(&well_formed(Kind::Plane));
}

#[test]
#[should_panic(expected = "this is the `dialect` battery and the plugin declares kind `plane`")]
fn a_plane_calling_the_dialect_battery_is_refused() {
    dialect(&well_formed(Kind::Plane));
}

/// The two new kinds are not each other either, which is the case a battery keyed on "is it one of
/// the new ones" would miss.
#[test]
#[should_panic(expected = "this is the `dialect` battery and the plugin declares kind `control`")]
fn a_control_surface_calling_the_dialect_battery_is_refused() {
    dialect(&well_formed(Kind::Control));
}

#[test]
#[should_panic(expected = "the empty key dispatches nothing")]
fn an_empty_registry_key_is_refused() {
    control(&Decl {
        key: "",
        kind: Kind::Control,
        abi: 1,
    });
}

#[test]
#[should_panic(expected = "registry keys are lowercase")]
fn a_mixed_case_registry_key_is_refused() {
    dialect(&Decl {
        key: "Anthropic",
        kind: Kind::Dialect,
        abi: 1,
    });
}

#[test]
#[should_panic(expected = "carries surrounding whitespace")]
fn a_registry_key_an_operator_cannot_retype_is_refused() {
    dialect(&Decl {
        key: "anthropic ",
        kind: Kind::Dialect,
        abi: 1,
    });
}

#[test]
#[should_panic(expected = "generation 0 is not a generation")]
fn an_undeclared_interface_generation_is_refused() {
    control(&Decl {
        key: "fixture",
        kind: Kind::Control,
        abi: 0,
    });
}
