// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One object-safety fixture per kind trait.

use busbar_contract::bounded::PlaneAlloc;
use busbar_contract::kinds::{Challenge, ChallengeState, Head, SecretRef, StoreError};
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

const _PLUGIN: Option<&dyn Plugin> = None;
const _PLANE_ALLOC: Option<&dyn PlaneAlloc> = None;

/// The smallest plane: its declarations, nothing more.
struct FixturePlane;

impl Plugin for FixturePlane {
    fn key(&self) -> &'static str {
        "fixture"
    }
    fn kind(&self) -> Kind {
        Kind::Plane
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion::from_wire(1)
    }
}

/// A transport's declarations. A transport is a memory-ABI framer door, not a trait object (step
struct FixtureTransport;

impl Plugin for FixtureTransport {
    fn key(&self) -> &'static str {
        "fixture"
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion::from_wire(1)
    }
}

/// The kind a plugin reports matches the kind of the trait it implements.
#[test]
fn a_plugin_reports_the_kind_of_the_trait_it_implements() {
    assert_eq!(
        FixturePlane.kind(),
        Kind::of::<busbar_contract::plugin::markers::PlaneKind>()
    );
    assert_eq!(
        FixtureTransport.kind(),
        Kind::of::<busbar_contract::plugin::markers::TransportKind>()
    );
}

/// The shapes the other kinds hand back exist and are constructible.
#[test]
fn the_remaining_kinds_shapes_are_constructible() {
    let _ = Challenge {
        bytes: vec![1],
        state: ChallengeState(vec![2]),
        rounds_left: 1,
    };
    let _: SecretRef = busbar_contract::json::from_value(&busbar_contract::json::json!({
        "module":"fixture-source", "settings":{"slot":"fixture-key"}
    }))
    .unwrap();
    let _: Result<Head, StoreError> = Err(StoreError::Unavailable);
}
