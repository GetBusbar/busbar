//! One object-safety fixture per remaining kind trait.
//!
//! The honesty table of the design lists object safety as a compile-time property proven by a
//! fixture per kind. That is what the assertions below are: each one only compiles if the trait
//! can be used behind a pointer, which is how the registry holds every plugin.

use busbar_contract::bounded::PlaneAlloc;
use busbar_contract::kinds::{Challenge, ChallengeState, Head, SecretRef, StoreError};
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

// ── the fixture per kind: each of these only compiles if the trait is object-safe ─────────────

const _PLUGIN: Option<&dyn Plugin> = None;
const _PLANE_ALLOC: Option<&dyn PlaneAlloc> = None;

// ── a plane's and a transport's declarations ──────────────────────────────────────────────────

/// A plane's declarations. A plane is a memory-ABI door, not a trait object, so what a fixture can
/// state of one is its kind and its declared facts.
struct FixturePlane;

impl Plugin for FixturePlane {
    fn key(&self) -> &'static str {
        "fixture"
    }
    fn kind(&self) -> Kind {
        Kind::Plane
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

/// A transport's declarations. A transport is a memory-ABI framer door, not a trait object (step
/// 36), so what a fixture can state of one is its kind and its declared facts.
struct FixtureTransport;

impl Plugin for FixtureTransport {
    fn key(&self) -> &'static str {
        "fixture"
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

// ── the tests ─────────────────────────────────────────────────────────────────────────────────

/// A plugin can be held behind a pointer, which is how the registry holds one.
#[test]
fn a_plugin_is_object_safe() {
    let plugin: &dyn Plugin = &FixturePlane;

    assert_eq!(plugin.kind(), Kind::Plane);
    assert_eq!(plugin.key(), "fixture");
}

/// The kind a plugin reports matches the kind of the marker it implements.
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
    let _ = SecretRef::file("fixture://key");
    let _: Result<Head, StoreError> = Err(StoreError::Unavailable);
}
