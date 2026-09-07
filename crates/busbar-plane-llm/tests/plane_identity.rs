// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the plane VALUE answers about itself, and what it answers about the upstreams it was
//! handed.
//!
//! Everything here is small enough to look like it cannot go wrong, which is exactly why none of it
//! was covered: the registration key, the kind, the ABI number and the first-upstream offer are all
//! one-line answers, and a one-line answer that changes silently is a plane that registers under
//! another plane's name or offers a unit no destination at all. Each of the four is pinned to the
//! one value the rest of the workspace reads it as.

use busbar_contract::ids::LaneId;
use busbar_contract::plane::PlaneMeta;
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use busbar_plane_llm::{LlmPlane, Upstream};

/// A configured upstream set with two entries, so "the first" is a choice and not the only one.
const UPSTREAMS: &[Upstream] = &[
    Upstream {
        lane: LaneId::new("lane-a"),
        host: "a.example",
        dialect: "anthropic",
        model: "model-a",
    },
    Upstream {
        lane: LaneId::new("lane-b"),
        host: "b.example",
        dialect: "openai",
        model: "model-b",
    },
];

/// The key the plugin answers to IS the key the plane declares, and it is the registry's `llm`.
///
/// The plugin trait's `key` and the plane's `KEY` are two different reads of one name — the
/// registry binds claims by the first and the composition root names the plane by the second — so a
/// key that drifted would register this plane's claims under a name nothing looks it up by. Both
/// spellings are asserted, and the literal is asserted too: a test that only checked the two
/// against each other would pass on a plane that renamed itself wholesale.
#[test]
fn the_plugin_key_is_the_plane_key_and_the_plane_key_is_llm() {
    let plane = LlmPlane::EMPTY;
    assert_eq!(plane.key(), <LlmPlane as PlaneMeta>::KEY);
    assert_eq!(plane.key(), "llm");
}

/// A plane registers as a PLANE, on the one ABI this workspace's loader accepts.
#[test]
fn the_plugin_registers_as_a_plane_on_abi_one() {
    let plane = LlmPlane::EMPTY;
    assert_eq!(plane.kind(), Kind::Plane);
    assert_eq!(plane.abi(), AbiVersion(1));
}

/// A configured plane offers its FIRST upstream, in declaration order, and the empty one offers
/// none.
///
/// Declaration order is the operator's own ordering: the plane filters on nothing and narrows on
/// nothing, so "the first" is the whole of the answer. A plane that answered `None` with upstreams
/// configured would leave every unit with no destination — a refusal that looks exactly like a
/// misconfiguration and is not one.
#[test]
fn the_first_configured_upstream_is_what_a_unit_is_offered() {
    let configured = LlmPlane::new(UPSTREAMS);
    let first = configured
        .first_upstream()
        .expect("a configured plane offers its first upstream");
    assert_eq!(first.host, "a.example");
    assert_eq!(first.dialect, "anthropic");
    assert_eq!(first.model, "model-a");
    assert_eq!(first.lane, LaneId::new("lane-a"));
    assert_eq!(first, &UPSTREAMS[0]);

    assert_eq!(LlmPlane::EMPTY.first_upstream(), None);
}

/// The configured list is handed back whole and in order, and the empty plane's is empty.
#[test]
fn the_configured_upstreams_are_returned_in_declaration_order() {
    assert_eq!(LlmPlane::new(UPSTREAMS).upstreams(), UPSTREAMS);
    assert!(LlmPlane::EMPTY.upstreams().is_empty());
}

/// The default plane is the EMPTY one, not a plane with an invented upstream in it.
#[test]
fn the_default_plane_is_the_empty_one() {
    assert_eq!(LlmPlane::default(), LlmPlane::EMPTY);
    assert_eq!(LlmPlane::default().upstreams().len(), 0);
}
