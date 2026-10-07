// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO VERB NAMES A PLANE OR A PROTOCOL — proven on the REAL shipped roster.
//!
//! The half of `src/tests/operation_tests.rs::no_verb_name_carries_a_protocol_identity` that needs
//! the real roster registered. The unit test reads the protocol names off core's own test registry;
//! the plane keys (one of them a plane core's unit test binary never registers) are only
//! enumerable once the planes install their test seams, which is an integration-test target's job
//! (see `plane_dispatch_cross_plane.rs`'s header for the same move).

mod linked;

use busbar_kernel::operation::OpVerb;

/// Register the real roster in the process registry — idempotent (first-wins).
fn register_planes() {
    linked::install();
}

/// No kernel verb may carry a plane key or a dialect the fallback plane declares, or a dashboard
/// would read a label claiming the engine knows which protocol it is serving.
#[test]
fn no_verb_name_carries_a_plane_key_or_a_protocol_name() {
    register_planes();
    // The keys come from the roster just registered, never from literals here.
    let plane_keys: Vec<&'static str> = busbar_kernel::plane::plane_keys().collect();
    assert!(
        plane_keys.len() >= 3,
        "the registered roster declares at least three plane keys: {plane_keys:?}"
    );
    let mut identities: Vec<&'static str> = plane_keys.clone();
    // The fallback plane's declared dialects: the protocol names a label could carry.
    identities.extend(busbar_kernel::plane::fallback_wire_formats());
    assert!(
        identities.len() > plane_keys.len(),
        "the fallback plane's dialects folded in: {identities:?}"
    );
    // The kernel's own verbs. The classes a plane declares are checked against its own dialects
    // beside its declaration (`busbar-plane-llm/tests/operation_labels.rs`).
    let verbs: Vec<OpVerb> = OpVerb::ALL.to_vec();
    for verb in verbs {
        let name = verb.name();
        for forbidden in &identities {
            assert!(
                !name.contains(forbidden),
                "`{name}` names the `{forbidden}` plane or protocol; verbs are shapes plus neutral words"
            );
        }
    }
}
