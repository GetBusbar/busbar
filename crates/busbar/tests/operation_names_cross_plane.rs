// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO VERB NAMES A PLANE OR A PROTOCOL — proven on the REAL shipped roster.
//!
//! The plane keys and the dialects the planes declare are only enumerable once the real roster is
//! registered, which is an integration-test target's job (see `plane_dispatch_cross_plane.rs`'s
//! header for the same move).

mod linked;

use busbar_kernel::operation::OpVerb;

/// Register the real roster in the process registry — idempotent (first-wins).
fn register_planes() {
    linked::install();
}

/// The core's metric-label surface is `Operation::ALL`. No word on it may carry a plane key or a
/// dialect a registered plane declares, or a dashboard would read a label claiming the engine knows
/// which protocol it is serving. (A plane's own named verbs are its constants, and the plane's suite
/// holds them to the same rule over its own dialects.)
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
    identities.extend(busbar_kernel::plane::provider_dialects());
    for verb in OpVerb::ALL {
        let name = verb.name();
        for forbidden in &identities {
            assert!(
                !name.contains(forbidden),
                "`{name}` names the `{forbidden}` plane or protocol; verbs are shapes plus neutral words"
            );
        }
    }
}
