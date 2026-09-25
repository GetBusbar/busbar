// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO VERB NAMES A PLANE OR A PROTOCOL — proven on the REAL shipped `[llm, mcp, a2a]` roster.
//!
//! The half of `src/tests/operation_tests.rs::no_verb_name_carries_a_protocol_identity` that needs
//! the real roster registered. The unit test reads the protocol names off core's own test registry;
//! the plane keys (`a2a` among them, whose plane core's unit test binary never registers) are only
//! enumerable once the planes install their test seams, which is an integration-test target's job
//! (see `plane_dispatch_cross_plane.rs`'s header for the same move).

use busbar_kernel::operation::Operation;

/// Register the real roster in the process registry — idempotent (first-wins).
fn register_planes() {
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
}

/// The closed metric-label surface is `Operation::ALL ∪ declared_verbs()`. No word on it may carry a
/// plane key or a registered protocol name, or a dashboard would read a label claiming the engine
/// knows which protocol it is serving.
#[test]
fn no_verb_name_carries_a_plane_key_or_a_protocol_name() {
    register_planes();
    let mut identities: Vec<&'static str> = busbar_kernel::plane::plane_keys().collect();
    identities.extend(
        busbar_kernel::proto::registry::registry()
            .decls()
            .iter()
            .map(|d| d.name),
    );
    for key in ["llm", "mcp", "a2a"] {
        assert!(
            identities.contains(&key),
            "{key} is missing from the roster's identities: {identities:?}"
        );
    }
    let verbs: Vec<Operation> = Operation::ALL
        .iter()
        .copied()
        .chain(
            busbar_kernel::proto::registry::declared_verbs()
                .iter()
                .copied(),
        )
        .collect();
    assert!(
        verbs.len() > Operation::ALL.len(),
        "the declared verbs folded in: {} verbs",
        verbs.len()
    );
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
