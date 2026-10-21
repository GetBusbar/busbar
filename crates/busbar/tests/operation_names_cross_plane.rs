// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO VERB NAMES A PLANE OR A PROTOCOL — proven on the REAL shipped roster.
//!
//! The half of `src/tests/operation_tests.rs::no_verb_name_carries_a_protocol_identity` that needs
//! the real roster registered. The unit test reads the provider dialects the kernel's neutral plane
//! declares; the plane keys (one of them a plane core's unit test binary never registers) are only
//! enumerable once the planes install their test seams, which is an integration-test target's job
//! (see `plane_dispatch_cross_plane.rs`'s header for the same move).

mod linked;

use busbar_kernel::operation::OpVerb;

/// Register the real roster in the process registry — idempotent (first-wins).
fn register_planes() {
    linked::install();
}

/// Every verb the fallback plane's door states (its Statement tail's operation classes, read through
/// the plane ABI, BUSBAR-1.6.0.md l.4965), deduped: the half of the operation vocabulary the planes
/// declare (the kernel owns `OpVerb::ALL`, the shape verbs).
fn declared_verbs() -> Vec<&'static str> {
    let mut verbs: Vec<&'static str> = Vec::new();
    for v in linked::fallback_op_classes() {
        if !verbs.contains(&v) {
            verbs.push(v);
        }
    }
    verbs
}

/// THE METRIC LABEL SURFACE, AS A SET, over the shipped roster: the kernel's six shape verbs and
/// the verbs the linked planes' dialects declare. `Operation::name` is a Prometheus/tracing label,
/// so the set of values it can take is the set of series an operator's dashboard can select — the
/// SAME thirteen labels the 1.5 era published. The kernel's own half is pinned in
/// `busbar-kernel`'s `operation_tests::the_kernel_owned_label_surface_is_exactly_these_six`.
#[test]
fn the_metric_label_surface_is_exactly_these_thirteen() {
    register_planes();
    let mut labels: Vec<&str> = OpVerb::ALL
        .iter()
        .map(|o| o.name())
        .chain(declared_verbs())
        .collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(
        labels,
        [
            "catalogue",
            "chat",
            "control",
            "embeddings",
            "fetch",
            "image",
            "invoke",
            "moderation",
            "rerank",
            "speech",
            "subscribe",
            "task",
            "transcription",
        ],
        "the operation metric label surface changed; a dashboard depends on this set"
    );
}

/// The closed metric-label surface is `Operation::ALL ∪ declared_verbs()`. No word on it may carry a
/// plane key or a registered protocol name, or a dashboard would read a label claiming the engine
/// knows which protocol it is serving.
#[test]
fn no_verb_name_carries_a_plane_key_or_a_protocol_name() {
    register_planes();
    // The keys come from the binary's door table over the roster, never from literals here.
    let plane_keys: Vec<&'static str> = linked::table().plane_keys().collect();
    assert!(
        plane_keys.len() >= 3,
        "the registered roster declares at least three plane keys: {plane_keys:?}"
    );
    let mut identities: Vec<&'static str> = plane_keys.clone();
    identities.extend(linked::fallback_dialects());
    let verbs: Vec<&'static str> = OpVerb::ALL
        .iter()
        .map(|o| o.name())
        .chain(declared_verbs())
        .collect();
    assert!(
        verbs.len() > OpVerb::ALL.len(),
        "the declared verbs folded in: {} verbs",
        verbs.len()
    );
    for name in verbs {
        for forbidden in &identities {
            assert!(
                !name.contains(forbidden),
                "`{name}` names the `{forbidden}` plane or protocol; verbs are shapes plus neutral words"
            );
        }
    }
}
