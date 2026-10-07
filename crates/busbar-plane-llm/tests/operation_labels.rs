// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATION LABEL SURFACE, over the kernel's shape verbs and this plane's declared operation
//! classes. Re-homed from the kernel's `tests/operation_tests.rs`, which read the declared half off
//! the kernel's protocol registry; the registry is gone (ARCHITECT ruling 2026-10-07: a plane's
//! declarations are its own), so the declared half is read off this plane's own statement, where it
//! lives.

use busbar_contract::operation::OpVerb;
use busbar_contract::plane::PlaneMeta;
use busbar_plane_llm::dialect::DIALECTS;
use busbar_plane_llm::LlmPlane;

/// The operation metric label surface: the kernel's six shape verbs plus the classes this plane
/// declares. With the llm plane linked this is the SAME thirteen labels the 1.5 era published — a
/// dashboard depends on the set. (Re-homed: kernel `the_metric_label_surface_is_exactly_these_thirteen`.)
#[test]
fn the_metric_label_surface_is_exactly_these_thirteen() {
    let mut labels: Vec<&str> = OpVerb::ALL
        .iter()
        .map(|o| o.name())
        .chain(
            <LlmPlane as PlaneMeta>::OP_CLASSES
                .iter()
                .map(|c| c.as_str()),
        )
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

/// NO OPERATION LABEL NAMES A PROTOCOL: neither a kernel shape verb nor a class this plane declares
/// contains any of this plane's dialect names. (Re-homed: kernel
/// `no_verb_name_carries_a_protocol_identity`, whose identities were the kernel registry's.)
#[test]
fn no_verb_name_carries_a_protocol_identity() {
    let identities: Vec<&str> = DIALECTS.iter().map(|d| d.name).collect();
    assert_eq!(identities.len(), 6, "the plane states six dialects");
    let names = OpVerb::ALL.iter().map(|o| o.name()).chain(
        <LlmPlane as PlaneMeta>::OP_CLASSES
            .iter()
            .map(|c| c.as_str()),
    );
    for name in names {
        for forbidden in &identities {
            assert!(
                !name.contains(forbidden),
                "`{name}` names the `{forbidden}` protocol; verbs are shapes plus neutral words"
            );
        }
    }
}
