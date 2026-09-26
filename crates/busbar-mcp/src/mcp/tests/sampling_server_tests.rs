// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE THAT ANSWERS A SAMPLING ASK is resolved by OPERATION CLASS through the host's registry
//! ([`super::completion_server`]), never named: this plane spells no other plane (#47/#49). The
//! refusals that name that plane read its DECLARED display name, and a registry where no plane
//! declares the class refuses exactly as a deployment with no such plane always has.

use super::{complete, completion_server, NO_COMPLETION_SERVER};
use crate::mcp::inputreq::Refusal;
use crate::mcp::test_engine::*;
use busbar_contract::plane::{PlaneDeclaration, ServedOpClass};
use busbar_kernel::{
    plane::registry::{PlaneDecl, TestRegistryIsolation},
    test_support::seam::{register_test_plane_seam, test_plane_seams},
    test_support::NEUTRAL_FALLBACK,
};
use busbar_plane_mcp::meta::SAMPLING_OP;

/// A neutral plane serving the sampling class under the display name `AI`.
static SERVING: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "neutral-completion-server",
        fallback: false,
        record_kinds: &[],
        served_op_classes: &[ServedOpClass {
            op: SAMPLING_OP,
            name: "AI",
        }],
        ..NEUTRAL_FALLBACK.declaration
    },
    ..NEUTRAL_FALLBACK
};

/// The same plane serving a DIFFERENT class — registered, but not the sampling class's server.
static SERVING_OTHER: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "neutral-completion-server",
        fallback: false,
        record_kinds: &[],
        served_op_classes: &[ServedOpClass {
            op: busbar_contract::ids::OpClassId::new("embeddings"),
            name: "AI",
        }],
        ..NEUTRAL_FALLBACK.declaration
    },
    ..NEUTRAL_FALLBACK
};

// The linked planes' test seams, as this crate's manifest lists them (`test-linked`, emitted by
// build.rs) — so the completion seam this test proves is NOT what refuses is a real, answering one.
include!(concat!(env!("OUT_DIR"), "/test_linked.rs"));

/// Install the linked planes' seams — the completion seam among them. With it installed, an ask
/// that got past the class resolution would reach a synthesizer and come back as something other
/// than the no-server refusal, so the refusal below is proven to come from the resolution.
fn install_linked_seams() {
    for entry in TEST_LINKED {
        register_test_plane_seam(entry);
    }
    for seam in test_plane_seams() {
        (seam.install)();
    }
}

/// The dispatch round the budget refusal below is raised on.
const ROUND: u32 = 3;

/// A budget refusal, as the loop raises it.
fn budget_refusal() -> Refusal {
    Refusal::BudgetExhausted {
        server: "hostile".to_string(),
        round: ROUND,
        reason: "budget: group `agents` requests/minute cap reached".to_string(),
    }
}

/// A policy the ask is answered under.
fn policy() -> crate::mcp::config::SamplingCfg {
    crate::mcp::config::SamplingCfg {
        model: "sampler-model".to_string(),
        max_tokens: 64,
        max_requests_per_minute: 10,
        max_messages: crate::mcp::config::DEFAULT_MAX_SAMPLING_MESSAGES,
        max_prompt_bytes: crate::mcp::config::DEFAULT_MAX_SAMPLING_PROMPT_BYTES,
        max_stop_sequences: crate::mcp::config::DEFAULT_MAX_STOP_SEQUENCES,
        max_stop_sequence_bytes: crate::mcp::config::DEFAULT_MAX_STOP_SEQUENCE_BYTES,
        temperature_min_milli: crate::mcp::config::DEFAULT_TEMPERATURE_MIN_MILLI,
        temperature_max_milli: crate::mcp::config::DEFAULT_TEMPERATURE_MAX_MILLI,
    }
}

#[test]
fn the_sampling_server_is_the_plane_declaring_the_class_and_the_refusal_reads_its_name() {
    let _registry = TestRegistryIsolation::seeded(&[&SERVING]);
    assert_eq!(
        completion_server(),
        Some(ServedOpClass {
            op: SAMPLING_OP,
            name: "AI",
        })
    );
    assert_eq!(
        budget_refusal().to_string(),
        format!(
            "round {ROUND} of this dispatch to MCP server `hostile` was refused by your budget: \
             budget: group `agents` requests/minute cap reached. A tool call is charged on the \
             same budget plane as an AI request, so a runaway loop stops when the budget stops it."
        )
    );
}

/// THE RED ARM: the one registered plane does not declare the sampling class, so nothing serves the
/// ask — the completion is refused, in the words a deployment with no such plane has always been
/// refused in, before the host is asked to drive anything; and the budget refusal names no plane.
#[tokio::test]
async fn a_plane_that_does_not_declare_the_class_answers_no_sampling_ask() {
    install_linked_seams();
    let app = test_app().build();
    let host = engine_host(&app);
    let _registry = TestRegistryIsolation::seeded(&[&SERVING_OTHER]);
    assert_eq!(completion_server(), None);
    let refused = complete(
        &host,
        &busbar_contract::records::PlaneRequestCtx::default(),
        &policy(),
        serde_json::json!({ "model": "sampler-model", "messages": [] }),
    )
    .await
    .unwrap_err();
    assert_eq!(refused, NO_COMPLETION_SERVER);
    assert_eq!(refused, "no default chat protocol is installed");
    assert_eq!(
        budget_refusal().to_string(),
        format!(
            "round {ROUND} of this dispatch to MCP server `hostile` was refused by your budget: \
             budget: group `agents` requests/minute cap reached. A tool call is charged on your \
             budget, so a runaway loop stops when the budget stops it."
        )
    );
}
