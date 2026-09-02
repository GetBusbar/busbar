// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS-TARGET DIFFERENTIAL PROOF — the boot-precomputed `(operation × stream)` table
//! (`egress::build_egress_targets`) must be BYTE-IDENTICAL to the per-request composition it
//! replaced (`Op::upstream_path` → `sign_and_wire_path_parts` → `format!("{base}{wire}")`), for
//! every registered protocol, both stream intents, and the lane-override shapes (Azure `path`
//! with query, Gemini `path_base`, Bedrock modelId with a reserved `:`). The old composition
//! stays in the tree AS the reference (`Op::upstream_path` is test-only now); if the two ever
//! drift — a `Url` re-encoding, a changed override precedence — this test is the tripwire, not a
//! production signature mismatch.

use crate::engine::AppEngineExt as _;
use crate::engine::OpEgressExt as _;
use crate::test_support::{LaneSpec, TestApp};

/// For one built lane, prove every table entry equals the reference composition, and that the
/// table covers chat for both stream intents (the hot path's keys).
fn assert_table_matches_reference(app: &busbar_core::state::App, lane_idx: usize) {
    let lane = &app.engine_tables().lanes()[lane_idx];
    let op = busbar_substrate::handlers::chat(
        lane.protocol,
        busbar_substrate::transport::Transport::Http,
    );
    for wants_stream in [false, true] {
        let target = lane
            .egress_target(op.operation, wants_stream)
            .expect("chat egress target present for a registered protocol");
        // Reference composition — the exact per-request form the engine used to run.
        let url_path = op
            .upstream_path(lane, wants_stream)
            .expect("reference upstream_path resolves for a registered protocol");
        let (wire_path, canonical_uri) = crate::engine::sign_and_wire_path_parts(&url_path);
        let composed = format!("{}{}", lane.base_url, wire_path);
        assert_eq!(
            target.url.as_str(),
            composed,
            "precomputed wire URL != reference composition (protocol '{}', stream {wants_stream})",
            lane.protocol
        );
        assert_eq!(
            target.canonical_uri, canonical_uri,
            "precomputed canonical URI != reference (protocol '{}', stream {wants_stream})",
            lane.protocol
        );
        assert_eq!(
            target.uri.to_string(),
            composed,
            "precomputed http::Uri != reference composition (protocol '{}', stream {wants_stream})",
            lane.protocol
        );
    }
}

#[test]
fn egress_targets_match_reference_composition_all_protocols() {
    crate::testkit::install_test_seams();
    for proto in [
        crate::proto_codec::PROTO_OPENAI,
        crate::proto_codec::PROTO_ANTHROPIC,
        crate::proto_codec::PROTO_GEMINI,
        crate::proto_codec::PROTO_COHERE,
        crate::proto_codec::PROTO_BEDROCK,
        crate::proto_codec::PROTO_RESPONSES,
    ] {
        let app = TestApp::new()
            .lane(LaneSpec::new("m-1", proto, "http://127.0.0.1:1"))
            .pool("", &[(0, 1)])
            .build();
        assert_table_matches_reference(&app, 0);
    }
}

#[test]
fn egress_targets_honor_azure_path_override_with_query() {
    crate::testkit::install_test_seams();
    // Azure OpenAI: full-path override carrying `?api-version=` — the precomputed URL must keep
    // the query verbatim (the boot parse never re-encodes it; `Url::join`/`set_path` would).
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto_codec::PROTO_OPENAI,
                "http://127.0.0.1:1",
            )
            .path("/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01"),
        )
        .pool("", &[(0, 1)])
        .build();
    assert_table_matches_reference(&app, 0);
    let op =
        busbar_substrate::handlers::chat("openai", busbar_substrate::transport::Transport::Http);
    let t = app.engine_tables().lanes()[0]
        .egress_target(op.operation, false)
        .unwrap();
    assert_eq!(
        t.url.as_str(),
        "http://127.0.0.1:1/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01"
    );
    assert_eq!(
        t.canonical_uri,
        "/openai/deployments/gpt-4o/chat/completions"
    );
}

#[test]
fn egress_targets_encode_bedrock_model_id_like_the_wire() {
    crate::testkit::install_test_seams();
    // A Bedrock modelId's reserved `:` must reach the wire single-encoded (`%3A`) with the SigV4
    // canonical double-encoded (`%253A`) — the sign-what-you-send rule `health_tests` pins. The
    // boot-time `Url::parse` must pass those `%XX` bytes through unchanged.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude",
                crate::proto_codec::PROTO_BEDROCK,
                "http://127.0.0.1:1",
            )
            .upstream_model("anthropic.claude-3-sonnet-20240229-v1:0"),
        )
        .pool("", &[(0, 1)])
        .build();
    assert_table_matches_reference(&app, 0);
    let op =
        busbar_substrate::handlers::chat("bedrock", busbar_substrate::transport::Transport::Http);
    let t = app.engine_tables().lanes()[0]
        .egress_target(op.operation, false)
        .unwrap();
    assert!(
        t.url.as_str().contains("%3A0"),
        "wire URL must carry the single-encoded modelId, got {}",
        t.url
    );
    assert!(
        t.canonical_uri.contains("%253A0"),
        "canonical URI must be double-encoded (non-S3 SigV4 rule), got {}",
        t.canonical_uri
    );
}
