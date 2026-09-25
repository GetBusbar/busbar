// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESIDUAL ENVELOPE, asserted against the REAL shipped planes. Relocated here from
//! `src/tests/tests.rs` (1.6.0 item 60, strict plane purity): both tests assert what the real
//! plane crates declare — the LLM dialects' own residual claims and residual default, and a real
//! plane's mount path — so they belong on the integration target that links those crates as normal
//! dependencies, not in the neutral crate's own source, which names no dialect and no plane.
//!
//! The error-shaping mechanics the table feeds (`fallback_error_response`, the 413 reshape and
//! their `x-amzn-*` / `error` envelopes) stay pinned in `src/tests/tests.rs`; what moved is only
//! the table of which dialect answers which residual path shape.

use busbar_kernel::test_support::{oversized_413_body, TestApp};

/// Register the shipped planes and their protocol declarations, as the composition root does.
fn register_planes() {
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
}

/// A deployment with NO plane mounted: every path resolves through the resolver's residual arm,
/// which is the arm these vendor-envelope assertions are about.
fn residual_planes() -> busbar_kernel::plane::PlaneDispatch {
    busbar_kernel::plane::PlaneDispatch::default()
}

/// The dialect a 404/405/413 is shaped in for `path` on a residual-only deployment — read through
/// the ONE resolver the fallback handlers read, so this table cannot drift from what they answer.
fn residual_dialect(path: &str) -> &'static str {
    busbar_kernel::ingress::native::envelope_dialect(residual_planes().ingress_of(path))
}

/// The fallback handlers resolve the ingress from the request path so a 404/405 is shaped in the
/// client's own dialect, not a bare axum body.
#[test]
fn test_residual_dialect_inference() {
    register_planes();
    assert_eq!(residual_dialect("/v1/chat/completions"), "openai");
    assert_eq!(residual_dialect("/v1/responses"), "responses");
    assert_eq!(residual_dialect("/v2/chat"), "cohere");
    // Both the stable v1 and v1beta Gemini surfaces infer gemini.
    assert_eq!(
        residual_dialect("/v1/models/gemini-pro:generateContent"),
        "gemini"
    );
    assert_eq!(
        residual_dialect("/v1beta/models/gemini-pro:streamGenerateContent"),
        "gemini"
    );
    // REGRESSION: an OpenAI-SDK `model.retrieve` hits
    // `GET /v1/models/{model_id}` — NO `:<action>` colon. That must infer OpenAI (so the 405/404
    // error is OpenAI-decodable), not Gemini, even though it shares the `/v1/models/` prefix.
    assert_eq!(residual_dialect("/v1/models/gpt-4o"), "openai");
    assert_eq!(residual_dialect("/v1/models"), "openai"); // list-models (no trailing id)
                                                          // A `/v1/models/` path WITH a colon action is still the Gemini surface.
    assert_eq!(
        residual_dialect("/v1/models/gemini-1.5-pro:generateContent"),
        "gemini"
    );
    // `/v1beta/models/...` is Gemini-only even without a colon (OpenAI has no v1beta surface).
    assert_eq!(residual_dialect("/v1beta/models/gemini-pro"), "gemini");
    assert_eq!(
        residual_dialect("/model/anthropic.claude/converse"),
        "bedrock"
    );
    assert_eq!(
        residual_dialect("/model/anthropic.claude/converse-stream"),
        "bedrock"
    );
    assert_eq!(residual_dialect("/my-model/v1/messages"), "anthropic");
    // REGRESSION: a NON-Converse `/model/...` path must NOT be classified as bedrock
    // (it lacks the `/converse`/`/converse-stream` suffix). The previous unconditional
    // `starts_with("/model/")` shaped it as bedrock here while auth shaped it as openai —
    // contradictory error envelopes for one path. The canonical classifier now requires the
    // suffix, so a bare `/model/foo/bar` falls through to the OpenAI default, matching auth.rs.
    assert_eq!(
        residual_dialect("/model/foo/bar"),
        "openai",
        "non-Converse /model/ path must align with auth.rs (openai), not bedrock"
    );
    assert_eq!(residual_dialect("/model/foo/predict"), "openai");
    // Unknown path defaults to the widely-understood OpenAI envelope.
    assert_eq!(residual_dialect("/totally/unknown"), "openai");
}

/// A PLANE CLAIMS A PATH ONLY WHEN THE OPERATOR MOUNTED IT. With no `mcp:` section there is no MCP
/// plane, so `/mcp` is an ordinary unclaimed path on the residual and is answered as one. The merge
/// must not turn an unmounted plane into one that claims paths by URL shape. The mounted twin is
/// `plane_integration::oversized_post_to_a_mounted_mcp_plane_is_refused_in_the_planes_own_dialect`.
#[tokio::test]
async fn an_unmounted_plane_claims_no_path_by_url_shape() {
    busbar_kernel::metrics::init();
    register_planes();
    let app = TestApp::new().build();

    let v = oversized_413_body(app, "/mcp").await;

    assert!(
        v.get("jsonrpc").is_none(),
        "nothing mounted MCP, so `/mcp` is a residual path and must not be answered as a plane; \
         got {v}"
    );
    assert!(
        v.pointer("/error/message").is_some(),
        "the residual plane answers the widely-understood envelope; got {v}"
    );
}
