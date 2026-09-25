// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESIDUAL-DIALECT TABLE — which of this plane's dialects a 404/405/413 on a residual-only
//! deployment is shaped in, read through the ONE resolver the fallback handlers read.
//!
//! Moved here from `busbar-kernel/tests/residual_envelope_cross_plane.rs` (K3; architect ruling "K3
//! intake list": the residual-dialect table is an llm-plane subject). Every row asserts what THIS
//! plane's own path-ingress and dialect declarations answer, so the plane tests it: "a plugin tests
//! itself; the kernel never tests or names a plugin". The kernel keeps its neutral half — an
//! unmounted plane claims no path — in that file, driven over the test-linked roster.

use busbar_kernel::{ingress::native::envelope_dialect, plane::PlaneDispatch};

/// The dialect a 404/405/413 is shaped in for `path` on a deployment with NO plane mounted: every
/// path resolves through the resolver's residual arm, which is the arm these vendor-envelope
/// assertions are about.
fn residual_dialect(path: &str) -> &'static str {
    envelope_dialect(PlaneDispatch::default().ingress_of(path))
}

/// The fallback handlers resolve the ingress from the request path so a 404/405 is shaped in the
/// client's own dialect, not a bare axum body.
#[test]
fn test_residual_dialect_inference() {
    crate::testkit::install_test_seams();
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
