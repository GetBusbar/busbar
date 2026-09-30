// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S ATTEMPT PATH AGAINST THE ENGINE'S. The plane answers an attempt with only the path
//! and query (the kernel joins them onto the member's base URL); the engine precomputes the whole
//! URL (`egress::build_egress_targets`). For every dialect, every family operation, both stream
//! intents and each override shape (a provider `path` with a query, a `path_base`, a wire model
//! outside the unreserved set), the engine's URL is the base URL followed by the plane's path, and
//! the two canonical signing paths are equal.

use crate::engine::xchg::attempt::{upstream_path, wire_and_canonical_path};
use crate::engine::xchg::shaping::Lane;
use busbar_contract::operation::OpVerb;

const BASE: &str = "https://far.example";

fn plane_lane(dialect: &'static str, model: &str, path: Option<&str>, base: Option<&str>) -> Lane {
    Lane {
        model: model.to_string(),
        provider: "p".to_string(),
        dialect,
        path: path.map(str::to_string),
        path_base: base.map(str::to_string),
        upstream_model: None,
        default_max_tokens: None,
        context_max: None,
        reasoning: false,
        prompt_caching: false,
        caps: Default::default(),
        error_map: Default::default(),
    }
}

#[test]
fn the_planes_attempt_path_is_the_engines_url_after_its_base() {
    crate::testkit::install_test_seams();
    let ops = [
        OpVerb::CHAT,
        OpVerb::EMBEDDINGS,
        OpVerb::MODERATION,
        OpVerb::IMAGE,
        OpVerb::TRANSCRIPTION,
        OpVerb::SPEECH,
        OpVerb::RERANK,
    ];
    let shapes: [(&str, Option<&str>, Option<&str>); 4] = [
        ("m-1", None, None),
        (
            "m-1",
            Some("/openai/deployments/d/chat?api-version=2024-10-21"),
            None,
        ),
        (
            "m-1",
            None,
            Some("/v1/projects/x/locations/y/publishers/google"),
        ),
        ("anthropic.claude-3:0", None, None),
    ];
    let mut checked = 0;
    for proto in [
        crate::proto_codec::PROTO_OPENAI,
        crate::proto_codec::PROTO_ANTHROPIC,
        crate::proto_codec::PROTO_GEMINI,
        crate::proto_codec::PROTO_COHERE,
        crate::proto_codec::PROTO_BEDROCK,
        crate::proto_codec::PROTO_RESPONSES,
    ] {
        for (model, path, base) in shapes {
            let engine = super::build_egress_targets(proto, path, base, model, BASE)
                .expect("the engine's table builds");
            let lane = plane_lane(proto, model, path, base);
            for op in ops {
                for stream in [false, true] {
                    let Some(target) = engine.get(&(op, stream)) else {
                        continue;
                    };
                    let url_path = upstream_path(&lane, op, stream).expect("the plane's path");
                    let (wire, canonical) = wire_and_canonical_path(&url_path);
                    assert_eq!(
                        target.uri.to_string(),
                        format!("{BASE}{wire}"),
                        "{proto} {op:?} stream {stream} {path:?} {base:?}"
                    );
                    assert_eq!(target.canonical_uri, canonical, "{proto} {op:?} {stream}");
                    checked += 1;
                }
            }
        }
    }
    assert!(checked >= 6 * 4 * 2, "{checked} cases");
}
