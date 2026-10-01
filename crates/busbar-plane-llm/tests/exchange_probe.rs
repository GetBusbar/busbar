// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A health probe's far-end request.

use busbar_plane_llm::exchange::probe::{probe_path, request};
use busbar_plane_llm::exchange::shaping::Shaping;
use serde_json::json;

fn shaping() -> Shaping {
    Shaping::from_settings(&json!({
        "providers": {
            "oai": { "protocol": "openai", "base_url": "https://a" },
            "ant": { "protocol": "anthropic", "base_url": "https://b" },
            "goo": { "protocol": "gemini", "base_url": "https://c" },
            "bed": { "protocol": "bedrock", "base_url": "https://d" },
            "res": { "protocol": "responses", "base_url": "https://e" },
            "coh": { "protocol": "cohere", "base_url": "https://f" },
            "vtx": { "protocol": "gemini", "base_url": "https://g", "path_base": "/v1/projects/p" },
            "fix": { "protocol": "openai", "base_url": "https://h", "path": "/fixed/chat" }
        },
        "models": {
            "oai": { "provider": "oai" }, "ant": { "provider": "ant" },
            "goo": { "provider": "goo", "upstream_model": "gemini-pro" },
            "bed": { "provider": "bed", "upstream_model": "anthropic.claude-3:0" },
            "res": { "provider": "res" }, "coh": { "provider": "coh" },
            "vtx": { "provider": "vtx" }, "fix": { "provider": "fix" }
        }
    }))
    .expect("reads")
}

#[test]
fn every_dialect_probes_with_its_own_body_on_its_single_answer_path() {
    let s = shaping();
    for m in ["oai", "ant", "goo", "bed", "res", "coh"] {
        let lane = s.lane(m).expect("lane");
        let r = request(lane).expect("probed");
        assert_eq!(r.verb, "POST");
        assert!(!r.body.is_empty(), "{m}: a probe body");
        assert!(r.target.starts_with('/'), "{m}: {}", r.target);
        assert!(!probe_path(lane).contains("stream"), "{m}: a single answer");
        let names: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["content-type", "user-agent", "accept"], "{m}");
    }
    let bed = request(s.lane("bed").expect("lane")).expect("probed");
    assert!(
        bed.target.contains("%3A"),
        "the wire model is encoded: {}",
        bed.target
    );
}

#[test]
fn a_lane_under_a_path_base_is_not_probed_and_a_fixed_path_is_kept() {
    let s = shaping();
    assert!(request(s.lane("vtx").expect("lane")).is_none());
    assert_eq!(
        request(s.lane("fix").expect("lane"))
            .expect("probed")
            .target,
        "/fixed/chat"
    );
}
