// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A health probe's far-end request.

use busbar_plane_llm::exchange::probe::{probe_path, request};
use busbar_plane_llm::exchange::shaping::Shaping;
use serde_json::json;

/// The codec host these tests hand the plane: the OS CSPRNG and the system clock in whole seconds,
/// read the way the kernel's host reads them.
struct TestHost;

impl busbar_contract::codec::CodecHost for TestHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        getrandom::fill(out).is_ok()
    }

    fn wall_clock_now(&self) -> Option<u64> {
        Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
    }
}

/// The handle every codec call here is handed.
const HOST: &dyn busbar_contract::codec::CodecHost = &TestHost;

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
        let r = request(HOST, lane).expect("probed");
        assert_eq!(r.verb, "POST");
        assert!(!r.body.is_empty(), "{m}: a probe body");
        assert!(r.target.starts_with('/'), "{m}: {}", r.target);
        assert!(!probe_path(lane).contains("stream"), "{m}: a single answer");
        let names: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
        let mut want: Vec<&str> = lane.statics.iter().map(|(n, _)| *n).collect();
        want.extend(["content-type", "user-agent", "accept"]);
        assert_eq!(names, want, "{m}");
    }
    let bed = request(HOST, s.lane("bed").expect("lane")).expect("probed");
    assert!(
        bed.target.contains("%3A"),
        "the wire model is encoded: {}",
        bed.target
    );
}

#[test]
fn a_lane_under_a_path_base_is_not_probed_and_a_fixed_path_is_kept() {
    let s = shaping();
    assert!(request(HOST, s.lane("vtx").expect("lane")).is_none());
    assert_eq!(
        request(HOST, s.lane("fix").expect("lane"))
            .expect("probed")
            .target,
        "/fixed/chat"
    );
}

/// The value of the head field `name` on `r`.
fn field_value<'a>(r: &'a busbar_plane_llm::exchange::attempt::FarRequest, name: &str) -> &'a [u8] {
    r.fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
        .unwrap_or_else(|| panic!("the request carries `{name}`"))
}

/// LEGACY `crates/busbar-llm/src/engine/tests/health_tests.rs::test_probe_sends_native_user_agent_and_accept_headers`
/// (coverage map v2 row 220). 1.5.5: an active probe of an anthropic lane sends the SAME native-SDK
/// fingerprint organic traffic sends: `user-agent: Anthropic/Python 0.39.0` and the non-streaming
/// `accept: application/json`, so a far end cannot tell busbar's probes from its clients.
///
/// RED: the probe's `user-agent` or `accept` value differs from the one an organic (UA-less,
/// non-streaming) anthropic request carries, or either moves off the pinned literal.
#[test]
fn test_probe_sends_native_user_agent_and_accept_headers() {
    use busbar_plane_llm::exchange::arrive::arrive;
    use busbar_plane_llm::exchange::attempt::build;
    let s = Shaping::from_settings(&json!({
        "providers": { "ant": { "protocol": "anthropic", "base_url": "https://b" } },
        "models": { "claude": { "provider": "ant" } },
        "pools": { "p": { "members": ["claude"] } }
    }))
    .expect("reads");
    let lane = s.lane("claude").expect("lane");
    let probe = request(HOST, lane).expect("probed");

    // Organic traffic on the same lane: a native caller that sent no user-agent, not streaming.
    let head: Vec<(&[u8], &[u8])> =
        vec![(b"content-type".as_slice(), b"application/json".as_slice())];
    let body = br#"{"model":"claude","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;
    let arrived = arrive("POST", "/v1/messages", &head, body, &()).expect("arrives");
    let organic = build(HOST, &arrived, &head, &s, "p", "claude").expect("built");

    assert_eq!(
        field_value(&probe, "user-agent"),
        field_value(&organic, "user-agent"),
        "probe must send the native User-Agent organic traffic sends"
    );
    assert_eq!(
        field_value(&probe, "user-agent"),
        b"Anthropic/Python 0.39.0"
    );
    assert_eq!(
        field_value(&probe, "accept"),
        field_value(&organic, "accept"),
        "probe must send the native Accept organic traffic sends"
    );
    assert_eq!(field_value(&probe, "accept"), b"application/json");
}

/// LEGACY `crates/busbar-llm/src/engine/tests/health_tests.rs::test_probe_signs_and_sends_same_encoded_path_for_reserved_chars`
/// (coverage map v2 row 230). 1.5.5: a probe of a bedrock model id carrying a reserved `:` sends
/// the `%3A`-encoded path, never the raw `:0/converse`, and the signature's canonical path is
/// computed from that SAME wire path, so the signed and sent paths cannot diverge
/// (`SignatureDoesNotMatch` would park every such lane dead).
///
/// RED: the raw colon reaches the wire, the probe sends a path other than the one the signature
/// is computed from, or the canonical path stops being the wire path's own encoding.
#[test]
fn test_probe_signs_and_sends_same_encoded_path_for_reserved_chars() {
    use busbar_plane_llm::exchange::attempt::{uri_encode_path, wire_and_canonical_path};
    let s = shaping();
    let lane = s.lane("bed").expect("lane");
    let probe = request(HOST, lane).expect("probed");
    let (wire_path, canonical) = wire_and_canonical_path(&probe_path(lane));
    assert!(
        probe.target.contains("%3A"),
        "Bedrock modelId ':' must be percent-encoded on the wire path: {}",
        probe.target
    );
    assert!(
        !probe.target.contains(":0/converse"),
        "the raw ':' must NOT survive on the wire path (would diverge from the signed URI): {}",
        probe.target
    );
    assert_eq!(
        probe.target, wire_path,
        "the probe sends exactly the wire path the signature is computed from"
    );
    assert_eq!(
        canonical,
        uri_encode_path(&wire_path),
        "the signed canonical path is the transmitted wire path's own encoding (signed == sent)"
    );
    assert_eq!(probe.target, "/model/anthropic.claude-3%3A0/converse");
}

/// A probe of a lane carries the lane's declared static fields exactly as organic traffic on the
/// lane does: an anthropic lane's probe without `anthropic-version` is answered 400 by the far end,
/// and the breaker would read that refusal as the lane's health. A lane under an operator `auth:`
/// override whose declaration carries no static field probes without one, as its organic traffic.
///
/// RED on dev: the probe wrote only `content-type`, `user-agent` and `accept`, so the
/// `anthropic-version` lookup below finds nothing.
#[test]
fn a_probe_carries_the_lanes_static_fields_as_organic_traffic_does() {
    use busbar_plane_llm::exchange::arrive::arrive;
    use busbar_plane_llm::exchange::attempt::build;
    let s = Shaping::from_settings(&json!({
        "providers": {
            "ant": { "protocol": "anthropic", "base_url": "https://b" },
            "key": { "protocol": "anthropic", "base_url": "https://c", "auth": "api-key" }
        },
        "models": { "claude": { "provider": "ant" }, "keyed": { "provider": "key" } },
        "pools": { "p": { "members": ["claude"] }, "k": { "members": ["keyed"] } }
    }))
    .expect("reads");
    let head: Vec<(&[u8], &[u8])> =
        vec![(b"content-type".as_slice(), b"application/json".as_slice())];
    let body = br#"{"model":"claude","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;
    let arrived = arrive("POST", "/v1/messages", &head, body, &()).expect("arrives");

    let probe = request(HOST, s.lane("claude").expect("lane")).expect("probed");
    let organic = build(HOST, &arrived, &head, &s, "p", "claude").expect("built");
    assert_eq!(field_value(&probe, "anthropic-version"), b"2023-06-01");
    assert_eq!(
        field_value(&probe, "anthropic-version"),
        field_value(&organic, "anthropic-version"),
        "the probe writes the version field organic traffic writes"
    );

    let keyed = request(HOST, s.lane("keyed").expect("lane")).expect("probed");
    let keyed_organic = build(HOST, &arrived, &head, &s, "k", "keyed").expect("built");
    let has = |r: &busbar_plane_llm::exchange::attempt::FarRequest| {
        r.fields
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("anthropic-version"))
    };
    assert_eq!(has(&keyed), has(&keyed_organic));
    assert!(
        !has(&keyed),
        "an api-key override's declaration carries no static field"
    );
}
