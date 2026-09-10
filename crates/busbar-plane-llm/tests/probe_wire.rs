//! The probe wire, frozen: what this plane asks a live upstream is what 1.5.5 asked it.
//!
//! Active probing moved off the retiring engine and became a capability of the node — the clock
//! raises it, the breaker unit schedules it — and the only part left to a plane is the question:
//! `Plane::probe_request`. A move is only a move if the bytes do not change, so the six bodies and
//! six request targets below are RECORDED FROM THE BASE, from the same two calls the engine's
//! `health.rs` made (`probe_body(wire_model)` and `upstream_path_for_stream(wire_model, false)`),
//! and frozen here as literals. They are compared with no normalization at all: if a byte moves, a
//! backend that fingerprints busbar's probes gets a new fingerprint, and the indistinguishability
//! the probe path exists to keep is gone.
//!
//! The envelope is checked in the same breath and for the same reason. `encode_egress` writes
//! method, path and content-type in that order for organic traffic; a probe that wrote them in
//! another order, or wrote a fourth field, or asked for a stream, would be a request a backend can
//! tell apart from a real one without reading a single byte of the body.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::Plane;
use busbar_plane_llm::{LlmPlane, Upstream};

/// The model every lane below rewrites its request to name. One model across all six dialects, so
/// a body that differs differs because the DIALECT differs and for no other reason.
const LANE_MODEL: &str = "gpt-4o-mini";

/// One frozen probe, as the base sent it.
struct Frozen {
    /// The dialect the lane speaks.
    dialect: &'static str,
    /// The request target, exactly as `upstream_path_for_stream(model, false)` built it.
    path: &'static str,
    /// The body, exactly as `probe_body(model)` serialized it.
    body: &'static str,
}

/// The base's probe wire, one row per dialect, recorded and never regenerated.
const FROZEN: &[Frozen] = &[
    Frozen {
        dialect: "anthropic",
        path: "/v1/messages",
        body: r#"{"max_tokens":1,"messages":[{"content":[{"text":"ping","type":"text"}],"role":"user"}],"model":"gpt-4o-mini","stream":false}"#,
    },
    Frozen {
        dialect: "openai",
        path: "/v1/chat/completions",
        body: r#"{"max_tokens":1,"messages":[{"content":[{"text":"ping","type":"text"}],"role":"user"}],"model":"gpt-4o-mini","stream":false}"#,
    },
    Frozen {
        dialect: "gemini",
        path: "/v1beta/models/gpt-4o-mini:generateContent",
        body: r#"{"contents":[{"parts":[{"text":"ping"}],"role":"user"}],"generationConfig":{"maxOutputTokens":1},"model":"gpt-4o-mini"}"#,
    },
    Frozen {
        dialect: "bedrock",
        path: "/model/gpt-4o-mini/converse",
        body: r#"{"inferenceConfig":{"maxTokens":1},"messages":[{"content":[{"text":"ping"}],"role":"user"}]}"#,
    },
    Frozen {
        dialect: "cohere",
        path: "/v2/chat",
        body: r#"{"max_tokens":1,"messages":[{"content":"ping","role":"user"}],"model":"gpt-4o-mini"}"#,
    },
    Frozen {
        dialect: "responses",
        path: "/v1/responses",
        body: r#"{"input":[{"content":[{"text":"ping","type":"input_text"}],"role":"user"}],"max_output_tokens":1,"model":"gpt-4o-mini","stream":false}"#,
    },
];

/// The lane each frozen row is reached on.
fn lane_of(dialect: &str) -> LaneId {
    match dialect {
        "anthropic" => LaneId::new("lane-anthropic"),
        "openai" => LaneId::new("lane-openai"),
        "gemini" => LaneId::new("lane-gemini"),
        "bedrock" => LaneId::new("lane-bedrock"),
        "cohere" => LaneId::new("lane-cohere"),
        "responses" => LaneId::new("lane-responses"),
        other => panic!("no lane is declared for the dialect {other}"),
    }
}

/// One configured upstream per dialect, each on its own lane.
const UPSTREAMS: &[Upstream] = &[
    Upstream {
        lane: LaneId::new("lane-anthropic"),
        host: "anthropic.invalid",
        dialect: "anthropic",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-openai"),
        host: "openai.invalid",
        dialect: "openai",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-gemini"),
        host: "gemini.invalid",
        dialect: "gemini",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-bedrock"),
        host: "bedrock.invalid",
        dialect: "bedrock",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-cohere"),
        host: "cohere.invalid",
        dialect: "cohere",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-responses"),
        host: "responses.invalid",
        dialect: "responses",
        model: LANE_MODEL,
    },
];

/// Read one envelope field by name.
fn field<'a>(egress: &'a busbar_contract::dest::EgressBody<'a>, name: &str) -> Option<&'a [u8]> {
    egress
        .envelope
        .fields
        .as_slice()
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.as_slice())
}

#[test]
fn the_probe_this_plane_writes_is_the_probe_the_engine_sent() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new("/", &[]);
    let labels = Labels::default();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    for row in FROZEN {
        let dest = harness::destination("upstream.invalid", lane_of(row.dialect));
        let egress = plane
            .probe_request(&dest, &ctx)
            .unwrap_or_else(|| panic!("the {} lane must have a probe to send", row.dialect));

        assert_eq!(
            egress.body.as_slice(),
            row.body.as_bytes(),
            "the {} probe body moved off the bytes the engine sent",
            row.dialect
        );
        assert_eq!(
            field(&egress, "path"),
            Some(row.path.as_bytes()),
            "the {} probe target moved off the target the engine used",
            row.dialect
        );
        assert_eq!(
            field(&egress, "method"),
            Some(b"POST".as_slice()),
            "a probe is a POST, exactly as an organic request of this dialect is"
        );
        assert_eq!(
            field(&egress, "content-type"),
            Some(b"application/json".as_slice()),
            "a probe declares the content type an organic request declares"
        );
        // The order is the wire's, not a detail: `encode_egress` writes these three in this order
        // for real traffic, and a probe that wrote them in another one is distinguishable from
        // real traffic before its body is read.
        let names: Vec<&str> = egress
            .envelope
            .fields
            .as_slice()
            .iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(
            names,
            vec!["method", "path", "content-type"],
            "the {} probe envelope carries the organic fields, in the organic order, and no fourth",
            row.dialect
        );
    }
}

#[test]
fn every_dialect_this_plane_speaks_has_a_frozen_probe() {
    for upstream in UPSTREAMS {
        assert!(
            FROZEN.iter().any(|f| f.dialect == upstream.dialect),
            "the dialect {} is configured and its probe wire is not frozen; a dialect whose probe \
             nothing pins can change what it sends without a test noticing",
            upstream.dialect
        );
    }
}

#[test]
fn an_upstream_this_plane_does_not_hold_is_not_probed() {
    // A destination on a lane this plane has no upstream for has no dialect to ask in, so there is
    // nothing to send. The honest answer is passive watching, not a fabricated request.
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new("/", &[]);
    let labels = Labels::default();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("elsewhere.invalid", LaneId::new("lane-nobody-configured"));
    assert!(
        plane.probe_request(&dest, &ctx).is_none(),
        "a lane this plane holds no upstream for must be watched passively, not probed blind"
    );
}

#[test]
fn a_plane_with_nothing_configured_probes_nothing() {
    let plane = LlmPlane::EMPTY;
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new("/", &[]);
    let labels = Labels::default();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("upstream.invalid", LaneId::new("lane-openai"));
    assert!(
        plane.probe_request(&dest, &ctx).is_none(),
        "a plane with no upstream configured has nothing to probe and must say so"
    );
}
