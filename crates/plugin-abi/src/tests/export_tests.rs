// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-abi/src/export.rs`.

use super::*;

/// The op-discriminated request round-trips through JSON unchanged (the variant is the op tag).
#[test]
fn request_json_roundtrip() {
    let reqs = vec![
        ExportRequest::Streams,
        ExportRequest::Deliver {
            stream: ExportStream::Metrics,
            payload: serde_json::json!({"samples": [{"name": "reqs", "value": 1}]}),
        },
        ExportRequest::Deliver {
            stream: ExportStream::Events,
            payload: serde_json::json!([]),
        },
    ];
    for r in reqs {
        let j = serde_json::to_vec(&r).unwrap();
        let back: ExportRequest = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }
}

/// The `op` field is the discriminant a plugin matches on — pin the wire tag names.
#[test]
fn request_op_tag_is_stable() {
    let v = serde_json::to_value(ExportRequest::Streams).unwrap();
    assert_eq!(v["op"], "streams");
    let v = serde_json::to_value(ExportRequest::Deliver {
        stream: ExportStream::Logs,
        payload: serde_json::json!({}),
    })
    .unwrap();
    assert_eq!(v["op"], "deliver");
    assert_eq!(v["stream"], "logs");
}

/// The stream tokens are the stable snake_case wire spellings a non-Rust author must match, and
/// `as_token` renders the SAME spelling serde does (config diagnostics name tokens without a
/// JSON round-trip, so the two spellings must not be able to drift).
#[test]
fn stream_wire_spellings_are_pinned() {
    for (stream, tok) in [
        (ExportStream::Metrics, "metrics"),
        (ExportStream::Logs, "logs"),
        (ExportStream::Traces, "traces"),
        (ExportStream::Costs, "costs"),
        (ExportStream::Decisions, "decisions"),
        (ExportStream::Events, "events"),
        (ExportStream::Identity, "identity"),
        (ExportStream::Prompts, "prompts"),
        (ExportStream::Completions, "completions"),
    ] {
        assert_eq!(
            serde_json::to_value(stream).unwrap(),
            serde_json::json!(tok)
        );
        assert_eq!(stream.as_token(), tok);
        assert_eq!(ExportStream::from_token(tok), Some(stream));
    }
    // Every stream in the frozen vocabulary is covered by the table above.
    for s in ExportStream::ALL {
        assert!(
            ExportStream::from_token(s.as_token()) == Some(*s),
            "{} does not round-trip through its token",
            s.as_token()
        );
    }
}

/// `audit` is REMOVED from the vocabulary: an auditor is a PROJECTION (a sink subscribing to
/// `logs`/`identity`/`decisions`/`events`/`costs`), not a data type. The token must not resolve —
/// including through serde, so a v1 plugin or an old config cannot smuggle it back in.
#[test]
fn audit_is_not_a_stream() {
    assert_eq!(ExportStream::from_token("audit"), None);
    assert!(serde_json::from_value::<ExportStream>(serde_json::json!("audit")).is_err());
    assert!(ExportStream::ALL.iter().all(|s| s.as_token() != "audit"));
}

/// The field vocabulary round-trips token ⇄ variant, and `bit()` is a stable, unique position
/// that fits the engine's 64-bit projection mask (the mask is the enforcement mechanism, so a
/// field whose bit collided or overflowed would silently mis-grant).
#[test]
fn field_tokens_and_bits_are_stable() {
    let mut seen = std::collections::BTreeSet::new();
    for f in ExportField::ALL {
        assert_eq!(ExportField::from_token(f.as_token()), Some(*f));
        assert_eq!(
            serde_json::to_value(f).unwrap(),
            serde_json::json!(f.as_token())
        );
        assert!(seen.insert(f.bit()), "duplicate bit for {}", f.as_token());
        assert!(
            f.bit() < 64,
            "{} exceeds the 64-bit projection mask width",
            f.as_token()
        );
    }
    assert_eq!(seen.len(), ExportField::ALL.len());
    assert_eq!(ExportField::from_token("not_a_field"), None);
}

/// EVERY pinned field is also a default field of its stream. If it were not, the pinned-field
/// rule ("`fields:` may not omit it") would demand a field the stream's own contract does not
/// carry — an unsatisfiable config. This is what keeps pinning a NARROWING rule on the operator's
/// list rather than a widening of the stream's contract.
#[test]
fn pinned_fields_are_a_subset_of_default_fields() {
    for s in ExportStream::ALL {
        for p in s.pinned_fields() {
            assert!(
                s.default_fields().contains(p),
                "{} is pinned on stream {} but is not one of its default fields",
                p.as_token(),
                s.as_token()
            );
        }
    }
}

/// `correlation_id` is the JOIN KEY: it is pinned on every PER-REQUEST stream, because splitting
/// one request across streams means the sink must reassemble the pieces. `metrics` (aggregate),
/// `traces` (joined by its own span ids) and `events` (not per-request, joined by its chain) are
/// the documented exceptions.
#[test]
fn correlation_id_is_pinned_on_every_per_request_stream() {
    for s in ExportStream::ALL {
        let per_request = !matches!(
            s,
            ExportStream::Metrics | ExportStream::Traces | ExportStream::Events
        );
        assert_eq!(
            s.pinned_fields().contains(&ExportField::CorrelationId),
            per_request,
            "correlation_id pinning is wrong for stream {}",
            s.as_token()
        );
    }
    // The chain fields are what makes `events` verifiable; dropping `prev_hash` would leave
    // records that look complete and cannot be chain-checked.
    for f in [ExportField::Seq, ExportField::Ts, ExportField::PrevHash] {
        assert!(ExportStream::Events.pinned_fields().contains(&f));
    }
}

/// The response round-trips: the streams catalog and the deliver ack.
#[test]
fn response_json_roundtrip() {
    for r in [
        ExportResponse::Streams(vec![ExportStream::Metrics, ExportStream::Events]),
        ExportResponse::Delivered,
    ] {
        let j = serde_json::to_vec(&r).unwrap();
        let back: ExportResponse = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }
}

/// The export payload schema is at v2 (1.5.3, the projection grammar: expanded vocabulary,
/// `audit` removed) — pinned so the SDK/loader floor and the wire cannot drift.
#[test]
fn export_abi_version_is_two() {
    assert_eq!(EXPORT_ABI_VERSION, 2);
}

/// The HTTP-endpoint ops (`routes`/`http_endpoint`) round-trip and carry the stable op tags — the
/// additive wire behind plugin route registration + dispatch.
#[test]
fn http_endpoint_ops_roundtrip_and_tags() {
    use crate::http_endpoint::{HttpEndpointRequest, RouteAuth, RouteMethod};
    let reqs = vec![
        ExportRequest::Routes,
        ExportRequest::HttpEndpoint {
            request: HttpEndpointRequest {
                method: "GET".into(),
                path: "/metrics".into(),
                query: String::new(),
                headers: vec![],
                body: vec![],
            },
        },
    ];
    for r in reqs {
        let j = serde_json::to_vec(&r).unwrap();
        let back: ExportRequest = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }
    assert_eq!(
        serde_json::to_value(ExportRequest::Routes).unwrap()["op"],
        "routes"
    );
    assert_eq!(
        serde_json::to_value(ExportRequest::HttpEndpoint {
            request: HttpEndpointRequest {
                method: "GET".into(),
                path: "/metrics".into(),
                query: String::new(),
                headers: vec![],
                body: vec![],
            },
        })
        .unwrap()["op"],
        "http_endpoint"
    );

    // Response arms round-trip too.
    for resp in [
        ExportResponse::Routes(vec![Route {
            path: "/metrics".into(),
            method: RouteMethod::Get,
            auth: RouteAuth::None,
        }]),
        ExportResponse::Http(HttpEndpointResponse {
            status: 200,
            headers: vec![],
            body: b"ok".to_vec(),
        }),
    ] {
        let j = serde_json::to_vec(&resp).unwrap();
        let back: ExportResponse = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }
}
