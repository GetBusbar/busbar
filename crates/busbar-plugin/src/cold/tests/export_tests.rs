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
        // plane-purity: frozen-wire ExportDefCfg `streams:` token (frozen since 1.5.5)
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

/// The export payload schema is at v3 (DECISIONS #85: the response became
/// [`crate::cold::observe::Envelope`]`<ExportResponse>`, so a sink can report the metrics it
/// produced and the diagnostics it raised) — pinned so the SDK's declared version, the loader's
/// window and the wire cannot drift apart.
///
/// v2 was 1.5.3's projection grammar (expanded vocabulary, `audit` removed) and is STILL LOADABLE:
/// #85 widened the window to `[2, 3]` rather than moving it, because a sink built against the bare
/// response is read by the loader exactly as it always was.
#[test]
fn export_abi_version_is_three() {
    assert_eq!(EXPORT_ABI_VERSION, 3);
}

/// THE MINOR COUNTS THE ADDITIVE HOST SEAMS (K9a) and moves with each one, while the version the
/// loader gates on stays put — pinned so a seam cannot land without saying so.
#[test]
fn export_abi_minor_counts_the_host_seams() {
    assert_eq!((EXPORT_ABI_VERSION, EXPORT_ABI_MINOR), (3, 9));
}

/// S1's declaration wire: `{"name": …, "type": …}`, the same `type` token a reported metric carries.
#[test]
fn a_declared_series_wire_is_pinned() {
    let d = crate::cold::observe::SeriesDecl::new("busbar_x_total", "counter");
    assert_eq!(
        serde_json::to_value(&d).expect("encode"),
        serde_json::json!({"name": "busbar_x_total", "type": "counter"})
    );
    // K9b's shed flag rides the same object, and only when set — an S1 declaration's bytes (and
    // therefore its signature) are unchanged by the flag existing.
    assert_eq!(
        serde_json::to_value(d.shed()).expect("encode"),
        serde_json::json!({"name": "busbar_x_total", "type": "counter", "shed": true})
    );
}

/// THE ENVELOPE IS THE EXPORT RESPONSE. The wire a v3 sink answers on is the kind's response
/// wrapped in `{ result, metrics[], diagnostics[] }` — pinned here because a plugin author in any
/// language matches these three keys literally, so their spelling is a contract and not a detail.
#[test]
fn a_v3_export_response_rides_the_observability_envelope() {
    use crate::cold::observe::{Envelope, Observations, PluginMetric};
    let enveloped = Observations::none()
        .metric(PluginMetric::counter("logs_rotated_total", 1.0))
        .into_envelope(ExportResponse::Delivered);
    assert_eq!(
        serde_json::to_string(&enveloped).unwrap(),
        r#"{"result":"Delivered","metrics":[{"name":"logs_rotated_total","type":"counter","value":1.0}]}"#
    );
    // And a sink with nothing to report costs exactly the wrapper: the back-channel is not a
    // per-call tax on a plugin that does not use it.
    let bare: Envelope<ExportResponse> = Envelope::bare(ExportResponse::Delivered);
    assert_eq!(
        serde_json::to_string(&bare).unwrap(),
        r#"{"result":"Delivered"}"#
    );
}

/// The HTTP-endpoint ops (`routes`/`http_endpoint`) round-trip and carry the stable op tags — the
/// additive wire behind plugin route registration + dispatch.
#[test]
fn http_endpoint_ops_roundtrip_and_tags() {
    use crate::cold::endpoint::{EndpointRequest, RouteAuth, RouteMethod};
    let reqs = vec![
        ExportRequest::Routes,
        ExportRequest::Endpoint {
            request: EndpointRequest {
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
        serde_json::to_value(ExportRequest::Endpoint {
            request: EndpointRequest {
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
        ExportResponse::Endpoint(EndpointResponse {
            status: 200,
            headers: vec![],
            body: b"ok".to_vec(),
        }),
    ] {
        let j = serde_json::to_vec(&resp).unwrap();
        let back: ExportResponse = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }
    // The externally-tagged Response wire key must still be "Http", byte-identical, despite the
    // Rust variant being renamed Http -> Endpoint.
    assert_eq!(
        serde_json::to_value(ExportResponse::Endpoint(EndpointResponse {
            status: 200,
            headers: vec![],
            body: b"ok".to_vec(),
        }))
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap(),
        "Http"
    );
}

/// The `status` op's wire is pinned: the request tag a sink matches on, and the response shape the
/// host folds. A plugin author in any language matches these spellings literally, and an older sink
/// that cannot decode the op answers `STATUS_UNSUPPORTED` — which is what makes the op additive —
/// so neither spelling may drift.
#[test]
fn status_op_wire_is_pinned() {
    assert_eq!(
        serde_json::to_string(&ExportRequest::Status).unwrap(),
        r#"{"op":"status"}"#
    );
    let resp = ExportResponse::Status {
        metrics: vec![serde_json::json!({"name": "queue_depth", "type": "gauge", "value": 3.0})],
        diagnostics: vec![],
    };
    let j = serde_json::to_string(&resp).unwrap();
    assert_eq!(
        j,
        r#"{"Status":{"metrics":[{"name":"queue_depth","type":"gauge","value":3.0}],"diagnostics":[]}}"#
    );
    let back: ExportResponse = serde_json::from_str(&j).unwrap();
    assert_eq!(serde_json::to_string(&back).unwrap(), j);
    // Either list may be omitted by the sink: an empty report is a valid answer.
    let omitted: ExportResponse = serde_json::from_str(r#"{"Status":{}}"#).unwrap();
    assert!(matches!(
        omitted,
        ExportResponse::Status { metrics, diagnostics } if metrics.is_empty() && diagnostics.is_empty()
    ));
}

/// S2's op wire: `{"op":"validate","instance":…,"settings":…}` answered `{"Validated":[…]}`.
#[test]
fn the_validate_op_wire_is_pinned() {
    let req = ExportRequest::Validate {
        instance: "tail".into(),
        settings: serde_json::json!({"k": 1}),
    };
    assert_eq!(
        serde_json::to_value(&req).expect("encode"),
        serde_json::json!({"op": "validate", "instance": "tail", "settings": {"k": 1}})
    );
    let resp = ExportResponse::Validated(vec!["export.tail.settings: no".into()]);
    assert_eq!(
        serde_json::to_value(&resp).expect("encode"),
        serde_json::json!({"Validated": ["export.tail.settings: no"]})
    );
}

/// S3's declaration wire: the catalogue entry's fields, one for one, and nothing else.
#[test]
fn a_declared_diagnostic_wire_is_pinned() {
    let wire = serde_json::json!({
        "code": 6990, "slug": "s", "title": "t", "severity": "actionable",
        "summary": "m", "action": "a", "since": "1.6.0"
    });
    let d: crate::cold::observe::DiagnosticDecl =
        serde_json::from_value(wire.clone()).expect("decode");
    assert_eq!(serde_json::to_value(&d).expect("encode"), wire);
    let mut extra = wire;
    extra["retired"] = serde_json::json!(true);
    assert!(serde_json::from_value::<crate::cold::observe::DiagnosticDecl>(extra).is_err());
}

/// S4's continuation wire: a delivery answered `{"Host":{"token":…,"ops":[…]}}` and resumed with
/// `{"op":"resume","token":…,"results":[…]}`.
#[test]
fn the_host_op_continuation_wire_is_pinned() {
    let asked = ExportResponse::Host {
        token: 7,
        ops: vec![HostOp::Write {
            destination: "path".into(),
            data: "line\n".into(),
            rotate_at: Some(10),
            keep: 9,
        }],
    };
    assert_eq!(
        serde_json::to_value(&asked).expect("encode"),
        serde_json::json!({"Host": {"token": 7, "ops": [
            {"op": "write", "destination": "path", "data": "line\n", "rotate_at": 10, "keep": 9}
        ]}})
    );
    let resumed = ExportRequest::Resume {
        token: 7,
        results: vec![
            HostResult::Done {
                rotation: Some(Rotation {
                    archive: "/l.1".into(),
                    renamed: true,
                    faults: vec![],
                }),
            },
            HostResult::Failed {
                step: "open".into(),
                error: "denied".into(),
                rotation: None,
            },
        ],
    };
    assert_eq!(
        serde_json::to_value(&resumed).expect("encode"),
        serde_json::json!({"op": "resume", "token": 7, "results": [
            {"outcome": "done", "rotation": {"archive": "/l.1", "renamed": true}},
            {"outcome": "failed", "step": "open", "error": "denied"}
        ]})
    );
    let defaulted: HostOp =
        serde_json::from_value(serde_json::json!({"op": "rotate", "destination": "path"}))
            .expect("decode");
    assert_eq!(
        defaulted,
        HostOp::Rotate {
            destination: "path".into(),
            keep: 9
        }
    );
}

/// S5's carrier wire: `{"op":"http","method":…,"url":…,…}` answered `{"outcome":"http","status":…}`.
#[test]
fn the_egress_carrier_wire_is_pinned() {
    let asked = HostOp::Http(HttpRequest {
        method: "POST".into(),
        url: "https://collector.example/v1".into(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: "{}".into(),
        timeout_ms: 5000,
    });
    assert_eq!(
        serde_json::to_value(&asked).expect("encode"),
        serde_json::json!({"op": "http", "method": "POST", "url": "https://collector.example/v1",
            "headers": [["content-type", "application/json"]], "body": "{}", "timeout_ms": 5000})
    );
    let answered = HostResult::Http(HttpResponse {
        status: 204,
        body: String::new(),
    });
    assert_eq!(
        serde_json::to_value(&answered).expect("encode"),
        serde_json::json!({"outcome": "http", "status": 204})
    );
}

/// S6's snapshot wire: `{"op":"scrape","families":[{"name","type","help","samples":[…]}]}`
/// answered `{"Exposition":{"content_type","body"}}`.
#[test]
fn the_recorder_snapshot_wire_is_pinned() {
    let req = ExportRequest::Scrape {
        families: vec![MetricFamily {
            name: "x_seconds".into(),
            kind: "summary".into(),
            help: Some("h".into()),
            samples: vec![MetricSample {
                name: "x_seconds".into(),
                labels: vec![("quantile".into(), "0.5".into())],
                value: "0.25".into(),
            }],
        }],
    };
    assert_eq!(
        serde_json::to_value(&req).expect("encode"),
        serde_json::json!({"op": "scrape", "families": [{"name": "x_seconds", "type": "summary",
            "help": "h", "samples": [{"name": "x_seconds", "labels": [["quantile", "0.5"]],
            "value": "0.25"}]}]})
    );
    let resp = ExportResponse::Exposition {
        content_type: "text/plain; version=0.0.4".into(),
        body: String::new(),
    };
    assert_eq!(
        serde_json::to_value(&resp).expect("encode"),
        serde_json::json!({"Exposition": {"content_type": "text/plain; version=0.0.4", "body": ""}})
    );
}

/// K9c's wire (export ABI minor 8): the `start` / `check` ops, the `Started` answer and the
/// `admit` host op — pinned so a sink in any language matches on stable bytes.
#[test]
fn the_start_check_and_admit_wire_is_pinned() {
    let start = serde_json::to_string(&ExportRequest::Start).unwrap();
    assert_eq!(start, r#"{"op":"start"}"#);
    let check = ExportRequest::Check {
        instances: vec![("a".into(), serde_json::json!({"url": "https://x/"}))],
        phase: CheckPhase::Limits,
    };
    assert_eq!(
        serde_json::to_string(&check).unwrap(),
        r#"{"op":"check","instances":[["a",{"url":"https://x/"}]],"phase":"limits"}"#
    );
    // Absent (the minor-8 wire): after the limits.
    let bare: ExportRequest = serde_json::from_str(r#"{"op":"check","instances":[]}"#).unwrap();
    assert!(matches!(
        bare,
        ExportRequest::Check {
            phase: CheckPhase::Instances,
            ..
        }
    ));
    let started = ExportResponse::Started {
        live: true,
        inflight: 64,
        gate: "webhook".into(),
    };
    assert_eq!(
        serde_json::to_string(&started).unwrap(),
        r#"{"Started":{"live":true,"inflight":64,"gate":"webhook"}}"#
    );
    // `inflight` / `gate` default: the host's admission.
    let bare: ExportResponse = serde_json::from_str(r#"{"Started":{"live":false}}"#).unwrap();
    assert!(
        matches!(bare, ExportResponse::Started { live: false, inflight: 0, ref gate } if gate.is_empty())
    );
    let admit = HostOp::Admit {
        url: "https://x/".into(),
    };
    assert_eq!(
        serde_json::to_string(&admit).unwrap(),
        r#"{"op":"admit","url":"https://x/"}"#
    );
}
