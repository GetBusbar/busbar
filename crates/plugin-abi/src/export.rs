// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **export** payload schema (kind = [`crate::kind::EXPORT`]) that rides the kind-neutral `call`.
//!
//! ## One transport, every export op
//!
//! A `kind: export` plugin is a telemetry SINK behind the frozen six-symbol C ABI — the seam that
//! carries the engine's observability streams (metrics, logs, audit, traces) OUT to an external
//! backend. Like every other kind it exports the SAME six neutral symbols ([`crate::symbol`]) at
//! `busbar_abi() == TRANSPORT_VERSION`; only its manifest `kind` and its own tiny request enum
//! ([`ExportRequest`]) distinguish it. Every op rides the ONE `busbar_call` as an op-discriminated
//! JSON envelope — the variant IS the op-code, so the C symbol set never grows.
//!
//! ## Two ops
//!
//! - `streams` — asked ONCE at load: which observability streams does THIS instance carry? The
//!   engine retains the answer and only routes deliveries for streams the plugin declared.
//! - `deliver` — hand one already-serialized batch for a declared stream to the sink. The payload is
//!   carried as an opaque [`serde_json::Value`] the engine built; the export ABI adds the envelope,
//!   never a second copy of the batch semantics.

use crate::http_endpoint::{HttpEndpointRequest, HttpEndpointResponse, Route};
use serde::{Deserialize, Serialize};

/// The export-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: export`).
/// v1: the initial `streams`/`deliver` wire. This is the per-kind PAYLOAD axis, NOT the transport axis
/// — an export plugin exports the SAME six neutral symbols ([`crate::symbol`]) as every other kind, at
/// `busbar_abi() == TRANSPORT_VERSION`. Named the same way [`crate::SECRET_ABI_VERSION`] and
/// [`crate::hook::HOOK_ABI_VERSION`] are, so the loader floor and the SDK's declared version share one
/// const and cannot silently drift apart.
pub const EXPORT_ABI_VERSION: u32 = 1;

/// One observability stream an export sink can carry OUT of the engine. `#[serde(rename_all =
/// "snake_case")]` pins the wire spelling (`"metrics"`/`"logs"`/`"audit"`/`"traces"`) so a plugin
/// author in any language matches on a stable token, never the Rust variant name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportStream {
    /// The metrics stream (counters/gauges/histograms).
    Metrics,
    /// The structured-logs stream.
    Logs,
    /// The admin audit-record stream.
    Audit,
    /// The distributed-traces stream.
    Traces,
}

/// An export operation, serialized as the `call` request payload. One self-describing enum keeps the
/// C ABI to a single `call` symbol; the `op` tag is the op-code. Serialized with the op as a JSON tag
/// so a plugin matches on it directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExportRequest {
    /// `streams` — which [`ExportStream`]s does this instance carry? Asked once at load; the reply is
    /// [`ExportResponse::Streams`].
    Streams,
    /// `deliver` — hand one batch for `stream` to the sink. `payload` is the engine-built batch as an
    /// opaque JSON value. Reply: [`ExportResponse::Delivered`].
    Deliver {
        /// The declared stream this batch belongs to.
        stream: ExportStream,
        /// The already-serialized batch (opaque to the ABI; built by the engine).
        payload: serde_json::Value,
    },
    /// `routes` — asked ONCE at load: which HTTP [`Route`]s does this instance serve? The engine
    /// collision-checks + namespace-confines the answer, then mounts them (see the `http_endpoint`
    /// module doc). Reply: [`ExportResponse::Routes`]. ADDITIVE: an older sink that cannot decode this
    /// op declares no routes (the loader treats the undecodable-variant signal as "no HTTP surface").
    Routes,
    /// `http_endpoint` — dispatch one inbound HTTP request matched to a registered route of THIS
    /// plugin. Fires only for a matched plugin route, off the data-plane hot path; the engine already
    /// enforced the route's declared auth. Reply: [`ExportResponse::Http`].
    HttpEndpoint {
        /// The host-built inbound request (bounded headers, no raw `Authorization`).
        request: HttpEndpointRequest,
    },
}

/// The success payload for an export `call`, matched to the request variant. A module-level FAILURE (a
/// sink that genuinely errored) rides `STATUS_ERR` with a UTF-8 message, NOT here.
///
/// UNLIKE [`ExportRequest`] (`op`-tagged, snake_case), this type carries NO `#[serde(...)]` attribute,
/// so it serializes with serde's default externally-tagged representation — the SAME asymmetry
/// [`crate::hook::HookReply`] carries and for the same reason: this is JSON over the frozen C-ABI
/// transport, so a tagging change is a wire-breaking change, not a cosmetic one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportResponse {
    /// `streams` — the streams this instance carries.
    Streams(Vec<ExportStream>),
    /// `deliver` — the batch was accepted by the sink (nothing to read back).
    Delivered,
    /// `routes` — the HTTP routes this instance serves (collected once at load).
    Routes(Vec<Route>),
    /// `http_endpoint` — the plugin's response to a dispatched inbound request, relayed verbatim.
    Http(HttpEndpointResponse),
}

#[cfg(test)]
mod tests {
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
                stream: ExportStream::Audit,
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

    /// The stream tokens are the stable snake_case wire spellings a non-Rust author must match.
    #[test]
    fn stream_wire_spellings_are_pinned() {
        for (stream, tok) in [
            (ExportStream::Metrics, "metrics"),
            (ExportStream::Logs, "logs"),
            (ExportStream::Audit, "audit"),
            (ExportStream::Traces, "traces"),
        ] {
            assert_eq!(
                serde_json::to_value(stream).unwrap(),
                serde_json::json!(tok)
            );
        }
    }

    /// The response round-trips: the streams catalog and the deliver ack.
    #[test]
    fn response_json_roundtrip() {
        for r in [
            ExportResponse::Streams(vec![ExportStream::Metrics, ExportStream::Audit]),
            ExportResponse::Delivered,
        ] {
            let j = serde_json::to_vec(&r).unwrap();
            let back: ExportResponse = serde_json::from_slice(&j).unwrap();
            assert_eq!(serde_json::to_vec(&back).unwrap(), j);
        }
    }

    /// The export payload schema is at v1 — pinned so the SDK/loader floor and the wire cannot drift.
    #[test]
    fn export_abi_version_is_one() {
        assert_eq!(EXPORT_ABI_VERSION, 1);
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
}
