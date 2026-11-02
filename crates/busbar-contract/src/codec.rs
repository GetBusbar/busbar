// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CODEC-CELL SHAPES (DECISIONS #83: contract = shapes) — the traits a protocol's codec cells

use crate::billing::{Billing, TokenUsage};
use crate::bounded::SlabBytes;
use crate::ir::handle::IrHandle;
use crate::operation::OpVerb;
use serde_json::Value;

/// A serialized wire body plus the content-type the OperationHandler chose for it. The engine relays both without

pub struct WireBody {
    pub bytes: SlabBytes,
    pub content_type: http::HeaderValue,
}

impl WireBody {
    /// JSON body — the common case.
    pub fn json(bytes: SlabBytes) -> Self {
        Self {
            bytes,
            content_type: http::HeaderValue::from_static(crate::protocol::APPLICATION_JSON),
        }
    }
    /// A body with an explicit content-type (e.g. audio speech). Falls back to octet-stream if the

    pub fn typed(bytes: SlabBytes, content_type: &str) -> Self {
        let content_type = http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| http::HeaderValue::from_static("application/octet-stream"));
        Self {
            bytes,
            content_type,
        }
    }
}

/// The egress request wire a hop produced: a JSON `Value` still to be shim/model-shaped by the

pub enum EgressWire {
    /// A JSON egress body the router still post-shapes (shim-key strip, model rewrite, path-base).
    Json(Value),
    /// A final egress body a non-JSON wire already serialized.
    Bytes(SlabBytes),
    /// NO egress body could be written, and `reason` says why. The loud arm: a handle that cannot
    Unrepresentable { reason: String },
}

/// The neutral outcome of a non-stream cross-protocol response translation. Mirrors every exit of the

pub enum TranslatedResponse {
    /// A JSON ingress body (`application/json`) the caller still post-processes (native response-metrics
    Json(Value),
    /// A final ingress body + its own content-type (a non-JSON ingress wire — speech audio — or the
    Typed(WireBody),
    /// Synthesized native stream frames (a wants-stream ingress answered by a BUFFERED upstream —
    StreamFrames(Vec<u8>),
    /// JSON path only: the ingress protocol does not serve this operation → the caller renders the 404
    IngressUnsupported,
    /// Opaque path only: the egress read succeeded but the ingress handler is absent, so no client body
    Untranslatable,
}

/// What routing hands a request handler so it can render the upstream URL path. RESOLVED PRIMITIVES

pub struct EgressCtx<'a> {
    /// Which operation's endpoint to render — the template selector.
    pub operation: OpVerb,
    /// The resolved wire model id (routing calls `Lane::wire_model()`), for protocols that carry the
    pub model: &'a str,
    /// Whether the caller asked to stream (chat/audio path variants); `false` for the JSON ops.
    pub stream: bool,
    /// Optional per-provider path-BASE override (the lane's `path_base`). For URL-model protocols it
    pub path_base: Option<&'a str>,
}

/// A request that could not be parsed into this operation's IR — rendered as a caller-dialect 4xx
/// (via the existing `proxy::ingress_error`). `UnsupportedSubOp` is the second 404 site
/// (`ImageIr.op` unsupported for the model) — distinct from handler-absence, same terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressReject {
    BadRequest(String),
    UnsupportedSubOp { op: OpVerb, model: String },
}

/// An upstream response body this OperationHandler could not decode into its operation's IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Malformed(String),
}

/// A USAGE-TAP FAULT: why a cell's usage tap could not read a same-protocol 2xx body, so the request
/// billed 0 tokens. It is DATA the tap returns ([`OperationHandler::extract_usage`]'s `Err`): the
/// plane carries it out on its door's answer beside the units it reports
/// ([`crate::abi::plane::OnPieceOut::tap_fault`]), and the kernel counts it (one increment of
/// `busbar_billing_tap_decode_fail_total{protocol,reason}`) and warns once per `(protocol, reason)`.
/// The contract carries only the shape: no port, no latch and no static, so a codec reaches no host
/// to report it and holds nothing that counts it.
///
/// ```compile_fail
/// // There is no host port to report through: the fault is returned, never reported.
/// busbar_contract::codec::report_usage_tap_decode_failure(
///     "proto",
///     &busbar_contract::codec::CodecError::Malformed(String::new()),
/// );
/// ```
///
/// ```compile_fail
/// // And no latch a codec asks whether to warn: the kernel's count is the only one.
/// let _ = busbar_contract::codec::usage_tap_fault_should_warn("proto", "decode");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageTapFault {
    /// The cell's own reader refused the body (`decode`).
    Decode,
    /// The body is not JSON (`bad_json`).
    BadJson,
    /// The caller's dialect is not one the tap reads (`unknown_protocol`).
    UnknownProtocol,
}

impl UsageTapFault {
    /// The `reason` label the kernel counts the fault under.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            UsageTapFault::Decode => "decode",
            UsageTapFault::BadJson => "bad_json",
            UsageTapFault::UnknownProtocol => "unknown_protocol",
        }
    }

    /// The fault's code on the door's answer ([`crate::abi::plane::TAP_FAULT_DECODE`] and on).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            UsageTapFault::Decode => crate::abi::plane::TAP_FAULT_DECODE,
            UsageTapFault::BadJson => crate::abi::plane::TAP_FAULT_BAD_JSON,
            UsageTapFault::UnknownProtocol => crate::abi::plane::TAP_FAULT_UNKNOWN_PROTOCOL,
        }
    }

    /// The reason the kernel counts a door's answer code under, the byte read as the CLOSED enum

    #[must_use]
    pub const fn reason_of(code: u8) -> Option<&'static str> {
        match Self::of_code(code) {
            Some(fault) => Some(fault.reason()),
            None if code == crate::abi::plane::TAP_FAULT_NONE => None,
            None => Some(Self::UNKNOWN_REASON),
        }
    }

    /// The `reason` a tap-fault byte outside the vocabulary is counted under.
    pub const UNKNOWN_REASON: &'static str = "unknown";

    /// The fault a door's answer code names; `None` for [`crate::abi::plane::TAP_FAULT_NONE`] and

    #[must_use]
    pub const fn of_code(code: u8) -> Option<Self> {
        match code {
            crate::abi::plane::TAP_FAULT_DECODE => Some(UsageTapFault::Decode),
            crate::abi::plane::TAP_FAULT_BAD_JSON => Some(UsageTapFault::BadJson),
            crate::abi::plane::TAP_FAULT_UNKNOWN_PROTOCOL => Some(UsageTapFault::UnknownProtocol),
            _ => None,
        }
    }
}

/// The translation cap a plane bounds a response's translation at when its settings name none:
/// 32 MiB, the host's own default for an unconfigured `limits.request_body_max_bytes`. The cap a
/// plane enforces is the one the kernel hands it in the settings it is opened and refreshed with
/// (`limits.request_body_max_bytes`), held in the plane's own state. The contract carries only this
/// default: there is no reader to install and no port a codec reads the cap through.
///
/// ```compile_fail
/// // The cap is no host port: a codec reads it from the plane's own settings.
/// let _ = busbar_contract::codec::max_translate_body_bytes();
/// ```
///
/// ```compile_fail
/// busbar_contract::codec::install_translate_cap_reader(|| 0);
/// ```
pub const TRANSLATE_BODY_MAX_BYTES_DEFAULT: usize = 32 * 1024 * 1024;

/// THE HOST SERVICES A CODEC READS — the handle a codec is HANDED, never a port it reaches.
///
/// A codec that mints a random wire identifier, or stamps a creation time the answer it is writing
/// does not carry, reads the HOST's entropy and the HOST's wall clock through the `&dyn CodecHost`
/// its caller passes down the codec call graph: the kernel hands its own for the linked engine, a
/// plane's door hands one over the host services it was given at open. The contract carries only
/// the shape: it is the ABI's home of shapes and holds no state (gate `contract-stateless`), so
/// there is no process-wide port here to arm, and a codec with no handle has nothing to call.
///
/// ```compile_fail
/// // A codec cannot reach the host without the handle: there is no free port to call.
/// let mut id = [0u8; 16];
/// let _ = busbar_contract::codec::fill_entropy(&mut id);
/// ```
///
/// ```compile_fail
/// let _ = busbar_contract::codec::wall_clock_now();
/// ```
pub trait CodecHost: Sync {
    /// Fill `out` with fresh bytes from the host's CSPRNG and answer `true`, or answer `false` when

    fn fill_entropy(&self, out: &mut [u8]) -> bool;

    /// The host's wall clock, whole seconds since the Unix epoch, or `None` when the host holds no

    fn wall_clock_now(&self) -> Option<u64>;

    /// The host's MONOTONIC clock, nanoseconds from an origin fixed for the process's life (the

    fn monotonic_ns(&self) -> Option<u64> {
        None
    }
}

/// ONE ROW OF A PROTOCOL'S SUPPORT MATRIX — a verb the protocol speaks and the codec that speaks it.

pub type Cell = (OpVerb, &'static dyn OperationHandler);

/// THE ROW LOOKUP every [`RequestHandler::operation_handler`] is — stated once so there are not

pub fn cell_of(cells: &'static [Cell], op: OpVerb) -> Option<&'static dyn OperationHandler> {
    cells
        .iter()
        .find(|(candidate, _)| *candidate == op)
        .map(|(_, handler)| *handler)
}

/// THE (verb → upstream path) LOOKUP, for the protocols whose egress paths are constants rather

pub fn path_of(paths: &'static [(OpVerb, &'static str)], op: OpVerb) -> Option<&'static str> {
    paths
        .iter()
        .find(|(candidate, _)| *candidate == op)
        .map(|(_, path)| *path)
}

/// A pure per-(protocol × operation) codec. Feed it wire, assert the IR; feed it IR, assert the wire.

pub trait OperationHandler: Send + Sync {
    /// WHAT THIS UPSTREAM'S FAILURE MEANT — the attributed outcome of one outbound attempt, which

    fn extract_error(&self, status: u16, _body: &[u8]) -> crate::upstream::RawUpstreamError {
        crate::upstream::RawUpstreamError::from_status(status)
    }

    /// Can this operation produce a client-facing incremental stream?
    fn streaming(&self) -> bool {
        false
    }
    /// Should the non-stream 2xx body be buffered so [`Self::extract_usage`] can read it?
    fn taps_usage(&self) -> bool {
        false
    }
    /// The caller's stream intent, from the parsed ingress body. Chat reads the body's top-level

    fn wants_stream(&self, _body: &Value) -> bool {
        false
    }
    /// A body-derived session-affinity key (used only when no affinity header is present). Chat uses

    fn body_affinity_key<'a>(&self, _body: &'a Value) -> Option<&'a str> {
        None
    }
    /// Extract billable usage from a complete same-protocol non-stream 2xx body (called once at stream

    fn extract_usage(
        &self,
        host: &dyn CodecHost,
        _ingress_protocol: &str,
        body: &[u8],
    ) -> Result<Option<TokenUsage>, UsageTapFault> {
        match self.read_response(host, body) {
            Ok(r) => Ok(r.token_usage()),
            Err(_) => Err(UsageTapFault::Decode),
        }
    }
    /// Recover independently reported billing when the complete response cannot be decoded.

    fn recover_response_billing(&self, _host: &dyn CodecHost, _body: &[u8]) -> Option<Billing> {
        None
    }
    /// The Content-Type of THIS operation's egress request wire (what `write_request` emits).

    fn egress_request_content_type(&self) -> &'static str {
        crate::protocol::APPLICATION_JSON
    }

    /// The egress `Accept` header for the upstream request. `egress_stream_accept` is the egress

    fn egress_accept(
        &self,
        egress_stream_accept: &'static str,
        wants_stream: bool,
    ) -> &'static str {
        if wants_stream {
            egress_stream_accept
        } else {
            crate::protocol::APPLICATION_JSON
        }
    }

    /// Value-level codec bridge (request) — for engine seams that already hold a PARSED JSON body

    fn read_request_value(&self, v: &Value) -> Result<Box<dyn IrHandle>, IngressReject> {
        let bytes = serde_json::to_vec(v).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        self.read_request(&bytes, crate::protocol::APPLICATION_JSON)
    }
    /// Value-level codec bridge (response).
    fn read_response_value(
        &self,
        host: &dyn CodecHost,
        v: &Value,
    ) -> Result<Box<dyn IrHandle>, CodecError> {
        let bytes = serde_json::to_vec(v).map_err(|e| CodecError::Malformed(e.to_string()))?;
        self.read_response(host, &bytes)
    }

    /// Wire → IR HANDLE (request). The OperationHandler owns the ENTIRE wire format: it receives RAW

    fn read_request(
        &self,
        body: &[u8],
        content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject>;
    /// Egress wire → IR HANDLE (response) — for the usage tap or a cross-protocol translation. Raw

    fn read_response(
        &self,
        host: &dyn CodecHost,
        wire: &[u8],
    ) -> Result<Box<dyn IrHandle>, CodecError>;
}

/// A protocol's dialect + its OperationHandlers (one impl per protocol).
pub trait RequestHandler: Send + Sync {
    /// Stable protocol identity (matches the dialect's own protocol name). Called only from `busbar-core`'s

    fn protocol_name(&self) -> &'static str;

    /// This protocol's row of the support matrix. `None` ⇒ the protocol does not serve the operation

    fn operation_handler(&self, op: OpVerb) -> Option<&dyn OperationHandler>;

    /// WHICH operation this request asks for — the RequestHandler knows its protocol and reads the

    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<OpVerb>;

    /// The model named in the PATH, for path-model dialects (`models/{m}:action`,

    fn path_model(&self, _path: &str) -> Option<String> {
        None
    }

    /// The `(protocol, operation) → path template` map: this protocol's upstream URL for the operation

    fn upstream_path(&self, ctx: &EgressCtx) -> String;
}
