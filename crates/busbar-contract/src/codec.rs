// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared wire bodies, neutral IR outcomes, usage faults and explicit host services.

use crate::bounded::SlabBytes;
use serde_json::Value;

/// A serialized wire body plus the content type its producer chose for it. The engine relays both without
#[derive(Debug)]
pub struct WireBody {
    /// Serialized payload bytes in the caller-owned slab.
    pub bytes: SlabBytes,
    /// Media type selected by the payload producer.
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
#[derive(Debug)]
pub enum EgressWire {
    /// A JSON egress body the router still post-shapes (shim-key strip, model rewrite, path-base).
    Json(Value),
    /// A final egress body a non-JSON wire already serialized.
    Bytes(SlabBytes),
    /// NO egress body could be written, and `reason` says why. The loud arm: a handle that cannot
    Unrepresentable {
        /// Why the requested representation cannot carry this payload.
        reason: String,
    },
}

/// The neutral outcome of a non-stream cross-protocol response translation. Mirrors every exit of the
#[derive(Debug)]
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

/// An upstream response body a producer could not decode into its operation's IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The payload violates the selected codec's grammar or required shape.
    Malformed(String),
}

/// A USAGE-TAP FAULT: why a cell's usage tap could not read a same-protocol 2xx body, so the request
/// billed 0 tokens. It is DATA the tap returns (a plane codec's error result): the
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
