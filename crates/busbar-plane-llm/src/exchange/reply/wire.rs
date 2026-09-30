//! The reply's byte helpers: the pure functions the previous release's answer path called between
//! its reads and its writes, moved here whole so the served path and the plane run one copy.
//!
//! Each is a read of a dialect declaration or a dialect codec and nothing else: which content types
//! stream, which content type a caller's stream wears, which far-end head fields a caller's dialect
//! relays and which request id it carries, the kind and message a far-end error is reshaped with,
//! the in-band error frame a cut stream ends on, the usage a body reported (or the floor it bills
//! when it reported none that can be read), the open classes a delivery counted, and whether a
//! generation the far end answered failed.

use std::collections::BTreeMap;

use busbar_contract::billing::{Billing, TokenUsage};
use busbar_contract::protocol::{
    ProtocolDecl, StreamTranslator, KIND_API_ERROR, KIND_AUTHENTICATION, KIND_INVALID_REQUEST,
    KIND_OVERLOADED, KIND_PERMISSION, KIND_RATE_LIMIT, KIND_TIMEOUT, PROVIDER_CODE_CONTEXT_LENGTH,
};
use busbar_contract::upstream::{CanonicalSignal, StatusClass};
use serde_json::Value;

use crate::codec::wire_shim::TRUNCATED_TAIL_BYTES_PER_TOKEN;
use crate::codec::DECLS;

fn decl(name: &str) -> Option<&'static ProtocolDecl> {
    DECLS.iter().copied().find(|d| d.name == name)
}

/// The message a far-end error with no readable message of its own is answered with.
pub const GENERIC_REJECTED_DETAIL: &str = "The request could not be processed.";

/// The message an answer that could not be relayed is answered with: a transfer that failed, a
/// body over the translation cap, or a shape the caller's dialect cannot be written from.
pub const GENERIC_RESPONSE_ERROR_DETAIL: &str =
    "An internal error occurred while processing the response.";

/// The message a stream cut after its first byte ends on.
pub const MID_STREAM_GENERIC_DETAIL: &str = busbar_contract::protocol::STREAM_ABORT_DETAIL;

/// True for a content type that carries an incremental answer: a content type some dialect
/// declares as its streaming one.
#[must_use]
pub fn is_stream_content_type(ct: &str) -> bool {
    DECLS
        .iter()
        .filter_map(|d| d.streaming_content_type)
        .any(|p| ct.starts_with(p))
}

/// The streaming content type the caller's dialect expects, or `None` for a dialect the plane does
/// not hold (the far end's content type is then kept).
#[must_use]
pub fn ingress_stream_content_type(ingress: &str) -> Option<&'static str> {
    decl(ingress).and_then(|d| d.streaming_content_type)
}

/// Whether every answer to a caller of `ingress` carries the far end's `x-amzn-*` head fields.
#[must_use]
pub fn ingress_relays_amzn_headers(ingress: &str) -> bool {
    decl(ingress).is_some_and(|d| d.ingress_relays_amzn_headers)
}

/// The far-end head field names a caller of `ingress` has relayed verbatim on a same-dialect
/// answer; the first is the primary request id.
#[must_use]
pub fn ingress_relayed_response_header_names(ingress: &str) -> &'static [&'static str] {
    decl(ingress).map_or(&[], |d| d.ingress_relayed_response_header_names)
}

/// The request-id head field a caller of `ingress` reads on its answer: the far end's own id when
/// one was captured, else a minted one; `None` for a dialect that carries none.
#[must_use]
pub fn response_request_id(
    ingress: &str,
    upstream_request_id: Option<&str>,
) -> Option<(&'static str, String)> {
    decl(ingress)
        .and_then(|d| d.dialect())
        .and_then(|di| di.ingress_response_request_id(upstream_request_id))
}

/// The error kind a far-end status is reshaped into for a caller of another dialect: the native
/// discriminant a single-vendor API uses for that status.
#[must_use]
pub fn cross_protocol_error_kind(status: u16) -> &'static str {
    match status {
        401 => KIND_AUTHENTICATION,
        403 => KIND_PERMISSION,
        429 => KIND_RATE_LIMIT,
        503 => KIND_OVERLOADED,
        504 => KIND_TIMEOUT,
        500..=599 => KIND_API_ERROR,
        _ => KIND_INVALID_REQUEST,
    }
}

/// The error kind a client-fault far-end error is reshaped with, by its class.
#[must_use]
pub fn client_fault_kind(class: StatusClass) -> &'static str {
    match class {
        StatusClass::ContextLength => PROVIDER_CODE_CONTEXT_LENGTH,
        StatusClass::ClientError => KIND_INVALID_REQUEST,
        StatusClass::RateLimit
        | StatusClass::Overloaded
        | StatusClass::ServerError
        | StatusClass::Timeout
        | StatusClass::Network
        | StatusClass::Auth
        | StatusClass::Billing => KIND_INVALID_REQUEST,
    }
}

/// The human message of a far-end error body (`error.message`, else a top-level `message`), or
/// `None` when the body is not JSON or names none.
#[must_use]
pub fn extract_error_message(bytes: &[u8]) -> Option<String> {
    let v: Value = crate::codec::json::parse(bytes).ok()?;
    v.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .or_else(|| v.get("message").and_then(|m| m.as_str()))
        .map(|s| s.to_string())
}

/// The kind and message a far-end error of `status` is reshaped with for a caller of another
/// dialect: its own message when it has one, else the generic one.
#[must_use]
pub fn cross_protocol_error(status: u16, bytes: &[u8]) -> (&'static str, String) {
    let kind = cross_protocol_error_kind(status);
    let msg = extract_error_message(bytes).unwrap_or_else(|| GENERIC_REJECTED_DETAIL.to_string());
    (kind, msg)
}

/// The bytes a stream cut after its first byte ends on, in the caller's own framing: a modeled
/// exception frame for a binary event-stream caller, else the caller's streaming error event, asked
/// of the live translator first (so the frame continues the stream's identity) and of the dialect
/// second; a dialect the plane does not hold, or one that frames no in-band error, gets a bare
/// `data:` frame.
#[must_use]
pub fn mid_stream_error_bytes(
    ingress: &str,
    ingress_eventstream: bool,
    message: &str,
    translate: Option<&mut (dyn StreamTranslator + 'static)>,
) -> Vec<u8> {
    let err = CanonicalSignal {
        class: StatusClass::ServerError,
        provider_signal: Some(message.to_string()),
        retry_after: None,
    };
    let Some(dialect) = decl(ingress).and_then(|d| d.dialect()) else {
        return agnostic_stream_error_frame(message);
    };
    if ingress_eventstream {
        if let Some((exc_name, msg)) = dialect.write_response_exception(&err) {
            return crate::codec::eventstream::encode_exception_frame(&exc_name, &msg);
        }
    }
    let frame = translate
        .and_then(|t| t.terminal_error_frame(&err))
        .or_else(|| dialect.write_error_frame(&err));
    match frame {
        Some((event_type, data)) => {
            let data = crate::codec::json::to_string(&data).unwrap_or_else(|_| {
                serde_json::json!({ "error": { "message": message, "type": KIND_API_ERROR } })
                    .to_string()
            });
            if event_type.is_empty() {
                format!("data: {data}\n\n").into_bytes()
            } else {
                format!("event: {event_type}\ndata: {data}\n\n").into_bytes()
            }
        }
        None => agnostic_stream_error_frame(message),
    }
}

/// The dialect-free terminal stream error frame: a bare `data:` frame over the agnostic envelope.
#[must_use]
pub fn agnostic_stream_error_frame(message: &str) -> Vec<u8> {
    let data = super::super::refuse::agnostic_envelope(KIND_API_ERROR, message).to_string();
    format!("data: {data}\n\n").into_bytes()
}

/// The floor a delivered body that demonstrably spent tokens bills when its usage cannot be read:
/// the bytes in hand over the conservative bytes-per-token divisor, as output, never zero.
#[must_use]
pub fn estimate_usage_from_truncated_tail(tail_len: usize) -> TokenUsage {
    TokenUsage {
        output: (tail_len as u64 / TRUNCATED_TAIL_BYTES_PER_TOKEN).max(1),
        ..Default::default()
    }
}

/// The usage the far end reported in the bytes in hand (the dialect's own scan for its usage
/// object), and nothing else.
#[must_use]
pub fn reported_usage(protocol: &str, buf: &[u8]) -> Option<TokenUsage> {
    decl(protocol)
        .and_then(|d| d.dialect())
        .and_then(|di| di.recover_truncated_usage(buf))
}

/// The usage of a delivered body whose usage could not be read whole: what the dialect's scan
/// recovers, else the floor over the bytes in hand.
#[must_use]
pub fn unrecovered_usage(protocol: &str, buf: &[u8]) -> TokenUsage {
    reported_usage(protocol, buf).unwrap_or_else(|| estimate_usage_from_truncated_tail(buf.len()))
}

/// The token figures of a delivery's billing, or `None` for a billing that counts no tokens.
#[must_use]
pub fn token_usage_of(usage: &Option<Billing>) -> Option<TokenUsage> {
    match usage {
        Some(Billing::Tokens(t)) => Some(t.clone()),
        Some(Billing::Duration { .. })
        | Some(Billing::Characters { .. })
        | Some(Billing::Images { .. })
        | Some(Billing::Counted { .. })
        | Some(Billing::Flat)
        | None => None,
    }
}

/// Every open class a delivery counted, by class: a counted unit verbatim, nothing for any other
/// shape.
#[must_use]
pub fn open_units_of(usage: &Option<Billing>) -> BTreeMap<String, u64> {
    match usage {
        Some(Billing::Counted { class, count }) => BTreeMap::from([(class.clone(), *count)]),
        Some(Billing::Tokens(_))
        | Some(Billing::Duration { .. })
        | Some(Billing::Characters { .. })
        | Some(Billing::Images { .. })
        | Some(Billing::Flat)
        | None => BTreeMap::new(),
    }
}

/// Whether the far end reported this whole answer's generation as failed: its dialect's reader
/// reads the stop reason as the error reason. A body the reader refuses answers `false`.
#[must_use]
pub fn generation_failed(egress: &str, rv: &Value) -> bool {
    crate::codec::proto_codec::with_reader(egress, |r| r.read_response(rv))
        .and_then(Result::ok)
        .is_some_and(|ir| ir.stop_reason == Some(crate::codec::ir::IrStopReason::Error))
}
