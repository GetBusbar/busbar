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
    HeadFields, ProtocolDecl, StreamTranslator, KIND_API_ERROR, KIND_AUTHENTICATION,
    KIND_INVALID_REQUEST, KIND_OVERLOADED, KIND_PERMISSION, KIND_RATE_LIMIT, KIND_TIMEOUT,
    PROVIDER_CODE_CONTEXT_LENGTH,
};
use busbar_contract::upstream::{CanonicalSignal, StatusClass};
use serde_json::Value;

use crate::codec::wire_shim::TRUNCATED_TAIL_BYTES_PER_TOKEN;
use crate::codec::DECLS;

use crate::exchange::decl_for as decl;

/// The message a far-end error with no readable message of its own is answered with.
pub const GENERIC_REJECTED_DETAIL: &str = "The request could not be processed.";

/// The message an answer that could not be relayed is answered with: a transfer that failed, a
/// body over the translation cap, or a shape the caller's dialect cannot be written from.
pub const GENERIC_RESPONSE_ERROR_DETAIL: &str =
    "An internal error occurred while processing the response.";

/// The message a stream cut after its first byte ends on.
pub const MID_STREAM_GENERIC_DETAIL: &str = busbar_contract::protocol::STREAM_ABORT_DETAIL;

/// The content type `d` declares for a streamed answer.
fn stream_ct(d: &ProtocolDecl) -> Option<&'static str> {
    d.streaming_content_type
}

/// True for a content type that carries an incremental answer: a content type some dialect
/// declares for a streamed answer.
#[must_use]
pub fn is_stream_content_type(ct: &str) -> bool {
    DECLS
        .iter()
        .filter_map(|d| stream_ct(d))
        .any(|p| ct.starts_with(p))
}

/// The content type the caller's dialect expects on a streamed answer, or `None` for a dialect the
/// plane does not hold (the far end's content type is then kept).
#[must_use]
pub fn ingress_stream_content_type(ingress: &str) -> Option<&'static str> {
    decl(ingress).and_then(stream_ct)
}

/// Whether busbar governs the answer head field `name` (compared without case) for a caller of
/// `dialect`: the far end's echo of busbar's own credential or tenant, never relayed.
#[must_use]
pub fn governed_response(dialect: &str, name: &str) -> bool {
    crate::dialect::dialect(dialect).is_some_and(|d| {
        d.governed_response_headers
            .iter()
            .any(|g| name.eq_ignore_ascii_case(g))
    })
}

/// Relay the far end's head onto a same-dialect answer (busbar is invisible to the caller too): each
/// far field, in order, under a name the answer's own `fields` do not already carry, but the ones
/// the dialect governs ([`governed_response`]). The per-connection fields are the writer's to drop
/// as it writes the answer; nothing is invented.
pub fn relay_far_head(
    dialect: &str,
    fields: &mut Vec<(String, Vec<u8>)>,
    far_head: HeadFields<'_>,
) {
    let own = fields.len();
    for (name, value) in far_head {
        let Some((name, value)) = std::str::from_utf8(name)
            .ok()
            .and_then(|n| head_field(n, value))
        else {
            continue;
        };
        if !governed_response(dialect, &name) && !fields[..own].iter().any(|(n, _)| *n == name) {
            fields.push((name, value));
        }
    }
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

/// The first value of the head field `name` in `head`, the name matched in any case.
#[must_use]
pub fn head_value<'a>(head: HeadFields<'a>, name: &str) -> Option<&'a [u8]> {
    head.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| *v)
}

/// A head field's value as text: visible ASCII and the tab, else `None`.
#[must_use]
pub fn head_text(value: &[u8]) -> Option<&str> {
    value
        .iter()
        .all(|b| *b == b'\t' || (0x20..0x7f).contains(b))
        .then(|| std::str::from_utf8(value).ok())
        .flatten()
}

/// Whether `b` may appear in a head field name (a token character).
fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A head field as a caller reads it: the name in its wire (lower-case) form, so a dialect may
/// declare a relayed field the way its vendor spells it. A name that is not a legal field name is
/// dropped, never relayed and never fatal.
#[must_use]
pub fn head_field(name: &str, value: &[u8]) -> Option<(String, Vec<u8>)> {
    (!name.is_empty() && name.bytes().all(name_byte))
        .then(|| (name.to_ascii_lowercase(), value.to_vec()))
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
/// exception frame for a binary event-stream caller, else the caller's own in-band error event,
/// asked of the live translator first (so the frame continues the stream's identity) and of the
/// dialect second; a dialect the plane does not hold, or one that frames no in-band error, gets a
/// bare `data:` frame.
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

/// Every open class a delivery counted that is not a token, by class (owner LEDGER-100: every unit
/// the far end reports is a ledger line under its meter class):
///
/// - a counted unit (a rerank's search units) verbatim;
/// - a per-image answer's image count as `images`;
/// - a transcription's reported duration as `audio_ms`, the exact decimal floored to the whole
///   millisecond (integer only; never more than was reported).
///
/// Token usage reaches the ledger through [`token_usage_of`] (its open counts ride
/// `TokenUsage::open_units`). `Characters` is the TTS request-seam size, no answer carries it,
/// and `Flat` reports no count. A zero count is no hit on its class.
#[must_use]
pub fn open_units_of(usage: &Option<Billing>) -> BTreeMap<String, u64> {
    use crate::codec::ir::open_class::{add, AUDIO_MS_CLASS, IMAGES_CLASS};
    let mut open = BTreeMap::new();
    match usage {
        Some(Billing::Counted { class, count }) => {
            open.insert(class.clone(), *count);
        }
        Some(Billing::Images { count, .. }) => add(&mut open, IMAGES_CLASS, u64::from(*count)),
        Some(Billing::Duration { seconds }) => {
            let ms = seconds.micros().max(0) / 1_000;
            add(
                &mut open,
                AUDIO_MS_CLASS,
                u64::try_from(ms).unwrap_or(u64::MAX),
            );
        }
        Some(Billing::Tokens(_))
        | Some(Billing::Characters { .. })
        | Some(Billing::Flat)
        | None => {}
    }
    open
}

/// Whether the far end reported this whole answer's generation as failed: its dialect's reader
/// reads the stop reason as the error reason. A body the reader refuses answers `false`.
#[must_use]
pub fn generation_failed(egress: &str, rv: &Value) -> bool {
    crate::codec::proto_codec::with_reader(egress, |r| r.read_response(rv))
        .and_then(Result::ok)
        .is_some_and(|ir| ir.stop_reason == Some(crate::codec::ir::IrStopReason::Error))
}
