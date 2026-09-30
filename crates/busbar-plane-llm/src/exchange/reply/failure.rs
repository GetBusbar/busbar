//! A far end's error answer, judged: what the error means (the far end's dialect reads it, the
//! provider's error map places it in a class, the class names its disposition) and what the caller
//! reads for it.
//!
//! The caller's answer is the previous release's, by disposition: a caller's own credential failing
//! at the far end, and a client fault on a same-dialect hop, are the far end's bytes relayed
//! verbatim (with the head fields a native answer carries); a client fault across dialects is
//! reshaped into the caller's envelope; the far end refusing the deployment's own credential is
//! the caller dialect's own authentication refusal; and every failure the walk may go past carries
//! the relay the walk answers with if it ends there.

use std::collections::HashMap;

use busbar_contract::http::{HeaderMap, HeaderName};
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::{ProtocolDecl, KIND_AUTHENTICATION, PROVIDER_CODE_CONTEXT_LENGTH};
use busbar_contract::upstream::{CanonicalSignal, Disposition, RawUpstreamError, StatusClass};

use super::super::refuse::{render, Rendered};
use super::wire;
use crate::codec::DECLS;

fn decl(name: &str) -> Option<&'static ProtocolDecl> {
    DECLS.iter().copied().find(|d| d.name == name)
}

/// The far end's error answer, as it arrived.
#[derive(Clone, Copy, Debug)]
pub struct FarError<'a> {
    /// Its status.
    pub status: u16,
    /// Its head fields.
    pub head: &'a HeaderMap,
    /// Its body.
    pub body: &'a [u8],
}

/// A head field as a caller reads it: the name in its wire (lower-case) form, so a dialect may
/// declare a relayed field the way its vendor spells it. A name that is not a legal field name is
/// dropped, never relayed and never fatal.
#[must_use]
pub fn head_field(name: &str, value: &[u8]) -> Option<(String, Vec<u8>)> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    Some((name.as_str().to_string(), value.to_vec()))
}

/// The request-id head field a caller of `ingress` reads, forwarding the far end's own id (the
/// first head field the caller's dialect relays) when it sent one.
pub(crate) fn request_id_field(ingress: &str, far_head: &HeaderMap) -> Option<(String, Vec<u8>)> {
    let upstream = wire::ingress_relayed_response_header_names(ingress)
        .first()
        .and_then(|name| far_head.get(*name))
        .and_then(|h| h.to_str().ok());
    let (name, id) = wire::response_request_id(ingress, upstream)?;
    head_field(name, id.as_bytes())
}

/// What the far end's dialect reads off its error answer: the codes and types its error shape
/// names, or the status alone when the dialect does not serve `operation`.
#[must_use]
pub fn raw_error(far: &str, operation: OpVerb, status: u16, body: &[u8]) -> RawUpstreamError {
    decl(far)
        .filter(|d| d.verbs.contains(&operation))
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(operation))
        .map_or_else(
            || RawUpstreamError::from_status(status),
            |h| h.extract_error(status, body),
        )
}

/// The non-standard overload status a provider sends as its overloaded signal.
const HTTP_OVERLOADED: u16 = 529;

/// THE CLASS of a far-end error under the provider's `error_map`: a mapped provider code first,
/// then the built-in context-length code on a request-size status, then a mapped structured type,
/// then the status. A mapping to `context_length` never masks a 5xx; a mapping to a string that
/// names no class is ignored.
#[must_use]
pub fn normalize(raw: &RawUpstreamError, error_map: &HashMap<String, String>) -> CanonicalSignal {
    let signal = |class, provider_signal| CanonicalSignal {
        class,
        provider_signal,
        retry_after: raw.retry_after_secs,
    };
    let masks_outage = |class: StatusClass| {
        class == StatusClass::ContextLength && (500..600).contains(&raw.http_status)
    };
    let provider_signal = match &raw.provider_code {
        Some(code) => {
            let mapped = error_map.get(code).and_then(|m| StatusClass::parse(m));
            if let Some(class) = mapped.filter(|c| !masks_outage(*c)) {
                return signal(class, Some(code.clone()));
            }
            if code == PROVIDER_CODE_CONTEXT_LENGTH
                && (raw.http_status == 400 || raw.http_status == 413)
            {
                return signal(StatusClass::ContextLength, Some(code.clone()));
            }
            Some(code.clone())
        }
        None => None,
    };
    if let Some(ty) = &raw.structured_type {
        let mapped = error_map.get(ty).and_then(|m| StatusClass::parse(m));
        if let Some(class) = mapped.filter(|c| !masks_outage(*c)) {
            return signal(class, provider_signal.or_else(|| Some(ty.clone())));
        }
    }
    let class = match raw.http_status {
        401 | 403 => StatusClass::Auth,
        429 => StatusClass::RateLimit,
        408 => StatusClass::Timeout,
        HTTP_OVERLOADED => StatusClass::Overloaded,
        500..=599 => StatusClass::ServerError,
        _ => StatusClass::ClientError,
    };
    signal(class, provider_signal)
}

/// The far end's error relayed as it arrived: its status, its content type, the head fields a
/// native answer of the caller's dialect carries (the far end's `x-amzn-*` fields for a caller
/// that relays them, else the request id), and its body.
#[must_use]
pub fn relay_verbatim(ingress: &str, far: &FarError<'_>) -> Rendered {
    let mut fields = Vec::new();
    if let Some(ct) = far.head.get(busbar_contract::http::header::CONTENT_TYPE) {
        fields.push(("content-type".to_string(), ct.as_bytes().to_vec()));
    }
    if wire::ingress_relays_amzn_headers(ingress) {
        for name in wire::ingress_relayed_response_header_names(ingress) {
            if let Some(v) = far.head.get(*name) {
                fields.extend(head_field(name, v.as_bytes()));
            }
        }
    } else {
        fields.extend(request_id_field(ingress, far.head));
    }
    Rendered {
        status: far.status,
        fields,
        body: far.body.to_vec(),
    }
}

/// The far end's error as the caller reads it when the walk ends on it: across dialects, reshaped
/// into the caller's envelope (a foreign error body is never relayed); within one, verbatim.
#[must_use]
pub fn relay(ingress: &str, egress: &str, far: &FarError<'_>) -> Rendered {
    if ingress != egress {
        let (kind, msg) = wire::cross_protocol_error(far.status, far.body);
        return render(ingress, far.status, kind, &msg, 0);
    }
    relay_verbatim(ingress, far)
}

/// A client fault as the caller reads it: across dialects, reshaped with the kind its class names
/// and the far end's own message (else the generic one); within one, verbatim.
#[must_use]
pub fn client_fault(
    ingress: &str,
    egress: &str,
    class: StatusClass,
    far: &FarError<'_>,
) -> Rendered {
    if ingress != egress {
        let msg = wire::extract_error_message(far.body)
            .unwrap_or_else(|| wire::GENERIC_REJECTED_DETAIL.to_string());
        return render(ingress, far.status, wire::client_fault_kind(class), &msg, 0);
    }
    relay_verbatim(ingress, far)
}

/// The caller dialect's own authentication refusal, for a far end that refused the deployment's
/// credential: its native status, kind and vendor sentence, never the far end's status or body.
#[must_use]
pub fn auth_failure(ingress: &str) -> Rendered {
    let d = decl(ingress);
    let (status, kind) = d.map_or((401, KIND_AUTHENTICATION), |d| {
        (
            d.auth_failure_status_and_kind.0.as_u16(),
            d.auth_failure_status_and_kind.1,
        )
    });
    let message = d.map_or("authentication failed", |d| d.auth_failure_message);
    render(ingress, status, kind, message, 0)
}

/// A far-end error, judged.
#[derive(Clone, Debug, PartialEq)]
pub struct Judged {
    /// The class the error was placed in; `None` for a caller's own credential failing, which is
    /// not classified.
    pub signal: Option<CanonicalSignal>,
    /// What the error means for the far end's standing and the walk.
    pub disposition: Disposition,
    /// What the caller reads: the answer itself for a client fault, a caller's own credential and
    /// the deployment's refused credential; for every other disposition the relay the walk answers
    /// with if it ends on this far end.
    pub answer: Rendered,
}

/// JUDGE a far-end error: `passthrough` says the far end was reached with the caller's own
/// credential (the kernel's fact), whose 401 or 403 is the caller's and is relayed unjudged.
#[must_use]
pub fn judge(
    ingress: &str,
    egress: &str,
    operation: OpVerb,
    error_map: &HashMap<String, String>,
    passthrough: bool,
    far: &FarError<'_>,
) -> Judged {
    if passthrough && (far.status == 401 || far.status == 403) {
        return Judged {
            signal: None,
            disposition: Disposition::ClientFault,
            answer: relay(ingress, egress, far),
        };
    }
    let sig = normalize(
        &raw_error(egress, operation, far.status, far.body),
        error_map,
    );
    let disposition = sig.class.disposition();
    let answer = match disposition {
        Disposition::ClientFault => client_fault(ingress, egress, sig.class, far),
        Disposition::HardDown if sig.class == StatusClass::Auth => auth_failure(ingress),
        Disposition::HardDown | Disposition::TransientUpstream | Disposition::ContextLength => {
            relay(ingress, egress, far)
        }
    };
    Judged {
        signal: Some(sig),
        disposition,
        answer,
    }
}
