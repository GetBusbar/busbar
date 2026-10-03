//! A refusal, rendered: the status, the head fields and the body the caller reads, in the dialect
//! envelope the previous release answered in.
//!
//! One renderer for every refusal the plane writes (its own decode refusals, an attempt it answers
//! without the far end, and the kernel's refusals), as 1.5.5's one renderer was: the envelope
//! dialect's own error writer over `(status, kind, message)`, `content-type: application/json`,
//! the dialect's own error headers, then `retry-after` when the refusal advises a wait. A dialect
//! the plane does not hold renders the agnostic envelope.
//!
//! For a kernel refusal the plane chooses the kind (and, for an authentication refusal, the
//! dialect's own vendor sentence) from the reason; every other message is the kernel's own text,
//! which names the facts only the kernel has (a group, a window, a model with no rate).

use busbar_contract::abi::plane::reason_of;
use busbar_contract::protocol::{
    ProtocolDecl, APPLICATION_JSON, KIND_API_ERROR, KIND_INSUFFICIENT_QUOTA, KIND_INVALID_REQUEST,
    KIND_NOT_FOUND, KIND_OVERLOADED, KIND_PERMISSION, KIND_RATE_LIMIT, KIND_REQUEST_TOO_LARGE,
};
use serde_json::Value;

use crate::codec::DECLS;

/// What the caller reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The status.
    pub status: u16,
    /// The head fields, in order.
    pub fields: Vec<(String, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
}

fn decl(name: &str) -> Option<&'static ProtocolDecl> {
    DECLS.iter().copied().find(|d| d.name == name)
}

/// The agnostic envelope: `{"error": {"message", "type"}}`.
#[must_use]
pub fn agnostic_envelope(kind: &str, message: &str) -> Value {
    serde_json::json!({ "error": { "message": message, "type": kind } })
}

/// RENDER one refusal in `envelope`'s dialect (empty or unknown: the agnostic envelope).
#[must_use]
pub fn render(
    envelope: &str,
    status: u16,
    kind: &str,
    message: &str,
    retry_after_s: u32,
) -> Rendered {
    let dialect = decl(envelope).and_then(|d| d.dialect());
    let written = match &dialect {
        Some(di) => di.write_error(status, kind, message),
        None => agnostic_envelope(kind, message),
    };
    let body = crate::codec::json::to_vec(&written).unwrap_or_else(|_| {
        crate::codec::json::to_vec(&agnostic_envelope(kind, message)).unwrap_or_default()
    });
    let mut fields = vec![(
        "content-type".to_string(),
        APPLICATION_JSON.as_bytes().to_vec(),
    )];
    if let Some(di) = &dialect {
        fields.extend(di.error_response_fields(kind, &written));
    }
    if retry_after_s != 0 {
        fields.push((
            "retry-after".to_string(),
            retry_after_s.to_string().into_bytes(),
        ));
    }
    Rendered {
        status,
        fields,
        body,
    }
}

/// The kind a kernel refusal wears, by its reason; an unknown reason by its status family.
#[must_use]
pub fn kind_of(reason: &str, status: u16) -> &'static str {
    match reason {
        "rate_limited" | "in_flight" | "in_flight_cap" => KIND_RATE_LIMIT,
        "over_budget" => KIND_INSUFFICIENT_QUOTA,
        "group_frozen" | "scope_denied" | "pool_not_permitted" | "hook_veto" => KIND_PERMISSION,
        "body_too_large" | "cursor_budget" | "credential_budget" => KIND_REQUEST_TOO_LARGE,
        "no_rate" | "unpriced" | "decode_failed" | "replayed" | "superseded" => {
            KIND_INVALID_REQUEST
        }
        "no_destination" => KIND_NOT_FOUND,
        "meter_disputed" | "handoff_mismatch" | "plane_panic" | "task_lost"
        | "secret_placeholder" => KIND_API_ERROR,
        _ if status >= 500 && status != 503 => KIND_API_ERROR,
        _ if status >= 500 => KIND_OVERLOADED,
        _ if status == 429 => KIND_RATE_LIMIT,
        _ if status == 403 => KIND_PERMISSION,
        _ if status == 413 => KIND_REQUEST_TOO_LARGE,
        _ => KIND_INVALID_REQUEST,
    }
}

/// The sentence the previous release answered a model with when it named no pool and no configured
/// model: the dialect's own copy where the path gave one (`shaped`), else the neutral sentence.
#[must_use]
pub fn model_not_found(model: &str, shaped: Option<&str>) -> String {
    shaped.map_or_else(
        || format!("The model '{model}' does not exist or you do not have access to it."),
        str::to_string,
    )
}

/// Whether a reason is an authentication refusal: those answer in the dialect's own vendor terms.
fn is_authentication(reason: &str) -> bool {
    matches!(
        reason,
        "unauthenticated"
            | "revoked"
            | "scheme_not_declared"
            | "session_unbound"
            | "challenge_exhausted"
    )
}

/// RENDER A KERNEL REFUSAL in `envelope`'s dialect: `reason` is the reason's code on the plane ABI,
/// `status` the status the kernel chose, `text` its message.
#[must_use]
pub fn kernel_refusal(
    envelope: &str,
    reason: u32,
    status: u16,
    text: &str,
    retry_after_s: u32,
) -> Rendered {
    let spelling = reason_of(reason).map_or("", |r| r.as_str());
    if is_authentication(spelling) {
        let d = decl(envelope);
        let kind = d.map_or(busbar_contract::protocol::KIND_AUTHENTICATION, |d| {
            d.auth_failure_status_and_kind.1
        });
        let message = d.map_or("authentication failed", |d| d.auth_failure_message);
        return render(envelope, status, kind, message, retry_after_s);
    }
    render(
        envelope,
        status,
        kind_of(spelling, status),
        text,
        retry_after_s,
    )
}

/// RENDER one of the plane's own arrival refusals.
#[must_use]
pub fn declined(d: &super::arrive::Declined) -> Rendered {
    render(d.envelope, d.status, d.kind, &d.message, 0)
}

/// RENDER a refusal an attempt answers without reaching the far end.
#[must_use]
pub fn answered(a: &super::attempt::Answer) -> Rendered {
    render(a.envelope, a.status, a.kind, &a.message, 0)
}
