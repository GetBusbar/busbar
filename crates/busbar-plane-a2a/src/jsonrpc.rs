//! Reading and writing this protocol's envelope, in the shape the existing codec already writes it.
//!
//! ## Reading is done as spans, not as a parse
//!
//! The kernel reads a body as spans, so the reader below walks the bytes once and reports where the
//! three members it cares about are. It builds no document and allocates nothing per byte. The
//! ACCEPT and REFUSE decisions it makes are the same three the existing ingress makes, in the same
//! order: the version member must be exactly the one string; the method member must be a string; and
//! the identifier, when present, must be a string or a number and nothing else.
//!
//! ## Writing goes through the same serializer, on purpose
//!
//! This crate writes an envelope by building the same value the codec builds and handing it to the
//! same serializer at the same version. That is what makes byte-identity a property rather than a
//! hope: the member order on the wire is the serializer's, not this module's, and a test asserts
//! which order that is so a change to the serializer's configuration is a red here rather than a
//! silent reshaping of every answer this node gives.
//!
//! An answer's result arrives here as the bytes the agent sent, and it is parsed and written again
//! rather than copied through. That is what the codec does today — it reads the agent's answer into
//! a document and serializes the envelope around it — so copying the bytes through verbatim would
//! be the change, not the fidelity.

use busbar_contract::bounded::Span;
use busbar_contract::wire::{Decode, Encode};

/// The version string every envelope of this protocol carries.
pub const VERSION: &str = "2.0";

/// The member carrying the protocol version.
pub const PTR_VERSION: &str = "/jsonrpc";

/// The member carrying the method name.
pub const PTR_METHOD: &str = "/method";

/// The member carrying the request identifier.
pub const PTR_ID: &str = "/id";

/// The member carrying the parameters.
pub const PTR_PARAMS: &str = "/params";

/// The member carrying the task identifier, where the parameters name one.
pub const PTR_PARAMS_ID: &str = "/params/id";

/// The member carrying the result of an answer.
pub const PTR_RESULT: &str = "/result";

/// The member carrying the error of an answer.
pub const PTR_ERROR: &str = "/error";

/// The member carrying an error's code.
pub const PTR_ERROR_CODE: &str = "/error/code";

/// The typed marker the codec stamps on an error's detail entry. Read by identity from the codec,
/// which is where the one spelling lives.
pub const ERROR_INFO_TYPE: &str = busbar_a2a_codec::ERROR_INFO_TYPE;

/// The domain the codec stamps on an error's detail entry. The codec's, likewise.
pub const ERROR_INFO_DOMAIN: &str = busbar_a2a_codec::ERROR_INFO_DOMAIN;

/// The error codes this protocol defines, with the word each one is reported under.
///
/// THE CODEC'S TABLE, read by identity rather than copied. It was a copy checked by searching the
/// server half's source text for each code and each word — which needed this crate to read a
/// sibling its manifest does not name, and which could only ever say the number 32001 occurs
/// somewhere in that file. There is one table now, and `busbar-a2a`'s own `A2aError` is pinned
/// against it row for row in the crate that owns the enum.
pub const ERRORS: &[(i64, &str)] = busbar_a2a_codec::ERRORS;

/// The request was not well formed.
pub const CODE_INVALID_REQUEST: i64 = -32600;

/// The method named is not one this node answers.
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;

/// The parameters were not admissible.
pub const CODE_INVALID_PARAMS: i64 = -32602;

/// Something on this side failed.
pub const CODE_INTERNAL: i64 = -32603;

/// The caller is not permitted to perform this operation.
pub const CODE_UNSUPPORTED_OPERATION: i64 = -32004;

/// What kind of scalar the identifier member held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdShape {
    /// A quoted string.
    Str,
    /// A number.
    Number,
}

/// One envelope, as the reader found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Where the method name is, quotes included.
    pub method: Span,
    /// Where the identifier is, and what shape it was — absent on a notification.
    pub id: Option<(Span, IdShape)>,
    /// Where the parameters are, where the caller sent any.
    pub params: Option<Span>,
}

impl Envelope {
    /// The method name, with its quotes stripped.
    #[must_use]
    pub fn method_str<'b>(&self, body: &'b [u8]) -> Option<&'b str> {
        let raw = body.get(self.method.start..self.method.end)?;
        let inner = raw.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
        core::str::from_utf8(inner).ok()
    }

    /// The identifier's raw bytes, exactly as they arrived.
    ///
    /// Quotes included on a string identifier, because those bytes are what an answer must echo.
    #[must_use]
    pub fn id_bytes<'b>(&self, body: &'b [u8]) -> Option<&'b [u8]> {
        let (span, _) = self.id?;
        body.get(span.start..span.end)
    }
}

/// Every pointer this plane declares over a REQUEST body, in one table.
///
/// The table is what the unit's span view is built from: the plane resolves these once, at the one
/// step entitled to read the bytes, and the loop reads the spans off the draft rather than scanning
/// the body again. A pointer named here that the body does not carry is simply absent from the
/// view, which is how "not sent" stays distinguishable from "sent empty".
pub const REQUEST_PTRS: &[&str] = &[PTR_VERSION, PTR_METHOD, PTR_ID, PTR_PARAMS, PTR_PARAMS_ID];

/// Every pointer this plane declares over a RESPONSE body, in one table.
pub const RESPONSE_PTRS: &[&str] = &[
    PTR_ID,
    PTR_RESULT,
    PTR_ERROR,
    PTR_ERROR_CODE,
    PTR_RESULT_STATE,
    PTR_RESULT_ID,
    PTR_RESULT_CONTEXT_ID,
    PTR_RESULT_FINAL,
    PTR_RESULT_KIND,
    PTR_TASK_ID,
];

/// Where an answer reports the task's state.
pub const PTR_RESULT_STATE: &str = "/result/status/state";

/// Where an answer names the task it is about.
pub const PTR_RESULT_ID: &str = "/result/id";

/// Where an answer names the conversation the task belongs to.
pub const PTR_RESULT_CONTEXT_ID: &str = "/result/contextId";

/// Where a streamed answer says it is the last one.
pub const PTR_RESULT_FINAL: &str = "/result/final";

/// Where a streamed answer says what kind of event it is.
pub const PTR_RESULT_KIND: &str = "/result/kind";

/// Where an agent's own pushed event names its task.
pub const PTR_TASK_ID: &str = "/taskId";

/// Read one envelope out of a request body.
///
/// # Errors
/// Returns a decode error when the bytes are not this protocol's shape: no version member or the
/// wrong one, no method member or a method that is not a string, or an identifier that is present
/// and is neither a string nor a number.
pub fn read(body: &[u8]) -> Result<Envelope, Decode> {
    let at = |ptr: &str| match busbar_contract::spans::resolve_pointer(body, ptr) {
        busbar_contract::spans::Resolved::Found(span) => Some(span),
        _ => None,
    };

    // The version member, exactly. A different value is a different protocol, not a variation.
    let version = at(PTR_VERSION).ok_or(Decode::MissingDeclaredFact)?;
    if body.get(version.start..version.end) != Some(b"\"2.0\"".as_slice()) {
        return Err(Decode::Malformed);
    }

    // The method member must be a string.
    let method = at(PTR_METHOD).ok_or(Decode::MissingDeclaredFact)?;
    let method_bytes = body
        .get(method.start..method.end)
        .ok_or(Decode::Malformed)?;
    if !(method_bytes.starts_with(b"\"")
        && method_bytes.len() >= 2
        && method_bytes.ends_with(b"\""))
    {
        return Err(Decode::Malformed);
    }

    // The identifier, where there is one, must be a string or a number. An identifier written as
    // the empty value is refused rather than read as absent: a caller that wrote one meant to
    // correlate, and answering it as a notification would drop an answer they are waiting for.
    let id = match at(PTR_ID) {
        None => None,
        Some(span) => {
            let raw = body.get(span.start..span.end).ok_or(Decode::Malformed)?;
            match id_shape(raw) {
                Some(shape) => Some((span, shape)),
                None => return Err(Decode::Malformed),
            }
        }
    };

    Ok(Envelope {
        method,
        id,
        params: at(PTR_PARAMS),
    })
}

/// What shape an identifier's raw bytes are, or nothing when they are neither shape.
#[must_use]
fn id_shape(raw: &[u8]) -> Option<IdShape> {
    match raw.first()? {
        b'"' if raw.len() >= 2 && raw.ends_with(b"\"") => Some(IdShape::Str),
        b'-' | b'0'..=b'9' if is_number(raw) => Some(IdShape::Number),
        _ => None,
    }
}

/// Whether a run of bytes is a NUMBER, by the one grammar a document has for writing one.
///
/// The test used to be "starts like a number, and every byte after that is a digit or one of the
/// punctuation marks a number can contain" — which the comment beside it described as at most one
/// point and at most one exponent, a thing it did not check. It admits `1.2.3`, `007`, `1e`, `--1`
/// and `1e+`: none of them is a number, and none of them can be written back, because the answer
/// echoes the identifier by parsing these same bytes into a value. So the reader admitted a request
/// whose every possible reply, success or refusal, failed to encode: the caller was told nothing at
/// all, which is the one outcome this protocol has no spelling for. Reading it the way it will be
/// written is what keeps the two ends agreeing.
fn is_number(raw: &[u8]) -> bool {
    let mut i = 0;
    if raw.first() == Some(&b'-') {
        i += 1;
    }
    // A leading zero stands alone: `0` is a number and `007` is not one.
    match raw.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while matches!(raw.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        _ => return false,
    }
    // A point, if present, is followed by at least one digit.
    if raw.get(i) == Some(&b'.') {
        i += 1;
        let digits = i;
        while matches!(raw.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == digits {
            return false;
        }
    }
    // An exponent, if present, is a sign at most and then at least one digit.
    if matches!(raw.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(raw.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let digits = i;
        while matches!(raw.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == digits {
            return false;
        }
    }
    i == raw.len()
}

/// The identifier as a document value, for building an answer that echoes it.
///
/// The bytes are parsed rather than pasted so the answer carries a value the serializer wrote,
/// which is the same path the codec takes.
///
/// # Errors
/// Returns an encode error when the bytes are not a value.
pub fn id_value(raw: &[u8]) -> Result<serde_json::Value, Encode> {
    serde_json::from_slice(raw).map_err(|_| Encode::Unrepresentable)
}

/// One successful answer, as bytes.
///
/// # Errors
/// Returns an encode error when the result bytes are not a document.
pub fn success(id: &serde_json::Value, result_bytes: &[u8]) -> Result<Vec<u8>, Encode> {
    let result: serde_json::Value =
        serde_json::from_slice(result_bytes).map_err(|_| Encode::Unrepresentable)?;
    let envelope = serde_json::json!({ "jsonrpc": VERSION, "id": id, "result": result });
    serde_json::to_vec(&envelope).map_err(|_| Encode::Unrepresentable)
}

/// One refused or failed answer, as bytes.
///
/// The detail entry is present exactly when this protocol names a word for the code, which is the
/// rule the codec follows: the five standard codes carry no word, and this protocol's own nine
/// each carry theirs.
///
/// # Errors
/// Returns an encode error when the value cannot be written.
pub fn error(id: &serde_json::Value, code: i64, message: &str) -> Result<Vec<u8>, Encode> {
    let mut err = serde_json::json!({ "code": code, "message": message });
    if let Some((_, reason)) = ERRORS.iter().find(|(c, _)| *c == code) {
        err["data"] = serde_json::json!([{
            "@type": ERROR_INFO_TYPE,
            "domain": ERROR_INFO_DOMAIN,
            "reason": reason,
        }]);
    }
    let envelope = serde_json::json!({ "jsonrpc": VERSION, "id": id, "error": err });
    serde_json::to_vec(&envelope).map_err(|_| Encode::Unrepresentable)
}

#[cfg(test)]
#[path = "tests/jsonrpc.rs"]
mod tests;
