//! Reading and writing this protocol's envelope, in the shape the existing codec already writes it.
//!
//! ## Reading is done as spans, not as a parse
//!
//! The kernel reads a body as spans, so the reader below walks the bytes once and reports where the
//! members it cares about are. It builds no document and allocates nothing per byte. The ACCEPT and
//! REFUSE decisions it makes are the same three the existing ingress makes, in the same order: the
//! version member must be exactly the one string; the method member must be a string; and the
//! identifier, when present, must be a string or a number and nothing else.
//!
//! ## Writing goes through the same serializer, on purpose
//!
//! This crate writes an envelope by building the same value the codec builds and handing it to the
//! same serializer at the same version. That is what makes byte-identity a property rather than a
//! hope: the member order on the wire is the serializer's, not this module's, and a test asserts
//! which order that is so a change to the serializer's configuration is a red here rather than a
//! silent reshaping of every answer this node gives.
//!
//! ## The two asymmetries that are easy to get wrong
//!
//! On a SUCCESSFUL answer the identifier member is OMITTED when there is none. On an ERROR it is
//! always present, and it is the empty value when there is none — because the specification makes
//! the member required on a response and names the empty value as the spelling for "no correlation",
//! and because a peer's own test for "is this a response" is whether the member is there at all.
//!
//! And every successful result carries a DISCRIMINATOR, stamped by this node rather than passed
//! through from whatever a server said about its own result. Three constructors exist rather than
//! one with a parameter, so which discriminator a caller receives is always visible at the call site
//! and can never be a value that arrived from a third party.

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

/// The member carrying the result of an answer.
pub const PTR_RESULT: &str = "/result";

/// The member carrying the error of an answer.
pub const PTR_ERROR: &str = "/error";

/// The member carrying an error's code.
pub const PTR_ERROR_CODE: &str = "/error/code";

/// The member carrying the discriminator of a result.
pub const PTR_RESULT_TYPE: &str = "/result/resultType";

/// The member saying whether a tool reported that it itself failed.
pub const PTR_IS_ERROR: &str = "/result/isError";

/// The discriminator on a result this node is handing over as finished.
pub const RESULT_TYPE_COMPLETE: &str = "complete";

/// The discriminator on a result that asks the caller for something first.
pub const RESULT_TYPE_INPUT_REQUIRED: &str = "input_required";

/// The discriminator on a result that hands back a task rather than an answer.
pub const RESULT_TYPE_TASK: &str = "task";

// Every code below is the CODEC's, read by identity rather than restated. This plane and the server
// half both write these onto the same wire and the plane cannot name the server half, so a value
// spelled on both sides is a value the two sides can silently come to disagree about — and a wrong
// JSON-RPC code reads entirely plausibly. The compiler holds the equality now; the assertion below
// holds the remaining question, which is whether the SET this plane may write is one the codec knows.

/// The bytes could not be read at all.
pub const CODE_PARSE_ERROR: i64 = busbar_mcp_codec::codec::CODE_PARSE_ERROR;

/// The envelope was not a request.
pub const CODE_INVALID_REQUEST: i64 = busbar_mcp_codec::codec::CODE_INVALID_REQUEST;

/// The method named is not one this node answers.
pub const CODE_METHOD_NOT_FOUND: i64 = busbar_mcp_codec::codec::CODE_METHOD_NOT_FOUND;

/// The parameters were not admissible.
pub const CODE_INVALID_PARAMS: i64 = busbar_mcp_codec::codec::CODE_INVALID_PARAMS;

/// Something on this side failed.
pub const CODE_INTERNAL: i64 = busbar_mcp_codec::codec::CODE_INTERNAL;

/// A mirrored header did not agree with the body it was mirrored from.
pub const CODE_HEADER_MISMATCH: i64 = busbar_mcp_codec::codec::CODE_HEADER_MISMATCH;

/// The caller did not declare a capability the answer would have needed.
pub const CODE_MISSING_CLIENT_CAPABILITY: i64 =
    busbar_mcp_codec::codec::CODE_MISSING_CLIENT_CAPABILITY;

/// The revision the caller asked for is not one this node speaks.
pub const CODE_UNSUPPORTED_PROTOCOL_VERSION: i64 =
    busbar_mcp_codec::codec::CODE_UNSUPPORTED_PROTOCOL_VERSION;

/// A policy said no.
pub const CODE_REFUSED: i64 = busbar_mcp_codec::codec::CODE_REFUSED;

/// The server this call would have reached could not be reached.
pub const CODE_UPSTREAM_UNAVAILABLE: i64 = busbar_mcp_codec::codec::CODE_UPSTREAM_UNAVAILABLE;

/// Every code this plane may write.
pub const CODES: &[i64] = &[
    CODE_PARSE_ERROR,
    CODE_INVALID_REQUEST,
    CODE_METHOD_NOT_FOUND,
    CODE_INVALID_PARAMS,
    CODE_INTERNAL,
    CODE_HEADER_MISMATCH,
    CODE_MISSING_CLIENT_CAPABILITY,
    CODE_UNSUPPORTED_PROTOCOL_VERSION,
    CODE_REFUSED,
    CODE_UPSTREAM_UNAVAILABLE,
];

/// The codes the current revision retired, which a conformant node must never write.
///
/// Declared so the test below can assert this plane writes none of them. A retired code is worse
/// than an unknown one: a peer that still recognises it will act on a meaning this node did not
/// intend.
pub const RETIRED_CODES: &[i64] = busbar_mcp_codec::codec::RETIRED_CODES;

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

    /// Whether this envelope obliges an answer.
    #[must_use]
    pub fn is_request(&self) -> bool {
        self.id.is_some()
    }
}

/// Every pointer this plane declares over a REQUEST body, in one table.
///
/// The table is what the unit's span view is built from: the plane resolves these once, at the one
/// step entitled to read the bytes, and the loop reads the spans off the draft rather than scanning
/// the body again. A pointer named here that the body does not carry is simply absent from the
/// view, which is how "not sent" stays distinguishable from "sent empty".
pub const REQUEST_PTRS: &[&str] = &[
    PTR_VERSION,
    PTR_METHOD,
    PTR_ID,
    PTR_PARAMS,
    PTR_PARAMS_NAME,
    PTR_PARAMS_URI,
    PTR_PARAMS_TASK_ID,
    PTR_PARAMS_META,
];

/// Every pointer this plane declares over a RESPONSE body, in one table.
pub const RESPONSE_PTRS: &[&str] = &[
    PTR_ID,
    PTR_RESULT,
    PTR_RESULT_TYPE,
    PTR_IS_ERROR,
    PTR_ERROR,
    PTR_ERROR_CODE,
];

/// Where a request's subject is, for the methods whose subject is a name.
pub const PTR_PARAMS_NAME: &str = "/params/name";

/// Where a request's subject is, for the methods whose subject is a resource.
pub const PTR_PARAMS_URI: &str = "/params/uri";

/// Where a request's subject is, for the methods whose subject is a task.
pub const PTR_PARAMS_TASK_ID: &str = "/params/taskId";

/// The caller's own metadata block.
pub const PTR_PARAMS_META: &str = "/params/_meta";

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

    let version = at(PTR_VERSION).ok_or(Decode::MissingDeclaredFact)?;
    if body.get(version.start..version.end) != Some(b"\"2.0\"".as_slice()) {
        return Err(Decode::Malformed);
    }

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

    // An identifier written as the empty value is REFUSED rather than read as absent, and this
    // protocol is stricter than the underlying one on exactly that point: a notification is a
    // message with NO identifier member, and a member present and empty is a caller who meant to
    // correlate and wrote it wrongly.
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
/// punctuation marks a number can contain". That admits `1.2.3`, `007`, `1e`, `--1` and `1e+` — none
/// of which is a number, all of which the ANSWER path then cannot write, because the answer echoes
/// the identifier by parsing these same bytes into a value. So the reader admitted a request whose
/// every possible reply, success or refusal, failed to encode: the caller was told nothing at all,
/// which is the one outcome this protocol has no spelling for. Reading it the way it will be
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
/// # Errors
/// Returns an encode error when the bytes are not a value.
pub fn id_value(raw: &[u8]) -> Result<serde_json::Value, Encode> {
    serde_json::from_slice(raw).map_err(|_| Encode::Unrepresentable)
}

/// One successful answer, as bytes, with the discriminator this node chose.
///
/// The discriminator is stamped INTO the result, replacing anything a server said about its own
/// result. That is deliberate and it is the safety property, not a convenience: a server that
/// answered with a demand for the caller's authority would otherwise have that demand handed on
/// under this node's name and this node's authentication.
///
/// A result that has nowhere to PUT the member — anything that is not an object — is refused rather
/// than written without one. The stamping is the safety property, and a result with no discriminator
/// reads as finished to a peer and to this plane's own reader; writing one silently would turn "this
/// asks the caller for something" into "this is the answer" for every shape but an object.
///
/// # Errors
/// Returns an encode error when the result bytes are not a document, or are a document with no
/// member the discriminator can be written to.
pub fn success(
    id: Option<&serde_json::Value>,
    result_bytes: &[u8],
    result_type: &str,
) -> Result<Vec<u8>, Encode> {
    let mut result: serde_json::Value =
        serde_json::from_slice(result_bytes).map_err(|_| Encode::Unrepresentable)?;
    let object = result.as_object_mut().ok_or(Encode::Unrepresentable)?;
    object.insert("resultType".into(), result_type.into());
    let mut envelope = serde_json::Map::new();
    envelope.insert("jsonrpc".into(), VERSION.into());
    // OMITTED when there is none: on the success path the member is written only if there is one.
    if let Some(id) = id {
        envelope.insert("id".into(), id.clone());
    }
    envelope.insert("result".into(), result);
    serde_json::to_vec(&serde_json::Value::Object(envelope)).map_err(|_| Encode::Unrepresentable)
}

/// One refused or failed answer, as bytes.
///
/// The identifier member is ALWAYS written, and it is the empty value when there is none.
///
/// # Errors
/// Returns an encode error when the value cannot be written.
pub fn error(
    id: Option<&serde_json::Value>,
    code: i64,
    message: &str,
    data: Option<serde_json::Value>,
) -> Result<Vec<u8>, Encode> {
    let mut err = serde_json::Map::new();
    err.insert("code".into(), code.into());
    err.insert("message".into(), message.into());
    if let Some(d) = data {
        err.insert("data".into(), d);
    }
    let mut envelope = serde_json::Map::new();
    envelope.insert("jsonrpc".into(), VERSION.into());
    envelope.insert("id".into(), id.cloned().unwrap_or(serde_json::Value::Null));
    envelope.insert("error".into(), serde_json::Value::Object(err));
    serde_json::to_vec(&serde_json::Value::Object(envelope)).map_err(|_| Encode::Unrepresentable)
}

#[cfg(test)]
#[path = "tests/jsonrpc.rs"]
mod tests;
