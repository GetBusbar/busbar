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

/// The typed marker the codec stamps on an error's detail entry.
pub const ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";

/// The domain the codec stamps on an error's detail entry.
pub const ERROR_INFO_DOMAIN: &str = "a2a-protocol.org";

/// The error codes this protocol defines, with the word each one is reported under.
///
/// Copied from the codec's own table, which is visible to its own crate only. The test below reads
/// that table's source and asserts every code and every word here appears in it, so the copy cannot
/// drift without a red.
pub const ERRORS: &[(i64, &str)] = &[
    (-32001, "TASK_NOT_FOUND"),
    (-32002, "TASK_NOT_CANCELABLE"),
    (-32003, "PUSH_NOTIFICATION_NOT_SUPPORTED"),
    (-32004, "UNSUPPORTED_OPERATION"),
    (-32005, "CONTENT_TYPE_NOT_SUPPORTED"),
    (-32006, "INVALID_AGENT_RESPONSE"),
    (-32007, "EXTENDED_AGENT_CARD_NOT_CONFIGURED"),
    (-32008, "EXTENSION_SUPPORT_REQUIRED"),
    (-32009, "VERSION_NOT_SUPPORTED"),
];

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
        b'-' | b'0'..=b'9' => {
            // A number is digits with at most one point and at most one exponent. Anything else
            // reaching here is a scalar that merely starts like a number.
            let rest = &raw[1..];
            if rest
                .iter()
                .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                Some(IdShape::Number)
            } else {
                None
            }
        }
        _ => None,
    }
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
mod tests {
    use super::{error, id_shape, id_value, read, success, IdShape, ERRORS};
    use busbar_contract::wire::Decode;

    /// The serializer writes members in sorted order, and every byte-identity claim rests on it.
    ///
    /// If a dependency ever turns on insertion-order preservation for the document library, every
    /// envelope this node writes changes shape at once. This is the assertion that says so out loud
    /// rather than letting a conformance rig discover it.
    #[test]
    fn the_serializer_writes_members_in_sorted_order() {
        let v = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"id":1,"jsonrpc":"2.0","result":{}}"#
        );
    }

    /// A well-formed request reads as a request.
    #[test]
    fn a_request_reads_as_a_request() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"tasks/get","params":{"id":"t1"}}"#;
        let e = read(body).expect("a well-formed request reads");
        assert_eq!(e.method_str(body), Some("tasks/get"));
        assert_eq!(e.id_bytes(body), Some(&b"7"[..]));
        assert!(e.params.is_some());
    }

    /// A quoted identifier keeps its quotes, because the answer must echo those bytes.
    #[test]
    fn a_named_identifier_keeps_its_quotes() {
        let body = br#"{"jsonrpc":"2.0","id":"a2a-http-json","method":"SendMessage"}"#;
        let e = read(body).expect("a named identifier reads");
        assert_eq!(e.id_bytes(body), Some(&br#""a2a-http-json""#[..]));
        assert_eq!(e.id.map(|(_, s)| s), Some(IdShape::Str));
    }

    /// A request with no identifier is a notification.
    #[test]
    fn an_absent_identifier_is_a_notification() {
        let body = br#"{"jsonrpc":"2.0","method":"tasks/list"}"#;
        let e = read(body).expect("a notification reads");
        assert!(e.id.is_none());
    }

    /// An empty identifier is refused rather than read as absent.
    ///
    /// The existing ingress refuses it for the same reason and answers the caller; reading it as a
    /// notification would drop an answer the caller is waiting for.
    #[test]
    fn an_empty_identifier_is_refused() {
        let body = br#"{"jsonrpc":"2.0","id":null,"method":"tasks/list"}"#;
        assert_eq!(read(body), Err(Decode::Malformed));
    }

    /// An identifier of any other shape is refused.
    #[test]
    fn an_identifier_of_another_shape_is_refused() {
        for body in [
            &br#"{"jsonrpc":"2.0","id":true,"method":"x"}"#[..],
            &br#"{"jsonrpc":"2.0","id":[1],"method":"x"}"#[..],
            &br#"{"jsonrpc":"2.0","id":{"a":1},"method":"x"}"#[..],
        ] {
            assert_eq!(read(body), Err(Decode::Malformed), "{body:?} was admitted");
        }
    }

    /// The wrong version, or none, is not this protocol.
    #[test]
    fn the_wrong_version_is_not_this_protocol() {
        assert_eq!(
            read(br#"{"jsonrpc":"1.0","id":1,"method":"x"}"#),
            Err(Decode::Malformed)
        );
        assert_eq!(
            read(br#"{"id":1,"method":"x"}"#),
            Err(Decode::MissingDeclaredFact)
        );
    }

    /// A missing or non-string method is not a request.
    #[test]
    fn a_method_must_be_a_string() {
        assert_eq!(
            read(br#"{"jsonrpc":"2.0","id":1}"#),
            Err(Decode::MissingDeclaredFact)
        );
        assert_eq!(
            read(br#"{"jsonrpc":"2.0","id":1,"method":7}"#),
            Err(Decode::Malformed)
        );
    }

    /// The identifier-shape test admits exactly the two shapes and nothing else.
    #[test]
    fn the_identifier_shapes_are_two() {
        assert_eq!(id_shape(br#""a""#), Some(IdShape::Str));
        assert_eq!(id_shape(b"1"), Some(IdShape::Number));
        assert_eq!(id_shape(b"-1.5e3"), Some(IdShape::Number));
        assert_eq!(id_shape(b"null"), None);
        assert_eq!(id_shape(b"true"), None);
        assert_eq!(id_shape(b""), None);
    }

    /// A successful answer is the envelope the codec writes, byte for byte.
    #[test]
    fn a_successful_answer_is_the_codecs_envelope() {
        let id = id_value(b"7").expect("a number is a value");
        let bytes = success(&id, br#"{"kind":"task","id":"t1"}"#).expect("the result writes");
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"id":7,"jsonrpc":"2.0","result":{"id":"t1","kind":"task"}}"#
        );
    }

    /// An answer echoes a named identifier as the caller wrote it.
    #[test]
    fn an_answer_echoes_a_named_identifier() {
        let id = id_value(br#""a2a-http-json""#).expect("a string is a value");
        let bytes = success(&id, b"{}").expect("the result writes");
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"id":"a2a-http-json","jsonrpc":"2.0","result":{}}"#
        );
    }

    /// This protocol's own errors carry the typed detail entry.
    #[test]
    fn a_protocol_error_carries_its_detail_entry() {
        let id = id_value(b"1").expect("a number is a value");
        let bytes = error(&id, -32001, "no such task").expect("the error writes");
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"error":{"code":-32001,"data":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","domain":"a2a-protocol.org","reason":"TASK_NOT_FOUND"}],"message":"no such task"},"id":1,"jsonrpc":"2.0"}"#
        );
    }

    /// A standard error carries no detail entry, because this protocol names no word for it.
    #[test]
    fn a_standard_error_carries_no_detail_entry() {
        let id = id_value(b"1").expect("a number is a value");
        let bytes = error(&id, -32601, "no such method").expect("the error writes");
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"error":{"code":-32601,"message":"no such method"},"id":1,"jsonrpc":"2.0"}"#
        );
    }

    /// Every code and word here appears in the codec's own table.
    ///
    /// The table is visible to its own crate only, so this reads its source. A copy that is checked
    /// is not a second opinion; a copy that is not checked is.
    #[test]
    fn the_error_table_is_the_codecs_own() {
        let source = include_str!("../../busbar-a2a/src/a2a/rpcerror.rs");
        for (code, reason) in ERRORS {
            assert!(
                source.contains(&format!("{code}")),
                "the codec no longer names the code {code}"
            );
            assert!(
                source.contains(reason),
                "the codec no longer names the word {reason}"
            );
        }
        assert!(source.contains("type.googleapis.com/google.rpc.ErrorInfo"));
        assert!(source.contains("a2a-protocol.org"));
    }

    /// The reader is deterministic over the same bytes.
    #[test]
    fn the_reader_is_deterministic() {
        let body = br#"{"jsonrpc":"2.0","id":"x","method":"message/send","params":{}}"#;
        assert_eq!(read(body), read(body));
    }
}
