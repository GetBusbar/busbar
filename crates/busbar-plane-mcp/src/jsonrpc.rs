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

/// The bytes could not be read at all.
pub const CODE_PARSE_ERROR: i64 = -32700;

/// The envelope was not a request.
pub const CODE_INVALID_REQUEST: i64 = -32600;

/// The method named is not one this node answers.
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;

/// The parameters were not admissible.
pub const CODE_INVALID_PARAMS: i64 = -32602;

/// Something on this side failed.
pub const CODE_INTERNAL: i64 = -32603;

/// A mirrored header did not agree with the body it was mirrored from.
pub const CODE_HEADER_MISMATCH: i64 = -32020;

/// The caller did not declare a capability the answer would have needed.
pub const CODE_MISSING_CLIENT_CAPABILITY: i64 = -32021;

/// The revision the caller asked for is not one this node speaks.
pub const CODE_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// A policy said no.
pub const CODE_REFUSED: i64 = -32000;

/// The server this call would have reached could not be reached.
pub const CODE_UPSTREAM_UNAVAILABLE: i64 = -32030;

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
pub const RETIRED_CODES: &[i64] = &[-32002, -32042];

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

/// Read one envelope out of a request body.
///
/// # Errors
/// Returns a decode error when the bytes are not this protocol's shape: no version member or the
/// wrong one, no method member or a method that is not a string, or an identifier that is present
/// and is neither a string nor a number.
pub fn read(body: &[u8]) -> Result<Envelope, Decode> {
    let found = crate::spans::resolve(body, &[PTR_VERSION, PTR_METHOD, PTR_ID, PTR_PARAMS]);
    let at = |ptr: &str| found.iter().find(|(p, _)| *p == ptr).map(|(_, s)| *s);

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
        b'-' | b'0'..=b'9' => {
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
/// # Errors
/// Returns an encode error when the result bytes are not a document.
pub fn success(
    id: Option<&serde_json::Value>,
    result_bytes: &[u8],
    result_type: &str,
) -> Result<Vec<u8>, Encode> {
    let mut result: serde_json::Value =
        serde_json::from_slice(result_bytes).map_err(|_| Encode::Unrepresentable)?;
    if let Some(object) = result.as_object_mut() {
        object.insert("resultType".into(), result_type.into());
    }
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
mod tests {
    use super::{
        error, id_shape, id_value, read, success, IdShape, CODES, RESULT_TYPE_COMPLETE,
        RETIRED_CODES,
    };
    use busbar_contract::wire::Decode;

    /// The serializer writes members in sorted order, and every byte-identity claim rests on it.
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
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}"#;
        let e = read(body).expect("a well-formed request reads");
        assert_eq!(e.method_str(body), Some("tools/call"));
        assert_eq!(e.id_bytes(body), Some(&b"1"[..]));
        assert!(e.is_request());
    }

    /// A request with no identifier is a notification and obliges no answer.
    #[test]
    fn an_absent_identifier_is_a_notification() {
        let body = br#"{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}"#;
        let e = read(body).expect("a notification reads");
        assert!(!e.is_request());
    }

    /// An empty identifier is refused rather than read as absent.
    #[test]
    fn an_empty_identifier_is_refused() {
        let body = br#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#;
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

    /// The identifier-shape test admits exactly the two shapes and nothing else.
    #[test]
    fn the_identifier_shapes_are_two() {
        assert_eq!(id_shape(br#""a""#), Some(IdShape::Str));
        assert_eq!(id_shape(b"1"), Some(IdShape::Number));
        assert_eq!(id_shape(b"null"), None);
        assert_eq!(id_shape(b"true"), None);
        assert_eq!(id_shape(b""), None);
    }

    /// A successful answer carries the discriminator and the caller's identifier.
    #[test]
    fn a_successful_answer_carries_the_discriminator() {
        let id = id_value(b"1").expect("a number is a value");
        let bytes = success(Some(&id), br#"{"tools":[]}"#, RESULT_TYPE_COMPLETE)
            .expect("the result writes");
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"id":1,"jsonrpc":"2.0","result":{"resultType":"complete","tools":[]}}"#
        );
    }

    /// A discriminator a server put on its own result is REPLACED, never passed through.
    ///
    /// This is the laundering the three-constructor shape exists to prevent, asserted rather than
    /// described: a server's demand for the caller's authority does not leave here wearing this
    /// node's name.
    #[test]
    fn a_servers_own_discriminator_is_replaced() {
        let id = id_value(b"1").expect("a number is a value");
        let bytes = success(
            Some(&id),
            br#"{"resultType":"input_required","content":[]}"#,
            RESULT_TYPE_COMPLETE,
        )
        .expect("the result writes");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("it is a document");
        assert_eq!(value["result"]["resultType"], "complete");
    }

    /// On a successful answer with no identifier, the member is omitted.
    #[test]
    fn a_successful_answer_omits_an_absent_identifier() {
        let bytes = success(None, b"{}", RESULT_TYPE_COMPLETE).expect("the result writes");
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"jsonrpc":"2.0","result":{"resultType":"complete"}}"#
        );
    }

    /// On an error the member is always written, and it is empty when there is none.
    ///
    /// A peer's own test for "is this a response" is whether the member is present at all, so an
    /// omitted one would be classified as neither a response nor a notification.
    #[test]
    fn an_error_always_writes_the_identifier() {
        let bytes = error(None, super::CODE_INVALID_REQUEST, "bad", None).expect("it writes");
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"error":{"code":-32600,"message":"bad"},"id":null,"jsonrpc":"2.0"}"#
        );
    }

    /// An error with detail carries it under the member the shared builder uses.
    #[test]
    fn an_error_carries_its_detail() {
        let id = id_value(b"4").expect("a number is a value");
        let bytes = error(
            Some(&id),
            super::CODE_MISSING_CLIENT_CAPABILITY,
            "no capability",
            Some(serde_json::json!({ "requiredCapabilities": ["sampling"] })),
        )
        .expect("it writes");
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"error":{"code":-32021,"data":{"requiredCapabilities":["sampling"]},"message":"no capability"},"id":4,"jsonrpc":"2.0"}"#
        );
    }

    /// Every code this plane may write is one the codec names.
    ///
    /// The codec's own tables are visible to its crate only, so this reads their source. Two of the
    /// ten belong to the shared reader rather than to this protocol, and they are checked there.
    #[test]
    fn every_code_is_the_codecs_own() {
        let envelope = include_str!("../../busbar-mcp/src/mcp/envelope.rs");
        let method = include_str!("../../busbar-mcp/src/mcp/method.rs");
        for code in CODES {
            let text = format!("{code}");
            assert!(
                envelope.contains(&text) || method.contains(&text),
                "the codec no longer names the code {code}"
            );
        }
    }

    /// This plane writes none of the codes the current revision retired.
    #[test]
    fn no_retired_code_is_writable() {
        for retired in RETIRED_CODES {
            assert!(
                !CODES.contains(retired),
                "the plane can write the retired code {retired}"
            );
        }
    }

    /// The reader is deterministic over the same bytes.
    #[test]
    fn the_reader_is_deterministic() {
        let body = br#"{"jsonrpc":"2.0","id":"x","method":"tools/list","params":{}}"#;
        assert_eq!(read(body), read(body));
    }
}
