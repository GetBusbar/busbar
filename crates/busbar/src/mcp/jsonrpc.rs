// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JSON-RPC 2.0, MIRRORED IN OUR OWN STRUCTS AND PARSED STRICTLY.
//!
//! The types are hand-written rather than generated from anyone's schema. A generated type is a
//! vendor's schema decisions welded into our wire: which member they made optional, how they spell a
//! variant, what they silently drop. Mirroring costs one file and keeps the decisions ours.
//!
//! ## Strict on the way in, conservative on the way out
//!
//! Every refusal below is a case where the alternative is GUESSING on behalf of a party we do not
//! control. A frame missing its version, a response carrying both outcomes, an id that is an object:
//! each of these has an obvious "probably meant" reading, and taking it means two implementations
//! reading the same bytes differently. That is the desync a protocol attack is made of, so an
//! ambiguous frame is refused by name instead.
//!
//! The one deliberate laxity is UNKNOWN MEMBERS, which are ignored. That is not a guess: JSON-RPC
//! and MCP both extend by adding members, so refusing an unknown one would make every future peer
//! revision unparseable. The rule is that unknown members never CHANGE the reading of the members we
//! do understand.

use serde_json::{Map, Value};

/// The one version string this implementation speaks.
const VERSION: &str = "2.0";

/// The prefix of the MCP notification namespace. A method in it must never be correlated.
const NOTIFICATION_NAMESPACE: &str = "notifications/";

/// Standard JSON-RPC error codes, spelled once.
pub(crate) const CODE_PARSE_ERROR: i64 = -32700;
pub(crate) const CODE_INVALID_REQUEST: i64 = -32600;
pub(crate) const CODE_METHOD_NOT_FOUND: i64 = -32601;
pub(crate) const CODE_INVALID_PARAMS: i64 = -32602;
pub(crate) const CODE_INTERNAL_ERROR: i64 = -32603;

/// A correlation id, which the specification allows to be a string or an integer.
///
/// The two are kept DISTINCT: `1` and `"1"` are different ids, and a parser that coerces between
/// them lets a peer have a reply matched to a request it never sent. Equality here is the pending
/// table's equality, so the distinction has to live in the type rather than at each comparison.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Id {
    Number(i64),
    Text(String),
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The rendering is unambiguous about which arm it came from, so an operator reading a
            // log can still tell `1` from `"1"` after the type is gone.
            Id::Number(n) => write!(f, "{n}"),
            Id::Text(s) => write!(f, "{s:?}"),
        }
    }
}

impl Id {
    fn to_value(&self) -> Value {
        match self {
            Id::Number(n) => Value::from(*n),
            Id::Text(s) => Value::from(s.clone()),
        }
    }
}

/// The `error` member of a response.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RpcError {
    pub(crate) code: i64,
    pub(crate) message: String,
    pub(crate) data: Option<Value>,
}

impl RpcError {
    pub(crate) fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
            data: None,
        }
    }
    pub(crate) fn parse_error(why: impl Into<String>) -> Self {
        Self::new(CODE_PARSE_ERROR, why)
    }
    pub(crate) fn invalid_request(why: impl Into<String>) -> Self {
        Self::new(CODE_INVALID_REQUEST, why)
    }
    pub(crate) fn method_not_found(what: impl std::fmt::Display) -> Self {
        Self::new(CODE_METHOD_NOT_FOUND, format!("method not found: {what}"))
    }
    pub(crate) fn invalid_params(why: impl Into<String>) -> Self {
        Self::new(CODE_INVALID_PARAMS, why)
    }
    pub(crate) fn internal(why: impl Into<String>) -> Self {
        Self::new(CODE_INTERNAL_ERROR, why)
    }
}

/// A request: a method that expects exactly one reply, correlated by id.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Request {
    pub(crate) id: Id,
    pub(crate) method: String,
    pub(crate) params: Option<Value>,
}

/// A notification: a method that expects no reply, and therefore carries no id.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Notification {
    pub(crate) method: String,
    pub(crate) params: Option<Value>,
}

/// A response: an id plus EXACTLY ONE outcome, which is why the outcome is a `Result` rather than
/// two independently-present members that could both be there or neither.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Response {
    pub(crate) id: Id,
    pub(crate) outcome: Result<Value, RpcError>,
}

/// One parsed frame.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Message {
    Request(Request),
    Notification(Notification),
    Response(Response),
}

/// Why a frame was refused. Every arm is a case where accepting it would mean deciding, on a peer's
/// behalf, something the peer did not say.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ProtocolError {
    /// Not JSON at all: truncated, empty, not UTF-8, or nested past the parser's recursion limit.
    NotJson(String),
    /// Valid JSON, but not an object.
    NotAnObject,
    /// A JSON array, which is a BATCH. Removed from MCP in the 2025-06-18 revision, so a peer
    /// sending one is speaking a protocol this implementation does not have.
    BatchUnsupported,
    /// `jsonrpc` absent, or not exactly the string `"2.0"`. Carries what was found.
    WrongVersion(String),
    /// `id` present but not a string or an integer (null, bool, float, object, array).
    IdNotStringOrInteger,
    /// `method` present but not a non-empty string.
    MethodNotAName,
    /// `params` present but a scalar. The specification requires a structured value.
    ParamsNotStructured,
    /// A method in the notification namespace carrying an id: a frame asking to be a request to one
    /// reader and a notification to another.
    NotificationCarriesId(String),
    /// A response carrying both `result` and `error`.
    ResponseIsBothOutcomes,
    /// A response carrying neither.
    ResponseHasNoOutcome,
    /// The `error` member is not a well-formed error object. Carries which part was wrong.
    MalformedError(&'static str),
    /// Neither a method nor an id: nothing that could be routed anywhere.
    Unroutable,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::NotJson(why) => write!(f, "frame is not valid JSON: {why}"),
            ProtocolError::NotAnObject => write!(f, "frame is not a JSON object"),
            ProtocolError::BatchUnsupported => write!(
                f,
                "batched frames are not supported (removed from MCP in the 2025-06-18 revision)"
            ),
            ProtocolError::WrongVersion(found) => {
                write!(f, "expected \"jsonrpc\": \"{VERSION}\", found {found}")
            }
            ProtocolError::IdNotStringOrInteger => {
                write!(f, "id must be a string or an integer")
            }
            ProtocolError::MethodNotAName => write!(f, "method must be a non-empty string"),
            ProtocolError::ParamsNotStructured => {
                write!(f, "params must be an object or an array")
            }
            ProtocolError::NotificationCarriesId(m) => {
                write!(f, "notification `{m}` carries an id")
            }
            ProtocolError::ResponseIsBothOutcomes => {
                write!(f, "response carries both a result and an error")
            }
            ProtocolError::ResponseHasNoOutcome => {
                write!(f, "response carries neither a result nor an error")
            }
            ProtocolError::MalformedError(what) => write!(f, "malformed error object: {what}"),
            ProtocolError::Unroutable => {
                write!(f, "frame carries neither a method nor an id")
            }
        }
    }
}

impl ProtocolError {
    /// The reply this refusal deserves, for the direction where we OWE the peer one. Kept next to
    /// the error so a new arm cannot be added without deciding its code.
    pub(crate) fn to_rpc_error(&self) -> RpcError {
        match self {
            ProtocolError::NotJson(why) => RpcError::parse_error(format!("parse error: {why}")),
            other => RpcError::invalid_request(other.to_string()),
        }
    }
}

impl Message {
    /// Parse ONE frame. Framing is [`super::framing`]'s job; this function is handed the bytes of a
    /// single message and never scans past them.
    pub(crate) fn parse(frame: &[u8]) -> Result<Message, ProtocolError> {
        // serde_json enforces its own recursion limit, so a nesting bomb comes back as a parse
        // error rather than as a stack overflow, which would abort the process rather than the task.
        let value: Value =
            serde_json::from_slice(frame).map_err(|e| ProtocolError::NotJson(e.to_string()))?;
        let obj = match value {
            Value::Object(map) => map,
            Value::Array(_) => return Err(ProtocolError::BatchUnsupported),
            _ => return Err(ProtocolError::NotAnObject),
        };
        Self::from_object(obj)
    }

    fn from_object(obj: Map<String, Value>) -> Result<Message, ProtocolError> {
        match obj.get("jsonrpc") {
            Some(Value::String(v)) if v == VERSION => {}
            Some(other) => return Err(ProtocolError::WrongVersion(other.to_string())),
            None => return Err(ProtocolError::WrongVersion("no jsonrpc member".into())),
        }

        // The id is read before the routing decision, because "absent" and "present but invalid"
        // are different frames and only the first of them is a notification.
        let id = match obj.get("id") {
            None => None,
            Some(Value::String(s)) => Some(Id::Text(s.clone())),
            Some(Value::Number(n)) => Some(Id::Number(
                n.as_i64().ok_or(ProtocolError::IdNotStringOrInteger)?,
            )),
            Some(_) => return Err(ProtocolError::IdNotStringOrInteger),
        };

        let method = match obj.get("method") {
            None => None,
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            Some(_) => return Err(ProtocolError::MethodNotAName),
        };

        match (method, id) {
            (Some(method), Some(id)) => {
                if method.starts_with(NOTIFICATION_NAMESPACE) {
                    return Err(ProtocolError::NotificationCarriesId(method));
                }
                Ok(Message::Request(Request {
                    id,
                    method,
                    params: params_of(&obj)?,
                }))
            }
            (Some(method), None) => Ok(Message::Notification(Notification {
                method,
                params: params_of(&obj)?,
            })),
            (None, Some(id)) => Ok(Message::Response(Response {
                id,
                outcome: outcome_of(&obj)?,
            })),
            (None, None) => Err(ProtocolError::Unroutable),
        }
    }
}

/// `params`, which may be absent, explicitly null (both meaning none), or structured. A scalar is a
/// refusal rather than a one-element positional list: guessing which the peer meant is exactly the
/// kind of repair this parser does not do.
fn params_of(obj: &Map<String, Value>) -> Result<Option<Value>, ProtocolError> {
    match obj.get("params") {
        None | Some(Value::Null) => Ok(None),
        Some(v @ (Value::Object(_) | Value::Array(_))) => Ok(Some(v.clone())),
        Some(_) => Err(ProtocolError::ParamsNotStructured),
    }
}

/// The single outcome of a response. `"result": null` is a RESULT (the reply to a call that returns
/// nothing), which is why presence is tested rather than truthiness.
fn outcome_of(obj: &Map<String, Value>) -> Result<Result<Value, RpcError>, ProtocolError> {
    match (obj.get("result"), obj.get("error")) {
        (Some(_), Some(_)) => Err(ProtocolError::ResponseIsBothOutcomes),
        (None, None) => Err(ProtocolError::ResponseHasNoOutcome),
        (Some(result), None) => Ok(Ok(result.clone())),
        (None, Some(error)) => Ok(Err(rpc_error_of(error)?)),
    }
}

fn rpc_error_of(value: &Value) -> Result<RpcError, ProtocolError> {
    let map = value
        .as_object()
        .ok_or(ProtocolError::MalformedError("error is not an object"))?;
    let code = map
        .get("code")
        .and_then(Value::as_i64)
        .ok_or(ProtocolError::MalformedError("code is not an integer"))?;
    let message = map
        .get("message")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::MalformedError("message is not a string"))?
        .to_string();
    Ok(RpcError {
        code,
        message,
        data: map.get("data").cloned(),
    })
}

// What we EMIT ------------------------------------------------------------------------------------
//
// A frame is built member by member rather than by deriving Serialize, for one reason: the response
// shape is "exactly one outcome", and a derive over two `Option` members can express the two illegal
// combinations the parser above refuses. Building it from the `Result` makes both unrepresentable.

impl Request {
    pub(crate) fn new(id: Id, method: impl Into<String>, params: Option<Value>) -> Self {
        Request {
            id,
            method: method.into(),
            params,
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("jsonrpc".into(), Value::from(VERSION));
        m.insert("id".into(), self.id.to_value());
        m.insert("method".into(), Value::from(self.method.clone()));
        if let Some(p) = &self.params {
            m.insert("params".into(), p.clone());
        }
        Value::Object(m)
    }

    pub(crate) fn to_frame(&self) -> Vec<u8> {
        frame_of(&self.to_value())
    }
}

impl Notification {
    pub(crate) fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Notification {
            method: method.into(),
            params,
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("jsonrpc".into(), Value::from(VERSION));
        m.insert("method".into(), Value::from(self.method.clone()));
        if let Some(p) = &self.params {
            m.insert("params".into(), p.clone());
        }
        Value::Object(m)
    }

    pub(crate) fn to_frame(&self) -> Vec<u8> {
        frame_of(&self.to_value())
    }
}

impl Response {
    pub(crate) fn ok(id: Id, result: Value) -> Self {
        Response {
            id,
            outcome: Ok(result),
        }
    }

    pub(crate) fn failed(id: Id, error: RpcError) -> Self {
        Response {
            id,
            outcome: Err(error),
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("jsonrpc".into(), Value::from(VERSION));
        m.insert("id".into(), self.id.to_value());
        match &self.outcome {
            Ok(result) => {
                m.insert("result".into(), result.clone());
            }
            Err(e) => {
                let mut em = Map::new();
                em.insert("code".into(), Value::from(e.code));
                em.insert("message".into(), Value::from(e.message.clone()));
                if let Some(d) = &e.data {
                    em.insert("data".into(), d.clone());
                }
                m.insert("error".into(), Value::Object(em));
            }
        }
        Value::Object(m)
    }

    pub(crate) fn to_frame(&self) -> Vec<u8> {
        frame_of(&self.to_value())
    }
}

/// Serialize one frame. `to_string` never emits a raw newline (serde escapes them inside strings),
/// which is what makes the emitted bytes safe for the newline-delimited stdio transport.
fn frame_of(v: &Value) -> Vec<u8> {
    // A Value assembled in this file cannot fail to serialize: there are no non-string map keys and
    // no non-finite floats in it. Falling back to an empty object rather than unwrapping keeps a
    // future Value we did not build from turning a serialization surprise into a panic on the
    // response path.
    serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec())
}

#[cfg(test)]
#[path = "tests/jsonrpc_tests.rs"]
mod jsonrpc_tests;
