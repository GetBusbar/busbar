// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE gRPC LINE'S CODEC: the a2aproject's own service, read and answered by the plane (the
//! engine's `a2a/grpc.rs`, ported; ARCHITECT ruling on FOLD-A2A, 2026-10-04: protobuf is decoded
//! and encoded in the plane; the grpc transport door owns the framing and the trailers).
//!
//! A2A's gRPC binding is the SAME protocol as its JSON-RPC binding: the rpc name IS the v1.0
//! JSON-RPC method, and A2A v1.0's JSON representation of a request message IS its ProtoJSON. So
//! the line is a transcoding and nothing else:
//!
//! 1. [`compose`]: the call's one request message, decoded, carried through the SDK's conversion
//!    rules ([`crate::proto::Normal`]) and written as its ProtoJSON, framed as the
//!    v1.0 JSON-RPC request the unit then serves exactly as the JSON-RPC line serves its own: the
//!    same arrival, catalogue, admission, task store and relay, nothing skipped and nothing added.
//! 2. [`answer_message`]: the JSON-RPC answer the unit wrote, transcoded back to the rpc's response
//!    message, or its `error` member turned into the status A2A section 5.4 binds it to, with the
//!    `google.rpc.ErrorInfo` the error carries as the status details (section 10.6).
//! 3. [`event`]: one event of an answer in events, as the `StreamResponse` message a
//!    server-streaming rpc answers with.
//!
//! No A2A wire fact is hand-written here: the messages, the method names and the ProtoJSON mapping
//! are generated from the a2aproject's own `a2a.proto` ([`crate::proto::pb`]). The status a call ends with is the gRPC numbering ([`Code`]) and its details the
//! `google.rpc.Status` message carrying the error's `google.rpc.ErrorInfo` ([`CallStatus::details`]),
//! the bytes the engine's status carried as its details.

use crate::proto::{pb, Normal};
use prost::Message as _;
use serde_json::Value;

/// THE STATUS NUMBERING a call ends with: the gRPC canonical codes the line answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Code {
    /// `OK`.
    Ok = 0,
    /// `UNKNOWN`.
    Unknown = 2,
    /// `INVALID_ARGUMENT`.
    InvalidArgument = 3,
    /// `NOT_FOUND`.
    NotFound = 5,
    /// `PERMISSION_DENIED`.
    PermissionDenied = 7,
    /// `RESOURCE_EXHAUSTED`.
    ResourceExhausted = 8,
    /// `FAILED_PRECONDITION`.
    FailedPrecondition = 9,
    /// `UNIMPLEMENTED`.
    Unimplemented = 12,
    /// `INTERNAL`.
    Internal = 13,
    /// `UNAVAILABLE`.
    Unavailable = 14,
    /// `UNAUTHENTICATED`.
    Unauthenticated = 16,
}

/// HOW A CALL ENDS when it ends with no message: its code, its message, and its details (the
/// encoded `google.rpc.Status`, empty when the error carries no `ErrorInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallStatus {
    code: Code,
    message: String,
    details: Vec<u8>,
}

impl CallStatus {
    /// A status with no details.
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        CallStatus {
            code,
            message: message.into(),
            details: Vec::new(),
        }
    }

    /// A status whose details carry `info`, as the error model's `google.rpc.Status` does.
    #[must_use]
    pub fn with_error_info(code: Code, message: impl Into<String>, info: ErrorInfo) -> Self {
        let message = message.into();
        let details = rpc::Status {
            code: code as i32,
            message: message.clone(),
            details: vec![rpc::Any {
                type_url: crate::ERROR_INFO_TYPE.to_string(),
                value: info.encode_to_vec(),
            }],
        }
        .encode_to_vec();
        CallStatus {
            code,
            message,
            details,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        CallStatus::new(Code::Internal, message)
    }

    fn invalid_argument(message: impl Into<String>) -> Self {
        CallStatus::new(Code::InvalidArgument, message)
    }

    /// The code.
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The encoded `google.rpc.Status` details; empty when there are none.
    #[must_use]
    pub fn details(&self) -> &[u8] {
        &self.details
    }

    /// The `ErrorInfo` the details carry, read back.
    #[must_use]
    pub fn error_info(&self) -> Option<ErrorInfo> {
        let status = rpc::Status::decode(self.details.as_slice()).ok()?;
        status
            .details
            .iter()
            .find(|any| any.type_url == crate::ERROR_INFO_TYPE)
            .and_then(|any| ErrorInfo::decode(any.value.as_slice()).ok())
    }
}

/// `google.rpc.ErrorInfo`: why an A2A error happened, in the protocol's own reason vocabulary.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ErrorInfo {
    /// The reason token.
    #[prost(string, tag = "1")]
    pub reason: String,
    /// The domain the reason is of.
    #[prost(string, tag = "2")]
    pub domain: String,
    /// What the error names.
    #[prost(btree_map = "string, string", tag = "3")]
    pub metadata: std::collections::BTreeMap<String, String>,
}

/// The error model's envelope messages the details are written in.
mod rpc {
    /// `google.rpc.Status`.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Status {
        #[prost(int32, tag = "1")]
        pub code: i32,
        #[prost(string, tag = "2")]
        pub message: String,
        #[prost(message, repeated, tag = "3")]
        pub details: Vec<Any>,
    }

    /// `google.protobuf.Any`.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Any {
        #[prost(string, tag = "1")]
        pub type_url: String,
        #[prost(bytes = "vec", tag = "2")]
        pub value: Vec<u8>,
    }
}

/// The service every rpc of the line is a method of: the target is `<SERVICE_PATH>/<rpc>`.
pub const SERVICE_PATH: &str = "/lf.a2a.v1.A2AService";

/// The A2A protocol version a call that names none speaks. The gRPC service descriptor IS the v1
/// protocol (there is no v0.3 protobuf), so an absent `a2a-version` is a 1.0 request here, unlike
/// the HTTP lines where an absent header means 0.3.
pub const DEFAULT_VERSION: &str = "1.0";

/// The JSON-RPC id the composed request is framed under. gRPC has no correlation member, so there
/// is nothing of the caller's to echo; the answer is read back under it and never leaves the plane.
pub const COMPOSED_ID: i64 = 1;

/// Every rpc of the service, by its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rpc {
    /// `SendMessage`.
    SendMessage,
    /// `SendStreamingMessage`: answered in events.
    SendStreamingMessage,
    /// `GetTask`.
    GetTask,
    /// `ListTasks`.
    ListTasks,
    /// `CancelTask`.
    CancelTask,
    /// `SubscribeToTask`: answered in events.
    SubscribeToTask,
    /// `CreateTaskPushNotificationConfig`.
    CreateTaskPushNotificationConfig,
    /// `GetTaskPushNotificationConfig`.
    GetTaskPushNotificationConfig,
    /// `ListTaskPushNotificationConfigs`.
    ListTaskPushNotificationConfigs,
    /// `GetExtendedAgentCard`.
    GetExtendedAgentCard,
    /// `DeleteTaskPushNotificationConfig`: answered with `google.protobuf.Empty`.
    DeleteTaskPushNotificationConfig,
}

/// Every rpc, in the service descriptor's order.
pub const RPCS: [Rpc; 11] = [
    Rpc::SendMessage,
    Rpc::SendStreamingMessage,
    Rpc::GetTask,
    Rpc::ListTasks,
    Rpc::CancelTask,
    Rpc::SubscribeToTask,
    Rpc::CreateTaskPushNotificationConfig,
    Rpc::GetTaskPushNotificationConfig,
    Rpc::ListTaskPushNotificationConfigs,
    Rpc::GetExtendedAgentCard,
    Rpc::DeleteTaskPushNotificationConfig,
];

impl Rpc {
    /// The rpc's name: its method segment, and the v1.0 JSON-RPC method it is.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Rpc::SendMessage => "SendMessage",
            Rpc::SendStreamingMessage => "SendStreamingMessage",
            Rpc::GetTask => "GetTask",
            Rpc::ListTasks => "ListTasks",
            Rpc::CancelTask => "CancelTask",
            Rpc::SubscribeToTask => "SubscribeToTask",
            Rpc::CreateTaskPushNotificationConfig => "CreateTaskPushNotificationConfig",
            Rpc::GetTaskPushNotificationConfig => "GetTaskPushNotificationConfig",
            Rpc::ListTaskPushNotificationConfigs => "ListTaskPushNotificationConfigs",
            Rpc::GetExtendedAgentCard => "GetExtendedAgentCard",
            Rpc::DeleteTaskPushNotificationConfig => "DeleteTaskPushNotificationConfig",
        }
    }

    /// The rpc a call's target names (`/lf.a2a.v1.A2AService/<rpc>`, its query ignored); `None` for
    /// a method the service does not have, which the service answers `UNIMPLEMENTED`.
    #[must_use]
    pub fn of_target(target: &str) -> Option<Self> {
        let path = target.split('?').next().unwrap_or_default();
        let name = path.strip_prefix(SERVICE_PATH)?.strip_prefix('/')?;
        RPCS.into_iter().find(|rpc| rpc.name() == name)
    }

    /// Whether the rpc is server-streaming: its answer is a stream of `StreamResponse` messages.
    #[must_use]
    pub const fn streams(self) -> bool {
        matches!(self, Rpc::SendStreamingMessage | Rpc::SubscribeToTask)
    }
}

/// The answer to a method the service does not have: `UNIMPLEMENTED` with no message, as the
/// generated service answered it.
#[must_use]
pub fn unimplemented() -> CallStatus {
    CallStatus::new(Code::Unimplemented, "")
}

/// PROTOBUF IN, the JSON-RPC request OUT: `message` decoded as `rpc`'s request message and framed
/// as the v1.0 JSON-RPC request it is. A message that does not decode is `INTERNAL` with the
/// decoder's words (the gRPC status table's mapping of a protobuf parse error, as the engine's
/// codec answered it); one whose ProtoJSON cannot be
/// written is `INVALID_ARGUMENT`.
///
/// # Errors
///
/// The status the call is answered with instead.
pub fn compose(rpc: Rpc, message: &[u8]) -> Result<Vec<u8>, CallStatus> {
    let params = match rpc {
        Rpc::SendMessage | Rpc::SendStreamingMessage => {
            to_params::<pb::SendMessageRequest>(message)?
        }
        Rpc::GetTask => to_params::<pb::GetTaskRequest>(message)?,
        Rpc::ListTasks => to_params::<pb::ListTasksRequest>(message)?,
        Rpc::CancelTask => to_params::<pb::CancelTaskRequest>(message)?,
        Rpc::SubscribeToTask => to_params::<pb::SubscribeToTaskRequest>(message)?,
        Rpc::CreateTaskPushNotificationConfig => {
            to_params::<pb::TaskPushNotificationConfig>(message)?
        }
        Rpc::GetTaskPushNotificationConfig => {
            to_params::<pb::GetTaskPushNotificationConfigRequest>(message)?
        }
        Rpc::ListTaskPushNotificationConfigs => {
            to_params::<pb::ListTaskPushNotificationConfigsRequest>(message)?
        }
        Rpc::GetExtendedAgentCard => to_params::<pb::GetExtendedAgentCardRequest>(message)?,
        Rpc::DeleteTaskPushNotificationConfig => {
            to_params::<pb::DeleteTaskPushNotificationConfigRequest>(message)?
        }
    };
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "id": COMPOSED_ID,
        "method": rpc.name(),
        "params": params,
    });
    Ok(envelope.to_string().into_bytes())
}

/// Whether `message` is a send whose request carries no message at all: the SDK's model gave it a
/// fresh user message under a new (v7) id, which the unit mints at its first attempt
/// ([`message_id_v7`]) from the host's clock and random bytes.
#[must_use]
pub fn mints_message_id(rpc: Rpc, message: &[u8]) -> bool {
    matches!(rpc, Rpc::SendMessage | Rpc::SendStreamingMessage)
        && pb::SendMessageRequest::decode(message).is_ok_and(|m| m.message.is_none())
}

/// A version-7 UUID (RFC 9562) over `unix_ms` and ten random bytes, as the SDK's model minted a
/// message id: the 48-bit millisecond time, the version, 12 random bits, the variant, 62 random
/// bits, written lower-case and hyphenated.
#[must_use]
pub fn message_id_v7(unix_ms: u64, random: &[u8; 10]) -> String {
    let mut b = [0_u8; 16];
    b[..6].copy_from_slice(&unix_ms.to_be_bytes()[2..]);
    b[6..].copy_from_slice(random);
    b[6] = 0x70 | (b[6] & 0x0f);
    b[8] = 0x80 | (b[8] & 0x3f);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// `envelope` with `id` as its message's `messageId` (the composed request already carries the
/// fresh message's user role, [`crate::proto::Normal`]).
#[must_use]
pub fn with_message_id(envelope: &Value, id: &str) -> Value {
    let mut envelope = envelope.clone();
    if let Some(params) = envelope.get_mut("params").and_then(Value::as_object_mut) {
        let message = params
            .entry("message")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(m) = message.as_object_mut() {
            m.insert("messageId".into(), Value::String(id.to_string()));
        }
    }
    envelope
}

/// PROTOBUF IN, CANONICAL JSON OUT: `message` decoded as `M` (a parse error is `INTERNAL` with the
/// decoder's words), carried through the model's rules, written as its ProtoJSON.
fn to_params<M>(message: &[u8]) -> Result<Value, CallStatus>
where
    M: prost::Message + Default + Normal + serde::Serialize,
{
    let mut m = M::decode(message).map_err(|e| CallStatus::internal(e.to_string()))?;
    m.normal()
        .map_err(|e| CallStatus::invalid_argument(format!("the request could not be read: {e}")))?;
    serde_json::to_value(&m).map_err(|e| {
        CallStatus::invalid_argument(format!(
            "the request could not be read: ProtoJSON error: {e}"
        ))
    })
}

/// CANONICAL JSON IN, PROTOBUF OUT: the same mapping in the other direction.
fn from_result<M>(result: Value) -> Result<Vec<u8>, CallStatus>
where
    M: prost::Message + Normal + serde::de::DeserializeOwned,
{
    let mut m: M = serde_json::from_value(result).map_err(|e| {
        CallStatus::internal(format!(
            "the answer could not be rendered: ProtoJSON error: {e}"
        ))
    })?;
    m.normal()
        .map_err(|e| CallStatus::internal(format!("the answer could not be rendered: {e}")))?;
    Ok(m.encode_to_vec())
}

/// THE JSON-RPC ANSWER OUT, the rpc's response message IN ITS PROTOBUF BYTES: `body` is the whole
/// answer the unit wrote at `status` (the neutral status it would have been sent under on the
/// JSON-RPC line). An `error` member is the status section 5.4 binds its code to; a body that is not
/// a JSON-RPC answer is the status gRPC's own HTTP mapping gives `status`. A server-streaming rpc
/// answered whole (the agent completed the work in one step) is its one `StreamResponse`.
///
/// # Errors
///
/// The status the call ends with instead of a message.
pub fn answer_message(rpc: Rpc, status: u32, body: &[u8]) -> Result<Vec<u8>, CallStatus> {
    let Ok(envelope) = serde_json::from_slice::<Value>(body) else {
        return Err(status_for_http(status));
    };
    if let Some(error) = envelope.get("error") {
        return Err(status_for_error(error, status));
    }
    let result = envelope
        .get("result")
        .cloned()
        .ok_or_else(|| status_for_http(status))?;
    match rpc {
        Rpc::SendMessage => from_result::<pb::SendMessageResponse>(result),
        Rpc::SendStreamingMessage | Rpc::SubscribeToTask => {
            from_result::<pb::StreamResponse>(result)
        }
        Rpc::GetTask | Rpc::CancelTask => from_result::<pb::Task>(result),
        Rpc::ListTasks => from_result::<pb::ListTasksResponse>(result),
        Rpc::CreateTaskPushNotificationConfig | Rpc::GetTaskPushNotificationConfig => {
            from_result::<pb::TaskPushNotificationConfig>(result)
        }
        Rpc::ListTaskPushNotificationConfigs => {
            from_result::<pb::ListTaskPushNotificationConfigsResponse>(result)
        }
        Rpc::GetExtendedAgentCard => from_result::<pb::AgentCard>(narrowed_to_the_proto(result)),
        // `google.protobuf.Empty`: the JSON-RPC answer carries `null`, and there is nothing in
        // either to transcode.
        Rpc::DeleteTaskPushNotificationConfig => Ok(Vec::new()),
    }
}

/// ONE EVENT OF AN ANSWER IN EVENTS (one event-stream frame, its blank line excluded), as the
/// `StreamResponse` message it carries: `None` for a frame that carries no JSON-RPC `result` (a
/// comment, a keep-alive, a frame the relay passed through unread), which the stream skips; an
/// `error` member ends the stream with that error's status.
#[must_use]
pub fn event(frame: &str) -> Option<Result<Vec<u8>, CallStatus>> {
    let data = crate::sse::sse_data(frame)?;
    let envelope: Value = serde_json::from_str(&data).ok()?;
    if let Some(error) = envelope.get("error") {
        return Some(Err(status_for_error(error, STATUS_INTERNAL)));
    }
    let result = envelope.get("result")?.clone();
    Some(from_result::<pb::StreamResponse>(result))
}

/// The reply head field the status details ride in, its value the details' base64 (unpadded, as
/// gRPC writes a binary field): the grpc transport renders it into the trailers verbatim, beside the
/// status it renders from the reply's status and the message it renders from the reply's bytes
/// (ARCHITECT ruling Q2, 2026-10-04).
pub const DETAILS_FIELD: &str = "grpc-status-details-bin";

/// Whether `target` (a request target, its query ignored) is a call on the gRPC service: a path
/// under [`SERVICE_PATH`], whether or not the service has the method it names.
#[must_use]
pub fn on_service(target: &str) -> bool {
    target
        .split('?')
        .next()
        .and_then(|path| path.strip_prefix(SERVICE_PATH))
        .is_some_and(|rest| rest.starts_with('/'))
}

/// ONE REPLY ON THE gRPC LINE, as the plane states it to the grpc transport: the status in the
/// line's own numbering (`0` = `OK`), the bytes (the response message on `OK`; the status message
/// otherwise), and the details field's value when the status carries details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedReply {
    /// The gRPC code.
    pub code: u32,
    /// The response message, or the status message.
    pub body: Vec<u8>,
    /// [`DETAILS_FIELD`]'s value.
    pub details: Option<String>,
}

impl From<CallStatus> for FramedReply {
    fn from(status: CallStatus) -> Self {
        use base64::Engine as _;
        let details = (!status.details.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD_NO_PAD.encode(&status.details));
        FramedReply {
            code: status.code as u32,
            body: status.message.into_bytes(),
            details,
        }
    }
}

impl FramedReply {
    /// An `OK` reply carrying `message`.
    #[must_use]
    pub fn ok(message: Vec<u8>) -> Self {
        FramedReply {
            code: Code::Ok as u32,
            body: message,
            details: None,
        }
    }
}

/// The whole JSON-RPC answer `body` at neutral `status`, as the rpc's reply ([`answer_message`]).
#[must_use]
pub fn framed_reply(rpc: Rpc, status: u32, body: &[u8]) -> FramedReply {
    match answer_message(rpc, status, body) {
        Ok(message) => FramedReply::ok(message),
        Err(status) => status.into(),
    }
}

/// A refusal the plane rendered as its JSON-RPC error envelope at neutral `status`, as the status
/// the call ends with (the engine's bridge read the envelope its ingress answered the same way).
#[must_use]
pub fn refusal(envelope: &[u8], status: u32) -> FramedReply {
    let error = serde_json::from_slice::<Value>(envelope)
        .ok()
        .and_then(|v| v.get("error").cloned());
    match error {
        Some(error) => status_for_error(&error, status).into(),
        None => status_for_http(status).into(),
    }
}

/// A reply's status as a CLOSING BLOCK (field lines, `name: value` CRLF each): `grpc-status`, then
/// `grpc-message` where there is a message, then [`DETAILS_FIELD`] where there are details — the
/// order and bytes 1.5.5's gRPC line closed a call with (tonic 0.14's `Status::add_header`). The
/// message is percent-encoded as tonic encoded it: every control byte, every byte past ASCII, the
/// space and each of `` "#%<>`?{}``, upper-case hex.
#[must_use]
pub fn status_block(reply: &FramedReply) -> Vec<u8> {
    let mut out = format!("grpc-status: {}\r\n", reply.code).into_bytes();
    if !reply.body.is_empty() {
        out.extend_from_slice(b"grpc-message: ");
        for &b in &reply.body {
            if (0x21..=0x7e).contains(&b) && !b"\"#%<>`?{}".contains(&b) {
                out.push(b);
            } else {
                out.extend_from_slice(format!("%{b:02X}").as_bytes());
            }
        }
        out.extend_from_slice(b"\r\n");
    }
    if let Some(details) = &reply.details {
        out.extend_from_slice(format!("{DETAILS_FIELD}: {details}\r\n").as_bytes());
    }
    out
}

/// AN ANSWER IN EVENTS, as the messages it carries: every whole event-stream frame of `buf` that
/// carries a result is one `StreamResponse` message, in order; an `error` frame (or a result the
/// model refuses) ends the stream with its status, and nothing after it is read. A unary rpc
/// answered in events was not a JSON-RPC answer to the engine's bridge: it ends with the status
/// gRPC's HTTP mapping gives a `200`.
#[must_use]
pub fn event_messages(rpc: Rpc, buf: &[u8]) -> (Vec<Vec<u8>>, Option<CallStatus>) {
    if !rpc.streams() {
        return (Vec::new(), Some(status_for_http(200)));
    }
    let mut messages = Vec::new();
    let mut rest = buf.to_vec();
    while !rest.is_empty() {
        let frame = take_frame(&mut rest).unwrap_or_else(|| {
            let whole = std::mem::take(&mut rest);
            String::from_utf8_lossy(&whole).into_owned()
        });
        match event(&frame) {
            Some(Ok(message)) => messages.push(message),
            Some(Err(status)) => return (messages, Some(status)),
            None => {}
        }
    }
    (messages, None)
}

/// The next complete event-stream frame in `buffered`, consumed from it: a frame ends at a blank
/// line, in any of the three line-ending spellings the grammar allows (the engine's `take_frame`).
fn take_frame(buffered: &mut Vec<u8>) -> Option<String> {
    const TERMINATORS: [&[u8]; 3] = [b"\r\n\r\n", b"\n\n", b"\r\r"];
    let (at, len) = TERMINATORS
        .iter()
        .filter_map(|t| {
            buffered
                .windows(t.len())
                .position(|w| w == *t)
                .map(|pos| (pos, t.len()))
        })
        .min_by_key(|(pos, len)| (*pos, std::cmp::Reverse(*len)))?;
    let rest = buffered.split_off(at + len);
    let frame = std::mem::replace(buffered, rest);
    Some(String::from_utf8_lossy(&frame[..at]).into_owned())
}

/// The neutral status an event's error is read under (the engine read a stream's error at `500`).
const STATUS_INTERNAL: u32 = 500;

/// THE STATUS FOR A JSON-RPC ERROR OBJECT, read off the code rather than the message: the code
/// maps through the section 5.4 table ([`grpc_code`]); a code that table does not define (a
/// backend's own extension, relayed) falls back to `http`'s mapping. The `google.rpc.ErrorInfo`
/// the error carries rides as the status details (section 10.6; TCK `GRPC-ERR-001`).
#[must_use]
pub fn status_for_error(error: &Value, http: u32) -> CallStatus {
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the request was refused")
        .to_string();
    let code = match error
        .get("code")
        .and_then(Value::as_i64)
        .and_then(grpc_code)
    {
        Some(code) => code,
        None => status_for_http(http).code(),
    };
    match error_info_of(error) {
        Some(info) => CallStatus::with_error_info(code, message, info),
        None => CallStatus::new(code, message),
    }
}

/// THE gRPC CODE section 5.4 binds an A2A or JSON-RPC error code to; `None` for a code A2A does
/// not define.
#[must_use]
pub fn grpc_code(code: i64) -> Option<Code> {
    Some(match code {
        -32001 => Code::NotFound,
        // FAILED_PRECONDITION for exactly the three rows section 5.4 binds to it.
        -32002 | -32007 | -32008 => Code::FailedPrecondition,
        // UNIMPLEMENTED: a capability the server does not implement (section 5.4, TCK
        // `GRPC-ERR-002`), and a method the endpoint does not have.
        -32003 | -32004 | -32009 | -32601 => Code::Unimplemented,
        -32005 | -32600 | -32602 | -32700 => Code::InvalidArgument,
        -32006 | -32603 => Code::Internal,
        _ => return None,
    })
}

/// THE `google.rpc.ErrorInfo` THIS ERROR ALREADY CARRIES, transcribed (never re-derived) into the
/// details shape; `None` for an error carrying none (the standard JSON-RPC errors have no reason).
fn error_info_of(error: &Value) -> Option<ErrorInfo> {
    let info = error
        .get("data")
        .and_then(Value::as_array)?
        .iter()
        .find(|d| d.get("@type").and_then(Value::as_str) == Some(crate::ERROR_INFO_TYPE))?;
    let metadata: std::collections::BTreeMap<String, String> = info
        .get("metadata")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();
    Some(ErrorInfo {
        reason: info
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        domain: info
            .get("domain")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        metadata,
    })
}

/// The status an HTTP status means, as the gRPC specification's own HTTP-to-status table defines
/// it: what an answer that is not a JSON-RPC answer ends the call with.
#[must_use]
pub fn status_for_http(status: u32) -> CallStatus {
    let code = match status {
        400 => Code::Internal,
        401 => Code::Unauthenticated,
        403 => Code::PermissionDenied,
        404 => Code::Unimplemented,
        429 | 502 | 503 | 504 => Code::Unavailable,
        413 => Code::ResourceExhausted,
        _ => Code::Unknown,
    };
    CallStatus::new(code, format!("busbar answered HTTP {status}"))
}

/// THE MEMBERS OF BUSBAR'S OWN AGENT CARD THAT THE NORMATIVE `a2a.proto` DOES NOT MODEL, as
/// `(object path, member)` pairs: dropped on this line and only this one, because a protobuf
/// `AgentCard` has no field for them and the generated ProtoJSON type refuses an unknown member.
/// Listed, never guessed: each drop is a line somebody wrote down.
const UNMODELLED_CARD_MEMBERS: &[(&str, &str)] = &[("capabilities", "stateTransitionHistory")];

/// Busbar's card, narrowed to what a protobuf `AgentCard` can carry, and not reshaped.
fn narrowed_to_the_proto(mut card: Value) -> Value {
    let Some(root) = card.as_object_mut() else {
        return card;
    };
    for (parent, member) in UNMODELLED_CARD_MEMBERS {
        if let Some(obj) = root.get_mut(*parent).and_then(Value::as_object_mut) {
            obj.remove(*member);
        }
    }
    card
}

// ── THE OUTBOUND DIRECTION: busbar dialling an agent's gRPC binding ─────────────────────────────
//
// The same codec the other way round (the engine's `relay::GrpcFraming`, ported; spec line
// 2026-09-30: "transport de-frames, plane transcodes protobuf<->ProtoJSON"): the hop's JSON-RPC
// `params` ARE the rpc's request message in ProtoJSON, written as protobuf ([`request_message`]);
// each message the far end answers is the rpc's response message, read back as the ProtoJSON
// `result` it is ([`response_result`]). The grpc transport frames the request and hands the answer
// back length-prefixed, message by message ([`take_message`]), its trailers as a field block
// ([`ended`]).

/// The `content-type` a dialled call carries, and the `accept` it declares (the engine's).
pub const DIAL_CONTENT_TYPE: &str = "application/grpc+proto";

/// The media type the gRPC line's answers carry, as the previous release's gRPC line (tonic)
/// stated it on every answer's head: an answer's messages under it, and an answer that closes
/// before its first message (trailers-only) beside its status.
pub const REPLY_CONTENT_TYPE: &str = "application/grpc";

/// The length prefix every message on the wire carries: one compression flag byte and a four-byte
/// big-endian length.
pub const MESSAGE_PREFIX: usize = 5;

impl Rpc {
    /// The rpc a JSON-RPC `method` is, in either A2A dialect's spelling; `None` for a method the
    /// service does not have.
    #[must_use]
    pub fn of_method(method: &str) -> Option<Self> {
        Some(match method {
            "SendMessage" | "message/send" => Rpc::SendMessage,
            "SendStreamingMessage" | "message/stream" => Rpc::SendStreamingMessage,
            "GetTask" | "tasks/get" => Rpc::GetTask,
            "ListTasks" | "tasks/list" => Rpc::ListTasks,
            "CancelTask" | "tasks/cancel" => Rpc::CancelTask,
            "SubscribeToTask" | "tasks/resubscribe" => Rpc::SubscribeToTask,
            "CreateTaskPushNotificationConfig" | "tasks/pushNotificationConfig/set" => {
                Rpc::CreateTaskPushNotificationConfig
            }
            "GetTaskPushNotificationConfig" | "tasks/pushNotificationConfig/get" => {
                Rpc::GetTaskPushNotificationConfig
            }
            "ListTaskPushNotificationConfigs" | "tasks/pushNotificationConfig/list" => {
                Rpc::ListTaskPushNotificationConfigs
            }
            "DeleteTaskPushNotificationConfig" | "tasks/pushNotificationConfig/delete" => {
                Rpc::DeleteTaskPushNotificationConfig
            }
            "GetExtendedAgentCard" | "agent/getAuthenticatedExtendedCard" => {
                Rpc::GetExtendedAgentCard
            }
            _ => return None,
        })
    }

    /// The target a dialled call of this rpc is sent at: the service's own path, never joined onto
    /// the operator's (a gRPC server routes on the fully-qualified service and rpc exactly).
    #[must_use]
    pub fn target(self) -> String {
        format!("{SERVICE_PATH}/{}", self.name())
    }
}

/// CANONICAL JSON IN, THE RPC'S REQUEST MESSAGE OUT: the hop's `params` read as `rpc`'s request
/// message (its ProtoJSON), carried through the model's rules, written as protobuf (unframed: the
/// grpc transport frames it).
///
/// # Errors
///
/// The params are not the request message's ProtoJSON, or the model refuses it (never shown to the
/// caller).
pub fn request_message(rpc: Rpc, params: &Value) -> Result<Vec<u8>, String> {
    let params = params.clone();
    match rpc {
        Rpc::SendMessage | Rpc::SendStreamingMessage => encoded::<pb::SendMessageRequest>(params),
        Rpc::GetTask => encoded::<pb::GetTaskRequest>(params),
        Rpc::ListTasks => encoded::<pb::ListTasksRequest>(params),
        Rpc::CancelTask => encoded::<pb::CancelTaskRequest>(params),
        Rpc::SubscribeToTask => encoded::<pb::SubscribeToTaskRequest>(params),
        Rpc::CreateTaskPushNotificationConfig => encoded::<pb::TaskPushNotificationConfig>(params),
        Rpc::GetTaskPushNotificationConfig => {
            encoded::<pb::GetTaskPushNotificationConfigRequest>(params)
        }
        Rpc::ListTaskPushNotificationConfigs => {
            encoded::<pb::ListTaskPushNotificationConfigsRequest>(params)
        }
        Rpc::GetExtendedAgentCard => encoded::<pb::GetExtendedAgentCardRequest>(params),
        Rpc::DeleteTaskPushNotificationConfig => {
            encoded::<pb::DeleteTaskPushNotificationConfigRequest>(params)
        }
    }
}

/// THE RPC'S RESPONSE MESSAGE IN, CANONICAL JSON OUT: one message the far end answered `rpc` with,
/// decoded, carried through the model's rules, written as the ProtoJSON `result` it is.
/// `DeleteTaskPushNotificationConfig` answers `google.protobuf.Empty`: its result is `null`.
///
/// # Errors
///
/// The message does not decode as the rpc's response, or the model refuses it.
pub fn response_result(rpc: Rpc, message: &[u8]) -> Result<Value, String> {
    match rpc {
        Rpc::SendMessage => decoded::<pb::SendMessageResponse>(message),
        Rpc::SendStreamingMessage | Rpc::SubscribeToTask => decoded::<pb::StreamResponse>(message),
        Rpc::GetTask | Rpc::CancelTask => decoded::<pb::Task>(message),
        Rpc::ListTasks => decoded::<pb::ListTasksResponse>(message),
        Rpc::CreateTaskPushNotificationConfig | Rpc::GetTaskPushNotificationConfig => {
            decoded::<pb::TaskPushNotificationConfig>(message)
        }
        Rpc::ListTaskPushNotificationConfigs => {
            decoded::<pb::ListTaskPushNotificationConfigsResponse>(message)
        }
        Rpc::GetExtendedAgentCard => decoded::<pb::AgentCard>(message),
        Rpc::DeleteTaskPushNotificationConfig => Ok(Value::Null),
    }
}

fn encoded<M>(params: Value) -> Result<Vec<u8>, String>
where
    M: prost::Message + Normal + serde::de::DeserializeOwned,
{
    let mut m: M = serde_json::from_value(params)
        .map_err(|e| format!("the request could not be rendered as protobuf: {e}"))?;
    m.normal()
        .map_err(|e| format!("the request could not be rendered as protobuf: {e}"))?;
    Ok(m.encode_to_vec())
}

fn decoded<M>(message: &[u8]) -> Result<Value, String>
where
    M: prost::Message + Default + Normal + serde::Serialize,
{
    let mut m =
        M::decode(message).map_err(|e| format!("the answer is not a readable message: {e}"))?;
    m.normal()
        .map_err(|e| format!("the answer could not be read: {e}"))?;
    serde_json::to_value(&m).map_err(|e| format!("the answer could not be rendered: {e}"))
}

/// THE MESSAGE AT THE HEAD OF `buf`: its payload's length and how many bytes it takes with its
/// prefix; `Ok(None)` while it is still arriving (the engine's `grpc_split`).
///
/// # Errors
///
/// A compressed message: busbar offers no compression, so a far end that compressed answered in a
/// framing busbar cannot read.
pub fn take_message(buf: &[u8]) -> Result<Option<(usize, usize)>, String> {
    if buf.len() < MESSAGE_PREFIX {
        return Ok(None);
    }
    if buf[0] != 0 {
        return Err("the far end compressed a message busbar did not offer to decompress".into());
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if buf.len() < MESSAGE_PREFIX + len {
        return Ok(None);
    }
    Ok(Some((len, MESSAGE_PREFIX + len)))
}

/// JSON-RPC's own error codes, beside A2A's ([`crate::ERRORS`]): the codes section 5.4's table
/// binds a gRPC status to.
const JSON_RPC_CODES: [i64; 5] = [-32700, -32600, -32601, -32602, -32603];

/// HOW A DIALLED CALL ENDED, as its trailers say: the gRPC code, and the `google.rpc.ErrorInfo`
/// its status details carry (A2A section 10.6).
#[derive(Debug, Clone, PartialEq)]
pub struct Ended {
    /// The gRPC code (`0` = `OK`).
    pub code: u32,
    /// The error's reason, when the details carry one.
    pub info: Option<ErrorInfo>,
}

impl Ended {
    /// The call ended `OK`.
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.code == Code::Ok as u32
    }

    /// THE A2A ERROR CODE it ended with: its `ErrorInfo` reason's (the protocol's own vocabulary),
    /// else the one code section 5.4 binds to this status alone; `None` where neither says.
    #[must_use]
    pub fn a2a_code(&self) -> Option<i64> {
        if let Some(reason) = self.info.as_ref().map(|i| i.reason.as_str()) {
            if let Some((code, _)) = crate::ERRORS.iter().find(|(_, r)| *r == reason) {
                return Some(*code);
            }
        }
        let mut bound = crate::ERRORS
            .iter()
            .map(|(code, _)| *code)
            .chain(JSON_RPC_CODES)
            .filter(|c| grpc_code(*c).is_some_and(|g| g as u32 == self.code));
        match (bound.next(), bound.next()) {
            (Some(code), None) => Some(code),
            _ => None,
        }
    }
}

/// HOW A DIALLED CALL ENDED (`block`, the field block the grpc transport hands back after the
/// messages; `stated`, the `grpc-status` it read off them, which the kernel hands on beside the
/// block, `BUSBAR-1.6.0.md` l.394, l.747): that code, with the `ErrorInfo` of the
/// `google.rpc.Status` its [`DETAILS_FIELD`] carries, where it carries one. The details never
/// state the code: `None` when no status was handed on.
#[must_use]
pub fn ended(block: &[u8], stated: Option<u32>) -> Option<Ended> {
    use base64::Engine as _;
    let code = stated?;
    let details = busbar_contract::abi::transport::fields::lines(block)
        .find(|(name, _)| name.eq_ignore_ascii_case(DETAILS_FIELD.as_bytes()))
        .and_then(|(_, value)| {
            let text = std::str::from_utf8(value)
                .ok()?
                .trim()
                .trim_end_matches('=');
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(text)
                .ok()
        })
        .and_then(|bytes| rpc::Status::decode(bytes.as_slice()).ok());
    let info = details.and_then(|s| {
        s.details
            .iter()
            .find(|any| any.type_url == crate::ERROR_INFO_TYPE)
            .and_then(|any| ErrorInfo::decode(any.value.as_slice()).ok())
    });
    Some(Ended { code, info })
}

#[cfg(test)]
#[path = "tests/framed_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/framed_dial_tests.rs"]
mod dial_tests;
