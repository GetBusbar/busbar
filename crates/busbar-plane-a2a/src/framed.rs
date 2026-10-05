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
//! 2. [`answer`]: the JSON-RPC answer the unit wrote, transcoded back to the rpc's response
//!    message, or its `error` member turned into the status A2A section 5.4 binds it to, with the
//!    `google.rpc.ErrorInfo` the error carries as the status details (section 10.6).
//! 3. [`event`]: one event of an answer in events, as the `StreamResponse` message a
//!    server-streaming rpc answers with.
//!
//! No A2A wire fact is hand-written here: the messages, the method names and the ProtoJSON mapping
//! are generated from the a2aproject's own `a2a.proto` ([`crate::proto::pb`]). The status a call ends with is the gRPC numbering ([`Code`]) and its details the
//! `google.rpc.Status` message carrying the error's `google.rpc.ErrorInfo` ([`Status::details`]),
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
pub struct Status {
    code: Code,
    message: String,
    details: Vec<u8>,
}

impl Status {
    /// A status with no details.
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Status {
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
        Status {
            code,
            message,
            details,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Status::new(Code::Internal, message)
    }

    fn invalid_argument(message: impl Into<String>) -> Self {
        Status::new(Code::InvalidArgument, message)
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
pub fn unimplemented() -> Status {
    Status::new(Code::Unimplemented, "")
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
pub fn compose(rpc: Rpc, message: &[u8]) -> Result<Vec<u8>, Status> {
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

/// PROTOBUF IN, CANONICAL JSON OUT: `message` decoded as `M` (a parse error is `INTERNAL` with the
/// decoder's words), carried through the model's rules, written as its ProtoJSON.
fn to_params<M>(message: &[u8]) -> Result<Value, Status>
where
    M: prost::Message + Default + Normal + serde::Serialize,
{
    let mut m = M::decode(message).map_err(|e| Status::internal(e.to_string()))?;
    m.normal()
        .map_err(|e| Status::invalid_argument(format!("the request could not be read: {e}")))?;
    serde_json::to_value(&m).map_err(|e| {
        Status::invalid_argument(format!(
            "the request could not be read: ProtoJSON error: {e}"
        ))
    })
}

/// CANONICAL JSON IN, PROTOBUF OUT: the same mapping in the other direction.
fn from_result<M>(result: Value) -> Result<Vec<u8>, Status>
where
    M: prost::Message + Normal + serde::de::DeserializeOwned,
{
    let mut m: M = serde_json::from_value(result).map_err(|e| {
        Status::internal(format!(
            "the answer could not be rendered: ProtoJSON error: {e}"
        ))
    })?;
    m.normal()
        .map_err(|e| Status::internal(format!("the answer could not be rendered: {e}")))?;
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
pub fn answer(rpc: Rpc, status: u32, body: &[u8]) -> Result<Vec<u8>, Status> {
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
pub fn event(frame: &str) -> Option<Result<Vec<u8>, Status>> {
    let data = crate::sse::sse_data(frame)?;
    let envelope: Value = serde_json::from_str(&data).ok()?;
    if let Some(error) = envelope.get("error") {
        return Some(Err(status_for_error(error, STATUS_INTERNAL)));
    }
    let result = envelope.get("result")?.clone();
    Some(from_result::<pb::StreamResponse>(result))
}

/// The neutral status an event's error is read under (the engine read a stream's error at `500`).
const STATUS_INTERNAL: u32 = 500;

/// THE STATUS FOR A JSON-RPC ERROR OBJECT, read off the code rather than the message: the code
/// maps through the section 5.4 table ([`grpc_code`]); a code that table does not define (a
/// backend's own extension, relayed) falls back to `http`'s mapping. The `google.rpc.ErrorInfo`
/// the error carries rides as the status details (section 10.6; TCK `GRPC-ERR-001`).
#[must_use]
pub fn status_for_error(error: &Value, http: u32) -> Status {
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
        Some(info) => Status::with_error_info(code, message, info),
        None => Status::new(code, message),
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
pub fn status_for_http(status: u32) -> Status {
    let code = match status {
        400 => Code::Internal,
        401 => Code::Unauthenticated,
        403 => Code::PermissionDenied,
        404 => Code::Unimplemented,
        429 | 502 | 503 | 504 => Code::Unavailable,
        413 => Code::ResourceExhausted,
        _ => Code::Unknown,
    };
    Status::new(code, format!("busbar answered HTTP {status}"))
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

#[cfg(test)]
#[path = "tests/framed_tests.rs"]
mod tests;
