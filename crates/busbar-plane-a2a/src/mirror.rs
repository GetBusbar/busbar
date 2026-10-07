// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR'S OWN CALLBACK, MIRRORED ONTO THE AGENT (the engine's `originate::mirror_push_config`;
//! ARCHITECT ruling Q3, 2026-10-04: sent over the agent's need from the local verb's `on_piece`).
//!
//! Whatever the caller did to the push config busbar holds for it, busbar does to the config BUSBAR
//! holds at the agent: a create arms the agent with busbar's own callback (`<public_url>/a2a/push`)
//! and a capability for that one task ([`crate::push::Tokens`]), a delete disarms it, and a read
//! reconciles: a read that does not find busbar's registration (or is not answered) re-arms it. The
//! caller's URL and credential never leave busbar.
//!
//! As the engine did, the mirror runs after the caller's answer is decided and before it is sent,
//! and only on a successful local answer about a task busbar holds as live, whose agent has named
//! it; it is best effort, its outcome never changes the caller's answer, and it bills nothing.

use serde_json::{json, Value};

use crate::binding::Binding;
use crate::local::LocalVerb;

/// The v1.0 method names the mirrored verbs are issued under, whatever the caller spelled.
pub mod method {
    /// Create (or replace) a task's push config.
    pub const CREATE_PUSH_CONFIG: &str = "CreateTaskPushNotificationConfig";
    /// Read one.
    pub const GET_PUSH_CONFIG: &str = "GetTaskPushNotificationConfig";
    /// List a task's.
    pub const LIST_PUSH_CONFIGS: &str = "ListTaskPushNotificationConfigs";
    /// Delete one.
    pub const DELETE_PUSH_CONFIG: &str = "DeleteTaskPushNotificationConfig";
}

/// The id every busbar-originated request carries: busbar originated the hop, so there is no
/// caller id to echo.
pub const ORIGINATED_RPC_ID: &str = "busbar-originated";

/// The verb busbar issues when a caller uses `verb`; `None` for a local verb that mirrors onto
/// nothing (`ListTasks` and `SubscribeToTask` name no registration busbar holds at an agent).
#[must_use]
pub fn mirrored_verb(verb: LocalVerb) -> Option<&'static str> {
    Some(match verb {
        LocalVerb::CreatePushConfig(_) => method::CREATE_PUSH_CONFIG,
        LocalVerb::GetPushConfig(_) => method::GET_PUSH_CONFIG,
        LocalVerb::ListPushConfigs(_) => method::LIST_PUSH_CONFIGS,
        LocalVerb::DeletePushConfig(_) => method::DELETE_PUSH_CONFIG,
        LocalVerb::ListTasks | LocalVerb::Subscribe => return None,
    })
}

/// Busbar's own callback address for `public_url`, or `None` where busbar offers none: no
/// `public_url`, or one that is not `https` (a task token in cleartext is refused, with no knob).
#[must_use]
pub fn callback_url(public_url: &str) -> Option<String> {
    let url = url::Url::parse(public_url).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    Some(format!(
        "{}{}{}",
        public_url.trim_end_matches('/'),
        crate::MOUNT_PATH,
        crate::PUSH_PATH_SUFFIX
    ))
}

/// The id of the one config busbar registers for the agent's task `backend_task`.
#[must_use]
pub fn config_id(backend_task: &str) -> String {
    format!("busbar-{backend_task}")
}

/// A create naming busbar's own callback.
#[must_use]
pub fn create_params(backend_task: &str, url: &str, token: &str) -> Value {
    json!({
        "taskId": backend_task,
        "id": config_id(backend_task),
        "url": url,
        "authentication": { "scheme": crate::push::TOKEN_SCHEME, "credentials": token },
    })
}

/// The params `method` is issued with: a list names the task, a get or delete busbar's config.
#[must_use]
pub fn params_for(method: &str, backend_task: &str, create: &Value) -> Value {
    match method {
        method::CREATE_PUSH_CONFIG => create.clone(),
        method::LIST_PUSH_CONFIGS => json!({ "taskId": backend_task }),
        _ => json!({ "taskId": backend_task, "id": config_id(backend_task) }),
    }
}

/// One originated request, framed for the agent's binding as a relayed one is: its verb, target,
/// head fields and body. `None` for a request the binding cannot frame.
#[must_use]
pub fn request(
    binding: Binding,
    url: &str,
    version: &'static str,
    method: &str,
    params: &Value,
) -> Option<busbar_contract::abi::sdk::exchange::Request> {
    use crate::relay::{Answer, From, Piece, Relay};
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": ORIGINATED_RPC_ID,
        "method": method,
        "params": params,
    });
    let body = serde_json::to_vec(&envelope).ok()?;
    let mut relay = Relay::new(Value::String(ORIGINATED_RPC_ID.into()), version);
    relay.bind(binding, &envelope);
    let piece = |from| Piece {
        from,
        bytes: &body,
        status: None,
        last: false,
    };
    let Answer::Attempt(attempt) = relay.on_piece(piece(From::Kernel(Some(url)))) else {
        return None;
    };
    let body = match relay.on_piece(piece(From::Caller)) {
        Answer::ToFarEnd(bytes) => bytes,
        _ => Vec::new(),
    };
    Some(busbar_contract::abi::sdk::exchange::Request {
        method: attempt.verb.as_bytes().to_vec(),
        target: attempt.target.into_bytes(),
        fields: attempt
            .fields
            .into_iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.into_bytes()))
            .collect(),
        body,
        timeout_ms: 0,
    })
}

/// THE ANSWER TO ONE ORIGINATED REQUEST, as the readers below read it: its status and body as the
/// far end answered them, except on the gRPC binding, where a call that ended `OK` (the exchange
/// completed) carries the rpc's response message, transcoded to the JSON-RPC envelope it is
/// (`200`, under [`ORIGINATED_RPC_ID`]); `None` for a gRPC answer that carries no message to read.
#[must_use]
pub fn answered(
    binding: Binding,
    method: &str,
    status: u16,
    body: Vec<u8>,
) -> Option<(u16, Vec<u8>)> {
    if binding != Binding::Grpc {
        return Some((status, body));
    }
    let rpc = crate::framed::Rpc::of_method(method)?;
    let (len, _) = crate::framed::take_message(&body).ok()??;
    let message = &body[crate::framed::MESSAGE_PREFIX..crate::framed::MESSAGE_PREFIX + len];
    let result = crate::framed::response_result(rpc, message).ok()?;
    let envelope = json!({ "jsonrpc": "2.0", "id": ORIGINATED_RPC_ID, "result": result });
    Some((200, serde_json::to_vec(&envelope).ok()?))
}

/// A REQUEST BUSBAR ORIGINATES THAT MADE NO HOP: the agent's `upstream_credential`, re-resolved for
/// it, is unavailable, so the host sent nothing (the engine's `originate` returning `None` once it
/// had logged `A2A_OUTBOUND_CRED_UNLEASED`, before any of its requests). Nothing follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unleased;

/// WHAT ONE ORIGINATED REQUEST CAME TO, out of its exchange's `answer`: the status and body
/// [`answered`] reads (`None` for a request that was not answered), or [`Unleased`] for one the host
/// refused for an unavailable credential, logged as the engine logged a lease it could not mint
/// (`A2A_OUTBOUND_CRED_UNLEASED`, naming `agent`).
///
/// # Errors
/// [`Unleased`].
pub fn landed(
    binding: Binding,
    agent: &str,
    method: &str,
    answer: Result<
        busbar_contract::abi::sdk::exchange::ExchangeResponse,
        busbar_contract::abi::sdk::conn::ConnFailure,
    >,
) -> Result<Option<(u16, Vec<u8>)>, Unleased> {
    use busbar_contract::abi::sdk::conn::ConnFailure;
    match answer {
        Err(ConnFailure::CredentialUnavailable) => {
            busbar_contract::diag_warn!(
                crate::diagnostics::A2A_OUTBOUND_CRED_UNLEASED,
                agent = %agent,
                "a2a: the outbound credential could not be leased"
            );
            Err(Unleased)
        }
        Err(_) => Ok(None),
        Ok(reply) => Ok(answered(binding, method, reply.status, reply.body)),
    }
}

/// Whether a read's answer leaves busbar's registration drifted (gone at the agent): an answer that
/// is not a JSON-RPC `result` naming [`config_id`] (a refusal, an error, nothing) has drifted.
#[must_use]
pub fn drifted(binding: Binding, answered: Option<(u16, &[u8])>, config_id: &str) -> bool {
    let Some((status, body)) = answered else {
        return true;
    };
    if !(200..300).contains(&status) {
        return true;
    }
    let id = Value::String(ORIGINATED_RPC_ID.into());
    let envelope = match binding {
        Binding::HttpJson => crate::binding::rewrap(body, &id).ok(),
        // A gRPC answer was transcoded to its JSON-RPC envelope as it arrived ([`answered`]).
        Binding::JsonRpc | Binding::Grpc => Some(body.to_vec()),
    };
    let result = envelope
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("result").cloned());
    !result.is_some_and(|r| r.to_string().contains(config_id))
}

/// Where a mirror stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The mirrored verb is to be (or is being) issued.
    Mirror,
    /// A read found busbar's registration gone: the create is to be (or is being) issued.
    Rearm,
    /// Nothing more to issue.
    Done,
}

/// ONE REQUEST BUSBAR ORIGINATES to an agent, across its piece's PENDING entries: the agent (its
/// registration name, url, private reach, binding and the version the request declares), the
/// handle the next host call takes, and the request in flight.
pub struct Originated {
    /// The agent's registration name: the dial names it ([`Exchange::as_member`]).
    ///
    /// [`Exchange::as_member`]: busbar_contract::abi::sdk::exchange::Exchange::as_member
    pub agent: String,
    /// The agent's url.
    pub url: String,
    /// Its registration's `allow_private`.
    pub allow_private: bool,
    /// The binding its held card speaks.
    pub binding: Binding,
    /// The version the request declares.
    pub version: &'static str,
    /// The handle the next host call takes.
    pub seq: u32,
    /// The request in flight: the handle it counts on from, and its exchange.
    pub exchange: Option<(u32, Box<busbar_contract::abi::sdk::exchange::Exchange>)>,
}

impl std::fmt::Debug for Originated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Originated")
            .field("agent", &self.agent)
            .field("seq", &self.seq)
            .field("in_flight", &self.exchange.is_some())
            .finish_non_exhaustive()
    }
}

/// ONE MIRROR: where it stands, the verb it mirrors, the agent's own id for the task, the create a
/// re-arm issues, and the requests it originates.
#[derive(Debug)]
pub struct Flight {
    /// Where it stands.
    pub stage: Stage,
    /// The mirrored verb.
    pub method: &'static str,
    /// The agent's own id for the task.
    pub backend_task: String,
    /// The create, for a re-arm.
    pub create: Value,
    /// The requests.
    pub hop: Originated,
}

impl Flight {
    /// The verb this stage issues.
    #[must_use]
    pub fn issuing(&self) -> &'static str {
        match self.stage {
            Stage::Rearm => method::CREATE_PUSH_CONFIG,
            _ => self.method,
        }
    }

    /// The params this stage issues.
    #[must_use]
    pub fn params(&self) -> Value {
        params_for(self.issuing(), &self.backend_task, &self.create)
    }

    /// The stage after this one's request came to `landed`: an [`Unleased`] request ends the mirror
    /// (the engine originated none of it, re-arm included); else [`Flight::advance`].
    pub fn land(&mut self, landed: Result<Option<(u16, &[u8])>, Unleased>) {
        match landed {
            Err(Unleased) => self.stage = Stage::Done,
            Ok(answered) => self.advance(answered),
        }
    }

    /// The stage after this one's request was answered (`answered` = its status and body, `None`
    /// when it was not answered or could not be framed).
    pub fn advance(&mut self, answered: Option<(u16, &[u8])>) {
        self.stage = match self.stage {
            Stage::Mirror => {
                let read = matches!(
                    self.method,
                    method::GET_PUSH_CONFIG | method::LIST_PUSH_CONFIGS
                );
                if read && drifted(self.hop.binding, answered, &config_id(&self.backend_task)) {
                    Stage::Rearm
                } else {
                    Stage::Done
                }
            }
            Stage::Rearm | Stage::Done => Stage::Done,
        };
    }
}

/// `ListTasks`, as busbar issues it to refresh its own rows from the agent (the engine's
/// `originate::refresh_listed_tasks`): no paging members, the agent's default page.
pub const LIST_TASKS: &str = "ListTasks";

/// WHAT A LISTING TAUGHT BUSBAR: for each entry of the agent's answer whose id is the agent's own
/// id for a task in `ours` (agent id to busbar id), the state it reports, read STRICTLY (an entry
/// whose state cannot be read taught nothing). An entry busbar cannot match is ignored in silence:
/// that is what stops one tenant's list from moving another's row.
#[must_use]
pub fn listed_states(
    binding: Binding,
    answered: Option<(u16, &[u8])>,
    ours: &std::collections::BTreeMap<String, String>,
) -> Vec<(String, crate::a2a::task::TaskState)> {
    let Some((status, body)) = answered else {
        return Vec::new();
    };
    if !(200..300).contains(&status) {
        return Vec::new();
    }
    let id = Value::String(ORIGINATED_RPC_ID.into());
    let envelope = match binding {
        Binding::HttpJson => crate::binding::rewrap(body, &id).ok(),
        // A gRPC answer was transcoded to its JSON-RPC envelope as it arrived ([`answered`]).
        Binding::JsonRpc | Binding::Grpc => Some(body.to_vec()),
    };
    let Some(result) = envelope
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("result").cloned())
    else {
        return Vec::new();
    };
    let listed = result
        .get("tasks")
        .and_then(Value::as_array)
        .or_else(|| result.as_array())
        .cloned()
        .unwrap_or_default();
    listed
        .iter()
        .filter_map(|entry| {
            let busbar = ours.get(entry.get("id")?.as_str()?)?;
            let state = entry
                .pointer("/status/state")
                .and_then(Value::as_str)
                .and_then(crate::identity::wire_state)?;
            Some((busbar.clone(), state))
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/mirror_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/mirror_legs_tests.rs"]
mod legs_tests;

#[cfg(test)]
#[path = "tests/mirror_unleased_tests.rs"]
mod unleased_tests;
