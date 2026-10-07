// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINE CARRIER: one JSON-RPC message per line, each line its own request unit through the
//! door (ARCHITECT round 4 Q-L3B-STDIO-SHAPE (B), Q1a): the carrier is the host's (it holds the
//! process's own stdin/stdout open as one session and opens a unit per line); every meaning a line
//! has is here, on the plane side, and what the plane writes unsolicited it writes with the host's
//! `session.emit` on that session.
//!
//! - THE MIRRORED FIELDS a header block would carry are SYNTHESISED FROM THE BODY
//!   ([`crate::codec::mirrored`]): nothing the body does not state is stated, so a body defect stays a
//!   body defect.
//! - THE STDIO-ERA VERBS (`initialize`, `ping`) are answered here ([`era`]), and none reaches the
//!   dispatch, the catalogue or an upstream. `logging/setLevel`, `resources/subscribe` and
//!   `resources/unsubscribe` are REFUSED (`-32601`) and not advertised: this revision keeps no
//!   per-session floor or watch set, and nothing on the plane announces a resource's change to
//!   deliver (a watch is `subscriptions/listen`'s; the 1.6.0 design, mcp bullet, keeps `subscribe` for
//!   the old revisions, on their sessions).
//! - BUSBAR'S OWN ASKS are LIVE REQUESTS on the line ([`LiveAsk`]): an `input_required` answer is
//!   issued as one request per ask, in order, each spelled `busbar:<n>`; the caller's answers become
//!   `inputResponses`, and the RETRY is the unit of the caller's last answer, through the whole
//!   door (its own admission; the seal, the round charge and the epoch checks run as they do when
//!   an HTTP caller retries itself). An UPSTREAM's ask, relayed (Law 11), is livened the same way.
//!   A live ask unanswered for [`ASK_TIMEOUT_NS`] is dropped and the caller handed the result
//!   itself; a request is livened at most [`MAX_LIVE_ASK_ROUNDS`] times.
//! - A SUBSCRIPTION is answered with its acknowledgement and kept on the session: what changes, a
//!   keepalive and its end are emitted on the session, until the carrier ends.

use serde_json::{json, Map, Value};

use crate::codec::PROTOCOL_VERSION;

/// The prefix of the id busbar spells its own requests on the line in.
pub const ASK_ID_PREFIX: &str = "busbar:";

/// How long busbar waits for the caller to answer ONE live ask before handing it the
/// `input_required` result itself (the sealed `requestState` makes that a continuation).
pub const ASK_TIMEOUT_NS: u64 = 30 * 1_000_000_000;

/// The most live ask rounds busbar drives for one request: the carrier's own belt against a
/// composition that never converges (the per-capability `max_caller_ask_rounds` still applies).
pub const MAX_LIVE_ASK_ROUNDS: u32 = 8;

/// The JSON-RPC code for a method this carrier does not carry.
const METHOD_NOT_FOUND: i64 = -32601;

/// One success envelope.
#[must_use]
pub fn result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// One method-not-found envelope.
fn unsupported(id: &Value, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": METHOD_NOT_FOUND, "message": message },
    })
}

/// The `initialize` answer: the dual-era negotiation the revision scopes to stdio. busbar
/// implements ONE revision and says so; no session is created because the revision has none.
#[must_use]
pub fn initialize_result(id: &Value) -> Value {
    result(
        id,
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": true },
                "prompts": { "listChanged": true },
                "resources": { "listChanged": true },
                "completions": {},
            },
            "serverInfo": {
                "name": "busbar",
                "version": crate::tool_door::VERSION,
            },
            "instructions": format!(
                "This server speaks MCP revision {PROTOCOL_VERSION}: no handshake is required, \
                 and every request states its protocol version and client capabilities in \
                 `params._meta`."
            ),
        }),
    )
}

/// What a stdio-era verb came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Era {
    /// Answered here, whole.
    Answer(Value),
    /// Not a stdio-era verb: the one dispatch's.
    Dispatch,
}

/// THE STDIO-ERA VERBS, read off a request (`method`, `id`) before the `_meta` gate, because a
/// legacy-era client sends them without one: that is what the era negotiation is for.
#[must_use]
pub fn era(value: &Value) -> Era {
    let (Some(method), Some(id)) = (
        value.get("method").and_then(Value::as_str),
        value.get("id").filter(|i| i.is_string() || i.is_number()),
    ) else {
        return Era::Dispatch;
    };
    match method {
        crate::adapt::METHOD_INITIALIZE => Era::Answer(initialize_result(id)),
        crate::adapt::METHOD_PING => Era::Answer(result(id, json!({}))),
        "logging/setLevel" => Era::Answer(unsupported(
            id,
            "this revision has no `logging/setLevel`: there is no session to remember a floor in. A \
             request states its floor in `params._meta`.",
        )),
        "resources/subscribe" | "resources/unsubscribe" => Era::Answer(unsupported(
            id,
            "this revision has no `resources/subscribe`: open `subscriptions/listen` with \
             `notifications.resourceSubscriptions` instead.",
        )),
        _ => Era::Dispatch,
    }
}

/// What a line that is not a request is, when it answers one of busbar's own.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// The caller answered ask `n` with this result.
    Answered(u64, Value),
    /// The caller answered ask `n` with an error, or with no answer.
    Failed(u64),
}

/// The ask number busbar spelled into an id it minted.
fn ask_of(id: &Value) -> Option<u64> {
    id.as_str()?.strip_prefix(ASK_ID_PREFIX)?.parse().ok()
}

/// Whether a line answers one of busbar's own requests, and which: a JSON-RPC RESPONSE (no
/// `method`, a `result` or an `error`) whose id busbar minted, or SEP-1036's out-of-band
/// `notifications/elicitation/response`, whose `params.requestId` names the elicitation (admissible
/// only because this one authenticated single-caller channel is the binding HTTP lacks).
#[must_use]
pub fn reply(value: &Value) -> Option<Reply> {
    let obj = value.as_object()?;
    match obj.get("method").and_then(Value::as_str) {
        None => {
            let n = ask_of(obj.get("id")?)?;
            match (obj.get("result"), obj.get("error")) {
                (Some(result), None) => Some(Reply::Answered(n, result.clone())),
                (_, Some(_)) => Some(Reply::Failed(n)),
                (None, None) => None,
            }
        }
        Some("notifications/elicitation/response") => {
            let n = ask_of(value.pointer("/params/requestId")?)?;
            Some(Reply::Answered(
                n,
                value
                    .pointer("/params/response")
                    .cloned()
                    .unwrap_or(Value::Null),
            ))
        }
        Some(_) => None,
    }
}

/// The request id a `notifications/cancelled` names.
#[must_use]
pub fn cancelled(value: &Value) -> Option<Value> {
    (value.get("method").and_then(Value::as_str) == Some("notifications/cancelled"))
        .then(|| value.pointer("/params/requestId").cloned())
        .flatten()
        .filter(|i| i.is_string() || i.is_number())
}

/// A stable key for a JSON-RPC id: type-tagged, so the string `"1"` and the number `1` (which never
/// correlate on the wire) never collide.
#[must_use]
pub fn id_key(id: &Value) -> String {
    match id {
        Value::String(s) => format!("s:{s}"),
        other => format!("n:{other}"),
    }
}

/// Whether a request already livened `round` times may be livened again.
#[must_use]
pub fn may_liven(round: u32) -> bool {
    round < MAX_LIVE_ASK_ROUNDS
}

/// Where a live ask stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskStand {
    /// Waiting on the caller's answer to the ask in flight.
    Waiting,
    /// Every ask of the round was answered: the retry went on as its own unit.
    Answered,
    /// The caller cancelled the request.
    Cancelled,
    /// The caller answered an ask with an error (or not at all): it is handed the result itself.
    Unanswered,
}

/// ONE LIVE ASK ROUND for one request: the request it continues, the round's asks in order, the
/// answers so far, the sealed state the retry echoes, and the unit holding the caller's answer.
#[derive(Debug, Clone)]
pub struct LiveAsk {
    /// The principal it was asked under.
    pub principal: String,
    /// The request as the caller sent it (its id is the caller's).
    pub original: Value,
    /// The `input_required` result itself: what the caller is handed when it does not answer.
    pub fallback: Vec<u8>,
    /// The asks not yet issued, in order: `(key, method, params)`.
    pub queued: Vec<(String, String, Value)>,
    /// The key of the ask in flight.
    pub current: String,
    /// The number the ask in flight was issued under (its request id is `busbar:<n>`).
    pub current_n: u64,
    /// The answers so far, by key.
    pub responses: Map<String, Value>,
    /// The sealed state the retry echoes.
    pub state: String,
    /// The live round this is (`0` = the request's first).
    pub round: u32,
    /// The carrier session it was asked on.
    pub session: u64,
    /// When the ask in flight lapses, on the host's monotonic clock.
    pub deadline_ns: u64,
    /// Where it stands.
    pub stand: AskStand,
}

impl LiveAsk {
    /// The round an `input_required` `result` asks of `original`; `None` when the result names no
    /// asks or no state (it is then handed to the caller as it is).
    #[must_use]
    pub fn of(
        principal: &str,
        original: Value,
        fallback: Vec<u8>,
        result: &Value,
        round: u32,
    ) -> Option<Self> {
        let requests = result.get("inputRequests")?.as_object()?;
        let state = result.get("requestState")?.as_str()?.to_string();
        let mut queued: Vec<(String, String, Value)> = requests
            .iter()
            .filter_map(|(key, ask)| {
                Some((
                    key.clone(),
                    ask.get("method")?.as_str()?.to_string(),
                    ask.get("params").cloned().unwrap_or(Value::Null),
                ))
            })
            .collect();
        if queued.is_empty() || queued.len() != requests.len() {
            return None;
        }
        queued.reverse();
        Some(LiveAsk {
            principal: principal.to_string(),
            original,
            fallback,
            queued,
            current: String::new(),
            current_n: 0,
            responses: Map::new(),
            state,
            round,
            session: 0,
            deadline_ns: 0,
            stand: AskStand::Waiting,
        })
    }

    /// Starts the clock on the ask in flight: it lapses [`ASK_TIMEOUT_NS`] after `now_ns`.
    pub fn arm(&mut self, now_ns: u64) {
        self.deadline_ns = now_ns.saturating_add(ASK_TIMEOUT_NS);
    }

    /// Whether the ask in flight went unanswered past its deadline at `now_ns`.
    #[must_use]
    pub fn lapsed(&self, now_ns: u64) -> bool {
        self.deadline_ns != 0 && now_ns >= self.deadline_ns
    }

    /// The next ask as the request line busbar writes, under ask number `n`; `None` once every ask
    /// was issued.
    pub fn issue(&mut self, n: u64) -> Option<Vec<u8>> {
        let (key, method, params) = self.queued.pop()?;
        self.current = key;
        self.current_n = n;
        let mut line = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": format!("{ASK_ID_PREFIX}{n}"),
            "method": method,
            "params": params,
        }))
        .unwrap_or_default();
        line.push(b'\n');
        Some(line)
    }

    /// The caller's answer to the ask in flight.
    pub fn answered(&mut self, response: Value) {
        self.responses
            .insert(std::mem::take(&mut self.current), response);
    }

    /// THE RETRY: the request as the caller sent it, carrying the round's answers and the sealed
    /// state. Its id stays the caller's, so its answer is the caller's answer.
    #[must_use]
    pub fn retry(&self) -> Option<Value> {
        let mut retry = self.original.clone();
        let params = retry.get_mut("params")?.as_object_mut()?;
        params.insert(
            "inputResponses".to_string(),
            Value::Object(self.responses.clone()),
        );
        params.insert("requestState".to_string(), Value::from(self.state.clone()));
        Some(retry)
    }
}

#[cfg(test)]
#[path = "tests/line_tests.rs"]
mod tests;
