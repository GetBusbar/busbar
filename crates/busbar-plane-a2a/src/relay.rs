// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNARY RELAY, AS THE KERNEL'S ROUTE PUMP DRIVES IT (`BUSBAR-1.6.0.md` Part 3, section 12):
//! one JSON-RPC hop to the agent the kernel's walk picked, in the order the pump pushes its pieces,
//! and what the plane answers each with. Ported from the served engine's hop
//! (`busbar-a2a` `relay::relay_once`, `relay::read_reply`, `relay::build_request`,
//! `receive::refuse_hop_early`, `refusal_client`); the kernel now owns what the engine did around
//! it (the guard and pin, the live trust gate, the breaker, the lease's auth fields, the walk).
//!
//! | piece | answer |
//! |---|---|
//! | ATTEMPT (the agent the walk picked) | `POST` at the agent's own path, `content-type`, `accept`, `a2a-version` |
//! | the caller's body | relayed to the far end VERBATIM: busbar is content-blind on this plane |
//! | the far end's answer | gathered; on its last piece, the caller's answer |
//!
//! The caller's answer is the backend's `result` in busbar's own envelope (`200`), or a refusal
//! in the engine's fixed words (`502`, `-32006`): a status outside 2xx, a reply over the ceiling, a
//! reply that is not JSON, one that answers a different request, or the backend's own JSON-RPC
//! `error`. No refusal echoes a byte the backend or its address chose.
//!
//! Every answer is plain data; writing it into the host's buffers is the door's job. A new ATTEMPT
//! forgets what the previous attempt's far end said.

use busbar_contract::jsonrpc::{read_response, NotAnAnswerKind, Reply as RpcReply};
use serde_json::{json, Value};

use crate::arrival::{Refusal, JSON_MEDIA_TYPE};

/// The verb every JSON-RPC hop is sent with.
pub const VERB: &str = "POST";

/// The `accept` a unary hop declares: the one document it reads.
pub const ACCEPT_UNARY: &str = JSON_MEDIA_TYPE;

/// The head field naming a body's media type.
pub const H_CONTENT_TYPE: &str = "content-type";
/// The head field naming the media types the hop reads.
pub const H_ACCEPT: &str = "accept";

/// The most reply bytes a hop reads (the engine's `FetchPolicy::max_body_bytes`): an unbounded read
/// is an allocation the backend chooses the size of.
pub const MAX_REPLY_BYTES: usize = 512 * 1024;

/// The status every refused hop answers with.
pub const STATUS_BAD_GATEWAY: u32 = 502;

/// The status a relayed answer is given.
pub const STATUS_OK: u32 = 200;

/// `InvalidAgentResponse`, the code every refused hop carries.
pub const CODE_INVALID_AGENT_RESPONSE: i64 = -32006;

/// Who pushed a piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum From<'a> {
    /// The caller: the request body.
    Caller,
    /// The far end: its answer.
    FarEnd,
    /// The kernel: an ATTEMPT, with the URL the operator wrote for the agent it picked (`None`
    /// when the plane's section names no such agent).
    Kernel(Option<&'a str>),
}

/// One piece, as the door read it off the crossing.
#[derive(Debug, Clone, Copy)]
pub struct Piece<'a> {
    /// Who pushed it.
    pub from: From<'a>,
    /// Its bytes.
    pub bytes: &'a [u8],
    /// On the far end's first piece: the status it answered.
    pub status: Option<u32>,
    /// No piece of this `from` follows.
    pub last: bool,
}

/// The request one attempt sends the far end: the verb, the target under the agent's origin, and
/// the head fields in the order the engine wrote them. The kernel leads them with the member's auth
/// fields and sends the body that follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The verb.
    pub verb: &'static str,
    /// The target: the agent URL's path and query.
    pub target: String,
    /// The head fields, in order.
    pub fields: Vec<(&'static str, String)>,
}

/// What the caller is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The status.
    pub status: u32,
    /// The body's media type.
    pub content_type: &'static str,
    /// The body.
    pub body: Vec<u8>,
}

/// The plane's answer to one piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Nothing to emit yet.
    Nothing,
    /// The request this attempt sends the far end; its body follows as [`Answer::ToFarEnd`].
    Attempt(Attempt),
    /// The request's body, bound for the far end.
    ToFarEnd(Vec<u8>),
    /// The caller's whole answer: the unit is done.
    ToCaller(Reply),
    /// The piece is one this relay never takes.
    Refused,
}

/// WHY A HOP HAS NO ANSWER TO RELAY, in the arms the plane can see (the engine's `RelayRefusal`;
/// the guard, the trust gate, the lease and the breaker are the kernel's now).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopRefusal {
    /// The backend answered outside 2xx.
    Status,
    /// The reply was over [`MAX_REPLY_BYTES`].
    BodyTooLarge,
    /// The reply is not a JSON-RPC answer.
    NotJson,
    /// The backend answered with a JSON-RPC `error`.
    BackendError,
    /// The reply names a different request.
    Uncorrelated,
}

impl HopRefusal {
    /// The stable token a caller may quote (the engine's `RelayRefusal::client_code`).
    #[must_use]
    pub const fn client_code(self) -> &'static str {
        match self {
            HopRefusal::Status => "a2a.hop.backend_status",
            HopRefusal::BodyTooLarge => "a2a.hop.reply_too_large",
            HopRefusal::NotJson => "a2a.hop.reply_not_json",
            HopRefusal::BackendError => "a2a.hop.backend_refused",
            HopRefusal::Uncorrelated => "a2a.hop.reply_uncorrelated",
        }
    }

    /// The caller's sentence: fixed per arm, interpolating nothing a backend, its address or its
    /// bytes could choose (the engine's `RelayRefusal::client_text`).
    #[must_use]
    pub fn client_text(self) -> String {
        let sentence = match self {
            HopRefusal::Status => "this agent's backend refused busbar's request",
            HopRefusal::BodyTooLarge => {
                "this agent's backend replied with more than the configured ceiling"
            }
            HopRefusal::NotJson => {
                "this agent's backend replied with something that is not a JSON-RPC answer"
            }
            HopRefusal::BackendError => "this agent's backend refused the request",
            HopRefusal::Uncorrelated => {
                "this agent's backend answered something busbar cannot correlate to the request it \
                 sent, so it is refused rather than relayed"
            }
        };
        format!("{}: {sentence}", self.client_code())
    }

    /// The caller's answer: the one error envelope, `-32006` with its `ErrorInfo`, at `502` (the
    /// engine's `receive::refuse_hop_early`).
    #[must_use]
    pub fn reply(self, id: &Value) -> Reply {
        let refusal = Refusal {
            status: STATUS_BAD_GATEWAY,
            id: Some(id.clone()),
            code: CODE_INVALID_AGENT_RESPONSE,
            message: self.client_text(),
        };
        Reply {
            status: STATUS_BAD_GATEWAY,
            content_type: JSON_MEDIA_TYPE,
            body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
        }
    }
}

/// The far end's whole answer, read AS THE ANSWER TO `id`: its `result`, or why it is refused (the
/// engine's `relay_once` checks after the send, then `read_reply`).
///
/// # Errors
///
/// The [`HopRefusal`] the answer earns.
pub fn read_answer(status: u32, body: &[u8], id: &Value) -> Result<Value, HopRefusal> {
    if !(200..300).contains(&status) {
        return Err(HopRefusal::Status);
    }
    if body.len() > MAX_REPLY_BYTES {
        return Err(HopRefusal::BodyTooLarge);
    }
    let envelope: Value = serde_json::from_slice(body).map_err(|_| HopRefusal::NotJson)?;
    match read_response(&envelope, id) {
        Ok(RpcReply::Result(result)) => Ok(result),
        Ok(RpcReply::Error { .. }) => Err(HopRefusal::BackendError),
        Err(e) => Err(match e.kind {
            NotAnAnswerKind::Uncorrelated => HopRefusal::Uncorrelated,
            NotAnAnswerKind::NotAResponse => HopRefusal::NotJson,
        }),
    }
}

/// The caller's answer to a relayed `result`, VERBATIM, under the caller's own `id`.
#[must_use]
pub fn relayed(id: &Value, result: Value) -> Reply {
    Reply {
        status: STATUS_OK,
        content_type: JSON_MEDIA_TYPE,
        body: serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            .unwrap_or_default(),
    }
}

/// The target an attempt is sent at: the agent URL's path and query. The kernel joins it onto the
/// agent's origin, so the far end is posted to at exactly the URL the operator wrote (the JSON-RPC
/// binding appends nothing). `None` for a URL that does not parse.
#[must_use]
pub fn target_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let mut target = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }
    Some(target)
}

/// ONE UNARY HOP: the caller's request id and negotiated version, and what the current attempt's
/// far end has said so far.
#[derive(Debug, Clone)]
pub struct Relay {
    id: Value,
    version: &'static str,
    sent: u64,
    status: Option<u32>,
    far: Vec<u8>,
    received: u64,
    answered: bool,
}

impl Relay {
    /// A hop answering the request `id`, declaring the `version` busbar's edge negotiated.
    #[must_use]
    pub fn new(id: Value, version: &'static str) -> Self {
        Relay {
            id,
            version,
            sent: 0,
            status: None,
            far: Vec::new(),
            received: 0,
            answered: false,
        }
    }

    /// `true` once the caller's answer has been given.
    #[must_use]
    pub const fn answered(&self) -> bool {
        self.answered
    }

    /// The payload bytes the hop has moved both ways, the request's and the reply's, once the far
    /// end has answered (an exchange that never happened moved nothing busbar can measure).
    #[must_use]
    pub fn moved(&self) -> u64 {
        if self.status.is_some() {
            self.sent.saturating_add(self.received)
        } else {
            0
        }
    }

    /// The plane's answer to `piece`.
    pub fn on_piece(&mut self, piece: Piece<'_>) -> Answer {
        if self.answered {
            return Answer::Nothing;
        }
        match piece.from {
            From::Kernel(url) => {
                self.sent = 0;
                self.status = None;
                self.far.clear();
                self.received = 0;
                match url.and_then(target_of) {
                    Some(target) => Answer::Attempt(Attempt {
                        verb: VERB,
                        target,
                        fields: vec![
                            (H_CONTENT_TYPE, JSON_MEDIA_TYPE.to_string()),
                            (H_ACCEPT, ACCEPT_UNARY.to_string()),
                            (crate::arrival::H_VERSION, self.version.to_string()),
                        ],
                    }),
                    None => Answer::Refused,
                }
            }
            From::Caller => {
                self.sent = self.sent.saturating_add(piece.bytes.len() as u64);
                if piece.bytes.is_empty() {
                    Answer::Nothing
                } else {
                    Answer::ToFarEnd(piece.bytes.to_vec())
                }
            }
            From::FarEnd => self.far_end_piece(piece),
        }
    }

    fn far_end_piece(&mut self, piece: Piece<'_>) -> Answer {
        if let Some(status) = piece.status {
            self.status = Some(status);
        }
        self.received = self.received.saturating_add(piece.bytes.len() as u64);
        // Kept only up to one byte past the ceiling: past it the reply is refused whole.
        let room = (MAX_REPLY_BYTES + 1).saturating_sub(self.far.len());
        self.far
            .extend_from_slice(&piece.bytes[..piece.bytes.len().min(room)]);
        if !piece.last {
            return Answer::Nothing;
        }
        let Some(status) = self.status else {
            return Answer::Refused;
        };
        self.answered = true;
        Answer::ToCaller(match read_answer(status, &self.far, &self.id) {
            Ok(result) => relayed(&self.id, result),
            Err(refusal) => refusal.reply(&self.id),
        })
    }
}

#[cfg(test)]
#[path = "tests/relay_tests.rs"]
mod tests;
