// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION REVISIONS AND THE LEGACY EVENT STREAM, SERVED, IN BOTH DIRECTIONS (THE DESIGN section 2,
//! the mcp bullet; `docs/design/BUSBAR-1.6.0.md` lines 379-390).
//!
//! INBOUND, on the endpoint's three verbs:
//!
//! - A POST that carries the stateless revision's own marker, or names neither a session nor
//!   `initialize`, is the stateless path, untouched ([`crate::adapt::classify_post`]).
//! - `initialize` opens a session in the revision negotiation picks ([`crate::revision::negotiate`];
//!   no revision is configured): its id is 128 bits of the host's CSPRNG (`random.fill`), bound to
//!   its OWNER, the unit's principal and credential (the kernel's opaque caller reference, minted
//!   from the key id; the ungoverned chain's one constant), and named in `Mcp-Session-Id`.
//! - A message in a session is answered only for that owner: any other owner, an unknown, ended or
//!   expired id, is `404` on every path. A dispatched method is RAISED into the stateless shape, sent
//!   through the one dispatch, and its answer LOWERED ([`crate::adapt`]); `ping`, the session's own
//!   verbs (`resources/subscribe`, `resources/unsubscribe`, `logging/setLevel`: subscribe stays for
//!   the old revisions) and notifications are the session's.
//! - A GET naming a session opens that session's stream (resumed after `Last-Event-ID`); a GET
//!   naming none and no `MCP-Protocol-Version` opens the `2024-11-05` stream, whose first event names
//!   the message address its client POSTs to, every answer then arriving on the stream
//!   ([`revision::sessionless_get`]); a GET naming a revision, a GET that accepts no event stream and
//!   a DELETE naming no session are `405`. DELETE ends the owner's session.
//! - Sessions are this process's ([`crate::tool_sessions`]), bounded per owner in count and bytes.
//!   On the ungoverned chain every caller is one owner, so the binding isolates nothing: the first
//!   `2024-11-05` stream of an instance (whose session id rides a URL) says so once, as the
//!   instance's diagnostic [`UNGOVERNED_LEGACY_STREAM`].
//!
//! OUTBOUND ([`Negotiating`]): busbar sends an upstream the stateless request first, byte for byte
//! what it always sent; only when the upstream refuses it does the client ladder
//! ([`crate::client::negotiate`]) open a session with it (`initialize`, `notifications/initialized`,
//! the request lowered into the session), every further hop over the door's own connector. An
//! upstream answering in the stateless revision is remembered as such and never renegotiated. The
//! ladder's last rung, the `2024-11-05` event stream, is not carried as a client: an upstream that
//! refuses both the stateless request and `initialize` fails the call in words that name it.

use std::collections::VecDeque;
use std::task::Poll;

use serde_json::{json, Value};

use super::{
    ask_entitlements, door_listen, exchange_at, write, CallUnit, Held, McpDoor, Pending, Step,
    Written,
};
use crate::adapt::{self, SessionMethod};
use crate::catalogue::Lookup;
use crate::client::jsonrpc::OutboundRequest;
use crate::client::negotiate::{Action, HopAnswer, Negotiator, Refusal as Refused, Verb};
use crate::codec::{
    CODE_INTERNAL, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND, CODE_REFUSED,
    H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use crate::framing::{CONTENT_LENGTH, CONTENT_TYPE, EVENT_STREAM};
use crate::revision::{self, HeaderCheck, Revision, SessionlessGet};
use crate::tool_arrival::{Disposition, Refusal};
use crate::tool_sessions::{Carriage, OpenRefused, Owner, Remembered, SessionTable};
use busbar_contract::abi::mechanism::call::{Outcome, SEVERITY_WARN};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{OnPieceIn, OnPieceOut, FROM_CALLER, FROM_KERNEL, PIECE_LAST};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Services};

/// THE INSTANCE'S DIAGNOSTIC that an ungoverned chain's sessions are unisolated, latched on its
/// first `2024-11-05` stream (the index of its id in the Statement's diagnostic ids).
pub(super) const UNGOVERNED_LEGACY_STREAM: u32 = 0;

/// The Statement's diagnostic ids, in index order.
pub(super) const DIAG_IDS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str(
        "mcp-legacy-stream-ungoverned",
    )];

/// The words of [`UNGOVERNED_LEGACY_STREAM`].
const UNGOVERNED_WORDS: &str =
    "an MCP 2024-11-05 event stream opened on the ungoverned chain: every \
     caller there is one owner, so a session id (which this revision carries in a URL) isolates \
     nothing between callers; govern the deployment to bind each session to its key";

/// The status a session that is not the caller's (unknown, ended, expired, or another owner's) is
/// answered with, on every path.
const STATUS_NOT_FOUND: u32 = 404;
/// The status of a session request whose version header disagrees with its session.
const STATUS_BAD_REQUEST: u32 = 400;
/// The status a session that cannot be opened is answered with.
const STATUS_UNAVAILABLE: u32 = 503;
/// The status of a message accepted and answered elsewhere (a notification, or a `2024-11-05`
/// message whose answer goes on its stream).
const STATUS_ACCEPTED: u32 = 202;

/// The most resource subscriptions one owner holds across its sessions.
const MAX_OWNER_SUBSCRIPTIONS: usize = 256;
/// The ceiling on one retained subscription uri, in bytes.
const MAX_RESOURCE_SUB_URI_BYTES: usize = 2048;
/// The most announced updates a session holds until its stream collects them; past it, the oldest
/// gives way.
const MAX_PENDING_UPDATES: usize = 64;

/// The RFC 5424 severities `logging/setLevel` names, least severe first.
const LEVELS: &[&str] = &[
    "debug",
    "info",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
];

/// What a unit is to the session machinery.
#[derive(Debug, Clone)]
pub(super) enum SessionUnit {
    /// `initialize` POSTed to the endpoint: it opens a session. `id` is the request's id.
    Open {
        id: Value,
        requested: Option<String>,
    },
    /// A message in `session`, carried as `carriage`, with the version header it carried.
    Message {
        session: String,
        carriage: Carriage,
        header: Option<String>,
        kind: Kind,
        /// The session check passed: its answer is lowered (and, on the `2024-11-05` stream,
        /// delivered there).
        checked: bool,
    },
    /// A GET stream: a session's (`Some`), or the `2024-11-05` stream opening (`None`). `mount`
    /// is the path the arrival named, the message address's own.
    Stream {
        session: Option<String>,
        last_event_id: Option<String>,
        mount: String,
    },
    /// DELETE of `session`.
    Delete { session: String },
    /// A line of a carrier session that negotiated a session revision: its answer is lowered.
    Line,
}

/// What a session message asks.
#[derive(Debug, Clone)]
pub(super) enum Kind {
    /// A method of the one dispatch, raised.
    Dispatch,
    /// Answered here: `ping`, the session's own verbs, `initialize` inside a `2024-11-05` session,
    /// or a method no session revision has.
    Here(Value),
    /// A notification or a client's response: accepted, unanswered.
    Accept(Value),
    /// Refused as it arrived, answered only once the session is the caller's.
    Refused(Box<Refusal>),
}

/// One arrival the session machinery takes.
pub(super) struct Arrival {
    pub(super) unit: SessionUnit,
    /// The raised body the one dispatch decides on; `None` = the unit is answered here.
    pub(super) dispatch: Option<Vec<u8>>,
    /// The head fields the raised body implies: read ahead of the caller's own.
    pub(super) mirror: Vec<(String, String)>,
}

/// What `arrive` makes of an arrival on the endpoint.
pub(super) enum Inbound {
    /// The stateless path, untouched.
    Stateless,
    /// `405`.
    NotAllowed,
    /// The session machinery's.
    Session(Box<Arrival>),
}

/// THE OWNER a unit's session is bound to: the kernel's caller reference (derived from the
/// principal's key id), or the ungoverned chain's one constant.
pub(super) fn owner_of(caller: &str) -> Owner {
    let who = if caller.is_empty() {
        crate::ask::UNGOVERNED
    } else {
        caller
    };
    Owner {
        principal: who.to_string(),
        credential: who.to_string(),
    }
}

/// READ ONE ARRIVAL on the endpoint (`verb`, `target`, `body`, and a reader over its head fields).
pub(super) fn arrive(
    held: Option<&Held>,
    verb: &str,
    target: &str,
    body: &[u8],
    field: &dyn Fn(&str) -> Option<String>,
) -> Inbound {
    let session = field(adapt::H_SESSION_ID).filter(|s| !s.is_empty());
    let (mount, query) = target
        .split_once('?')
        .map_or((target, None), |(p, q)| (p, Some(q)));
    match verb {
        "GET" => {
            let streams = field("accept").is_some_and(|a| a.contains(EVENT_STREAM));
            if !streams {
                return Inbound::NotAllowed;
            }
            let opens = session.is_some()
                || revision::sessionless_get(field(H_PROTOCOL_VERSION).as_deref())
                    == SessionlessGet::EventStream;
            if !opens {
                return Inbound::NotAllowed;
            }
            Inbound::Session(Box::new(Arrival {
                unit: SessionUnit::Stream {
                    session,
                    last_event_id: field(adapt::H_LAST_EVENT_ID),
                    mount: mount.to_string(),
                },
                dispatch: None,
                mirror: Vec::new(),
            }))
        }
        "DELETE" => match session {
            Some(session) => Inbound::Session(Box::new(Arrival {
                unit: SessionUnit::Delete { session },
                dispatch: None,
                mirror: Vec::new(),
            })),
            None => Inbound::NotAllowed,
        },
        "POST" => {
            let value = serde_json::from_slice::<Value>(body).ok();
            let message_session = adapt::message_session_of(query).map(str::to_string);
            let kind = match &value {
                Some(v) => adapt::classify_post(v, session.as_deref(), message_session.as_deref()),
                None if message_session.is_some() => adapt::PostKind::EventStreamMessage,
                None if session.is_some() => adapt::PostKind::InSession,
                None => adapt::PostKind::Stateless,
            };
            match (kind, value) {
                (adapt::PostKind::Initialize, Some(v)) => Inbound::Session(Box::new(Arrival {
                    unit: SessionUnit::Open {
                        id: v.get("id").cloned().unwrap_or(Value::Null),
                        requested: v
                            .pointer("/params/protocolVersion")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    },
                    dispatch: None,
                    mirror: Vec::new(),
                })),
                (adapt::PostKind::InSession, value) => Inbound::Session(message(
                    held,
                    session.unwrap_or_default(),
                    Carriage::Endpoint,
                    field(H_PROTOCOL_VERSION),
                    value,
                )),
                (adapt::PostKind::EventStreamMessage, value) => Inbound::Session(message(
                    held,
                    message_session.unwrap_or_default(),
                    Carriage::EventStream,
                    None,
                    value,
                )),
                _ => Inbound::Stateless,
            }
        }
        _ => Inbound::NotAllowed,
    }
}

/// One message in a session: what it asks, and the raised body when the one dispatch answers it.
fn message(
    held: Option<&Held>,
    session: String,
    carriage: Carriage,
    header: Option<String>,
    value: Option<Value>,
) -> Box<Arrival> {
    let unit = |kind| SessionUnit::Message {
        session,
        carriage,
        header,
        kind,
        checked: false,
    };
    let Some(mut value) = value else {
        let refusal = Refusal {
            status: STATUS_BAD_REQUEST,
            id: None,
            code: busbar_contract::jsonrpc::PARSE_ERROR,
            message: crate::tool_arrival::NOT_JSON.to_string(),
            data: None,
        };
        return Box::new(Arrival {
            unit: unit(Kind::Refused(Box::new(refusal))),
            dispatch: None,
            mirror: Vec::new(),
        });
    };
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_string);
    let has_id = value.get("id").is_some_and(|i| !i.is_null());
    let (kind, dispatch, mirror) = match adapt::session_method(method.as_deref(), has_id) {
        SessionMethod::Accept => (Kind::Accept(value), None, Vec::new()),
        SessionMethod::Ping | SessionMethod::Session | SessionMethod::NotFound => {
            (Kind::Here(value), None, Vec::new())
        }
        SessionMethod::Dispatch => match adapt::raise(&mut value) {
            None => (Kind::Here(value), None, Vec::new()),
            Some(raised) => {
                let mut mirror = vec![
                    (H_PROTOCOL_VERSION.to_string(), raised.version.to_string()),
                    (H_MCP_METHOD.to_string(), raised.method.clone()),
                ];
                if let Some(name) = &raised.name {
                    mirror.push((
                        H_MCP_NAME.to_string(),
                        crate::client::jsonrpc::encode_sentinel(name),
                    ));
                }
                // A `tools/call` mirrors its annotated arguments, as its caller's revision
                // cannot.
                if raised.method == crate::codec::METHOD_TOOLS_CALL {
                    let schema = raised
                        .name
                        .as_deref()
                        .and_then(|n| held?.catalogue.tool(n)?.input_schema.clone());
                    let arguments = value.pointer("/params/arguments");
                    for (name, v) in adapt::param_mirror(schema.as_ref(), arguments) {
                        mirror.push((name.to_ascii_lowercase(), v));
                    }
                }
                let dispatch = serde_json::to_vec(&value).unwrap_or_default();
                (Kind::Dispatch, Some(dispatch), mirror)
            }
        },
    };
    Box::new(Arrival {
        unit: unit(kind),
        dispatch,
        mirror,
    })
}

/// The disposition a session unit answered here is decided under, and counted as: an `initialize`
/// or a message answered here is a discovery, a stream holds open as a subscription does, and a
/// DELETE or an accepted message is a notification.
pub(super) fn disposition(unit: &SessionUnit) -> Disposition {
    let request = |method: &str, id: Value| match crate::tool_ops::method_row_for(method) {
        Some(row) => Disposition::Request { row, id },
        None => Disposition::Notice {
            method: String::new(),
        },
    };
    match unit {
        SessionUnit::Open { id, .. } => request("server/discover", id.clone()),
        SessionUnit::Stream { .. } => request("subscriptions/listen", Value::Null),
        SessionUnit::Message { kind, .. } => match kind {
            Kind::Here(v) => request(
                "server/discover",
                v.get("id").cloned().unwrap_or(Value::Null),
            ),
            Kind::Refused(r) => request("server/discover", r.id.clone().unwrap_or(Value::Null)),
            Kind::Accept(v) => Disposition::Notice {
                method: v
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
            Kind::Dispatch => Disposition::Notice {
                method: String::new(),
            },
        },
        SessionUnit::Delete { .. } | SessionUnit::Line => Disposition::Notice {
            method: String::new(),
        },
    }
}

/// A session unit's arrival refused by the one dispatch: answered once the session is the
/// caller's, never before (a mismatch answers `404` on every path).
pub(super) fn refused_in_session(unit: &mut SessionUnit, refusal: &Refusal) -> bool {
    match unit {
        SessionUnit::Message { kind, .. } => {
            *kind = Kind::Refused(Box::new(refusal.clone()));
            true
        }
        _ => false,
    }
}

// ── the host's services, on a unit's ticket ─────────────────────────────────────────────────────

/// A fresh completion handle on `ticket`, counted in `issued`.
fn handle(ticket: Ticket, issued: &mut u32) -> CompletionHandle {
    let h = CompletionHandle {
        ticket,
        seq: *issued,
        _reserved: 0,
    };
    *issued += 1;
    h
}

/// The kernel's wall clock in milliseconds; `0` with no clock.
pub(super) fn wall_ms(services: Option<Services>, ticket: Ticket, issued: &mut u32) -> u64 {
    services.map_or(0, |s| {
        s.clock_now(handle(ticket, issued))
            .map_or(0, |r| r.wall_ns / 1_000_000)
    })
}

/// The session table.
fn slots<R>(plane: &McpDoor, f: impl FnOnce(&mut SessionTable) -> R) -> Option<R> {
    plane.sessions.with(&(), |t| t.map(f))
}

/// OPENS a session for `owner`: 128 bits from the host's CSPRNG (a collision draws again once).
fn open_session(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    owner: &Owner,
    revision: Revision,
    carriage: Carriage,
    now: u64,
) -> Result<String, &'static str> {
    for _ in 0..2 {
        let mut entropy = [0_u8; 16];
        let drawn = plane.services.is_some_and(|s| {
            s.random_fill(handle(ticket, &mut unit.issued), &mut entropy)
                .is_ok()
        });
        if !drawn {
            return Err("the host's random source did not answer, so no session id can be minted");
        }
        let opened = slots(plane,|t| {
            t.open(entropy, owner.clone(), revision, carriage, now)
        });
        match opened {
            Some(Ok(id)) => return Ok(id.as_str().to_string()),
            Some(Err(OpenRefused::Collision)) => {}
            Some(Err(OpenRefused::NoEntropy)) => {
                return Err("the host's random source answered no entropy")
            }
            Some(Err(OpenRefused::Full)) | None => {
                return Err("this caller holds as many MCP sessions as this node keeps for it")
            }
        }
    }
    Err("two fresh session ids collided")
}

/// A JSON-RPC error envelope.
fn error_json(id: &Value, code: i64, message: &str) -> Vec<u8> {
    serde_json::to_vec(&busbar_contract::jsonrpc::error_body(
        id.clone(),
        code,
        message,
        None,
    ))
    .unwrap_or_default()
}

/// A whole JSON answer.
fn answer_of(status: u32, body: Vec<u8>) -> Pending {
    Pending::answer(status, body, None, &[])
}

/// The answer to a session that is not the caller's.
fn not_found(id: &Value) -> Pending {
    answer_of(
        STATUS_NOT_FOUND,
        error_json(
            id,
            CODE_REFUSED,
            "Session not found: it ended, expired, or is not this caller's. Send `initialize` \
             without Mcp-Session-Id to open a new one.",
        ),
    )
}

/// The id a session message carries.
fn id_of(kind: &Kind) -> Value {
    match kind {
        Kind::Here(v) | Kind::Accept(v) => v.get("id").cloned().unwrap_or(Value::Null),
        Kind::Refused(r) => r.id.clone().unwrap_or(Value::Null),
        Kind::Dispatch => Value::Null,
    }
}

// ── the answers ─────────────────────────────────────────────────────────────────────────────────

/// ANSWER A SESSION UNIT on its caller's piece, the session first checked against its owner:
/// `None` for a unit the one dispatch answers (its session checked).
pub(super) fn answer(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    let session_unit = unit.session.clone()?;
    let owner = owner_of(caller);
    let now = wall_ms(plane.services, ticket, &mut unit.issued);
    let pending = match session_unit {
        SessionUnit::Line | SessionUnit::Stream { .. } => return None,
        SessionUnit::Open { id, requested } => {
            open_endpoint(plane, ticket, unit, &owner, &id, requested.as_deref(), now)
        }
        SessionUnit::Delete { session } => {
            if slots(plane,|t| t.close(&session, &owner, now)) == Some(true) {
                plane.session_state.remove(&session);
                // Each of its streams ends at its next collection.
                due(plane, &session);
                answer_of(200, Vec::new())
            } else {
                not_found(&Value::Null)
            }
        }
        SessionUnit::Message {
            session,
            carriage,
            header,
            kind,
            ..
        } => {
            let held = slots(plane,|t| {
                let revision = t.revision(&session, &owner, now)?;
                (t.carriage(&session, &owner, now)? == carriage).then_some(revision)
            })
            .flatten();
            let Some(revision) = held else {
                return Some(written(unit, not_found(&id_of(&kind))));
            };
            if carriage == Carriage::Endpoint
                && revision::check_header(revision, header.as_deref()) == HeaderCheck::Disagrees
            {
                let body = error_json(
                    &id_of(&kind),
                    CODE_INVALID_REQUEST,
                    "The MCP-Protocol-Version header names another revision than this session's.",
                );
                return Some(written(unit, answer_of(STATUS_BAD_REQUEST, body)));
            }
            if let Some(SessionUnit::Message { checked, .. }) = unit.session.as_mut() {
                *checked = true;
            }
            match kind {
                Kind::Dispatch => return None,
                Kind::Accept(v) => {
                    if v.get("method").and_then(Value::as_str) == Some(adapt::METHOD_INITIALIZED) {
                        slots(plane,|t| t.mark_initialized(&session, &owner, now));
                    }
                    answer_of(STATUS_ACCEPTED, Vec::new())
                }
                Kind::Refused(r) => answer_of(r.status, r.body()),
                Kind::Here(v) => {
                    let body = here(
                        plane,
                        ticket,
                        unit,
                        (session.as_str(), &owner),
                        revision,
                        carriage,
                        &v,
                    );
                    answer_of(200, body)
                }
            }
        }
    };
    Some(written(unit, pending))
}

/// `pending` kept as the unit's answer.
fn written(unit: &mut CallUnit, pending: Pending) -> Step {
    unit.pending = Some(pending);
    Step::Write
}

/// The discovery document this caller is entitled to, as `initialize` answers from it.
fn discovery(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit, id: &Value) -> Option<Value> {
    let held = unit.held.clone().or_else(|| plane.current())?;
    ask_entitlements(plane.services, ticket, unit, &held.catalogue.grants());
    let entitled = &unit.entitled;
    let admit = |kind: &str, name: &str| {
        entitled
            .get(&format!("{kind}:{name}"))
            .copied()
            .unwrap_or(false)
    };
    let document = crate::answer::discover(&held.catalogue, id, &admit);
    serde_json::from_slice::<Value>(&document)
        .ok()?
        .get("result")
        .cloned()
}

/// `initialize` on the endpoint: the revision negotiation picks, a session opened in it.
fn open_endpoint(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    owner: &Owner,
    id: &Value,
    requested: Option<&str>,
    now: u64,
) -> Pending {
    // The event-stream revision is opened by its GET, never by a POSTed `initialize`.
    let revision = match revision::negotiate(requested) {
        r if r.is_event_stream_revision() => revision::SESSION_REVISIONS[0],
        r => r,
    };
    let Some(discovered) = discovery(plane, ticket, unit, id) else {
        return answer_of(
            STATUS_UNAVAILABLE,
            error_json(
                id,
                CODE_INTERNAL,
                "this node publishes no MCP catalogue yet",
            ),
        );
    };
    let session = match open_session(
        plane,
        ticket,
        unit,
        owner,
        revision,
        Carriage::Endpoint,
        now,
    ) {
        Ok(session) => session,
        Err(why) => return answer_of(STATUS_UNAVAILABLE, error_json(id, CODE_INTERNAL, why)),
    };
    let result = adapt::initialize_result(&discovered, revision, false);
    let body = serde_json::to_vec(&crate::line::result(id, result)).unwrap_or_default();
    let mut pending = answer_of(200, body);
    pending
        .fields
        .push((adapt::H_SESSION_ID.to_string(), session));
    pending
}

/// A message the session answers itself.
fn here(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    (session, owner): (&str, &Owner),
    revision: Revision,
    carriage: Carriage,
    value: &Value,
) -> Vec<u8> {
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
    let ok =
        |result: Value| serde_json::to_vec(&crate::line::result(&id, result)).unwrap_or_default();
    let invalid = |message: &str| error_json(&id, CODE_INVALID_PARAMS, message);
    let uri = value.pointer("/params/uri").and_then(Value::as_str);
    match method {
        adapt::METHOD_PING => ok(json!({})),
        // The `2024-11-05` session opened with its stream; its `initialize` arrives inside it.
        adapt::METHOD_INITIALIZE if carriage == Carriage::EventStream => {
            match discovery(plane, ticket, unit, &id) {
                Some(d) => ok(adapt::initialize_result(&d, revision, false)),
                None => error_json(
                    &id,
                    CODE_INTERNAL,
                    "this node publishes no MCP catalogue yet",
                ),
            }
        }
        adapt::METHOD_INITIALIZE => error_json(
            &id,
            CODE_INVALID_REQUEST,
            "this session is already open: send `initialize` without Mcp-Session-Id to open \
             another",
        ),
        "resources/subscribe" => {
            let Some(uri) = uri else {
                return invalid("`params.uri` is required: the resource to watch.");
            };
            if uri.len() > MAX_RESOURCE_SUB_URI_BYTES {
                return invalid(
                    "`params.uri` is longer than a session retains: a subscription is held for \
                     the session, so it is bounded.",
                );
            }
            let Some(held) = unit.held.clone().or_else(|| plane.current()) else {
                return invalid("this node publishes no MCP catalogue yet");
            };
            ask_entitlements(plane.services, ticket, unit, &held.catalogue.grants());
            let entitled = &unit.entitled;
            let admit = |kind: &str, name: &str| {
                entitled
                    .get(&format!("{kind}:{name}"))
                    .copied()
                    .unwrap_or(false)
            };
            if !matches!(held.catalogue.resource_by_uri(&admit, uri), Lookup::One(_)) {
                return invalid("`params.uri` names no resource this caller may read.");
            }
            if subscribe(plane, session, owner, uri) {
                ok(json!({}))
            } else {
                invalid(
                    "this caller already holds as many resource subscriptions as this node \
                     watches for it: unsubscribe from one before subscribing to another.",
                )
            }
        }
        "resources/unsubscribe" => {
            let Some(uri) = uri else {
                return invalid("`params.uri` is required: the resource to stop watching.");
            };
            plane.session_state.with(&session.to_string(), |s| {
                if let Some(s) = s {
                    s.uris.retain(|u| u != uri);
                }
            });
            ok(json!({}))
        }
        "logging/setLevel" => {
            let level = value.pointer("/params/level").and_then(Value::as_str);
            match level.filter(|l| LEVELS.contains(l)) {
                Some(level) => {
                    state_of(plane, session, owner, |s| s.level = Some(level.to_string()));
                    ok(json!({}))
                }
                None => invalid(
                    "`params.level` must name an RFC 5424 severity: the floor this session's \
                     `notifications/message` records are filtered at.",
                ),
            }
        }
        _ => error_json(
            &id,
            CODE_METHOD_NOT_FOUND,
            &format!("Method `{method}` is not implemented by this server for this revision."),
        ),
    }
}

// ── what a session holds beside its table row ───────────────────────────────────────────────────

/// A session's own state: its owner, the resources it watches, its log floor, and the updates
/// announced for it its stream has not collected.
#[derive(Debug, Clone, Default)]
pub(super) struct SessionState {
    owner: Option<Owner>,
    uris: Vec<String>,
    level: Option<String>,
    updates: VecDeque<(String, String)>,
}

/// Runs `f` on `session`'s state, made for `owner` when it has none.
fn state_of(plane: &McpDoor, session: &str, owner: &Owner, f: impl FnOnce(&mut SessionState)) {
    plane.session_state.with_all(|m| {
        let s = m.entry(session.to_string()).or_default();
        s.owner.get_or_insert_with(|| owner.clone());
        f(s);
    });
}

/// Subscribes `session` to `uri`: `false` past the owner's subscription quota.
fn subscribe(plane: &McpDoor, session: &str, owner: &Owner, uri: &str) -> bool {
    plane.session_state.with_all(|m| {
        if m.get(session)
            .is_some_and(|s| s.uris.iter().any(|u| u == uri))
        {
            return true;
        }
        let held: usize = m
            .values()
            .filter(|s| s.owner.as_ref() == Some(owner))
            .map(|s| s.uris.len())
            .sum();
        if held >= MAX_OWNER_SUBSCRIPTIONS {
            return false;
        }
        let s = m.entry(session.to_string()).or_default();
        s.owner.get_or_insert_with(|| owner.clone());
        s.uris.push(uri.to_string());
        true
    })
}

/// AN UPSTREAM ANNOUNCED that `uri` of its registration `server` changed: every session watching
/// that uri holds it until its stream collects it, where the subscriber's entitlement is asked
/// again (Listen's relay rule: the uri resolves under its live grant to the announcing server's
/// declared resource).
pub(super) fn announce(plane: &McpDoor, server: &str, uri: &str) {
    let sessions: Vec<String> = plane.session_state.with_all(|m| {
        let mut hit = Vec::new();
        for (session, s) in m.iter_mut() {
            if s.uris.iter().any(|u| u == uri) {
                if s.updates.len() >= MAX_PENDING_UPDATES {
                    s.updates.pop_front();
                }
                s.updates.push_back((server.to_string(), uri.to_string()));
                hit.push(session.clone());
            }
        }
        hit
    });
    for session in sessions {
        due(plane, &session);
    }
}

/// WHAT AN UPSTREAM SAID ON ITS EVENT STREAM beside a relayed call's answer: its resource updates
/// are announced to every watching session, and, for a caller in a session, its log records past
/// the session's floor are delivered on that session's stream.
pub(super) fn heard(
    plane: &McpDoor,
    server: &str,
    raw: &[u8],
    session: Option<(&str, &Owner, u64)>,
) {
    for line in String::from_utf8_lossy(raw).lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let Ok(frame) = serde_json::from_str::<Value>(data.trim()) else {
            continue;
        };
        match frame.get("method").and_then(Value::as_str) {
            Some("notifications/resources/updated") => {
                if let Some(uri) = frame.pointer("/params/uri").and_then(Value::as_str) {
                    announce(plane, server, uri);
                }
            }
            Some("notifications/message") => {
                let Some((id, owner, now)) = session else {
                    continue;
                };
                let floor = plane
                    .session_state
                    .get(&id.to_string())
                    .and_then(|s| s.level);
                let level = frame.pointer("/params/level").and_then(Value::as_str);
                let rank = |l: &str| LEVELS.iter().position(|x| *x == l);
                let passes = match (floor.as_deref().and_then(rank), level.and_then(rank)) {
                    (Some(floor), Some(level)) => level >= floor,
                    (Some(_), None) => false,
                    (None, _) => true,
                };
                if passes {
                    deliver(plane, id, owner, &frame.to_string(), now);
                }
            }
            _ => {}
        }
    }
}

/// The session a unit's caller is in, when it is in one whose check passed.
pub(super) fn session_of(unit: &Option<SessionUnit>) -> Option<String> {
    match unit {
        Some(SessionUnit::Message {
            session,
            checked: true,
            ..
        }) => Some(session.clone()),
        _ => None,
    }
}

// ── the answer, lowered ─────────────────────────────────────────────────────────────────────────

/// LOWERS the answer a session unit's dispatch wrote, before its first byte: the session
/// revision's shape (a result no session revision can carry becomes an error), every JSON-RPC
/// answer at `200`; on the `2024-11-05` stream, the answer goes on the stream and the POST is
/// accepted (`202`).
pub(super) fn lower(plane: &McpDoor, ticket: Ticket, caller: &str, unit: &mut CallUnit) {
    let (line, legacy) = match &unit.session {
        Some(SessionUnit::Message {
            checked: true,
            carriage,
            session,
            ..
        }) => (
            false,
            (*carriage == Carriage::EventStream).then(|| session.clone()),
        ),
        Some(SessionUnit::Line) => (true, None),
        _ => return,
    };
    let lowerable = unit
        .pending
        .as_ref()
        .is_some_and(|p| !p.headed && p.request.is_none() && !p.bytes.is_empty());
    if !lowerable {
        return;
    }
    let now = legacy
        .as_ref()
        .map_or(0, |_| wall_ms(plane.services, ticket, &mut unit.issued));
    let Some(pending) = unit.pending.as_mut() else {
        return;
    };
    let Ok(mut v) = serde_json::from_slice::<Value>(&pending.bytes) else {
        return;
    };
    let inexpressible = v
        .get_mut("result")
        .is_some_and(|result| adapt::lower_result(result).is_err());
    if inexpressible {
        let id = v.get("id").cloned().unwrap_or(Value::Null);
        v = busbar_contract::jsonrpc::error_body(
            id,
            CODE_REFUSED,
            "this answer asks for input or names a task, which this session's MCP revision \
             cannot carry",
            None,
        );
    }
    let rpc = v.get("jsonrpc").is_some() && (v.get("result").is_some() || v.get("error").is_some());
    let bytes = serde_json::to_vec(&v).unwrap_or_default();
    if line {
        pending.bytes = bytes;
        return;
    }
    match legacy {
        Some(session) => {
            deliver(
                plane,
                &session,
                &owner_of(caller),
                &String::from_utf8_lossy(&bytes),
                now,
            );
            pending.bytes.clear();
            pending.fields.clear();
            pending.status = STATUS_ACCEPTED;
        }
        None => {
            if rpc {
                pending.status = 200;
            }
            for (name, value) in &mut pending.fields {
                if name.as_str() == CONTENT_LENGTH {
                    *value = bytes.len().to_string();
                }
            }
            pending.bytes = bytes;
        }
    }
}

// ── the streams ─────────────────────────────────────────────────────────────────────────────────

/// One held GET stream, by its unit.
#[derive(Debug, Clone)]
pub(super) struct Stream {
    session: String,
    owner: Owner,
    /// The session table's stream the events are buffered on.
    stream: u32,
    /// The last event seq written to the caller.
    delivered: u64,
    /// The `2024-11-05` stream (no event ids).
    legacy: bool,
    /// The session's caller-side ticket.
    ticket: Ticket,
    /// The stream owes a collection.
    due: bool,
    /// When it last wrote (the host's monotonic clock).
    last_write_ns: u64,
}

/// Whether `unit` is a held session stream (its pieces are this module's).
pub(super) fn holds(plane: &McpDoor, unit: u64) -> bool {
    plane.units.with(&unit, |u| {
        u.is_some_and(|u| matches!(u.session, Some(SessionUnit::Stream { .. })))
    })
}

/// `data` buffered on `session`'s stream, and the stream named due.
fn deliver(plane: &McpDoor, session: &str, owner: &Owner, data: &str, now: u64) {
    let target = plane
        .streams
        .with_all(|m| m.values().find(|s| s.session == session).map(|s| s.stream));
    if let Some(stream) = target {
        slots(plane,|t| t.push(session, owner, stream, data, now));
        due(plane, session);
    }
}

/// Every stream of `session` named due, and the driver woken.
fn due(plane: &McpDoor, session: &str) {
    let any = plane.streams.with_all(|m| {
        let mut any = false;
        for s in m.values_mut().filter(|s| s.session == session) {
            s.due = true;
            any = true;
        }
        any
    });
    if any {
        door_listen::wake_driver(plane);
    }
}

/// The streams owing a collection.
pub(super) fn due_streams(plane: &McpDoor) -> Vec<u64> {
    plane
        .streams
        .with_all(|m| m.iter().filter(|(_, s)| s.due).map(|(k, _)| *k).collect())
}

/// The streams named to the host: no longer owing.
pub(super) fn taken(plane: &McpDoor, named: &[u64]) {
    plane.streams.with_all(|m| {
        for key in named {
            if let Some(s) = m.get_mut(key) {
                s.due = false;
            }
        }
    });
}

/// THE TICK: every held stream owes a collection (its keepalive, or its end once its session is
/// gone), and the state of every session the table no longer holds is dropped.
pub(super) fn tick(plane: &McpDoor) {
    let any = plane.streams.with_all(|m| {
        for s in m.values_mut() {
            s.due = true;
        }
        !m.is_empty()
    });
    let gone: Vec<String> = plane
        .session_state
        .with_all(|m| m.keys().cloned().collect());
    let gone: Vec<String> = gone
        .into_iter()
        .filter(|id| slots(plane,|t| !t.holds(id)).unwrap_or(true))
        .collect();
    plane.session_state.with_all(|m| {
        for id in &gone {
            m.remove(id);
        }
    });
    if any {
        door_listen::wake_driver(plane);
    }
}

/// The op on `ticket` was cancelled: the stream it carried is dropped.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) {
    plane
        .streams
        .with_all(|m| m.retain(|_, s| s.ticket != ticket));
}

/// What an idle stream writes to say it is alive.
const KEEPALIVE: &[u8] = b": keepalive\n\n";

/// ONE PIECE OF A HELD SESSION STREAM: the caller's piece opens it, a collection writes what its
/// session buffered (or a keepalive, or its end), and the caller's side ending ends it.
pub(super) fn piece(
    plane: &McpDoor,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> Outcome {
    let given = input.get();
    let (key, ticket) = (given.unit, given.head.ticket);
    let caller = input
        .field(|i| &i.caller_ref)
        .as_str()
        .unwrap_or_default()
        .to_string();
    let owner = owner_of(&caller);
    let mut say_ungoverned = false;
    let step = plane.units.with(&key, |unit| {
        let unit = unit?;
        unit.ticket = Some(ticket);
        if unit.pending.is_some() {
            return Some(true);
        }
        match given.from {
            FROM_CALLER if given.flags & PIECE_LAST != 0 => {
                plane.streams.remove(&key);
                unit.pending = Some(door_listen::frame(Vec::new(), true, true));
                Some(true)
            }
            FROM_CALLER => {
                let (wrote, legacy_ungoverned) = open_stream(plane, ticket, &owner, unit)?;
                say_ungoverned = legacy_ungoverned;
                Some(wrote)
            }
            FROM_KERNEL if given.attempt_no == 0 => step_stream(plane, ticket, unit),
            FROM_KERNEL => Some(false),
            _ => None,
        }
    });
    // THE UNGOVERNED CHAIN SAYS SO, once per instance, on its first `2024-11-05` stream.
    if say_ungoverned && plane.said_ungoverned.insert((), ()).is_none() {
        let _reported = out.diag(UNGOVERNED_LEGACY_STREAM, SEVERITY_WARN, UNGOVERNED_WORDS);
    }
    match step {
        None => Outcome::Refused,
        Some(false) => Outcome::Ready,
        Some(true) => {
            let written = plane.units.with(&key, |unit| {
                let pending = unit?.pending.as_mut()?;
                Some(write(&input, out, pending))
            });
            match written {
                None | Some(Err(())) => Outcome::Failed,
                Some(Ok(Written::More)) => Outcome::Ready,
                Some(Ok(Written::Sent)) => {
                    plane.units.with(&key, |unit| {
                        if let Some(unit) = unit {
                            unit.pending = None;
                        }
                    });
                    Outcome::Ready
                }
                Some(Ok(Written::Done)) => {
                    plane.units.remove(&key);
                    plane.streams.remove(&key);
                    Outcome::Ready
                }
            }
        }
    }
}

/// The events after a stream's cursor, framed: `(bytes, the last seq)`.
fn frames(events: &[(String, String)], legacy: bool) -> (Vec<u8>, Option<u64>) {
    let mut bytes = Vec::new();
    let mut last = None;
    for (id, data) in events {
        let id_word = (!legacy).then_some(id.as_str());
        bytes.extend_from_slice(adapt::frame(id_word, Some(adapt::EVENT_MESSAGE), data).as_bytes());
        last = id.split_once('-').and_then(|(_, q)| q.parse().ok());
    }
    (bytes, last)
}

/// OPENS the stream the unit's GET asks for: `(wrote, an ungoverned 2024-11-05 stream)`.
fn open_stream(
    plane: &McpDoor,
    ticket: Ticket,
    owner: &Owner,
    unit: &mut CallUnit,
) -> Option<(bool, bool)> {
    let Some(SessionUnit::Stream {
        session,
        last_event_id,
        mount,
    }) = unit.session.clone()
    else {
        return None;
    };
    if plane.streams.with(&unit.key, |s| s.is_some()) {
        return Some((false, false));
    }
    let now = wall_ms(plane.services, ticket, &mut unit.issued);
    let mono = door_listen::mono_ns(plane.services, ticket, unit);
    let ungoverned = owner.principal == crate::ask::UNGOVERNED;
    let (session, stream, delivered, legacy, bytes) = match session {
        None => {
            let opened = open_session(
                plane,
                ticket,
                unit,
                owner,
                Revision::R2024_11_05,
                Carriage::EventStream,
                now,
            );
            let session = match opened {
                Ok(session) => session,
                Err(why) => {
                    let body = error_json(&Value::Null, CODE_INTERNAL, why);
                    unit.pending = Some(answer_of(STATUS_UNAVAILABLE, body));
                    return Some((true, false));
                }
            };
            let stream = slots(plane,|t| t.open_stream(&session, owner, now)).flatten()?;
            let endpoint = adapt::endpoint_event(&mount, &session);
            (session, stream, 0, true, endpoint.into_bytes())
        }
        Some(session) => {
            let carriage = slots(plane,|t| t.carriage(&session, owner, now)).flatten();
            if carriage != Some(Carriage::Endpoint) {
                unit.pending = Some(not_found(&Value::Null));
                return Some((true, false));
            }
            let resumed = last_event_id
                .and_then(|cursor| slots(plane,|t| t.replay(&session, owner, &cursor, now)))
                .flatten();
            match resumed {
                Some(replay) => {
                    let (bytes, last) = frames(&replay.events, false);
                    let delivered = last.unwrap_or(0);
                    let bytes = if bytes.is_empty() {
                        KEEPALIVE.to_vec()
                    } else {
                        bytes
                    };
                    (session, replay.stream, delivered, false, bytes)
                }
                None => {
                    let stream = slots(plane,|t| t.open_stream(&session, owner, now)).flatten()?;
                    (session, stream, 0, false, KEEPALIVE.to_vec())
                }
            }
        }
    };
    // One stream per live unit, so the unit table's admission bound (it refuses past `MAX_UNITS`,
    // and evicts nothing) bounds this table too.
    plane.streams.insert(
        unit.key,
        Stream {
            session,
            owner: owner.clone(),
            stream,
            delivered,
            legacy,
            ticket,
            due: false,
            last_write_ns: mono,
        },
    );
    unit.pending = Some(door_listen::frame(bytes, false, false));
    Some((true, legacy && ungoverned))
}

/// ONE COLLECTION of a held stream: the updates announced for its session (each re-judged under
/// the caller's live grants), then every event buffered after its cursor; a keepalive when quiet;
/// its end once its session is gone.
fn step_stream(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> Option<bool> {
    let held_stream = plane.streams.get(&unit.key)?;
    let now = wall_ms(plane.services, ticket, &mut unit.issued);
    let mono = door_listen::mono_ns(plane.services, ticket, unit);
    let updates: Vec<(String, String)> = plane
        .session_state
        .with(&held_stream.session, |s| {
            s.map(|s| s.updates.drain(..).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    if !updates.is_empty() {
        if let Some(held) = plane.current().or_else(|| unit.held.clone()) {
            door_listen::entitled_afresh(plane, ticket, unit, &held);
            let entitled = &unit.entitled;
            let admit = |kind: &str, name: &str| {
                entitled
                    .get(&format!("{kind}:{name}"))
                    .copied()
                    .unwrap_or(false)
            };
            for (server, uri) in updates {
                let theirs = matches!(
                    held.catalogue.resource_by_uri(&admit, &uri),
                    Lookup::One(entry) if entry.server == server
                );
                if theirs {
                    let note = json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/updated",
                        "params": { "uri": uri },
                    });
                    slots(plane,|t| {
                        t.push(
                            &held_stream.session,
                            &held_stream.owner,
                            held_stream.stream,
                            &note.to_string(),
                            now,
                        )
                    });
                }
            }
        }
    }
    let cursor = format!("{}-{}", held_stream.stream, held_stream.delivered);
    let replay = slots(plane,|t| {
        t.replay(&held_stream.session, &held_stream.owner, &cursor, now)
    })
    .flatten();
    let Some(replay) = replay else {
        // The session is gone (ended, expired, evicted): so is its stream.
        plane.streams.remove(&unit.key);
        unit.pending = Some(door_listen::frame(Vec::new(), true, true));
        return Some(true);
    };
    let (bytes, last) = frames(&replay.events, held_stream.legacy);
    let bytes = if !bytes.is_empty() {
        bytes
    } else if mono.saturating_sub(held_stream.last_write_ns) >= crate::subscribe::KEEPALIVE_NS {
        KEEPALIVE.to_vec()
    } else {
        return Some(false);
    };
    plane.streams.with(&unit.key, |s| {
        if let Some(s) = s {
            if let Some(last) = last {
                s.delivered = last;
            }
            s.last_write_ns = mono;
        }
    });
    unit.pending = Some(door_listen::frame(bytes, false, true));
    Some(true)
}

// ── busbar as a client: the negotiated upstream conversation ────────────────────────────────────

/// How many connector handles one hop of a negotiation may number.
pub(super) const HOP_SPAN: u32 = 1 << 9;

/// What busbar remembers about `member`.
fn remembered(plane: &McpDoor, member: &str) -> Option<Remembered> {
    plane.upstreams.with(&(), |t| t.and_then(|t| t.get(member)))
}

/// One hop's answer as the connector read it: its status, its head fields (lower-case names) and
/// its body.
type Hop = (u16, Vec<(String, String)>, Vec<u8>);

/// What a negotiation came to.
pub(super) enum Negotiated {
    /// The answer to hand on: the status, the body as the upstream sent it, and whether it is an
    /// event stream.
    Answer(u16, Vec<u8>, bool),
    /// No answer: why, in words, for the caller's upstream-failure answer.
    Failed(String),
}

/// ONE UPSTREAM CONVERSATION, NEGOTIATED ([`Negotiator`]), parked on its unit across PENDING
/// entries: the action under way, the hops sent, and what the answers so far said.
#[derive(Debug)]
pub(super) struct Negotiating {
    negotiator: Negotiator,
    next: Option<Action>,
    hops: u32,
    /// The first hop is the stateless request, not yet answered.
    probing: bool,
    /// The upstream answered the stateless revision before: it is not renegotiated.
    stateless_known: bool,
    /// The walk's answer was fed (a resumed FAR-END piece carries it again).
    pub(super) fed: bool,
    /// The session the walk's answer named (its head crosses with its first piece).
    pub(super) walk_session: Option<String>,
    /// The last answer's body as sent, and whether it is an event stream.
    raw: (Vec<u8>, bool),
    /// The statuses of the hops that refused, for the words of a failure.
    refused: Vec<u16>,
    /// Why the last hop had no answer at all.
    failure: Option<String>,
}

impl Negotiating {
    /// A conversation carrying `original` (a stateless request) to `member`, and the request its
    /// first hop is: `original` itself, or lowered into the session busbar remembers.
    pub(super) fn begin(plane: &McpDoor, member: &str, original: OutboundRequest) -> Self {
        let remembered = remembered(plane, member);
        let stateless_known = remembered
            .as_ref()
            .is_some_and(|r| r.revision == Revision::R2026_07_28);
        let probing = !remembered
            .as_ref()
            .is_some_and(|r| r.revision.has_sessions());
        let mut negotiator = Negotiator::new(original, remembered, super::VERSION);
        let first = negotiator.start();
        Negotiating {
            negotiator,
            next: Some(first),
            hops: 0,
            probing,
            stateless_known,
            fed: false,
            walk_session: None,
            raw: (Vec::new(), false),
            refused: Vec::new(),
            failure: None,
        }
    }

    /// The request the first hop sends, when it is one.
    pub(super) fn first_request(&self) -> Option<&OutboundRequest> {
        match &self.next {
            Some(Action::Send { request, .. }) => Some(request),
            _ => None,
        }
    }

    /// Feeds one hop's answer (`None`: none at all) and answers the next action.
    fn feed(&mut self, answer: Option<Hop>) -> Action {
        let probing = std::mem::replace(&mut self.probing, false);
        let Some((status, fields, body)) = answer else {
            return self.negotiator.on_answer(None);
        };
        let sse = fields
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case(CONTENT_TYPE) && v.starts_with(EVENT_STREAM));
        let json = if sse {
            crate::call::last_sse_data(&body)
        } else {
            body.clone()
        };
        self.raw = (body, sse);
        let hop = HopAnswer {
            status,
            fields,
            body: json,
        };
        // A KNOWN STATELESS UPSTREAM, or a refusal that says nothing about the revision (the
        // credential, or a rate): its answer is the stateless path's, unrenegotiated.
        if probing && (self.stateless_known || matches!(status, 401 | 403 | 407 | 429)) {
            return Action::Finish(hop);
        }
        if !(200..300).contains(&status) {
            self.refused.push(status);
        }
        self.negotiator.on_answer(Some(hop))
    }

    /// DRIVES the conversation over the door's connector, hop by hop, from `base`: PENDING while a
    /// hop pends (the action kept), READY with what it came to. What busbar learnt is kept for the
    /// next call to `member`.
    fn drive(
        &mut self,
        instance: &Instance<'_, McpDoor>,
        plane: &McpDoor,
        base: u32,
        member: &str,
        timeout_ms: u64,
    ) -> Poll<Negotiated> {
        loop {
            match self.next.take() {
                Some(Action::Send { verb, request }) => {
                    let at = base.saturating_add(self.hops.saturating_mul(HOP_SPAN));
                    let polled = exchange_at(
                        instance,
                        plane.host.as_ref(),
                        at,
                        &request.url,
                        member,
                        || exchange_request(verb, &request, timeout_ms),
                    );
                    let Poll::Ready(answered) = polled else {
                        self.next = Some(Action::Send { verb, request });
                        return Poll::Pending;
                    };
                    self.hops += 1;
                    let answered = match answered {
                        Ok(r) => Some((
                            r.status,
                            r.fields
                                .iter()
                                .map(|(n, v)| {
                                    (
                                        String::from_utf8_lossy(n).to_ascii_lowercase(),
                                        String::from_utf8_lossy(v).into_owned(),
                                    )
                                })
                                .collect(),
                            r.body,
                        )),
                        Err(e) => {
                            self.failure = Some(e.to_string());
                            None
                        }
                    };
                    self.next = Some(self.feed(answered));
                }
                Some(Action::Finish(answer)) => {
                    self.keep(plane, member);
                    let (raw, sse) = std::mem::take(&mut self.raw);
                    let raw = if raw.is_empty() { answer.body } else { raw };
                    return Poll::Ready(Negotiated::Answer(answer.status, raw, sse));
                }
                Some(Action::Fail(refusal)) => {
                    self.keep(plane, member);
                    return Poll::Ready(self.failed(&refusal, member));
                }
                // THE LAST RUNG, NOT CARRIED: the `2024-11-05` event stream is read only as a held
                // stream, which the exchange cannot hold. Said, never papered over.
                Some(Action::OpenStream { .. } | Action::AwaitEvent) | None => {
                    self.keep(plane, member);
                    return Poll::Ready(Negotiated::Failed(self.legacy_only(member)));
                }
            }
        }
    }

    /// What busbar learnt, kept (or forgotten) for the next call to `member`.
    fn keep(&self, plane: &McpDoor, member: &str) {
        plane.upstreams.with(&(), |t| {
            if let Some(t) = t {
                match self.negotiator.remembered() {
                    Some(r) => t.put(member, r),
                    None => t.forget(member),
                }
            }
        });
    }

    /// The words of an upstream that refused every revision busbar carries as a client.
    fn legacy_only(&self, member: &str) -> String {
        let statuses: Vec<String> = self.refused.iter().map(u16::to_string).collect();
        format!(
            "MCP server `{member}` refused the stateless {PROTOCOL_VERSION} request and refused \
             `initialize` (HTTP {}); the one revision left is 2024-11-05 (HTTP+SSE), which busbar \
             does not speak as a client",
            statuses.join(", ")
        )
    }

    /// A failed conversation, in words; an answer it did get is handed on as it came.
    fn failed(&mut self, refusal: &Refused, member: &str) -> Negotiated {
        match refusal {
            Refused::Unreachable(Some(answer)) => {
                let (raw, sse) = std::mem::take(&mut self.raw);
                let raw = if raw.is_empty() {
                    answer.body.clone()
                } else {
                    raw
                };
                Negotiated::Answer(answer.status, raw, sse)
            }
            Refused::Unreachable(None) => Negotiated::Failed(
                self.failure
                    .clone()
                    .unwrap_or_else(|| format!("MCP server `{member}` could not be reached")),
            ),
            Refused::OfferedUnsupported => Negotiated::Failed(format!(
                "MCP server `{member}` answered `initialize` with an MCP revision busbar does not \
                 carry as a client (it carries 2025-11-25 and 2025-06-18 on a session)"
            )),
            Refused::NoCommonRevision | Refused::AddressRefused | Refused::StreamLost => {
                Negotiated::Failed(self.legacy_only(member))
            }
        }
    }
}

/// One hop as the connector's exchange sends it.
fn exchange_request(
    verb: Verb,
    request: &OutboundRequest,
    timeout_ms: u64,
) -> busbar_contract::abi::sdk::exchange::Request {
    busbar_contract::abi::sdk::exchange::Request {
        method: match verb {
            Verb::Post => b"POST".to_vec(),
            Verb::Delete => b"DELETE".to_vec(),
        },
        target: crate::call::path_of(&request.url).into_bytes(),
        fields: request
            .headers
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect(),
        body: request.body.clone(),
        timeout_ms,
    }
}

/// A FETCH OF THE DOOR'S OWN (verify-on-call's `tools/list`), negotiated: every hop over the
/// connector from `base`, the conversation parked on the unit while one pends.
pub(super) fn fetch(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    unit: &mut CallUnit,
    (base, member, timeout_ms): (u32, &str, u64),
    original: OutboundRequest,
) -> Poll<Result<busbar_contract::abi::sdk::exchange::ExchangeResponse, String>> {
    let negotiating = unit
        .negotiating
        .get_or_insert_with(|| Box::new(Negotiating::begin(plane, member, original)));
    let Poll::Ready(done) = negotiating.drive(instance, plane, base, member, timeout_ms) else {
        return Poll::Pending;
    };
    unit.negotiating = None;
    Poll::Ready(match done {
        Negotiated::Answer(status, raw, sse) => {
            Ok(busbar_contract::abi::sdk::exchange::ExchangeResponse {
                status,
                body: if sse {
                    crate::call::last_sse_data(&raw)
                } else {
                    raw
                },
                ..Default::default()
            })
        }
        Negotiated::Failed(reason) => Err(reason),
    })
}

/// THE WALK'S ANSWER to a relayed call's first hop (`status`, event stream or not, `far`), and the
/// conversation from there: READY with what it came to, `None` when the answer is handed on as it
/// came (the stateless path, or no connector to negotiate over).
pub(super) fn far_answer(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    negotiating: &mut Negotiating,
    (base, member, timeout_ms): (u32, &str, u64),
    (status, sse, far): (u32, bool, &[u8]),
) -> Poll<Option<Negotiated>> {
    if !negotiating.fed {
        negotiating.fed = true;
        let mut fields = Vec::new();
        if sse {
            fields.push((CONTENT_TYPE.to_string(), EVENT_STREAM.to_string()));
        }
        if let Some(session) = negotiating.walk_session.clone() {
            fields.push((adapt::H_SESSION_ID.to_string(), session));
        }
        let status = u16::try_from(status).unwrap_or(0);
        let next = negotiating.feed(Some((status, fields, far.to_vec())));
        // The walk's own answer, or a refusal with no connector to negotiate over: handed on.
        let lends = plane.host.is_some_and(|h| h.lends_connector());
        match next {
            Action::Finish(_) => {
                negotiating.keep(plane, member);
                return Poll::Ready(None);
            }
            Action::Send { .. } if !lends => return Poll::Ready(None),
            next => negotiating.next = Some(next),
        }
    }
    negotiating
        .drive(instance, plane, base, member, timeout_ms)
        .map(Some)
}

/// The stateless request a relayed call's outbound is, for its negotiation.
pub(super) fn original(url: &str, outbound: &crate::call::OutboundCall) -> OutboundRequest {
    OutboundRequest {
        url: url.to_string(),
        headers: outbound.fields.clone(),
        body: outbound.body.clone(),
    }
}
