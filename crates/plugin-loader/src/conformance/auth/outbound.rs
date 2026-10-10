// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S OUTBOUND SCRIPT (`abi/auth/outbound.rs`, v3; ARCHITECT ruling, P5 outbound auth
//! conformance). It drives the OUTBOUND family — `open_outbound`, `fields`, `outbound_ready` —
//! the way the kernel drives a provider's auth binding: the instance opened over the binding's
//! settings (so a need whose target comes from them is declared pinned to it), the style bound to
//! its credential, and the per-request call (THE DESIGN §6.4, §11.6: one memory-ABI call per
//! request, the plugin caches internally) made ticket-less on the caller's thread, as the kernel
//! tries it first. A minting style's token exchange runs on the instance's driver ticket, on
//! `tick`, over the plugin's own need; the suite serves that need with a scripted token endpoint
//! (a connection-table double: no socket, no client), so every exchange is counted and its request
//! read back.
//!
//! Inputs (`conformance.json`, `auth.outbound`: one entry per style the tail declares; every
//! declared style must be driven and no undeclared one may be named):
//!
//! ```json
//! { "style": "<a style the tail declares>",
//!   "credential": "<the literal test credential>" | null,
//!   "settings": { <the one JSON object `open_outbound` reads; the instance opens over it too> },
//!   "head": { "method": "POST", "authority": "host[:port]", "target": "/path[?query]",
//!             "timestamp": <epoch seconds>, "fields": [["name", "value"], ...], "body": "..." },
//!   "expect_fields": [["name", "value"(, flags)], ...],
//!   // a MINTING style only:
//!   "token_endpoint": [ { "expect_request": { "method": "POST", "target": "<the token URL>",
//!                                              "fields_subset": [["name", "value"], ...],
//!                                              "body": "..." | "body_prefix": "..." },
//!                         "respond": { "status": 200, "body": "<the token response>" } }, ... ],
//!   "expires_in": <the first token's lifetime, seconds>,
//!   "refreshed_fields": [["name", "value"(, flags)], ...],
//!   "refusal": "Refused" | "Failed" | "Pending" }
//! ```
//!
//! An ON-DEMAND minting style (one exchanged per call, one token cell per scope, no refresh ahead of
//! expiry, no retry: the RFC 8693 exchange 1.5.5 ran) states `"mint": "on_demand"` and differs:
//!
//! ```json
//! { "mint": "on_demand",
//!   "head": { ..., "extensions": { "scope": "<S>" } },   // the call's extensions blob
//!   "second_scope": "<S2>",
//!   "token_endpoint": [ <S's exchange>, <S2's exchange>, <S's exchange once expired> ],
//!   "expires_in": <S's first token's lifetime, seconds>,
//!   "second_scope_fields": [["name", "value"(, flags)], ...],
//!   "expired_fields": [["name", "value"(, flags)], ...],
//!   "refusal": "Failed" }
//! ```
//!
//! (the third exchange's token must outlive the instant the suite calls S past its first token's
//! expiry: `expires_in` + 1 second from now.)
//!
//! `token_endpoint` lists the exchanges in order (the N-th request answered by the N-th entry; the
//! last answers every later one). `head.fields` are lent only to a style stating
//! `STYLE_NEEDS_HEADERS`, and `head.body` only at `POINT_HEAD_BODY`; a style states exactly one
//! point here (one stating several fails the suite rather than pass the others unseen).
//!
//! THE STEPS, each at its pinned crossings, per style on an instance of its own: `validate` 1,
//! `open` 1, `ready`, `open_outbound` 1 → the handle. A non-minting style: `fields` ×2 (1 each),
//! both writes EXACTLY `expect_fields` (names, bytes, flags, order). A minting style: `fields`
//! before any mint 1 (never a READY answer: nothing is presented that was not minted); `tick` 1 on
//! the driver ticket → EXACTLY ONE token exchange, its request as `expect_request`; `fields` ×2,
//! both `expect_fields`, and still ONE exchange across them (the plugin caches); its refresh due
//! (the `next_tick_ns` the mint tick answered) ahead of `expires_in`; `tick` 1 at that instant →
//! EXACTLY ONE new exchange (refresh-ahead), and the next `fields` writes `refreshed_fields`. Then
//! a FAILING endpoint, on an instance of its own: every exchange answers status 500, the mint
//! `tick` makes exactly one, and `fields` answers the declared `refusal` (its shape recorded in the
//! transcript), `outbound_ready` 0. Every instance: `outbound_ready` 1, `close` 1, and `fields`
//! after `close` 0 (the host refuses an op on a closed instance before any crossing). The inbound
//! and login families the tail does not declare answer REFUSED.
//!
//! AN ON-DEMAND style (ARCHITECT ruling, the on-demand outbound script): `fields`(S) on a ticket
//! before the first `tick` 1 → PENDING, and a second ticket's `fields`(S) while it waits 1 → PENDING,
//! no exchange yet; `tick` → EXACTLY ONE exchange, and both waiting calls READY with the same token
//! (`expect_fields`; the tick is the one first invocation, the two calls resume — SINGLE-FLIGHT); ticket-less
//! `fields`(S) ×2 still ONE exchange; `outbound_ready` 1; a `tick` before S's expiry makes NO
//! exchange (nothing is refreshed ahead); `fields`(S2) on a ticket → PENDING, one `drive`, EXACTLY
//! ONE new exchange (its own cell), READY with `second_scope_fields` (2 first invocations: the call and the drive; the call resumes); `fields`(S) on a
//! ticket at an instant past S's token's expiry → PENDING, one `drive`, EXACTLY ONE new exchange,
//! READY with `expired_fields` (2 first invocations, as above). Then the FAILING endpoint: `fields`(S) on a ticket
//! answers the declared `refusal` after EXACTLY ONE attempt (NO RETRY: the endpoint's hit count is 1).
//!
//! THE RED ARMS ([`red_outbound_wrong_byte`], [`red_outbound_writes_nothing`],
//! [`red_outbound_double_fetch`]): the real door restated with a `fields` that writes one wrong
//! byte, with a `fields` that answers READY having written no field, and with an `open_outbound` that binds a
//! second token cell (so its mint fetches the token twice) and a `fields` that, waiting, arms a
//! second on-demand cell too (so the waiting calls fetch twice), each fail this script.

use std::collections::{HashMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::auth::{
    self, slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldSpan, FieldsIn, FieldsOut,
    IdentifyOut, NamedValue, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut,
    RequestFacts, VerifyIn, MODE_OWN, POINT_HEAD_BODY, STYLE_NEEDS_HEADERS,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, RawOutcome, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::OpsHead;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;

use super::super::{
    bind, called, close, crossings, dispatcher, input, json, open, output, ready_step, real_door,
    validate, Counts, Fold, Leg, Recorder, Restated, Subject,
};
use super::{secret, stated, undeclared, Stated};
use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::{
    load_dropped, load_linked, now_ns, Bind, ConnTable, Dispatcher, Frame, Lent, LinkedRow, Plugin,
    Reply,
};

/// The suite's tick clock at the first `tick` (any instant; the plugin's schedule is read back).
const T0: u64 = 1_000_000_000_000;
/// Nanoseconds in a second.
const NS: u64 = 1_000_000_000;
/// How long a submitted `tick` is awaited.
const TICK_WAIT: Duration = Duration::from_secs(10);
/// The failing endpoint's answer body.
const FAILURE_BODY: &[u8] = b"conformance: the token endpoint is down";

// ---- the inputs ----

/// The request one `fields` call signs.
#[derive(Clone)]
struct Head {
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
    timestamp: u64,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
    /// The call's extensions blob entries (`head.extensions`), in order.
    extensions: Vec<(String, String)>,
}

impl Head {
    /// This head with the extension `key` set to `value` (added when absent).
    fn with_extension(&self, key: &str, value: &str) -> Self {
        let mut h = self.clone();
        match h.extensions.iter_mut().find(|(k, _)| k == key) {
            Some(e) => value.clone_into(&mut e.1),
            None => h.extensions.push((key.to_string(), value.to_string())),
        }
        h
    }

    /// This head at another request instant.
    fn at(&self, timestamp: u64) -> Self {
        let mut h = self.clone();
        h.timestamp = timestamp;
        h
    }

    /// The encoded extensions blob.
    fn extensions_blob(&self) -> Vec<u8> {
        if self.extensions.is_empty() {
            return Vec::new();
        }
        let entries: Vec<(&str, &[u8])> = self
            .extensions
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_bytes()))
            .collect();
        extensions::encode(&entries)
    }
}

/// What one token request must be.
struct ExpectRequest {
    method: String,
    target: String,
    fields_subset: Vec<(String, String)>,
    body: Option<String>,
    body_prefix: Option<String>,
}

/// One scripted exchange: the request it expects and the answer it gives.
struct Exchange {
    expect: ExpectRequest,
    status: u32,
    body: Vec<u8>,
}

/// A minting style's token endpoint script.
struct Minting {
    exchanges: Vec<Exchange>,
    expires_in: u64,
    /// Tick-driven: the refreshed token's fields. On demand: unused.
    refreshed: String,
    refusal: String,
    /// `"mint": "on_demand"`: minted per call, one cell per scope.
    on_demand: Option<OnDemand>,
}

/// An on-demand style's second scope and the fields its later exchanges write.
struct OnDemand {
    second_scope: String,
    second: String,
    expired: String,
}

/// One `auth.outbound` entry.
struct Style {
    style: String,
    credential: Option<Vec<u8>>,
    // settings-leak-lint: allow — NON-PROJECTION conformance-harness type: one `auth.outbound`
    // entry's settings, handed to the plugin under test; never serialized and never served.
    settings: Vec<u8>,
    head: Head,
    expect: String,
    minting: Option<Minting>,
}

fn str_of<'a>(v: &'a serde_json::Value, what: &str) -> &'a str {
    v.as_str()
        .unwrap_or_else(|| panic!("conformance.json: {what} must be a string"))
}

fn pairs(v: &serde_json::Value, what: &str) -> Vec<(String, String)> {
    match v {
        serde_json::Value::Null => Vec::new(),
        serde_json::Value::Array(a) => a
            .iter()
            .map(|p| {
                let p = p.as_array().unwrap_or_else(|| {
                    panic!("conformance.json: {what} holds [name, value] pairs")
                });
                (
                    str_of(&p[0], what).to_string(),
                    str_of(&p[1], what).to_string(),
                )
            })
            .collect(),
        _ => panic!("conformance.json: {what} is an array of [name, value] pairs"),
    }
}

/// The transcript's spelling of written fields: `name: value (flags=N)`, in order.
fn listing<'a>(fields: impl Iterator<Item = (&'a [u8], &'a [u8], u32)>) -> String {
    fields
        .map(|(n, v, f)| {
            format!(
                "{}: {} (flags={f})",
                String::from_utf8_lossy(n),
                String::from_utf8_lossy(v)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The answer a `fields` call writing exactly `v`'s fields reads as.
fn expected(v: &serde_json::Value, what: &str) -> String {
    let a = v.as_array().unwrap_or_else(|| {
        panic!("conformance.json: {what} is an array of [name, value(, flags)]")
    });
    let owned: Vec<(Vec<u8>, Vec<u8>, u32)> = a
        .iter()
        .map(|p| {
            let p = p
                .as_array()
                .unwrap_or_else(|| panic!("conformance.json: {what} holds [name, value(, flags)]"));
            (
                str_of(&p[0], what).as_bytes().to_vec(),
                str_of(&p[1], what).as_bytes().to_vec(),
                match p.get(2) {
                    // No third element: the field carries no flag.
                    None => 0,
                    Some(f) => f
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .unwrap_or_else(|| {
                            panic!("conformance.json: {what}'s flags must be a u32")
                        }),
                },
            )
        })
        .collect();
    // A style whose expectation is no field at all would pass a door that writes nothing: every
    // outbound style presents something (a header, a query parameter), so an empty list is refused
    // here rather than let the script compare nothing with nothing.
    assert!(
        !owned.is_empty(),
        "conformance.json: {what} is empty: an outbound style writes at least one field, and an \
         empty expectation would pass a door that writes none"
    );
    format!(
        "Ready fields=[{}]",
        listing(
            owned
                .iter()
                .map(|(n, v, f)| (n.as_slice(), v.as_slice(), *f))
        )
    )
}

fn settings_of(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::Null => b"{}".to_vec(),
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        other => other.to_string().into_bytes(),
    }
}

impl Style {
    fn parse(v: &serde_json::Value) -> Self {
        let style = str_of(&v["style"], "auth.outbound[].style").to_string();
        let h = &v["head"];
        assert!(
            h.is_object(),
            "conformance.json: style `{style}` has no `head`"
        );
        let target = str_of(&h["target"], "head.target");
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (target.to_string(), None),
        };
        let head = Head {
            method: str_of(&h["method"], "head.method").to_string(),
            authority: str_of(&h["authority"], "head.authority").to_string(),
            path,
            query,
            timestamp: h["timestamp"].as_u64().unwrap_or_else(|| {
                panic!("conformance.json: style `{style}`'s head.timestamp must be epoch seconds")
            }),
            fields: pairs(&h["fields"], "head.fields"),
            body: h["body"].as_str().unwrap_or("").as_bytes().to_vec(),
            extensions: match &h["extensions"] {
                serde_json::Value::Null => Vec::new(),
                serde_json::Value::Object(m) => m
                    .iter()
                    .map(|(k, v)| (k.clone(), str_of(v, "head.extensions").to_string()))
                    .collect(),
                _ => panic!("conformance.json: style `{style}`'s head.extensions is an object"),
            },
        };
        let on_demand = match v["mint"].as_str() {
            None => false,
            Some("on_demand") => true,
            Some(other) => panic!(
                "conformance.json: style `{style}` states mint `{other}`; the outbound script \
                 knows a tick-driven style (no `mint`) and `on_demand`"
            ),
        };
        let minting = match &v["token_endpoint"] {
            serde_json::Value::Null => None,
            serde_json::Value::Array(a) => {
                assert!(
                    !a.is_empty(),
                    "conformance.json: style `{style}`'s token_endpoint is empty"
                );
                let exchanges = a
                    .iter()
                    .map(|x| {
                        let e = &x["expect_request"];
                        let r = &x["respond"];
                        Exchange {
                            expect: ExpectRequest {
                                method: str_of(&e["method"], "expect_request.method").to_string(),
                                target: str_of(&e["target"], "expect_request.target").to_string(),
                                fields_subset: pairs(
                                    &e["fields_subset"],
                                    "expect_request.fields_subset",
                                ),
                                body: e["body"].as_str().map(String::from),
                                body_prefix: e["body_prefix"].as_str().map(String::from),
                            },
                            status: r["status"]
                                .as_u64()
                                .unwrap_or_else(|| panic!("conformance.json: respond.status"))
                                as u32,
                            body: str_of(&r["body"], "respond.body").as_bytes().to_vec(),
                        }
                    })
                    .collect();
                let on_demand = on_demand.then(|| {
                    assert!(
                        a.len() >= 3,
                        "conformance.json: on-demand style `{style}`'s token_endpoint scripts \
                         three exchanges (S, the second scope, S once expired)"
                    );
                    OnDemand {
                        second_scope: str_of(&v["second_scope"], "second_scope").to_string(),
                        second: expected(&v["second_scope_fields"], "second_scope_fields"),
                        expired: expected(&v["expired_fields"], "expired_fields"),
                    }
                });
                Some(Minting {
                    exchanges,
                    expires_in: v["expires_in"].as_u64().unwrap_or_else(|| {
                        panic!("conformance.json: minting style `{style}` states `expires_in`")
                    }),
                    refreshed: if on_demand.is_some() {
                        String::new()
                    } else {
                        expected(&v["refreshed_fields"], "refreshed_fields")
                    },
                    refusal: str_of(&v["refusal"], "refusal").to_string(),
                    on_demand,
                })
            }
            _ => panic!("conformance.json: style `{style}`'s token_endpoint is an array"),
        };
        assert!(
            !on_demand || minting.is_some(),
            "conformance.json: on-demand style `{style}` scripts its token_endpoint"
        );
        Style {
            credential: v["credential"].as_str().map(|c| c.as_bytes().to_vec()),
            settings: settings_of(&v["settings"]),
            head,
            expect: expected(&v["expect_fields"], "expect_fields"),
            minting,
            style,
        }
    }
}

// ---- the token endpoint: the host's connection table, scripted ----

/// One request the plugin sent over its need.
#[derive(Debug, Clone)]
struct Sent {
    target: String,
    method: String,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Each open connection's reply, piece by piece, with its bytes.
type Replies = HashMap<ConnId, VecDeque<(Piece, Vec<u8>)>>;

/// A connection table whose needs are framed: each open is ONE token request, recorded, and
/// answered by the script's next reply, one piece per read.
#[derive(Default)]
struct Endpoint {
    slab: ConnSlab<()>,
    answers: Vec<(u32, Vec<u8>)>,
    sent: Mutex<Vec<Sent>>,
    replies: Mutex<Replies>,
}

fn piece(kind: PieceKind, len: usize, status: Option<u32>) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: kind != PieceKind::Fields,
        status: None,
        status_code: status,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
    }
}

impl Endpoint {
    fn new(answers: Vec<(u32, Vec<u8>)>) -> Self {
        Self {
            answers,
            ..Self::default()
        }
    }

    fn count(&self) -> usize {
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Every exchange so far, each judged against its expected request.
    fn report(&self, script: &[Exchange]) -> String {
        let sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
        let judged: Vec<String> = sent
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let want = &script[i.min(script.len() - 1)].expect;
                let mut off = Vec::new();
                if s.method != want.method {
                    off.push("method");
                }
                if s.target != want.target {
                    off.push("target");
                }
                if !want
                    .fields_subset
                    .iter()
                    .all(|w| s.fields.iter().any(|f| f == w))
                {
                    off.push("fields");
                }
                if want.body.as_ref().is_some_and(|b| s.body != b.as_bytes()) {
                    off.push("body");
                }
                if want
                    .body_prefix
                    .as_ref()
                    .is_some_and(|b| !s.body.starts_with(b.as_bytes()))
                {
                    off.push("body_prefix");
                }
                if off.is_empty() {
                    "ok".to_string()
                } else {
                    format!("off({})", off.join(","))
                }
            })
            .collect();
        format!("exchanges={} [{}]", sent.len(), judged.join(", "))
    }
}

impl DeclaredConns for Endpoint {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        _trust: Option<&str>,
    ) -> Result<(), ConnError> {
        // A `target_from` that resolved to nothing is refused, as the connector refuses it.
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

impl Conns for Endpoint {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        let n = {
            let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
            sent.push(Sent {
                target: desc.target.to_owned(),
                method: String::from_utf8_lossy(desc.method).into_owned(),
                fields: desc
                    .fields
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), String::from_utf8_lossy(v).into_owned()))
                    .collect(),
                body: desc.body.to_vec(),
            });
            sent.len()
        };
        let (status, body) = self.answers[(n - 1).min(self.answers.len() - 1)].clone();
        let id = self.slab.insert(caller, need, ())?;
        self.replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id,
                VecDeque::from([
                    (piece(PieceKind::Fields, 0, Some(status)), Vec::new()),
                    (piece(PieceKind::Body, body.len(), None), body),
                    (piece(PieceKind::Completion, 0, None), Vec::new()),
                ]),
            );
        Ok(id)
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Ok(b.len())
    }
    fn read(&self, c: InstanceId, id: ConnId, _: u64, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        let mut replies = self.replies.lock().unwrap_or_else(|e| e.into_inner());
        let queue = replies.get_mut(&id).ok_or(ConnError::Closed)?;
        let (p, bytes) = queue.pop_front().ok_or(ConnError::Closed)?;
        if bytes.len() > buf.len() {
            // The rest of a body larger than the reader's buffer is the next piece.
            let (now, later) = bytes.split_at(buf.len());
            buf.copy_from_slice(now);
            queue.push_front((piece(PieceKind::Body, later.len(), None), later.to_vec()));
            return Ok(Piece {
                len: now.len(),
                end: false,
                ..p
            });
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(p)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        self.slab.remove(c, id).map(|_| ())
    }
}

// ---- the calls ----

fn abi_str(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

const NO_STR: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The leg's instance of `door`, through the ONE loader, on `conns` (a minting style's endpoint).
fn load_leg(
    s: &Subject,
    leg: Leg,
    door: DoorFn,
    d: &Dispatcher,
    instance: &str,
    conns: Option<Arc<dyn DeclaredConns>>,
) -> Plugin<Auth> {
    // A minting style serves its own need on the scripted endpoint; one that mints nothing is
    // bound as the subject binds any door (its needs, if it declares any, on the subject's table).
    let b = match conns {
        Some(table) => Bind {
            conns: ConnTable::Host(table),
            ..bind(d, instance)
        },
        None => s.bind(d, instance),
    };
    match leg {
        Leg::Linked => load_linked::<Auth>(
            &LinkedRow::of(door).unwrap_or_else(|e| panic!("the linked door is refused: {e}")),
            b,
        ),
        Leg::Dropped => load_dropped::<Auth>(&s.cdylib(), &s.stated(), b),
    }
    .unwrap_or_else(|e| panic!("the auth door loads ({leg:?}): {e}"))
}

/// `open_outbound` of `x`: its answer and the handle.
fn open_outbound(p: &Plugin<Auth>, x: &Style) -> (String, u64) {
    let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(input(), output());
    f.input.style = abi_str(x.style.as_bytes());
    f.input.credential = x.credential.as_deref().map_or(Blob::ABSENT, secret);
    f.input.settings = json(&x.settings);
    let c = p.call(slot::OPEN_OUTBOUND, &mut f);
    (called(&c), f.out.handle)
}

/// `outbound_ready` of `handle`.
fn ready_fact(p: &Plugin<Auth>, handle: u64) -> String {
    let mut f: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(input(), output());
    f.input.handle = handle;
    let c = p.call(slot::OUTBOUND_READY, &mut f);
    format!("{} ready={}", called(&c), f.out.ready)
}

/// THE MEMORY ONE `fields` call lends the plugin: the host's field buffer and spans, the head's
/// lines, its body and its extensions blob. Lent whole to a call on a ticket (the dispatcher keeps
/// it alive until the op completes), so its pointers stay valid however the call ends.
struct Lend {
    buf: Vec<u8>,
    spans: Vec<FieldSpan>,
    names: Vec<Vec<u8>>,
    values: Vec<Vec<u8>>,
    lines: Vec<NamedValue>,
    request: [Vec<u8>; 4],
    body: Vec<u8>,
    ext: Vec<u8>,
}

// SAFETY: the raw pointers in `lines` point into `names` and `values`, owned by the same `Lend`;
// nothing mutates a `Lend` once its frame is built but the plugin's writes into `buf` and `spans`,
// which the host reads only after the op completes.
unsafe impl Send for Lend {}
// SAFETY: as above.
unsafe impl Sync for Lend {}

impl Lend {
    fn new(h: &Head) -> Box<Self> {
        let blank = FieldSpan {
            name: Span { offset: 0, len: 0 },
            value: Span { offset: 0, len: 0 },
            flags: 0,
            _reserved: 0,
        };
        let mut l = Box::new(Self {
            buf: vec![0_u8; auth::FIELDS_BUF_BYTES],
            spans: vec![blank; auth::FIELDS_MAX as usize],
            names: h
                .fields
                .iter()
                .map(|(n, _)| n.as_bytes().to_vec())
                .collect(),
            values: h
                .fields
                .iter()
                .map(|(_, v)| v.as_bytes().to_vec())
                .collect(),
            lines: Vec::new(),
            request: [
                h.method.as_bytes().to_vec(),
                h.authority.as_bytes().to_vec(),
                h.path.as_bytes().to_vec(),
                h.query.as_deref().unwrap_or("").as_bytes().to_vec(),
            ],
            body: h.body.clone(),
            ext: h.extensions_blob(),
        });
        l.lines = l
            .names
            .iter()
            .zip(&l.values)
            .map(|(n, v)| NamedValue {
                name: abi_str(n),
                value: Blob {
                    ptr: v.as_ptr(),
                    len: v.len(),
                    fmt: BLOB_OCTETS,
                    flags: 0,
                },
            })
            .collect();
        l
    }

    /// The `fields` input over this memory, at the style's one point.
    fn input(&mut self, handle: u64, h: &Head, flags: u32, point: u32) -> FieldsIn {
        let mut i: FieldsIn = input();
        i.handle = handle;
        i.mode = MODE_OWN;
        i.point = point;
        i.request = RequestFacts {
            method: abi_str(&self.request[0]),
            authority: abi_str(&self.request[1]),
            canonical_path: abi_str(&self.request[2]),
            query: if h.query.is_some() {
                abi_str(&self.request[3])
            } else {
                NO_STR
            },
            timestamp: h.timestamp,
        };
        i.field_buf = self.buf.as_mut_ptr();
        i.field_buf_cap = self.buf.len();
        i.fields = self.spans.as_mut_ptr();
        i.fields_cap = self.spans.len() as u32;
        if flags & STYLE_NEEDS_HEADERS != 0 {
            i.headers = self.lines.as_ptr();
            i.headers_len = self.lines.len();
        }
        if point == POINT_HEAD_BODY {
            i.body = Blob {
                ptr: self.body.as_ptr(),
                len: self.body.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
        }
        if !self.ext.is_empty() {
            i.head.extensions = Blob {
                ptr: self.ext.as_ptr(),
                len: self.ext.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
        }
        i
    }

    /// The transcript's line for an answer: on READY exactly what was written.
    fn answer(
        &self,
        outcome: Outcome,
        error: Option<&[u8]>,
        short: bool,
        out: &FieldsOut,
    ) -> String {
        if outcome != Outcome::Ready {
            let text = error.map(String::from_utf8_lossy).unwrap_or_default();
            let short = if short { " short" } else { "" };
            return format!("{outcome:?}{short} {text}");
        }
        let n = (out.fields_len as usize).min(self.spans.len());
        format!(
            "Ready fields=[{}]",
            listing(self.spans[..n].iter().map(|s| (
                at(&self.buf, s.name),
                at(&self.buf, s.value),
                s.flags
            )))
        )
    }
}

/// ONE `fields` call ("sign"): ticket-less, at the style's one point, over `h`, the host's
/// starting buffers. The answer, and on READY exactly what it wrote.
fn sign(p: &Plugin<Auth>, handle: u64, h: &Head, flags: u32, point: u32) -> String {
    let mut lend = Lend::new(h);
    let mut f: Frame<FieldsIn, FieldsOut> =
        Frame::new(lend.input(handle, h, flags, point), output());
    let c = p.call(slot::FIELDS, &mut f);
    lend.answer(c.outcome, c.error.as_deref(), c.recall.is_some(), &f.out)
}

/// ONE `fields` call ON A TICKET (as the host submits a call the plugin may make wait): minted on
/// the dispatcher, its memory lent to the op. Its reply, and the memory to read the answer from.
struct OnTicket {
    reply: Reply<FieldsIn, FieldsOut>,
    lend: Arc<Lend>,
    /// The answer, when it came before the suite asked whether the call waits.
    early: Option<String>,
}

/// How long a ticket's `fields` may wait before its deadline (well past every wait here).
const FIELDS_DEADLINE: Duration = Duration::from_secs(60);

fn submit_fields(
    p: &Plugin<Auth>,
    d: &Dispatcher,
    handle: u64,
    h: &Head,
    flags: u32,
    point: u32,
) -> OnTicket {
    let ticket = d.mint(0).expect("a request ticket is minted");
    let mut lend = Lend::new(h);
    let input = lend.input(handle, h, flags, point);
    let lend: Arc<Lend> = Arc::from(lend);
    let deadline =
        now_ns().saturating_add(u64::try_from(FIELDS_DEADLINE.as_nanos()).unwrap_or(u64::MAX));
    let reply = d.submit_lent(
        p,
        ticket,
        slot::FIELDS,
        Frame::new(input, output()),
        DeadlineClass::Call,
        deadline,
        Arc::clone(&lend) as Lent,
    );
    OnTicket {
        reply,
        lend,
        early: None,
    }
}

impl OnTicket {
    /// Whether the call is still waiting (PENDING); an answer that already came is kept.
    fn waiting(&mut self) -> bool {
        match self.reply.wait(Duration::ZERO) {
            None => true,
            Some(done) => {
                self.early = Some(self.read(&done));
                false
            }
        }
    }

    fn read(&self, done: &crate::dispatch::Done<FieldsIn, FieldsOut>) -> String {
        match done.frame.as_ref() {
            Some(f) => self
                .lend
                .answer(done.outcome, done.error.as_deref(), done.short, &f.out),
            None => format!("{:?} (no frame)", done.outcome),
        }
    }

    /// The answer once the op completes (`no answer` past [`TICK_WAIT`]).
    fn answered(self) -> String {
        if let Some(a) = self.early {
            return a;
        }
        match self.reply.wait(TICK_WAIT) {
            None => {
                // The op runs on; its memory stays with it.
                self.reply.detach();
                "no answer".to_string()
            }
            Some(done) => self.read(&done),
        }
    }
}

/// Wait until `counter` has advanced past `from` by `n` first-invocation crossings (or
/// [`TICK_WAIT`] passed).
fn crossed(counter: &Counts<'_>, from: u64, n: u64) {
    let until = std::time::Instant::now() + TICK_WAIT;
    while counter.read().0 < from + n && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The wall clock, epoch seconds.
fn epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The bytes `sp` names in the host's field buffer.
fn at(buf: &[u8], sp: Span) -> &[u8] {
    buf.get(sp.offset as usize..sp.offset as usize + sp.len as usize)
        .unwrap_or(&b"<out of the buffer>"[..])
}

/// `tick` at `now_ns` on the instance's driver ticket, awaited: its outcome and `next_tick_ns`.
fn tick_driver(p: &Plugin<Auth>, d: &Dispatcher, driver: Ticket, now_ns: u64) -> (String, u64) {
    let reply = d.tick(p, driver, now_ns);
    let Some(done) = reply.wait(TICK_WAIT) else {
        return ("no answer".to_string(), 0);
    };
    let next = done.frame.as_ref().map_or(0, |f| f.out.next_tick_ns);
    (format!("{:?}", done.outcome), next)
}

// ---- the script ----

/// The style's one point, as the tail states it.
fn point_of(st: &Stated, style: &str) -> (u32, u32) {
    let (_, flags, points) = st
        .styles
        .iter()
        .find(|(n, _, _)| n == style)
        .unwrap_or_else(|| {
            panic!("conformance.json drives style `{style}`, which the tail does not declare")
        });
    assert!(
        points.count_ones() == 1,
        "style `{style}` states auth points {points:#x}: the outbound script drives a style at \
         exactly one point, and fails rather than pass the others unseen"
    );
    (*flags, *points)
}

/// THE OUTBOUND SCRIPT over `door` (the subject's, or a RED arm's restated one), reached by `leg`.
pub(super) fn fold(s: &Subject, leg: Leg, door: DoorFn, st: &Stated) -> Fold {
    let k = s.kind_inputs("auth");
    let styles: Vec<Style> = k["outbound"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "conformance.json: the tail declares the outbound family; `auth.outbound` must \
                 drive its styles"
            )
        })
        .iter()
        .map(Style::parse)
        .collect();
    for (name, _, _) in &st.styles {
        assert!(
            styles.iter().any(|x| &x.style == name),
            "the tail declares style `{name}`; conformance.json's auth.outbound drives no entry \
             for it"
        );
    }
    let mut fold = Fold::new();
    for (i, x) in styles.iter().enumerate() {
        let (flags, point) = point_of(st, &x.style);
        let label = |what: &str| format!("outbound {} #{i}: {what}", x.style);
        let endpoint = x.minting.as_ref().map(|m| {
            Arc::new(Endpoint::new(
                m.exchanges
                    .iter()
                    .map(|e| (e.status, e.body.clone()))
                    .collect(),
            ))
        });
        let d = dispatcher();
        let conns = endpoint.clone().map(|e| e as Arc<dyn DeclaredConns>);
        let p = load_leg(s, leg, door, &d, "auth-outbound", conns);
        let mut r = Recorder::new(crossings(&p));
        if i == 0 {
            r.line("outbound facts", 0, || {
                format!(
                    "{:?} {} max_inflight={} caps={} styles={:?}",
                    p.kind(),
                    p.name(),
                    p.max_inflight(),
                    st.caps,
                    st.styles
                )
            });
        }
        r.line(&label("validate"), 1, || called(&validate(&p, &x.settings)));
        r.line(&label("open"), 1, || called(&open(&p, &x.settings)));
        ready_step(&mut r, s, &p, &d);
        let handle = r.step(&label("open_outbound"), 1, || open_outbound(&p, x));
        let signed = || sign(&p, handle, &x.head, flags, point);
        match (&x.minting, &endpoint) {
            (Some(m), Some(e)) if m.on_demand.is_some() => {
                let od = m.on_demand.as_ref().expect("on demand");
                let counter = crossings(&p);
                let driver = d
                    .driver(&p, 0)
                    .expect("the instance's driver ticket is minted");
                // SINGLE-FLIGHT: two calls wait on S before anything drives the exchange.
                let first = r.step(&label("fields on a ticket, before any exchange"), 1, || {
                    let from = counter.read().0;
                    let mut t = submit_fields(&p, &d, handle, &x.head, flags, point);
                    crossed(&counter, from, 1);
                    let waits = if t.waiting() {
                        "waiting"
                    } else {
                        "answered at once"
                    };
                    (format!("{waits} exchanges={}", e.count()), t)
                });
                let second = r.step(
                    &label("fields on a second ticket, while the first waits"),
                    1,
                    || {
                        let from = counter.read().0;
                        let mut t = submit_fields(&p, &d, handle, &x.head, flags, point);
                        crossed(&counter, from, 1);
                        let waits = if t.waiting() {
                            "waiting"
                        } else {
                            "answered at once"
                        };
                        (format!("{waits} exchanges={}", e.count()), t)
                    },
                );
                r.line(&label("tick: the exchange"), 1, || {
                    let (line, _) = tick_driver(&p, &d, driver, T0);
                    let a = first.answered();
                    let b = second.answered();
                    format!("{line} exchanges={} | {a} | {b}", e.count())
                });
                r.line(&label("fields #1"), 1, signed);
                r.line(&label("fields #2"), 1, signed);
                r.line(&label("exchanges across the two calls"), 0, || {
                    e.report(&m.exchanges)
                });
                r.line(&label("outbound_ready"), 1, || ready_fact(&p, handle));
                r.line(&label("tick before expiry"), 1, || {
                    let at = T0.saturating_add(m.expires_in / 2 * NS);
                    let (line, _) = tick_driver(&p, &d, driver, at);
                    format!("{line} exchanges={}", e.count())
                });
                let s2 = x.head.with_extension(auth::EXT_SCOPE, &od.second_scope);
                r.line(&label("fields on a ticket, the second scope"), 2, || {
                    let a = submit_fields(&p, &d, handle, &s2, flags, point).answered();
                    format!("{a} exchanges={}", e.count())
                });
                let expired = x.head.at(epoch_now().saturating_add(m.expires_in + 1));
                r.line(
                    &label("fields on a ticket, past the first token's expiry"),
                    2,
                    || {
                        let a = submit_fields(&p, &d, handle, &expired, flags, point).answered();
                        format!("{a} exchanges={}", e.count())
                    },
                );
                r.line(&label("exchanges after expiry"), 0, || {
                    e.report(&m.exchanges)
                });
            }
            (Some(m), Some(e)) => {
                r.line(&label("fields before the first mint"), 1, signed);
                let driver = d
                    .driver(&p, 0)
                    .expect("the instance's driver ticket is minted");
                let next = r.step(&label("tick: the first mint"), 1, || {
                    let (line, next) = tick_driver(&p, &d, driver, T0);
                    (format!("{line} exchanges={}", e.count()), next)
                });
                r.line(&label("fields #1"), 1, signed);
                r.line(&label("fields #2"), 1, signed);
                r.line(&label("exchanges across the two calls"), 0, || {
                    e.report(&m.exchanges)
                });
                r.line(&label("outbound_ready"), 1, || ready_fact(&p, handle));
                let ahead = next > T0 && next <= T0.saturating_add(m.expires_in * NS);
                r.line(&label("refresh due ahead of expiry"), 0, || {
                    format!("refresh_ahead={ahead}")
                });
                r.line(&label("tick: the refresh"), 1, || {
                    let (line, _) = tick_driver(&p, &d, driver, next.max(T0));
                    format!("{line} exchanges={}", e.count())
                });
                r.line(&label("fields after the refresh"), 1, signed);
                r.line(&label("exchanges after the refresh"), 0, || {
                    e.report(&m.exchanges)
                });
            }
            _ => {
                r.line(&label("fields #1"), 1, signed);
                r.line(&label("fields #2"), 1, signed);
                r.line(&label("outbound_ready"), 1, || ready_fact(&p, handle));
            }
        }
        if i == 0 {
            if st.caps & auth::CAP_INBOUND == 0 {
                r.line("verify undeclared", 1, || {
                    undeclared::<VerifyIn, IdentifyOut>(&p, slot::VERIFY)
                });
            }
            r.line("begin_login undeclared", 1, || {
                undeclared::<BeginLoginIn, BeginLoginOut>(&p, slot::BEGIN_LOGIN)
            });
            r.line("complete_login undeclared", 1, || {
                undeclared::<CompleteLoginIn, IdentifyOut>(&p, slot::COMPLETE_LOGIN)
            });
        }
        r.line(&label("close"), 1, || called(&close(&p)));
        // 0: a closed instance answers without a crossing.
        r.line(&label("fields after close"), 0, signed);
        fold.extend(r.fold());

        // THE FAILING ENDPOINT, on an instance of its own: every exchange answers 500.
        if x.minting.as_ref().is_some_and(|m| m.on_demand.is_some()) {
            let failing = Arc::new(Endpoint::new(vec![(500, FAILURE_BODY.to_vec())]));
            let d = dispatcher();
            let q = load_leg(
                s,
                leg,
                door,
                &d,
                "auth-outbound-failing",
                Some(failing.clone() as Arc<dyn DeclaredConns>),
            );
            let mut rq = Recorder::new(crossings(&q));
            rq.line(&label("failing endpoint: open"), 1, || {
                called(&open(&q, &x.settings))
            });
            ready_step(&mut rq, s, &q, &d);
            let hq = rq.step(&label("failing endpoint: open_outbound"), 1, || {
                open_outbound(&q, x)
            });
            let driver = d
                .driver(&q, 0)
                .expect("the instance's driver ticket is minted");
            rq.line(&label("failing endpoint: tick"), 1, || {
                let (line, _) = tick_driver(&q, &d, driver, T0);
                format!("{line} exchanges={}", failing.count())
            });
            rq.line(&label("failing endpoint: fields"), 2, || {
                submit_fields(&q, &d, hq, &x.head, flags, point).answered()
            });
            // NO RETRY: whatever the instance would do next on its own, it does not exchange again.
            rq.line(&label("failing endpoint: attempts"), 0, || {
                std::thread::sleep(Duration::from_millis(200));
                format!("exchanges={}", failing.count())
            });
            rq.line(&label("failing endpoint: close"), 1, || called(&close(&q)));
            fold.extend(rq.fold());
        } else if x.minting.is_some() {
            let failing = Arc::new(Endpoint::new(vec![(500, FAILURE_BODY.to_vec())]));
            let d = dispatcher();
            let q = load_leg(
                s,
                leg,
                door,
                &d,
                "auth-outbound-failing",
                Some(failing.clone() as Arc<dyn DeclaredConns>),
            );
            let mut rq = Recorder::new(crossings(&q));
            rq.line(&label("failing endpoint: open"), 1, || {
                called(&open(&q, &x.settings))
            });
            ready_step(&mut rq, s, &q, &d);
            let hq = rq.step(&label("failing endpoint: open_outbound"), 1, || {
                open_outbound(&q, x)
            });
            let driver = d
                .driver(&q, 0)
                .expect("the instance's driver ticket is minted");
            rq.line(&label("failing endpoint: tick"), 1, || {
                let (line, _) = tick_driver(&q, &d, driver, T0);
                format!("{line} exchanges={}", failing.count())
            });
            rq.line(&label("failing endpoint: fields"), 1, || {
                sign(&q, hq, &x.head, flags, point)
            });
            rq.line(&label("failing endpoint: outbound_ready"), 1, || {
                ready_fact(&q, hq)
            });
            rq.line(&label("failing endpoint: close"), 1, || called(&close(&q)));
            fold.extend(rq.fold());
        }
    }
    contract(&fold, &styles);
    fold
}

/// THE OUTBOUND CONTRACT over the fold, so two equal folds of failures cannot pass.
fn contract(fold: &Fold, styles: &[Style]) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    for (i, x) in styles.iter().enumerate() {
        let l = |what: &str| format!("outbound {} #{i}: {what}", x.style);
        let od = x.minting.as_ref().and_then(|m| m.on_demand.as_ref());
        // The exchange counts first: a door that fetched twice may also have written another
        // token, and the count is the finding.
        if let (Some(m), Some(od)) = (&x.minting, od) {
            on_demand_contract(fold, i, x, m, od);
        } else if x.minting.is_some() {
            assert!(
                at(&l("tick: the first mint")).ends_with(" exchanges=1"),
                "{}: the first mint is exactly ONE token exchange: {}",
                l("tick: the first mint"),
                at(&l("tick: the first mint"))
            );
            assert_eq!(
                at(&l("exchanges across the two calls")),
                "exchanges=1 [ok]",
                "{}: ONE token exchange across the two calls, its request as expect_request \
                 (the plugin caches: one memory-ABI call per request)",
                l("exchanges across the two calls")
            );
        }
        for what in ["validate", "open", "open_outbound", "close"] {
            assert!(
                at(&l(what)).starts_with("Ready "),
                "{}: {}",
                l(what),
                at(&l(what))
            );
        }
        for what in ["fields #1", "fields #2"] {
            assert_eq!(
                at(&l(what)),
                x.expect,
                "{}: the fields written are not exactly expect_fields",
                l(what)
            );
        }
        assert!(
            at(&l("outbound_ready")).starts_with("Ready ")
                && at(&l("outbound_ready")).ends_with(" ready=1"),
            "{}: {}",
            l("outbound_ready"),
            at(&l("outbound_ready"))
        );
        assert!(
            !at(&l("fields after close")).starts_with("Ready"),
            "a closed instance writes no fields: {}",
            at(&l("fields after close"))
        );
        let Some(m) = x.minting.as_ref().filter(|m| m.on_demand.is_none()) else {
            continue;
        };
        assert!(
            !at(&l("fields before the first mint")).starts_with("Ready"),
            "{}: nothing is presented before a token is minted: {}",
            l("fields before the first mint"),
            at(&l("fields before the first mint"))
        );
        assert_eq!(
            at(&l("refresh due ahead of expiry")),
            "refresh_ahead=true",
            "the mint tick schedules its refresh after now and no later than expires_in ({}s)",
            m.expires_in
        );
        assert!(
            at(&l("tick: the refresh")).ends_with(" exchanges=2"),
            "{}: the refresh is exactly ONE new exchange: {}",
            l("tick: the refresh"),
            at(&l("tick: the refresh"))
        );
        assert_eq!(
            at(&l("fields after the refresh")),
            m.refreshed,
            "{}: the refreshed token is written (refreshed_fields)",
            l("fields after the refresh")
        );
        assert_eq!(
            at(&l("exchanges after the refresh")),
            "exchanges=2 [ok, ok]",
            "{}",
            l("exchanges after the refresh")
        );
        assert!(
            at(&l("failing endpoint: tick")).ends_with(" exchanges=1"),
            "{}: {}",
            l("failing endpoint: tick"),
            at(&l("failing endpoint: tick"))
        );
        let refused = at(&l("failing endpoint: fields"));
        assert!(
            refused.starts_with(&format!("{} ", m.refusal)) || refused == m.refusal,
            "{}: a failed mint answers the declared refusal `{}`: {refused}",
            l("failing endpoint: fields"),
            m.refusal
        );
        assert!(
            at(&l("failing endpoint: outbound_ready")).ends_with(" ready=0"),
            "{}: {}",
            l("failing endpoint: outbound_ready"),
            at(&l("failing endpoint: outbound_ready"))
        );
    }
    for st in fold.iter().filter(|s| s.label.ends_with(" undeclared")) {
        assert!(
            st.answer.starts_with("Refused "),
            "{}: {}",
            st.label,
            st.answer
        );
    }
}

/// THE ON-DEMAND CONTRACT (ARCHITECT ruling): single-flight, a cell per scope, no refresh ahead,
/// a re-mint on demand once expired, no retry. The exchange counts first.
fn on_demand_contract(fold: &Fold, i: usize, x: &Style, m: &Minting, od: &OnDemand) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.clone())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    let l = |what: &str| format!("outbound {} #{i}: {what}", x.style);
    let exchange = at(&l("tick: the exchange"));
    assert!(
        exchange.contains(" exchanges=1 |"),
        "{}: exactly ONE token exchange for the calls waiting on one scope (single-flight): \
         {exchange}",
        l("tick: the exchange")
    );
    for what in [
        "fields on a ticket, before any exchange",
        "fields on a second ticket, while the first waits",
    ] {
        assert_eq!(
            at(&l(what)),
            "waiting exchanges=0",
            "{}: a call on a ticket with no token waits (PENDING) for the exchange it arms, and \
             nothing is exchanged before the instance is driven",
            l(what)
        );
    }
    assert_eq!(
        at(&l("exchanges across the two calls")),
        "exchanges=1 [ok]",
        "{}: ONE token exchange across the waiting and the two later calls, its request as \
         expect_request",
        l("exchanges across the two calls")
    );
    assert!(
        at(&l("tick before expiry")).ends_with(" exchanges=1"),
        "{}: an on-demand token is never refreshed ahead of expiry, so exactly ONE exchange \
         stands: {}",
        l("tick before expiry"),
        at(&l("tick before expiry"))
    );
    let second = at(&l("fields on a ticket, the second scope"));
    assert!(
        second.ends_with(" exchanges=2"),
        "{}: a second scope is its own cell, exactly ONE new exchange: {second}",
        l("fields on a ticket, the second scope")
    );
    let expired = at(&l("fields on a ticket, past the first token's expiry"));
    assert!(
        expired.ends_with(" exchanges=3"),
        "{}: an expired token is exchanged again on demand, exactly ONE new exchange: {expired}",
        l("fields on a ticket, past the first token's expiry")
    );
    assert_eq!(
        at(&l("exchanges after expiry")),
        "exchanges=3 [ok, ok, ok]",
        "{}",
        l("exchanges after expiry")
    );
    let waited = format!(" | {} | {}", x.expect, x.expect);
    assert!(
        exchange.ends_with(&waited),
        "{}: both waiting calls write exactly expect_fields, the one token: {exchange}",
        l("tick: the exchange")
    );
    assert_eq!(
        second,
        format!("{} exchanges=2", od.second),
        "{}: the second scope's token is written (second_scope_fields)",
        l("fields on a ticket, the second scope")
    );
    assert_eq!(
        expired,
        format!("{} exchanges=3", od.expired),
        "{}: the re-minted token is written (expired_fields)",
        l("fields on a ticket, past the first token's expiry")
    );
    assert!(
        at(&l("failing endpoint: tick")).ends_with(" exchanges=0"),
        "{}: nothing is exchanged before a call asks: {}",
        l("failing endpoint: tick"),
        at(&l("failing endpoint: tick"))
    );
    let refused = at(&l("failing endpoint: fields"));
    assert!(
        refused.starts_with(&format!("{} ", m.refusal)) || refused == m.refusal,
        "{}: a failed exchange answers the declared refusal `{}`: {refused}",
        l("failing endpoint: fields"),
        m.refusal
    );
    assert_eq!(
        at(&l("failing endpoint: attempts")),
        "exchanges=1",
        "{}: NO RETRY: a failed exchange is exactly ONE attempt",
        l("failing endpoint: attempts")
    );
}

// ---- the RED arms ----

/// The real auth ops a plant forwards to.
static REAL_OPS: Mutex<Option<auth::Ops>> = Mutex::new(None);
static PLANT_BYTE: Restated = Restated::new();
static PLANT_FETCH: Restated = Restated::new();
static PLANT_NOTHING: Restated = Restated::new();

extern "C" fn plant_byte_door() -> *const Door {
    PLANT_BYTE.get()
}
extern "C" fn plant_fetch_door() -> *const Door {
    PLANT_FETCH.get()
}
extern "C" fn plant_nothing_door() -> *const Door {
    PLANT_NOTHING.get()
}

fn real_ops() -> Option<auth::Ops> {
    *REAL_OPS.lock().unwrap_or_else(|e| e.into_inner())
}

/// `fields`, then ONE byte of the first value written flipped.
extern "C" fn fields_one_byte_off(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let Some(real) = real_ops().and_then(|o| o.fields) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let answered = real(instance, input, out);
    if answered.outcome() == Outcome::Ready {
        // SAFETY: the host hands `fields` a `FieldsIn` and a `FieldsOut`; the plugin answered
        // READY, so its first span (when it wrote one) lies inside the host's field buffer.
        unsafe {
            let i = &*input.cast::<FieldsIn>();
            let o = &*out.cast::<FieldsOut>();
            if o.fields_len > 0 && !i.fields.is_null() && !i.field_buf.is_null() {
                let v = (*i.fields).value;
                if v.len > 0 && (v.offset as usize + v.len as usize) <= i.field_buf_cap {
                    *i.field_buf.add(v.offset as usize + v.len as usize - 1) ^= 1;
                }
            }
        }
    }
    answered
}

/// `fields`, then the fields it wrote taken back: READY with none written.
extern "C" fn fields_writing_nothing(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let Some(real) = real_ops().and_then(|o| o.fields) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let answered = real(instance, input, out);
    if answered.outcome() == Outcome::Ready {
        // SAFETY: the host hands `fields` a `FieldsOut` it owns for the call.
        unsafe {
            (*out.cast::<FieldsOut>()).fields_len = 0;
        }
    }
    answered
}

/// `open_outbound`, then a SECOND binding over the same style and credential under settings one
/// byte longer: a second token cell, so the plugin's mint fetches the token twice.
extern "C" fn open_outbound_twice(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let Some(real) = real_ops().and_then(|o| o.open_outbound) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let answered = real(instance, input, out);
    // SAFETY: the host hands `open_outbound` an `OpenOutboundIn`; its settings blob is the
    // host's for the call. The second call's `in` and `out` are this frame's own.
    unsafe {
        let mut again = *input.cast::<OpenOutboundIn>();
        let mut longer = if again.settings.ptr.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(again.settings.ptr, again.settings.len).to_vec()
        };
        longer.push(b' ');
        again.settings = json(&longer);
        let mut scratch: OpenOutboundOut = output();
        let _ = real(
            instance,
            std::ptr::addr_of!(again).cast(),
            std::ptr::addr_of_mut!(scratch).cast(),
        );
    }
    answered
}

/// `fields`, and when it WAITS (an on-demand cell armed) the same call again under the scope one
/// byte longer: a second cell armed for the same waiting request, so the waiting calls fetch twice.
extern "C" fn fields_arming_twice(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let Some(real) = real_ops().and_then(|o| o.fields) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let answered = real(instance, input, out);
    if answered.outcome() == Outcome::Pending {
        // SAFETY: the host hands `fields` a `FieldsIn`; its extensions blob is the host's for the
        // call. The second call's `in` and `out` are this frame's own.
        unsafe {
            let mut again = *input.cast::<FieldsIn>();
            let ext = again.head.extensions;
            let blob = if ext.ptr.is_null() {
                &[][..]
            } else {
                std::slice::from_raw_parts(ext.ptr, ext.len)
            };
            let mut scope = extensions::get(blob, auth::EXT_SCOPE)
                .unwrap_or_default()
                .to_vec();
            scope.push(b' ');
            let other = extensions::encode(&[(auth::EXT_SCOPE, &scope)]);
            again.head.extensions = Blob {
                ptr: other.as_ptr(),
                len: other.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
            let mut scratch: FieldsOut = output();
            let _ = real(
                instance,
                std::ptr::addr_of!(again).cast(),
                std::ptr::addr_of_mut!(scratch).cast(),
            );
        }
    }
    answered
}

/// The subject's door restated with its auth ops `edit`ed, served by `slot`.
fn plant(s: &Subject, slot: &Restated, edit: impl FnOnce(&mut auth::Ops)) {
    let real = real_door(s);
    // SAFETY: an auth door's ops table is an `auth::Ops` (`abi/auth/mod.rs`), `'static`.
    let ops = unsafe { real.ops.cast::<auth::Ops>().read_unaligned() };
    *REAL_OPS.lock().unwrap_or_else(|e| e.into_inner()) = Some(ops);
    let mut planted = ops;
    edit(&mut planted);
    let planted: &'static auth::Ops = Box::leak(Box::new(planted));
    slot.set(Door {
        ops: std::ptr::from_ref(planted).cast::<OpsHead>(),
        ..real
    });
}

/// The panic text of a run, or `None` when it passed.
fn failed(run: impl FnOnce()) -> Option<String> {
    catch_unwind(AssertUnwindSafe(run)).err().map(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default()
    })
}

/// The subject's auth tail, when it declares the outbound family.
fn outbound_subject(s: &Subject) -> Option<Stated> {
    if s.kind() != KindCode::Auth {
        return None;
    }
    let st = stated(s);
    (st.caps & auth::CAP_OUTBOUND != 0).then_some(st)
}

/// **RED: a door writing one wrong field byte fails the outbound script.** The real door restated
/// with a `fields` that flips the last byte of the first value it writes is driven linked; the
/// script must refuse it on the fields it wrote. A door with no outbound family has nothing to
/// plant.
///
/// # Panics
/// When the planted door passes the script, or fails it for another reason.
pub fn red_outbound_wrong_byte(s: &Subject) {
    s.apply_env();
    let Some(st) = outbound_subject(s) else {
        eprintln!("conformance: the door states no outbound family; no outbound plant to run");
        return;
    };
    plant(s, &PLANT_BYTE, |o| o.fields = Some(fields_one_byte_off));
    let why = failed(|| {
        fold(s, Leg::Linked, plant_byte_door, &st);
    })
    .expect("RED: a door writing one wrong field byte passed the outbound script");
    assert!(
        why.contains("expect_fields") || why.contains("refreshed_fields"),
        "RED: the one-byte plant failed for another reason than the fields written: {why}"
    );
}

/// **RED: a door stating the outbound family whose `fields` writes nothing fails the outbound
/// script.** The real door restated with a `fields` that answers READY having written no field is
/// driven linked; the script must refuse it on the fields it wrote (every style's expectation
/// names at least one field: an empty one is refused when the inputs are read). A door with no
/// outbound family has nothing to plant.
///
/// # Panics
/// When the planted door passes the script, or fails it for another reason.
pub fn red_outbound_writes_nothing(s: &Subject) {
    s.apply_env();
    let Some(st) = outbound_subject(s) else {
        eprintln!("conformance: the door states no outbound family; no outbound plant to run");
        return;
    };
    plant(s, &PLANT_NOTHING, |o| {
        o.fields = Some(fields_writing_nothing)
    });
    let why = failed(|| {
        fold(s, Leg::Linked, plant_nothing_door, &st);
    })
    .expect("RED: an outbound door writing no field passed the outbound script");
    assert!(
        why.contains("expect_fields")
            || why.contains("refreshed_fields")
            || why.contains("second_scope_fields")
            || why.contains("expired_fields"),
        "RED: the write-nothing plant failed for another reason than the fields written: {why}"
    );
}

/// **RED: a door that fetches the token twice fails the outbound script.** The real door restated
/// with an `open_outbound` that binds a second token cell, and a `fields` that arms a second
/// on-demand cell whenever it waits, is driven linked; its mint makes two token exchanges where the
/// script allows exactly one. A door whose styles mint nothing has no
/// token to fetch twice.
///
/// # Panics
/// When the planted door passes the script, or fails it for another reason.
pub fn red_outbound_double_fetch(s: &Subject) {
    s.apply_env();
    let Some(st) = outbound_subject(s) else {
        eprintln!("conformance: the door states no outbound family; no outbound plant to run");
        return;
    };
    let mints = s.kind_inputs("auth")["outbound"]
        .as_array()
        .is_some_and(|a| a.iter().any(|x| !x["token_endpoint"].is_null()));
    if !mints {
        eprintln!("conformance: no outbound style mints a token; no double-fetch plant to run");
        return;
    }
    plant(s, &PLANT_FETCH, |o| {
        o.open_outbound = Some(open_outbound_twice);
        o.fields = Some(fields_arming_twice);
    });
    let why = failed(|| {
        fold(s, Leg::Linked, plant_fetch_door, &st);
    })
    .expect("RED: a door fetching the token twice passed the outbound script");
    assert!(
        why.contains("exactly ONE") || why.contains("ONE token exchange"),
        "RED: the double-fetch plant failed for another reason than the exchange count: {why}"
    );
}
