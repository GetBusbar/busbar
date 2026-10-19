// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND AUTH HANDLE, KERNEL SIDE (`BUSBAR-1.6.0.md` THE DESIGN §6, "Auth points and guest
//! lists", step 4 "Inbound", l.938-962; step 3 for the chain rule, l.921-926; step 7 for pending,
//! l.973-978; Part 2 #65 and #74): what the kernel does when a listener's transport calls its line's
//! auth (`auth.call`), hands a request in (`unit.hand_in`) or asks for a refusal (`unit.refuse`).
//!
//! * **The tables.** Per (listener owner, configuration generation) the kernel holds the sealed
//!   [`GuestList`]: a line's id is its index in the list's order, and its auth handle's id is the
//!   one the composition root minted for it ([`Listener::ids`]) from the shared ref-id space: never
//!   `0`, and never with the top bit ([`BINDING_BIT`]) an outbound binding's id carries, so a line's
//!   handle is never a binding's (#74; refused at [`Inbound::install`]). Beside it: the opened auths each line
//!   names, the size gate's limit a `HeadBody` line holds the body to, the generation's [`App`]
//!   (its mount table shapes the refusals) and the door routes' unit-less refusals.
//! * **The unit table.** The kernel mints a request's unit on its FIRST `auth.call` (or at
//!   `unit.hand_in` for a `none` line), before any verdict (l.949-950), with a fresh per-request
//!   secret; the transport receives the unit's ref, MAC'd by the injected [`Seals::mac`] over
//!   (secret, generation, owner, line, unit) (#74). Every subsequent call presents it and is verified:
//!   a unit of another request, owner, generation or line is refused.
//! * **The verdict is first-hand.** At each point the kernel calls, in list order, each undecided
//!   auth of the line that needs the point (through [`AuthCalls::verify`]), and fixes the verdict
//!   in list order by 1.5.5's chain rule: the first identity admits, a reject (or a verify that
//!   answered no verdict) refuses, an overloaded verifier stops (the 503), all-pass refuses
//!   (l.921-926; the data-plane walk's rule, `auth::chain_verdict_of` / `data_verdict_of`). The
//!   identity and its credential stay HERE, on the unit; the credential is a redacted [`Secret`]
//!   zeroised when the unit exits (l.946-948). The transport is answered only continue or stop and
//!   the NAMES its auths named to strip (l.942-945); no kernel step names a credential line.
//! * **The hand-in checks** (a) to (c) (l.953-958), each failure a stop.
//! * **Every refusal is the kernel's** (l.962-964): no route is the listener's 1.5.5 no-route
//!   answer and opens no unit; a method miss is the 405, an over-gate body the 413 (before any
//!   verdict, l.940-941), each from the very builder the data router answers with today
//!   ([`crate::router::fallback_error_response`]); a stop is the 401 of the line's claimant (the
//!   door route's unit-less refusal) or the kernel's default, through the same function the auth
//!   gate answers with (`auth::unauthorized_with_completion_taps`). A refused unit bills nothing
//!   and draws no lease; it is reported to the [`RefusedSink`] and leaves the table (l.950-951).
//!
//! This module names no loader: the composition root glues it to the plugin loader's auth handle,
//! injecting the MAC, the unit mint, the spawner and the refusal sink.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use busbar_contract::abi::auth::{AuthPoint, POINT_HEAD_BODY};
use busbar_contract::abi::host::service::{
    UnitRef, FLOW_CONTINUE, FLOW_STOP, REFUSE_CHECK_FAILED, REFUSE_METHOD_MISS, REFUSE_NO_ROUTE,
    REFUSE_OVER_GATE, REFUSE_STOPPED,
};
use busbar_contract::auth_calls::{
    AuthCalls, Strip, StripPlace, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest,
};
use busbar_contract::redacted::Secret;

use crate::guest::{GuestList, Line, LineAuth, Matched};
use crate::state::App;

/// The refusal text of a call on a listener the kernel holds no list for at that generation.
pub const NO_LIST: &str = "the kernel holds no guest list for this listener at this generation";
/// The refusal text of a handle or line id that names no line of the list.
pub const NO_LINE: &str = "the handle names no line of this listener's list";
/// The refusal text of an `auth.call` on a line whose auth is `none`.
pub const LINE_OPEN: &str = "the line's auth is none: it has no auth to call";
/// The refusal text of an `auth.call` at a point the line's auth does not need.
pub const POINT_UNNEEDED: &str = "the line's auth needs no call at this point";
/// The refusal text of a peer-point `auth.call` that presents a unit, a body or any byte of a
/// request: the peer point is before any head, and carries nothing (the Peer rule).
pub const PEER_BYTES: &str = "a peer-point call presents no unit, no request and no body";
/// The most connections whose `Peer` verdict the kernel holds at once. A verdict leaves when its
/// framing ends ([`Inbound::framing_ended`]); a NEW framing's peer call at the bound is
/// refused LOUDLY ([`PEER_TABLE_FULL`], an error event), and no live connection's verdict is ever
/// evicted for it.
pub const PEER_CONNECTIONS_MAX: usize = 65_536;
/// The refusal text of a new framing's peer call while [`PEER_CONNECTIONS_MAX`] framings hold a
/// verdict.
pub const PEER_TABLE_FULL: &str =
    "the kernel holds the most connection verdicts it may; this connection's peer call is refused";
/// The refusal text of a body past the line's size gate presented at the body point.
pub const OVER_GATE: &str = "the body passes the line's size gate";
/// The refusal text of a unit the kernel did not mint for this owner, generation and line.
pub const UNIT_FOREIGN: &str = "the unit is not one the kernel minted for this request";
/// The refusal text of a unit that could not be minted (no secret, or no MAC).
pub const UNIT_UNMINTED: &str = "the kernel could not mint the request's unit";
/// The refusal text of a call whose connection is not the one its framing's earlier calls named.
pub const CONN_MISMATCH: &str =
    "the call names another connection than the one its framing's calls named";
/// The refusal text of an unknown refusal cause.
pub const CAUSE_UNKNOWN: &str = "the refusal names no cause the kernel answers";

/// The refusal text of a listener table whose line ids break the ref-id space's rule.
pub const IDS_REFUSED: &str =
    "a line's handle id is 0, carries the binding bit, repeats, or the ids do not cover the lines";

/// The top bit of the ref-id space: every outbound binding's handle id carries it and no inbound
/// line's does (the loader's `auth_handle::RefSpace`; one rule both ways, #74).
pub const BINDING_BIT: u64 = 1 << 63;

/// Whether `id` may name an inbound line's handle: not the absent handle, not a binding's.
#[must_use]
pub const fn is_line_id(id: u64) -> bool {
    id != 0 && id & BINDING_BIT == 0
}

/// One request's head, as a transport decoded it: neutral fields only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Head {
    /// The method.
    pub method: String,
    /// The target's path, as received.
    pub target: String,
    /// The authority.
    pub authority: String,
    /// The query without `?`; `None` = absent.
    pub query: Option<String>,
    /// The field lines, in order: (name, value). A value may be a credential.
    pub fields: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Debug for Head {
    // Never a field value: a field line may carry the credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Head")
            .field("method", &self.method)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Head {
    /// Whether the head carries nothing: the peer point's view.
    fn is_empty(&self) -> bool {
        self.method.is_empty()
            && self.target.is_empty()
            && self.authority.is_empty()
            && self.query.is_none()
            && self.fields.is_empty()
    }

    /// The target with its query, as a door route's refusal renders for it.
    fn path_and_query(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{q}", self.target),
            None => self.target.clone(),
        }
    }
}

/// `auth.call` on an inbound line.
#[derive(Debug)]
pub struct Call {
    /// The listener's owner (the transport's instance identity).
    pub owner: u64,
    /// The generation the handle was verified at.
    pub generation: u64,
    /// The verified handle's id ([`Listener::ids`]).
    pub auth: u64,
    /// The presented unit; [`UnitRef::NONE`] on the request's first call.
    pub unit: UnitRef,
    /// The point bit.
    pub point: u32,
    /// The connection, as the transport names it: checked against its framing's.
    pub conn: u64,
    /// THE FRAMING the call was made on: the host's own identity of the connection side (the
    /// ticket of the framer op the call was made inside), never the transport's word. A
    /// connection's `Peer` verdict is held by it, and leaves with it ([`Inbound::framing_ended`]).
    pub framing: u64,
    /// The request.
    pub head: Head,
    /// The whole body, at the body point only.
    pub body: Option<Vec<u8>>,
    /// The deadline of the op the call was made for (the framer op's ticket, minted with its
    /// deadline class): past it no verify runs and none is awaited, and the walk stops; `None` =
    /// none (a write-behind op, or no deadline).
    pub deadline: Option<std::time::Instant>,
}

/// What `auth.call` answers the transport: continue or stop, the unit, and the names to strip.
/// Never the verdict, never a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// [`FLOW_CONTINUE`] | [`FLOW_STOP`].
    pub flow: u32,
    /// The request's unit.
    pub unit: UnitRef,
    /// The field lines and query keys the line's auths named, the union so far.
    pub strips: Vec<Strip>,
}

/// Where a pended `auth.call` answers: once, from any thread.
pub type Done = Box<dyn FnOnce(Result<Answer, &'static str>) + Send>;

/// `unit.hand_in`.
#[derive(Debug)]
pub struct HandIn {
    /// The listener's owner.
    pub owner: u64,
    /// The generation the handle was verified at.
    pub generation: u64,
    /// The verified handle's id.
    pub auth: u64,
    /// The presented unit; [`UnitRef::NONE`] for a `none` line.
    pub unit: UnitRef,
    /// The line the transport matched.
    pub line: u32,
    /// The connection, as the transport names it.
    pub conn: u64,
    /// The framing the hand-in was made on ([`Call::framing`]): a `Peer` line's verdict is its
    /// framing's. `None` for a ticketless hand-in, which no `Peer` verdict reaches.
    pub framing: Option<u64>,
    /// The request, after the transport stripped what the auths named.
    pub head: Head,
}

/// `unit.refuse`.
#[derive(Debug)]
pub struct Refuse {
    /// The listener's owner.
    pub owner: u64,
    /// The generation the listener serves.
    pub generation: u64,
    /// The presented unit; [`UnitRef::NONE`] when there is none.
    pub unit: UnitRef,
    /// `REFUSE_*`.
    pub cause: u32,
    /// The matched line; [`LINE_NONE`](busbar_contract::abi::host::service::LINE_NONE) for no route.
    pub line: u32,
    /// The request being refused, as the transport decoded it (`UnitRefuseIn::request`): its path
    /// shapes the bytes of a refusal with no unit (no route, a method miss, an over-gate body) as
    /// 1.5.5's router shaped them, by the path's dialect. A unit's own head, when it holds one, is
    /// read first; with neither, the line's route path, else the listener's root.
    pub request: Option<Head>,
}

/// A refusal's bytes: the status, the head fields in order, the body. The transport frames them
/// verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The status.
    pub status: u16,
    /// The head fields: (name, value).
    pub fields: Vec<(String, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Refusal {
    /// The bytes of a response a kernel builder answered: its status, its fields, its whole body
    /// (every refusal builder answers a body already in memory).
    #[must_use]
    pub fn of(resp: axum::response::Response) -> Self {
        use futures::FutureExt as _;
        use http_body_util::BodyExt as _;
        let (parts, body) = resp.into_parts();
        let body = body
            .collect()
            .now_or_never()
            .and_then(Result::ok)
            .map(|c| c.to_bytes().to_vec())
            .unwrap_or_default();
        Self {
            status: parts.status.as_u16(),
            fields: parts
                .headers
                .iter()
                .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
                .collect(),
            body,
        }
    }
}

/// A refusal the kernel answered, as its sink is told it: the unit it refused (none for a request
/// that matched no line or was refused before any), whose listener, which line and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusedUnit {
    /// The refused unit; `None` when the request had none.
    pub unit: Option<u64>,
    /// The listener's owner.
    pub owner: u64,
    /// The line; [`LINE_NONE`](busbar_contract::abi::host::service::LINE_NONE) for no route.
    pub line: u32,
    /// `REFUSE_*`.
    pub cause: u32,
    /// The status answered.
    pub status: u16,
}

/// What a unit ref's MAC covers (#74).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnitTag {
    /// The request's own kernel secret.
    pub secret: [u64; 2],
    /// The generation.
    pub generation: u64,
    /// The listener's owner.
    pub owner: u64,
    /// The line.
    pub line: u32,
    /// The unit.
    pub unit: u64,
}

impl std::fmt::Debug for UnitTag {
    // Never the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitTag")
            .field("generation", &self.generation)
            .field("owner", &self.owner)
            .field("line", &self.line)
            .field("unit", &self.unit)
            .finish_non_exhaustive()
    }
}

/// The MAC over a [`UnitTag`] under the host's key; `None` when it cannot be drawn.
pub type UnitMac = Arc<dyn Fn(&UnitTag) -> Option<u64> + Send + Sync>;
/// The kernel's one unit mint (the node's): a fresh, never-zero unit key.
pub type MintUnit = Arc<dyn Fn() -> u64 + Send + Sync>;
/// Runs a pended `auth.call` to its end, off the caller's thread.
pub type Spawn = Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>;
/// Told every refusal the kernel answers: the audit of a refused unit (it bills nothing, draws no
/// lease).
pub type RefusedSink = Arc<dyn Fn(&RefusedUnit) + Send + Sync>;

/// The two things the kernel's unit table is minted with, injected by the composition root.
#[derive(Clone)]
pub struct Seals {
    /// The unit mint.
    pub mint: MintUnit,
    /// The unit ref's MAC.
    pub mac: UnitMac,
}

impl std::fmt::Debug for Seals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seals").finish_non_exhaustive()
    }
}

/// One listener's table at one generation.
pub struct Listener {
    /// The sealed guest list.
    pub guests: GuestList,
    /// The opened auths a line names, by name.
    pub auths: HashMap<String, Arc<dyn AuthCalls>>,
    /// The size gate's limit: a `HeadBody` line holds the body to it (l.940).
    pub body_limit: u64,
    /// The generation's application state: its mount table shapes the refusals, its governance
    /// holds the replay claims.
    pub app: Arc<App>,
    /// The door routes' unit-less refusals: a claimant's 401 under its refusal dialect.
    pub door_refusals: Vec<crate::plane_routes::PlaneRefusalSpec>,
    /// Each line's handle id, in the list's order, as the root minted it from the ref-id space's
    /// line half ([`is_line_id`]).
    pub ids: Vec<u64>,
    /// Whether a request's path is answered by a dialect that signs ([`signed_by_dialect`]).
    pub signed_ingress: SignedIngress,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("lines", &self.guests.lines().len())
            .field("body_limit", &self.body_limit)
            .finish_non_exhaustive()
    }
}

/// One line as a transport is lent it, beside the handle the composition root mints for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineSpec {
    /// The line's id.
    pub line: u32,
    /// Its handle's id ([`Listener::ids`]); the root mints the handle's MAC for the listener's owner.
    pub auth: u64,
    /// The points its auth needs; `0` for a `none` line.
    pub points: u32,
    /// The body bound at the body point; `0` without it.
    pub body_limit: u64,
}

impl Listener {
    /// The line table a transport is lent: one [`LineSpec`] per line, in the list's order.
    #[must_use]
    pub fn specs(&self) -> Vec<LineSpec> {
        (0u32..)
            .zip(self.guests.lines().iter().zip(&self.ids))
            .map(|(i, (l, id))| {
                let points = l.auth.points().bits();
                LineSpec {
                    line: i,
                    auth: *id,
                    points,
                    body_limit: if points & POINT_HEAD_BODY != 0 {
                        self.body_limit
                    } else {
                        0
                    },
                }
            })
            .collect()
    }
}

/// One position's answer as the unit holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Judged {
    Identity,
    Pass,
    Denied,
    Overloaded,
}

/// The verdict, fixed in list order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fixed {
    Admitted(usize),
    Denied,
    Overloaded,
}

/// THE IDENTITY a unit was admitted under, first-hand: the provider (the line's auth name) and
/// who it identified, without its credential (held apart, [`Inbound::with_credential`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Admitted {
    /// The provider name.
    pub provider: String,
    /// The identity, its credential taken out.
    pub identity: VerifiedIdentity,
    /// The governance key the `keys` arm resolved (the one verdict that carries one, as 1.5.5's
    /// chain did); `None` for every plugin position.
    pub resolved: Option<Arc<crate::governance::VirtualKey>>,
}

/// One unit, as the kernel holds it.
struct UnitState {
    owner: u64,
    generation: u64,
    line: u32,
    secret: [u64; 2],
    head: Option<Head>,
    answers: Vec<Option<Judged>>,
    /// The line's auth names, in list order.
    providers: Vec<String>,
    /// Each position's identity, held until the verdict is fixed in list order.
    identities: Vec<Option<VerifiedIdentity>>,
    strips: Vec<Strip>,
    admitted: Option<Admitted>,
    /// The verified credential, zeroised when the unit leaves the table (its drop).
    credential: Option<Secret<String>>,
    /// The governance key the `keys` arm resolved, held until the verdict is fixed.
    resolved: Option<Arc<crate::governance::VirtualKey>>,
}

impl UnitState {
    /// A state with no answer yet, over the line's ordered `providers`.
    fn open(
        owner: u64,
        generation: u64,
        line: u32,
        secret: [u64; 2],
        providers: &[String],
    ) -> Self {
        Self {
            owner,
            generation,
            line,
            secret,
            head: None,
            answers: vec![None; providers.len()],
            providers: providers.to_vec(),
            identities: vec![None; providers.len()],
            strips: Vec::new(),
            admitted: None,
            credential: None,
            resolved: None,
        }
    }

    /// Once the verdict is fixed: on an identity, it and its credential (taken out of it) and the
    /// key the `keys` arm resolved are held first-hand; on a refusal, every identity a following
    /// position answered is dropped.
    fn settle(&mut self) {
        match self.fixed() {
            Some(Fixed::Admitted(i)) if self.admitted.is_none() => {
                if let Some(mut id) = self.identities.get_mut(i).and_then(Option::take) {
                    self.credential = id.credential.take();
                    let provider = self.providers.get(i).cloned().unwrap_or_default();
                    let resolved = if provider == crate::config::KEYS_MODULE {
                        self.resolved.take()
                    } else {
                        None
                    };
                    self.admitted = Some(Admitted {
                        provider,
                        identity: id,
                        resolved,
                    });
                }
                self.identities.clear();
                self.resolved = None;
            }
            Some(Fixed::Denied | Fixed::Overloaded) => {
                self.identities.clear();
                self.resolved = None;
            }
            _ => {}
        }
    }

    /// The verdict in list order: `None` while an earlier position is still undecided.
    fn fixed(&self) -> Option<Fixed> {
        for (i, a) in self.answers.iter().enumerate() {
            match a {
                None => return None,
                Some(Judged::Pass) => {}
                Some(Judged::Identity) => return Some(Fixed::Admitted(i)),
                Some(Judged::Denied) => return Some(Fixed::Denied),
                Some(Judged::Overloaded) => return Some(Fixed::Overloaded),
            }
        }
        // All-pass on a non-empty list is 401 (l.923-924).
        Some(Fixed::Denied)
    }
}

/// A listener's table with its door refusals indexed.
struct Table {
    listener: Listener,
    doors: crate::core_routes::CoreRouteTable,
    /// Handle id -> line.
    lines_by_id: HashMap<u64, u32>,
}

impl Table {
    /// The line handle `id` names on this list.
    fn line_of(&self, id: u64) -> Option<u32> {
        self.lines_by_id.get(&id).copied()
    }
}

/// THE INBOUND HANDLE'S KERNEL SIDE: the tables, the unit table, and what the root injected.
pub struct Inbound {
    tables: RwLock<HashMap<(u64, u64), Arc<Table>>>,
    units: Mutex<HashMap<u64, UnitState>>,
    /// The connection each framing's calls named, by (owner, framing).
    framing_conns: Mutex<HashMap<(u64, u64), u64>>,
    /// Each framing's `Peer` verdict, by (owner, generation, framing), at most
    /// [`PEER_CONNECTIONS_MAX`].
    peers: Mutex<HashMap<(u64, u64, u64), UnitState>>,
    seals: Seals,
    spawn: Spawn,
    refused: RefusedSink,
}

impl std::fmt::Debug for Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbound").finish_non_exhaustive()
    }
}

/// A fresh per-request secret from the OS random source; `None` when it cannot answer.
fn fresh_secret() -> Option<[u64; 2]> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).ok()?;
    let (a, z) = b.split_at(8);
    Some([
        u64::from_le_bytes(a.try_into().ok()?),
        u64::from_le_bytes(z.try_into().ok()?),
    ])
}

/// `want` against `got`, the whole difference folded before it is judged.
fn same(want: u64, got: u64) -> bool {
    std::hint::black_box(want ^ got) == 0
}

/// Whether any of `strips` is still in `head`: a field line case-insensitively, a query key
/// case-sensitively (l.957-958).
fn still_present(strips: &[Strip], head: &Head) -> bool {
    strips.iter().any(|s| match s.place {
        StripPlace::Field => head
            .fields
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(&s.name)),
        StripPlace::Query => head.query.as_deref().is_some_and(|q| {
            q.split('&')
                .any(|pair| pair.split_once('=').map_or(pair, |(k, _)| k) == s.name)
        }),
    })
}

/// The `verify` request one position is lent at `point`: the head as received, the body at the
/// body point; no candidate credential (no kernel step names an inbound credential line, l.944).
fn verify_request(
    head: &Head,
    point: AuthPoint,
    conn: u64,
    unit: u64,
    body: Option<&[u8]>,
) -> VerifyRequest {
    VerifyRequest {
        point,
        conn,
        unit,
        credential: None,
        lines: head
            .fields
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), Secret::new(v.clone())))
            .collect(),
        peer: None,
        body: body.map(<[u8]>::to_vec),
        method: head.method.clone(),
        authority: head.authority.clone(),
        path: head.target.clone(),
        query: head.query.clone(),
        timestamp: crate::store::now(),
    }
}

/// What a walk records into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// A request's unit.
    Unit(u64),
    /// A connection's `Peer` verdict: (owner, generation, connection).
    Peer((u64, u64, u64)),
}

/// Who answers a position.
enum PositionKind {
    /// An opened auth instance; `None` when the generation opened none for the name.
    Plugin(Option<Arc<dyn AuthCalls>>),
    /// The kernel's own `keys` arm: a busbar-minted signed key verified against governance.
    Keys,
}

/// One position the walk may call.
struct Position {
    index: usize,
    provider: String,
    kind: PositionKind,
}

/// What a position answered, as [`Inbound::record`] judges it.
enum Judging<'a> {
    /// No verdict: no auth opened for it, or the op's deadline passed (a deny).
    Nothing,
    /// The `keys` arm, over the request's head, after the signed-request reader's answer when one
    /// was asked.
    Keys(&'a Head, Option<SignedAnswer>),
    /// An auth's `verify` answer.
    Answer(VerifyAnswer),
}

/// A host-held credential verifier's answer to a signed request (1.5.5's signed-ingress pre-step),
/// with the credential kinds it reads.
struct SignedAnswer {
    answer: VerifyAnswer,
    faulted: bool,
    kinds: Vec<String>,
}

/// Whether a request on `path` is answered by a dialect that signs its requests (the dialect's
/// declared ingress auth, never a name), so the `keys` arm asks the host-held credentials'
/// verifier first, as 1.5.5's gate did. Answered by the listener's [`Listener::signed_ingress`].
pub type SignedIngress = Arc<dyn Fn(&App, &str) -> bool + Send + Sync>;

/// THE DECLARED ANSWER ([`SignedIngress`]): the path's residual dialect declares a signed ingress,
/// on the residual plane only (an audience-bound plane admits bearer tokens alone).
#[must_use]
pub fn signed_by_dialect() -> SignedIngress {
    Arc::new(|app: &App, path: &str| {
        let ingress = app.planes.ingress_of(path);
        matches!(ingress, crate::plane::Ingress::Fallback(_))
            && crate::proto::decl_for(crate::ingress::native::envelope_dialect(ingress))
                .is_some_and(|d| d.uses_sigv4_ingress_auth())
    })
}

/// The request's field lines as a header map (a value that is no header value is left out).
fn header_map(head: &Head) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    for (n, v) in &head.fields {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(n.as_bytes()),
            axum::http::HeaderValue::from_bytes(v),
        ) {
            headers.append(n, v);
        }
    }
    headers
}

/// A line's auth names in the order the chain walks them (1.5.5's `walk`): every plugin position
/// in list order, then the `keys` arm, which runs after them whatever its place in the list.
fn ordered(names: &[String]) -> Vec<String> {
    let keys = crate::config::KEYS_MODULE;
    names
        .iter()
        .filter(|n| *n != keys)
        .chain(names.iter().filter(|n| *n == keys).take(1))
        .cloned()
        .collect()
}

/// THE `keys` ARM with the signed-request pre-step ahead of it, as 1.5.5's gate ran them: a
/// verifier's identity is the governance key holding that credential (enabled, live, not revoked)
/// or a deny; its pass falls through to the token path; a reject or no verdict denies; an
/// overloaded verifier is the 503. The lines both named are named.
fn signed_then_keys(
    app: &App,
    gov: Option<&crate::governance::GovState>,
    head: &Head,
    signed: Option<SignedAnswer>,
    now: u64,
) -> (
    Judged,
    Option<VerifiedIdentity>,
    Vec<Strip>,
    Option<Arc<crate::governance::VirtualKey>>,
) {
    let mut named = Vec::new();
    if let Some(s) = signed {
        named.extend(s.answer.strips);
        let verified = if s.faulted {
            Verified::Failed
        } else {
            s.answer.verified
        };
        match verified {
            Verified::Identity(id) => {
                let key = gov.and_then(|g| {
                    s.kinds.iter().find_map(|kind| {
                        let (key, cred) = g.lookup_credential(kind, &id.subject)?;
                        (key.enabled && cred.meta.is_live(now) && !g.is_revoked(&key.id))
                            .then_some(key)
                    })
                });
                return match key {
                    Some(key) => (
                        Judged::Identity,
                        Some(VerifiedIdentity {
                            subject: key.id.clone(),
                            key_id: Some(key.id.clone()),
                            key_name: Some(key.name.clone()),
                            ..VerifiedIdentity::default()
                        }),
                        named,
                        Some(key),
                    ),
                    None => (Judged::Denied, None, named, None),
                };
            }
            Verified::Pass => {}
            Verified::Reject | Verified::Failed => return (Judged::Denied, None, named, None),
            Verified::Overloaded => return (Judged::Overloaded, None, named, None),
        }
    }
    let (judged, identity, strips, resolved) = keys_judged(app, gov, head, now);
    named.extend(strips);
    (judged, identity, named, resolved)
}

/// THE `keys` ARM over one head (1.5.5's `keys_arm_verdict`, the data plane's engine arm): the
/// candidate the default inbound style's carriers carry, verified against governance. Its
/// carriers are every line the gate consumed in 1.5.5, named whatever its verdict (names only).
fn keys_judged(
    app: &App,
    gov: Option<&crate::governance::GovState>,
    head: &Head,
    now: u64,
) -> (
    Judged,
    Option<VerifiedIdentity>,
    Vec<Strip>,
    Option<Arc<crate::governance::VirtualKey>>,
) {
    let carriers = app.auth.carriers();
    let headers = header_map(head);
    let candidate = crate::auth::carried_credential(carriers, &headers);
    let strips = carriers
        .iter()
        .map(|c| Strip::field(c.as_str().to_string()))
        .collect();
    match crate::auth::keys_arm_verdict(gov, candidate.as_deref(), now, None) {
        crate::auth::ChainVerdict::Identified {
            principal,
            resolved,
            ..
        } => (
            Judged::Identity,
            Some(VerifiedIdentity {
                subject: principal.id.clone(),
                key_id: resolved.as_ref().map(|k| k.id.clone()),
                key_name: principal.name.clone(),
                ..VerifiedIdentity::default()
            }),
            strips,
            resolved,
        ),
        _ => (Judged::Denied, None, strips, None),
    }
}

impl Inbound {
    /// A kernel side with no tables yet.
    #[must_use]
    pub fn new(seals: Seals, spawn: Spawn, refused: RefusedSink) -> Arc<Self> {
        Arc::new(Self {
            tables: RwLock::default(),
            units: Mutex::default(),
            peers: Mutex::default(),
            framing_conns: Mutex::default(),
            seals,
            spawn,
            refused,
        })
    }

    /// Install `listener` as `owner`'s list at `generation`, and keep only that generation and the
    /// one before it for `owner` (requests already inside finish on the old one, l.981-983).
    ///
    /// # Errors
    ///
    /// [`IDS_REFUSED`] when the line ids do not name every line once from the line half of the
    /// ref-id space ([`is_line_id`]): nothing is installed.
    pub fn install(
        &self,
        owner: u64,
        generation: u64,
        listener: Listener,
    ) -> Result<(), &'static str> {
        let lines = listener.guests.lines().len();
        let lines_by_id: HashMap<u64, u32> = listener.ids.iter().copied().zip(0u32..).collect();
        if listener.ids.len() != lines
            || lines_by_id.len() != lines
            || !listener.ids.iter().all(|id| is_line_id(*id))
        {
            return Err(IDS_REFUSED);
        }
        let doors = crate::core_routes::CoreRouteTable::default()
            .with_door_refusals(listener.door_refusals.clone());
        let mut tables = self.tables.write().unwrap_or_else(PoisonError::into_inner);
        tables.insert(
            (owner, generation),
            Arc::new(Table {
                listener,
                doors,
                lines_by_id,
            }),
        );
        tables.retain(|(o, g), _| *o != owner || g.saturating_add(1) >= generation);
        Ok(())
    }

    /// The line table `owner` is lent at `generation`.
    #[must_use]
    pub fn specs(&self, owner: u64, generation: u64) -> Option<Vec<LineSpec>> {
        self.table(owner, generation).map(|t| t.listener.specs())
    }

    fn table(&self, owner: u64, generation: u64) -> Option<Arc<Table>> {
        self.tables
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(owner, generation))
            .cloned()
    }

    fn units(&self) -> std::sync::MutexGuard<'_, HashMap<u64, UnitState>> {
        self.units.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn peers(&self) -> std::sync::MutexGuard<'_, HashMap<(u64, u64, u64), UnitState>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The secret, generation and line `owner`'s live unit `unit` was minted under.
    #[must_use]
    pub fn unit_secret(&self, owner: u64, unit: u64) -> Option<([u64; 2], u64, u32)> {
        self.units()
            .get(&unit)
            .filter(|u| u.owner == owner)
            .map(|u| (u.secret, u.generation, u.line))
    }

    /// The identity `unit` was admitted under, first-hand; `None` before a verdict admits it.
    #[must_use]
    pub fn admitted(&self, unit: u64) -> Option<Admitted> {
        self.units().get(&unit).and_then(|u| u.admitted.clone())
    }

    /// `f` over the credential `unit` was verified from, held on the unit (the `caller-credential`
    /// style's, §6.6); `None` when it holds none.
    pub fn with_credential<R>(&self, unit: u64, f: impl FnOnce(&Secret<String>) -> R) -> Option<R> {
        self.units()
            .get(&unit)
            .and_then(|u| u.credential.as_ref())
            .map(f)
    }

    /// The unit leaves the table: its credential is zeroised (its drop).
    pub fn exit(&self, unit: u64) {
        drop(self.units().remove(&unit));
    }

    /// THE HOST'S END NOTIFICATION: the framing `framing` ended (the loader retired the ticket of
    /// the connection side it drove). Its `Peer` verdict, at every generation and for every owner,
    /// leaves the table (its credential zeroised), and so does the connection it named.
    pub fn framing_ended(&self, framing: u64) {
        self.peers().retain(|(_, _, f), _| *f != framing);
        self.framing_conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(_, f), _| *f != framing);
    }

    /// The connection a framing's calls name: the first call's, and every later call must name the
    /// same ([`CONN_MISMATCH`]).
    fn same_conn(&self, owner: u64, framing: u64, conn: u64) -> Result<(), &'static str> {
        let mut conns = self
            .framing_conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match conns.entry((owner, framing)) {
            std::collections::hash_map::Entry::Occupied(e) if *e.get() != conn => {
                Err(CONN_MISMATCH)
            }
            std::collections::hash_map::Entry::Occupied(_) => Ok(()),
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(conn);
                Ok(())
            }
        }
    }

    /// How many connections hold a `Peer` verdict.
    #[must_use]
    pub fn peer_verdicts(&self) -> usize {
        self.peers().len()
    }

    /// Mint a unit for `owner`'s `line` at `generation` on framing `framing`: its key, its fresh
    /// secret, its MAC. The framing's `Peer` verdict, held for the same ordered auths, is the
    /// unit's from the start (l.975-976: a `{Peer}`-only verdict is applied to every unit on it).
    fn mint(
        &self,
        owner: u64,
        generation: u64,
        line: u32,
        providers: &[String],
        framing: Option<u64>,
    ) -> Result<UnitRef, &'static str> {
        let secret = fresh_secret().ok_or(UNIT_UNMINTED)?;
        let unit = (self.seals.mint)();
        if unit == 0 {
            return Err(UNIT_UNMINTED);
        }
        let mac = (self.seals.mac)(&UnitTag {
            secret,
            generation,
            owner,
            line,
            unit,
        })
        .ok_or(UNIT_UNMINTED)?;
        let mut state = UnitState::open(owner, generation, line, secret, providers);
        if let Some(peer) = framing.and_then(|f| {
            self.peers()
                .get(&(owner, generation, f))
                .filter(|p| p.providers == providers)
                .map(|p| (p.answers.clone(), p.admitted.clone(), p.credential.clone()))
        }) {
            (state.answers, state.admitted, state.credential) = peer;
        }
        self.units().insert(unit, state);
        Ok(UnitRef { id: unit, mac })
    }

    /// Whether `r` is a unit this kernel minted for `owner`, at `generation`, for `line`.
    fn verified(&self, owner: u64, generation: Option<u64>, line: Option<u32>, r: UnitRef) -> bool {
        let units = self.units();
        let Some(u) = units.get(&r.id) else {
            return false;
        };
        if u.owner != owner
            || generation.is_some_and(|g| g != u.generation)
            || line.is_some_and(|l| l != u.line)
        {
            return false;
        }
        (self.seals.mac)(&UnitTag {
            secret: u.secret,
            generation: u.generation,
            owner,
            line: u.line,
            unit: r.id,
        })
        .is_some_and(|mac| same(mac, r.mac))
    }

    /// `auth.call` on an inbound line: `Some` with the answer when it finished at once; `None` when
    /// a verify must be awaited, and `done` answers it (the call pends on its own ticket, l.973-974;
    /// past the call's deadline the walk stops, [`Call::deadline`]).
    pub fn auth_call(
        self: &Arc<Self>,
        call: Call,
        done: Done,
    ) -> Option<Result<Answer, &'static str>> {
        let walk = match self.prepare(call) {
            Ok(walk) => walk,
            Err(e) => return Some(Err(e)),
        };
        let mut walk = Box::pin(walk);
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        match walk.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(answer) => Some(answer),
            std::task::Poll::Pending => {
                (self.spawn)(Box::pin(async move { done(walk.await) }));
                None
            }
        }
    }

    /// The state a walk records into: a request's unit, or a connection's `Peer` verdict.
    fn with_state<R>(&self, target: Target, f: impl FnOnce(&mut UnitState) -> R) -> Option<R> {
        match target {
            Target::Unit(unit) => self.units().get_mut(&unit).map(f),
            Target::Peer(key) => self.peers().get_mut(&key).map(f),
        }
    }

    /// The checks before any auth is called, the unit minted or verified (or, at the peer point,
    /// the connection's verdict opened), then the walk.
    fn prepare(
        self: &Arc<Self>,
        call: Call,
    ) -> Result<impl Future<Output = Result<Answer, &'static str>> + Send + 'static, &'static str>
    {
        let table = self.table(call.owner, call.generation).ok_or(NO_LIST)?;
        let line_ix = table.line_of(call.auth).ok_or(NO_LINE)?;
        let line = table
            .listener
            .guests
            .lines()
            .get(line_ix as usize)
            .ok_or(NO_LINE)?;
        let LineAuth::Chain(names, points) = &line.auth else {
            return Err(LINE_OPEN);
        };
        let point = AuthPoint::from_bit(call.point)
            .filter(|p| points.has(*p))
            .ok_or(POINT_UNNEEDED)?;
        let providers = ordered(names);
        // THE PEER POINT (l.973-978; the Peer rule): once per connection, before any head; no unit,
        // and its answer is continue or stop alone, with no name beside it.
        let peer = point == AuthPoint::Peer;
        if peer && (!call.unit.is_none() || call.body.is_some() || !call.head.is_empty()) {
            return Err(PEER_BYTES);
        }
        if call
            .body
            .as_ref()
            .is_some_and(|b| b.len() as u64 > table.listener.body_limit)
        {
            return Err(OVER_GATE);
        }
        self.same_conn(call.owner, call.framing, call.conn)?;
        let (target, unit) = if peer {
            let key = (call.owner, call.generation, call.framing);
            let mut peers = self.peers();
            if !peers.contains_key(&key) && peers.len() >= PEER_CONNECTIONS_MAX {
                // Bounded, and LOUD: no live connection's verdict is evicted for a new one.
                tracing::error!(
                    owner = call.owner,
                    conn = call.conn,
                    held = peers.len(),
                    "{PEER_TABLE_FULL}"
                );
                return Err(PEER_TABLE_FULL);
            }
            peers.entry(key).or_insert_with(|| {
                UnitState::open(call.owner, call.generation, line_ix, [0; 2], &providers)
            });
            (Target::Peer(key), UnitRef::NONE)
        } else {
            let unit = if call.unit.is_none() {
                self.mint(
                    call.owner,
                    call.generation,
                    line_ix,
                    &providers,
                    Some(call.framing),
                )?
            } else if self.verified(call.owner, Some(call.generation), Some(line_ix), call.unit) {
                call.unit
            } else {
                return Err(UNIT_FOREIGN);
            };
            if let Some(u) = self.units().get_mut(&unit.id) {
                if u.head.is_none() {
                    u.head = Some(call.head.clone());
                }
            }
            (Target::Unit(unit.id), unit)
        };
        let positions: Vec<Position> = providers
            .iter()
            .enumerate()
            .map(|(index, name)| Position {
                index,
                provider: name.clone(),
                kind: if name == crate::config::KEYS_MODULE {
                    PositionKind::Keys
                } else {
                    PositionKind::Plugin(table.listener.auths.get(name).cloned())
                },
            })
            .collect();
        // The `keys` arm answers at the line's last per-request point: with the body when a
        // host-held credential's verifier needs it, else at the head.
        let keys_point = if points.has(AuthPoint::HeadBody) {
            AuthPoint::HeadBody
        } else {
            AuthPoint::Head
        };
        let me = Arc::clone(self);
        let deadline = call.deadline;
        let (head, body, conn) = (call.head, call.body, call.conn);
        Ok(async move {
            for p in positions {
                let undecided = me
                    .with_state(target, |u| {
                        (u.fixed().is_none()).then(|| u.answers.get(p.index).copied().flatten())
                    })
                    .ok_or(UNIT_FOREIGN)?;
                match undecided {
                    // The verdict is fixed: nothing after it is called.
                    None => break,
                    Some(Some(_)) => continue,
                    Some(None) => {}
                }
                if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                    // The op the call was made for is past its deadline: no verify runs, and the
                    // position answers no verdict (a deny, fail closed).
                    me.record(target, p.index, &p.provider, Judging::Nothing, &table);
                    break;
                }
                let calls = match &p.kind {
                    PositionKind::Keys => {
                        if point != keys_point {
                            continue;
                        }
                        // THE SIGNED-REQUEST PRE-STEP (1.5.5's gate): on a dialect that signs, a
                        // request carrying a host-held credential verifier's lines is verified by
                        // it over the whole body, before the token path.
                        let app = &table.listener.app;
                        let reader = (table.listener.signed_ingress)(app, &head.target)
                            .then(|| app.auth.signed_reader(&header_map(&head)))
                            .flatten();
                        let signed = match reader {
                            None => None,
                            Some((calls, kinds)) => {
                                let unit_id = match target {
                                    Target::Unit(u) => u,
                                    Target::Peer(_) => 0,
                                };
                                let req = verify_request(
                                    &head,
                                    AuthPoint::HeadBody,
                                    conn,
                                    unit_id,
                                    Some(body.as_deref().unwrap_or_default()),
                                );
                                let mut verifying = calls.verify(req);
                                let answer = (&mut verifying).await;
                                Some(SignedAnswer {
                                    faulted: verifying.faulted(),
                                    answer,
                                    kinds,
                                })
                            }
                        };
                        me.record(
                            target,
                            p.index,
                            &p.provider,
                            Judging::Keys(&head, signed),
                            &table,
                        );
                        continue;
                    }
                    PositionKind::Plugin(None) => {
                        // A line naming an auth the generation did not open: fail closed.
                        me.record(target, p.index, &p.provider, Judging::Nothing, &table);
                        continue;
                    }
                    PositionKind::Plugin(Some(calls)) => Arc::clone(calls),
                };
                if !calls.inbound_points().has(point) {
                    continue;
                }
                let unit_id = match target {
                    Target::Unit(u) => u,
                    Target::Peer(_) => 0,
                };
                let req = verify_request(&head, point, conn, unit_id, body.as_deref());
                let mut verifying = calls.verify(req);
                let answer = match (deadline, tokio::runtime::Handle::try_current()) {
                    (Some(d), Ok(_)) => {
                        tokio::time::timeout_at(tokio::time::Instant::from_std(d), &mut verifying)
                            .await
                            .ok()
                    }
                    _ => Some((&mut verifying).await),
                };
                let judging = match answer {
                    Some(a) if verifying.faulted() => Judging::Answer(VerifyAnswer {
                        verified: Verified::Failed,
                        ..a
                    }),
                    Some(a) => Judging::Answer(a),
                    None => Judging::Nothing,
                };
                me.record(target, p.index, &p.provider, judging, &table);
            }
            let (flow, strips) = me
                .with_state(target, |u| {
                    let flow = match u.fixed() {
                        Some(Fixed::Denied | Fixed::Overloaded) => FLOW_STOP,
                        Some(Fixed::Admitted(_)) | None => FLOW_CONTINUE,
                    };
                    (flow, u.strips.clone())
                })
                .ok_or(UNIT_FOREIGN)?;
            // The Peer rule: a peer answer names nothing.
            let strips = if peer { Vec::new() } else { strips };
            Ok(Answer { flow, unit, strips })
        })
    }

    /// Record position `index`'s answer on `target` FIRST-HAND: its verdict by the data-plane chain
    /// rule, the lines it named, and, once the verdict is fixed in list order on an identity, that
    /// identity, its credential taken out of it, and for the `keys` arm the governance key it
    /// resolved.
    fn record(
        &self,
        target: Target,
        index: usize,
        provider: &str,
        judging: Judging<'_>,
        table: &Table,
    ) {
        let gov = table.listener.app.governance.as_deref();
        let now = crate::store::now();
        let (judged, identity, strips, resolved) = match judging {
            Judging::Nothing => (Judged::Denied, None, Vec::new(), None),
            Judging::Keys(head, signed) => {
                signed_then_keys(&table.listener.app, gov, head, signed, now)
            }
            Judging::Answer(a) => {
                let (judged, identity) = match a.verified {
                    Verified::Identity(id) => {
                        let claimed = id
                            .replay
                            .as_deref()
                            .is_none_or(|r| crate::auth::replay_claimed(gov, provider, r, now));
                        if claimed {
                            (Judged::Identity, Some(id))
                        } else {
                            (Judged::Denied, None)
                        }
                    }
                    Verified::Pass => (Judged::Pass, None),
                    Verified::Reject | Verified::Failed => (Judged::Denied, None),
                    Verified::Overloaded => (Judged::Overloaded, None),
                };
                (judged, identity, a.strips, None)
            }
        };
        self.with_state(target, |u| {
            for s in strips {
                if !u.strips.contains(&s) {
                    u.strips.push(s);
                }
            }
            if let Some(slot) = u.answers.get_mut(index) {
                *slot = Some(judged);
            }
            if let Some(slot) = u.identities.get_mut(index) {
                *slot = identity;
            }
            if resolved.is_some() {
                u.resolved = resolved;
            }
            u.settle();
        });
    }

    /// `unit.hand_in`: `(flow, unit)`. A `none` line's request (and any request handed in with no
    /// unit) has its unit minted here, so a stop always names the unit it refuses. Never pends.
    ///
    /// # Errors
    ///
    /// [`NO_LIST`] for a listener the kernel holds no list for; [`UNIT_FOREIGN`] for a presented
    /// unit it did not mint for this owner; [`UNIT_UNMINTED`] when no unit could be minted.
    pub fn hand_in(&self, h: HandIn) -> Result<(u32, UnitRef), &'static str> {
        let table = self.table(h.owner, h.generation).ok_or(NO_LIST)?;
        if let Some(f) = h.framing {
            self.same_conn(h.owner, f, h.conn)?;
        }
        let lines = table.listener.guests.lines();
        let unit = if h.unit.is_none() {
            let names: &[String] = match lines.get(h.line as usize).map(|l| &l.auth) {
                Some(LineAuth::Chain(names, _)) => names,
                _ => &[],
            };
            self.mint(h.owner, h.generation, h.line, &ordered(names), h.framing)?
        } else if self.verified(h.owner, None, None, h.unit) {
            h.unit
        } else {
            return Err(UNIT_FOREIGN);
        };
        let flow = if self.admits(&table, &h, unit) {
            FLOW_CONTINUE
        } else {
            FLOW_STOP
        };
        if let Some(u) = self.units().get_mut(&unit.id) {
            u.head = Some(h.head);
        }
        Ok((flow, unit))
    }

    /// The hand-in's checks (a) to (c) (l.953-958).
    fn admits(&self, table: &Table, h: &HandIn, unit: UnitRef) -> bool {
        let lines = table.listener.guests.lines();
        let Some(line) = lines.get(h.line as usize) else {
            return false;
        };
        // (a) the handle is the line's own, and the line is the list's own match.
        if table.line_of(h.auth) != Some(h.line) {
            return false;
        }
        let fields: Vec<(&str, &[u8])> = h
            .head
            .fields
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        match table
            .listener
            .guests
            .matched(&h.head.method, &h.head.target, &fields)
        {
            Matched::Line(m) if std::ptr::eq::<Line>(m, line) => {}
            _ => return false,
        }
        let units = self.units();
        let Some(u) = units.get(&unit.id) else {
            return false;
        };
        if u.line != h.line || u.generation != h.generation {
            return false;
        }
        // (b) unless the line's auth is none, a first-hand identity from that line's auth.
        if matches!(line.auth, LineAuth::Chain(..))
            && !matches!(u.fixed(), Some(Fixed::Admitted(_)))
        {
            return false;
        }
        // (c) nothing the auths named is still present.
        !still_present(&u.strips, &h.head)
    }

    /// `unit.refuse`: the refusal's bytes, from the builders the data router answers with today.
    /// The unit, when there is one, is refused and leaves the table. Never pends.
    ///
    /// # Errors
    ///
    /// [`NO_LIST`], [`NO_LINE`] for a line the list does not hold, [`UNIT_FOREIGN`] for a unit the
    /// kernel did not mint for this owner and line, [`CAUSE_UNKNOWN`].
    pub fn refuse(&self, r: Refuse) -> Result<Refusal, &'static str> {
        use axum::http::StatusCode;
        let table = self.table(r.owner, r.generation).ok_or(NO_LIST)?;
        let line = if r.cause == REFUSE_NO_ROUTE {
            None
        } else {
            Some(
                table
                    .listener
                    .guests
                    .lines()
                    .get(r.line as usize)
                    .ok_or(NO_LINE)?,
            )
        };
        let unit = (!r.unit.is_none()).then_some(r.unit);
        if let Some(u) = unit {
            if !self.verified(r.owner, None, line.map(|_| r.line), u) {
                return Err(UNIT_FOREIGN);
            }
        }
        let (head, overloaded) = unit
            .and_then(|u| {
                self.units()
                    .get(&u.id)
                    .map(|s| (s.head.clone(), s.fixed() == Some(Fixed::Overloaded)))
            })
            .unwrap_or((None, false));
        // The unit's own head first, then the request the transport hands with the refusal.
        // RED: the request is not read.
        let _ = r.request;
        let path = head
            .as_ref()
            .map(|h| h.target.clone())
            .or_else(|| line.map(|l| l.route.path.clone()))
            .unwrap_or_else(|| "/".to_string());
        let target = head
            .as_ref()
            .map(Head::path_and_query)
            .unwrap_or_else(|| path.clone());
        let app = &table.listener.app;
        let resp = match r.cause {
            REFUSE_NO_ROUTE => crate::router::fallback_error_response(
                &app.planes,
                &path,
                StatusCode::NOT_FOUND,
                crate::taxonomy::ERR_TYPE_NOT_FOUND,
                "the requested resource was not found",
            ),
            REFUSE_METHOD_MISS => crate::router::fallback_error_response(
                &app.planes,
                &path,
                StatusCode::METHOD_NOT_ALLOWED,
                crate::taxonomy::ERR_TYPE_INVALID_REQUEST,
                "method not allowed for this resource",
            ),
            REFUSE_OVER_GATE => crate::router::fallback_error_response(
                &app.planes,
                &path,
                StatusCode::PAYLOAD_TOO_LARGE,
                crate::proxy::KIND_REQUEST_TOO_LARGE,
                "request body exceeds the maximum allowed size",
            ),
            REFUSE_STOPPED | REFUSE_CHECK_FAILED if overloaded => {
                crate::auth::verifier_overloaded_response()
            }
            REFUSE_STOPPED | REFUSE_CHECK_FAILED => {
                let method = head
                    .as_ref()
                    .and_then(|h| axum::http::Method::from_bytes(h.method.as_bytes()).ok());
                let door = method
                    .and_then(|m| table.doors.door_refusal(&path, &m).cloned())
                    .map(|refuse| (refuse, target));
                crate::auth::unauthorized_with_completion_taps(app, &path, door.as_ref())
            }
            _ => return Err(CAUSE_UNKNOWN),
        };
        let refusal = Refusal::of(resp);
        if let Some(u) = unit {
            self.exit(u.id);
        }
        (self.refused)(&RefusedUnit {
            unit: unit.map(|u| u.id),
            owner: r.owner,
            line: r.line,
            cause: r.cause,
            status: refusal.status,
        });
        Ok(refusal)
    }
}

#[cfg(test)]
#[path = "tests/inbound_tests.rs"]
mod tests;
