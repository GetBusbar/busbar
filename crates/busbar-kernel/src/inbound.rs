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

#![allow(dead_code, unused_imports)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use busbar_contract::abi::auth::{AuthPoint, POINT_HEAD_BODY, POINT_PEER};
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
/// The refusal text of an `auth.call` at the peer point: a connection's `Peer` verdict is not
/// served by this handle yet, and is refused rather than admitted.
pub const PEER_UNSERVED: &str = "the peer point is not served by the inbound handle";
/// The refusal text of a body past the line's size gate presented at the body point.
pub const OVER_GATE: &str = "the body passes the line's size gate";
/// The refusal text of a unit the kernel did not mint for this owner, generation and line.
pub const UNIT_FOREIGN: &str = "the unit is not one the kernel minted for this request";
/// The refusal text of a unit that could not be minted (no secret, or no MAC).
pub const UNIT_UNMINTED: &str = "the kernel could not mint the request's unit";
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
    /// The connection.
    pub conn: u64,
    /// The request.
    pub head: Head,
    /// The whole body, at the body point only.
    pub body: Option<Vec<u8>>,
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
    /// The request's target (path, `?query`), when the caller holds it. The unit's own head is read
    /// first; with neither, the line's route path, else the listener's root.
    pub target: Option<String>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The provider name.
    pub provider: String,
    /// The identity, its credential taken out.
    pub identity: VerifiedIdentity,
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
}

impl UnitState {
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

/// One position the walk may call.
struct Position {
    index: usize,
    provider: String,
    calls: Option<Arc<dyn AuthCalls>>,
}

impl Inbound {
    /// A kernel side with no tables yet.
    #[must_use]
    pub fn new(seals: Seals, spawn: Spawn, refused: RefusedSink) -> Arc<Self> {
        Arc::new(Self {
            tables: RwLock::default(),
            units: Mutex::default(),
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
        // RED: the ids are not judged.
        let _ = lines;
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

    /// Mint a unit for `owner`'s `line` at `generation`: its key, its fresh secret, its MAC.
    fn mint(
        &self,
        owner: u64,
        generation: u64,
        line: u32,
        providers: &[String],
    ) -> Result<UnitRef, &'static str> {
        let positions = providers.len();
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
        self.units().insert(
            unit,
            UnitState {
                owner,
                generation,
                line,
                secret,
                head: None,
                answers: vec![None; positions],
                providers: providers.to_vec(),
                identities: vec![None; positions],
                strips: Vec::new(),
                admitted: None,
                credential: None,
            },
        );
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
    /// a verify must be awaited, and `done` answers it (the call pends on its own ticket, l.973-974).
    pub fn auth_call(
        self: &Arc<Self>,
        call: Call,
        done: Done,
    ) -> Option<Result<Answer, &'static str>> {
        // RED: not yet served.
        let _ = (call, done);
        Some(Err(NO_LIST))
    }

    /// The checks before any auth is called, the unit minted or verified, then the walk.
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
        if call.point == POINT_PEER {
            return Err(PEER_UNSERVED);
        }
        let point = AuthPoint::from_bit(call.point)
            .filter(|p| points.has(*p))
            .ok_or(POINT_UNNEEDED)?;
        if call
            .body
            .as_ref()
            .is_some_and(|b| b.len() as u64 > table.listener.body_limit)
        {
            return Err(OVER_GATE);
        }
        let unit = if call.unit.is_none() {
            self.mint(call.owner, call.generation, line_ix, names)?
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
        let positions: Vec<Position> = names
            .iter()
            .enumerate()
            .map(|(index, name)| Position {
                index,
                provider: name.clone(),
                calls: table.listener.auths.get(name).cloned(),
            })
            .collect();
        let gov = table.listener.app.governance.clone();
        let me = Arc::clone(self);
        let (head, body, conn) = (call.head, call.body, call.conn);
        Ok(async move {
            for p in positions {
                {
                    let units = me.units();
                    let u = units.get(&unit.id).ok_or(UNIT_FOREIGN)?;
                    if u.fixed().is_some() {
                        break;
                    }
                    if u.answers.get(p.index).copied().flatten().is_some() {
                        continue;
                    }
                }
                let Some(calls) = p.calls else {
                    // A line naming an auth the generation did not open: fail closed.
                    me.record(unit.id, p.index, &p.provider, None, gov.as_deref());
                    continue;
                };
                if !calls.inbound_points().has(point) {
                    continue;
                }
                let req = verify_request(&head, point, conn, unit.id, body.as_deref());
                let mut verifying = calls.verify(req);
                let answer = (&mut verifying).await;
                let answered = if verifying.faulted() {
                    VerifyAnswer {
                        verified: Verified::Failed,
                        ..answer
                    }
                } else {
                    answer
                };
                me.record(
                    unit.id,
                    p.index,
                    &p.provider,
                    Some(answered),
                    gov.as_deref(),
                );
            }
            let units = me.units();
            let u = units.get(&unit.id).ok_or(UNIT_FOREIGN)?;
            let flow = match u.fixed() {
                Some(Fixed::Denied | Fixed::Overloaded) => FLOW_STOP,
                Some(Fixed::Admitted(_)) | None => FLOW_CONTINUE,
            };
            Ok(Answer {
                flow,
                unit,
                strips: u.strips.clone(),
            })
        })
    }

    /// Record position `index`'s answer on `unit` FIRST-HAND (`None`: no auth to call, a deny):
    /// its verdict by the data-plane chain rule, the lines it named, and on an identity that
    /// fixes the verdict its credential, taken out of the identity.
    fn record(
        &self,
        unit: u64,
        index: usize,
        provider: &str,
        answer: Option<VerifyAnswer>,
        gov: Option<&crate::governance::GovState>,
    ) {
        let mut units = self.units();
        let Some(u) = units.get_mut(&unit) else {
            return;
        };
        let (judged, identity) = match answer {
            None => (Judged::Denied, None),
            Some(a) => {
                for s in a.strips {
                    if !u.strips.contains(&s) {
                        u.strips.push(s);
                    }
                }
                match a.verified {
                    Verified::Identity(id) => {
                        let claimed = id.replay.as_deref().is_none_or(|r| {
                            crate::auth::replay_claimed(gov, provider, r, crate::store::now())
                        });
                        if claimed {
                            (Judged::Identity, Some(id))
                        } else {
                            (Judged::Denied, None)
                        }
                    }
                    Verified::Pass => (Judged::Pass, None),
                    Verified::Reject | Verified::Failed => (Judged::Denied, None),
                    Verified::Overloaded => (Judged::Overloaded, None),
                }
            }
        };
        if let Some(slot) = u.answers.get_mut(index) {
            *slot = Some(judged);
        }
        if let Some(slot) = u.identities.get_mut(index) {
            *slot = identity;
        }
        match u.fixed() {
            Some(Fixed::Admitted(i)) if u.admitted.is_none() => {
                if let Some(mut id) = u.identities.get_mut(i).and_then(Option::take) {
                    u.credential = id.credential.take();
                    u.admitted = Some(Admitted {
                        provider: u.providers.get(i).cloned().unwrap_or_default(),
                        identity: id,
                    });
                }
                u.identities.clear();
            }
            // A refusal admits no one: the identities a following position answered are dropped.
            Some(Fixed::Denied | Fixed::Overloaded) => u.identities.clear(),
            _ => {}
        }
    }

    /// `unit.hand_in`: `(flow, unit)`. A `none` line's request (and any request handed in with no
    /// unit) has its unit minted here, so a stop always names the unit it refuses. Never pends.
    ///
    /// # Errors
    ///
    /// [`NO_LIST`] for a listener the kernel holds no list for; [`UNIT_FOREIGN`] for a presented
    /// unit it did not mint for this owner; [`UNIT_UNMINTED`] when no unit could be minted.
    pub fn hand_in(&self, h: HandIn) -> Result<(u32, UnitRef), &'static str> {
        // RED: not yet served.
        let _ = h;
        Err(NO_LIST)
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
        // RED: not yet served.
        let _ = r;
        Err(NO_LIST)
    }
}

#[cfg(test)]
#[path = "tests/inbound_tests.rs"]
mod tests;
