// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, HashSet};
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

pub const NO_LIST: &str = "the kernel holds no guest list for this listener at this generation";

pub const NO_LINE: &str = "the handle names no line of this listener's list";

pub const LINE_OPEN: &str = "the line's auth is none: it has no auth to call";

pub const POINT_UNNEEDED: &str = "the line's auth needs no call at this point";

pub const PEER_BYTES: &str = "a peer-point call presents no unit, no request and no body";

pub const PEER_CONNECTIONS_MAX: usize = 65_536;

pub const PEER_TABLE_FULL: &str =
    "the kernel holds the most connection verdicts it may; this connection's peer call is refused";

pub const OVER_GATE: &str = "the body passes the line's size gate";

pub const UNIT_FOREIGN: &str = "the unit is not one the kernel minted for this request";

pub const UNIT_UNMINTED: &str = "the kernel could not mint the request's unit";

pub const CONN_MISMATCH: &str =
    "the call names another connection than the one its framing's calls named";

pub const CAUSE_UNKNOWN: &str = "the refusal names no cause the kernel answers";

pub const IDS_REFUSED: &str =
    "a line's handle id is 0, carries the binding bit, repeats, or the ids do not cover the lines";

pub const BINDING_BIT: u64 = 1 << 63;

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Head")
            .field("method", &self.method)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Drop for Head {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.target.zeroize();
        if let Some(query) = &mut self.query {
            query.zeroize();
        }
        for (_, value) in &mut self.fields {
            value.zeroize();
        }
    }
}

impl Head {
    fn stripped(&self, strips: &[Strip]) -> Option<Self> {
        use zeroize::Zeroize as _;
        let mut head = self.clone();
        head.fields.retain_mut(|(name, value)| {
            let remove = strips.iter().any(|strip| {
                strip.place == StripPlace::Field && strip.name.eq_ignore_ascii_case(name)
            });
            if remove {
                value.zeroize();
            }
            !remove
        });
        let keys: Vec<&str> = strips
            .iter()
            .filter(|strip| strip.place == StripPlace::Query)
            .map(|strip| strip.name.as_ref())
            .collect();
        if !keys.is_empty() {
            let bytes = bytes::Bytes::from_owner(FieldBytes(zeroize::Zeroizing::new(
                head.path_and_query().into_bytes(),
            )));
            let uri = axum::http::Uri::from_maybe_shared(bytes).ok()?;
            if let Some(stripped) = crate::auth::without_query_keys(&uri, &keys) {
                let mut original =
                    std::mem::replace(&mut head.query, stripped.query().map(str::to_owned));
                if let Some(query) = &mut original {
                    query.zeroize();
                }
            }
        }
        Some(head)
    }

    fn is_empty(&self) -> bool {
        self.method.is_empty()
            && self.target.is_empty()
            && self.authority.is_empty()
            && self.query.is_none()
            && self.fields.is_empty()
    }

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
    /// The request's stream on the connection.
    pub stream: u64,
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
    /// The request's stream on the connection.
    pub stream: u64,
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
    /// The connection carrying the refused request.
    pub conn: u64,
    /// The request's stream on the connection.
    pub stream: u64,
    /// The host framing making the refusal, absent for a ticketless call.
    pub framing: Option<u64>,
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitTag")
            .field("generation", &self.generation)
            .field("owner", &self.owner)
            .field("line", &self.line)
            .field("unit", &self.unit)
            .finish_non_exhaustive()
    }
}

pub type UnitMac = Arc<dyn Fn(&UnitTag) -> Option<u64> + Send + Sync>;

pub type MintUnit = Arc<dyn Fn() -> u64 + Send + Sync>;

pub type Spawn = Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>;

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
#[derive(Clone)]
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
    /// Whether a request's path is answered by a dialect that signs, supplied by [`SignedIngress`].
    pub signed_ingress: SignedIngress,
    /// Physical claimant resolution. Absent only for the original root listener API.
    pub scope: Option<ListenerScope>,
}

pub type ListenerAdmission =
    Arc<dyn Fn(&App, &Head) -> Option<crate::plane_driver::dispatch::PlaneAdmission> + Send + Sync>;

/// Host-only route ownership retained with one listener generation.
#[derive(Clone)]
pub struct ListenerScope {
    /// Resolve the selected claimant's own audience, never another listener's path match.
    pub admission: ListenerAdmission,
    /// Whether the root's legacy fallback surface is physically present.
    pub legacy_fallback: bool,
}

impl Listener {
    fn admission(&self, head: &Head) -> Option<crate::plane_driver::dispatch::PlaneAdmission> {
        self.scope.as_ref().map_or_else(
            || self.app.planes.admission_for(&head.target).cloned(),
            |scope| (scope.admission)(&self.app, head),
        )
    }
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

/// A host-claimed request admission. Only a successful hand-in can create one; plugins never
/// receive this Rust value. Its application snapshot belongs to this request across reloads.
#[derive(Clone)]
pub struct RequestAdmission {
    pub(crate) inner: Arc<AdmittedRequest>,
}

pub(crate) struct AdmittedRequest {
    table: Arc<Table>,
    pub(crate) admitted: Option<Admitted>,
    pub(crate) credential: Option<Secret<String>>,

    pub(crate) signed: bool,
    pub(crate) original: Head,
    pub(crate) strips: Vec<Strip>,
    replay: Option<Arc<ReplayAdmission>>,
    deadline: Option<std::time::Instant>,
    alive: Arc<std::sync::atomic::AtomicBool>,
}

struct ReplayAdmission {
    pending: crate::auth::PendingClaim,
    won: tokio::sync::OnceCell<bool>,
}

impl RequestAdmission {
    #[must_use]
    pub fn body_limit(&self) -> u64 {
        self.inner.table.listener.body_limit
    }

    pub(crate) fn plane_admission(&self) -> Option<crate::plane_driver::dispatch::PlaneAdmission> {
        self.inner.table.listener.admission(&self.inner.original)
    }

    pub(crate) fn app(&self) -> Arc<App> {
        Arc::clone(&self.inner.table.listener.app)
    }

    pub(crate) fn verdict(&self) -> crate::auth::ChainVerdict {
        admission_verdict(self.inner.admitted.as_ref())
    }

    pub(crate) async fn claim_replay(&self) -> bool {
        claim_request_replay(
            &self.inner.alive,
            self.inner.replay.as_deref(),
            self.inner.deadline,
        )
        .await
    }
}

fn admitted_identity(
    provider: String,
    mut identity: VerifiedIdentity,
    resolved: Option<Arc<crate::governance::VirtualKey>>,
) -> (Admitted, Option<Secret<String>>) {
    let credential = identity.credential.take();
    (
        Admitted {
            provider,
            identity,
            resolved,
        },
        credential,
    )
}

fn admission_verdict(admitted: Option<&Admitted>) -> crate::auth::ChainVerdict {
    match admitted {
        None => crate::auth::ChainVerdict::Open,
        Some(admitted) => crate::auth::ChainVerdict::Identified {
            module: admitted.provider.clone(),
            principal: admitted.resolved.as_ref().map_or_else(
                || busbar_contract::auth::Principal {
                    id: admitted.identity.subject.clone(),
                    name: admitted.identity.name.clone(),
                    roles: admitted.identity.groups.clone(),
                    ttl_secs: admitted.identity.ttl_secs,
                },
                |key| crate::auth::principal_from_vkey(key),
            ),
            resolved: admitted.resolved.clone(),
        },
    }
}

async fn claim_request_replay(
    alive: &std::sync::atomic::AtomicBool,
    replay: Option<&ReplayAdmission>,
    deadline: Option<std::time::Instant>,
) -> bool {
    if !alive.load(std::sync::atomic::Ordering::Acquire) {
        return false;
    }
    let Some(replay) = replay else {
        return true;
    };
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        return false;
    }
    let won = until_deadline(deadline, replay.won.get_or_init(|| replay.pending.win()))
        .await
        .copied()
        .unwrap_or(false);
    won && alive.load(std::sync::atomic::Ordering::Acquire)
}

fn same_request(left: &Head, right: &Head) -> bool {
    fn fields(head: &Head) -> std::collections::BTreeMap<String, Vec<&[u8]>> {
        let mut fields = std::collections::BTreeMap::<String, Vec<&[u8]>>::new();
        for (name, value) in &head.fields {
            fields
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value);
        }
        fields
    }
    left.method == right.method
        && left.target == right.target
        && left.authority == right.authority
        && left.query == right.query
        && fields(left) == fields(right)
}

fn continuation_head(original: &Head, current: &Head, strips: &[Strip]) -> bool {
    if same_request(original, current) {
        return true;
    }
    if original.method != current.method
        || original.target != current.target
        || original.authority != current.authority
    {
        return false;
    }
    fn fields(head: &Head) -> std::collections::BTreeMap<String, Vec<&[u8]>> {
        let mut fields = std::collections::BTreeMap::<String, Vec<&[u8]>>::new();
        for (name, value) in &head.fields {
            fields
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value);
        }
        fields
    }
    let mut current_fields = fields(current);
    for (name, values) in fields(original) {
        let retained = current_fields.remove(&name).unwrap_or_default();
        if strips
            .iter()
            .any(|strip| strip.place == StripPlace::Field && strip.name.eq_ignore_ascii_case(&name))
        {
            let mut retained = retained.into_iter();
            let mut next = retained.next();
            for value in values {
                if next == Some(value) {
                    next = retained.next();
                }
            }
            if next.is_some() {
                return false;
            }
        } else if values != retained {
            return false;
        }
    }
    if !current_fields.is_empty() {
        return false;
    }
    let mut retained = current
        .query
        .as_deref()
        .into_iter()
        .flat_map(|query| query.split('&'));
    let mut next = retained.next();
    for pair in original
        .query
        .as_deref()
        .into_iter()
        .flat_map(|query| query.split('&'))
    {
        if next == Some(pair) {
            next = retained.next();
            continue;
        }
        let key = pair.split_once('=').map_or(pair, |(key, _)| key);
        let decoded = url::form_urlencoded::parse(key.as_bytes())
            .next()
            .map(|(key, _)| key);
        if !strips.iter().any(|strip| {
            strip.place == StripPlace::Query
                && (strip.name == key || decoded.as_deref() == Some(strip.name.as_ref()))
        }) {
            return false;
        }
    }
    next.is_none()
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RequestBinding {
    conn: u64,
    stream: u64,
    framing: Option<u64>,
}

struct UnitState {
    table: Arc<Table>,
    owner: u64,
    generation: u64,
    line: u32,
    binding: RequestBinding,
    secret: [u64; 2],
    head: Option<Head>,

    handed_head: Option<Head>,
    claimed: bool,
    deadline: Option<std::time::Instant>,
    alive: Arc<std::sync::atomic::AtomicBool>,
    answers: Vec<Option<Judged>>,

    providers: Vec<String>,

    identities: Vec<Option<VerifiedIdentity>>,
    replays: Vec<Option<Arc<ReplayAdmission>>>,
    replay: Option<Arc<ReplayAdmission>>,
    strips: Vec<Strip>,
    admitted: Option<Admitted>,

    credential: Option<Secret<String>>,
    signed: bool,

    signed_pending: bool,

    resolved: Option<Arc<crate::governance::VirtualKey>>,
}

impl Drop for UnitState {
    fn drop(&mut self) {
        self.alive
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

impl UnitState {
    fn open(
        owner: u64,
        generation: u64,
        line: u32,
        secret: [u64; 2],
        providers: &[String],
        binding: RequestBinding,
        table: Arc<Table>,
    ) -> Self {
        Self {
            table,
            owner,
            generation,
            line,
            binding,
            secret,
            head: None,
            handed_head: None,
            claimed: false,
            deadline: None,
            alive: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            answers: vec![None; providers.len()],
            providers: providers.to_vec(),
            identities: vec![None; providers.len()],
            replays: vec![None; providers.len()],
            replay: None,
            strips: Vec::new(),
            admitted: None,
            credential: None,
            signed: false,
            signed_pending: false,
            resolved: None,
        }
    }

    fn settle(&mut self) {
        match self.fixed() {
            Some(Fixed::Admitted(i)) if self.admitted.is_none() => {
                if let Some(id) = self.identities.get_mut(i).and_then(Option::take) {
                    self.replay = self.replays.get_mut(i).and_then(Option::take);
                    let provider = self.providers.get(i).cloned().unwrap_or_default();
                    let resolved = if provider == crate::config::KEYS_MODULE {
                        self.resolved.take()
                    } else {
                        None
                    };
                    let (admitted, credential) = admitted_identity(provider, id, resolved);
                    self.credential = credential;
                    self.admitted = Some(admitted);
                }
                self.identities.clear();
                self.replays.clear();
                self.resolved = None;
            }
            Some(Fixed::Denied | Fixed::Overloaded) => {
                self.identities.clear();
                self.replays.clear();
                self.resolved = None;
            }
            _ => {}
        }
    }

    fn fixed(&self) -> Option<Fixed> {
        self.fixed_at(false)
    }

    fn fixed_at(&self, peer: bool) -> Option<Fixed> {
        fixed_answer_at(
            &self.answers,
            &self.providers,
            &self.table.request_auths,
            peer,
        )
    }
}

fn fixed_answer_at(
    answers: &[Option<Judged>],
    providers: &[String],
    request_auths: &HashSet<String>,
    peer: bool,
) -> Option<Fixed> {
    for (i, a) in answers.iter().enumerate() {
        if peer
            && request_auths.contains(&providers[i])
            && matches!(a, Some(Judged::Identity | Judged::Pass))
        {
            return None;
        }
        match a {
            None => return None,
            Some(Judged::Pass) => {}
            Some(Judged::Identity) => return Some(Fixed::Admitted(i)),
            Some(Judged::Denied) => return Some(Fixed::Denied),
            Some(Judged::Overloaded) => return Some(Fixed::Overloaded),
        }
    }

    Some(Fixed::Denied)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PositionWork {
    Finished,
    Answered,
    Verify,
}

fn position_work(fixed: Option<Fixed>, answer: Option<Judged>) -> PositionWork {
    match (fixed, answer) {
        (Some(_), _) => PositionWork::Finished,
        (None, Some(_)) => PositionWork::Answered,
        (None, None) => PositionWork::Verify,
    }
}

struct InheritedPeerAnswer {
    index: usize,
    answer: Option<Judged>,
    identity: Option<VerifiedIdentity>,
    replay: Option<Arc<ReplayAdmission>>,
}

fn inherited_peer_answers<'a>(
    providers: &'a [String],
    request_auths: &'a HashSet<String>,
    answers: &'a [Option<Judged>],
    identities: &'a [Option<VerifiedIdentity>],
    replays: &'a [Option<Arc<ReplayAdmission>>],
) -> impl Iterator<Item = InheritedPeerAnswer> + 'a {
    answers
        .iter()
        .copied()
        .enumerate()
        .filter_map(move |(index, answer)| {
            if request_auths.contains(&providers[index])
                && matches!(answer, Some(Judged::Identity | Judged::Pass))
            {
                return None;
            }
            Some(InheritedPeerAnswer {
                index,
                answer,
                identity: identities.get(index).cloned().flatten(),
                replay: replays.get(index).cloned().flatten(),
            })
        })
}

fn peer_capacity(existing: bool, held: usize) -> Result<(), &'static str> {
    if !existing && held >= PEER_CONNECTIONS_MAX {
        Err(PEER_TABLE_FULL)
    } else {
        Ok(())
    }
}

fn take_framing_peers<T>(peers: &mut HashMap<(u64, u64, u64), T>, framing: u64) -> Vec<T> {
    peers
        .extract_if(|(_, _, f), _| *f == framing)
        .map(|(_, peer)| peer)
        .collect()
}

fn peer_payload_empty(unit: UnitRef, head: &Head, body: Option<&[u8]>) -> bool {
    unit.is_none() && body.is_none() && head.is_empty()
}

fn inbound_answer(fixed: Option<Fixed>, unit: UnitRef, peer: bool, strips: &[Strip]) -> Answer {
    Answer {
        flow: match fixed {
            Some(Fixed::Denied | Fixed::Overloaded) => FLOW_STOP,
            Some(Fixed::Admitted(_)) | None => FLOW_CONTINUE,
        },
        unit,
        strips: if peer { Vec::new() } else { strips.to_vec() },
    }
}

fn checked_line_ids(ids: &[u64], lines: usize) -> Result<HashMap<u64, u32>, &'static str> {
    let lines_by_id: HashMap<u64, u32> = ids.iter().copied().zip(0u32..).collect();
    if ids.len() != lines || lines_by_id.len() != lines || !ids.iter().all(|id| is_line_id(*id)) {
        return Err(IDS_REFUSED);
    }
    Ok(lines_by_id)
}

fn connection_allows_key_prestep(answers: &[Option<Judged>]) -> bool {
    !answers
        .iter()
        .any(|answer| matches!(answer, Some(Judged::Denied | Judged::Overloaded)))
}

enum SignedReaderStep {
    Pass(Vec<Strip>),
    Final(Option<VerifyAnswer>),
}

fn signed_reader_step(answer: Option<VerifyAnswer>, faulted: bool) -> SignedReaderStep {
    match answer {
        Some(answer) if !faulted && matches!(&answer.verified, Verified::Pass) => {
            SignedReaderStep::Pass(answer.strips)
        }
        answer => SignedReaderStep::Final(answer),
    }
}

struct Table {
    listener: Listener,
    doors: crate::core_routes::CoreRouteTable,

    lines_by_id: HashMap<u64, u32>,

    request_auths: HashSet<String>,
}

struct FramingListener {
    listener: u64,
    generation: u64,
    opening: Option<Arc<Table>>,
    ended_streams: HashSet<u64>,
    status: FramingStatus,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FramingStatus {
    Active,
    Detached,
    Adopting,
}

struct PendingAdoption {
    source: busbar_contract::framing_scope::AdoptionSource,
    id: u64,
    unit: UnitState,
}

impl Table {
    fn line_of(&self, id: u64) -> Option<u32> {
        self.lines_by_id.get(&id).copied()
    }
}

type StreamGrants = HashMap<(u64, u64, u64), (u64, Arc<Table>)>;

pub struct Inbound {
    tables: RwLock<HashMap<(u64, u64, u64), Arc<Table>>>,

    framing_listeners: Mutex<HashMap<(u64, u64), FramingListener>>,

    stream_grants: Mutex<StreamGrants>,
    units: Mutex<HashMap<u64, UnitState>>,
    adoptions: Mutex<HashMap<(u64, u64), PendingAdoption>>,

    framing_conns: Mutex<HashMap<(u64, u64), u64>>,

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

fn fresh_secret() -> Option<[u64; 2]> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).ok()?;
    let (a, z) = b.split_at(8);
    Some([
        u64::from_le_bytes(a.try_into().ok()?),
        u64::from_le_bytes(z.try_into().ok()?),
    ])
}

fn same(want: u64, got: u64) -> bool {
    std::hint::black_box(want ^ got) == 0
}

fn still_present(strips: &[Strip], head: &Head) -> bool {
    strips.iter().any(|s| match s.place {
        StripPlace::Field => head
            .fields
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(&s.name)),
        StripPlace::Query => head.query.as_deref().is_some_and(|q| {
            q.split('&').any(|pair| {
                let key = pair.split_once('=').map_or(pair, |(key, _)| key);
                let decoded = url::form_urlencoded::parse(key.as_bytes())
                    .next()
                    .map(|(key, _)| key);
                key == s.name || decoded.as_deref() == Some(s.name.as_ref())
            })
        }),
    })
}

fn verify_request(
    head: &Head,
    point: AuthPoint,
    conn: u64,
    unit: u64,
    body: Option<&[u8]>,
    candidate: Option<&Secret<String>>,
) -> VerifyRequest {
    VerifyRequest {
        point,
        conn,
        unit,
        credential: candidate.map(|candidate| {
            Secret::new(candidate.expose(&crate::seal::lend()).as_bytes().to_vec())
        }),
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

async fn until_deadline<F: Future>(
    deadline: Option<std::time::Instant>,
    future: F,
) -> Option<F::Output> {
    match (deadline, tokio::runtime::Handle::try_current()) {
        (Some(deadline), Ok(_)) => {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
                .await
                .ok()
        }
        _ => Some(future.await),
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

enum PositionKind {
    Plugin(Option<Arc<dyn AuthCalls>>),

    Keys,
}

struct Position {
    index: usize,
    provider: String,
    kind: PositionKind,
}

enum Judging<'a> {
    Nothing,

    Keys(&'a Head, Option<SignedAnswer>),

    Answer(VerifyAnswer),
}

struct SignedAnswer {
    answer: VerifyAnswer,
    faulted: bool,
    kinds: Vec<String>,
    provider: String,
}

pub type SignedIngress = Arc<dyn Fn(&App, &str) -> bool + Send + Sync>;

struct FieldBytes(zeroize::Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for FieldBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(crate) fn header_map(head: &Head) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    for (n, v) in &head.fields {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(n.as_bytes()),
            axum::http::HeaderValue::from_maybe_shared(bytes::Bytes::from_owner(FieldBytes(
                zeroize::Zeroizing::new(v.clone()),
            ))),
        ) {
            let mut v = v;
            v.set_sensitive(true);
            headers.append(n, v);
        }
    }
    headers
}

fn ordered(names: &[String]) -> Vec<String> {
    let keys = crate::config::KEYS_MODULE;
    names
        .iter()
        .filter(|n| *n != keys)
        .chain(names.iter().filter(|n| *n == keys).take(1))
        .cloned()
        .collect()
}

fn signed_then_keys(
    app: &App,
    gov: Option<&crate::governance::GovState>,
    head: &Head,
    signed: Option<SignedAnswer>,
    now: u64,
    expected_aud: Option<&str>,
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
                            replay: id.replay,
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
    let (judged, identity, strips, resolved) = keys_judged(app, gov, head, now, expected_aud);
    named.extend(strips);
    (judged, identity, named, resolved)
}

fn keys_judged(
    app: &App,
    gov: Option<&crate::governance::GovState>,
    head: &Head,
    now: u64,
    expected_aud: Option<&str>,
) -> (
    Judged,
    Option<VerifiedIdentity>,
    Vec<Strip>,
    Option<Arc<crate::governance::VirtualKey>>,
) {
    let carriers = app.auth.carriers();
    let headers = header_map(head);
    let candidate = crate::auth::inbound_candidate(app, &headers);
    let strips = carriers
        .iter()
        .map(|c| Strip::field(c.as_str().to_string()))
        .collect();
    match crate::auth::keys_arm_verdict(
        gov,
        candidate
            .as_ref()
            .map(|candidate| candidate.expose(&crate::seal::lend()).as_str()),
        now,
        expected_aud,
    ) {
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
    #[must_use]
    pub fn new(seals: Seals, spawn: Spawn, refused: RefusedSink) -> Arc<Self> {
        Arc::new(Self {
            tables: RwLock::default(),
            framing_listeners: Mutex::default(),
            stream_grants: Mutex::default(),
            units: Mutex::default(),
            adoptions: Mutex::default(),
            peers: Mutex::default(),
            framing_conns: Mutex::default(),
            seals,
            spawn,
            refused,
        })
    }

    pub fn install(
        &self,
        owner: u64,
        generation: u64,
        listener: Listener,
    ) -> Result<(), &'static str> {
        self.install_at(owner, 0, generation, listener)
    }

    pub fn install_at(
        &self,
        owner: u64,
        listener_id: u64,
        generation: u64,
        listener: Listener,
    ) -> Result<(), &'static str> {
        let lines_by_id = checked_line_ids(&listener.ids, listener.guests.lines().len())?;
        let doors = crate::core_routes::CoreRouteTable::default()
            .with_door_refusals(listener.door_refusals.clone());
        let request_auths = listener
            .auths
            .iter()
            .filter(|(_, auth)| {
                let points = auth.inbound_points();
                points.has(AuthPoint::Head) || points.has(AuthPoint::HeadBody)
            })
            .map(|(name, _)| name.clone())
            .chain(std::iter::once(crate::config::KEYS_MODULE.to_owned()))
            .collect();
        let mut tables = self.tables.write().unwrap_or_else(PoisonError::into_inner);
        let mut retired = Vec::new();
        let replaced = tables.insert(
            (owner, listener_id, generation),
            Arc::new(Table {
                listener,
                doors,
                lines_by_id,
                request_auths,
            }),
        );
        retired.extend(replaced);
        tables.retain(|(o, listener, g), table| {
            let keep = *o != owner || *listener != listener_id || g.saturating_add(1) >= generation;
            if !keep {
                retired.push(Arc::clone(table));
            }
            keep
        });
        drop(tables);
        drop(retired);
        Ok(())
    }

    #[must_use]
    pub fn specs(&self, owner: u64, generation: u64) -> Option<Vec<LineSpec>> {
        self.table(owner, generation).map(|t| t.listener.specs())
    }

    fn table(&self, owner: u64, generation: u64) -> Option<Arc<Table>> {
        self.table_at(owner, 0, generation)
    }

    fn table_at(&self, owner: u64, listener: u64, generation: u64) -> Option<Arc<Table>> {
        self.tables
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(owner, listener, generation))
            .cloned()
    }

    #[must_use]
    pub fn specs_at(&self, owner: u64, listener: u64, generation: u64) -> Option<Vec<LineSpec>> {
        self.table_at(owner, listener, generation)
            .map(|t| t.listener.specs())
    }

    pub fn retire_before(&self, generation: u64) {
        let mut tables = self.tables.write().unwrap_or_else(PoisonError::into_inner);
        let mut retired = Vec::new();
        tables.retain(|(_, _, old), table| {
            if old.saturating_add(1) < generation {
                retired.push(Arc::clone(table));
                false
            } else {
                true
            }
        });
        drop(tables);
        drop(retired);
    }

    pub fn forget_listener(&self, owner: u64, listener: u64) {
        let mut tables = self.tables.write().unwrap_or_else(PoisonError::into_inner);
        let mut retired = Vec::new();
        tables.retain(|(o, l, _), table| {
            if *o == owner && *l == listener {
                retired.push(Arc::clone(table));
                false
            } else {
                true
            }
        });
        drop(tables);
        drop(retired);
    }

    pub fn framing_started(
        &self,
        owner: u64,
        listener: u64,
        framing: u64,
        generation: u64,
    ) -> Result<(), &'static str> {
        if owner == 0 || listener == 0 || framing == 0 {
            return Err(NO_LIST);
        }
        let table = self.table_at(owner, listener, generation).ok_or(NO_LIST)?;
        let mut held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match held.entry((owner, framing)) {
            std::collections::hash_map::Entry::Vacant(at) => {
                at.insert(FramingListener {
                    listener,
                    generation,
                    opening: Some(Arc::clone(&table)),
                    ended_streams: HashSet::new(),
                    status: FramingStatus::Active,
                });
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(at)
                if at.get().listener == listener
                    && at.get().generation == generation
                    && at.get().status == FramingStatus::Active =>
            {
                Ok(())
            }
            _ => Err(UNIT_FOREIGN),
        }
    }

    pub fn framing_ready(&self, owner: u64, framing: u64) {
        let opening = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&(owner, framing))
            .and_then(|binding| binding.opening.take());
        drop(opening);
    }

    pub fn framing_detached(&self, owner: u64, framing: u64) -> Result<(), &'static str> {
        let mut held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let source = held.get_mut(&(owner, framing)).ok_or(UNIT_FOREIGN)?;
        if source.status != FramingStatus::Active {
            return Err(UNIT_FOREIGN);
        }
        source.status = FramingStatus::Detached;
        Ok(())
    }

    fn claimed_session(
        units: &HashMap<u64, UnitState>,
        source: busbar_contract::framing_scope::AdoptionSource,
    ) -> Result<(u64, u64, u32, [u64; 2]), &'static str> {
        let mut matching = units.iter().filter(|(_, unit)| {
            unit.owner == source.owner
                && unit.binding.framing == Some(source.leg)
                && unit.claimed
                && unit.handed_head.is_some()
        });
        let (&id, unit) = matching.next().ok_or(UNIT_FOREIGN)?;
        if matching.next().is_some()
            || unit.binding.conn != source.conn
            || !unit.alive.load(std::sync::atomic::Ordering::Acquire)
            || unit
                .replay
                .as_ref()
                .is_some_and(|replay| replay.won.get() != Some(&true))
        {
            return Err(UNIT_FOREIGN);
        }
        Ok((id, unit.generation, unit.line, unit.secret))
    }

    pub fn framing_adopting(
        &self,
        source: busbar_contract::framing_scope::AdoptionSource,
        owner: u64,
        framing: u64,
    ) -> Result<busbar_contract::framing_scope::SessionTransfer, &'static str> {
        if owner == 0 || framing == 0 || framing == source.leg || source.conn == 0 {
            return Err(UNIT_FOREIGN);
        }
        let original = {
            let held = self
                .framing_listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let binding = held.get(&(source.owner, source.leg)).ok_or(UNIT_FOREIGN)?;
            if binding.listener != source.listener || binding.status != FramingStatus::Detached {
                return Err(UNIT_FOREIGN);
            }
            Self::claimed_session(&self.units(), source)?
        };
        let (id, generation, line, _) = original;
        let secret = fresh_secret().ok_or(UNIT_UNMINTED)?;
        let mac = (self.seals.mac)(&UnitTag {
            secret,
            generation,
            owner,
            line,
            unit: id,
        })
        .ok_or(UNIT_UNMINTED)?;
        let mut held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let binding = held.get(&(source.owner, source.leg)).ok_or(UNIT_FOREIGN)?;
        if binding.listener != source.listener
            || binding.status != FramingStatus::Detached
            || held.contains_key(&(owner, framing))
        {
            return Err(UNIT_FOREIGN);
        }
        let mut pending = self
            .adoptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if pending.contains_key(&(owner, framing))
            || pending.values().any(|p| p.source.leg == source.leg)
        {
            return Err(UNIT_FOREIGN);
        }
        let mut units = self.units();
        if Self::claimed_session(&units, source)? != original {
            return Err(UNIT_FOREIGN);
        }
        let stream = units.get(&id).ok_or(UNIT_FOREIGN)?.binding.stream;
        if binding.ended_streams.contains(&stream) {
            return Err(UNIT_FOREIGN);
        }
        let mut unit = units.remove(&id).ok_or(UNIT_FOREIGN)?;
        unit.owner = owner;
        unit.secret = secret;
        pending.insert((owner, framing), PendingAdoption { source, id, unit });
        held.insert(
            (owner, framing),
            FramingListener {
                listener: source.listener,
                generation,
                opening: None,
                ended_streams: HashSet::new(),
                status: FramingStatus::Adopting,
            },
        );
        Ok(busbar_contract::framing_scope::SessionTransfer {
            session: busbar_contract::abi::transport::adopted_session::AdoptedSession {
                stream,
                unit: UnitRef { id, mac },
            },
            generation,
        })
    }

    pub fn framing_adopted(&self, owner: u64, framing: u64, conn: u64) -> Result<(), &'static str> {
        if conn == 0 {
            return Err(UNIT_FOREIGN);
        }
        let mut held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let destination = held.get(&(owner, framing)).ok_or(UNIT_FOREIGN)?;
        if destination.status != FramingStatus::Adopting {
            return Err(UNIT_FOREIGN);
        }
        let mut pending = self
            .adoptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let stage = pending.get(&(owner, framing)).ok_or(UNIT_FOREIGN)?;
        if !held
            .get(&(stage.source.owner, stage.source.leg))
            .is_some_and(|source| source.status == FramingStatus::Detached)
            || destination
                .ended_streams
                .contains(&stage.unit.binding.stream)
        {
            return Err(UNIT_FOREIGN);
        }
        let mut conns = self
            .framing_conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if conns.contains_key(&(owner, framing)) {
            return Err(CONN_MISMATCH);
        }
        let mut units = self.units();
        if units.contains_key(&stage.id) {
            return Err(UNIT_FOREIGN);
        }
        let mut stage = pending.remove(&(owner, framing)).ok_or(UNIT_FOREIGN)?;
        stage.unit.binding.conn = conn;
        stage.unit.binding.framing = Some(framing);
        units.insert(stage.id, stage.unit);
        conns.insert((owner, framing), conn);
        held.get_mut(&(owner, framing)).ok_or(UNIT_FOREIGN)?.status = FramingStatus::Active;
        Ok(())
    }

    pub fn grant_stream(
        &self,
        owner: u64,
        framing: u64,
        stream: u64,
        generation: u64,
    ) -> Result<(), &'static str> {
        let key = (owner, framing, stream);
        let (listener, opening_generation) = {
            let held = self
                .framing_listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let binding = held.get(&(owner, framing)).ok_or(NO_LIST)?;
            if binding.status != FramingStatus::Active || binding.ended_streams.contains(&stream) {
                return Err(UNIT_FOREIGN);
            }
            let grants = self
                .stream_grants
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some((granted, _)) = grants.get(&key) {
                return if *granted == generation {
                    Ok(())
                } else {
                    Err(UNIT_FOREIGN)
                };
            }
            (binding.listener, binding.generation)
        };
        let table = self.table_at(owner, listener, generation).ok_or(NO_LIST)?;
        let held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let binding = held.get(&(owner, framing)).ok_or(NO_LIST)?;
        if binding.listener != listener
            || binding.generation != opening_generation
            || binding.status != FramingStatus::Active
        {
            return Err(UNIT_FOREIGN);
        }
        if binding.ended_streams.contains(&stream) {
            return Err(UNIT_FOREIGN);
        }
        let mut grants = self
            .stream_grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match grants.entry(key) {
            std::collections::hash_map::Entry::Vacant(at) => {
                at.insert((generation, Arc::clone(&table)));
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(at) if at.get().0 == generation => Ok(()),
            _ => Err(UNIT_FOREIGN),
        }
    }

    fn request_table(
        &self,
        owner: u64,
        generation: u64,
        binding: RequestBinding,
        unit: UnitRef,
        peer: bool,
    ) -> Result<Arc<Table>, &'static str> {
        if unit.is_none() {
            if let Some(framing) = binding.framing {
                let held = self
                    .framing_listeners
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if let Some(listener) = held.get(&(owner, framing)) {
                    if listener.status != FramingStatus::Active {
                        return Err(UNIT_FOREIGN);
                    }
                    if peer && listener.generation == generation {
                        if let Some(table) = &listener.opening {
                            return Ok(Arc::clone(table));
                        }
                    }
                    return self
                        .stream_grants
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get(&(owner, framing, binding.stream))
                        .filter(|(granted, _)| *granted == generation)
                        .map(|(_, table)| Arc::clone(table))
                        .ok_or(NO_LIST);
                }
            }
            return self.table(owner, generation).ok_or(NO_LIST);
        }
        if !self.verified(owner, Some(generation), None, binding, unit) {
            return Err(UNIT_FOREIGN);
        }
        self.units()
            .get(&unit.id)
            .map(|u| Arc::clone(&u.table))
            .ok_or(UNIT_FOREIGN)
    }

    fn units(&self) -> std::sync::MutexGuard<'_, HashMap<u64, UnitState>> {
        self.units.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn peers(&self) -> std::sync::MutexGuard<'_, HashMap<(u64, u64, u64), UnitState>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[must_use]
    pub fn unit_secret(&self, owner: u64, unit: u64) -> Option<([u64; 2], u64, u32)> {
        self.units()
            .get(&unit)
            .filter(|u| u.owner == owner)
            .map(|u| (u.secret, u.generation, u.line))
    }

    #[must_use]
    pub fn admitted(&self, unit: u64) -> Option<Admitted> {
        self.units().get(&unit).and_then(|u| u.admitted.clone())
    }

    pub fn claim_request(
        &self,
        owner: u64,
        framing: u64,
        stream: u64,
        head: &Head,
    ) -> Result<RequestAdmission, &'static str> {
        let held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let binding = held.get(&(owner, framing)).ok_or(NO_LIST)?;
        if binding.status != FramingStatus::Active || binding.ended_streams.contains(&stream) {
            return Err(UNIT_FOREIGN);
        }
        let mut units = self.units();
        let mut matching = units.iter().filter(|(_, unit)| {
            unit.owner == owner
                && unit.binding.framing == Some(framing)
                && unit.binding.stream == stream
                && !unit.claimed
                && unit.handed_head.is_some()
        });
        let id = *matching.next().ok_or(UNIT_FOREIGN)?.0;
        if matching.next().is_some() {
            return Err(UNIT_FOREIGN);
        }
        let unit = units.get_mut(&id).ok_or(UNIT_FOREIGN)?;
        let handed = unit.handed_head.as_ref().ok_or(UNIT_FOREIGN)?;
        if !same_request(handed, head) {
            return Err(UNIT_FOREIGN);
        }
        let line = unit
            .table
            .listener
            .guests
            .lines()
            .get(unit.line as usize)
            .ok_or(NO_LINE)?;
        if matches!(line.auth, LineAuth::Chain(..)) && unit.admitted.is_none() {
            return Err(UNIT_FOREIGN);
        }
        let admission = RequestAdmission {
            inner: Arc::new(AdmittedRequest {
                table: Arc::clone(&unit.table),
                admitted: unit.admitted.clone(),
                credential: unit.credential.clone(),
                signed: unit.signed,
                original: unit.head.as_ref().unwrap_or(handed).clone(),
                strips: unit.strips.clone(),
                replay: unit.replay.clone(),
                deadline: unit.deadline,
                alive: Arc::clone(&unit.alive),
            }),
        };
        unit.claimed = true;
        Ok(admission)
    }

    pub fn with_credential<R>(&self, unit: u64, f: impl FnOnce(&Secret<String>) -> R) -> Option<R> {
        self.units()
            .get(&unit)
            .and_then(|u| u.credential.as_ref())
            .map(f)
    }

    pub fn exit(&self, unit: u64) {
        let retired = self.units().remove(&unit);
        drop(retired);
    }

    pub fn framing_ended(&self, framing: u64) {
        let mut held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let retired_bindings: Vec<_> = held
            .extract_if(|(_, f), _| *f == framing)
            .map(|(_, binding)| binding)
            .collect();
        let retired_adoptions: Vec<_> = self
            .adoptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extract_if(|(_, leg), stage| *leg == framing || stage.source.leg == framing)
            .map(|(_, stage)| stage)
            .collect();
        let retired_grants: Vec<_> = self
            .stream_grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extract_if(|(_, f, _), _| *f == framing)
            .map(|(_, grant)| grant)
            .collect();
        let retired_units: Vec<_> = self
            .units()
            .extract_if(|_, u| u.binding.framing == Some(framing))
            .map(|(_, u)| u)
            .collect();
        let retired_peers = take_framing_peers(&mut self.peers(), framing);
        self.framing_conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(_, f), _| *f != framing);
        drop(held);
        drop((
            retired_bindings,
            retired_adoptions,
            retired_grants,
            retired_units,
            retired_peers,
        ));
    }

    pub fn stream_ended(&self, owner: u64, framing: u64, stream: u64) {
        let mut held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(binding) = held.get_mut(&(owner, framing)) {
            binding.ended_streams.insert(stream);
        }
        let retired_grant = self
            .stream_grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(owner, framing, stream));
        let retired_units: Vec<_> = self
            .units()
            .extract_if(|_, unit| {
                unit.owner == owner
                    && unit.binding.framing == Some(framing)
                    && unit.binding.stream == stream
            })
            .map(|(_, unit)| unit)
            .collect();
        drop(held);
        drop((retired_grant, retired_units));
    }

    fn same_conn(
        &self,
        owner: u64,
        generation: u64,
        framing: u64,
        conn: u64,
    ) -> Result<(), &'static str> {
        let held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let registered =
            held.contains_key(&(owner, framing)) || self.table(owner, generation).is_some();
        let mut conns = self
            .framing_conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match conns.entry((owner, framing)) {
            std::collections::hash_map::Entry::Occupied(e) if *e.get() != conn => {
                Err(CONN_MISMATCH)
            }
            std::collections::hash_map::Entry::Occupied(_) => Ok(()),

            std::collections::hash_map::Entry::Vacant(_) if !registered => Err(NO_LIST),
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(conn);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn peer_verdicts(&self) -> usize {
        self.peers().len()
    }

    fn mint(
        &self,
        owner: u64,
        generation: u64,
        line: u32,
        providers: &[String],
        binding: RequestBinding,
        table: Arc<Table>,
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
        let mut state = UnitState::open(owner, generation, line, secret, providers, binding, table);
        if let Some(framing) = binding.framing {
            let peers = self.peers();
            if let Some(peer) = peers
                .get(&(owner, generation, framing))
                .filter(|p| p.providers == providers)
            {
                for inherited in inherited_peer_answers(
                    providers,
                    &state.table.request_auths,
                    &peer.answers,
                    &peer.identities,
                    &peer.replays,
                ) {
                    state.answers[inherited.index] = inherited.answer;
                    state.identities[inherited.index] = inherited.identity;
                    state.replays[inherited.index] = inherited.replay;
                }
            }
        }
        state.settle();

        let held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(framing) = binding.framing {
            match held.get(&(owner, framing)) {
                Some(listener) => {
                    if listener.status != FramingStatus::Active
                        || listener.ended_streams.contains(&binding.stream)
                        || !self
                            .stream_grants
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get(&(owner, framing, binding.stream))
                            .is_some_and(|(g, policy)| {
                                *g == generation && Arc::ptr_eq(policy, &state.table)
                            })
                    {
                        return Err(UNIT_FOREIGN);
                    }
                }
                None if self.table(owner, generation).is_some() => {}
                None => return Err(UNIT_FOREIGN),
            }
        }
        self.units().insert(unit, state);
        Ok(UnitRef { id: unit, mac })
    }

    fn verified(
        &self,
        owner: u64,
        generation: Option<u64>,
        line: Option<u32>,
        binding: RequestBinding,
        r: UnitRef,
    ) -> bool {
        let held = self
            .framing_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(framing) = binding.framing {
            if held.get(&(owner, framing)).is_some_and(|listener| {
                listener.status != FramingStatus::Active
                    || listener.ended_streams.contains(&binding.stream)
            }) {
                return false;
            }
        }
        let units = self.units();
        let Some(u) = units.get(&r.id) else {
            return false;
        };
        if u.owner != owner
            || u.binding != binding
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

    fn with_state<R>(&self, target: Target, f: impl FnOnce(&mut UnitState) -> R) -> Option<R> {
        match target {
            Target::Unit(unit) => self.units().get_mut(&unit).map(f),
            Target::Peer(key) => self.peers().get_mut(&key).map(f),
        }
    }

    fn prepare(
        self: &Arc<Self>,
        mut call: Call,
    ) -> Result<impl Future<Output = Result<Answer, &'static str>> + Send + 'static, &'static str>
    {
        let body = call.body.take().map(zeroize::Zeroizing::new);
        let first_request = call.unit.is_none();
        let binding = RequestBinding {
            conn: call.conn,
            stream: call.stream,
            framing: Some(call.framing),
        };

        let peer = AuthPoint::from_bit(call.point) == Some(AuthPoint::Peer);
        let policy_unit = if peer { UnitRef::NONE } else { call.unit };
        let table = self.request_table(call.owner, call.generation, binding, policy_unit, peer)?;
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

        let peer = point == AuthPoint::Peer;
        if peer && !peer_payload_empty(call.unit, &call.head, body.as_deref().map(Vec::as_slice)) {
            return Err(PEER_BYTES);
        }
        if body
            .as_ref()
            .is_some_and(|b| b.len() as u64 > table.listener.body_limit)
        {
            return Err(OVER_GATE);
        }
        self.same_conn(call.owner, call.generation, call.framing, call.conn)?;
        let (target, unit) = if peer {
            let held = self
                .framing_listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !held.contains_key(&(call.owner, call.framing))
                && self.table(call.owner, call.generation).is_none()
            {
                return Err(NO_LIST);
            }
            let key = (call.owner, call.generation, call.framing);
            let mut peers = self.peers();
            if peer_capacity(peers.contains_key(&key), peers.len()).is_err() {
                tracing::error!(
                    owner = call.owner,
                    conn = call.conn,
                    held = peers.len(),
                    "{PEER_TABLE_FULL}"
                );
                return Err(PEER_TABLE_FULL);
            }
            peers.entry(key).or_insert_with(|| {
                UnitState::open(
                    call.owner,
                    call.generation,
                    line_ix,
                    [0; 2],
                    &providers,
                    binding,
                    Arc::clone(&table),
                )
            });
            (Target::Peer(key), UnitRef::NONE)
        } else {
            let unit = if call.unit.is_none() {
                self.mint(
                    call.owner,
                    call.generation,
                    line_ix,
                    &providers,
                    binding,
                    Arc::clone(&table),
                )?
            } else if self.verified(
                call.owner,
                Some(call.generation),
                Some(line_ix),
                binding,
                call.unit,
            ) {
                call.unit
            } else {
                return Err(UNIT_FOREIGN);
            };
            {
                let mut units = self.units();
                let u = units.get_mut(&unit.id).ok_or(UNIT_FOREIGN)?;
                if u.owner != call.owner
                    || u.generation != call.generation
                    || u.line != line_ix
                    || u.binding != binding
                    || u.head
                        .as_ref()
                        .is_some_and(|original| !continuation_head(original, &call.head, &u.strips))
                {
                    return Err(UNIT_FOREIGN);
                }
                u.deadline = call.deadline;
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

        let points = *points;
        let keys_point = if points.has(AuthPoint::HeadBody) {
            AuthPoint::HeadBody
        } else {
            AuthPoint::Head
        };
        let me = Arc::clone(self);
        let deadline = call.deadline;
        let (head, conn) = (call.head, call.conn);
        Ok(async move {
            let original = (!peer)
                .then(|| me.with_state(target, |u| u.head.clone()).flatten())
                .flatten();
            let candidate = original.as_ref().and_then(|head| {
                crate::auth::inbound_candidate(&table.listener.app, &header_map(head))
            });

            let unfinished = me
                .with_state(target, |u| {
                    first_request || u.signed_pending || u.fixed().is_none()
                })
                .ok_or(UNIT_FOREIGN)?;
            if unfinished && !peer && table.listener.app.auth.keys_in_chain {
                let connection_denied = me
                    .with_state(target, |u| !connection_allows_key_prestep(&u.answers))
                    .ok_or(UNIT_FOREIGN)?;
                let method = axum::http::Method::from_bytes(head.method.as_bytes()).ok();
                let prefix = method
                    .as_ref()
                    .and_then(|method| table.doors.door_ticket(&head.target, method));
                let token = candidate
                    .as_ref()
                    .map(|c| c.expose(&crate::seal::lend()).as_str());
                let keys = positions
                    .iter()
                    .find(|p| matches!(p.kind, PositionKind::Keys));
                let signed_reader = (table.listener.admission(&head).is_none()
                    && (table.doors.signed_ingress(&head.target)
                        || (table.listener.signed_ingress)(&table.listener.app, &head.target)))
                .then(|| {
                    table
                        .listener
                        .app
                        .auth
                        .signed_reader(&header_map(original.as_ref().unwrap_or(&head)))
                })
                .flatten();
                if let (Some(keys), Some((provider, calls, kinds))) = (keys, signed_reader) {
                    if !connection_denied {
                        me.with_state(target, |u| u.signed_pending = true)
                            .ok_or(UNIT_FOREIGN)?;
                        if deadline.is_some_and(|d| std::time::Instant::now() >= d)
                            || !points.has(AuthPoint::HeadBody)
                        {
                            me.preflight_keys(target, keys.index)?;
                            me.record(target, keys.index, &keys.provider, Judging::Nothing, &table);
                            return me.answer(target, unit, peer);
                        }
                        if point != AuthPoint::HeadBody {
                            return me.answer(target, unit, peer);
                        }
                        let req = verify_request(
                            original.as_ref().unwrap_or(&head),
                            AuthPoint::HeadBody,
                            conn,
                            unit.id,
                            Some(body.as_ref().map_or(&[], |b| b.as_slice())),
                            None,
                        );
                        let mut verifying = calls.verify(req);
                        let answer = until_deadline(deadline, &mut verifying).await;
                        let faulted = verifying.faulted();
                        match signed_reader_step(answer, faulted) {
                            SignedReaderStep::Pass(strips) => {
                                me.with_state(target, |u| {
                                    u.signed_pending = false;
                                    for strip in strips {
                                        if !u.strips.contains(&strip) {
                                            u.strips.push(strip);
                                        }
                                    }
                                })
                                .ok_or(UNIT_FOREIGN)?;
                            }
                            SignedReaderStep::Final(answer) => {
                                me.preflight_keys(target, keys.index)?;
                                let judging = match answer {
                                    Some(answer) => Judging::Keys(
                                        original.as_ref().unwrap_or(&head),
                                        Some(SignedAnswer {
                                            faulted,
                                            answer,
                                            kinds,
                                            provider,
                                        }),
                                    ),
                                    None => Judging::Nothing,
                                };
                                me.record(target, keys.index, &keys.provider, judging, &table);
                                return me.answer(target, unit, peer);
                            }
                        }
                    }
                }
                if let (Some(prefix), Some(token), Some(keys)) = (prefix, token, keys) {
                    if token.starts_with(prefix) && !connection_denied {
                        let key = match table.listener.app.governance.as_ref() {
                            Some(gov)
                                if !deadline.is_some_and(|d| std::time::Instant::now() >= d) =>
                            {
                                until_deadline(
                                    deadline,
                                    gov.peek_ticket_async(prefix, token, crate::store::now()),
                                )
                                .await
                                .flatten()
                            }
                            _ => None,
                        };
                        let flow = if key.is_some() {
                            FLOW_CONTINUE
                        } else {
                            FLOW_STOP
                        };
                        let (retired, strips) = me
                            .with_state(target, |u| {
                                let retired = (
                                    u.admitted.take(),
                                    u.credential.take(),
                                    u.resolved.take(),
                                    std::mem::take(&mut u.identities),
                                    std::mem::take(&mut u.replays),
                                    u.replay.take(),
                                );
                                u.signed = false;
                                u.signed_pending = false;
                                u.answers.fill(Some(Judged::Pass));
                                u.answers[keys.index] = Some(if key.is_some() {
                                    Judged::Identity
                                } else {
                                    Judged::Denied
                                });
                                u.admitted = key.map(|key| Admitted {
                                    provider: crate::config::KEYS_MODULE.to_string(),
                                    identity: VerifiedIdentity {
                                        subject: key.id.clone(),
                                        key_id: Some(key.id.clone()),
                                        key_name: Some(key.name.clone()),
                                        ..VerifiedIdentity::default()
                                    },
                                    resolved: Some(key),
                                });
                                for carrier in table.listener.app.auth.carriers() {
                                    let strip = Strip::field(carrier.as_str().to_string());
                                    if !u.strips.contains(&strip) {
                                        u.strips.push(strip);
                                    }
                                }
                                (retired, u.strips.clone())
                            })
                            .ok_or(UNIT_FOREIGN)?;
                        drop(retired);
                        return Ok(Answer { flow, unit, strips });
                    }
                }
            }
            for p in positions {
                let position = me
                    .with_state(target, |u| {
                        position_work(u.fixed_at(peer), u.answers.get(p.index).copied().flatten())
                    })
                    .ok_or(UNIT_FOREIGN)?;
                match position {
                    PositionWork::Finished => break,
                    PositionWork::Answered => continue,
                    PositionWork::Verify => {}
                }
                if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                    me.record(target, p.index, &p.provider, Judging::Nothing, &table);
                    break;
                }
                let calls = match &p.kind {
                    PositionKind::Keys => {
                        if point != keys_point {
                            continue;
                        }
                        me.record(
                            target,
                            p.index,
                            &p.provider,
                            Judging::Keys(original.as_ref().unwrap_or(&head), None),
                            &table,
                        );
                        continue;
                    }
                    PositionKind::Plugin(None) => {
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
                let req = verify_request(
                    &head,
                    point,
                    conn,
                    unit_id,
                    body.as_ref().map(|b| b.as_slice()),
                    candidate.as_ref(),
                );
                let mut verifying = calls.verify(req);
                let answer = until_deadline(deadline, &mut verifying).await;
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
            me.answer(target, unit, peer)
        })
    }

    fn answer(&self, target: Target, unit: UnitRef, peer: bool) -> Result<Answer, &'static str> {
        self.with_state(target, |u| {
            inbound_answer(u.fixed_at(peer), unit, peer, &u.strips)
        })
        .ok_or(UNIT_FOREIGN)
    }

    fn preflight_keys(&self, target: Target, index: usize) -> Result<(), &'static str> {
        let retired = self
            .with_state(target, |u| {
                let retired = (
                    u.admitted.take(),
                    u.credential.take(),
                    u.resolved.take(),
                    std::mem::take(&mut u.identities),
                    std::mem::take(&mut u.replays),
                    u.replay.take(),
                );
                u.answers.fill(Some(Judged::Pass));
                u.answers[index] = None;
                u.identities = vec![None; u.answers.len()];
                u.replays = vec![None; u.answers.len()];
                u.signed = false;
                u.signed_pending = false;
                retired
            })
            .ok_or(UNIT_FOREIGN)?;
        drop(retired);
        Ok(())
    }

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
        let signed_identity = matches!(&judging, Judging::Keys(_, Some(signed))
            if !signed.faulted && matches!(&signed.answer.verified, Verified::Identity(_)));
        let replay_provider = match &judging {
            Judging::Keys(_, Some(signed)) => signed.provider.as_str(),
            _ => provider,
        }
        .to_owned();
        let (judged, identity, strips, resolved) = match judging {
            Judging::Nothing => (Judged::Denied, None, Vec::new(), None),
            Judging::Keys(head, signed) => {
                let admission = table.listener.admission(head);
                signed_then_keys(
                    &table.listener.app,
                    gov,
                    head,
                    signed,
                    now,
                    admission
                        .as_ref()
                        .map(|admission| admission.audience.as_str()),
                )
            }
            Judging::Answer(a) => {
                let (judged, identity) = match a.verified {
                    Verified::Identity(id) => (Judged::Identity, Some(id)),
                    Verified::Pass => (Judged::Pass, None),
                    Verified::Reject | Verified::Failed => (Judged::Denied, None),
                    Verified::Overloaded => (Judged::Overloaded, None),
                };
                (judged, identity, a.strips, None)
            }
        };
        let replay = identity.as_ref().and_then(|id| {
            crate::auth::PendingClaim::for_identity(
                &replay_provider,
                id,
                table.listener.app.governance.clone(),
                now,
            )
            .map(|pending| {
                Arc::new(ReplayAdmission {
                    pending,
                    won: tokio::sync::OnceCell::new(),
                })
            })
        });
        self.with_state(target, |u| {
            if signed_identity && judged == Judged::Identity {
                u.signed = true;
            }
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
            if let Some(slot) = u.replays.get_mut(index) {
                *slot = replay;
            }
            if resolved.is_some() {
                u.resolved = resolved;
            }

            if matches!(target, Target::Unit(_)) {
                u.settle();
            }
        });
    }

    pub fn hand_in(&self, h: HandIn) -> Result<(u32, UnitRef), &'static str> {
        self.hand_in_with_deadline(h, None)
    }

    pub fn hand_in_with_deadline(
        &self,
        h: HandIn,
        deadline: Option<std::time::Instant>,
    ) -> Result<(u32, UnitRef), &'static str> {
        let binding = RequestBinding {
            conn: h.conn,
            stream: h.stream,
            framing: h.framing,
        };
        let table = self.request_table(h.owner, h.generation, binding, h.unit, false)?;
        if let Some(f) = h.framing {
            self.same_conn(h.owner, h.generation, f, h.conn)?;
        }
        let lines = table.listener.guests.lines();
        let unit = if h.unit.is_none() {
            let names: &[String] = match lines.get(h.line as usize).map(|l| &l.auth) {
                Some(LineAuth::Chain(names, _)) => names,
                _ => &[],
            };
            self.mint(
                h.owner,
                h.generation,
                h.line,
                &ordered(names),
                binding,
                Arc::clone(&table),
            )?
        } else if self.verified(h.owner, None, None, binding, h.unit) {
            h.unit
        } else {
            return Err(UNIT_FOREIGN);
        };
        let flow = if self.admits(&table, &h, unit) {
            FLOW_CONTINUE
        } else {
            FLOW_STOP
        };
        let mut units = self.units();
        let u = units.get_mut(&unit.id).ok_or(UNIT_FOREIGN)?;
        if u.head.is_none() {
            u.head = Some(h.head.clone());
        }
        if flow == FLOW_CONTINUE {
            if u.handed_head.is_some() || u.claimed {
                return Err(UNIT_FOREIGN);
            }
            u.handed_head = Some(h.head);
            u.deadline = deadline;
        }
        Ok((flow, unit))
    }

    fn admits(&self, table: &Table, h: &HandIn, unit: UnitRef) -> bool {
        let lines = table.listener.guests.lines();
        let Some(line) = lines.get(h.line as usize) else {
            return false;
        };

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
        if u.line != h.line || u.generation != h.generation || u.signed_pending {
            return false;
        }
        if let Some(original) = &u.head {
            if !original
                .stripped(&u.strips)
                .is_some_and(|original| same_request(&original, &h.head))
            {
                return false;
            }
        }

        if matches!(line.auth, LineAuth::Chain(..))
            && !matches!(u.fixed(), Some(Fixed::Admitted(_)))
        {
            return false;
        }

        !still_present(&u.strips, &h.head)
    }

    pub fn refuse(&self, r: Refuse) -> Result<Refusal, &'static str> {
        use axum::http::StatusCode;
        let table = self.request_table(
            r.owner,
            r.generation,
            RequestBinding {
                conn: r.conn,
                stream: r.stream,
                framing: r.framing,
            },
            r.unit,
            false,
        )?;
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
            if !self.verified(
                r.owner,
                None,
                line.map(|_| r.line),
                RequestBinding {
                    conn: r.conn,
                    stream: r.stream,
                    framing: r.framing,
                },
                u,
            ) {
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

        let head = head.or(r.request);
        let path = head
            .as_ref()
            .map(|h| h.target.clone())
            .or_else(|| line.map(|l| l.route.path.clone()))
            .unwrap_or_else(|| "/".to_string());
        let target = zeroize::Zeroizing::new(
            head.as_ref()
                .map(Head::path_and_query)
                .unwrap_or_else(|| path.clone()),
        );
        let app = &table.listener.app;
        let respond = || {
            Ok(match r.cause {
                REFUSE_NO_ROUTE => crate::router::fallback_error_response(
                    &app.planes,
                    &path,
                    StatusCode::NOT_FOUND,
                    busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
                    "the requested resource was not found",
                ),
                REFUSE_METHOD_MISS => crate::router::fallback_error_response(
                    &app.planes,
                    &path,
                    StatusCode::METHOD_NOT_ALLOWED,
                    busbar_contract::protocol::ERR_TYPE_INVALID_REQUEST,
                    "method not allowed for this resource",
                ),
                REFUSE_OVER_GATE => crate::router::fallback_error_response(
                    &app.planes,
                    &path,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    busbar_contract::protocol::KIND_REQUEST_TOO_LARGE,
                    "request body exceeds the maximum allowed size",
                ),
                REFUSE_STOPPED | REFUSE_CHECK_FAILED if overloaded => {
                    crate::auth::verifier_unavailable_response()
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
            })
        };
        let resp = if table
            .listener
            .scope
            .as_ref()
            .is_none_or(|scope| scope.legacy_fallback)
        {
            respond()
        } else {
            crate::router::private_listener_scope(respond)
        }?;
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

#[cfg(test)]
#[path = "tests/inbound_owner_policies.rs"]
mod owner_policies;
