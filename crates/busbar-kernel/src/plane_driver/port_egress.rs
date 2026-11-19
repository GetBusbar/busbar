// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The egress half of a port-driven session (IF §8.6, §12.3; PLANE-DRIVER.md slice 5, the part it left): the
//! old `far_end.rs` walk ([`EgressFarEnd`], async and token-bound) ported onto the port driver's seams.
//!
//! [`WalkMembers`] is [`Members`] and [`WalkSend`] is [`UpSend`] over any [`FarEnd`]: `next` is the walk's own
//! pick (breaker, permit, pool terminals, W_UPSTREAM through `allowed_member`, W_AFFINITY and the stream want
//! through the route), `open` is the far end's own `send` and `next` (the durable dispatch record, the member's
//! auth fields, the connector's open) with the reply read piece by piece, and the plane's verdicts are the
//! breaker's inputs (`failed` and `served` are `judged_stating`). Every step is awaited on the session's own task:
//! the egress holds no runtime handle, and the far end's I/O is woken where the session runs. The walk and its
//! carrier are static (generic over the [`FarEnd`]), so no step boxes a future; the far end is built from the
//! session's wants at the first pick, because the route it walks under (stream, affinity, pin) is only known once
//! the plane has forwarded.
//!
//! Every dial is judged. The connector judges the destination (the egress class of the member's Need, the guard's
//! name and address checks) as it always did; on top, core judges the transport with `transport_verdict` under the
//! plane instance's own core-held `accept` ([`UnitRoute::accept`], set by [`PortEgress`]): a plaintext target is
//! refused unless the instance's `insecure_transport.accept` holds `plaintext`. The plane never states or
//! chooses any of it.
//!
//! [`PortEgress`] is the production [`PortUpstream`] (an [`Egress`], a kernel, the pool the instance walks, how a
//! member reads as a plane `Target`); [`EgressProbes`] is its [`ProbeFar`], the probe service's side of the same
//! walk (`PortProbes`).

use std::hash::BuildHasher;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use busbar_contract::abi::transport::{FAULT_HARD, FAULT_NONE, FAULT_RATE_LIMIT, FAULT_TRANSIENT};
use busbar_contract::caps::{Pass, Route};
use busbar_contract::conn::NeedId;
use busbar_contract::kept::Text;
use busbar_kernel_egress::ports::{DestinationId, Outcome};
use busbar_plugin_abi::host_side::caller::Accept;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{
    ATT_HARD, CARRIER_DEFAULT, CARRIER_HTTP, CARRIER_WEBSOCKET, FC_RATE_LIMIT, MSG_BINARY, MSG_FIN,
    MSG_TEXT, OUTBOUND_NONE,
};

use super::far_end::{Egress, UnitRoute};
use super::port_probes::ProbeFar;
use super::port_serve::{Ran, SessionRun};
use super::port_session::{Owned, SessionError, UpExchange};
use super::port_upstream::{
    Candidate, Chunk, Failure, Members, ProbeOutcome, SendFailed, TargetIdentity, UpChunks, UpOpen,
    UpReply, UpSend, Wants, Whole,
};
use super::request_admission::{AdmittedRequest, RequestPoolReceipt, RequestWalk};
use super::route::{operator_name, FarEnd, OutboundRequest, Pick, RIDE_WEBSOCKET};
use crate::teller::Kernel;
use crate::upstreams::UpstreamDef;

#[path = "port_selected_send.rs"]
mod selected_send;
pub(crate) use selected_send::SelectedFailure;
pub use selected_send::{OwnedPreparation, SelectedHandoff, SelectedOpen, SelectedSendError};

/// The actual immutable definition retained by the route materializer.
#[derive(Clone)]
pub struct TargetDefinition(Arc<UpstreamDef>);

impl TargetDefinition {
    #[must_use]
    pub fn new(definition: Arc<UpstreamDef>) -> Self {
        Self(definition)
    }

    #[must_use]
    pub fn as_arc(&self) -> &Arc<UpstreamDef> {
        &self.0
    }
}

impl std::fmt::Debug for TargetDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetDefinition").finish_non_exhaustive()
    }
}

impl PartialEq for TargetDefinition {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for TargetDefinition {}

/// How a member reads as the plane's `Target` (§6.1): the plane-owned provider keys, the base path, TGT_* flags
/// and the route's configured parameters. Operator vocabulary only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberTarget {
    pub identity: TargetIdentity,
    /// Actual root-created definition; a matching name alone does not supply this association.
    pub definition: Option<TargetDefinition>,
    /// Optional operator-configured rate resource from this exact target record.
    pub resource: Option<Box<str>>,
    /// Exact admitted registration name. Provider models have no registration authority.
    pub registered_upstream: Option<Box<str>>,
    /// The plane-owned provider keys as one canonical JSON object.
    pub provider: Box<str>,
    pub base_path: Box<str>,
    pub flags: u32,
    pub params: Vec<(Box<str>, Box<str>)>,
}

impl MemberTarget {
    /// A member with no provider keys, no base path, no flags and no parameters.
    #[must_use]
    pub fn bare() -> Self {
        Self {
            identity: TargetIdentity::Registration,
            definition: None,
            resource: None,
            registered_upstream: None,
            provider: "{}".into(),
            base_path: "".into(),
            flags: 0,
            params: Vec::new(),
        }
    }
}

/// The exact selected `(pool, qualified member)` as a [`MemberTarget`]. Lookup never
/// falls back to an unqualified name; `None` makes the walk skip that member.
pub type Targets = Arc<dyn Fn(&str, &str) -> Option<MemberTarget> + Send + Sync>;

/// What one session needs of the egress side: the unit it bills to.
#[derive(Clone)]
pub struct SessionFacts {
    pub unit: busbar_contract::UnitKey,
    pub pending: Option<Arc<super::port_admission::Pending>>,
}

/// The production seam of `PortDriver::serve`: runs one session's walk. The seat holds it as a trait object, so this
/// is where a session crosses from dynamic to static dispatch, once: `walk` makes the walk's members and carrier
/// (concrete types) and awaits `run` over them, monomorphised for them. Its future is boxed: one allocation per
/// forwarded session, none per pick, send or reply chunk.
pub trait PortUpstream: Send + Sync {
    /// Read the immutable current target projection; this does not select or admit a dispatch.
    fn target(&self, _pool: &str, _qualified_member: &str) -> Option<MemberTarget> {
        None
    }
    fn walk<'a>(
        &'a self,
        facts: SessionFacts,
        run: SessionRun<'a>,
    ) -> BoxFut<'a, Result<Ran, SessionError>>;
}

/// The member in hand: its candidate, its preparation number, its provider and its target definition.
type InHand = (Candidate, u32, Box<str>, Option<TargetDefinition>);

/// The lane a member's money is priced, ledgered and metered under. A provider model is its
/// configured model name, the key the root `rate_card:` prices it by (v1.5.5's lane); any other
/// member is its plane-qualified name, priced by its plane's own card.
fn money_lane(member: &Candidate) -> &str {
    match member.identity {
        TargetIdentity::Model { .. } => &member.upstream,
        TargetIdentity::Registration => &member.qualified_member,
    }
}

/// One session's walk over a [`FarEnd`] built from the session's wants. What changes as the walk goes is kept in
/// [`Owned`] cells: the walk's members and its carrier both read it, across the awaits of the session's task.
struct Shared<'a, F: FarEnd> {
    make: &'a (dyn Fn(&Wants, Option<&RequestPoolReceipt>) -> F + Sync),
    far: OnceLock<F>,
    request_walk: Option<RequestWalk>,
    pending: Option<Arc<super::port_admission::Pending>>,
    admitted: OnceLock<AdmittedRequest>,
    selected: Owned<Option<InHand>>,
    token: &'a Pass<Route>,
    targets: &'a (dyn Fn(&str, &str) -> Option<MemberTarget> + Send + Sync),
    /// Picks made so far (the walk's attempt number).
    picks: Owned<u32>,
    preparations: Owned<u32>,
    /// The member (as the walk names it) and the pool in hand: the pick's own shared names.
    names: Owned<(Text, Text)>,
    /// The Retry-After the walk stated when it found no member left.
    exhausted_wait: Owned<Option<u32>>,
}

impl<F: FarEnd> Shared<'_, F> {
    fn far(&self, wants: &Wants) -> Option<&F> {
        if self.request_walk.is_some() && !self.admitted.get().is_some_and(AdmittedRequest::is_live)
        {
            return None;
        }
        Some(self.far.get_or_init(|| (self.make)(wants, None)))
    }

    /// The far end a hook stage inspects and constrains. On a request's own walk it is the one
    /// `select_request` built from the request's resolved walk (the key's grant of it is already
    /// judged), and it is read BEFORE the request's money is asked: a hook that refuses must
    /// have spoken before any unit is opened. It is never built here, and nothing is picked or
    /// sent through it: every pick and send goes through [`Self::far`], which still needs the
    /// admitted request.
    fn inspected(&self, wants: &Wants) -> Option<&F> {
        if self.request_walk.is_some() {
            return self.far.get();
        }
        Some(self.far.get_or_init(|| (self.make)(wants, None)))
    }

    /// The far end's request for `exchange` as the member in hand, at the walk's attempt number.
    fn request(&self, exchange: UpExchange) -> Option<OutboundRequest> {
        let picks = self.picks.get();
        self.names
            .with(|(member, pool)| request_of(member, pool, picks, exchange))
    }
}

/// Actual eligibility from this walk, consumed once by the selected money owner.
pub(crate) struct SelectedWalkAttempt {
    walk: RequestWalk,
    target: Candidate,
    preparation: u32,
    provider: Box<str>,
    definition: Option<TargetDefinition>,
}
impl SelectedWalkAttempt {
    pub(crate) fn walk(&self) -> &RequestWalk {
        &self.walk
    }
    pub(crate) fn target(&self) -> &Candidate {
        &self.target
    }
    pub(crate) fn pool(&self) -> &str {
        &self.target.pool
    }
    pub(crate) fn qualified_member(&self) -> &str {
        &self.target.qualified_member
    }
    pub(crate) fn preparation(&self) -> u32 {
        self.preparation
    }
    pub(crate) fn resource(&self) -> Option<&str> {
        self.target.resource.as_deref()
    }
    pub(crate) fn provider(&self) -> &str {
        &self.provider
    }
    pub(crate) fn definition(&self) -> Option<&Arc<UpstreamDef>> {
        self.definition.as_ref().map(TargetDefinition::as_arc)
    }
}

/// A walk over any [`FarEnd`]: the [`Members`] and the [`UpSend`] of one session, sharing its far end.
pub struct EgressWalk<'a, F: FarEnd> {
    shared: Shared<'a, F>,
}

/// Test orchestration over the real request, walk, admission and preparation producers.
/// It does not construct any selection or money token, and returns the still-live Task.
#[cfg(test)]
pub(crate) async fn prepare_fixture<
    'k,
    'w,
    K: super::port_session::Calls + ?Sized,
    F: FarEnd + Send,
>(
    calls: &'k K,
    request: &busbar_ports::plane::PlaneIn<'_>,
    body: &[u8],
    effects: &dyn super::port_session::Effects,
    pending: Arc<super::port_admission::Pending>,
    walk: EgressWalk<'w, F>,
) -> Result<
    (
        super::port_session::Task<'k, K>,
        super::PreparedRateAttempt,
        EgressWalk<'w, F>,
    ),
    super::port_session::SessionError,
> {
    use super::port_session::{Buffered, SessionError, Task};
    let walk = walk
        .pending(Arc::clone(&pending))
        .map_err(|_| SessionError::NotDriven)?;
    let held = Buffered::new(effects);
    let (mut task, first) = Task::begin(calls, request, body, &held)?;
    if !first.intents.is_empty() || !first.ex_msgs.is_empty() {
        return Err(SessionError::NotDriven);
    }
    let forward = first.forward.ok_or(SessionError::NotDriven)?;
    let wants = Wants::from_facts(&forward.wants);
    let mut members = walk.members();
    pending.admit(
        Some(&mut members),
        Some(&wants),
        task.request_declaration()?,
    )?;
    task.bind_admission(&pending)?;
    held.release();
    let target = members.next(&wants).await.ok_or(SessionError::NotDriven)?;
    let prepared = task
        .prepare_selected(&target, 1, "", "", effects)?
        .ok_or(SessionError::NotDriven)?;
    let selection = walk
        .sender()
        .take_selected(&target, prepared.attempt())
        .ok_or(SessionError::NotDriven)?;
    let prepared = if let Some(data) = task.data() {
        prepared.bind_resource(&selection, Arc::clone(data))?
    } else {
        prepared
    };
    let money = pending
        .admitted()
        .and_then(|admitted| admitted.selected.as_ref())
        .ok_or(SessionError::NotDriven)?;
    let prepared = money
        .prepare(selection, prepared)
        .map_err(|_| SessionError::NotDriven)?;
    Ok((task, prepared, walk))
}

impl<'a, F: FarEnd> EgressWalk<'a, F> {
    /// `make` builds the far end from the session's wants, at the first pick.
    pub fn new(
        make: &'a (dyn Fn(&Wants, Option<&RequestPoolReceipt>) -> F + Sync),
        token: &'a Pass<Route>,
        targets: &'a (dyn Fn(&str, &str) -> Option<MemberTarget> + Send + Sync),
    ) -> Self {
        Self {
            shared: Shared {
                make,
                far: OnceLock::new(),
                request_walk: None,
                pending: None,
                admitted: OnceLock::new(),
                selected: Owned::new(None),
                token,
                targets,
                picks: Owned::new(0),
                preparations: Owned::new(0),
                names: Owned::new((Text::EMPTY, Text::EMPTY)),
                exhausted_wait: Owned::new(None),
            },
        }
    }

    pub(crate) fn pending(
        mut self,
        pending: Arc<super::port_admission::Pending>,
    ) -> Result<Self, super::request_admission::AdmissionError> {
        self.shared.request_walk = Some(RequestWalk::new(pending.context())?);
        self.shared.pending = Some(pending);
        Ok(self)
    }

    /// The far end, once the first pick built it.
    #[must_use]
    pub fn far(&self) -> Option<&F> {
        self.shared.far.get()
    }

    #[must_use]
    pub fn members(&self) -> WalkMembers<'_, 'a, F> {
        WalkMembers(&self.shared)
    }

    #[must_use]
    pub fn sender(&self) -> WalkSend<'_, 'a, F> {
        WalkSend(&self.shared)
    }
}

/// [`Members`] over a [`FarEnd`].
pub struct WalkMembers<'s, 'a, F: FarEnd>(&'s Shared<'a, F>);

/// [`UpSend`] over a [`FarEnd`].
pub struct WalkSend<'s, 'a, F: FarEnd>(&'s Shared<'a, F>);

impl<F: FarEnd> WalkSend<'_, '_, F> {
    /// Consumes only the current eligible member of this exact admitted walk.
    pub(crate) fn take_selected(
        &mut self,
        target: &Candidate,
        preparation: u32,
    ) -> Option<SelectedWalkAttempt> {
        let shared = self.0;
        let walk = shared.request_walk.as_ref()?;
        let admitted = shared.admitted.get()?;
        if !admitted.is_live() || !admitted.accepts_walk(walk) {
            return None;
        }
        let (target, preparation, provider, definition) = shared.selected.with(|selected| {
            let (actual, ordinal, _, _) = selected.as_ref()?;
            if actual != target || *ordinal != preparation {
                return None;
            }
            selected.take()
        })?;
        Some(SelectedWalkAttempt {
            walk: walk.clone(),
            target,
            preparation,
            provider,
            definition,
        })
    }
}

/// The breaker's reading of the plane's verdict (the old `OnPieceOut::fault`).
fn fault_of(failure: &Failure) -> u8 {
    if failure.verdict == ATT_HARD {
        FAULT_HARD
    } else if failure.class == FC_RATE_LIMIT {
        FAULT_RATE_LIMIT
    } else {
        FAULT_TRANSIENT
    }
}

impl<F: FarEnd + Send> Members for WalkMembers<'_, '_, F> {
    fn request_walk(&self) -> Option<&RequestWalk> {
        self.0.request_walk.as_ref()
    }

    fn select_request(&mut self, receipt: &RequestPoolReceipt, wants: &Wants) -> bool {
        let Some(key) = receipt.walk_key() else {
            return false;
        };
        if self.0.request_walk.is_none() || self.0.far.get().is_some() {
            return false;
        }
        let far = (self.0.make)(wants, Some(receipt));
        if far
            .scope(self.0.token)
            .as_ref()
            .is_none_or(|scope| scope.pool != key)
        {
            return false;
        }
        self.0.far.set(far).is_ok()
    }

    fn admit_request(&mut self, request: &AdmittedRequest) -> bool {
        let Some(walk) = self.0.request_walk.as_ref() else {
            return false;
        };
        let Some(far) = self.0.far.get() else {
            return false;
        };
        if !request.accepts_walk(walk)
            || far
                .scope(self.0.token)
                .as_ref()
                .is_none_or(|scope| Some(scope.pool.as_str()) != request.walk_key())
        {
            return false;
        }
        self.0.admitted.set(request.clone()).is_ok()
    }
    fn hook_remaining(&self) -> Option<usize> {
        self.0.far.get()?.remaining(self.0.token)
    }
    fn hook_failure(&self) -> Option<&str> {
        self.0.far.get()?.failure(self.0.token)
    }

    fn hook_candidates(&mut self, wants: &Wants) -> Option<super::hooks::Candidates> {
        let far = self.0.inspected(wants)?;
        far.candidates(self.0.token)
    }

    fn hook_scope(&mut self, wants: &Wants) -> Option<super::RoutedScope> {
        let far = self.0.inspected(wants)?;
        far.scope(self.0.token)
    }

    fn hook_lane(&mut self, wants: &Wants, index: usize) -> Option<String> {
        let far = self.0.inspected(wants)?;
        far.candidate_lane(self.0.token, index)
    }

    fn hook_constrain(&mut self, wants: &Wants, constraint: super::hooks::Constraint) -> bool {
        let Some(far) = self.0.inspected(wants) else {
            return false;
        };
        if far.candidates(self.0.token).is_none() {
            return false;
        }
        far.constrain(self.0.token, constraint);
        true
    }

    async fn next(&mut self, wants: &Wants) -> Option<Candidate> {
        let s = self.0;
        s.selected.set(None);
        let far = s.far(wants)?;
        loop {
            let n = s.picks.get().saturating_add(1);
            s.picks.set(n);
            match far.member(s.token, n).await {
                Pick::Member {
                    name,
                    pool,
                    provider,
                    ..
                } => {
                    let Some(target) = (s.targets)(&pool, &name) else {
                        continue;
                    };
                    // The plane's candidate states its pool and member as its own text.
                    let candidate = Candidate {
                        pool: pool.as_str().into(),
                        upstream: String::from_utf8_lossy(operator_name(name.as_bytes())).into(),
                        qualified_member: name.as_str().into(),
                        identity: target.identity,
                        resource: target.resource,
                        provider: target.provider,
                        base_path: target.base_path,
                        flags: target.flags,
                        params: target.params,
                    };
                    // A member whose lane the request's rate card cannot price is never dialled:
                    // the call is refused before it is served, never served as free (#42).
                    if s.pending
                        .as_ref()
                        .is_some_and(|pending| pending.lane_unpriced(money_lane(&candidate)))
                    {
                        tracing::warn!(
                            member = %candidate.upstream,
                            "the rate card in force names no price for this member's lane; it is not dialled"
                        );
                        continue;
                    }
                    // The names in hand are the pick's own: moved in, nothing copied.
                    s.names.set((name, pool));
                    let preparation = s.preparations.get().checked_add(1)?;
                    s.preparations.set(preparation);
                    s.selected.set(Some((
                        candidate.clone(),
                        preparation,
                        provider.as_str().into(),
                        target.definition,
                    )));
                    return Some(candidate);
                }
                Pick::Exhausted { retry_after, .. } => {
                    s.exhausted_wait.set(retry_after);
                    return None;
                }
                // Vetoed or refused: no member is left.
                _ => return None,
            }
        }
    }

    fn declined(&mut self, _member: &Candidate) {
        self.0.selected.set(None);
        // Never dialled and nothing to charge: the next pick settles the attempt and frees its permit.
    }

    fn failed(&mut self, _member: &Candidate, failure: &Failure) {
        if let Some(far) = self.0.far.get() {
            // The plane's own wait (a body Retry-After it read) rides with its verdict into the breaker (§12.3).
            let wait = (failure.retry_after_s > 0).then_some(failure.retry_after_s);
            far.judged_waiting(self.0.token, fault_of(failure), wait);
        }
    }

    fn served(&mut self, member: &Candidate) {
        let s = self.0;
        if let Some(far) = s.far.get() {
            far.judged_stating(s.token, FAULT_NONE, None);
        }
        // The unit's money follows the member that served it: its lane and its provider.
        if let Some(pending) = &s.pending {
            s.selected.with(|held| {
                if let Some((selected, _, provider, _)) = held
                    .as_ref()
                    .filter(|(selected, ..)| selected.qualified_member == member.qualified_member)
                {
                    pending.served(money_lane(selected), provider);
                }
            });
        }
    }

    fn retry_after(&self) -> Option<u32> {
        self.0.exhausted_wait.get()
    }
}

/// The far end's request for `exchange` as `member` in `pool`, attempt `attempt`: the exchange moves
/// in, its header list, method, path, scope and body become the request's own with no copy, and its
/// outbound mode is the request's `no_member_auth`. `None` = an exchange this carrier does not send
/// (another carrier, no method or path).
///
/// A `CARRIER_WEBSOCKET` exchange (owner decision 18) is the handshake request of a WebSocket far end: it
/// rides the member's WebSocket transport ([`RIDE_WEBSOCKET`]), its verb is GET when the plane stated none,
/// and it has no body (a handshake has none: an exchange that states one is not sent). The member's
/// credential leads its head exactly as an HTTP request's does; the handshake's own lines are the
/// transport's and are never taken from the plane's head (the connector drops them).
fn request_of(
    member: &Text,
    pool: &Text,
    attempt: u32,
    exchange: UpExchange,
) -> Option<OutboundRequest> {
    let websocket = exchange.carrier == CARRIER_WEBSOCKET;
    if !websocket && !matches!(exchange.carrier, CARRIER_DEFAULT | CARRIER_HTTP) {
        return None;
    }
    let UpExchange {
        outbound,
        method,
        path,
        scope,
        headers: fields,
        body,
        ..
    } = exchange;
    if websocket && !body.is_empty() {
        return None;
    }
    let verb = match method {
        Some(method) => method.into_boxed_bytes().into_vec(),
        None if websocket => b"GET".to_vec(),
        None => return None,
    };
    Some(OutboundRequest {
        member: member.clone(),
        pool: pool.clone(),
        attempt_no: attempt,
        verb,
        target: path?.into_boxed_bytes().into_vec(),
        fields,
        body,
        need: if websocket { RIDE_WEBSOCKET } else { 0 },
        text: false,
        scope: scope.map(|scope| scope.into_boxed_bytes().into_vec()),
        no_member_auth: outbound == OUTBOUND_NONE,
    })
}

/// Whether `request` is what [`request_of`] builds from these parts for `request.attempt_no`, compared in
/// place: the selected path's custody keeps its exchange and asks only whether a request is its own.
pub(super) fn is_request_of(
    request: &OutboundRequest,
    member: &str,
    pool: &str,
    exchange: &UpExchange,
) -> bool {
    if !matches!(exchange.carrier, CARRIER_DEFAULT | CARRIER_HTTP) {
        return false;
    }
    let (Some(method), Some(path)) = (exchange.method.as_deref(), exchange.path.as_deref()) else {
        return false;
    };
    request.member == member
        && request.pool == pool
        && request.verb == method.as_bytes()
        && request.target == path.as_bytes()
        && request.fields == exchange.headers
        && request.body == exchange.body
        && request.need == 0
        && !request.text
        && request.scope.as_deref() == exchange.scope.as_deref().map(str::as_bytes)
        && request.no_member_auth == (exchange.outbound == OUTBOUND_NONE)
}

/// The rest of a reply, read from the far end as the plane takes it, on the session's task.
pub struct Chunks<'a, F: FarEnd> {
    far: &'a F,
    token: &'a Pass<Route>,
    pending: Option<Chunk>,
    done: bool,
    /// The messages the `upstream` answer wrote beside a WebSocket handshake head: written after the 101.
    queued: Vec<(u32, Vec<u8>)>,
    /// The code the far end closed with, from the cut piece that ended the read (`FarPiece::close_code`).
    closed: Option<u32>,
}

impl<F: FarEnd> UpChunks for Chunks<'_, F> {
    async fn next(&mut self) -> Result<Option<Chunk>, SendFailed> {
        if let Some(chunk) = self.pending.take() {
            return Ok(Some(chunk));
        }
        while !self.done {
            let Some(piece) = self.far.next(self.token).await else {
                self.done = true;
                break;
            };
            if piece.last {
                self.done = true;
                if piece.cut {
                    return Err(SendFailed);
                }
            }
            if piece.bytes.is_empty() {
                continue;
            }
            return Ok(Some(if piece.fields {
                Chunk::Trailers(piece.bytes)
            } else {
                Chunk::Body(piece.bytes)
            }));
        }
        Ok(None)
    }

    /// The far end's next message piece. The read is the far end's own (`FarEnd::next`): dropped while it
    /// waits, it has taken nothing.
    async fn next_message(&mut self) -> Result<Option<super::port_duplex::UpMessage>, SendFailed> {
        // Bytes that came with the handshake answer's head are not a message: a 101 has no body.
        self.pending = None;
        while !self.done {
            let Some(piece) = self.far.next(self.token).await else {
                self.done = true;
                break;
            };
            if piece.last {
                self.done = true;
                if piece.cut {
                    self.closed = piece.close_code;
                    return Err(SendFailed);
                }
            }
            if piece.fields {
                continue;
            }
            let flags = match piece.message {
                Some(message) => {
                    let kind = match message.text {
                        Some(true) => MSG_TEXT,
                        // A table that does not say what the message is hands it on as bytes.
                        Some(false) | None => MSG_BINARY,
                    };
                    if message.fin {
                        kind | MSG_FIN
                    } else {
                        kind
                    }
                }
                // A far end that states no messages: nothing but its end is read.
                None if piece.bytes.is_empty() => continue,
                None => MSG_BINARY | MSG_FIN,
            };
            return Ok(Some(super::port_duplex::UpMessage {
                flags,
                bytes: piece.bytes,
            }));
        }
        Ok(None)
    }

    async fn write_message(&mut self, flags: u32, bytes: Vec<u8>) -> bool {
        if self.done {
            return false;
        }
        self.far
            .write(
                self.token,
                OutboundRequest {
                    body: bytes,
                    text: flags & MSG_TEXT != 0,
                    ..OutboundRequest::default()
                },
            )
            .await
    }

    async fn close(&mut self) {
        if !self.done {
            self.done = true;
            let _ = self.far.close(self.token).await;
        }
    }

    fn take_queued(&mut self) -> Vec<(u32, Vec<u8>)> {
        std::mem::take(&mut self.queued)
    }

    fn close_code(&self) -> Option<u32> {
        self.closed
    }
}

/// The rest of a reply's body, read to its end: the first body chunk's own buffer becomes the body and a later
/// chunk is appended to it (trailers are not body).
async fn whole_body<R: UpChunks>(rest: &mut R) -> Result<Vec<u8>, SendFailed> {
    let mut body: Option<Vec<u8>> = None;
    while let Some(chunk) = rest.next().await? {
        if let Chunk::Body(bytes) = chunk {
            match &mut body {
                None => body = Some(bytes),
                Some(body) => body.extend_from_slice(&bytes),
            }
        }
    }
    Ok(body.unwrap_or_default())
}

/// Sends `exchange` through `far` and reads the reply's head.
async fn open_on<'a, F: FarEnd>(
    far: &'a F,
    token: &'a Pass<Route>,
    request: OutboundRequest,
) -> Result<UpOpen<Chunks<'a, F>>, SendFailed> {
    if !far.send(token, request).await {
        return Err(SendFailed);
    }
    read_open(far, token).await
}

async fn read_open<'a, F: FarEnd>(
    far: &'a F,
    token: &'a Pass<Route>,
) -> Result<UpOpen<Chunks<'a, F>>, SendFailed> {
    let first = far.next(token).await.ok_or(SendFailed)?;
    // The walk's own status table failed this attempt over before the plane could see it.
    if first.fail_over || (first.last && first.cut) {
        return Err(SendFailed);
    }
    let (code, _class) = first.status.ok_or(SendFailed)?;
    let status = match u16::try_from(code) {
        Ok(0) | Err(_) => 200,
        Ok(status) => status,
    };
    // The first piece is taken apart: its bytes move into the pending chunk, its head into the open.
    let pending = if first.bytes.is_empty() {
        None
    } else if first.fields {
        Some(Chunk::Trailers(first.bytes))
    } else {
        Some(Chunk::Body(first.bytes))
    };
    Ok(UpOpen {
        status,
        headers: first.head,
        rest: Chunks {
            far,
            token,
            pending,
            done: first.last,
            queued: Vec::new(),
            closed: None,
        },
    })
}

impl<'s, 'w, F: FarEnd + Send> UpSend for WalkSend<'s, 'w, F> {
    type Rest<'a>
        = Chunks<'a, F>
    where
        Self: 'a;

    async fn open_selected<'a>(
        &'a mut self,
        owned: OwnedPreparation,
    ) -> Result<SelectedOpen<Chunks<'a, F>>, SelectedSendError> {
        let pending = Arc::clone(
            self.0
                .pending
                .as_ref()
                .ok_or_else(SelectedSendError::internal)?,
        );
        let selection = self
            .take_selected(owned.prepared.target(), owned.prepared.attempt())
            .ok_or_else(SelectedSendError::internal)?;
        let prepared = match owned.data {
            Some(data) => owned
                .prepared
                .bind_resource(&selection, data)
                .map_err(|_| SelectedSendError::internal())?,
            None => owned.prepared,
        };
        let money = pending
            .admitted()
            .and_then(|unit| unit.selected.as_ref())
            .ok_or_else(SelectedSendError::internal)?;
        let prepared = money
            .prepare(selection, prepared)
            .map_err(|_| SelectedSendError::backend())?;
        let mut handoff = SelectedHandoff::new(pending, prepared)?;
        let s = self.0;
        let far = s.far.get().ok_or_else(SelectedSendError::internal)?;
        let request = s
            .request(
                // The attempt's custody keeps its exchange for `commit` and `accepts_request`: the copy is
                // written here, once, where it is made.
                handoff
                    .exchange()
                    .ok_or_else(SelectedSendError::internal)?
                    .clone(),
            )
            .ok_or_else(SelectedSendError::internal)?;
        let sent = far.send_selected(s.token, request, &mut handoff).await;
        let attempt = handoff.take_committed()?;
        Ok(SelectedOpen {
            opened: if sent {
                read_open(far, s.token).await
            } else {
                Err(SendFailed)
            },
            attempt,
        })
    }

    async fn open<'a>(
        &'a mut self,
        _member: &'a Candidate,
        exchange: UpExchange,
    ) -> Result<UpOpen<Chunks<'a, F>>, SendFailed> {
        let s = self.0;
        if s.request_walk.is_some() && !s.admitted.get().is_some_and(AdmittedRequest::is_live) {
            return Err(SendFailed);
        }
        let far = s.far.get().ok_or(SendFailed)?;
        // Messages the plane wrote beside a WebSocket handshake head wait for the 101 (no message is sent
        // before it): the relay writes them first. On every other carrier the list is empty.
        let mut exchange = exchange;
        let queued = std::mem::take(&mut exchange.msgs);
        let request = s.request(exchange).ok_or(SendFailed)?;
        let mut opened = open_on(far, s.token, request).await?;
        opened.rest.queued = queued;
        Ok(opened)
    }
}

/// The affinity key as the walk's sticky-routing number: the sanctioned hasher (foldhash, ruling 311) under its
/// fixed seed, so a key maps to the same number in every process of a build, as before.
fn affinity_of(key: &str) -> u64 {
    foldhash::fast::FixedState::default().hash_one(key)
}

/// The route one session walks under, from what the plane wanted (§8.6).
fn route_of(
    pool: Text,
    unit: busbar_contract::UnitKey,
    accept: Accept,
    wants: &Wants,
) -> UnitRoute {
    UnitRoute {
        allowed_member: wants.upstream.as_deref().map(str::to_owned),
        unit,
        pool,
        affinity: wants.affinity.as_deref().map(affinity_of),
        wants_stream: wants.stream,
        accept,
        ..UnitRoute::default()
    }
}

/// One walked member of a [`SeatPool`]: the destination it is in the walk, the configured upstream it is, and the
/// need its connections open on (the member's index, declared by the root on the connection table).
#[derive(Clone, PartialEq, Eq)]
pub struct SeatMember {
    pub destination: DestinationId,
    pub upstream: Box<str>,
    pub need: NeedId,
    pub url: Box<str>,
}

/// The member's URL is not printed: a configured URL may carry credentials (printable-url).
impl std::fmt::Debug for SeatMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeatMember")
            .field("destination", &self.destination)
            .field("upstream", &self.upstream)
            .field("need", &self.need)
            .finish_non_exhaustive()
    }
}

/// One admitted probe row. Destination alone cannot choose a pool's target or credential policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeTarget {
    pub destination: DestinationId,
    pub pool: String,
    pub qualified_member: String,
}

impl ProbeTarget {
    /// Display spelling only; lookup always uses `qualified_member` intact.
    pub fn name(&self) -> &str {
        std::str::from_utf8(operator_name(self.qualified_member.as_bytes()))
            .expect("a qualified UTF-8 member has a UTF-8 display name")
    }
}

/// The pool a plane instance walks, composed from its configured upstreams (K9). Every upstream with a `url` is one
/// member, in name order, named `<instance>\x1f<upstream>` (the lane spelling the walk's pins and the billing lane
/// read back with `operator_name`); a `command` upstream is reached over a channel and is never walked. The pool is
/// named after the instance. A route carries the upstream's operator CA as extra anchors and its one SPKI pin; what
/// this path cannot enforce yet (two or more pins, a client identity) refuses the composition, so a configured
/// check is never silently dropped.
pub struct SeatPool {
    /// The pool the instance's sessions walk.
    pub pool: String,
    pub pools: foldhash::HashMap<Text, busbar_kernel_egress::Pool>,
    pub routes: foldhash::HashMap<DestinationId, super::far_end::MemberRoute>,
    pub members: Vec<SeatMember>,
}

pub use crate::off_path::plane_port_egress::upstream_targets;

/// The production [`PortUpstream`]: the instance's pool walked over the kernel's [`Egress`].
pub struct PortEgress {
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    pool: String,
    accept: Accept,
    targets: Targets,
}

impl PortEgress {
    /// `pool` is the pool the plane instance walks, `accept` its core-held `insecure_transport.accept`
    /// (`Accept::default()` = verified TLS only), `targets` how a member reads as a plane `Target`.
    #[must_use]
    pub fn new(
        egress: Arc<Egress>,
        kernel: Arc<Kernel>,
        pool: String,
        accept: Accept,
        targets: Targets,
    ) -> Self {
        Self {
            egress,
            kernel,
            pool,
            accept,
            targets,
        }
    }

    /// The far end one session walks: the unit's route under the wants the plane forwarded with (and, for a
    /// selected request, its pool receipt). The walk builds it at its first pick.
    pub(crate) fn far_end(
        &self,
        facts: &SessionFacts,
        wants: &Wants,
        receipt: Option<&RequestPoolReceipt>,
    ) -> super::far_end::EgressFarEnd<'_> {
        let pool = receipt
            .and_then(RequestPoolReceipt::walk_key)
            .unwrap_or(&self.pool);
        // The unit routes under the pools' own shared name for its pool.
        let mut route = route_of(self.egress.pool_name(pool), facts.unit, self.accept, wants);
        if let Some(receipt) = receipt {
            route.native_member_grants = Some(Arc::clone(receipt.shared_member_grants()));
            route.authorization = facts
                .pending
                .as_ref()
                .map(|pending| Arc::clone(pending.context().generation().core().units()));
        }
        self.egress.unit(route)
    }

    /// How a member of this walk reads as a plane `Target`.
    pub(crate) fn targets(&self) -> &(dyn Fn(&str, &str) -> Option<MemberTarget> + Send + Sync) {
        &*self.targets
    }

    /// A fresh route token for one session's walk.
    pub(crate) fn token(&self) -> Pass<Route> {
        Pass::<Route>::mint_bound(self.kernel.seal(), self.kernel.next_call())
    }

    /// The probe service's side of this walk over `members` (member index, its destination and configured name).
    #[must_use]
    pub fn probes(&self, members: Vec<ProbeTarget>) -> EgressProbes {
        EgressProbes {
            egress: Arc::clone(&self.egress),
            kernel: Arc::clone(&self.kernel),
            accept: self.accept,
            members,
            targets: Arc::clone(&self.targets),
        }
    }
}

impl PortUpstream for PortEgress {
    fn target(&self, pool: &str, qualified_member: &str) -> Option<MemberTarget> {
        (self.targets)(pool, qualified_member)
    }

    fn walk<'a>(
        &'a self,
        facts: SessionFacts,
        run: SessionRun<'a>,
    ) -> BoxFut<'a, Result<Ran, SessionError>> {
        Box::pin(async move {
            let token = self.token();
            let make = |wants: &Wants, receipt: Option<&RequestPoolReceipt>| {
                self.far_end(&facts, wants, receipt)
            };
            let mut walk = EgressWalk::new(&make, &token, self.targets());
            if let Some(pending) = &facts.pending {
                walk = walk
                    .pending(Arc::clone(pending))
                    .map_err(|_| SessionError::NotDriven)?;
            }
            let (mut members, mut sender) = (walk.members(), walk.sender());
            run.run(&mut members, &mut sender).await
        })
    }
}

/// The probe service's far end: one probe exchange to one member, judged like any other dial, and the finding
/// handed to the breaker.
pub struct EgressProbes {
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    accept: Accept,
    members: Vec<ProbeTarget>,
    targets: Targets,
}

/// The probe exchange of one member: a far end built for that destination alone, its reply read whole.
pub struct ProbeSender {
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    accept: Accept,
    selected: ProbeTarget,
    timeout: Duration,
}

impl ProbeSender {
    async fn reply(
        &mut self,
        member: &Candidate,
        exchange: UpExchange,
    ) -> Result<UpReply, SendFailed> {
        if member.pool.as_ref() != self.selected.pool
            || member.qualified_member.as_ref() != self.selected.qualified_member
        {
            return Err(SendFailed);
        }
        let far = self
            .egress
            .probe_selected(
                &self.selected.pool,
                &self.selected.qualified_member,
                self.selected.destination,
                self.timeout,
            )
            .ok_or(SendFailed)?
            .accepting(self.accept);
        let token = Pass::<Route>::mint_bound(self.kernel.seal(), self.kernel.next_call());
        let Pick::Member { name, pool, .. } = far.member(&token, 1).await else {
            return Err(SendFailed);
        };
        let request = request_of(&name, &pool, 1, exchange).ok_or(SendFailed)?;
        let mut open = open_on(&far, &token, request).await?;
        Ok(UpReply {
            status: open.status,
            body: whole_body(&mut open.rest).await?,
            headers: open.headers,
        })
    }
}

impl UpSend for ProbeSender {
    type Rest<'a> = Whole;

    async fn open<'a>(
        &'a mut self,
        member: &'a Candidate,
        exchange: UpExchange,
    ) -> Result<UpOpen<Whole>, SendFailed> {
        self.reply(member, exchange).await.map(UpReply::opened)
    }
}

impl ProbeFar for EgressProbes {
    fn suppressing(&self, member: usize) -> bool {
        self.members.get(member).is_some_and(|selected| {
            (self.egress.breaker)().suppressing(
                selected.destination,
                self.egress.clock.now().wall_ns / 1_000_000_000,
            )
        })
    }

    fn candidate(&self, member: usize) -> Option<Candidate> {
        let selected = self.members.get(member)?;
        let target = (self.targets)(&selected.pool, &selected.qualified_member)?;
        Some(Candidate {
            pool: selected.pool.clone().into(),
            qualified_member: selected.qualified_member.clone().into(),
            identity: target.identity,
            resource: target.resource,
            upstream: selected.name().into(),
            provider: target.provider,
            base_path: target.base_path,
            flags: target.flags,
            params: target.params,
        })
    }

    type Sender = ProbeSender;

    fn sender(&self, member: usize, timeout: Duration) -> Option<ProbeSender> {
        let selected = self.members.get(member)?;
        // A member that relays the caller's own credential is never probed.
        self.egress.probe_selected(
            &selected.pool,
            &selected.qualified_member,
            selected.destination,
            timeout,
        )?;
        Some(ProbeSender {
            egress: Arc::clone(&self.egress),
            kernel: Arc::clone(&self.kernel),
            accept: self.accept,
            selected: selected.clone(),
            timeout,
        })
    }

    fn reported(&self, member: usize, outcome: ProbeOutcome) {
        let Some(selected) = self.members.get(member) else {
            return;
        };
        let outcome = match outcome {
            ProbeOutcome::Healthy => Outcome::Success,
            ProbeOutcome::Unhealthy => Outcome::Transient { retry_after: None },
            ProbeOutcome::Declined => return,
        };
        let token = Pass::<Route>::mint_bound(self.kernel.seal(), self.kernel.next_call());
        (self.egress.breaker)().probed(
            selected.destination,
            outcome,
            self.egress.clock.now().wall_ns / 1_000_000_000,
            &token,
        );
    }
}

#[cfg(test)]
#[path = "tests/port_egress_tests.rs"]
mod tests;
