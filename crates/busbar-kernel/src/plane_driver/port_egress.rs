// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The egress half of a port-driven session (IF §8.6, §12.3; PLANE-DRIVER.md slice 5, the part it left): the
//! old `far_end.rs` walk ([`EgressFarEnd`], async and token-bound) ported onto the port driver's seams.
//!
//! [`WalkMembers`] is [`Members`] and [`WalkSend`] is [`UpSend`] over any [`FarEnd`]: `next` is the walk's own
//! pick (breaker, permit, pool terminals, W_UPSTREAM through `allowed_member`, W_AFFINITY and the stream want
//! through the route), `open` is the far end's own `send` and `next` (the durable dispatch record, the member's
//! auth fields, the connector's open) with the reply read piece by piece, and the plane's verdicts are the
//! breaker's inputs (`failed` and `served` are `judged_stating`). The walk is async and the port is not, so a
//! session runs on a blocking thread and each step blocks on the runtime [`Handle`], the way `KernelIntents`
//! does; the far end is built from the session's wants at the first pick, because the route it walks under
//! (stream, affinity, pin) is only known once the plane has forwarded.
//!
//! Every dial is judged. The connector judges the destination (the egress class of the member's Need, the guard's
//! name and address checks) as it always did; on top, core judges the transport with `transport_verdict` under the
//! plane instance's own core-held `accept` ([`UnitRoute::accept`], set by [`PortEgress`]): a plaintext target is
//! refused unless the instance's `insecure_transport.accept` holds `plaintext`. The plane never states or
//! chooses any of it.
//!
//! [`PortEgress`] is the production [`PortUpstream`] (an [`Egress`], a kernel, a runtime handle, the pool the
//! instance walks, how a member reads as a plane `Target`); [`EgressProbes`] is its [`ProbeFar`], the probe
//! service's side of the same walk (`PortProbes`).

use std::cell::{Cell, OnceCell, RefCell};
use std::hash::BuildHasher;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::NO_MEMBER_AUTH_FIELD;
use busbar_contract::abi::transport::{FAULT_HARD, FAULT_NONE, FAULT_RATE_LIMIT, FAULT_TRANSIENT};
use busbar_contract::caps::{Pass, Route};
use busbar_contract::conn::NeedId;
use busbar_kernel_egress::ports::{DestinationId, Outcome};
use busbar_plugin_abi::host_side::caller::Accept;
use busbar_plugin_abi::plane::{
    ATT_HARD, CARRIER_DEFAULT, CARRIER_HTTP, FC_RATE_LIMIT, OUTBOUND_NONE,
};
use tokio::runtime::Handle;

use super::far_end::{Egress, UnitRoute};
use super::port_probes::ProbeFar;
use super::port_session::UpExchange;
use super::port_upstream::{
    Candidate, Chunk, Failure, Members, ProbeOutcome, SendFailed, TargetIdentity, UpChunks, UpOpen,
    UpReply, UpSend, Wants,
};
use super::request_admission::{AdmittedRequest, RequestPoolReceipt, RequestWalk};
use super::route::{operator_name, FarEnd, OutboundRequest, Pick};
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

/// The production seam of `PortDriver::serve`: runs one session's walk. `run` gets the members and the carrier of
/// the walk and runs on the calling (blocking) thread.
pub trait PortUpstream: Send + Sync {
    /// Read the immutable current target projection; this does not select or admit a dispatch.
    fn target(&self, _pool: &str, _qualified_member: &str) -> Option<MemberTarget> {
        None
    }
    fn walk(&self, facts: SessionFacts, run: &mut dyn FnMut(&mut dyn Members, &mut dyn UpSend));
}

/// The member in hand: its candidate, its preparation number, its provider and its target definition.
type InHand = (Candidate, u32, Box<str>, Option<TargetDefinition>);

/// One session's walk over a [`FarEnd`] built from the session's wants.
struct Shared<'a, F: FarEnd> {
    make: &'a dyn Fn(&Wants, Option<&RequestPoolReceipt>) -> F,
    far: OnceCell<F>,
    request_walk: Option<RequestWalk>,
    pending: Option<Arc<super::port_admission::Pending>>,
    admitted: OnceCell<AdmittedRequest>,
    selected: RefCell<Option<InHand>>,
    token: &'a Pass<Route>,
    handle: &'a Handle,
    targets: &'a (dyn Fn(&str, &str) -> Option<MemberTarget> + Send + Sync),
    /// Picks made so far (the walk's attempt number).
    picks: Cell<u32>,
    preparations: Cell<u32>,
    /// The member (as the walk names it) and pool in hand.
    member: RefCell<String>,
    pool: RefCell<String>,
    /// The Retry-After the walk stated when it found no member left.
    exhausted_wait: Cell<Option<u32>>,
}

impl<F: FarEnd> Shared<'_, F> {
    fn far(&self, wants: &Wants) -> Option<&F> {
        if self.request_walk.is_some() && !self.admitted.get().is_some_and(AdmittedRequest::is_live)
        {
            return None;
        }
        Some(self.far.get_or_init(|| (self.make)(wants, None)))
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
pub(crate) fn prepare_fixture<'k, 'w, K: super::port_session::Calls + ?Sized, F: FarEnd>(
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
    let target = members.next(&wants).ok_or(SessionError::NotDriven)?;
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
        make: &'a dyn Fn(&Wants, Option<&RequestPoolReceipt>) -> F,
        token: &'a Pass<Route>,
        handle: &'a Handle,
        targets: &'a (dyn Fn(&str, &str) -> Option<MemberTarget> + Send + Sync),
    ) -> Self {
        Self {
            shared: Shared {
                make,
                far: OnceCell::new(),
                request_walk: None,
                pending: None,
                admitted: OnceCell::new(),
                selected: RefCell::new(None),
                token,
                handle,
                targets,
                picks: Cell::new(0),
                preparations: Cell::new(0),
                member: RefCell::new(String::new()),
                pool: RefCell::new(String::new()),
                exhausted_wait: Cell::new(None),
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
        let mut selected = shared.selected.borrow_mut();
        let (actual, ordinal, _, _) = selected.as_ref()?;
        if actual != target || *ordinal != preparation {
            return None;
        }
        let (target, preparation, provider, definition) = selected.take()?;
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

impl<F: FarEnd> Members for WalkMembers<'_, '_, F> {
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
        let far = self.0.far(wants)?;
        far.candidates(self.0.token)
    }

    fn hook_scope(&mut self, wants: &Wants) -> Option<super::RoutedScope> {
        let far = self.0.far(wants)?;
        far.scope(self.0.token)
    }

    fn hook_lane(&mut self, wants: &Wants, index: usize) -> Option<String> {
        let far = self.0.far(wants)?;
        far.candidate_lane(self.0.token, index)
    }

    fn hook_constrain(&mut self, wants: &Wants, constraint: super::hooks::Constraint) -> bool {
        let Some(far) = self.0.far(wants) else {
            return false;
        };
        if far.candidates(self.0.token).is_none() {
            return false;
        }
        far.constrain(self.0.token, constraint);
        true
    }

    fn next(&mut self, wants: &Wants) -> Option<Candidate> {
        let s = self.0;
        s.selected.borrow_mut().take();
        let far = s.far(wants)?;
        loop {
            let n = s.picks.get().saturating_add(1);
            s.picks.set(n);
            match s.handle.block_on(far.member(s.token, n)) {
                Pick::Member {
                    name,
                    pool,
                    provider,
                    ..
                } => {
                    let Some(target) = (s.targets)(&pool, &name) else {
                        continue;
                    };
                    s.member.borrow_mut().clone_from(&name);
                    s.pool.borrow_mut().clone_from(&pool);
                    let candidate = Candidate {
                        pool: pool.into(),
                        upstream: String::from_utf8_lossy(operator_name(name.as_bytes())).into(),
                        qualified_member: name.into(),
                        identity: target.identity,
                        resource: target.resource,
                        provider: target.provider,
                        base_path: target.base_path,
                        flags: target.flags,
                        params: target.params,
                    };
                    let preparation = s.preparations.get().checked_add(1)?;
                    s.preparations.set(preparation);
                    *s.selected.borrow_mut() = Some((
                        candidate.clone(),
                        preparation,
                        provider.into(),
                        target.definition,
                    ));
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
        self.0.selected.borrow_mut().take();
        // Never dialled and nothing to charge: the next pick settles the attempt and frees its permit.
    }

    fn failed(&mut self, _member: &Candidate, failure: &Failure) {
        if let Some(far) = self.0.far.get() {
            // The plane's own wait (a body Retry-After it read) rides with its verdict into the breaker (§12.3).
            let wait = (failure.retry_after_s > 0).then_some(failure.retry_after_s);
            far.judged_waiting(self.0.token, fault_of(failure), wait);
        }
    }

    fn served(&mut self, _member: &Candidate) {
        if let Some(far) = self.0.far.get() {
            far.judged_stating(self.0.token, FAULT_NONE, None);
        }
    }

    fn retry_after(&self) -> Option<u32> {
        self.0.exhausted_wait.get()
    }
}

/// The far end's request for `exchange` as `member` in `pool`, attempt `attempt`: the exchange moves
/// in, its header list, method, path and body become the request's own with no copy. `None` = an
/// exchange this carrier does not send (another carrier, no method or path).
fn request_of(
    member: &str,
    pool: &str,
    attempt: u32,
    exchange: UpExchange,
) -> Option<OutboundRequest> {
    if !matches!(exchange.carrier, CARRIER_DEFAULT | CARRIER_HTTP) {
        return None;
    }
    let outbound = exchange.outbound;
    let UpExchange {
        method,
        path,
        scope,
        headers: mut fields,
        body,
        ..
    } = exchange;
    if outbound == OUTBOUND_NONE {
        fields.push((NO_MEMBER_AUTH_FIELD.as_bytes().to_vec(), b"1".to_vec()));
    }
    if let Some(scope) = scope {
        fields.push((
            busbar_contract::abi::auth::SCOPE_REQUEST_FIELD
                .as_bytes()
                .to_vec(),
            scope.into_boxed_bytes().into_vec(),
        ));
    }
    Some(OutboundRequest {
        member: member.to_owned(),
        pool: pool.to_owned(),
        attempt_no: attempt,
        verb: method?.into_boxed_bytes().into_vec(),
        target: path?.into_boxed_bytes().into_vec(),
        fields,
        body,
        need: 0,
        text: false,
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
    let mut fields = request.fields.iter();
    let mut same = request.member == member
        && request.pool == pool
        && request.verb == method.as_bytes()
        && request.target == path.as_bytes()
        && request.body == exchange.body
        && request.need == 0
        && !request.text;
    for expected in &exchange.headers {
        same &= fields.next() == Some(expected);
    }
    if exchange.outbound == OUTBOUND_NONE {
        same &= fields
            .next()
            .is_some_and(|(name, value)| name == NO_MEMBER_AUTH_FIELD.as_bytes() && value == b"1");
    }
    if let Some(scope) = &exchange.scope {
        same &= fields.next().is_some_and(|(name, value)| {
            name == busbar_contract::abi::auth::SCOPE_REQUEST_FIELD.as_bytes()
                && value == scope.as_bytes()
        });
    }
    same && fields.next().is_none()
}

/// The rest of a reply, read from the far end as the plane takes it.
struct Chunks<'a, F: FarEnd> {
    far: &'a F,
    token: &'a Pass<Route>,
    handle: &'a Handle,
    pending: Option<Chunk>,
    done: bool,
}

impl<F: FarEnd> UpChunks for Chunks<'_, F> {
    fn next(&mut self) -> Result<Option<Chunk>, SendFailed> {
        if let Some(chunk) = self.pending.take() {
            return Ok(Some(chunk));
        }
        while !self.done {
            let Some(piece) = self.handle.block_on(self.far.next(self.token)) else {
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
}

/// The rest of a reply's body, read to its end: the first body chunk's own buffer becomes the body and a later
/// chunk is appended to it (trailers are not body).
fn whole_body<'a>(rest: &mut (dyn UpChunks + 'a)) -> Result<Vec<u8>, SendFailed> {
    let mut body: Option<Vec<u8>> = None;
    while let Some(chunk) = rest.next()? {
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
fn open_on<'a, F: FarEnd>(
    far: &'a F,
    token: &'a Pass<Route>,
    handle: &'a Handle,
    request: OutboundRequest,
) -> Result<UpOpen<'a>, SendFailed> {
    if !handle.block_on(far.send(token, request)) {
        return Err(SendFailed);
    }
    read_open(far, token, handle)
}

fn read_open<'a, F: FarEnd>(
    far: &'a F,
    token: &'a Pass<Route>,
    handle: &'a Handle,
) -> Result<UpOpen<'a>, SendFailed> {
    let first = handle.block_on(far.next(token)).ok_or(SendFailed)?;
    // The walk's own status table failed this attempt over before the plane could see it.
    if first.fail_over || (first.last && first.cut) {
        return Err(SendFailed);
    }
    let (code, _class) = first.status.ok_or(SendFailed)?;
    let status = match u16::try_from(code) {
        Ok(0) | Err(_) => 200,
        Ok(status) => status,
    };
    let pending = (!first.bytes.is_empty()).then(|| {
        if first.fields {
            Chunk::Trailers(first.bytes.clone())
        } else {
            Chunk::Body(first.bytes.clone())
        }
    });
    Ok(UpOpen {
        status,
        headers: first.head,
        rest: Box::new(Chunks {
            far,
            token,
            handle,
            pending,
            done: first.last,
        }),
    })
}

impl<F: FarEnd> UpSend for WalkSend<'_, '_, F> {
    fn open_selected<'a>(
        &'a mut self,
        owned: OwnedPreparation,
    ) -> Result<SelectedOpen<'a>, SelectedSendError> {
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
        let request = request_of(
            &s.member.borrow(),
            &s.pool.borrow(),
            s.picks.get(),
            // The attempt's custody keeps its exchange for `commit` and `accepts_request`: the copy is
            // written here, once, where it is made.
            handoff
                .exchange()
                .ok_or_else(SelectedSendError::internal)?
                .clone(),
        )
        .ok_or_else(SelectedSendError::internal)?;
        let sent = s
            .handle
            .block_on(far.send_selected(s.token, request, &mut handoff));
        let attempt = handoff.take_committed()?;
        Ok(SelectedOpen {
            opened: if sent {
                read_open(far, s.token, s.handle)
            } else {
                Err(SendFailed)
            },
            attempt,
        })
    }

    fn send(&mut self, member: &Candidate, exchange: UpExchange) -> Result<UpReply, SendFailed> {
        let mut open = self.open(member, exchange)?;
        Ok(UpReply {
            status: open.status,
            body: whole_body(&mut *open.rest)?,
            headers: open.headers,
        })
    }

    fn open<'a>(
        &'a mut self,
        _member: &Candidate,
        exchange: UpExchange,
    ) -> Result<UpOpen<'a>, SendFailed> {
        let s = self.0;
        if s.request_walk.is_some() && !s.admitted.get().is_some_and(AdmittedRequest::is_live) {
            return Err(SendFailed);
        }
        let far = s.far.get().ok_or(SendFailed)?;
        let request = request_of(
            &s.member.borrow(),
            &s.pool.borrow(),
            s.picks.get(),
            exchange,
        )
        .ok_or(SendFailed)?;
        open_on(far, s.token, s.handle, request)
    }
}

/// The affinity key as the walk's sticky-routing number: the sanctioned hasher (foldhash, ruling 311) under its
/// fixed seed, so a key maps to the same number in every process of a build, as before.
fn affinity_of(key: &str) -> u64 {
    foldhash::fast::FixedState::default().hash_one(key)
}

/// The route one session walks under, from what the plane wanted (§8.6).
fn route_of(
    pool: &str,
    unit: busbar_contract::UnitKey,
    accept: Accept,
    wants: &Wants,
) -> UnitRoute {
    UnitRoute {
        allowed_member: wants.upstream.as_deref().map(str::to_owned),
        unit,
        pool: pool.to_owned(),
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
    pub pools: foldhash::HashMap<String, busbar_kernel_egress::Pool>,
    pub routes: foldhash::HashMap<DestinationId, super::far_end::MemberRoute>,
    pub members: Vec<SeatMember>,
}

pub use crate::off_path::plane_port_egress::upstream_targets;

/// The production [`PortUpstream`]: the instance's pool walked over the kernel's [`Egress`].
pub struct PortEgress {
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    handle: Handle,
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
        handle: Handle,
        pool: String,
        accept: Accept,
        targets: Targets,
    ) -> Self {
        Self {
            egress,
            kernel,
            handle,
            pool,
            accept,
            targets,
        }
    }

    /// The probe service's side of this walk over `members` (member index, its destination and configured name).
    #[must_use]
    pub fn probes(&self, members: Vec<ProbeTarget>) -> EgressProbes {
        EgressProbes {
            egress: Arc::clone(&self.egress),
            kernel: Arc::clone(&self.kernel),
            handle: self.handle.clone(),
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

    fn walk(&self, facts: SessionFacts, run: &mut dyn FnMut(&mut dyn Members, &mut dyn UpSend)) {
        let token = Pass::<Route>::mint_bound(self.kernel.seal(), self.kernel.next_call());
        let make = |wants: &Wants, receipt: Option<&RequestPoolReceipt>| {
            let pool = receipt
                .and_then(RequestPoolReceipt::walk_key)
                .unwrap_or(&self.pool);
            let mut route = route_of(pool, facts.unit, self.accept, wants);
            if let Some(receipt) = receipt {
                route.native_member_grants = Some(receipt.member_grants().clone());
                route.authorization = facts
                    .pending
                    .as_ref()
                    .map(|pending| Arc::clone(pending.context().generation().core().units()));
            }
            self.egress.unit(route)
        };
        let targets = &*self.targets;
        let mut walk = EgressWalk::new(&make, &token, &self.handle, targets);
        if let Some(pending) = &facts.pending {
            let Ok(pending) = walk.pending(Arc::clone(pending)) else {
                return;
            };
            walk = pending;
        }
        run(&mut walk.members(), &mut walk.sender());
    }
}

/// The probe service's far end: one probe exchange to one member, judged like any other dial, and the finding
/// handed to the breaker.
pub struct EgressProbes {
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    handle: Handle,
    accept: Accept,
    members: Vec<ProbeTarget>,
    targets: Targets,
}

/// The probe exchange of one member: a far end built for that destination alone.
struct ProbeSender {
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    handle: Handle,
    accept: Accept,
    selected: ProbeTarget,
    timeout: Duration,
}

impl UpSend for ProbeSender {
    fn send(&mut self, member: &Candidate, exchange: UpExchange) -> Result<UpReply, SendFailed> {
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
        let Pick::Member { name, pool, .. } = self.handle.block_on(far.member(&token, 1)) else {
            return Err(SendFailed);
        };
        let request = request_of(&name, &pool, 1, exchange).ok_or(SendFailed)?;
        let mut open = open_on(&far, &token, &self.handle, request)?;
        Ok(UpReply {
            status: open.status,
            body: whole_body(&mut *open.rest)?,
            headers: open.headers,
        })
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

    fn sender(&self, member: usize, timeout: Duration) -> Option<Box<dyn UpSend + Send>> {
        let selected = self.members.get(member)?;
        // A member that relays the caller's own credential is never probed.
        self.egress.probe_selected(
            &selected.pool,
            &selected.qualified_member,
            selected.destination,
            timeout,
        )?;
        Some(Box::new(ProbeSender {
            egress: Arc::clone(&self.egress),
            kernel: Arc::clone(&self.kernel),
            handle: self.handle.clone(),
            accept: self.accept,
            selected: selected.clone(),
            timeout,
        }))
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
