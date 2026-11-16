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
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::NO_MEMBER_AUTH_FIELD;
use busbar_contract::abi::transport::{FAULT_HARD, FAULT_NONE, FAULT_RATE_LIMIT, FAULT_TRANSIENT};
use busbar_contract::caps::{Pass, Route};
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
    Candidate, Chunk, Failure, Members, ProbeOutcome, SendFailed, UpChunks, UpOpen, UpReply,
    UpSend, Wants,
};
use super::route::{operator_name, FarEnd, OutboundRequest, Pick};
use crate::teller::Kernel;

/// How a member reads as the plane's `Target` (§6.1): the plane-owned provider keys, the base path, TGT_* flags
/// and the route's configured parameters. Operator vocabulary only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberTarget {
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
            provider: "{}".into(),
            base_path: "".into(),
            flags: 0,
            params: Vec::new(),
        }
    }
}

/// The member (configured upstream name) as a [`MemberTarget`]; `None` = the plane has no such upstream and the
/// walk skips it.
pub type Targets = Arc<dyn Fn(&str) -> Option<MemberTarget> + Send + Sync>;

/// What one session needs of the egress side: the unit it bills to.
#[derive(Clone, Copy, Debug)]
pub struct SessionFacts {
    pub unit: busbar_contract::UnitKey,
}

/// The production seam of `PortDriver::serve`: runs one session's walk. `run` gets the members and the carrier of
/// the walk and runs on the calling (blocking) thread.
pub trait PortUpstream: Send + Sync {
    fn walk(&self, facts: SessionFacts, run: &mut dyn FnMut(&mut dyn Members, &mut dyn UpSend));
}

/// One session's walk over a [`FarEnd`] built from the session's wants.
struct Shared<'a, F: FarEnd> {
    make: &'a dyn Fn(&Wants) -> F,
    far: OnceCell<F>,
    token: &'a Pass<Route>,
    handle: &'a Handle,
    targets: &'a (dyn Fn(&str) -> Option<MemberTarget> + Send + Sync),
    /// Picks made so far (the walk's attempt number).
    picks: Cell<u32>,
    /// The member (as the walk names it) and pool in hand.
    member: RefCell<String>,
    pool: RefCell<String>,
}

/// A walk over any [`FarEnd`]: the [`Members`] and the [`UpSend`] of one session, sharing its far end.
pub struct EgressWalk<'a, F: FarEnd> {
    shared: Shared<'a, F>,
}

impl<'a, F: FarEnd> EgressWalk<'a, F> {
    /// `make` builds the far end from the session's wants, at the first pick.
    pub fn new(
        make: &'a dyn Fn(&Wants) -> F,
        token: &'a Pass<Route>,
        handle: &'a Handle,
        targets: &'a (dyn Fn(&str) -> Option<MemberTarget> + Send + Sync),
    ) -> Self {
        Self {
            shared: Shared {
                make,
                far: OnceCell::new(),
                token,
                handle,
                targets,
                picks: Cell::new(0),
                member: RefCell::new(String::new()),
                pool: RefCell::new(String::new()),
            },
        }
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
    fn next(&mut self, wants: &Wants) -> Option<Candidate> {
        let s = self.0;
        let far = s.far.get_or_init(|| (s.make)(wants));
        loop {
            let n = s.picks.get().saturating_add(1);
            s.picks.set(n);
            match s.handle.block_on(far.member(s.token, n)) {
                Pick::Member { name, pool, .. } => {
                    let operator =
                        String::from_utf8_lossy(operator_name(name.as_bytes())).into_owned();
                    // A member the plane has no upstream for is passed over: the next pick retires it unjudged.
                    let Some(target) = (s.targets)(&operator) else {
                        continue;
                    };
                    *s.member.borrow_mut() = name;
                    *s.pool.borrow_mut() = pool;
                    return Some(Candidate {
                        upstream: operator.into(),
                        provider: target.provider,
                        base_path: target.base_path,
                        flags: target.flags,
                        params: target.params,
                    });
                }
                // Exhausted, vetoed or refused: no member is left.
                _ => return None,
            }
        }
    }

    fn declined(&mut self, _member: &Candidate) {
        // Never dialled and nothing to charge: the next pick settles the attempt and frees its permit.
    }

    fn failed(&mut self, _member: &Candidate, failure: &Failure) {
        if let Some(far) = self.0.far.get() {
            far.judged_stating(self.0.token, fault_of(failure), None);
        }
    }

    fn served(&mut self, _member: &Candidate) {
        if let Some(far) = self.0.far.get() {
            far.judged_stating(self.0.token, FAULT_NONE, None);
        }
    }
}

/// The far end's request for `exchange` as `member` in `pool`, attempt `attempt`. `None` = an exchange this
/// carrier does not send (another carrier, no method or path).
fn request_of(
    member: &str,
    pool: &str,
    attempt: u32,
    exchange: &UpExchange,
) -> Option<OutboundRequest> {
    if !matches!(exchange.carrier, CARRIER_DEFAULT | CARRIER_HTTP) {
        return None;
    }
    let mut fields = exchange.headers.clone();
    if exchange.outbound == OUTBOUND_NONE {
        fields.push((NO_MEMBER_AUTH_FIELD.as_bytes().to_vec(), b"1".to_vec()));
    }
    if let Some(scope) = &exchange.scope {
        fields.push((
            busbar_contract::abi::auth::SCOPE_REQUEST_FIELD
                .as_bytes()
                .to_vec(),
            scope.as_bytes().to_vec(),
        ));
    }
    Some(OutboundRequest {
        member: member.to_owned(),
        pool: pool.to_owned(),
        attempt_no: attempt,
        verb: exchange.method.as_deref()?.as_bytes().to_vec(),
        target: exchange.path.as_deref()?.as_bytes().to_vec(),
        fields,
        body: exchange.body.clone(),
        need: 0,
        text: false,
    })
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
    fn send(&mut self, member: &Candidate, exchange: &UpExchange) -> Result<UpReply, SendFailed> {
        let mut open = self.open(member, exchange)?;
        let mut body = Vec::new();
        while let Some(chunk) = open.rest.next()? {
            if let Chunk::Body(bytes) = chunk {
                body.extend_from_slice(&bytes);
            }
        }
        Ok(UpReply {
            status: open.status,
            headers: open.headers,
            body,
        })
    }

    fn open<'a>(
        &'a mut self,
        _member: &Candidate,
        exchange: &UpExchange,
    ) -> Result<UpOpen<'a>, SendFailed> {
        let s = self.0;
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

/// The affinity key as the walk's sticky-routing number.
fn affinity_of(key: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
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
        accept: Some(accept),
        ..UnitRoute::default()
    }
}

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
    pub fn probes(&self, members: Vec<(DestinationId, String)>) -> EgressProbes {
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
    fn walk(&self, facts: SessionFacts, run: &mut dyn FnMut(&mut dyn Members, &mut dyn UpSend)) {
        let token = Pass::<Route>::mint_bound(self.kernel.seal(), self.kernel.next_call());
        let make = |wants: &Wants| {
            self.egress
                .unit(route_of(&self.pool, facts.unit, self.accept, wants))
        };
        let targets = &*self.targets;
        let walk = EgressWalk::new(&make, &token, &self.handle, targets);
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
    members: Vec<(DestinationId, String)>,
    targets: Targets,
}

/// The probe exchange of one member: a far end built for that destination alone.
struct ProbeSender {
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    handle: Handle,
    accept: Accept,
    destination: DestinationId,
    timeout: Duration,
}

impl UpSend for ProbeSender {
    fn send(&mut self, _member: &Candidate, exchange: &UpExchange) -> Result<UpReply, SendFailed> {
        let far = self
            .egress
            .probe(self.destination, self.timeout)
            .ok_or(SendFailed)?
            .accepting(self.accept);
        let token = Pass::<Route>::mint_bound(self.kernel.seal(), self.kernel.next_call());
        let Pick::Member { name, pool, .. } = self.handle.block_on(far.member(&token, 1)) else {
            return Err(SendFailed);
        };
        let request = request_of(&name, &pool, 1, exchange).ok_or(SendFailed)?;
        let mut open = open_on(&far, &token, &self.handle, request)?;
        let mut body = Vec::new();
        while let Some(chunk) = open.rest.next()? {
            if let Chunk::Body(bytes) = chunk {
                body.extend_from_slice(&bytes);
            }
        }
        Ok(UpReply {
            status: open.status,
            headers: open.headers,
            body,
        })
    }
}

impl ProbeFar for EgressProbes {
    fn suppressing(&self, member: usize) -> bool {
        self.members.get(member).is_some_and(|(destination, _)| {
            (self.egress.breaker)().suppressing(*destination, self.egress.clock.now_secs())
        })
    }

    fn candidate(&self, member: usize) -> Option<Candidate> {
        let (_, name) = self.members.get(member)?;
        let target = (self.targets)(name)?;
        Some(Candidate {
            upstream: name.as_str().into(),
            provider: target.provider,
            base_path: target.base_path,
            flags: target.flags,
            params: target.params,
        })
    }

    fn sender(&self, member: usize, timeout: Duration) -> Option<Box<dyn UpSend + Send>> {
        let (destination, _) = self.members.get(member)?;
        // A member that relays the caller's own credential is never probed.
        self.egress.probe(*destination, timeout)?;
        Some(Box::new(ProbeSender {
            egress: Arc::clone(&self.egress),
            kernel: Arc::clone(&self.kernel),
            handle: self.handle.clone(),
            accept: self.accept,
            destination: *destination,
            timeout,
        }))
    }

    fn reported(&self, member: usize, outcome: ProbeOutcome) {
        let Some((destination, _)) = self.members.get(member) else {
            return;
        };
        let outcome = match outcome {
            ProbeOutcome::Healthy => Outcome::Success,
            ProbeOutcome::Unhealthy => Outcome::Transient { retry_after: None },
            ProbeOutcome::Declined => return,
        };
        let token = Pass::<Route>::mint_bound(self.kernel.seal(), self.kernel.next_call());
        (self.egress.breaker)().probed(*destination, outcome, self.egress.clock.now_secs(), &token);
    }
}

#[cfg(test)]
#[path = "tests/port_egress_tests.rs"]
mod tests;
