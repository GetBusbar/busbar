// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Physical arrival custody for the native listener. None of these pending values grants
//! authenticated execution: final data/admin completion owns that separate transition.

use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Instant;

use busbar_contract::abi::mechanism::route::RouteAuth;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::secure::SecureVec;
use busbar_contract::services::Caller;
use busbar_ports::transport::TransportPort;
use foldhash::HashMap;
use tokio_util::sync::CancellationToken;

use super::Head;
use crate::guest::{Claimant, GuestList, Line, Matched};
use crate::limits::process_admission::{AdmissionClass, ByteCredit, RequestLease};
use crate::plane_driver::port_routes::Mounted;
use crate::router::PreparedListener;
use crate::state::{App, AppHandle, InvocationId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    Missing,
    Slot,
    Transport,
    Routes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrivalRefusal {
    Binding(BindError),
    NoRoute,
    Method,
    DuplicateStream,
    InvalidStream,
    Class,
    Capacity,
    Deadline,
    Cancelled,
    BodyIncomplete,
    BodyTooLarge,
    ForeignInput,
}

/// Full native class metadata beside the exact opened plane Caller. A GuestList's
/// LineAuth projection cannot replace the route's effective class or credential header.
pub struct NativeTarget {
    caller: Caller,
    mounted: Mounted,
    auth_instances: Box<[Box<str>]>,
}
impl NativeTarget {
    pub fn caller(&self) -> &Caller {
        &self.caller
    }
    pub fn mounted(&self) -> &Mounted {
        &self.mounted
    }
    pub fn auth_instances(&self) -> &[Box<str>] {
        &self.auth_instances
    }
}

pub enum RouteTarget {
    Plane(NativeTarget),
    Core(RouteAuth),
}

/// Opaque token for one sealed route. Equality of paths or wire route numbers is not
/// equality of this binding; final completion retains this exact Arc.
pub struct RouteBinding {
    line: Line,
    target: RouteTarget,
}
impl RouteBinding {
    pub fn plane(
        line: Line,
        caller: Caller,
        mounted: Mounted,
        auth_instances: Vec<Box<str>>,
    ) -> Result<Self, BindError> {
        if caller.kind() != KindCode::Plane
            || !matches!(&line.claimant, Claimant::Plane(name) if name.as_str() == caller.namespace().as_ref())
            || line.route.rung != mounted.route
            || line.route.path != mounted.pattern.as_ref()
            || line.route.methods != mounted.methods
        {
            return Err(BindError::Routes);
        }
        Ok(Self {
            line,
            target: RouteTarget::Plane(NativeTarget {
                caller,
                mounted,
                auth_instances: auth_instances.into_boxed_slice(),
            }),
        })
    }

    /// Core routes keep their actual route authentication class, including admin. This
    /// constructor grants no native data authority to a core/admin route.
    pub fn core(line: Line, auth: RouteAuth) -> Result<Self, BindError> {
        if !matches!(&line.claimant, Claimant::Clean(_)) {
            return Err(BindError::Routes);
        }
        Ok(Self {
            line,
            target: RouteTarget::Core(auth),
        })
    }
    pub fn line(&self) -> &Line {
        &self.line
    }
    pub fn target(&self) -> &RouteTarget {
        &self.target
    }
}

/// Constructed with the candidate's actual immutable route and transport owners. This
/// contains no App reference: an App may own its PreparedListener without a cycle.
pub struct PhysicalPlan {
    slot: Box<str>,
    transport: Arc<dyn TransportPort>,
    guests: GuestList,
    routes: Box<[Arc<RouteBinding>]>,
}
impl PhysicalPlan {
    /// Candidate assembly uses these same tokens to attach its actual native data plans.
    pub fn routes(&self) -> &[Arc<RouteBinding>] {
        &self.routes
    }
    pub fn new(
        slot: Box<str>,
        transport: Arc<dyn TransportPort>,
        guests: GuestList,
        routes: Vec<RouteBinding>,
    ) -> Result<Self, BindError> {
        if slot.is_empty() {
            return Err(BindError::Slot);
        }
        if routes.len() != guests.lines().len() {
            return Err(BindError::Routes);
        }
        // Match complete sealed lines, including predicates, auth and upgrades. Every
        // sealed line has exactly one binding; no partial candidate is published.
        let mut ordered = Vec::with_capacity(routes.len());
        let mut remaining: Vec<_> = routes.into_iter().map(Some).collect();
        for line in guests.lines() {
            let mut matches = remaining.iter().enumerate().filter_map(|(at, route)| {
                route
                    .as_ref()
                    .filter(|route| &route.line == line)
                    .map(|_| at)
            });
            let at = matches.next().ok_or(BindError::Routes)?;
            if matches.next().is_some() {
                return Err(BindError::Routes);
            }
            ordered.push(Arc::new(
                remaining
                    .get_mut(at)
                    .and_then(Option::take)
                    .ok_or(BindError::Routes)?,
            ));
        }
        Ok(Self {
            slot,
            transport,
            guests,
            routes: ordered.into_boxed_slice(),
        })
    }

    fn route(&self, head: &Head) -> Result<Arc<RouteBinding>, ArrivalRefusal> {
        let fields: Vec<_> = head
            .fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let line = match self.guests.matched(&head.method, &head.target, &fields) {
            Matched::Line(line) => line,
            Matched::MethodMiss(_) => return Err(ArrivalRefusal::Method),
            Matched::NoRoute => return Err(ArrivalRefusal::NoRoute),
        };
        self.guests
            .lines()
            .iter()
            .position(|candidate| std::ptr::eq(candidate, line))
            .and_then(|at| self.routes.get(at))
            .cloned()
            .ok_or(ArrivalRefusal::Binding(BindError::Routes))
    }
}

impl PreparedListener {
    pub fn with_physical(mut self, plan: PhysicalPlan) -> Result<Self, BindError> {
        if self.physical.is_some() {
            return Err(BindError::Routes);
        }
        self.physical = Some(Arc::new(plan));
        Ok(self)
    }
}

/// The composition root's canonical App -> slot -> PreparedListener lookup. This
/// resolves route ownership only; it does not perform or assert authentication.
pub type SelectListener = Arc<dyn Fn(&App, &str) -> Option<Arc<PreparedListener>> + Send + Sync>;

pub struct PhysicalListener {
    handle: Arc<AppHandle>,
    slot: Box<str>,
    transport: Arc<dyn TransportPort>,
    class: AdmissionClass,
    select: SelectListener,
}
impl PhysicalListener {
    pub fn new(
        handle: Arc<AppHandle>,
        slot: Box<str>,
        transport: Arc<dyn TransportPort>,
        class: AdmissionClass,
        select: SelectListener,
    ) -> Result<Self, BindError> {
        let listener = Self {
            handle,
            slot,
            transport,
            class,
            select,
        };
        listener.selected()?;
        Ok(listener)
    }

    fn selected(&self) -> Result<(Arc<App>, Arc<PreparedListener>), BindError> {
        let app = self.handle.load();
        let prepared = (self.select)(&app, &self.slot).ok_or(BindError::Missing)?;
        let plan = prepared.physical.as_ref().ok_or(BindError::Missing)?;
        if plan.slot != self.slot {
            return Err(BindError::Slot);
        }
        if !Arc::ptr_eq(&plan.transport, &self.transport) {
            return Err(BindError::Transport);
        }
        Ok((app, prepared))
    }

    /// Root calls this for the accepted, secured socket using the exact selected framer.
    /// Connection identity is a fresh host allocation, never the plugin's session number.
    pub fn connect(&self, facts: AcceptedConnection) -> PhysicalConnection {
        PhysicalConnection {
            listener: Self {
                handle: self.handle.clone(),
                slot: self.slot.clone(),
                transport: self.transport.clone(),
                class: self.class,
                select: self.select.clone(),
            },
            facts: Arc::new(facts),
            streams: Arc::new(Mutex::new(HashMap::default())),
        }
    }
}

/// Root-owned socket facts, frozen before the framer receives any application bytes.
pub struct AcceptedConnection {
    pub peer: Box<str>,
    pub local: Box<str>,
    pub alpn: Box<str>,
    pub peer_certificate: SecureVec,
}

type Streams = Arc<Mutex<HashMap<u64, Weak<StreamState>>>>;

pub struct PhysicalConnection {
    listener: PhysicalListener,
    facts: Arc<AcceptedConnection>,
    streams: Streams,
}
impl PhysicalConnection {
    pub fn head(
        &self,
        stream: u64,
        head: Head,
        request: RequestLease,
        deadline: Option<Instant>,
    ) -> Result<(PhysicalRequest, StreamOwner), ArrivalRefusal> {
        if stream == 0 {
            return Err(ArrivalRefusal::InvalidStream);
        }
        if request.class() != self.listener.class {
            return Err(ArrivalRefusal::Class);
        }
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        let (app, prepared) = self.listener.selected().map_err(ArrivalRefusal::Binding)?;
        let plan = prepared
            .physical
            .as_ref()
            .ok_or(ArrivalRefusal::Binding(BindError::Missing))?;
        let route = plan.route(&head)?;
        let bytes = head_size(&head).ok_or(ArrivalRefusal::Capacity)?;
        let credit = request
            .try_reserve(bytes)
            .map_err(|_| ArrivalRefusal::Capacity)?;
        let invocation = std::num::NonZeroU64::new(app.next_request_id())
            .map(InvocationId::from_request_id)
            .ok_or(ArrivalRefusal::Capacity)?;
        let state = Arc::new(StreamState {
            phase: Mutex::new(Phase::Pending),
            cancelled: CancellationToken::new(),
            _request: request.clone(),
        });
        {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            if streams.get(&stream).and_then(Weak::upgrade).is_some() {
                return Err(ArrivalRefusal::DuplicateStream);
            }
            streams.insert(stream, Arc::downgrade(&state));
        }
        let binding = Arc::new(RequestBinding {
            app,
            prepared,
            route,
            invocation,
            head,
            request,
            _head_credit: credit,
            deadline,
            facts: self.facts.clone(),
            state: state.clone(),
            stream,
            body: OnceLock::new(),
        });
        Ok((
            PhysicalRequest {
                binding,
                cancel_on_drop: true,
            },
            StreamOwner {
                stream,
                state,
                streams: self.streams.clone(),
            },
        ))
    }

    /// Consume cancellation only through this connection's exact live stream owner.
    /// The bridge resolves numeric input events to these owners before starting async work.
    pub fn cancel(&self, owner: &StreamOwner) -> bool {
        if !Arc::ptr_eq(&self.streams, &owner.streams) {
            return false;
        }
        owner.retire()
    }
}
impl Drop for PhysicalConnection {
    fn drop(&mut self) {
        let streams =
            std::mem::take(&mut *self.streams.lock().unwrap_or_else(PoisonError::into_inner));
        for state in streams.into_values().filter_map(|state| state.upgrade()) {
            state.cancel();
        }
    }
}

fn head_size(head: &Head) -> Option<usize> {
    let mut bytes = head
        .method
        .len()
        .checked_add(head.target.len())?
        .checked_add(head.authority.len())?
        .checked_add(head.query.as_ref().map_or(0, String::len))?;
    for (name, value) in &head.fields {
        bytes = bytes.checked_add(name.len())?.checked_add(value.len())?;
    }
    Some(bytes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pending,
    Completing,
    Cancelled,
}
struct StreamState {
    phase: Mutex<Phase>,
    cancelled: CancellationToken,
    // The response/feed owner may outlive both the Router call and all input backing.
    _request: RequestLease,
}
impl StreamState {
    fn cancel(&self) {
        *self.phase.lock().unwrap_or_else(PoisonError::into_inner) = Phase::Cancelled;
        self.cancelled.cancel();
    }
}

/// Actual task/response custody. Retain it until terminal response/upgrade retirement;
/// request-body EOS is not a reason to drop it.
pub struct StreamOwner {
    stream: u64,
    state: Arc<StreamState>,
    streams: Streams,
}
impl StreamOwner {
    fn retire(&self) -> bool {
        let removed = {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            let same = streams
                .get(&self.stream)
                .is_some_and(|current| Weak::ptr_eq(current, &Arc::downgrade(&self.state)));
            if same {
                streams.remove(&self.stream);
            }
            same
        };
        self.state.cancel();
        removed
    }
    pub fn stream(&self) -> u64 {
        self.stream
    }
}
impl Drop for StreamOwner {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Immutable physical input identity retained by native preparation and completed proofs.
/// Public accessors project facts only; none constructs execution authority.
pub struct RequestBinding {
    app: Arc<App>,
    prepared: Arc<PreparedListener>,
    route: Arc<RouteBinding>,
    invocation: InvocationId,
    head: Head,
    request: RequestLease,
    _head_credit: ByteCredit,
    deadline: Option<Instant>,
    facts: Arc<AcceptedConnection>,
    state: Arc<StreamState>,
    stream: u64,
    body: OnceLock<PhysicalBody>,
}

struct PhysicalBody {
    // Field drop order: wipe backing before retiring its original count/byte custody.
    bytes: SecureVec,
    _credit: ByteCredit,
}
impl RequestBinding {
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }
    pub fn prepared(&self) -> &Arc<PreparedListener> {
        &self.prepared
    }
    pub fn route(&self) -> &Arc<RouteBinding> {
        &self.route
    }
    pub fn invocation(&self) -> InvocationId {
        self.invocation
    }
    pub fn head(&self) -> &Head {
        &self.head
    }
    pub fn request(&self) -> &RequestLease {
        &self.request
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub fn connection(&self) -> &AcceptedConnection {
        &self.facts
    }
    pub fn stream(&self) -> u64 {
        self.stream
    }
    pub fn body(&self) -> Option<&[u8]> {
        self.body.get().map(|body| body.bytes.as_slice())
    }
    pub async fn cancelled(&self) {
        self.state.cancelled.cancelled().await;
    }
    pub fn check_live(&self) -> Result<(), ArrivalRefusal> {
        if *self
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            == Phase::Cancelled
        {
            return Err(ArrivalRefusal::Cancelled);
        }
        if self.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        Ok(())
    }
}

/// Move-only arrival. Abandoning it cancels this exact request even if a verifier retained
/// read-only input. Starting completion is not authentication or permission to execute.
pub struct PhysicalRequest {
    binding: Arc<RequestBinding>,
    cancel_on_drop: bool,
}
impl PhysicalRequest {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    /// Transfer the complete decoded body and its pre-existing credit exactly once.
    /// This adds no charge and never releases an independently retained input's backing.
    pub fn finish_input(self, body: SecureVec, credit: ByteCredit) -> Result<Self, ArrivalRefusal> {
        let binding = self.binding();
        binding.check_live()?;
        if credit.len() != body.len() {
            return Err(ArrivalRefusal::ForeignInput);
        }
        let limit = binding.app.limits.as_ref().map_or(
            crate::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES,
            |limits| limits.request_body_max_bytes,
        );
        if body.len() > limit {
            return Err(ArrivalRefusal::BodyTooLarge);
        }
        // try_merge already enforces opaque request identity, not merely budget/class.
        // A zero credit lets that existing owner check adopt the exact supplied credit.
        let mut own = binding
            .request
            .try_reserve(0)
            .map_err(|_| ArrivalRefusal::Capacity)?;
        own.try_merge(credit)
            .map_err(|_| ArrivalRefusal::ForeignInput)?;
        let phase = binding
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *phase != Phase::Pending {
            return Err(ArrivalRefusal::Cancelled);
        }
        binding
            .body
            .set(PhysicalBody {
                bytes: body,
                _credit: own,
            })
            .map_err(|_| ArrivalRefusal::ForeignInput)?;
        // Retain the state guard through the one-time body publication. No await or callback.
        drop(phase);
        Ok(self)
    }
    pub fn begin_completion(mut self) -> Result<CompletingPhysicalRequest, ArrivalRefusal> {
        let binding = self.binding();
        binding.check_live()?;
        if binding.body.get().is_none() {
            return Err(ArrivalRefusal::BodyIncomplete);
        }
        {
            let mut phase = binding
                .state
                .phase
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *phase != Phase::Pending {
                return Err(ArrivalRefusal::Cancelled);
            }
            *phase = Phase::Completing;
        }
        self.cancel_on_drop = false;
        Ok(CompletingPhysicalRequest {
            binding: self.binding.clone(),
            cancel_on_drop: true,
        })
    }
}
impl Drop for PhysicalRequest {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.binding.state.cancel();
        }
    }
}

/// Consumed by the actual final native authorization owner. It cannot be cloned or
/// converted back to arrival. Drop during verification/replay cancels the pending request.
pub struct CompletingPhysicalRequest {
    pub(crate) binding: Arc<RequestBinding>,
    cancel_on_drop: bool,
}
impl CompletingPhysicalRequest {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
}
impl Drop for CompletingPhysicalRequest {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.binding.state.cancel();
        }
    }
}

#[cfg(test)]
#[path = "../tests/native_physical_admission.rs"]
mod tests;
