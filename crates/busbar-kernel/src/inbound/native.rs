// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Physical request custody for the native listener. Arrival alone grants no execution;
//! final data transitions consume the actual authorization and allocation proofs.

use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Instant;

use busbar_contract::kinds::codes::KindCode;
use busbar_contract::route::RouteAuth;
use busbar_contract::secure::SecureVec;
use busbar_contract::services::Caller;
use busbar_contract::storage::{StorageCredit, StorageDenied, StorageSource};
use busbar_contract::transport::wire::PeerCertificate;
use busbar_ports::transport::TransportPort;
use foldhash::HashMap;
use tokio_util::sync::CancellationToken;

use super::request_snapshot::{ChargedRequestSnapshot, SnapshotError, SnapshotInput};
use super::Head;
use crate::auth::native_admin::ExecutionAdmission;
use crate::auth::native_data::{DataAuthorization, DataExecutionAdmission};
use crate::guest::{Claimant, GuestList, Line, Matched};
use crate::limits::process_admission::{AdmissionClass, ByteCredit, RequestLease};
use crate::plane_driver::port_routes::Mounted;
use crate::router::PreparedListener;
use crate::state::{AdmissionLease, App, AppHandle, InvocationId};

#[path = "native_refusal.rs"]
mod refusal;
use refusal::PreparationState;
pub use refusal::{
    DataPreparation, DataPreparationDenied, DataPreparationSuccess, PhysicalRefusal,
    PhysicalUpgrade,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    Missing,
    Generation,
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
    /// No sealed line matched the head ([`PhysicalPlan::with_unrouted`]): the request is answered as
    /// an unauthenticated one, never served.
    Unrouted,
}

/// The claimant word of the unrouted binding's line (a line no head matches: it has no path form).
pub const UNROUTED: &str = "core/unrouted";

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
    /// The binding of a head no sealed line matched. Its line matches nothing (no methods, no path
    /// form); only [`PhysicalPlan::with_unrouted`] hands it out.
    fn unrouted() -> Self {
        Self {
            line: Line {
                route: crate::guest::Route {
                    methods: 0,
                    path_form: 0,
                    path: String::new(),
                    fields: Vec::new(),
                    rung: 0,
                },
                claimant: Claimant::Clean(UNROUTED.into()),
                dialect: 0,
                auth: crate::guest::LineAuth::None,
                upgrade: None,
                offered: Default::default(),
            },
            target: RouteTarget::Unrouted,
        }
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
    /// Where a head no line matches is bound ([`Self::with_unrouted`]); `None` = refused at arrival.
    unrouted: Option<Arc<RouteBinding>>,
}
impl PhysicalPlan {
    /// Bind a head no sealed line matches (no route, or a route without that method) to one
    /// unrouted binding, answered as an unauthenticated request is: a caller that has not
    /// authenticated cannot tell a missing route from a gated one. The binding is kept by the plan.
    #[must_use]
    pub fn with_unrouted(mut self) -> Self {
        self.unrouted = Some(Arc::new(RouteBinding::unrouted()));
        self
    }
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
            unrouted: None,
        })
    }

    fn route(&self, head: &Head) -> Result<Arc<RouteBinding>, ArrivalRefusal> {
        // The head's fields as borrowed pairs, on the stack for any ordinary head (as the framed
        // path lends them): the route match reads them and keeps nothing.
        let mut fields: smallvec::SmallVec<[(&str, &[u8]); 32]> = smallvec::SmallVec::new();
        for (name, value) in &head.fields {
            fields.push((name.as_str(), value.as_slice()));
        }
        let line = match self.guests.matched(&head.method, &head.target, &fields) {
            Matched::Line(line) => line,
            Matched::MethodMiss(_) | Matched::NoRoute if self.unrouted.is_some() => {
                return self
                    .unrouted
                    .clone()
                    .ok_or(ArrivalRefusal::Binding(BindError::Routes));
            }
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
    peer: Box<str>,
    local: Box<str>,
    alpn: Box<str>,
    sni: Box<str>,
    // Charged to the connection's account by whoever captured it; it holds its own credit.
    peer_certificate: PeerCertificate,
    // Backing fields drop first. The same facts Arc may outlive both socket and connection task.
    _credit: StorageCredit,
}
impl AcceptedConnection {
    /// Capture actual accepted socket/security metadata against its original trusted account.
    /// All separately allocated backing is reserved before any copy; no request is admitted here.
    pub fn capture(
        source: &StorageSource,
        peer: &str,
        local: &str,
        alpn: &str,
        peer_certificate: &[u8],
    ) -> Result<Self, StorageDenied> {
        let mut credit = source.try_reserve(
            text_bytes(peer, local, alpn, "")?
                .checked_add(peer_certificate.len())
                .ok_or(StorageDenied)?,
        )?;
        let certificate =
            PeerCertificate::charged(credit.split(peer_certificate.len())?, peer_certificate)?;
        Self::capture_metadata(credit, peer, local, alpn, certificate, None)
    }

    /// Preserve security facts from the actual socket wrapper, including TLS without SNI
    /// or a client certificate. Request fields never supply these facts. The wrapper's
    /// certificate is taken by move, already charged: it is neither reserved nor copied again.
    pub fn capture_secured(
        handshake: Option<&busbar_contract::transport::wire::HandshakeInfo>,
        peer_certificate: PeerCertificate,
        source: &StorageSource,
        peer: &str,
        local: &str,
    ) -> Result<Self, StorageDenied> {
        let alpn = handshake
            .and_then(|info| info.alpn())
            .map(std::str::from_utf8)
            .transpose()
            .map_err(|_| StorageDenied)?
            .unwrap_or("");
        let sni = handshake.map(|info| info.server_name().unwrap_or(""));
        let credit = source.try_reserve(text_bytes(peer, local, alpn, sni.unwrap_or(""))?)?;
        Self::capture_metadata(credit, peer, local, alpn, peer_certificate, sni)
    }

    fn capture_metadata(
        credit: StorageCredit,
        peer: &str,
        local: &str,
        alpn: &str,
        peer_certificate: PeerCertificate,
        tls_sni: Option<&str>,
    ) -> Result<Self, StorageDenied> {
        let sni = tls_sni.unwrap_or("");
        let peer = accepted_text(peer)?;
        let local = accepted_text(local)?;
        let alpn = accepted_text(alpn)?;
        let sni = accepted_text(sni)?;
        Ok(Self {
            peer,
            local,
            alpn,
            sni,
            peer_certificate,
            _credit: credit,
        })
    }
    pub fn peer(&self) -> &str {
        &self.peer
    }
    pub fn local(&self) -> &str {
        &self.local
    }
    pub fn alpn(&self) -> &str {
        &self.alpn
    }
    pub fn sni(&self) -> &str {
        &self.sni
    }
    pub fn peer_certificate(&self) -> &[u8] {
        self.peer_certificate.as_slice()
    }
}

fn text_bytes(peer: &str, local: &str, alpn: &str, sni: &str) -> Result<usize, StorageDenied> {
    peer.len()
        .checked_add(local.len())
        .and_then(|n| n.checked_add(alpn.len()))
        .and_then(|n| n.checked_add(sni.len()))
        .ok_or(StorageDenied)
}

fn accepted_text(text: &str) -> Result<Box<str>, StorageDenied> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(text.len())
        .map_err(|_| StorageDenied)?;
    if owned.capacity() > text.len() {
        return Err(StorageDenied);
    }
    owned.push_str(text);
    Ok(owned.into_boxed_str())
}

type Streams = Arc<Mutex<HashMap<u64, Weak<StreamState>>>>;

pub struct PhysicalConnection {
    listener: PhysicalListener,
    facts: Arc<AcceptedConnection>,
    streams: Streams,
}
impl PhysicalConnection {
    /// The connection's frozen socket and security facts, lent for as long as the borrow.
    pub fn facts(&self) -> &AcceptedConnection {
        &self.facts
    }

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
            preparation: Mutex::new(PreparationState::Unused),
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
            handle: self.listener.handle.clone(),
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
            snapshot: Mutex::new(None),
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
    // Retain allocation debt, including unused capacity and the header descriptor array.
    // Logical lengths alone would refund backing that this immutable Head still owns.
    let mut bytes = head
        .method
        .capacity()
        .checked_add(head.target.capacity())?
        .checked_add(head.authority.capacity())?
        .checked_add(head.query.as_ref().map_or(0, String::capacity))?
        .checked_add(
            head.fields
                .capacity()
                .checked_mul(std::mem::size_of::<(String, Vec<u8>)>())?,
        )?;
    for (name, value) in &head.fields {
        bytes = bytes
            .checked_add(name.capacity())?
            .checked_add(value.capacity())?;
    }
    Some(bytes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pending,
    Completing,
    Admitted,
    Refusing,
    Executing { deadline: Option<Instant> },
    Cancelled,
}
struct StreamState {
    phase: Mutex<Phase>,
    preparation: Mutex<PreparationState>,
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
    handle: Arc<AppHandle>,
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
    snapshot: Mutex<Option<Arc<ChargedRequestSnapshot>>>,
}

struct PhysicalBody {
    // Field drop order: wipe backing before retiring its original count/byte custody.
    bytes: SecureVec,
    credit: ByteCredit,
}
impl RequestBinding {
    /// Compare the exact retained physical owner, including after cancellation or retirement.
    /// An equal wire stream number on another connection conveys no matching authority.
    pub fn owns_stream(&self, owner: &StreamOwner) -> bool {
        self.stream == owner.stream && Arc::ptr_eq(&self.state, &owner.state)
    }

    /// The originating publication handle; an equal App in another handle is not equivalent.
    pub fn handle(&self) -> &Arc<AppHandle> {
        &self.handle
    }
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }
    pub fn prepared(&self) -> &Arc<PreparedListener> {
        &self.prepared
    }
    pub fn slot(&self) -> &str {
        &self
            .prepared
            .physical
            .as_ref()
            .expect("physical arrival retains its prepared plan")
            .slot
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
    /// Capture the original physical facts once. Shared budget lineage alone cannot attest
    /// a caller's fields, so no external snapshot can be attached to this binding.
    pub fn snapshot(&self) -> Result<Arc<ChargedRequestSnapshot>, SnapshotError> {
        let body = self.body().ok_or(SnapshotError::Invalid)?;
        let mut saved = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(snapshot) = saved.as_ref() {
            return Ok(snapshot.clone());
        }
        let snapshot = ChargedRequestSnapshot::capture(
            SnapshotInput {
                method: &self.head.method,
                path: &self.head.target,
                query: self.head.query.as_deref().unwrap_or_default(),
                query_present: self.head.query.is_some(),
                authority: &self.head.authority,
                headers: self
                    .head
                    .fields
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_slice())),
                peer: &self.facts.peer,
                tls_peer_cert: self.facts.peer_certificate(),
                body,
                now_s: crate::store::now(),
            },
            &self.request,
        )?;
        *saved = Some(snapshot.clone());
        Ok(snapshot)
    }
    pub async fn cancelled(&self) {
        self.state.cancelled.cancelled().await;
    }
    /// Neither cancelled nor refusing, under the phase lock.
    fn check_not_cancelled(&self) -> Result<(), ArrivalRefusal> {
        if matches!(
            *self
                .state
                .phase
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            Phase::Cancelled | Phase::Refusing
        ) {
            return Err(ArrivalRefusal::Cancelled);
        }
        Ok(())
    }
    pub fn check_live(&self) -> Result<(), ArrivalRefusal> {
        self.check_not_cancelled()?;
        if self.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        Ok(())
    }
    /// [`Self::check_live`], answering the reading it judged the deadline at: taken after the
    /// phase lock, as `check_live`'s is. A caller with a deadline of its own to judge in the same
    /// step judges it at this reading instead of reading again. It is good for that step only:
    /// never across an await, and never for a check that sits behind a lock or other work.
    pub fn check_live_now(&self) -> Result<Instant, ArrivalRefusal> {
        self.check_not_cancelled()?;
        let now = Instant::now();
        if self.deadline.is_some_and(|at| now >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        Ok(now)
    }
    /// The effect gate requires the final physical execution transition, not mere liveness.
    pub fn check_executing(&self) -> Result<(), ArrivalRefusal> {
        let phase = self
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Phase::Executing { deadline } = *phase else {
            return Err(ArrivalRefusal::Cancelled);
        };
        if deadline.is_some_and(|at| Instant::now() >= at) {
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
        // Bundle before any refusal so every exit wipes backing before refunding its credit.
        let body = PhysicalBody {
            bytes: body,
            credit,
        };
        let binding = self.binding();
        binding.check_live()?;
        if body.credit.len() != body.bytes.len()
            || body.bytes.capacity() > body.credit.len()
            || !binding.request.same_request(body.credit.request())
        {
            return Err(ArrivalRefusal::ForeignInput);
        }
        let limit = binding.app.limits.as_ref().map_or(
            crate::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES,
            |limits| limits.request_body_max_bytes,
        );
        if body.bytes.len() > limit {
            return Err(ArrivalRefusal::BodyTooLarge);
        }
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
            .set(body)
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

    /// Complete only a canonical core route explicitly declared unauthenticated. The actual
    /// publication gate still decides which generation owns this operation; no plane class
    /// or absent credential can enter this path.
    pub fn complete_public(mut self) -> Result<PhysicalPublicExecution, ArrivalRefusal> {
        if !matches!(
            self.binding.route.target(),
            RouteTarget::Core(RouteAuth::None)
        ) {
            return Err(ArrivalRefusal::Class);
        }
        self.binding.check_live()?;
        let lease = self
            .binding
            .handle
            .admit_current(self.binding.app(), self.binding.invocation(), |_| {
                Ok::<(), std::convert::Infallible>(())
            })
            .map_err(|_| ArrivalRefusal::Binding(BindError::Generation))?;
        {
            let mut phase = self
                .binding
                .state
                .phase
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *phase != Phase::Completing {
                return Err(ArrivalRefusal::Cancelled);
            }
            if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
                return Err(ArrivalRefusal::Deadline);
            }
            *phase = Phase::Executing {
                deadline: self.binding.deadline,
            };
        }
        self.cancel_on_drop = false;
        Ok(PhysicalPublicExecution {
            binding: self.binding.clone(),
            lease,
        })
    }

    fn check_admin_route(&self) -> Result<(), ArrivalRefusal> {
        if self.binding.request.class() != AdmissionClass::Operator
            || !matches!(
                self.binding.route.target(),
                RouteTarget::Core(RouteAuth::Admin)
            )
        {
            return Err(ArrivalRefusal::Class);
        }
        self.binding.check_live()
    }

    /// HTTP extensions can clone custody, but can extract this completion right only once.
    pub fn into_admin(self) -> Result<AdminPhysicalRequest, ArrivalRefusal> {
        self.check_admin_route()?;
        Ok(AdminPhysicalRequest {
            binding: self.binding.clone(),
            pending: Arc::new(Mutex::new(AdminCarrierState::Pending(self))),
        })
    }

    /// Join the existing final operator proof without another verifier or replay call.
    pub fn complete_admin(
        mut self,
        admission: Arc<ExecutionAdmission>,
    ) -> Result<PhysicalAdminExecution, ArrivalRefusal> {
        self.check_admin_route()?;
        let (lease, prepared) = admission.native().ok_or(ArrivalRefusal::ForeignInput)?;
        let (handle, cx) = admission
            .native_origin()
            .ok_or(ArrivalRefusal::ForeignInput)?;
        let original = self
            .binding
            .snapshot()
            .map_err(|_| ArrivalRefusal::Capacity)?;
        if !Arc::ptr_eq(handle, self.binding.handle())
            || !Arc::ptr_eq(lease.generation(), self.binding.app())
            || lease.invocation() != self.binding.invocation()
            || cx.request_id != self.binding.invocation().request_id().get()
            || !Arc::ptr_eq(&original, prepared.request())
        {
            return Err(ArrivalRefusal::ForeignInput);
        }
        let deadline = self
            .binding
            .deadline
            .map_or(cx.deadline, |at| at.min(cx.deadline));
        {
            let mut phase = self
                .binding
                .state
                .phase
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *phase != Phase::Completing {
                return Err(ArrivalRefusal::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(ArrivalRefusal::Deadline);
            }
            *phase = Phase::Executing {
                deadline: Some(deadline),
            };
        }
        self.cancel_on_drop = false;
        Ok(PhysicalAdminExecution {
            binding: self.binding.clone(),
            admission,
        })
    }

    /// Join the real final data policy result to this exact physical arrival once.
    pub fn complete(
        mut self,
        authorization: DataAuthorization,
    ) -> Result<AuthorizedPhysicalData, ArrivalRefusal> {
        if !Arc::ptr_eq(&self.binding, authorization.binding()) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        if !Arc::ptr_eq(&self.binding, authorization.preparation().binding()) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        {
            let mut phase = self
                .binding
                .state
                .phase
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *phase != Phase::Completing {
                return Err(ArrivalRefusal::Cancelled);
            }
            if *self
                .binding
                .state
                .preparation
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                != PreparationState::Authorized
            {
                return Err(ArrivalRefusal::Cancelled);
            }
            if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
                return Err(ArrivalRefusal::Deadline);
            }
            *phase = Phase::Admitted;
        }
        self.cancel_on_drop = false;
        Ok(AuthorizedPhysicalData {
            authorization,
            physical: PhysicalExecutionOwner {
                binding: self.binding.clone(),
            },
        })
    }
}
impl Drop for CompletingPhysicalRequest {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.binding.state.cancel();
        }
    }
}

/// Cloneable transport for the single pending operator right in HTTP extensions.
#[derive(Clone)]
pub struct AdminPhysicalRequest {
    binding: Arc<RequestBinding>,
    pending: Arc<Mutex<AdminCarrierState>>,
}
enum AdminCarrierState {
    Pending(CompletingPhysicalRequest),
    Taken,
    Refused(PhysicalRefusal),
    Spent,
}

/// A denial reuses its original Admin extension allocation, with one final extraction.
#[derive(Clone)]
pub struct PhysicalRefusalCarrier {
    original: AdminPhysicalRequest,
}
impl PhysicalRefusalCarrier {
    pub fn take(&self) -> Result<PhysicalRefusal, ArrivalRefusal> {
        let mut state = self
            .original
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match std::mem::replace(&mut *state, AdminCarrierState::Spent) {
            AdminCarrierState::Refused(refusal) => Ok(refusal),
            other => {
                *state = other;
                Err(ArrivalRefusal::ForeignInput)
            }
        }
    }
}
impl AdminPhysicalRequest {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    pub fn take(&self) -> Result<CompletingPhysicalRequest, ArrivalRefusal> {
        let request = {
            let mut state = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            match std::mem::replace(&mut *state, AdminCarrierState::Taken) {
                AdminCarrierState::Pending(request) => request,
                other => {
                    *state = other;
                    return Err(ArrivalRefusal::ForeignInput);
                }
            }
        };
        request.check_admin_route()?;
        Ok(request)
    }

    pub fn retain_refusal(
        self,
        refusal: PhysicalRefusal,
    ) -> Result<PhysicalRefusalCarrier, ArrivalRefusal> {
        if !Arc::ptr_eq(&self.binding, refusal.binding()) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        {
            let mut state = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            if !matches!(*state, AdminCarrierState::Taken) {
                return Err(ArrivalRefusal::ForeignInput);
            }
            *state = AdminCarrierState::Refused(refusal);
        }
        Ok(PhysicalRefusalCarrier { original: self })
    }
}

/// A native admin request the kernel's admin middleware refused, on its way back to root.
///
/// The middleware takes the request's pending physical owner before it judges the credential. On
/// a refusal it has no admin unit to record the refusal under, and a refusal is output authority
/// only once it is recorded ([`CompletingPhysicalRequest::refuse_admin`]). So the unspent owner
/// and its carrier ride the refusing answer's extensions in this cell; root records the refusal
/// as the request's own unit and then makes it the answer's authority. Dropped untaken, the owner
/// cancels its request as it always did.
#[derive(Clone, Default)]
pub struct AdminDenialReturn {
    held: Arc<Mutex<Option<(CompletingPhysicalRequest, AdminPhysicalRequest)>>>,
}
impl AdminDenialReturn {
    /// The unspent owner and its carrier, once.
    pub fn take(&self) -> Option<(CompletingPhysicalRequest, AdminPhysicalRequest)> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Put this cell in `response`'s extensions if it holds a refused request's owner.
    pub(crate) fn ride(&self, response: &mut axum::response::Response) {
        let holds = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if holds {
            response.extensions_mut().insert(self.clone());
        }
    }
}

/// The admin middleware's hold on a native request's pending owner. It reads as the
/// `Option<CompletingPhysicalRequest>` it holds. Dropped with the owner still unspent (every
/// refusing return of the middleware), it moves owner and carrier into its [`AdminDenialReturn`]
/// instead of dropping, and so cancelling, the request.
pub(crate) struct HeldAdminPending {
    pending: Option<CompletingPhysicalRequest>,
    carrier: Option<AdminPhysicalRequest>,
    back: AdminDenialReturn,
}
impl HeldAdminPending {
    /// Take the pending owner out of `carrier`, if the request carries one.
    pub(crate) fn take_from(
        carrier: Option<AdminPhysicalRequest>,
        back: AdminDenialReturn,
    ) -> Result<Self, ArrivalRefusal> {
        let pending = carrier
            .as_ref()
            .map(AdminPhysicalRequest::take)
            .transpose()?;
        Ok(Self {
            pending,
            carrier,
            back,
        })
    }
}
impl std::ops::Deref for HeldAdminPending {
    type Target = Option<CompletingPhysicalRequest>;
    fn deref(&self) -> &Self::Target {
        &self.pending
    }
}
impl std::ops::DerefMut for HeldAdminPending {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pending
    }
}
impl Drop for HeldAdminPending {
    fn drop(&mut self) {
        if let (Some(pending), Some(carrier)) = (self.pending.take(), self.carrier.take()) {
            *self
                .back
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some((pending, carrier));
        }
    }
}

/// Actual operator execution custody. Keep an Arc of this owner through handler/response work;
/// retaining only the projected auth proof does not retain physical execution authority.
pub struct PhysicalAdminExecution {
    binding: Arc<RequestBinding>,
    admission: Arc<ExecutionAdmission>,
}
impl PhysicalAdminExecution {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    pub fn admission(&self) -> &Arc<ExecutionAdmission> {
        &self.admission
    }
    pub fn check_executing(&self) -> Result<(), ArrivalRefusal> {
        self.binding.check_executing()
    }
}
impl Drop for PhysicalAdminExecution {
    fn drop(&mut self) {
        self.binding.state.cancel();
    }
}

/// A public core operation's actual physical/publication custody; no principal or plane proof.
pub struct PhysicalPublicExecution {
    binding: Arc<RequestBinding>,
    lease: AdmissionLease,
}
impl PhysicalPublicExecution {
    /// Execute only the original public core request against its retained prepared generation.
    /// No caller-supplied URI, router or replacement request can borrow this execution right.
    pub async fn http_response(&self) -> Result<axum::response::Response, ArrivalRefusal> {
        use tower::ServiceExt;
        self.check_executing()?;
        let snapshot = self
            .binding
            .snapshot()
            .map_err(|_| ArrivalRefusal::Capacity)?;
        let mut request = super::http_projection::HttpProjection::from_snapshot(snapshot.clone())
            .map_err(|_| ArrivalRefusal::Capacity)?
            .into_request(axum::body::Body::from(snapshot.body_bytes()));
        request.extensions_mut().insert(self.binding.app.clone());
        let prepared = &self.binding.prepared;
        let router = (prepared.dispatch_layer)(prepared.router.clone())
            .with_state(self.binding.handle.clone());
        Ok(router
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {}))
    }

    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    pub fn lease(&self) -> &AdmissionLease {
        &self.lease
    }
    pub fn check_executing(&self) -> Result<(), ArrivalRefusal> {
        self.binding.check_executing()
    }
}
impl Drop for PhysicalPublicExecution {
    fn drop(&mut self) {
        self.binding.state.cancel();
    }
}

/// Move-only handoff to native allocation. Neither component is publicly constructible.
pub struct AuthorizedPhysicalData {
    authorization: DataAuthorization,
    physical: PhysicalExecutionOwner,
}
impl AuthorizedPhysicalData {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        self.physical.binding()
    }
    pub(crate) fn into_parts(self) -> (DataAuthorization, PhysicalExecutionOwner) {
        (self.authorization, self.physical)
    }
}

/// Retained by final native data execution through its effects. Dropping the owner closes
/// the same state read by the effect gate, even if other code retains input projections.
pub struct PhysicalExecutionOwner {
    binding: Arc<RequestBinding>,
}
impl PhysicalExecutionOwner {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }

    /// Start once with the exact final allocation/money proof. Reset and this transition
    /// arbitrate under one lock; a reset that wins cannot be followed by execution.
    pub fn start_execution(
        &self,
        admission: &DataExecutionAdmission,
    ) -> Result<(), ArrivalRefusal> {
        if !Arc::ptr_eq(&self.binding, admission.binding()) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        let mut phase = self
            .binding
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *phase != Phase::Admitted {
            return Err(ArrivalRefusal::Cancelled);
        }
        if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        *phase = Phase::Executing {
            deadline: self.binding.deadline,
        };
        Ok(())
    }
}
impl Drop for PhysicalExecutionOwner {
    fn drop(&mut self) {
        self.binding.state.cancel();
    }
}

#[cfg(test)]
#[path = "../tests/native_physical_admission.rs"]
pub(crate) mod tests;
