// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane driver over the MIN-3 plane port (IF §11.3, §12.23). A [`PortDriver`] owns one plane instance opened
//! by `Registry::open_plane` and serves it through `PlanePort` alone: no `PlaneCalls`, no old `abi::plane`. It grows
//! slice by slice (PLANE-DRIVER.md) until it replaces `PlaneDriver`; this slice drives the stdin/stdout line carrier
//! (`ROUTE_LINE`): `request`, `end`, `PlaneOut::Emit` into `LineCarriers::emit_from_plane`, and
//! `admin(ADMIN_CARRIER_END)` once per carrier.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::services::{Caller, Incarnation};
use busbar_plugin_abi::fail::failed::F_INTERNAL;
use busbar_plugin_abi::plane::{ADMIN_CARRIER_END, ADMIN_TICK, RQ_PROJECT};
use busbar_plugin_abi::records::{tag as g, Reply, U64Rec, Writer};
use busbar_ports::plane::{PlaneIn, PlanePort};
use busbar_ports::{CallCx, PortError};

use crate::channels::line_carriers::{CarrierSink, LineCarriers};
use crate::host_services::{KernelServices, RecoveryWork};

use super::port_auth::{
    admit, catalog, refuse, Admitted, Credentials, NoTickets, Principal, Subject, TicketDoor,
};
use super::port_carrier::PortCarrier;
use super::port_channels::{decode_tick, TickOut};
use super::port_charge::charge;
use super::port_egress::{PortUpstream, SessionFacts};
use super::port_intents::{IntentHost, Namespace, Resolver};
use super::port_money::PortMoney;
use super::port_routes::{admin_hydrate, recovery_request, recovery_route, Mounted, PortRoutes};
use super::port_serve::{AuditOnly, Books, Ran, SessionRun, UnitBooks};
use super::port_session::{ClientSink, Effects, SessionError, ToClient};

use super::AuditSink;
use crate::push::StorePushQueue;
use crate::refusal::{ClientRefusal, RefusalMap};
use crate::teller::UnitCtx;
use busbar_plugin_abi::types::{Bytes, Pair, Str};

/// How long the plane has to drop its per-carrier state at a carrier's end.
const CARRIER_END_GRACE: Duration = Duration::from_secs(5);

/// How long the plane has to answer one tick.
const TICK_GRACE: Duration = Duration::from_secs(30);

/// Why a line got no answer line.
#[derive(Debug)]
pub enum LineRefused {
    /// The plane declares no `ROUTE_LINE` route.
    NoLineRoute,
    /// The plane refused, failed or faulted, or broke a once rule, or answered with an item a later slice drives.
    Session(SessionError),
    /// The line's task was cancelled.
    Cancelled,
}

/// A line's effects outside its response line: an `Emit` is written to its carrier at once, which is before this
/// line's own response line (§12.23 rule 3).
struct LineEffects<'a> {
    carriers: &'a LineCarriers,
    owner: &'a Incarnation,
}

impl Effects for LineEffects<'_> {
    fn emit(&self, carrier: u64, bytes: &[u8]) {
        self.carriers.emit_from_plane(self.owner, carrier, bytes);
    }
}

/// A served request's effects: the line carriers' emits, and the client's streamed items when the route layer
/// gave a sink.
struct ServeEffects<'a> {
    data: Option<Arc<crate::auth::native_data::NativeDataPending>>,
    admission: Option<Arc<super::port_admission::Pending>>,
    lines: LineEffects<'a>,
    client: Option<Arc<dyn ClientSink>>,
    invocation: Option<crate::host_services::InvocationContext>,
    hooks: Option<super::port_hooks::Invocation>,
}

impl Effects for ServeEffects<'_> {
    fn admission_owner(&self) -> Option<&Arc<super::port_admission::Pending>> {
        self.admission.as_ref()
    }
    fn data(&self) -> Option<&Arc<crate::auth::native_data::NativeDataPending>> {
        self.data.as_ref()
    }
    fn admission(&self) -> Option<&super::port_admission::Pending> {
        self.admission.as_deref()
    }
    fn hooks(&self) -> Option<&super::port_hooks::Invocation> {
        self.hooks.as_ref()
    }

    fn invocation(&self) -> Option<&crate::host_services::InvocationContext> {
        self.invocation.as_ref()
    }

    fn emit(&self, carrier: u64, bytes: &[u8]) {
        self.lines.emit(carrier, bytes);
    }

    fn client(&self) -> Option<&dyn ClientSink> {
        self.client.as_deref()
    }
}

/// The response line without its terminator: the to-client BODY bytes. RESPOND's status, the head and the end
/// carry nothing on a line; empty writes nothing. A message item has no line form.
fn line_of(items: Vec<ToClient>) -> Result<Vec<u8>, LineRefused> {
    // The first BODY's own buffer becomes the line; a later BODY is appended to it.
    let mut line: Option<Vec<u8>> = None;
    for item in items {
        match item {
            ToClient::Body(bytes) => match &mut line {
                None => line = Some(bytes),
                Some(line) => line.extend_from_slice(&bytes),
            },
            ToClient::Msg { .. } => return Err(LineRefused::Session(SessionError::NotDriven)),
            ToClient::Head { .. } | ToClient::Trailers(_) | ToClient::End => {}
        }
    }
    Ok(line.unwrap_or_default())
}

/// The argument of `admin(ADMIN_CARRIER_END)`: one `U64Rec(carrier)` (§12.23 rule 5).
pub(crate) fn carrier_end_arg(carrier: u64) -> Reply {
    let mut arg = Reply::new();
    arg.put_pod(g::TEXT, &U64Rec { value: carrier })
        .expect("one eight-byte record fits an empty reply");
    arg
}

/// One served MIN-3 plane instance: its driver, the audience its line session is bound to (the `canonical_uri`
/// of its config block, `None` when it states none), what its intents run against and who it is to the store.
#[derive(Clone)]
pub struct PortSeat {
    /// Actual admitted image metadata retained by the same read that opened this seat.
    pub image: Arc<super::image_identity::PlaneImageIdentity>,
    pub instance: String,
    /// Exact catalog and registration request domains retained by this serving generation.
    pub request_routes: Arc<super::request_admission::RequestRoutes>,
    /// The same stable instance capacity used by this seat's channel driver.
    /// Original unit allocation derives one unit account here and retains it through every attach.
    pub channel_budget: crate::channels::budget::InstanceBudget,
    pub driver: Arc<PortDriver>,
    pub audience: Option<String>,
    /// Core's public URL as this plane instance is given it (the value core writes at the plane's
    /// D_PUBLIC_URL_PATH): what `{public_url}` in a route's challenge is replaced with when the route
    /// is mounted. `None`: the operator configured none.
    pub public_url: Option<String>,
    /// What this instance's intents (records, push, signals, WORK) run against: [`PortDriver::serve`]'s `intents`.
    pub intents: Arc<dyn IntentHost>,
    /// The instance's record namespace (§12.5): the caller its pushes are queued under.
    pub who: Namespace,
    /// The egress walk a FORWARD runs over (`PortEgress`); `None` = this instance forwards nothing yet (its
    /// pool is not configured: a FORWARD fails `NotDriven`).
    pub upstream: Option<Arc<dyn PortUpstream>>,
    /// The channel carrier a session's CHANNEL, EX_MSG, WAKE_AT and DETACH run over (`PortCarrier`); `None` = this
    /// instance has no carrier yet: a CHANNEL is `P_ERROR` and a session ends with its walk.
    pub carrier: Option<Arc<PortCarrier>>,
}

impl PortSeat {
    /// The plane instance's configured public URL (D_PUBLIC_URL_PATH), if any.
    pub fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    /// One `admin(ADMIN_TICK)`: the plane's PUSHes are queued under this instance's namespace (EMITs already went
    /// to their carriers). A refused or failed tick, or a push the queue refuses, is logged and dropped: the next
    /// tick is the retry. Answers how many pushes were queued. `at`: the timer's reading this tick fired at.
    async fn tick_once(&self, queue: &StorePushQueue, at: Instant) -> usize {
        let out = match self.driver.tick(at).await {
            Ok(out) => out,
            Err(error) => {
                tracing::warn!(instance = %self.instance, ?error, "a plane tick failed");
                return 0;
            }
        };
        let who = self.who.caller();
        let mut queued = 0;
        for (ttl_s, recs) in &out.pushes {
            match queue.enqueue(&who, *ttl_s, recs).await {
                Ok(()) => queued += 1,
                Err(denied) => {
                    tracing::warn!(instance = %self.instance, ?denied, "a plane push was not queued");
                }
            }
        }
        queued
    }

    /// The tick timer task (§8.6 `tick_s`): `tick_once` every period until the task is dropped. A plane that
    /// states no period is never ticked (the task returns at once).
    pub async fn tick_task(self, queue: Arc<StorePushQueue>) {
        let Some(period) = self.driver.tick_s().filter(|s| *s > 0) else {
            return;
        };
        let mut every = tokio::time::interval(Duration::from_secs(period));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick of an interval is immediate: the plane has just opened, its first period starts now.
        every.tick().await;
        loop {
            // The timer's own reading of this tick is the one clock reading the tick takes.
            let at = every.tick().await.into_std();
            self.tick_once(&queue, at).await;
        }
    }
}

impl std::fmt::Debug for PortSeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortSeat")
            .field("instance", &self.instance)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

/// A plane instance served through its port.
pub struct PortDriver {
    pub(crate) port: Arc<dyn PlanePort>,
    pub(crate) services: Arc<KernelServices>,
    pub(crate) caller: Caller,
    pub(crate) refusals: Arc<dyn RefusalMap>,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) routes: PortRoutes,
    /// The data, upgrade and admin routes by id (`off_path::plane_port`): what a request is served on.
    pub(crate) mounted: BTreeMap<u32, Arc<Mounted>>,
    pub(crate) tickets: Arc<dyn TicketDoor>,
    /// The native ticket desk ([`PortDriver::ticket_desk`]).
    pub(crate) ticket_desk: Option<Arc<crate::auth::native_ticket::TicketDesk>>,
    /// The declared usage classes (D_USAGE_CLASS) in the Statement's order: a unit count's class indexes them.
    pub(crate) usage: Arc<[String]>,
    /// The same classes as the port declares them, shared with each hooked request's invocation.
    pub(crate) classes: Arc<[busbar_ports::plane::UsageClass]>,
    pub(crate) hooks: Option<Arc<super::native_hook_bindings::Bindings>>,
}

impl PortDriver {
    pub(crate) fn has_hooks(&self, route: u32) -> bool {
        self.hooks
            .as_ref()
            .is_some_and(|binder| binder.active(route))
    }

    /// The exact instance owner admitted by root; callers must never mint a lookalike.
    pub fn caller(&self) -> &Caller {
        &self.caller
    }

    /// Complete core owned by this seat, for root's same-generation assembly check.
    pub fn core(&self) -> &Arc<KernelServices> {
        &self.services
    }

    /// Bind execution to this driver's core and exact registered instance/unit.
    pub fn invocation(
        &self,
        generation: Arc<crate::host_services::ServingGeneration>,
        unit: u64,
    ) -> Result<crate::host_services::InvocationContext, &'static str> {
        if !Arc::ptr_eq(&self.services, generation.core()) {
            return Err("the native seat belongs to a different core generation");
        }
        crate::host_services::InvocationContext::new(generation, self.caller.clone(), unit)
    }

    /// Consume a complete immutable hook binding before this driver is published in a seat.
    #[must_use]
    pub fn with_hooks(mut self, hooks: Arc<super::native_hook_bindings::Bindings>) -> Self {
        self.hooks = Some(hooks);
        self
    }

    /// The instance's declared usage classes, in the order a unit count's class indexes them.
    #[must_use]
    pub fn usage_classes(&self) -> Arc<[String]> {
        Arc::clone(&self.usage)
    }

    /// The routes this instance declares, sorted by where core mounts them.
    #[must_use]
    pub fn routes(&self) -> &PortRoutes {
        &self.routes
    }

    /// The instance's port: what its carrier's `demux`, its probes and its charges are asked through.
    #[must_use]
    pub fn port(&self) -> Arc<dyn PlanePort> {
        Arc::clone(&self.port)
    }

    /// `admin(ADMIN_HYDRATE)`: hands the plane the records it asked core to keep.
    ///
    /// # Errors
    /// The plane refused, failed or faulted.
    pub async fn hydrate(&self, stored: &[u8]) -> Result<Vec<u8>, PortError> {
        admin_hydrate(&*self.port, stored).await
    }

    /// The tickets this instance admits on an `AUTH_TICKET` route (default: none; `port_serve::TicketGate` is the
    /// production door, built where the ticket key is known).
    #[must_use]
    pub fn with_tickets(mut self, tickets: Arc<dyn TicketDoor>) -> Self {
        self.tickets = tickets;
        self
    }

    /// The instance's native ticket desk (`auth::native_ticket`): where its ticket routes redeem and where its
    /// served principals are entered for a MINT. Set only where core's ticket store is open.
    #[must_use]
    pub fn with_ticket_desk(mut self, desk: Arc<crate::auth::native_ticket::TicketDesk>) -> Self {
        self.ticket_desk = Some(desk);
        self
    }

    /// The instance's native ticket desk; `None`: core's ticket store is shut, so no ticket route of this
    /// instance is mounted.
    #[must_use]
    pub fn ticket_desk(&self) -> Option<&Arc<crate::auth::native_ticket::TicketDesk>> {
        self.ticket_desk.as_ref()
    }

    /// This instance serving a request the native path admitted with no unit (`owner`): what the listener's
    /// unbilled path serves through ([`UnbilledServe::serve`]).
    #[must_use]
    pub fn admitted_by<'d>(
        &'d self,
        owner: &'d crate::inbound::native::PhysicalUnbilledExecution,
    ) -> UnbilledServe<'d> {
        UnbilledServe {
            driver: self,
            owner,
        }
    }

    /// [`Self::serve`] for a request the native path admitted with no unit (`owner`). Where a core ticket
    /// admitted it, the plane is handed the ticket's class, identity and record from that admission: the ticket
    /// was spent at the route's desk, so nothing is redeemed here and no credential is read.
    async fn serve_unbilled(
        &self,
        input: ServeIn<'_>,
        owner: &crate::inbound::native::PhysicalUnbilledExecution,
    ) -> Result<Served, ServeError> {
        let Some((authorization, record)) = owner
            .authorization()
            .and_then(|authorization| Some((authorization, authorization.ticket_record()?)))
        else {
            return self.serve_inner(input, None).await;
        };
        if !authorization.made_on(self, input.route) {
            return Err(ServeError::Invocation(
                "the ticket's admission is not this route's",
            ));
        }
        let ticket = Admitted::ticket(authorization.identity().clone(), record);
        self.serve_as(input, None, Some(ticket)).await
    }

    /// Serves one request of a mounted route: admission (§12.11, the call site of `admit` for HTTP), then the
    /// whole session ([`run_session`]) with its books, on the caller's own task. The plane's calls are direct
    /// entries made between the session's awaits; nothing is handed to another thread.
    ///
    /// # Errors
    /// [`ServeError`]; a refusal is not an error, it is [`Served::Refused`].
    pub async fn serve(&self, input: ServeIn<'_>) -> Result<Served, ServeError> {
        self.serve_inner(input, None).await
    }

    /// Consume the actual DATA/physical preparatory owner, retaining its charged original input.
    pub async fn serve_admitted(
        &self,
        mut input: ServeIn<'_>,
        data: Arc<crate::auth::native_data::NativeDataPending>,
    ) -> Result<NativeServed, ServeError> {
        let snapshot = data.snapshot();
        if !data.accepts(self, input.route)
            || input.unit.is_some()
            || !input.request.same_request(snapshot.request())
            || input.http.request_id != data.binding().invocation().request_id().get()
            || !input.http.same_head(snapshot)
            || input.http.body.as_ref() != snapshot.body()
            || input.now_s != snapshot.now_s()
            || input
                .invocation
                .as_ref()
                .is_some_and(|context| !context.same_unit(data.context()))
            || input
                .admission
                .as_ref()
                .is_some_and(|pending| !Arc::ptr_eq(pending, data.pending()))
        {
            return Err(ServeError::Invocation(
                "DATA input does not match its original physical request",
            ));
        }
        input.http.body = snapshot.body_bytes();
        // The carriers the route's chain judged never reach the plane, whoever built the input.
        input.http.withhold(Arc::clone(data.withheld()));
        input.invocation = Some(data.context().clone());
        input.admission = Some(Arc::clone(data.pending()));
        let served = self.serve_inner(input, Some(data.clone())).await?;
        let decision = match &served {
            Served::Refused(refused) => Some(refused.decision.clone()),
            Served::Ran(_) => None,
        };
        Ok(NativeServed {
            served,
            retirement: NativeTaskRetirement {
                pending: data,
                decision,
                refusal: None,
            },
        })
    }

    async fn serve_inner(
        &self,
        input: ServeIn<'_>,
        data: Option<Arc<crate::auth::native_data::NativeDataPending>>,
    ) -> Result<Served, ServeError> {
        self.serve_as(input, data, None).await
    }

    /// `ticket`: the admission of a request a core ticket already admitted with no unit
    /// ([`Self::serve_unbilled`]); it stands in place of `admit`, which would redeem the spent ticket again.
    async fn serve_as(
        &self,
        input: ServeIn<'_>,
        data: Option<Arc<crate::auth::native_data::NativeDataPending>>,
        ticket: Option<Admitted>,
    ) -> Result<Served, ServeError> {
        if input.admission.is_some() && (input.unit.is_some() || input.invocation.is_none()) {
            return Err(ServeError::Invocation(
                "pending admission must own one unbilled invocation",
            ));
        }
        if let Some(context) = &input.invocation {
            if !Arc::ptr_eq(&self.services, context.generation().core())
                || !context.accepts(&self.caller)
                || input
                    .unit
                    .as_ref()
                    .is_none_or(|unit| unit.ctx.key.get() != context.unit())
                    && input
                        .admission
                        .as_ref()
                        .is_none_or(|pending| !pending.context().same_unit(context))
                    // A verified request on a route that opens no unit owns neither: it is
                    // there for the route's hooks to run under, and for nothing else.
                    && !context.opens_no_unit()
                // Such a request is never a unit to bill and never a pending admission.
                || context.opens_no_unit() && (input.unit.is_some() || input.admission.is_some())
            {
                return Err(ServeError::Invocation(
                    "the invocation does not own this native unit",
                ));
            }
        }
        let route = self
            .mounted
            .get(&input.route)
            .cloned()
            .ok_or(ServeError::NoRoute)?;
        let admission = if let Some(data) = data {
            ServingAdmission::Data(data)
        } else if let Some(ticket) = ticket {
            // A ticket route's own class must be among the route's: nothing else is served as a ticket.
            if route.effective & busbar_plugin_abi::plane::AUTH_TICKET == 0 {
                return Err(ServeError::Invocation(
                    "a ticket's admission on a route that admits no ticket",
                ));
            }
            ServingAdmission::Credentials(Ok(ticket))
        } else {
            ServingAdmission::Credentials(
                admit(
                    route.route,
                    route.effective,
                    &input.creds,
                    &*self.tickets,
                    &*self.refusals,
                    input.audience,
                    input.now_s,
                )
                .await,
            )
        };
        let hook_binder = self.hooks.clone();
        let arrived = input.now_s;
        let ServeIn {
            request,
            http,
            creds,
            unit,
            upstream,
            client,
            carrier,
            intents,
            models,
            invocation,
            admission: pending_admission,
            ..
        } = input;
        // Who the request is served as: a DATA request's verified identity, else the credentials' verified subject.
        let principal = match (&admission, creds.principal) {
            (ServingAdmission::Data(data), _) => Some(Subject::Identity(data.identity().clone())),
            (_, Principal::Verified(subject)) => Some(subject),
            _ => None,
        };
        // The count owner is held for the whole session, including when the HTTP body is empty; dropping this
        // future between two crossings cancels the plugin session and releases it at once.
        let _request = request;
        // A panic in the session (core's side of a crossing; a plugin's own panic is a FAULT from busbar-ffi) ends
        // this one request as `Cancelled`, as it did when the session ran on a blocking thread, and the core's
        // task goes on: one `catch_unwind` frame per poll, no allocation.
        let session = serve_session(
            &*self.port,
            &*self.refusals,
            &*self.audit,
            LineEffects {
                carriers: self.services.line_carriers(),
                owner: self.caller.incarnation(),
            },
            Serving {
                route,
                admission,
                http,
                principal,
                unit,
                upstream,
                client,
                carrier,
                intents,
                models,
                invocation,
                pending_admission,
                hook_binder,
                classes: Arc::clone(&self.classes),
                now_s: arrived,
            },
        );
        futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(session))
            .await
            .map_err(|_| ServeError::Cancelled)?
    }

    /// Render a core refusal in this exact admitted route's dialect without opening a unit.
    pub fn render_refusal_now(
        &self,
        route: u32,
        http: &HttpIn,
        refusal: &ClientRefusal,
    ) -> Result<Vec<ToClient>, ServeError> {
        let auth = self.refusal_auth(route)?;
        Ok(render_native_refusal(
            &*self.port,
            route,
            auth,
            http,
            refusal,
        ))
    }

    fn refusal_auth(&self, route: u32) -> Result<u32, ServeError> {
        let mounted = self.mounted.get(&route).ok_or(ServeError::NoRoute)?;
        Ok(mounted.effective & mounted.effective.wrapping_neg())
    }

    /// D_TICK_S: the period core calls [`tick`](Self::tick) at, if the plane declares one.
    #[must_use]
    pub fn tick_s(&self) -> Option<u64> {
        self.port.tick_s()
    }

    /// One `admin(ADMIN_TICK)` (§8.6): the plane's EMITs are written to their carriers at once (an ended carrier,
    /// or one another instance owns, drops it and counts), and its PUSHes are returned for the push queue, which
    /// belongs to the caller (it enqueues them under the instance's namespace, §12.9).
    ///
    /// # Errors
    /// The plane refused, failed or faulted, or its answer is not records.
    async fn tick(&self, at: Instant) -> Result<TickOut, PortError> {
        let cx = CallCx {
            deadline: at + TICK_GRACE,
            request_id: 0,
            stack: Default::default(),
        };
        let answer = self.port.admin(cx, ADMIN_TICK, &[]).await?;
        let out = decode_tick(&answer).map_err(|_| PortError::Failed {
            code: F_INTERNAL,
            text: "the plane tick answer is not records".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        })?;
        for (carrier, bytes) in &out.emits {
            self.services.line_carriers().emit_from_plane(
                self.caller.incarnation(),
                *carrier,
                bytes,
            );
        }
        Ok(out)
    }

    /// Whether the plane declares a `ROUTE_LINE` route.
    #[must_use]
    pub fn serves_lines(&self) -> bool {
        self.routes.line.is_some()
    }

    /// Opens a line carrier owned by this instance, serving as `principal`, written through `sink`.
    pub fn open_carrier(&self, principal: &Arc<str>, sink: CarrierSink) -> NonZeroU64 {
        NonZeroU64::new(
            self.services
                .open_carrier_session(&self.caller, principal, sink),
        )
        .expect("kernel carrier sessions are minted above zero")
    }

    /// Closes the carrier's writer side: an `Emit` to it is dropped from here on.
    pub fn close_carrier(&self, carrier: NonZeroU64) {
        self.services.close_carrier_session(carrier.get());
    }

    /// Tells the plane the carrier has ended, once, after its line sessions ended and its writer closed. The plane
    /// answers nothing; a plane that fails here has its fault handled by the port, and the carrier is gone anyway.
    pub async fn carrier_ended(&self, carrier: NonZeroU64) {
        let arg = carrier_end_arg(carrier.get());
        let cx = CallCx {
            // The node's monotonic clock service, read once for this carrier's end.
            deadline: busbar_contract::mono_instant::instant_at(crate::store::monotonic_ns())
                + CARRIER_END_GRACE,
            request_id: 0,
            stack: Default::default(),
        };
        if let Err(error) = self.port.admin(cx, ADMIN_CARRIER_END, arg.as_bytes()).await {
            tracing::warn!(?error, carrier = carrier.get(), "plane carrier end failed");
        }
    }
}

fn render_native_refusal(
    port: &dyn PlanePort,
    route: u32,
    auth: u32,
    http: &HttpIn,
    refusal: &ClientRefusal,
) -> Vec<ToClient> {
    struct RenderOnly;
    impl Effects for RenderOnly {
        fn emit(&self, _: u64, _: &[u8]) {}
    }
    let headers = lent_headers(http);
    let req = PlaneIn {
        route,
        flags: 0,
        auth,
        method: http.method(),
        path: http.path(),
        query: http.query(),
        headers: &headers,
        identity: &[],
        request_id: http.request_id,
        carrier: 0,
        work: "",
        ticket_record: &[],
    };
    refuse(port, &req, refusal, &RenderOnly)
}

/// A request's header fields lent to the plane for one call, on the stack up to 32 (as `LentFields`).
type LentPairs<'a> = smallvec::SmallVec<[Pair<'a>; 32]>;

/// The request's header fields as the plane reads them, borrowed from `http`.
fn lent_headers(http: &HttpIn) -> LentPairs<'_> {
    let mut headers = LentPairs::new();
    http.each_header(|name, value| {
        headers.push(Pair {
            name: Str::new(name),
            value: Bytes::new(value),
        });
    });
    headers
}

/// The carrier's own binding, as its lines see it: the principal its session was bound as, and whether that was a
/// verified credential (an unbound session is anonymous).
#[derive(Clone, Debug)]
pub struct LineCaller {
    pub principal: Arc<str>,
    pub authenticated: bool,
}

/// A line's admission (IF §12.11): the carrier's principal is the one credential a line has, so a PRINCIPAL route
/// takes it as the identity (ID_SUBJECT), OPTIONAL takes it when the carrier is authenticated, PUBLIC takes none.
/// A line has no credential header, so a ticket never applies and PRINCIPAL beside TICKET runs PRINCIPAL.
pub(crate) async fn admit_line(
    route: u32,
    effective: u32,
    caller: &LineCaller,
    refusals: &dyn RefusalMap,
) -> Result<Admitted, ClientRefusal> {
    let principal = if caller.authenticated {
        Principal::Verified(Subject::Shared(Arc::clone(&caller.principal)))
    } else {
        Principal::Anonymous
    };
    let creds = Credentials {
        bearer: None,
        principal,
        operator: false,
        signed: None,
    };
    admit(route, effective, &creds, &NoTickets, refusals, "", 0).await
}

/// What a port error becomes for the client: core's generic refusal, never the plugin's words (§12.15).
pub(crate) fn refusal_of(
    route: u32,
    error: &PortError,
    refusals: &dyn RefusalMap,
) -> ClientRefusal {
    refusals.for_port(route, error)
}

/// Preserve the current authority's refusal vocabulary at the original route renderer.
fn selected_refusal(
    route: u32,
    failure: &super::port_egress::SelectedFailure,
    refusals: &dyn RefusalMap,
) -> ClientRefusal {
    use super::port_egress::SelectedFailure;
    use crate::governance::selected_policy::SelectedPolicyRefusal;
    use busbar_contract::caps::ReasonCode;
    use busbar_plugin_abi::fail::refused::{R_NO_ROUTE, R_POLICY, R_RATE_LIMITED};

    match failure {
        SelectedFailure::Quota => return refusals.for_core(route, R_RATE_LIMITED),
        SelectedFailure::NoSend
        | SelectedFailure::Policy(SelectedPolicyRefusal::StalePolicyTarget) => {
            return refusals.for_core(route, R_NO_ROUTE);
        }
        SelectedFailure::Policy(SelectedPolicyRefusal::CurrentAuthority(reason)) => {
            if let Some(code) = reason.auth_code() {
                return refusals.for_auth(route, code);
            }
        }
        SelectedFailure::Policy(SelectedPolicyRefusal::CurrentGroup(
            ReasonCode::ScopeDenied | ReasonCode::GroupFrozen,
        )) => return refusals.for_core(route, R_POLICY),
        _ => {}
    }
    refusals.for_port(
        route,
        &PortError::Failed {
            code: if matches!(failure, SelectedFailure::Backend) {
                busbar_plugin_abi::fail::failed::F_UNAVAILABLE
            } else {
                busbar_plugin_abi::fail::failed::F_INTERNAL
            },
            text: "".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        },
    )
}

/// Ties a request builder's two borrowed inputs to the one lifetime of the [`PlaneIn`] it returns (a closure
/// with elided reference parameters would give each its own, and the result borrows both).
fn one_lifetime<'a, F>(build: F) -> F
where
    F: Fn(u32, &'a [u8], &'a [u8]) -> PlaneIn<'a>,
{
    build
}

/// What a seat's core-built sessions (a line, a recovery poll) run against, borrowed from the seat for the session:
/// the driver's plane and books, and the seat's intents, walk and carrier.
struct Seated<'s> {
    port: &'s dyn PlanePort,
    refusals: &'s dyn RefusalMap,
    audit: &'s dyn AuditSink,
    services: &'s KernelServices,
    owner: &'s Incarnation,
    intents: &'s dyn IntentHost,
    upstream: Option<&'s Arc<dyn PortUpstream>>,
    carrier: Option<&'s Arc<PortCarrier>>,
}

impl Seated<'_> {
    /// A session's effects: emits to the line carriers; no client sink (the items are collected).
    fn effects(&self) -> ServeEffects<'_> {
        ServeEffects {
            data: None,
            admission: None,
            lines: LineEffects {
                carriers: self.services.line_carriers(),
                owner: self.owner,
            },
            client: None,
            invocation: None,
            hooks: None,
        }
    }

    /// What a session of this seat is driven against, with `effects`.
    fn driving<'a>(&'a self, effects: &'a ServeEffects<'a>) -> Driving<'a> {
        Driving {
            port: self.port,
            refusals: self.refusals,
            audit: self.audit,
            effects,
            intents: self.intents,
            upstream: self.upstream,
            carrier: self.carrier,
        }
    }
}

/// Why a durable-work poll was not delivered (§12.24 step 3).
#[derive(Debug)]
pub enum RecoverRefused {
    /// The work target lies on none of the instance's ROUTE_RECOVERY routes.
    NoRecoveryRoute,
    Session(ServeError),
}

impl PortSeat {
    fn seated(&self) -> Seated<'_> {
        Seated {
            port: &*self.driver.port,
            refusals: &*self.driver.refusals,
            audit: &*self.driver.audit,
            services: &self.driver.services,
            owner: self.driver.caller.incarnation(),
            intents: &*self.intents,
            upstream: self.upstream.as_ref(),
            carrier: self.carrier.as_ref(),
        }
    }

    /// Serves one line of `carrier` (IF §12.23 rule 3): admitted as the carrier's principal, then driven like any
    /// other session (FORWARD over this seat's walk, intents, upstream exchanges, channels, `end`). The response line,
    /// without its terminator, is the to-client BODY bytes, empty when the plane wrote none; EMITs went to their
    /// carriers before it. The plane's calls are direct entries on this task.
    ///
    /// # Errors
    /// [`LineRefused`]: no line route, a broken session, or a cancelled task.
    pub async fn answer_line(
        &self,
        carrier: NonZeroU64,
        request_id: u64,
        line: crate::plane_driver::SessionInput,
        from: &LineCaller,
    ) -> Result<Vec<u8>, LineRefused> {
        let route = self
            .driver
            .routes
            .line
            .clone()
            .ok_or(LineRefused::NoLineRoute)?;
        if self
            .driver
            .hooks
            .as_ref()
            .is_some_and(|hooks| hooks.active(route.route))
        {
            return Err(LineRefused::Session(SessionError::HookPrerequisite));
        }
        let admission =
            admit_line(route.route, route.effective, from, &*self.driver.refusals).await;
        // Caller-scoped records, WORK and audit rows take a verified principal only.
        let principal = from.authenticated.then(|| Arc::clone(&from.principal));
        let seated = self.seated();
        // The complete input owner, custody included, is held for the whole session.
        line_session(
            &seated,
            &route,
            admission,
            principal.as_deref(),
            carrier.get(),
            request_id,
            &line.bytes,
        )
        .await
    }

    /// Delivers one durable-work poll (IF §12.24 step 3): `recovery_request` on the ROUTE_RECOVERY route the work's
    /// target lies on, as the restored principal `subject`, driven like any session with a client side that discards.
    /// Core infers nothing from the answer: the plane settles the work itself, or the row is polled again.
    ///
    /// # Errors
    /// [`RecoverRefused`]: no recovery route for the target, or the session broke.
    pub async fn recover(
        &self,
        work: &RecoveryWork,
        subject: &str,
        request_id: u64,
    ) -> Result<(), RecoverRefused> {
        let route = recovery_route(&self.driver.routes, work.target())
            .cloned()
            .ok_or(RecoverRefused::NoRecoveryRoute)?;
        if self
            .driver
            .hooks
            .as_ref()
            .is_some_and(|hooks| hooks.active(route.route))
        {
            return Err(RecoverRefused::Session(ServeError::Invocation(
                "recovery hook invocation requires an admitted unit",
            )));
        }
        let reference = work.reference();
        let seated = self.seated();
        recover_session(
            &seated,
            &route,
            &reference,
            subject,
            work.target(),
            request_id,
        )
        .await
        .map_err(RecoverRefused::Session)
    }
}

/// One line on the caller's task: a refused admission is rendered by the plane (`render(RENDER_REFUSAL)`), else the
/// whole session; either way the body is the response line.
async fn line_session(
    seated: &Seated<'_>,
    route: &Mounted,
    admission: Result<Admitted, ClientRefusal>,
    principal: Option<&str>,
    carrier: u64,
    request_id: u64,
    line: &[u8],
) -> Result<Vec<u8>, LineRefused> {
    let effects = seated.effects();
    let build = one_lifetime(|auth, identity, ticket_record| PlaneIn {
        route: route.route,
        flags: 0,
        auth,
        method: "POST",
        path: &route.pattern,
        query: "",
        headers: &[],
        identity,
        request_id,
        carrier,
        work: "",
        ticket_record,
    });
    let admitted = match admission {
        Ok(admitted) => admitted,
        Err(refusal) => {
            let lowest = route.effective & route.effective.wrapping_neg();
            let req = build(lowest, &[], &[]);
            return line_of(refuse(&*seated.port, &req, &refusal, &effects));
        }
    };
    let req = build(
        admitted.auth,
        admitted.identity_records(),
        admitted.ticket_record(),
    );
    let served = drive_session(
        &seated.driving(&effects),
        route.route,
        &req,
        line,
        principal,
        None,
    )
    .await;
    match served {
        Ok(Served::Ran(ran)) => line_of(ran.client),
        Ok(Served::Refused(refused)) => line_of(refused.items),
        Err(ServeError::Session(error)) => Err(LineRefused::Session(error)),
        Err(ServeError::NoRoute) => Err(LineRefused::NoLineRoute),
        Err(ServeError::Cancelled) => Err(LineRefused::Cancelled),
        Err(ServeError::Invocation(_)) => Err(LineRefused::Session(SessionError::HookPrerequisite)),
    }
}

/// One recovery poll on the caller's task. What the plane answers the (absent) client is dropped.
async fn recover_session(
    seated: &Seated<'_>,
    route: &Mounted,
    work: &str,
    subject: &str,
    target: &str,
    request_id: u64,
) -> Result<(), ServeError> {
    let effects = seated.effects();
    let identity = busbar_ports::auth::Identity::of_subject(subject);
    let req = recovery_request(route, work, identity.identity_records(), target, request_id);
    drive_session(
        &seated.driving(&effects),
        route.route,
        &req,
        &[],
        Some(subject),
        None,
    )
    .await
    .map(|_| ())
}

/// One request of a mounted route, as the route layer read it. Its head is held as it arrived, never copied to be
/// served: the inbound request's own parts (moved in), the admitted DATA request's charged snapshot (shared), or the
/// text a core-built request (an admin call, a nested dispatch, a refusal render) already owns.
pub struct HttpIn {
    head: HttpHead,
    /// Shared inbound backing; clones retain its process byte credit without copying payload.
    pub body: bytes::Bytes,
    pub request_id: u64,
    /// The credential carriers core judged this request on (lowercase header names): never lent to the plane
    /// ([`Self::each_header`]), so neither the plane nor anything it forwards upstream sees them (`D_CRED_HEADER`:
    /// "core strips it upstream"). Shared with the route that owns the list; nothing is copied per request.
    withheld: Option<Arc<[Box<str>]>>,
}

/// Where a request's method, target and header fields live (see [`HttpIn`]).
pub enum HttpHead {
    /// The inbound request's parts: its route method, its URI (path and query read from it) and its header map.
    Parts {
        method: &'static str,
        uri: http::Uri,
        headers: http::HeaderMap,
    },
    /// The admitted DATA request's charged snapshot.
    Snapshot(Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot>),
    /// A head core built itself, already owned by its caller.
    Text {
        method: String,
        path: String,
        query: String,
        headers: Vec<(String, Vec<u8>)>,
    },
}

impl HttpIn {
    #[must_use]
    pub fn new(head: HttpHead, body: bytes::Bytes, request_id: u64) -> Self {
        Self {
            head,
            body,
            request_id,
            withheld: None,
        }
    }

    /// Withhold these credential carriers (lowercase names) from every header the plane is lent.
    pub fn withhold(&mut self, carriers: Arc<[Box<str>]>) {
        self.withheld = Some(carriers);
    }

    fn is_withheld(&self, name: &str) -> bool {
        self.withheld.as_deref().is_some_and(|carriers| {
            carriers
                .iter()
                .any(|carrier| carrier.eq_ignore_ascii_case(name))
        })
    }

    #[must_use]
    pub fn method(&self) -> &str {
        match &self.head {
            HttpHead::Parts { method, .. } => method,
            HttpHead::Snapshot(snapshot) => snapshot.method(),
            HttpHead::Text { method, .. } => method,
        }
    }

    #[must_use]
    pub fn path(&self) -> &str {
        match &self.head {
            HttpHead::Parts { uri, .. } => uri.path(),
            HttpHead::Snapshot(snapshot) => snapshot.path(),
            HttpHead::Text { path, .. } => path,
        }
    }

    /// The query without its `?`; empty when the target has none.
    #[must_use]
    pub fn query(&self) -> &str {
        match &self.head {
            HttpHead::Parts { uri, .. } => uri.query().unwrap_or_default(),
            HttpHead::Snapshot(snapshot) => snapshot.query(),
            HttpHead::Text { query, .. } => query,
        }
    }

    /// Each header field (name, value) the plane may see, in the order the head holds them: every field but the
    /// withheld credential carriers.
    pub fn each_header<'a>(&'a self, mut field: impl FnMut(&'a str, &'a [u8])) {
        self.each_field(|name, value| {
            if !self.is_withheld(name) {
                field(name, value);
            }
        });
    }

    /// Every header field as it arrived, carriers included: core's own reads, never lent to a plane.
    fn each_field<'a>(&'a self, mut field: impl FnMut(&'a str, &'a [u8])) {
        match &self.head {
            HttpHead::Parts { headers, .. } => {
                for (name, value) in headers {
                    field(name.as_str(), value.as_bytes());
                }
            }
            HttpHead::Snapshot(snapshot) => {
                for (name, value) in snapshot.headers() {
                    field(name, value);
                }
            }
            HttpHead::Text { headers, .. } => {
                for (name, value) in headers {
                    field(name, value);
                }
            }
        }
    }

    /// Whether this head is `snapshot`'s: the same snapshot, or the same method, target and header fields in order.
    fn same_head(
        &self,
        snapshot: &Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot>,
    ) -> bool {
        if let HttpHead::Snapshot(own) = &self.head {
            if Arc::ptr_eq(own, snapshot) {
                return true;
            }
        }
        if self.method() != snapshot.method()
            || self.path() != snapshot.path()
            || self.query() != snapshot.query()
        {
            return false;
        }
        let mut theirs = snapshot.headers();
        let mut same = true;
        self.each_field(|name, value| same &= theirs.next() == Some((name, value)));
        same && theirs.next().is_none()
    }
}

/// The billed unit a request runs as: its money seam and the unit it posts to.
pub struct Unit {
    pub money: PortMoney,
    pub ctx: UnitCtx,
    /// Where the unit's end user goes (`records.user`); `None` keeps none.
    pub journal: Option<Arc<dyn super::HookJournal>>,
}

/// What the route layer hands [`PortDriver::serve`] beside the request.
pub struct ServeIn<'a> {
    /// The original process admission, retained through the whole session even for an empty body.
    pub request: crate::limits::process_admission::RequestLease,
    /// The exact pre-money allocation and one callback; mutually exclusive with `unit`.
    pub admission: Option<Arc<super::port_admission::Pending>>,
    /// Checked root dispatch authority for the exact selected seat, unit and serving generation.
    pub invocation: Option<crate::host_services::InvocationContext>,
    /// The mounted route's id (`PortRoutes`).
    pub route: u32,
    pub http: HttpIn,
    /// What the request carries into admission (§12.11).
    pub creds: Credentials<'a>,
    /// The audience a ticket must match (the config block's `canonical_uri`).
    pub audience: &'a str,
    pub now_s: u64,
    /// The unit the request bills to; `None` = not a billed unit (audit rows only).
    pub unit: Option<Unit>,
    /// The member walk and the far end for a FORWARD; `None` = the route never forwards.
    pub upstream: Option<Arc<dyn PortUpstream>>,
    /// Where the client's items go as they are decided (a streamed reply); `None` = they are collected in [`Ran`].
    pub client: Option<Arc<dyn ClientSink>>,
    /// The seat's channel carrier (`PortSeat::carrier`).
    pub carrier: Option<Arc<PortCarrier>>,
    /// What the plane's intents run against.
    pub intents: Arc<dyn IntentHost>,
    /// The model names a ROUTE_CATALOG route lists (the principal's view, `endpoints::catalog_names`); empty for any
    /// other route.
    pub models: Vec<String>,
}

/// How a request ended, for the route layer.
pub enum Served {
    /// Admission refused it, or the plane refused it: the client items are already rendered.
    Refused(Refused),
    Ran(Ran),
}

/// The decision and the very items rendered for that decision remain together.
pub struct Refused {
    pub decision: ClientRefusal,
    pub items: Vec<ToClient>,
}

pub struct NativeServed {
    served: Served,
    retirement: NativeTaskRetirement,
}
impl NativeServed {
    pub fn into_parts(self) -> (Served, NativeTaskRetirement) {
        (self.served, self.retirement)
    }
}

/// Minted only by the original native serving call after its session has ended.
pub struct NativeTaskRetirement {
    pending: Arc<crate::auth::native_data::NativeDataPending>,
    decision: Option<ClientRefusal>,
    refusal: Option<crate::auth::native_data::DataRefusalCustody>,
}
impl NativeTaskRetirement {
    pub(crate) fn unit(&self) -> busbar_contract::UnitKey {
        busbar_contract::UnitKey::new(self.pending.context().unit())
    }
    pub(crate) fn permits_refusal(
        &self,
        binding: &Arc<crate::inbound::native::RequestBinding>,
    ) -> bool {
        self.refusal
            .as_ref()
            .is_some_and(|custody| custody.matches(binding))
            && Arc::ptr_eq(self.pending.binding(), binding)
    }
    /// The hooks that ran for the refused request, in the order they ran, the refusing hook's
    /// record among them (head `veto`): what the refusal's audit record names its hook from.
    /// Empty before [`Self::refuse`] took the refusal, and for a request no hook ran for.
    pub fn refused_hooks(&self) -> &[busbar_kernel_audit::record::HookApplied] {
        match &self.refusal {
            Some(custody) => custody.hooks(),
            None => &[],
        }
    }
    pub fn refuse(
        mut self,
    ) -> Result<crate::inbound::native::PhysicalRefusal, crate::auth::native_data::DataRefused>
    {
        let decision = self
            .decision
            .as_ref()
            .ok_or(crate::auth::native_data::DataRefused::Unit)?;
        let (physical, custody) = self.pending.take_refusal(decision)?;
        self.refusal = Some(custody);
        physical
            .refuse_data(self)
            .map_err(|_| crate::auth::native_data::DataRefused::Cancelled)
    }
}

/// Why a request got no answer.
#[derive(Debug)]
pub enum ServeError {
    Invocation(&'static str),
    /// The id names no data or upgrade route of this instance.
    NoRoute,
    Session(SessionError),
    /// The request's task was cancelled.
    Cancelled,
}

/// A plane instance serving one request the native path admitted with no unit ([`PortDriver::admitted_by`]).
pub struct UnbilledServe<'d> {
    driver: &'d PortDriver,
    owner: &'d crate::inbound::native::PhysicalUnbilledExecution,
}

impl UnbilledServe<'_> {
    /// [`PortDriver::serve`], with the request's own admission in hand: a request a core ticket admitted is
    /// handed to its plane as that ticket (its class, identity and record), and nothing is redeemed twice.
    ///
    /// # Errors
    /// [`ServeError`]; a refusal is not an error, it is [`Served::Refused`].
    pub async fn serve(&self, input: ServeIn<'_>) -> Result<Served, ServeError> {
        self.driver.serve_unbilled(input, self.owner).await
    }
}

/// One request: the admission's refusal, or the session.
enum ServingAdmission {
    Credentials(Result<Admitted, ClientRefusal>),
    Data(Arc<crate::auth::native_data::NativeDataPending>),
}

/// One request's owned inputs, held by its session.
struct Serving {
    route: Arc<Mounted>,
    admission: ServingAdmission,
    http: HttpIn,
    /// Who the request is served as: the scope of its caller-bound records, its audit rows and its WORK.
    principal: Option<Subject>,
    unit: Option<Unit>,
    upstream: Option<Arc<dyn PortUpstream>>,
    client: Option<Arc<dyn ClientSink>>,
    carrier: Option<Arc<PortCarrier>>,
    intents: Arc<dyn IntentHost>,
    models: Vec<String>,
    invocation: Option<crate::host_services::InvocationContext>,
    pending_admission: Option<Arc<super::port_admission::Pending>>,
    hook_binder: Option<Arc<super::native_hook_bindings::Bindings>>,
    classes: Arc<[busbar_ports::plane::UsageClass]>,
    now_s: u64,
}

async fn serve_session(
    port: &dyn PlanePort,
    refusals: &dyn RefusalMap,
    audit: &dyn AuditSink,
    lines: LineEffects<'_>,
    serving: Serving,
) -> Result<Served, ServeError> {
    let Serving {
        route,
        admission,
        http,
        principal,
        unit,
        upstream,
        client,
        carrier,
        intents,
        models,
        invocation,
        pending_admission,
        hook_binder,
        classes,
        now_s,
    } = serving;
    // A catalog renders core's list and runs no session: no hook is bound to a listing, so it
    // needs none of what a hook runs under (`NativeDataRoute::hooks_run`).
    let hook_binder = hook_binder.filter(|binder| binder.active(route.route) && !route.catalog);
    // A verified request on a route that opens no unit is handed its own invocation
    // (`NativeDataRoute::hook_invocation`): the route's hooks run under the request itself.
    let no_unit = invocation
        .as_ref()
        .filter(|context| context.opens_no_unit());
    if hook_binder.is_some()
        && (invocation.is_none()
            || (unit.is_none() && pending_admission.is_none() && no_unit.is_none()))
    {
        return Err(ServeError::Invocation(
            "native hooks need the admitted unit and generation",
        ));
    }
    let hook_unit = unit
        .as_ref()
        .map(|unit| (unit.ctx.key, unit.journal.clone()))
        .or_else(|| {
            pending_admission.as_ref().map(|pending| {
                (
                    busbar_contract::UnitKey::new(pending.context().unit()),
                    pending.journal(),
                )
            })
        })
        // No unit and no journal: the number the request's invocation is registered under.
        .or_else(|| no_unit.map(|context| (busbar_contract::UnitKey::new(context.unit()), None)));
    // Where the hooks' records go when no open unit holds them: a native request's refusal
    // custody, or the custody of a request that opens no unit.
    let hook_records = match &admission {
        ServingAdmission::Data(data) => Some(data.refusal_records()),
        ServingAdmission::Credentials(_) => invocation
            .as_ref()
            .and_then(|context| context.hook_records()),
    };
    let hooks =
        hook_binder
            .zip(hook_unit)
            .map(|(binder, (unit, journal))| super::port_hooks::Invocation {
                binder,
                principal: principal.clone(),
                now_s,
                classes: Arc::clone(&classes),
                journal,
                unit,
                records: hook_records,
            });
    let effects = ServeEffects {
        data: match &admission {
            ServingAdmission::Data(data) => Some(Arc::clone(data)),
            ServingAdmission::Credentials(_) => None,
        },
        admission: pending_admission,
        hooks,
        lines,
        client,
        invocation,
    };
    let headers = lent_headers(&http);
    // `records.user`: a node that keeps the end user asks the plane for its projection (PJ_END_USER).
    let project = effects.hooks.is_some()
        || effects
            .admission
            .as_ref()
            .and_then(|pending| pending.journal())
            .is_some_and(|journal| journal.keeps_end_user())
        || unit
            .as_ref()
            .and_then(|u| u.journal.as_deref())
            .is_some_and(|journal| journal.keeps_end_user());
    let build = one_lifetime(|auth, identity, ticket_record| PlaneIn {
        route: route.route,
        flags: if project { RQ_PROJECT } else { 0 },
        auth,
        method: http.method(),
        path: http.path(),
        query: http.query(),
        headers: &headers,
        identity,
        request_id: http.request_id,
        carrier: 0,
        work: "",
        ticket_record,
    });
    let req = match &admission {
        ServingAdmission::Data(data) => build(
            // A principal's class, or a ticket's with the record its plane stored at the mint.
            data.auth_class(),
            data.identity().identity_records(),
            data.ticket_record(),
        ),
        ServingAdmission::Credentials(Ok(admitted)) => build(
            admitted.auth,
            admitted.identity_records(),
            admitted.ticket_record(),
        ),
        ServingAdmission::Credentials(Err(refusal)) => {
            let lowest = route.effective & route.effective.wrapping_neg();
            let req = build(lowest, &[], &[]);
            return Ok(Served::Refused(Refused {
                items: refuse(port, &req, refusal, &effects),
                decision: refusal.clone(),
            }));
        }
    };
    if route.catalog {
        // A ROUTE_CATALOG route lists models: the plane renders core's list in its dialect, no session runs.
        let mut names: smallvec::SmallVec<[&str; 32]> = smallvec::SmallVec::new();
        names.extend(models.iter().map(String::as_str));
        return match catalog(port, &req, &names, &effects) {
            Ok(client) => Ok(Served::Ran(Ran {
                client,
                ..Ran::default()
            })),
            Err(error) => Err(ServeError::Session(error)),
        };
    }
    drive_session(
        &Driving {
            port,
            refusals,
            audit,
            effects: &effects,
            intents: &*intents,
            upstream: upstream.as_ref(),
            carrier: carrier.as_ref(),
        },
        route.route,
        &req,
        &http.body,
        principal.as_ref().map(Subject::as_str),
        unit.as_ref(),
    )
    .await
}

/// What a session is driven against: the plane, its refusal map and audit sink, the session's effects, and the
/// seat's intents, walk and carrier.
#[derive(Clone, Copy)]
struct Driving<'a> {
    port: &'a dyn PlanePort,
    refusals: &'a dyn RefusalMap,
    audit: &'a dyn AuditSink,
    effects: &'a ServeEffects<'a>,
    intents: &'a dyn IntentHost,
    upstream: Option<&'a Arc<dyn PortUpstream>>,
    carrier: Option<&'a Arc<PortCarrier>>,
}

/// One admitted request's whole session, on the caller's task, for every origin (a mounted route, a line, a
/// recovery poll): intents resolved under the verified `principal`, a FORWARD walked over `upstream`, channels over
/// `carrier`, the books (`unit`, else audit rows only). A request the plane refused or failed is rendered by the
/// plane; a broken session charges the image.
async fn drive_session(
    on: &Driving<'_>,
    route: u32,
    req: &PlaneIn<'_>,
    body: &[u8],
    principal: Option<&str>,
    unit: Option<&Unit>,
) -> Result<Served, ServeError> {
    let Driving {
        port,
        refusals,
        audit,
        effects,
        intents,
        upstream,
        carrier,
    } = *on;
    let resolver = match principal {
        Some(subject) => Resolver::new(intents, None).with_principal(subject, req.identity),
        None => Resolver::new(intents, None),
    }
    .with_route(route)
    .with_admission(effects.admission.as_deref());
    let session = carrier.map(|carrier| {
        carrier
            .session_with_budget(
                effects
                    .admission
                    .as_ref()
                    .and_then(|pending| pending.channel_budget())
                    .cloned(),
            )
            .with_admission(effects.admission.clone())
    });
    let resolver = match &session {
        Some(session) => resolver.with_channels(&session.host),
        None => resolver,
    };
    let dialect = port.dialects().first().map_or("", |d| &**d);
    let ran = {
        let unit_books = unit.map(|u| {
            UnitBooks::new(&u.money, &u.ctx, principal).with_journal(u.journal.as_deref())
        });
        let audit_books = AuditOnly {
            sink: audit,
            principal,
        };
        let books: &dyn Books = match (&unit_books, effects.admission.as_deref()) {
            (_, Some(pending)) => pending,
            (Some(books), None) => books,
            (None, None) => &audit_books,
        };
        let run = SessionRun {
            port,
            req,
            body,
            resolver: &resolver,
            dialect,
            refusals,
            effects,
            books,
            carrier: session.as_ref(),
        };
        match upstream {
            Some(upstream) => {
                let facts = SessionFacts {
                    unit: unit
                        .map(|u| u.ctx.key)
                        .or_else(|| {
                            effects.admission.as_ref().map(|pending| {
                                busbar_contract::UnitKey::new(pending.context().unit())
                            })
                        })
                        .unwrap_or(busbar_contract::UnitKey::new(0)),
                    pending: effects.admission.clone(),
                };
                upstream.walk(facts, run).await
            }
            None => run.alone().await,
        }
    };
    match ran {
        Ok(ran) => Ok(Served::Ran(ran)),
        Err(SessionError::CoreRefused(code)) => {
            let refusal = refusals.for_core(req.route, code);
            Ok(Served::Refused(Refused {
                items: refuse(port, req, &refusal, effects),
                decision: refusal,
            }))
        }
        Err(SessionError::SelectedRefused(error)) => {
            let refusal = selected_refusal(req.route, &error.0, refusals);
            Ok(Served::Refused(Refused {
                items: refuse(port, req, &refusal, effects),
                decision: refusal,
            }))
        }
        Err(SessionError::HookRefused(refusal) | SessionError::AdmissionRefused(refusal)) => {
            Ok(Served::Refused(Refused {
                items: refuse(port, req, &refusal, effects),
                decision: refusal,
            }))
        }
        Err(SessionError::Port(error)) => {
            let refusal = refusal_of(route, &error, refusals);
            Ok(Served::Refused(Refused {
                items: refuse(port, req, &refusal, effects),
                decision: refusal,
            }))
        }
        Err(error) => {
            charge(port, &error);
            Err(ServeError::Session(error))
        }
    }
}

#[cfg(test)]
#[path = "tests/port_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/port_input_custody.rs"]
mod input_custody_tests;

#[cfg(test)]
#[path = "tests/port_thread_tests.rs"]
mod thread_tests;
