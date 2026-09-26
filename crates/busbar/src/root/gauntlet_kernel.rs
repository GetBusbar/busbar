// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL-LOOP RUNNER behind `busbar_kernel::plane_host::run_gauntlet` — LIVE.
//!
//! [`run_gauntlet_via_kernel`] drives the SAME [`GauntletPlane`] the substrate gauntlet drives, but
//! through `busbar_kernel::teller::run_unit_async` (the ONE unified loop) instead of the substrate
//! Teller loop. It is the loop-unification rider (DECISIONS #28): MCP is the first WITNESS — its
//! existing [`GauntletPlane`] (`busbar_mcp`'s `ToolCallPlane`) rides UNCHANGED, so its governance,
//! per-round metering, breaker, reroute and JSON-RPC envelope stay byte-identical inside `drive`.
//!
//! NEUTRAL BY CONSTRUCTION: this file names NO plane. It reaches every plane through the neutral
//! [`GauntletPlane`] seam and returns the neutral [`PlaneAnswer`] out of the neutral
//! [`PlaneInFlight`] table, keyed by the bare `ctx.key`. a2a/voice/llm ride this IDENTICAL rider
//! with zero new code — only a re-point of their gauntlet call.
//!
//! MONEY-NEUTRAL, AND THE SHIPPED PATH: the rider opens an EMPTY admit hold
//! ([`Admission::ZeroHold`]) and reports ZERO [`Evidence`] at the kernel exit, so the kernel loop
//! settles NOTHING and cannot double-count the plane's own per-round metering (which stays inside
//! `drive`). It binds no money book. `gauntlet_install::install()` registers it at boot under the
//! capability key of every plane in the build (item 125), so every `run_gauntlet[_session]` call for
//! those planes — `tools_call_via_gauntlet` included — dispatches here. The proof it reproduces the
//! deleted substrate gauntlet byte-for-byte is the shadow-compare test below.

use axum::response::Response;

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, ArrivalRecord, Audit, Authenticate,
    Authenticated, Consumption, Decision, Decode, Dial, Encode, Frame, Grant, Meter, OpClassId,
    OriginKind, Outcome, Pass, PrincipalId, ReasonCode, Refusal, Route, Usage, VerifiedDestination,
    Verify,
};
use busbar_contract::{AuditFacts, FinishClass, RoutePlan, ScopeFacts, UnitKey};
use busbar_kernel::plane_host::{
    Admitted, GauntletPlane, GauntletRequest, PlaneAnswer, PlaneInFlight, VerifyOutcome,
};
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::teller::{AccrualMeter, Evidence, RouteAwait, RouteLeg, UnitCtx, Units};

/// The transport stack every gauntlet request arrives over — one HTTP layer, named rather than
/// empty (mirrors the LLM plane's arrival record). The value only reaches the audit/record surface,
/// which this rider posts nothing onto.
const TRANSPORT_CHAIN: [&str; 1] = ["http"];

/// The neutral per-request counter for the rider's `ctx.key`. Each call takes the next value;
/// nothing outside this file reads it, so a process-global monotonic is enough.
static NEXT_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(test)]
thread_local! {
    /// TEST-ONLY: how many plane `drive`s THIS thread has run inside the kernel loop's Route step.
    /// The served-leg witnesses (`tests/gauntlet_kernel.rs`) read it before and after a plane's own
    /// served scenario, so "the capability was exercised on the served path" is a count of drives
    /// this rider actually carried — never inferred from a status code. Per thread because the test
    /// harness runs tests in parallel and a `#[tokio::test]` runs its whole scenario on its own.
    pub(crate) static DRIVES_IN_LOOP: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// TEST-ONLY: how many session opens THIS thread has run through the kernel loop's door — the
    /// session plane's twin of [`DRIVES_IN_LOOP`]: a session rides no `drive`, so what the rider
    /// carries of it is the open, counted where the loop is asked to open it.
    pub(crate) static OPENS_IN_LOOP: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// One gauntlet request expressed as a kernel [`Units`] value: the plane rides at Verify (its
/// `verify_destination`) and Route (its `drive`); every other step proceeds with the neutral facts a
/// pass-through carries, exactly as the substrate `GauntletAdapter` does — only the loop differs.
///
/// The plane sits in a `Mutex<Option<..>>`: `verify` borrows it, `route` takes it (drive consumes its
/// box). The answer the plane produced — a `drive` response or a pre-charge refusal — is stashed into
/// the neutral [`PlaneInFlight`] table under `key`, which the outer handler reads back after the loop.
struct GauntletKernelUnit<'p> {
    plane: std::sync::Mutex<Option<Box<dyn GauntletPlane + 'p>>>,
    gov: &'p busbar_api::PlaneRequestCtx,
    destination: &'p str,
    correlation_id: u64,
    charged_at: u64,
    started: std::time::Instant,
    principal: PrincipalId,
    op_class: OpClassId,
    table: &'p PlaneInFlight,
    key: u64,
}

impl<'p> GauntletKernelUnit<'p> {
    /// Rebuild the neutral per-request facts the plane's `verify_destination`/`drive` read — field
    /// for field, exactly as the substrate `GauntletAdapter` rebuilds them from its unit.
    fn request(&self) -> GauntletRequest<'p> {
        GauntletRequest {
            gov: self.gov,
            destination: self.destination,
            correlation_id: self.correlation_id,
            charged_at: self.charged_at,
            started: self.started,
        }
    }

    /// The response for a plane already consumed — unreachable by construction (Verify runs before
    /// Route and Route at most once), kept so the rider never panics.
    fn plane_spent() -> Response {
        Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::empty())
            .unwrap_or_default()
    }
}

impl Units for GauntletKernelUnit<'_> {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        Decision::proceed(
            token,
            ArrivalRecord {
                source: String::new(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: TRANSPORT_CHAIN.to_vec(),
            },
        )
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        Decision::proceed(token, self.op_class)
    }

    fn authenticate(&self, token: &Pass<Authenticate>, _ctx: &UnitCtx) -> Decision<Authenticate> {
        // Identity is already resolved upstream and threaded via `gov`; this step states it.
        Decision::proceed(token, Authenticated::Principal(self.principal.clone()))
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        _trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> Decision<Verify> {
        // The plane's OWN pre-admission destination check, in its verify-STRICTLY-before-charge
        // position — byte-identical to the substrate gauntlet. A refusal is the plane's own finished
        // response, stashed for the outer handler; the sealed set is empty (the plane's engine owns
        // routing inside `drive`), so no upstream candidate and no flat fee.
        let outcome = {
            let guard = self
                .plane
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.as_deref() {
                Some(plane) => plane.verify_destination(&self.request()),
                None => VerifyOutcome::Refuse(Self::plane_spent()),
            }
        };
        match outcome {
            VerifyOutcome::Proceed => Decision::proceed(token, Vec::<VerifiedDestination>::new()),
            VerifyOutcome::Refuse(resp) => {
                self.table.store(self.key, PlaneAnswer::Live(resp));
                Decision::refuse(token, Refusal::new(ReasonCode::NoDestination))
            }
        }
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        Decision::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        _admit: &Grant<Admittance>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        // THE EMPTY DOOR. The plane's own admission/charge lives inside `drive`, so the kernel door
        // opens nothing — the zero-hold admission — and the exit settles nothing.
        Decision::proceed(token, Admission::ZeroHold)
    }

    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _meter: &AccrualMeter,
        _destinations: &[busbar_contract::caps::VerifiedDestination],
    ) -> Decision<Route> {
        // This rider's Route AWAITS (the plane's `drive`), so the loop reaches it through the
        // `RouteAwait` arm below and this synchronous one is never taken. Answered rather than
        // unwrapped: there is no task here to run the leg on.
        Decision::refuse(token, Refusal::new(ReasonCode::TaskLost))
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[busbar_contract::caps::VerifiedDestination],
    ) -> Decision<Meter> {
        // The plane metered inside `drive`; the kernel meter reports nothing, so the exit settles a
        // zero it cannot mistake for a charge. Empty is a valid report.
        Decision::proceed(
            token,
            Usage::report(usage, Vec::new()).expect("an empty usage report never overflows"),
        )
    }

    fn audit(&self, token: &Pass<Audit>, _ctx: &UnitCtx, _outcome: &Outcome) -> Decision<Audit> {
        Decision::proceed(
            token,
            AuditFacts {
                op_class: self.op_class,
                finish: FinishClass::Complete,
            },
        )
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        // The plane already finished its refusal (stashed at Verify); nothing was charged.
        Decision::proceed(
            token,
            AuditFacts {
                op_class: self.op_class,
                finish: FinishClass::Error,
            },
        )
    }

    fn encode(&self, token: &Pass<Encode>, _ctx: &UnitCtx, _outcome: &Outcome) -> Decision<Encode> {
        // The plane's `drive` already produced the bytes and the transport owns the envelope; there
        // is no frame this rider writes around one.
        Decision::proceed(
            token,
            Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        // ZERO evidence: no located figure, no floor, no upstream candidate, no fee. The settlement
        // table therefore posts zero, and with no book bound the exit moves nothing — the plane's own
        // metering inside `drive` is the sole authority. This is what forbids a double count.
        Evidence::default()
    }
}

impl RouteAwait for GauntletKernelUnit<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _meter: &'a AccrualMeter,
        _destinations: &'a [busbar_contract::caps::VerifiedDestination],
    ) -> RouteLeg<'a> {
        Box::pin(async move {
            let plane = self
                .plane
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let resp = match plane {
                Some(plane) => {
                    #[cfg(test)]
                    DRIVES_IN_LOOP.with(|n| n.set(n.get() + 1));
                    plane.drive(self.request()).await
                }
                None => Self::plane_spent(),
            };
            // The plane's response is the answer, verbatim — stashed as a live body the outer handler
            // serves. Byte identity is a property of this construction: the loop wraps nothing.
            self.table.store(self.key, PlaneAnswer::Live(resp));
            Decision::proceed(token, RoutePlan::default())
        })
    }

    /// The end of a unit whose caller went away, handed here by the loop's guard (item 99).
    ///
    /// Treated exactly as this rider treats a RETURNED end, which it drops: the rider opens a zero
    /// hold, reports zero evidence and binds no money book (see the module note), so the end carries
    /// no posting any book is owed, and the plane's own per-round metering inside `drive` remains the
    /// sole authority. A rider that binds a book posts this end where it posts its returned one.
    fn abandoned(&self, _ctx: &UnitCtx, _ended: busbar_kernel::teller::Ended) {}
}

/// Derive the caller's principal from the resolved gov, exactly as the sibling planes do: the
/// virtual key's id when governed, the anonymous actor otherwise. Only the (posted-nothing) record
/// reads it, so the exact string does not touch the response bytes.
fn principal_of(gov: &busbar_api::PlaneRequestCtx) -> PrincipalId {
    match gov.key() {
        Some(key) => PrincipalId::new(key.id.as_str()),
        None => PrincipalId::new("anonymous"),
    }
}

/// Run one gauntlet request through the UNIFIED kernel loop and return the plane's response verbatim.
///
/// The kernel-loop twin of [`busbar_kernel::plane_host::run_gauntlet`]: same plane, same
/// verify-before-charge order, same bytes out — driven through `busbar_kernel::teller::run_unit_async`
/// over an ephemeral per-request kernel harness (uncapped in-flight table, node-wide gauge, canary).
/// The loop's `Ended` is discarded: this rider binds no book and settles nothing (see the module
/// header). The shipped path for every plane `gauntlet_install::install()` flips.
pub async fn run_gauntlet_via_kernel(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Response {
    let kernel = crate::root::kernel::new_kernel();
    let gauge = busbar_kernel::slice::ConcurrencyGauge::new();
    let canary = busbar_contract::caps::Canary::new();
    let inflight = busbar_kernel::inflight::InFlight::new(usize::MAX);
    let meter = AccrualMeter::new();
    let table = PlaneInFlight::new();

    let raw_key = NEXT_KEY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let key = UnitKey::new(raw_key);
    let principal = principal_of(req.gov);

    let unit = GauntletKernelUnit {
        plane: std::sync::Mutex::new(Some(plane)),
        gov: req.gov,
        destination: req.destination,
        correlation_id: req.correlation_id,
        charged_at: req.charged_at,
        started: req.started,
        principal: principal.clone(),
        // A neutral static class: this rider posts no record, so the class only labels the
        // (unposted) audit fact and never touches the response bytes. A `'static` literal because
        // `OpClassId` interns a `&'static str`.
        op_class: OpClassId::new("gauntlet"),
        table: &table,
        key: raw_key,
    };
    table.open(raw_key);

    let arrival = busbar_kernel::inflight::arrival_hold(
        &kernel,
        &crate::root::kernel::AdmissionDoor,
        principal,
    );
    let entered = inflight.insert(busbar_kernel::inflight::Enter {
        key,
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        zero_hold_tick: false,
        arrival,
        now: busbar_substrate_values::store::now_ms(),
    });

    match entered {
        Err(_refused) => GauntletKernelUnit::plane_spent(),
        Ok(slot) => {
            let _ended = busbar_kernel::teller::run_unit_async(
                &kernel,
                &unit,
                &UnitCtx {
                    key,
                    origin: OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: false,
                    kernel_verb_only: false,
                },
                busbar_kernel::teller::Run {
                    cell: slot.cell(),
                    parent: None,
                    leases: slot.leases(),
                    gauge: &gauge,
                    canary: &canary,
                    meter: &meter,
                },
                &unit,
            )
            .await;
            // The answer the rider stashed — the plane's own response, verbatim. Unreachable fallback
            // (every unit passes an audit door), answered rather than unwrapped.
            table
                .take(raw_key)
                .map(PlaneAnswer::into_response)
                .unwrap_or_else(GauntletKernelUnit::plane_spent)
        }
    }
}

/// OPEN A SESSION through the UNIFIED kernel loop and return at the door — the kernel-loop twin of
/// `busbar_kernel::plane_host::run_gauntlet_session` (its `admit_open` seat).
///
/// Runs the SAME plane's `verify_destination` in its verify-STRICTLY-before-charge position through
/// `busbar_kernel::teller::open_unit` (governance-to-door, no Route, no settling exit), over an
/// ephemeral per-request kernel harness. On a pass the door admitted at `Admission::ZeroHold` — an
/// EMPTY hold, nothing settled — and the caller opens its own carrier next (its reserve-on-admit and
/// per-turn settle stay plane-side, AFTER this gate, so there is no overlap and no double count). On
/// a refusal the plane's OWN finished response comes back verbatim. Same shape and same admit
/// decision as the substrate session opener; the shipped session admit for every session plane
/// `gauntlet_install::install()` flips.
///
/// Synchronous: a session's steps up to and including the door are all sync (only Route awaits, and a
/// session has none here), exactly like the substrate `run_gauntlet_session`.
///
/// (`result_large_err`: the `Err` is the plane's OWN finished refusal `Response`, carried BY VALUE so
/// refusal shaping stays byte-identical — the same type and the same reason the substrate
/// `run_gauntlet_session`/`admit_open` carry it un-boxed.)
#[allow(clippy::result_large_err)]
pub fn open_gauntlet_via_kernel(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Result<Admitted, Response> {
    let kernel = crate::root::kernel::new_kernel();
    let gauge = busbar_kernel::slice::ConcurrencyGauge::new();
    let canary = busbar_contract::caps::Canary::new();
    let inflight = busbar_kernel::inflight::InFlight::new(usize::MAX);
    let meter = AccrualMeter::new();
    let table = PlaneInFlight::new();

    let raw_key = NEXT_KEY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let key = UnitKey::new(raw_key);
    let principal = principal_of(req.gov);
    let correlation_id = req.correlation_id;

    let unit = GauntletKernelUnit {
        plane: std::sync::Mutex::new(Some(plane)),
        gov: req.gov,
        destination: req.destination,
        correlation_id,
        charged_at: req.charged_at,
        started: req.started,
        principal: principal.clone(),
        op_class: OpClassId::new("gauntlet"),
        table: &table,
        key: raw_key,
    };
    table.open(raw_key);

    let arrival = busbar_kernel::inflight::arrival_hold(
        &kernel,
        &crate::root::kernel::AdmissionDoor,
        principal,
    );
    let entered = inflight.insert(busbar_kernel::inflight::Enter {
        key,
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        zero_hold_tick: false,
        arrival,
        now: busbar_substrate_values::store::now_ms(),
    });

    match entered {
        Err(_refused) => Err(GauntletKernelUnit::plane_spent()),
        Ok(slot) => {
            #[cfg(test)]
            OPENS_IN_LOOP.with(|n| n.set(n.get() + 1));
            let opened = busbar_kernel::teller::open_unit(
                &kernel,
                &unit,
                &UnitCtx {
                    key,
                    origin: OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: false,
                    kernel_verb_only: false,
                },
                busbar_kernel::teller::Run {
                    cell: slot.cell(),
                    parent: None,
                    leases: slot.leases(),
                    gauge: &gauge,
                    canary: &canary,
                    meter: &meter,
                },
            );
            match opened {
                // The door passed at ZeroHold — the caller opens its own carrier next. The
                // correlation is the request's own, exactly as the substrate opener returns it.
                busbar_kernel::teller::SessionOpen::Admitted => Ok(Admitted { correlation_id }),
                // The plane refused at its verify step; its own finished response was stashed.
                busbar_kernel::teller::SessionOpen::Refused => Err(table
                    .take(raw_key)
                    .map(PlaneAnswer::into_response)
                    .unwrap_or_else(GauntletKernelUnit::plane_spent)),
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/gauntlet_kernel.rs"]
mod tests;
