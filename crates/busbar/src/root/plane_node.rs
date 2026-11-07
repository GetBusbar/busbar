// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use axum::http::StatusCode;
use axum::response::Response;

use busbar_contract::caps::{
    Audit, Grant, OpClassId, OriginKind, Outcome, Pass, PrincipalId, Route, VerifiedDestination,
};
use busbar_contract::{LaneId, UnitKey};
use busbar_kernel::plane_driver::PlaneAnswer;
use busbar_kernel::teller::{
    AccrualMeter, Ended, Evidence, RouteAwait, RouteLeg, Screen, UnitCtx, Units,
};
use busbar_kernel::Registration;
use busbar_kernel_audit::{
    AuditInputs, Controls, FinishClass as RecordFinish, HookApplied, OpClassId as RecordOpClass,
    OutcomeFacts, Subject, Usage as RecordUsage, UsageLine as RecordLine, What,
};

use crate::root::linked::node::{Handed, Late, Reported, Resolve};

struct LaneNames {
    interner: Arc<Mutex<Registration>>,
    resolved: HashMap<String, LaneId>,
    consulted: u64,
}

/// WHEN ONE UNIT ARRIVED — one reading of the wall clock, spelled in both the units this loop asks
/// for.
///
/// The loop needs the arrival instant twice and in two shapes: SECONDS, which is the window every
/// charge and every refund this unit makes lands in, and MILLISECONDS, which is the stamp the
/// in-flight table enters it under. Read the clock twice and those are two arrivals, not one in two
/// shapes — a request that arrives at the very end of a window can have its seconds fall in that
/// window and its milliseconds in the next, and the books then bill it in a window the table says it
/// did not arrive in. Nothing downstream can tell which of the two readings was the truth, because
/// both of them were.
///
/// So the clock is read ONCE, here, and every figure is spelled out of that one reading. Being a
/// value rather than a call is also what lets a test name the instant a unit arrived at, which is
/// the only way to drive the case that matters — the last millisecond of a window.
/// It carries the node's MONOTONIC reading beside the wall one, because the audit record and the
/// posting stamp each want both and they want different things from them. A wall clock is
/// steppable — an operator sets it, NTP corrects it, a leap second repeats it — so it DATES a record
/// and cannot order one. The monotonic reading only ever goes up, so it ORDERS the record and
/// cannot date it. Stamped from the wall clock twice, the second field is a copy rather than a
/// reading, and two units of one second become unorderable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrived {
    /// Milliseconds since the epoch: the reading, at the finest resolution either caller needs.
    ms: u64,
    /// The node's monotonic reading at the same arrival.
    mono: u64,
}

impl Arrived {
    #[must_use]
    pub fn at(ms: u64, mono: u64) -> Self {
        Self { ms, mono }
    }

    #[must_use]
    pub fn secs(self) -> u64 {
        self.ms / 1_000
    }

    #[must_use]
    pub fn ms(self) -> u64 {
        self.ms
    }

    #[must_use]
    pub fn mono(self) -> u64 {
        self.mono
    }
}

impl LaneNames {
    fn resolve(&mut self, name: &str) -> Option<LaneId> {
        if let Some(lane) = self.resolved.get(name) {
            return Some(*lane);
        }
        self.consulted += 1;
        let lane = self
            .interner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lane(name)?;
        self.resolved.insert(name.to_owned(), lane);
        Some(lane)
    }

    fn consulted(&self) -> u64 {
        self.consulted
    }
}

pub struct Node {
    kernel: Arc<busbar_kernel::teller::Kernel>,
    inflight: busbar_kernel::inflight::InFlight,
    gauge: busbar_kernel::slice::ConcurrencyGauge,
    canary: busbar_kernel::canary::Canary,
    door: crate::root::kernel::AdmissionDoor,

    lanes: Arc<Mutex<Registration>>,

    lane_names: Arc<Mutex<LaneNames>>,
    next_key: Arc<busbar_kernel::door::UnitKeyMint>,

    marked: AtomicU64,

    lost: Mutex<HashMap<UnitKey, Lost>>,

    mono: AtomicU64,

    book: std::sync::OnceLock<Arc<Mutex<crate::root::durability::Durability>>>,

    lane: std::sync::OnceLock<Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>>,

    durability_token: busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,

    usage_token: busbar_contract::caps::Grant<busbar_contract::caps::Consumption>,

    dispatch: Arc<dyn crate::root::transports::PlaneDispatch>,

    pub(crate) ticket_custody: Arc<crate::root::serve::TicketCustody>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node").finish_non_exhaustive()
    }
}

impl Default for Node {
    fn default() -> Self {
        Self::new()
    }
}

impl Node {
    #[must_use]
    pub fn new() -> Self {
        let lanes = Arc::new(Mutex::new(crate::root::kernel::new_registration()));
        let kernel = crate::root::kernel::new_kernel();
        Self {
            durability_token: kernel.durability_token(),
            usage_token: kernel.usage_token(),
            book: std::sync::OnceLock::new(),
            lane: std::sync::OnceLock::new(),
            kernel: Arc::new(kernel),

            inflight: busbar_kernel::inflight::InFlight::new(usize::MAX),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_kernel::canary::Canary::new(),
            door: crate::root::kernel::AdmissionDoor,
            lanes: Arc::clone(&lanes),
            lane_names: Arc::new(Mutex::new(LaneNames {
                interner: lanes,
                resolved: HashMap::new(),
                consulted: 0,
            })),
            next_key: Arc::default(),
            marked: AtomicU64::new(0),
            lost: Mutex::new(HashMap::new()),
            mono: AtomicU64::new(0),

            dispatch: Arc::new(crate::root::transports::DrivenOnce::new()),
            ticket_custody: crate::root::serve::TicketCustody::new(),
        }
    }

    /// A composed fixture must share the real inbound host's unit identity allocator while
    /// retaining its own journal and accounting state for independent assertions.
    #[cfg(test)]
    pub(crate) fn with_inbound_keys() -> Self {
        Self {
            next_key: node().kernel_and_keys().1,
            ..Self::new()
        }
    }

    #[must_use]
    pub fn kernel_and_keys(
        &self,
    ) -> (
        Arc<busbar_kernel::teller::Kernel>,
        Arc<busbar_kernel::door::UnitKeyMint>,
    ) {
        (Arc::clone(&self.kernel), Arc::clone(&self.next_key))
    }

    #[must_use]
    pub fn driven(&self) -> Option<u64> {
        self.dispatch.driven()
    }

    pub fn arrived(&self) -> Arrived {
        Arrived::at(
            busbar_kernel::store::now_ms(),
            self.mono.fetch_add(1, Ordering::AcqRel),
        )
    }

    #[must_use]
    pub fn lanes(&self) -> Arc<Mutex<Registration>> {
        Arc::clone(&self.lanes)
    }

    pub fn resolver(&self) -> Resolve {
        let names = Arc::clone(&self.lane_names);
        Arc::new(move |name: &str| {
            names
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .resolve(name)
        })
    }

    pub fn bind_book(&self, book: Arc<Mutex<crate::root::durability::Durability>>) {
        let journal = book
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .journal
            .clone();
        let _ = self.lane.set(journal);
        let _ = self.book.set(book);
    }
    pub fn journal_lane(
        &self,
    ) -> Option<Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>> {
        self.lane.get().cloned()
    }
    pub(crate) async fn retry_held_journal(&self) -> Result<(), String> {
        if let Some(journal) = self.lane.get() {
            journal
                .flush()
                .await
                .map_err(|error| format!("native journal: {error:?}"))?;
        }
        Ok(())
    }
    #[must_use]
    pub fn journal_refusal(&self) -> Option<String> {
        self.lane.get().and_then(|journal| journal.refuses_money())
    }

    fn seal_end(
        &self,
        principal: &PrincipalId,
        arrived: Arrived,
        card: Option<&crate::root::kernel::PinnedHistory>,
        ended: busbar_kernel::teller::Ended,
        seal: Option<impl Into<Sealing>>,
        lines: Vec<RecordLine>,
    ) {
        drop(self.seal_end_task(principal, arrived, card, ended, seal, lines));
    }

    fn seal_end_task(
        &self,
        principal: &PrincipalId,
        arrived: Arrived,
        card: Option<&crate::root::kernel::PinnedHistory>,
        ended: busbar_kernel::teller::Ended,
        seal: Option<impl Into<Sealing>>,
        lines: Vec<RecordLine>,
    ) -> Option<TerminalConfirmation> {
        let seal = seal.map(Into::<Sealing>::into)?;
        let key = seal.seal.key;
        let completed =
            matches!(&ended, Ended::Settled { end, .. } if end.outcome().is_completed());
        let receipt = self.seal_end_ack(principal, arrived, card, ended, seal, lines);
        match receipt {
            Some(receipt) => receipt.confirm_terminal(self.ticket_custody.clone(), key, completed),
            None => {
                self.ticket_custody.terminal(key, false);
                None
            }
        }
    }

    fn seal_end_ack(
        &self,
        principal: &PrincipalId,
        arrived: Arrived,
        card: Option<&crate::root::kernel::PinnedHistory>,
        ended: busbar_kernel::teller::Ended,
        seal: Sealing,
        lines: Vec<RecordLine>,
    ) -> Option<StagedAudit> {
        let book = self.book.get()?;
        let busbar_kernel::teller::Ended::Settled { end, .. } = ended else {
            return None;
        };
        let outcome = end.outcome();
        end.into_posted().ok()?;
        seal.seal(
            book,
            &self.durability_token,
            principal,
            arrived,
            card,
            outcome,
            lines,
            0,
            None,
        )
        .ok()
    }

    pub fn sweep(&self, now: Arrived) -> usize {
        if self.marked.swap(0, Ordering::AcqRel) == 0 {
            return 0;
        }
        let mut swept = 0;
        for slot in self.inflight.snapshot() {
            if !slot.is_marked() {
                continue;
            }

            let Some(lost) = self
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&slot.key())
            else {
                continue;
            };
            let verdict = busbar_kernel::tick::sweep(
                &slot,
                busbar_contract::caps::StepName::Route,
                now.ms(),
                busbar_kernel::Millis::MAX,
                false,
            );

            let settled = busbar_kernel::tick::sweep_settle(
                &self.kernel,
                &slot,
                verdict,
                &Evidence::default(),
                &self.canary,
                &self.gauge,
            );
            if let Some(busbar_kernel::tick::Swept { end, line, audit }) = settled {
                if let Ok(posted) = end.posted() {
                    let principal = posted.principal().clone();

                    let entered = lost.arrived;

                    let lines: Vec<RecordLine> = Registration::meter_class(line.class.as_str())
                        .filter(|class| *class != busbar_kernel::teller::KERNEL_ACCRUAL_CLASS)
                        .map(|class| RecordLine { class, ..line })
                        .into_iter()
                        .collect();
                    let (history, op_class, ran) = match lost.open {
                        Some(open) => (
                            Some(open.history),
                            open.sealing
                                .door
                                .map_or(lost.op_class, |(facts, _)| facts.op_class),
                            open.sealing.ran,
                        ),
                        None => (None, lost.op_class, Ran::default()),
                    };
                    let seal = Some(Sealing {
                        seal: UnitSeal {
                            facts: busbar_contract::caps::AuditFacts {
                                op_class,
                                finish: busbar_contract::FinishClass::Error,
                            },
                            pass: audit,
                            key: slot.key(),
                            origin: self.kernel.origin(slot.origin()),
                            parent: match slot.origin() {
                                OriginKind::Nested { parent } => Some(parent),
                                _ => None,
                            },
                        },
                        ran,
                    });
                    let card = history.unwrap_or_else(|| crate::root::kernel::ROOT_CARD.pin());
                    self.seal_end(
                        &principal,
                        entered,
                        card.as_ref(),
                        busbar_kernel::teller::Ended::Settled {
                            end,

                            requests: 0,
                            fee: 0,
                        },
                        seal,
                        lines,
                    );
                }
            }
            self.inflight.remove(slot.key());
            swept += 1;
        }
        swept
    }

    #[must_use]
    pub fn parent(&self, key: UnitKey) -> Option<Parent> {
        self.inflight.get(key).map(|slot| Parent { key, slot })
    }

    /// Seal a first-auth unit that never entered the teller. This uses the same signed
    /// journal and bounded Store lane as an ordinary end, without an arrival hold or ledger.
    pub(crate) fn refused_inbound(&self, refused: &busbar_kernel::inbound::RefusedUnit) {
        if let Some(unit) = refused.unit {
            let anonymous = busbar_kernel::auth::AuthPrincipal(None);
            self.unmetered_inbound(
                UnitKey::new(unit),
                refused.audit_kind,
                &PrincipalId::new(
                    refused
                        .principal
                        .as_deref()
                        .unwrap_or_else(|| anonymous.actor_id()),
                ),
                Outcome::Refused(refused.step, refused.reason),
            );
        }
    }

    pub(crate) fn unmetered_inbound(
        &self,
        key: UnitKey,
        audit_kind: OpClassId,
        principal: &PrincipalId,
        outcome: Outcome,
    ) {
        let Some(book) = self.book.get() else {
            return;
        };
        let seal = Sealing::from(UnitSeal {
            facts: busbar_contract::caps::AuditFacts {
                op_class: audit_kind,
                finish: if outcome.is_completed() {
                    busbar_contract::FinishClass::Complete
                } else {
                    busbar_contract::FinishClass::Error
                },
            },
            pass: busbar_kernel::teller::verb_audit_pass(&self.kernel),
            key,
            origin: self.kernel.origin(OriginKind::Client),
            parent: None,
        });
        let _ = seal.seal(
            book,
            &self.durability_token,
            principal,
            self.arrived(),
            None,
            outcome,
            Vec::new(),
            0,
            None,
        );
    }

    #[must_use]
    pub fn mint(&self) -> UnitKey {
        self.next_key.mint()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn drive_borrowed<U: Units + RouteAwait>(
        &self,
        key: UnitKey,
        arrived: Arrived,
        principal: &PrincipalId,
        post: &NodeEndPost,
        units: &U,
        late: Late,
        history: Option<crate::root::kernel::PinnedHistory>,
        parent: Option<&Parent>,
        audit_kind: OpClassId,
        admission: Option<&busbar_kernel::inbound::RequestAdmission>,
    ) -> Option<Outcome> {
        self.sweep(arrived);
        if self.journal_refusal().is_some() {
            if let Some(admission) = admission {
                admission.refuse(
                    busbar_contract::caps::StepName::Arrival,
                    busbar_contract::caps::ReasonCode::DurabilityUnavailable,
                );
            }
            return None;
        }
        if admission.is_some_and(|admission| !admission.begin_execution()) {
            return None;
        }
        post.open(key, principal.clone(), arrived, history.clone());
        post.checkpoint_identity(
            key,
            audit_kind,
            parent.map_or(OriginKind::Client, |p| OriginKind::Nested { parent: p.key }),
        );
        let meter = Arc::new(AccrualMeter::new());
        let origin = parent.map_or(OriginKind::Client, |p| OriginKind::Nested { parent: p.key });
        let call = self.kernel.next_call();
        let hold = busbar_kernel::inflight::arrival_hold(
            &self.kernel,
            &self.door,
            principal.clone(),
            call,
        );
        let Ok(slot) = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: arrived.ms(),
        }) else {
            post.close(key);
            if let Some(admission) = admission {
                admission.execution_unavailable();
            }
            return None;
        };
        let mut occupied = Occupied {
            node: self,
            post: Some(post),
            slot: Arc::clone(&slot),
            arrived,
            op_class: audit_kind,
            reached_end: false,
        };
        let ctx = UnitCtx {
            call,
            key,
            origin,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        self.ticket_custody.bind_source(&ctx, &slot);
        let ended = busbar_kernel::teller::run_unit_async(
            &self.kernel,
            units,
            &ctx,
            busbar_kernel::teller::Run {
                cell: slot.cell(),
                parent: parent.map(|p| p.slot.cell()),
                leases: slot.leases(),
                gauge: &self.gauge,
                canary: &self.canary,
                meter: &meter,
                taps: Some(post),
            },
            units,
        )
        .await;

        let outcome = match &ended {
            Ended::Settled { end, .. } => Some(end.outcome()),
            Ended::AlreadySettled => None,
        };

        let seal = post.take(key).and_then(|open| {
            open.sealing
                .into_seal(key, self.kernel.origin(origin), parent.map(|p| p.key))
        });
        match self.late_arm(Some(late), principal, arrived, history.as_ref()) {
            Some(mut arm) => {
                arm.seal = seal;
                drop(arm.carrying(ended).post());
            }
            None => self.seal_end(
                principal,
                arrived,
                history.as_ref(),
                ended,
                seal,
                Vec::new(),
            ),
        }
        occupied.reached_end = true;
        if let Err(error) = self.retry_held_journal().await {
            tracing::error!(reason = error, "unit audit remains unconfirmed");
            return None;
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_borrowed<'n, U: Units + RouteAwait>(
        &'n self,
        key: UnitKey,
        arrived: Arrived,
        principal: &PrincipalId,
        post: &'n NodeEndPost,
        units: &U,
        history: Option<crate::root::kernel::PinnedHistory>,
        audit_kind: OpClassId,
        admission: Option<&busbar_kernel::inbound::RequestAdmission>,
    ) -> Option<(busbar_kernel::teller::SessionOpen, UnitCtx, SessionSlot<'n>)> {
        self.sweep(arrived);
        if self.journal_refusal().is_some() {
            if let Some(admission) = admission {
                admission.refuse(
                    busbar_contract::caps::StepName::Arrival,
                    busbar_contract::caps::ReasonCode::DurabilityUnavailable,
                );
            }
            return None;
        }
        if admission.is_some_and(|admission| !admission.begin_execution()) {
            return None;
        }
        post.open(key, principal.clone(), arrived, history);
        post.checkpoint_identity(key, audit_kind, OriginKind::Client);
        let meter = Arc::new(AccrualMeter::new());
        let call = self.kernel.next_call();
        let hold = busbar_kernel::inflight::arrival_hold(
            &self.kernel,
            &self.door,
            principal.clone(),
            call,
        );
        let Ok(slot) = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: arrived.ms(),
        }) else {
            post.close(key);
            if let Some(admission) = admission {
                admission.execution_unavailable();
            }
            return None;
        };
        let mut occupied = Occupied {
            node: self,
            post: Some(post),
            slot: Arc::clone(&slot),
            arrived,
            op_class: audit_kind,
            reached_end: false,
        };
        let ctx = UnitCtx {
            call,
            key,
            origin: OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        self.ticket_custody.bind_source(&ctx, &slot);
        let opened = busbar_kernel::teller::open_unit_screened(
            &self.kernel,
            units,
            &ctx,
            busbar_kernel::teller::Run {
                cell: slot.cell(),
                parent: None,
                leases: slot.leases(),
                gauge: &self.gauge,
                canary: &self.canary,
                meter: &meter,
                taps: Some(post),
            },
            units,
        )
        .await;

        let (opened, own) = match opened {
            busbar_kernel::teller::SessionOpen::Admitted {
                route,
                destinations,
                own,
            } => {
                post.routed(key, &destinations);
                (
                    busbar_kernel::teller::SessionOpen::Admitted {
                        route,
                        destinations,
                        own: None,
                    },
                    own,
                )
            }
            busbar_kernel::teller::SessionOpen::Settled(ended) => {
                if let Some(open) = post.take(key) {
                    self.seal_session(key, open, Some(ended));
                }
                (busbar_kernel::teller::SessionOpen::Refused, None)
            }
            busbar_kernel::teller::SessionOpen::Refused => {
                (busbar_kernel::teller::SessionOpen::Refused, None)
            }
        };
        if let Some(op_class) = post.door_class(key) {
            occupied.op_class = op_class;
        }
        let session = SessionSlot {
            occupied,
            key,
            ctx: ctx.clone(),
            meter,
            own,
            money: None,
        };
        Some((opened, ctx, session))
    }

    fn seal_session(&self, key: UnitKey, open: OpenUnit, ended: Option<Ended>) {
        drop(self.seal_session_task(key, open, ended));
    }

    fn seal_session_task(
        &self,
        key: UnitKey,
        mut open: OpenUnit,
        ended: Option<Ended>,
    ) -> Option<TerminalConfirmation> {
        if let Some(ended) = ended {
            let Ended::Settled { end, .. } = ended else {
                self.ticket_custody.terminal(key, false);
                return None;
            };
            open.sealing.said = Some(end.outcome());
            if end.into_posted().is_err() {
                self.ticket_custody.terminal(key, false);
                return None;
            }
        }
        let book = self.book.get()?;
        let OpenUnit {
            principal,
            arrived,
            history,
            mut sealing,
            ..
        } = open;
        let (said, report) = (sealing.said.take(), sealing.report.take());
        let outcome = said?;
        let seal = sealing.into_seal(key, self.kernel.origin(OriginKind::Client), None)?;
        let (lines, fee_count) = report
            .as_ref()
            .map_or((Vec::new(), 0), |r| (report_lines(r), r.fee_count));
        let acknowledged = seal.seal(
            book,
            &self.durability_token,
            &principal,
            arrived,
            history.as_ref(),
            outcome,
            lines,
            fee_count,
            report.as_ref().map(|r| r.lane.as_str()),
        );
        match acknowledged {
            Ok(receipt) => {
                receipt.confirm_terminal(self.ticket_custody.clone(), key, outcome.is_completed())
            }
            Err(_) => {
                self.ticket_custody.terminal(key, false);
                None
            }
        }
    }

    #[must_use]
    pub async fn answer(&self, handed: Handed) -> Response {
        self.answer_arriving_at(handed, self.arrived()).await
    }

    #[must_use]
    pub async fn answer_arriving_at(&self, handed: Handed, arrived: Arrived) -> Response {
        self.answer_pinned(handed, arrived, || crate::root::kernel::ROOT_CARD.pin())
            .await
    }

    async fn answer_pinned(
        &self,
        handed: Handed,
        arrived: Arrived,
        pin: impl FnOnce() -> Option<crate::root::kernel::PinnedHistory>,
    ) -> Response {
        self.sweep(arrived);

        let (principal, op_class, proto, build) = handed;

        if let Some(why) = self.journal_refusal() {
            return journal_unavailable(proto, &why);
        }
        let key = self.next_key.mint();

        let meter = Arc::new(AccrualMeter::new());

        let history = pin();

        let (units, route, finish) = build((self.resolver(), arrived.secs()));

        let call = self.kernel.next_call();
        let hold = busbar_kernel::inflight::arrival_hold(
            &self.kernel,
            &self.door,
            principal.clone(),
            call,
        );
        let entered = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,

            now: arrived.ms(),
        });

        match entered {
            Err(_refused) => unavailable(proto),
            Ok(slot) => {
                let mut occupied = Occupied {
                    node: self,
                    post: None,
                    slot: Arc::clone(&slot),
                    arrived,
                    op_class,
                    reached_end: false,
                };
                let ctx = UnitCtx {
                    call,
                    key,
                    origin: OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: false,
                    kernel_verb_only: false,
                };
                let driven = Driven {
                    node: self,
                    route: &*route,
                    op_class,
                    principal: &principal,
                    arrived,
                    history: history.as_ref(),
                    sealing: Mutex::new(Some(Accruing::default())),
                };
                let ended = busbar_kernel::teller::run_unit_async(
                    &self.kernel,
                    &*units,
                    &ctx,
                    busbar_kernel::teller::Run {
                        cell: slot.cell(),
                        parent: None,
                        leases: slot.leases(),
                        gauge: &self.gauge,
                        canary: &self.canary,
                        meter: &meter,
                        taps: Some(&driven),
                    },
                    &driven,
                )
                .await;

                let (answer, late) = finish();
                let response =
                    answer.map_or_else(|| unavailable(proto), PlaneAnswer::into_response);
                let seal = driven.take_seal(key);
                let response = self
                    .tail(
                        ended,
                        response,
                        late,
                        &principal,
                        arrived,
                        history.as_ref(),
                        seal,
                    )
                    .await;

                occupied.reached_end = true;
                response
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn tail(
        &self,
        ended: Ended,
        response: Response,
        late: Option<Late>,
        principal: &PrincipalId,
        arrived: Arrived,
        history: Option<&crate::root::kernel::PinnedHistory>,
        seal: Option<Sealing>,
    ) -> Response {
        match self.late_arm(late, principal, arrived, history) {
            Some(mut arm) => {
                arm.seal = seal;

                let arm = arm.carrying(ended);
                let (parts, body) = response.into_parts();
                Response::from_parts(parts, axum::body::Body::new(LateBody::new(body, arm)))
            }
            None => {
                let confirmation =
                    self.seal_end_task(principal, arrived, history, ended, seal, Vec::new());
                if let Err(error) = await_terminal(confirmation).await {
                    return journal_unavailable("", &error);
                }
                match self.retry_held_journal().await {
                    Ok(()) => response,
                    Err(error) => journal_unavailable("", &error),
                }
            }
        }
    }

    fn late_arm(
        &self,
        late: Option<Late>,
        principal: &PrincipalId,
        arrived: Arrived,
        history: Option<&crate::root::kernel::PinnedHistory>,
    ) -> Option<LateAccrual> {
        let book = self.book.get()?;
        let history = history?.clone();
        let late = late?;
        Some(LateAccrual {
            book: Arc::clone(book),
            custody: Arc::clone(&self.ticket_custody),
            history,

            durability_token: self.kernel.durability_token(),
            principal: principal.clone(),

            arrived,
            late,
            posted: false,
            outcome: None,
            seal: None,
        })
    }
}

/// WHAT A UNIT CONSUMED, read after its body drained — the plane's report, in the node's hands.
///
/// A REPORT, not an amount, and the distinction is the whole shape of the seam. The plane says what a
/// unit did — the quantities it consumed, by class, and how many billable requests it is — and names
/// the serving lane the row is keyed by. What any of that is WORTH is the card's answer, and the card
/// is this node's; the fee lands as a line of that pricing rather than as a number the plane invented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Every class the tap reported, by neutral unit class — the reserved token split and every open
    /// class beside it (a rerank's search units): the same counts the governance ledger accrued when
    /// the cell filled. Empty for a response that billed nothing.
    pub usage: busbar_contract::billing::ExactUsage,
    /// How many billable requests this unit is: one for a delivered client request that reached an
    /// upstream, zero otherwise — the Meter step's own count, carried rather than re-decided.
    pub fee_count: u32,
    /// The SERVING lane's config name — the lane that actually answered, after any failover, which
    /// is the key a rate card is written against and the key the legacy row carries.
    pub lane: String,
}

impl Report {
    fn of((usage, fee_count, lane): Reported) -> Self {
        Report {
            usage,
            fee_count,
            lane,
        }
    }
}

struct LateAccrual {
    custody: Arc<crate::root::serve::TicketCustody>,
    book: Arc<Mutex<crate::root::durability::Durability>>,

    history: crate::root::kernel::PinnedHistory,
    durability_token: busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
    principal: PrincipalId,
    arrived: Arrived,

    late: Late,

    posted: bool,

    outcome: Option<Outcome>,

    seal: Option<Sealing>,
}

impl LateAccrual {
    fn carrying(mut self, ended: Ended) -> Self {
        if let Ended::Settled { end, .. } = ended {
            self.outcome = Some(end.outcome());
            self.posted = end.into_posted().is_ok();
        }
        self
    }

    fn post(self) -> Option<TerminalConfirmation> {
        let LateAccrual {
            custody,
            book,
            history,
            durability_token,
            principal,
            arrived,
            late,
            posted,
            outcome,
            seal,
        } = self;

        let completed = outcome.is_some_and(Outcome::is_completed);
        let report = late().map(Report::of).filter(|report| {
            completed
                || report.fee_count > 0
                || report.usage.usage_units.values().any(|n| !n.is_zero())
        });
        let (Some(seal), Some(outcome)) = (seal, outcome) else {
            return None;
        };
        let key = seal.seal.key;
        let acknowledged = match report {
            Some(report) => seal.seal(
                &book,
                &durability_token,
                &principal,
                arrived,
                Some(&history),
                outcome,
                report_lines(&report),
                report.fee_count,
                Some(report.lane.as_str()),
            ),

            None if posted => seal.seal(
                &book,
                &durability_token,
                &principal,
                arrived,
                Some(&history),
                outcome,
                Vec::new(),
                0,
                None,
            ),
            None => {
                custody.terminal(key, false);
                return None;
            }
        };
        match acknowledged {
            Ok(receipt) => receipt.confirm_terminal(custody, key, posted && completed),
            Err(_) => {
                custody.terminal(key, false);
                None
            }
        }
    }
}

type JournalConfirmation =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;

struct LateBody {
    inner: Option<axum::body::Body>,

    arm: Option<LateAccrual>,
    confirmation: Option<JournalConfirmation>,
    journal: Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
}

impl LateBody {
    fn new(inner: axum::body::Body, arm: LateAccrual) -> Self {
        let journal = arm
            .book
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .journal
            .clone();
        LateBody {
            inner: Some(inner),
            arm: Some(arm),
            confirmation: None,
            journal,
        }
    }

    fn fire(&mut self) -> Option<TerminalConfirmation> {
        self.arm.take().and_then(LateAccrual::post)
    }
}

impl http_body::Body for LateBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = match this.inner.as_mut() {
            Some(inner) => std::pin::Pin::new(inner).poll_frame(cx),
            None if this.confirmation.is_some() => std::task::Poll::Pending,
            None => return std::task::Poll::Ready(None),
        };

        if matches!(polled, std::task::Poll::Ready(None)) {
            let terminal = this.fire();
            this.inner = None;
            let journal = this.journal.clone();
            this.confirmation = Some(Box::pin(async move {
                await_terminal(terminal).await?;
                journal
                    .flush()
                    .await
                    .map_err(|error| format!("terminal audit is unconfirmed: {error:?}"))
            }));
        }
        if let Some(confirmation) = &mut this.confirmation {
            match confirmation.as_mut().poll(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(result) => {
                    this.confirmation = None;
                    return std::task::Poll::Ready(
                        result
                            .err()
                            .map(|error| Err(axum::Error::new(std::io::Error::other(error)))),
                    );
                }
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.arm.is_none()
            && self.confirmation.is_none()
            && self
                .inner
                .as_ref()
                .is_none_or(http_body::Body::is_end_stream)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.as_ref().map_or_else(
            || http_body::SizeHint::with_exact(0),
            http_body::Body::size_hint,
        )
    }
}

impl Drop for LateBody {
    fn drop(&mut self) {
        drop(self.inner.take());
        drop(self.fire());
    }
}

struct Occupied<'n> {
    node: &'n Node,

    post: Option<&'n NodeEndPost>,
    slot: Arc<busbar_kernel::inflight::UnitSlot>,

    arrived: Arrived,

    op_class: OpClassId,

    reached_end: bool,
}

struct Lost {
    arrived: Arrived,

    op_class: OpClassId,

    open: Option<OpenUnit>,
}

#[must_use = "a session slot dropped unfinished is marked for the sweep"]
pub struct SessionSlot<'n> {
    occupied: Occupied<'n>,
    key: UnitKey,
    ctx: UnitCtx,
    meter: Arc<AccrualMeter>,
    own: Option<busbar_kernel::teller::SessionOwn>,
    money: Option<(
        std::sync::Weak<busbar_kernel::plane_driver::PlaneMoney>,
        crate::root::door_steps::DoorFacts,
    )>,
}

impl std::fmt::Debug for SessionSlot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSlot")
            .field("key", &self.key)
            .finish()
    }
}

impl SessionSlot<'_> {
    pub(crate) fn with_money(
        mut self,
        money: &Arc<busbar_kernel::plane_driver::PlaneMoney>,
        facts: &crate::root::door_steps::DoorFacts,
    ) -> Self {
        self.money = Some((Arc::downgrade(money), facts.clone()));
        self
    }

    fn money_report(&self) -> Option<crate::root::linked::node::Reported> {
        let (money, facts) = self.money.as_ref()?;
        let money = money.upgrade()?;
        crate::root::serve::report_of(money.as_ref(), self.key, facts)
    }

    pub async fn finish(mut self, post: &NodeEndPost) -> Result<(), String> {
        let confirmation = self.finish_inner(post, None, Evidence::default());
        await_terminal(confirmation).await?;
        self.occupied.node.retry_held_journal().await
    }

    pub async fn finish_with<U: Units>(
        mut self,
        post: &NodeEndPost,
        units: &U,
    ) -> Result<(), String> {
        let evidence = units.evidence(&self.ctx);
        let confirmation = self.finish_inner(post, None, evidence);
        await_terminal(confirmation).await?;
        self.occupied.node.retry_held_journal().await
    }

    fn finish_inner(
        &mut self,
        post: &NodeEndPost,
        override_outcome: Option<Outcome>,
        evidence: Evidence,
    ) -> Option<TerminalConfirmation> {
        let node = self.occupied.node;
        let mut open = post.take(self.key);
        if let Some(open) = open.as_mut() {
            if open.sealing.report.is_none() {
                open.sealing.report = self.money_report().map(Report::of);
            }
        }
        let outcome = override_outcome
            .or_else(|| open.as_ref().and_then(|o| o.sealing.said))
            .unwrap_or(Outcome::Aborted(busbar_contract::caps::Abort::Kernel {
                reason: busbar_contract::caps::ReasonCode::ClientGone,
            }));
        let ended = self.own.take().map(|own| {
            own.finish(
                &node.kernel,
                &self.ctx,
                busbar_kernel::teller::Run {
                    cell: self.occupied.slot.cell(),
                    parent: None,
                    leases: self.occupied.slot.leases(),
                    gauge: &node.gauge,
                    canary: &node.canary,
                    meter: &self.meter,
                    taps: None,
                },
                outcome,
                evidence,
            )
        });
        let confirmation = if let Some(open) = open {
            node.seal_session_task(self.key, open, ended)
        } else {
            node.ticket_custody.terminal(self.key, false);
            None
        };
        self.occupied.reached_end = true;
        confirmation
    }
}

impl Drop for SessionSlot<'_> {
    fn drop(&mut self) {
        if self.own.is_some() {
            if let Some(post) = self.occupied.post {
                let evidence = self
                    .money_report()
                    .map(|(_, fee_units, _)| Evidence {
                        fee_units,
                        ..Evidence::default()
                    })
                    .unwrap_or_default();
                drop(self.finish_inner(
                    post,
                    Some(Outcome::Aborted(busbar_contract::caps::Abort::Kernel {
                        reason: busbar_contract::caps::ReasonCode::ClientGone,
                    })),
                    evidence,
                ));
                if let Some(money) = self.money.as_ref().and_then(|(money, _)| money.upgrade()) {
                    busbar_kernel::plane_driver::MoneySeam::abandoned(
                        &*money,
                        &self.ctx,
                        Ended::AlreadySettled,
                    );
                }
            }
        }
    }
}

impl Drop for Occupied<'_> {
    fn drop(&mut self) {
        if self.reached_end {
            self.node.inflight.remove(self.slot.key());
        } else {
            let open = self.post.and_then(|post| post.take(self.slot.key()));
            self.node
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    self.slot.key(),
                    Lost {
                        arrived: self.arrived,
                        op_class: self.op_class,
                        open,
                    },
                );
            self.slot.mark();
            self.node.marked.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn journal_unavailable(proto: &str, why: &str) -> Response {
    busbar_kernel::ingress::ingress_error(
        proto,
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_contract::protocol::KIND_OVERLOADED,
        why,
    )
}

fn unavailable(proto: &str) -> Response {
    busbar_kernel::ingress::ingress_error(
        proto,
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_contract::protocol::KIND_OVERLOADED,
        "The service is temporarily overloaded. Please retry shortly.",
    )
}

struct Driven<'n> {
    node: &'n Node,
    route: &'n (dyn RouteAwait + Send + Sync),
    op_class: OpClassId,

    principal: &'n PrincipalId,

    arrived: Arrived,

    history: Option<&'n crate::root::kernel::PinnedHistory>,

    sealing: Mutex<Option<Accruing>>,
}

impl Driven<'_> {
    fn take_seal(&self, key: UnitKey) -> Option<Sealing> {
        let accruing = self
            .sealing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()?;
        accruing.into_seal(key, self.node.kernel.origin(OriginKind::Client), None)
    }

    fn accruing(&self) -> std::sync::MutexGuard<'_, Option<Accruing>> {
        self.sealing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl busbar_kernel::teller::UnitTaps for Driven<'_> {
    fn audited(&self, _ctx: &UnitCtx, facts: busbar_contract::caps::AuditFacts, pass: Pass<Audit>) {
        self.accruing().get_or_insert_with(Accruing::default).door = Some((facts, pass));
    }

    fn ended_as(&self, _ctx: &UnitCtx, _outcome: Outcome) {}

    fn routed(&self, _ctx: &UnitCtx, _destinations: &[VerifiedDestination]) {}
}

impl RouteAwait for Driven<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        self.accruing()
            .get_or_insert_with(Accruing::default)
            .ran
            .verified = lanes_of(destinations);

        self.node.dispatch.execute(
            self.op_class,
            self.route.route_leg(token, ctx, destinations),
        )
    }

    fn screen<'a>(&'a self, ctx: &'a UnitCtx) -> Screen<'a> {
        self.route.screen(ctx)
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        let seal = self.take_seal(ctx.key);
        self.node.seal_end(
            self.principal,
            self.arrived,
            self.history,
            ended,
            seal,
            Vec::new(),
        );
    }
}

type OpenUnits = HashMap<UnitKey, OpenUnit>;

struct OpenUnit {
    principal: PrincipalId,

    arrived: Arrived,

    history: Option<crate::root::kernel::PinnedHistory>,

    sealing: Accruing,
    checkpoint_class: Option<OpClassId>,
    checkpoint_origin: OriginKind,
}

pub struct NodeEndPost {
    node: Arc<Node>,
    open: Vec<Mutex<OpenUnits>>,
}

impl std::fmt::Debug for NodeEndPost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeEndPost").finish_non_exhaustive()
    }
}

impl busbar_kernel::teller::UnitTaps for NodeEndPost {
    fn audited(&self, ctx: &UnitCtx, facts: busbar_contract::caps::AuditFacts, pass: Pass<Audit>) {
        NodeEndPost::audited(self, ctx.key, facts, pass);
    }

    fn ended_as(&self, ctx: &UnitCtx, outcome: Outcome) {
        NodeEndPost::ended_as(self, ctx.key, outcome);
    }

    fn routed(&self, ctx: &UnitCtx, destinations: &[VerifiedDestination]) {
        NodeEndPost::routed(self, ctx.key, destinations);
    }
}

impl NodeEndPost {
    #[must_use]
    pub fn new(node: Arc<Node>) -> Self {
        NodeEndPost {
            node,
            open: (0..busbar_kernel::inflight::SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
        }
    }

    fn lock(&self, key: UnitKey) -> std::sync::MutexGuard<'_, OpenUnits> {
        self.open[(key.get() as usize) & (busbar_kernel::inflight::SHARDS - 1)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    pub fn open(
        &self,
        key: UnitKey,
        principal: PrincipalId,
        arrived: Arrived,
        history: Option<crate::root::kernel::PinnedHistory>,
    ) {
        self.lock(key).insert(
            key,
            OpenUnit {
                principal,
                arrived,
                history,
                sealing: Accruing::default(),
                checkpoint_class: None,
                checkpoint_origin: OriginKind::Client,
            },
        );
    }

    pub(crate) fn checkpoint_identity(&self, key: UnitKey, class: OpClassId, origin: OriginKind) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.checkpoint_class = Some(class);
            open.checkpoint_origin = origin;
        }
    }

    fn routed(&self, key: UnitKey, destinations: &[VerifiedDestination]) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.ran.verified = lanes_of(destinations);
        }
    }

    pub fn audited(
        &self,
        key: UnitKey,
        facts: busbar_contract::caps::AuditFacts,
        pass: Pass<Audit>,
    ) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.door = Some((facts, pass));
        }
    }

    fn door_class(&self, key: UnitKey) -> Option<OpClassId> {
        self.lock(key)
            .get(&key)
            .and_then(|open| open.sealing.door.as_ref().map(|(facts, _)| facts.op_class))
    }

    fn ended_as(&self, key: UnitKey, outcome: Outcome) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.said = Some(outcome);
        }
    }

    pub(crate) fn completed(&self, key: UnitKey) {
        self.ended_as(key, Outcome::Completed);
    }

    pub fn stopped(&self, key: UnitKey, reason: busbar_contract::caps::ReasonCode) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.said = Some(Outcome::Refused(
                busbar_contract::caps::StepName::Route,
                reason,
            ));
        }
    }

    pub fn reported(&self, key: UnitKey, report: Option<Reported>) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.report = report.map(Report::of);
        }
    }

    fn take(&self, key: UnitKey) -> Option<OpenUnit> {
        self.lock(key).remove(&key)
    }

    pub fn close(&self, key: UnitKey) {
        self.lock(key).remove(&key);
    }

    #[must_use]
    pub fn open_units(&self) -> usize {
        self.open
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .sum()
    }
}

impl busbar_kernel_egress::ports::Journal for NodeEndPost {
    fn dispatched(
        &self,
        record: &busbar_kernel_egress::ports::Dispatched,
    ) -> Result<(), busbar_kernel_egress::ports::DurabilityUnavailable> {
        self.lock(record.unit)
            .get_mut(&record.unit)
            .map(|open| open.sealing.ran.dialled = record.lane)
            .ok_or(busbar_kernel_egress::ports::DurabilityUnavailable)
    }

    fn abandoned(&self, _record: &busbar_kernel_egress::ports::Dispatched) {}
}

impl busbar_kernel::plane_driver::HookJournal for NodeEndPost {
    fn hooks_ran(&self, record: &busbar_kernel::plane_driver::HooksRan) {
        if let Some(open) = self.lock(record.unit).get_mut(&record.unit) {
            open.sealing.ran.hooks.extend(record.hooks.iter().cloned());
        }
    }
}

impl busbar_kernel::plane_driver::EndPost for NodeEndPost {
    fn checkpoint_decoded(&self, key: UnitKey, class: OpClassId) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.checkpoint_class = Some(class);
        }
    }

    fn checkpoint_facts(&self, key: UnitKey) -> Option<Vec<u8>> {
        let all = self.lock(key);
        let open = all.get(&key)?;
        let book = self
            .node
            .book
            .get()?
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let captured = crate::root::durability::RunningAudit {
            incarnation: book.incarnation,
            principal: open.principal.as_str().to_string(),
            op_class: open.checkpoint_class?.as_str().to_string(),
            origin: open.checkpoint_origin.as_str().to_string(),
            parent: match open.checkpoint_origin {
                OriginKind::Nested { parent } | OriginKind::Delivery { parent } => {
                    Some(parent.get())
                }
                _ => None,
            },
            wall: open.arrived.secs(),
            mono: open.arrived.mono(),
            destination: open.sealing.ran.destination(None),
            rate_card: card_in_force(open.history.as_ref(), open.arrived.ms()),
            policy_epoch: policy_in_force(open.history.as_ref(), open.arrived.ms()),
            hooks: open
                .sealing
                .ran
                .hooks
                .iter()
                .map(|hook| {
                    (
                        hook.hook.clone(),
                        hook.head.as_str().to_string(),
                        hook.failed,
                    )
                })
                .collect(),
        };
        serde_json::to_vec(&captured).ok()
    }

    fn post(&self, ctx: &UnitCtx, ended: Ended) {
        let facts = self.lock(ctx.key).remove(&ctx.key);
        if let Some(open) = facts {
            let parent = match ctx.origin {
                OriginKind::Nested { parent } => Some(parent),
                _ => None,
            };
            let seal = open
                .sealing
                .into_seal(ctx.key, self.node.kernel.origin(ctx.origin), parent);
            self.node.seal_end(
                &open.principal,
                open.arrived,
                open.history.as_ref(),
                ended,
                seal,
                Vec::new(),
            );
        }
    }
}

pub struct Parent {
    key: UnitKey,
    slot: Arc<busbar_kernel::inflight::UnitSlot>,
}

impl Parent {
    #[must_use]
    pub fn key(&self) -> UnitKey {
        self.key
    }

    #[must_use]
    pub fn cell(&self) -> &busbar_contract::caps::HoldCell {
        self.slot.cell()
    }
}

impl std::fmt::Debug for Parent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parent").field("key", &self.key).finish()
    }
}

struct UnitSeal {
    facts: busbar_contract::caps::AuditFacts,
    pass: Pass<Audit>,
    key: UnitKey,
    origin: busbar_contract::caps::Origin,

    parent: Option<UnitKey>,
}

/// WHAT THE UNIT RAN UNDER AND WHERE IT WENT, as the node saw it happen: the facts its record's
/// destination and controls are taken from, beside what its audit door sealed.
#[derive(Default)]
struct Ran {
    /// The sealed destinations its Route leg was lent: empty for a unit that never routed.
    verified: Vec<LaneId>,
    /// The lane of the verified destination its egress walk last dialled, where one dialled.
    dialled: Option<LaneId>,
    /// Every hook its hook stage reported running, in the order they ran (THE DESIGN §1: "hooks
    /// applied"): empty for a unit no hook ran for.
    hooks: Vec<HookApplied>,
}

/// A unit's record-to-be while it runs: what the node saw ([`Ran`]), and its audit door's facts and
/// pass once the loop handed them back.
#[derive(Default)]
struct Accruing {
    door: Option<(busbar_contract::caps::AuditFacts, Pass<Audit>)>,
    ran: Ran,
    /// How the unit's own steps said it ended, as its encode door was told: a session's outcome.
    said: Option<Outcome>,
    /// What a session consumed, as its plane reported it at its end.
    report: Option<Report>,
}

impl Accruing {
    fn into_seal(
        self,
        key: UnitKey,
        origin: busbar_contract::caps::Origin,
        parent: Option<UnitKey>,
    ) -> Option<Sealing> {
        let (facts, pass) = self.door?;
        Some(Sealing {
            seal: UnitSeal {
                facts,
                pass,
                key,
                origin,
                parent,
            },
            ran: self.ran,
        })
    }
}

// Serving waits for both native confirmation and ticket readiness. Dropping the
// JoinHandle only detaches the owned task; cancellation never abandons its original.
type TerminalConfirmation = tokio::task::JoinHandle<Result<(), String>>;

async fn await_terminal(confirmation: Option<TerminalConfirmation>) -> Result<(), String> {
    if let Some(task) = confirmation {
        task.await
            .map_err(|error| format!("terminal confirmation task failed: {error}"))??;
    }
    Ok(())
}

struct StagedAudit {
    journal: Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
    run: Arc<busbar_kernel::persistence::journal::runtime::StagedRun>,
}
impl StagedAudit {
    fn confirm_terminal(
        self,
        custody: Arc<crate::root::serve::TicketCustody>,
        key: UnitKey,
        completed: bool,
    ) -> Option<TerminalConfirmation> {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            custody.terminal(key, false);
            return None;
        };
        Some(runtime.spawn(async move {
            let confirmed = self.journal.confirm(&self.run).await;
            custody.terminal(key, completed && confirmed.is_ok());
            confirmed.map_err(|error| format!("terminal audit is unconfirmed: {error:?}"))
        }))
    }
}

struct Sealing {
    seal: UnitSeal,
    ran: Ran,
}

impl From<UnitSeal> for Sealing {
    fn from(seal: UnitSeal) -> Self {
        Sealing {
            seal,
            ran: Ran::default(),
        }
    }
}

fn lanes_of(destinations: &[VerifiedDestination]) -> Vec<LaneId> {
    destinations.iter().map(|d| *d.lane()).collect()
}

impl Ran {
    fn destination(&self, served: Option<&str>) -> Option<String> {
        let sealed = |lane: &str| self.verified.iter().any(|v| v.as_str() == lane);
        let lane = match (self.dialled, served) {
            (Some(dialled), _) => Some(dialled.as_str()),
            (None, Some(served)) if sealed(served) => Some(served),

            (None, _) => match self.verified.as_slice() {
                [only] => Some(only.as_str()),
                _ => None,
            },
        };
        lane.map(str::to_owned)
    }
}

#[cfg(test)]
#[test]
fn a_local_billing_lane_keeps_only_a_unique_verified_route_destination() {
    let a = LaneId::new("a2a\u{1f}planner-a");
    let b = LaneId::new("a2a\u{1f}planner-b");
    let billing = Some("a2a\u{1f}agent:planner-b");
    let mut ran = Ran::default();
    assert_eq!(ran.destination(billing), None, "no unverified attribution");
    ran.verified = vec![b];
    assert_eq!(ran.destination(billing), Some(b.as_str().to_owned()));
    ran.verified = vec![a, b];
    assert_eq!(
        ran.destination(billing),
        None,
        "no choice between verified entries"
    );
    assert_eq!(
        ran.destination(Some(a.as_str())),
        Some(a.as_str().to_owned())
    );
    ran.dialled = Some(b);
    assert_eq!(
        ran.destination(Some(a.as_str())),
        Some(b.as_str().to_owned())
    );
}

impl Sealing {
    #[allow(clippy::too_many_arguments)]
    fn seal(
        self,
        book: &Arc<Mutex<crate::root::durability::Durability>>,
        token: &Grant<busbar_contract::caps::DurableWrite>,
        principal: &PrincipalId,
        arrived: Arrived,
        card: Option<&crate::root::kernel::PinnedHistory>,
        outcome: Outcome,
        lines: Vec<RecordLine>,
        fee_count: u32,
        served: Option<&str>,
    ) -> Result<StagedAudit, busbar_contract::caps::DurabilityLost> {
        let Sealing { seal, ran } = self;
        let refused = matches!(outcome, Outcome::Refused(..));

        let hook_failed = ran.hooks.iter().any(|hook| hook.failed);
        let destination = ran.destination(served);
        let controls = Controls {
            policy_epoch: policy_in_force(card, arrived.ms()),
            hooks_applied: ran.hooks,
            ..Controls::default()
        };
        let inputs = AuditInputs {
            subject: Subject::PrincipalId(principal.as_str().to_string()),
            what: What {
                unit_key: seal.key,
                incarnation: 0,
                op_class: RecordOpClass::new(seal.facts.op_class.as_str()),
                destination,
                parent: seal.parent,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: arrived.secs(),
            mono: arrived.mono(),
            origin: seal.origin,
            outcome: OutcomeFacts {
                unit_end: outcome,
                step: outcome.step(),
                finish: audit_finish(seal.facts.finish),
                hook_failed,
                emission_delta: 0,
                stale_policy: false,
            },
            usage: RecordUsage {
                lines: if refused { Vec::new() } else { lines },
                tier_bp: 10_000,
                fee_count: if refused { 0 } else { fee_count },
                rate_card_version: card_in_force(card, arrived.ms()),
                bucket_chain_ref: String::new(),
            },
            controls,
            correlation_label: None,
        };
        let mut book = book.lock().unwrap_or_else(|poison| poison.into_inner());
        let journal = book.journal.clone();
        let (_, run) = book.stage_unit(inputs, seal.pass, token)?;
        Ok(StagedAudit { journal, run })
    }
}

pub(crate) fn audit_finish(finish: busbar_contract::FinishClass) -> RecordFinish {
    match finish {
        busbar_contract::FinishClass::Complete => RecordFinish::Complete,
        busbar_contract::FinishClass::TurnComplete => RecordFinish::TurnComplete,
        busbar_contract::FinishClass::Partial => RecordFinish::Partial,
        busbar_contract::FinishClass::Error => RecordFinish::Error,
    }
}

fn report_lines(report: &Report) -> Vec<RecordLine> {
    report
        .usage
        .usage_units
        .iter()
        .filter(|(_, count)| !count.is_zero())
        .filter_map(|(class, count)| {
            Some(RecordLine {
                class: Registration::meter_class(class)?,
                quantity: *count,
                source: busbar_contract::caps::QuantitySource::Count,
                estimated: false,
            })
        })
        .collect()
}

pub(crate) fn card_in_force(
    card: Option<&crate::root::kernel::PinnedHistory>,
    arrived_ms: u64,
) -> Option<[u8; 20]> {
    card.and_then(|pinned| {
        pinned
            .view()
            .entry_at(arrived_ms)
            .map(|entry| entry.key().0)
    })
}

pub(crate) fn policy_in_force(
    card: Option<&crate::root::kernel::PinnedHistory>,
    arrived_ms: u64,
) -> u64 {
    card.and_then(|pinned| {
        pinned
            .view()
            .entries()
            .iter()
            .rev()
            .filter(|entry| entry.covers(arrived_ms))
            .find_map(|entry| match entry.author() {
                busbar_kernel_ledger::cost::Author::Config { policy_epoch } => Some(*policy_epoch),
                busbar_kernel_ledger::cost::Author::Opening
                | busbar_kernel_ledger::cost::Author::Amend { .. } => None,
            })
    })
    .unwrap_or(0)
}

static NODE: LazyLock<Arc<Node>> = LazyLock::new(|| Arc::new(Node::new()));

#[must_use]
pub fn node() -> Arc<Node> {
    Arc::clone(&NODE)
}

fn drive(
    handed: Handed,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlaneAnswer> + Send>> {
    Box::pin(async move { PlaneAnswer::Live(NODE.answer(handed).await) })
}

pub fn bind_book(book: Arc<Mutex<crate::root::durability::Durability>>) {
    bind_node_book(&NODE, &crate::root::kernel::ROOT_CARD, book);
}

pub const ROOT_UNIT: crate::root::linked::RootUnit = crate::root::linked::RootUnit {
    seal: None,
    drive: Some(drive),
    on_config: Some(|_| crate::root::kernel::install_card_repricer()),
    opens_book: true,
    on_book: Some(|ctx| bind_book(Arc::clone(&ctx.book.durability))),
    end_post: Some(|| Arc::new(NodeEndPost::new(node()))),
};

fn bind_node_book(
    node: &Node,
    cards: &crate::root::kernel::RootHistory,
    book: Arc<Mutex<crate::root::durability::Durability>>,
) {
    let _ = cards;
    node.bind_book(book);
}

#[cfg(all(test, linked_axis_node))]
#[path = "tests/plane_node.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/plane_node_seal.rs"]
mod seal_tests;

#[cfg(test)]
#[path = "tests/plane_node_money.rs"]
mod node_money_tests;
