// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use foldhash::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

#[cfg(test)]
use axum::http::StatusCode;
#[cfg(test)]
use axum::response::Response;

use busbar_contract::caps::CallId;
#[cfg(test)]
use busbar_contract::caps::Route;
use busbar_contract::caps::{
    Audit, Grant, OpClassId, OriginKind, Outcome, Pass, PrincipalId, VerifiedDestination,
};
use busbar_contract::kept::Text;
use busbar_contract::{LaneId, UnitKey};
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission, RequestLease};
#[path = "plane_node/terminal_book.rs"]
mod terminal_book;
#[cfg(test)]
use busbar_kernel::plane_driver::PlaneAnswer;
use busbar_kernel::teller::{AccrualMeter, Ended, Evidence, RouteAwait, UnitCtx, Units};
#[cfg(test)]
use busbar_kernel::teller::{RouteLeg, Screen};
use busbar_kernel::Registration;
use busbar_kernel_audit::{
    Attempt, AttemptOutcome, AuditInputs, Controls, FinishClass as RecordFinish, HookApplied,
    OpClassId as RecordOpClass, OutcomeFacts, Subject, Usage as RecordUsage,
    UsageLine as RecordLine, What, ATTEMPT_SLOTS,
};
use terminal_book::TerminalBook;

/// The charged terminal table. The Node owns it; the original notary observes it weakly.
pub(crate) struct RetainedBook(Mutex<Option<TerminalBook>>);

impl RetainedBook {
    fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, Option<TerminalBook>>> {
        self.0.lock()
    }
}

#[path = "plane_node/native.rs"]
mod native;
#[cfg(test)]
pub(crate) use native::retained_fixture;
pub(crate) use native::{deliver_original_page, fund_original_page, NativeNodeHandle};

#[cfg(test)]
use crate::root::linked::node::Handed;
use crate::root::linked::node::{Late, Reported, Resolve};

struct LaneNames {
    interner: Arc<Mutex<Registration>>,
    resolved: HashMap<String, LaneId>,
    consulted: u64,
}

struct ResponseIntentOwner {
    store: Arc<busbar_kernel::persistence::facade::CoreStore>,
    service: Arc<crate::root::durability::response_intent::ResponseIntentService>,
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
pub(crate) struct Arrived {
    /// Milliseconds since the epoch: the reading, at the finest resolution either caller needs.
    ms: u64,
    /// The node's monotonic reading at the same arrival.
    mono: u64,
}

impl Arrived {
    #[must_use]
    pub(crate) fn at(ms: u64, mono: u64) -> Self {
        Self { ms, mono }
    }

    #[must_use]
    pub(crate) fn secs(self) -> u64 {
        self.ms / 1_000
    }

    #[must_use]
    pub(crate) fn ms(self) -> u64 {
        self.ms
    }

    #[must_use]
    pub(crate) fn mono(self) -> u64 {
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
        crate::root::cold::first_resolved(&mut self.resolved, name, lane);
        Some(lane)
    }

    #[cfg(test)]
    fn consulted(&self) -> u64 {
        self.consulted
    }
}

pub(crate) struct Node {
    kernel: Arc<busbar_kernel::teller::Kernel>,
    pub(in crate::root) inflight: busbar_kernel::inflight::InFlight,
    gauge: busbar_kernel::slice::ConcurrencyGauge,
    canary: busbar_kernel::canary::Canary,
    door: crate::root::kernel::AdmissionDoor,

    #[cfg(test)]
    lanes: Arc<Mutex<Registration>>,

    lane_names: Arc<Mutex<LaneNames>>,
    next_key: Arc<busbar_kernel::door::UnitKeyMint>,

    marked: AtomicU64,

    lost: Arc<RetainedBook>,

    mono: AtomicU64,

    /// The clock a unit's arrival is read from: once, at the door, and every window it is
    /// admitted and billed in is the one that reading names.
    clock: Arc<dyn busbar_kernel::Clock>,

    book: std::sync::OnceLock<Arc<Mutex<crate::root::durability::Durability>>>,

    lane: std::sync::OnceLock<Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>>,
    response_intent: std::sync::OnceLock<ResponseIntentOwner>,

    /// The node the bound book seals as: the node half of every unit id this node stamps.
    sealing: std::sync::OnceLock<crate::root::durability::LineIdentity>,

    durability_token: busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
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
    pub(crate) fn new() -> Self {
        let lanes = Arc::new(Mutex::new(crate::root::kernel::new_registration()));
        let kernel = crate::root::kernel::new_kernel();
        Self {
            durability_token: kernel.durability_token(),
            book: std::sync::OnceLock::new(),
            lane: std::sync::OnceLock::new(),
            response_intent: std::sync::OnceLock::new(),
            sealing: std::sync::OnceLock::new(),
            kernel: Arc::new(kernel),

            inflight: busbar_kernel::inflight::InFlight::new(usize::MAX),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_kernel::canary::Canary::new(),
            door: crate::root::kernel::AdmissionDoor,
            #[cfg(test)]
            lanes: Arc::clone(&lanes),
            lane_names: Arc::new(Mutex::new(LaneNames {
                interner: lanes,
                resolved: HashMap::default(),
                consulted: 0,
            })),
            next_key: Arc::default(),
            marked: AtomicU64::new(0),
            lost: Arc::new(RetainedBook(Mutex::new(Self::fixture_terminal_book()))),
            mono: AtomicU64::new(0),
            clock: Arc::new(busbar_kernel::WallClock),
        }
    }

    /// Bind the actual process accounts once, before any terminal owner enters.
    pub(crate) fn bind_terminal_storage(
        &self,
        process: &Arc<ProcessAdmission>,
    ) -> Result<(), &'static str> {
        let mut book = self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if book.is_some() {
            return Err("terminal storage already bound");
        }
        *book = Some(TerminalBook::new(
            process.connection_storage(AdmissionClass::Data),
            process.connection_storage(AdmissionClass::Operator),
        ));
        Ok(())
    }

    /// Production binds the actual boot ProcessAdmission in main; nothing is bound by default.
    #[cfg(not(test))]
    fn fixture_terminal_book() -> Option<TerminalBook> {
        None
    }

    /// Unit fixtures use a real ProcessAdmission, as production does. A fixture asserting on
    /// its own boot budget rebinds through `rebind_terminal_storage` before any unit enters.
    #[cfg(test)]
    fn fixture_terminal_book() -> Option<TerminalBook> {
        let process = ProcessAdmission::new(0);
        Some(TerminalBook::new(
            process.connection_storage(AdmissionClass::Data),
            process.connection_storage(AdmissionClass::Operator),
        ))
    }

    /// Replace an empty fixture book with the fixture's own boot-bound process storage.
    #[cfg(test)]
    pub(crate) fn rebind_terminal_storage(&self, process: &Arc<ProcessAdmission>) {
        let mut book = self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            book.as_ref().is_none_or(|book| book.len() == 0),
            "terminal storage is rebound only before any unit enters"
        );
        *book = Some(TerminalBook::new(
            process.connection_storage(AdmissionClass::Data),
            process.connection_storage(AdmissionClass::Operator),
        ));
    }

    pub(crate) fn terminal_pending(&self) -> usize {
        self.lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, TerminalBook::len)
    }

    fn reserve_terminal(
        &self,
        class: AdmissionClass,
        key: UnitKey,
        call: CallId,
    ) -> Option<TerminalReservation<'_>> {
        self.lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()?
            .insert(class, key, RetainedUnit::reserved(call))
            .ok()?;
        Some(TerminalReservation {
            node: self,
            class,
            key,
            call,
            active: true,
        })
    }

    /// A node whose arrivals are read from `clock`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_clock(clock: Arc<dyn busbar_kernel::Clock>) -> Self {
        Self {
            clock,
            ..Self::new()
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
    pub(crate) fn kernel_and_keys(
        &self,
    ) -> (
        Arc<busbar_kernel::teller::Kernel>,
        Arc<busbar_kernel::door::UnitKeyMint>,
    ) {
        (Arc::clone(&self.kernel), Arc::clone(&self.next_key))
    }

    pub(crate) fn arrived(&self) -> Arrived {
        self.checked_arrived()
            .expect("node monotonic clock exhausted")
    }

    /// Response finalization can refuse exhausted identity before publishing any output.
    /// All node stamps share this allocator, so an ordinary arrival cannot wrap it first.
    pub(crate) fn checked_arrived(&self) -> Result<Arrived, &'static str> {
        let mono = self
            .mono
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "node monotonic clock exhausted")?;
        Ok(Arrived::at(self.clock.now(), mono))
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn lanes(&self) -> Arc<Mutex<Registration>> {
        Arc::clone(&self.lanes)
    }

    pub(crate) fn resolver(&self) -> Resolve {
        let names = Arc::clone(&self.lane_names);
        Arc::new(move |name: &str| {
            names
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .resolve(name)
        })
    }

    pub(crate) fn bind_book(&self, book: Arc<Mutex<crate::root::durability::Durability>>) {
        let (journal, sealing) = {
            let held = book.lock().unwrap_or_else(|poison| poison.into_inner());
            (held.journal.clone(), held.line_identity())
        };
        let _ = self.lane.set(journal);
        let _ = self.sealing.set(sealing);
        let _ = self.book.set(book);
    }

    pub(crate) fn bind_response_intents(
        &self,
        store: Arc<busbar_kernel::persistence::facade::CoreStore>,
        service: Arc<crate::root::durability::response_intent::ResponseIntentService>,
    ) -> Result<(), &'static str> {
        let book = self
            .book
            .get()
            .ok_or("response intent node book unavailable")?
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !self
            .lane
            .get()
            .is_some_and(|journal| Arc::ptr_eq(journal, service.journal()))
            || !service.journal().is_bound_to(&store)
            || book.incarnation != service.incarnation()
            || book.record.node() != service.journal().node()
        {
            return Err("response intent owner differs from the admitted node journal");
        }
        self.response_intent
            .set(ResponseIntentOwner { store, service })
            .map_err(|_| "response intent owner already installed")
    }

    pub(crate) fn response_intents(
        &self,
    ) -> Option<Arc<crate::root::durability::response_intent::ResponseIntentService>> {
        self.response_intent
            .get()
            .map(|owner| Arc::clone(&owner.service))
    }

    pub(crate) fn response_intent_stamp(
        &self,
        journal: &Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
    ) -> Result<busbar_kernel_audit::response_intent::ResponseIntentStamp, String> {
        let owner = self
            .response_intent
            .get()
            .ok_or("response intent owner unavailable")?;
        if !Arc::ptr_eq(journal, owner.service.journal()) || !journal.is_bound_to(&owner.store) {
            return Err("response intent journal differs from the retained attachment".into());
        }
        let authority = owner
            .store
            .authority()
            .map_err(|error| format!("response intent writer: {error:?}"))?;
        let history = crate::root::kernel::ROOT_CARD.pin();
        let captured = self.checked_arrived()?;
        Ok(busbar_kernel_audit::response_intent::ResponseIntentStamp {
            lease_epoch: authority.writer_epoch,
            policy_epoch: policy_in_force(history.as_ref(), captured.ms()),
            wall: captured.secs(),
            mono: captured.mono(),
        })
    }

    /// THE NODE-QUALIFIED ID of `unit` (ADMIN-API-1.6 §3.4): the one string its sealed record's
    /// `unit` and its data-plane `X-Request-Id` both carry. `None` before a book is bound, or
    /// when the process has no boot nonce.
    #[must_use]
    pub(crate) fn unit_id(&self, unit: UnitKey) -> Option<busbar_kernel_audit::UnitId> {
        let node = self.sealing.get()?.node;
        busbar_kernel_audit::UnitId::of(node, busbar_kernel::snapshot::boot_nonce(), unit.get())
    }
    pub(crate) async fn retry_held_journal(&self) -> Result<(), String> {
        if let Some(journal) = self.lane.get() {
            journal
                .flush()
                .await
                .map_err(|error| crate::root::cold::native_journal_refused(&error))?;
        }
        Ok(())
    }
    /// The journal's sticky custody failure on a finish path, in O(1). A unit
    /// waits only for its own record; held runs of other units stay with the
    /// lease-tick retry and the admission refusal at unit open.
    pub(crate) fn journal_failed(&self) -> Result<(), String> {
        match self.lane.get().and_then(|journal| journal.failed()) {
            Some(error) => Err(crate::root::cold::native_journal_refused(&error)),
            None => Ok(()),
        }
    }
    /// Settle in-doubt store attempts (≤ 64 per tick) and publish `busbar_store_slots`.
    pub(crate) async fn settle_store(&self) {
        let Some(journal) = self.lane.get() else {
            return;
        };
        match journal.settle_store().await {
            Ok(states) => {
                for (state, count) in [
                    ("free", states.free),
                    ("in_flight", states.in_flight),
                    ("in_doubt", states.in_doubt),
                    ("resolved_uncollected", states.resolved_uncollected),
                    ("reconcile", states.reconcile),
                ] {
                    metrics::gauge!(busbar_kernel::snapshot::STORE_SLOTS, "state" => state)
                        .set(count as f64);
                }
            }
            Err(error) => tracing::warn!(?error, "store slot settle pass failed"),
        }
    }
    #[must_use]
    pub(crate) fn journal_refusal(&self) -> Option<String> {
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
        let receipt = self.seal_end_ack(principal, arrived, card, ended, seal, lines);
        match receipt {
            Ok(receipt) => receipt.confirm_terminal(),
            Err(error) => Some(TerminalConfirmation::failed(error)),
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
    ) -> Result<StagedAudit, busbar_contract::caps::DurabilityLost> {
        let lost = || {
            busbar_contract::caps::DurabilityLost::observed(
                &self.durability_token,
                busbar_contract::caps::StepName::Audit,
            )
        };
        let book = self.book.get().ok_or_else(lost)?;
        let busbar_kernel::teller::Ended::Settled { end, .. } = ended else {
            return Err(lost());
        };
        let outcome = end.outcome();
        end.into_posted().map_err(|_| lost())?;
        seal.seal(
            book,
            self.sealing.get().copied(),
            &self.durability_token,
            principal,
            arrived,
            card,
            outcome,
            lines,
            0,
            None,
            String::new(),
        )
    }

    /// Freeze a funded copy while the original native entry still owns its facts and pass.
    /// This performs no journal stage, chain advance, receipt transfer or source removal.
    pub(super) fn freeze_native_inputs(
        &self,
        terminal: &busbar_kernel::teller::native_data_audit::NativeAuditTerminal,
        open: &OpenUnit,
        // The original money owner's transferred report, never a re-derived bill.
        report: Option<&Report>,
    ) -> Result<AuditInputs, &'static str> {
        let context = terminal.context();
        let outcome = terminal.outcome();
        let facts = terminal.facts();
        if terminal.admission().is_some() && report.is_none() {
            return Err("native terminal has no original monetary report");
        }
        let ran = &open.sealing.ran;
        let (attempts, attempts_total) = ran.attempts(outcome);
        let refused = matches!(outcome, Outcome::Refused(..));
        let card = open.history.as_ref();
        let served = report.map(|report| report.lane.as_str());
        Ok(AuditInputs {
            subject: Subject::PrincipalId(open.principal.text().clone()),
            what: What {
                unit_key: context.key,
                incarnation: 0,
                op_class: RecordOpClass::new(facts.op_class.as_str()),
                destination: ran.destination(served).map(str::to_owned),
                parent: match context.origin {
                    OriginKind::Nested { parent } => Some(parent),
                    _ => None,
                },
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: open.arrived.secs(),
            mono: open.arrived.mono(),
            origin: self.kernel.origin(context.origin),
            outcome: OutcomeFacts {
                unit_end: outcome,
                step: outcome.step(),
                finish: audit_finish(facts.finish),
                hook_failed: ran.hooks.iter().any(|hook| hook.failed),
                emission_delta: 0,
                stale_policy: false,
            },
            usage: RecordUsage {
                lines: if refused {
                    Vec::new()
                } else {
                    report.map(report_lines).unwrap_or_default()
                },
                tier_bp: 10_000,
                fee_count: if refused {
                    0
                } else {
                    report.map_or(0, |report| report.fee_count)
                },
                rate_card_version: card_in_force(card, open.arrived.ms()),
                bucket_chain_ref: String::new(),
            },
            controls: Controls {
                policy_epoch: policy_in_force(card, open.arrived.ms()),
                hooks_applied: ran.hooks.clone(),
                ..Controls::default()
            },
            correlation_label: None,
            unit: busbar_kernel_audit::UnitFacts {
                billing: None,
                wall_ms: open.arrived.ms(),
                attribution: report.map_or_else(String::new, |report| report.attribution.clone()),
                boot_nonce: busbar_kernel::snapshot::boot_nonce(),
                status: ran.measured.status,
                ttft_us: ran.measured.ttft_us,
                total_us: ran.measured.total_us,
                attempts,
                attempts_total,
                records: ran.records.clone(),
            },
        })
    }

    pub(crate) fn sweep(&self, now: Arrived) -> usize {
        if self.marked.swap(0, Ordering::AcqRel) == 0 {
            return 0;
        }
        self.sweep_marked(now)
    }

    /// One slot of the tick's sweep: a marked unit that lost its owner is settled, sealed and
    /// forgotten (`true`); any other slot is left as it is.
    pub(in crate::root) fn sweep_slot(
        &self,
        slot: &Arc<busbar_kernel::inflight::UnitSlot>,
        now: Arrived,
    ) -> bool {
        if !slot.is_marked() {
            return false;
        }

        let lost = {
            let mut book = self
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(book) = book.as_mut() else {
                return false;
            };
            let class = [AdmissionClass::Data, AdmissionClass::Operator].into_iter().find(|class| {
                book.get(*class, slot.key()).is_some_and(|entry| {
                    matches!(&entry.state, RetainedState::Abandoned(lost) if Arc::ptr_eq(&lost.slot, slot))
                })
            });
            let Some(class) = class else {
                return false;
            };
            let Some(entry) = book.remove(class, slot.key()) else {
                return false;
            };
            let RetainedState::Abandoned(lost) = entry.state else {
                unreachable!("validated original abandoned owner")
            };
            lost
        };
        let verdict = busbar_kernel::tick::sweep(
            slot,
            busbar_contract::caps::StepName::Route,
            now.ms(),
            busbar_kernel::Millis::MAX,
            false,
        );

        let settled = busbar_kernel::tick::sweep_settle(
            &self.kernel,
            slot,
            verdict,
            &Evidence::default(),
            &self.canary,
            &self.gauge,
        );
        if let Some(busbar_kernel::tick::Swept { end, line, audit }) = settled {
            if let Ok(posted) = end.posted() {
                let principal = posted.principal().clone();

                let entered = lost.arrived;

                let lines = crate::root::cold::lost_unit_lines(line);
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
        true
    }

    #[must_use]
    pub(crate) fn parent(&self, key: UnitKey) -> Option<Parent> {
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
            self.sealing.get().copied(),
            &self.durability_token,
            principal,
            self.arrived(),
            None,
            outcome,
            Vec::new(),
            0,
            None,
            String::new(),
        );
    }

    #[must_use]
    pub(crate) fn mint(&self) -> UnitKey {
        self.next_key.mint()
    }

    pub(crate) async fn drive_borrowed<U: Units + RouteAwait>(
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
        timing: Option<Timing<'_>>,
        request: &RequestLease,
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
        let call = self.kernel.next_call();
        let reservation = self.reserve_terminal(request.class(), key, call)?;
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
            reservation,
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

        // Both readings precede the seal: the total is the unit's last frame handed over, and
        // the first write already happened inside the unit (§9).
        if let Some(timing) = timing {
            post.measured(key, timing.read());
        }
        let seal = post.take(key).and_then(|open| {
            open.sealing
                .into_seal(key, self.kernel.origin(origin), parent.map(|p| p.key))
        });
        let confirmation = match self.late_arm(Some(late), principal, arrived, history.as_ref()) {
            Some(mut arm) => {
                arm.seal = seal;
                arm.carrying(ended).post()
            }
            None => self.seal_end_task(
                principal,
                arrived,
                history.as_ref(),
                ended,
                seal,
                Vec::new(),
            ),
        };
        occupied.reached_end = true;
        let mut confirming = ConfirmingUnit {
            route: Some(units),
            ctx: &ctx,
        };
        let result = async {
            if let Err(error) = await_terminal(confirmation).await {
                tracing::error!(reason = error, "unit terminal audit remains unconfirmed");
                return None;
            }
            if let Err(error) = self.journal_failed() {
                tracing::error!(reason = error, "unit audit remains unconfirmed");
                return None;
            }
            outcome
        }
        .await;
        confirming.route = None;
        result
    }

    pub(crate) async fn open_borrowed<'n, U: Units + RouteAwait>(
        &'n self,
        key: UnitKey,
        arrived: Arrived,
        principal: &PrincipalId,
        post: &'n NodeEndPost,
        units: &U,
        history: Option<crate::root::kernel::PinnedHistory>,
        audit_kind: OpClassId,
        admission: Option<&busbar_kernel::inbound::RequestAdmission>,
        request: &RequestLease,
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
        let call = self.kernel.next_call();
        let reservation = self.reserve_terminal(request.class(), key, call)?;
        if admission.is_some_and(|admission| !admission.begin_execution()) {
            return None;
        }
        post.open(key, principal.clone(), arrived, history);
        post.checkpoint_identity(key, audit_kind, OriginKind::Client);
        let meter = Arc::new(AccrualMeter::new());
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
            reservation,
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
                return None;
            };
            open.sealing.said = Some(end.outcome());
            if end.into_posted().is_err() {
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
        let (said, mut report) = (sealing.said.take(), sealing.report.take());
        let outcome = said?;
        let seal = sealing.into_seal(key, self.kernel.origin(OriginKind::Client), None)?;
        let (lines, fee_count) = report
            .as_ref()
            .map_or((Vec::new(), 0), |r| (report_lines(r), r.fee_count));
        let attribution = report
            .as_mut()
            .map(|r| std::mem::take(&mut r.attribution))
            .unwrap_or_default();
        let acknowledged = seal.seal(
            book,
            self.sealing.get().copied(),
            &self.durability_token,
            &principal,
            arrived,
            history.as_ref(),
            outcome,
            lines,
            fee_count,
            report.as_ref().map(|r| r.lane.as_str()),
            attribution,
        );
        match acknowledged {
            Ok(receipt) => receipt.confirm_terminal(),
            Err(error) => Some(TerminalConfirmation::failed(error)),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) async fn answer(&self, handed: Handed) -> Response {
        self.answer_arriving_at(handed, self.arrived()).await
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) async fn answer_arriving_at(&self, handed: Handed, arrived: Arrived) -> Response {
        self.answer_pinned(handed, arrived, || crate::root::kernel::ROOT_CARD.pin())
            .await
    }

    #[cfg(test)]
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
        let Some(reservation) = self.reserve_terminal(AdmissionClass::Data, key, call) else {
            return unavailable(proto);
        };
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
                    reservation,
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

    #[cfg(test)]
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
                match self.journal_failed() {
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
            line: self.sealing.get().copied(),
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
pub(crate) struct Report {
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
    /// The unit's metering `group`, `pool` and `provider`, as recipe `v7` seals them.
    pub attribution: String,
}

impl Report {
    fn of((usage, fee_count, lane, attribution): crate::root::linked::node::LegacyReport) -> Self {
        Report {
            usage,
            fee_count,
            lane,
            attribution,
        }
    }
}

struct LateAccrual {
    book: Arc<Mutex<crate::root::durability::Durability>>,
    /// The book's boot constants, so the late line is prepared before its lock.
    line: Option<crate::root::durability::LineIdentity>,

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
            book,
            line,
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
        // A report that bills nothing is not sealed as usage, but its attribution still is.
        let reported = late();
        if matches!(reported, Some(Reported::Partitioned)) {
            return preview_confirmation(outcome, seal);
        }
        let (report, attribution) = match reported.and_then(Reported::legacy).map(Report::of) {
            Some(report)
                if completed
                    || report.fee_count > 0
                    || report.usage.usage_units.values().any(|n| !n.is_zero()) =>
            {
                (Some(report), String::new())
            }
            Some(report) => (None, report.attribution),
            None => (None, String::new()),
        };
        let (Some(seal), Some(outcome)) = (seal, outcome) else {
            return None;
        };
        let acknowledged = match report {
            Some(report) => {
                let lines = report_lines(&report);
                let Report {
                    fee_count,
                    lane,
                    attribution,
                    ..
                } = report;
                seal.seal(
                    &book,
                    line,
                    &durability_token,
                    &principal,
                    arrived,
                    Some(&history),
                    outcome,
                    lines,
                    fee_count,
                    Some(lane.as_str()),
                    attribution,
                )
            }

            None if posted => seal.seal(
                &book,
                line,
                &durability_token,
                &principal,
                arrived,
                Some(&history),
                outcome,
                Vec::new(),
                0,
                None,
                attribution,
            ),
            None => return None,
        };
        match acknowledged {
            Ok(receipt) => receipt.confirm_terminal(),
            Err(error) => Some(TerminalConfirmation::failed(error)),
        }
    }
}

#[cfg(test)]
type JournalConfirmation =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;

#[cfg(test)]
struct LateBody {
    inner: Option<axum::body::Body>,

    arm: Option<LateAccrual>,
    confirmation: Option<JournalConfirmation>,
    journal: Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
}

#[cfg(test)]
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

#[cfg(test)]
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
            let confirmation: JournalConfirmation = Box::pin(async move {
                await_terminal(terminal).await?;
                journal
                    .flush()
                    .await
                    .map_err(|error| crate::root::cold::terminal_audit_unconfirmed(&error))
            });
            this.confirmation = Some(confirmation);
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

#[cfg(test)]
impl Drop for LateBody {
    fn drop(&mut self) {
        drop(self.inner.take());
        drop(self.fire());
    }
}

struct Occupied<'n> {
    node: &'n Node,
    reservation: TerminalReservation<'n>,

    post: Option<&'n NodeEndPost>,
    slot: Arc<busbar_kernel::inflight::UnitSlot>,

    arrived: Arrived,

    op_class: OpClassId,

    reached_end: bool,
}

// The teller has settled and the node has consumed its post, but the caller still owns
// the financial end until confirmation returns. Dropping that caller must retire the
// finished money entry even though neither the teller nor the driver is still running.
struct ConfirmingUnit<'a, R: RouteAwait> {
    route: Option<&'a R>,
    ctx: &'a UnitCtx,
}

impl<R: RouteAwait> Drop for ConfirmingUnit<'_, R> {
    fn drop(&mut self) {
        if let Some(route) = self.route.take() {
            route.abandoned(self.ctx, Ended::AlreadySettled);
        }
    }
}

pub(super) struct RetainedUnit {
    call: CallId,
    state: RetainedState,
}
impl RetainedUnit {
    fn reserved(call: CallId) -> Self {
        Self {
            call,
            state: RetainedState::Reserved,
        }
    }
}
enum RetainedState {
    Reserved,
    Abandoned(Lost),
    Native(native::NativeUnit),
    /// Test fixture only: an original's notary-facing custody without its live request owners.
    #[cfg(test)]
    Original {
        staged: Option<crate::root::durability::NativeStagedAudit>,
        receipt: Option<crate::root::durability::notary::original::OriginalLineReceipt>,
        credit: Option<busbar_contract::storage::StorageCredit>,
    },
}
struct TerminalReservation<'n> {
    node: &'n Node,
    class: AdmissionClass,
    key: UnitKey,
    call: CallId,
    active: bool,
}
impl Drop for TerminalReservation<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut book = self
            .node
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(book) = book.as_mut() else {
            return;
        };
        if book.get(self.class, self.key).is_some_and(|unit| {
            unit.call == self.call && matches!(unit.state, RetainedState::Reserved)
        }) {
            book.remove(self.class, self.key);
        }
    }
}

struct Lost {
    slot: Arc<busbar_kernel::inflight::UnitSlot>,
    arrived: Arrived,

    op_class: OpClassId,

    open: Option<OpenUnit>,
}

#[must_use = "a session slot dropped unfinished is marked for the sweep"]
pub(crate) struct SessionSlot<'n> {
    occupied: Occupied<'n>,
    key: UnitKey,
    ctx: UnitCtx,
    meter: Arc<AccrualMeter>,
    own: Option<busbar_kernel::teller::SessionOwn>,
}

impl std::fmt::Debug for SessionSlot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSlot")
            .field("key", &self.key)
            .finish()
    }
}

impl SessionSlot<'_> {
    #[cfg(test)]
    pub(crate) async fn finish(mut self, post: &NodeEndPost) -> Result<(), String> {
        let confirmation = self.finish_inner(post, None, Evidence::default());
        await_terminal(confirmation).await?;
        self.occupied.node.journal_failed()
    }

    pub(crate) async fn finish_with<U: Units>(
        mut self,
        post: &NodeEndPost,
        units: &U,
    ) -> Result<(), String> {
        let evidence = units.evidence(&self.ctx);
        let confirmation = self.finish_inner(post, None, evidence);
        await_terminal(confirmation).await?;
        self.occupied.node.journal_failed()
    }

    fn finish_inner(
        &mut self,
        post: &NodeEndPost,
        override_outcome: Option<Outcome>,
        evidence: Evidence,
    ) -> Option<TerminalConfirmation> {
        let node = self.occupied.node;
        let open = post.take(self.key);
        let outcome = override_outcome
            .or_else(|| open.as_ref().and_then(|o| o.sealing.said))
            .unwrap_or(Outcome::Aborted(busbar_contract::caps::Abort::Kernel {
                reason: busbar_contract::caps::ReasonCode::ClientGone,
            }));
        if let Some(reason) = refusal_reason(outcome) {
            busbar_kernel::telemetry::unit_refusal_on(
                busbar_kernel::plane_driver::dispatch::fallback_key(),
                reason.as_str(),
            );
        }
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
            None
        };
        self.occupied.reached_end = true;
        confirmation
    }
}

/// The closed reason a unit that did not complete ended under; `None` for a completed unit.
fn refusal_reason(outcome: Outcome) -> Option<busbar_contract::caps::ReasonCode> {
    match outcome {
        Outcome::Completed => None,
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason) => Some(reason),
        Outcome::Aborted(abort) => Some(abort.reason()),
        Outcome::TimedOut(_) => Some(busbar_contract::caps::ReasonCode::DeadlineExceeded),
    }
}

impl Drop for SessionSlot<'_> {
    fn drop(&mut self) {
        if self.own.is_some() {
            if let Some(post) = self.occupied.post {
                drop(self.finish_inner(
                    post,
                    Some(Outcome::Aborted(busbar_contract::caps::Abort::Kernel {
                        reason: busbar_contract::caps::ReasonCode::ClientGone,
                    })),
                    Evidence::default(),
                ));
            }
        }
    }
}

impl Drop for Occupied<'_> {
    fn drop(&mut self) {
        if self.reached_end {
            self.node.inflight.remove(self.slot.key());
        } else {
            let mut book = self
                .node
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = book
                .as_mut()
                .and_then(|book| book.get_mut(self.reservation.class, self.reservation.key))
                .expect("effects require an installed terminal reservation");
            assert!(
                entry.call == self.reservation.call
                    && matches!(entry.state, RetainedState::Reserved)
            );
            let open = self.post.and_then(|post| post.take(self.slot.key()));
            entry.state = RetainedState::Abandoned(Lost {
                slot: Arc::clone(&self.slot),
                arrived: self.arrived,
                op_class: self.op_class,
                open,
            });
            self.reservation.active = false;
            self.slot.mark();
            self.node.marked.fetch_add(1, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
fn journal_unavailable(proto: &str, why: &str) -> Response {
    busbar_kernel::ingress::ingress_error(
        proto,
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_contract::protocol::KIND_OVERLOADED,
        why,
    )
}

#[cfg(test)]
fn unavailable(proto: &str) -> Response {
    busbar_kernel::ingress::ingress_error(
        proto,
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_contract::protocol::KIND_OVERLOADED,
        "The service is temporarily overloaded. Please retry shortly.",
    )
}

#[cfg(test)]
struct Driven<'n> {
    node: &'n Node,
    route: &'n (dyn RouteAwait + Send + Sync),
    op_class: OpClassId,

    principal: &'n PrincipalId,

    arrived: Arrived,

    history: Option<&'n crate::root::kernel::PinnedHistory>,

    sealing: Mutex<Option<Accruing>>,
}

#[cfg(test)]
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

#[cfg(test)]
impl busbar_kernel::teller::UnitTaps for Driven<'_> {
    fn audited(&self, _ctx: &UnitCtx, facts: busbar_contract::caps::AuditFacts, pass: Pass<Audit>) {
        self.accruing().get_or_insert_with(Accruing::default).door = Some((facts, pass));
    }

    fn ended_as(&self, _ctx: &UnitCtx, _outcome: Outcome) {}

    fn routed(&self, _ctx: &UnitCtx, _destinations: &[VerifiedDestination]) {}
}

#[cfg(test)]
impl RouteAwait for Driven<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        seal_lanes(
            &mut self
                .accruing()
                .get_or_insert_with(Accruing::default)
                .ran
                .verified,
            destinations,
        );

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

pub(in crate::root) type OpenUnits = HashMap<UnitKey, OpenUnit>;

pub(in crate::root) struct OpenUnit {
    principal: PrincipalId,

    arrived: Arrived,

    history: Option<crate::root::kernel::PinnedHistory>,

    sealing: Accruing,
    checkpoint_class: Option<OpClassId>,
    checkpoint_origin: OriginKind,
}

pub(crate) struct NodeEndPost {
    pub(in crate::root) node: std::sync::Weak<Node>,
    pub(in crate::root) open: Vec<Mutex<OpenUnits>>,
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
    fn lock(&self, key: UnitKey) -> std::sync::MutexGuard<'_, OpenUnits> {
        self.open[(key.get() as usize) & (busbar_kernel::inflight::SHARDS - 1)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub(crate) fn node(&self) -> Option<Arc<Node>> {
        self.node.upgrade()
    }

    pub(crate) fn open(
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
            seal_lanes(&mut open.sealing.ran.verified, destinations);
        }
    }

    pub(crate) fn audited(
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

    pub(crate) fn stopped(&self, key: UnitKey, reason: busbar_contract::caps::ReasonCode) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.said = Some(Outcome::Refused(
                busbar_contract::caps::StepName::Route,
                reason,
            ));
        }
    }

    /// The drive's readings of the unit, taken before it seals (§9).
    pub(crate) fn measured(&self, key: UnitKey, measured: Measured) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.ran.measured = measured;
        }
    }

    pub(crate) fn reported(&self, key: UnitKey, report: Option<Reported>) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.report = report.and_then(Reported::legacy).map(Report::of);
        }
    }

    fn take(&self, key: UnitKey) -> Option<OpenUnit> {
        self.lock(key).remove(&key)
    }

    pub(crate) fn close(&self, key: UnitKey) {
        self.lock(key).remove(&key);
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn open_units(&self) -> usize {
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
            .map(|open| {
                open.sealing.ran.dialled = record.lane;
                open.sealing.ran.dial(record.lane);
            })
            .ok_or(busbar_kernel_egress::ports::DurabilityUnavailable)
    }

    fn abandoned(&self, record: &busbar_kernel_egress::ports::Dispatched) {
        if let Some(open) = self.lock(record.unit).get_mut(&record.unit) {
            open.sealing.ran.cancel_latest();
        }
    }
}

impl busbar_kernel::plane_driver::HookJournal for NodeEndPost {
    fn hooks_ran(&self, record: &busbar_kernel::plane_driver::HooksRan<'_>) {
        if let Some(open) = self.lock(record.unit).get_mut(&record.unit) {
            open.sealing.ran.hooks.extend(record.hooks.iter().cloned());
        }
    }

    fn keeps_end_user(&self) -> bool {
        crate::root::records_capture::keeps_user()
    }

    /// `records.user` (ADMIN-API-1.6 §3.5): the end user as the record keeps it, a pseudonym or
    /// the cut plain value, onto the unit's record-to-be.
    fn end_user(&self, unit: UnitKey, user: &str) {
        let Some(kept) = crate::root::records_capture::user(user) else {
            return;
        };
        if let Some(open) = self.lock(unit).get_mut(&unit) {
            open.sealing.ran.records.user = Some(kept);
        }
    }

    /// `records.labels` (ADMIN-API-1.6 §3.5): the allow-listed headers, copied at Decode. Off,
    /// nothing is copied and no lock is taken.
    fn decoded_fields(&self, unit: UnitKey, fields: &[(Vec<u8>, Vec<u8>)]) {
        let labels = crate::root::records_capture::labels(fields);
        if labels.is_empty() {
            return;
        }
        if let Some(open) = self.lock(unit).get_mut(&unit) {
            open.sealing.ran.records.labels = labels;
        }
    }
}

/// A unit's captured checkpoint facts, borrowed from the open unit: the fields of
/// [`crate::root::durability::RunningAudit`], in its order and its shapes, so they serialize to the
/// very bytes that record reads back.
#[derive(serde::Serialize)]
struct RunningAuditFacts<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_identity: Option<SelectedIdentityFacts<'a>>,
    incarnation: u64,
    principal: &'a str,
    op_class: &'a str,
    origin: &'a str,
    parent: Option<u64>,
    wall: u64,
    mono: u64,
    destination: Option<&'a str>,
    rate_card: Option<[u8; 20]>,
    policy_epoch: u64,
    hooks: HookFacts<'a>,
}

/// The selected identity a checkpoint captures, borrowed from the open unit: the fields of
/// [`crate::root::durability::SelectedAuditIdentity`], in its order and its shapes, so they
/// serialize to the very bytes that record reads back. Capturing it copies nothing.
#[derive(serde::Serialize)]
struct SelectedIdentityFacts<'a> {
    node: u64,
    boot_nonce: [u8; 16],
    user: Option<&'a str>,
    labels: LabelFacts<'a>,
}

/// A unit's kept request labels, spelled as the record's `(name, value)` pairs.
struct LabelFacts<'a>(&'a [(Arc<str>, String)]);

impl serde::Serialize for LabelFacts<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(
            self.0
                .iter()
                .map(|(name, value)| (name.as_ref(), value.as_str())),
        )
    }
}

/// The hooks a unit ran, spelled as the record's `(hook, head, failed)` triples.
struct HookFacts<'a>(&'a [HookApplied]);

impl serde::Serialize for HookFacts<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(
            self.0
                .iter()
                .map(|hook| (hook.hook.as_str(), hook.head.as_str(), hook.failed)),
        )
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
        let node = self.node()?;
        let book = node.book.get()?.lock().unwrap_or_else(|p| p.into_inner());
        let captured = RunningAuditFacts {
            selected_identity: Some(SelectedIdentityFacts {
                node: book.record.node(),
                boot_nonce: busbar_kernel::snapshot::boot_nonce(),
                user: open.sealing.ran.records.user.as_deref(),
                labels: LabelFacts(&open.sealing.ran.records.labels),
            }),
            incarnation: book.incarnation,
            principal: open.principal.as_str(),
            op_class: open.checkpoint_class?.as_str(),
            origin: open.checkpoint_origin.as_str(),
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
            hooks: HookFacts(&open.sealing.ran.hooks),
        };
        busbar_kernel::json::to_vec(&captured).ok()
    }

    fn post(&self, ctx: &UnitCtx, ended: Ended) {
        // Failed upgrade is permanent forced destruction of the original Node, not a
        // retry against a replacement Node and never a successful terminal acknowledgement.
        let Some(node) = self.node() else {
            return;
        };
        let facts = self.lock(ctx.key).remove(&ctx.key);
        if let Some(open) = facts {
            let parent = match ctx.origin {
                OriginKind::Nested { parent } => Some(parent),
                _ => None,
            };
            let seal = open
                .sealing
                .into_seal(ctx.key, node.kernel.origin(ctx.origin), parent);
            node.seal_end(
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

pub(crate) struct Parent {
    key: UnitKey,
    slot: Arc<busbar_kernel::inflight::UnitSlot>,
}

impl Parent {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn key(&self) -> UnitKey {
        self.key
    }

    #[must_use]
    pub(crate) fn cell(&self) -> &busbar_contract::caps::HoldCell {
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
    /// What the drive measured at the unit's end (ADMIN-API-1.6 §9): copies, no allocation.
    measured: Measured,
    /// The first dials of the unit's walks, in the order they were made (§9).
    walked: [Option<Walked>; ATTEMPT_SLOTS],
    /// Every dial made, including those beyond the slots.
    walked_total: u32,
    /// What `records.user` and `records.labels` keep of the unit (ADMIN-API-1.6 §3.5): empty, with
    /// no allocation, unless the operator switched them on.
    records: busbar_kernel_audit::RecordFacts,
}

/// The drive's clock and the caller it reads the unit's first write and status from (§9).
pub(crate) struct Timing<'a> {
    /// When the drive began the unit.
    pub(crate) started: std::time::Instant,
    /// The caller the unit wrote its reply through.
    pub(crate) caller: &'a (dyn crate::root::serve::Stated + Sync),
}

impl Timing<'_> {
    /// Read the unit's three measurements: one monotonic read, and atomic loads.
    fn read(&self) -> Measured {
        let total = u64::try_from(
            busbar_core_connector::framer::now()
                .saturating_duration_since(self.started)
                .as_micros(),
        )
        .unwrap_or(u64::MAX);
        let first_ns = self.caller.first_write_ns();
        Measured {
            status: self
                .caller
                .stated()
                .and_then(|s| u16::try_from(s).ok())
                .unwrap_or(0),
            ttft_us: if first_ns == 0 {
                0
            } else {
                (first_ns / 1_000).max(1)
            },
            total_us: total.max(1),
        }
    }
}

/// The three readings the drive takes of a unit before it seals: all `0` when not measured.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct Measured {
    /// The status the caller was answered with.
    pub(crate) status: u16,
    /// Microseconds to the first body write.
    pub(crate) ttft_us: u64,
    /// Microseconds until the last frame was handed over.
    pub(crate) total_us: u64,
}

/// One dial of an egress walk, as the journal port saw it: copies only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Walked {
    lane: Option<LaneId>,
    cancelled: bool,
}

impl Ran {
    /// A dial is about to be made: the first [`ATTEMPT_SLOTS`] are kept, the rest only counted.
    fn dial(&mut self, lane: Option<LaneId>) {
        if let Some(slot) = self.walked.get_mut(self.walked_total as usize) {
            *slot = Some(Walked {
                lane,
                cancelled: false,
            });
        }
        self.walked_total = self.walked_total.saturating_add(1);
    }

    /// The latest dial never produced an answer.
    fn cancel_latest(&mut self) {
        let latest = (self.walked_total as usize).checked_sub(1);
        if let Some(Some(walked)) = latest.and_then(|i| self.walked.get_mut(i)) {
            walked.cancelled = true;
        }
    }

    /// The attempts a `v7` record seals, given how the unit ended: every dial but the last moved
    /// on, and the last answered when the unit completed and failed when it did not.
    fn attempts(&self, outcome: Outcome) -> ([Option<Attempt>; ATTEMPT_SLOTS], u32) {
        let mut out: [Option<Attempt>; ATTEMPT_SLOTS] = Default::default();
        let total = self.walked_total as usize;
        for (i, (slot, walked)) in out.iter_mut().zip(&self.walked).enumerate() {
            let Some(walked) = walked else { break };
            let last = i + 1 == total;
            let (kind, reason) = if walked.cancelled {
                (AttemptOutcome::Cancelled, "")
            } else if !last {
                (AttemptOutcome::Failover, "")
            } else if outcome.is_completed() {
                (AttemptOutcome::Ok, "")
            } else {
                (AttemptOutcome::Failed, attempt_reason(outcome))
            };
            // A lane's name and a reason code's text are fixed in the program: the attempt names
            // them and copies neither.
            *slot = Some(Attempt {
                outcome: kind,
                target: walked.lane.map_or(Text::EMPTY, |l| Text::fixed(l.as_str())),
                reason: Text::fixed(reason),
                us: 0,
            });
        }
        (out, self.walked_total)
    }
}

/// The reason text an unfinished unit's last attempt carries.
fn attempt_reason(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason) => reason.as_str(),
        Outcome::TimedOut(_) => "timed_out",
        Outcome::Completed | Outcome::Aborted(_) => "",
    }
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

// Serving waits for both native confirmation and ticket readiness. The awaiting
// task runs the confirmation itself; a confirmation dropped unfinished (never
// awaited, or its awaiter cancelled mid-confirm) is restarted in one detached
// task, so cancellation never abandons its original. `confirm` is cancel-safe.
fn preview_confirmation(
    outcome: Option<Outcome>,
    seal: Option<Sealing>,
) -> Option<TerminalConfirmation> {
    let (Some(_), Some(_)) = (seal, outcome) else {
        return None;
    };
    // A partitioned usage preview is never terminal custody: refuse the seal.
    Some(TerminalConfirmation {
        inner: Err("selected audit requires final reader custody, not a usage preview".into()),
    })
}

struct TerminalConfirmation {
    inner: Result<Option<TerminalTask>, String>,
}

enum TerminalTask {
    Staged(Confirm),
}

impl TerminalTask {
    async fn run(&mut self) -> Result<(), String> {
        match self {
            Self::Staged(confirm) => confirm.run().await,
        }
    }
}

struct Confirm {
    audit: StagedAudit,
}

impl Confirm {
    async fn run(&mut self) -> Result<(), String> {
        let confirmed = self.audit.journal.confirm(&self.audit.run).await;
        if confirmed.is_ok() {
            crate::root::durability::records_pulse().notify_waiters();
        }
        confirmed.map_err(|error| crate::root::cold::terminal_audit_unconfirmed(&error))
    }
}

impl TerminalConfirmation {
    fn failed(error: busbar_contract::caps::DurabilityLost) -> Self {
        Self {
            inner: Err(crate::root::cold::terminal_audit_stage_failed(&error)),
        }
    }

    async fn wait(mut self) -> Result<(), String> {
        let Some(inner) = self.inner.as_mut().map_err(|error| error.clone())? else {
            return Ok(());
        };
        let confirmed = inner.run().await;
        self.inner = Ok(None);
        confirmed
    }
}

impl Drop for TerminalConfirmation {
    fn drop(&mut self) {
        let Ok(Some(mut inner)) = std::mem::replace(&mut self.inner, Ok(None)) else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move {
                let _ = inner.run().await;
            }));
        }
    }
}

async fn await_terminal(confirmation: Option<TerminalConfirmation>) -> Result<(), String> {
    match confirmation {
        Some(confirmation) => confirmation.wait().await,
        None => Ok(()),
    }
}

struct StagedAudit {
    journal: Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
    run: Arc<busbar_kernel::persistence::journal::runtime::StagedRun>,
}
impl StagedAudit {
    fn confirm_terminal(self) -> Option<TerminalConfirmation> {
        tokio::runtime::Handle::try_current().ok()?;
        Some(TerminalConfirmation {
            inner: Ok(Some(TerminalTask::Staged(Confirm { audit: self }))),
        })
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

/// Record the unit's verified lanes in its own list, reusing the list's room.
fn seal_lanes(verified: &mut Vec<LaneId>, destinations: &[VerifiedDestination]) {
    verified.clear();
    verified.extend(destinations.iter().map(|d| *d.lane()));
}

impl Ran {
    fn destination<'s>(&self, served: Option<&'s str>) -> Option<&'s str> {
        let lane = match (self.dialled, served) {
            (Some(dialled), _) => Some(dialled.as_str()),
            (None, Some(served)) if verified_lane(&self.verified, served) => Some(served),

            (None, _) => match self.verified.as_slice() {
                [only] => Some(only.as_str()),
                _ => None,
            },
        };
        lane
    }
}

/// Whether `lane` is one of the unit's own verified lanes (a handful, sealed per unit).
fn verified_lane(verified: &[LaneId], lane: &str) -> bool {
    verified.iter().any(|v| v.as_str() == lane)
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
    assert_eq!(ran.destination(billing), Some(b.as_str()));
    ran.verified = vec![a, b];
    assert_eq!(
        ran.destination(billing),
        None,
        "no choice between verified entries"
    );
    assert_eq!(ran.destination(Some(a.as_str())), Some(a.as_str()));
    ran.dialled = Some(b);
    assert_eq!(ran.destination(Some(a.as_str())), Some(b.as_str()));
}

/// The selected identity a checkpoint captures is borrowed from the open unit; what it writes
/// is byte for byte what the owned record ([`crate::root::durability::SelectedAuditIdentity`])
/// writes and reads back, with a user and without, with labels and without.
#[cfg(test)]
#[test]
fn the_captured_selected_identity_is_the_bytes_its_record_reads_back() {
    let kept: Vec<(Arc<str>, String)> = vec![
        (Arc::from("x-team"), "blue".to_owned()),
        (Arc::from("x-env"), "prod \"quoted\"".to_owned()),
    ];
    let none: &[(Arc<str>, String)] = &[];
    for labels in [&kept[..], none] {
        for user in [None, Some("user-1")] {
            let borrowed = SelectedIdentityFacts {
                node: 7,
                boot_nonce: [0xab; 16],
                user,
                labels: LabelFacts(labels),
            };
            let owned = crate::root::durability::SelectedAuditIdentity {
                node: 7,
                boot_nonce: [0xab; 16],
                user: user.map(str::to_owned),
                labels: labels
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.clone()))
                    .collect(),
            };
            let written = busbar_kernel::json::to_vec(&borrowed).expect("it serializes");
            assert_eq!(
                Some(&written),
                busbar_kernel::json::to_vec(&owned).ok().as_ref()
            );
        }
    }
}

/// RED (ADMIN-API-1.6 §9): a walk that failed over seals one attempt per dial, the earlier ones
/// `failover` and the last by how the unit ended; dials beyond the slots are only counted.
#[cfg(test)]
#[test]
fn attempts_recorded_on_failover() {
    use busbar_contract::caps::{ReasonCode, StepName};
    let a = LaneId::new("pool\u{1f}a");
    let b = LaneId::new("pool\u{1f}b");

    let mut ran = Ran::default();
    ran.dial(Some(a));
    ran.dial(Some(b));
    let (attempts, total) = ran.attempts(Outcome::Completed);
    assert_eq!(total, 2);
    let kinds: Vec<_> = attempts
        .iter()
        .flatten()
        .map(|t| (t.target.as_str(), t.outcome))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (a.as_str(), AttemptOutcome::Failover),
            (b.as_str(), AttemptOutcome::Ok)
        ]
    );

    let failed = Outcome::Failed(StepName::Arrival, ReasonCode::PlanePanic);
    let (attempts, _) = ran.attempts(failed);
    let last = attempts[1].as_ref().map(|t| (t.outcome, t.reason.as_str()));
    assert_eq!(
        last,
        Some((AttemptOutcome::Failed, ReasonCode::PlanePanic.as_str()))
    );

    ran.cancel_latest();
    let (attempts, _) = ran.attempts(Outcome::Completed);
    assert_eq!(
        attempts[1].as_ref().map(|t| t.outcome),
        Some(AttemptOutcome::Cancelled)
    );

    let mut many = Ran::default();
    for _ in 0..6 {
        many.dial(Some(a));
    }
    let (attempts, total) = many.attempts(Outcome::Completed);
    assert_eq!(total, 6, "dials beyond the slots are counted");
    assert!(
        attempts.iter().all(Option::is_some),
        "the first four are kept"
    );

    let (none, zero) = Ran::default().attempts(Outcome::Completed);
    assert_eq!((zero, none.iter().flatten().count()), (0, 0));
}

impl Sealing {
    fn seal(
        self,
        book: &Arc<Mutex<crate::root::durability::Durability>>,
        line: Option<crate::root::durability::LineIdentity>,
        token: &Grant<busbar_contract::caps::DurableWrite>,
        principal: &PrincipalId,
        arrived: Arrived,
        card: Option<&crate::root::kernel::PinnedHistory>,
        outcome: Outcome,
        lines: Vec<RecordLine>,
        fee_count: u32,
        served: Option<&str>,
        attribution: String,
    ) -> Result<StagedAudit, busbar_contract::caps::DurabilityLost> {
        self.seal_billing(
            book,
            line,
            token,
            principal,
            arrived,
            card,
            outcome,
            lines,
            fee_count,
            served,
            attribution,
            None,
        )
    }

    fn seal_billing(
        self,
        book: &Arc<Mutex<crate::root::durability::Durability>>,
        line: Option<crate::root::durability::LineIdentity>,
        token: &Grant<busbar_contract::caps::DurableWrite>,
        principal: &PrincipalId,
        arrived: Arrived,
        card: Option<&crate::root::kernel::PinnedHistory>,
        outcome: Outcome,
        lines: Vec<RecordLine>,
        fee_count: u32,
        served: Option<&str>,
        attribution: String,
        billing: Option<busbar_kernel_audit::record::billing::PartitionedBillingV1>,
    ) -> Result<StagedAudit, busbar_contract::caps::DurabilityLost> {
        let Sealing { seal, ran } = self;
        let (attempts, attempts_total) = ran.attempts(outcome);
        let measured = ran.measured;
        let refused = matches!(outcome, Outcome::Refused(..));

        let hook_failed = ran.hooks.iter().any(|hook| hook.failed);
        let destination = ran.destination(served).map(str::to_owned);
        let controls = Controls {
            policy_epoch: policy_in_force(card, arrived.ms()),
            hooks_applied: ran.hooks,
            ..Controls::default()
        };
        let inputs = AuditInputs {
            subject: Subject::PrincipalId(principal.text().clone()),
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
                lines: if refused || billing.is_some() {
                    Vec::new()
                } else {
                    lines
                },
                tier_bp: 10_000,
                fee_count: billing
                    .as_ref()
                    .map_or(if refused { 0 } else { fee_count }, |billing| {
                        billing.fee_count()
                    }),
                rate_card_version: card_in_force(card, arrived.ms()),
                bucket_chain_ref: String::new(),
            },
            controls,
            correlation_label: None,
            // Recipe v7 (ADMIN-API-1.6 §3.2): copies of what the unit already holds, and the one
            // attribution text its report built.
            unit: busbar_kernel_audit::UnitFacts {
                billing,
                wall_ms: arrived.ms(),
                attribution,
                boot_nonce: busbar_kernel::snapshot::boot_nonce(),
                status: measured.status,
                ttft_us: measured.ttft_us,
                total_us: measured.total_us,
                attempts,
                attempts_total,
                records: ran.records,
            },
        };
        let unit = seal.key.get();
        // The line is built and its content hashed BEFORE the book's lock (SEALING-FIX §3.2): the
        // lock covers only the clock read, the link trailer, the stage and the head publish. The
        // request path never signs; the notary stamps pages off this path.
        let (journal, run, hints) = match line {
            Some(id) => {
                let mut inputs = inputs;
                inputs.what.incarnation = id.incarnation;
                let prepared = busbar_kernel_audit::AuditChain::prepare(inputs, id.node);
                let mut book = book.lock().unwrap_or_else(|poison| poison.into_inner());
                let journal = book.journal.clone();
                let (_, run) = book.stage_prepared(prepared, &seal.pass, token)?;
                (journal, run, book.audit_hints.clone())
            }
            None => {
                let mut book = book.lock().unwrap_or_else(|poison| poison.into_inner());
                let journal = book.journal.clone();
                let (_, run) = book.stage_line(inputs, seal.pass, token)?;
                (journal, run, book.audit_hints.clone())
            }
        };
        // The unit's checkpoint removal reads this one line by the evidence sealed here, not by a
        // journal scan (SHUTDOWN-HANG F1a). A unit with no checkpoint entry is a counted miss.
        if let Some(gov) = hints.as_ref().and_then(std::sync::Weak::upgrade) {
            if gov.unit_checkpoints_enabled() {
                if let Some(line) = run.carried().next() {
                    gov.note_unit_audit(unit, line.seq, line.hash).ok();
                }
            }
        }
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
pub(crate) fn node() -> Arc<Node> {
    Arc::clone(&NODE)
}

#[cfg(any(test, distribution_root))]
pub(crate) fn bind_book(book: Arc<Mutex<crate::root::durability::Durability>>) {
    bind_node_book(&NODE, &crate::root::kernel::ROOT_CARD, book);
}

#[cfg(any(test, distribution_root))]
pub(crate) const ROOT_UNIT: crate::root::linked::RootUnit = crate::root::linked::RootUnit {
    seal: None,
    on_config: Some(|_| crate::root::kernel::install_card_repricer()),
    #[cfg(test)]
    opens_book: true,
    on_book: Some(|ctx| bind_book(Arc::clone(&ctx.book.durability))),
};

#[cfg(any(test, distribution_root))]
fn bind_node_book(
    node: &Node,
    cards: &crate::root::kernel::RootHistory,
    book: Arc<Mutex<crate::root::durability::Durability>>,
) {
    let _ = cards;
    node.bind_book(book);
}

#[cfg(test)]
#[path = "tests/plane_node.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/plane_node_seal.rs"]
mod seal_tests;

#[cfg(test)]
#[path = "tests/plane_node_money.rs"]
mod node_money_tests;

#[cfg(test)]
#[test]
fn checkpoint_facts_serialize_to_the_running_audit_record_bytes() {
    let hooks = [
        HookApplied {
            hook: Text::fixed("guard"),
            head: busbar_kernel_audit::HookHead::Modify,
            failed: false,
        },
        HookApplied {
            hook: Text::fixed("late"),
            head: busbar_kernel_audit::HookHead::Veto,
            failed: true,
        },
    ];
    let borrowed = RunningAuditFacts {
        selected_identity: None,
        incarnation: 7,
        principal: "key-1",
        op_class: "chat",
        origin: "direct",
        parent: Some(3),
        wall: 1_700_000_000,
        mono: 42,
        destination: Some("llm\u{1f}openai"),
        rate_card: Some([9; 20]),
        policy_epoch: 5,
        hooks: HookFacts(&hooks),
    };
    let owned = crate::root::durability::RunningAudit {
        selected_identity: None,
        incarnation: 7,
        principal: "key-1".to_owned(),
        op_class: "chat".to_owned(),
        origin: "direct".to_owned(),
        parent: Some(3),
        wall: 1_700_000_000,
        mono: 42,
        destination: Some("llm\u{1f}openai".to_owned()),
        rate_card: Some([9; 20]),
        policy_epoch: 5,
        hooks: vec![
            ("guard".to_owned(), "modify".to_owned(), false),
            ("late".to_owned(), "veto".to_owned(), true),
        ],
    };
    assert_eq!(
        busbar_contract::json::to_vec(&borrowed).unwrap(),
        busbar_contract::json::to_vec(&owned).unwrap()
    );
    let empty = RunningAuditFacts {
        destination: None,
        parent: None,
        rate_card: None,
        hooks: HookFacts(&[]),
        ..borrowed
    };
    let empty_owned = crate::root::durability::RunningAudit {
        destination: None,
        parent: None,
        rate_card: None,
        hooks: Vec::new(),
        ..owned
    };
    assert_eq!(
        busbar_contract::json::to_vec(&empty).unwrap(),
        busbar_contract::json::to_vec(&empty_owned).unwrap()
    );
}
