// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use foldhash::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use busbar_contract::caps::CallId;
use busbar_contract::caps::{
    Audit, Grant, OpClassId, OriginKind, Outcome, Pass, PrincipalId, VerifiedDestination,
};
use busbar_contract::kept::Text;
use busbar_contract::{LaneId, UnitKey};
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
#[path = "plane_node/terminal_book.rs"]
mod terminal_book;
use busbar_kernel::teller::{Ended, UnitCtx};
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

#[path = "plane_node/money_gate.rs"]
mod money_gate;
#[path = "plane_node/native.rs"]
mod native;
#[cfg(test)]
pub(crate) use native::retained_fixture;
pub(crate) use native::{
    deliver_original_page, fee_debt_owner, fund_original_page, NativeNodeHandle,
};

/// The op class of the one aggregate line per (listener, reason) of refused requests that had no
/// identity, per flush interval (design 2, A5).
pub(crate) const REFUSALS_OP_CLASS: &str = "refusals";

/// The op class of the line a metered response waits for under `advanced.wait_for_commit`.
pub(crate) const RESPONSE_OP_CLASS: &str = "response";

struct ResponseIntentOwner {
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

pub(crate) struct Node {
    kernel: Arc<busbar_kernel::teller::Kernel>,
    pub(in crate::root) inflight: busbar_kernel::inflight::InFlight,
    gauge: busbar_kernel::slice::ConcurrencyGauge,
    door: crate::root::kernel::AdmissionDoor,

    #[cfg(test)]
    lanes: Arc<Mutex<Registration>>,

    next_key: Arc<busbar_kernel::door::UnitKeyMint>,

    lost: Arc<RetainedBook>,

    mono: AtomicU64,

    /// The money seams of the native serving generations, held weakly: what the exit walk reads
    /// for its open-units report (SHUTDOWN-HANG F4). A generation that a reload replaced stays
    /// listed while one of its units is still open and drops out when its seam is destroyed.
    native_money: Mutex<Vec<std::sync::Weak<busbar_kernel::plane_driver::PlaneMoney>>>,

    /// The clock a unit's arrival is read from: once, at the door, and every window it is
    /// admitted and billed in is the one that reading names.
    clock: Arc<dyn busbar_kernel::Clock>,

    book: std::sync::OnceLock<Arc<Mutex<crate::root::durability::Durability>>>,

    lane: std::sync::OnceLock<Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>>,
    /// The money gate is in a refusal episode (logged once at its start and once at its end).
    money_refusing: std::sync::atomic::AtomicBool,
    /// Billable opens refused because the journal could not record money.
    money_refusals: AtomicU64,
    response_intent: std::sync::OnceLock<ResponseIntentOwner>,

    /// The cores' audit state and the flusher that pulls it (design 2, A3).
    cores: crate::root::durability::core_audit::CoreFlusher,

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
        let kernel = crate::root::kernel::new_kernel();
        Self {
            durability_token: kernel.durability_token(),
            book: std::sync::OnceLock::new(),
            lane: std::sync::OnceLock::new(),
            money_refusing: std::sync::atomic::AtomicBool::new(false),
            money_refusals: AtomicU64::new(0),
            response_intent: std::sync::OnceLock::new(),
            cores: crate::root::durability::core_audit::CoreFlusher::default(),
            sealing: std::sync::OnceLock::new(),
            kernel: Arc::new(kernel),

            inflight: busbar_kernel::inflight::InFlight::new(usize::MAX),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            door: crate::root::kernel::AdmissionDoor,
            #[cfg(test)]
            lanes: Arc::new(Mutex::new(crate::root::kernel::new_registration())),
            next_key: Arc::default(),
            lost: Arc::new(RetainedBook(Mutex::new(Self::fixture_terminal_book()))),
            mono: AtomicU64::new(0),
            native_money: Mutex::new(Vec::new()),
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

    /// The account a native dial's framer session is charged to: the bound boot admission's Data class, the account
    /// inbound connections are charged to. `None` before the boot binds it.
    pub(crate) fn dial_storage(&self) -> Option<busbar_contract::storage::StorageSource> {
        self.lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(TerminalBook::data_source)
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

    /// Reserve `key`'s terminal-book entry in `class`'s partition before any effect; `None` when
    /// the book is unbound or that partition is full. Test-only here: the door unit entries that
    /// reserved through it are deleted, and a native unit inserts itself (`plane_node/native.rs`).
    /// Kept so the book's two storage refusals stay proven through the node.
    #[cfg(test)]
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
            .insert(
                class,
                key,
                RetainedUnit {
                    call,
                    state: RetainedState::Original {
                        staged: None,
                        receipt: None,
                        credit: None,
                    },
                },
            )
            .ok()?;
        Some(TerminalReservation {
            node: self,
            class,
            key,
            call,
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

    /// Response finalization can refuse exhausted identity before publishing any output.
    /// All node stamps share this allocator, so an ordinary arrival cannot wrap it first.
    pub(crate) fn checked_arrived(&self) -> Result<Arrived, &'static str> {
        let mono = self.checked_mono()?;
        Ok(Arrived::at(self.clock.now(), mono))
    }

    /// The node's next monotonic reading alone, for an operation whose wall reading was already
    /// taken once (an admin request's arrival): the pair a record stamps is that one wall reading
    /// and this one ordering reading, never a unit key standing in for either.
    pub(crate) fn checked_mono(&self) -> Result<u64, &'static str> {
        self.mono
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "node monotonic clock exhausted")
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn lanes(&self) -> Arc<Mutex<Registration>> {
        Arc::clone(&self.lanes)
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
            .set(ResponseIntentOwner { service })
            .map_err(|_| "response intent owner already installed")
    }

    pub(crate) fn response_intents(
        &self,
    ) -> Option<Arc<crate::root::durability::response_intent::ResponseIntentService>> {
        self.response_intent
            .get()
            .map(|owner| Arc::clone(&owner.service))
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
    /// Settle in-doubt store attempts (≤ 64 per tick) and publish `busbar_store_slots`.
    pub(crate) async fn settle_store(&self) {
        let Some(journal) = self.lane.get() else {
            return;
        };
        self.close_money_episode(journal);
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
    /// Why a request that would create a record must be refused now, judged by the age of the
    /// flusher's last good commit (design 2, A8), never by a count of held records: the journal
    /// failed for this process, or nothing has been committed for longer than the stall limit.
    #[must_use]
    pub(crate) fn journal_refusal(&self) -> Option<String> {
        // The flusher's stall is one of the journal's money-refusal causes (`State::refusal`).
        self.lane.get().and_then(|journal| journal.refuses_money())
    }

    /// A new core's audit state, pulled by this node's flusher (design 2, A1). The core's
    /// listener loop owns it and hands it to each connection.
    pub(crate) fn core_audit(&self) -> Arc<crate::root::durability::core_audit::CoreAudit> {
        self.cores.core()
    }

    /// ONE FLUSH (design 2, A3): pull every core, link each line into the chain in monotonic
    /// order, write one aggregate line per non-zero (listener, reason) refusal count of the
    /// interval, and commit the group with everything else the journal holds. The notary signs the
    /// head this publishes. What could not be staged or committed is carried to the next flush;
    /// waiters are released only by a commit that holds their item.
    pub(crate) async fn flush_cores(&self) -> Result<(), String> {
        let (Some(book), Some(journal)) = (self.book.get(), self.lane.get()) else {
            return Ok(());
        };
        let (from_ms, to_ms) = self.cores.interval(self.clock.now());
        let mut pulled = self.cores.pull();
        // Judged without this flusher's own stall report, which must never stop its recovery.
        if let Some(why) = journal.refuses_staging() {
            self.cores.carry(pulled);
            return Err(why);
        }
        let refusals = std::mem::take(&mut pulled.refusals);
        // A stage the journal refuses after `refuses_staging` passed (its buffer filled during
        // this pull, say) hands its line back: it and every line after it are kept, in order, for
        // the next flush, and nothing of this pull is settled. A line is never dropped, so a later
        // commit can never settle the waiter of a line it does not hold.
        let mut refused = false;
        let mut unstaged = Vec::new();
        {
            let mut held = book
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let pass = busbar_kernel::teller::verb_audit_pass(&self.kernel);
            for prepared in std::mem::take(&mut pulled.kept) {
                if refused {
                    pulled.kept.push(prepared);
                    continue;
                }
                if let Err((_, back)) = held.stage_kept(prepared, &pass, &self.durability_token) {
                    refused = true;
                    pulled.kept.push(back);
                }
            }
            for (core, inputs) in std::mem::take(&mut pulled.lines) {
                if refused {
                    unstaged.push((core, inputs));
                    continue;
                }
                let prepared = held.prepare_line(inputs);
                if let Err((_, back)) = held.stage_kept(prepared, &pass, &self.durability_token) {
                    refused = true;
                    pulled.kept.push(back);
                }
            }
            for count in refusals {
                let staged = !refused
                    && self.checked_mono().is_ok_and(|mono| {
                        let inputs = self.refusal_line(&count, from_ms, to_ms, mono);
                        let pass = busbar_kernel::teller::verb_audit_pass(&self.kernel);
                        held.stage_line(inputs, pass, &self.durability_token)
                            .is_ok()
                    });
                if !staged {
                    pulled.refusals.push(count);
                }
            }
        }
        let flushed = journal.flush().await;
        if refused || !pulled.refusals.is_empty() {
            let kept = pulled.kept.len() + unstaged.len();
            pulled.lines = unstaged;
            self.cores.carry(pulled);
            return Err(format!(
                "audit staging refused ({kept} lines kept for the next flush)"
            ));
        }
        match flushed {
            Ok(()) => {
                for (core, through) in pulled.cores {
                    core.records().settled(through);
                }
                self.cores.good(tokio::time::Instant::now());
                Ok(())
            }
            Err(error) => {
                // Staged lines stay with the journal, which retries them; their waiters are
                // released by the next flush that commits.
                self.cores.carry(pulled);
                Err(crate::root::cold::native_journal_refused(&error))
            }
        }
    }

    /// The line a metered response hands over under `advanced.wait_for_commit` (design 2, A7):
    /// its principal, its unit, the time its response was registered (this node's one reading for
    /// it) and, filled at release, its status. Its unit's own line, with usage, follows after
    /// delivery as without the setting; this one is what the release waited for.
    pub(crate) fn response_line(
        &self,
        admission: &busbar_kernel::plane_driver::request_admission::AdmittedRequest,
    ) -> Result<AuditInputs, &'static str> {
        let registered = self.checked_arrived()?;
        let card = crate::root::kernel::ROOT_CARD.pin();
        Ok(AuditInputs {
            subject: Subject::PrincipalId(admission.key().id.as_str().into()),
            what: What {
                unit_key: admission.unit(),
                incarnation: 0,
                op_class: RecordOpClass::new(RESPONSE_OP_CLASS),
                destination: None,
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: registered.secs(),
            mono: registered.mono(),
            origin: self.kernel.origin(OriginKind::Client),
            outcome: OutcomeFacts {
                unit_end: Outcome::Completed,
                step: None,
                finish: RecordFinish::Complete,
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            usage: RecordUsage {
                lines: Vec::new(),
                tier_bp: 10_000,
                fee_count: 0,
                rate_card_version: card_in_force(card.as_ref(), registered.ms()),
                bucket_chain_ref: String::new(),
            },
            controls: Controls {
                policy_epoch: policy_in_force(card.as_ref(), registered.ms()),
                ..Controls::default()
            },
            correlation_label: None,
            unit: busbar_kernel_audit::UnitFacts {
                boot_nonce: busbar_kernel::snapshot::boot_nonce(),
                ..busbar_kernel_audit::UnitFacts::at(registered.ms())
            },
        })
    }

    /// The one aggregate line for `count` refusals of one (listener, reason) between `from_ms`
    /// and `to_ms`: subject `Aggregate`, op class `refusals`, the listener in `destination`, the
    /// count in `attempts_total`, the interval's start in `wall_ms` and its end in `wall`.
    fn refusal_line(
        &self,
        count: &crate::root::durability::core_audit::RefusalCount,
        from_ms: u64,
        to_ms: u64,
        mono: u64,
    ) -> AuditInputs {
        let card = crate::root::kernel::ROOT_CARD.pin();
        AuditInputs {
            subject: Subject::Aggregate,
            what: What {
                unit_key: self.mint(),
                incarnation: 0,
                op_class: RecordOpClass::new(REFUSALS_OP_CLASS),
                destination: Some(count.listener.to_string()),
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: to_ms / 1_000,
            mono,
            origin: self.kernel.origin(OriginKind::Arrival),
            outcome: OutcomeFacts {
                unit_end: Outcome::Refused(count.step, count.reason),
                step: Some(count.step),
                finish: RecordFinish::Error,
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            usage: RecordUsage {
                lines: Vec::new(),
                tier_bp: 10_000,
                fee_count: 0,
                rate_card_version: card_in_force(card.as_ref(), to_ms),
                bucket_chain_ref: String::new(),
            },
            controls: Controls {
                policy_epoch: policy_in_force(card.as_ref(), to_ms),
                ..Controls::default()
            },
            correlation_label: None,
            unit: busbar_kernel_audit::UnitFacts {
                status: count.status,
                attempts_total: u32::try_from(count.count).unwrap_or(u32::MAX),
                boot_nonce: busbar_kernel::snapshot::boot_nonce(),
                ..busbar_kernel_audit::UnitFacts::at(from_ms)
            },
        }
    }

    /// THE FLUSHER (design 2, A3): pulls every core every `advanced.usage_flush_interval_ms`
    /// (read at each tick: a live change applies at the next one), or at once when an
    /// administrative change or a metered request under `advanced.wait_for_commit` asks. A request
    /// never wakes it otherwise. A flush that fails is retried at the next tick; the first failure
    /// after a good flush is logged, and the stall is reported once it passes the stall limit.
    pub(crate) async fn run_core_flusher(self: Arc<Self>) {
        let shutdown = busbar_kernel::detached::worker_shutdown();
        self.cores.started(tokio::time::Instant::now());
        let mut failing = false;
        let mut reported = false;
        loop {
            let every = std::time::Duration::from_millis(
                busbar_kernel::limits::usage_flush_interval_ms().clamp(1, 1_000),
            );
            let stopping = tokio::select! {
                biased;
                () = busbar_kernel::detached::shutdown_fired(shutdown.clone()) => true,
                () = self.cores.wake().notified() => false,
                () = tokio::time::sleep(every) => false,
            };
            match self.flush_cores().await {
                Ok(()) => {
                    if let Some(journal) = self.lane.get() {
                        journal.set_flusher_stalled(false);
                    }
                    if failing {
                        tracing::info!("audit flusher committed again; durable service resumed");
                    }
                    (failing, reported) = (false, false);
                }
                Err(why) => {
                    if !failing {
                        tracing::warn!(reason = %why, "audit flusher could not commit; retrying each tick");
                    }
                    failing = true;
                    let stalled = self.cores.stalled(tokio::time::Instant::now());
                    if stalled {
                        // The one flag the billable open's gate reads (`refuses_money`).
                        if let Some(journal) = self.lane.get() {
                            journal.set_flusher_stalled(true);
                        }
                    }
                    if !reported && stalled {
                        busbar_kernel::diag_error!(
                            busbar_kernel::diagnostics::DURABILITY_STALLED,
                            reason = %why,
                            "records have not been committed for longer than the stall limit; \
                             requests that need a record are refused"
                        );
                        reported = true;
                    }
                }
            }
            if stopping {
                return;
            }
        }
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

    #[must_use]
    pub(crate) fn mint(&self) -> UnitKey {
        self.next_key.mint()
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

pub(super) struct RetainedUnit {
    call: CallId,
    state: RetainedState,
}

/// A reserved terminal-book entry: dropping it removes the entry it reserved.
#[cfg(test)]
struct TerminalReservation<'n> {
    node: &'n Node,
    class: AdmissionClass,
    key: UnitKey,
    call: CallId,
}
#[cfg(test)]
impl Drop for TerminalReservation<'_> {
    fn drop(&mut self) {
        let mut book = self
            .node
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(book) = book.as_mut() else {
            return;
        };
        if book
            .get(self.class, self.key)
            .is_some_and(|unit| unit.call == self.call)
        {
            book.remove(self.class, self.key);
        }
    }
}
enum RetainedState {
    Native(native::NativeUnit),
    /// Test fixture only: an original's notary-facing custody without its live request owners.
    #[cfg(test)]
    Original {
        staged: Option<crate::root::durability::NativeStagedAudit>,
        receipt: Option<crate::root::durability::notary::original::OriginalLineReceipt>,
        credit: Option<busbar_contract::storage::StorageCredit>,
    },
}
impl RetainedState {
    /// The live native unit, where this entry holds one.
    fn native_mut(&mut self) -> Option<&mut native::NativeUnit> {
        match self {
            Self::Native(native) => Some(native),
            #[cfg(test)]
            Self::Original { .. } => None,
        }
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

    fn ended_as(&self, key: UnitKey, outcome: Outcome) {
        if let Some(open) = self.lock(key).get_mut(&key) {
            open.sealing.said = Some(outcome);
        }
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
