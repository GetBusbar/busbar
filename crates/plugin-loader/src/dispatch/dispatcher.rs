// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DISPATCHER: what every op of the instances it adopted shares, with no scheduler. Each op
//! runs down the one call path ([`super::call`]): admitted once, its crossings on plugin threads,
//! PENDING on an inline ticket ([`super::inline`]) whose wake resumes it. The dispatcher holds:
//!
//! * the TICKETS: the inline tickets every op pends on, the request tickets held for their callers
//!   ([`Dispatcher::mint`]) and the instances' driver tickets ([`Dispatcher::driver`],
//!   [`super::driver`]);
//! * the HOST SERVICES its instances are served from (their stored results, the host's I/O, the
//!   seal it was lent, the process's runtime);
//! * THE WATCHDOG (`watchdog`): a crossing that does not RETURN within its class budget (or its
//!   op's own watch budget) is a breach; its op is answered FAULT while it runs on, and the
//!   instance is quarantined on its Nth.
//!
//! Every ticket's generation is a keyed permutation of its slot's mint counter (#74): a wake for a
//! generation no slot minted is a forgery, blamed on its supplier.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::lifecycle::slot;
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::plugin::{is_lifecycle, Instance, Plugin};
use super::services::{HostServices, Served, ServiceStore};
use super::ticket::WakeRoute;
use super::{watchdog, Frame, Kind};
#[cfg(any(test, feature = "conformance"))]
use super::{InFrame, OutFrame};

/// The longest a crossing may take before the watchdog faults it, per class. A crossing never
/// blocks by contract, so these bound a wedged plugin, not a slow request (that is the deadline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    /// Call-class crossings (and `tick`).
    pub call: Duration,
    /// Stream-class crossings.
    pub stream: Duration,
    /// Connection-class crossings (and `drive`).
    pub connection: Duration,
    /// WriteBehind-class crossings.
    pub write_behind: Duration,
    /// `validate`, `open`, `refresh`, `retire` and `close`.
    pub lifecycle: Duration,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            call: Duration::from_secs(1),
            stream: Duration::from_secs(1),
            connection: Duration::from_secs(1),
            write_behind: Duration::from_secs(5),
            lifecycle: Duration::from_secs(30),
        }
    }
}

impl Budgets {
    pub(crate) fn of(&self, s: u32, class: DeadlineClass) -> Duration {
        if s == slot::VALIDATE || is_lifecycle(s) {
            return self.lifecycle;
        }
        match class {
            DeadlineClass::Call => self.call,
            DeadlineClass::Stream => self.stream,
            DeadlineClass::Connection => self.connection,
            DeadlineClass::WriteBehind => self.write_behind,
        }
    }
}

/// A dispatcher's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchConfig {
    /// The watchdog's budgets.
    pub budgets: Budgets,
    /// How often the watchdog looks.
    pub watchdog_period: Duration,
    /// THE QUARANTINE COUNT, N (THE DESIGN A.8): the breaches of the watch budget an instance
    /// survives before it is quarantined. Every breach settles the hung op as FAULT; the Nth also
    /// quarantines the instance — every new call answers FAULT without a
    /// crossing (a hook's caller goes to its `on_error`, and the hook door's timed trial brings a
    /// fresh instance back, R2), with a diagnostic and `bb_plugin_quarantined_total`. Clamped to
    /// at least 1; the default [`DEFAULT_QUARANTINE_AFTER`] quarantines on the first breach.
    pub quarantine_after: u32,
}

/// The default [`DispatchConfig::quarantine_after`]: the first breach quarantines, as before the
/// count existed.
pub const DEFAULT_QUARANTINE_AFTER: u32 = 1;

/// The quarantine counter's exposition name (THE DESIGN A.8): [`DispatchStats::quarantined`], the
/// process's sum over every plugin.
pub const QUARANTINED_TOTAL: &str = "bb_plugin_quarantined_total";

/// The lost-wake counter's exposition name (THE DESIGN A.4.3):
/// [`DispatchStats::deadline_without_wake`].
pub const DEADLINE_WITHOUT_WAKE_TOTAL: &str = "bb_deadline_without_wake_total";

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            budgets: Budgets::default(),
            watchdog_period: Duration::from_millis(50),
            quarantine_after: DEFAULT_QUARANTINE_AFTER,
        }
    }
}

/// What the dispatcher counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchStats {
    /// Wakes dropped: a stale generation, a recycled slot.
    pub stale_wakes: u64,
    /// Instances the watchdog quarantined: `bb_plugin_quarantined_total` (THE DESIGN A.8), the
    /// process's sum over every plugin.
    pub quarantined: u64,
    /// WriteBehind ops that completed after their caller stopped waiting.
    pub write_behind_late: u64,
    /// Library unloads still running on their reapers, process-wide: a count that stays up names a
    /// hung `.fini_array` (never forced; see `load::reap`).
    pub live_reapers: u64,
    /// The most service answers one driver ticket kept over one tick cycle (a high-water gauge).
    pub driver_kept_high: u64,
    /// `bb_deadline_without_wake_total` (THE DESIGN A.4.3): ops that answered PENDING and were
    /// still owed their wake when their DEADLINE settled them (a Call/Stream/Connection op
    /// cancelled, a WriteBehind op's caller released), never woken before it. A door whose every
    /// wait is woken keeps it 0; every conformance script requires 0.
    pub deadline_without_wake: u64,
    /// Contexts plugins handed the host that it did not mint, process-wide (#74,
    /// `dispatch::handle`): each inside a crossing quarantined its instance.
    pub forged_handles: u64,
    /// The off-crossing latch tripped (#74): nothing resolves outside a crossing any more.
    pub handles_latched: bool,
}

/// One `bb_*` counter family the dispatcher exposes: its name, its HELP text and its value.
pub type CounterFamily = (&'static str, &'static str, u64);

impl DispatchStats {
    /// EVERY `bb_*` COUNTER these stats hold, each with its name and HELP text: the dispatcher's
    /// own counts, read by whoever holds the dispatcher (the conformance suite). They are NOT on
    /// the customer `/metrics` scrape: 1.5.5 served no `bb_*` family and the scrape must match it
    /// (oracle row 86).
    #[must_use]
    pub const fn families(&self) -> [CounterFamily; 2] {
        [
            (
                DEADLINE_WITHOUT_WAKE_TOTAL,
                "Plugin operations that waited and were settled by their deadline without ever \
                 being woken; 0 while every plugin wakes what it parks",
                self.deadline_without_wake,
            ),
            (
                QUARANTINED_TOTAL,
                "Plugin instances the crossing watchdog quarantined for overrunning their call \
                 budget, summed over every plugin",
                self.quarantined,
            ),
        ]
    }
}

#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) stale_wakes: AtomicU64,
    pub(crate) quarantined: AtomicU64,
    pub(crate) write_behind_late: AtomicU64,
    pub(crate) driver_kept_high: AtomicU64,
    pub(crate) deadline_without_wake: AtomicU64,
}

/// What every op of the dispatcher's instances shares.
pub(crate) struct Env {
    pub(crate) budgets: Budgets,
    /// [`DispatchConfig::quarantine_after`], at least 1.
    pub(crate) quarantine_after: u32,
    pub(crate) stats: Arc<Stats>,
    /// The host services' stored results.
    pub(crate) services: Arc<ServiceStore>,
    /// What the host services are served from; `None` = the host bound none, and every service
    /// answers REFUSED.
    pub(crate) provider: Option<Arc<dyn HostServices>>,
    /// THE PROCESS'S RUNTIME, the reactor a plugin's connection is registered on: a crossing on a
    /// plugin thread runs inside it, so a dial the connector makes there (a plugin's `exchange`)
    /// lands on a reactor that is always driven (THE DESIGN, the connections section). INSTALLED,
    /// never captured ([`Dispatcher::install_runtime`]): the host installs the process's one
    /// runtime at boot (busbar: the connector's own I/O thread). None installed: a crossing off any
    /// runtime enters none, and its I/O takes the connector's own refusal.
    pub(crate) runtime: std::sync::OnceLock<tokio::runtime::Handle>,
    /// THE HOST'S I/O (`io.*`) the instances of this dispatcher are served from; unset = none, and
    /// every `io` slot answers REFUSED.
    pub(crate) io: std::sync::OnceLock<Arc<dyn busbar_contract::io_host::IoHost>>,
    /// The tickets of ops driven inline on the calling thread (a carrier's connection sides).
    pub(crate) inline: Arc<super::inline::InlineTickets>,
    /// THE HOST'S OBSERVABILITY of every door this dispatcher binds: the observer and the series
    /// predicate the host installs on it ([`Dispatcher::observing`]), never a process-global seam.
    pub(crate) observing: Arc<crate::observe::Observing>,
    /// The latch a forged ticket with no supplier counts against: the process's, but in a test
    /// that names its own ([`Dispatcher::judge_against`]).
    latch: std::sync::OnceLock<&'static super::handle::Latch>,
    /// THE SEAL THE HOST LENT THIS DISPATCHER (Part 2 #54): what a door it binds presents to read
    /// a resolved `Secret` it hands a plugin ([`Dispatcher::lend_seal`]). None lent: every such
    /// reveal is refused.
    pub(crate) seal:
        std::sync::OnceLock<Arc<dyn busbar_contract::plugin::KernelSeal + Send + Sync>>,
    /// The request tickets held for their callers until recycled ([`Dispatcher::mint`]), each with
    /// what a client drop asks of the op on it ([`Dispatcher::drop_client`]).
    pub(crate) held: Mutex<std::collections::HashMap<Ticket, HeldTicket>>,
    /// The driver tickets minted and not yet recycled ([`Dispatcher::driver`]).
    pub(crate) drivers: Mutex<std::collections::HashMap<Ticket, Arc<super::driver::Driver>>>,
}

impl Env {
    pub(crate) fn latch(&self) -> &'static super::handle::Latch {
        self.latch
            .get()
            .copied()
            .unwrap_or_else(super::handle::process_latch)
    }
}

/// A request ticket held for its caller, and what a client drop asks of the op on it.
pub(crate) type HeldTicket = (super::inline::InlineTicket, Arc<super::call::CancelRequest>);

/// What an op lends its plugin: the owner of every buffer its frame's pointers name, held by the
/// op until its last crossing returned.
pub type Lent = Arc<dyn std::any::Any + Send + Sync>;

/// [`Dispatcher::call_on`] for an instance already adopted: owned, so it may run on any thread.
#[cfg(any(test, feature = "conformance"))]
#[allow(clippy::too_many_arguments)] // as `call_on`
pub(crate) async fn submitted<K: Kind, I: InFrame, O: OutFrame>(
    plugin: Arc<Plugin<K>>,
    ticket: Ticket,
    s: u32,
    f: Frame<I, O>,
    (class, deadline_ns): (DeadlineClass, u64),
    lent: Lent,
    watch: Duration,
    cancel: Option<Arc<super::call::CancelRequest>>,
    admission: super::plugin::Admission,
) -> Done<I, O> {
    let deadline = (deadline_ns != 0).then(|| {
        Instant::now() + Duration::from_nanos(deadline_ns.saturating_sub(super::now_ns()))
    });
    if class == DeadlineClass::WriteBehind {
        // NEVER CANCELLED: at its deadline the caller stops waiting (`detached`), and the op runs
        // on to its end, a later wake still completing it.
        let ran = super::call::call_write_behind(
            plugin,
            s,
            f,
            lent,
            Arc::default(),
            Box::new(|_| None),
            cancel,
        );
        let Some(deadline) = deadline else {
            return Done::of::<K>(ran.await);
        };
        let mut ran = std::pin::pin!(ran);
        let mut at = std::pin::pin!(super::timer::sleep_until(deadline));
        return std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(ran) = ran.as_mut().poll(cx) {
                return std::task::Poll::Ready(Done::of::<K>(ran));
            }
            if at.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(Done {
                    detached: true,
                    ..Done::host(K::TIMEOUT)
                });
            }
            std::task::Poll::Pending
        })
        .await;
    }
    let ran = super::call::call(
        &plugin,
        s,
        f,
        lent,
        super::call::Opts {
            class,
            deadline,
            watch,
            leave: false,
            lane: None,
            admission,
            ticket: (!ticket.is_none()).then_some(ticket),
            inline: false,
            cancel,
        },
        &mut |_| None,
    )
    .await;
    Done::of::<K>(ran)
}

#[cfg(any(test, feature = "conformance"))]
impl<I, O> Done<I, O> {
    /// An op the host answered without a crossing.
    pub(crate) fn host(outcome: Outcome) -> Self {
        Self {
            outcome,
            error: None,
            lease: 0,
            frame: None,
            detached: false,
            short: false,
            disposition: None,
            cancel_writes: Vec::new(),
        }
    }

    /// What one op of kind `K` ran to, as its completion.
    pub(crate) fn of<K: Kind>(ran: super::call::Ran<I, O>) -> Self {
        match ran {
            super::call::Ran::Answered { called, frame, .. } => Self {
                outcome: called.outcome,
                error: called.error,
                lease: called.lease,
                short: called.recall.is_some(),
                frame: Some(frame),
                ..Self::host(Outcome::Ready)
            },
            // Ended by its `cancel`: the kind's timeout with what the cancel said; a `cancel` that
            // FAULTed makes the op FAULT, with no disposition.
            super::call::Ran::TimedOut { cancelled: Some(c) } if c.outcome != Outcome::Fault => {
                Self {
                    disposition: c.disposition,
                    cancel_writes: if c.outcome == Outcome::Ready {
                        c.writes
                    } else {
                        Vec::new()
                    },
                    ..Self::host(K::TIMEOUT)
                }
            }
            super::call::Ran::TimedOut { cancelled: Some(_) } | super::call::Ran::Faulted => {
                Self::host(Outcome::Fault)
            }
            super::call::Ran::TimedOut { cancelled: None } => Self::host(K::TIMEOUT),
            super::call::Ran::NoTicket => Self::host(Outcome::Refused),
        }
    }
}

/// One op's completion.
#[derive(Debug)]
pub struct Done<I, O> {
    /// The authoritative outcome.
    pub outcome: Outcome,
    /// The error text, copied, for FAILED/REFUSED.
    pub error: Option<Vec<u8>>,
    /// A lease for `release`; `0` = none.
    pub lease: u64,
    /// The frame, back to its owner; `None` when the op was faulted mid-crossing or detached.
    pub frame: Option<Box<Frame<I, O>>>,
    /// A WriteBehind op whose caller stopped waiting at its deadline; it runs on.
    pub detached: bool,
    /// A FAILED answer the kind calls SHORT: re-submit ONCE on the same ticket with bigger
    /// buffers; a second short answer is FAULT (the short-buffer rule on `OutHead`).
    pub short: bool,
    /// When the op ended through `cancel` (a deadline or a client drop): the kind's disposition
    /// `CancelOut.disposition` answered (store: 0 UNKNOWN, 1 NOT_APPLIED, 2 APPLIED). A `cancel`
    /// that FAULTed makes the op FAULT, with no disposition.
    pub disposition: Option<u32>,
    /// The record writes that `cancel` carried (a plane's, SEAM-L(r)).
    pub cancel_writes: Vec<busbar_contract::plane_calls::CancelWrite>,
}

pub(crate) struct Pool {
    pub(crate) env: Arc<Env>,
    pub(crate) stop: AtomicBool,
    /// Every instance this dispatcher adopted, for the watchdog's ticket-less scan.
    pub(crate) adopted: Mutex<Vec<Weak<Instance>>>,
}

impl WakeRoute for Pool {
    /// Wake the task of an inline ticket. Never blocks on the plugin. A generation the slot minted
    /// and no longer holds is a late wake, dropped and counted; one no slot minted is a forgery,
    /// blamed on its supplier (#74).
    fn wake(&self, t: Ticket, supplier: Option<&'static super::ticket::InstanceWake>) {
        // Judged with the inline table's lock let go (#74).
        match self.env.inline.wake(t) {
            super::inline::Judged::Woken => {}
            super::inline::Judged::Stale => {
                self.env.stats.stale_wakes.fetch_add(1, Ordering::Relaxed);
            }
            super::inline::Judged::Forged => {
                self.env.stats.stale_wakes.fetch_add(1, Ordering::Relaxed);
                super::handle::forged_ticket(supplier, self.env.latch());
            }
        }
    }
    fn services(&self) -> Option<Served> {
        Some(Served {
            store: Arc::clone(&self.env.services),
            provider: Arc::clone(self.env.provider.as_ref()?),
        })
    }

    fn store(&self) -> Option<Arc<ServiceStore>> {
        Some(Arc::clone(&self.env.services))
    }

    fn io(&self) -> Option<Arc<dyn busbar_contract::io_host::IoHost>> {
        self.env.io.get().cloned()
    }

    fn seal(&self) -> Option<Arc<dyn busbar_contract::plugin::KernelSeal + Send + Sync>> {
        self.env.seal.get().cloned()
    }

    fn inline_waker(&self, t: Ticket) -> Option<std::task::Waker> {
        self.env.inline.waker_of(t)
    }

    fn runtime(&self) -> Option<tokio::runtime::Handle> {
        self.env.runtime.get().cloned()
    }

    fn stats(&self) -> Option<Arc<Stats>> {
        Some(Arc::clone(&self.env.stats))
    }

    fn inline(&self) -> Option<Arc<super::inline::InlineTickets>> {
        Some(Arc::clone(&self.env.inline))
    }
}

/// A slot's mint counter after `count`; `None` once it is spent (#74): the generation is a
/// permutation of the counter, so a counter that wrapped would re-mint a generation the slot
/// already handed out. A spent slot is RETIRED instead, never handed out again.
pub(crate) fn next_count(count: u32) -> Option<u32> {
    count.checked_add(1)
}

/// A dispatcher's adoption handle ([`Dispatcher::adopter`]), held by a [`super::Bind`].
#[derive(Clone)]
pub struct Adopter {
    pool: Weak<Pool>,
}

impl std::fmt::Debug for Adopter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adopter").finish_non_exhaustive()
    }
}

impl Adopter {
    /// TEST ONLY: an adopter of no dispatcher; the instance is adopted by the first dispatcher
    /// that submits to it.
    #[cfg(test)]
    pub(crate) fn unwatched() -> Self {
        Self { pool: Weak::new() }
    }

    /// The host's observability of the dispatcher this adopter belongs to; `None` when it adopts
    /// for no dispatcher (or that one is gone), and the door's back-channel is then dropped.
    pub(crate) fn observing(&self) -> Option<Arc<crate::observe::Observing>> {
        self.pool
            .upgrade()
            .map(|pool| Arc::clone(&pool.env.observing))
    }

    /// Route `inst`'s wakes to the dispatcher and put it under its watchdog; `false` when the
    /// instance already belongs to another dispatcher (or this one is gone).
    pub(crate) fn adopt(&self, inst: &Arc<Instance>) -> bool {
        let Some(pool) = self.pool.upgrade() else {
            return false;
        };
        let route: Arc<dyn WakeRoute> = pool.clone();
        let mine = Arc::downgrade(&route);
        let bound = inst.wake.route.get_or_init(|| {
            pool.adopted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Arc::downgrade(inst));
            mine.clone()
        });
        Weak::ptr_eq(bound, &mine)
    }
}

/// THE DISPATCHER: the tickets, host services and watchdog of the instances it adopted.
pub struct Dispatcher {
    pool: Arc<Pool>,
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish_non_exhaustive()
    }
}

impl Dispatcher {
    /// A dispatcher and its watchdog, per `config`, with no host services bound: every service answers
    /// REFUSED.
    ///
    /// # Panics
    ///
    /// When the OS random source cannot answer the handle key (#74): a boot with no key is refused,
    /// never run under a weaker one. [`Dispatcher::try_new`] answers the refusal instead.
    pub fn new(config: DispatchConfig) -> Self {
        Self::try_new(config).unwrap_or_else(|e| panic!("{e}"))
    }

    /// THE LOADER'S BOOT (#74): the handle key drawn first, then the dispatcher.
    ///
    /// # Errors
    ///
    /// [`LoadError::Entropy`](super::LoadError::Entropy) when the OS random source cannot answer.
    pub fn try_new(config: DispatchConfig) -> Result<Self, super::LoadError> {
        let key = super::handle::ticket_key()?;
        Ok(Self::build(config, None, key))
    }

    /// The connection table's wake: its wake number ([`super::conn_services::conn_ticket`]) routed to
    /// the ticket it names, with the caller the table registered it for as the
    /// ticket's supplier (#74: a forged generation quarantines that instance; the root's own
    /// identity names none). The root hands it to its one connector.
    #[must_use]
    pub fn conn_waker(&self) -> busbar_contract::conn::ConnWake {
        let pool = Arc::downgrade(&self.pool);
        Arc::new(move |owner, n| {
            if let Some(pool) = pool.upgrade() {
                pool.wake(
                    super::conn_services::ticket_of(n),
                    super::handle::supplier_of(owner),
                );
            }
        })
    }

    /// THE HOST'S OBSERVABILITY of the doors this dispatcher binds: the composition root installs
    /// its plugin observer ([`crate::observe::Observing::install_observer`]) and its own series
    /// predicate ([`crate::observe::Observing::install_host_series`]) here, before the first door
    /// binds, and every door's envelope folds through it.
    #[must_use]
    pub fn observing(&self) -> &crate::observe::Observing {
        &self.pool.env.observing
    }

    /// LEND THIS DISPATCHER THE HOST'S SEAL (Part 2 #54): a kernel-minted `Pass` or `Grant`, what
    /// a door it binds presents to read a resolved `Secret` it hands a plugin (a verify's
    /// credential, a login's submitted fields, an outbound caller credential, a secret source's
    /// material). The composition root lends `busbar_kernel::seal::lend()` on the process's one
    /// dispatcher at boot. The first lend holds; a later one answers `false`. A dispatcher lent no
    /// seal REFUSES every such reveal (fail closed).
    pub fn lend_seal(
        &self,
        seal: impl busbar_contract::plugin::KernelSeal + Send + Sync + 'static,
    ) -> bool {
        self.pool.env.seal.set(Arc::new(seal)).is_ok()
    }

    /// The seal this dispatcher was lent, if any ([`Self::lend_seal`]).
    pub(crate) fn seal(&self) -> Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)> {
        self.pool.env.seal.get().map(|seal| &**seal)
    }

    /// INSTALL THE PROCESS'S RUNTIME every crossing off a runtime runs inside (see `Env::runtime`):
    /// the one the host drives on a thread of its own. The first install holds; a later one is
    /// ignored and answers `false`. Never taken from a submitter.
    pub fn install_runtime(&self, handle: tokio::runtime::Handle) -> bool {
        self.pool.env.runtime.set(handle).is_ok()
    }

    /// The runtime crossings run inside, when one is installed.
    #[cfg(test)]
    pub(crate) fn installed_runtime(&self) -> Option<&tokio::runtime::Handle> {
        self.pool.env.runtime.get()
    }

    /// A dispatcher and its watchdog, per `config`, serving the host services the kernel implements.
    ///
    /// # Panics
    ///
    /// As [`Dispatcher::new`]; [`Dispatcher::try_with_services`] answers the refusal instead.
    pub fn with_services(config: DispatchConfig, provider: Arc<dyn HostServices>) -> Self {
        Self::try_with_services(config, provider).unwrap_or_else(|e| panic!("{e}"))
    }

    /// [`Dispatcher::try_new`], serving `provider`.
    ///
    /// # Errors
    ///
    /// [`LoadError::Entropy`](super::LoadError::Entropy) when the OS random source cannot answer.
    pub fn try_with_services(
        config: DispatchConfig,
        provider: Arc<dyn HostServices>,
    ) -> Result<Self, super::LoadError> {
        let key = super::handle::ticket_key()?;
        Ok(Self::build(config, Some(provider), key))
    }

    fn build(
        config: DispatchConfig,
        provider: Option<Arc<dyn HostServices>>,
        ticket_key: super::handle::TicketKey,
    ) -> Self {
        let built = Self::build_unlent(config, provider, ticket_key);
        // This crate's own tests lend the dev-only test seal to every dispatcher they build.
        #[cfg(test)]
        let _ = built.lend_seal(busbar_contract::plugin::TestKernelSeal);
        built
    }

    /// TEST ONLY: a dispatcher lent NO seal, so every reveal its doors would make is refused (the
    /// fail-closed arm of [`Self::lend_seal`]).
    #[cfg(test)]
    pub(crate) fn new_unlent(config: DispatchConfig) -> Self {
        let key = super::handle::ticket_key().unwrap_or_else(|e| panic!("{e}"));
        Self::build_unlent(config, None, key)
    }

    fn build_unlent(
        config: DispatchConfig,
        provider: Option<Arc<dyn HostServices>>,
        ticket_key: super::handle::TicketKey,
    ) -> Self {
        let services: Arc<ServiceStore> = Arc::default();
        let env = Arc::new(Env {
            budgets: config.budgets,
            quarantine_after: config.quarantine_after.max(1),
            stats: Arc::default(),
            inline: Arc::new(super::inline::InlineTickets::new(ticket_key, &services)),
            services,
            provider,
            runtime: std::sync::OnceLock::new(),
            io: std::sync::OnceLock::new(),
            observing: Arc::default(),
            latch: std::sync::OnceLock::new(),
            seal: std::sync::OnceLock::new(),
            held: Mutex::default(),
            drivers: Mutex::default(),
        });
        let pool = Arc::new(Pool {
            env,
            stop: AtomicBool::new(false),
            adopted: Mutex::new(Vec::new()),
        });
        watchdog::spawn(Arc::downgrade(&pool), config.watchdog_period);
        Self { pool }
    }

    /// The watchdog's budgets this dispatcher runs on.
    #[must_use]
    pub fn budgets(&self) -> Budgets {
        self.pool.env.budgets
    }

    /// What the dispatcher counted.
    pub fn stats(&self) -> DispatchStats {
        let s = &self.pool.env.stats;
        DispatchStats {
            stale_wakes: s.stale_wakes.load(Ordering::Relaxed),
            quarantined: s.quarantined.load(Ordering::Relaxed),
            write_behind_late: s.write_behind_late.load(Ordering::Relaxed),
            live_reapers: super::load::live_reapers(),
            driver_kept_high: s.driver_kept_high.load(Ordering::Relaxed),
            deadline_without_wake: s.deadline_without_wake.load(Ordering::Relaxed),
            forged_handles: super::handle::forged(),
            handles_latched: super::handle::latched(),
        }
    }

    /// The host services' stored results.
    pub fn services(&self) -> &ServiceStore {
        &self.pool.env.services
    }

    /// The host services this dispatcher serves; `None` when it was built with none, and then
    /// every service answers REFUSED.
    pub fn host_services(&self) -> Option<&Arc<dyn HostServices>> {
        self.pool.env.provider.as_ref()
    }

    /// Bind `inst`'s wakes to this dispatcher; `false` when it is bound to another.
    fn adopt(&self, inst: &Arc<Instance>) -> bool {
        self.adopter().adopt(inst)
    }

    /// Serve every instance of this dispatcher the HOST'S I/O (`io.*`) from `io`; the first install
    /// stands. `false` when one was installed already.
    pub fn install_io(&self, io: Arc<dyn busbar_contract::io_host::IoHost>) -> bool {
        self.pool.env.io.set(io).is_ok()
    }

    /// A ticket for ops driven INLINE on the calling thread ([`super::inline`]): one per side of a
    /// carrier's connection. `None` when every inline slot is held.
    #[must_use]
    pub fn inline_ticket(&self) -> Option<super::inline::InlineTicket> {
        self.pool.env.inline.mint()
    }

    /// The handle a [`super::Bind`] carries to be adopted by this dispatcher at bind.
    pub fn adopter(&self) -> Adopter {
        Adopter {
            pool: Arc::downgrade(&self.pool),
        }
    }

    /// The host services' store itself (test witness: a test serves into it as an instance's
    /// service call would).
    #[cfg(test)]
    pub(crate) fn service_store(&self) -> Arc<ServiceStore> {
        Arc::clone(&self.pool.env.services)
    }

    /// TEST ONLY: a forged ticket with no supplier counts against `latch`, not the process's.
    #[cfg(test)]
    pub(crate) fn judge_against(&self, latch: &'static super::handle::Latch) {
        assert!(
            self.pool.env.latch.set(latch).is_ok(),
            "one latch per dispatcher"
        );
    }

    /// TEST ONLY: the inline tickets, shared, for a test that mints from inside a hook.
    #[cfg(test)]
    pub(crate) fn inline_tickets_arc(&self) -> Arc<super::inline::InlineTickets> {
        Arc::clone(&self.pool.env.inline)
    }

    /// TEST ONLY: the inline tickets, for a test that seeds a slot's counter.
    #[cfg(test)]
    pub(crate) fn inline_tickets(&self) -> &super::inline::InlineTickets {
        &self.pool.env.inline
    }

    /// TEST ONLY: the dispatcher's ticket key.
    #[cfg(test)]
    pub(crate) fn ticket_key(&self) -> super::handle::TicketKey {
        self.pool.env.inline.key()
    }

    /// A REQUEST TICKET held for the caller until it recycles it ([`Dispatcher::recycle`]): an
    /// inline ticket its ops run on ([`Dispatcher::call_on`]).
    #[cfg(any(test, feature = "conformance"))]
    pub fn mint(&self) -> Option<Ticket> {
        let t = self.pool.env.inline.mint()?;
        let ticket = t.ticket();
        self.pool
            .env
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ticket, (t, Arc::default()));
        Some(ticket)
    }

    /// Op `s` of `plugin` over `f` on the held `ticket` ([`Dispatcher::mint`]; `NONE`: a ticket of
    /// its own), down the one call path, awaited: deadline class and deadline `class`/`deadline_ns`
    /// (0 = none), `lent` the owner of every buffer `f`'s pointers name (the op holds it until its
    /// last crossing returned), `watch` its own watch budget (`ZERO` keeps its class's). A SHORT
    /// answer comes back as [`Done::short`], re-called by submitting again on the same ticket.
    #[cfg(any(test, feature = "conformance"))]
    #[allow(clippy::too_many_arguments)] // the op, its ticket and frame, its deadline, lend and watch
    pub(crate) fn call_on<K: Kind, I: InFrame, O: OutFrame>(
        &self,
        plugin: &Plugin<K>,
        ticket: Ticket,
        s: u32,
        f: Frame<I, O>,
        (class, deadline_ns): (DeadlineClass, u64),
        lent: Lent,
        watch: Duration,
    ) -> impl Future<Output = Done<I, O>> + Send + 'static {
        self.call_admitted(
            plugin,
            ticket,
            s,
            f,
            (class, deadline_ns),
            lent,
            watch,
            super::plugin::Admission::Cap,
        )
    }

    /// [`Dispatcher::call_on`], admitted as `admission` says (an admitted unit's op holds no
    /// `max_inflight` unit, `Admission::Unit`).
    #[cfg(any(test, feature = "conformance"))]
    #[allow(clippy::too_many_arguments)] // `call_on`'s, and the admission
    pub(crate) fn call_admitted<K: Kind, I: InFrame, O: OutFrame>(
        &self,
        plugin: &Plugin<K>,
        ticket: Ticket,
        s: u32,
        f: Frame<I, O>,
        (class, deadline_ns): (DeadlineClass, u64),
        lent: Lent,
        watch: Duration,
        admission: super::plugin::Admission,
    ) -> impl Future<Output = Done<I, O>> + Send + 'static {
        let adopted = self.adopt(&plugin.inner);
        // A fresh cancel request for this op, what a client drop of its ticket asks.
        let cancel = self
            .pool
            .env
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&ticket)
            .map(|(_, c)| {
                *c = Arc::default();
                Arc::clone(c)
            });
        let plugin = plugin.shared();
        async move {
            if !adopted {
                return Done::host(Outcome::Refused);
            }
            submitted(
                plugin,
                ticket,
                s,
                f,
                (class, deadline_ns),
                lent,
                watch,
                cancel,
                admission,
            )
            .await
        }
    }

    /// The client of `t` (a ticket held for it, [`Dispatcher::mint`]) went away: the op on it is
    /// cancelled (`cancel`, then the kind's timeout outcome); a WriteBehind op runs on.
    #[cfg(any(test, feature = "conformance"))]
    pub fn drop_client(&self, t: Ticket) {
        let cancel = self
            .pool
            .env
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&t)
            .map(|(_, c)| Arc::clone(c));
        if let Some(c) = cancel {
            c.request();
        }
    }

    /// TEST ONLY: whether the op on the held ticket `t` answered PENDING and waits for its wake.
    #[cfg(test)]
    pub(crate) fn is_pending(&self, t: Ticket) -> bool {
        self.pool
            .env
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&t)
            .is_some_and(|(_, c)| c.waiting())
    }

    /// Recycle `t`, a ticket minted for the caller ([`Dispatcher::mint`]) or a driver ticket
    /// ([`Dispatcher::driver`]): its generation is bumped and late wakes for it are dropped from
    /// then on; what its ops kept goes with it.
    pub fn recycle(&self, t: Ticket) {
        let driver = self
            .pool
            .env
            .drivers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&t);
        if let Some(driver) = driver {
            // Let go on a plugin thread, never the caller's nor under the drivers' lock: the
            // instance it may hold last closes there (plugin code). Its ticket goes once no
            // crossing on it runs (the crossing holds the driver).
            crate::ffi_thread::spawn_on_plugin_thread(move || drop(driver));
            return;
        }
        let held = self
            .pool
            .env
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&t);
        drop(held);
    }

    /// A DRIVER TICKET for `plugin`: persistent until recycled, owned by the instance, outside
    /// `max_inflight`. Every wake on it calls `drive` ([`super::driver`]).
    pub fn driver<K: Kind>(&self, plugin: &Plugin<K>) -> Option<Ticket> {
        let inst = &plugin.inner;
        if !self.adopt(inst) || !inst.is_open() || inst.faulted.load(Ordering::Acquire) {
            return None;
        }
        let env = &self.pool.env;
        let d = super::driver::Driver::new(
            Arc::clone(inst),
            env.inline.mint()?,
            K::drive_frame(),
            Arc::clone(&env.services),
            Arc::clone(&env.stats),
        );
        let t = d.ticket();
        env.drivers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(t, d);
        Some(t)
    }

    /// `tick` at `now_ns` on `driver`, the instance's driver ticket ([`Dispatcher::driver`]). The
    /// head carries `driver`, so a service that pends inside `tick` registers on it and its wake
    /// calls `drive`. Outside `max_inflight`: it never holds a slot. The caller owns the schedule
    /// ([`super::driver::Ticked::next_tick_ns`]); this is one crossing of it. FAULT for a ticket
    /// that is no driver of `plugin`.
    pub fn tick<K: Kind>(
        &self,
        plugin: &Plugin<K>,
        driver: Ticket,
        now_ns: u64,
    ) -> impl Future<Output = super::driver::Ticked> + Send + 'static {
        let d = self
            .pool
            .env
            .drivers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&driver)
            .filter(|d| d.is_of(&plugin.inner))
            .cloned();
        async move {
            match d {
                Some(d) => d.tick(now_ns).await,
                None => super::driver::Ticked {
                    outcome: Outcome::Fault,
                    error: None,
                    lease: 0,
                    next_tick_ns: 0,
                },
            }
        }
    }

    /// A reload DRAIN: wait up to `timeout` until no Call/Stream/Connection op of `plugin` is in
    /// flight. WriteBehind ops are never waited on: they carry over to the next generation.
    pub fn drain<K: Kind>(&self, plugin: &Plugin<K>, timeout: Duration) -> bool {
        let until = Instant::now() + timeout;
        loop {
            if plugin.inner.drainable.load(Ordering::Acquire) == 0 {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        self.pool.stop.store(true, Ordering::Release);
    }
}
