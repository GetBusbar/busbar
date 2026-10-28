// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEALTH PROBE, schedule target to wire (K7), over the far end's doubles and a plane double
//! that declares probes: the probe unit arrives on the probe claim, pushes its ATTEMPT piece alone,
//! sends the request the plane emitted to the ONE member it is pinned to (past that member's
//! breaker), and the far end's answer is recorded on every cell of it. Proven: a probe recovers a
//! tripped member; a client-fault answer records nothing; the plane's stated fault reading of the
//! probe's answer is recorded as an organic answer's is; a probe that brings no answer is a
//! transient and tries no other member; the unit is zero-billed; a passthrough member, a plane
//! that does not declare probes and a plane that refuses the probe are never sent one.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicU32;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{Outcome as AbiOutcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket as PlaneTicket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut,
    ServeIn, ServeOut, UnitCount, CLAIM_PROBE, EMIT_DONE, EMIT_TO_FAR_END, FROM_FAR_END,
    FROM_KERNEL, TAIL_PROBES, UNITS_REPORTED,
};
use busbar_contract::caps::OpClassId;
use busbar_contract::plane_calls::{
    Answered, Grow, InstanceDecl, Lent, PieceInFlight, PlaneCalls, ServeInFlight,
};

use super::*;
use crate::door::UnitKeyMint;
use crate::plane_driver::{
    refusal_status, BufferCaps, CancelBill, Checkpoint, DriverConfig, MoneySeam, PlaneDriver,
    PlaneProbes,
};
use crate::probe::ProbeTarget;
use crate::teller::{Ended, Kernel, UnitCtx};

// ── the plane ───────────────────────────────────────────────────────────────────────────────────

/// The probe request the plane emits: its verb and its target.
const PROBE: (&[u8], &[u8]) = (b"GET", b"/health");

/// A plane that answers probes: its `arrive` takes the probe claim, its ATTEMPT piece emits the
/// probe request, and its answer to the far end's piece reports units (which a probe never bills).
#[derive(Default)]
struct Prober {
    /// Refuse every arrival.
    refuse: bool,
    /// The claim every `arrive` carried.
    claims: Mutex<Vec<u32>>,
    /// Every `on_piece`'s source and attempt number.
    pieces: Mutex<Vec<(u32, u32)>>,
    /// The breaker fault reading (`FAULT_*`) it states of the far end's answer.
    fault: u8,
    next: AtomicU32,
}

const READY: Answered = Answered {
    outcome: AbiOutcome::Ready,
    short: false,
    disposition: None,
};

/// An answer already in.
struct Now(OnPieceOut);
// SAFETY: plain data the double wrote; its pointers are never dereferenced.
unsafe impl Send for Now {}

impl Future for Now {
    type Output = Answered;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Answered> {
        Poll::Ready(READY)
    }
}

impl PieceInFlight for Now {
    fn settled(&mut self) -> Option<Answered> {
        Some(READY)
    }
    fn out(&self) -> Option<OnPieceOut> {
        Some(self.0)
    }
}

/// The prober serves no route: every `serve` answers FAULT at once.
struct NoServe;

impl Future for NoServe {
    type Output = Answered;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Answered> {
        Poll::Ready(Answered {
            outcome: AbiOutcome::Fault,
            short: false,
            disposition: None,
        })
    }
}

impl ServeInFlight for NoServe {
    fn out(&self) -> Option<ServeOut> {
        None
    }
}

impl PlaneCalls for Prober {
    fn now_ns(&self) -> u64 {
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }

    fn arrive(
        &self,
        input: &mut ArriveIn,
        out: &mut ArriveOut,
        _: Grow<'_, ArriveIn, ArriveOut>,
    ) -> AbiOutcome {
        self.claims.lock().unwrap().push(input.claim);
        if self.refuse {
            out.refusal = 7;
            out.refusal_status = 404;
            return AbiOutcome::Refused;
        }
        AbiOutcome::Ready
    }

    fn arrived_pool(&self, _out: &ArriveOut) -> Option<Vec<u8>> {
        None
    }

    fn refusal(
        &self,
        _: &mut RefusalIn,
        _: &mut RefusalOut,
        _: Grow<'_, RefusalIn, RefusalOut>,
    ) -> AbiOutcome {
        AbiOutcome::Fault
    }

    fn project(
        &self,
        _: &mut ProjectIn,
        _: &mut ProjectOut,
        _: Grow<'_, ProjectIn, ProjectOut>,
    ) -> AbiOutcome {
        AbiOutcome::Ready
    }

    fn cancel(&self, _: PlaneTicket, _: u64) -> Option<busbar_contract::plane_calls::Cancelled> {
        None
    }

    fn declared(&self) -> InstanceDecl {
        InstanceDecl {
            label: "prober".into(),
            ..InstanceDecl::default()
        }
    }

    fn driver(&self) -> Option<PlaneTicket> {
        self.mint()
    }

    fn tick(&self, _: PlaneTicket, _: u64) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
        Box::pin(std::future::ready(Some(0)))
    }

    fn ready(&self) -> Pin<Box<dyn Future<Output = Vec<u64>> + Send>> {
        Box::pin(std::future::ready(Vec::new()))
    }

    fn mint(&self) -> Option<PlaneTicket> {
        Some(PlaneTicket {
            slot: self.next.fetch_add(1, Ordering::SeqCst),
            generation: 1,
        })
    }

    fn recycle(&self, _: PlaneTicket) {}

    fn drop_client(&self, _: PlaneTicket) {}

    fn serve(&self, _: PlaneTicket, _: ServeIn, _: ServeOut, _: Lent) -> Box<dyn ServeInFlight> {
        Box::new(NoServe)
    }

    fn on_piece(
        &self,
        _: PlaneTicket,
        i: OnPieceIn,
        mut o: OnPieceOut,
        _: Lent,
    ) -> Box<dyn PieceInFlight> {
        self.pieces.lock().unwrap().push((i.from, i.attempt_no));
        match i.from {
            FROM_KERNEL if i.claim == CLAIM_PROBE => {
                let (verb, target) = PROBE;
                let words = [verb, target].concat();
                assert!(words.len() <= i.arena_cap);
                // SAFETY: the driver's arena of `arena_cap` bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(words.as_ptr(), i.arena_buf, words.len());
                }
                o.verb = Span {
                    offset: 0,
                    len: verb.len() as u32,
                };
                o.target = Span {
                    offset: verb.len() as u32,
                    len: target.len() as u32,
                };
                o.arena_written = words.len() as u64;
                o.flags = EMIT_TO_FAR_END;
            }
            FROM_FAR_END => {
                // SAFETY: the driver's buffer of `units_cap` (> 0) counts.
                unsafe {
                    *i.units_buf = UnitCount {
                        class: 0,
                        source: UNITS_REPORTED,
                        amount: 5,
                    };
                }
                o.units_written = 1;
                o.reply_status = i.status_code;
                o.flags = EMIT_DONE;
                o.fault = self.fault;
            }
            _ => {}
        }
        Box::new(Now(o))
    }
}

/// The money seam, counting every call: a probe makes none.
#[derive(Default)]
struct Till(AtomicU64);

impl Till {
    fn count(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl MoneySeam for Till {
    fn checkpoint(&self, _: &UnitCtx, _: &[UnitCount]) -> Checkpoint {
        self.count();
        Checkpoint::Continue
    }
    fn cancelled(&self, _: &UnitCtx, _: &CancelBill) {
        self.count();
    }
    fn finished(&self, _: &UnitCtx) {
        self.count();
    }
    fn served(&self, _: &UnitCtx, _: &str, _: &str) {
        self.count();
    }
    fn abandoned(&self, _: &UnitCtx, _: Ended) {
        self.count();
    }
}

/// The journal, counting every record it is asked to write: a probe writes none.
#[derive(Default)]
struct Ledger {
    dispatched: AtomicU64,
    abandoned: AtomicU64,
}

impl Journal for Ledger {
    fn dispatched(&self, _: &Dispatched) -> Result<(), DurabilityUnavailable> {
        self.dispatched.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn abandoned(&self, _: &Dispatched) {
        self.abandoned.fetch_add(1, Ordering::SeqCst);
    }
}

// ── the rig ─────────────────────────────────────────────────────────────────────────────────────

const TIMEOUT: Duration = Duration::from_secs(5);

/// The first member, tripped: its cooldown never ends on its own.
const TRIPPED: DestinationId = DestinationId::new(1);

struct Probing {
    plane: Arc<Prober>,
    till: Arc<Till>,
    journal: Arc<Ledger>,
    table: Arc<Table>,
    book: Arc<Book>,
    probes: PlaneProbes,
}

/// The target over `hosts` (see [`rig`]) for a plane `plane` whose tail flags are `tail`, probing
/// the first member, which is tripped.
fn probing(hosts: &[(&'static str, Script)], plane: Prober, tail: u32) -> Option<Probing> {
    let mut r = rig(hosts, OnExhausted::Status503, None);
    let journal = Arc::new(Ledger::default());
    r.egress.journal = journal.clone();
    r.book.cooldown.lock().unwrap().insert(TRIPPED, u64::MAX);
    let plane = Arc::new(plane);
    let till = Arc::new(Till::default());
    let driver = PlaneDriver::new(
        plane.clone(),
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("probe")],
            status_of: refusal_status,
            refusal_statuses: Vec::new(),
            caller_refs: None,
        },
        till.clone(),
        Arc::new(crate::host_services::KernelServices::new()),
        ("probe", &serde_yaml::Value::Null),
    )
    .expect("the instance is admitted");
    let probes = PlaneProbes::new(
        tail,
        Arc::new(driver),
        Arc::new(r.egress),
        Arc::new(Kernel::new()),
        Arc::new(UnitKeyMint::default()),
        vec![TRIPPED],
    )?;
    Some(Probing {
        plane,
        till,
        journal,
        table: r.table,
        book: r.book,
        probes,
    })
}

fn probed(p: &Probing) -> Vec<(DestinationId, Outcome)> {
    p.book.probed.lock().unwrap().clone()
}

// ── the probe's answer in the served breaker (F25 row 155 rehomes) ─────────────────────────────

/// THE SERVED BREAKER for the probe cases that pin a cell's state: busbar-kernel-breaker's unit
/// bound to the egress port as the composition root's `BreakerAdapter` binds it
/// (`crates/busbar/src/root/adapters.rs`), every pool under the default ladder.
struct Cells(busbar_kernel_breaker::BreakerUnit);

impl busbar_kernel_egress::ports::Breaker for Cells {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        use busbar_kernel_breaker::LaneState;
        self.0
            .try_admit(pool, destination, now)
            .map_err(|state| match state {
                LaneState::Suppressed { until } => Unavailable::BreakerOpen { until },
                LaneState::BudgetExhausted => Unavailable::BudgetExhausted,
                LaneState::ProbeInFlight | LaneState::Ready => Unavailable::ProbeInFlight,
            })
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        busbar_kernel_breaker::Breaker::state(&self.0, pool, destination, now, token)
            == busbar_kernel_breaker::LaneState::Ready
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        self.0.budget_remaining(destination) != Some(0)
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        match busbar_kernel_breaker::Breaker::state(&self.0, pool, destination, now, token) {
            busbar_kernel_breaker::LaneState::Suppressed { until } => until.saturating_sub(now),
            _ => 0,
        }
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        // The root adapter's own reading (`root::adapters`): no number crosses, the transport's
        // fault reading of the frame does; no class and no reading at all is no answer.
        let reading = if status.class.is_none() && status.fault.is_none() {
            busbar_kernel_breaker::classify::Reading::NoAnswer
        } else {
            busbar_kernel_breaker::classify::Reading::Answered(status.fault)
        };
        busbar_kernel_breaker::port::classify_upstream(
            busbar_kernel_breaker::port::UpstreamStatus {
                reading,
                retry_after: status.retry_after,
            },
        )
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        busbar_kernel_breaker::Breaker::observe(
            &self.0,
            pool,
            destination,
            outcome,
            &busbar_kernel_breaker::cfg::BreakerCfg::default(),
            now,
            token,
        )
    }

    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        self.0.suppressing(destination, now)
    }

    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, token: &Pass<Route>) {
        self.0.probed(
            destination,
            outcome,
            &|_: &str| Some(busbar_kernel_breaker::cfg::BreakerCfg::default()),
            now,
            token,
        );
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, _now: u64) {
        self.0.release_probe(pool, destination, epoch);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.0.spend_budget(destination)
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.0.refund_budget(destination);
    }
}

/// The probe target over the SERVED breaker for a plane that declares probes: the rig's first
/// member (`a.test`, answering `script`, destination [`TRIPPED`]), its cell in pool [`POOL`] made
/// as organic traffic makes it. Answers the target, the breaker and the connection table.
fn probing_served(script: Script) -> (PlaneProbes, Arc<Cells>, Arc<Table>) {
    let mut r = rig(&[("a.test", script)], OnExhausted::Status503, None);
    let cells = Arc::new(Cells(busbar_kernel_breaker::BreakerUnit::new()));
    let _ = cells.0.cell(POOL, TRIPPED);
    r.egress.breaker = crate::plane_driver::fixed_breaker(Arc::clone(&cells) as _);
    let driver = PlaneDriver::new(
        Arc::new(Prober::default()),
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("probe")],
            status_of: refusal_status,
            refusal_statuses: Vec::new(),
            caller_refs: None,
        },
        Arc::new(Till::default()),
        Arc::new(crate::host_services::KernelServices::new()),
        ("probe", &serde_yaml::Value::Null),
    )
    .expect("the instance is admitted");
    let probes = PlaneProbes::new(
        TAIL_PROBES,
        Arc::new(driver),
        Arc::new(r.egress),
        Arc::new(Kernel::new()),
        Arc::new(UnitKeyMint::default()),
        vec![TRIPPED],
    )
    .expect("the plane declares probes");
    (probes, cells, r.table)
}

/// F25 row 189: rehomed from the retired engine crate's src/engine/tests/forward_pool_integration_tests.rs::test_health_probe_failure_records_transient.
/// A probe whose far end ANSWERS 500 `{"error":"down"}` records exactly one transient against the
/// member in the served breaker: its default cell's and its pool cell's error counts each rise by 1.
#[tokio::test]
async fn test_health_probe_failure_records_transient() {
    let (probes, cells, table) =
        probing_served(Script::Answer(500, None, vec![b"{\"error\":\"down\"}"]));
    let before = (
        cells.0.cell("", TRIPPED).err_count(),
        cells.0.cell(POOL, TRIPPED).err_count(),
    );

    probes.probe(0, TIMEOUT).await;

    assert_eq!(table.opened.lock().unwrap().len(), 1, "the probe was sent");
    assert_eq!(
        cells.0.cell("", TRIPPED).err_count(),
        before.0 + 1,
        "a failing health probe records a transient error"
    );
    assert_eq!(cells.0.cell(POOL, TRIPPED).err_count(), before.1 + 1);
}

/// F25 row 221: rehomed from the retired engine crate's src/engine/tests/health_tests.rs::test_probe_auth_failure_is_hard_down_not_transient.
/// A 401 probe answer parks the member hard-down: the default cell is Open and the pool cell carries
/// the long sticky hard-down cooldown (more than 60 s), and no transient is recorded.
#[tokio::test]
async fn test_probe_auth_failure_is_hard_down_not_transient() {
    let (probes, cells, _table) = probing_served(Script::Answer(401, None, vec![b"unauthorized"]));

    probes.probe(0, TIMEOUT).await;

    let now = Wall.now_secs();
    assert!(
        matches!(
            cells.0.cell("", TRIPPED).state(),
            busbar_kernel_breaker::cell::BreakerState::Open { .. }
        ),
        "a 401 probe trips the default cell Open (hard-down), got {:?}",
        cells.0.cell("", TRIPPED).state()
    );
    assert!(
        cells
            .0
            .cell(POOL, TRIPPED)
            .cooldown_until()
            .saturating_sub(now)
            > 60,
        "a 401 probe arms the long sticky hard-down cooldown on the pool cell, not a short \
         transient one"
    );
    assert_eq!(
        cells.0.cell("", TRIPPED).err_count(),
        0,
        "and it is not recorded as a transient"
    );
}

/// F25 row 222: rehomed from the retired engine crate's src/engine/tests/health_tests.rs::test_probe_server_error_is_transient_not_hard_down.
/// A single 503 probe answer is a transient: one failure is recorded, and the default cell stays
/// Closed (one sub-threshold transient under the default error-rate breaker), never the hard-down.
#[tokio::test]
async fn test_probe_server_error_is_transient_not_hard_down() {
    let (probes, cells, _table) = probing_served(Script::Answer(
        503,
        None,
        vec![b"{\"error\":\"upstream down\"}"],
    ));

    probes.probe(0, TIMEOUT).await;

    assert_eq!(
        cells.0.cell("", TRIPPED).state(),
        busbar_kernel_breaker::cell::BreakerState::Closed,
        "a single 503 probe records a transient, no immediate hard-down trip"
    );
    assert_eq!(cells.0.cell("", TRIPPED).err_count(), 1);
}

/// F25 row 234: rehomed from the retired engine crate's src/engine/tests/health_tests.rs::test_probe_with_an_unrepresentable_timeout_still_classifies.
/// A probe under a timeout the clock cannot represent (2^63 s) runs to its classification and does
/// not panic: the far end's 401 still parks the member, its default cell Open.
#[tokio::test]
async fn test_probe_with_an_unrepresentable_timeout_still_classifies() {
    let (probes, cells, _table) = probing_served(Script::Answer(401, None, vec![b"unauthorized"]));

    probes.probe(0, Duration::from_secs(1u64 << 63)).await;

    assert!(
        matches!(
            cells.0.cell("", TRIPPED).state(),
            busbar_kernel_breaker::cell::BreakerState::Open { .. }
        ),
        "the probe completes and classifies the 401, got {:?}",
        cells.0.cell("", TRIPPED).state()
    );
}

// ── the cases ───────────────────────────────────────────────────────────────────────────────────

/// THE ACCEPTANCE: a tripped member is probed past its breaker; the plane's probe request goes to
/// it alone and its 200 recovers it. The unit arrived on the probe claim and pushed its ATTEMPT
/// piece alone (no caller body), recorded nothing organic, spent no budget and billed nothing,
/// though the plane reported units.
#[tokio::test]
async fn a_probe_recovers_a_tripped_member() {
    let hosts = [("a.test", Script::Answer(200, None, vec![b"ok"]))];
    let p = probing(&hosts, Prober::default(), TAIL_PROBES).expect("the plane declares probes");
    assert!(p.probes.suppressing(0));

    p.probes.probe(0, TIMEOUT).await;

    assert_eq!(probed(&p), vec![(TRIPPED, Outcome::Success)]);
    assert!(!p.probes.suppressing(0), "recovered");
    assert_eq!(*p.plane.claims.lock().unwrap(), vec![CLAIM_PROBE]);
    assert_eq!(
        *p.plane.pieces.lock().unwrap(),
        vec![(FROM_KERNEL, 1), (FROM_FAR_END, 0)]
    );
    let opened = p.table.opened.lock().unwrap();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].0, "https://a.test/v1/health");
    assert_eq!(p.table.words.lock().unwrap()[0].0, PROBE.0);
    assert!(p.book.observed.lock().unwrap().is_empty());
    assert_eq!(p.book.spent.load(Ordering::SeqCst), 0);
    assert_eq!(
        p.book.refunded.load(Ordering::SeqCst),
        0,
        "a probe spends no budget, so there is none to refund"
    );
    assert_eq!(p.till.0.load(Ordering::SeqCst), 0, "zero-billed");
}

/// A probe writes no dispatch record: no `dispatched` line to recover from and no `abandoned`
/// line to match it, on the answered path and on the no-answer path alike.
#[tokio::test]
async fn a_probe_writes_no_dispatch_record() {
    for script in [Script::Answer(200, None, vec![b"ok"]), Script::Refused] {
        let p = probing(&[("a.test", script)], Prober::default(), TAIL_PROBES)
            .expect("the plane declares probes");
        p.probes.probe(0, TIMEOUT).await;
        assert_eq!(
            p.table.opened.lock().unwrap().len(),
            1,
            "the probe was sent"
        );
        assert_eq!(p.journal.dispatched.load(Ordering::SeqCst), 0);
        assert_eq!(p.journal.abandoned.load(Ordering::SeqCst), 0);
    }
}

/// A client-fault answer is the probe request's fault, not the member's: it records nothing, and
/// the tripped member stays tripped.
#[tokio::test]
async fn a_client_fault_answer_records_nothing() {
    let hosts = [("a.test", Script::Answer(400, None, vec![b"bad probe"]))];
    let p = probing(&hosts, Prober::default(), TAIL_PROBES).expect("the plane declares probes");
    p.probes.probe(0, TIMEOUT).await;
    assert_eq!(probed(&p), vec![(TRIPPED, Outcome::RecordNothing)]);
    assert!(p.probes.suppressing(0), "still tripped");
}

/// THE PLANE'S READING OF A PROBE ANSWER is recorded as an organic answer's is (Part 3 §12: the
/// breaker service classifies the probe's answer as it classifies organic traffic): a 502 the plane
/// reads HEALTHY is a success on every cell and recovers the member. RED before the plane's reading
/// was read on a probe: the transport's 502 was recorded at once, a transient, and the member stayed
/// tripped.
#[tokio::test]
async fn a_probe_answer_the_plane_reads_healthy_records_success() {
    let hosts = [(
        "a.test",
        Script::Answer(502, None, vec![b"an error, well formed"]),
    )];
    let plane = Prober {
        fault: FAULT_HEALTHY,
        ..Prober::default()
    };
    let p = probing(&hosts, plane, TAIL_PROBES).expect("the plane declares probes");
    p.probes.probe(0, TIMEOUT).await;
    assert_eq!(probed(&p), vec![(TRIPPED, Outcome::Success)]);
    assert!(!p.probes.suppressing(0), "recovered");
    assert!(
        p.book.observed.lock().unwrap().is_empty(),
        "nothing organic"
    );
}

/// A probe answer the plane reads as a FAULT records that fault, over the transport's reading: a
/// 400 (the caller's, by the table: nothing) the plane reads TRANSIENT is a transient, and a 502
/// (transient, by the table) the plane reads HARD is a hard-down. RED before the plane's reading
/// was read on a probe: the table's reading was recorded (nothing; a transient).
#[tokio::test]
async fn a_probe_answer_the_plane_reads_as_a_fault_records_that_fault() {
    for (code, fault, outcome) in [
        (
            400,
            FAULT_TRANSIENT,
            Outcome::Transient { retry_after: None },
        ),
        (502, FAULT_HARD, Outcome::HardDown),
    ] {
        let hosts = [("a.test", Script::Answer(code, None, vec![b"no"]))];
        let plane = Prober {
            fault,
            ..Prober::default()
        };
        let p = probing(&hosts, plane, TAIL_PROBES).expect("the plane declares probes");
        p.probes.probe(0, TIMEOUT).await;
        assert_eq!(probed(&p), vec![(TRIPPED, outcome)], "{code}");
        assert!(p.probes.suppressing(0), "{code}: still tripped");
    }
}

/// A probe answer the plane states NO reading of is recorded with the transport's: the table's
/// transient for a 502.
#[tokio::test]
async fn a_probe_answer_the_plane_states_no_reading_of_records_the_tables() {
    let hosts = [("a.test", Script::Answer(502, None, vec![b"down"]))];
    let p = probing(&hosts, Prober::default(), TAIL_PROBES).expect("the plane declares probes");
    p.probes.probe(0, TIMEOUT).await;
    assert_eq!(
        probed(&p),
        vec![(TRIPPED, Outcome::Transient { retry_after: None })]
    );
}

/// A probe that brings no answer is a transient on the member, and the probe tries no other.
#[tokio::test]
async fn a_probe_that_brings_no_answer_is_a_transient_and_tries_no_other_member() {
    let hosts = [
        ("a.test", Script::Refused),
        ("b.test", Script::Answer(200, None, vec![b"ok"])),
    ];
    let p = probing(&hosts, Prober::default(), TAIL_PROBES).expect("the plane declares probes");
    p.probes.probe(0, TIMEOUT).await;
    assert_eq!(
        probed(&p),
        vec![(TRIPPED, Outcome::Transient { retry_after: None })]
    );
    assert_eq!(p.table.opened.lock().unwrap().len(), 1);
    assert_eq!(p.till.0.load(Ordering::SeqCst), 0, "zero-billed");
    assert_eq!(p.book.spent.load(Ordering::SeqCst), 0);
    assert_eq!(p.book.refunded.load(Ordering::SeqCst), 0);
}

/// A plane that refuses the probe arrival sends nothing, and nothing is recorded.
#[tokio::test]
async fn a_plane_that_refuses_the_probe_sends_nothing() {
    let hosts = [("a.test", Script::Answer(200, None, vec![b"ok"]))];
    let plane = Prober {
        refuse: true,
        ..Prober::default()
    };
    let p = probing(&hosts, plane, TAIL_PROBES).expect("the plane declares probes");
    p.probes.probe(0, TIMEOUT).await;
    assert!(p.table.opened.lock().unwrap().is_empty());
    assert!(probed(&p).is_empty());
}

/// A plane that does not state `TAIL_PROBES` gets no target, and a member configured for
/// passthrough (no credential of its own) gets no probe far end.
#[test]
fn an_undeclared_plane_and_a_passthrough_member_are_never_probed() {
    let hosts = [("a.test", Script::Answer(200, None, vec![b"ok"]))];
    assert!(probing(&hosts, Prober::default(), 0).is_none());
    let r = rig(
        &[
            ("a.test", Script::Answer(200, None, vec![b"ok"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    assert!(r.egress.probe(DestinationId::new(1), TIMEOUT).is_some());
    assert!(
        r.egress.probe(DestinationId::new(2), TIMEOUT).is_none(),
        "the rig's second member is passthrough"
    );
}
