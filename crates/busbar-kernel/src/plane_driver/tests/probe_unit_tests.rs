// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEALTH PROBE, schedule target to wire (K7), over the far end's doubles and a plane double
//! that declares probes: the probe unit arrives on the probe claim, pushes its ATTEMPT piece alone,
//! sends the request the plane emitted to the ONE member it is pinned to (past that member's
//! breaker), and the far end's answer is recorded on every cell of it. Proven: a probe recovers a
//! tripped member; a client-fault answer records nothing; a probe that brings no answer is a
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
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, RefusalIn, RefusalOut, ServeIn, ServeOut,
    UnitCount, CLAIM_PROBE, EMIT_DONE, EMIT_TO_FAR_END, FROM_FAR_END, FROM_KERNEL, TAIL_PROBES,
    UNITS_REPORTED,
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

    fn refusal(
        &self,
        _: &mut RefusalIn,
        _: &mut RefusalOut,
        _: Grow<'_, RefusalIn, RefusalOut>,
    ) -> AbiOutcome {
        AbiOutcome::Fault
    }

    fn cancel(&self, _: PlaneTicket) -> Option<u32> {
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
