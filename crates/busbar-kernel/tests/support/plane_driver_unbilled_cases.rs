// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PROVIDER-CHARGED USAGE THAT BILLED 0 (design `unbilled`, K0/K0a/K0b/K4): a unit whose plane
//! said done has stated its final usage, so a cancel that follows it (any cause) bills that usage,
//! priced at the member that served it; a refused or unpriced final report bills the last accepted
//! one and is audited as unread (`BUSBAR-5046`).
//!
//! THE FIXTURE. A scripted plane over a two-member pool `[a, b]` (or `[b]` alone). Member `a`
//! answers its head piece (a 503) with `VERDICT_RETRY` and nothing emitted, so the walk fails
//! over (route.rs `Step::Retry`) and `served` never runs for `a`. Member `b` is a buffered
//! non-stream answer: its head piece (status 200, not last) is usage-only (3 in, 4 out, nothing
//! emitted, `reply_status == 0`), folded at the walk's checkpoint; its last piece is the plane's
//! done piece (`EMIT_DONE`, `more == 0`), carrying the head, the body and (7 in, 11 out), unless a
//! case states another final answer. The money seam records every call in order.

use super::*;

use std::collections::VecDeque;

use futures::FutureExt as _;

use busbar_contract::caps::{Outcome as UnitOutcome, Pass, ReasonCode, Route};
use busbar_contract::plane::codes::{VERDICT_COUNT_REFUSED, VERDICT_RETRY};
use busbar_contract::Count;
use busbar_kernel::canary::Canary;
use busbar_kernel::plane_driver::{
    AuditSink, CallerEnd, CancelBill, Checkpoint, FarEnd, FarPiece, MoneySeam, OutboundRequest,
    Pick, PlaneUnits, SessionCaller,
};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run, UnitCtx};

const INPUT: u32 = 0;
const OUTPUT: u32 = 1;
const REFUSED_WORDS: &[u8] = b"usage count input is outside the declared store range";

fn reported(input: u64, output: u64) -> Vec<UnitCount> {
    vec![
        UnitCount {
            class: INPUT,
            source: UNITS_REPORTED,
            amount: input,
        },
        UnitCount {
            class: OUTPUT,
            source: UNITS_REPORTED,
            amount: output,
        },
    ]
}

fn billed(input: u64, output: u64) -> Vec<(u32, Count)> {
    vec![(INPUT, Count::from(input)), (OUTPUT, Count::from(output))]
}

/// One scripted `on_piece` answer.
#[derive(Clone)]
struct Reply {
    flags: u32,
    verdict: u32,
    status: u32,
    body: Vec<u8>,
    units: Vec<UnitCount>,
    fault_reason: &'static [u8],
}

impl Reply {
    fn blank() -> Self {
        Reply {
            flags: 0,
            verdict: 0,
            status: 0,
            body: Vec::new(),
            units: Vec::new(),
            fault_reason: b"",
        }
    }

    /// `a`'s head: a retryable failure, nothing emitted (the walk fails over).
    fn retry() -> Self {
        Reply {
            verdict: VERDICT_RETRY,
            ..Reply::blank()
        }
    }

    /// `b`'s head: usage only.
    fn usage(input: u64, output: u64) -> Self {
        Reply {
            units: reported(input, output),
            ..Reply::blank()
        }
    }

    /// `b`'s done piece: the head, the body and the final stated usage.
    fn done(input: u64, output: u64) -> Self {
        Reply {
            flags: EMIT_DONE,
            status: 200,
            body: b"the answer".to_vec(),
            units: reported(input, output),
            ..Reply::blank()
        }
    }

    /// `b`'s done piece whose count the plane refused (what plane-llm writes for a negative
    /// count): `VERDICT_COUNT_REFUSED`, `EMIT_DONE`, the head and body, (input -5, output 11).
    fn refused_done() -> Self {
        Reply {
            verdict: VERDICT_COUNT_REFUSED,
            fault_reason: REFUSED_WORDS,
            units: vec![
                UnitCount {
                    class: INPUT,
                    source: UNITS_REPORTED,
                    amount: (-5i64) as u64,
                },
                UnitCount {
                    class: OUTPUT,
                    source: UNITS_REPORTED,
                    amount: 11,
                },
            ],
            ..Reply::done(0, 0)
        }
    }
}

struct Gate {
    answer: Mutex<Option<OnPieceOut>>,
    waker: Mutex<Option<Waker>>,
    out: OnPieceOut,
}

// SAFETY: the `OnPieceOut`s are plain data the plane wrote; their pointers are never dereferenced.
unsafe impl Send for Gate {}
unsafe impl Sync for Gate {}

impl Gate {
    fn release(&self, wake: bool) {
        *self.answer.lock().unwrap() = Some(self.out);
        if wake {
            if let Some(w) = self.waker.lock().unwrap().take() {
                w.wake();
            }
        }
    }
}

enum Flight {
    Now(Box<OnPieceOut>),
    Held(Arc<Gate>),
}

// SAFETY: as `Gate`.
unsafe impl Send for Flight {}

const READY: Answered = Answered {
    outcome: Outcome::Ready,
    short: false,
    disposition: None,
};

impl Future for Flight {
    type Output = Answered;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Answered> {
        match &*self {
            Flight::Now(_) => Poll::Ready(READY),
            Flight::Held(gate) => {
                if gate.answer.lock().unwrap().is_some() {
                    return Poll::Ready(READY);
                }
                *gate.waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl PieceInFlight for Flight {
    fn settled(&mut self) -> Option<Answered> {
        match self {
            Flight::Now(_) => Some(READY),
            Flight::Held(gate) => gate.answer.lock().unwrap().map(|_| READY),
        }
    }
    fn out(&self) -> Option<OnPieceOut> {
        match self {
            Flight::Now(out) => Some(**out),
            Flight::Held(gate) => *gate.answer.lock().unwrap(),
        }
    }
}

/// The scripted plane: see the module doc.
#[derive(Default)]
struct Scripted {
    next: AtomicU32,
    member: Mutex<Vec<u8>>,
    far_pieces: AtomicU32,
    /// `b`'s answers, piece by piece; `[usage(3, 4), done(7, 11)]` when unset.
    script: Mutex<Option<Vec<Reply>>>,
    /// `b`'s last answer stays in flight until the kernel drops its client (a cancel) or the case
    /// releases it.
    hold: AtomicBool,
    held: Mutex<Option<Arc<Gate>>>,
    held_notice: tokio::sync::Notify,
    cancels: AtomicU32,
}

impl Scripted {
    fn script(&self) -> Vec<Reply> {
        self.script
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| vec![Reply::usage(3, 4), Reply::done(7, 11)])
    }

    /// `b`'s head reports (3, 4); its last piece answers `last`.
    fn answering(last: Reply) -> Self {
        let plane = Scripted::default();
        *plane.script.lock().unwrap() = Some(vec![Reply::usage(3, 4), last]);
        plane
    }

    /// As [`Scripted::answering`], with the last answer held in flight.
    fn holding(last: Reply) -> Self {
        let plane = Scripted::answering(last);
        plane.hold.store(true, Ordering::SeqCst);
        plane
    }

    fn is_held(&self) -> bool {
        self.held.lock().unwrap().is_some()
    }

    /// Settle the held answer without waking its task (it settled before the unit was dropped).
    fn settle_quietly(&self) {
        if let Some(gate) = self.held.lock().unwrap().as_ref() {
            gate.release(false);
        }
    }

    fn reply_for(&self, member: &[u8], index: u32) -> (Reply, bool) {
        if member == b"a" {
            return (Reply::retry(), false);
        }
        let script = self.script();
        let last = index as usize + 1 >= script.len();
        let reply = script
            .get(index as usize)
            .cloned()
            .unwrap_or_else(Reply::blank);
        (reply, last)
    }
}

/// Write `reply` into the driver's buffers.
unsafe fn answer(i: &OnPieceIn, mut o: OnPieceOut, reply: &Reply) -> OnPieceOut {
    assert!(reply.body.len() <= i.reply_cap && reply.units.len() <= i.units_cap);
    std::ptr::copy_nonoverlapping(reply.body.as_ptr(), i.reply_buf, reply.body.len());
    for (k, u) in reply.units.iter().enumerate() {
        *i.units_buf.add(k) = *u;
    }
    let mut at = 0;
    if !reply.fault_reason.is_empty() {
        o.fault_reason = put(i, &mut at, reply.fault_reason);
    }
    o.arena_written = at as u64;
    o.emitted = reply.body.len() as u64;
    o.units_written = reply.units.len() as u32;
    o.flags = reply.flags;
    o.verdict = reply.verdict;
    o.reply_status = reply.status;
    o.more = 0;
    o
}

impl PlaneCalls for Scripted {
    fn now_ns(&self) -> u64 {
        now_ns()
    }

    fn arrive(
        &self,
        input: &mut ArriveIn,
        out: &mut ArriveOut,
        _: Grow<'_, ArriveIn, ArriveOut>,
    ) -> Outcome {
        // SAFETY: the driver's buffer of `units_cap` (> 0) counts.
        unsafe {
            *input.units_buf = UnitCount {
                class: INPUT,
                source: UNITS_ESTIMATED,
                amount: 1,
            };
        }
        out.units_written = 1;
        out.op_class = 0;
        out.dialect = 0;
        out.principal_need = PRINCIPAL_OPTIONAL;
        Outcome::Ready
    }

    fn arrived_pool(&self, _: &ArriveOut) -> Option<Vec<u8>> {
        None
    }

    fn refusal(
        &self,
        _: &mut RefusalIn,
        _: &mut RefusalOut,
        _: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome {
        Outcome::Fault
    }

    fn project(
        &self,
        _: &mut ProjectIn,
        _: &mut ProjectOut,
        _: Grow<'_, ProjectIn, ProjectOut>,
    ) -> Outcome {
        Outcome::Ready
    }

    fn cancel(&self, _: Ticket, _: u64) -> Option<busbar_contract::plane_calls::Cancelled> {
        self.cancels.fetch_add(1, Ordering::SeqCst);
        Some(busbar_contract::plane_calls::Cancelled {
            disposition: CANCEL_FAILED,
            writes: Vec::new(),
        })
    }

    fn declared(&self) -> InstanceDecl {
        InstanceDecl {
            label: "unbilled".into(),
            ..InstanceDecl::default()
        }
    }

    fn driver(&self) -> Option<Ticket> {
        self.mint()
    }

    fn tick(&self, _: Ticket, _: u64) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
        Box::pin(std::future::ready(Some(0)))
    }

    fn ready(&self) -> Pin<Box<dyn Future<Output = Vec<u64>> + Send>> {
        Box::pin(std::future::ready(Vec::new()))
    }

    fn mint(&self) -> Option<Ticket> {
        Some(Ticket {
            slot: self.next.fetch_add(1, Ordering::SeqCst),
            generation: 1,
        })
    }

    fn recycle(&self, _: Ticket) {}

    /// The kernel cancels the piece in flight: the plane completes it (Ready, its scripted answer).
    fn drop_client(&self, _: Ticket) {
        if let Some(gate) = self.held.lock().unwrap().as_ref() {
            gate.release(true);
        }
    }

    fn serve(&self, _: Ticket, _: ServeIn, _: ServeOut, _: Lent) -> Box<dyn ServeInFlight> {
        unreachable!("no unit here is served")
    }

    fn on_piece(&self, _: Ticket, i: OnPieceIn, o: OnPieceOut, _: Lent) -> Box<dyn PieceInFlight> {
        match i.from {
            FROM_KERNEL if i.attempt_no > 0 => {
                // SAFETY: the driver's member string, alive for the call.
                *self.member.lock().unwrap() = unsafe { text(i.member) }.to_vec();
                self.far_pieces.store(0, Ordering::SeqCst);
                Box::new(Flight::Now(Box::new(o)))
            }
            FROM_FAR_END => {
                let member = self.member.lock().unwrap().clone();
                let index = self.far_pieces.fetch_add(1, Ordering::SeqCst);
                let (reply, last) = self.reply_for(&member, index);
                // SAFETY: the driver's buffers of the stated capacities.
                let out = unsafe { answer(&i, o, &reply) };
                if member == b"b" && last && self.hold.load(Ordering::SeqCst) {
                    let gate = Arc::new(Gate {
                        answer: Mutex::new(None),
                        waker: Mutex::new(None),
                        out,
                    });
                    *self.held.lock().unwrap() = Some(Arc::clone(&gate));
                    self.held_notice.notify_one();
                    Box::new(Flight::Held(gate))
                } else {
                    Box::new(Flight::Now(Box::new(out)))
                }
            }
            _ => Box::new(Flight::Now(Box::new(o))),
        }
    }
}

/// The pool: `a` answers a 503 (one last piece), every other member a head piece then a last one.
struct Pool {
    members: Vec<&'static str>,
    /// How many pieces a member other than `a` answers in.
    pieces: usize,
    current: Mutex<VecDeque<FarPiece>>,
    sends: AtomicU32,
}

impl Pool {
    fn new(members: &[&'static str]) -> Self {
        Pool {
            members: members.to_vec(),
            pieces: 2,
            current: Mutex::new(VecDeque::new()),
            sends: AtomicU32::new(0),
        }
    }
}

impl FarEnd for Pool {
    fn member<'a>(
        &'a self,
        _: &'a Pass<Route>,
        attempt_no: u32,
    ) -> impl Future<Output = Pick> + Send + 'a {
        let pick = match self.members.get(attempt_no as usize - 1) {
            Some(m) => Pick::Member {
                name: (*m).into(),
                pool: "p".into(),
                passthrough: false,
                provider: format!("prov-{m}").as_str().into(),
            },
            None => Pick::Exhausted {
                status: 503,
                retry_after: None,
                detail: "exhausted",
            },
        };
        async move { pick }
    }

    fn send<'a>(
        &'a self,
        _: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        self.sends.fetch_add(1, Ordering::SeqCst);
        let piece = |bytes: &[u8], status: Option<(u32, u32)>, last: bool| FarPiece {
            bytes: bytes.to_vec(),
            status,
            last,
            ..FarPiece::default()
        };
        let script = if request.member == "a" {
            vec![piece(b"overloaded", Some((503, 5)), true)]
        } else {
            (0..self.pieces)
                .map(|k| {
                    piece(
                        b"{\"part\":1}",
                        (k == 0).then_some((200, 2)),
                        k + 1 == self.pieces,
                    )
                })
                .collect()
        };
        *self.current.lock().unwrap() = script.into_iter().collect();
        async { true }
    }

    async fn next(&self, _: &Pass<Route>) -> Option<FarPiece> {
        self.current.lock().unwrap().pop_front()
    }

    async fn write(&self, _: &Pass<Route>, _: OutboundRequest) -> bool {
        false
    }
}

/// The caller: its `n`th write (from 0) fails (`fail_at`) or never completes (`stall_at`).
#[derive(Default)]
struct Leaving {
    fail_at: Option<u64>,
    stall_at: Option<u64>,
    writes: AtomicU64,
    stalled: AtomicBool,
    status: Mutex<Option<u32>>,
}

impl CallerEnd for Leaving {
    fn head(&self, status: u32, _: Vec<(Vec<u8>, Vec<u8>)>) {
        *self.status.lock().unwrap() = Some(status);
    }

    async fn write(&self, _: &[u8]) -> bool {
        let n = self.writes.fetch_add(1, Ordering::SeqCst);
        if self.stall_at == Some(n) {
            self.stalled.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        self.fail_at != Some(n)
    }
}

impl SessionCaller for Leaving {
    async fn read(&self) -> Option<Vec<u8>> {
        None
    }
}

/// The money seam, recording every call in order.
#[derive(Default)]
struct Till {
    events: Mutex<Vec<String>>,
    bills: Mutex<Vec<CancelBill>>,
    /// The checkpoint answer for a report whose output count is this.
    unpriced_at: Option<u64>,
    cut_at: Option<u64>,
}

impl Till {
    fn event(&self, e: String) {
        self.events.lock().unwrap().push(e);
    }
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
    fn bills(&self) -> Vec<CancelBill> {
        self.bills.lock().unwrap().clone()
    }
    fn served(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter(|e| e.starts_with("served"))
            .collect()
    }
    /// The serving member named before the one bill was ledgered.
    fn served_before_the_bill(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .take_while(|e| e != "cancelled")
            .filter(|e| e.starts_with("served"))
            .collect()
    }
}

impl MoneySeam for Till {
    fn checkpoint(&self, _: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        let output = units
            .iter()
            .find(|u| u.class == OUTPUT)
            .map_or(0, |u| u.amount);
        self.event(format!("checkpoint:{output}"));
        if self.unpriced_at == Some(output) {
            Checkpoint::Unpriced
        } else if self.cut_at == Some(output) {
            Checkpoint::Cut
        } else {
            Checkpoint::Continue
        }
    }

    fn cancelled(&self, _: &UnitCtx, bill: &CancelBill) {
        self.event("cancelled".to_string());
        self.bills.lock().unwrap().push(bill.clone());
    }

    fn abandoned(&self, _: &UnitCtx, _: Ended) {}

    fn served(&self, _: &UnitCtx, member: &str, provider: &str) {
        self.event(format!("served:{member}:{provider}"));
    }

    fn laned(&self, _: &UnitCtx, lane: &str) {
        self.event(format!("laned:{lane}"));
    }
}

/// The driver's audit chain, recording every row.
#[derive(Default)]
struct Rows(Mutex<Vec<(String, String, &'static str)>>);

impl AuditSink for Rows {
    fn record(&self, action: &str, resource: &str, outcome: &'static str, _principal: &str) {
        self.0
            .lock()
            .unwrap()
            .push((action.to_string(), resource.to_string(), outcome));
    }
}

impl Rows {
    /// The `BUSBAR-5046 plane-usage-unread` rows: the reason each names.
    fn unread(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(action, _, _)| action == "plane-usage-unread")
            .map(|(_, resource, _)| resource.clone())
            .collect()
    }
}

struct Fixture {
    plane: Arc<Scripted>,
    till: Arc<Till>,
    rows: Arc<Rows>,
    driver: PlaneDriver,
}

fn fixture(plane: Scripted, till: Till) -> Fixture {
    let plane = Arc::new(plane);
    let till = Arc::new(till);
    let rows = Arc::new(Rows::default());
    let driver = PlaneDriver::new(
        plane.clone(),
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("call")],
            status_of: refusal_status,
            refusal_statuses: cases::statuses(),
            caller_refs: None,
        },
        till.clone(),
        services(),
        ("unbilled", &busbar_contract::yaml::Value::Null),
    )
    .now_or_never()
    .expect("non-persistent fixture admission completes immediately")
    .expect("the instance is admitted")
    .with_audit(rows.clone());
    Fixture {
        plane,
        till,
        rows,
        driver,
    }
}

async fn drive<F: FarEnd, C: CallerEnd + SessionCaller>(
    units: &PlaneUnits<'_, common::TestUnits, F, C>,
    key: u64,
) -> UnitOutcome {
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        Canary::new(),
        LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = common::cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
        taps: None,
    };
    match run_unit_async(&kernel, units, &common::ctx(key), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}

/// Poll `fut` until `ready` holds (the unit reached the state the case drops it in).
async fn poll_until<F: Future + Unpin>(fut: &mut F, ready: impl Fn() -> bool) {
    for _ in 0..1_000 {
        if ready() {
            return;
        }
        assert!(
            futures::poll!(&mut *fut).is_pending(),
            "the unit ended first"
        );
        tokio::task::yield_now().await;
    }
    panic!("the unit never reached the state the case drops it in");
}

fn the_one_bill(till: &Till) -> CancelBill {
    let bills = till.bills();
    assert_eq!(bills.len(), 1, "exactly one line: {bills:?}");
    bills[0].clone()
}

/// K0 site 1 (route.rs says_done close): the plane said done with (7, 11), the head and body are
/// committed, then the caller's write of the body fails. Today: `Run::cancel` sees `Close::Closed`,
/// skips the plane cancel, the disposition is `CANCEL_FAILED`, and `cancel_bills_reported_units`
/// needs `CANCEL_OK_PARTIAL`, so the line bills `[]`.
#[tokio::test]
async fn a_caller_whose_last_write_fails_bills_the_stated_usage() {
    let f = fixture(Scripted::default(), Till::default());
    let (steps, far) = (common::TestUnits::passing(), Pool::new(&["b"]));
    let caller = Leaving {
        fail_at: Some(0),
        ..Leaving::default()
    };
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let _ = drive(&units, 401).await;
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::ClientGone);
    assert_eq!(bill.disposition, CANCEL_FAILED, "no plane cancel ack");
    assert_eq!(bill.billed, billed(7, 11), "the provider's stated usage");
    assert_eq!(
        f.plane.cancels.load(Ordering::SeqCst),
        0,
        "the plane was done"
    );
    assert!(f.rows.unread().is_empty(), "nothing went unread");
}

fn unread_row(key: u64, reason: ReasonCode) -> Vec<String> {
    vec![format!("unit:{key} reason:{}", reason.as_str())]
}

/// The deadline the straddling cases run under: long enough to reach the held done piece.
fn soon() -> u64 {
    now_ns() + 300_000_000
}

/// K0 site 1 for a stream: `b`'s head piece writes its first bytes (the unit streams, and its head
/// commits `served`), then the plane's done piece states (7, 11) and its write fails. Today the
/// closed unit's disposition is `CANCEL_FAILED`, which never bills reported units, so `[]`.
#[tokio::test]
async fn a_stream_whose_last_write_fails_bills_the_stated_usage() {
    let plane = Scripted::default();
    *plane.script.lock().unwrap() = Some(vec![
        Reply {
            status: 200,
            body: b"data: a".to_vec(),
            units: reported(3, 4),
            ..Reply::blank()
        },
        Reply {
            body: b"data: end".to_vec(),
            ..Reply::done(7, 11)
        },
    ]);
    let f = fixture(plane, Till::default());
    let (steps, far) = (common::TestUnits::passing(), Pool::new(&["b"]));
    let caller = Leaving {
        fail_at: Some(1),
        ..Leaving::default()
    };
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let _ = drive(&units, 402).await;
    let bill = the_one_bill(&f.till);
    assert!(bill.streamed, "the unit streamed before its last write");
    assert_eq!(bill.cause, ReasonCode::ClientGone);
    assert_eq!(bill.disposition, CANCEL_FAILED);
    assert_eq!(bill.billed, billed(7, 11), "the provider's stated usage");
}

/// K0, `OverBudget`: the done piece's checkpoint answers `Cut` after its (7, 11) were folded
/// (route.rs fold, then the `Checkpoint::Cut` return). Today the closed unit bills `[]`; the
/// ceiling never rewrites the provider's actual obligation.
#[tokio::test]
async fn a_done_piece_cut_by_budget_bills_the_stated_usage() {
    let till = Till {
        cut_at: Some(11),
        ..Till::default()
    };
    let f = fixture(Scripted::default(), till);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let _ = drive(&units, 403).await;
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::OverBudget);
    assert_eq!(bill.billed, billed(7, 11), "the provider's stated usage");
    assert!(f.rows.unread().is_empty());
}

/// K0, `Unpriced`: the done piece's checkpoint answers `Unpriced` for (7, 11), after the unit
/// closed on it. The last accepted report (3, 4) bills, and the unread final report is audited.
/// Today: `Run::cancel` sees `Close::Closed`, `CANCEL_FAILED`, non-stream: `[]`, no row.
#[tokio::test]
async fn an_unpriced_done_piece_bills_the_last_accepted_report_and_records_unread() {
    let till = Till {
        unpriced_at: Some(11),
        ..Till::default()
    };
    let f = fixture(Scripted::default(), till);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let _ = drive(&units, 404).await;
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::Unpriced);
    assert_eq!(bill.disposition, CANCEL_FAILED);
    assert_eq!(bill.billed, billed(3, 4), "the last accepted report");
    assert_eq!(f.rows.unread(), unread_row(404, ReasonCode::Unpriced));
}

/// What every refused-count case asserts (183b, 183c): the last accepted report (3, 4) bills,
/// `CANCEL_FAILED`, the unread report is audited, the line is `b`'s (its member and provider named
/// before the bill, `a` never), and nothing of the refused piece (-5, 11) was folded or laned.
fn assert_refused_count_bill(f: &Fixture, key: u64, cause: ReasonCode) -> CancelBill {
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, cause);
    assert_eq!(bill.disposition, CANCEL_FAILED);
    assert_eq!(bill.billed, billed(3, 4), "the last accepted report");
    assert_eq!(f.rows.unread(), unread_row(key, ReasonCode::Unpriced));
    assert_eq!(
        f.till.served_before_the_bill(),
        vec!["served:b:prov-b".to_string()],
        "the line is the serving member's, with its provider"
    );
    let events = f.till.events();
    assert!(
        !events
            .iter()
            .any(|e| e == "checkpoint:11" || e.starts_with("laned")),
        "nothing of the refused piece was taken: {events:?}"
    );
    assert_eq!(
        f.plane.cancels.load(Ordering::SeqCst),
        0,
        "the plane closed the unit: no plane cancel"
    );
    bill
}

/// K0b, normal path (183c): `b`'s done piece is `VERDICT_COUNT_REFUSED`. Today the walk returns
/// `End::Cancel(Unpriced, Some(done))` before its says-done close, so `Run::cancel` calls the
/// plane's `cancel` (`cancel_now`); a non-stream unit then bills `[]` whatever the disposition, and
/// `served` never ran for `b` (no earlier `b` piece committed the head), so the line is `a`'s lane.
#[tokio::test]
async fn a_count_refused_done_piece_bills_the_last_accepted_report() {
    let f = fixture(Scripted::answering(Reply::refused_done()), Till::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["a", "b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let _ = drive(&units, 405).await;
    assert_eq!(far.sends.load(Ordering::SeqCst), 2, "a, then b");
    assert_refused_count_bill(&f, 405, ReasonCode::Unpriced);
}

/// K0b, site 2 (183b): the same refused done piece, its `on_piece` still running when the deadline
/// fires (the kernel awaits it; it answers Ready + done). Today `cross` closes on it (`closes_unit`
/// ignores the verdict), `push` returns the cancel, `Run::cancel` takes `Close::Closed`:
/// `CANCEL_FAILED`, non-stream, `[]`, no row. The bill must equal 183c's, field by field.
#[tokio::test]
async fn a_count_refused_done_piece_straddling_the_deadline_bills_the_last_accepted_report() {
    let f = fixture(Scripted::holding(Reply::refused_done()), Till::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["a", "b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), soon());
    let _ = drive(&units, 406).await;
    let straddled = assert_refused_count_bill(&f, 406, ReasonCode::DeadlineExceeded);

    let g = fixture(Scripted::answering(Reply::refused_done()), Till::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["a", "b"]),
        Leaving::default(),
    );
    let units = g
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let _ = drive(&units, 406).await;
    let unraced = assert_refused_count_bill(&g, 406, ReasonCode::Unpriced);
    assert_eq!(
        (
            straddled.disposition,
            straddled.billed,
            straddled.far_end_answered,
            straddled.streamed
        ),
        (
            unraced.disposition,
            unraced.billed,
            unraced.far_end_answered,
            unraced.streamed
        ),
        "the raced and un-raced refusals bill the same"
    );
    assert_eq!(f.till.served(), g.till.served());
}

/// K0 site 2 (183): `b`'s done piece (7, 11) is still in `on_piece` when the deadline fires; the
/// kernel awaits it and it answers Ready + `EMIT_DONE`. Today `push` returns the cancel before the
/// lane, `served` and the fold, `Run::cancel` takes `Close::Closed`, and a non-stream
/// `CANCEL_FAILED` bills `[]`.
#[tokio::test]
async fn a_done_piece_straddling_the_deadline_bills_the_stated_usage() {
    let f = fixture(Scripted::holding(Reply::done(7, 11)), Till::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["a", "b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), soon());
    let _ = drive(&units, 407).await;
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::DeadlineExceeded);
    assert_eq!(bill.billed, billed(7, 11), "the provider's stated usage");
    assert!(f.rows.unread().is_empty(), "the final report was read");
    assert_eq!(
        f.till.served_before_the_bill(),
        vec!["served:b:prov-b".to_string()]
    );
}

/// K0 site 2's reload twin: a plane-generation stop (`Drain`) while the done piece is in flight.
#[tokio::test]
async fn a_done_piece_straddling_a_reload_bills_the_stated_usage() {
    let f = fixture(Scripted::holding(Reply::done(7, 11)), Till::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["a", "b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let reload = async {
        f.plane.held_notice.notified().await;
        f.driver.reload();
    };
    let _ = tokio::join!(drive(&units, 408), reload);
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::Drain);
    assert_eq!(bill.billed, billed(7, 11), "the provider's stated usage");
    assert!(f.rows.unread().is_empty());
    assert_eq!(
        f.till.served_before_the_bill(),
        vec!["served:b:prov-b".to_string()]
    );
}

/// GUARD (K0b `Panic`, site 2): `b`'s final piece, pushed toward the far leg, answers
/// `EMIT_DONE | EMIT_TO_FAR_END` with (7, 11) while the deadline fires. The walk would end it as
/// `PlanePanic` (a far-bound answer that also says done), so nothing of it is folded or attributed:
/// `[]`, `CANCEL_FAILED`, as today, and the unread report is audited as `PlanePanic`.
#[tokio::test]
async fn a_far_bound_done_piece_on_the_far_leg_straddling_the_deadline_is_not_folded() {
    let breach = Reply {
        flags: EMIT_DONE | EMIT_TO_FAR_END,
        units: reported(7, 11),
        ..Reply::blank()
    };
    let f = fixture(Scripted::holding(breach), Till::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["a", "b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), soon());
    let _ = drive(&units, 409).await;
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::DeadlineExceeded);
    assert_eq!(bill.disposition, CANCEL_FAILED);
    assert!(
        bill.billed.is_empty(),
        "a contract breach never bills: {bill:?}"
    );
    assert!(
        f.till.served().is_empty(),
        "no served for b from that piece"
    );
    assert_eq!(f.rows.unread(), unread_row(409, ReasonCode::PlanePanic));
}

/// K0 site 4 (182): the unit future is dropped while `b`'s done piece is in `on_piece`
/// (`Pumping::drop` buries it unsettled); the plane then settles it Ready + done with (7, 11) and
/// the sweep bills. The done piece's units were never folded: the held (3, 4) bill under
/// `ClientGone`, the unread report is audited, and the line is `b`'s. Today: `[]`, no row, and
/// `served` never ran for `b`.
#[tokio::test]
async fn a_unit_buried_with_its_done_piece_in_flight_records_and_bills() {
    let f = fixture(Scripted::holding(Reply::done(7, 11)), Till::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["a", "b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let mut unit = Box::pin(drive(&units, 410));
    poll_until(&mut unit, || f.plane.is_held()).await;
    drop(unit);
    assert!(f.till.bills().is_empty(), "nothing bills inside the drop");
    f.driver.sweep();
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::ClientGone);
    assert_eq!(bill.disposition, CANCEL_FAILED, "no plane cancel ack");
    assert_eq!(bill.billed, billed(3, 4), "the held units");
    assert_eq!(f.rows.unread(), unread_row(410, ReasonCode::ClientGone));
    assert_eq!(
        f.till.served_before_the_bill(),
        vec!["served:b:prov-b".to_string()]
    );
}

/// K0 site 3 (183a): the same, but the done piece settled before the unit future was dropped
/// (`Pumping::drop` finds it settled and done).
#[tokio::test]
async fn a_unit_buried_with_its_done_piece_settled_is_attributed() {
    let f = fixture(Scripted::holding(Reply::done(7, 11)), Till::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        Pool::new(&["a", "b"]),
        Leaving::default(),
    );
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let mut unit = Box::pin(drive(&units, 411));
    poll_until(&mut unit, || f.plane.is_held()).await;
    f.plane.settle_quietly();
    drop(unit);
    f.driver.sweep();
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::ClientGone);
    assert_eq!(bill.billed, billed(3, 4), "the held units");
    assert_eq!(f.rows.unread(), unread_row(411, ReasonCode::ClientGone));
    assert_eq!(
        f.till.served_before_the_bill(),
        vec!["served:b:prov-b".to_string()]
    );
}

/// K0 via the sweep, no flight: the plane said done with (7, 11) and its units were folded, then
/// the caller stopped reading on the body's write and the unit future was dropped. Today the sweep
/// bills `CANCEL_FAILED` on the closed unit: `[]`.
#[tokio::test]
async fn a_buried_plane_done_unit_bills_the_stated_usage() {
    let f = fixture(Scripted::default(), Till::default());
    let (steps, far) = (common::TestUnits::passing(), Pool::new(&["b"]));
    let caller = Leaving {
        stall_at: Some(0),
        ..Leaving::default()
    };
    let units = f
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let mut unit = Box::pin(drive(&units, 412));
    poll_until(&mut unit, || caller.stalled.load(Ordering::SeqCst)).await;
    drop(unit);
    f.driver.sweep();
    let bill = the_one_bill(&f.till);
    assert_eq!(bill.cause, ReasonCode::ClientGone);
    assert_eq!(bill.billed, billed(7, 11), "the provider's stated usage");
    assert!(f.rows.unread().is_empty(), "the final report was folded");
}
