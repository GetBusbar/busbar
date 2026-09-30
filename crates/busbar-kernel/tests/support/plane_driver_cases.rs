// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DRIVER'S CASES (`BUSBAR-1.6.0.md` Part 3, §12), written once and run twice: by the
//! kernel against a contract-level plane double, and by the composition root against a real test
//! plane, linked and dlopened. The file that includes this module supplies the plane: `Way`,
//! `ways()`, `rig(way, caps, book) -> Rig` (with `Rig::stats`), `now_ns()` on the plane's clock, and
//! `common::TestUnits`, the kernel steps.
//!
//! What is proven, per plane: one unit end to end; zero plane→host calls per chunk (the plane
//! counts its own crossings and host calls); backpressure; a PENDING answer woken while the
//! runtime thread keeps running other tasks; FAULT as a failed end; failover before the first
//! byte and none after it; the short-buffer re-call for `arrive` and `on_piece`, and a second
//! short answer as FAULT; cancel on the deadline, the cut, the reload and the caller-drop paths,
//! and a FAULT disposition billed as `CANCEL_FAILED`; and the session opener.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::abi::plane::{UnitCount, CANCEL_FAILED, CANCEL_OK_PARTIAL};
use busbar_contract::caps::{Canary, Outcome, ReasonCode, StepName};
use busbar_kernel::plane_driver::{
    Arrival, BufferCaps, CallerEnd, CancelBill, CancelCause, Checkpoint, FarEnd, FarPiece,
    MoneySeam, OutboundRequest, PlaneUnits,
};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{
    open_unit, run_unit_async, AccrualMeter, Ended, Kernel, Run, SessionOpen, UnitCtx,
};

use super::common::{cell, ctx, TestUnits};
use super::{now_ns, rig, ways};

/// The counters a test plane reports, in this order.
pub mod stat {
    /// `on_piece` crossings.
    pub const ON_PIECES: usize = 0;
    /// Calls the plane made into the host (the wake).
    pub const HOST_CALLS: usize = 1;
    /// `cancel` crossings.
    pub const CANCELS: usize = 2;
    /// `cancel` crossings the dispatcher made for a pending op, on the op's worker.
    pub const CANCELS_ON_WORKER: usize = 3;
    /// The last disposition `cancel` answered (`0` for FAULT).
    pub const LAST_DISPOSITION: usize = 4;
    /// `drive` crossings (read by the composition root's suite only).
    #[allow(dead_code)]
    pub const DRIVES: usize = 5;
    /// The unit key the last `on_piece` carried.
    pub const UNIT: usize = 6;
    /// How many.
    pub const COUNT: usize = 7;
}

// ── the doubles ──────────────────────────────────────────────────────────────────────────────────

/// A far end that answers every attempt with the same script, and records what it was sent.
struct Far {
    members: Vec<&'static str>,
    script: Vec<FarPiece>,
    sent: Mutex<Vec<OutboundRequest>>,
    current: Mutex<VecDeque<FarPiece>>,
}

impl Far {
    fn new(members: &[&'static str], chunks: &[&[u8]]) -> Self {
        let n = chunks.len();
        let script = chunks
            .iter()
            .enumerate()
            .map(|(k, c)| FarPiece {
                bytes: c.to_vec(),
                status: (k == 0).then_some((200, 2)),
                last: k + 1 == n,
            })
            .collect();
        Far {
            members: members.to_vec(),
            script,
            sent: Mutex::new(Vec::new()),
            current: Mutex::new(VecDeque::new()),
        }
    }

    fn sent(&self) -> Vec<OutboundRequest> {
        self.sent.lock().unwrap().clone()
    }
}

impl FarEnd for Far {
    fn member(&self, attempt_no: u32) -> Option<String> {
        self.members
            .get(attempt_no as usize - 1)
            .map(|m| (*m).to_string())
    }

    fn send(&self, request: OutboundRequest) -> impl Future<Output = bool> + Send + '_ {
        self.sent.lock().unwrap().push(request);
        *self.current.lock().unwrap() = self.script.iter().cloned().collect();
        async { true }
    }

    fn next(&self) -> impl Future<Output = Option<FarPiece>> + Send + '_ {
        let piece = self.current.lock().unwrap().pop_front();
        async move {
            tokio::task::yield_now().await;
            piece
        }
    }
}

/// A reply head as the caller saw it.
type Head = (u32, Vec<(Vec<u8>, Vec<u8>)>);

/// A caller whose every write waits one turn of the runtime (its side becoming writable).
#[derive(Default)]
struct Caller {
    head: Mutex<Option<Head>>,
    bytes: Mutex<Vec<u8>>,
    writes: AtomicU64,
}

impl CallerEnd for Caller {
    fn head(&self, status: u32, fields: Vec<(Vec<u8>, Vec<u8>)>) {
        *self.head.lock().unwrap() = Some((status, fields));
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        tokio::task::yield_now().await;
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        self.writes.fetch_add(1, Ordering::SeqCst);
        true
    }
}

impl Caller {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes.lock().unwrap()).into_owned()
    }
    fn status(&self) -> Option<u32> {
        self.head.lock().unwrap().as_ref().map(|h| h.0)
    }
}

/// The money seam, recording: checkpoints, bills and abandoned ends; a cut once the reported units
/// reach `cut_at`.
#[derive(Default)]
pub(crate) struct Book {
    cut_at: Option<u64>,
    checkpoints: Mutex<Vec<u64>>,
    bills: Mutex<Vec<CancelBill>>,
    abandoned: AtomicU64,
}

impl MoneySeam for Book {
    fn checkpoint(&self, _ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        let amount = units.iter().map(|u| u.amount).max().unwrap_or(0);
        self.checkpoints.lock().unwrap().push(amount);
        match self.cut_at {
            Some(at) if amount >= at => Checkpoint::Cut,
            _ => Checkpoint::Continue,
        }
    }

    fn cancelled(&self, _ctx: &UnitCtx, bill: &CancelBill) {
        self.bills.lock().unwrap().push(bill.clone());
    }

    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {
        self.abandoned.fetch_add(1, Ordering::SeqCst);
    }
}

impl Book {
    fn bills(&self) -> Vec<CancelBill> {
        self.bills.lock().unwrap().clone()
    }
}

fn arrival(target: &str, body: &[u8]) -> Arrival {
    Arrival {
        claim: 0,
        target: target.as_bytes().to_vec(),
        fields: vec![(b"content-type".to_vec(), b"text/plain".to_vec())],
        body: Arc::from(body),
    }
}

/// The deadline `ms` from now on the dispatcher's clock.
fn after(ms: u64) -> u64 {
    now_ns() + ms * 1_000_000
}

/// Run one unit through the one loop; its outcome.
async fn drive(units: &PlaneUnits<'_, TestUnits, Far, Caller>) -> Outcome {
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        Canary::new(),
        LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
    };
    match run_unit_async(&kernel, units, &ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}

const CHUNKS: &[&[u8]] = &[b"hello ", b"far ", b"end"];

// ── one unit ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn one_unit_end_to_end() {
    let mut transcripts = Vec::new();
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"ping"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Completed),
            "{way:?}: {outcome:?}"
        );
        assert_eq!(caller.text(), "hello far end", "{way:?}");
        assert_eq!(caller.status(), Some(200), "{way:?}");
        let sent = far.sent();
        assert_eq!(sent.len(), 1, "{way:?}: one live attempt");
        assert_eq!(sent[0].verb, b"POST");
        assert_eq!(
            sent[0].target, b"/far/ok/call",
            "{way:?}: the plane kept the caller's target from `arrive`, keyed by the unit"
        );
        assert_eq!(
            sent[0].body, b"ping",
            "{way:?}: the kept caller body is re-pushed"
        );
        assert_eq!(sent[0].fields, vec![(b"x-attempt".to_vec(), b"1".to_vec())]);
        assert_eq!(units.decoded().map(|d| d.expected.len()), Some(1));
        assert_eq!(
            *r.book.checkpoints.lock().unwrap(),
            vec![6, 10, 13],
            "{way:?}: every READY answer's cumulative units reach the money seam"
        );
        transcripts.push((caller.text(), caller.head.lock().unwrap().clone(), sent));
    }
    transcripts.dedup();
    assert_eq!(
        transcripts.len(),
        1,
        "every way of reaching the plane answers alike"
    );
}

#[tokio::test]
async fn zero_plane_to_host_calls_per_chunk() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let chunks: Vec<Vec<u8>> = (0..50).map(|k| format!("c{k:02}").into_bytes()).collect();
        let chunks: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &chunks),
            Caller::default(),
        );
        let before = r.stats();
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        let after = r.stats();
        let on_pieces = after[stat::ON_PIECES] - before[stat::ON_PIECES];
        assert_eq!(
            on_pieces,
            2 + 50,
            "{way:?}: ATTEMPT + body, then one crossing per chunk"
        );
        assert_eq!(
            after[stat::HOST_CALLS],
            0,
            "{way:?}: zero plane->host calls over 50 chunks"
        );
    }
}

#[tokio::test]
async fn backpressure_flushes_and_calls_again() {
    for way in ways() {
        let caps = BufferCaps {
            reply: 4,
            ..BufferCaps::default()
        };
        let r = rig(way, caps, Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"0123456789"]),
            Caller::default(),
        );
        let before = r.stats()[stat::ON_PIECES];
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"ab"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        assert_eq!(
            caller.text(),
            "0123456789",
            "{way:?}: nothing lost across more = 1"
        );
        assert_eq!(
            caller.writes.load(Ordering::SeqCst),
            3,
            "{way:?}: 4 + 4 + 2"
        );
        let on_pieces = r.stats()[stat::ON_PIECES] - before;
        assert_eq!(
            on_pieces,
            2 + 3,
            "{way:?}: the far piece and two empty continuations"
        );
    }
}

/// The re-call after `more = 1` is a piece of the same `from` with no bytes and no flags: the
/// plane faults any other (plane ABI, the backpressure re-call rule). Toward the caller the source
/// is the far end; the re-calls never re-push the far end's bytes.
#[tokio::test]
async fn the_more_recall_keeps_its_source_and_carries_no_bytes() {
    for way in ways() {
        let caps = BufferCaps {
            reply: 2,
            ..BufferCaps::default()
        };
        let r = rig(way, caps, Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"abcdef", b"gh"]),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Completed),
            "{way:?}: {outcome:?}"
        );
        assert_eq!(
            caller.text(),
            "abcdefgh",
            "{way:?}: each byte once, in order"
        );
    }
}

/// ONE UNIT, ONE KEY: `arrive` and every `on_piece` carry the unit's kernel-minted key, the
/// caller's head crosses once at `arrive`, and the plane finds it again by that key.
#[tokio::test]
async fn every_op_of_a_unit_carries_its_kernel_minted_key() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/keyed", b"k"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        assert_eq!(
            r.stats()[stat::UNIT],
            ctx(7).key.get(),
            "{way:?}: the pieces carried the unit's key"
        );
        assert_eq!(far.sent()[0].target, b"/far/ok/keyed", "{way:?}");
    }
}

/// A PENDING `on_piece` is an await; the runtime thread keeps running other tasks while the
/// plane waits, and the plane's one wake resumes it. On a current-thread runtime a blocking wait
/// would starve the ticker below.
#[test]
fn pending_wake_resumes_without_blocking_the_runtime() {
    for way in ways() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (TestUnits::passing(), Far::new(&["pend"], CHUNKS), Caller::default());
            let ticks = Arc::new(AtomicU64::new(0));
            let ticker = {
                let ticks = ticks.clone();
                tokio::spawn(async move {
                    loop {
                        ticks.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
            };
            let units = r.driver.unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
            let outcome = drive(&units).await;
            ticker.abort();
            assert!(matches!(outcome, Outcome::Completed), "{way:?}: {outcome:?}");
            assert_eq!(caller.text(), "hello far end");
            assert!(
                ticks.load(Ordering::SeqCst) >= 10,
                "{way:?}: the runtime thread ran other tasks while the plane was PENDING ({} ticks)",
                ticks.load(Ordering::SeqCst)
            );
            assert_eq!(r.stats()[stat::HOST_CALLS], 1, "the one wake");
        });
    }
}

#[tokio::test]
async fn a_fault_becomes_a_failed_end_with_the_planes_refusal() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["fault"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(
                outcome,
                Outcome::Failed(StepName::Route, ReasonCode::PlanePanic)
            ),
            "{way:?}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the refusal is rendered");
        assert_eq!(rendered.status, 502);
        assert_eq!(rendered.body, b"refused:502:plane_panic");
        assert_eq!(caller.text(), "", "nothing had streamed");
    }
}

/// THE LENT MEMORY (ARCHITECT ruling 2026-09-29, every kind): a crossing the host answered FAULT
/// (the watchdog, past the Stream budget) may still be running; it keeps the unit's host buffers
/// until it returns, then re-reads its piece and writes its reply buffer into memory that is still
/// the unit's. The witness is the caller's body, which the buffers hold: it outlives the unit until
/// the wedged crossing returns, and not a moment longer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_on_piece_keeps_the_units_buffers_until_it_returns() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["wedge"], CHUNKS),
            Caller::default(),
        );
        let body: Arc<[u8]> = Arc::from(&b"wedged"[..]);
        let arrival = Arrival {
            body: body.clone(),
            ..arrival("/call", b"")
        };
        let units = r.driver.unit(&steps, &far, &caller, arrival, 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(
                outcome,
                Outcome::Failed(StepName::Route, ReasonCode::PlanePanic)
            ),
            "{way:?}: {outcome:?}"
        );
        drop(units);
        assert_eq!(
            Arc::strong_count(&body),
            2,
            "{way:?}: the unit is over, but its FAULTed crossing has not returned: the buffers it \
             points into must still be alive"
        );
        let t = Instant::now();
        while Arc::strong_count(&body) != 1 {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "{way:?}: the buffers go once the wedged crossing returns"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[tokio::test]
async fn a_retry_verdict_before_the_first_byte_fails_over() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["retry", "ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        let sent = far.sent();
        assert_eq!(sent.len(), 2, "{way:?}: failed over to the second member");
        assert_eq!(sent[1].target, b"/far/ok/call");
        assert_eq!(
            sent[1].body, b"p",
            "{way:?}: the kept body is re-pushed on attempt 2"
        );
        assert_eq!(sent[1].fields, vec![(b"x-attempt".to_vec(), b"2".to_vec())]);
        assert_eq!(caller.text(), "hello far end");
    }
}

/// A retry verdict after the first byte reached the caller is hard: no failover.
#[tokio::test]
async fn a_retry_verdict_after_the_first_byte_is_hard() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["retry-late", "ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        assert_eq!(
            far.sent().len(),
            1,
            "{way:?}: no second attempt after the first byte"
        );
        assert_eq!(caller.text(), "hello far end");
    }
}

// ── the short-buffer rule ────────────────────────────────────────────────────────────────────────

fn small_units() -> BufferCaps {
    BufferCaps {
        units: 1,
        ..BufferCaps::default()
    }
}

#[tokio::test]
async fn a_short_arrive_is_recalled_once_with_what_it_needs() {
    for way in ways() {
        let r = rig(way, small_units(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/short", b"x"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        assert_eq!(
            units.decoded().map(|d| d.expected.len()),
            Some(2),
            "{way:?}"
        );
    }
}

/// RED: a second short answer to `arrive` is FAULT; the unit is refused at decode and never
/// reaches the far end.
#[tokio::test]
async fn a_second_short_arrive_is_fault_and_refuses_at_decode() {
    for way in ways() {
        let r = rig(way, small_units(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/short-twice", b"x"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(
                outcome,
                Outcome::Refused(StepName::Decode, ReasonCode::DecodeFailed)
            ),
            "{way:?}: {outcome:?}"
        );
        assert!(far.sent().is_empty());
        let rendered = units.take_rendered().expect("the refusal is rendered");
        assert_eq!(rendered.body, b"refused:400:decode_failed");
    }
}

#[tokio::test]
async fn a_short_on_piece_is_recalled_once_and_a_second_short_is_fault() {
    for way in ways() {
        let r = rig(way, small_units(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["short"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed), "{way:?}");
        assert_eq!(caller.text(), "hello far end");

        // RED: `short-twice` answers short again on the re-call; the dispatcher makes it FAULT.
        let r = rig(way, small_units(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["short-twice"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(
                outcome,
                Outcome::Failed(StepName::Route, ReasonCode::PlanePanic)
            ),
            "{way:?}: {outcome:?}"
        );
    }
}

// ── cancel ───────────────────────────────────────────────────────────────────────────────────────

/// The deadline passes with `on_piece` in flight: the driver sends the op to the dispatcher's
/// cancel path, the cancel crosses on the ticket's worker, and its disposition is billed.
#[tokio::test]
async fn cancel_on_the_deadline() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["hang"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), after(60));
        let outcome = drive(&units).await;
        assert!(
            matches!(
                outcome,
                Outcome::Failed(StepName::Route, ReasonCode::DeadlineExceeded)
            ),
            "{way:?}: {outcome:?}"
        );
        let bills = r.book.bills();
        assert_eq!(bills.len(), 1, "{way:?}");
        assert_eq!(bills[0].cause, CancelCause::Deadline);
        assert_eq!(
            bills[0].disposition, CANCEL_FAILED,
            "far end answered, nothing streamed"
        );
        assert!(bills[0].billed.is_empty());
        let s = r.stats();
        assert_eq!(s[stat::CANCELS], 1, "{way:?}: one cancel");
        assert_eq!(s[stat::CANCELS_ON_WORKER], 1, "{way:?}: on the worker");
    }
}

/// A checkpoint dries the budget: the driver makes the ticketless `cancel` itself (no op is in
/// flight), the plane renders the in-stream error frame, and the streamed units bill.
#[tokio::test]
async fn cancel_on_the_cut() {
    for way in ways() {
        let book = Book {
            cut_at: Some(6),
            ..Book::default()
        };
        let r = rig(way, BufferCaps::default(), book);
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(
                outcome,
                Outcome::Failed(StepName::Route, ReasonCode::OverBudget)
            ),
            "{way:?}: {outcome:?}"
        );
        assert_eq!(caller.text(), "hello refused:429:over_budget", "{way:?}");
        let bill = units.cancel_bill().expect("the cut was billed");
        assert_eq!(bill.cause, CancelCause::Cut);
        assert_eq!(bill.disposition, CANCEL_OK_PARTIAL);
        assert_eq!(
            bill.billed,
            vec![(0, 6)],
            "{way:?}: the streamed, far-end-reported units"
        );
        let s = r.stats();
        assert_eq!(s[stat::CANCELS], 1);
        assert_eq!(s[stat::CANCELS_ON_WORKER], 0, "ticketless, on this task");
        assert!(
            units.take_rendered().is_none(),
            "the frame went in the stream"
        );
    }
}

#[tokio::test]
async fn cancel_on_reload() {
    for way in ways() {
        let r = Arc::new(rig(way, BufferCaps::default(), Book::default()));
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["hang"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        let reloader = {
            let r = r.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(40)).await;
                r.driver.reload();
            })
        };
        let outcome = drive(&units).await;
        reloader.await.unwrap();
        assert!(
            matches!(outcome, Outcome::Failed(StepName::Route, ReasonCode::Drain)),
            "{way:?}: {outcome:?}"
        );
        let bills = r.book.bills();
        assert_eq!(bills.len(), 1);
        assert_eq!(bills[0].cause, CancelCause::Reload);
        assert_eq!(r.stats()[stat::CANCELS_ON_WORKER], 1);
    }
}

/// The caller goes away with `on_piece` in flight: the loop's future is dropped, nothing crosses
/// inside the drop, the op goes to the dispatcher's client-drop path (the cancel crosses on the
/// worker), the loop's end is handed to the money seam, and the sweep bills the disposition once
/// the op settles, releasing the buffers it held.
#[tokio::test]
async fn cancel_when_the_caller_goes_away() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["hang"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        let gone = tokio::time::timeout(Duration::from_millis(60), drive(&units)).await;
        assert!(
            gone.is_err(),
            "{way:?}: the unit was still waiting on the plane"
        );
        assert_eq!(
            r.book.abandoned.load(Ordering::SeqCst),
            1,
            "the loop's end was posted"
        );
        assert_eq!(r.driver.buried(), 1, "{way:?}: buried with its op");
        let until = Instant::now() + Duration::from_secs(5);
        while r.driver.buried() > 0 && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(5)).await;
            r.driver.sweep();
        }
        assert_eq!(r.driver.buried(), 0, "{way:?}: the sweep finished it");
        let bills = r.book.bills();
        assert_eq!(bills.len(), 1);
        assert_eq!(bills[0].cause, CancelCause::ClientGone);
        assert_eq!(bills[0].disposition, CANCEL_FAILED);
        let s = r.stats();
        assert_eq!(s[stat::CANCELS], 1, "{way:?}: one cancel");
        assert_eq!(
            s[stat::CANCELS_ON_WORKER],
            1,
            "{way:?}: made on the dispatcher's worker, not inside the drop"
        );
    }
}

/// A `cancel` that answers FAULT bills as `CANCEL_FAILED`: nothing.
#[tokio::test]
async fn a_fault_disposition_bills_as_cancel_failed() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["cancel-fault"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), after(50));
        let _ = drive(&units).await;
        let bills = r.book.bills();
        assert_eq!(bills.len(), 1, "{way:?}");
        assert_eq!(bills[0].disposition, CANCEL_FAILED);
        assert!(bills[0].billed.is_empty());
        assert_eq!(r.stats()[stat::LAST_DISPOSITION], 0, "it FAULTed");
    }
}

// ── the session opener drives it too ─────────────────────────────────────────────────────────────

#[test]
fn open_unit_drives_the_same_steps() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        for (target, want) in [
            ("/call", SessionOpen::Admitted),
            ("/refuse", SessionOpen::Refused),
        ] {
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&["ok"], CHUNKS),
                Caller::default(),
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival(target, b"x"), 0);
            let kernel = Kernel::new();
            let (gauge, canary, leases, meter) = (
                ConcurrencyGauge::new(),
                Canary::new(),
                LeaseCell::new(),
                AccrualMeter::new(),
            );
            let cell = cell(&kernel);
            let run = Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            };
            assert_eq!(
                open_unit(&kernel, &units, &ctx(9), run),
                want,
                "{way:?} {target}"
            );
            if want == SessionOpen::Refused {
                assert_eq!(
                    units.take_rendered().unwrap().body,
                    b"refused:400:decode_failed"
                );
            }
        }
    }
}
