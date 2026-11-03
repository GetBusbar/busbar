// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::abi::plane::{
    reason_code, RefusalStatus, UnitCount, CANCEL_FAILED, CANCEL_OK_PARTIAL, REFUSAL_ANY_DIALECT,
};
use busbar_contract::caps::{Outcome, Pass, ReasonCode, Route, StepName};
use busbar_kernel::canary::Canary;
use busbar_kernel::plane_driver::{
    Arrival, BufferCaps, CallerEnd, CancelBill, Checkpoint, FarEnd, FarPiece, MoneySeam,
    OutboundRequest, Pick, PlaneUnits, SessionCaller,
};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{
    open_unit, run_unit_async, AccrualMeter, Ended, Kernel, Run, SessionOpen, UnitCtx,
};

use super::common::{cell, ctx, TestUnits};
use super::{now_ns, rig, ways};

pub mod stat {

    pub const ON_PIECES: usize = 0;

    pub const HOST_CALLS: usize = 1;

    pub const CANCELS: usize = 2;

    pub const CANCELS_ON_WORKER: usize = 3;

    pub const LAST_DISPOSITION: usize = 4;

    #[allow(dead_code)]
    pub const DRIVES: usize = 5;

    pub const UNIT: usize = 6;

    pub const COUNT: usize = 7;
}

pub(crate) struct Far {
    members: Vec<&'static str>,
    script: Vec<FarPiece>,
    sent: Mutex<Vec<OutboundRequest>>,
    current: Mutex<VecDeque<FarPiece>>,

    held: bool,

    written: Mutex<Vec<(Vec<u8>, bool)>>,

    open: std::sync::atomic::AtomicBool,

    arrived: tokio::sync::Notify,

    ceiling: Option<Duration>,

    picks: std::sync::atomic::AtomicU32,

    names_its_pool: bool,
}

pub(crate) const GREETING: &[u8] = b"hello";

pub(crate) const BYE: &[u8] = b"bye";

impl Far {
    pub(crate) fn new(members: &[&'static str], chunks: &[&[u8]]) -> Self {
        let n = chunks.len();
        let script = chunks
            .iter()
            .enumerate()
            .map(|(k, c)| FarPiece {
                bytes: c.to_vec(),
                status: (k == 0).then_some((200, 2)),
                last: k + 1 == n,
                fail_over: false,
                fields: false,
                head: Vec::new(),
                relayed: false,
                cut: false,
            })
            .collect();
        Far {
            members: members.to_vec(),
            script,
            sent: Mutex::new(Vec::new()),
            current: Mutex::new(VecDeque::new()),
            held: false,
            written: Mutex::new(Vec::new()),
            open: std::sync::atomic::AtomicBool::new(false),
            arrived: tokio::sync::Notify::new(),
            ceiling: None,
            picks: std::sync::atomic::AtomicU32::new(0),
            names_its_pool: false,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn naming_its_pool(mut self) -> Self {
        self.names_its_pool = true;
        self
    }

    pub(crate) fn stating(self, ceiling: Duration) -> Self {
        Far {
            ceiling: Some(ceiling),
            ..self
        }
    }

    #[allow(dead_code)]
    pub(crate) fn held(members: &[&'static str]) -> Self {
        Far {
            held: true,
            ..Far::new(members, &[])
        }
    }

    pub(crate) fn sent(&self) -> Vec<OutboundRequest> {
        self.sent.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub(crate) fn picks(&self) -> u32 {
        self.picks.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub(crate) fn written(&self) -> Vec<(Vec<u8>, bool)> {
        self.written.lock().unwrap().clone()
    }

    fn answer(&self, frame: &[u8]) {
        let mut current = self.current.lock().unwrap();
        current.push_back(FarPiece {
            bytes: [b"re:".as_slice(), frame].concat(),
            ..FarPiece::default()
        });
        if frame == BYE {
            self.open.store(false, Ordering::SeqCst);
            current.push_back(FarPiece {
                last: true,
                ..FarPiece::default()
            });
        }
        drop(current);
        self.arrived.notify_one();
    }
}

const POOL: &str = "pool-a";

const PROVIDER: &str = "acme";

const OVERLOADED: &str = "overloaded";

impl FarEnd for Far {
    fn candidates(&self, _: &Pass<Route>) -> Option<busbar_kernel::plane_driver::Candidates> {
        self.names_its_pool
            .then(|| busbar_kernel::plane_driver::Candidates {
                pool: POOL.to_string(),
                members: self
                    .members
                    .iter()
                    .enumerate()
                    .map(|(idx, m)| busbar_kernel::plane_driver::CandidateFacts {
                        idx,
                        model: (*m).to_string(),
                        provider: PROVIDER.to_string(),
                        weight: 1,
                        ..Default::default()
                    })
                    .collect(),
            })
    }

    fn deadline_ns(&self, now_ns: u64) -> u64 {
        self.ceiling.map_or(0, |c| {
            now_ns.saturating_add(u64::try_from(c.as_nanos()).unwrap_or(u64::MAX))
        })
    }

    fn member<'a>(
        &'a self,
        _: &'a Pass<Route>,
        attempt_no: u32,
    ) -> impl Future<Output = Pick> + Send + 'a {
        self.picks.fetch_add(1, Ordering::SeqCst);
        let pick = match self.members.get(attempt_no as usize - 1) {
            Some(m) => Pick::Member {
                name: (*m).to_string(),
                pool: POOL.to_string(),
                passthrough: false,
                provider: PROVIDER.to_string(),
            },
            None => Pick::Exhausted {
                status: 503,
                retry_after: Some(2),
                detail: "The service is temporarily overloaded. Please retry shortly.",
            },
        };
        async move { pick }
    }

    fn send<'a>(
        &'a self,
        _: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        let held_body = self.held.then(|| request.body.clone());
        let script = if request.member == OVERLOADED {
            vec![FarPiece {
                bytes: b"overloaded".to_vec(),
                status: Some((529, 5)),
                last: true,
                fail_over: true,
                fields: false,
                head: Vec::new(),
                relayed: false,
                cut: false,
            }]
        } else if request.member.starts_with("trailers") {
            let mut script = self.script.clone();
            if let Some(last) = script.last_mut() {
                last.last = false;
            }
            script.push(FarPiece {
                bytes: b"far-status: 0".to_vec(),
                last: true,
                fields: true,
                ..FarPiece::default()
            });
            script
        } else if request.member.starts_with("cut") {
            let mut script = self.script.clone();
            if let Some(last) = script.last_mut() {
                last.cut = true;
            }
            script
        } else if held_body.is_some() {
            vec![FarPiece {
                bytes: GREETING.to_vec(),
                status: Some((101, 1)),
                ..FarPiece::default()
            }]
        } else {
            self.script.clone()
        };
        self.sent.lock().unwrap().push(request);
        *self.current.lock().unwrap() = script.into_iter().collect();
        if let Some(body) = held_body {
            self.open.store(true, Ordering::SeqCst);
            self.answer(&body);
        }
        async { true }
    }

    async fn next(&self, _: &Pass<Route>) -> Option<FarPiece> {
        loop {
            let arrived = self.arrived.notified();
            let piece = self.current.lock().unwrap().pop_front();
            match piece {
                Some(piece) => {
                    tokio::task::yield_now().await;
                    return Some(piece);
                }

                None if self.open.load(Ordering::SeqCst) => arrived.await,
                None => {
                    tokio::task::yield_now().await;
                    return None;
                }
            }
        }
    }

    fn write<'a>(
        &'a self,
        _: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        let open = self.open.load(Ordering::SeqCst);
        self.written
            .lock()
            .unwrap()
            .push((request.body.clone(), open));
        if open {
            self.answer(&request.body);
        }
        async move { open }
    }
}

type Head = (u32, Vec<(Vec<u8>, Vec<u8>)>);

pub(crate) type Finale = (u32, Vec<u8>, Vec<u8>);

/// A caller whose every write waits one turn of the runtime (its side becoming writable).
#[derive(Default)]
pub(crate) struct Caller {
    head: Mutex<Option<Head>>,
    bytes: Mutex<Vec<u8>>,
    writes: AtomicU64,
    /// Writes that came as ONE text message.
    texts: AtomicU64,
    /// Message boundaries the caller's side was handed.
    pub(crate) boundaries: AtomicU64,
    /// The reply's final status, message and details, once stated.
    pub(crate) finale: Mutex<Option<Finale>>,
    /// A STALLED caller: once it has taken this many writes its side is never writable again, and
    /// it never goes away (a client that stops reading with its socket open).
    pub(crate) stall_after: Option<u64>,
}

impl CallerEnd for Caller {
    fn head(&self, status: u32, fields: Vec<(Vec<u8>, Vec<u8>)>) {
        *self.head.lock().unwrap() = Some((status, fields));
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        if self
            .stall_after
            .is_some_and(|n| self.writes.load(Ordering::SeqCst) >= n)
        {
            std::future::pending::<()>().await;
        }
        tokio::task::yield_now().await;
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        self.writes.fetch_add(1, Ordering::SeqCst);
        true
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        self.texts.fetch_add(1, Ordering::SeqCst);
        self.write(bytes).await
    }

    async fn write_piece(&self, bytes: &[u8], text: bool, message_end: bool) -> bool {
        if message_end {
            self.boundaries.fetch_add(1, Ordering::SeqCst);
        }
        if bytes.is_empty() {
            return true;
        }
        if text {
            self.write_text(bytes).await
        } else {
            self.write(bytes).await
        }
    }

    fn final_status(&self, status: u32, message: &[u8], details: &[u8]) {
        *self.finale.lock().unwrap() = Some((status, message.to_vec(), details.to_vec()));
    }
}

impl SessionCaller for Caller {
    async fn read(&self) -> Option<Vec<u8>> {
        None
    }
}

impl Caller {
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes.lock().unwrap()).into_owned()
    }
    pub(crate) fn status(&self) -> Option<u32> {
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
    /// Every serving member the driver named, in order.
    served: Mutex<Vec<(String, String)>>,
    /// Every ledger lane the driver named, in order.
    laned: Mutex<Vec<String>>,
    /// The production money steps every call is also handed to, when set.
    forward: Option<Arc<dyn MoneySeam>>,
    /// Sessions whose one cleanup ran (the book admits every session).
    pub(crate) sessions_ended: AtomicU64,
}

impl Book {
    #[allow(dead_code)]
    pub(crate) fn forwarding(money: Arc<dyn MoneySeam>) -> Self {
        Book {
            forward: Some(money),
            ..Book::default()
        }
    }
}

impl MoneySeam for Book {
    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        let forwarded = self.forward.as_ref().map(|f| f.checkpoint(ctx, units));
        let amount = units.iter().map(|u| u.amount).max().unwrap_or(0);
        self.checkpoints.lock().unwrap().push(amount);
        match self.cut_at {
            Some(at) if amount >= at => Checkpoint::Cut,
            _ => forwarded.unwrap_or(Checkpoint::Continue),
        }
    }

    fn cancelled(&self, _ctx: &UnitCtx, bill: &CancelBill) {
        self.bills.lock().unwrap().push(bill.clone());
    }

    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {
        self.abandoned.fetch_add(1, Ordering::SeqCst);
    }

    fn session_opened(&self, _ctx: &UnitCtx) -> Result<(), ReasonCode> {
        Ok(())
    }

    fn session_ended(&self, _ctx: &UnitCtx) {
        self.sessions_ended.fetch_add(1, Ordering::SeqCst);
    }

    fn served(&self, ctx: &UnitCtx, model: &str, provider: &str) {
        if let Some(f) = &self.forward {
            f.served(ctx, model, provider);
        }
        (self.served.lock().unwrap()).push((model.to_string(), provider.to_string()));
    }

    fn laned(&self, ctx: &UnitCtx, lane: &str) {
        if let Some(f) = &self.forward {
            f.laned(ctx, lane);
        }
        self.laned.lock().unwrap().push(lane.to_string());
    }
}

impl Book {
    pub(crate) fn bills(&self) -> Vec<CancelBill> {
        self.bills.lock().unwrap().clone()
    }

    fn served(&self) -> Vec<(String, String)> {
        self.served.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub(crate) fn laned(&self) -> Vec<String> {
        self.laned.lock().unwrap().clone()
    }
}

pub(crate) fn arrival(target: &str, body: &[u8]) -> Arrival {
    arrival_by("POST", target, body)
}

fn arrival_by(method: &str, target: &str, body: &[u8]) -> Arrival {
    Arrival {
        claim: 0,
        method: method.as_bytes().to_vec(),
        target: target.as_bytes().to_vec(),
        fields: vec![(b"content-type".to_vec(), b"text/plain".to_vec())],
        body: bytes::Bytes::copy_from_slice(body),
    }
}

fn after(ms: u64) -> u64 {
    now_ns() + ms * 1_000_000
}

pub(crate) async fn drive(units: &PlaneUnits<'_, TestUnits, Far, Caller>) -> Outcome {
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
        taps: None,
    };
    match run_unit_async(&kernel, units, &ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}

pub(crate) const CHUNKS: &[&[u8]] = &[b"hello ", b"far ", b"end"];

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

#[test]
fn pending_wake_resumes_and_preserves_the_answer() {
    for way in ways() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&["pend"], CHUNKS),
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
            assert_eq!(caller.text(), "hello far end");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_on_piece_keeps_the_units_buffers_until_it_returns() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["wedge"], CHUNKS),
            Caller::default(),
        );

        struct Counted(Arc<[u8]>);
        impl AsRef<[u8]> for Counted {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        let body: Arc<[u8]> = Arc::from(&b"wedged"[..]);
        let arrival = Arrival {
            body: bytes::Bytes::from_owner(Counted(body.clone())),
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
async fn a_local_answer_ends_the_unit_without_the_far_end() {
    for way in ways() {
        for members in [&["ok"][..], &[][..]] {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(members, CHUNKS),
                Caller::default(),
            );
            let units = r.driver.unit(
                &steps,
                &far,
                &caller,
                arrival("/local", b"answered here"),
                0,
            );
            let outcome = drive(&units).await;
            assert!(
                matches!(outcome, Outcome::Completed),
                "{way:?} {members:?}: {outcome:?}"
            );
            assert_eq!(caller.text(), "answered here", "{way:?} {members:?}");
            assert_eq!(caller.status(), Some(200), "{way:?} {members:?}");
            assert!(
                far.sent().is_empty(),
                "{way:?} {members:?}: the far end is never sent to"
            );
        }
    }
}

#[tokio::test]
async fn with_no_member_a_far_bound_unit_ends_at_the_walks_terminal() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&[], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(
                outcome,
                Outcome::Refused(StepName::Route, ReasonCode::BreakerOpen)
                    | Outcome::Failed(StepName::Route, ReasonCode::BreakerOpen)
            ),
            "{way:?}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the terminal is rendered");
        assert_eq!(rendered.status, 503, "{way:?}");
        assert!(far.sent().is_empty(), "{way:?}");
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

#[tokio::test]
async fn a_usage_tap_fault_the_door_returns_reaches_the_kernel_counter() {
    use metrics::{
        Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };
    use std::collections::BTreeMap;
    type Counts = Arc<Mutex<BTreeMap<String, u64>>>;
    struct Cell(Counts, String);
    impl CounterFn for Cell {
        fn increment(&self, value: u64) {
            *self.0.lock().unwrap().entry(self.1.clone()).or_insert(0) += value;
        }
        fn absolute(&self, value: u64) {
            self.0.lock().unwrap().insert(self.1.clone(), value);
        }
    }
    struct Local(Counts);
    impl Recorder for Local {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let series = format!("{}{{{}}}", key.name(), labels.join(","));
            Counter::from_arc(Arc::new(Cell(Arc::clone(&self.0), series)))
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }
    let counts = Counts::default();
    let local = Local(Arc::clone(&counts));
    let _recording = metrics::set_default_local_recorder(&local);
    let mut ran = 0u64;
    for way in ways() {
        ran += 1;
        for (member, reason) in [("tap-bad-json", "bad_json"), ("tap-unknown", "unknown")] {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&[member], CHUNKS),
                Caller::default(),
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
            assert!(matches!(drive(&units).await, Outcome::Completed));
            let seen: Vec<&str> = steps
                .tap_faults
                .lock()
                .unwrap()
                .iter()
                .map(|f| f.1)
                .collect();
            assert_eq!(seen, vec![reason], "{way:?}: one fault per unit");
        }
        let ok = TestUnits::passing();
        let (far, caller) = (Far::new(&["ok"], CHUNKS), Caller::default());
        let r = rig(way, BufferCaps::default(), Book::default());
        let units = r.driver.unit(&ok, &far, &caller, arrival("/call", b"p"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        assert!(
            ok.tap_faults.lock().unwrap().is_empty(),
            "{way:?}: an answer carrying none counts none"
        );
    }
    let series = |reason: &str| {
        format!(
            "busbar_billing_tap_decode_fail_total{{protocol={},reason={reason}}}",
            super::common::TAP_FAULT_PROTOCOL
        )
    };
    let counts = counts.lock().unwrap().clone();
    assert_eq!(counts.get(&series("bad_json")), Some(&ran), "{counts:?}");
    assert_eq!(counts.get(&series("unknown")), Some(&ran), "{counts:?}");
}

#[tokio::test]
async fn the_answering_member_is_named_to_the_money_steps_once() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        assert_eq!(
            r.book.served(),
            vec![("ok".to_string(), PROVIDER.to_string())],
            "{way:?}"
        );
    }
}

#[tokio::test]
async fn a_failed_over_unit_names_the_member_that_answered() {
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
        assert_eq!(
            r.book.served(),
            vec![("ok".to_string(), PROVIDER.to_string())],
            "{way:?}"
        );
    }
}

#[tokio::test]
async fn a_served_unit_writes_exactly_one_metering_row() {
    use busbar_kernel::governance::{metering_bucket, GovState};
    use busbar_kernel::plane_driver::{EndPost, FeeRefund, PlaneMoney, UnitMoney};
    struct NoPost;
    impl EndPost for NoPost {
        fn post(&self, _: &UnitCtx, _: Ended) {}
    }
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let dispatcher = Arc::new(busbar_plugin_loader::dispatch::Dispatcher::new(
        busbar_plugin_loader::dispatch::DispatchConfig::default(),
    ));
    let plugin = busbar_plugin_loader::dispatch::load_dropped::<
        busbar_plugin_loader::dispatch::kinds::store::Store,
    >(
        &path,
        &statement,
        busbar_plugin_loader::dispatch::Bind {
            instance: format!("plane-metering-{}", busbar_kernel::door::op_id().counter()).into(),
            max_inflight_cap: 1024,
            sink: Arc::new(busbar_plugin_loader::dispatch::NoSink),
            dispatcher: dispatcher.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the actual store loads through the memory ABI");
    let settings =
        std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".to_string());
    let _: serde_json::Value =
        serde_json::from_str(&settings).expect("the actual store settings are JSON");
    let store = Arc::new(
        busbar_plugin_loader::store_v3::LoadedStore::open(
            plugin,
            dispatcher,
            settings.as_bytes(),
            busbar_kernel::door::op_id,
        )
        .expect("the actual store opens"),
    );
    let gov = Arc::new(GovState::new_with_signer(store, None, None).expect("gov"));
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(NoPost)));
    let at = 1_700_000_000;
    let unit = ctx(7);
    money.open(
        unit.key,
        UnitMoney {
            key: Arc::new(busbar_contract::records::VirtualKey {
                id: "k".into(),
                enabled: true,
                ..Default::default()
            }),
            cost: Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
                None,
                0,
                &std::collections::BTreeMap::new(),
            )),
            pool: String::new(),
            lane: "opened".into(),
            classes: Arc::from(vec!["input".to_string()]),
            arrived: at,
            mode: busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
            fee: FeeRefund::CallerStatus,
            charge: Default::default(),
        },
    );
    let book = Book {
        forward: Some(money.clone()),
        ..Book::default()
    };
    let way = ways()[0];
    let r = rig(way, BufferCaps::default(), book);
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["retry", "ok"], CHUNKS),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
    assert!(matches!(drive(&units).await, Outcome::Completed));
    money.settle_end(unit.key, 200);
    gov.flush_metering();
    let rows = gov
        .metering_for(metering_bucket(at))
        .expect("metering read");
    assert_eq!(rows.len(), 1, "exactly one row");
    assert_eq!(
        (
            rows[0].model.as_str(),
            rows[0].provider.as_str(),
            rows[0].requests
        ),
        ("ok", PROVIDER, 1),
        "the serving member's row, one request"
    );
}

#[tokio::test]
async fn an_attempt_carries_the_pool_the_walk_picked() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        let sent = far.sent();
        assert_eq!(
            (sent[0].member.as_str(), sent[0].pool.as_str()),
            ("ok", POOL),
            "{way:?}"
        );
    }
}

#[tokio::test]
async fn the_walks_status_table_fails_over_before_the_plane_sees_the_piece() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&[OVERLOADED, "ok"], CHUNKS),
            Caller::default(),
        );
        let before = r.stats()[stat::ON_PIECES];
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
        assert!(matches!(drive(&units).await, Outcome::Completed));
        assert_eq!(
            far.sent().len(),
            2,
            "{way:?}: failed over to the second member"
        );
        assert_eq!(
            caller.text(),
            "hello far end",
            "{way:?}: no 529 byte reached the caller"
        );
        assert_eq!(caller.status(), Some(200));
        assert_eq!(
            r.stats()[stat::ON_PIECES] - before,
            2 + 2 + 3,
            "{way:?}: ATTEMPT + body twice, then the second far end's three pieces; never the 529"
        );
    }
}

#[tokio::test]
async fn trailers_reach_the_plane_which_decides() {
    for way in ways() {
        for (member, expect) in [
            ("trailers", "hello far end[far-status: 0]"),
            ("trailers-ignored", "hello far end"),
        ] {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&[member], CHUNKS),
                Caller::default(),
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
            assert!(
                matches!(drive(&units).await, Outcome::Completed),
                "{way:?} {member}"
            );
            assert_eq!(caller.text(), expect, "{way:?} {member}");
        }
    }
}

#[tokio::test]
async fn a_cut_answer_ends_cleanly_on_a_plane_that_reads_no_cut() {
    for way in ways() {
        for member in ["cut", "ok"] {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&[member], CHUNKS),
                Caller::default(),
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
            assert!(
                matches!(drive(&units).await, Outcome::Completed),
                "{way:?} {member}"
            );
            assert_eq!(caller.text(), "hello far end", "{way:?} {member}");
        }
    }
}

#[tokio::test]
async fn a_text_message_reaches_the_caller_as_text() {
    for way in ways() {
        for (member, texts) in [("text", true), ("ok", false)] {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&[member], CHUNKS),
                Caller::default(),
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
            assert!(
                matches!(drive(&units).await, Outcome::Completed),
                "{way:?} {member}"
            );
            let (t, w) = (
                caller.texts.load(Ordering::SeqCst),
                caller.writes.load(Ordering::SeqCst),
            );
            assert!(w > 0, "{way:?} {member}");
            assert_eq!(
                t == w,
                texts,
                "{way:?} {member}: {t} of {w} writes were text"
            );
        }
    }
}

#[tokio::test]
async fn exhaustion_answers_the_walks_status_and_retry_after() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&[OVERLOADED], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"p"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(
                outcome,
                Outcome::Refused(StepName::Route, ReasonCode::BreakerOpen)
                    | Outcome::Failed(StepName::Route, ReasonCode::BreakerOpen)
            ),
            "{way:?}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the terminal is rendered");
        assert_eq!(rendered.status, 503, "{way:?}");
        assert_eq!(
            rendered.body,
            b"refused:503:The service is temporarily overloaded. Please retry shortly.:retry=2",
            "{way:?}: the plane renders the walk's status, Retry-After and the shed's own words"
        );
        assert_eq!(caller.text(), "", "{way:?}: nothing had streamed");
    }
}

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

pub fn statuses() -> Vec<RefusalStatus> {
    let row = |dialect, reason, status| RefusalStatus {
        dialect,
        reason: reason_code(reason),
        status,
        _reserved: 0,
    };
    vec![
        row(0, ReasonCode::Revoked, 403),
        row(REFUSAL_ANY_DIALECT, ReasonCode::Revoked, 451),
        row(REFUSAL_ANY_DIALECT, ReasonCode::ScopeDenied, 404),
    ]
}

#[tokio::test]
async fn a_refusal_wears_the_status_the_plane_states_for_its_dialect() {
    for way in ways() {
        for (step, reason, body) in [
            (
                StepName::Authenticate,
                ReasonCode::Revoked,
                "refused:403:revoked",
            ),
            (
                StepName::Approve,
                ReasonCode::ScopeDenied,
                "refused:404:scope_denied",
            ),
            (
                StepName::Admit,
                ReasonCode::OverBudget,
                "refused:429:over_budget",
            ),
        ] {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::refusing(step, reason),
                Far::new(&["ok"], CHUNKS),
                Caller::default(),
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
            let outcome = drive(&units).await;
            assert!(
                matches!(outcome, Outcome::Refused(s, r) if s == step && r == reason),
                "{way:?}: {outcome:?}"
            );
            let rendered = units.take_rendered().expect("the refusal is rendered");
            assert_eq!(
                String::from_utf8_lossy(&rendered.body),
                body,
                "{way:?} {reason:?}"
            );
        }
    }
}

#[tokio::test]
async fn an_admission_refusal_carries_its_window_reset_to_the_plane() {
    for way in ways() {
        for (reason, wait, body) in [
            (
                ReasonCode::OverBudget,
                Some(3_600),
                "refused:429:over_budget:retry=3600",
            ),
            (
                ReasonCode::RateLimited,
                Some(42),
                "refused:429:rate_limited:retry=42",
            ),
            (ReasonCode::OverBudget, None, "refused:429:over_budget"),
        ] {
            let r = rig(way, BufferCaps::default(), Book::default());
            let steps = TestUnits {
                refuse_wait: wait,
                ..TestUnits::refusing(StepName::Admit, reason)
            };
            let (far, caller) = (Far::new(&["ok"], CHUNKS), Caller::default());
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
            let outcome = drive(&units).await;
            assert!(
                matches!(outcome, Outcome::Refused(StepName::Admit, r) if r == reason),
                "{way:?}: {outcome:?}"
            );
            assert!(far.sent().is_empty(), "{way:?}: nothing was dispatched");
            let rendered = units.take_rendered().expect("the refusal is rendered");
            assert_eq!(rendered.status, 429, "{way:?} {reason:?}");
            assert_eq!(
                String::from_utf8_lossy(&rendered.body),
                body,
                "{way:?} {reason:?} {wait:?}: the plane renders the refusal's own Retry-After"
            );
        }
    }
}

#[tokio::test]
async fn a_refused_arrival_wears_the_planes_status_and_code() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/refuse", b"x"), 0);
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
        assert_eq!(rendered.status, 404, "{way:?}");
        assert_eq!(
            String::from_utf8_lossy(&rendered.body),
            "refused:404:decode_failed:7@7",
            "{way:?}"
        );
    }
}

#[tokio::test]
async fn the_method_crosses_at_arrive() {
    for way in ways() {
        for (method, refused) in [("POST", false), ("GET", true)] {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&["ok"], CHUNKS),
                Caller::default(),
            );
            let units = r.driver.unit(
                &steps,
                &far,
                &caller,
                arrival_by(method, "/post-only", b"x"),
                0,
            );
            let outcome = drive(&units).await;
            if refused {
                assert!(
                    matches!(
                        outcome,
                        Outcome::Refused(StepName::Decode, ReasonCode::DecodeFailed)
                    ),
                    "{way:?}: {outcome:?}"
                );
                let rendered = units.take_rendered().expect("the refusal is rendered");
                assert_eq!(rendered.status, 405, "{way:?}");
                assert_eq!(
                    String::from_utf8_lossy(&rendered.body),
                    "refused:405:decode_failed:9@7"
                );
            } else {
                assert!(
                    !matches!(outcome, Outcome::Refused(StepName::Decode, _)),
                    "{way:?}: {outcome:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_refusal_carries_the_request_target() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::refusing(StepName::Authenticate, ReasonCode::Unauthenticated),
            Far::new(&["ok"], CHUNKS),
            Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/target-echo", b"x"), 0);
        let _ = drive(&units).await;
        let rendered = units.take_rendered().expect("the refusal is rendered");
        assert_eq!(
            String::from_utf8_lossy(&rendered.body),
            "refused:401:unauthenticated for /target-echo",
            "{way:?}"
        );
    }
}

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
        assert_eq!(bills[0].cause, ReasonCode::DeadlineExceeded);
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

#[tokio::test]
async fn a_stalled_caller_is_released_at_the_stated_ceiling_and_held_without_one() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS).stating(Duration::from_millis(150)),
            Caller {
                stall_after: Some(1),
                ..Caller::default()
            },
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        let outcome = tokio::time::timeout(Duration::from_secs(10), drive(&units))
            .await
            .unwrap_or_else(|_| {
                panic!("{way:?}: the stalled caller held the unit past its ceiling")
            });
        assert!(
            matches!(
                outcome,
                Outcome::Failed(StepName::Route, ReasonCode::DeadlineExceeded)
            ),
            "{way:?}: {outcome:?}"
        );
        assert_eq!(
            caller.text(),
            "hello ",
            "{way:?}: delivered before the stall"
        );
        let bill = units.cancel_bill().expect("the cut was billed");
        assert_eq!(bill.cause, ReasonCode::DeadlineExceeded, "{way:?}");

        let r = rig(way, BufferCaps::default(), Book::default());
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], CHUNKS),
            Caller {
                stall_after: Some(1),
                ..Caller::default()
            },
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(400), drive(&units))
                .await
                .is_err(),
            "{way:?}: with no ceiling stated the stalled caller holds the unit until it goes"
        );
    }
}

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
        assert_eq!(bill.cause, ReasonCode::OverBudget);
        assert_eq!(bill.disposition, CANCEL_OK_PARTIAL);
        assert_eq!(
            bill.billed,
            vec![(0, 6)],
            "{way:?}: the streamed, far-end-reported units"
        );
        let s = r.stats();
        assert_eq!(s[stat::CANCELS], 1);
        assert_eq!(
            s[stat::CANCELS_ON_WORKER],
            1,
            "ordered on the unit's worker"
        );
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
        assert_eq!(bills[0].cause, ReasonCode::Drain);
        assert_eq!(r.stats()[stat::CANCELS_ON_WORKER], 1);
    }
}

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
        assert_eq!(bills[0].cause, ReasonCode::ClientGone);
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

#[tokio::test]
async fn open_unit_drives_the_same_steps() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), Book::default());
        for (target, admitted) in [("/call", true), ("/refuse", false)] {
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
                taps: None,
            };
            let opened = open_unit(&kernel, &units, &ctx(9), run).await;
            assert_eq!(
                matches!(opened, SessionOpen::Admitted { .. }),
                admitted,
                "{way:?} {target}"
            );
            if !admitted {
                assert_eq!(
                    units.take_rendered().unwrap().body,
                    b"refused:404:decode_failed:7@9"
                );
            }
        }
    }
}
