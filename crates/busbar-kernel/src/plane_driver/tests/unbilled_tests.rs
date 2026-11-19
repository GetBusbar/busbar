// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PROVIDER-CHARGED USAGE THAT MUST NOT BILL 0, ON THE PORT PATH (design `unbilled`, K0; owed proof
//! PROOF-086). The money rule: usage the upstream incurred and the plane stated is billed exactly
//! once, at the member that served it, whatever becomes of the caller's last write.
//!
//! THE FIXTURE. One whole session over the port ([`super::run_session`]): a scripted plane that
//! FORWARDs, one member `b` whose far end answers 200 `ok`, and the plane's three far-end pieces
//! (HEAD, BODY, END). The HEAD piece states its running usage (3 in, 4 out); the END piece is the
//! plane's done answer and states the final usage (7 in, 11 out) unless a case states another. The
//! books are the production [`UnitBooks`] over [`PortMoney`] over the real [`PlaneMoney`] (a unit
//! opened on lane `m`, priced 1 micro-unit per token), behind a seam that records every call it
//! passes on. The unit is settled as the listener settles it (`port_mount::Settle`): the status of
//! the head the plane wrote, `ran`. The bill is read back from the governance ledger: exact tokens.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::abi::plane::UnitCount;
use busbar_contract::caps::{OriginKind, ReasonCode};
use busbar_contract::records::VirtualKey;
use busbar_contract::{Count, UnitKey};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{SRC_REPORTED, W_MODEL};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::{FactRef, PortError};

use super::{Drive, Ran, UnitBooks};
use crate::config::groups::{ExhaustionMode, GroupCfg};
use crate::cost::CostModel;
use crate::governance::{GovState, WINDOW_TOTAL};
use crate::plane_driver::port_billing::end_of;
use crate::plane_driver::port_intents::{IntentHost, Looked, Resolver, WorkOutcome};
use crate::plane_driver::port_money::PortMoney;
use crate::plane_driver::port_session::{Calls, ClientSink, Effects, ToClient};
use crate::plane_driver::port_upstream::{
    Candidate, Failure, Members, SendFailed, UpOpen, UpReply, UpSend, Wants, Whole,
};
use crate::plane_driver::{
    AuditSink, CancelBill, Checkpoint, EndPost, FeeRefund, MoneySeam, OpenUnitEvidence, PlaneMoney,
    UnitMoney,
};
use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
use crate::refusal::CoreRefusals;
use crate::registry::Generation;
use crate::teller::{Ended, UnitCtx};

const NOW: u64 = 1_700_000_000;
const UNIT: u64 = 1;

/// The unit's billable classes: a count's class is its index here (`input` 0, `output` 1, `bytes`
/// 2). The plane declares `bytes`; lane `m`'s card names no price for it.
fn classes() -> Arc<[String]> {
    Arc::from(vec![
        "input".to_string(),
        "output".to_string(),
        "bytes".to_string(),
    ])
}

// ---------------------------------------------------------------------------------------------
// The scripted plane.
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
enum It {
    Respond(u16),
    Body(&'static [u8]),
    End,
    Forward,
    Want(u32, &'static str),
    UpMethod(&'static str),
    UpPath(&'static str),
    UpEnd,
    /// A cumulative SRC_REPORTED USAGE at scale 0.
    Usage(&'static str, u64),
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
            It::Respond(status) => PlaneOut::Respond { status: *status },
            It::Body(bytes) => PlaneOut::Body(bytes),
            It::End => PlaneOut::End,
            It::Forward => PlaneOut::Forward { stream: false },
            It::Want(key, value) => PlaneOut::Want(*key, FactRef::Text(value)),
            It::UpMethod(method) => PlaneOut::UpMethod(method),
            It::UpPath(path) => PlaneOut::UpPath(path),
            It::UpEnd => PlaneOut::UpEnd,
            It::Usage(class, amount) => PlaneOut::Usage {
                class,
                amount: *amount,
                scale: 0,
                source: SRC_REPORTED,
            },
        });
    }
}

struct Live;

/// A plane that FORWARDs to one member and answers the far end's HEAD, BODY and END pieces with
/// `pieces`, in order.
struct Plane {
    pieces: Mutex<VecDeque<Vec<It>>>,
}

impl Plane {
    fn answering(head: Vec<It>, body: Vec<It>, done: Vec<It>) -> Self {
        Self {
            pieces: Mutex::new(VecDeque::from([head, body, done])),
        }
    }
}

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

impl Calls for Plane {
    type Session = Live;

    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Live, PortError> {
        play(&[It::Forward, It::Want(W_MODEL, "m")], sink);
        Ok(Live)
    }

    fn piece(
        &self,
        _: &mut Live,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let items = self.pieces.lock().unwrap().pop_front().unwrap_or_default();
        play(&items, sink);
        Ok(())
    }

    fn rewrite(
        &self,
        _: &mut Live,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }

    fn end(&self, _: Live, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Ok(())
    }

    fn probe(&self, _: &TargetIn<'_>, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<Live, PortError> {
        Err(refused())
    }

    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }

    fn upstream(
        &self,
        _: &mut Live,
        _: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        play(&[It::UpMethod("POST"), It::UpPath("/p"), It::UpEnd], sink);
        Ok(())
    }
}

fn req() -> PlaneIn<'static> {
    PlaneIn {
        route: 1,
        flags: 0,
        auth: 1,
        method: "POST",
        path: "/x",
        query: "",
        headers: &[],
        identity: &[],
        request_id: 1,
        carrier: 0,
        work: "",
        ticket_record: &[],
    }
}

// ---------------------------------------------------------------------------------------------
// The walk (one member, `b`), its far end and the records the session's intents would use.
// ---------------------------------------------------------------------------------------------

struct Walk {
    queue: VecDeque<Candidate>,
    served: Vec<String>,
}

impl Walk {
    fn of_b() -> Self {
        Self {
            queue: VecDeque::from([Candidate {
                pool: "pool".into(),
                qualified_member: "pool/b".into(),
                identity: crate::plane_driver::port_upstream::TargetIdentity::Registration,
                resource: None,
                upstream: "b".into(),
                provider: "{}".into(),
                base_path: "/v1".into(),
                flags: 0,
                params: Vec::new(),
            }]),
            served: Vec::new(),
        }
    }
}

impl Members for Walk {
    async fn next(&mut self, _: &Wants) -> Option<Candidate> {
        self.queue.pop_front()
    }
    fn declined(&mut self, _: &Candidate) {}
    fn failed(&mut self, _: &Candidate, _: &Failure) {}
    fn served(&mut self, member: &Candidate) {
        self.served.push(member.upstream.to_string());
    }
}

/// The far end: it answers 200 `ok` (a HEAD, one BODY, END).
struct Far;

impl UpSend for Far {
    type Rest<'a> = Whole;

    async fn open<'a>(
        &'a mut self,
        _: &'a Candidate,
        _: crate::plane_driver::port_session::UpExchange,
    ) -> Result<UpOpen<Whole>, SendFailed> {
        Ok(UpReply {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        }
        .opened())
    }
}

struct Store;

impl IntentHost for Store {
    fn lookup<'a>(
        &'a self,
        _: Scope,
        _: u32,
        _: u32,
        key: &'a [u8],
        looked: &'a mut Looked,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        looked.push(&[key], b"v");
        Box::pin(std::future::ready(Ok(())))
    }
    fn store<'a>(
        &'a self,
        _: Scope,
        _: u32,
        _: u64,
        _: &'a [u8],
        _: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn delete<'a>(&'a self, _: Scope, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn commit<'a>(
        &'a self,
        _: Scope,
        _: &'a [CommitOp<'a>],
    ) -> BoxFut<'a, Result<CommitOutcome, RecordsDenied>> {
        Box::pin(std::future::ready(Ok(CommitOutcome::Applied)))
    }
    fn work<'a>(
        &'a self,
        _: &'a crate::plane_driver::port_intents::WorkIntent<'a>,
    ) -> BoxFut<'a, WorkOutcome<'a>> {
        Box::pin(std::future::ready(WorkOutcome::unsupported()))
    }
    fn push<'a>(&'a self, _: u64, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
}

// ---------------------------------------------------------------------------------------------
// The caller: its `fail_at`th write (from 0) fails, as the listener's pipe does once the client
// is gone; its `hang_at`th write never completes (the session is held there until it is dropped).
// Like the listener's sink, it notes the status of the first head it is handed, written or not:
// the unit is settled with it.
// ---------------------------------------------------------------------------------------------

struct Caller {
    fail_at: usize,
    hang_at: usize,
    writes: AtomicUsize,
    status: AtomicU16,
    /// What reached the caller, in order.
    took: Mutex<Vec<String>>,
}

impl Caller {
    fn failing_at(fail_at: usize) -> Self {
        Self {
            fail_at,
            hang_at: usize::MAX,
            writes: AtomicUsize::new(0),
            status: AtomicU16::new(0),
            took: Mutex::new(Vec::new()),
        }
    }

    fn staying() -> Self {
        Self::failing_at(usize::MAX)
    }

    fn hanging_at(hang_at: usize) -> Self {
        Self {
            hang_at,
            ..Self::staying()
        }
    }

    fn took(&self) -> Vec<String> {
        self.took.lock().unwrap().clone()
    }
}

fn shown(item: &ToClient) -> String {
    match item {
        ToClient::Head { status, .. } => format!("head {status}"),
        ToClient::Body(bytes) => format!("body {}", String::from_utf8_lossy(bytes)),
        ToClient::End => "end".to_owned(),
        other => format!("{other:?}"),
    }
}

impl ClientSink for Caller {
    fn poll_items(&self, _: &mut Context<'_>, items: &mut Vec<ToClient>) -> Poll<bool> {
        for item in items.iter() {
            if let ToClient::Head { status, .. } = item {
                let _ =
                    self.status
                        .compare_exchange(0, *status, Ordering::Relaxed, Ordering::Relaxed);
            }
        }
        let write = self.writes.fetch_add(1, Ordering::SeqCst);
        if write == self.hang_at {
            return Poll::Pending;
        }
        if write == self.fail_at {
            return Poll::Ready(false);
        }
        self.took
            .lock()
            .unwrap()
            .extend(items.drain(..).map(|item| shown(&item)));
        Poll::Ready(true)
    }
}

impl Effects for Caller {
    fn emit(&self, _: u64, _: &[u8]) {}

    fn client(&self) -> Option<&dyn ClientSink> {
        Some(self)
    }
}

// ---------------------------------------------------------------------------------------------
// The money: the real plane money, behind a seam that records what passes through it.
// ---------------------------------------------------------------------------------------------

struct Posted;

impl EndPost for Posted {
    fn post(&self, _: &UnitCtx, _: Ended) {}
}

/// Passes every call on to the plane money and records the ones that decide the bill.
struct Witness {
    money: Arc<PlaneMoney>,
    log: Mutex<Vec<String>>,
}

impl Witness {
    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl MoneySeam for Witness {
    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        let verdict = MoneySeam::checkpoint(&*self.money, ctx, units);
        let counts: Vec<(u32, u64)> = units.iter().map(|u| (u.class, u.amount)).collect();
        self.log
            .lock()
            .unwrap()
            .push(format!("checkpoint {counts:?} {verdict:?}"));
        verdict
    }

    fn cancelled(&self, ctx: &UnitCtx, bill: &CancelBill) {
        self.log
            .lock()
            .unwrap()
            .push(format!("cancelled {:?} {:?}", bill.cause, bill.billed));
        MoneySeam::cancelled(&*self.money, ctx, bill);
    }

    fn finished(&self, ctx: &UnitCtx) {
        self.log.lock().unwrap().push("finished".into());
        MoneySeam::finished(&*self.money, ctx);
    }

    fn served(&self, ctx: &UnitCtx, member: &str, provider: &str) {
        MoneySeam::served(&*self.money, ctx, member, provider);
    }

    fn laned(&self, ctx: &UnitCtx, lane: &str) {
        MoneySeam::laned(&*self.money, ctx, lane);
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        self.log.lock().unwrap().push("abandoned".into());
        MoneySeam::abandoned(&*self.money, ctx, ended);
    }

    fn session_opened(&self, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        MoneySeam::session_opened(&*self.money, ctx)
    }

    fn session_ended(&self, ctx: &UnitCtx) {
        MoneySeam::session_ended(&*self.money, ctx);
    }

    fn open_units(&self, out: &mut Vec<OpenUnitEvidence>) {
        MoneySeam::open_units(&*self.money, out);
    }
}

/// The unit's audit chain (`plane_usage_undeclared`, `plane_usage_rounded`, the plane's rows).
#[derive(Default)]
struct Rows(Mutex<Vec<String>>);

impl AuditSink for Rows {
    fn record(&self, action: &str, resource: &str, _: &'static str, _: &str) {
        self.0.lock().unwrap().push(format!("{action} {resource}"));
    }
}

struct Rig {
    gov: Arc<GovState>,
    money: Arc<PlaneMoney>,
    seam: Arc<Witness>,
    rows: Arc<Rows>,
    cost: Arc<CostModel>,
    key: Arc<VirtualKey>,
}

/// One open unit on lane `m` (1 micro-unit per input and per output token), no budget.
async fn rig() -> Rig {
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .expect("gov"),
    );
    let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(Posted)));
    let rate = || crate::config::RateEntryCfg {
        input_utok: 1.0,
        output_utok: 1.0,
        ..Default::default()
    };
    let card = BTreeMap::from([("m".to_string(), rate())]);
    let groups = BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            enabled: true,
            ..Default::default()
        },
    )]);
    let cost = Arc::new(CostModel::resolve_parts(Some(&card), 0, &groups));
    let key = Arc::new(VirtualKey {
        id: "k".into(),
        generation_hash: "h:k".into(),
        name: "k".into(),
        enabled: true,
        group: Some("g".into()),
        revision: 1,
        ..Default::default()
    });
    // Admitted as the request's one admission admits it: the request is counted.
    let grant = gov
        .try_admit(&cost, &key, "", NOW)
        .expect("admitted, the request counted");
    money.open(
        UnitKey::new(UNIT),
        UnitMoney {
            key: Arc::clone(&key),
            cost: Arc::clone(&cost),
            pool: String::new(),
            lane: "m".into(),
            classes: classes(),
            arrived: NOW,
            mode: ExhaustionMode::FinishUnit,
            fee: FeeRefund::CallerStatus,
            charge: grant.charge().clone(),
        },
    );
    let seam = Arc::new(Witness {
        money: Arc::clone(&money),
        log: Mutex::new(Vec::new()),
    });
    Rig {
        gov,
        money,
        seam,
        rows: Arc::default(),
        cost,
        key,
    }
}

fn unit_ctx() -> UnitCtx {
    UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(UNIT),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

/// The session to its end over member `b`, its books the unit's.
async fn serve(r: &Rig, plane: &Plane, caller: &Caller, walk: &mut Walk) -> Ran {
    session(r, plane, caller, walk)
        .await
        .expect("the session runs to its end")
}

/// [`serve`], its outcome as the session returned it.
async fn session(
    r: &Rig,
    plane: &Plane,
    caller: &Caller,
    walk: &mut Walk,
) -> Result<Ran, crate::plane_driver::port_session::SessionError> {
    let store = Store;
    let resolver = Resolver::new(&store, Some([1; 32]));
    let refusals = CoreRefusals::new();
    let money = PortMoney::new(
        Arc::clone(&r.seam) as Arc<dyn MoneySeam>,
        classes(),
        Arc::clone(&r.rows) as Arc<dyn AuditSink>,
    );
    let ctx = unit_ctx();
    let books = UnitBooks::new(&money, &ctx, Some("k"));
    let mut far = Far;
    super::run_session(
        plane,
        &req(),
        b"{}",
        Drive {
            resolver: &resolver,
            members: Some(walk),
            send: Some(&mut far),
            dialect: "openai",
            refusals: &refusals,
            effects: caller,
            books: &books,
            carrier: None,
        },
    )
    .await
}

/// The unit's settlement as the listener makes it for a session that failed or was dropped
/// unfinished (`port_mount::Settle`: `Err`, or its drop): a gateway failure that ran nothing.
fn settle_failed(r: &Rig) {
    r.money
        .settle_end_as(UnitKey::new(UNIT), end_of(502, false));
}

/// The requests the governance book counts for the caller's key.
async fn requests(r: &Rig) -> u64 {
    r.gov
        .derived_bucket_usage_async(&r.cost, &r.key.id, WINDOW_TOTAL, true, NOW)
        .await
        .expect("usage")
        .requests
}

/// The checkpoint the witness logs for `counts` (class index, amount) answered `verdict`.
fn checkpointed(counts: &[(u32, u64)], verdict: Checkpoint) -> String {
    format!("checkpoint {counts:?} {verdict:?}")
}

/// The unit's settlement, as the listener makes it once its session returned (`Settle::finish`):
/// the status of the head the plane wrote (502 when none), the session ran.
fn settle(r: &Rig, caller: &Caller) {
    let status = match caller.status.load(Ordering::Relaxed) {
        0 => 502,
        status => status,
    };
    r.money
        .settle_end_as(UnitKey::new(UNIT), end_of(u32::from(status), true));
}

/// The tokens the ledger holds for the caller's key.
async fn ledgered(r: &Rig) -> Count {
    r.gov
        .derived_bucket_usage_async(&r.cost, &r.key.id, WINDOW_TOTAL, true, NOW)
        .await
        .expect("usage")
        .tokens
}

/// What every case that bills the stated (7, 11) asserts: the books took the HEAD's running (3, 4)
/// as it was accepted, then the plane's final usage once, as one checkpoint answered `verdict`, and
/// no cancel; the unit settles to exactly 18 tokens, closes, and a second settlement adds nothing;
/// nothing was audited unread or dropped.
async fn assert_billed_the_stated_usage_once(r: &Rig, caller: &Caller, verdict: Checkpoint) {
    assert_eq!(
        r.seam.log(),
        vec![
            checkpointed(&[(0, 3), (1, 4)], Checkpoint::Continue),
            checkpointed(&[(0, 7), (1, 11)], verdict),
            "finished".to_string(),
        ],
        "each usage reached the books once as it was accepted, and nothing cancelled it"
    );
    settle(r, caller);
    assert_eq!(
        ledgered(r).await,
        Count::from(18u64),
        "the provider's stated usage (7 + 11), exactly"
    );
    assert_eq!(r.money.open_units(), 0, "the settlement closed the unit");
    settle(r, caller);
    assert_eq!(
        ledgered(r).await,
        Count::from(18u64),
        "a second settlement bills nothing again"
    );
    assert!(
        r.rows.0.lock().unwrap().is_empty(),
        "nothing went unread or was dropped: {:?}",
        r.rows.0.lock().unwrap()
    );
}

// ---------------------------------------------------------------------------------------------
// P087: the caller's last write fails; a stream's last write fails; cut by budget.
// ---------------------------------------------------------------------------------------------

/// K0 site 1, a reply that never streamed: the far end answered, the plane wrote the whole reply
/// in its done answer with the final usage (7, 11), and that one write to the caller fails, so not
/// a byte reached the caller (cancel-table rule 3's facts). The session still ends on the plane's
/// own `end`: the stated usage bills, once.
#[tokio::test]
async fn unbilled_a_caller_whose_last_write_fails_bills_the_stated_usage() {
    let r = rig().await;
    let plane = Plane::answering(
        vec![It::Usage("input", 3), It::Usage("output", 4)],
        Vec::new(),
        vec![
            It::Respond(200),
            It::Body(b"done"),
            It::End,
            It::Usage("input", 7),
            It::Usage("output", 11),
        ],
    );
    let caller = Caller::failing_at(0);
    let mut walk = Walk::of_b();
    let ran = serve(&r, &plane, &caller, &mut walk).await;
    assert_eq!(walk.served, ["b"], "b served the unit");
    assert_eq!(ran.member.as_deref(), Some("b"));
    assert_eq!(
        caller.writes.load(Ordering::SeqCst),
        1,
        "one write, the last"
    );
    assert!(caller.took().is_empty(), "nothing reached the caller");
    assert_billed_the_stated_usage_once(&r, &caller, Checkpoint::Continue).await;
}

/// K0 site 1 for a stream: the HEAD piece's answer writes the head and the BODY piece's the first
/// bytes (the reply streams), then the done answer states (7, 11) and its write fails. The done
/// answer's final usage is what bills, not the running (3, 4).
#[tokio::test]
async fn unbilled_a_stream_whose_last_write_fails_bills_the_stated_usage() {
    let r = rig().await;
    let plane = Plane::answering(
        vec![
            It::Respond(200),
            It::Usage("input", 3),
            It::Usage("output", 4),
        ],
        vec![It::Body(b"data: a")],
        vec![
            It::Body(b"data: end"),
            It::End,
            It::Usage("input", 7),
            It::Usage("output", 11),
        ],
    );
    let caller = Caller::failing_at(2);
    let mut walk = Walk::of_b();
    serve(&r, &plane, &caller, &mut walk).await;
    assert_eq!(walk.served, ["b"]);
    assert_eq!(
        caller.took(),
        ["head 200", "body data: a"],
        "the reply streamed before its last write"
    );
    assert_eq!(
        caller.writes.load(Ordering::SeqCst),
        3,
        "the third write, the done answer's, failed"
    );
    assert_billed_the_stated_usage_once(&r, &caller, Checkpoint::Continue).await;
}

/// K0, `OverBudget`: the unit's spend ceiling (10 micro-units) is crossed by the done answer's
/// final usage (18 micro-units), so the checkpoint that takes it answers `Cut`. The ceiling never
/// rewrites the provider's actual obligation: the stated (7, 11) bills, once.
#[tokio::test]
async fn unbilled_a_done_piece_cut_by_budget_bills_the_stated_usage() {
    let r = rig().await;
    r.money
        .limit_unit_spend(UnitKey::new(UNIT), 10)
        .expect("the unit's spend ceiling");
    let plane = Plane::answering(
        vec![It::Usage("input", 3), It::Usage("output", 4)],
        Vec::new(),
        vec![
            It::Respond(200),
            It::Body(b"done"),
            It::End,
            It::Usage("input", 7),
            It::Usage("output", 11),
        ],
    );
    let caller = Caller::staying();
    let mut walk = Walk::of_b();
    serve(&r, &plane, &caller, &mut walk).await;
    assert_eq!(walk.served, ["b"]);
    assert_eq!(caller.took(), ["head 200", "body done", "end"]);
    assert_billed_the_stated_usage_once(&r, &caller, Checkpoint::Cut).await;
}

// ---------------------------------------------------------------------------------------------
// P087B: the unpriced done piece; the count-refused done piece; a session dropped before its end.
// The rule (owner decision, P087B): a session bills exactly the usage it accepted, once, whatever
// its ending. A final report the money cannot price is never billed as 0 nor at an invented price:
// it is audited `plane-usage-unread` (BUSBAR-5046) with its raw stated counts and the unit is left
// unread (unresolved), while the usage accepted before it bills at the admitted card.
// ---------------------------------------------------------------------------------------------

/// K0 `Unpriced`: the HEAD piece states (3, 4), which the money accepts as it comes; the done
/// piece states (7, 11) and 5 `bytes`, a class lane `m`'s card names no price for, so the money
/// cannot price that final report under the unit's spend ceiling. It is not billed (neither 0 nor
/// an invented price): the unit is left unread, one `plane-usage-unread` row carries the unit, its
/// lane and the raw stated counts, and the accepted (3, 4) bills exactly once.
#[tokio::test]
async fn unbilled_an_unpriced_done_piece_bills_the_accepted_usage_once_and_records_unread() {
    let r = rig().await;
    r.money
        .limit_unit_spend(UnitKey::new(UNIT), 1_000)
        .expect("the unit's spend ceiling");
    let plane = Plane::answering(
        vec![It::Usage("input", 3), It::Usage("output", 4)],
        Vec::new(),
        vec![
            It::Respond(200),
            It::Body(b"done"),
            It::End,
            It::Usage("input", 7),
            It::Usage("output", 11),
            It::Usage("bytes", 5),
        ],
    );
    let caller = Caller::staying();
    let mut walk = Walk::of_b();
    serve(&r, &plane, &caller, &mut walk).await;
    assert_eq!(caller.took(), ["head 200", "body done", "end"]);
    assert_eq!(
        r.seam.log(),
        vec![
            checkpointed(&[(0, 3), (1, 4)], Checkpoint::Continue),
            checkpointed(&[(0, 7), (1, 11), (2, 5)], Checkpoint::Unpriced),
            "unread Unpriced".to_string(),
            "finished".to_string(),
        ],
        "the final report was asked once, answered Unpriced, and the unit was left unread"
    );
    assert_eq!(
        *r.rows.0.lock().unwrap(),
        [format!(
            "plane-usage-unread unit:{UNIT} lane:m reason:unpriced \
             stated:input=7/reported,output=11/reported,bytes=5/reported"
        )],
        "one unread row: the unit, its lane and the raw stated counts"
    );
    settle(&r, &caller);
    assert_eq!(
        ledgered(&r).await,
        Count::from(7u64),
        "the accepted (3 + 4), exactly: the unpriced report is neither 0 nor priced"
    );
    assert_eq!(r.money.open_units(), 0, "the settlement closed the unit");
    settle(&r, &caller);
    assert_eq!(
        ledgered(&r).await,
        Count::from(7u64),
        "a second settlement bills nothing again"
    );
    assert_eq!(r.rows.0.lock().unwrap().len(), 1, "never audited twice");
}

/// K0b: the done piece states (7, 11) beside a USAGE the session may not keep (a class no plane
/// may name). The session refuses the whole answer and fails. The rule is no longer "a failed
/// session bills nothing": the usage it accepted, the HEAD's (3, 4), bills exactly once, at the
/// owner's settlement of the failure; the refused report is never billed, and is audited
/// `plane-usage-unread` with the reason it was refused.
#[tokio::test]
async fn unbilled_a_count_refused_done_piece_bills_the_accepted_usage_once_and_audits_the_refusal()
{
    let r = rig().await;
    let plane = Plane::answering(
        vec![It::Usage("input", 3), It::Usage("output", 4)],
        Vec::new(),
        vec![
            It::Respond(200),
            It::Body(b"done"),
            It::End,
            It::Usage("input", 7),
            It::Usage("output", 11),
            It::Usage("Bad", 1),
        ],
    );
    let caller = Caller::staying();
    let mut walk = Walk::of_b();
    let ran = session(&r, &plane, &caller, &mut walk).await;
    assert!(
        matches!(
            ran,
            Err(crate::plane_driver::port_session::SessionError::Violation(
                crate::plane_driver::port_session::Violation::Usage(
                    crate::plane_driver::usage::UsageInvalid::Class
                )
            ))
        ),
        "the refused count failed the session: {ran:?}"
    );
    assert!(
        caller.took().is_empty(),
        "nothing of the refused answer reached the caller"
    );
    assert_eq!(
        r.seam.log(),
        vec![
            checkpointed(&[(0, 3), (1, 4)], Checkpoint::Continue),
            "unread Unpriced".to_string(),
            checkpointed(&[(0, 3), (1, 4)], Checkpoint::Continue),
            "finished".to_string(),
        ],
        "the accepted (3, 4) is the failed session's bill; nothing of the refused report was taken"
    );
    assert_eq!(
        *r.rows.0.lock().unwrap(),
        [format!(
            "plane-usage-unread unit:{UNIT} lane:m reason:unpriced refused:class"
        )],
        "the refused report is audited with its reason"
    );
    settle_failed(&r);
    assert_eq!(
        ledgered(&r).await,
        Count::from(7u64),
        "the accepted (3 + 4), exactly; nothing of the refused (7, 11)"
    );
    assert_eq!(r.money.open_units(), 0, "the settlement closed the unit");
    settle_failed(&r);
    assert_eq!(
        ledgered(&r).await,
        Count::from(7u64),
        "a second settlement bills nothing again"
    );
    assert_eq!(requests(&r).await, 1, "the request stays counted, once");
}

/// P090 (1): the session is dropped (its task cancelled) after the far end's HEAD piece stated
/// (3, 4), while the head's write to the caller is pending, before the plane's end. The owner
/// settles it as a failure that ran nothing; the usage the session accepted bills exactly once.
#[tokio::test]
async fn unbilled_a_session_dropped_before_its_end_bills_the_accepted_usage_once() {
    let r = rig().await;
    let plane = Plane::answering(
        vec![
            It::Respond(200),
            It::Usage("input", 3),
            It::Usage("output", 4),
        ],
        Vec::new(),
        Vec::new(),
    );
    let caller = Caller::hanging_at(0);
    let mut walk = Walk::of_b();
    {
        let mut running = Box::pin(session(&r, &plane, &caller, &mut walk));
        std::future::poll_fn(|cx| {
            assert!(
                std::future::Future::poll(running.as_mut(), cx).is_pending(),
                "the caller never takes the head"
            );
            Poll::Ready(())
        })
        .await;
    }
    assert_eq!(
        caller.writes.load(Ordering::SeqCst),
        1,
        "dropped at the head's write"
    );
    assert_eq!(
        r.seam.log(),
        vec![checkpointed(&[(0, 3), (1, 4)], Checkpoint::Continue)],
        "the HEAD's usage reached the books as it was accepted; the session never ended"
    );
    assert_eq!(r.money.open_units(), 1, "the unit waits for its owner");
    settle_failed(&r);
    assert_eq!(
        ledgered(&r).await,
        Count::from(7u64),
        "the accepted (3 + 4), exactly"
    );
    assert_eq!(r.money.open_units(), 0, "the settlement closed the unit");
    settle_failed(&r);
    assert_eq!(
        ledgered(&r).await,
        Count::from(7u64),
        "a second settlement bills nothing again"
    );
    assert_eq!(requests(&r).await, 1, "the request stays counted, once");
    assert!(
        r.rows.0.lock().unwrap().is_empty(),
        "{:?}",
        r.rows.0.lock().unwrap()
    );
}

/// P090 (2): the far end is dialled and its HEAD reaches the plane, which states no usage yet; the
/// session is dropped at the head's write. A dialled far end counts as run: the owner's "ran
/// nothing" settlement does not release the request count admission took, and bills nothing.
#[tokio::test]
async fn unbilled_a_session_dropped_after_dialling_keeps_its_request_counted() {
    let r = rig().await;
    assert_eq!(requests(&r).await, 1, "admission counted the request");
    let plane = Plane::answering(vec![It::Respond(200)], Vec::new(), Vec::new());
    let caller = Caller::hanging_at(0);
    let mut walk = Walk::of_b();
    {
        let mut running = Box::pin(session(&r, &plane, &caller, &mut walk));
        std::future::poll_fn(|cx| {
            assert!(
                std::future::Future::poll(running.as_mut(), cx).is_pending(),
                "the caller never takes the head"
            );
            Poll::Ready(())
        })
        .await;
    }
    assert_eq!(
        caller.writes.load(Ordering::SeqCst),
        1,
        "the far end answered"
    );
    assert!(r.seam.log().is_empty(), "no usage was stated");
    settle_failed(&r);
    assert_eq!(r.money.open_units(), 0, "the settlement closed the unit");
    assert_eq!(
        requests(&r).await,
        1,
        "the far end was dialled: the request is counted"
    );
    assert_eq!(ledgered(&r).await, Count::ZERO, "nothing was stated");
}

// ---------------------------------------------------------------------------------------------
// P088: the second half (a done piece straddling the deadline or a reload; a unit buried with its
// done piece in flight or settled). Its cases follow here, on the same fixture.
//
// THE PORT'S CANCEL. On the port the plane's calls are synchronous entries made between the
// session's awaits, so no cancel can land inside the plane's done answer: whatever cancels a unit
// (its deadline, a reload of its plane, its caller gone) does it by dropping the session at its
// next await, and the unit's owner then settles it as a gateway failure that ran nothing
// (`port_mount::Settle`'s drop, `end_of(502, false)`). A done piece "straddling" a cancel is one
// the plane answered and whose write to the caller was still pending when the cancel came; a done
// piece "in flight" is one the far end had not yet delivered. The rule every case asserts: the
// session bills exactly the usage it accepted, once, whatever its ending; a report the session
// refused is never billed. The deadline runs on tokio's paused clock: nothing sleeps for real.
// ---------------------------------------------------------------------------------------------

use std::future::Future;
use std::sync::atomic::AtomicBool;

use tokio::sync::Notify;
use tokio::time::Instant;

use crate::config::pools::DEFAULT_FAILOVER_DEADLINE_SECS;
use crate::plane_driver::port_session::{SessionError, UpExchange};
use crate::plane_driver::port_upstream::{Chunk, UpChunks};

/// The far end on the paused clock: it answers 200 `ok` at once, and its reply's end arrives at
/// `end_at` (never, when `None`). `awaiting_end` is set once the session waits for that end.
struct Timed {
    end_at: Option<Instant>,
    awaiting_end: Arc<AtomicBool>,
}

impl Timed {
    fn ending_at(end_at: Option<Instant>) -> Self {
        Self {
            end_at,
            awaiting_end: Arc::new(AtomicBool::new(false)),
        }
    }
}

struct TimedRest {
    body: Option<Vec<u8>>,
    end_at: Option<Instant>,
    awaiting_end: Arc<AtomicBool>,
}

impl UpChunks for TimedRest {
    async fn next(&mut self) -> Result<Option<Chunk>, SendFailed> {
        if let Some(body) = self.body.take() {
            return Ok(Some(Chunk::Body(body)));
        }
        self.awaiting_end.store(true, Ordering::SeqCst);
        match self.end_at {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending::<()>().await,
        }
        Ok(None)
    }
}

impl UpSend for Timed {
    type Rest<'a> = TimedRest;

    async fn open<'a>(
        &'a mut self,
        _: &'a Candidate,
        _: UpExchange,
    ) -> Result<UpOpen<TimedRest>, SendFailed> {
        Ok(UpOpen {
            status: 200,
            headers: Vec::new(),
            rest: TimedRest {
                body: Some(b"ok".to_vec()),
                end_at: self.end_at,
                awaiting_end: Arc::clone(&self.awaiting_end),
            },
        })
    }
}

/// A caller that takes nothing from the done answer on: its first write is never answered
/// (`Pending`, as a client that stopped reading), so the session waits there until its owner
/// drops it. `held` tells whoever waits for that moment.
#[derive(Default)]
struct Holding {
    polls: AtomicUsize,
    held: Notify,
}

impl ClientSink for Holding {
    fn poll_items(&self, _: &mut Context<'_>, _: &mut Vec<ToClient>) -> Poll<bool> {
        if self.polls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.held.notify_one();
        }
        Poll::Pending
    }
}

impl Effects for Holding {
    fn emit(&self, _: u64, _: &[u8]) {}

    fn client(&self) -> Option<&dyn ClientSink> {
        Some(self)
    }
}

/// [`serve`] over any far end, its outcome as the session returned it.
async fn session_over<S: UpSend>(
    r: &Rig,
    plane: &Plane,
    effects: &dyn Effects,
    walk: &mut Walk,
    far: &mut S,
) -> Result<Ran, SessionError> {
    let store = Store;
    let resolver = Resolver::new(&store, Some([1; 32]));
    let refusals = CoreRefusals::new();
    let money = PortMoney::new(
        Arc::clone(&r.seam) as Arc<dyn MoneySeam>,
        classes(),
        Arc::clone(&r.rows) as Arc<dyn AuditSink>,
    );
    let ctx = unit_ctx();
    let books = UnitBooks::new(&money, &ctx, Some("k"));
    super::run_session(
        plane,
        &req(),
        b"{}",
        Drive {
            resolver: &resolver,
            members: Some(walk),
            send: Some(far),
            dialect: "openai",
            refusals: &refusals,
            effects,
            books: &books,
            carrier: None,
        },
    )
    .await
}

/// The unit's deadline on the paused clock: the request's default failover deadline from now.
fn deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(DEFAULT_FAILOVER_DEADLINE_SECS)
}

/// The owner's settlement of a unit whose session was cancelled or failed (`port_mount::Settle`:
/// dropped unfinished, or `Err`): a gateway failure that ran nothing.
fn settle_cancelled(r: &Rig) {
    r.money
        .settle_end_as(UnitKey::new(UNIT), end_of(502, false));
}

/// What every cancelled or failed case asserts once the session is gone: the owner's settlement
/// bills exactly `tokens`, closes the unit, and a second settlement adds nothing.
async fn assert_settled_once(r: &Rig, tokens: u64, what: &str) {
    settle_cancelled(r);
    assert_eq!(ledgered(r).await, Count::from(tokens), "{what}, exactly");
    assert_eq!(r.money.open_units(), 0, "the settlement closed the unit");
    settle_cancelled(r);
    assert_eq!(
        ledgered(r).await,
        Count::from(tokens),
        "a second settlement bills nothing again"
    );
}

/// The running usage (3, 4) the far end's HEAD piece states, and a done answer for the far end's
/// END piece: the whole reply and `usage`.
fn plane_done_with(done: &[It]) -> Plane {
    let mut piece = vec![It::Respond(200), It::Body(b"done"), It::End];
    piece.extend_from_slice(done);
    Plane::answering(
        vec![It::Usage("input", 3), It::Usage("output", 4)],
        Vec::new(),
        piece,
    )
}

/// The checkpoint entry the witness logs for counts (7, 11), whatever the verdict.
fn took_the_final_report(log: &[String]) -> bool {
    let counts = format!("checkpoint {:?}", vec![(0u32, 7u64), (1, 11)]);
    log.iter().any(|entry| entry.starts_with(&counts))
}

/// K0 site 2: the far end's END reaches the plane at the unit's deadline, the plane answers it
/// done with (7, 11), and the deadline cuts the session while that answer's write is pending. The
/// stated usage bills, once, and nothing goes unread.
#[tokio::test]
async fn unbilled_a_done_piece_straddling_the_deadline_bills_the_stated_usage() {
    let r = rig().await;
    tokio::time::pause();
    let at = deadline();
    let plane = plane_done_with(&[It::Usage("input", 7), It::Usage("output", 11)]);
    let caller = Holding::default();
    let mut walk = Walk::of_b();
    let mut far = Timed::ending_at(Some(at));
    let cut =
        tokio::time::timeout_at(at, session_over(&r, &plane, &caller, &mut walk, &mut far)).await;
    tokio::time::resume();
    assert!(cut.is_err(), "the deadline cut the session");
    assert!(
        plane.pieces.lock().unwrap().is_empty(),
        "the plane answered the far end's END: its done piece"
    );
    assert_eq!(
        caller.polls.load(Ordering::SeqCst),
        1,
        "the done answer's write was pending when the deadline came"
    );
    assert_settled_once(&r, 18, "the provider's stated usage (7 + 11)").await;
    assert!(
        r.rows.0.lock().unwrap().is_empty(),
        "nothing went unread: {:?}",
        r.rows.0.lock().unwrap()
    );
}

/// K0b site 2: the same deadline, but the done piece states a count the session refuses (a class
/// no plane may name). The refusal ends the session before the deadline can: it bills the last
/// report the session accepted, (3, 4), records the refused one unread, and takes nothing of it.
/// Raced against the deadline or not, the bill and the rows are the same.
#[tokio::test]
async fn unbilled_a_count_refused_done_piece_straddling_the_deadline_bills_the_last_accepted_report(
) {
    let refused = [It::Usage("input", 7), It::Usage("Output", 11)];

    let raced = rig().await;
    tokio::time::pause();
    let at = deadline();
    let plane = plane_done_with(&refused);
    let caller = Caller::staying();
    let mut walk = Walk::of_b();
    let mut far = Timed::ending_at(Some(at));
    let ran = tokio::time::timeout_at(
        at,
        session_over(&raced, &plane, &caller, &mut walk, &mut far),
    )
    .await;
    tokio::time::resume();
    assert!(
        matches!(ran, Ok(Err(SessionError::Violation(_)))),
        "the refusal ended the session, not the deadline: {ran:?}"
    );
    assert!(plane.pieces.lock().unwrap().is_empty());

    let unraced = rig().await;
    let plane = plane_done_with(&refused);
    let caller = Caller::staying();
    let mut walk = Walk::of_b();
    let ran = session_over(&unraced, &plane, &caller, &mut walk, &mut Far).await;
    assert!(matches!(ran, Err(SessionError::Violation(_))), "{ran:?}");

    for r in [&raced, &unraced] {
        assert!(
            !took_the_final_report(&r.seam.log()),
            "nothing of the refused piece was taken: {:?}",
            r.seam.log()
        );
        assert_settled_once(r, 7, "the last accepted report (3 + 4)").await;
        let rows = r.rows.0.lock().unwrap().clone();
        assert_eq!(rows.len(), 1, "one unread row: {rows:?}");
        assert!(
            rows[0].ends_with(&format!("unit:{UNIT} reason:Unpriced")),
            "{rows:?}"
        );
    }
    assert_eq!(
        (raced.seam.log(), raced.rows.0.lock().unwrap().clone()),
        (unraced.seam.log(), unraced.rows.0.lock().unwrap().clone()),
        "the raced and the un-raced refusals book the same"
    );
}

/// K0 site 2's reload twin: the plane's generation is replaced while the done answer's write is
/// pending, and the reload stops the session (the port's cancel). The stated usage bills, once.
#[tokio::test]
async fn unbilled_a_done_piece_straddling_a_reload_bills_the_stated_usage() {
    let r = rig().await;
    let plane = plane_done_with(&[It::Usage("input", 7), It::Usage("output", 11)]);
    let caller = Holding::default();
    let mut walk = Walk::of_b();
    let mut far = Far;
    let mut running = Box::pin(session_over(&r, &plane, &caller, &mut walk, &mut far));
    tokio::select! {
        biased;
        ended = running.as_mut() => panic!("the caller never takes the done answer: {ended:?}"),
        () = caller.held.notified() => {}
    }
    // The reload: the old generation's session is stopped where it waits.
    drop(running);
    assert!(
        plane.pieces.lock().unwrap().is_empty(),
        "the done piece was answered"
    );
    assert_settled_once(&r, 18, "the provider's stated usage (7 + 11)").await;
    assert!(
        r.rows.0.lock().unwrap().is_empty(),
        "nothing went unread: {:?}",
        r.rows.0.lock().unwrap()
    );
}

/// GUARD (K0b `Panic`, site 2): the plane answers the far end's END, at the deadline, with a
/// far-bound FORWARD beside its done reply and (7, 11): a shape no piece answer may take. The
/// session fails on it before the deadline can cut it; nothing of that answer is folded or billed,
/// and the usage the session accepted before it, (3, 4), bills once.
#[tokio::test]
async fn unbilled_a_far_bound_done_piece_on_the_far_leg_straddling_the_deadline_is_not_folded() {
    let r = rig().await;
    tokio::time::pause();
    let at = deadline();
    let plane = Plane::answering(
        vec![It::Usage("input", 3), It::Usage("output", 4)],
        Vec::new(),
        vec![
            It::Forward,
            It::Respond(200),
            It::Body(b"done"),
            It::End,
            It::Usage("input", 7),
            It::Usage("output", 11),
        ],
    );
    let caller = Caller::staying();
    let mut walk = Walk::of_b();
    let mut far = Timed::ending_at(Some(at));
    let ran =
        tokio::time::timeout_at(at, session_over(&r, &plane, &caller, &mut walk, &mut far)).await;
    tokio::time::resume();
    assert!(
        matches!(ran, Ok(Err(SessionError::Violation(_)))),
        "the breach failed the session, not the deadline: {ran:?}"
    );
    assert!(
        caller.took().is_empty(),
        "nothing of the breach reached the caller"
    );
    assert!(walk.served.is_empty(), "no member served by that answer");
    assert!(
        !took_the_final_report(&r.seam.log()),
        "a contract breach is never folded: {:?}",
        r.seam.log()
    );
    assert_settled_once(&r, 7, "the usage accepted before the breach (3 + 4)").await;
}

/// K0 site 4: the unit is buried (its session dropped) while the far end has not yet delivered the
/// END its done piece answers. The session accepted the HEAD's (3, 4) and nothing after it: those
/// bill, once; no report was stated and left unread.
#[tokio::test]
async fn unbilled_a_unit_buried_with_its_done_piece_in_flight_records_and_bills() {
    let r = rig().await;
    let plane = plane_done_with(&[It::Usage("input", 7), It::Usage("output", 11)]);
    let caller = Caller::staying();
    let mut walk = Walk::of_b();
    let mut far = Timed::ending_at(None);
    let awaiting_end = Arc::clone(&far.awaiting_end);
    let mut running = Box::pin(session_over(&r, &plane, &caller, &mut walk, &mut far));
    std::future::poll_fn(|cx| {
        assert!(
            running.as_mut().poll(cx).is_pending(),
            "the far end's END never comes"
        );
        assert!(
            awaiting_end.load(Ordering::SeqCst),
            "the session waits for the far end's END"
        );
        Poll::Ready(())
    })
    .await;
    drop(running);
    assert_eq!(
        plane.pieces.lock().unwrap().len(),
        1,
        "the done piece was never answered"
    );
    assert!(r.seam.log().iter().all(|entry| entry != "finished"));
    assert_settled_once(&r, 7, "the usage the session accepted (3 + 4)").await;
    assert!(
        r.rows.0.lock().unwrap().is_empty(),
        "{:?}",
        r.rows.0.lock().unwrap()
    );
}

/// K0 site 3: the unit is buried after the plane answered the far end's END done with (7, 11)
/// (its answer settled), while that answer's write to the caller is pending. The usage the
/// session accepted is the stated (7, 11): it bills, once, on the unit's lane.
#[tokio::test]
async fn unbilled_a_unit_buried_with_its_done_piece_settled_is_attributed() {
    let r = rig().await;
    let plane = plane_done_with(&[It::Usage("input", 7), It::Usage("output", 11)]);
    let caller = Holding::default();
    let mut walk = Walk::of_b();
    let mut far = Far;
    let mut running = Box::pin(session_over(&r, &plane, &caller, &mut walk, &mut far));
    std::future::poll_fn(|cx| {
        assert!(running.as_mut().poll(cx).is_pending(), "the caller holds");
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        caller.polls.load(Ordering::SeqCst),
        1,
        "the done answer's write"
    );
    drop(running);
    assert!(
        plane.pieces.lock().unwrap().is_empty(),
        "the done piece was answered"
    );
    assert_eq!(
        r.money
            .serving(UnitKey::new(UNIT), str::to_owned)
            .as_deref(),
        Some("m"),
        "the unit is billed on its lane"
    );
    assert_settled_once(&r, 18, "the provider's stated usage (7 + 11)").await;
    assert!(
        r.rows.0.lock().unwrap().is_empty(),
        "{:?}",
        r.rows.0.lock().unwrap()
    );
}
