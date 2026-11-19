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

/// The unit's billable classes: a count's class is its index here (`input` 0, `output` 1).
fn classes() -> Arc<[String]> {
    Arc::from(vec!["input".to_string(), "output".to_string()])
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
// is gone. Like the listener's sink, it notes the status of the first head it is handed, written
// or not: the unit is settled with it.
// ---------------------------------------------------------------------------------------------

struct Caller {
    fail_at: usize,
    writes: AtomicUsize,
    status: AtomicU16,
    /// What reached the caller, in order.
    took: Mutex<Vec<String>>,
}

impl Caller {
    fn failing_at(fail_at: usize) -> Self {
        Self {
            fail_at,
            writes: AtomicUsize::new(0),
            status: AtomicU16::new(0),
            took: Mutex::new(Vec::new()),
        }
    }

    fn staying() -> Self {
        Self::failing_at(usize::MAX)
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
        if self.writes.fetch_add(1, Ordering::SeqCst) == self.fail_at {
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
            charge: Default::default(),
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
    .expect("the session runs to its end")
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

/// What every case that bills the stated (7, 11) asserts: the books took the plane's final usage
/// once, as one checkpoint answered `verdict`, and no cancel; the unit settles to exactly 18
/// tokens, closes, and a second settlement adds nothing; nothing was audited unread or dropped.
async fn assert_billed_the_stated_usage_once(r: &Rig, caller: &Caller, verdict: Checkpoint) {
    assert_eq!(
        r.seam.log(),
        vec![
            format!("checkpoint {:?} {verdict:?}", vec![(0u32, 7u64), (1, 11)]),
            "finished".to_string(),
        ],
        "the plane's final usage reached the books once, and nothing cancelled it"
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

// The two other P087 cases (an unpriced done piece; a count-refused done piece) are owed, not
// written here: on the port path the plane's running usage reaches the money only at the session's
// end and a refused USAGE fails the session (which posts nothing), so neither "the last accepted
// report bills" nor its `plane-usage-unread` row exists yet (D/pass1/NEEDS.tsv, card P087).

// ---------------------------------------------------------------------------------------------
// P088: the second half (a done piece straddling the deadline or a reload; a unit buried with its
// done piece in flight or settled). Its cases follow here, on the same fixture.
// ---------------------------------------------------------------------------------------------
