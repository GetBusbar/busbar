// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MONEY-OWED, retirement (LEDGER M-11, PROOF-086 rows 19-22): the four cases of the deleted old
//! driver's `plane_driver_retirement_cases.rs`, proven on the port path. A unit is opened by its
//! production owner ([`PortBilling`]), its session runs through `run_session` with the production
//! books ([`UnitBooks`] over [`PortMoney`]) on the real [`PlaneMoney`] and governance book, and it is
//! retired the way its owner retires it (`PortBilling::settle`). The plane, the member walk and the
//! far end are scripted. The port's cancel is the drop of the session (`busbar_ports::plane`: a
//! session dropped without `end` is cancelled); a plane FAULT ends the session `Failed`, which
//! bills exactly the usage it accepted (§12.4 as changed by P087B).

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::abi::plane::UnitCount;
use busbar_contract::caps::{CallId, OriginKind, ReasonCode};
use busbar_contract::records::VirtualKey;
use busbar_contract::vocab::OUTCOME_APPLIED;
use busbar_contract::{Count, UnitKey};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{UsageRec, AUDIT_APPLIED, SRC_REPORTED, W_MODEL};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::{FactRef, PortError};

use super::{end_of, Admit, PortBilling};
use crate::config::groups::{ExhaustionMode, GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::cost::CostModel;
use crate::door::UnitKeyMint;
use crate::governance::{GovState, WINDOW_TOTAL};
use crate::plane_driver::cancel::{CancelBill, Checkpoint, MoneySeam, OpenUnitEvidence};
use crate::plane_driver::port_intents::{IntentHost, Looked, Resolver, WorkOutcome};
use crate::plane_driver::port_money::PortMoney;
use crate::plane_driver::port_serve::{run_session, Books, Drive, Ran, UnitBooks};
use crate::plane_driver::port_session::{
    Calls, ClientSink, Effects, SessionError, ToClient, UpExchange,
};
use crate::plane_driver::port_upstream::{
    Candidate, Failure, Members, SendFailed, TargetIdentity, UpOpen, UpReply, UpSend, Wants, Whole,
};
use crate::plane_driver::usage::{Ending, SessionUsage};
use crate::plane_driver::{AuditSink, EndPost, FeeRefund, PlaneMoney, UnitMoney};
use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
use crate::refusal::CoreRefusals;
use crate::registry::Generation;
use crate::teller::{Ended, UnitCtx};

const NOW: u64 = 1_700_000_000;
const PRINCIPAL: &str = "p:retirement";
/// The serving member's money lane, priced on the card.
const LANE: &str = "m";
const INPUT: &str = "input";

// ---- the money: the real book, seen through a recorder ------------------------------------------

/// What the session's books asked of the money seam, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Served(String),
    Checkpoint,
    Finished,
    Cancelled {
        cause: ReasonCode,
        disposition: u32,
        billed: Vec<(u32, Count)>,
    },
}

/// The production [`PlaneMoney`] as the unit's seam, every call recorded before it is passed on.
struct Recorder {
    inner: Arc<PlaneMoney>,
    seen: Mutex<Vec<Seen>>,
}

impl Recorder {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn note(&self, seen: Seen) {
        self.seen.lock().unwrap().push(seen);
    }
}

impl MoneySeam for Recorder {
    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        self.note(Seen::Checkpoint);
        MoneySeam::checkpoint(&*self.inner, ctx, units)
    }
    fn cancelled(&self, ctx: &UnitCtx, bill: &CancelBill) {
        self.note(Seen::Cancelled {
            cause: bill.cause,
            disposition: bill.disposition,
            billed: bill.billed.clone(),
        });
        MoneySeam::cancelled(&*self.inner, ctx, bill);
    }
    fn finished(&self, ctx: &UnitCtx) {
        self.note(Seen::Finished);
        MoneySeam::finished(&*self.inner, ctx);
    }
    fn served(&self, ctx: &UnitCtx, member: &str, provider: &str) {
        self.note(Seen::Served(member.to_owned()));
        MoneySeam::served(&*self.inner, ctx, member, provider);
    }
    fn laned(&self, ctx: &UnitCtx, lane: &str) {
        MoneySeam::laned(&*self.inner, ctx, lane);
    }
    fn dialled(&self, ctx: &UnitCtx) {
        MoneySeam::dialled(&*self.inner, ctx);
    }
    fn unread(&self, ctx: &UnitCtx, reason: ReasonCode) -> bool {
        MoneySeam::unread(&*self.inner, ctx, reason)
    }
    fn lane(&self, ctx: &UnitCtx) -> Option<String> {
        MoneySeam::lane(&*self.inner, ctx)
    }
    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        MoneySeam::abandoned(&*self.inner, ctx, ended);
    }
    fn session_opened(&self, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        MoneySeam::session_opened(&*self.inner, ctx)
    }
    fn session_ended(&self, ctx: &UnitCtx) {
        MoneySeam::session_ended(&*self.inner, ctx);
    }
    fn open_units(&self, out: &mut Vec<OpenUnitEvidence>) {
        MoneySeam::open_units(&*self.inner, out);
    }
}

/// The audit chain's rows: (action, resource, outcome, principal).
#[derive(Default)]
struct Audits(Mutex<Vec<(String, String, &'static str, String)>>);

impl AuditSink for Audits {
    fn record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        self.0.lock().unwrap().push((
            action.to_owned(),
            resource.to_owned(),
            outcome,
            principal.to_owned(),
        ));
    }
}

struct NoPost;

impl EndPost for NoPost {
    fn post(&self, _: &UnitCtx, _: Ended) {}
}

fn key() -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: "k".into(),
        generation_hash: "h:k".into(),
        name: "k".into(),
        enabled: true,
        group: Some("g".into()),
        revision: 1,
        ..Default::default()
    })
}

fn rate(input_utok: f64) -> crate::config::RateEntryCfg {
    crate::config::RateEntryCfg {
        input_utok,
        output_utok: 1.0,
        ..Default::default()
    }
}

/// A card that prices `lanes` (name, input µ$ per token) for group `g`, with `budget_cents` a month
/// when given.
fn card(lanes: &[(&str, f64)], budget_cents: Option<u64>) -> Arc<CostModel> {
    let limits = budget_cents
        .map(|amount| {
            vec![LimitCfg {
                selected: None,
                metric: LimitMetric::Budget,
                amount,
                per: Some(LimitWindow::Month),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }]
        })
        .unwrap_or_default();
    let groups = BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            enabled: true,
            limits,
            ..Default::default()
        },
    )]);
    let card = lanes
        .iter()
        .map(|(lane, input)| ((*lane).to_string(), rate(*input)))
        .collect::<BTreeMap<_, _>>();
    Arc::new(CostModel::resolve_parts(Some(&card), 0, &groups))
}

fn classes() -> Arc<[String]> {
    Arc::from(vec![INPUT.to_string()])
}

struct Rig {
    gov: Arc<GovState>,
    money: Arc<PlaneMoney>,
    billing: PortBilling,
    cost: Arc<CostModel>,
    seam: Arc<Recorder>,
    audits: Arc<Audits>,
}

async fn rig() -> Rig {
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .expect("governance"),
    );
    let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(NoPost)));
    let audits = Arc::new(Audits::default());
    let billing = PortBilling::new(
        Arc::clone(&money),
        Arc::clone(&gov),
        Arc::new(UnitKeyMint::default()),
        Arc::clone(&audits) as Arc<dyn AuditSink>,
    );
    let seam = Arc::new(Recorder {
        inner: Arc::clone(&money),
        seen: Mutex::new(Vec::new()),
    });
    Rig {
        gov,
        money,
        billing,
        cost: card(&[(LANE, 1.0)], None),
        seam,
        audits,
    }
}

/// One request admitted and opened by its owner; its books' money is the recorded seam.
fn open(r: &Rig) -> (PortMoney, UnitCtx) {
    let unit = r
        .billing
        .open(Admit {
            instance: "mcp",
            classes: classes(),
            key: key(),
            cost: Arc::clone(&r.cost),
            mode: ExhaustionMode::FinishUnit,
            arrived: NOW,
        })
        .expect("admitted");
    let money = PortMoney::new(
        Arc::clone(&r.seam) as Arc<dyn MoneySeam>,
        classes(),
        Arc::clone(&r.audits) as Arc<dyn AuditSink>,
    );
    (money, unit.ctx)
}

/// The key's whole-window (tokens, spend in cents, requests).
async fn usage(r: &Rig) -> (Count, i64, u64) {
    let u = r
        .gov
        .derived_bucket_usage_async(&r.cost, "k", WINDOW_TOTAL, true, NOW)
        .await
        .expect("usage");
    (u.tokens, u.spend_cents, u.requests)
}

// ---- the session: a scripted plane, walk and far end --------------------------------------------

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
    Usage(&'static str, u64),
    Audit(&'static str, &'static str),
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
            It::Respond(status) => PlaneOut::Respond { status: *status },
            It::Body(b) => PlaneOut::Body(b),
            It::End => PlaneOut::End,
            It::Forward => PlaneOut::Forward { stream: false },
            It::Want(k, v) => PlaneOut::Want(*k, FactRef::Text(v)),
            It::UpMethod(m) => PlaneOut::UpMethod(m),
            It::UpPath(p) => PlaneOut::UpPath(p),
            It::UpEnd => PlaneOut::UpEnd,
            It::Usage(class, amount) => PlaneOut::Usage {
                class,
                amount: *amount,
                scale: 0,
                source: SRC_REPORTED,
            },
            It::Audit(action, resource) => PlaneOut::Audit {
                verdict: AUDIT_APPLIED,
                action,
                resource,
            },
        });
    }
}

struct Live;

#[derive(Default)]
struct Plane {
    request: Vec<It>,
    /// One answer per piece the plane is handed (the far end's head, body and end).
    pieces: Mutex<VecDeque<Vec<It>>>,
    end: Vec<It>,
    /// Every piece FAULTs.
    fault_pieces: bool,
}

fn nope() -> PortError {
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
        play(&self.request, sink);
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
        if self.fault_pieces {
            return Err(nope());
        }
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

    fn end(&self, _: Live, sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        play(&self.end, sink);
        Ok(())
    }

    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(nope())
    }

    fn probe(&self, _: &TargetIn<'_>, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<Live, PortError> {
        Err(nope())
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

/// A plane that FORWARDs its request to the walk; `request` is said before the FORWARD.
fn forwarding(before: &[It], pieces: Vec<Vec<It>>, end: Vec<It>) -> Plane {
    let mut request = before.to_vec();
    request.extend([It::Forward, It::Want(W_MODEL, "m")]);
    Plane {
        request,
        pieces: Mutex::new(VecDeque::from(pieces)),
        end,
        fault_pieces: false,
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

fn member() -> Candidate {
    Candidate {
        pool: "pool".into(),
        qualified_member: "fixture-member".into(),
        identity: TargetIdentity::Registration,
        resource: None,
        upstream: "m1".into(),
        provider: "{}".into(),
        base_path: "/v1".into(),
        flags: 0,
        params: Vec::new(),
    }
}

/// One member; the member that serves names the unit's money lane, as the egress walk does
/// (`port_egress`: `pending.served(money_lane(selected), provider)`).
struct Walk {
    queue: VecDeque<Candidate>,
    money: PortMoney,
    ctx: UnitCtx,
}

impl Walk {
    fn of(money: &PortMoney, ctx: &UnitCtx) -> Self {
        Self {
            queue: VecDeque::from([member()]),
            money: money.clone(),
            ctx: ctx.clone(),
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
        self.money.served(&self.ctx, LANE, &member.upstream);
    }
}

/// The far end: it answers 200 at once, or (`hang`) never answers once it was dialled.
#[derive(Default)]
struct Far {
    hang: bool,
    dialled: Arc<AtomicBool>,
}

impl UpSend for Far {
    type Rest<'a> = Whole;

    async fn open<'a>(
        &'a mut self,
        _: &'a Candidate,
        _: UpExchange,
    ) -> Result<UpOpen<Whole>, SendFailed> {
        self.dialled.store(true, Ordering::SeqCst);
        if self.hang {
            std::future::pending::<()>().await;
        }
        Ok(UpReply {
            status: 200,
            headers: Vec::new(),
            body: b"hi".to_vec(),
        }
        .opened())
    }
}

struct Quiet;

impl Effects for Quiet {
    fn emit(&self, _: u64, _: &[u8]) {}
}

/// A caller that went away: it takes nothing (`Ready(false)`), and keeps the status of the first
/// head written to it, as the owner's client sink does (`port_mount::Counted`).
#[derive(Default)]
struct Gone {
    polls: AtomicUsize,
    status: AtomicU16,
}

impl ClientSink for Gone {
    fn poll_items(&self, _: &mut Context<'_>, items: &mut Vec<ToClient>) -> Poll<bool> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        for item in items.iter() {
            if let ToClient::Head { status, .. } = item {
                let _ =
                    self.status
                        .compare_exchange(0, *status, Ordering::SeqCst, Ordering::SeqCst);
            }
        }
        Poll::Ready(false)
    }
}

impl Effects for Gone {
    fn emit(&self, _: u64, _: &[u8]) {}
    fn client(&self) -> Option<&dyn ClientSink> {
        Some(self)
    }
}

/// One session of `plane` over `walk` and `far`, its books the unit's.
async fn session(
    plane: &Plane,
    walk: &mut Walk,
    far: &mut Far,
    effects: &dyn Effects,
    books: &dyn Books,
) -> Result<Ran, SessionError> {
    let store = Store;
    let resolver = Resolver::new(&store, Some([1; 32]));
    let refusals = CoreRefusals::new();
    run_session(
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
            books,
            carrier: None,
        },
    )
    .await
}

fn usage_of(amount: u64) -> SessionUsage {
    let mut usage = SessionUsage::new();
    usage
        .answer(
            INPUT,
            UsageRec {
                amount,
                scale: 0,
                source: SRC_REPORTED,
            },
        )
        .expect("a valid report");
    usage
}

// ---- the four cases -------------------------------------------------------------------------------

/// PROOF-086 row 19 (old: `an_unpolled_worker_cancel_keeps_its_disposition_and_record_writes`). The
/// plane writes its record (an AUDIT row) and FORWARDs; the far end is dialled and has not answered;
/// the session is cancelled (dropped) before its caller polled any of it. The record it wrote stays
/// written, once, under the request's principal; the cancel tells the books nothing (no bill, no
/// end); the unit stays open for its owner, whose retirement (a gateway failure that ran nothing,
/// `end_of(502, false)`) closes it with nothing billed; a later sweep bills nothing and writes no
/// record again.
#[tokio::test]
async fn retirement_an_unpolled_cancel_keeps_its_disposition_and_record_writes() {
    let r = rig().await;
    let (money, ctx) = open(&r);
    let books = UnitBooks::new(&money, &ctx, Some(PRINCIPAL));
    let plane = forwarding(
        &[It::Audit("thing.cancel", "thing:x")],
        Vec::new(),
        Vec::new(),
    );
    let mut walk = Walk::of(&money, &ctx);
    let mut far = Far {
        hang: true,
        ..Far::default()
    };
    let dialled = Arc::clone(&far.dialled);
    let mut running = Box::pin(session(&plane, &mut walk, &mut far, &Quiet, &books));
    std::future::poll_fn(|cx| {
        for _ in 0..32 {
            assert!(
                running.as_mut().poll(cx).is_pending(),
                "the far end never answers"
            );
            if dialled.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }
        }
        panic!("the far end was never dialled");
    })
    .await;
    drop(running);

    let written = vec![(
        "thing.cancel".to_owned(),
        "thing:x".to_owned(),
        OUTCOME_APPLIED,
        PRINCIPAL.to_owned(),
    )];
    assert_eq!(*r.audits.0.lock().unwrap(), written, "the record, once");
    assert_eq!(
        r.seam.seen(),
        Vec::<Seen>::new(),
        "the cancel bills nothing"
    );
    assert_eq!(r.money.open_units(), 1, "the unit waits for its owner");

    r.billing.settle(ctx.key, end_of(502, false));
    assert_eq!(r.money.open_units(), 0);
    let (tokens, spend, _) = usage(&r).await;
    assert_eq!((tokens, spend), (Count::ZERO, 0), "nothing was reported");

    r.billing.settle(ctx.key, end_of(502, false));
    assert_eq!(
        usage(&r).await.0,
        Count::ZERO,
        "a later sweep bills nothing"
    );
    assert_eq!(r.seam.seen(), Vec::<Seen>::new());
    assert_eq!(
        *r.audits.0.lock().unwrap(),
        written,
        "and writes no record again"
    );
}

/// PROOF-086 row 20 (old: `an_unpolled_worker_cancel_fault_is_not_cancelled_again`). The plane
/// FAULTs on the far end's answer before its caller got anything: the session ends `Failed`, which
/// bills exactly the usage it accepted (none) and is no cancel (owner decision P087B replaced the
/// CANCEL_FAILED bill of nothing): its books finish the unit once. The unit is never cancelled:
/// its owner's retirement adds no cancel and no bill, and the request stays counted (its far end
/// was dialled, so the owner's "ran nothing" does not release it).
#[tokio::test]
async fn retirement_a_cancel_fault_is_not_cancelled_again() {
    let r = rig().await;
    let (money, ctx) = open(&r);
    let books = UnitBooks::new(&money, &ctx, Some(PRINCIPAL));
    let plane = Plane {
        fault_pieces: true,
        ..forwarding(&[], Vec::new(), Vec::new())
    };
    let mut walk = Walk::of(&money, &ctx);
    let mut far = Far::default();
    let ran = session(&plane, &mut walk, &mut far, &Quiet, &books).await;
    assert!(matches!(ran, Err(SessionError::Port(_))), "{ran:?}");
    drop(walk);

    let once = vec![Seen::Finished];
    assert_eq!(r.seam.seen(), once, "the failed end, once: no cancel, no bill");
    assert_eq!(r.money.open_units(), 1, "the unit waits for its owner");

    r.billing.settle(ctx.key, end_of(502, false));
    assert_eq!(r.money.open_units(), 0);
    assert_eq!(
        usage(&r).await,
        (Count::ZERO, 0, 1),
        "nothing billed, the request counted once"
    );

    r.billing.settle(ctx.key, end_of(502, false));
    assert_eq!(r.seam.seen(), once, "never cancelled again");
    assert_eq!(usage(&r).await, (Count::ZERO, 0, 1));
}

/// PROOF-086 row 21 (old: `the_first_checkpoint_prices_its_answer_lane_on_the_admitted_card`). A
/// unit's route entry (`m`) and the lane that answers it (`tool_x`, the serving member's) are priced
/// in opposite ways. Its first checkpoint prices the answer lane, on the card it was admitted under:
/// with a 1-cent budget, an expensive answer lane cuts it (the driver's OverBudget) and a cheap one
/// lets it run, whatever the route entry costs. A later card that prices the same lanes the other way
/// prices only the units admitted under it.
#[tokio::test]
async fn retirement_the_first_checkpoint_prices_its_answer_lane_on_the_admitted_card() {
    const ANSWER: &str = "tool_x";
    const ROUTE_ENTRY: &str = "m";
    let card_of = |expensive: bool| {
        let (cheap, dear) = (1.0, 100_000.0);
        card(
            &[
                (ROUTE_ENTRY, if expensive { cheap } else { dear }),
                (ANSWER, if expensive { dear } else { cheap }),
            ],
            Some(1),
        )
    };
    for expensive in [false, true] {
        let gov = Arc::new(
            GovState::new_with_core(crate::real_store::core().await, None, None)
                .await
                .expect("governance"),
        );
        let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(NoPost)));
        let audits: Arc<dyn AuditSink> = Arc::new(Audits::default());
        let key = key();
        let admit = |unit: u64, cost: Arc<CostModel>| {
            let grant = gov.try_admit(&cost, &key, "", NOW).expect("admitted");
            money.open_admitted(
                UnitKey::new(unit),
                UnitMoney {
                    key: Arc::clone(&key),
                    cost,
                    pool: String::new(),
                    lane: ROUTE_ENTRY.to_string(),
                    classes: classes(),
                    arrived: NOW,
                    mode: ExhaustionMode::CutStream,
                    fee: FeeRefund::CallerStatus,
                    charge: Default::default(),
                },
                Arc::new(grant),
            );
            UnitCtx {
                call: CallId::UNBOUND,
                key: UnitKey::new(unit),
                origin: OriginKind::Client,
                session: None,
                generation: Generation::FIRST,
                admin_listener: false,
                kernel_verb_only: false,
            }
        };
        let books = PortMoney::new(
            Arc::clone(&money) as Arc<dyn MoneySeam>,
            classes(),
            Arc::clone(&audits),
        );
        let admitted = admit(7, card_of(expensive));
        // The card changes after the unit was admitted: the next unit is admitted under it.
        let later = admit(8, card_of(!expensive));
        for ctx in [&admitted, &later] {
            books.served(ctx, ANSWER, "p");
            assert_eq!(
                money.serving(ctx.key, str::to_owned).as_deref(),
                Some(ANSWER)
            );
        }
        let cut = |dear: bool| {
            if dear {
                Checkpoint::Cut
            } else {
                Checkpoint::Continue
            }
        };
        assert_eq!(
            books.checkpoint(&admitted, &usage_of(1), None),
            cut(expensive),
            "the first checkpoint prices the answer lane on the admitted card (expensive: {expensive})"
        );
        assert_eq!(
            books.checkpoint(&later, &usage_of(1), None),
            cut(!expensive),
            "the later card prices only the unit admitted under it (expensive: {expensive})"
        );
        money.settle_end(admitted.key, if expensive { 429 } else { 200 });
        money.settle_end(later.key, if expensive { 200 } else { 429 });
        assert_eq!(money.open_units(), 0);
    }
}

/// PROOF-086 row 22 (old: `idle_maintenance_bills_a_dropped_stream_once_without_another_arrival`).
/// The caller of a streamed reply goes away at its first item. Nothing else arrives: the session
/// runs on to its end on its own, its books end the unit once with the plane's stated usage, and the
/// unit waits, open, for its owner; the owner's retirement (settled by the status the client was
/// answered) bills that usage exactly once, and a later settlement or a late cancel bill adds nothing.
#[tokio::test]
async fn retirement_a_dropped_stream_is_billed_once_without_another_arrival() {
    let r = rig().await;
    let (money, ctx) = open(&r);
    let books = UnitBooks::new(&money, &ctx, Some(PRINCIPAL));
    let plane = forwarding(
        &[],
        vec![vec![It::Respond(200)], vec![It::Body(b"hi")], vec![It::End]],
        vec![It::Usage(INPUT, 30)],
    );
    let mut walk = Walk::of(&money, &ctx);
    let mut far = Far::default();
    let caller = Gone::default();
    let ran = session(&plane, &mut walk, &mut far, &caller, &books).await;
    assert!(ran.is_ok(), "{ran:?}");
    assert!(
        caller.polls.load(Ordering::SeqCst) >= 1,
        "the caller was gone"
    );
    assert_eq!(
        r.seam.seen(),
        vec![
            Seen::Served(LANE.to_owned()),
            Seen::Checkpoint,
            Seen::Finished
        ],
        "the session's end, once"
    );
    assert_eq!(r.money.open_units(), 1, "the unit waits for its owner");
    assert_eq!(usage(&r).await.0, Count::ZERO, "nothing billed before it");

    let status = u32::from(caller.status.load(Ordering::SeqCst));
    assert_eq!(status, 200);
    r.billing.settle(ctx.key, end_of(status, true));
    assert_eq!(r.money.open_units(), 0);
    let (tokens, _, requests) = usage(&r).await;
    assert_eq!(
        (tokens, requests),
        (Count::from(30u64), 1),
        "the stated usage, once"
    );

    r.billing.settle(ctx.key, end_of(status, true));
    books.ended(
        Ending::Cancel {
            cause: ReasonCode::ClientGone,
            far_end_answered: true,
            streamed: true,
        },
        &usage_of(30),
    );
    let (tokens, _, requests) = usage(&r).await;
    assert_eq!(
        (tokens, requests),
        (Count::from(30u64), 1),
        "billed once: a later settlement or cancel adds nothing"
    );
    assert_eq!(r.money.open_units(), 0);
}
