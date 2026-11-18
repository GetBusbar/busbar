// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6, §11.3, §12.4, §12.11 (PLANE-DRIVER slice 9): one whole session over the port (intents, FORWARD, the
//! attempt walk, EXHAUSTED, end and the books), the production ticket door, and the unit books over `PortMoney`.
//! The plane is scripted; the member walk, the far end and the money seam are fakes.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::plane::UnitCount;
use busbar_contract::caps::{OriginKind, ReasonCode};
use busbar_contract::UnitKey;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::plane::{
    UsageRec, AUDIT_APPLIED, FROM_CORE, P_EXHAUSTED, P_LOOKUP, SRC_REPORTED, W_MODEL,
};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::{FactRef, PortError};

use super::{run_session, Books, Drive, TicketGate, UnitBooks};
use crate::plane_driver::cancel::{CancelBill, Checkpoint, MoneySeam};
use crate::plane_driver::port_auth::TicketDoor;
use crate::plane_driver::port_intents::{
    Hit, IntentHost, Looked, Namespace, Resolver, WorkOutcome,
};
use crate::plane_driver::port_money::{AuditRow, PortMoney};
use crate::plane_driver::port_session::{Calls, Effects, SessionError, ToClient};
use crate::plane_driver::port_upstream::{
    Candidate, Failure, Members, SendFailed, UpReply, UpSend,
};
use crate::plane_driver::usage::{Ending, SessionUsage};
use crate::plane_driver::AuditSink;
use crate::plane_grants::{TicketAdmitted, TicketDenied, TicketMint, Tickets};
use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
use crate::refusal::CoreRefusals;
use crate::registry::Generation;
use crate::teller::{Ended, UnitCtx};

#[derive(Clone)]
enum It {
    Respond(u16),
    Emit,
    Body(&'static [u8]),
    End,
    Forward,
    Want(u32, &'static str),
    Lookup(&'static [u8]),
    UpMethod(&'static str),
    UpPath(&'static str),
    UpEnd,
    Usage(&'static str, u64),
    Audit(&'static str),
    Fact(u32, &'static str),
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
            It::Emit => PlaneOut::Emit {
                carrier: 1,
                bytes: b"must stay held",
            },
            It::Respond(status) => PlaneOut::Respond { status: *status },
            It::Body(b) => PlaneOut::Body(b),
            It::End => PlaneOut::End,
            It::Forward => PlaneOut::Forward { stream: false },
            It::Want(k, v) => PlaneOut::Want(*k, FactRef::Text(v)),
            It::Lookup(key) => PlaneOut::Lookup {
                flags: 0,
                limit: 1,
                key,
            },
            It::UpMethod(m) => PlaneOut::UpMethod(m),
            It::UpPath(p) => PlaneOut::UpPath(p),
            It::UpEnd => PlaneOut::UpEnd,
            It::Usage(class, amount) => PlaneOut::Usage {
                class,
                amount: *amount,
                scale: 0,
                source: SRC_REPORTED,
            },
            It::Fact(k, v) => PlaneOut::Fact(*k, FactRef::Text(v)),
            It::Audit(action) => PlaneOut::Audit {
                verdict: AUDIT_APPLIED,
                action,
                resource: "r",
            },
        });
    }
}

struct Live;

/// The pieces the plane was handed, one entry per call.
type PieceLog = Mutex<Vec<(u32, u32, u32, Vec<u8>)>>;

#[derive(Default)]
struct Plane {
    usage_facts: u64,
    resource_scoped: bool,
    request: Vec<It>,
    upstream: Mutex<VecDeque<Vec<It>>>,
    pieces: Mutex<VecDeque<Vec<It>>>,
    end: Vec<It>,
    fault_pieces: bool,
    piece_log: PieceLog,
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

    fn usage_metadata(&self) -> (u64, &[busbar_ports::plane::UsageClass], &[Box<str>]) {
        (self.usage_facts, &[], &[])
    }

    fn resource_scoped(&self, _: u32) -> bool {
        self.resource_scoped
    }

    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Live, PortError> {
        assert!(
            !self.resource_scoped,
            "resource admission must finish before request dispatch"
        );
        play(&self.request, sink);
        Ok(Live)
    }

    fn piece(
        &self,
        _: &mut Live,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.piece_log
            .lock()
            .unwrap()
            .push((from, exchange, flags, bytes.to_vec()));
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
        let items = self
            .upstream
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default();
        play(&items, sink);
        Ok(())
    }
}

struct Quiet;

impl Effects for Quiet {
    fn emit(&self, _: u64, _: &[u8]) {}
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

#[derive(Default)]
struct Log(Mutex<Vec<String>>);

impl Books for Log {
    fn ended(&self, ending: Ending, usage: &SessionUsage) {
        let classes = usage.last().len();
        self.0
            .lock()
            .unwrap()
            .push(format!("ended {ending:?} classes={classes}"));
    }

    fn audit(&self, row: &AuditRow) {
        self.0.lock().unwrap().push(format!("audit {}", row.action));
    }

    fn end_user(&self, user: &str) {
        self.0.lock().unwrap().push(format!("user {user}"));
    }
}

struct Store;

impl IntentHost for Store {
    fn lookup(&self, _: Scope, _: u32, _: u32, key: &[u8]) -> Result<Looked, RecordsDenied> {
        Ok(Looked {
            hits: vec![Hit {
                key: key.to_vec(),
                value: b"v".to_vec(),
            }],
            chain: None,
        })
    }
    fn store(&self, _: Scope, _: u32, _: u64, _: &[u8], _: &[u8]) -> Result<(), RecordsDenied> {
        Ok(())
    }
    fn delete(&self, _: Scope, _: &[u8]) -> Result<(), RecordsDenied> {
        Ok(())
    }
    fn commit(&self, _: Scope, _: &[CommitOp<'_>]) -> Result<CommitOutcome, RecordsDenied> {
        Ok(CommitOutcome::Applied)
    }
    fn work(&self, _: &crate::plane_driver::port_intents::WorkIntent) -> WorkOutcome {
        WorkOutcome::unsupported()
    }
    fn push(&self, _: u64, _: &[u8]) -> Result<(), RecordsDenied> {
        Ok(())
    }
    fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
}

fn candidate() -> Candidate {
    Candidate {
        pool: "pool".into(),
        qualified_member: "fixture-member".into(),
        identity: crate::plane_driver::port_upstream::TargetIdentity::Registration,
        resource: None,
        upstream: "m1".into(),
        provider: "{}".into(),
        base_path: "/v1".into(),
        flags: 0,
        params: Vec::new(),
    }
}

#[derive(Default)]
struct Walk {
    queue: VecDeque<Candidate>,
    served: Vec<String>,
    failed: usize,
    /// The Retry-After the walk states once it is exhausted.
    wait: Option<u32>,
}

impl Members for Walk {
    fn next(&mut self, _: &crate::plane_driver::port_upstream::Wants) -> Option<Candidate> {
        self.queue.pop_front()
    }
    fn declined(&mut self, _: &Candidate) {}
    fn failed(&mut self, _: &Candidate, _: &Failure) {
        self.failed += 1;
    }
    fn served(&mut self, member: &Candidate) {
        self.served.push(member.upstream.to_string());
    }
    fn retry_after(&self) -> Option<u32> {
        self.wait
    }
}

struct Far;

impl UpSend for Far {
    fn send(
        &mut self,
        _: &Candidate,
        _: crate::plane_driver::port_session::UpExchange,
    ) -> Result<UpReply, SendFailed> {
        Ok(UpReply {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        })
    }
}

fn run(plane: &Plane, walk: Option<&mut Walk>, books: &Log) -> Result<super::Ran, SessionError> {
    let store = Store;
    let resolver = Resolver::new(&store, Some([1; 32]));
    let refusals = CoreRefusals::new();
    let mut far = Far;
    let (members, send): (Option<&mut dyn Members>, Option<&mut dyn UpSend>) = match walk {
        Some(w) => (Some(w), Some(&mut far)),
        None => (None, None),
    };
    run_session(
        plane,
        &req(),
        b"{}",
        Drive {
            resolver: &resolver,
            members,
            send,
            dialect: "openai",
            refusals: &refusals,
            effects: &Quiet,
            books,
            carrier: None,
        },
    )
}

fn forwarding() -> Plane {
    let plane = Plane {
        request: vec![It::Forward, It::Want(W_MODEL, "m")],
        ..Plane::default()
    };
    *plane.upstream.lock().unwrap() =
        VecDeque::from([vec![It::UpMethod("POST"), It::UpPath("/p"), It::UpEnd]]);
    *plane.pieces.lock().unwrap() =
        VecDeque::from([vec![It::Respond(200)], vec![It::Body(b"hi")], vec![It::End]]);
    plane
}

#[test]
fn a_resource_scoped_route_cannot_execute_without_completed_admission() {
    let plane = Plane {
        resource_scoped: true,
        request: vec![It::Respond(200), It::End],
        ..Plane::default()
    };
    let books = Log::default();
    assert!(matches!(
        run(&plane, None, &books),
        Err(SessionError::NotDriven)
    ));
    assert!(books.0.lock().unwrap().is_empty());
}

#[test]
fn pending_money_refusal_holds_emits_even_without_hooks() {
    pending_money_refusal(0);
}

#[test]
fn selected_declaration_never_uses_the_ordinary_money_callback() {
    pending_money_refusal(busbar_plugin_abi::plane::FB_PREPARED_ESTIMATES);
}

fn pending_money_refusal(usage_facts: u64) {
    use crate::host_services::{
        InvocationContext, KernelServices, Nest, NestDone, NestRoute, ServingGeneration,
    };
    use crate::plane_driver::port_admission::Pending;
    use crate::plane_driver::request_admission::{RequestAllocation, RequestDomain, RequestRoutes};
    use crate::refusal::RefusalMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct NoChildren;
    impl NestRoute for NoChildren {
        fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
            panic!("no child before admission");
        }
    }
    let core = Arc::new(KernelServices::new());
    let caller = busbar_contract::services::Caller::for_test(
        Arc::from("seat"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    );
    let _lease = core.admit_native_invocation(&caller).unwrap();
    assert!(core.units().pre_admitted_for(
        41,
        &caller,
        crate::host_units::UnitRecord {
            principal: Some(Arc::new(busbar_contract::records::VirtualKey {
                id: "payer".into(),
                enabled: true,
                ..Default::default()
            })),
            depth: 0,
        }
    ));
    let context = InvocationContext::new(
        Arc::new(ServingGeneration::new(core, Arc::new(NoChildren))),
        caller,
        41,
    )
    .unwrap();
    let allocation = RequestAllocation::new(
        context,
        Arc::new(crate::cost::CostModel::resolve_parts(
            None,
            0,
            &Default::default(),
        )),
        100,
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let pending = Pending::new(
        allocation,
        Arc::new(RequestRoutes::new("seat", None, None, None).unwrap()),
        None,
        move |receipt| {
            assert_eq!(receipt.domain(), &RequestDomain::Local);
            count.fetch_add(1, Ordering::SeqCst);
            Err(CoreRefusals::new().for_core(0, busbar_plugin_abi::fail::refused::R_POLICY))
        },
    );
    struct Waiting<'a>(&'a Pending);
    impl Effects for Waiting<'_> {
        fn admission(&self) -> Option<&Pending> {
            Some(self.0)
        }
        fn invocation(&self) -> Option<&InvocationContext> {
            Some(self.0.context())
        }
        fn emit(&self, _: u64, _: &[u8]) {
            panic!("money refusal must not release emitted bytes");
        }
    }
    let plane = Plane {
        usage_facts,
        request: vec![It::Emit, It::Respond(200), It::End],
        ..Plane::default()
    };
    let store = Store;
    let resolver = Resolver::new(&store, None);
    let refusals = CoreRefusals::new();
    let effects = Waiting(&pending);
    let result = run_session(
        &plane,
        &req(),
        b"{}",
        Drive {
            resolver: &resolver,
            members: None,
            send: None,
            dialect: "test",
            refusals: &refusals,
            effects: &effects,
            books: &pending,
            carrier: None,
        },
    );
    if usage_facts == 0 {
        assert!(
            matches!(result, Err(SessionError::AdmissionRefused(_))),
            "{result:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    } else {
        assert!(matches!(result, Err(SessionError::NotDriven)), "{result:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    assert!(!pending.context().effects_allowed());
}

fn statuses(client: &[ToClient]) -> Vec<String> {
    client
        .iter()
        .map(|c| match c {
            ToClient::Head { status, .. } => format!("head {status}"),
            ToClient::Body(b) => format!("body {}", String::from_utf8_lossy(b)),
            ToClient::End => "end".to_owned(),
            other => format!("{other:?}"),
        })
        .collect()
}

#[test]
fn a_local_answer_is_served_with_its_audit_rows_and_billed_as_an_end() {
    let plane = Plane {
        request: vec![It::Respond(201), It::Body(b"x"), It::End],
        end: vec![It::Usage("tokens", 5), It::Audit("did_it")],
        ..Plane::default()
    };
    let books = Log::default();
    let ran = run(&plane, None, &books).unwrap();
    assert_eq!(statuses(&ran.client), ["head 201", "body x", "end"]);
    assert!(!ran.exhausted && ran.member.is_none());
    assert_eq!(
        *books.0.lock().unwrap(),
        ["audit did_it", "ended End classes=1"]
    );
}

/// RED (ADMIN-API-1.6 §3.5, `records.user` on the MIN-3 path): the end user the plane projected (PJ_END_USER on
/// its request answer) reaches the unit's books once, before the session ends; a plane that states none tells
/// the books nothing.
#[test]
fn the_end_user_a_plane_projects_reaches_the_books() {
    let stated = Plane {
        request: vec![
            It::Fact(busbar_plugin_abi::fail::fact::PJ_END_USER, "u-1"),
            It::Respond(200),
            It::End,
        ],
        ..Plane::default()
    };
    let books = Log::default();
    run(&stated, None, &books).unwrap();
    assert_eq!(
        *books.0.lock().unwrap(),
        ["user u-1", "ended End classes=0"]
    );

    let silent = Plane {
        request: vec![It::Respond(200), It::End],
        ..Plane::default()
    };
    let books = Log::default();
    run(&silent, None, &books).unwrap();
    assert_eq!(*books.0.lock().unwrap(), ["ended End classes=0"]);
}

#[test]
fn a_forwarded_session_is_walked_fed_and_ended_and_the_member_that_served_is_named() {
    let plane = forwarding();
    let mut walk = Walk {
        queue: VecDeque::from([candidate()]),
        ..Walk::default()
    };
    let books = Log::default();
    let ran = run(&plane, Some(&mut walk), &books).unwrap();
    assert_eq!(statuses(&ran.client), ["head 200", "body hi", "end"]);
    assert_eq!(ran.member.as_deref(), Some("m1"));
    assert_eq!(ran.attempts, 1);
    assert_eq!(walk.served, ["m1"]);
}

#[test]
fn intents_resolve_before_the_forward_is_walked() {
    let plane = Plane {
        request: vec![It::Lookup(b"k")],
        ..forwarding()
    };
    // The P_LOOKUP answer is the deferred FORWARD; the pieces after it feed the reply.
    let mut pieces = plane.pieces.lock().unwrap();
    pieces.push_front(vec![It::Forward, It::Want(W_MODEL, "m")]);
    drop(pieces);
    let mut walk = Walk {
        queue: VecDeque::from([candidate()]),
        ..Walk::default()
    };
    let ran = run(&plane, Some(&mut walk), &Log::default()).unwrap();
    let log = plane.piece_log.lock().unwrap().clone();
    assert_eq!((log[0].0, log[0].2), (FROM_CORE, P_LOOKUP));
    assert_eq!(statuses(&ran.client), ["head 200", "body hi", "end"]);
}

#[test]
fn an_exhausted_walk_tells_the_plane_and_serves_what_it_renders_else_cores_refusal() {
    let rendered = Plane {
        request: vec![It::Forward],
        pieces: Mutex::new(VecDeque::from([vec![
            It::Respond(503),
            It::Body(b"plane words"),
            It::End,
        ]])),
        ..Plane::default()
    };
    let ran = run(&rendered, Some(&mut Walk::default()), &Log::default()).unwrap();
    assert!(ran.exhausted);
    let log = rendered.piece_log.lock().unwrap().clone();
    assert_eq!((log[0].0, log[0].2), (FROM_CORE, P_EXHAUSTED));
    assert_eq!(
        statuses(&ran.client),
        ["head 503", "body plane words", "end"]
    );

    let silent = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    let ran = run(&silent, Some(&mut Walk::default()), &Log::default()).unwrap();
    assert!(ran.exhausted);
    let items = statuses(&ran.client);
    assert!(
        items[0].starts_with("head 5"),
        "core's own refusal: {items:?}"
    );
    assert_eq!(items.last().map(String::as_str), Some("end"));
}

#[test]
fn a_forward_with_no_upstream_to_walk_is_not_driven() {
    let plane = forwarding();
    let err = run(&plane, None, &Log::default()).unwrap_err();
    assert!(matches!(err, SessionError::NotDriven));
}

#[test]
fn a_plane_fault_after_the_session_began_is_billed_as_failed() {
    let plane = Plane {
        request: vec![It::Lookup(b"k")],
        fault_pieces: true,
        ..Plane::default()
    };
    let books = Log::default();
    let err = run(&plane, None, &books).unwrap_err();
    assert!(matches!(err, SessionError::Port(_)));
    assert_eq!(*books.0.lock().unwrap(), ["ended Failed classes=0"]);
}

/// A ticket store that records who asked and denies.
#[derive(Default)]
struct Press {
    asked: Mutex<Vec<(String, String, String, String)>>,
}

impl Tickets for Press {
    fn mint<'a>(
        &'a self,
        _: &'a Caller<'_>,
        _: TicketMint<'a>,
    ) -> BoxFut<'a, Result<(Box<str>, u64), RecordsDenied>> {
        Box::pin(async { Err(RecordsDenied::Unavailable) })
    }

    fn is_ticket(&self, credential: &str) -> bool {
        credential.starts_with("bbt1.")
    }

    fn admit<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        audience: &'a str,
        credential: &'a str,
        _: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        self.asked.lock().unwrap().push((
            plane.plugin.into(),
            plane.name.into(),
            audience.into(),
            credential.into(),
        ));
        Box::pin(async { Err(TicketDenied::Expired) })
    }
}

#[tokio::test]
async fn the_ticket_gate_asks_the_ticket_store_as_the_plane_instance() {
    let press = Arc::new(Press::default());
    let gate = TicketGate::new(
        Arc::clone(&press) as Arc<dyn Tickets>,
        Namespace {
            plugin: "plane-x".into(),
            name: "front".into(),
            instance: 3,
            slot: 0,
        },
    );
    assert!(gate.is_ticket("bbt1.abc"));
    assert!(!gate.is_ticket("sk-123"));
    let denied = gate.admit("aud", "bbt1.abc", 100).await;
    assert!(matches!(denied, Err(TicketDenied::Expired)));
    assert_eq!(
        *press.asked.lock().unwrap(),
        vec![(
            "plane-x".to_owned(),
            "front".to_owned(),
            "aud".to_owned(),
            "bbt1.abc".to_owned()
        )]
    );
}

#[derive(Default)]
struct Seam(Mutex<Vec<String>>);

impl MoneySeam for Seam {
    fn checkpoint(&self, _: &UnitCtx, _: &[UnitCount]) -> Checkpoint {
        self.0.lock().unwrap().push("checkpoint".into());
        Checkpoint::Continue
    }
    fn cancelled(&self, _: &UnitCtx, bill: &CancelBill) {
        self.0
            .lock()
            .unwrap()
            .push(format!("cancelled {:?}", bill.cause));
    }
    fn finished(&self, _: &UnitCtx) {
        self.0.lock().unwrap().push("finished".into());
    }
    fn abandoned(&self, _: &UnitCtx, _: Ended) {}
}

#[derive(Default)]
struct Audits(Mutex<Vec<(String, String)>>);

impl AuditSink for Audits {
    fn record(&self, action: &str, _: &str, _: &'static str, principal: &str) {
        self.0
            .lock()
            .unwrap()
            .push((action.into(), principal.into()));
    }
}

#[test]
fn the_unit_books_post_the_end_through_the_unit_and_write_audit_rows_under_the_principal() {
    let seam = Arc::new(Seam::default());
    let audits = Arc::new(Audits::default());
    let money = PortMoney::new(
        Arc::clone(&seam) as Arc<dyn MoneySeam>,
        Arc::from(vec!["tokens".to_string()]),
        Arc::clone(&audits) as Arc<dyn AuditSink>,
    );
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(9),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let books = UnitBooks::new(&money, &ctx, Some("alice"));
    let mut usage = SessionUsage::new();
    usage
        .answer(
            "tokens",
            UsageRec {
                amount: 4,
                scale: 0,
                source: SRC_REPORTED,
            },
        )
        .unwrap();
    books.audit(&AuditRow {
        verdict: AUDIT_APPLIED,
        action: "act".into(),
        resource: "res".into(),
    });
    books.ended(Ending::End, &usage);
    assert_eq!(
        *audits.0.lock().unwrap(),
        vec![("act".to_owned(), "alice".to_owned())]
    );
    assert_eq!(*seam.0.lock().unwrap(), ["checkpoint", "finished"]);
    books.ended(
        Ending::Cancel {
            cause: ReasonCode::PlanePanic,
            far_end_answered: false,
            streamed: false,
        },
        &usage,
    );
    assert!(seam
        .0
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .starts_with("cancelled"));
}

#[tokio::test]
async fn a_ticket_gate_asks_the_ticket_store_as_its_instance() {
    let press = Arc::new(Press::default());
    let gate = TicketGate::new(
        Arc::clone(&press) as Arc<dyn Tickets>,
        Namespace {
            plugin: "plane-x".into(),
            name: "front".into(),
            instance: 3,
            slot: 0,
        },
    );
    let door: &dyn TicketDoor = &gate;
    assert!(door.is_ticket("bbt1.abc"));
    assert!(matches!(
        door.admit("aud", "bbt1.abc", 100).await,
        Err(TicketDenied::Expired)
    ));
}

/// The `retry-after` value of the first head in `client`, if it states one.
fn retry_after_of(client: &[ToClient]) -> Option<String> {
    client.iter().find_map(|item| match item {
        ToClient::Head { fields, .. } => fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(b"retry-after"))
            .map(|(_, value)| String::from_utf8_lossy(value).into_owned()),
        _ => None,
    })
}

#[test]
fn an_exhausted_walk_s_wait_rides_on_the_refusal_the_client_gets() {
    let rendered = Plane {
        request: vec![It::Forward],
        pieces: Mutex::new(VecDeque::from([vec![
            It::Respond(503),
            It::Body(b"busy"),
            It::End,
        ]])),
        ..Plane::default()
    };
    let mut walk = Walk {
        wait: Some(30),
        ..Walk::default()
    };
    let ran = run(&rendered, Some(&mut walk), &Log::default()).unwrap();
    assert!(ran.exhausted);
    assert_eq!(retry_after_of(&ran.client).as_deref(), Some("30"));

    let silent = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    let mut walk = Walk {
        wait: Some(7),
        ..Walk::default()
    };
    let ran = run(&silent, Some(&mut walk), &Log::default()).unwrap();
    assert_eq!(
        retry_after_of(&ran.client).as_deref(),
        Some("7"),
        "core's own refusal carries it too"
    );

    let unstated = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    let ran = run(&unstated, Some(&mut Walk::default()), &Log::default()).unwrap();
    assert_eq!(retry_after_of(&ran.client), None, "no wait, no field");
}

#[test]
fn a_retry_after_the_plane_stated_is_never_overwritten() {
    let mut items = vec![
        ToClient::Head {
            status: 429,
            fields: vec![(b"Retry-After".to_vec(), b"9".to_vec())],
        },
        ToClient::End,
    ];
    super::stamp_retry_after(&mut items, Some(30));
    assert_eq!(retry_after_of(&items).as_deref(), Some("9"));
    let Some(ToClient::Head { fields, .. }) = items.first() else {
        panic!("a head");
    };
    assert_eq!(fields.len(), 1);
}

#[test]
fn a_native_hook_cannot_run_without_its_admitted_invocation() {
    use crate::plane_driver::port_hooks::{Binder, Invocation, Selected, Selection};
    struct Required;
    impl Binder for Required {
        fn active(&self, _: u32) -> bool {
            true
        }
        fn enforcing(&self, _: u32) -> bool {
            true
        }
        fn select(&self, _: &Selection<'_>) -> Result<Selected, &'static str> {
            panic!("unadmitted hook selection must never run")
        }
    }
    struct Hooked(Invocation);
    impl Effects for Hooked {
        fn hooks(&self) -> Option<&Invocation> {
            Some(&self.0)
        }
        fn emit(&self, _: u64, _: &[u8]) {
            panic!("unadmitted hook effects must never escape")
        }
    }
    let effects = Hooked(Invocation {
        binder: Arc::new(Required),
        principal: None,
        identity: None,
        now_s: 1,
        classes: Arc::default(),
        journal: None,
        unit: UnitKey::new(1),
    });
    let plane = Plane {
        request: vec![It::Respond(200), It::End],
        ..Plane::default()
    };
    let store = Store;
    let resolver = Resolver::new(&store, None);
    let refusals = CoreRefusals::new();
    let books = Log::default();
    let result = run_session(
        &plane,
        &req(),
        b"{}",
        Drive {
            resolver: &resolver,
            members: None,
            send: None,
            dialect: "test",
            refusals: &refusals,
            effects: &effects,
            books: &books,
            carrier: None,
        },
    );
    assert!(
        matches!(result, Err(SessionError::HookPrerequisite)),
        "{result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_native_gate_holds_emits_and_tells_response_taps_why_it_refused() {
    use crate::config::{PromptAccess, UserAccess};
    use crate::plane_driver::port_hooks::tests::{configured, Fixture};
    use crate::plane_driver::port_hooks::{Binder, Invocation, Selected, Selection};
    use busbar_plugin_abi::kinds::hook::hook as abi;
    use busbar_ports::hook::{HookAnswer, HookCall, HookPort, HookView};
    use busbar_ports::CallCx;
    struct Gate(tokio::sync::mpsc::UnboundedSender<Vec<(u32, busbar_ports::FactVal)>>);
    impl HookPort for Gate {
        fn points(&self) -> u32 {
            (1 << abi::POINT_ROUTE) | (1 << abi::POINT_NOTIFY)
        }
        fn facts(&self) -> u64 {
            0
        }
        fn on<'a>(&'a self, _: CallCx, point: u32, view: &'a HookView<'a>) -> HookCall<'a> {
            if point == abi::POINT_NOTIFY {
                self.0
                    .send(
                        view.signals
                            .iter()
                            .map(|(key, value)| {
                                (
                                    *key,
                                    match value {
                                        FactRef::U(value) => busbar_ports::FactVal::U(*value),
                                        FactRef::Text(value) => {
                                            busbar_ports::FactVal::Text((*value).into())
                                        }
                                    },
                                )
                            })
                            .collect(),
                    )
                    .unwrap();
            }
            HookCall::Done(Ok(HookAnswer {
                verb: abi::VERB_REJECT,
                reject_status: Some(409),
                order: Vec::new(),
                restrict: Vec::new(),
                message: Some("operator-only".into()),
                rewrite: None,
            }))
        }
    }
    struct Bound(Selected);
    impl Binder for Bound {
        fn active(&self, _: u32) -> bool {
            true
        }
        fn enforcing(&self, _: u32) -> bool {
            true
        }
        fn select(&self, _: &Selection<'_>) -> Result<Selected, &'static str> {
            Ok(self.0.clone())
        }
    }
    struct Hooked {
        invocation: Invocation,
        context: crate::host_services::InvocationContext,
    }
    impl Effects for Hooked {
        fn hooks(&self) -> Option<&Invocation> {
            Some(&self.invocation)
        }
        fn invocation(&self) -> Option<&crate::host_services::InvocationContext> {
            Some(&self.context)
        }
        fn emit(&self, _: u64, _: &[u8]) {
            panic!("the rejected session emitted before enforcement")
        }
    }
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
    let fixture = Fixture::new();
    let call = configured(Arc::new(Gate(sent)), PromptAccess::No, UserAccess::No);
    let mut selected = fixture.selected.clone();
    // The fixture selects nothing: this gate and this tap are the only ones.
    selected.gates = Arc::from([call.clone()]);
    selected.taps.response = Arc::from([call]);
    let effects = Hooked {
        invocation: Invocation {
            binder: Arc::new(Bound(selected)),
            principal: None,
            identity: None,
            now_s: 1,
            classes: Arc::default(),
            journal: None,
            unit: UnitKey::new(7),
        },
        context: fixture.context.clone(),
    };
    tokio::task::spawn_blocking(move || {
        let plane = Plane {
            request: vec![It::Emit, It::Respond(200), It::End],
            ..Plane::default()
        };
        let store = Store;
        let resolver = Resolver::new(&store, None);
        let refusals = CoreRefusals::new();
        let books = Log::default();
        let result = run_session(
            &plane,
            &req(),
            b"{}",
            Drive {
                resolver: &resolver,
                members: None,
                send: None,
                dialect: "test",
                refusals: &refusals,
                effects: &effects,
                books: &books,
                carrier: None,
            },
        );
        match result {
            Err(SessionError::HookRefused(refusal)) => {
                assert_eq!(refusal.status, 409);
                assert_eq!(refusal.text, "the request was refused by policy");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            books.0.lock().unwrap().len(),
            1,
            "the refused unit is booked once"
        );
    })
    .await
    .unwrap();
    let signals = tokio::time::timeout(std::time::Duration::from_secs(1), received.recv())
        .await
        .expect("a gate refusal fires its response tap")
        .unwrap();
    assert!(signals.contains(&(abi::S_STAGE, busbar_ports::FactVal::U(abi::STAGE_RESPONSE))));
    assert!(signals.contains(&(abi::S_STATUS, busbar_ports::FactVal::U(409))));
    assert!(signals.contains(&(
        abi::S_OUTCOME,
        busbar_ports::FactVal::Text("rejected_by_gate".into())
    )));
    assert!(
        received.try_recv().is_err(),
        "the response stage fires once"
    );
}

/// Counts every counter the stage registers, by name and label set.
#[derive(Default)]
struct Counted(Mutex<std::collections::BTreeMap<String, Arc<std::sync::atomic::AtomicU64>>>);

impl Counted {
    fn get(&self, series: &str) -> u64 {
        self.0
            .lock()
            .unwrap()
            .get(series)
            .map_or(0, |n| n.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl metrics::Recorder for Counted {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        let labels = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect::<Vec<_>>()
            .join(",");
        let cell = Arc::clone(
            self.0
                .lock()
                .unwrap()
                .entry(format!("{}{{{labels}}}", key.name()))
                .or_default(),
        );
        metrics::Counter::from_arc(cell)
    }
    fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }
    fn register_histogram(
        &self,
        _: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

/// DES-NATIVE-HOOKS-PARITY r3 §C: a pool walk's counters are bound with the walk, and the stage
/// reconcile moves them. `busbar_route_policy_selections_total` counts the deciding name (the
/// strategy word of a bound strategy, else the hook name) when an order is installed;
/// `busbar_route_policy_rejections_total` counts a VERB_REJECT at the client refusal's status.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_policy_selections_and_rejections_counters_move() {
    use crate::config::{PromptAccess, UserAccess};
    use crate::plane_driver::hooks::{CandidateFacts, Candidates, Constraint};
    use crate::plane_driver::port_hooks::tests::{configured, Fixture};
    use crate::plane_driver::port_hooks::{
        Binder, Call, Invocation, RouteCounters, Selected, Selection,
    };
    use crate::plane_driver::port_upstream::Wants;
    use busbar_plugin_abi::kinds::hook::hook as abi;
    use busbar_ports::hook::{HookAnswer, HookCall, HookPort, HookView};
    use busbar_ports::CallCx;

    struct Answers(HookAnswer);
    impl HookPort for Answers {
        fn points(&self) -> u32 {
            1 << abi::POINT_ROUTE
        }
        fn facts(&self) -> u64 {
            0
        }
        fn on<'a>(&'a self, _: CallCx, _: u32, _: &'a HookView<'a>) -> HookCall<'a> {
            HookCall::Done(Ok(self.0.clone()))
        }
    }
    fn answer(verb: u32, order: Vec<u32>, reject_status: Option<u16>) -> HookAnswer {
        HookAnswer {
            verb,
            reject_status,
            order,
            restrict: Vec::new(),
            message: None,
            rewrite: None,
        }
    }
    struct Bound(Selected);
    impl Binder for Bound {
        fn active(&self, _: u32) -> bool {
            true
        }
        fn enforcing(&self, _: u32) -> bool {
            true
        }
        fn select(&self, _: &Selection<'_>) -> Result<Selected, &'static str> {
            Ok(self.0.clone())
        }
    }
    struct Hooked {
        invocation: Invocation,
        context: crate::host_services::InvocationContext,
    }
    impl Effects for Hooked {
        fn hooks(&self) -> Option<&Invocation> {
            Some(&self.invocation)
        }
        fn invocation(&self) -> Option<&crate::host_services::InvocationContext> {
            Some(&self.context)
        }
        fn emit(&self, _: u64, _: &[u8]) {}
    }
    /// The pool walk the hooks see: two members, and the constraint the reconcile installs.
    #[derive(Default)]
    struct Ranked {
        queue: VecDeque<Candidate>,
        constrained: Option<Constraint>,
    }
    impl Members for Ranked {
        fn hook_scope(&mut self, _: &Wants) -> Option<crate::plane_driver::RoutedScope> {
            Some(crate::plane_driver::RoutedScope {
                pool: "pool".into(),
                container: String::new(),
            })
        }
        fn hook_candidates(&mut self, _: &Wants) -> Option<Candidates> {
            Some(Candidates {
                pool: "pool".into(),
                members: (0..2)
                    .map(|idx| CandidateFacts {
                        idx,
                        ..CandidateFacts::default()
                    })
                    .collect(),
            })
        }
        fn hook_lane(&mut self, _: &Wants, index: usize) -> Option<String> {
            Some(format!("lane-{index}"))
        }
        fn hook_constrain(&mut self, _: &Wants, constraint: Constraint) -> bool {
            self.constrained = Some(constraint);
            true
        }
        fn next(&mut self, _: &Wants) -> Option<Candidate> {
            self.queue.pop_front()
        }
        fn declined(&mut self, _: &Candidate) {}
        fn failed(&mut self, _: &Candidate, _: &Failure) {}
        fn served(&mut self, _: &Candidate) {}
    }

    let fixture = Fixture::new();
    let gate_name: Arc<str> = Arc::from("configured-name");
    let preferring = configured(
        Arc::new(Answers(answer(abi::VERB_PREFER, vec![1, 0], None))),
        PromptAccess::No,
        UserAccess::No,
    );
    let rejecting = configured(
        Arc::new(Answers(answer(abi::VERB_REJECT, Vec::new(), Some(409)))),
        PromptAccess::No,
        UserAccess::No,
    );
    let strategy = Arc::new(Call {
        name: Arc::from("ranking-instance"),
        port: Arc::new(Answers(answer(abi::VERB_PREFER, vec![0, 1], None))),
        timeout: std::time::Duration::from_secs(1),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        signals: crate::hooks::RequestedSignals::default(),
        on_error: crate::config::PolicyOnError::Weighted,
        on_empty: crate::config::PolicyOnError::Reject,
        fallbacks: Vec::new(),
        strategy: Some(Arc::from("cheapest")),
    });
    let base = fixture.selected.clone();
    let context = fixture.context.clone();
    let counted = tokio::task::spawn_blocking(move || {
        let counted = Counted::default();
        metrics::with_local_recorder(&counted, || {
            let counters = Arc::new(RouteCounters::bind(
                "pool",
                [&preferring, &rejecting, &strategy],
            ));
            let session = |gates: Vec<Arc<Call>>, policy: Option<Arc<Call>>| {
                let mut selected = base.clone();
                selected.gates = gates.into();
                selected.policy = policy;
                selected.counters = Some(Arc::clone(&counters));
                let effects = Hooked {
                    invocation: Invocation {
                        binder: Arc::new(Bound(selected)),
                        principal: None,
                        identity: None,
                        now_s: 1,
                        classes: Arc::default(),
                        journal: None,
                        unit: UnitKey::new(7),
                    },
                    context: context.clone(),
                };
                let plane = forwarding();
                let store = Store;
                let resolver = Resolver::new(&store, Some([1; 32]));
                let refusals = CoreRefusals::new();
                let books = Log::default();
                let mut walk = Ranked {
                    queue: VecDeque::from([candidate()]),
                    ..Ranked::default()
                };
                let mut far = Far;
                let result = run_session(
                    &plane,
                    &req(),
                    b"{}",
                    Drive {
                        resolver: &resolver,
                        members: Some(&mut walk),
                        send: Some(&mut far),
                        dialect: "openai",
                        refusals: &refusals,
                        effects: &effects,
                        books: &books,
                        carrier: None,
                    },
                );
                (result.map(|_| ()), walk.constrained)
            };

            let (ran, constrained) = session(vec![preferring.clone()], None);
            ran.expect("a gate's order is served");
            let constrained = constrained.expect("the reconcile installs the gate's order");
            assert_eq!(constrained.order, Some(vec![1, 0]));
            assert_eq!(constrained.policy.as_deref(), Some(&*gate_name));

            let (ran, constrained) = session(Vec::new(), Some(strategy.clone()));
            ran.expect("the strategy's order is served");
            let constrained = constrained.expect("the reconcile installs the strategy's order");
            assert_eq!(constrained.order, Some(vec![0, 1]));
            assert_eq!(
                constrained.policy.as_deref(),
                Some("cheapest"),
                "a bound strategy decides under its word, not its instance name"
            );

            match session(vec![rejecting.clone()], None).0 {
                Err(SessionError::HookRefused(refusal)) => assert_eq!(refusal.status, 409),
                other => panic!("{other:?}"),
            }
        });
        counted
    })
    .await
    .unwrap();

    assert_eq!(
        counted.get("busbar_route_policy_selections_total{policy=configured-name,pool=pool}"),
        1,
        "the gate's installed order is one selection"
    );
    assert_eq!(
        counted.get("busbar_route_policy_selections_total{policy=cheapest,pool=pool}"),
        1,
        "the strategy's installed order is one selection under its word"
    );
    assert_eq!(
        counted.get(
            "busbar_route_policy_rejections_total{policy=configured-name,pool=pool,status=409}"
        ),
        1,
        "the gate's VERB_REJECT is one rejection at its status"
    );
    assert_eq!(
        counted.get("busbar_route_policy_selections_total{policy=ranking-instance,pool=pool}"),
        0,
        "a strategy is never counted under its instance name"
    );
}
