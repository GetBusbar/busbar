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
use busbar_plugin_loader::ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_plugin_loader::ports::{FactRef, PortError};

use super::{run_session, Books, Drive, LateDoor, TicketGate, UnitBooks};
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
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
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
            It::Audit(action) => PlaneOut::Audit {
                verdict: AUDIT_APPLIED,
                action,
                resource: "r",
            },
        });
    }
}

struct Live;

#[derive(Default)]
struct Plane {
    request: Vec<It>,
    upstream: Mutex<VecDeque<Vec<It>>>,
    pieces: Mutex<VecDeque<Vec<It>>>,
    end: Vec<It>,
    fault_pieces: bool,
    piece_log: Mutex<Vec<(u32, u32, u32, Vec<u8>)>>,
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
}

struct Far;

impl UpSend for Far {
    fn send(
        &mut self,
        _: &Candidate,
        _: &crate::plane_driver::port_session::UpExchange,
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
async fn a_late_door_refuses_every_ticket_until_the_host_key_is_installed() {
    let late = LateDoor::default();
    let door: &dyn TicketDoor = &late;
    // Before the install nothing is a ticket and nothing is admitted: the door fails closed.
    assert!(!door.is_ticket("bbt1.abc"));
    assert!(matches!(
        door.admit("aud", "bbt1.abc", 100).await,
        Err(TicketDenied::Unavailable)
    ));
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
    assert!(late.install(Arc::new(gate)));
    // Every clone of the door is the installed one; the first install stays.
    let clone = late.clone();
    assert!(clone.is_ticket("bbt1.abc"));
    assert!(matches!(
        clone.admit("aud", "bbt1.abc", 100).await,
        Err(TicketDenied::Expired)
    ));
    assert!(!late.install(Arc::new(crate::plane_driver::port_auth::NoTickets)));
}
