// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6 CHANNEL, EX_MSG, WAKE_AT, DETACH, SIGNAL (PLANE-CARRIER): the exchange-to-upstream map, and the session
//! loop that keeps a session with a held channel, a wake time or a DETACH alive and delivers what happens to it.
//! The plane is scripted and the channels are fakes whose attachments the test feeds; the session runs on the
//! test's own thread over a runtime handle, as it does on a blocking thread in production.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::plane::{
    CARRIER_STDIO, CH_FRAME_NDJSON, FROM_CORE, FROM_UPSTREAM, MSG_ASK, P_CHANNEL, P_ERROR, P_FIN,
    P_SIGNAL, P_TEXT, P_TIMER,
};
use busbar_plugin_abi::records::Records;
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::PortError;
use tokio::sync::mpsc;

use super::{ExchangeUpstreams, Mapped, PortCarrier};
use crate::channels::link::Link;
use crate::channels::signals::SignalRegistry;
use crate::channels::{Attachment, ChannelMsg, ChannelReq, UpstreamChannels};
use crate::plane_driver::port_intents::{
    Hit, IntentHost, Looked, Namespace, Resolver, WorkOutcome,
};
use crate::plane_driver::port_money::AuditRow;
use crate::plane_driver::port_serve::{run_session, Books, Drive, Ran};
use crate::plane_driver::port_session::{Calls, Effects, SessionError, ToClient};
use crate::plane_driver::port_upstream::{Candidate, Failure, Members, Wants};
use crate::plane_driver::usage::{Ending, SessionUsage};
use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
use crate::refusal::CoreRefusals;
use crate::upstreams::{ProgramPin, StdioCommand, UpstreamDef, UpstreamTls, Upstreams};

const INSTANCE: u64 = 7;

fn def(name: &str) -> Arc<UpstreamDef> {
    Arc::new(UpstreamDef {
        resource: None,
        allow_private: false,
        name: name.into(),
        url: None,
        command: Some(StdioCommand {
            argv: vec!["/bin/member".into()],
            env: Vec::new(),
            cwd: None,
            pin: ProgramPin::Unpinned,
            idle_s: 300,
        }),
        tls: UpstreamTls {
            pin_spki: Vec::new(),
            client_identity: None,
            trust: None,
        },
        auth: None,
    })
}

struct Table(HashMap<String, Arc<UpstreamDef>>);

impl Upstreams for Table {
    fn get(&self, name: &str) -> Option<Arc<UpstreamDef>> {
        self.0.get(name).cloned()
    }
}

fn table(names: &[&str]) -> Arc<Table> {
    Arc::new(Table(
        names.iter().map(|n| ((*n).to_owned(), def(n))).collect(),
    ))
}

fn candidate(name: &str) -> Candidate {
    Candidate {
        pool: "pool".into(),
        qualified_member: "fixture-member".into(),
        identity: crate::plane_driver::port_upstream::TargetIdentity::Registration,
        resource: None,
        upstream: name.into(),
        provider: "{}".into(),
        base_path: "".into(),
        flags: 0,
        params: Vec::new(),
    }
}

#[test]
fn an_exchange_goes_to_the_upstream_it_was_bound_to_else_the_current_target() {
    let map = ExchangeUpstreams::new(table(&["a", "b"]));
    assert!(map.of(1).is_none(), "no target yet");
    map.point("a");
    assert_eq!(&*map.of(1).unwrap().name, "a");
    map.bind(2, "b");
    assert_eq!(&*map.of(2).unwrap().name, "b");
    assert_eq!(
        &*map.of(1).unwrap().name,
        "a",
        "the others follow the current target"
    );
    map.point("missing");
    assert!(
        map.of(1).is_none(),
        "a name the table does not know attaches nothing"
    );
    assert_eq!(&*map.of(2).unwrap().name, "b");
}

#[test]
fn a_forward_that_pins_a_member_names_the_target_before_any_pick() {
    let map = ExchangeUpstreams::new(table(&["a"]));
    map.point_wanted(&Wants::default());
    assert!(map.of(1).is_none(), "no W_UPSTREAM, no target");
    map.point_wanted(&Wants {
        upstream: Some("a".into()),
        ..Wants::default()
    });
    assert_eq!(&*map.of(9).unwrap().name, "a");
}

#[derive(Default)]
struct Picks {
    queue: VecDeque<Candidate>,
    said: Vec<String>,
}

impl Members for Picks {
    fn next(&mut self, _: &Wants) -> Option<Candidate> {
        self.queue.pop_front()
    }
    fn declined(&mut self, member: &Candidate) {
        self.said.push(format!("declined {}", member.upstream));
    }
    fn failed(&mut self, member: &Candidate, _: &Failure) {
        self.said.push(format!("failed {}", member.upstream));
    }
    fn served(&mut self, member: &Candidate) {
        self.said.push(format!("served {}", member.upstream));
    }
}

#[test]
fn the_walks_pick_becomes_exchange_zeros_upstream_and_every_verdict_still_reaches_the_walk() {
    let map = ExchangeUpstreams::new(table(&["a", "b"]));
    let mut picks = Picks {
        queue: VecDeque::from([candidate("a"), candidate("b")]),
        said: Vec::new(),
    };
    let wants = Wants::default();
    {
        let mut mapped = Mapped::new(&mut picks, &map);
        let a = mapped.next(&wants).unwrap();
        assert_eq!(&*map.of(0).unwrap().name, "a");
        mapped.declined(&a);
        let b = mapped.next(&wants).unwrap();
        assert_eq!(&*map.of(0).unwrap().name, "b", "the walk moved on");
        assert_eq!(
            &*map.of(5).unwrap().name,
            "b",
            "and so did the current target"
        );
        mapped.failed(
            &b,
            &Failure {
                verdict: 1,
                class: 0,
                retry_after_s: 0,
            },
        );
        mapped.served(&b);
        assert!(mapped.next(&wants).is_none());
    }
    assert_eq!(
        picks.said,
        ["declined a", "failed b", "served b"],
        "the wrapper passes every verdict through"
    );
}

// ---- the session loop -------------------------------------------------------------------------------------------

#[derive(Clone)]
enum It {
    Respond(u16),
    Body(&'static [u8]),
    End,
    Finish,
    Channel,
    ExMsg(u32, u32, &'static [u8]),
    WakeAt(u64),
    Detach(u64),
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
            It::Respond(status) => PlaneOut::Respond { status: *status },
            It::Body(b) => PlaneOut::Body(b),
            It::End => PlaneOut::End,
            It::Finish => PlaneOut::Finish,
            It::Channel => PlaneOut::Channel {
                exchange: 1,
                carrier: CARRIER_STDIO,
                flags: 0,
                framing: CH_FRAME_NDJSON,
                key: "k",
                head: Records::new(&[]),
            },
            It::ExMsg(exchange, flags, bytes) => PlaneOut::ExMsg {
                exchange: *exchange,
                flags: *flags,
                stream: 0,
                bytes,
            },
            It::WakeAt(ns) => PlaneOut::WakeAt(*ns),
            It::Detach(ttl_s) => PlaneOut::Detach {
                ttl_s: *ttl_s,
                flags: 0,
                key: b"k",
            },
        });
    }
}

struct Live;

#[derive(Default)]
struct Plane {
    request: Vec<It>,
    pieces: Mutex<VecDeque<Vec<It>>>,
    log: Mutex<Vec<(u32, u32, u32, Vec<u8>)>>,
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
        self.log
            .lock()
            .unwrap()
            .push((from, exchange, flags, bytes.to_vec()));
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
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(nope())
    }
}

struct Quiet;

impl Effects for Quiet {
    fn emit(&self, _: u64, _: &[u8]) {}
}

struct NoBooks;

impl Books for NoBooks {
    fn ended(&self, _: Ending, _: &SessionUsage) {}
    fn audit(&self, _: &AuditRow) {}
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

/// Channels whose attachments the test feeds: `preload` is queued on every attach; what the session writes is read
/// back from `writes`; `refuse_writes` closes the writer so a send fails.
#[derive(Default)]
struct FakeChannels {
    budget: Option<crate::channels::budget::InstanceBudget>,
    preload: Mutex<Vec<ChannelMsg>>,
    refuse_writes: bool,
    writes: Mutex<Vec<mpsc::Receiver<crate::channels::protected::GuardedWrite>>>,
    senders: Mutex<Vec<mpsc::Sender<ChannelMsg>>>,
    upstreams: Mutex<Vec<String>>,
    attached: AtomicUsize,
}

impl UpstreamChannels for FakeChannels {
    fn attach<'a>(
        &'a self,
        _: &'a Caller<'_>,
        upstream: &'a UpstreamDef,
        req: ChannelReq<'a>,
    ) -> BoxFut<'a, Result<Attachment, RecordsDenied>> {
        Box::pin(async move {
            self.attached.fetch_add(1, Ordering::SeqCst);
            self.upstreams
                .lock()
                .unwrap()
                .push(upstream.name.to_string());
            let (link, queue) = Link::new(
                false,
                crate::channels::frame::Framing::Ndjson,
                self.budget.as_ref().unwrap().link(),
            );
            let (tx, rx) = mpsc::channel(8);
            for message in self.preload.lock().unwrap().drain(..) {
                tx.try_send(message).ok().unwrap();
            }
            if !self.refuse_writes {
                self.writes.lock().unwrap().push(queue);
            }
            self.senders.lock().unwrap().push(tx);
            Attachment::linked(
                link,
                req.budget.clone(),
                1,
                u64::from(req.exchange),
                true,
                Box::default(),
                rx,
            )
        })
    }
}

struct Rig {
    budget: crate::channels::budget::InstanceBudget,
    rt: tokio::runtime::Runtime,
    channels: Arc<FakeChannels>,
    registry: Arc<SignalRegistry>,
    carrier: PortCarrier,
}

fn rig(mut channels: FakeChannels, upstreams: &[&str]) -> Rig {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let budget = crate::channels::budget::ChannelBudget::new().instance();
    channels.budget = Some(budget.clone());
    let channels = Arc::new(channels);
    let registry = SignalRegistry::new();
    let carrier = PortCarrier::new(
        Arc::clone(&channels) as Arc<dyn UpstreamChannels>,
        table(upstreams),
        Arc::clone(&registry),
        Namespace {
            plugin: "plane-x".into(),
            name: "x".into(),
            instance: INSTANCE,
            slot: 0,
        },
        Arc::new(|| 0),
        rt.handle().clone(),
    );
    Rig {
        budget,
        rt,
        channels,
        registry,
        carrier,
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

/// Runs `plane` as one session on this thread, the carrier aimed at upstream `member`.
fn run(rig: &Rig, plane: &Plane, point: Option<&str>) -> Result<Ran, SessionError> {
    let session = rig.carrier.session_with_budget(Some(rig.budget.unit()));
    if let Some(member) = point {
        session.map.point(member);
    }
    let store = Store;
    let resolver = Resolver::new(&store, Some([1; 32])).with_channels(&session.host);
    let refusals = CoreRefusals::new();
    run_session(
        plane,
        &req(),
        b"{}",
        Drive {
            resolver: &resolver,
            members: None,
            send: None,
            dialect: "x",
            refusals: &refusals,
            effects: &Quiet,
            books: &NoBooks,
            carrier: Some(&session),
        },
    )
}

fn plane(request: Vec<It>, pieces: Vec<Vec<It>>) -> Plane {
    Plane {
        request,
        pieces: Mutex::new(VecDeque::from(pieces)),
        log: Mutex::new(Vec::new()),
    }
}

fn statuses(client: &[ToClient]) -> Vec<String> {
    client
        .iter()
        .map(|item| match item {
            ToClient::Head { status, .. } => format!("head {status}"),
            ToClient::Body(bytes) => format!("body {}", String::from_utf8_lossy(bytes)),
            ToClient::End => "end".to_owned(),
            _ => "other".to_owned(),
        })
        .collect()
}

#[test]
fn a_channel_message_reaches_the_plane_as_a_from_upstream_piece_and_its_write_reaches_the_channel()
{
    let rig = rig(
        FakeChannels {
            preload: Mutex::new(vec![ChannelMsg::Message(b"world".to_vec().into())]),
            ..FakeChannels::default()
        },
        &["member"],
    );
    let plane = plane(
        vec![It::Channel],
        vec![
            // piece 1: the CH_ATTACH; the plane's first message on the channel, a call that expects a reply.
            vec![It::ExMsg(1, MSG_ASK, b"hello")],
            // piece 2: the reply the channel delivered.
            vec![
                It::Respond(200),
                It::Body(b"got world"),
                It::End,
                It::Finish,
            ],
        ],
    );
    let ran = run(&rig, &plane, Some("member")).unwrap();
    let log = plane.log.lock().unwrap().clone();
    assert_eq!(log.len(), 2);
    assert_eq!((log[0].0, log[0].1, log[0].2), (FROM_CORE, 1, P_CHANNEL));
    assert_eq!(
        log[1],
        (FROM_UPSTREAM, 1, P_TEXT | P_FIN, b"world".to_vec()),
        "the message of exchange 1's channel, delivered to the plane"
    );
    assert_eq!(statuses(&ran.client), ["head 200", "body got world", "end"]);
    assert!(ran.finished);
    assert_eq!(
        rig.channels.upstreams.lock().unwrap().clone(),
        ["member"],
        "the CHANNEL attached the current target's upstream"
    );
    let written = rig.channels.writes.lock().unwrap()[0].try_recv().unwrap();
    assert_eq!(
        written.as_bytes(),
        b"hello",
        "the EX_MSG was written to the channel"
    );
}

#[test]
fn a_channel_with_no_target_upstream_is_a_p_error_and_the_session_ends() {
    let rig = rig(FakeChannels::default(), &["member"]);
    let plane = plane(
        vec![It::Channel],
        vec![vec![It::Respond(502), It::End, It::Finish]],
    );
    let ran = run(&rig, &plane, None).unwrap();
    let log = plane.log.lock().unwrap().clone();
    assert_eq!((log[0].0, log[0].1, log[0].2), (FROM_CORE, 1, P_ERROR));
    assert_eq!(rig.channels.attached.load(Ordering::SeqCst), 0);
    assert!(ran.finished);
}

#[test]
fn a_channel_that_ends_is_a_p_error_on_its_exchange_and_the_channel_is_let_go() {
    let rig = rig(
        FakeChannels {
            preload: Mutex::new(vec![ChannelMsg::Ended]),
            ..FakeChannels::default()
        },
        &["member"],
    );
    let plane = plane(
        vec![It::Channel],
        vec![vec![], vec![It::Respond(502), It::End, It::Finish]],
    );
    let ran = run(&rig, &plane, Some("member")).unwrap();
    let log = plane.log.lock().unwrap().clone();
    assert_eq!((log[0].0, log[0].1, log[0].2), (FROM_CORE, 1, P_CHANNEL));
    assert_eq!((log[1].0, log[1].1, log[1].2), (FROM_CORE, 1, P_ERROR));
    assert!(ran.finished);
}

#[test]
fn a_write_the_channel_refuses_ends_it_with_a_p_error_for_the_plane() {
    let rig = rig(
        FakeChannels {
            refuse_writes: true,
            ..FakeChannels::default()
        },
        &["member"],
    );
    let plane = plane(
        vec![It::Channel],
        vec![
            vec![It::ExMsg(1, 0, b"x")],
            vec![It::Respond(502), It::End, It::Finish],
        ],
    );
    let ran = run(&rig, &plane, Some("member")).unwrap();
    let log = plane.log.lock().unwrap().clone();
    assert_eq!((log[1].0, log[1].1, log[1].2), (FROM_CORE, 1, P_ERROR));
    assert!(ran.finished);
}

#[test]
fn an_ex_msg_on_an_exchange_that_holds_nothing_is_dropped_and_the_session_ends_with_its_answer() {
    let rig = rig(FakeChannels::default(), &["member"]);
    // An EX_MSG is an upstream exchange item: it is placed in a piece answer (here the CH_ATTACH's), never in the
    // request answer, where it is out of place.
    let plane = plane(
        vec![It::Channel],
        vec![vec![
            It::Respond(200),
            It::ExMsg(5, 0, b"x"),
            It::End,
            It::Finish,
        ]],
    );
    let started = Instant::now();
    let ran = run(&rig, &plane, Some("member")).unwrap();
    let log = plane.log.lock().unwrap().clone();
    assert_eq!(
        (log.len(), log[0].0, log[0].1, log[0].2),
        (1, FROM_CORE, 1, P_CHANNEL),
        "the dropped message sends the plane nothing more than its attach"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "nothing is held: no wait"
    );
    assert_eq!(statuses(&ran.client), ["head 200", "end"]);
}

#[test]
fn a_wake_time_delivers_p_timer_when_it_passes() {
    let rig = rig(FakeChannels::default(), &[]);
    let plane = plane(
        vec![It::WakeAt(30_000_000)],
        vec![vec![It::Respond(200), It::End, It::Finish]],
    );
    let started = Instant::now();
    let ran = run(&rig, &plane, None).unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(25),
        "waited for the wake time"
    );
    let log = plane.log.lock().unwrap().clone();
    assert_eq!(log, [(FROM_CORE, 0, P_TIMER, Vec::new())]);
    assert!(ran.finished);
    assert_eq!(ran.wake_at, None);
}

#[test]
fn a_detached_session_is_delivered_the_signals_of_its_key_until_finish() {
    let rig = rig(FakeChannels::default(), &[]);
    let plane = plane(
        vec![It::Detach(30)],
        vec![vec![
            It::Respond(200),
            It::Body(b"signalled"),
            It::End,
            It::Finish,
        ]],
    );
    let registry = Arc::clone(&rig.registry);
    let sender = std::thread::spawn(move || {
        let waited = Instant::now();
        while registry.live(INSTANCE, b"k") == 0 {
            assert!(
                waited.elapsed() < Duration::from_secs(5),
                "the session registered"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        crate::channels::SessionSignals::signal(&*registry, INSTANCE, b"k", None, P_SIGNAL, b"k")
    });
    let ran = run(&rig, &plane, None).unwrap();
    assert_eq!(sender.join().unwrap(), 1);
    let log = plane.log.lock().unwrap().clone();
    assert_eq!(log, [(FROM_CORE, 0, P_SIGNAL, b"k".to_vec())]);
    assert!(ran.finished);
    assert_eq!(
        rig.registry.live(INSTANCE, b"k"),
        0,
        "the registration ends with the session"
    );
}

#[test]
fn a_detach_whose_ttl_passed_ends_the_session_without_waiting_for_a_signal() {
    let rig = rig(FakeChannels::default(), &[]);
    let plane = plane(vec![It::Detach(0), It::Respond(200), It::End], vec![]);
    let started = Instant::now();
    let ran = run(&rig, &plane, None).unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!ran.finished);
    assert_eq!(statuses(&ran.client), ["head 200", "end"]);
}
