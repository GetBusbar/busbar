// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The message session after an upgrade (IF §8.6 MSG and UP_MSG, §12.27; owner decision 18): what the
//! relay hands the plane for each thing either side does, what it writes to each side from the plane's
//! answers, and how it ends. The plane is scripted; the far end, the member walk and the caller's side are
//! fakes that play one shared script, so the order of events is the script's.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use busbar_plugin_abi::plane::{
    ATT_RETRY, CARRIER_WEBSOCKET, FC_SERVER, FROM_CLIENT, FROM_CORE, FROM_UPSTREAM, MSG_BINARY,
    MSG_FIN, MSG_TEXT, P_BINARY, P_CLIENT_GONE, P_END, P_ERROR, P_FIN, P_HEAD, P_TEXT, P_TIMER,
    SRC_REPORTED,
};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::PortError;

use super::{caller_close_code, piece_flags, ClientEvent, ClientMessages, Ending, UpMessage};
use crate::plane_driver::port_session::{
    finish, Calls, ClientSink, Effects, SessionError, Task, ToClient, UpExchange, Violation,
};
use crate::plane_driver::port_upstream::{
    run_attempts, Attempted, Candidate, Chunk, Failure, Members, SendFailed, TargetIdentity,
    UpChunks, UpOpen, UpSend, Wants,
};
use crate::plane_driver::usage::SessionUsage;

const TEXT: u32 = MSG_TEXT | MSG_FIN;
const BINARY: u32 = MSG_BINARY | MSG_FIN;

/// What the plane writes in one answer.
#[derive(Clone)]
enum It {
    Respond(u16),
    Header(&'static str, &'static [u8]),
    Msg(u32, &'static [u8]),
    End,
    Finish,
    Forward,
    UpCarrier(u32),
    UpPath(&'static str),
    UpMsg(u32, &'static [u8]),
    UpBody(&'static [u8]),
    UpEnd,
    WakeAt(u64),
    Usage(&'static str, u64),
    Attempt(u32, u32),
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
            It::Respond(status) => PlaneOut::Respond { status: *status },
            It::Header(name, value) => PlaneOut::Header(name, value),
            It::Msg(flags, bytes) => PlaneOut::Msg {
                flags: *flags,
                bytes,
            },
            It::End => PlaneOut::End,
            It::Finish => PlaneOut::Finish,
            It::Forward => PlaneOut::Forward { stream: true },
            It::UpCarrier(carrier) => PlaneOut::UpCarrier {
                carrier: *carrier,
                outbound: 0,
            },
            It::UpPath(path) => PlaneOut::UpPath(path),
            It::UpMsg(flags, bytes) => PlaneOut::UpMsg {
                flags: *flags,
                bytes,
            },
            It::UpBody(bytes) => PlaneOut::UpBody(bytes),
            It::UpEnd => PlaneOut::UpEnd,
            It::WakeAt(at) => PlaneOut::WakeAt(*at),
            It::Usage(class, amount) => PlaneOut::Usage {
                class,
                amount: *amount,
                scale: 0,
                source: SRC_REPORTED,
            },
            It::Attempt(verdict, class) => PlaneOut::Attempt {
                verdict: *verdict,
                class: *class,
                retry_after_s: 0,
                reason: "the far end refused the upgrade",
            },
        });
    }
}

/// One `piece` the plane was handed: from, exchange, flags, bytes.
type Handed = (u32, u32, u32, Vec<u8>);

#[derive(Default)]
struct Plane {
    upstream: Mutex<VecDeque<Vec<It>>>,
    pieces: Mutex<VecDeque<Vec<It>>>,
    handed: Mutex<Vec<Handed>>,
    /// The `piece` call (counted from 0) that fails, if any.
    fails_at: Option<usize>,
}

impl Plane {
    fn handed(&self) -> Vec<Handed> {
        self.handed.lock().unwrap().clone()
    }
}

fn failed() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

impl Calls for Plane {
    type Session = ();

    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        play(&[It::Forward], sink);
        Ok(())
    }

    fn piece(
        &self,
        _: &mut (),
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let at = {
            let mut handed = self.handed.lock().unwrap();
            handed.push((from, exchange, flags, bytes.to_vec()));
            handed.len() - 1
        };
        if self.fails_at == Some(at) {
            return Err(failed());
        }
        let items = self.pieces.lock().unwrap().pop_front().unwrap_or_default();
        play(&items, sink);
        Ok(())
    }

    fn rewrite(
        &self,
        _: &mut (),
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }

    fn end(&self, _: (), _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Ok(())
    }

    fn probe(&self, _: &TargetIn<'_>, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(failed())
    }

    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(failed())
    }

    fn upstream(
        &self,
        _: &mut (),
        _: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let items = self
            .upstream
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(handshake);
        play(&items, sink);
        Ok(())
    }
}

/// The handshake request of a WebSocket far end, as a plane states it.
fn handshake() -> Vec<It> {
    vec![It::UpCarrier(CARRIER_WEBSOCKET), It::UpPath("/v1/realtime")]
}

/// One thing a side does, in the order the test says.
#[derive(Clone, Debug)]
enum Step {
    Caller(ClientEvent),
    Far(Result<Option<UpMessage>, SendFailed>),
}

/// The one script both fakes play: a side is ready only when the next step is its own.
#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    waiting: Mutex<Vec<Waker>>,
    caller_polls: AtomicUsize,
}

impl Script {
    fn of(steps: Vec<Step>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into()),
            ..Self::default()
        })
    }

    fn take(&self, cx: &mut Context<'_>, caller: bool) -> Poll<Step> {
        let mut steps = self.steps.lock().unwrap();
        let mine = matches!(
            (steps.front(), caller),
            (Some(Step::Caller(_)), true) | (Some(Step::Far(_)), false)
        );
        if !mine {
            self.waiting.lock().unwrap().push(cx.waker().clone());
            return Poll::Pending;
        }
        let step = steps.pop_front().expect("the step just seen");
        for waker in self.waiting.lock().unwrap().drain(..) {
            waker.wake();
        }
        Poll::Ready(step)
    }
}

fn says(flags: u32, bytes: &[u8]) -> Step {
    Step::Caller(ClientEvent::Message {
        flags,
        bytes: bytes.to_vec(),
    })
}

fn answers(flags: u32, bytes: &[u8]) -> Step {
    Step::Far(Ok(Some(UpMessage {
        flags,
        bytes: bytes.to_vec(),
    })))
}

/// The caller's side: the sink the session writes to and the messages it reads.
struct Side {
    script: Arc<Script>,
    items: Mutex<Vec<ToClient>>,
    /// How many items the caller's side takes before it is gone (`None` = all).
    takes: Option<usize>,
    endings: Mutex<Vec<Ending>>,
    /// `false` = the request is not an upgrade: its client side takes no messages.
    upgrade: bool,
}

impl Side {
    fn new(script: &Arc<Script>) -> Self {
        Self {
            script: Arc::clone(script),
            items: Mutex::new(Vec::new()),
            takes: None,
            endings: Mutex::new(Vec::new()),
            upgrade: true,
        }
    }

    fn items(&self) -> Vec<ToClient> {
        self.items.lock().unwrap().clone()
    }
}

impl ClientSink for Side {
    fn poll_items(&self, _: &mut Context<'_>, items: &mut Vec<ToClient>) -> Poll<bool> {
        let mut taken = self.items.lock().unwrap();
        for item in items.drain(..) {
            if self.takes.is_some_and(|takes| taken.len() >= takes) {
                return Poll::Ready(false);
            }
            taken.push(item);
        }
        Poll::Ready(true)
    }

    fn messages(&self) -> Option<&dyn ClientMessages> {
        self.upgrade.then_some(self as &dyn ClientMessages)
    }
}

impl ClientMessages for Side {
    fn poll_message(&self, cx: &mut Context<'_>) -> Poll<ClientEvent> {
        self.script.caller_polls.fetch_add(1, Ordering::SeqCst);
        match self.script.take(cx, true) {
            Poll::Ready(Step::Caller(event)) => Poll::Ready(event),
            Poll::Ready(Step::Far(_)) => unreachable!("the script hands a side only its own step"),
            Poll::Pending => Poll::Pending,
        }
    }

    fn ending(&self, cause: Ending) {
        self.endings.lock().unwrap().push(cause);
    }
}

/// The session's effects: the caller's side, and every usage total the session showed.
struct Fx<'a> {
    side: &'a Side,
    shown: Mutex<Vec<Vec<(String, u64)>>>,
}

impl<'a> Fx<'a> {
    fn new(side: &'a Side) -> Self {
        Self {
            side,
            shown: Mutex::new(Vec::new()),
        }
    }

    fn last_shown(&self) -> Vec<(String, u64)> {
        self.shown
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

fn totals(usage: &SessionUsage) -> Vec<(String, u64)> {
    let mut totals: Vec<(String, u64)> = usage
        .last()
        .iter()
        .map(|kept| (kept.class.to_string(), kept.amount))
        .collect();
    totals.sort();
    totals
}

impl Effects for Fx<'_> {
    fn emit(&self, _: u64, _: &[u8]) {}

    fn client(&self) -> Option<&dyn ClientSink> {
        Some(self.side)
    }

    fn observed_usage(&self, usage: &SessionUsage) {
        self.shown.lock().unwrap().push(totals(usage));
    }
}

/// What the far end was written and how often the engine closed it.
#[derive(Default)]
struct Wire {
    written: Mutex<Vec<(u32, Vec<u8>)>>,
    closed: AtomicUsize,
    /// How many messages the far end takes before a write fails (`None` = all).
    takes: Option<usize>,
    /// The code the far end closed with, where its failure is its own close with a code.
    close_code: Option<u32>,
}

impl Wire {
    fn written(&self) -> Vec<(u32, Vec<u8>)> {
        self.written.lock().unwrap().clone()
    }
}

/// The rest of one far end's answer.
struct Rest {
    script: Arc<Script>,
    wire: Arc<Wire>,
    queued: Vec<(u32, Vec<u8>)>,
}

impl UpChunks for Rest {
    async fn next(&mut self) -> Result<Option<Chunk>, SendFailed> {
        Ok(None)
    }

    async fn next_message(&mut self) -> Result<Option<UpMessage>, SendFailed> {
        let script = Arc::clone(&self.script);
        match std::future::poll_fn(|cx| script.take(cx, false)).await {
            Step::Far(event) => event,
            Step::Caller(_) => unreachable!("the script hands a side only its own step"),
        }
    }

    async fn write_message(&mut self, flags: u32, bytes: Vec<u8>) -> bool {
        let mut written = self.wire.written.lock().unwrap();
        if self.wire.takes.is_some_and(|takes| written.len() >= takes) {
            return false;
        }
        written.push((flags, bytes));
        true
    }

    async fn close(&mut self) {
        self.wire.closed.fetch_add(1, Ordering::SeqCst);
    }

    fn take_queued(&mut self) -> Vec<(u32, Vec<u8>)> {
        std::mem::take(&mut self.queued)
    }

    fn close_code(&self) -> Option<u32> {
        self.wire.close_code
    }
}

/// The carrier: each open answers the next status of `answers` (or fails), and keeps what it was sent.
struct Far {
    script: Arc<Script>,
    wire: Arc<Wire>,
    answers: VecDeque<Result<u16, SendFailed>>,
    sent: Vec<(String, u32, String)>,
}

impl Far {
    fn new(script: &Arc<Script>, answers: Vec<Result<u16, SendFailed>>) -> Self {
        Self {
            script: Arc::clone(script),
            wire: Arc::new(Wire::default()),
            answers: answers.into(),
            sent: Vec::new(),
        }
    }
}

impl UpSend for Far {
    type Rest<'a> = Rest;

    async fn open<'a>(
        &'a mut self,
        member: &'a Candidate,
        mut exchange: UpExchange,
    ) -> Result<UpOpen<Rest>, SendFailed> {
        self.sent.push((
            member.upstream.to_string(),
            exchange.carrier,
            exchange.path.as_deref().unwrap_or_default().to_owned(),
        ));
        let status = self.answers.pop_front().unwrap_or(Err(SendFailed))?;
        Ok(UpOpen {
            status,
            headers: vec![(b"sec-websocket-protocol".to_vec(), b"realtime".to_vec())],
            rest: Rest {
                script: Arc::clone(&self.script),
                wire: Arc::clone(&self.wire),
                // As the egress carrier does: messages beside the handshake head wait for the 101.
                queued: std::mem::take(&mut exchange.msgs),
            },
        })
    }
}

#[derive(Default)]
struct Walk {
    queue: VecDeque<Candidate>,
    failed: Vec<(String, u32)>,
    served: Vec<String>,
}

impl Members for Walk {
    async fn next(&mut self, _: &Wants) -> Option<Candidate> {
        self.queue.pop_front()
    }

    fn declined(&mut self, _: &Candidate) {}

    fn failed(&mut self, member: &Candidate, failure: &Failure) {
        self.failed
            .push((member.upstream.to_string(), failure.verdict));
    }

    fn served(&mut self, member: &Candidate) {
        self.served.push(member.upstream.to_string());
    }
}

fn walk(names: &[&str]) -> Walk {
    Walk {
        queue: names
            .iter()
            .map(|name| Candidate {
                pool: "pool".into(),
                qualified_member: "fixture-member".into(),
                identity: TargetIdentity::Registration,
                resource: None,
                upstream: (*name).into(),
                provider: "{}".into(),
                base_path: "/v1".into(),
                flags: 0,
                params: Vec::new(),
            })
            .collect(),
        ..Walk::default()
    }
}

fn req() -> PlaneIn<'static> {
    PlaneIn {
        route: 1,
        flags: 0,
        auth: 1,
        method: "GET",
        path: "/v1/realtime",
        query: "",
        headers: &[],
        identity: &[],
        request_id: 1,
        carrier: 0,
        work: "",
        ticket_record: &[],
    }
}

fn pieces(plane: &Plane, answers: Vec<Vec<It>>) {
    *plane.pieces.lock().unwrap() = answers.into();
}

/// One upgrade session over one member that answers 101, driven to the end of its attempt walk.
struct Session {
    plane: Plane,
    script: Arc<Script>,
}

struct Ran {
    result: Result<Attempted, SessionError>,
    plane: Plane,
    side_items: Vec<ToClient>,
    endings: Vec<Ending>,
    wire: Arc<Wire>,
    usage: Vec<(String, u64)>,
    last_shown: Vec<(String, u64)>,
    caller_polls: usize,
}

impl Session {
    fn new(steps: Vec<Step>, answers: Vec<Vec<It>>) -> Self {
        let plane = Plane::default();
        pieces(&plane, answers);
        Self {
            plane,
            script: Script::of(steps),
        }
    }

    fn run(self) -> Ran {
        self.run_with(|_| {}, |_| {})
    }

    fn run_with(self, side: impl FnOnce(&mut Side), wire: impl FnOnce(&mut Wire)) -> Ran {
        let Self { plane, script } = self;
        let mut caller = Side::new(&script);
        side(&mut caller);
        let mut far = Far::new(&script, vec![Ok(101)]);
        let mut shaped = Wire::default();
        wire(&mut shaped);
        far.wire = Arc::new(shaped);
        let wire = Arc::clone(&far.wire);
        let fx = Fx::new(&caller);
        let mut members = walk(&["a"]);
        let (result, usage) = {
            let (mut task, _first) = Task::begin(&plane, &req(), b"", &fx).unwrap();
            let result = finish(run_attempts(
                &mut task,
                &Wants::default(),
                "realtime",
                "model",
                &mut members,
                &mut far,
                &fx,
            ));
            (result, totals(task.usage()))
        };
        let last_shown = fx.last_shown();
        let endings = caller.endings.lock().unwrap().clone();
        Ran {
            result,
            side_items: caller.items(),
            endings,
            wire,
            usage,
            last_shown,
            caller_polls: script.caller_polls.load(Ordering::SeqCst),
            plane,
        }
    }
}

fn commit() -> Vec<It> {
    vec![
        It::Respond(101),
        It::Header("sec-websocket-protocol", b"realtime"),
    ]
}

fn over() -> Vec<It> {
    vec![It::UpEnd, It::End, It::Finish]
}

fn client_view(items: &[ToClient]) -> Vec<String> {
    items
        .iter()
        .map(|item| match item {
            ToClient::Head { status, .. } => format!("head {status}"),
            ToClient::Msg { flags, bytes } => {
                format!("msg {flags} {}", String::from_utf8_lossy(bytes))
            }
            ToClient::End => "end".to_owned(),
            other => format!("{other:?}"),
        })
        .collect()
}

#[test]
fn a_text_and_a_binary_message_are_relayed_each_way_through_the_plane() {
    let ran = Session::new(
        vec![
            says(TEXT, b"hi"),
            answers(TEXT, b"yo"),
            says(BINARY, &[1, 2]),
            answers(BINARY, &[3, 4]),
            Step::Caller(ClientEvent::Closed),
        ],
        vec![
            [commit(), vec![It::UpMsg(TEXT, b"lock")]].concat(),
            vec![It::UpMsg(TEXT, b"hi")],
            vec![It::Msg(TEXT, b"yo")],
            vec![It::UpMsg(BINARY, &[1, 2])],
            vec![It::Msg(BINARY, &[3, 4])],
            over(),
        ],
    )
    .run();
    assert!(
        matches!(&ran.result, Ok(Attempted::Served { member, attempts: 1, .. }) if &**member == "a"),
        "{:?}",
        ran.result
    );
    let handed = ran.plane.handed();
    assert_eq!(handed[0].0, FROM_UPSTREAM);
    assert_eq!(handed[0].2, P_HEAD, "the far end's 101 is its head");
    assert_eq!(
        handed[1..],
        [
            (FROM_CLIENT, 0, P_TEXT | P_FIN, b"hi".to_vec()),
            (FROM_UPSTREAM, 0, P_TEXT | P_FIN, b"yo".to_vec()),
            (FROM_CLIENT, 0, P_BINARY | P_FIN, vec![1, 2]),
            (FROM_UPSTREAM, 0, P_BINARY | P_FIN, vec![3, 4]),
            (FROM_CLIENT, 0, P_END, Vec::new()),
        ]
    );
    assert_eq!(
        ran.wire.written(),
        [
            (TEXT, b"lock".to_vec()),
            (TEXT, b"hi".to_vec()),
            (BINARY, vec![1, 2]),
        ],
        "the far end is written only what the plane wrote for it, in its order"
    );
    assert_eq!(
        client_view(&ran.side_items),
        [
            "head 101".to_owned(),
            format!("msg {TEXT} yo"),
            format!("msg {BINARY} \u{3}\u{4}"),
            "end".to_owned(),
        ]
    );
    assert_eq!(
        ran.wire.closed.load(Ordering::SeqCst),
        1,
        "the engine closes the far end once"
    );
    assert!(ran.endings.is_empty(), "an orderly end states no cause");
}

#[test]
fn the_101_carries_the_planes_own_pairs() {
    let ran = Session::new(
        vec![Step::Caller(ClientEvent::Closed)],
        vec![commit(), over()],
    )
    .run();
    let Some(ToClient::Head { status, fields }) = ran.side_items.first() else {
        panic!("no head: {:?}", ran.side_items);
    };
    assert_eq!(*status, 101);
    assert_eq!(
        fields,
        &vec![(b"sec-websocket-protocol".to_vec(), b"realtime".to_vec())],
        "the subprotocol the plane chose is what the caller is answered"
    );
}

#[test]
fn a_far_end_that_refuses_the_handshake_is_answered_before_any_101() {
    let script = Script::of(Vec::new());
    let plane = Plane::default();
    // The first member answers 503: the plane fails the attempt. The second cannot be reached.
    pieces(&plane, vec![vec![It::Attempt(ATT_RETRY, FC_SERVER)]]);
    let caller = Side::new(&script);
    let fx = Fx::new(&caller);
    let mut far = Far::new(&script, vec![Ok(503), Err(SendFailed)]);
    let mut members = walk(&["a", "b"]);
    let (mut task, _first) = Task::begin(&plane, &req(), b"", &fx).unwrap();
    let result = finish(run_attempts(
        &mut task,
        &Wants::default(),
        "realtime",
        "model",
        &mut members,
        &mut far,
        &fx,
    ));
    assert!(
        matches!(result, Ok(Attempted::Exhausted { attempts: 2, .. })),
        "{result:?}"
    );
    assert_eq!(
        far.sent,
        [
            ("a".to_owned(), CARRIER_WEBSOCKET, "/v1/realtime".to_owned()),
            ("b".to_owned(), CARRIER_WEBSOCKET, "/v1/realtime".to_owned()),
        ]
    );
    assert_eq!(members.failed.len(), 2);
    assert!(members.served.is_empty());
    assert!(
        caller.items().is_empty(),
        "nothing reaches the caller before a member accepted: no 101, so the answer is still HTTP's"
    );
    assert_eq!(
        script.caller_polls.load(Ordering::SeqCst),
        0,
        "the caller's side is not read before the 101"
    );
    assert!(far.wire.written().is_empty(), "no message before a 101");
}

#[test]
fn the_far_ends_close_ends_the_session_and_the_caller_is_closed_in_order() {
    let ran = Session::new(
        vec![answers(TEXT, b"bye"), Step::Far(Ok(None))],
        vec![
            commit(),
            vec![It::Msg(TEXT, b"bye")],
            vec![It::End, It::Finish],
        ],
    )
    .run();
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(
        ran.plane.handed().last(),
        Some(&(FROM_UPSTREAM, 0, P_END, Vec::new()))
    );
    assert_eq!(
        client_view(&ran.side_items),
        [
            "head 101".to_owned(),
            format!("msg {TEXT} bye"),
            "end".to_owned()
        ]
    );
    assert_eq!(
        ran.wire.closed.load(Ordering::SeqCst),
        0,
        "a far end that closed is not closed again"
    );
    assert!(ran.endings.is_empty());
}

#[test]
fn a_caller_that_drops_ends_the_session_and_what_the_plane_stated_is_what_settles() {
    let ran = Session::new(
        vec![says(TEXT, b"a"), Step::Caller(ClientEvent::Gone)],
        vec![
            [commit(), vec![It::Usage("requests", 1)]].concat(),
            vec![It::UpMsg(TEXT, b"a"), It::Usage("text_tokens_in", 7)],
            [vec![It::Usage("text_tokens_in", 9)], over()].concat(),
        ],
    )
    .run();
    assert!(
        matches!(&ran.result, Ok(Attempted::Served { .. })),
        "a dropped caller is an end of the session, not a failure of the walk: {:?}",
        ran.result
    );
    assert_eq!(
        ran.plane.handed().last(),
        Some(&(FROM_CORE, 0, P_CLIENT_GONE, Vec::new())),
        "the plane is told the caller went away, so it can state its final total"
    );
    let stated = vec![("requests".to_owned(), 1), ("text_tokens_in".to_owned(), 9)];
    assert_eq!(
        ran.usage, stated,
        "the session's usage is its running total"
    );
    assert_eq!(
        ran.last_shown, stated,
        "the total a cut unit settles on is the one the session showed last"
    );
    assert_eq!(
        ran.wire.closed.load(Ordering::SeqCst),
        1,
        "the far end is let go"
    );
    assert_eq!(
        client_view(&ran.side_items),
        ["head 101"],
        "nothing is handed to a caller that is gone"
    );
}

#[test]
fn a_callers_side_that_takes_nothing_more_is_a_caller_that_went_away() {
    let ran = Session::new(
        vec![answers(TEXT, b"x")],
        vec![commit(), vec![It::Msg(TEXT, b"x")], vec![It::Finish]],
    )
    // The caller's side takes the 101 and then nothing.
    .run_with(|side| side.takes = Some(1), |_| {});
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    let handed = ran.plane.handed();
    assert_eq!(
        handed
            .iter()
            .filter(|piece| piece.2 == P_CLIENT_GONE)
            .count(),
        1,
        "the plane is told once: {handed:?}"
    );
    assert_eq!(ran.wire.closed.load(Ordering::SeqCst), 1);
}

#[test]
fn a_far_end_that_fails_mid_session_is_told_to_the_plane_and_to_the_callers_close() {
    let ran = Session::new(
        vec![Step::Far(Err(SendFailed))],
        vec![commit(), vec![It::End, It::Finish]],
    )
    .run();
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    let handed = ran.plane.handed();
    let (from, exchange, flags, bytes) = handed.last().unwrap();
    assert_eq!((*from, *exchange, *flags), (FROM_UPSTREAM, 0, P_ERROR));
    assert!(
        String::from_utf8_lossy(bytes).contains("the upstream failed"),
        "one REFUSAL names the failure"
    );
    assert_eq!(
        ran.endings,
        [Ending::UpstreamFailed],
        "the caller's close is not the orderly one"
    );
    assert_eq!(client_view(&ran.side_items), ["head 101", "end"]);
}

#[test]
fn a_far_end_that_takes_no_more_messages_has_failed() {
    let ran = Session::new(
        vec![says(TEXT, b"a")],
        vec![
            commit(),
            vec![It::UpMsg(TEXT, b"a")],
            vec![It::End, It::Finish],
        ],
    )
    .run_with(|_| {}, |wire| wire.takes = Some(0));
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(ran.plane.handed().last().unwrap().2, P_ERROR);
    assert_eq!(ran.endings, [Ending::UpstreamFailed]);
    assert!(ran.wire.written().is_empty());
}

#[test]
fn the_planes_wake_time_is_answered_with_a_timer_piece() {
    // A wake time already passed: the session's ceiling.
    let ran = Session::new(
        Vec::new(),
        vec![[commit(), vec![It::WakeAt(0)]].concat(), over()],
    )
    .run();
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(
        ran.plane.handed().last(),
        Some(&(FROM_CORE, 0, P_TIMER, Vec::new()))
    );
    assert_eq!(client_view(&ran.side_items), ["head 101", "end"]);
    assert_eq!(ran.wire.closed.load(Ordering::SeqCst), 1);
}

#[test]
fn a_body_on_the_message_exchange_is_the_planes_breach() {
    let ran = Session::new(
        vec![says(TEXT, b"a")],
        vec![commit(), vec![It::UpBody(b"not a message")]],
    )
    .run();
    assert!(
        matches!(
            ran.result,
            Err(SessionError::Violation(Violation::BadRecords))
        ),
        "{:?}",
        ran.result
    );
    assert_eq!(
        ran.wire.closed.load(Ordering::SeqCst),
        1,
        "the far end is let go on the error path too"
    );
    assert!(ran.wire.written().is_empty());
}

#[test]
fn a_plane_call_that_fails_mid_session_ends_it_and_lets_the_far_end_go() {
    let mut session = Session::new(
        vec![says(TEXT, b"a"), says(TEXT, b"b")],
        vec![
            [commit(), vec![It::Usage("requests", 1)]].concat(),
            vec![It::UpMsg(TEXT, b"a"), It::Usage("text_tokens_in", 4)],
        ],
    );
    // The head is call 0, the first message call 1; the second message's call fails.
    session.plane.fails_at = Some(2);
    let ran = session.run();
    assert!(
        matches!(ran.result, Err(SessionError::Port(_))),
        "{:?}",
        ran.result
    );
    assert_eq!(ran.wire.closed.load(Ordering::SeqCst), 1);
    assert_eq!(
        ran.last_shown,
        [("requests".to_owned(), 1), ("text_tokens_in".to_owned(), 4)],
        "what was stated before the failure is still what the unit settles on"
    );
}

#[test]
fn messages_the_upstream_answer_wrote_wait_for_the_101_and_go_first() {
    let session = Session::new(
        vec![Step::Far(Ok(None))],
        vec![
            [commit(), vec![It::UpMsg(TEXT, b"lock")]].concat(),
            vec![It::End, It::Finish],
        ],
    );
    *session.plane.upstream.lock().unwrap() =
        vec![[handshake(), vec![It::UpMsg(TEXT, b"early")]].concat()].into();
    let ran = session.run();
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(
        ran.wire.written(),
        [(TEXT, b"early".to_vec()), (TEXT, b"lock".to_vec())]
    );
}

#[test]
fn a_message_for_the_far_end_in_pieces_is_written_whole() {
    let ran = Session::new(
        vec![says(TEXT, b"abcd"), Step::Caller(ClientEvent::Closed)],
        vec![
            commit(),
            vec![It::UpMsg(MSG_TEXT, b"ab"), It::UpMsg(TEXT, b"cd")],
            over(),
        ],
    )
    .run();
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(ran.wire.written(), [(TEXT, b"abcd".to_vec())]);
}

#[test]
fn a_request_that_is_not_an_upgrade_is_never_relayed() {
    // The same plane and far end, on a client side that takes no messages (any request but an upgrade).
    let ran = Session::new(Vec::new(), vec![commit(), vec![It::End]])
        .run_with(|side| side.upgrade = false, |_| {});
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(ran.caller_polls, 0, "no message is read from the caller");
    let handed = ran.plane.handed();
    assert_eq!(
        handed.iter().map(|piece| piece.2).collect::<Vec<_>>(),
        [P_HEAD, P_END],
        "the reply is fed as a reply: its head and its end"
    );
    assert!(ran.wire.written().is_empty());
}

#[test]
fn the_piece_flags_are_the_transports_message_flags() {
    assert_eq!(piece_flags(MSG_TEXT | MSG_FIN), P_TEXT | P_FIN);
    assert_eq!(piece_flags(MSG_BINARY | MSG_FIN), P_BINARY | P_FIN);
    assert_eq!(piece_flags(MSG_TEXT), P_TEXT);
    assert_eq!(piece_flags(MSG_BINARY), P_BINARY);
    assert_eq!(
        piece_flags(MSG_FIN),
        P_BINARY | P_FIN,
        "a piece that states no kind is bytes, and still a message"
    );
}

/// A committed session whose far end ends failed, having closed with `code` (`None` = with none).
fn closed_with(code: Option<u32>) -> Ran {
    Session::new(
        vec![Step::Far(Err(SendFailed))],
        vec![commit(), vec![It::End, It::Finish]],
    )
    .run_with(|_| {}, |wire| wire.close_code = code)
}

#[test]
fn a_text_message_of_the_far_end_reaches_the_caller_as_text_and_a_binary_one_as_binary() {
    let ran = Session::new(
        vec![
            answers(TEXT, b"words"),
            answers(BINARY, &[0, 255]),
            answers(MSG_TEXT, b"wo"),
            answers(TEXT, b"rds"),
            Step::Far(Ok(None)),
        ],
        vec![
            commit(),
            vec![It::Msg(TEXT, b"words")],
            vec![It::Msg(BINARY, &[0, 255])],
            vec![It::Msg(MSG_TEXT, b"wo")],
            vec![It::Msg(TEXT, b"rds")],
            vec![It::End, It::Finish],
        ],
    )
    .run();
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    let from_far: Vec<(u32, Vec<u8>)> = ran
        .plane
        .handed()
        .into_iter()
        .filter(|piece| piece.0 == FROM_UPSTREAM && piece.2 & (P_TEXT | P_BINARY) != 0)
        .map(|piece| (piece.2, piece.3))
        .collect();
    assert_eq!(
        from_far,
        [
            (P_TEXT | P_FIN, b"words".to_vec()),
            (P_BINARY | P_FIN, vec![0, 255]),
            (P_TEXT, b"wo".to_vec()),
            (P_TEXT | P_FIN, b"rds".to_vec()),
        ],
        "the plane is handed each piece as the kind the far end stated, a fragment included"
    );
    let to_caller: Vec<(u32, Vec<u8>)> = ran
        .side_items
        .iter()
        .filter_map(|item| match item {
            ToClient::Msg { flags, bytes } => Some((*flags, bytes.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        to_caller,
        [
            (TEXT, b"words".to_vec()),
            (BINARY, vec![0, 255]),
            (MSG_TEXT, b"wo".to_vec()),
            (TEXT, b"rds".to_vec()),
        ],
        "and the caller is written the kind the plane answered with"
    );
}

#[test]
fn a_far_end_close_code_the_protocol_lets_an_endpoint_send_reaches_the_caller() {
    for code in [1001_u16, 1003, 1008, 1013, 3000, 4000, 4999] {
        let ran = closed_with(Some(u32::from(code)));
        assert!(ran.result.is_ok(), "{:?}", ran.result);
        assert_eq!(
            ran.endings,
            [Ending::UpstreamClosed(code)],
            "the caller's close carries the far end's own code {code}"
        );
        // The plane is told what it is told of every far end that did not end in order.
        assert_eq!(ran.plane.handed().last().unwrap().2, P_ERROR);
    }
}

#[test]
fn a_far_end_close_code_no_endpoint_may_send_does_not_reach_the_caller() {
    // RFC 6455 section 7.4.1: 1005, 1006 and 1015 are never set in a close frame, 1004 is reserved;
    // section 7.4.2: under 1000 is not used, 1016 to 2999 is the protocol's and unassigned, above 4999 is
    // no code. The engine's own stall cut (`RESET_STALLED`) is no wire code either.
    for code in [
        0_u32,
        999,
        1004,
        1005,
        1006,
        1014,
        1015,
        1016,
        2999,
        5000,
        65_536 + 1001,
        0xFFFF_0001,
    ] {
        let ran = closed_with(Some(code));
        assert!(ran.result.is_ok(), "{:?}", ran.result);
        assert_eq!(
            ran.endings,
            [Ending::UpstreamFailed],
            "code {code} is written as the failure's close"
        );
    }
    assert_eq!(closed_with(None).endings, [Ending::UpstreamFailed]);
}

#[test]
fn the_callers_close_code_is_the_far_ends_only_where_an_endpoint_may_send_it() {
    for code in (1000_u16..=1003).chain(1007..=1013).chain(3000..=4999) {
        assert_eq!(caller_close_code(u32::from(code)), Some(code), "{code}");
    }
    for code in (0_u32..1000)
        .chain(1004..=1006)
        .chain(1014..3000)
        .chain(5000..=70_000)
    {
        assert_eq!(caller_close_code(code), None, "{code}");
    }
    assert_eq!(caller_close_code(u32::MAX), None);
}
