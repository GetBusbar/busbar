// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll};

use busbar_contract::abi::auth::POINT_HEAD;
use busbar_contract::abi::host::service::{UnitRef, FLOW_CONTINUE};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_CONTAINS};
use busbar_contract::abi::transport::{CLOSE_NORMAL, SIDE_ACCEPT};
use busbar_contract::framing_scope::FramingScope;
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::carrier::{Carry, Side};
use busbar_core_connector::framer::{
    Call, Crossed, DoorFacts, Established, FramerDoor, Framing, GuestLine, GuestLines, Refused,
    Yielded,
};

use crate::root::doors::{bind_on, Dispatched};
use crate::root::loader::dispatch::auth_handle::{
    self, AuthCallAnswer, AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, RefusalBytes,
    RefuseAsk, UnitSecret,
};
use crate::root::loader::dispatch::{framing_context, DispatchConfig, Dispatcher};

#[derive(Debug)]
struct Seen {
    owner: u64,
    leg: u64,
    conn: u64,
    stream: u64,
    listener: Option<u64>,
    physical: Option<u64>,
    target: String,
}

#[derive(Default)]
struct Host {
    seen: Mutex<Vec<Seen>>,
    pending: Mutex<HashMap<u64, AuthDone>>,
    pending_changed: Condvar,
    ended: Mutex<Vec<u64>>,
    close_seen: Mutex<Vec<(Option<u64>, Option<u64>)>>,
}

fn answer(_stream: u64) -> AuthCallAnswer {
    AuthCallAnswer {
        flow: FLOW_CONTINUE,
        unit: UnitRef::NONE,
        strips: Vec::new(),
    }
}

impl Host {
    fn wait_pending(&self, stream: u64) -> bool {
        let (held, _) = self
            .pending_changed
            .wait_timeout_while(
                self.pending.lock().unwrap(),
                std::time::Duration::from_secs(5),
                |p| !p.contains_key(&stream),
            )
            .unwrap();
        held.contains_key(&stream)
    }
    fn release(&self, stream: u64) -> bool {
        let done = self.pending.lock().unwrap().remove(&stream);
        if let Some(done) = done {
            done(Ok(answer(stream)));
            true
        } else {
            false
        }
    }
}

impl AuthHandleHost for Host {
    fn unit_secret(&self, _: u64, _: u64) -> Option<UnitSecret> {
        None
    }
    fn auth_call(&self, ask: AuthCallAsk, done: AuthDone) -> AuthRan {
        let scope = framing_context::current();
        let stream = ask.stream;
        self.seen.lock().unwrap().push(Seen {
            owner: ask.owner,
            leg: ask.framing,
            conn: ask.conn,
            stream,
            listener: scope.as_ref().map(|s| s.listener()),
            physical: scope.as_ref().map(|s| s.connection()),
            target: ask.request.target.clone(),
        });
        if matches!(stream, 1 | 2) {
            self.pending.lock().unwrap().insert(stream, done);
            self.pending_changed.notify_all();
            AuthRan::Pending
        } else {
            AuthRan::Now(Ok(answer(stream)))
        }
    }
    fn hand_in(&self, ask: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
        let scope = framing_context::current().expect("real HTTP hand-in retains its scope");
        assert_eq!(ask.framing, Some(scope.leg()));
        assert_eq!(ask.owner, scope.owner());
        Ok((FLOW_CONTINUE, ask.unit))
    }
    fn refuse(&self, ask: RefuseAsk) -> Result<RefusalBytes, &'static str> {
        let context = framing_context::current();
        self.close_seen
            .lock()
            .unwrap()
            .push((context.as_ref().map(|c| c.leg()), ask.framing));
        Ok(RefusalBytes {
            status: 404,
            fields: Vec::new(),
            body: Vec::new(),
        })
    }
    fn framing_ended(&self, framing: u64) {
        self.ended.lock().unwrap().push(framing);
    }
}

struct ReleaseAll(Arc<Host>);
impl Drop for ReleaseAll {
    fn drop(&mut self) {
        let pending: Vec<_> = self.0.pending.lock().unwrap().drain().collect();
        for (stream, done) in pending {
            done(Ok(answer(stream)));
        }
    }
}

// This observer preserves the product's inputs, outputs, tickets and contexts.
// Its sole fault injection is the mismatch test's invalid provisional host token.
struct TraceDoor {
    inner: Arc<Dispatched>,
    ingests: Mutex<Vec<(Ticket, bool, usize)>>,
    mismatched_claim: AtomicBool,
    returned: AtomicU64,
    finishes: Mutex<Vec<u64>>,
}
impl FramerDoor for TraceDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn instance(&self) -> Option<u64> {
        self.inner.instance()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }
    fn framing_side(&self) -> Option<Box<dyn Side>> {
        self.inner.framing_side()
    }
    fn framing_context(
        &self,
        listener: u64,
        connection: u64,
    ) -> Result<Option<Arc<dyn FramingScope>>, Refused> {
        self.inner.framing_context(listener, connection)
    }
    fn cancel_scoped(
        &self,
        context: Option<&Arc<dyn FramingScope>>,
        side: &dyn Side,
        call: Carry<'_>,
    ) -> Crossed {
        self.inner.cancel_scoped(context, side, call)
    }
    fn cross_scoped(
        &self,
        context: Option<&Arc<dyn FramingScope>>,
        side: Option<&dyn Side>,
        resume: bool,
        call: Call<'_>,
    ) -> Crossed {
        match call {
            Call::Begin(input, out) => {
                let crossed =
                    self.inner
                        .cross_scoped(context, side, resume, Call::Begin(input, out));
                if crossed.outcome == busbar_contract::abi::mechanism::call::Outcome::Ready {
                    self.returned.store(out.framing, Ordering::SeqCst);
                    if self.mismatched_claim.swap(false, Ordering::SeqCst) {
                        let scope = context.expect("a real HTTP opening has host custody");
                        scope.check(scope.owner(), out.framing + 1, false).expect("the deliberately wrong provisional service token is initially unconfirmed");
                    }
                }
                crossed
            }
            Call::Ingest(input, out) => {
                self.ingests.lock().unwrap().push((
                    side.expect("real operation ticket").ticket(),
                    resume,
                    input.len,
                ));
                self.inner
                    .cross_scoped(context, side, resume, Call::Ingest(input, out))
            }
            Call::Finish(input, out) => {
                let token = input.framing;
                let crossed =
                    self.inner
                        .cross_scoped(context, side, resume, Call::Finish(input, out));
                assert_eq!(
                    crossed.outcome,
                    busbar_contract::abi::mechanism::call::Outcome::Ready,
                    "the actual HTTP product finished its returned resource"
                );
                self.finishes.lock().unwrap().push(token);
                crossed
            }
            call => self.inner.cross_scoped(context, side, resume, call),
        }
    }
}

fn opened() -> (Arc<TraceDoor>, Arc<Host>) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let host = Arc::new(Host::default());
    assert!(dispatcher.install_auth_handle(host.clone()));
    let plugin = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door::door,
        bind_on(&dispatcher),
    );
    let door = Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher)
        .expect("the SDK door opens");
    (
        Arc::new(TraceDoor {
            inner: Arc::new(door),
            ingests: Mutex::new(Vec::new()),
            mismatched_claim: AtomicBool::new(false),
            returned: AtomicU64::new(0),
            finishes: Mutex::new(Vec::new()),
        }),
        host,
    )
}

fn begin(
    door: Arc<TraceDoor>,
    target: &str,
) -> Result<(Framing, Yielded), busbar_core_connector::framer::Refused> {
    let owner = door.instance().expect("actual loaded owner");
    let guests = Arc::new(GuestLines::registered(
        71,
        vec![GuestLine {
            line: 0,
            points: POINT_HEAD,
            auth: auth_handle::mint_auth_ref(owner, auth_handle::generation(), 3)
                .expect("host auth ref"),
            body_limit: 0,
            methods: METHOD_POST,
            path_form: PATH_CONTAINS,
            path: "/".into(),
            fields: Vec::new(),
            rung: 0,
        }],
    ));
    Framing::begin_lent(
        door,
        SIDE_ACCEPT,
        target,
        &Established {
            scheme: Established::scheme_of(false),
            ..Established::default()
        },
        Some(guests),
    )
}

fn settled_stream(
    framing: &mut Framing,
    mut yielded: Yielded,
    stream: u64,
    host: &Host,
) -> Yielded {
    struct ProgressWake {
        generation: Mutex<u64>,
        changed: Condvar,
    }
    impl std::task::Wake for ProgressWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            *self.generation.lock().unwrap() += 1;
            self.changed.notify_all();
        }
    }
    let wake = Arc::new(ProgressWake {
        generation: Mutex::new(0),
        changed: Condvar::new(),
    });
    let waker = std::task::Waker::from(wake.clone());
    let started = std::time::Instant::now();
    let bound = std::time::Duration::from_secs(5);
    let mut cx = Context::from_waker(&waker);
    loop {
        if yielded
            .pieces
            .iter()
            .any(|piece| piece.stream == stream && piece.fields)
        {
            return yielded;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(5),
            "real HTTP stream {stream} did not complete; last yield={yielded:?}; host calls={:?}; pending={:?}",
            *host.seen.lock().unwrap(), host.pending.lock().unwrap().keys().copied().collect::<Vec<_>>());
        let generation = *wake.generation.lock().unwrap();
        match framing.poll_parked(&mut cx) {
            Poll::Ready(Ok(next)) => yielded = next,
            Poll::Ready(Err(error)) => panic!("actual HTTP continuation refused: {error}"),
            Poll::Pending => {
                let _ = wake
                    .changed
                    .wait_timeout_while(
                        wake.generation.lock().unwrap(),
                        bound.saturating_sub(started.elapsed()),
                        |current| *current == generation,
                    )
                    .unwrap();
            }
        }
    }
}

#[test]
fn loaded_http_streams_keep_their_scope_when_a_sibling_ticket_is_disposed() {
    use super::inbound_reload_tests::request;
    let (door, host) = opened();
    let owner = door.instance().unwrap();
    let (mut framing, _) = begin(door.clone(), "").expect("accepted");
    let cleanup = ReleaseAll(host.clone());
    let one = framing
        .ingest(&request(1, "/one", true), false)
        .expect("first stream parks");
    let three = framing
        .ingest(&request(3, "/three", false), false)
        .expect("second stream parks");
    let five = framing
        .ingest(&request(5, "/five", false), false)
        .expect("sibling progresses");
    let five = settled_stream(&mut framing, five, 3, &host);
    assert!(one.pieces.is_empty() && three.pieces.is_empty());
    assert!(
        five.pieces
            .iter()
            .any(|piece| piece.stream == 3 && piece.fields),
        "third HTTP stream yield={five:?}; host calls={:?}; pending={:?}; operations={:?}",
        *host.seen.lock().unwrap(),
        host.pending
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        *door.ingests.lock().unwrap()
    );
    assert_eq!(host.pending.lock().unwrap().len(), 2);
    let original_tickets = door
        .ingests
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, resume, len)| !resume && *len != 0)
        .map(|(ticket, _, _)| *ticket)
        .collect::<Vec<_>>();
    assert_eq!(original_tickets.len(), 3);
    assert!(host.release(2));
    let middle = settled_stream(&mut framing, Yielded::default(), 2, &host);
    assert!(middle
        .pieces
        .iter()
        .any(|piece| piece.stream == 2 && piece.fields));
    assert!(host.pending.lock().unwrap().contains_key(&1));
    let extra = door
        .framing_side()
        .expect("an independent operation ticket");
    let extra_ticket = extra.ticket();
    assert_eq!(
        extra_ticket.slot, original_tickets[1].slot,
        "the completed operation's slot was actually recycled"
    );
    assert_ne!(extra_ticket.generation, original_tickets[1].generation);
    drop(extra);
    assert!(
        host.ended.lock().unwrap().is_empty(),
        "disposing a sibling ticket cannot end the physical framing"
    );
    assert!(host.release(1));
    let last = settled_stream(&mut framing, Yielded::default(), 1, &host);
    assert!(last
        .pieces
        .iter()
        .any(|piece| piece.stream == 1 && piece.fields));
    let resumed = door
        .ingests
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, resume, _)| *resume)
        .map(|(ticket, _, _)| *ticket)
        .collect::<Vec<_>>();
    assert!(resumed.contains(&original_tickets[1]));
    assert!(
        resumed.contains(&original_tickets[0]),
        "the original auth resumes on its exact live operation ticket"
    );
    drop(cleanup);
    framing.finish(CLOSE_NORMAL);
    let seen = host.seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        3,
        "resumes redeem the original auth call exactly once"
    );
    assert_eq!(seen.iter().map(|s| s.stream).collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(
        seen.iter().map(|s| s.target.as_str()).collect::<Vec<_>>(),
        ["/one", "/three", "/five"]
    );
    for s in seen.iter() {
        assert_eq!((s.owner, s.listener), (owner, Some(71)));
        assert_eq!(
            (s.leg, s.conn, s.physical),
            (seen[0].leg, seen[0].conn, seen[0].physical)
        );
    }
    assert_eq!(*host.ended.lock().unwrap(), vec![seen[0].leg]);
    assert!(seen[0].physical.is_some_and(|id| id != 0));
}

#[test]
fn a_ready_token_mismatch_finishes_the_actual_returned_http_resource() {
    let (door, host) = opened();
    door.mismatched_claim.store(true, Ordering::SeqCst);
    assert!(
        begin(door.clone(), "").is_err(),
        "READY must agree with the provisional service token"
    );
    let returned = door.returned.load(Ordering::SeqCst);
    assert_ne!(
        returned, 0,
        "the real HTTP product allocated an actual resource"
    );
    assert_eq!(
        *door.finishes.lock().unwrap(),
        vec![returned],
        "the rejected opening finishes the actual resource returned by the product"
    );
    assert_eq!(host.ended.lock().unwrap().len(), 1);
    let (framing, _) =
        begin(door.clone(), "").expect("the real product still opens an independent connection");
    framing.finish(CLOSE_NORMAL);
    assert_eq!(host.ended.lock().unwrap().len(), 2);
}

#[test]
fn a_worker_resume_and_lifecycle_hop_retain_the_submitted_framing_scope() {
    use crate::root::loader::dispatch::Frame;
    use busbar_contract::abi::host::service::SCHEME_PLAIN;
    use busbar_contract::abi::mechanism::call::{DeadlineClass, InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::door::{abi_str, blank_in, blank_out};
    use busbar_contract::abi::transport::{
        self as t,
        route::{LineEntry, RouteMatch},
    };

    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let host = Arc::new(Host::default());
    let served: Arc<dyn AuthHandleHost> = host.clone();
    assert!(dispatcher.install_auth_handle(served.clone()));
    let plugin = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door::door,
        bind_on(&dispatcher),
    );
    let mut opened_frame = Frame::new(blank_in::<OpenIn>(), blank_out::<OpenOut>());
    assert_eq!(
        plugin.call(life::OPEN, &mut opened_frame).outcome,
        Outcome::Ready
    );
    let owner = plugin.instance().0;
    let context = framing_context::FramingContext::new(owner, 71, 0, Some(Arc::downgrade(&served)))
        .expect("host scope");
    let scope: Arc<dyn busbar_contract::framing_scope::FramingScope> = context.clone();
    let mut route = RouteMatch::EMPTY;
    route.methods = METHOD_POST;
    route.path_form = PATH_CONTAINS;
    route.path = abi_str("/");
    let line = LineEntry {
        line: 0,
        points: POINT_HEAD,
        auth: auth_handle::mint_auth_ref(owner, auth_handle::generation(), 3).unwrap(),
        body_limit: 0,
        route,
    };
    let mut input: t::BeginIn = blank_in();
    input.side = SIDE_ACCEPT;
    input.scheme = SCHEME_PLAIN;
    input.lines = &line;
    input.lines_len = 1;
    let mut opening = Frame::new(input, blank_out::<t::FramerOut>());
    let side = dispatcher.inline_ticket().expect("opening ticket");
    let opened = framing_context::with_context(Some(scope.clone()), || {
        plugin.call_inline(side.ticket(), false, t::slot::BEGIN, &mut opening)
    });
    assert_eq!(opened.outcome, Outcome::Ready);
    context.confirm(opening.out.framing).unwrap();
    drop(side);

    let cleanup = ReleaseAll(host.clone());
    let bytes = Arc::new(super::inbound_reload_tests::request(1, "/worker", true));
    let mut input: t::IngestIn = blank_in();
    input.framing = opening.out.framing;
    input.bytes = bytes.as_ptr();
    input.len = bytes.len();
    let frame = Frame::new(input, blank_out::<t::FramerOut>());
    let ticket = dispatcher.mint(0).expect("worker ticket");
    let reply = framing_context::with_context(Some(scope.clone()), || {
        dispatcher.submit_lent(
            &plugin,
            ticket,
            t::slot::INGEST,
            frame,
            DeadlineClass::Connection,
            0,
            bytes.clone(),
        )
    });
    let caller_scope_restored = framing_context::current().is_none();
    let pending = host.wait_pending(1);
    let released = host.release(1);
    let done = reply.wait(std::time::Duration::from_secs(5));
    drop(cleanup);
    drop(reply);
    dispatcher.recycle(ticket);
    let mut closing = Frame::new(blank_in::<InHead>(), blank_out::<OutHead>());
    let closed = framing_context::with_context(Some(scope), || {
        assert_eq!(framing_context::current().unwrap().leg(), context.leg());
        plugin.call(life::CLOSE, &mut closing)
    });
    context.end();

    assert!(caller_scope_restored && pending && released);
    assert_eq!(done.map(|d| d.outcome), Some(Outcome::Ready));
    assert_eq!(closed.outcome, Outcome::Ready);
    let seen = host.seen.lock().unwrap();
    assert_eq!(seen.iter().map(|s| s.stream).collect::<Vec<_>>(), [1]);
    assert_eq!(
        seen[0].target, "/worker",
        "the actual pending HTTP auth call resumes once"
    );
    assert!(seen.iter().all(|s| s.owner == owner
        && s.leg == context.leg()
        && s.listener == Some(71)
        && s.physical == Some(context.connection())));
    assert!(
        framing_context::current().is_none(),
        "the lifecycle hop restores the caller's scope"
    );
    assert_eq!(*host.ended.lock().unwrap(), vec![context.leg()]);
}
