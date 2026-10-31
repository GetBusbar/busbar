// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::abi::auth::POINT_HEAD;
use busbar_contract::abi::host::service::{UnitRef, FLOW_CONTINUE};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_CONTAINS};
use busbar_contract::abi::transport::{CLOSE_NORMAL, SIDE_ACCEPT};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::framer::{
    Established, FramerDoor, Framing, GuestLine, GuestLines, Yielded,
};
use busbar_test_kit::root_door_fixtures::scoped_mux;

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
    ticket: Ticket,
}

#[derive(Default)]
struct Host {
    seen: Mutex<Vec<Seen>>,
    pending: Mutex<HashMap<u64, AuthDone>>,
    ended: Mutex<Vec<u64>>,
}

fn answer(stream: u64) -> AuthCallAnswer {
    AuthCallAnswer {
        flow: FLOW_CONTINUE,
        unit: UnitRef {
            id: 1000 + stream,
            mac: 1,
        },
        strips: Vec::new(),
    }
}

impl Host {
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
        let (slot, generation) = ask
            .request
            .target
            .strip_prefix("/tickets/")
            .and_then(|s| s.split_once('/'))
            .expect("fixture exposes its operation ticket");
        let ticket = Ticket {
            slot: slot.parse().unwrap(),
            generation: generation.parse().unwrap(),
        };
        self.seen.lock().unwrap().push(Seen {
            owner: ask.owner,
            leg: ask.framing,
            conn: ask.conn,
            stream,
            listener: scope.as_ref().map(|s| s.listener()),
            physical: scope.as_ref().map(|s| s.connection()),
            ticket,
        });
        if matches!(stream, 1 | 3) {
            self.pending.lock().unwrap().insert(stream, done);
            AuthRan::Pending
        } else {
            AuthRan::Now(Ok(answer(stream)))
        }
    }
    fn hand_in(&self, _: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
        Err("not served by this fixture")
    }
    fn refuse(&self, _: RefuseAsk) -> Result<RefusalBytes, &'static str> {
        Err("not served by this fixture")
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

fn opened() -> (Arc<Dispatched>, Arc<Host>) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let host = Arc::new(Host::default());
    assert!(dispatcher.install_auth_handle(host.clone()));
    let plugin =
        crate::root::test_plugins::linked_transport(scoped_mux::door, bind_on(&dispatcher));
    let door = Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher)
        .expect("the SDK door opens");
    (Arc::new(door), host)
}

fn begin(
    door: Arc<Dispatched>,
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

fn ticket(y: &Yielded, stream: u64) -> Option<Ticket> {
    let bytes = &y.pieces.iter().find(|p| p.stream == stream)?.bytes;
    (bytes.len() == 8).then(|| Ticket {
        slot: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        generation: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
    })
}

#[test]
fn loaded_framing_survives_surplus_ticket_disposal_and_resumes_its_original_stream() {
    let (door, host) = opened();
    let owner = door.instance().unwrap();
    let (mut framing, _) = begin(door.clone(), "").expect("accepted");
    let cleanup = ReleaseAll(host.clone());
    let one = framing.ingest(&[1], false).expect("first stream parks");
    let three = framing.ingest(&[3], false).expect("second stream parks");
    let five = framing.ingest(&[5], false).expect("sibling completes");
    let held_before = host
        .pending
        .lock()
        .unwrap()
        .keys()
        .copied()
        .collect::<Vec<_>>();
    let released_three = host.release(3);
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    let middle = framing.poll_parked(&mut cx);
    let still_held = host.pending.lock().unwrap().contains_key(&1);
    let ended_before = host.ended.lock().unwrap().clone();
    let extra = door
        .framing_side()
        .expect("a side can reuse the retired slot");
    let extra_ticket = extra.ticket();
    drop(extra);
    let ended_after_extra = host.ended.lock().unwrap().clone();
    let released_one = host.release(1);
    let last = framing.poll_parked(&mut cx);
    drop(cleanup);
    framing.finish(CLOSE_NORMAL);

    assert!(one.pieces.is_empty() && three.pieces.is_empty());
    assert_eq!(held_before.len(), 2);
    assert!(released_three && released_one && still_held);
    assert!(
        ticket(&five, 5).is_some(),
        "the sibling finishes before either pending stream"
    );
    let Poll::Ready(Ok(middle)) = middle else {
        panic!("stream 3 must complete independently");
    };
    let retired = ticket(&middle, 3).expect("stream 3 includes its actual operation ticket");
    assert_eq!(
        extra_ticket.slot, retired.slot,
        "surplus ticket was actually recycled"
    );
    assert_ne!(extra_ticket.generation, retired.generation);
    assert!(ended_before.is_empty() && ended_after_extra.is_empty());
    let Poll::Ready(Ok(last)) = last else {
        panic!("stream 1 must resume");
    };
    let original = ticket(&last, 1).expect("the original pending stream completed");
    assert_ne!(original.slot, retired.slot);
    let seen = host.seen.lock().unwrap();
    assert_eq!(seen.len(), 3, "resumes redeem the original auth call");
    assert_eq!(
        original, seen[0].ticket,
        "the original operation ticket survived its sibling's disposal"
    );
    assert_eq!(retired, seen[1].ticket);
    assert_eq!(ticket(&five, 5), Some(seen[2].ticket));
    assert_eq!(seen.iter().map(|s| s.stream).collect::<Vec<_>>(), [1, 3, 5]);
    for s in seen.iter() {
        assert_eq!(
            (s.owner, s.conn, s.listener),
            (owner, scoped_mux::TOKEN, Some(71))
        );
        assert_eq!((s.leg, s.physical), (seen[0].leg, seen[0].physical));
    }
    assert_eq!(*host.ended.lock().unwrap(), vec![seen[0].leg]);
    assert!(seen[0].physical.is_some_and(|id| id != 0));
}

#[test]
fn a_ready_token_mismatch_still_finishes_the_returned_plugin_resource() {
    let (door, host) = opened();
    let rejected = match begin(door.clone(), "mismatch") {
        Err(_) => true,
        Ok((framing, _)) => {
            framing.finish(CLOSE_NORMAL);
            false
        }
    };
    let (mut observing, _) = begin(door, "").expect("another connection may reuse the local token");
    let report = observing
        .ingest(&[9], false)
        .expect("the fixture reports its last Finish token");
    observing.finish(CLOSE_NORMAL);
    assert!(
        rejected,
        "READY must agree with the provisional service claim"
    );
    assert_eq!(report.pieces.len(), 1);
    assert_eq!(
        report.pieces[0].bytes,
        (scoped_mux::TOKEN + 1).to_le_bytes()
    );
    assert_eq!(host.ended.lock().unwrap().len(), 2);
}
