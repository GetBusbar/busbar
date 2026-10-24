// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A datagram session's caller leg: its channel messages are the session's pieces, what the plane
//! writes before the channel opens waits for it, and a plane that falls behind its caller ends the
//! session (its pairing closes, the leg with it).

use std::sync::Arc;
use std::time::Instant;

use busbar_core_connector::datagram::Pairing;
use busbar_core_connector::framer::Got;
use busbar_core_connector::udp::{bind, ReadyPort};
use tokio::sync::mpsc;

use super::{lock, CallerLeg, ClaimDoor, ClaimDoors, CALLER_QUEUE};

fn got(stream: u64, bytes: &[u8], fields: bool) -> Got {
    Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        fields,
        text: false,
        reason: None,
        failed: false,
        end: false,
    }
}

fn leg(
    capacity: usize,
) -> (
    Arc<ClaimDoor>,
    Arc<CallerLeg>,
    Arc<Pairing>,
    mpsc::Receiver<Vec<u8>>,
) {
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let (tx, rx) = mpsc::channel(capacity);
    let leg = CallerLeg::new(&door, tx);
    let pairing = Pairing::new(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        door.local(),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    (door, leg, pairing, rx)
}

#[tokio::test]
async fn a_channels_messages_are_the_sessions_pieces_and_early_writes_wait_for_the_channel() {
    let (door, leg, pairing, mut rx) = leg(8);
    let mut doors = ClaimDoors::default();
    doors.insert("dg", Arc::clone(&door));
    assert!(doors.get("dg").is_some() && doors.get("other").is_none());
    let now = Instant::now();
    // Written before the channel opened: held, not lost.
    assert!(leg.write(b"early", true, now));
    assert_eq!(lock(&leg.held).len(), 1);
    leg.take(
        vec![
            got(0, b"description", false),
            got(1, b"label: events\r\n", true),
            got(1, b"{\"type\":\"x\"}", false),
        ],
        now,
    );
    assert_eq!(
        *lock(&leg.channel),
        Some(1),
        "the first channel is the session's"
    );
    assert!(lock(&leg.held).is_empty(), "released onto the channel");
    assert_eq!(rx.recv().await.unwrap(), b"{\"type\":\"x\"}");
    assert!(rx.try_recv().is_err(), "the description is never a piece");
    assert!(!pairing.closed());
}

/// RED: a plane that does not keep up with its caller ends the session: the pairing closes and
/// the caller's queue with it.
#[tokio::test]
async fn a_plane_that_falls_behind_its_caller_ends_the_session() {
    let (_door, leg, pairing, mut rx) = leg(2);
    let now = Instant::now();
    let mut pieces = vec![got(1, b"label: events\r\n", true)];
    pieces.extend((0..3).map(|_| got(1, b"m", false)));
    leg.take(pieces, now);
    assert!(pairing.closed(), "the third message found the queue full");
    assert!(lock(&leg.to_session).is_none());
    assert_eq!(rx.recv().await.unwrap(), b"m");
    assert_eq!(rx.recv().await.unwrap(), b"m");
    assert!(rx.recv().await.is_none(), "the session's caller side ended");
}

/// Up to the caller queue's bound, what the plane writes before the far end opens a channel waits
/// for it and is released onto it once the channel opens; the session stands (THE DESIGN l.758-765:
/// application data waits). The green twin of the test below; RED before the fix: none, it passes
/// before and after.
#[tokio::test]
async fn early_writes_up_to_the_bound_wait_for_the_channel() {
    let (_door, leg, pairing, _rx) = leg(8);
    let now = Instant::now();
    for _ in 0..CALLER_QUEUE {
        assert!(leg.write(b"early", false, now));
    }
    assert_eq!(lock(&leg.held).len(), CALLER_QUEUE);
    assert!(!pairing.closed());
    leg.take(vec![got(1, b"label: events\r\n", true)], now);
    assert!(lock(&leg.held).is_empty(), "released onto the channel");
    assert!(!pairing.closed());
}

/// What the plane writes before the far end opens a channel is held to the same bound as what the
/// caller sends the plane: the write past it is refused and ends the session (its pairing closes,
/// the leg and what it held with it), as a plane that falls behind its caller does; a far end that
/// never opens a channel cannot grow the host's memory for the session's whole life (THE DESIGN
/// l.758-765; l.2221 #38(c): every collection has a ceiling). RED before the fix: the held queue had
/// no bound, so the write past it was accepted and held, the session stood, and a closed leg went
/// on holding writes.
#[tokio::test]
async fn a_plane_that_writes_past_the_bound_before_the_channel_opens_ends_the_session() {
    let (_door, leg, pairing, mut rx) = leg(8);
    let now = Instant::now();
    for _ in 0..CALLER_QUEUE {
        assert!(leg.write(b"early", false, now));
    }
    assert!(
        !leg.write(b"one too many", false, now),
        "the write past the bound is refused"
    );
    assert!(pairing.closed(), "the session ended");
    assert!(lock(&leg.held).is_empty(), "what it held went with it");
    assert!(lock(&leg.to_session).is_none());
    assert!(rx.recv().await.is_none(), "the session's caller side ended");
    assert!(
        !leg.write(b"after", false, now),
        "a closed leg takes no write"
    );
    assert!(lock(&leg.held).is_empty(), "nor holds one");
}

/// A door that states only its facts.
struct Stated(busbar_core_connector::framer::DoorFacts);

impl busbar_core_connector::framer::FramerDoor for Stated {
    fn facts(&self) -> &busbar_core_connector::framer::DoorFacts {
        &self.0
    }
    fn cross(
        &self,
        _call: busbar_core_connector::framer::Call<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        busbar_core_connector::framer::Crossed {
            outcome: busbar_contract::abi::mechanism::call::Outcome::Refused,
            error: None,
        }
    }
}

fn stated(
    name: &'static str,
    datagram: bool,
) -> Arc<dyn busbar_core_connector::framer::FramerDoor> {
    Arc::new(Stated(busbar_core_connector::framer::DoorFacts {
        name: name.into(),
        claims: vec![name],
        role: busbar_contract::abi::transport::ROLE_FRAMER,
        composes_over: Vec::new(),
        ported: false,
        status_rows: Vec::new(),
        duplex: vec![name],
        datagram,
    }))
}

fn need(transport: &str, listen: &str) -> crate::root::loader::boot::InboundBind {
    crate::root::loader::boot::InboundBind {
        owner: crate::root::loader::boot::BindOwner::Need {
            instance: "streams".into(),
            kind: busbar_contract::abi::mechanism::KindCode::Plane,
            need: 0,
        },
        transport: transport.into(),
        at: format!("streams.{transport}"),
        listen: listen.parse().unwrap(),
        tls: None,
        max_conns: 1024,
    }
}

fn framers(scheme: &str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> {
    match scheme {
        "dg" => Some(stated("dg", true)),
        "lp" => Some(stated("lp", false)),
        _ => None,
    }
}

/// Ruling (d): a claim door is bound for every inbound listener whose transport a datagram framer
/// answers, on its `{listen}` address, and for no other listener. RED arms: a wildcard address
/// (no candidate to advertise) and a second door for one claim are refused, naming the setting.
#[tokio::test]
async fn boot_binds_a_claim_door_for_each_datagram_listener_and_no_other() {
    let root = crate::root::loader::boot::InboundBind {
        owner: crate::root::loader::boot::BindOwner::Root,
        transport: String::new(),
        at: "listen".into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: None,
        max_conns: u64::MAX,
    };
    let doors = ClaimDoors::bind(
        &[root, need("lp", "127.0.0.1:0"), need("dg", "127.0.0.1:0")],
        framers,
    )
    .expect("the claim doors bind");
    let dg = doors
        .get("dg")
        .expect("the datagram listener is a claim door");
    assert_eq!(dg.local().ip(), std::net::IpAddr::from([127, 0, 0, 1]));
    assert_ne!(dg.local().port(), 0, "bound");
    assert!(
        doors.get("lp").is_none(),
        "a stream listener is no claim door"
    );
    assert!(
        doors.get("").is_none(),
        "the root's own listener is no claim door"
    );

    let wild = ClaimDoors::bind(&[need("dg", "0.0.0.0:0")], framers).expect_err("a wildcard");
    assert!(wild.contains("streams.dg.listen"), "{wild}");
    let twice = ClaimDoors::bind(
        &[need("dg", "127.0.0.1:0"), need("dg", "127.0.0.1:0")],
        framers,
    )
    .expect_err("one claim, two doors");
    assert!(twice.contains("a second claim door"), "{twice}");
}

/// A datagram session's open answers under the head its plane states on the session's first
/// crossing (ARCHITECT row 132 ruling (a)): the plane's status and its fields, `location` among
/// them, as it stated them.
#[tokio::test]
async fn the_open_answers_under_the_head_the_plane_states() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let location = (b"location".to_vec(), b"/v1/calls/c_0123abcd".to_vec());
    tx.send((201, vec![location.clone()])).unwrap();
    let head = super::plane_head(rx, std::time::Duration::from_secs(5)).await;
    assert_eq!(head, Some((201, vec![location])));
}

/// RED: a plane that states no head within the open's bound, or whose session ends first, answers
/// nothing: the open is refused, never a bare 201.
#[tokio::test]
async fn a_plane_that_states_no_head_in_time_answers_nothing() {
    let (_held, rx) = tokio::sync::oneshot::channel::<(u32, super::HeadFields)>();
    let started = Instant::now();
    assert_eq!(
        super::plane_head(rx, std::time::Duration::from_millis(50)).await,
        None
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(50));
    let (dropped, rx) = tokio::sync::oneshot::channel::<(u32, super::HeadFields)>();
    drop(dropped);
    assert_eq!(
        super::plane_head(rx, std::time::Duration::from_secs(5)).await,
        None
    );
}

/// The session's caller side opens with one empty piece, before the caller's first message: the
/// plane crosses the session once before the open is answered.
#[tokio::test]
async fn the_caller_side_opens_with_one_empty_piece() {
    use busbar_kernel::plane_driver::SessionCaller;
    let (_door, leg, _pairing, _rx) = leg(8);
    let (to, from) = mpsc::channel(8);
    let (head, _rx) = tokio::sync::oneshot::channel();
    let caller = super::DatagramCaller {
        leg,
        from: tokio::sync::Mutex::new(from),
        head: std::sync::Mutex::new(Some(head)),
        stated: std::sync::atomic::AtomicU32::new(0),
        opened: std::sync::atomic::AtomicBool::new(false),
    };
    to.send(b"{\"type\":\"x\"}".to_vec()).await.unwrap();
    assert_eq!(caller.read().await, Some(Vec::new()), "the open");
    assert_eq!(caller.read().await, Some(b"{\"type\":\"x\"}".to_vec()));
    drop(to);
    assert_eq!(caller.read().await, None);
}
