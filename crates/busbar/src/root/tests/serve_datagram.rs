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

use super::{lock, CallerLeg, ClaimDoor, ClaimDoors};

fn got(stream: u64, bytes: &[u8], fields: bool) -> Got {
    Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        status_class: 0,
        retry_after_secs: None,
        fields,
        text: false,
        reason: None,
        failed: false,
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
