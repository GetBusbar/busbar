// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The listener pieces that outlive the retired hyper/framed listener: accept backoff and the
//! per-worker connection balancer the native supervisor shares.

#[test]
fn accept_backoff_spins_only_on_per_connection_transients() {
    use std::io::{Error, ErrorKind};
    let mut b = super::AcceptBackoff::new();

    assert_eq!(
        b.next_delay(&Error::from(ErrorKind::ConnectionAborted)),
        None,
        "a per-connection transient must retry immediately"
    );
    assert_eq!(b.next_delay(&Error::from(ErrorKind::Interrupted)), None);

    let emfile = Error::from_raw_os_error(24);
    let first = b.next_delay(&emfile).expect("exhaustion must back off");
    assert_eq!(first, super::AcceptBackoff::FIRST);
    let second = b.next_delay(&emfile).expect("still failing");
    assert!(
        second > first,
        "the backoff must GROW: {first:?} -> {second:?}"
    );
    for _ in 0..20 {
        let d = b.next_delay(&emfile).expect("still failing");
        assert!(d <= super::AcceptBackoff::CAP, "capped at CAP, got {d:?}");
    }
    assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::CAP));

    b.reset();
    assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::FIRST));

    let _ = b.next_delay(&emfile);
    assert_eq!(
        b.next_delay(&Error::from(ErrorKind::ConnectionAborted)),
        None
    );
    assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::FIRST));
}

async fn socket_pair(
    listener: &tokio::net::TcpListener,
) -> (
    tokio::net::TcpStream,
    tokio::net::TcpStream,
    std::net::SocketAddr,
) {
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    (client, server, peer)
}

fn admitted(
    s: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> busbar_core_connector::listen::Admitted {
    busbar_core_connector::listen::Admitted {
        stream: s.into_std().unwrap(),
        peer,
        hold: None,
    }
}

#[tokio::test]
async fn balancer_hands_off_only_past_margin_and_counts_exactly() {
    let mut handles = super::ConnBalancer::build(3);
    let b2 = handles.pop().unwrap();
    let b1 = handles.pop().unwrap();
    let b0 = handles.pop().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

    let (_c1, s1, p1) = socket_pair(&listener).await;
    let kept = b0.try_hand_off(admitted(s1, p1));
    assert!(kept.is_some(), "at equal load the connection stays local");
    let g1 = b0.place_local();

    let (_c2, s2, p2) = socket_pair(&listener).await;
    assert!(b0.try_hand_off(admitted(s2, p2)).is_some());
    let g2 = b0.place_local();

    let (_c3, s3, p3) = socket_pair(&listener).await;
    assert!(
        b0.try_hand_off(admitted(s3, p3)).is_none(),
        "at min+2 the connection must be handed to the least-loaded worker"
    );
    let others: u32 = [&b1, &b2]
        .iter()
        .map(|b| b.counts[b.me].0.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    assert_eq!(others, 1, "exactly one target counted the handoff");

    let target = if b1.counts[b1.me]
        .0
        .load(std::sync::atomic::Ordering::Relaxed)
        == 1
    {
        &b1
    } else {
        &b2
    };
    let g3 = target.adopt();
    drop(g3);
    drop(g2);
    drop(g1);
    let total: u32 = b0
        .counts
        .iter()
        .map(|c| c.0.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    assert_eq!(
        total, 0,
        "all guards dropped — every count must return to zero"
    );

    let mut local_guards = Vec::new();
    for _ in 0..2 {
        let (_c, s, p) = socket_pair(&listener).await;
        assert!(b0.try_hand_off(admitted(s, p)).is_some());
        local_guards.push(b0.place_local());
    }

    let mut fillers = Vec::new();
    loop {
        let (_c, s, p) = socket_pair(&listener).await;
        fillers.push(_c);
        match b0.txs[1].try_send(admitted(s, p)) {
            Ok(()) => continue,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => break,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                panic!("worker 1's channel must remain open for the full-channel fallback")
            }
        }
    }

    b2.counts[b2.me]
        .0
        .store(100, std::sync::atomic::Ordering::Relaxed);
    let before = b1.counts[b1.me]
        .0
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        b0.counts[b0.me]
            .0
            .load(std::sync::atomic::Ordering::Relaxed),
        before + super::REBALANCE_MARGIN,
        "the local guards must keep the handoff threshold reached"
    );
    let (_c, s, p) = socket_pair(&listener).await;
    let kept = b0.try_hand_off(admitted(s, p));
    assert!(
        kept.is_some(),
        "a full target channel must fall back to serving locally, never dropping the connection"
    );
    assert_eq!(
        b1.counts[b1.me]
            .0
            .load(std::sync::atomic::Ordering::Relaxed),
        before,
        "the failed handoff must roll its increment back"
    );
    drop(local_guards);
    assert_eq!(
        b0.counts[b0.me]
            .0
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "releasing the local connections restores this worker's count"
    );
    drop(b1);
}

#[test]
fn recv_side_from_std_failure_releases_the_sender_increment() {
    let mut handles = super::ConnBalancer::build(2);
    let recv = handles.pop().unwrap();
    let _sender = handles.pop().unwrap();
    use std::sync::atomic::Ordering;

    let baseline = recv.counts[recv.me].0.load(Ordering::Relaxed);

    recv.counts[recv.me].0.fetch_add(1, Ordering::Relaxed);
    assert_eq!(recv.counts[recv.me].0.load(Ordering::Relaxed), baseline + 1);

    {
        let _guard = recv.adopt();
    }

    assert_eq!(
        recv.counts[recv.me].0.load(Ordering::Relaxed),
        baseline,
        "a from_std-failure continue must release the sender's increment, not strand it"
    );
}
