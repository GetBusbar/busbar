// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The end of a stream or of a connection retires its own rows and allocates nothing
//! (EXTRACT-IF-SWEEPS S3, S4): no row is collected into a fresh `Vec` and no table is swept.
use super::*;

/// Bytes this thread allocated while `f` ran (zero exactly when `f` made no allocation).
fn allocations_in(f: impl FnOnce()) -> u64 {
    crate::ThreadAllocated::reset();
    f();
    crate::ThreadAllocated::bytes()
}

/// Mint one unit on `stream` of `framing` (a connection id equal to the framing id).
async fn mint(inbound: &Arc<Inbound>, framing: u64, stream: u64) -> UnitRef {
    inbound.grant_stream(OWNER, framing, stream, GEN).unwrap();
    let (sent, received) = tokio::sync::oneshot::channel();
    let answer = inbound.auth_call(
        Call {
            owner: OWNER,
            generation: GEN,
            auth: auth_id(inbound),
            unit: UnitRef::NONE,
            point: POINT_HEAD,
            conn: framing,
            stream,
            framing,
            head: signed_head(),
            body: None,
            deadline: None,
        },
        Box::new(move |answer| {
            let _ = sent.send(answer);
        }),
    );
    let answer = match answer {
        Some(answer) => answer,
        None => received.await.expect("the asynchronous auth call answers"),
    };
    answer.unwrap().unit
}

#[tokio::test]
async fn ending_a_stream_allocates_nothing() {
    let inbound = host(Arc::new(test_mac));
    let mut units = Vec::new();
    for stream in 1..=6 {
        units.push(mint(&inbound, 1, stream).await);
    }
    // The first two ends size the ended-stream set; the measured one fits in it.
    inbound.stream_ended(OWNER, 1, 1);
    inbound.stream_ended(OWNER, 1, 2);
    assert_eq!(inbound.units().len(), 4);
    let spent = allocations_in(|| inbound.stream_ended(OWNER, 1, 3));
    assert_eq!(inbound.units().len(), 3);
    assert!(inbound.unit_secret(OWNER, units[2].id).is_none());
    assert!(inbound.unit_secret(OWNER, units[3].id).is_some());
    assert_eq!(spent, 0, "a stream end must not collect its retired rows");
}

#[tokio::test]
async fn ending_a_framing_allocates_nothing() {
    let inbound = host(Arc::new(test_mac));
    inbound.framing_started(OWNER, LISTENER, 2, GEN).unwrap();
    let mut kept = Vec::new();
    for stream in 1..=3 {
        kept.push(mint(&inbound, 1, stream).await);
    }
    let gone = mint(&inbound, 2, 1).await;
    assert_eq!(inbound.units().len(), 4);
    let spent = allocations_in(|| inbound.framing_ended(2));
    assert_eq!(inbound.units().len(), 3);
    assert!(inbound.unit_secret(OWNER, gone.id).is_none());
    for unit in &kept {
        assert!(inbound.unit_secret(OWNER, unit.id).is_some());
    }
    assert_eq!(inbound.peer_verdicts(), 0);
    assert_eq!(
        spent, 0,
        "a connection end must not collect its retired rows"
    );
    // The other framing still mints and ends normally; the ended one refuses a new grant.
    assert!(inbound.grant_stream(OWNER, 2, 2, GEN).is_err());
    mint(&inbound, 1, 4).await;
    assert_eq!(inbound.units().len(), 4);
}
