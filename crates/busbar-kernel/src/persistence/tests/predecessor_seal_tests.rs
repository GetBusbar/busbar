// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §3.6.2 at kernel level (MR-5): the fence mark written with the permanent fence,
//! the host scan, the one-winner seal row and the mark's `sealed` list (tests 4(c'), 4(d), 4(i),
//! 4(o)), over the store double SHUTDOWN-HANG 8.14 uses.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use busbar_contract::persistence::{control, Mutation};

use super::expired_writers_tests::{
    attach, control_address, node_address, writer_id, Store, EPOCH, OWN,
};
use super::{
    archive_key, host_key, id_key, predecessor_seal::fenced_key, Assignment, BootIdentity,
    FenceMark, ObservedBy, PredecessorFence, PredecessorRetire, SealOutcome, SealRow,
    UndrainedWriter, LEASE_TTL_MS,
};
use crate::persistence::undrained::ledger_test_guard;

const HOST: &str = "seal-host";

/// SEALING-FIX test29: operational failures remain retryable, while identity/corrupt
/// observations are refused immediately instead of being retried thirty times.
#[tokio::test]
async fn predecessor_failures_preserve_transient_and_permanent_classification() {
    let _guard = ledger_test_guard().await;
    use super::RetireError;
    use crate::persistence::facade::AccessError;
    use busbar_contract::persistence::Failure;
    assert!(matches!(
        RetireError::from(AccessError::Overloaded),
        RetireError::Transient(_)
    ));
    assert!(matches!(
        RetireError::from(Failure::Unavailable),
        RetireError::Transient(_)
    ));
    assert!(matches!(
        RetireError::from(AccessError::Corrupt),
        RetireError::Permanent(_)
    ));
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    let dead = writer_id();
    dead_node(&store, dead, 77, 40_000, false);
    assert!(matches!(
        fence
            .retire_predecessor(EPOCH + 1, dead, seen(dead, 77))
            .await,
        Err(RetireError::Permanent(_))
    ));
}

fn assignment(id: u64, writer: [u8; 16]) -> Vec<u8> {
    Assignment {
        id,
        epoch: EPOCH,
        writer,
    }
    .bytes()
}

/// A dead process's node on `HOST`: its open writer, lease row, host (or archive) row and `id:`
/// reservation.
fn dead_node(store: &Store, writer: [u8; 16], id: u64, expires_ms: u64, archive: bool) {
    store.admit(writer);
    store.put_lease(writer, expires_ms);
    let key = if archive {
        archive_key(HOST, id)
    } else {
        host_key(HOST)
    };
    store.put_node_row(&key, assignment(id, writer));
    store.put_node_row(&id_key(id), assignment(id, writer));
}

fn seen(writer: [u8; 16], id: u64) -> UndrainedWriter {
    UndrainedWriter {
        node: Some(id),
        other_nodes: Vec::new(),
        epoch: EPOCH,
        writer,
        host: Some(HOST.into()),
        observed_by: ObservedBy::Successor,
    }
}

async fn fenced(fence: &PredecessorFence, writer: [u8; 16], id: u64) {
    for _ in 0..100 {
        match fence
            .retire_predecessor(EPOCH, writer, seen(writer, id))
            .await
            .unwrap()
        {
            PredecessorRetire::Retired { .. } => return,
            PredecessorRetire::Pending => {}
            PredecessorRetire::Live { retry_at_ms } => {
                panic!("the dead writer is still live until {retry_at_ms}")
            }
        }
    }
    panic!("the fence never settled");
}

fn mark(store: &Store, writer: [u8; 16]) -> Option<FenceMark> {
    store
        .node_row(&fenced_key(EPOCH, writer))
        .map(|bytes| FenceMark::parse(&bytes).expect("the mark decodes"))
}

/// Test 4(c'), decision 193: the permanent fence and the fence mark commit in one compare-and-set,
/// the mark holding the guarded lease row's own `expires_ms` and no sealed node yet; a writer
/// already closed is never re-marked.
#[tokio::test]
async fn the_fence_writes_its_mark_in_the_same_compare_and_set() {
    let _guard = ledger_test_guard().await;
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    let dead = writer_id();
    dead_node(&store, dead, 77, 40_000, false);
    store.now.store(100, Ordering::SeqCst);
    fenced(&fence, dead, 77).await;
    assert_eq!(
        store.control(dead),
        Some(control::Writer {
            retired_through: u64::MAX,
            admitted_through: u64::MAX,
        })
    );
    assert_eq!(
        mark(&store, dead),
        Some(FenceMark {
            lease_expires_ms: 40_000,
            sealed: Vec::new(),
        })
    );
    let candidates = store.fence_candidates();
    let fence_candidate = candidates.last().expect("one fence was sent");
    let puts: Vec<_> = fence_candidate
        .candidate()
        .mutations
        .iter()
        .filter_map(|m| match m {
            Mutation::Put { address, .. } => Some(address.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        puts,
        vec![
            control_address(dead),
            node_address(&fenced_key(EPOCH, dead))
        ],
        "one candidate: the control row and the mark"
    );
    // A second fence finds the writer closed and writes nothing.
    let before = store.fence_candidates().len();
    fenced(&fence, dead, 77).await;
    assert_eq!(store.fence_candidates().len(), before);
}

/// A lost fence reply must replay the complete atomic intent, including shared control
/// cleanup and the predecessor mark. A new process then seals from those durable rows.
#[tokio::test]
async fn fence_mark_and_writer_cleanup_survive_exact_replay_and_restart() {
    let _guard = ledger_test_guard().await;
    use super::expired_writers_tests::{CLOSED, OPEN};
    use busbar_contract::Secret;

    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    let dead = writer_id();
    dead_node(&store, dead, 77, 40_000, false);
    store.now.store(100, Ordering::SeqCst);
    store.lose_fence_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        fence.retire_predecessor(EPOCH, dead, seen(dead, 77)).await,
        Ok(PredecessorRetire::Pending)
    ));
    assert_eq!(
        fence.retained(),
        1,
        "Unknown retains the exact fence intent"
    );
    let first = store.fence_candidates().pop().expect("fence crossed");
    let mut expected = control::writer_put(dead, Some(OPEN), CLOSED).unwrap();
    expected.push(Mutation::Put {
        address: node_address(&fenced_key(EPOCH, dead)),
        value: Secret::new(
            FenceMark {
                lease_expires_ms: 40_000,
                sealed: Vec::new(),
            }
            .bytes(),
        ),
    });
    let body = first.candidate();
    let expected_body = busbar_contract::persistence::Candidate {
        id: body.id,
        codec: body.codec,
        predicates: body
            .predicates
            .iter()
            .map(|predicate| busbar_contract::persistence::Predicate {
                address: predicate.address.clone(),
                expected: match &predicate.expected {
                    busbar_contract::persistence::ExpectedValue::Absent => {
                        busbar_contract::persistence::ExpectedValue::Absent
                    }
                    busbar_contract::persistence::ExpectedValue::Exact(value) => {
                        busbar_contract::persistence::ExpectedValue::Exact(Secret::new(
                            value.expose(&crate::seal::lend()).to_vec(),
                        ))
                    }
                },
            })
            .collect(),
        mutations: expected,
        time: body.time,
        result: Secret::new(body.result.expose(&crate::seal::lend()).to_vec()),
    };
    let expected = busbar_contract::persistence::PreparedCandidate::new(expected_body).unwrap();
    assert_eq!(
        first.fingerprint(),
        expected.fingerprint(),
        "one atomic candidate preserves every shared epoch/slot effect and the mark"
    );
    control::admit(&first).expect("the combined candidate obeys the control contract");
    fenced(&fence, dead, 77).await;
    let sent = store.fence_candidates();
    assert_eq!(sent.len(), 2, "the unknown attempt was replayed once");
    assert_eq!(sent[1].candidate().id, first.candidate().id);
    assert_eq!(sent[1].fingerprint(), first.fingerprint());
    assert_eq!(sent[1].fingerprint(), expected.fingerprint());
    assert_eq!(store.fence_applies(dead), 1);
    assert_eq!(fence.retained(), 0);
    drop(fence);

    let restarted = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    fenced(&restarted, dead, 77).await;
    assert_eq!(store.fence_candidates().len(), 2, "restart never refences");
    let state = restarted.seal_state(77, EPOCH, dead).await.unwrap();
    assert_eq!(store.control(dead), Some(CLOSED));
    assert_eq!(
        state.mark,
        Some(FenceMark {
            lease_expires_ms: 40_000,
            sealed: Vec::new(),
        })
    );
    let row = SealRow {
        sealer: 88,
        outcome: SealOutcome::Clean { through: 12 },
    };
    assert!(restarted
        .seal_node(77, EPOCH, dead, &row, &state, true)
        .await
        .unwrap());
    drop(restarted);

    let after = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    let state = after.seal_state(77, EPOCH, dead).await.unwrap();
    assert_eq!(
        SealRow::parse(state.row.as_deref().expect("durable seal")).unwrap(),
        row
    );
    assert_eq!(state.mark.unwrap().sealed, vec![77]);
}

/// Test 4(d) and G11: exactly one seal row per node. The winner's compare-and-set adds the node to
/// the mark; a second successor holding the state it read before loses and writes nothing.
#[tokio::test]
async fn one_seal_row_wins_and_the_mark_lists_its_node() {
    let _guard = ledger_test_guard().await;
    let store = Store::new();
    let first = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    let second = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    let dead = writer_id();
    dead_node(&store, dead, 77, 40_000, false);
    store.now.store(100, Ordering::SeqCst);
    fenced(&first, dead, 77).await;
    let a = first.seal_state(77, EPOCH, dead).await.unwrap();
    let b = second.seal_state(77, EPOCH, dead).await.unwrap();
    assert!(a.row.is_none() && a.mark.as_ref().is_some_and(|m| m.is_open_for(77)));
    let row = SealRow {
        sealer: 1,
        outcome: SealOutcome::Clean { through: 12 },
    };
    assert!(first
        .seal_node(77, EPOCH, dead, &row, &a, true)
        .await
        .unwrap());
    let other = SealRow {
        sealer: 2,
        outcome: SealOutcome::Clean { through: 12 },
    };
    assert!(
        !second
            .seal_node(77, EPOCH, dead, &other, &b, true)
            .await
            .unwrap(),
        "the second successor loses"
    );
    let after = second.seal_state(77, EPOCH, dead).await.unwrap();
    assert_eq!(
        SealRow::parse(after.row.as_deref().expect("the row")).unwrap(),
        row
    );
    assert_eq!(after.mark.expect("kept").sealed, vec![77]);
}

/// Test 4(o), `one_writer_two_nodes_both_sealed`: one writer owns a host row and an archive row on
/// the host. One fence, one mark; sealing the first node keeps the mark and lists it; the second
/// node's compare-and-set made with the stale mark loses, is redone with the new mark (the outcome
/// unchanged), and the mark lists both. A break over an `unsealed_fenced` node leaves it unchanged.
#[tokio::test]
async fn one_writer_two_nodes_are_both_sealed_under_one_mark() {
    let _guard = ledger_test_guard().await;
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    let dead = writer_id();
    dead_node(&store, dead, 77, 40_000, false);
    dead_node(&store, dead, 78, 40_000, true);
    store.now.store(100, Ordering::SeqCst);
    fenced(&fence, dead, 77).await;
    let x = fence.seal_state(77, EPOCH, dead).await.unwrap();
    let y_stale = fence.seal_state(78, EPOCH, dead).await.unwrap();
    let row = |through| SealRow {
        sealer: 9,
        outcome: SealOutcome::Clean { through },
    };
    assert!(fence
        .seal_node(77, EPOCH, dead, &row(3), &x, true)
        .await
        .unwrap());
    assert!(!fence
        .seal_node(78, EPOCH, dead, &row(4), &y_stale, true)
        .await
        .unwrap());
    let y = fence.seal_state(78, EPOCH, dead).await.unwrap();
    assert!(y.row.is_none() && y.mark.as_ref().is_some_and(|m| m.is_open_for(78)));
    assert!(fence
        .seal_node(78, EPOCH, dead, &row(4), &y, true)
        .await
        .unwrap());
    assert_eq!(mark(&store, dead).unwrap().sealed, vec![77, 78]);

    // The mark is never deleted, and a node it already lists is not open for it.
    let marked = mark(&store, dead).unwrap();
    assert!(!marked.is_open_for(77) && !marked.is_open_for(78));
    assert_eq!(FenceMark::parse(&marked.bytes()).unwrap(), marked);
    assert_eq!(marked.with_sealed(78), marked);
}

/// Test 4(i) and the host scan: the host row and every archive row of this host are listed with
/// their writer lease expiry; a row with no matching `id:` reservation is refused (`assignment`),
/// another host's rows are never read, and the caller's own node is left out.
#[tokio::test]
async fn the_host_scan_lists_reserved_nodes_and_refuses_the_rest() {
    let _guard = ledger_test_guard().await;
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, HOST).unwrap();
    let (w1, w2, w3, w4) = (writer_id(), writer_id(), writer_id(), writer_id());
    dead_node(&store, w1, 71, 10_000, false);
    dead_node(&store, w2, 72, 20_000, true);
    // Fabricated: an archive row with no reservation.
    store.admit(w3);
    store.put_node_row(&archive_key(HOST, 73), assignment(73, w3));
    // The caller's own node.
    dead_node(&store, OWN, 74, 30_000, true);
    // Another host's node.
    store.admit(w4);
    store.put_node_row(&host_key("other-host"), assignment(75, w4));
    store.put_node_row(&id_key(75), assignment(75, w4));
    store.now.store(50, Ordering::SeqCst);
    let listed = fence.host_nodes(74).await.unwrap();
    let mut ids: Vec<(u64, Option<u64>)> = listed
        .nodes
        .iter()
        .map(|n| (n.id, n.lease_expires_ms))
        .collect();
    ids.sort();
    assert_eq!(ids, vec![(71, Some(10_000)), (72, Some(20_000))]);
    assert_eq!(listed.refused.len(), 1);
    assert_eq!(listed.refused[0].id, Some(73));
    assert_eq!(listed.refused[0].reason, "assignment");
    assert_eq!(listed.listed_ms, 50_000);
}

/// §3.6.2 "Dead at start": `take_node` hands back the store clock it read, the bound every
/// predecessor's last renewal is compared against.
#[tokio::test]
async fn take_node_reports_the_store_clock_it_read() {
    let store = Store::new();
    store.now.store(1_234, Ordering::SeqCst);
    let identity = Arc::new(BootIdentity::new(attach(&store, OWN).await).unwrap());
    let taken = identity.take_node(HOST).await.unwrap();
    assert_eq!(taken.taken_at_ms, 1_234_000);
    assert!(taken.taken_at_ms + LEASE_TTL_MS > taken.taken_at_ms);
}

/// The seal row round-trips each outcome and refuses what does not decode (a malformed row is
/// never trusted and never replaced).
#[test]
fn seal_rows_round_trip_and_refuse_garbage() {
    for outcome in [
        SealOutcome::Clean { through: 0 },
        SealOutcome::Clean { through: 99 },
        SealOutcome::Stamp(vec![1, 2, 3]),
        SealOutcome::Break(vec![4, 5]),
    ] {
        let row = SealRow { sealer: 7, outcome };
        assert_eq!(SealRow::parse(&row.bytes()).unwrap(), row);
    }
    assert!(SealRow::parse(b"BBSEAL01").is_err());
    assert!(SealRow::parse(&[0; 32]).is_err());
    assert!(FenceMark::parse(b"BBFENCE1short").is_err());
    let unsorted = [
        b"BBFENCE1".as_slice(),
        &[0; 8],
        &2u64.to_be_bytes(),
        &1u64.to_be_bytes(),
    ]
    .concat();
    assert!(FenceMark::parse(&unsorted).is_err());
}
