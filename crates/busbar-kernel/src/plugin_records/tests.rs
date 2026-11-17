// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-K5: plugin records over CoreStore (IF §12.5), on core's in-tree store. C-COMMIT's arms are in
//! busbar-plugin-test (tests/c_commit.rs); C-PLANE-CHAIN's core arm is W1-K8A's (WBS rule 10), so the chain
//! code is proven here.

use std::cell::Cell;
use std::sync::Arc;

use busbar_contract::Secret;
use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::types::KindCode;

use super::store::{label, CHAINS, RECORDS};
use super::{
    chain, ChainRead, CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope, StoreRecords,
    MAX_CHAIN_ENTRY, MAX_KEY, MAX_TTL_S, MAX_VALUE,
};
use crate::audit::stream_registry::{StreamInput, StreamRecord};
use crate::audit::{Chain, Framing};
use crate::persistence::scoped::ScopedStore;

#[path = "cancellation_tests.rs"]
mod cancellation;

const START: u64 = 1_800_000_000;

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(START) };
}

fn clock() -> u64 {
    NOW.with(Cell::get)
}

fn set_now(now: u64) {
    NOW.with(|cell| cell.set(now));
}

fn caller<'a>(plugin: &'a str, name: &'a str) -> Caller<'a> {
    Caller {
        plugin,
        kind: KindCode::Plane,
        name,
        instance: 7,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now(),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

async fn records() -> StoreRecords {
    StoreRecords::with_clock(crate::real_store::core().await, clock)
}

fn subject(n: u8) -> Scope {
    Scope {
        subject: Some([n; 32]),
    }
}

async fn get(
    r: &impl PluginRecords,
    who: &Caller<'_>,
    scope: Scope,
    key: &[u8],
) -> Option<Vec<u8>> {
    let mut out = None;
    let found = r
        .get(who, scope, key, &mut |value: &[u8]| {
            out = Some(value.to_vec())
        })
        .await
        .expect("get answers");
    assert_eq!(found, out.is_some(), "found iff the sink was called");
    out
}

async fn list(
    r: &StoreRecords,
    who: &Caller<'_>,
    scope: Scope,
    prefix: &[u8],
    limit: u32,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let n = r
        .list(
            who,
            scope,
            prefix,
            limit,
            &mut |key: &[u8], value: &[u8]| {
                out.push((key.to_vec(), value.to_vec()));
            },
        )
        .await
        .expect("list answers");
    assert_eq!(n as usize, out.len());
    out
}

async fn read_chain(
    r: &StoreRecords,
    who: &Caller<'_>,
    scope: Scope,
    name: &[u8],
    after: u64,
    limit: u32,
) -> (ChainRead, Vec<(u64, Vec<u8>)>) {
    let mut out = Vec::new();
    let read = r
        .chain(
            who,
            scope,
            name,
            after,
            limit,
            &mut |seq: u64, entry: &[u8]| {
                out.push((seq, entry.to_vec()));
            },
        )
        .await
        .expect("chain answers");
    assert_eq!(read.hits as usize, out.len());
    (read, out)
}

/// The test's own view of the instance's rows, to tamper with them as a store operator could.
fn backing(r: &StoreRecords, who: &Caller<'_>) -> ScopedStore {
    ScopedStore::host_private(
        Arc::clone(r.store_for_tests()),
        &label(who),
        [RECORDS.to_string(), CHAINS.to_string()],
    )
    .expect("scope")
}

#[tokio::test]
async fn a_put_reads_back_and_a_missing_key_is_not_found() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    assert_eq!(get(&r, &who, Scope::default(), b"task/1").await, None);
    r.put(&who, Scope::default(), b"task/1", b"working", 0)
        .await
        .expect("put");
    assert_eq!(
        get(&r, &who, Scope::default(), b"task/1").await.as_deref(),
        Some(&b"working"[..])
    );
    r.put(&who, Scope::default(), b"task/1", b"", 0)
        .await
        .expect("an empty value is a value");
    assert_eq!(
        get(&r, &who, Scope::default(), b"task/1").await.as_deref(),
        Some(&b""[..])
    );
}

#[tokio::test]
async fn ttl_zero_never_expires_and_a_ttl_is_clamped_to_the_maximum() {
    let r = records().await;
    let who = caller("plane-mcp", "tools");
    let s = Scope::default();
    r.put(&who, s, b"forever", b"0", 0).await.expect("put");
    r.put(&who, s, b"ten", b"10", 10).await.expect("put");
    r.put(&who, s, b"clamped", b"max", u64::MAX)
        .await
        .expect("put");

    set_now(START + 9);
    assert!(
        get(&r, &who, s, b"ten").await.is_some(),
        "live before its TTL"
    );
    set_now(START + 10);
    assert!(get(&r, &who, s, b"ten").await.is_none(), "gone at its TTL");

    set_now(START + MAX_TTL_S - 1);
    assert!(get(&r, &who, s, b"clamped").await.is_some());
    set_now(START + MAX_TTL_S);
    assert!(
        get(&r, &who, s, b"clamped").await.is_none(),
        "a TTL above the maximum is clamped to it"
    );
    set_now(START + 10 * MAX_TTL_S);
    assert_eq!(
        get(&r, &who, s, b"forever").await.as_deref(),
        Some(&b"0"[..]),
        "ttl 0 = no expiry, still readable after the clamp maximum has passed"
    );
}

#[tokio::test]
async fn a_claim_wins_once_and_again_after_expiry() {
    let r = records().await;
    let who = caller("auth-webhook-signature", "hooks");
    let s = Scope::default();
    assert!(r
        .claim(&who, s, b"replay/abc", b"1", 60)
        .await
        .expect("claim"));
    assert!(!r
        .claim(&who, s, b"replay/abc", b"2", 60)
        .await
        .expect("claim"));
    assert_eq!(
        get(&r, &who, s, b"replay/abc").await.as_deref(),
        Some(&b"1"[..])
    );
    set_now(START + 60);
    assert!(
        r.claim(&who, s, b"replay/abc", b"3", 60)
            .await
            .expect("claim"),
        "an expired claim is absent"
    );
    assert_eq!(
        get(&r, &who, s, b"replay/abc").await.as_deref(),
        Some(&b"3"[..])
    );
}

#[tokio::test]
async fn instances_and_scopes_never_share_a_record() {
    let r = records().await;
    let a = caller("plane-a2a", "east");
    let b = caller("plane-a2a", "west");
    let c = caller("plane-mcp", "east");
    let d = caller("plane-a", "2a/east");
    r.put(&a, Scope::default(), b"k", b"a", 0)
        .await
        .expect("put");
    r.put(&a, subject(1), b"k", b"a1", 0).await.expect("put");
    for other in [&b, &c, &d] {
        assert_eq!(get(&r, other, Scope::default(), b"k").await, None);
    }
    assert_eq!(get(&r, &a, subject(2), b"k").await, None);
    assert_eq!(
        get(&r, &a, subject(1), b"k").await.as_deref(),
        Some(&b"a1"[..])
    );
    assert_eq!(
        get(&r, &a, Scope::default(), b"k").await.as_deref(),
        Some(&b"a"[..])
    );
}

#[tokio::test]
async fn list_answers_live_records_in_key_order_up_to_the_limit() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    let s = Scope::default();
    r.put(&who, s, b"k3", b"3", 0).await.expect("put");
    r.put(&who, s, b"k1", b"1", 0).await.expect("put");
    r.put(&who, s, b"k2", b"2", 5).await.expect("put");
    r.put(&who, s, b"j1", b"x", 0).await.expect("put");
    r.put(&who, subject(9), b"k0", b"caller", 0)
        .await
        .expect("put");
    set_now(START + 5);
    assert_eq!(
        list(&r, &who, s, b"k", 10).await,
        vec![
            (b"k1".to_vec(), b"1".to_vec()),
            (b"k3".to_vec(), b"3".to_vec())
        ],
        "expired k2 and the caller-scoped k0 are not listed"
    );
    assert_eq!(list(&r, &who, s, b"k", 1).await.len(), 1);
    assert_eq!(list(&r, &who, s, b"", 0).await.len(), 0);
    assert_eq!(
        list(&r, &who, subject(9), b"k", 10).await,
        vec![(b"k0".to_vec(), b"caller".to_vec())]
    );
}

#[tokio::test]
async fn a_failed_predicate_applies_nothing_and_names_its_op() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    let s = Scope::default();
    r.put(&who, s, b"x", b"1", 0).await.expect("put");
    let outcome = r
        .commit(
            &who,
            s,
            &[
                CommitOp::Put {
                    key: b"y",
                    value: b"new",
                    ttl_s: 0,
                    caller: false,
                },
                CommitOp::Equals {
                    key: b"x",
                    value: b"2",
                    caller: false,
                },
                CommitOp::Del {
                    key: b"x",
                    caller: false,
                },
            ],
        )
        .await
        .expect("commit");
    assert_eq!(outcome, CommitOutcome::Conflict { failed: 1 });
    assert_eq!(get(&r, &who, s, b"y").await, None, "nothing applied");
    assert_eq!(get(&r, &who, s, b"x").await.as_deref(), Some(&b"1"[..]));

    let outcome = r
        .commit(
            &who,
            s,
            &[
                CommitOp::Equals {
                    key: b"x",
                    value: b"1",
                    caller: false,
                },
                CommitOp::Absent {
                    key: b"y",
                    caller: false,
                },
                CommitOp::Put {
                    key: b"y",
                    value: b"new",
                    ttl_s: 0,
                    caller: false,
                },
                CommitOp::Del {
                    key: b"x",
                    caller: false,
                },
            ],
        )
        .await
        .expect("commit");
    assert_eq!(outcome, CommitOutcome::Applied);
    assert_eq!(get(&r, &who, s, b"y").await.as_deref(), Some(&b"new"[..]));
    assert_eq!(get(&r, &who, s, b"x").await, None);
}

#[tokio::test]
async fn an_expired_record_is_absent_to_the_predicates() {
    let r = records().await;
    let who = caller("plane-mcp", "tools");
    let s = Scope::default();
    r.put(&who, s, b"lease", b"held", 30).await.expect("put");
    let present = [CommitOp::Present {
        key: b"lease",
        caller: false,
    }];
    assert_eq!(
        r.commit(&who, s, &present).await.expect("commit"),
        CommitOutcome::Applied
    );
    set_now(START + 30);
    assert_eq!(
        r.commit(&who, s, &present).await.expect("commit"),
        CommitOutcome::Conflict { failed: 0 }
    );
    let take = [
        CommitOp::Absent {
            key: b"lease",
            caller: false,
        },
        CommitOp::Put {
            key: b"lease",
            value: b"mine",
            ttl_s: 30,
            caller: false,
        },
    ];
    assert_eq!(
        r.commit(&who, s, &take).await.expect("commit"),
        CommitOutcome::Applied
    );
    assert_eq!(
        get(&r, &who, s, b"lease").await.as_deref(),
        Some(&b"mine"[..])
    );
}

#[tokio::test]
async fn commit_bounds_and_scope_rules() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    let s = Scope::default();
    let one = CommitOp::Present {
        key: b"k",
        caller: false,
    };
    assert_eq!(
        r.commit(&who, s, &[one; 65]).await,
        Err(RecordsDenied::Invalid),
        "more than commit::MAX_OPS ops"
    );
    let twice = [
        CommitOp::Put {
            key: b"k",
            value: b"1",
            ttl_s: 0,
            caller: false,
        },
        CommitOp::Del {
            key: b"k",
            caller: false,
        },
    ];
    assert_eq!(r.commit(&who, s, &twice).await, Err(RecordsDenied::Invalid));
    let unscoped_caller = [CommitOp::Absent {
        key: b"k",
        caller: true,
    }];
    assert_eq!(
        r.commit(&who, s, &unscoped_caller).await,
        Err(RecordsDenied::Invalid),
        "REC_CALLER without a subject"
    );
    let long = vec![b'k'; MAX_KEY + 1];
    let big = vec![0u8; MAX_VALUE + 1];
    assert_eq!(
        r.commit(
            &who,
            s,
            &[CommitOp::Absent {
                key: &long,
                caller: false
            }]
        )
        .await,
        Err(RecordsDenied::TooLarge)
    );
    assert_eq!(
        r.put(&who, s, b"k", &big, 0).await,
        Err(RecordsDenied::TooLarge)
    );
    assert_eq!(
        r.commit(&who, s, &[]).await,
        Ok(CommitOutcome::Applied),
        "an empty commit applies nothing and holds"
    );
    // REC_CALLER ops use the commit's subject; the others the instance's own scope.
    let split = [
        CommitOp::Put {
            key: b"mine",
            value: b"c",
            ttl_s: 0,
            caller: true,
        },
        CommitOp::Put {
            key: b"shared",
            value: b"s",
            ttl_s: 0,
            caller: false,
        },
    ];
    assert_eq!(
        r.commit(&who, subject(3), &split).await,
        Ok(CommitOutcome::Applied)
    );
    assert_eq!(
        get(&r, &who, subject(3), b"mine").await.as_deref(),
        Some(&b"c"[..])
    );
    assert_eq!(get(&r, &who, s, b"mine").await, None);
    assert_eq!(
        get(&r, &who, s, b"shared").await.as_deref(),
        Some(&b"s"[..])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_racing_commits_on_one_key_apply_exactly_one() {
    let r = Arc::new(records().await);
    for round in 0..32u32 {
        let key: &'static [u8] = Box::leak(format!("task/{round}").into_bytes().into_boxed_slice());
        let racers: Vec<_> = [&b"a"[..], &b"b"[..]]
            .into_iter()
            .map(|value| {
                let r = Arc::clone(&r);
                tokio::spawn(async move {
                    let who = caller("plane-a2a", "agents");
                    let ops = [
                        CommitOp::Absent { key, caller: false },
                        CommitOp::Put {
                            key,
                            value,
                            ttl_s: 0,
                            caller: false,
                        },
                    ];
                    (value, r.commit(&who, Scope::default(), &ops).await)
                })
            })
            .collect();
        let mut applied = Vec::new();
        for racer in racers {
            let (value, outcome) = racer.await.expect("racer");
            match outcome.expect("commit answers") {
                CommitOutcome::Applied => applied.push(value),
                CommitOutcome::Conflict { failed } => assert_eq!(failed, 0),
            }
        }
        assert_eq!(applied.len(), 1, "exactly one APPLIED");
        let who = caller("plane-a2a", "agents");
        assert_eq!(
            get(&*r, &who, Scope::default(), key).await.as_deref(),
            Some(applied[0])
        );
    }
}

#[tokio::test]
async fn deleting_a_key_drops_its_record_and_its_chain() {
    let r = records().await;
    let who = caller("plane-mcp", "tools");
    let s = Scope::default();
    r.put(&who, s, b"principal-1", b"row", 0)
        .await
        .expect("put");
    for n in 0..3u8 {
        r.append(&who, s, b"principal-1", &[n])
            .await
            .expect("append");
    }
    r.del(&who, s, b"principal-1").await.expect("del");
    assert_eq!(get(&r, &who, s, b"principal-1").await, None);
    let (read, _) = read_chain(&r, &who, s, b"principal-1", 0, 10).await;
    assert_eq!(read, ChainRead::default());
    assert_eq!(
        r.append(&who, s, b"principal-1", b"again").await,
        Ok(1),
        "a dropped chain starts again at 1"
    );
    r.del(&who, s, b"never-written")
        .await
        .expect("del of nothing");
}

#[tokio::test]
async fn a_chain_appends_in_order_and_reads_back_in_pages() {
    let r = records().await;
    let who = caller("plane-mcp", "tools");
    let s = subject(4);
    for n in 1..=250u64 {
        let seq = r
            .append(&who, s, b"principal-1", &n.to_be_bytes())
            .await
            .expect("append");
        assert_eq!(seq, n);
    }
    let mut seen = Vec::new();
    for page in 0..3u64 {
        let (read, hits) = read_chain(&r, &who, s, b"principal-1", page * 100, 100).await;
        assert_eq!(read.len, 250);
        assert_eq!(read.broken_at, 0);
        seen.extend(hits);
    }
    assert_eq!(seen.len(), 250);
    for (i, (seq, entry)) in seen.iter().enumerate() {
        let n = i as u64 + 1;
        assert_eq!(*seq, n);
        assert_eq!(entry.as_slice(), &n.to_be_bytes());
    }
    let (read, hits) = read_chain(&r, &who, Scope::default(), b"principal-1", 0, 10).await;
    assert_eq!(
        (read.len, hits.len()),
        (0, 0),
        "another scope holds no chain"
    );
}

#[tokio::test]
async fn stored_frames_are_the_kernel_chain_frames() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    let s = Scope::default();
    let entries: [&[u8]; 3] = [b"submitted", b"working", b"completed"];
    for entry in entries {
        r.append(&who, s, b"task-7", entry).await.expect("append");
    }
    let mut expected = Chain::<StreamRecord>::new();
    let rows = backing(&r, &who);
    let prefix = chain::entries_prefix(s, b"task-7");
    for (i, entry) in entries.iter().enumerate() {
        let record = expected.append(
            "task-7",
            StreamInput::new(entry.to_vec(), Framing::LengthPrefixed, true),
        );
        let frame = crate::host_chains::encode(&record).expect("frame");
        let stored = rows
            .get(CHAINS, &chain::entry_key(&prefix, i as u64 + 1))
            .await
            .expect("read")
            .expect("stored");
        let seal = crate::seal::lend();
        assert_eq!(
            stored.expose(&seal),
            &frame,
            "entry {} is host_chains.rs's frame",
            i + 1
        );
    }
}

#[tokio::test]
async fn a_tampered_entry_breaks_the_chain_there() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    let s = Scope::default();
    for n in 1..=10u8 {
        r.append(&who, s, b"task-1", &[n; 16])
            .await
            .expect("append");
    }
    let rows = backing(&r, &who);
    let at = chain::entry_key(&chain::entries_prefix(s, b"task-1"), 5);
    let mut bytes = {
        let stored = rows.get(CHAINS, &at).await.expect("read").expect("stored");
        let seal = crate::seal::lend();
        stored.expose(&seal).clone()
    };
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    rows.put(CHAINS, &at, Secret::new(bytes))
        .await
        .expect("tamper");
    let (read, hits) = read_chain(&r, &who, s, b"task-1", 0, 100).await;
    assert_eq!(read.broken_at, 5);
    assert_eq!(read.len, 10);
    assert_eq!(
        hits.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    let (read, hits) = read_chain(&r, &who, s, b"task-1", 6, 100).await;
    assert_eq!(
        (read.broken_at, hits.len()),
        (5, 0),
        "nothing past the break"
    );
}

#[tokio::test]
async fn a_missing_tail_entry_breaks_at_len() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    let s = Scope::default();
    for n in 1..=10u8 {
        r.append(&who, s, b"task-2", &[n]).await.expect("append");
    }
    let rows = backing(&r, &who);
    rows.delete(
        CHAINS,
        &chain::entry_key(&chain::entries_prefix(s, b"task-2"), 10),
    )
    .await
    .expect("delete the tail");
    let (read, hits) = read_chain(&r, &who, s, b"task-2", 0, 100).await;
    assert_eq!(read.broken_at, read.len);
    assert_eq!(read.len, 10);
    assert_eq!(hits.len(), 9);
}

#[tokio::test]
async fn chain_names_and_entries_are_bounded() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    let s = Scope::default();
    for bad in [&b""[..], &[0xff, 0xfe][..], &b"x/00000000000000000001"[..]] {
        assert_eq!(
            r.append(&who, s, bad, b"e").await,
            Err(RecordsDenied::Invalid)
        );
    }
    assert_eq!(
        r.append(&who, s, &vec![b'c'; MAX_KEY + 1], b"e").await,
        Err(RecordsDenied::TooLarge)
    );
    assert_eq!(
        r.append(&who, s, b"c", &vec![0; MAX_CHAIN_ENTRY + 1]).await,
        Err(RecordsDenied::TooLarge)
    );
    assert_eq!(
        r.append(&who, s, b"c", &vec![0; MAX_CHAIN_ENTRY]).await,
        Ok(1)
    );
}

#[tokio::test]
async fn two_instances_chains_with_one_name_are_separate() {
    let r = records().await;
    let a = caller("plane-a2a", "east");
    let b = caller("plane-a2a", "west");
    let s = Scope::default();
    assert_eq!(r.append(&a, s, b"task", b"a1").await, Ok(1));
    assert_eq!(r.append(&b, s, b"task", b"b1").await, Ok(1));
    assert_eq!(r.append(&a, s, b"task", b"a2").await, Ok(2));
    let (read, hits) = read_chain(&r, &b, s, b"task", 0, 10).await;
    assert_eq!((read.len, read.broken_at), (1, 0));
    assert_eq!(hits, vec![(1, b"b1".to_vec())]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_appends_take_distinct_sequences() {
    let r = Arc::new(records().await);
    let tasks: Vec<_> = (0..8u8)
        .map(|n| {
            let r = Arc::clone(&r);
            tokio::spawn(async move {
                let who = caller("plane-mcp", "tools");
                r.append(&who, Scope::default(), b"log", &[n]).await
            })
        })
        .collect();
    let mut seqs = Vec::new();
    for task in tasks {
        seqs.push(task.await.expect("task").expect("append"));
    }
    seqs.sort();
    assert_eq!(seqs, (1..=8).collect::<Vec<u64>>());
    let who = caller("plane-mcp", "tools");
    let (read, hits) = read_chain(&r, &who, Scope::default(), b"log", 0, 100).await;
    assert_eq!((read.len, read.broken_at, hits.len()), (8, 0, 8));
}

#[tokio::test]
async fn the_arc_impl_serves_the_same_namespace() {
    let r = Arc::new(records().await);
    let who = caller("plane-a2a", "agents");
    r.put(&who, Scope::default(), b"k", b"v", 0)
        .await
        .expect("put");
    assert_eq!(
        get(&r, &who, Scope::default(), b"k").await.as_deref(),
        Some(&b"v"[..])
    );
    assert_eq!(
        get(&*r, &who, Scope::default(), b"k").await.as_deref(),
        Some(&b"v"[..])
    );
}

#[tokio::test]
async fn a_sweep_deletes_only_expired_records() {
    let r = records().await;
    let who = caller("plane-a2a", "agents");
    r.put(&who, Scope::default(), b"old", b"1", 10)
        .await
        .expect("put");
    r.put(&who, subject(5), b"old", b"2", 10)
        .await
        .expect("put");
    r.put(&who, Scope::default(), b"kept", b"3", 0)
        .await
        .expect("put");
    assert_eq!(r.sweep_expired(&who).await, Ok(0));
    set_now(START + 10);
    assert_eq!(r.sweep_expired(&who).await, Ok(2));
    let rows = backing(&r, &who);
    let page = rows.page(RECORDS, &[], None).await.expect("page");
    assert_eq!(page.rows.len(), 1, "only the unexpiring record is left");
    assert_eq!(
        get(&r, &who, Scope::default(), b"kept").await.as_deref(),
        Some(&b"3"[..])
    );
    assert_eq!(r.settle().await, 0, "nothing in doubt");
}
