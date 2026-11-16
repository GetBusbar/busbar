// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-COMMIT (ABI-MIN3-INTERFACE §14): Two concurrent conflicting COMMITs on one key: exactly one APPLIED; a failed
//! predicate applies nothing.
//!
//! W1-K5: both arms run on the kernel's own plugin records (`StoreRecords`, IF §12.5) over core's in-tree
//! in-memory store, the contract busbar-store-memory serves; FakeNeeds answers COMMIT Invalid on purpose.

#[path = "../../busbar-kernel/src/tests/memory_backend.rs"]
mod memory_backend;

use std::sync::{Arc, Barrier};

use busbar_kernel::persistence::facade::{CoreStore, Limits};
use busbar_kernel::persistence::startup::{Progress, Startup};
use busbar_kernel::plugin_records::{CommitOp, CommitOutcome, PluginRecords, Scope, StoreRecords};
use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::types::KindCode;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a test runtime")
}

async fn store() -> Arc<CoreStore> {
    let mut startup = Startup::new(
        Arc::new(memory_backend::MemoryBackend::default()),
        Limits {
            pending_operations: 64,
            conflict_retries: 8,
            scan_items: 128,
            scan_bytes: 1024 * 1024,
        },
        true,
    )
    .expect("store authority");
    loop {
        match startup.advance().await.expect("store startup") {
            Progress::Advanced => {}
            Progress::Admitted => break,
            other => panic!("the store did not admit: {other:?}"),
        }
    }
    startup.store().expect("the admitted store")
}

fn plane() -> Caller<'static> {
    Caller {
        plugin: "plane-a2a",
        kind: KindCode::Plane,
        name: "agents",
        instance: 1,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now(),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

fn read(rt: &tokio::runtime::Runtime, records: &StoreRecords, key: &[u8]) -> Option<Vec<u8>> {
    let mut out = None;
    rt.block_on(
        records.get(&plane(), Scope::default(), key, &mut |value: &[u8]| {
            out = Some(value.to_vec());
        }),
    )
    .expect("get answers");
    out
}

/// Two threads, released together, each COMMIT `[ABSENT key, PUT key = its own value]` on one key, 64 times.
#[test]
fn two_conflicting_commits_apply_exactly_one() {
    let rt = runtime();
    let records = Arc::new(StoreRecords::new(rt.block_on(store())));
    for round in 0..64u32 {
        let key: Arc<[u8]> = Arc::from(format!("task/{round}").into_bytes());
        let gate = Arc::new(Barrier::new(2));
        let racers: Vec<_> = [&b"first"[..], &b"second"[..]]
            .into_iter()
            .map(|value| {
                let (records, gate, key) =
                    (Arc::clone(&records), Arc::clone(&gate), Arc::clone(&key));
                std::thread::spawn(move || {
                    let rt = runtime();
                    let ops = [
                        CommitOp::Absent {
                            key: &key,
                            caller: false,
                        },
                        CommitOp::Put {
                            key: &key,
                            value,
                            ttl_s: 0,
                            caller: false,
                        },
                    ];
                    gate.wait();
                    (
                        value,
                        rt.block_on(records.commit(&plane(), Scope::default(), &ops)),
                    )
                })
            })
            .collect();
        let mut applied = Vec::new();
        for racer in racers {
            let (value, outcome) = racer.join().expect("a racer");
            match outcome.expect("COMMIT answers") {
                CommitOutcome::Applied => applied.push(value),
                CommitOutcome::Conflict { failed } => {
                    assert_eq!(failed, 0, "the loser's ABSENT predicate failed");
                }
            }
        }
        assert_eq!(applied.len(), 1, "round {round}: exactly one APPLIED");
        assert_eq!(
            read(&rt, &records, &key).as_deref(),
            Some(applied[0]),
            "round {round}: the winner's value stands"
        );
    }
}

/// A COMMIT whose second predicate fails applies none of its mutations, before or after that predicate.
#[test]
fn a_failed_predicate_applies_nothing() {
    let rt = runtime();
    let records = StoreRecords::new(rt.block_on(store()));
    let who = plane();
    rt.block_on(records.put(&who, Scope::default(), b"task/1", b"working", 0))
        .expect("put");
    let outcome = rt
        .block_on(records.commit(
            &who,
            Scope::default(),
            &[
                CommitOp::Put {
                    key: b"task/2",
                    value: b"submitted",
                    ttl_s: 0,
                    caller: false,
                },
                CommitOp::Equals {
                    key: b"task/1",
                    value: b"completed",
                    caller: false,
                },
                CommitOp::Del {
                    key: b"task/1",
                    caller: false,
                },
            ],
        ))
        .expect("COMMIT answers");
    assert_eq!(outcome, CommitOutcome::Conflict { failed: 1 });
    assert_eq!(
        read(&rt, &records, b"task/2"),
        None,
        "the PUT did not apply"
    );
    assert_eq!(
        read(&rt, &records, b"task/1").as_deref(),
        Some(&b"working"[..]),
        "the DEL did not apply"
    );
}
