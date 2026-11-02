// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::DeadlineClass;
use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request, VERSION,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::store_calls::{StoreCalls, StoreFailure};

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_dropped, load_linked, rendering_of, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::store_v3::LoadedStore;

#[path = "../../tests/fixtures/conditional_store_fixture.rs"]
mod fixture;

fn request() -> Request {
    Request {
        version: VERSION,
        op_id: OpId::from_parts(0xc0de, 1),
        predicates: vec![Predicate {
            schema: "actual-schema".into(),
            key: vec![0, 0xff, b'/'],
            expected: Expected::Absent,
        }],
        mutations: vec![Mutation::Put {
            schema: "actual-schema".into(),
            key: vec![0, 0xff, b'/'],
            value: b"new".to_vec(),
        }],
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime")
}

fn open(dropped: bool, legacy: bool, mode: &str) -> (Arc<LoadedStore>, Arc<Dispatcher>) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let door = if legacy {
        fixture::legacy::door
    } else {
        fixture::negotiated::door
    };
    let bind = Bind {
        instance: Arc::from("conditional-witness"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    };
    let plugin = if dropped {
        let example = if legacy {
            "conditional_store_legacy_door"
        } else {
            "conditional_store_door"
        };
        load_dropped::<Store>(
            &crate::both_ways::example_cdylib(example),
            &rendering_of(door).expect("statement"),
            bind,
        )
    } else {
        load_linked::<Store>(&LinkedRow::of(door).expect("linked statement"), bind)
    }
    .expect("the actual store table loads");
    let settings = serde_json::to_vec(&serde_json::json!({"mode": mode})).expect("settings");
    let store = LoadedStore::open(plugin, dispatcher.clone(), &settings, || {
        OpId::from_parts(0xc0de, 2)
    })
    .expect("open");
    (Arc::new(store), dispatcher)
}

async fn stats(store: &LoadedStore) -> serde_json::Value {
    let bytes = StoreCalls::record_get(store, "observer", b"stats")
        .await
        .expect("observer GET")
        .expect("stats");
    serde_json::from_slice(bytes.as_slice()).expect("stats JSON")
}

async fn wait_stats(
    store: &LoadedStore,
    predicate: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let value = stats(store).await;
        if predicate(&value) {
            return value;
        }
        assert!(
            Instant::now() < until,
            "store did not reach expected state: {value}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[test]
fn typed_transaction_selects_write_behind_and_real_address_both_ways() {
    for dropped in [false, true] {
        let (store, _) = open(dropped, false, "applied");
        runtime().block_on(async {
            assert!(store.supports_record_transaction());
            assert_eq!(
                store.record_transaction(&request()).await.unwrap(),
                Decision::Applied
            );
            let state = stats(&store).await;
            assert_eq!(state["class"], DeadlineClass::WriteBehind as u8);
            assert_eq!(state["deadline"], 0);
            assert_eq!(state["schema"], "actual-schema");
            assert_eq!(state["key"], serde_json::json!([0, 255, 47]));
            assert_eq!(state["released"], 1);
            assert_eq!(state["held"], 0);
            assert_eq!(state["get_class"], DeadlineClass::Call as u8);
            assert!(state["get_deadline"].as_u64().unwrap() > 0);
        });
    }
}

#[test]
fn old_store_refuses_before_any_get_dispatch_both_ways() {
    for dropped in [false, true] {
        let (store, _) = open(dropped, true, "applied");
        runtime().block_on(async {
            assert!(!store.supports_record_transaction());
            assert!(matches!(
                store.record_transaction(&request()).await,
                Err(StoreFailure::Refused(_))
            ));
            let state = stats(&store).await;
            assert_eq!(state["tx_calls"], 0);
            assert_eq!(state["get_calls"], 1, "only the observer GET crossed");
            assert_eq!(state["writes"], 0);
        });
    }
}

#[test]
fn only_a_complete_correlated_leased_ready_result_is_a_decision_both_ways() {
    for dropped in [false, true] {
        for mode in [
            "missing",
            "missing-result",
            "duplicate-result",
            "trailing-result",
            "unleased",
            "malformed",
            "wrong-version",
            "wrong-id",
            "wrong-digest",
            "wrong-decision",
            "wrong-format",
            "wrong-flags",
            "null-result",
            "oversize-result",
        ] {
            let (store, _) = open(dropped, false, mode);
            runtime().block_on(async {
                assert!(
                    matches!(
                        store.record_transaction(&request()).await,
                        Err(StoreFailure::Fault(_))
                    ),
                    "{mode}"
                );
                let state = stats(&store).await;
                assert_eq!(state["held"], 0, "{mode}");
                let expected = u64::from(!matches!(mode, "missing" | "unleased"));
                assert_eq!(state["released"], expected, "{mode}");
            });
        }
        let (store, _) = open(dropped, false, "conflict");
        runtime().block_on(async {
            assert_eq!(
                store.record_transaction(&request()).await.unwrap(),
                Decision::ConditionConflict
            );
            let state = stats(&store).await;
            assert_eq!(state["writes"], 0);
            assert_eq!(state["receipts"], 0);
            assert_eq!(state["released"], 1);
        });
    }
}

async fn transaction_with_short_buffer(
    store: &LoadedStore,
    candidate: &Request,
) -> Result<Decision, StoreFailure> {
    let mut request = super::ConditionalReq::new(candidate)?;
    request.read.buf = Vec::new();
    let (ran, request) = store.submit(request).await;
    store.transaction_result(ran, &request.get().candidate)
}

#[test]
fn short_and_pending_preserve_intent_and_release_each_answer_once_both_ways() {
    for dropped in [false, true] {
        for mode in ["short", "pending"] {
            let (store, _) = open(dropped, false, mode);
            runtime().block_on(async {
                let decision = if mode == "short" {
                    transaction_with_short_buffer(&store, &request()).await
                } else {
                    store.record_transaction(&request()).await
                };
                assert_eq!(decision.unwrap(), Decision::Applied);
                let state = stats(&store).await;
                assert_eq!(state["tx_calls"], 2, "{mode}");
                assert_eq!(state["writes"], 1, "{mode}");
                assert_eq!(state["receipts"], 1, "{mode}");
                assert_eq!(state["same"], true, "{mode}");
                assert_eq!(state["class"], DeadlineClass::WriteBehind as u8);
                assert_eq!(state["deadline"], 0);
                assert_eq!(state["released"], 2, "{mode}");
                assert_eq!(state["held"], 0, "{mode}");
            });
        }
    }
}

#[test]
fn ambiguous_failure_retries_identical_id_and_body_both_ways() {
    for dropped in [false, true] {
        let (store, _) = open(dropped, false, "failed-once");
        runtime().block_on(async {
            let candidate = request();
            assert!(matches!(
                store.record_transaction(&candidate).await,
                Err(StoreFailure::Failed(_))
            ));
            assert_eq!(
                store.record_transaction(&candidate).await.unwrap(),
                Decision::Applied
            );
            let state = stats(&store).await;
            assert_eq!(state["same"], true);
            assert_eq!(state["writes"], 1);
            assert_eq!(state["receipts"], 1);
        });
    }
}

#[test]
fn dropped_caller_keeps_intent_live_and_releases_late_result_both_ways() {
    for dropped in [false, true] {
        let (store, dispatcher) = open(dropped, false, "hold");
        runtime().block_on(async {
            let background = store.clone();
            let task = tokio::spawn(async move {
                let candidate = request();
                background.record_transaction(&candidate).await
            });
            wait_stats(&store, |v| v["tx_calls"] == 1).await;
            assert!(
                dispatcher.drain(store.plugin(), Duration::from_millis(100)),
                "the worker Meta is WriteBehind"
            );
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            StoreCalls::record_get(&*store, "observer", b"finish")
                .await
                .expect("finish GET");
            let state = wait_stats(&store, |v| v["tx_calls"] == 2 && v["held"] == 0).await;
            assert_eq!(state["same"], true, "the candidate survived its caller");
            assert_eq!(state["released"], 1);
            assert_eq!(
                state["cancelled"], 0,
                "WriteBehind runs on after client drop"
            );
        });
    }
}

#[test]
fn invalid_candidate_is_refused_before_dispatch_and_second_short_never_applies_both_ways() {
    for dropped in [false, true] {
        let (store, _) = open(dropped, false, "applied");
        runtime().block_on(async {
            let mut invalid = request();
            invalid.version += 1;
            assert!(matches!(
                store.record_transaction(&invalid).await,
                Err(StoreFailure::Refused(_))
            ));
            let mut invalid = request();
            invalid.predicates.push(invalid.predicates[0].clone());
            assert!(matches!(
                store.record_transaction(&invalid).await,
                Err(StoreFailure::Refused(_))
            ));
            assert_eq!(stats(&store).await["tx_calls"], 0);
        });
        let (store, _) = open(dropped, false, "short-twice");
        runtime().block_on(async {
            assert!(matches!(
                transaction_with_short_buffer(&store, &request()).await,
                Err(StoreFailure::Fault(_))
            ));
            let state = stats(&store).await;
            assert_eq!(state["tx_calls"], 2);
            assert_eq!(state["writes"], 0);
            assert_eq!(state["receipts"], 0);
            assert_eq!(state["released"], 2);
            assert_eq!(state["held"], 0);
        });
    }
}

#[test]
fn operation_id_conflict_remains_distinct_from_condition_conflict_both_ways() {
    for dropped in [false, true] {
        let (store, _) = open(dropped, false, "op-id-conflict");
        runtime().block_on(async {
            assert!(matches!(
                store.record_transaction(&request()).await,
                Err(StoreFailure::Conflict)
            ));
            let state = stats(&store).await;
            assert_eq!(state["writes"], 0);
            assert_eq!(state["receipts"], 0);
        });
    }
}

fn correction_request() -> busbar_contract::records::correction::Request {
    use busbar_contract::records::correction::{Request, UsageAddress, UsageChange, VERSION};
    use busbar_contract::records::UsageLedger;
    Request {
        version: VERSION,
        op_id: OpId::from_parts(0xc0de, 3),
        key_id: "historical-key".into(),
        day_start: 0,
        metering: vec![],
        usage: vec![UsageChange {
            address: UsageAddress {
                bucket_id: "historical-key".into(),
                window_start: 0,
            },
            expected: UsageLedger {
                requests: 100,
                billable_requests: 100,
                models: vec![],
            },
            replacement: UsageLedger {
                requests: 100,
                billable_requests: 40,
                models: vec![],
            },
        }],
    }
}

#[test]
fn correction_requires_negotiation_and_correlated_leased_decision_both_ways() {
    use busbar_contract::records::correction::Decision;
    for dropped in [false, true] {
        let (store, _) = open(dropped, true, "applied");
        runtime().block_on(async {
            assert!(!store.supports_usage_correction());
            assert!(matches!(
                StoreCalls::apply_usage_correction(&*store, &correction_request()).await,
                Err(StoreFailure::Refused(_))
            ));
            assert_eq!(stats(&store).await["tx_calls"], 0);
        });
        for mode in [
            "missing",
            "unleased",
            "malformed",
            "wrong-id",
            "wrong-digest",
            "duplicate-result",
            "trailing-result",
            "wrong-format",
            "wrong-flags",
        ] {
            let (store, _) = open(dropped, false, mode);
            runtime().block_on(async {
                assert!(store.supports_usage_correction());
                assert!(
                    matches!(
                        StoreCalls::apply_usage_correction(&*store, &correction_request()).await,
                        Err(StoreFailure::Fault(_))
                    ),
                    "{mode}"
                );
                assert_eq!(stats(&store).await["held"], 0, "{mode}");
            });
        }
        for (mode, expected) in [
            ("applied", Decision::Applied),
            ("pending", Decision::Applied),
            ("conflict", Decision::ConditionConflict),
        ] {
            let (store, _) = open(dropped, false, mode);
            runtime().block_on(async {
                assert_eq!(
                    StoreCalls::apply_usage_correction(&*store, &correction_request())
                        .await
                        .unwrap(),
                    expected
                );
                let state = stats(&store).await;
                assert_eq!(state["held"], 0);
                assert_eq!(state["same"], true);
                assert_eq!(state["released"], 1);
                assert_eq!(state["class"], DeadlineClass::WriteBehind as u8);
                assert_eq!(state["deadline"], 0);
                assert_eq!(state["writes"], u64::from(expected == Decision::Applied));
            });
        }
    }
}

#[test]
fn correction_replay_and_dropped_caller_keep_exact_candidate_both_ways() {
    use busbar_contract::records::correction::Decision;
    for dropped in [false, true] {
        let (store, _) = open(dropped, false, "failed-once");
        runtime().block_on(async {
            let request = correction_request();
            assert!(matches!(
                StoreCalls::apply_usage_correction(&*store, &request).await,
                Err(StoreFailure::Failed(_))
            ));
            assert_eq!(
                StoreCalls::apply_usage_correction(&*store, &request)
                    .await
                    .unwrap(),
                Decision::Applied
            );
            let state = stats(&store).await;
            assert_eq!(state["same"], true);
            assert_eq!(state["writes"], 1);
            assert_eq!(state["receipts"], 1);
        });
        let (store, dispatcher) = open(dropped, false, "hold");
        runtime().block_on(async {
            let background = store.clone();
            let task = tokio::spawn(async move {
                StoreCalls::apply_usage_correction(&*background, &correction_request()).await
            });
            wait_stats(&store, |v| v["tx_calls"] == 1).await;
            assert!(dispatcher.drain(store.plugin(), Duration::from_millis(100)));
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            StoreCalls::record_get(&*store, "observer", b"finish")
                .await
                .unwrap();
            let state = wait_stats(&store, |v| v["tx_calls"] == 2 && v["held"] == 0).await;
            assert_eq!(state["same"], true);
            assert_eq!(state["released"], 1);
            assert_eq!(state["cancelled"], 0);
        });
    }
}

#[test]
fn correction_validation_op_id_conflict_and_synchronous_bridge_both_ways() {
    use busbar_contract::records::{correction::Decision, RecordStore};
    for dropped in [false, true] {
        let (store, _) = open(dropped, false, "applied");
        runtime().block_on(async {
            let mut invalid = correction_request();
            invalid.version += 1;
            assert!(matches!(
                StoreCalls::apply_usage_correction(&*store, &invalid).await,
                Err(StoreFailure::Refused(_))
            ));
            assert_eq!(stats(&store).await["tx_calls"], 0);
        });
        let (store, _) = open(dropped, false, "op-id-conflict");
        runtime().block_on(async {
            assert!(matches!(
                StoreCalls::apply_usage_correction(&*store, &correction_request()).await,
                Err(StoreFailure::Conflict)
            ));
            let state = stats(&store).await;
            assert_eq!(state["writes"], 0);
            assert_eq!(state["receipts"], 0);
        });
        let (store, _) = open(dropped, false, "pending");
        assert_eq!(
            RecordStore::apply_usage_correction(&*store, &correction_request()).unwrap(),
            Decision::Applied
        );
        runtime().block_on(async {
            let state = stats(&store).await;
            assert_eq!(state["same"], true);
            assert_eq!(state["released"], 1);
            assert_eq!(state["held"], 0);
        });
    }
}
