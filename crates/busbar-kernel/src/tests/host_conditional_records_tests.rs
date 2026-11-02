// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_chains::{ChainFraming, ConditionalChain, CHAIN_LIFE_SCHEMA};
use busbar_contract::abi::plane::{RecordChain, CHAIN_DIGESTS_SCOPE, CHAIN_PIPE_SEPARATED};
use conditional::{Decision, Expected, Mutation, Predicate, Request, VERSION};

const STATE: RecordSchemaId = RecordSchemaId::new("state");
const EVENTS: RecordSchemaId = RecordSchemaId::new("events");
const INSTANCE: &str = "instance";

type Address = (String, Vec<u8>);

#[derive(Default)]
struct AtomicState {
    rows: BTreeMap<Address, Vec<u8>>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
    calls: Vec<Request>,
    lose_reply: bool,
    fail_before_commit: bool,
    refuse: bool,
    scans: usize,
    refuse_scan: bool,
}

#[derive(Default)]
struct AtomicRows(Mutex<AtomicState>);

impl RecordRows for AtomicRows {
    fn supports_record_transaction(&self) -> bool {
        true
    }

    fn record_transaction(&self, request: &Request) -> Result<Decision, StoreFailure> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(request.clone());
        if state.refuse {
            return Err(StoreFailure::Refused("temporarily unsupported".into()));
        }
        let fingerprint = request.fingerprint();
        if let Some(held) = state.receipts.get(&request.op_id.0) {
            return if *held == fingerprint {
                Ok(Decision::Applied)
            } else {
                Err(StoreFailure::Conflict)
            };
        }
        for predicate in &request.predicates {
            let held = state
                .rows
                .get(&(predicate.schema.clone(), predicate.key.clone()));
            let matches = match &predicate.expected {
                Expected::Absent => held.is_none(),
                Expected::Bytes(bytes) => held == Some(bytes),
            };
            if !matches {
                return Ok(Decision::ConditionConflict);
            }
        }
        if state.fail_before_commit {
            state.fail_before_commit = false;
            return Err(StoreFailure::Failed("rolled back".into()));
        }
        for mutation in &request.mutations {
            match mutation {
                Mutation::Put { schema, key, value } => {
                    state
                        .rows
                        .insert((schema.clone(), key.clone()), value.clone());
                }
                Mutation::Delete { schema, key } => {
                    state.rows.remove(&(schema.clone(), key.clone()));
                }
                Mutation::DeleteRange {
                    schema,
                    prefix,
                    exact_key_length,
                } => {
                    state.rows.retain(|(held_schema, key), _| {
                        held_schema != schema
                            || !key.starts_with(prefix)
                            || key.len() as u64 != *exact_key_length
                    });
                }
            }
        }
        state.receipts.insert(request.op_id.0, fingerprint);
        if state.lose_reply {
            state.lose_reply = false;
            Err(StoreFailure::Fault("lost commit answer".into()))
        } else {
            Ok(Decision::Applied)
        }
    }

    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError> {
        self.0.lock().unwrap().rows.insert(
            (schema.as_str().into(), key.to_vec()),
            value.as_slice().to_vec(),
        );
        Ok(())
    }
    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .rows
            .get(&(schema.as_str().into(), key.to_vec()))
            .map(|bytes| RecordBytes::new(bytes.clone()).unwrap()))
    }
    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        let mut state = self.0.lock().unwrap();
        state.scans += 1;
        if state.refuse_scan {
            return Err(StoreError::Unavailable);
        }
        Ok(state
            .rows
            .iter()
            .filter(|((s, key), _)| s == schema.as_str() && key.starts_with(prefix))
            .take(limit as usize)
            .map(|((_, key), value)| (key.clone(), RecordBytes::new(value.clone()).unwrap()))
            .collect())
    }
    fn claim(&self, _: &str, _: &str, _: u64, _: u64) -> Result<bool, StoreError> {
        panic!("conditional publication never claims a position")
    }
}

fn framing() -> ChainFraming {
    ChainFraming::of(&RecordChain {
        kind: 1,
        framing: CHAIN_PIPE_SEPARATED,
        flags: CHAIN_DIGESTS_SCOPE,
        _reserved: 0,
    })
    .unwrap()
}

fn operation(content: Option<&[u8]>) -> ConditionalChain {
    ConditionalChain {
        schema: EVENTS,
        scope: "principal/task".into(),
        framing: framing(),
        life: Expected::Absent,
        action: content.map_or(crate::host_chains::ConditionalChainAction::Drop, |bytes| {
            crate::host_chains::ConditionalChainAction::Append(vec![bytes.to_vec()])
        }),
    }
}

fn request(expected: Expected, value: &[u8]) -> Request {
    Request {
        version: VERSION,
        op_id: crate::door::op_id(),
        predicates: vec![Predicate {
            schema: STATE.as_str().into(),
            key: record_key(INSTANCE, b"task"),
            expected,
        }],
        mutations: vec![Mutation::Put {
            schema: STATE.as_str().into(),
            key: record_key(INSTANCE, b"task"),
            value: value.to_vec(),
        }],
    }
}

fn prepared(
    rows: &AtomicRows,
    expected: Expected,
    value: &[u8],
    content: Option<&[u8]>,
) -> Request {
    let mut request = request(expected, value);
    let mut chain = operation(content);
    chain.life =
        crate::host_chains::observe_life(rows, INSTANCE, EVENTS, "principal/task").unwrap();
    chain
        .prepare(
            rows,
            INSTANCE,
            &mut request,
            &crate::host_chains::ChainBook::default(),
        )
        .unwrap();
    request.validate().unwrap();
    request
}

#[test]
fn concurrent_genesis_has_one_atomic_winner_without_a_position_claim() {
    let rows = AtomicRows::default();
    let a = prepared(&rows, Expected::Absent, b"A", Some(b"a"));
    let b = prepared(&rows, Expected::Absent, b"B", Some(b"b"));
    assert_eq!(rows.record_transaction(&a), Ok(Decision::Applied));
    assert_eq!(rows.record_transaction(&b), Ok(Decision::ConditionConflict));
    let state = rows.0.lock().unwrap();
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.rows.len(), 2);
    assert_eq!(
        state
            .rows
            .get(&(STATE.as_str().into(), record_key(INSTANCE, b"task"))),
        Some(&b"A".to_vec())
    );
}

#[test]
fn append_and_drop_fence_each_other_in_both_orders() {
    for drop_first in [false, true] {
        let rows = AtomicRows::default();
        let seed = prepared(&rows, Expected::Absent, b"seed", Some(b"seed"));
        assert_eq!(rows.record_transaction(&seed), Ok(Decision::Applied));
        let append = prepared(
            &rows,
            Expected::Bytes(b"seed".to_vec()),
            b"append",
            Some(b"append"),
        );
        let drop = prepared(&rows, Expected::Bytes(b"seed".to_vec()), b"drop", None);
        let (first, second) = if drop_first {
            (&drop, &append)
        } else {
            (&append, &drop)
        };
        assert_eq!(rows.record_transaction(first), Ok(Decision::Applied));
        assert_eq!(
            rows.record_transaction(second),
            Ok(Decision::ConditionConflict)
        );
        assert_eq!(rows.0.lock().unwrap().receipts.len(), 2);
    }
}

#[test]
fn drop_linearizes_after_an_append_whose_task_preimage_remains_identical() {
    let rows = AtomicRows::default();
    let seed = prepared(&rows, Expected::Absent, b"same", Some(b"seed"));
    assert_eq!(rows.record_transaction(&seed), Ok(Decision::Applied));
    let stale_drop = prepared(&rows, Expected::Bytes(b"same".to_vec()), b"dropped", None);
    let append = prepared(
        &rows,
        Expected::Bytes(b"same".to_vec()),
        b"same",
        Some(b"next"),
    );
    assert_eq!(rows.record_transaction(&append), Ok(Decision::Applied));
    assert_eq!(rows.record_transaction(&stale_drop), Ok(Decision::Applied));
    assert!(rows
        .record_scan(EVENTS, &record_key(INSTANCE, b"principal/task/"), u32::MAX)
        .unwrap()
        .is_empty());
}

#[test]
fn drop_recreate_rejects_old_life_even_when_all_task_and_event_bytes_match() {
    let rows = AtomicRows::default();
    let seed = prepared(&rows, Expected::Absent, b"same", Some(b"same"));
    assert_eq!(rows.record_transaction(&seed), Ok(Decision::Applied));
    let stale = prepared(
        &rows,
        Expected::Bytes(b"same".to_vec()),
        b"stale",
        Some(b"stale"),
    );
    let drop = prepared(&rows, Expected::Bytes(b"same".to_vec()), b"same", None);
    assert_eq!(rows.record_transaction(&drop), Ok(Decision::Applied));
    let recreate = prepared(
        &rows,
        Expected::Bytes(b"same".to_vec()),
        b"same",
        Some(b"same"),
    );
    assert_eq!(rows.record_transaction(&recreate), Ok(Decision::Applied));
    assert_eq!(
        rows.record_transaction(&stale),
        Ok(Decision::ConditionConflict)
    );
    assert_eq!(
        rows.record_get(
            CHAIN_LIFE_SCHEMA,
            &crate::host_chains::life_key(INSTANCE, EVENTS, "principal/task")
        )
        .unwrap()
        .unwrap()
        .as_slice(),
        &1u64.to_be_bytes()
    );
}

#[test]
fn candidate_keeps_exact_preimage_bytes_including_json_whitespace() {
    let rows = AtomicRows::default();
    let bytes = b"{ \"state\" : 1 }";
    rows.record_put(
        STATE,
        &record_key(INSTANCE, b"task"),
        &RecordBytes::new(bytes.to_vec()).unwrap(),
    )
    .unwrap();
    let candidate = prepared(
        &rows,
        Expected::Bytes(bytes.to_vec()),
        b"next",
        Some(b"event"),
    );
    assert_eq!(
        candidate.predicates[0].expected,
        Expected::Bytes(bytes.to_vec())
    );
    assert_eq!(rows.record_transaction(&candidate), Ok(Decision::Applied));
}

#[test]
fn malformed_life_and_drop_overflow_refuse_before_submission() {
    for bytes in [vec![], vec![1], u64::MAX.to_be_bytes().to_vec()] {
        let rows = AtomicRows::default();
        rows.record_put(
            CHAIN_LIFE_SCHEMA,
            &crate::host_chains::life_key(INSTANCE, EVENTS, "principal/task"),
            &RecordBytes::new(bytes).unwrap(),
        )
        .unwrap();
        let mut candidate = request(Expected::Absent, b"next");
        match crate::host_chains::observe_life(&rows, INSTANCE, EVENTS, "principal/task") {
            Err(_) => {}
            Ok(life) => {
                let mut chain = operation(None);
                chain.life = life;
                assert!(chain
                    .prepare(
                        &rows,
                        INSTANCE,
                        &mut candidate,
                        &crate::host_chains::ChainBook::default()
                    )
                    .is_err());
            }
        }
        let state = rows.0.lock().unwrap();
        assert!(state.calls.is_empty());
        assert!(state.receipts.is_empty());
    }
}

fn queued(request: Request, answers: Arc<Mutex<Vec<ConditionalResult>>>) -> ConditionalWrite {
    ConditionalWrite::new(
        Arc::from(INSTANCE),
        zeroize::Zeroizing::new(request),
        zeroize::Zeroizing::new(vec![operation(Some(b"event"))]),
        ConditionalOwed::new(
            7,
            Box::new(move |answer| answers.lock().unwrap().push(answer)),
        ),
        None,
    )
}

#[test]
fn unknown_commit_replays_exact_body_and_identity_without_optimistic_visibility() {
    let rows = AtomicRows::default();
    rows.0.lock().unwrap().lose_reply = true;
    let pending = PendingRecords::default();
    let queue = WriteBehind::default();
    let answers = Arc::new(Mutex::new(Vec::new()));
    assert_eq!(
        queue.push_conditional(queued(
            request(Expected::Absent, b"state"),
            Arc::clone(&answers)
        )),
        Some(true)
    );
    assert_eq!(pending.queued(), 0);
    queue.flush(&pending, &rows, &crate::host_chains::ChainBook::default());
    assert!(answers.lock().unwrap().is_empty());
    assert!(!queue.idle());

    rows.record_put(
        STATE,
        &record_key(INSTANCE, b"task"),
        &RecordBytes::new(b"later".to_vec()).unwrap(),
    )
    .unwrap();
    assert!(queue.start());
    queue.flush(&pending, &rows, &crate::host_chains::ChainBook::default());
    assert!(queue.idle());
    let state = rows.0.lock().unwrap();
    assert_eq!(state.calls.len(), 2);
    assert_eq!(state.calls[0], state.calls[1]);
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(answers.lock().unwrap()[0].decision, Ok(Decision::Applied));
}

#[test]
fn pre_submission_abandonment_changes_no_rows_or_claims() {
    let rows = AtomicRows::default();
    let answers = Arc::new(Mutex::new(Vec::new()));
    drop(queued(request(Expected::Absent, b"state"), answers));
    let state = rows.0.lock().unwrap();
    assert!(state.rows.is_empty());
    assert!(state.calls.is_empty());
    assert!(state.receipts.is_empty());
}

#[test]
fn rollback_retries_same_request_and_condition_conflict_has_no_receipt() {
    let rows = AtomicRows::default();
    rows.0.lock().unwrap().fail_before_commit = true;
    let pending = PendingRecords::default();
    let queue = WriteBehind::default();
    let answers = Arc::new(Mutex::new(Vec::new()));
    queue
        .push_conditional(queued(
            request(Expected::Absent, b"state"),
            Arc::clone(&answers),
        ))
        .unwrap();
    queue.flush(&pending, &rows, &crate::host_chains::ChainBook::default());
    assert!(rows.0.lock().unwrap().rows.is_empty());
    assert!(rows.0.lock().unwrap().receipts.is_empty());
    assert!(queue.start());
    queue.flush(&pending, &rows, &crate::host_chains::ChainBook::default());
    let rejected = prepared(&rows, Expected::Absent, b"no", Some(b"no"));
    assert_eq!(
        rows.record_transaction(&rejected),
        Ok(Decision::ConditionConflict)
    );
    let state = rows.0.lock().unwrap();
    assert_eq!(state.calls[0], state.calls[1]);
    assert_eq!(state.receipts.len(), 1);
}

#[test]
fn drop_clears_fixed_width_slots_but_preserves_nested_chain_rows() {
    let rows = AtomicRows::default();
    let seed = prepared(&rows, Expected::Absent, b"seed", Some(b"seed"));
    assert_eq!(rows.record_transaction(&seed), Ok(Decision::Applied));
    let mut nested = request(Expected::Bytes(b"seed".to_vec()), b"seed");
    let nested_chain = ConditionalChain {
        scope: "principal/task/nested".into(),
        ..operation(Some(b"nested"))
    };
    nested_chain
        .prepare(
            &rows,
            INSTANCE,
            &mut nested,
            &crate::host_chains::ChainBook::default(),
        )
        .unwrap();
    assert_eq!(rows.record_transaction(&nested), Ok(Decision::Applied));
    let corrupt_key = record_key(INSTANCE, b"principal/task/xxxxxxxxxxxxxxxxxxxx");
    rows.record_put(
        EVENTS,
        &corrupt_key,
        &RecordBytes::new(b"corrupt".to_vec()).unwrap(),
    )
    .unwrap();
    let drop = prepared(&rows, Expected::Bytes(b"seed".to_vec()), b"gone", None);
    assert_eq!(rows.record_transaction(&drop), Ok(Decision::Applied));
    assert!(rows.record_get(EVENTS, &corrupt_key).unwrap().is_none());
    let nested_key = record_key(
        INSTANCE,
        &busbar_contract::services::chain_key(b"principal/task/nested", 1),
    );
    assert!(rows.record_get(EVENTS, &nested_key).unwrap().is_some());
}

#[test]
fn stale_drop_is_rejected_after_another_drop_even_on_an_empty_chain() {
    let rows = AtomicRows::default();
    let first = prepared(&rows, Expected::Absent, b"same", None);
    let second = prepared(&rows, Expected::Absent, b"same", None);
    assert_eq!(rows.record_transaction(&first), Ok(Decision::Applied));
    assert_eq!(
        rows.record_transaction(&second),
        Ok(Decision::ConditionConflict)
    );
}

#[test]
fn changed_body_operation_identity_is_distinct_from_condition_conflict() {
    let rows = AtomicRows::default();
    let candidate = prepared(&rows, Expected::Absent, b"state", Some(b"event"));
    assert_eq!(rows.record_transaction(&candidate), Ok(Decision::Applied));
    let mut changed = candidate.clone();
    changed.mutations[0] = Mutation::Put {
        schema: STATE.as_str().into(),
        key: record_key(INSTANCE, b"task"),
        value: b"different".to_vec(),
    };
    let answers = Arc::new(Mutex::new(Vec::new()));
    let mut write = queued(changed, Arc::clone(&answers));
    write.prepared = true;
    assert!(write
        .attempt(&rows, &crate::host_chains::ChainBook::default())
        .is_none());
    assert_eq!(
        answers.lock().unwrap()[0].decision,
        Err(ConditionalFailure::OpIdConflict)
    );
}

#[test]
fn replay_horizon_reports_indeterminate_without_new_dispatch_or_loss_of_custody() {
    let rows = AtomicRows::default();
    let answers = Arc::new(Mutex::new(Vec::new()));
    let mut write = queued(request(Expected::Absent, b"state"), Arc::clone(&answers));
    write.prepared = true;
    write.submitted = Some(
        std::time::Instant::now()
            - std::time::Duration::from_secs(busbar_contract::abi::store::OP_ID_RETENTION_SECS),
    );
    let identity = write.request.clone();
    let retained = write
        .attempt(&rows, &crate::host_chains::ChainBook::default())
        .expect("expired ambiguous operation remains owned");
    assert_eq!(retained.request, identity);
    assert_eq!(
        answers.lock().unwrap()[0].decision,
        Err(ConditionalFailure::Indeterminate)
    );
    assert!(rows.0.lock().unwrap().calls.is_empty());
    assert!(retained
        .attempt(&rows, &crate::host_chains::ChainBook::default())
        .is_some());
    assert_eq!(answers.lock().unwrap().len(), 1);
}

struct Inline;
impl crate::host_services::Offload for Inline {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
}

fn caller() -> busbar_contract::services::Caller {
    busbar_contract::services::Caller {
        instance: Arc::from(INSTANCE),
        plugin: Arc::from("plane"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    }
}

fn logical() -> ConditionalCandidate {
    ConditionalCandidate {
        correlation: 11,
        predicates: vec![RecordPredicate {
            kind: 0,
            key: b"task".to_vec(),
            expected: Expected::Absent,
        }],
        mutations: vec![RecordMutation::Put {
            kind: 0,
            key: b"task".to_vec(),
            value: b"state".to_vec(),
        }],
        chains: vec![ChainMutation::Append {
            kind: 1,
            scope: b"principal/task".to_vec(),
            life: Expected::Absent,
            content: b"event".to_vec(),
        }],
    }
}

fn services(rows: Arc<AtomicRows>, opted_in: bool) -> crate::host_services::KernelServices {
    let services = crate::host_services::KernelServices::new()
        .with_records(rows)
        .with_pool(Arc::new(Inline));
    services
        .admit(
            INSTANCE,
            crate::host_services::InstanceFacts {
                record_kinds: vec![STATE, EVENTS, RecordSchemaId::new("cache")],
                conditional_record_kinds: if opted_in { vec![0, 1] } else { Vec::new() },
                record_chains: vec![RecordChain {
                    kind: 1,
                    framing: CHAIN_PIPE_SEPARATED,
                    flags: CHAIN_DIGESTS_SCOPE,
                    _reserved: 0,
                }],
                ..Default::default()
            },
        )
        .unwrap();
    services
}

#[test]
fn opted_in_host_translates_only_declared_kinds_and_preserves_logical_scope() {
    let rows = Arc::new(AtomicRows::default());
    let services = services(Arc::clone(&rows), true);
    let answers = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&answers);
    services
        .record_transaction(
            &caller(),
            None,
            logical(),
            Box::new(move |answer| into.lock().unwrap().push(answer)),
        )
        .unwrap();
    assert_eq!(answers.lock().unwrap()[0].decision, Ok(Decision::Applied));
    assert_eq!(
        rows.0.lock().unwrap().calls[0].predicates[0].key,
        record_key(INSTANCE, b"task")
    );
    assert_eq!(services.pending().queued(), 0);
    let mut bad = logical();
    bad.predicates[0].kind = 99;
    assert!(services
        .record_transaction(&caller(), None, bad, Box::new(|_| panic!("no dispatch")))
        .is_err());
    assert_eq!(rows.0.lock().unwrap().calls.len(), 1);
}

#[test]
fn opt_in_refuses_legacy_writes_and_mixed_chain_operations_before_effects() {
    let rows = Arc::new(AtomicRows::default());
    let host = services(Arc::clone(&rows), true);
    assert!(host
        .record_write(
            &caller(),
            STATE.as_str(),
            b"task",
            RecordBytes::new(b"unsafe".to_vec()).unwrap(),
            Box::new(|_| panic!("no legacy ACK"))
        )
        .is_err());
    let mut candidate = logical();
    candidate.chains.push(ChainMutation::Drop {
        kind: 1,
        scope: b"principal/task".to_vec(),
        life: Expected::Absent,
    });
    assert!(host
        .record_transaction(
            &caller(),
            None,
            candidate,
            Box::new(|_| panic!("no candidate ACK"))
        )
        .is_err());
    assert!(rows.0.lock().unwrap().rows.is_empty());
    assert_eq!(host.pending().queued(), 0);
    let ordinary = services(Arc::new(AtomicRows::default()), false);
    assert!(ordinary
        .record_transaction(
            &caller(),
            None,
            logical(),
            Box::new(|_| panic!("not opted in"))
        )
        .is_err());
}

#[test]
fn submitted_request_survives_caller_unit_retirement() {
    let rows = Arc::new(AtomicRows::default());
    rows.0.lock().unwrap().lose_reply = true;
    let host = services(Arc::clone(&rows), true);
    host.units()
        .admitted(71, crate::host_units::UnitRecord::default());

    let receiver_alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let callback_alive = Arc::clone(&receiver_alive);
    host.record_transaction(
        &caller(),
        Some(71),
        logical(),
        Box::new(move |answer| {
            assert!(!callback_alive.load(Ordering::Relaxed));
            assert_eq!(answer.decision, Ok(Decision::Applied));
        }),
    )
    .unwrap();
    receiver_alive.store(false, Ordering::Relaxed);
    host.units().ended(71);
    host.flush_tick();
    let state = rows.0.lock().unwrap();
    assert_eq!(state.calls.len(), 2);
    assert_eq!(state.calls[0], state.calls[1]);
    assert_eq!(state.receipts.len(), 1);
}

#[test]
fn later_refusal_does_not_discard_an_earlier_unknown_commit() {
    let rows = AtomicRows::default();
    rows.0.lock().unwrap().lose_reply = true;
    let answers = Arc::new(Mutex::new(Vec::new()));
    let write = queued(request(Expected::Absent, b"state"), Arc::clone(&answers));
    let unknown = write
        .attempt(&rows, &crate::host_chains::ChainBook::default())
        .unwrap();
    rows.0.lock().unwrap().refuse = true;
    let still_unknown = unknown
        .attempt(&rows, &crate::host_chains::ChainBook::default())
        .expect("refused retry does not settle earlier commit");
    assert!(answers.lock().unwrap().is_empty());
    rows.0.lock().unwrap().refuse = false;
    assert!(still_unknown
        .attempt(&rows, &crate::host_chains::ChainBook::default())
        .is_none());
    assert_eq!(answers.lock().unwrap()[0].decision, Ok(Decision::Applied));
    let state = rows.0.lock().unwrap();
    assert_eq!(state.calls[0], state.calls[1]);
    assert_eq!(state.calls[1], state.calls[2]);
}

#[test]
fn selected_kind_fence_preserves_unrelated_cache_writes() {
    let rows = Arc::new(AtomicRows::default());
    let host = services(Arc::clone(&rows), true);
    let answered = Arc::new(Mutex::new(None));
    let into = Arc::clone(&answered);
    host.record_write(
        &caller(),
        "cache",
        b"entry",
        RecordBytes::new(b"cached".to_vec()).unwrap(),
        Box::new(move |result| *into.lock().unwrap() = Some(result)),
    )
    .unwrap();
    assert_eq!(*answered.lock().unwrap(), Some(Ok(())));
    let mut candidate = logical();
    candidate.mutations.push(RecordMutation::Delete {
        kind: 2,
        key: b"entry".to_vec(),
    });
    assert!(host
        .record_transaction(
            &caller(),
            None,
            candidate,
            Box::new(|_| panic!("unselected kind"))
        )
        .is_err());
    assert!(rows.0.lock().unwrap().calls.is_empty());
}

#[test]
fn invalid_or_repeated_conditional_kind_is_refused_at_admission() {
    for required in [vec![1], vec![0, 0]] {
        let host = crate::host_services::KernelServices::new();
        assert!(matches!(
            host.admit(
                INSTANCE,
                crate::host_services::InstanceFacts {
                    record_kinds: vec![STATE],
                    conditional_record_kinds: required,
                    ..Default::default()
                }
            ),
            Err(crate::host_services::AdmitRefused::ConditionalKind { .. })
        ));
    }
}

#[test]
fn absent_life_is_not_equivalent_to_present_zero_bytes() {
    let rows = AtomicRows::default();
    let candidate = prepared(&rows, Expected::Absent, b"state", Some(b"event"));
    rows.record_put(
        CHAIN_LIFE_SCHEMA,
        &crate::host_chains::life_key(INSTANCE, EVENTS, "principal/task"),
        &RecordBytes::new(0u64.to_be_bytes().to_vec()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        rows.record_transaction(&candidate),
        Ok(Decision::ConditionConflict)
    );
    assert!(rows.0.lock().unwrap().receipts.is_empty());
}

struct UnsupportedRows(Arc<AtomicRows>);
impl RecordRows for UnsupportedRows {
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError> {
        self.0.record_put(schema, key, value)
    }
    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        self.0.record_get(schema, key)
    }
    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        self.0.record_scan(schema, prefix, limit)
    }
    fn claim(&self, _: &str, _: &str, _: u64, _: u64) -> Result<bool, StoreError> {
        panic!("no claims")
    }
}

#[test]
fn missing_store_capability_refuses_before_transaction_dispatch() {
    let rows = Arc::new(AtomicRows::default());
    let host = crate::host_services::KernelServices::new()
        .with_records(Arc::new(UnsupportedRows(Arc::clone(&rows))))
        .with_pool(Arc::new(Inline));
    host.admit(
        INSTANCE,
        crate::host_services::InstanceFacts {
            record_kinds: vec![STATE],
            conditional_record_kinds: vec![0],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!host.supports_record_transactions());
    let mut candidate = logical();
    candidate.chains.clear();
    assert!(host
        .record_transaction(
            &caller(),
            None,
            candidate,
            Box::new(|_| panic!("no submission"))
        )
        .is_err());
    let state = rows.0.lock().unwrap();
    assert!(state.calls.is_empty());
    assert!(state.rows.is_empty());
}

#[test]
fn read_bound_life_rejects_drop_recreate_before_first_submission() {
    let rows = AtomicRows::default();
    let seed = prepared(&rows, Expected::Absent, b"same", Some(b"same"));
    assert_eq!(rows.record_transaction(&seed), Ok(Decision::Applied));

    let original_life =
        crate::host_chains::observe_life(&rows, INSTANCE, EVENTS, "principal/task").unwrap();
    let original_task = rows
        .record_get(STATE, &record_key(INSTANCE, b"task"))
        .unwrap()
        .unwrap();
    let drop = prepared(&rows, Expected::Bytes(b"same".to_vec()), b"same", None);
    assert_eq!(rows.record_transaction(&drop), Ok(Decision::Applied));
    let recreated = prepared(
        &rows,
        Expected::Bytes(b"same".to_vec()),
        b"same",
        Some(b"same"),
    );
    assert_eq!(rows.record_transaction(&recreated), Ok(Decision::Applied));

    let mut stale = request(Expected::Bytes(original_task.as_slice().to_vec()), b"stale");
    let mut append = operation(Some(b"stale"));
    append.life = original_life;
    append
        .prepare(
            &rows,
            INSTANCE,
            &mut stale,
            &crate::host_chains::ChainBook::default(),
        )
        .unwrap();
    assert_eq!(
        rows.record_transaction(&stale),
        Ok(Decision::ConditionConflict)
    );
    assert_eq!(rows.0.lock().unwrap().receipts.len(), 3);
}

#[test]
fn read_bound_life_also_fences_a_plain_config_write_without_chain_mutation() {
    let rows = AtomicRows::default();
    let original_life =
        crate::host_chains::observe_life(&rows, INSTANCE, EVENTS, "principal/task").unwrap();
    let drop = prepared(&rows, Expected::Absent, b"same", None);
    assert_eq!(rows.record_transaction(&drop), Ok(Decision::Applied));
    let mut stale = request(Expected::Bytes(b"same".to_vec()), b"config-change");
    let mut fence = operation(None);
    fence.life = original_life;
    fence.action = crate::host_chains::ConditionalChainAction::Check;
    fence
        .prepare(
            &rows,
            INSTANCE,
            &mut stale,
            &crate::host_chains::ChainBook::default(),
        )
        .unwrap();
    assert_eq!(
        rows.record_transaction(&stale),
        Ok(Decision::ConditionConflict)
    );
}

#[test]
fn observation_returns_exact_absence_and_bytes_under_declared_instance_scope() {
    let rows = Arc::new(AtomicRows::default());
    let host = services(Arc::clone(&rows), true);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&observed);
    host.observe_chain_life(
        &caller(),
        1,
        b"principal/task",
        Box::new(move |life| into.lock().unwrap().push(life)),
    )
    .unwrap();
    assert_eq!(observed.lock().unwrap()[0], Ok(Expected::Absent));
    rows.record_put(
        CHAIN_LIFE_SCHEMA,
        &crate::host_chains::life_key(INSTANCE, EVENTS, "principal/task"),
        &RecordBytes::new(2u64.to_be_bytes().to_vec()).unwrap(),
    )
    .unwrap();
    let into = Arc::clone(&observed);
    host.observe_chain_life(
        &caller(),
        1,
        b"principal/task",
        Box::new(move |life| into.lock().unwrap().push(life)),
    )
    .unwrap();
    assert_eq!(
        observed.lock().unwrap()[1],
        Ok(Expected::Bytes(2u64.to_be_bytes().to_vec()))
    );
    assert!(host
        .observe_chain_life(
            &caller(),
            0,
            b"principal/task",
            Box::new(|_| panic!("not a chain"))
        )
        .is_err());
}

#[test]
fn selected_schema_alias_cannot_admit_a_plain_writer_into_chain_storage() {
    let rows = Arc::new(AtomicRows::default());
    let host = crate::host_services::KernelServices::new()
        .with_records(rows.clone())
        .with_pool(Arc::new(Inline));
    assert!(host
        .admit(
            INSTANCE,
            crate::host_services::InstanceFacts {
                record_kinds: vec![EVENTS, EVENTS],
                conditional_record_kinds: vec![0, 1],
                record_chains: vec![RecordChain {
                    kind: 0,
                    framing: CHAIN_PIPE_SEPARATED,
                    flags: 0,
                    _reserved: 0
                }],
                ..Default::default()
            }
        )
        .is_err());
    let candidate = ConditionalCandidate {
        correlation: 1,
        predicates: vec![RecordPredicate {
            kind: 1,
            key: b"scope/00000000000000000001".to_vec(),
            expected: Expected::Absent,
        }],
        mutations: vec![RecordMutation::Put {
            kind: 1,
            key: b"scope/00000000000000000001".to_vec(),
            value: b"unframed".to_vec(),
        }],
        chains: vec![],
    };
    assert!(host
        .record_transaction(
            &caller(),
            None,
            candidate,
            Box::new(|_| panic!("alias must never dispatch"))
        )
        .is_err());
    assert!(rows.0.lock().unwrap().rows.is_empty());
    assert!(rows.0.lock().unwrap().calls.is_empty());

    assert!(host
        .admit(
            INSTANCE,
            crate::host_services::InstanceFacts {
                record_kinds: vec![EVENTS, EVENTS],
                ..Default::default()
            }
        )
        .is_ok());
}

#[test]
fn check_and_drop_never_scan_history_and_retire_exhausted_or_corrupt_slots() {
    let rows = AtomicRows::default();
    rows.0.lock().unwrap().refuse_scan = true;
    rows.record_put(
        EVENTS,
        &record_key(
            INSTANCE,
            &busbar_contract::services::chain_key(b"principal/task", u64::MAX),
        ),
        &RecordBytes::new(b"corrupt tail".to_vec()).unwrap(),
    )
    .unwrap();
    let book = crate::host_chains::ChainBook::default();
    let mut check = operation(None);
    check.action = crate::host_chains::ConditionalChainAction::Check;
    let mut checked = request(Expected::Absent, b"same");
    check.prepare(&rows, INSTANCE, &mut checked, &book).unwrap();
    assert_eq!(checked.predicates.len(), 2);
    assert_eq!(rows.record_transaction(&checked), Ok(Decision::Applied));
    let mut drop = request(Expected::Bytes(b"same".to_vec()), b"gone");
    operation(None)
        .prepare(&rows, INSTANCE, &mut drop, &book)
        .unwrap();
    assert_eq!(rows.record_transaction(&drop), Ok(Decision::Applied));
    let state = rows.0.lock().unwrap();
    assert_eq!(state.scans, 0);
    assert!(!state
        .rows
        .keys()
        .any(|(schema, _)| schema == EVENTS.as_str()));
}

#[test]
fn two_ordered_appends_use_one_fence_and_link_frames_in_one_atomic_publication() {
    let rows = Arc::new(AtomicRows::default());
    let host = services(rows.clone(), true);
    let mut candidate = logical();
    candidate.chains.push(ChainMutation::Append {
        kind: 1,
        scope: b"principal/task".to_vec(),
        life: Expected::Absent,
        content: b"delegated".to_vec(),
    });
    host.record_transaction(
        &caller(),
        None,
        candidate,
        Box::new(|answer| assert_eq!(answer.decision, Ok(Decision::Applied))),
    )
    .unwrap();
    let state = rows.0.lock().unwrap();
    assert_eq!(state.calls.len(), 1);
    let call = &state.calls[0];
    assert_eq!(
        call.predicates
            .iter()
            .filter(|p| p.schema == CHAIN_LIFE_SCHEMA.as_str())
            .count(),
        1
    );
    let mut frames = Vec::new();
    for mutation in &call.mutations {
        if let Mutation::Put { schema, value, .. } = mutation {
            if schema == EVENTS.as_str() {
                frames
                    .push(crate::host_chains::decode("principal/task", value, framing()).unwrap());
            }
        }
    }
    use crate::audit::journal::NeutralRecord;
    use crate::audit::ChainedRecord;
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].seq(), 1);
    assert_eq!(frames[1].seq(), 2);
    crate::audit::verify_chain(&frames).unwrap();
    assert_eq!(frames[1].content(), b"delegated");
}

#[test]
fn steady_state_append_uses_committed_position_without_rescanning_history() {
    let rows = Arc::new(AtomicRows::default());
    let host = services(rows.clone(), true);
    host.record_transaction(
        &caller(),
        None,
        logical(),
        Box::new(|answer| assert_eq!(answer.decision, Ok(Decision::Applied))),
    )
    .unwrap();
    rows.0.lock().unwrap().refuse_scan = true;
    let mut next = logical();
    next.correlation = 12;
    next.predicates[0].expected = Expected::Bytes(b"state".to_vec());
    host.record_transaction(
        &caller(),
        None,
        next,
        Box::new(|answer| assert_eq!(answer.decision, Ok(Decision::Applied))),
    )
    .unwrap();
    let state = rows.0.lock().unwrap();
    assert_eq!(state.scans, 1);
    assert_eq!(state.calls.len(), 2);
}

#[test]
fn delayed_applied_receipt_does_not_regress_a_newer_committed_chain_position() {
    let rows = AtomicRows::default();
    let book = crate::host_chains::ChainBook::default();
    let mut first = request(Expected::Absent, b"a");
    let first_position = operation(Some(b"a"))
        .prepare(&rows, INSTANCE, &mut first, &book)
        .unwrap();
    assert_eq!(rows.record_transaction(&first), Ok(Decision::Applied));
    let mut next = request(Expected::Bytes(b"a".to_vec()), b"c");
    let next_position = operation(Some(b"c"))
        .prepare(&rows, INSTANCE, &mut next, &book)
        .unwrap();
    assert_eq!(rows.record_transaction(&next), Ok(Decision::Applied));
    book.conditional_settled(&next_position, Decision::Applied);
    book.conditional_settled(&first_position, Decision::Applied);
    rows.0.lock().unwrap().refuse_scan = true;
    let mut third = request(Expected::Bytes(b"c".to_vec()), b"d");
    operation(Some(b"d"))
        .prepare(&rows, INSTANCE, &mut third, &book)
        .unwrap();
    assert_eq!(rows.record_transaction(&third), Ok(Decision::Applied));
    assert_eq!(rows.0.lock().unwrap().scans, 2);
}

#[test]
fn repeated_append_requires_identical_original_life_observations() {
    let rows = Arc::new(AtomicRows::default());
    let host = services(rows.clone(), true);
    let mut candidate = logical();
    candidate.chains.push(ChainMutation::Append {
        kind: 1,
        scope: b"principal/task".to_vec(),
        life: Expected::Bytes(0u64.to_be_bytes().to_vec()),
        content: b"second".to_vec(),
    });
    assert!(host
        .record_transaction(
            &caller(),
            None,
            candidate,
            Box::new(|_| panic!("conflicting life"))
        )
        .is_err());
    let state = rows.0.lock().unwrap();
    assert!(state.calls.is_empty());
    assert!(state.rows.is_empty());
}

#[test]
fn conflicting_append_invalidates_stale_committed_hint_before_fresh_resume() {
    let rows = AtomicRows::default();
    let book = crate::host_chains::ChainBook::default();
    let mut first = request(Expected::Absent, b"a");
    let first_position = operation(Some(b"a"))
        .prepare(&rows, INSTANCE, &mut first, &book)
        .unwrap();
    assert_eq!(rows.record_transaction(&first), Ok(Decision::Applied));
    book.conditional_settled(&first_position, Decision::Applied);
    let remote = prepared(&rows, Expected::Bytes(b"a".to_vec()), b"b", Some(b"b"));
    assert_eq!(rows.record_transaction(&remote), Ok(Decision::Applied));
    let mut stale = request(Expected::Bytes(b"b".to_vec()), b"c");
    let position = operation(Some(b"c"))
        .prepare(&rows, INSTANCE, &mut stale, &book)
        .unwrap();
    assert_eq!(
        rows.record_transaction(&stale),
        Ok(Decision::ConditionConflict)
    );
    book.conditional_settled(&position, Decision::ConditionConflict);
    let mut retry = request(Expected::Bytes(b"b".to_vec()), b"c");
    operation(Some(b"c"))
        .prepare(&rows, INSTANCE, &mut retry, &book)
        .unwrap();
    assert_eq!(rows.record_transaction(&retry), Ok(Decision::Applied));
    assert_eq!(rows.0.lock().unwrap().scans, 3);
}
