// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use crate::persistence::host_records::tests::{attach, Backend};
use std::sync::atomic::Ordering;

fn binding() -> Binding {
    Binding {
        principal: "principal".into(),
        group: "group-at-admission".into(),
        instance: "fixture".into(),
        destination: "destination".into(),
        accounting_namespace: "account".into(),
        serving_subject: "serving".into(),
        rate_time: 100,
        subjects: vec![
            RatedSubject {
                name: "serving".into(),
                rates_nanos: BTreeMap::from([(0, 10)]),
            },
            RatedSubject {
                name: "leaf".into(),
                rates_nanos: BTreeMap::from([(0, 30)]),
            },
        ],
        budgets: vec![BudgetBinding {
            id: "budget@0".into(),
            limit_nanos: 10000,
            reserve_nanos: 1000,
        }],
        ordered_revisions: true,
        classes: BTreeMap::from([(0, "work".into())]),
    }
}
async fn setup() -> (Arc<Backend>, ObservationStore, BoundScope) {
    let backend = Arc::new(Backend::default());
    let owner = ObservationStore::open(Arc::new(attach(backend.clone()).await)).unwrap();
    let id = owner.create_scope(binding()).await.unwrap();
    let scope = owner.bind_scope(id, binding().identity()).await.unwrap();
    (backend, owner, scope)
}
fn final_usage(scope: ScopeId, n: u64, revision: u64) -> Observation {
    Observation::new(scope, b"event".to_vec(), b"component".to_vec())
        .count(0, Count::from(n))
        .unwrap()
        .revision(revision.to_be_bytes().to_vec(), revision)
        .final_totals()
}
#[tokio::test]
async fn two_nodes_duplicate_final_and_restart_correction_settle_once() {
    use busbar_contract::persistence::{
        BackendInfo, Call, ClockObservation, DatasetId, Page, PersistenceBackend, Scan,
    };
    struct YieldRead(Arc<Backend>);
    impl PersistenceBackend for YieldRead {
        fn info(&self) -> BackendInfo {
            self.0.info()
        }
        fn read(&self, r: Arc<Read>) -> Call<'_, ReadResult> {
            Box::pin(async move {
                let result = self.0.read(r).await;
                // Both nodes retain the same old snapshot before either can commit.
                tokio::task::yield_now().await;
                result
            })
        }
        fn scan(&self, r: Arc<Scan>) -> Call<'_, Page> {
            self.0.scan(r)
        }
        fn commit(&self, r: PreparedCandidate) -> Call<'_, Decision> {
            self.0.commit(r)
        }
        fn clock(&self, d: DatasetId) -> Call<'_, ClockObservation> {
            self.0.clock(d)
        }
    }
    async fn node(backend: Arc<Backend>) -> ObservationStore {
        let store = CoreStore::attach(
            Arc::new(YieldRead(backend)),
            super::super::facade::WriterAuthority {
                writer_epoch: 2,
                writer: [4; 16],
                execution_epoch: 3,
            },
            super::super::facade::Limits {
                pending_operations: 16,
                conflict_retries: 8,
                scan_items: 32,
                scan_bytes: 65536,
            },
        )
        .await
        .unwrap();
        ObservationStore::open(Arc::new(store)).unwrap()
    }
    let backend = Arc::new(Backend::default());
    let owner = node(backend.clone()).await;
    assert!(!owner.has_accounting().await.unwrap());
    let id = owner.create_scope(binding()).await.unwrap();
    let scope = owner.bind_scope(id, binding().identity()).await.unwrap();
    let other = node(backend.clone()).await;
    let second = other
        .bind_scope(scope.id(), binding().identity())
        .await
        .unwrap();
    let observation = final_usage(scope.id(), 20, 1);
    let (a, b) = tokio::join!(
        owner.submit(&scope, &observation, 110),
        other.submit(&second, &observation, 111)
    );
    assert_ne!(a.unwrap().duplicate, b.unwrap().duplicate);
    assert_eq!(owner.budget("budget@0").await.unwrap().spent_nanos, 200);
    owner.close_scope(&scope).await.unwrap();
    assert_eq!(owner.budget("budget@0").await.unwrap().reserved_nanos, 0);
    drop(owner);
    drop(other);
    let restarted = ObservationStore::open(Arc::new(attach(backend).await)).unwrap();
    let bound = restarted
        .bind_scope(scope.id(), binding().identity())
        .await
        .unwrap();
    restarted
        .submit(&bound, &final_usage(scope.id(), 12, 2), 99999)
        .await
        .unwrap();
    assert_eq!(restarted.budget("budget@0").await.unwrap().spent_nanos, 120);
    let replay = restarted
        .submit(&bound, &observation, 999999)
        .await
        .unwrap();
    assert!(replay.duplicate && !replay.quarantined);
    assert!(restarted.has_accounting().await.unwrap());
    let journal = restarted.journal(&bound).await.unwrap();
    assert_eq!(journal.len(), 2);
    assert_eq!(journal.iter().map(|j| j.nanos_delta).sum::<i128>(), 120);
    assert!(journal.iter().all(|j| j.accounting_time == 100));
    let records = restarted.dated_records().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].group, "group-at-admission");
    assert_eq!(records[0].serving_subject, "serving");
    assert_eq!(records[0].rate_time, 100);
    assert_eq!(records[0].spent_nanos, 120);
    assert_eq!(restarted.dated_records_for_day(0).await.unwrap(), records);
    assert!(restarted
        .dated_records_for_day(86400)
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        restarted.dated_records_for_day(1).await,
        Err(Error::Invalid)
    ));
    assert_eq!(
        restarted.dated_total(&bound, 0).await.unwrap().counts[&0],
        Count::from(12)
    );
}
#[tokio::test]
async fn lost_ack_and_cancel_do_not_lose_or_reapply_committed_liability() {
    let (backend, owner, scope) = setup().await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    let observation = final_usage(scope.id(), 9, 1);
    let error = owner.submit(&scope, &observation, 110).await.unwrap_err();
    let Error::Pending {
        operation,
        scope: id,
    } = error
    else {
        panic!("expected pending")
    };
    assert_eq!(owner.budget("budget@0").await.unwrap().spent_nanos, 90);
    assert!(owner.retry(operation, id).await.unwrap());
    assert!(
        owner
            .submit(&scope, &observation, 120)
            .await
            .unwrap()
            .duplicate
    );
    assert_eq!(owner.journal(&scope).await.unwrap().len(), 1);
    backend.hang.store(true, Ordering::SeqCst);
    let correction = final_usage(scope.id(), 10, 2);
    {
        let pending = owner.submit(&scope, &correction, 130);
        tokio::pin!(pending);
        assert!(futures::poll!(&mut pending).is_pending());
    }
    backend.hang.store(false, Ordering::SeqCst);
    // The accepted earlier final remains authoritative through cancellation.
    assert_eq!(owner.budget("budget@0").await.unwrap().spent_nanos, 90);
    let restarted = ObservationStore::open(Arc::new(attach(backend).await)).unwrap();
    restarted.submit(&scope, &correction, 140).await.unwrap();
    assert_eq!(restarted.budget("budget@0").await.unwrap().spent_nanos, 100);
}
#[tokio::test]
async fn provisional_unknown_and_quarantined_revisions_keep_reservations() {
    let (_, owner, scope) = setup().await;
    let mut observation = final_usage(scope.id(), 10, 1);
    observation.state = State::Provisional;
    owner.submit(&scope, &observation, 110).await.unwrap();
    assert_eq!(
        owner.budget("budget@0").await.unwrap(),
        BudgetTotal {
            spent_nanos: 0,
            reserved_nanos: 1000,
            units: BTreeMap::new(),
        }
    );
    assert!(owner.close_scope(&scope).await.is_err());
    observation.state = State::Final;
    owner.submit(&scope, &observation, 120).await.unwrap();
    assert!(
        owner
            .submit(&scope, &final_usage(scope.id(), 20, 1), 130)
            .await
            .unwrap()
            .quarantined
    );
    // Same totals can advance the ordering watermark without creating spend.
    owner
        .submit(&scope, &final_usage(scope.id(), 10, 3), 140)
        .await
        .unwrap();
    assert!(
        owner
            .submit(&scope, &final_usage(scope.id(), 12, 2), 150)
            .await
            .unwrap()
            .quarantined
    );
    assert_eq!(owner.budget("budget@0").await.unwrap().spent_nanos, 100);
}
#[tokio::test]
async fn owner_subject_account_namespace_and_missing_tariff_are_enforced() {
    let (_, owner, scope) = setup().await;
    let mut intruder = binding().identity();
    intruder.principal = "other".into();
    assert!(matches!(
        owner.bind_scope(scope.id(), intruder).await,
        Err(Error::Unauthorized)
    ));
    let escaped = final_usage(scope.id(), 1, 1).rated_to(99);
    assert!(matches!(
        owner.submit(&scope, &escaped, 110).await,
        Err(Error::Unauthorized)
    ));
    let unpriced = Observation::new(scope.id(), vec![1], vec![2])
        .count(99, Count::ONE)
        .unwrap()
        .final_totals();
    assert!(matches!(
        owner.submit(&scope, &unpriced, 110).await,
        Err(Error::Unpriced)
    ));
    owner
        .submit(&scope, &final_usage(scope.id(), 2, 1).rated_to(1), 120)
        .await
        .unwrap();
    assert_eq!(owner.budget("budget@0").await.unwrap().spent_nanos, 60);
    let duplicate_id = owner.create_scope(binding()).await.unwrap();
    let duplicate_scope = owner
        .bind_scope(duplicate_id, binding().identity())
        .await
        .unwrap();
    assert!(matches!(
        owner
            .submit(&duplicate_scope, &final_usage(duplicate_id, 2, 1), 120)
            .await,
        Err(Error::Unauthorized)
    ));
    let mut separate = binding();
    separate.accounting_namespace = "another-account".into();
    let id = owner.create_scope(separate.clone()).await.unwrap();
    let another = owner.bind_scope(id, separate.identity()).await.unwrap();
    owner
        .submit(&another, &final_usage(id, 2, 1), 130)
        .await
        .unwrap();
    assert_eq!(owner.budget("budget@0").await.unwrap().spent_nanos, 80);
}

#[tokio::test]
async fn correction_quarantine_after_close_restores_durable_reconciliation_liability() {
    let (backend, owner, scope) = setup().await;
    assert_eq!(
        owner.pending_scopes(&binding().identity()).await.unwrap(),
        vec![scope.id()]
    );
    owner
        .submit(&scope, &final_usage(scope.id(), 10, 1), 110)
        .await
        .unwrap();
    owner.close_scope(&scope).await.unwrap();
    assert!(owner
        .pending_scopes(&binding().identity())
        .await
        .unwrap()
        .is_empty());
    owner
        .submit(&scope, &final_usage(scope.id(), 20, 1), 120)
        .await
        .unwrap();
    assert_eq!(owner.budget("budget@0").await.unwrap().reserved_nanos, 1000);
    assert!(owner.close_scope(&scope).await.is_err());
    let restarted = ObservationStore::open(Arc::new(attach(backend).await)).unwrap();
    assert_eq!(
        restarted
            .pending_scopes(&binding().identity())
            .await
            .unwrap(),
        vec![scope.id()]
    );
    let mut new_component = final_usage(scope.id(), 1, 2);
    new_component.component_key = b"unapproved-late-component".to_vec();
    assert!(matches!(
        restarted.submit(&scope, &new_component, 130).await,
        Err(Error::Closed)
    ));
    restarted
        .submit(&scope, &final_usage(scope.id(), 20, 2), 140)
        .await
        .unwrap();
    restarted.close_scope(&scope).await.unwrap();
    assert_eq!(
        restarted.budget("budget@0").await.unwrap(),
        BudgetTotal {
            spent_nanos: 200,
            reserved_nanos: 0,
            units: BTreeMap::from([(
                "serving".into(),
                BTreeMap::from([("work".into(), Count::from(20))])
            )]),
        }
    );
}

#[tokio::test]
async fn ephemeral_store_never_advertises_observation_capability() {
    use busbar_contract::persistence::{
        BackendInfo, Call, ClockObservation, DatasetId, Page, PersistenceBackend, Scan,
    };
    struct Ephemeral(Backend);
    impl PersistenceBackend for Ephemeral {
        fn info(&self) -> BackendInfo {
            let mut info = self.0.info();
            info.durability = Durability::Ephemeral;
            info
        }
        fn read(&self, r: Arc<Read>) -> Call<'_, ReadResult> {
            self.0.read(r)
        }
        fn scan(&self, r: Arc<Scan>) -> Call<'_, Page> {
            self.0.scan(r)
        }
        fn commit(&self, r: PreparedCandidate) -> Call<'_, Decision> {
            self.0.commit(r)
        }
        fn clock(&self, d: DatasetId) -> Call<'_, ClockObservation> {
            self.0.clock(d)
        }
    }
    let store = CoreStore::attach(
        Arc::new(Ephemeral(Backend::default())),
        super::super::facade::WriterAuthority {
            writer_epoch: 2,
            writer: [4; 16],
            execution_epoch: 3,
        },
        super::super::facade::Limits {
            pending_operations: 16,
            conflict_retries: 8,
            scan_items: 32,
            scan_bytes: 65536,
        },
    )
    .await
    .unwrap();
    assert!(!ObservationStore::supports(&store));
    assert!(matches!(
        ObservationStore::open(Arc::new(store)),
        Err(Error::UnsupportedStore)
    ));
}
