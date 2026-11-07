// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Faults wrap the actual primitive Store ABI. Domain planning and receipts still
//! execute in CoreStore; no synchronous business Store adapter participates.
use super::*;
use crate::persistence::facade::CoreStore;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Mutation, Page,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::records::correction::{UsageAddress, UsageChange};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
};

pub(super) type Hook = Box<dyn FnOnce() -> futures::future::BoxFuture<'static, ()> + Send>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ObservedCorrection {
    pub op_id: busbar_contract::records::OpId,
    pub usage: Vec<UsageChange>,
    fingerprint: [u8; 32],
}
#[derive(Default)]
pub(super) struct Faults {
    pub down: AtomicBool,
    pub usage_read_down: AtomicBool,
    pub readonly: AtomicBool,
    pub meter_fail_n: AtomicI64,
    pub meter_calls: AtomicUsize,
    pub meter_in_flight: AtomicUsize,
    pub meter_high_water: AtomicUsize,
    pub meter_down: AtomicBool,
    pub era_down: AtomicBool,
    pub before_add: Mutex<Option<Hook>>,
    pub lose_correction_reply: AtomicBool,
    pub lose_usage_reply: AtomicBool,
    pub unwind_usage: AtomicBool,
    pub correction_calls: Mutex<Vec<ObservedCorrection>>,
}
#[derive(serde::Deserialize)]
struct StoredLedger {
    version: u32,
    record: UsageLedger,
}
fn ledger(value: &busbar_contract::Secret<Vec<u8>>) -> UsageLedger {
    let value: StoredLedger = serde_json::from_slice(value.expose(&crate::seal::lend())).unwrap();
    assert_eq!(value.version, 1);
    value.record
}
pub(super) fn usage_changes(prepared: &PreparedCandidate) -> Vec<UsageChange> {
    prepared
        .candidate()
        .mutations
        .iter()
        .filter_map(|mutation| {
            let Mutation::Put { address, value } = mutation else {
                return None;
            };
            let parts = crate::persistence::keys::components(&address.key, b'U').ok()?;
            let [family, bucket, window] = parts.as_slice() else {
                return None;
            };
            if *family != crate::governance::persistence::ledger::USAGE.0 {
                return None;
            }
            let expected = prepared
                .candidate()
                .predicates
                .iter()
                .find(|p| p.address == *address)
                .map(|p| match &p.expected {
                    busbar_contract::persistence::ExpectedValue::Absent => UsageLedger::default(),
                    busbar_contract::persistence::ExpectedValue::Exact(value) => ledger(value),
                })
                .expect("the actual native candidate guards every usage row");
            Some(UsageChange {
                address: UsageAddress {
                    bucket_id: std::str::from_utf8(bucket).unwrap().into(),
                    window_start: u64::from_be_bytes((*window).try_into().unwrap()),
                },
                expected,
                replacement: ledger(value),
            })
        })
        .collect()
}
pub(super) fn is_correction(changes: &[UsageChange]) -> bool {
    changes.iter().any(|change| {
        busbar_contract::records::correction::reserved_bucket(&change.address.bucket_id)
    })
}
struct FaultBackend {
    inner: Arc<dyn PersistenceBackend>,
    faults: Arc<Faults>,
}
impl PersistenceBackend for FaultBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if self.faults.usage_read_down.load(Ordering::SeqCst)
                && request
                    .addresses
                    .iter()
                    .any(|a| a.key.first() == Some(&b'U'))
            {
                return Err(Failure::Unavailable);
            }
            self.inner.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            assert!(
                !self.faults.readonly.load(Ordering::SeqCst),
                "hydration must never write"
            );
            let changes = usage_changes(&prepared);
            let correction = is_correction(&changes);
            if correction {
                self.faults
                    .correction_calls
                    .lock()
                    .unwrap()
                    .push(ObservedCorrection {
                        op_id: busbar_contract::records::OpId(prepared.candidate().id.operation),
                        usage: changes.clone(),
                        fingerprint: prepared.fingerprint(),
                    });
            }
            if !changes.is_empty() {
                let hook = self.faults.before_add.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook().await;
                }
            }
            let metering = prepared.candidate().mutations.iter().any(|mutation| matches!(mutation, Mutation::Put { address, .. } if address.key.first() == Some(&b'M')));
            struct Active<'a>(&'a AtomicUsize);
            impl Drop for Active<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _active = if metering {
                self.faults.meter_calls.fetch_add(1, Ordering::SeqCst);
                let active = self.faults.meter_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.faults
                    .meter_high_water
                    .fetch_max(active, Ordering::SeqCst);
                tokio::task::yield_now().await;
                Some(Active(&self.faults.meter_in_flight))
            } else {
                None
            };
            let meter_failure = metering
                && self
                    .faults
                    .meter_fail_n
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        (n > 0).then(|| n - 1)
                    })
                    .is_ok();
            if meter_failure
                || (!changes.is_empty() && self.faults.down.load(Ordering::SeqCst))
                || (metering && self.faults.meter_down.load(Ordering::SeqCst))
                || (!correction
                    && changes.iter().any(|change| {
                        change
                            .address
                            .bucket_id
                            .starts_with(crate::governance::ERA_BUCKET_PREFIX)
                    })
                    && self.faults.era_down.load(Ordering::SeqCst))
            {
                return Err(Failure::Unknown);
            }
            let result = self.inner.commit(prepared).await;
            if !changes.is_empty()
                && result.is_ok()
                && self.faults.lose_usage_reply.swap(false, Ordering::SeqCst)
            {
                assert!(
                    !self.faults.unwind_usage.load(Ordering::SeqCst),
                    "planted unwind after ordinary usage commit"
                );
                return Err(Failure::Unknown);
            }
            if correction
                && self
                    .faults
                    .lose_correction_reply
                    .swap(false, Ordering::SeqCst)
            {
                return Err(Failure::Unknown);
            }
            result
        })
    }
}
pub(super) struct FlakyStore {
    pub inner: Arc<CoreStore>,
    native: Arc<CoreStore>,
    faults: Arc<Faults>,
}
impl std::ops::Deref for FlakyStore {
    type Target = Faults;
    fn deref(&self) -> &Faults {
        &self.faults
    }
}
impl FlakyStore {
    pub fn ledger(&self) -> crate::governance::persistence::ledger::Ledger<'_> {
        self.native.ledger()
    }
    pub fn identity(&self) -> crate::governance::persistence::identity::Identity<'_> {
        self.native.identity()
    }

    pub async fn new() -> Self {
        let backend = crate::real_store::native_backend().await;
        let inner = crate::real_store::core_over(backend.clone()).await;
        let faults = Arc::new(Faults::default());
        let native = crate::real_store::core_over(Arc::new(FaultBackend {
            inner: backend,
            faults: faults.clone(),
        }))
        .await;
        Self {
            inner,
            native,
            faults,
        }
    }
    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }
}
pub(super) trait CoreHandle {
    fn core(&self) -> Arc<CoreStore>;
}
impl CoreHandle for Arc<CoreStore> {
    fn core(&self) -> Arc<CoreStore> {
        self.clone()
    }
}
impl CoreHandle for Arc<FlakyStore> {
    fn core(&self) -> Arc<CoreStore> {
        self.native.clone()
    }
}
