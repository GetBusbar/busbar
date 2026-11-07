// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Staged exact accounting owner. Logical receipts have no age-based collection.
//! Pending submissions remain owned by CoreStore; runtime recovery custody is separate.
//! Applied receipts and unresolved attempts bind the original intent. A definitive
//! no-effect refusal does not durably accept intent; the runtime recovery owner must
//! persist acknowledged work before promising recovery across process death.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::persistence::{
    commit::SubmitResult,
    facade::{CoreStore, LogicalClaim, LogicalId, LogicalPermit, Submission},
    fences::scan_guard,
    keys, partition,
};
use busbar_contract::{
    persistence::{
        Address, Candidate, Decision, ExpectedValue, Failure, Mutation, NamespaceId, Predicate,
        PreparedCandidate, Read, ReadResult, CANDIDATE_VERSION,
    },
    records::{
        correction, dedupe::Dedupe, MeteringDelta, MeteringRow, OpId, RecordStoreError,
        RecordStoreResult, UsageDelta, UsageLedger,
    },
    Secret,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const USAGE: NamespaceId = NamespaceId(*b"busbar.usage.v1\0");
pub const METERING: NamespaceId = NamespaceId(*b"busbar.meter.v1\0");
pub const LOGICAL_RECEIPTS: NamespaceId = NamespaceId(*b"busbar.logical1\0");

pub struct Ledger<'a> {
    store: &'a CoreStore,
}
impl CoreStore {
    pub fn ledger(&self) -> Ledger<'_> {
        Ledger { store: self }
    }
}

#[derive(Debug)]
enum Error {
    Conflict,
    Store(RecordStoreError),
}
type Result<T> = std::result::Result<T, Error>;
impl From<RecordStoreError> for Error {
    fn from(e: RecordStoreError) -> Self {
        Self::Store(e)
    }
}
impl From<Failure> for Error {
    fn from(e: Failure) -> Self {
        if e == Failure::StaleScan {
            Self::Conflict
        } else {
            invalid(format!("ledger backend: {e:?}"))
        }
    }
}
impl From<crate::persistence::facade::AccessError> for Error {
    fn from(e: crate::persistence::facade::AccessError) -> Self {
        invalid(format!("ledger access: {e:?}"))
    }
}
impl From<keys::KeyError> for Error {
    fn from(_: keys::KeyError) -> Self {
        corrupt()
    }
}
impl From<busbar_contract::count::CountError> for Error {
    fn from(e: busbar_contract::count::CountError) -> Self {
        invalid(e.to_string())
    }
}
impl From<Error> for RecordStoreError {
    fn from(e: Error) -> Self {
        match e {
            Error::Conflict => Self("ledger condition conflict".into()),
            Error::Store(e) => e,
        }
    }
}
fn invalid(message: impl Into<String>) -> Error {
    Error::Store(RecordStoreError(message.into()))
}
fn corrupt() -> Error {
    invalid("corrupt or unsupported canonical ledger record")
}
fn address(namespace: NamespaceId, tag: u8, parts: &[&[u8]]) -> Result<Address> {
    Ok(Address {
        namespace: namespace.0,
        key: keys::framed(tag, parts)?,
    })
}
fn usage_address(bucket: &str, window: u64) -> Result<Address> {
    address(
        time_namespace(USAGE, window),
        b'U',
        &[&USAGE.0, bucket.as_bytes(), &window.to_be_bytes()],
    )
}
fn meter_address(bucket: u64, row: &MeteringRow) -> Result<Address> {
    address(
        time_namespace(METERING, bucket),
        b'M',
        &[
            &METERING.0,
            &bucket.to_be_bytes(),
            row.key_id.as_bytes(),
            row.model.as_bytes(),
            row.provider.as_bytes(),
            &row.priced_from_ms.to_be_bytes(),
            row.key_group_at_use.as_bytes(),
            row.pricing_version.as_bytes(),
        ],
    )
}
fn time_namespace(family: NamespaceId, time: u64) -> NamespaceId {
    partition::namespace(family, &[&time.to_be_bytes()])
}
fn receipt_address(op: OpId) -> Result<Address> {
    address(
        partition::namespace(LOGICAL_RECEIPTS, &[&op.0[..8]]),
        b'R',
        &[&LOGICAL_RECEIPTS.0, &op.0],
    )
}
fn index_address(family: NamespaceId, time: u64) -> Result<Address> {
    address(family, b'P', &[&time.to_be_bytes()])
}
fn index_bytes(time: u64) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes
}
fn index_time(at: &Address, value: &Secret<Vec<u8>>, family: NamespaceId) -> Result<u64> {
    let parts = keys::components(&at.key, b'P')?;
    if at.namespace != family.0 || parts.len() != 1 {
        return Err(corrupt());
    }
    let time = u64::from_be_bytes(parts[0].try_into().map_err(|_| corrupt())?);
    let seal = crate::seal::lend();
    if value.expose(&seal) != &index_bytes(time) {
        return Err(corrupt());
    }
    Ok(time)
}
/// Check that a migration destination belongs to an accounting business cell or
/// its partition-discovery index. Historical logical receipts are never authorized.
pub fn migration_authorizes(at: &Address) -> bool {
    let time = |bytes: &[u8]| bytes.try_into().ok().map(u64::from_be_bytes);
    match at.key.first().copied() {
        Some(b'U') => {
            let Ok(parts) = keys::components(&at.key, b'U') else {
                return false;
            };
            let [family, bucket, window] = parts.as_slice() else {
                return false;
            };
            let Some(window) = time(window) else {
                return false;
            };
            *family == USAGE.0
                && std::str::from_utf8(bucket).is_ok()
                && at.namespace == time_namespace(USAGE, window).0
        }
        Some(b'M') => {
            let Ok(parts) = keys::components(&at.key, b'M') else {
                return false;
            };
            let [family, bucket, key, model, provider, priced, group, version] = parts.as_slice()
            else {
                return false;
            };
            let Some(bucket) = time(bucket) else {
                return false;
            };
            *family == METERING.0
                && time(priced).is_some()
                && [key, model, provider, group, version]
                    .iter()
                    .all(|part| std::str::from_utf8(part).is_ok())
                && at.namespace == time_namespace(METERING, bucket).0
        }
        Some(b'P') => {
            let Ok(parts) = keys::components(&at.key, b'P') else {
                return false;
            };
            let [partition] = parts.as_slice() else {
                return false;
            };
            time(partition).is_some() && [USAGE.0, METERING.0].contains(&at.namespace)
        }
        _ => false,
    }
}

/// Encode a complete imported usage cell and its discovery index without submitting it.
/// The migration coordinator must reject duplicate business addresses; only identical
/// partition-index entries may be deduplicated across source rows.
pub fn migration_usage(
    bucket: &str,
    window: u64,
    row: &UsageLedger,
) -> RecordStoreResult<Vec<(Address, Secret<Vec<u8>>)>> {
    let build = || -> Result<_> {
        let mut row = row.clone();
        row.normalize_scale6()?;
        row.models.sort_by(|a, b| a.model.cmp(&b.model));
        if row
            .models
            .windows(2)
            .any(|pair| pair[0].model == pair[1].model)
        {
            return Err(invalid("duplicate imported usage model identity"));
        }
        // Import includes reserved adjustment rows and zero counters: neither is a
        // fresh ordinary usage mutation, and both are historical evidence.
        Ok(vec![
            (usage_address(bucket, window)?, Secret::new(encode(&row)?)),
            (
                index_address(USAGE, window)?,
                Secret::new(index_bytes(window)),
            ),
        ])
    };
    build().map_err(Into::into)
}

/// Encode one exact metering identity and its discovery index. No receipt or
/// operation identity is invented for historical measurements.
pub fn migration_metering(
    bucket: u64,
    row: &MeteringRow,
) -> RecordStoreResult<Vec<(Address, Secret<Vec<u8>>)>> {
    let build = || -> Result<_> {
        let mut row = row.clone();
        row.normalize_scale6()?;
        Ok(vec![
            (meter_address(bucket, &row)?, Secret::new(encode(&row)?)),
            (
                index_address(METERING, bucket)?,
                Secret::new(index_bytes(bucket)),
            ),
        ])
    };
    build().map_err(Into::into)
}

fn empty_meter(d: &MeteringDelta) -> MeteringRow {
    MeteringRow {
        scale: busbar_contract::COUNT_SCALE,
        key_id: d.key_id.clone(),
        model: d.model.clone(),
        provider: d.provider.clone(),
        tokens_input: 0,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 0,
        billable_requests: 0,
        key_group_at_use: d.key_group_at_use.clone(),
        pricing_version: d.pricing_version.clone(),
        priced_from_ms: d.priced_from_ms,
        usage_units: BTreeMap::new(),
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    version: u32,
    record: T,
}
fn encode<T: Serialize>(record: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(&Record { version: 1, record }).map_err(|_| corrupt())
}
trait Canonical {
    fn check(value: &serde_json::Value) -> Result<()>;
}
fn fields(value: &serde_json::Value, allowed: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or_else(corrupt)?;
    if object.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(corrupt());
    }
    Ok(())
}
impl Canonical for UsageLedger {
    fn check(value: &serde_json::Value) -> Result<()> {
        fields(value, &["requests", "billable_requests", "models"])?;
        for model in value
            .get("models")
            .and_then(|v| v.as_array())
            .ok_or_else(corrupt)?
        {
            fields(model, &["scale", "model", "usage_units"])?;
        }
        Ok(())
    }
}
impl Canonical for MeteringRow {
    fn check(value: &serde_json::Value) -> Result<()> {
        fields(
            value,
            &[
                "scale",
                "key_id",
                "model",
                "provider",
                "tokens_input",
                "tokens_output",
                "tokens_cache_read",
                "tokens_cache_write",
                "requests",
                "billable_requests",
                "key_group_at_use",
                "pricing_version",
                "priced_from_ms",
                "usage_units",
            ],
        )
    }
}
// Metadata inspection never supplies quantity values. Counts decode directly from
// the original bytes into i128; JSON object order and whitespace are immaterial.
fn decode<T: DeserializeOwned + Canonical>(bytes: &Secret<Vec<u8>>) -> Result<T> {
    let seal = crate::seal::lend();
    let bytes = bytes.expose(&seal);
    let metadata: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    fields(&metadata, &["version", "record"])?;
    T::check(metadata.get("record").ok_or_else(corrupt)?)?;
    let value: Record<T> = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    if value.version != 1 {
        return Err(corrupt());
    }
    Ok(value.record)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    digest: [u8; 32],
    result: u8,
}
impl Canonical for Receipt {
    fn check(value: &serde_json::Value) -> Result<()> {
        fields(value, &["digest", "result"])
    }
}

struct Tx<'a> {
    store: &'a CoreStore,
    observed: BTreeMap<Address, Option<Secret<Vec<u8>>>>,
    changes: BTreeMap<Address, Option<Secret<Vec<u8>>>>,
    guards: Vec<Predicate>,
    indexed: BTreeSet<Address>,
}
impl<'a> Tx<'a> {
    fn new(store: &'a CoreStore) -> Self {
        Self {
            store,
            observed: BTreeMap::new(),
            changes: BTreeMap::new(),
            guards: Vec::new(),
            indexed: BTreeSet::new(),
        }
    }
    async fn prefetch(&mut self, mut addresses: Vec<Address>) -> Result<()> {
        addresses.sort_unstable();
        addresses.dedup();
        addresses.retain(|at| !self.observed.contains_key(at) && !self.changes.contains_key(at));
        if addresses.is_empty() {
            return Ok(());
        }
        let request = Arc::new(Read {
            dataset: self.store.info().dataset,
            addresses,
            time: None,
        });
        let result = self.store.backend().read(request.clone()).await?;
        let ReadResult::Values {
            observed_at,
            values,
        } = result
        else {
            return Err(corrupt());
        };
        if observed_at.authority != self.store.info().clock_authority
            || values.len() != request.addresses.len()
        {
            return Err(corrupt());
        }
        for (at, value) in request.addresses.iter().zip(values) {
            self.observed.insert(at.clone(), value);
        }
        Ok(())
    }
    async fn one(&mut self, at: Address) -> Result<Option<Secret<Vec<u8>>>> {
        if let Some(v) = self.changes.get(&at).or_else(|| self.observed.get(&at)) {
            return Ok(v.clone());
        }
        self.prefetch(vec![at.clone()]).await?;
        self.observed.get(&at).cloned().ok_or_else(corrupt)
    }
    async fn ensure_partition(&mut self, family: NamespaceId, time: u64) -> Result<()> {
        let at = index_address(family, time)?;
        if self.indexed.contains(&at) {
            return Ok(());
        }
        if let Some(bytes) = self.one(at.clone()).await? {
            index_time(&at, &bytes, family)?;
            // Index entries never disappear. Existing entries are not shared write
            // predicates, so ordinary writes contend only in their data partitions.
            self.observed.remove(&at);
        } else {
            self.changes
                .insert(at.clone(), Some(Secret::new(index_bytes(time))));
        }
        self.indexed.insert(at);
        Ok(())
    }
    async fn validate_guards(&self) -> Result<()> {
        if self.store.guards_hold(&self.guards).await? {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
    fn put<T: Serialize>(&mut self, at: Address, row: &T) -> Result<()> {
        self.changes.insert(at, Some(Secret::new(encode(row)?)));
        Ok(())
    }
    async fn usage(&mut self, at: Address) -> Result<UsageLedger> {
        let mut row = self
            .one(at)
            .await?
            .as_ref()
            .map(decode)
            .transpose()?
            .unwrap_or_default();
        UsageLedger::normalize_scale6(&mut row)?;
        Ok(row)
    }
    async fn scan(
        &mut self,
        namespace: NamespaceId,
        prefix: Vec<u8>,
    ) -> Result<Vec<(Address, Secret<Vec<u8>>)>> {
        let collection = self.store.scan(namespace, prefix, None).await?;
        let guard = scan_guard(namespace, collection.generation);
        if let Some(previous) = self.guards.iter().find(|p| p.address == guard.address) {
            let seal = crate::seal::lend();
            let same = match (&previous.expected, &guard.expected) {
                (ExpectedValue::Absent, ExpectedValue::Absent) => true,
                (ExpectedValue::Exact(a), ExpectedValue::Exact(b)) => {
                    a.expose(&seal) == b.expose(&seal)
                }
                _ => false,
            };
            if !same {
                return Err(Error::Conflict);
            }
        } else {
            self.guards.push(guard);
        }
        Ok(collection.rows)
    }

    async fn commit(self, result: u8, permit: Option<LogicalPermit<'_>>) -> Result<u8> {
        let mut predicates = self.guards;
        predicates.extend(self.observed.into_iter().map(|(address, v)| Predicate {
            address,
            expected: v.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
        }));
        let candidate = PreparedCandidate::new(Candidate {
            id: self.store.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations: self
                .changes
                .into_iter()
                .map(|(address, v)| match v {
                    Some(value) => Mutation::Put { address, value },
                    None => Mutation::Delete(address),
                })
                .collect(),
            time: None,
            result: Secret::new(vec![result]),
        })
        .map_err(|_| corrupt())?;
        let submission = if let Some(permit) = permit {
            permit.submit(candidate).await?
        } else {
            self.store.submit(candidate).await?
        };
        submission_result(submission)
    }
}

enum Change<'a> {
    Put(&'a str, u64, &'a UsageLedger),
    Usage(&'a [(&'a str, u64, UsageDelta)]),
    Meter(&'a [MeteringDelta]),
    Correction(&'a correction::Request),
}
impl Change<'_> {
    fn addresses(&self) -> Result<Vec<Address>> {
        let count = match self {
            Self::Put(..) => 1,
            Self::Usage(cells) => cells.len(),
            Self::Meter(deltas) => deltas.len(),
            Self::Correction(request) => request.usage.len().checked_add(1).ok_or_else(corrupt)?,
        };
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(count.checked_mul(2).ok_or_else(corrupt)?)
            .map_err(|_| invalid("ledger read allocation exhausted"))?;
        match self {
            Self::Put(bucket, window, _) => {
                addresses.push(usage_address(bucket, *window)?);
                addresses.push(index_address(USAGE, *window)?);
            }
            Self::Usage(cells) => {
                for (bucket, window, _) in *cells {
                    addresses.push(usage_address(bucket, *window)?);
                    addresses.push(index_address(USAGE, *window)?);
                }
            }
            Self::Meter(deltas) => {
                for delta in *deltas {
                    addresses.push(meter_address(delta.bucket, &empty_meter(delta))?);
                    addresses.push(index_address(METERING, delta.bucket)?);
                }
            }
            Self::Correction(request) => {
                addresses.push(super::identity::key_address(&request.key_id)?);
                for change in &request.usage {
                    addresses.push(usage_address(
                        &change.address.bucket_id,
                        change.address.window_start,
                    )?);
                    addresses.push(index_address(USAGE, change.address.window_start)?);
                }
            }
        }
        Ok(addresses)
    }
}
impl Ledger<'_> {
    /// Read-only canonical decision proof. Absence is only an observation; the
    /// recovery owner must independently fence the original writer first.
    pub(crate) async fn recovery_receipt(
        &self,
        op: OpId,
        digest: [u8; 32],
    ) -> RecordStoreResult<(Option<u8>, Predicate)> {
        let address = receipt_address(op).map_err(RecordStoreError::from)?;
        let result = self
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.store.info().dataset,
                addresses: vec![address.clone()],
                time: None,
            }))
            .await
            .map_err(Error::from)
            .map_err(RecordStoreError::from)?;
        let ReadResult::Values {
            observed_at,
            mut values,
        } = result
        else {
            return Err(RecordStoreError("unexpected recovery receipt read".into()));
        };
        if observed_at.authority != self.store.info().clock_authority || values.len() != 1 {
            return Err(RecordStoreError(
                "invalid recovery receipt observation".into(),
            ));
        }
        let value = values.pop().flatten();
        let decision = value
            .as_ref()
            .map(|bytes| {
                let receipt: Receipt = decode(bytes)?;
                if receipt.digest != digest || receipt.result > 1 {
                    return Err(invalid(
                        "recovery logical receipt differs from original body",
                    ));
                }
                Ok(receipt.result)
            })
            .transpose()
            .map_err(RecordStoreError::from)?;
        Ok((
            decision,
            Predicate {
                address,
                expected: value.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
            },
        ))
    }
    async fn change(
        &self,
        change: Change<'_>,
        logical: Option<(OpId, [u8; 32])>,
    ) -> RecordStoreResult<u8> {
        for retry in 0..=self.store.limits().conflict_retries {
            let claim = if let Some((op, digest)) = logical {
                Some(
                    self.store
                        .claim_logical(
                            LogicalId {
                                namespace: LOGICAL_RECEIPTS.0,
                                operation: op.0,
                            },
                            digest,
                        )
                        .map_err(Error::from)
                        .map_err(RecordStoreError::from)?,
                )
            } else {
                None
            };
            let result = match claim {
                Some(LogicalClaim::Retained(id)) => match self.store.retry(id).await {
                    Ok(s) => submission_result(s),
                    Err(e) => Err(e.into()),
                },
                Some(LogicalClaim::Busy) => {
                    Err(invalid("ledger logical operation is already being planned"))
                }
                Some(LogicalClaim::Prepare(permit)) => {
                    self.attempt(&change, logical, Some(permit)).await
                }
                None => self.attempt(&change, logical, None).await,
            };
            if matches!(result, Err(Error::Conflict))
                && retry < self.store.limits().conflict_retries
            {
                continue;
            }
            return result.map_err(Into::into);
        }
        unreachable!()
    }
    async fn attempt(
        &self,
        change: &Change<'_>,
        logical: Option<(OpId, [u8; 32])>,
        permit: Option<LogicalPermit<'_>>,
    ) -> Result<u8> {
        let mut tx = Tx::new(self.store);
        let mut addresses = change.addresses()?;
        if let Some((op, _)) = logical {
            addresses
                .try_reserve(1)
                .map_err(|_| invalid("ledger read allocation exhausted"))?;
            addresses.push(receipt_address(op)?);
        }
        tx.prefetch(addresses).await?;
        let receipt = if let Some((op, digest)) = logical {
            let at = receipt_address(op)?;
            if let Some(bytes) = tx.one(at.clone()).await? {
                let found: Receipt = decode(&bytes)?;
                if found.digest != digest {
                    return Err(invalid("ledger logical operation identity conflict"));
                }
                if found.result > 1 {
                    return Err(corrupt());
                }
                return Ok(found.result);
            }
            Some((at, digest))
        } else {
            None
        };
        let result = match change {
            Change::Put(bucket, window, row) => {
                check_bucket(bucket)?;
                let mut row = (*row).clone();
                row.normalize_scale6()?;
                let at = usage_address(bucket, *window)?;
                tx.ensure_partition(USAGE, *window).await?;
                tx.one(at.clone()).await?;
                tx.put(at, &row)?;
                0
            }
            Change::Usage(cells) => {
                for (bucket, window, delta) in *cells {
                    check_bucket(bucket)?;
                    let at = usage_address(bucket, *window)?;
                    let mut row = tx.usage(at.clone()).await?;
                    row.checked_apply_delta(delta)?;
                    tx.ensure_partition(USAGE, *window).await?;
                    tx.put(at, &row)?;
                }
                0
            }
            Change::Meter(deltas) => {
                for delta in *deltas {
                    let mut delta = delta.clone();
                    delta.normalize_scale6()?;
                    let mut row = empty_meter(&delta);
                    let at = meter_address(delta.bucket, &row)?;
                    if let Some(bytes) = tx.one(at.clone()).await? {
                        row = decode(&bytes)?;
                        if meter_address(delta.bucket, &row)? != at {
                            return Err(corrupt());
                        }
                    }
                    row.checked_add_delta(&delta)?;
                    tx.ensure_partition(METERING, delta.bucket).await?;
                    tx.put(at, &row)?;
                }
                0
            }
            Change::Correction(request) => {
                let request = busbar_contract::records::correction::normalized(request)?;
                let key_at = super::identity::key_address(&request.key_id)?;
                let key = tx
                    .one(key_at)
                    .await?
                    .as_ref()
                    .map(super::identity::decode_key)
                    .transpose()?;
                if key
                    .as_ref()
                    .is_none_or(|k| k.id != request.key_id || k.deleted_at.is_some())
                {
                    return Ok(1);
                }
                let mut metering = self
                    .metering(&mut tx, request.day_start, Some(&request.key_id))
                    .await?;
                correction::canonical_metering(&mut metering);
                if metering != request.metering {
                    return Ok(1);
                }
                for change in &request.usage {
                    let mut row = tx
                        .usage(usage_address(
                            &change.address.bucket_id,
                            change.address.window_start,
                        )?)
                        .await?;
                    correction::canonical_ledger(&mut row).map_err(invalid)?;
                    if row != change.expected {
                        return Ok(1);
                    }
                }
                for change in &request.usage {
                    tx.ensure_partition(USAGE, change.address.window_start)
                        .await?;
                    tx.put(
                        usage_address(&change.address.bucket_id, change.address.window_start)?,
                        &change.replacement,
                    )?;
                }
                0
            }
        };
        if let Some((at, digest)) = receipt {
            tx.put(at, &Receipt { digest, result })?;
        }
        tx.commit(result, permit).await
    }
    async fn metering(
        &self,
        tx: &mut Tx<'_>,
        bucket: u64,
        key: Option<&str>,
    ) -> Result<Vec<MeteringRow>> {
        let bucket_bytes = bucket.to_be_bytes();
        let prefix = if let Some(key) = key {
            keys::framed(b'M', &[&METERING.0, &bucket_bytes, key.as_bytes()])?
        } else {
            keys::framed(b'M', &[&METERING.0, &bucket_bytes])?
        };
        let mut result = Vec::new();
        for (at, bytes) in tx.scan(time_namespace(METERING, bucket), prefix).await? {
            let mut row: MeteringRow = decode(&bytes)?;
            if meter_address(bucket, &row)? != at {
                return Err(corrupt());
            }
            row.normalize_scale6()?;
            result
                .try_reserve(1)
                .map_err(|_| invalid("ledger scan allocation exhausted"))?;
            result.push(row);
        }
        result.sort_by(|a, b| {
            (
                &a.key_id,
                &a.model,
                &a.provider,
                a.priced_from_ms,
                &a.key_group_at_use,
                &a.pricing_version,
            )
                .cmp(&(
                    &b.key_id,
                    &b.model,
                    &b.provider,
                    b.priced_from_ms,
                    &b.key_group_at_use,
                    &b.pricing_version,
                ))
        });
        Ok(result)
    }
    pub async fn get_usage(&self, bucket: &str, window: u64) -> RecordStoreResult<UsageLedger> {
        Tx::new(self.store)
            .usage(usage_address(bucket, window).map_err(RecordStoreError::from)?)
            .await
            .map_err(Into::into)
    }
    /// Read aggregate and provenance rows from one coherent backend observation.
    pub async fn get_usage_pair(
        &self,
        bucket: &str,
        dated_bucket: &str,
        window: u64,
    ) -> RecordStoreResult<(UsageLedger, UsageLedger)> {
        let read = async {
            let plain = usage_address(bucket, window)?;
            let dated = usage_address(dated_bucket, window)?;
            let mut tx = Tx::new(self.store);
            tx.prefetch(vec![plain.clone(), dated.clone()]).await?;
            Ok::<_, Error>((tx.usage(plain).await?, tx.usage(dated).await?))
        };
        read.await.map_err(Into::into)
    }

    pub async fn put_usage(
        &self,
        bucket: &str,
        window: u64,
        row: &UsageLedger,
    ) -> RecordStoreResult<()> {
        self.change(Change::Put(bucket, window, row), None)
            .await
            .map(|_| ())
    }
    pub async fn add_usage(
        &self,
        bucket: &str,
        window: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.change(Change::Usage(&[(bucket, window, delta.clone())]), None)
            .await
            .map(|_| ())
    }
    pub async fn add_usage_batch_deduped(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.change(
            Change::Usage(cells),
            Some((op, *Dedupe::usage(cells).body())),
        )
        .await
        .map(|_| ())
    }
    pub async fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.change(Change::Meter(std::slice::from_ref(delta)), None)
            .await
            .map(|_| ())
    }
    pub async fn add_metering_batch_deduped(
        &self,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.change(
            Change::Meter(deltas),
            Some((op, *Dedupe::metering(deltas).body())),
        )
        .await
        .map(|_| ())
    }
    pub async fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        request.validate().map_err(RecordStoreError::from)?;
        self.change(
            Change::Correction(request),
            Some((request.op_id, *Dedupe::usage_correction(request).body())),
        )
        .await
        .map(|r| {
            if r == 0 {
                correction::Decision::Applied
            } else {
                correction::Decision::ConditionConflict
            }
        })
    }
    pub async fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        for retry in 0..=self.store.limits().conflict_retries {
            let result = self.metering(&mut Tx::new(self.store), bucket, None).await;
            if matches!(result, Err(Error::Conflict))
                && retry < self.store.limits().conflict_retries
            {
                continue;
            }
            return result.map_err(Into::into);
        }
        unreachable!()
    }
    /// Remove dated usage only; lifetime window zero is retained.
    pub async fn prune_usage_before(&self, before: u64) -> RecordStoreResult<u64> {
        self.prune(USAGE, b'U', before).await
    }
    pub async fn prune_metering_before(&self, before: u64) -> RecordStoreResult<u64> {
        self.prune(METERING, b'M', before).await
    }
    async fn prune(&self, namespace: NamespaceId, tag: u8, before: u64) -> RecordStoreResult<u64> {
        for retry in 0..=self.store.limits().conflict_retries {
            let result = self.prune_attempt(namespace, tag, before).await;
            if matches!(result, Err(Error::Conflict))
                && retry < self.store.limits().conflict_retries
            {
                continue;
            }
            return result.map_err(Into::into);
        }
        unreachable!()
    }
    async fn prune_attempt(&self, namespace: NamespaceId, tag: u8, before: u64) -> Result<u64> {
        let mut tx = Tx::new(self.store);
        let mut count = 0u64;
        for (index, value) in tx.scan(namespace, vec![b'P']).await? {
            let partition_time = index_time(&index, &value, namespace)?;
            if partition_time >= before || (namespace == USAGE && partition_time == 0) {
                continue;
            }
            for (at, value) in tx
                .scan(
                    time_namespace(namespace, partition_time),
                    keys::framed(tag, &[&namespace.0])?,
                )
                .await?
            {
                let parts = keys::components(&at.key, tag)?;
                let time = if namespace == USAGE {
                    if parts.len() != 3 || parts[0] != USAGE.0 {
                        return Err(corrupt());
                    }
                    let bucket = std::str::from_utf8(parts[1]).map_err(|_| corrupt())?;
                    let window = u64::from_be_bytes(parts[2].try_into().map_err(|_| corrupt())?);
                    let mut row: UsageLedger = decode(&value)?;
                    row.normalize_scale6()?;
                    if usage_address(bucket, window)? != at {
                        return Err(corrupt());
                    }
                    window
                } else {
                    if parts.len() != 8 || parts[0] != METERING.0 {
                        return Err(corrupt());
                    }
                    let bucket = u64::from_be_bytes(parts[1].try_into().map_err(|_| corrupt())?);
                    let mut row: MeteringRow = decode(&value)?;
                    row.normalize_scale6()?;
                    if meter_address(bucket, &row)? != at {
                        return Err(corrupt());
                    }
                    bucket
                };
                if time == partition_time {
                    count = count.checked_add(1).ok_or_else(corrupt)?;
                    tx.observed.insert(at.clone(), Some(value));
                    tx.changes.insert(at, None);
                }
            }
        }
        if count == 0 {
            tx.validate_guards().await?;
            return Ok(0);
        }
        tx.commit(0, None).await?;
        Ok(count)
    }
}
fn check_bucket(bucket: &str) -> Result<()> {
    if correction::reserved_bucket(bucket) {
        return Err(invalid(
            "reserved adjustment rows require atomic usage correction",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;

fn submission_result(submission: Submission) -> Result<u8> {
    match submission.result {
        SubmitResult::Decided(d) => match d.as_ref() {
            Decision::Applied(v) => {
                let seal = crate::seal::lend();
                match v.expose(&seal).as_slice() {
                    [r @ 0..=1] => Ok(*r),
                    _ => Err(corrupt()),
                }
            }
            Decision::ConditionConflict => Err(Error::Conflict),
            _ => Err(invalid("ledger commit refused")),
        },
        SubmitResult::NoEffect(f) => Err(f.into()),
        SubmitResult::Uncertain | SubmitResult::Reconcile | SubmitResult::Busy => {
            Err(invalid(format!(
                "ledger outcome unresolved; retained operation {}",
                hex::encode(submission.id.0)
            )))
        }
    }
}

#[cfg(test)]
mod migration_encoding_tests {
    use super::*;
    use busbar_contract::records::ModelTokens;

    #[test]
    fn usage_import_preserves_exact_counts_zero_evidence_and_partition_discovery() {
        let row = UsageLedger {
            requests: u64::MAX,
            billable_requests: 0,
            models: vec![
                ModelTokens {
                    scale: 6,
                    model: "exact".into(),
                    usage_units: BTreeMap::from([
                        ("maximum".into(), i128::MAX),
                        ("zero".into(), 0),
                    ]),
                },
                ModelTokens {
                    scale: 0,
                    model: "whole".into(),
                    usage_units: BTreeMap::from([("input".into(), 1)]),
                },
            ],
        };
        let rows = migration_usage(correction::ADJUST_UP_BUCKET, 42, &row).unwrap();
        assert!(rows.iter().all(|(at, _)| migration_authorizes(at)));
        let mut wrong_partition = rows[0].0.clone();
        wrong_partition.namespace[0] ^= 1;
        assert!(!migration_authorizes(&wrong_partition));
        assert!(!migration_authorizes(
            &receipt_address(OpId([7; 16])).unwrap()
        ));
        let decoded: UsageLedger = decode(&rows[0].1).unwrap();
        assert_eq!(decoded.requests, u64::MAX);
        assert_eq!(decoded.models[0].usage_units["maximum"], i128::MAX);
        assert_eq!(decoded.models[0].usage_units["zero"], 0);
        assert_eq!(decoded.models[1].usage_units["input"], 1_000_000);
        assert_eq!(index_time(&rows[1].0, &rows[1].1, USAGE).unwrap(), 42);
        let another = migration_usage("other", 42, &row).unwrap();
        assert_ne!(rows[0].0, another[0].0);
        assert_eq!(rows[1].0, another[1].0);
        let seal = crate::seal::lend();
        assert_eq!(rows[1].1.expose(&seal), another[1].1.expose(&seal));
    }

    #[test]
    fn usage_import_refuses_duplicate_models_and_legacy_overflow() {
        let model = ModelTokens {
            scale: 6,
            model: "duplicate".into(),
            usage_units: BTreeMap::new(),
        };
        let mut row = UsageLedger {
            models: vec![model.clone(), model],
            ..Default::default()
        };
        assert!(migration_usage("bucket", 0, &row).is_err());
        row.models.truncate(1);
        row.models[0].scale = 0;
        row.models[0].usage_units.insert("input".into(), i128::MAX);
        assert!(migration_usage("bucket", 0, &row).is_err());
    }
}
