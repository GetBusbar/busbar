// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Boot-owned node allocation and deployment keys. A host lease never transfers a
//! journal: a new owner receives a fresh node even when a previous lease expired.
use std::sync::{Arc, Mutex};

use busbar_contract::Secret;

use super::{
    facade::CoreStore,
    scoped::{Expected, Mutation, Outcome, Predicate, Request, ScopedStore},
};

pub const INSTANCE: &str = "busbar.boot";
pub const NODE_SCHEMA: &str = "busbar.node.v1";
pub const KEYSET_SCHEMA: &str = "busbar.keyset.v1";
const KEYSET_KEY: &[u8] = b"deployment";
const ASSIGNMENT_MAGIC: &[u8; 8] = b"BBNODE01";
const ID_ATTEMPTS: usize = 16;
const JOURNAL_INVENTORY_MAGIC: &[u8; 8] = b"BBJINV01";
const JOURNAL_INVENTORY_PREFIX: &[u8] = b"journal:";

pub(crate) fn journal_inventory_key(node: u64) -> Vec<u8> {
    [JOURNAL_INVENTORY_PREFIX, &node.to_be_bytes()].concat()
}
pub(crate) fn journal_inventory_address(
    node: u64,
) -> Result<busbar_contract::persistence::Address, super::host_records::Error> {
    super::scoped::migration_address(true, INSTANCE, NODE_SCHEMA, &journal_inventory_key(node))
}
pub(crate) fn journal_inventory_address_class(
    address: &busbar_contract::persistence::Address,
) -> bool {
    // Reserve the complete logical prefix, including malformed suffixes, so a
    // generic boot-schema importer cannot bypass proof admission for them.
    super::scoped::migration_address(true, INSTANCE, NODE_SCHEMA, JOURNAL_INVENTORY_PREFIX)
        .is_ok_and(|prefix| {
            address.namespace == prefix.namespace && address.key.starts_with(&prefix.key)
        })
}
pub(crate) fn journal_inventory_bytes(
    node: u64,
    count: u64,
    tail: (u64, [u8; 32]),
    original_digest: [u8; 32],
) -> Vec<u8> {
    let mut bytes = [
        JOURNAL_INVENTORY_MAGIC.as_slice(),
        &node.to_be_bytes(),
        &count.to_be_bytes(),
        &tail.0.to_be_bytes(),
        &tail.1,
        &original_digest,
    ]
    .concat();
    bytes.extend_from_slice(&journal_inventory_checksum(&bytes));
    bytes
}
fn journal_inventory_checksum(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"busbar.node.original-journal-inventory/1\0");
    hash.update(bytes);
    hash.finalize().into()
}
fn journal_inventory_node(key: &[u8], bytes: &[u8]) -> Result<u64, String> {
    let suffix = key
        .strip_prefix(JOURNAL_INVENTORY_PREFIX)
        .ok_or("invalid journal inventory key")?;
    if suffix.len() != 8 || bytes.len() != 128 || &bytes[..8] != JOURNAL_INVENTORY_MAGIC {
        return Err("malformed journal inventory".into());
    }
    if bytes[96..] != journal_inventory_checksum(&bytes[..96]) {
        return Err("journal inventory checksum differs".into());
    }
    let node = u64::from_be_bytes(suffix.try_into().map_err(error)?);
    let stored_node = u64::from_be_bytes(bytes[8..16].try_into().map_err(error)?);
    let count = u64::from_be_bytes(bytes[16..24].try_into().map_err(error)?);
    let tail = u64::from_be_bytes(bytes[24..32].try_into().map_err(error)?);
    if node == 0 || node != stored_node || count == 0 || tail == 0 || tail < count {
        return Err("invalid journal inventory identity".into());
    }
    Ok(node)
}

pub const LEASE_TTL_MS: u64 = 9_000;

pub(crate) enum WriterRetirement {
    Live { retry_at_ms: u64 },
    Pending,
    Retired(Vec<busbar_contract::persistence::Predicate>),
}

/// Domain custody survives cancellation and Unknown. The CoreStore retains the
/// native Attempt, while this owner retains its exact target and candidate.
#[derive(Default)]
pub(crate) struct WriterRetirements {
    gate: tokio::sync::Mutex<()>,
    pending: Mutex<PendingRetirements>,
}
type PendingRetirements =
    std::collections::BTreeMap<(u64, [u8; 16]), busbar_contract::persistence::PreparedCandidate>;
impl WriterRetirements {
    pub(crate) async fn retire(
        &self,
        core: &CoreStore,
        epoch: u64,
        writer: [u8; 16],
    ) -> Result<WriterRetirement, String> {
        use super::{commit::SubmitResult, facade::PendingId};
        use busbar_contract::persistence::{self as native, control};
        let _gate = self.gate.lock().await;
        let target = (epoch, writer);
        let retained = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&target)
            .cloned();
        if let Some(candidate) = retained {
            let submission = core
                .retry(PendingId(candidate.candidate().id.operation))
                .await
                .map_err(error)?;
            match submission.result {
                SubmitResult::Decided(_) | SubmitResult::NoEffect(_) => {
                    self.pending
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&target);
                }
                SubmitResult::Uncertain | SubmitResult::Busy => {
                    return Ok(WriterRetirement::Pending);
                }
                SubmitResult::Reconcile => {
                    return Err("writer retirement retains unresolved original attempt".into());
                }
            }
        }
        let root_address = native::Address {
            namespace: control::NAMESPACE.0,
            key: control::DATASET_KEY.to_vec(),
        };
        let control_address = native::Address {
            namespace: control::NAMESPACE.0,
            key: control::writer_key(writer).to_vec(),
        };
        let lease_address = super::scoped::migration_address(
            true,
            INSTANCE,
            NODE_SCHEMA,
            &writer_lease_key(epoch, writer),
        )
        .map_err(error)?;
        let observed = core
            .backend()
            .read(Arc::new(native::Read {
                dataset: core.info().dataset,
                addresses: vec![
                    root_address.clone(),
                    control_address.clone(),
                    lease_address.clone(),
                ],
                time: None,
            }))
            .await
            .map_err(error)?;
        let native::ReadResult::Values {
            observed_at,
            mut values,
        } = observed
        else {
            return Err("unexpected writer retirement observation".into());
        };
        if values.len() != 3 || observed_at.authority != core.info().clock_authority {
            return Err("invalid writer retirement observation".into());
        }
        let lease = values.pop().flatten();
        let control_raw = values.pop().flatten();
        let root_raw = values
            .pop()
            .flatten()
            .ok_or("writer retirement dataset missing")?;
        let root = control::Dataset::decode(root_raw.expose(&crate::seal::lend()))
            .ok_or("invalid writer retirement dataset")?;
        if epoch == 0
            || writer == [0; 16]
            || root.id != core.info().dataset
            || root.writer_epoch < epoch
        {
            return Err("writer retirement identity differs".into());
        }
        let root_guard = native::Predicate {
            address: root_address,
            expected: native::ExpectedValue::Exact(root_raw),
        };
        if root.writer_epoch > epoch {
            return Ok(WriterRetirement::Retired(vec![root_guard]));
        }
        let control_raw = control_raw.ok_or("writer retirement control missing")?;
        let old = control::Writer::decode(control_raw.expose(&crate::seal::lend()))
            .ok_or("invalid writer retirement control")?;
        let permanently_closed = control::Writer {
            retired_through: u64::MAX,
            admitted_through: u64::MAX,
        };
        if old == permanently_closed {
            return Ok(WriterRetirement::Retired(vec![
                root_guard,
                native::Predicate {
                    address: control_address,
                    expected: native::ExpectedValue::Exact(control_raw),
                },
            ]));
        }
        if core.authority().map_err(error)?.writer == writer {
            return Err("cannot retire current writer".into());
        }
        let lease = lease.ok_or("current journal owner has no durable writer lease")?;
        let lease_row = LeaseRow::parse(lease.expose(&crate::seal::lend()))?;
        let now_ms = observed_at
            .unix_seconds
            .checked_mul(1000)
            .ok_or("writer retirement clock overflow")?;
        if now_ms < lease_row.expires_ms {
            return Ok(WriterRetirement::Live {
                retry_at_ms: lease_row.expires_ms,
            });
        }
        let fence = super::fences::writer(
            core.next_id().map_err(error)?,
            writer,
            Some(old),
            permanently_closed,
        )
        .map_err(error)?;
        let body = fence.candidate();
        let candidate = native::PreparedCandidate::new(native::Candidate {
            id: body.id,
            codec: body.codec,
            predicates: vec![
                root_guard,
                native::Predicate {
                    address: control_address.clone(),
                    expected: native::ExpectedValue::Exact(control_raw),
                },
                native::Predicate {
                    address: lease_address,
                    expected: native::ExpectedValue::Exact(lease),
                },
            ],
            mutations: vec![native::Mutation::Put {
                address: control_address,
                value: Secret::new(
                    permanently_closed
                        .encode()
                        .ok_or("invalid permanent fence")?
                        .to_vec(),
                ),
            }],
            time: Some(native::TimeGuard {
                not_before: Some(lease_row.expires_ms.div_ceil(1000)),
                before: None,
            }),
            result: Secret::default(),
        })
        .map_err(error)?;
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(target, candidate.clone());
        let submission = match core.submit(candidate).await {
            Ok(submission) => submission,
            Err(cause) => {
                self.pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&target);
                return Err(error(cause));
            }
        };
        match submission.result {
            SubmitResult::Decided(_) | SubmitResult::NoEffect(_) => {
                self.pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&target);
                // Only a subsequent coherent permanent-fence read grants proof.
                Ok(WriterRetirement::Pending)
            }
            SubmitResult::Uncertain | SubmitResult::Busy => Ok(WriterRetirement::Pending),
            SubmitResult::Reconcile => {
                Err("writer retirement retains unresolved original attempt".into())
            }
        }
    }
}

pub(crate) fn error(error: impl std::fmt::Debug) -> String {
    format!("boot persistence: {error:?}")
}

/// The policy owner retains the exact logical request before its first crossing.
/// Cancellation releases the async gate, but cannot discard an uncertain body.
pub(crate) struct BootRecords {
    pub(crate) records: ScopedStore,
    pub(crate) gate: tokio::sync::Mutex<()>,
    pending: Mutex<Option<Arc<Request>>>,
}
impl BootRecords {
    pub(crate) fn new(core: Arc<CoreStore>, schemas: &[&str]) -> Result<Self, String> {
        Ok(Self {
            records: ScopedStore::host_private(core, INSTANCE, schemas.iter().map(|s| (*s).into()))
                .map_err(error)?,
            gate: tokio::sync::Mutex::new(()),
            pending: Mutex::new(None),
        })
    }

    pub(crate) async fn resume(&self) -> Result<Option<bool>, String> {
        let request = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let Some(request) = request else {
            return Ok(None);
        };
        loop {
            let outcome = match self.records.conditional_native(&request).await {
                Ok(outcome) => outcome,
                Err(super::host_records::Error::Backend(
                    busbar_contract::persistence::Failure::Unavailable
                    | busbar_contract::persistence::Failure::Overloaded,
                ))
                | Err(super::host_records::Error::Access(super::facade::AccessError::Overloaded))
                | Err(super::host_records::Error::Access(super::facade::AccessError::Backend(
                    busbar_contract::persistence::Failure::Unavailable
                    | busbar_contract::persistence::Failure::Overloaded,
                ))) => {
                    // The original request remains owned, including the allocated node
                    // and lease result in the suspended caller. Never reenter allocation.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                Err(cause) => return Err(error(cause)),
            };
            match outcome {
                outcome @ (Outcome::Applied | Outcome::ConditionConflict) => {
                    *self.pending.lock().unwrap_or_else(|p| p.into_inner()) = None;
                    return Ok(Some(matches!(outcome, Outcome::Applied)));
                }
                Outcome::Pending(_) | Outcome::Busy(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                outcome => return Err(format!("boot mutation remains retained: {outcome:?}")),
            }
        }
    }

    pub(crate) async fn decide(
        &self,
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
    ) -> Result<bool, String> {
        let request = Arc::new(Request {
            op_id: crate::door::op_id().0,
            predicates,
            mutations,
        });
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            if pending.is_some() {
                return Err("a prior boot mutation is still unresolved".into());
            }
            *pending = Some(request);
        }
        self.resume()
            .await?
            .ok_or_else(|| "boot mutation disappeared".into())
    }
}

fn expected(value: Option<Secret<Vec<u8>>>) -> Expected {
    value.map_or(Expected::Absent, Expected::Exact)
}
fn predicate(schema: &str, key: Vec<u8>, value: Option<Secret<Vec<u8>>>) -> Predicate {
    Predicate {
        schema: schema.into(),
        key,
        expected: expected(value),
    }
}
fn put(schema: &str, key: Vec<u8>, bytes: Vec<u8>) -> Mutation {
    Mutation::Put {
        schema: schema.into(),
        key,
        value: Secret::new(bytes),
    }
}
fn host_key(host: &str) -> Vec<u8> {
    [b"host:".as_slice(), host.as_bytes()].concat()
}
fn lease_key(host: &str) -> Vec<u8> {
    [b"lease:".as_slice(), host.as_bytes()].concat()
}
fn writer_lease_key(epoch: u64, writer: [u8; 16]) -> Vec<u8> {
    [b"writer:".as_slice(), &epoch.to_be_bytes(), &writer].concat()
}
fn archive_key(host: &str, id: u64) -> Vec<u8> {
    let mut key = host_key(host);
    key.push(0);
    key.extend_from_slice(format!("{id:016x}").as_bytes());
    key
}
fn id_key(id: u64) -> Vec<u8> {
    [b"id:".as_slice(), &id.to_be_bytes()].concat()
}
fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(error)?;
    Ok(bytes)
}

#[derive(Clone, Copy)]
struct Assignment {
    id: u64,
    epoch: u64,
    writer: [u8; 16],
}
impl Assignment {
    fn bytes(self) -> Vec<u8> {
        [
            ASSIGNMENT_MAGIC.as_slice(),
            &self.id.to_be_bytes(),
            &self.epoch.to_be_bytes(),
            &self.writer,
        ]
        .concat()
    }
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 40 || &bytes[..8] != ASSIGNMENT_MAGIC {
            return Err("malformed node assignment".into());
        }
        let value = Self {
            id: u64::from_be_bytes(bytes[8..16].try_into().map_err(error)?),
            epoch: u64::from_be_bytes(bytes[16..24].try_into().map_err(error)?),
            writer: bytes[24..].try_into().map_err(error)?,
        };
        if value.id == 0 || value.epoch == 0 || value.writer == [0; 16] {
            return Err("invalid node assignment".into());
        }
        Ok(value)
    }
}
fn node_id(bytes: &[u8]) -> Result<u64, String> {
    let id = if bytes.len() == 8 {
        u64::from_be_bytes(bytes.try_into().map_err(error)?)
    } else {
        Assignment::parse(bytes)?.id
    };
    if id == 0 {
        Err("zero node identity".into())
    } else {
        Ok(id)
    }
}
#[derive(Clone, Copy)]
struct LeaseRow {
    holder: [u8; 16],
    expires_ms: u64,
}
impl LeaseRow {
    fn bytes(self) -> Vec<u8> {
        [&self.holder[..], &self.expires_ms.to_be_bytes()].concat()
    }
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 24 {
            return Err("malformed node lease".into());
        }
        Ok(Self {
            holder: bytes[..16].try_into().map_err(error)?,
            expires_ms: u64::from_be_bytes(bytes[16..].try_into().map_err(error)?),
        })
    }
}

pub struct BootIdentity {
    core: Arc<CoreStore>,
    records: BootRecords,
    holder: [u8; 16],
}
impl BootIdentity {
    pub fn new(core: Arc<CoreStore>) -> Result<Self, String> {
        Ok(Self {
            records: BootRecords::new(core.clone(), &[NODE_SCHEMA, KEYSET_SCHEMA])?,
            core,
            holder: random()?,
        })
    }
    async fn now_ms(&self) -> Result<u64, String> {
        let now = self
            .core
            .backend()
            .clock(self.core.info().dataset)
            .await
            .map_err(error)?;
        if now.authority != self.core.info().clock_authority {
            return Err("node lease clock authority changed".into());
        }
        now.unix_seconds
            .checked_mul(1_000)
            .ok_or_else(|| "node lease clock overflow".into())
    }
    pub async fn registered(&self) -> Result<Vec<(String, u64)>, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        self.registered_locked().await
    }

    async fn registered_locked(&self) -> Result<Vec<(String, u64)>, String> {
        let mut cursor = None;
        let mut nodes = Vec::new();
        loop {
            // One generation-checked scan covers both assignments and readonly
            // imports; two prefix scans could observe different inventories.
            let page = self
                .records
                .records
                .page(NODE_SCHEMA, b"", cursor.as_ref())
                .await
                .map_err(error)?;
            for (key, value) in page.rows {
                if let Some(host) = key.strip_prefix(b"host:") {
                    let host = std::str::from_utf8(host).map_err(error)?.to_string();
                    let id = node_id(value.expose(&crate::seal::lend()))?;
                    nodes.push((host, id));
                } else if key.starts_with(JOURNAL_INVENTORY_PREFIX) {
                    let node = journal_inventory_node(&key, value.expose(&crate::seal::lend()))?;
                    nodes.push((format!("journal:{node:016x}"), node));
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(nodes),
            }
        }
    }
    pub async fn take_node(self: &Arc<Self>, host: &str) -> Result<TakenNode, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        for _ in 0..ID_ATTEMPTS {
            let key = host_key(host);
            let lease_at = lease_key(host);
            let mut observation = self
                .records
                .records
                .read(&[(NODE_SCHEMA, &key), (NODE_SCHEMA, &lease_at)])
                .await
                .map_err(error)?
                .into_iter();
            let previous = observation.next().ok_or("node observation missing")?;
            let lease = observation.next().ok_or("lease observation missing")?;
            let now = self.now_ms().await?;
            let lease_row = lease
                .as_ref()
                .map(|v| LeaseRow::parse(v.expose(&crate::seal::lend())))
                .transpose()?;
            let authority = self.core.authority().map_err(error)?;
            let writer_key = writer_lease_key(authority.writer_epoch, authority.writer);
            let writer_lease = self
                .records
                .records
                .get(NODE_SCHEMA, &writer_key)
                .await
                .map_err(error)?;
            let writer_row = writer_lease
                .as_ref()
                .map(|value| LeaseRow::parse(value.expose(&crate::seal::lend())))
                .transpose()?;
            let previous_id = previous
                .as_ref()
                .map(|v| node_id(v.expose(&crate::seal::lend())))
                .transpose()?;
            if let Some(bytes) = previous.as_ref() {
                if let Ok(assignment) = Assignment::parse(bytes.expose(&crate::seal::lend())) {
                    if assignment.epoch == authority.writer_epoch
                        && assignment.writer == authority.writer
                        && lease_row.is_some_and(|lease| {
                            lease.holder == self.holder && lease.expires_ms != 0
                        })
                    {
                        return Ok(TakenNode {
                            id: assignment.id,
                            lease: Some(NodeLease {
                                owner: self.clone(),
                                host: host.into(),
                                id: assignment.id,
                                assignment_key: key,
                                primary: true,
                                released: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                            }),
                        });
                    }
                }
            }
            let taken = self.registered_locked().await?;
            let id = u64::from_be_bytes(random()?);
            if id == 0 || taken.iter().any(|(_, taken)| *taken == id) {
                continue;
            }
            let assignment = Assignment {
                id,
                epoch: authority.writer_epoch,
                writer: authority.writer,
            }
            .bytes();
            let primary = lease_row.is_none_or(|lease| lease.expires_ms <= now);
            let target = if primary {
                key.clone()
            } else {
                archive_key(host, id)
            };
            let reservation = id_key(id);
            let mut predicates = vec![predicate(NODE_SCHEMA, reservation.clone(), None)];
            let mut mutations = vec![put(NODE_SCHEMA, reservation, assignment.clone())];
            predicates.push(predicate(NODE_SCHEMA, writer_key.clone(), writer_lease));
            mutations.push(put(
                NODE_SCHEMA,
                writer_key,
                LeaseRow {
                    holder: writer_row.map_or(self.holder, |row| row.holder),
                    expires_ms: now
                        .checked_add(LEASE_TTL_MS)
                        .ok_or("writer lease expiry overflow")?,
                }
                .bytes(),
            ));
            if primary {
                predicates.push(predicate(NODE_SCHEMA, key, previous.clone()));
                predicates.push(predicate(NODE_SCHEMA, lease_at.clone(), lease));
                if let Some(old) = previous_id {
                    let archive = archive_key(host, old);
                    let held = self
                        .records
                        .records
                        .get(NODE_SCHEMA, &archive)
                        .await
                        .map_err(error)?;
                    if let Some(value) = held.as_ref() {
                        if node_id(value.expose(&crate::seal::lend()))? != old {
                            return Err("archived node identity conflict".into());
                        }
                    } else {
                        predicates.push(predicate(NODE_SCHEMA, archive.clone(), None));
                        mutations.push(Mutation::Put {
                            schema: NODE_SCHEMA.into(),
                            key: archive,
                            value: previous.clone().ok_or("archived identity missing")?,
                        });
                    }
                }
                mutations.push(put(
                    NODE_SCHEMA,
                    lease_at,
                    LeaseRow {
                        holder: self.holder,
                        expires_ms: now
                            .checked_add(LEASE_TTL_MS)
                            .ok_or("node lease expiry overflow")?,
                    }
                    .bytes(),
                ));
            } else {
                predicates.push(predicate(NODE_SCHEMA, target.clone(), None));
            }
            mutations.push(put(NODE_SCHEMA, target.clone(), assignment));
            if self.records.decide(predicates, mutations).await? {
                return Ok(TakenNode {
                    id,
                    lease: Some(NodeLease {
                        owner: self.clone(),
                        host: host.into(),
                        id,
                        assignment_key: target,
                        primary,
                        released: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    }),
                });
            }
        }
        Err("node allocation exhausted its conflict/randomness budget".into())
    }
    pub async fn stored_keyset(&self) -> Result<Option<String>, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        self.stored_keyset_locked().await
    }

    async fn stored_keyset_locked(&self) -> Result<Option<String>, String> {
        self.records
            .records
            .get(KEYSET_SCHEMA, KEYSET_KEY)
            .await
            .map_err(error)?
            .map(|v| String::from_utf8(v.expose(&crate::seal::lend()).clone()).map_err(error))
            .transpose()
    }
    pub async fn keep_keyset(&self, seed_hex: &str) -> Result<String, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        if let Some(held) = self.stored_keyset_locked().await? {
            return Ok(held);
        }
        self.records
            .decide(
                vec![predicate(KEYSET_SCHEMA, KEYSET_KEY.into(), None)],
                vec![put(
                    KEYSET_SCHEMA,
                    KEYSET_KEY.into(),
                    seed_hex.as_bytes().to_vec(),
                )],
            )
            .await?;
        self.stored_keyset_locked()
            .await?
            .ok_or_else(|| "deployment keyset was not kept".into())
    }
}

pub struct TakenNode {
    pub id: u64,
    pub lease: Option<NodeLease>,
}
#[derive(Clone)]
pub struct NodeLease {
    owner: Arc<BootIdentity>,
    host: String,
    id: u64,
    assignment_key: Vec<u8>,
    primary: bool,
    released: Arc<std::sync::atomic::AtomicBool>,
}
impl NodeLease {
    pub async fn refresh(&self) -> Result<bool, String> {
        self.change(false).await
    }
    pub async fn release(&self) -> Result<(), String> {
        self.change(true).await.map(|_| ())
    }
    async fn change(&self, release: bool) -> Result<bool, String> {
        use std::sync::atomic::Ordering;
        if self.released.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let owner = &self.owner;
        let _gate = owner.records.gate.lock().await;
        owner.records.resume().await?;
        loop {
            let host = self.assignment_key.clone();
            let key = lease_key(&self.host);
            let authority = owner.core.authority().map_err(error)?;
            let writer_key = writer_lease_key(authority.writer_epoch, authority.writer);
            let mut values = owner
                .records
                .records
                .read(&[
                    (NODE_SCHEMA, &host),
                    (NODE_SCHEMA, &key),
                    (NODE_SCHEMA, &writer_key),
                ])
                .await
                .map_err(error)?
                .into_iter();
            let assignment = values.next().ok_or("node observation missing")?;
            let lease = values.next().ok_or("lease observation missing")?;
            let writer_lease = values.next().ok_or("writer lease observation missing")?;
            let Some(bytes) = assignment.as_ref() else {
                return Ok(false);
            };
            let assignment_row = Assignment::parse(bytes.expose(&crate::seal::lend()))?;
            if assignment_row.id != self.id
                || assignment_row.epoch != authority.writer_epoch
                || assignment_row.writer != authority.writer
            {
                return Ok(false);
            }
            if self.primary {
                let Some(bytes) = lease.as_ref() else {
                    return Ok(false);
                };
                let row = LeaseRow::parse(bytes.expose(&crate::seal::lend()))?;
                if row.holder != owner.holder || row.expires_ms == 0 {
                    return Ok(false);
                }
            }
            let Some(writer_bytes) = writer_lease.as_ref() else {
                return Ok(false);
            };
            let writer_row = LeaseRow::parse(writer_bytes.expose(&crate::seal::lend()))?;
            let expires_ms = if release {
                0
            } else {
                owner
                    .now_ms()
                    .await?
                    .checked_add(LEASE_TTL_MS)
                    .ok_or("node lease expiry overflow")?
            };
            let mut predicates = vec![
                predicate(NODE_SCHEMA, host, assignment),
                predicate(NODE_SCHEMA, writer_key.clone(), writer_lease),
            ];
            let mut mutations = Vec::new();
            if self.primary {
                predicates.push(predicate(NODE_SCHEMA, key.clone(), lease));
                mutations.push(put(
                    NODE_SCHEMA,
                    key,
                    LeaseRow {
                        holder: owner.holder,
                        expires_ms,
                    }
                    .bytes(),
                ));
            }
            if !release {
                mutations.push(put(
                    NODE_SCHEMA,
                    writer_key,
                    LeaseRow {
                        holder: writer_row.holder,
                        expires_ms,
                    }
                    .bytes(),
                ));
            } else if !self.primary {
                // Keep the shared lease live for other nodes. A secondary has
                // no host lease to release; its assignment is immutable history.
                self.released.store(true, Ordering::SeqCst);
                return Ok(true);
            }
            if owner.records.decide(predicates, mutations).await? {
                if release {
                    self.released.store(true, Ordering::SeqCst);
                }
                return Ok(true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::host_records::tests::{attach, Backend};
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn verified_imported_journal_is_discoverable_without_assignment_or_lease() {
        use crate::persistence::import_target::journal as import;
        struct Original(Vec<u8>);
        impl import::IndexedFrames for Original {
            fn count(&self) -> u64 {
                1
            }
            fn frame(&mut self, ordinal: u64) -> Result<Vec<u8>, import::Error> {
                if ordinal != 1 {
                    return Err(import::Error::Invalid);
                }
                Ok(self.0.clone())
            }
        }
        let body = b"original retained journal".to_vec();
        let mut original = busbar_kernel_wal::JournalRecord {
            class: busbar_kernel_wal::RecordClass::Reconciliation,
            node: 7,
            node_seq: 9,
            lease_epoch: 1,
            policy_epoch: 1,
            wall: 10,
            mono: 1,
            body_hash: busbar_kernel_wal::journal::body_digest(&body),
            body,
            prev_hash: [17; 32],
            hash: [0; 32],
        };
        original.hash = original.digest_of_chain();
        let proof = import::verify_source(
            7,
            &mut Original(original.encode()),
            import::SourceBudget {
                max_frame_bytes: 4096,
                max_reads: 4,
            },
        )
        .unwrap();
        let (address, value) = import::inventory_row(&proof).unwrap();
        assert!(import::inventory_matches(&proof, &address, &value));
        assert!(import::inventory_address_class(&address));
        for malformed in [
            b"journal:".as_slice(),
            b"journal:x",
            b"journal:\0\0\0\0\0\0\0\0",
        ] {
            let reserved =
                super::super::scoped::migration_address(true, INSTANCE, NODE_SCHEMA, malformed)
                    .unwrap();
            assert!(import::inventory_address_class(&reserved));
            assert!(!import::inventory_matches(&proof, &reserved, &value));
        }
        let assignment =
            super::super::scoped::migration_address(true, INSTANCE, NODE_SCHEMA, &host_key("host"))
                .unwrap();
        assert!(!import::inventory_address_class(&assignment));
        let key = journal_inventory_key(7);
        let bytes = value.expose(&crate::seal::lend());
        assert_eq!(journal_inventory_node(&key, bytes).unwrap(), 7);
        // Every retained field, including both historical digests, participates
        // in the inventory checksum. A different stored identity is refused.
        for at in 0..bytes.len() {
            let mut altered = bytes.clone();
            altered[at] ^= 1;
            assert!(journal_inventory_node(&key, &altered).is_err());
        }
        assert!(journal_inventory_node(&journal_inventory_key(8), bytes).is_err());
        let backend = Arc::new(Backend::default());
        let core = Arc::new(attach(backend).await);
        let owner = BootIdentity::new(core).unwrap();
        assert!(owner
            .records
            .decide(
                vec![predicate(NODE_SCHEMA, key.clone(), None)],
                vec![put(NODE_SCHEMA, key.clone(), bytes.clone())]
            )
            .await
            .unwrap());
        let nodes = owner.registered().await.unwrap();
        assert_eq!(nodes, vec![("journal:0000000000000007".into(), 7)]);
        let absent = owner
            .records
            .records
            .read(&[
                (NODE_SCHEMA, &host_key("journal:0000000000000007")),
                (NODE_SCHEMA, &lease_key("journal:0000000000000007")),
                (NODE_SCHEMA, &id_key(7)),
            ])
            .await
            .unwrap();
        assert!(absent.iter().all(Option::is_none));
        let mut corrupt = bytes.clone();
        corrupt[64] ^= 1;
        assert!(owner
            .records
            .decide(
                vec![predicate(NODE_SCHEMA, key.clone(), Some(value))],
                vec![put(NODE_SCHEMA, key, corrupt)]
            )
            .await
            .unwrap());
        assert!(owner.registered().await.is_err());
    }

    #[tokio::test]
    async fn new_holder_never_reuses_a_live_or_released_historical_node() {
        let backend = Arc::new(Backend::default());
        let core = Arc::new(attach(backend).await);
        let owner = Arc::new(BootIdentity::new(core.clone()).unwrap());
        let first = owner.take_node("host").await.unwrap();
        assert_eq!(owner.take_node("host").await.unwrap().id, first.id);
        let concurrent = Arc::new(BootIdentity::new(core.clone()).unwrap());
        let second = concurrent.take_node("host").await.unwrap();
        assert_ne!(first.id, second.id);
        assert!(second.lease.is_some());
        first.lease.as_ref().unwrap().release().await.unwrap();
        let reopened = Arc::new(BootIdentity::new(core).unwrap());
        let third = reopened.take_node("host").await.unwrap();
        assert_ne!(first.id, third.id);
        assert_ne!(second.id, third.id);
        assert!(third.lease.is_some());
        assert!(!first.lease.unwrap().refresh().await.unwrap());
        let nodes = reopened.registered().await.unwrap();
        for id in [first.id, second.id, third.id] {
            assert!(nodes.iter().any(|(_, found)| *found == id));
        }
    }

    #[tokio::test]
    async fn renewal_changes_exact_lease_bytes_and_rejects_stale_mutation() {
        let backend = Arc::new(Backend::default());
        let owner = Arc::new(BootIdentity::new(Arc::new(attach(backend.clone()).await)).unwrap());
        let taken = owner.take_node("renewal").await.unwrap();
        let lease = taken.lease.unwrap();
        let key = lease_key("renewal");
        let before = owner.records.records.get(NODE_SCHEMA, &key).await.unwrap();
        backend.now.fetch_add(1, Ordering::SeqCst);
        assert!(lease.refresh().await.unwrap());
        let after = owner.records.records.get(NODE_SCHEMA, &key).await.unwrap();
        assert_ne!(before, after);
        assert!(!owner
            .records
            .decide(
                vec![predicate(NODE_SCHEMA, key, before)],
                vec![put(
                    NODE_SCHEMA,
                    b"stale-renewal-must-not-write".to_vec(),
                    vec![1]
                )],
            )
            .await
            .unwrap());
        assert!(owner
            .records
            .records
            .get(NODE_SCHEMA, b"stale-renewal-must-not-write")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn secondary_heartbeat_keeps_shared_writer_lease_after_primary_release() {
        let backend = Arc::new(Backend::default());
        let core = Arc::new(attach(backend.clone()).await);
        let primary_owner = Arc::new(BootIdentity::new(core.clone()).unwrap());
        let primary = primary_owner
            .take_node("shared")
            .await
            .unwrap()
            .lease
            .unwrap();
        let secondary_owner = Arc::new(BootIdentity::new(core.clone()).unwrap());
        let secondary = secondary_owner
            .take_node("shared")
            .await
            .unwrap()
            .lease
            .unwrap();
        let authority = core.authority().unwrap();
        let key = writer_lease_key(authority.writer_epoch, authority.writer);
        let before = secondary_owner
            .records
            .records
            .get(NODE_SCHEMA, &key)
            .await
            .unwrap()
            .unwrap();
        primary.release().await.unwrap();
        assert!(!primary.refresh().await.unwrap());
        backend.now.fetch_add(1, Ordering::SeqCst);
        assert!(secondary.refresh().await.unwrap());
        let after = secondary_owner
            .records
            .records
            .get(NODE_SCHEMA, &key)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(before, after);
        let row = LeaseRow::parse(after.expose(&crate::seal::lend())).unwrap();
        assert_eq!(row.expires_ms, 20_000);
        secondary.release().await.unwrap();
        assert_eq!(
            secondary_owner
                .records
                .records
                .get(NODE_SCHEMA, &key)
                .await
                .unwrap()
                .unwrap(),
            after
        );
    }

    #[tokio::test]
    async fn stale_lease_cannot_renew_or_release_replacement_missing_or_reassigned_owner() {
        for change in 0..4 {
            let backend = Arc::new(Backend::default());
            let owner = Arc::new(BootIdentity::new(Arc::new(attach(backend).await)).unwrap());
            let taken = owner.take_node("replaced").await.unwrap();
            let lease = taken.lease.unwrap();
            let key = lease_key("replaced");
            match change {
                0 => lease.release().await.unwrap(),
                1 => {
                    assert!(owner
                        .records
                        .decide(
                            vec![],
                            vec![put(
                                NODE_SCHEMA,
                                key.clone(),
                                LeaseRow {
                                    holder: [owner.holder[0].wrapping_add(1); 16],
                                    expires_ms: u64::MAX
                                }
                                .bytes()
                            )]
                        )
                        .await
                        .unwrap());
                }
                2 => {
                    assert!(owner
                        .records
                        .decide(
                            vec![],
                            vec![Mutation::Delete {
                                schema: NODE_SCHEMA.into(),
                                key: key.clone(),
                            }]
                        )
                        .await
                        .unwrap());
                }
                _ => {
                    let authority = owner.core.authority().unwrap();
                    assert!(owner
                        .records
                        .decide(
                            vec![],
                            vec![put(
                                NODE_SCHEMA,
                                host_key("replaced"),
                                Assignment {
                                    id: taken.id.wrapping_add(1),
                                    epoch: authority.writer_epoch,
                                    writer: authority.writer
                                }
                                .bytes()
                            )]
                        )
                        .await
                        .unwrap());
                }
            }
            let before = owner.records.records.get(NODE_SCHEMA, &key).await.unwrap();
            assert!(!lease.refresh().await.unwrap(), "change {change}");
            lease.release().await.unwrap();
            assert_eq!(
                owner.records.records.get(NODE_SCHEMA, &key).await.unwrap(),
                before,
                "stale release must preserve current lease for change {change}"
            );
        }
    }

    #[tokio::test]
    async fn cancelled_keyset_write_keeps_original_body_before_a_new_call_can_plan() {
        let backend = Arc::new(Backend::default());
        let core = Arc::new(attach(backend.clone()).await);
        let owner = BootIdentity::new(core).unwrap();
        backend.hang.store(true, Ordering::SeqCst);
        {
            let write = owner.keep_keyset("original");
            tokio::pin!(write);
            assert!(futures::poll!(&mut write).is_pending());
            assert!(owner.records.pending.lock().unwrap().is_some());
        }
        backend.hang.store(false, Ordering::SeqCst);
        assert_eq!(owner.keep_keyset("replacement").await.unwrap(), "original");
        assert!(owner.records.pending.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn lost_keyset_acknowledgement_replays_before_publishing() {
        let backend = Arc::new(Backend::default());
        let owner = BootIdentity::new(Arc::new(attach(backend.clone()).await)).unwrap();
        backend.lose_reply.store(true, Ordering::SeqCst);
        assert_eq!(owner.keep_keyset("seed").await.unwrap(), "seed");
        assert!(!backend.lose_reply.load(Ordering::SeqCst));
        assert!(owner.records.pending.lock().unwrap().is_none());
    }
}
