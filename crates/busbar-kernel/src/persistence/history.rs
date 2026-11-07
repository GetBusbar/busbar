// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-authorized envelope collections. Payloads are opaque raw bytes, separate
//! from strict versioned metadata. Relationships are explicit core declarations;
//! a durable immutable descriptor refuses changed declarations until migration.
//! Listings are non-snapshot across partitions. Mutation plans compare every
//! observed partition generation and publish all deletions atomically.

use super::{
    commit::SubmitResult,
    facade::{
        AccessError, CoreStore, LogicalClaim, LogicalId, LogicalPermit, PendingId, Submission,
    },
    fences::scan_guard,
    keys, partition,
};
use busbar_contract::{
    persistence::{
        Address, Candidate, Decision, ExpectedValue, Failure, Mutation, NamespaceId, Predicate,
        PreparedCandidate, Read, ReadResult, CANDIDATE_VERSION,
    },
    records::{
        AuditRecord, PlaneDisposition, PlaneRecord, PlaneRecordRef, PlaneSelector, Retention,
    },
    Secret,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const HISTORY: NamespaceId = NamespaceId(*b"busbar.history1\0");
const INDEX: NamespaceId = NamespaceId(*b"busbar.histidx1\0");
const DECLARATIONS: NamespaceId = NamespaceId(*b"busbar.histdecl1");
const AUDIT: NamespaceId = NamespaceId(*b"busbar.audit.v1\0");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Upsert,
    Append,
}
#[derive(Debug, Clone, Copy)]
pub struct Collection<'a> {
    pub kind: &'a str,
    pub mode: Mode,
    pub retention: Retention,
    /// A parent's identity is its upsert id. Append collections cannot be parents.
    pub parent: Option<&'a str>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unauthorized,
    Invalid,
    Corrupt,
    MissingParent,
    Conflict,
    Fork,
    Overflow,
    Access(AccessError),
    Backend(Failure),
}
type Result<T> = std::result::Result<T, Error>;
impl From<AccessError> for Error {
    fn from(e: AccessError) -> Self {
        Self::Access(e)
    }
}
impl From<Failure> for Error {
    fn from(e: Failure) -> Self {
        Self::Backend(e)
    }
}
impl From<keys::KeyError> for Error {
    fn from(_: keys::KeyError) -> Self {
        Self::Invalid
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Conflict,
    OpIdConflict,
    Pending(PendingId),
    Reconcile(PendingId),
    Busy(PendingId),
    NoEffect(Failure),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Versioned<T> {
    version: u32,
    record: T,
}
fn encode<T: Serialize>(record: &T) -> Result<Secret<Vec<u8>>> {
    serde_json::to_vec(&Versioned { version: 1, record })
        .map(Secret::new)
        .map_err(|_| Error::Invalid)
}
fn decode<T: DeserializeOwned>(bytes: &Secret<Vec<u8>>) -> Result<T> {
    let row: Versioned<T> =
        serde_json::from_slice(bytes.expose(&crate::seal::lend())).map_err(|_| Error::Corrupt)?;
    if row.version != 1 {
        return Err(Error::Corrupt);
    }
    Ok(row.record)
}
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Metadata {
    kind: String,
    id: String,
    parent: Option<String>,
    seq: u64,
    ts: u64,
    disposition: PlaneDisposition,
    parent_life: Option<u64>,
}
impl Metadata {
    fn new(r: PlaneRecordRef<'_>, parent_life: Option<u64>) -> Self {
        Self {
            kind: r.kind.into(),
            id: r.id.into(),
            parent: r.parent.map(str::to_owned),
            seq: r.seq,
            ts: r.ts,
            disposition: r.disposition,
            parent_life,
        }
    }
    fn record(self, body: Vec<u8>) -> PlaneRecord {
        PlaneRecord {
            kind: self.kind,
            id: self.id,
            parent: self.parent,
            seq: self.seq,
            ts: self.ts,
            disposition: self.disposition,
            body,
        }
    }
}
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
struct Life {
    serial: u64,
    alive: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Partition {
    identity: String,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Declaration {
    kind: String,
    mode: u8,
    retention: u32,
    parent: Option<String>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Declarations {
    collections: Vec<Declaration>,
}
struct Row {
    meta: Metadata,
    body: Secret<Vec<u8>>,
    meta_at: Address,
    body_at: Address,
}
struct Observed {
    rows: Vec<Row>,
    life: Option<Life>,
}

fn validated_declarations<'a>(
    declarations: impl IntoIterator<Item = Collection<'a>>,
) -> Result<BTreeMap<&'a str, Collection<'a>>> {
    let mut map = BTreeMap::new();
    for declaration in declarations {
        if declaration.kind.is_empty() || map.insert(declaration.kind, declaration).is_some() {
            return Err(Error::Invalid);
        }
    }
    for declaration in map.values() {
        let mut seen = BTreeSet::new();
        let mut next = Some(declaration.kind);
        while let Some(kind) = next {
            if !seen.insert(kind) {
                return Err(Error::Invalid);
            }
            let current = map.get(kind).ok_or(Error::Unauthorized)?;
            if let Some(parent) = current.parent {
                if map.get(parent).ok_or(Error::Unauthorized)?.mode != Mode::Upsert {
                    return Err(Error::Invalid);
                }
            }
            next = current.parent;
        }
    }
    Ok(map)
}

fn declaration_address(owner: &str) -> Result<Address> {
    Ok(Address {
        namespace: partition::namespace(DECLARATIONS, &[owner.as_bytes()]).0,
        key: keys::framed(b'D', &[&DECLARATIONS.0, owner.as_bytes()])?,
    })
}
fn history_prefix(
    owner: &str,
    family: NamespaceId,
    kind: &str,
    identity: Option<&str>,
) -> Result<Vec<u8>> {
    let mut parts = vec![family.0.as_slice(), owner.as_bytes(), kind.as_bytes()];
    if let Some(identity) = identity {
        parts.push(identity.as_bytes());
    }
    Ok(keys::framed(b'H', &parts)?)
}
fn history_namespace(owner: &str, kind: &str, identity: &str) -> NamespaceId {
    partition::namespace(
        HISTORY,
        &[owner.as_bytes(), kind.as_bytes(), identity.as_bytes()],
    )
}
fn history_address(owner: &str, kind: &str, identity: &str, tag: u8, seq: u64) -> Result<Address> {
    let mut key = history_prefix(owner, HISTORY, kind, Some(identity))?;
    key.push(tag);
    key.extend_from_slice(&seq.to_be_bytes());
    Ok(Address {
        namespace: history_namespace(owner, kind, identity).0,
        key,
    })
}
fn index_address(owner: &str, kind: &str, identity: &str) -> Result<Address> {
    Ok(Address {
        namespace: partition::namespace(INDEX, &[owner.as_bytes(), kind.as_bytes()]).0,
        key: history_prefix(owner, INDEX, kind, Some(identity))?,
    })
}
fn declaration_metadata(declarations: &BTreeMap<&str, Collection<'_>>) -> Declarations {
    Declarations {
        collections: declarations
            .values()
            .map(|d| Declaration {
                kind: d.kind.into(),
                mode: match d.mode {
                    Mode::Upsert => 0,
                    Mode::Append => 1,
                },
                retention: d.retention.code(),
                parent: d.parent.map(str::to_owned),
            })
            .collect(),
    }
}

/// Encode one row of a fenced fresh legacy snapshot using the live owner's
/// exact metadata and addresses. Caller verifies source graph membership and
/// coalesces identical descriptor/index rows before atomic destination commits.
/// Legacy upsert identities start at incarnation one; parent_life is explicitly
/// supplied by the compiled source binding, never inferred from the payload.
pub(crate) fn migration_rows<'a>(
    owner: &str,
    declarations: impl IntoIterator<Item = Collection<'a>>,
    record: PlaneRecordRef<'_>,
    parent_life: Option<u64>,
) -> Result<Vec<(Address, Secret<Vec<u8>>)>> {
    let declarations = validated_declarations(declarations)?;
    let declaration = declarations.get(record.kind).ok_or(Error::Unauthorized)?;
    if declaration.parent.is_some() != parent_life.is_some()
        || parent_life == Some(0)
        || declaration.parent.is_some() && record.parent.is_none()
    {
        return Err(Error::Invalid);
    }
    let identity = if declaration.mode == Mode::Upsert {
        record.id
    } else {
        record.parent.unwrap_or(record.id)
    };
    let seq = if declaration.mode == Mode::Upsert {
        0
    } else {
        record.seq
    };
    let mut rows = vec![
        (
            declaration_address(owner)?,
            encode(&declaration_metadata(&declarations))?,
        ),
        (
            index_address(owner, record.kind, identity)?,
            encode(&Partition {
                identity: identity.into(),
            })?,
        ),
        (
            history_address(owner, record.kind, identity, b'M', seq)?,
            encode(&Metadata::new(record, parent_life))?,
        ),
        (
            history_address(owner, record.kind, identity, b'B', seq)?,
            Secret::new(record.body.to_vec()),
        ),
    ];
    if declaration.mode == Mode::Upsert {
        rows.push((
            history_address(owner, record.kind, identity, b'L', 0)?,
            encode(&Life {
                serial: 1,
                alive: true,
            })?,
        ));
    }
    Ok(rows)
}

pub(crate) fn migration_authorizes<'a>(
    owner: &str,
    declarations: impl IntoIterator<Item = Collection<'a>>,
    address: &Address,
) -> bool {
    let Ok(declarations) = validated_declarations(declarations) else {
        return false;
    };
    if declaration_address(owner).is_ok_and(|at| at == *address) {
        return true;
    }
    if let Ok(parts) = keys::components(&address.key, b'H') {
        if parts.len() == 4 && parts[0] == INDEX.0 && parts[1] == owner.as_bytes() {
            if let (Ok(kind), Ok(identity)) =
                (std::str::from_utf8(parts[2]), std::str::from_utf8(parts[3]))
            {
                return declarations.contains_key(kind)
                    && index_address(owner, kind, identity).is_ok_and(|at| at == *address);
            }
        }
    }
    let Some(split) = address.key.len().checked_sub(9) else {
        return false;
    };
    let Ok(parts) = keys::components(&address.key[..split], b'H') else {
        return false;
    };
    if parts.len() != 4 || parts[0] != HISTORY.0 || parts[1] != owner.as_bytes() {
        return false;
    }
    let (Ok(kind), Ok(identity)) = (std::str::from_utf8(parts[2]), std::str::from_utf8(parts[3]))
    else {
        return false;
    };
    let Some(declaration) = declarations.get(kind) else {
        return false;
    };
    let tag = address.key[split];
    let Ok(sequence) = address.key[split + 1..].try_into().map(u64::from_be_bytes) else {
        return false;
    };
    if !matches!(tag, b'M' | b'B') && !(tag == b'L' && declaration.mode == Mode::Upsert) {
        return false;
    }
    if declaration.mode == Mode::Upsert && sequence != 0 {
        return false;
    }
    history_address(owner, kind, identity, tag, sequence).is_ok_and(|at| at == *address)
}

/// One immutable native candidate is retained by CoreStore after uncertainty.
/// Call retry with that PendingId; never repeat planning to resolve Unknown.
pub(crate) struct History<'a> {
    store: &'a CoreStore,
    owner: &'a str,
    declarations: BTreeMap<&'a str, Collection<'a>>,
}
impl<'a> History<'a> {
    pub(crate) fn authorized(
        store: &'a CoreStore,
        owner: &'a str,
        declarations: impl IntoIterator<Item = Collection<'a>>,
    ) -> Result<Self> {
        let map = validated_declarations(declarations)?;
        Ok(Self {
            store,
            owner,
            declarations: map,
        })
    }
    async fn plan(&self) -> Result<Plan<'a>> {
        let mut plan = Plan::new(self.store);
        let expected = declaration_metadata(&self.declarations);
        let at = declaration_address(self.owner)?;
        if let Some(bytes) = plan.one(at.clone()).await? {
            if decode::<Declarations>(&bytes)? != expected {
                return Err(Error::Unauthorized);
            }
        } else {
            // An owner without a descriptor is virgin, never an implicit legacy
            // adoption. Known partition indexes must all be empty before binding.
            for kind in self.declarations.keys() {
                if !plan
                    .scan(self.index_namespace(kind), self.prefix(INDEX, kind, None)?)
                    .await?
                    .is_empty()
                {
                    return Err(Error::Corrupt);
                }
            }
            plan.initialization = Some((at, encode(&expected)?));
        }
        Ok(plan)
    }
    fn declaration(&self, kind: &str) -> Result<Collection<'a>> {
        self.declarations
            .get(kind)
            .copied()
            .ok_or(Error::Unauthorized)
    }
    fn prefix(&self, family: NamespaceId, kind: &str, identity: Option<&str>) -> Result<Vec<u8>> {
        history_prefix(self.owner, family, kind, identity)
    }
    fn namespace(&self, kind: &str, identity: &str) -> NamespaceId {
        history_namespace(self.owner, kind, identity)
    }
    fn index_namespace(&self, kind: &str) -> NamespaceId {
        partition::namespace(INDEX, &[self.owner.as_bytes(), kind.as_bytes()])
    }
    fn address(&self, kind: &str, identity: &str, tag: u8, seq: u64) -> Result<Address> {
        history_address(self.owner, kind, identity, tag, seq)
    }
    fn index_address(&self, kind: &str, identity: &str) -> Result<Address> {
        index_address(self.owner, kind, identity)
    }
    async fn observe(&self, plan: &mut Plan<'_>, kind: &str, identity: &str) -> Result<Observed> {
        let declaration = self.declaration(kind)?;
        let prefix = self.prefix(HISTORY, kind, Some(identity))?;
        let found = plan
            .scan(self.namespace(kind, identity), prefix.clone())
            .await?;
        if plan.initialization.is_some() && !found.is_empty() {
            return Err(Error::Corrupt);
        }
        let mut values: BTreeMap<_, _> = found.into_iter().collect();
        let life_at = self.address(kind, identity, b'L', 0)?;
        let life = values
            .remove(&life_at)
            .map(|v| decode::<Life>(&v))
            .transpose()?;
        if life.is_some_and(|v| v.serial == 0) {
            return Err(Error::Corrupt);
        }
        let mut rows = Vec::new();
        let meta_keys: Vec<_> = values
            .keys()
            .filter(|a| a.key.get(prefix.len()) == Some(&b'M'))
            .cloned()
            .collect();
        for at in meta_keys {
            let meta: Metadata = decode(&values.remove(&at).ok_or(Error::Corrupt)?)?;
            let seq = if declaration.mode == Mode::Upsert {
                0
            } else {
                meta.seq
            };
            let record_identity = if declaration.mode == Mode::Upsert {
                &meta.id
            } else {
                meta.parent.as_deref().unwrap_or(&meta.id)
            };
            if meta.kind != kind
                || record_identity != identity
                || at != self.address(kind, identity, b'M', seq)?
                || declaration.parent.is_some() != meta.parent_life.is_some()
                || meta.parent_life == Some(0)
                || declaration.parent.is_some() && meta.parent.is_none()
            {
                return Err(Error::Corrupt);
            }
            let body_at = self.address(kind, identity, b'B', seq)?;
            let body = values.remove(&body_at).ok_or(Error::Corrupt)?;
            rows.push(Row {
                meta,
                body,
                meta_at: at,
                body_at,
            });
        }
        if !values.is_empty()
            || (declaration.mode == Mode::Upsert
                && (rows.len() > 1 || life.is_some_and(|l| l.alive) != !rows.is_empty()))
            || declaration.mode == Mode::Append && life.is_some()
        {
            return Err(Error::Corrupt);
        }
        Ok(Observed { rows, life })
    }
    async fn identities(&self, plan: &mut Plan<'_>, kind: &str) -> Result<Vec<String>> {
        self.declaration(kind)?;
        let rows = plan
            .scan(self.index_namespace(kind), self.prefix(INDEX, kind, None)?)
            .await?;
        let mut result = Vec::new();
        for (at, bytes) in rows {
            let row: Partition = decode(&bytes)?;
            if at != self.index_address(kind, &row.identity)? {
                return Err(Error::Corrupt);
            }
            result.push(row.identity);
        }
        Ok(result)
    }
    async fn ensure_index(&self, plan: &mut Plan<'_>, kind: &str, identity: &str) -> Result<()> {
        let at = self.index_address(kind, identity)?;
        if let Some(bytes) = plan.one(at.clone()).await? {
            if decode::<Partition>(&bytes)?.identity != identity {
                return Err(Error::Corrupt);
            }
            // Entries are permanent. Existing membership needs no write guard.
            plan.guards.remove(&at);
        } else {
            plan.put(
                at,
                encode(&Partition {
                    identity: identity.into(),
                })?,
            );
        }
        Ok(())
    }
    /// Coherent envelope and raw body observation for future host owners.
    pub(crate) async fn get(&self, kind: &str, id: &str) -> Result<Option<PlaneRecord>> {
        if self.declaration(kind)?.mode != Mode::Upsert {
            return Err(Error::Invalid);
        }
        let mut plan = self.plan().await?;
        Ok(self
            .observe(&mut plan, kind, id)
            .await?
            .rows
            .into_iter()
            .next()
            .map(|r| r.meta.record(r.body.expose(&crate::seal::lend()).clone())))
    }
    pub(crate) async fn upsert(&self, record: PlaneRecordRef<'_>) -> Result<Outcome> {
        self.write(record, Mode::Upsert, None).await
    }
    pub(crate) async fn append(&self, record: PlaneRecordRef<'_>) -> Result<Outcome> {
        self.write(record, Mode::Append, None).await
    }
    pub(crate) async fn append_with_id(
        &self,
        operation: [u8; 16],
        record: PlaneRecordRef<'_>,
    ) -> Result<Outcome> {
        self.write(record, Mode::Append, Some(operation)).await
    }
    pub(crate) async fn upsert_with_id(
        &self,
        operation: [u8; 16],
        record: PlaneRecordRef<'_>,
    ) -> Result<Outcome> {
        self.write(record, Mode::Upsert, Some(operation)).await
    }
    async fn write(
        &self,
        record: PlaneRecordRef<'_>,
        mode: Mode,
        operation: Option<[u8; 16]>,
    ) -> Result<Outcome> {
        let declaration = self.declaration(record.kind)?;
        if declaration.mode != mode || record.seq > i64::MAX as u64 || record.ts > i64::MAX as u64 {
            return Err(Error::Invalid);
        }
        let permit = if let Some(operation) = operation {
            if operation == [0; 16] {
                return Err(Error::Invalid);
            }
            let metadata = encode(&Metadata::new(record, None))?;
            let declarations = encode(&declaration_metadata(&self.declarations))?;
            let seal = crate::seal::lend();
            let mut hash = Sha256::new();
            hash.update(b"busbar.history-request.v1");
            for bytes in [
                self.owner.as_bytes(),
                metadata.expose(&seal).as_slice(),
                declarations.expose(&seal).as_slice(),
                record.body,
            ] {
                hash.update((bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
            }
            match self.store.claim_logical(
                LogicalId {
                    namespace: HISTORY.0,
                    operation,
                },
                hash.finalize().into(),
            ) {
                Ok(LogicalClaim::Prepare(permit)) => Some(permit),
                Ok(LogicalClaim::Retained(id)) => return self.retry(id).await,
                Ok(LogicalClaim::Busy) => return Err(Error::Access(AccessError::Overloaded)),
                Err(AccessError::OperationConflict) => return Ok(Outcome::OpIdConflict),
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        let identity = if mode == Mode::Upsert {
            record.id
        } else {
            record.parent.unwrap_or(record.id)
        };
        let mut plan = self.plan().await?;
        plan.logical = permit;
        let parent_life = if let Some(parent_kind) = declaration.parent {
            let parent = self
                .observe(
                    &mut plan,
                    parent_kind,
                    record.parent.ok_or(Error::MissingParent)?,
                )
                .await?;
            Some(
                parent
                    .life
                    .filter(|l| l.alive)
                    .ok_or(Error::MissingParent)?
                    .serial,
            )
        } else {
            None
        };
        let observed = self.observe(&mut plan, record.kind, identity).await?;
        let meta = Metadata::new(record, parent_life);
        if mode == Mode::Append {
            if let Some(existing) = observed.rows.iter().find(|r| r.meta.seq == record.seq) {
                if existing.meta != meta
                    || existing.body.expose(&crate::seal::lend()) != record.body
                {
                    return Err(Error::Fork);
                }
                // An exact replay still compares the parent life and observed generation.
                return plan.submit().await;
            }
        } else {
            let serial = match observed.life {
                Some(life) if life.alive => life.serial,
                Some(life) => life.serial.checked_add(1).ok_or(Error::Overflow)?,
                None => 1,
            };
            plan.put(
                self.address(record.kind, identity, b'L', 0)?,
                encode(&Life {
                    serial,
                    alive: true,
                })?,
            );
        }
        self.ensure_index(&mut plan, record.kind, identity).await?;
        let seq = if mode == Mode::Upsert { 0 } else { record.seq };
        plan.put(
            self.address(record.kind, identity, b'M', seq)?,
            encode(&meta)?,
        );
        plan.put(
            self.address(record.kind, identity, b'B', seq)?,
            Secret::new(record.body.to_vec()),
        );
        plan.submit().await
    }
    async fn all(&self, plan: &mut Plan<'_>, kind: &str) -> Result<Vec<Row>> {
        let mut rows = Vec::new();
        for identity in self.identities(plan, kind).await? {
            rows.extend(self.observe(plan, kind, &identity).await?.rows);
        }
        rows.sort_by(|a, b| {
            (
                a.meta.seq,
                a.meta.parent.as_deref().unwrap_or(&a.meta.id),
                &a.meta.id,
            )
                .cmp(&(
                    b.meta.seq,
                    b.meta.parent.as_deref().unwrap_or(&b.meta.id),
                    &b.meta.id,
                ))
        });
        Ok(rows)
    }
    /// Non-snapshot across partitions, with each partition's pages generation-pinned.
    pub(crate) async fn list(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Result<Vec<PlaneRecord>> {
        let mut plan = self.plan().await?;
        let rows = self.all(&mut plan, kind).await?;
        Ok(rows
            .into_iter()
            .filter(|r| match selector {
                PlaneSelector::All => true,
                PlaneSelector::Parent(p) => r.meta.parent.as_deref() == Some(p.as_ref()),
            })
            .map(|r| r.meta.record(r.body.expose(&crate::seal::lend()).clone()))
            .collect())
    }
    pub(crate) async fn parents(&self, kind: &str) -> Result<Vec<String>> {
        Ok(self
            .list(kind, &PlaneSelector::All)
            .await?
            .into_iter()
            .filter_map(|r| r.parent)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }
    async fn cascade(&self, plan: &mut Plan<'_>, initial: Vec<(String, String)>) -> Result<()> {
        let mut pending = initial;
        let mut visited = BTreeSet::new();
        while let Some((kind, id)) = pending.pop() {
            if !visited.insert((kind.clone(), id.clone())) {
                continue;
            }
            let declaration = self.declaration(&kind)?;
            let observed = self.observe(plan, &kind, &id).await?;
            if declaration.mode != Mode::Upsert {
                return Err(Error::Invalid);
            }
            if !observed.life.is_some_and(|l| l.alive) {
                continue;
            }
            let life = observed.life.ok_or(Error::Corrupt)?;
            plan.put(
                self.address(&kind, &id, b'L', 0)?,
                encode(&Life {
                    serial: life.serial.checked_add(1).ok_or(Error::Overflow)?,
                    alive: false,
                })?,
            );
            for row in observed.rows {
                plan.delete(row.meta_at);
                plan.delete(row.body_at);
            }
            for child in self
                .declarations
                .values()
                .filter(|c| c.parent == Some(kind.as_str()))
            {
                // Upsert children partition by their own identity; their explicit
                // collection index is the complete enumeration, including empties.
                let children = if child.mode == Mode::Append {
                    self.observe(plan, child.kind, &id).await?.rows
                } else {
                    self.all(plan, child.kind).await?
                };
                for row in children
                    .into_iter()
                    .filter(|r| r.meta.parent.as_deref() == Some(id.as_str()))
                {
                    if row.meta.parent_life != Some(life.serial) {
                        return Err(Error::Corrupt);
                    }
                    if child.mode == Mode::Upsert {
                        pending.push((child.kind.into(), row.meta.id));
                    } else {
                        plan.delete(row.meta_at);
                        plan.delete(row.body_at);
                    }
                }
            }
        }
        Ok(())
    }
    pub(crate) async fn delete(&self, kind: &str, id: &str) -> Result<Outcome> {
        let mut plan = self.plan().await?;
        if self.declaration(kind)?.mode == Mode::Upsert {
            self.cascade(&mut plan, vec![(kind.into(), id.into())])
                .await?;
        } else {
            // Legacy delete identifies an append chain, not the child row's id.
            for row in self.observe(&mut plan, kind, id).await?.rows {
                plan.delete(row.meta_at);
                plan.delete(row.body_at);
            }
        }
        plan.submit().await
    }
    /// Retention belongs to the authorized declaration. All selected effects,
    /// including recursive child cascades, share one candidate (never page commits).
    pub(crate) async fn purge(&self, kind: &str, before: u64) -> Result<(Outcome, u64)> {
        let declaration = self.declaration(kind)?;
        let mut plan = self.plan().await?;
        let selected: Vec<_> = self
            .all(&mut plan, kind)
            .await?
            .into_iter()
            .filter(|r| {
                declaration
                    .retention
                    .drops(r.meta.ts, before, r.meta.disposition)
            })
            .collect();
        let count = u64::try_from(selected.len()).map_err(|_| Error::Overflow)?;
        if declaration.mode == Mode::Upsert {
            self.cascade(
                &mut plan,
                selected
                    .into_iter()
                    .map(|r| (kind.into(), r.meta.id))
                    .collect(),
            )
            .await?;
        } else {
            for row in selected {
                plan.delete(row.meta_at);
                plan.delete(row.body_at);
            }
        }
        // Count is proposed; callers publish it only when outcome is Applied.
        Ok((plan.submit().await?, count))
    }
    pub(crate) async fn retry(&self, id: PendingId) -> Result<Outcome> {
        outcome(self.store.retry(id).await?)
    }
}

struct Plan<'a> {
    store: &'a CoreStore,
    guards: BTreeMap<Address, ExpectedValue>,
    changes: BTreeMap<Address, Option<Secret<Vec<u8>>>>,
    logical: Option<LogicalPermit<'a>>,
    initialization: Option<(Address, Secret<Vec<u8>>)>,
}
impl<'a> Plan<'a> {
    fn new(store: &'a CoreStore) -> Self {
        Self {
            store,
            guards: BTreeMap::new(),
            changes: BTreeMap::new(),
            logical: None,
            initialization: None,
        }
    }
    fn guard(&mut self, at: Address, expected: ExpectedValue) -> Result<()> {
        if let Some(old) = self.guards.get(&at) {
            let same = match (old, &expected) {
                (ExpectedValue::Absent, ExpectedValue::Absent) => true,
                (ExpectedValue::Exact(a), ExpectedValue::Exact(b)) => a == b,
                _ => false,
            };
            if !same {
                return Err(Error::Conflict);
            }
        } else {
            self.guards.insert(at, expected);
        }
        Ok(())
    }
    async fn one(&mut self, at: Address) -> Result<Option<Secret<Vec<u8>>>> {
        let result = self
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.store.info().dataset,
                addresses: vec![at.clone()],
                time: None,
            }))
            .await?;
        let ReadResult::Values {
            observed_at,
            mut values,
        } = result
        else {
            return Err(Error::Corrupt);
        };
        if values.len() != 1 || observed_at.authority != self.store.info().clock_authority {
            return Err(Error::Corrupt);
        }
        let value = values.pop().ok_or(Error::Corrupt)?;
        self.guard(
            at,
            value
                .clone()
                .map_or(ExpectedValue::Absent, ExpectedValue::Exact),
        )?;
        Ok(value)
    }
    async fn scan(
        &mut self,
        namespace: NamespaceId,
        prefix: Vec<u8>,
    ) -> Result<Vec<(Address, Secret<Vec<u8>>)>> {
        let found = self.store.scan(namespace, prefix, None).await?;
        let guard = scan_guard(namespace, found.generation);
        self.guard(guard.address, guard.expected)?;
        Ok(found.rows)
    }
    fn put(&mut self, at: Address, value: Secret<Vec<u8>>) {
        self.changes.insert(at, Some(value));
    }
    fn delete(&mut self, at: Address) {
        self.changes.insert(at, None);
    }
    async fn submit(mut self) -> Result<Outcome> {
        if self.changes.is_empty() {
            let guards: Vec<_> = self
                .guards
                .into_iter()
                .map(|(address, expected)| Predicate { address, expected })
                .collect();
            return Ok(if self.store.guards_hold(&guards).await? {
                Outcome::Applied
            } else {
                Outcome::Conflict
            });
        }
        if let Some((at, value)) = self.initialization.take() {
            self.put(at, value);
        }
        let prepared = PreparedCandidate::new(Candidate {
            id: self.store.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates: self
                .guards
                .into_iter()
                .map(|(address, expected)| Predicate { address, expected })
                .collect(),
            mutations: self
                .changes
                .into_iter()
                .map(|(address, value)| match value {
                    Some(value) => Mutation::Put { address, value },
                    None => Mutation::Delete(address),
                })
                .collect(),
            time: None,
            result: Secret::default(),
        })
        .map_err(|_| Error::Invalid)?;
        outcome(match self.logical {
            Some(permit) => permit.submit(prepared).await?,
            None => self.store.submit(prepared).await?,
        })
    }
}
fn outcome(submission: Submission) -> Result<Outcome> {
    Ok(match submission.result {
        SubmitResult::Decided(decision) => match decision.as_ref() {
            Decision::Applied(_) => Outcome::Applied,
            Decision::ConditionConflict => Outcome::Conflict,
            Decision::OpIdConflict => Outcome::OpIdConflict,
            Decision::ExpiredUnknown => Outcome::Reconcile(submission.id),
            _ => return Err(Error::Corrupt),
        },
        SubmitResult::NoEffect(f) => Outcome::NoEffect(f),
        SubmitResult::Uncertain => Outcome::Pending(submission.id),
        SubmitResult::Reconcile => Outcome::Reconcile(submission.id),
        SubmitResult::Busy => Outcome::Busy(submission.id),
    })
}

/// Legacy admin audit records have the published pipe recipe. Persistence keeps
/// their exact fields; the owning audit module supplies framing and validation.
pub(crate) struct Audit<'a> {
    store: &'a CoreStore,
    owner: &'a str,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditMetadata {
    seq: u64,
    ts: u64,
    action: String,
    resource: String,
    outcome: String,
    principal: String,
    prev_hash: String,
    hash: String,
}
impl From<&AuditRecord> for AuditMetadata {
    fn from(r: &AuditRecord) -> Self {
        Self {
            seq: r.seq,
            ts: r.ts,
            action: r.action.clone(),
            resource: r.resource.clone(),
            outcome: r.outcome.clone(),
            principal: r.principal.clone(),
            prev_hash: r.prev_hash.clone(),
            hash: r.hash.clone(),
        }
    }
}
impl From<AuditMetadata> for AuditRecord {
    fn from(r: AuditMetadata) -> Self {
        Self {
            seq: r.seq,
            ts: r.ts,
            action: r.action,
            resource: r.resource,
            outcome: r.outcome,
            principal: r.principal,
            prev_hash: r.prev_hash,
            hash: r.hash,
        }
    }
}
fn audit_address(owner: &str, sequence: u64) -> Result<Address> {
    let mut key = keys::framed(b'A', &[&AUDIT.0, owner.as_bytes()])?;
    key.extend_from_slice(&sequence.to_be_bytes());
    Ok(Address {
        namespace: partition::namespace(AUDIT, &[owner.as_bytes()]).0,
        key,
    })
}
pub(crate) fn migration_audit_rows(
    owner: &str,
    record: &AuditRecord,
) -> Result<Vec<(Address, Secret<Vec<u8>>)>> {
    // Historical verification failures are evidence restored by the audit owner;
    // import preserves exact fields rather than repairing hashes or ancestry.
    Ok(vec![(
        audit_address(owner, record.seq)?,
        encode(&AuditMetadata::from(record))?,
    )])
}
pub(crate) fn migration_audit_authorizes(owner: &str, address: &Address) -> bool {
    let Some(split) = address.key.len().checked_sub(8) else {
        return false;
    };
    let Ok(parts) = keys::components(&address.key[..split], b'A') else {
        return false;
    };
    if parts.len() != 2 || parts[0] != AUDIT.0 || parts[1] != owner.as_bytes() {
        return false;
    }
    let Ok(sequence) = address.key[split..].try_into().map(u64::from_be_bytes) else {
        return false;
    };
    audit_address(owner, sequence).is_ok_and(|expected| expected == *address)
}

impl<'a> Audit<'a> {
    pub(crate) fn authorized(store: &'a CoreStore, owner: &'a str) -> Self {
        Self { store, owner }
    }
    fn namespace(&self) -> NamespaceId {
        partition::namespace(AUDIT, &[self.owner.as_bytes()])
    }
    fn prefix(&self) -> Result<Vec<u8>> {
        Ok(keys::framed(b'A', &[&AUDIT.0, self.owner.as_bytes()])?)
    }
    fn address(&self, seq: u64) -> Result<Address> {
        audit_address(self.owner, seq)
    }
    fn validate(record: &AuditRecord) -> Result<()> {
        let framed = crate::audit::stream_registry::StreamRecord::from_parts(
            String::new(),
            record.seq,
            record.prev_hash.clone(),
            record.hash.clone(),
            crate::audit::auditlog::audit_suffix(
                record.ts,
                &record.action,
                &record.resource,
                &record.outcome,
                &record.principal,
            ),
            crate::audit::Framing::PipeSeparated,
            false,
        );
        if crate::audit::digest(&framed) != record.hash {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub(crate) async fn append(&self, record: &AuditRecord) -> Result<Outcome> {
        Self::validate(record)?;
        let mut plan = Plan::new(self.store);
        let at = self.address(record.seq)?;
        if let Some(found) = plan.one(at.clone()).await? {
            let existing: AuditRecord = decode::<AuditMetadata>(&found)?.into();
            if &existing != record {
                return Err(Error::Fork);
            }
        } else {
            plan.put(at, encode(&AuditMetadata::from(record))?);
        }
        plan.submit().await
    }
    pub(crate) async fn list(&self) -> Result<Vec<AuditRecord>> {
        self.list_tail(u64::MAX).await
    }
    /// Retains only the requested tail in memory; each crossing is bounded and
    /// pins the first observed generation. Sequence gaps preserve legacy ordering.
    pub(crate) async fn list_tail(&self, limit: u64) -> Result<Vec<AuditRecord>> {
        use busbar_contract::persistence::Scan;
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut retained = std::collections::VecDeque::new();
        let mut after: Option<Vec<u8>> = None;
        let mut generation = None;
        let limits = self.store.limits();
        let prefix = self.prefix()?;
        loop {
            let page = self
                .store
                .backend()
                .scan(Arc::new(Scan {
                    dataset: self.store.info().dataset,
                    namespace: self.namespace(),
                    prefix: prefix.clone(),
                    after: after.clone(),
                    generation,
                    allow_change: false,
                    max_items: limits.scan_items,
                    max_bytes: limits.scan_bytes,
                }))
                .await?;
            if generation.is_some_and(|g| g != page.generation) {
                return Err(Error::Backend(Failure::StaleScan));
            }
            generation = Some(page.generation);
            if page.rows.len() > limits.scan_items
                || page
                    .next
                    .as_ref()
                    .is_some_and(|next| page.rows.last().map(|(at, _)| &at.key) != Some(next))
            {
                return Err(Error::Corrupt);
            }
            let mut bytes = 0usize;
            let mut previous = after.clone();
            for (at, value) in page.rows {
                bytes = bytes
                    .checked_add(at.key.len())
                    .and_then(|n| n.checked_add(value.expose(&crate::seal::lend()).len()))
                    .ok_or(Error::Corrupt)?;
                if bytes > limits.scan_bytes || previous.as_ref().is_some_and(|p| p >= &at.key) {
                    return Err(Error::Corrupt);
                }
                let record: AuditRecord = decode::<AuditMetadata>(&value)?.into();
                if at != self.address(record.seq)? {
                    return Err(Error::Corrupt);
                }
                // Restore must return original historical fields even when their
                // hash fails verification; the audit owner reports tamper evidence.
                previous = Some(at.key);
                if retained.len() == limit {
                    retained.pop_front();
                }
                retained.push_back(record);
            }
            after = page.next;
            if after.is_none() {
                return Ok(retained.into_iter().collect());
            }
        }
    }
    pub(crate) async fn retry(&self, id: PendingId) -> Result<Outcome> {
        outcome(self.store.retry(id).await?)
    }
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
