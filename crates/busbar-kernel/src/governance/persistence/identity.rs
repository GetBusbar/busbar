// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Canonical identity ownership over opaque Store primitives. No crypto lives here:
//! confidential values are the exact envelopes produced by `at_rest`.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::persistence::{commit::SubmitResult, facade::CoreStore, keys};
use busbar_contract::persistence::{
    Address, Candidate, Decision, ExpectedValue, Failure, Mutation, NamespaceId, Predicate,
    PreparedCandidate, Read, ReadResult, CANDIDATE_VERSION,
};
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, RecordStoreError, RecordStoreResult, SecretForm, VirtualKey,
};
use busbar_contract::Secret;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const NAMESPACE: NamespaceId = NamespaceId(*b"busbar.identity1");
pub const CONFIDENTIAL: NamespaceId = NamespaceId(*b"busbar.secret.v1");

/// A borrowed domain view; raw backend access remains inside core.
#[derive(Debug)]
pub struct IdentitySnapshot {
    pub revision: u64,
    pub keys: Vec<VirtualKey>,
    pub credentials: Vec<CredentialSecret>,
    pub denied: Vec<String>,
}

/// Exact rows prepared by one confirmed canonical identity transaction.
/// Never constructed for an Unknown, cancelled, or otherwise unresolved write.
#[derive(Debug)]
pub struct IdentityCommit {
    pub changed: bool,
    pub revision: u64,
    pub keys: Vec<VirtualKey>,
    pub credentials: Vec<CredentialSecret>,
    pub denied: Vec<String>,
}

pub struct Identity<'a> {
    store: &'a CoreStore,
}
impl CoreStore {
    pub fn identity(&self) -> Identity<'_> {
        Identity { store: self }
    }
}

#[derive(Debug)]
enum Error {
    Conflict,
    Invalid(&'static str),
    Backend(Failure),
    Access(crate::persistence::facade::AccessError),
    Pending(crate::persistence::facade::PendingId),
}
type Result<T> = std::result::Result<T, Error>;
impl From<Failure> for Error {
    fn from(value: Failure) -> Self {
        if value == Failure::StaleScan {
            Self::Conflict
        } else {
            Self::Backend(value)
        }
    }
}
impl From<crate::persistence::facade::AccessError> for Error {
    fn from(value: crate::persistence::facade::AccessError) -> Self {
        Self::Access(value)
    }
}
impl From<keys::KeyError> for Error {
    fn from(_: keys::KeyError) -> Self {
        Self::Invalid("invalid identity key framing")
    }
}
impl From<Error> for RecordStoreError {
    fn from(value: Error) -> Self {
        Self(match value {
            Error::Conflict => "identity conflict retry budget exhausted".into(),
            Error::Invalid(message) => message.into(),
            Error::Backend(failure) => format!("identity backend: {failure:?}"),
            Error::Access(failure) => format!("identity access: {failure:?}"),
            Error::Pending(id) => format!(
                "identity outcome unresolved; retained operation {}",
                hex::encode(id.0)
            ),
        })
    }
}
fn corrupt() -> Error {
    Error::Invalid("corrupt or unsupported canonical identity record")
}
fn address(tag: u8, parts: &[&[u8]]) -> Result<Address> {
    Ok(Address {
        namespace: NAMESPACE.0,
        key: keys::framed(tag, parts)?,
    })
}
fn row(tag: u8, id: &str) -> Result<Address> {
    address(tag, &[id.as_bytes()])
}
fn confidential(id: &str) -> Result<Address> {
    let mut at = row(b'C', id)?;
    at.namespace = CONFIDENTIAL.0;
    Ok(at)
}
fn slot(meta: &CredentialMeta) -> Result<Address> {
    address(
        b'S',
        &[meta.key_id.as_bytes(), meta.kind.as_bytes(), &[meta.slot]],
    )
}
fn public(meta: &CredentialMeta) -> Result<Address> {
    address(b'P', &[meta.kind.as_bytes(), meta.public_id.as_bytes()])
}
fn revision_key(family: u8, revision: u64, id: &str) -> Result<Address> {
    address(b'R', &[&[family], &revision.to_be_bytes(), id.as_bytes()])
}
fn revision_decode(bytes: Option<&Secret<Vec<u8>>>) -> Result<u64> {
    let Some(bytes) = bytes else {
        return Ok(0);
    };
    let seal = crate::seal::lend();
    let bytes = bytes.expose(&seal);
    if bytes.len() != 9 || bytes[0] != 1 {
        return Err(corrupt());
    }
    Ok(u64::from_be_bytes(
        bytes[1..].try_into().map_err(|_| corrupt())?,
    ))
}
fn revision_encode(revision: u64) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&revision.to_be_bytes());
    bytes
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    version: u32,
    record: T,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Denied {
    subject: String,
    reason: String,
    created_at: u64,
    revision: u64,
}
fn encode<T: Serialize>(record: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(&Record { version: 1, record }).map_err(|_| corrupt())
}
fn decode<T: DeserializeOwned>(
    bytes: &Secret<Vec<u8>>,
    fields: Option<&[&str]>,
    scopes: bool,
) -> Result<T> {
    let seal = crate::seal::lend();
    let value: serde_json::Value =
        serde_json::from_slice(bytes.expose(&seal)).map_err(|_| corrupt())?;
    if let Some(fields) = fields {
        let record = value
            .get("record")
            .and_then(|v| v.as_object())
            .ok_or_else(corrupt)?;
        if record.keys().any(|name| {
            !fields.contains(&name.as_str())
                && !(scopes
                    && busbar_contract::records::scope_kinds::kind_for_wire_field(name).is_some())
        }) {
            return Err(corrupt());
        }
    }
    let record: Record<T> = serde_json::from_value(value).map_err(|_| corrupt())?;
    if record.version != 1 {
        return Err(corrupt());
    }
    Ok(record.record)
}
const KEY_FIELDS: &[&str] = &[
    "id",
    "generation_hash",
    "name",
    "allowed_pools",
    "enabled",
    "created_at",
    "group",
    "labels",
    "expires_at",
    "deleted_at",
    "revision",
    "idp_subject",
    "binding_mode",
    "minted_by",
    "idp_provider",
];
const CREDENTIAL_FIELDS: &[&str] = &[
    "id",
    "key_id",
    "kind",
    "slot",
    "public_id",
    "secret_form",
    "created_at",
    "updated_at",
    "expires_at",
    "revoked_at",
    "revoke_reason",
    "revision",
];
/// Canonical address for other core owners' coherent identity reads.
pub(crate) fn key_address(id: &str) -> RecordStoreResult<Address> {
    row(b'K', id).map_err(Into::into)
}
/// Strict decoding shared by identity-dependent core operations.
pub(crate) fn decode_key(bytes: &Secret<Vec<u8>>) -> RecordStoreResult<VirtualKey> {
    key_decode(bytes).map_err(Into::into)
}
fn key_decode(bytes: &Secret<Vec<u8>>) -> Result<VirtualKey> {
    decode(bytes, Some(KEY_FIELDS), true)
}
fn meta_decode(bytes: &Secret<Vec<u8>>) -> Result<CredentialMeta> {
    let meta: CredentialMeta = decode(bytes, Some(CREDENTIAL_FIELDS), false)?;
    if meta.slot > 1 {
        return Err(corrupt());
    }
    Ok(meta)
}

struct Tx<'a> {
    store: &'a CoreStore,
    observed: Option<Secret<Vec<u8>>>,
    revision: u64,
    now: u64,
    changes: BTreeMap<Address, Option<Secret<Vec<u8>>>>,
    superseded: BTreeMap<String, CredentialSecret>,
    observed_keys: BTreeMap<String, VirtualKey>,
}
impl<'a> Tx<'a> {
    async fn start(store: &'a CoreStore) -> Result<Self> {
        let mut tx = Self {
            store,
            observed: None,
            revision: 0,
            now: 0,
            changes: BTreeMap::new(),
            superseded: BTreeMap::new(),
            observed_keys: BTreeMap::new(),
        };
        let (now, mut values) = tx.raw_read(vec![address(b'V', &[])?]).await?;
        tx.now = now;
        tx.observed = values.pop().ok_or_else(corrupt)?;
        tx.revision = revision_decode(tx.observed.as_ref())?;
        Ok(tx)
    }
    async fn raw_read(
        &self,
        addresses: Vec<Address>,
    ) -> Result<(u64, Vec<Option<Secret<Vec<u8>>>>)> {
        let length = addresses.len();
        let result = self
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.store.info().dataset,
                addresses,
                time: None,
            }))
            .await?;
        let ReadResult::Values {
            observed_at,
            values,
        } = result
        else {
            return Err(corrupt());
        };
        if observed_at.authority != self.store.info().clock_authority || values.len() != length {
            return Err(corrupt());
        }
        Ok((observed_at.unix_seconds, values))
    }
    async fn read(&self, mut addresses: Vec<Address>) -> Result<Vec<Option<Secret<Vec<u8>>>>> {
        addresses.push(address(b'V', &[])?);
        let (_, mut values) = self.raw_read(addresses).await?;
        let current = values.pop().ok_or_else(corrupt)?;
        let seal = crate::seal::lend();
        if current.as_ref().map(|v| v.expose(&seal))
            != self.observed.as_ref().map(|v| v.expose(&seal))
        {
            return Err(Error::Conflict);
        }
        Ok(values)
    }
    async fn one(&self, at: Address) -> Result<Option<Secret<Vec<u8>>>> {
        self.read(vec![at]).await?.pop().ok_or_else(corrupt)
    }
    async fn key(&self, id: &str) -> Result<Option<VirtualKey>> {
        let found = self
            .one(key_address(id).map_err(|_| corrupt())?)
            .await?
            .map(|v| decode_key(&v).map_err(|_| corrupt()))
            .transpose()?;
        if found.as_ref().is_some_and(|key| key.id != id) {
            return Err(corrupt());
        }
        Ok(found)
    }
    async fn meta(&self, id: &str) -> Result<Option<CredentialMeta>> {
        let found = self
            .one(row(b'C', id)?)
            .await?
            .map(|v| meta_decode(&v))
            .transpose()?;
        if found.as_ref().is_some_and(|meta| meta.id != id) {
            return Err(corrupt());
        }
        Ok(found)
    }
    async fn credential(&self, id: &str) -> Result<Option<CredentialSecret>> {
        let mut values = self
            .read(vec![row(b'C', id)?, confidential(id)?])
            .await?
            .into_iter();
        let meta = values.next().ok_or_else(corrupt)?;
        let secret = values.next().ok_or_else(corrupt)?;
        let Some(meta) = meta else {
            return if secret.is_none() {
                Ok(None)
            } else {
                Err(corrupt())
            };
        };
        let meta = meta_decode(&meta)?;
        if meta.id != id {
            return Err(corrupt());
        }
        let secret = secret.ok_or_else(corrupt)?;
        let seal = crate::seal::lend();
        if meta.revoked_at.is_some() && !secret.expose(&seal).is_empty() {
            return Err(corrupt());
        }
        let secret = std::str::from_utf8(secret.expose(&seal))
            .map_err(|_| corrupt())?
            .to_owned();
        Ok(Some(CredentialSecret { meta, secret }))
    }
    async fn index(&self, at: Address) -> Result<Option<String>> {
        self.one(at)
            .await?
            .map(|v| decode::<Index>(&v, None, false).map(|i| i.id))
            .transpose()
    }
    async fn scan(&self, prefix: Vec<u8>) -> Result<Vec<(Address, Secret<Vec<u8>>)>> {
        self.scan_after(prefix, None).await
    }
    async fn scan_after(
        &self,
        prefix: Vec<u8>,
        after: Option<Vec<u8>>,
    ) -> Result<Vec<(Address, Secret<Vec<u8>>)>> {
        let collection = self.store.scan(NAMESPACE, prefix, after).await?;
        // The shared helper guards pages; the identity revision additionally binds
        // those pages to all preceding and subsequent point-read waves.
        self.read(vec![]).await?;
        Ok(collection.rows)
    }
    fn put(&mut self, at: Address, value: Vec<u8>) {
        self.changes.insert(at, Some(Secret::new(value)));
    }
    fn remove(&mut self, at: Address) {
        self.changes.insert(at, None);
    }
    fn bump(&mut self) -> Result<u64> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::Invalid("identity revision exhausted"))?;
        Ok(self.revision)
    }
    fn revision(&mut self, family: u8, id: &str, old: u64, new: u64) -> Result<()> {
        if old != 0 {
            self.remove(revision_key(family, old, id)?);
        }
        self.put(
            revision_key(family, new, id)?,
            encode(&Index { id: id.into() })?,
        );
        Ok(())
    }
    fn write_key(&mut self, key: &VirtualKey, old: u64) -> Result<()> {
        let mut key = key.clone();
        key.revision = self.bump()?;
        self.revision(b'K', &key.id, old, key.revision)?;
        self.put(row(b'K', &key.id)?, encode(&key)?);
        Ok(())
    }
    fn write_credential(&mut self, meta: &CredentialMeta, secret: &[u8], old: u64) -> Result<()> {
        let mut meta = meta.clone();
        meta.revision = self.bump()?;
        self.revision(b'C', &meta.id, old, meta.revision)?;
        self.put(row(b'C', &meta.id)?, encode(&meta)?);
        self.put(confidential(&meta.id)?, secret.to_vec());
        Ok(())
    }
    async fn revoke(&mut self, mut meta: CredentialMeta, reason: &str) -> Result<()> {
        if meta.revoked_at.is_none() {
            let old = meta.revision;
            meta.revoked_at = Some(self.now);
            meta.revoke_reason = Some(reason.into());
            meta.secret_form = SecretForm::None;
            self.write_credential(&meta, &[], old)?;
        } else {
            self.superseded.insert(
                meta.id.clone(),
                CredentialSecret {
                    meta,
                    secret: String::new(),
                },
            );
        }
        Ok(())
    }
    async fn cascade(&mut self, id: &str) -> Result<()> {
        for (at, value) in self.scan(keys::framed(b'S', &[id.as_bytes()])?).await? {
            let index: Index = decode(&value, None, false)?;
            let meta = self.meta(&index.id).await?.ok_or_else(corrupt)?;
            if meta.key_id != id || slot(&meta)? != at {
                return Err(corrupt());
            }
            self.remove(at);
            self.remove(public(&meta)?);
            self.revoke(meta, "owning key deleted").await?;
        }
        Ok(())
    }
    async fn put_key(&mut self, key: &VirtualKey) -> Result<()> {
        let current = self.key(&key.id).await?;
        if current.as_ref().is_some_and(|k| k.deleted_at.is_some()) && key.deleted_at.is_none() {
            return Err(Error::Invalid(
                "key is tombstoned; its id cannot be reissued",
            ));
        }
        let mut key = key.clone();
        if key.deleted_at.is_some() {
            key.enabled = false;
            self.cascade(&key.id).await?;
        }
        self.write_key(&key, current.map_or(0, |k| k.revision))
    }
    async fn put_credential(&mut self, secret: &CredentialSecret) -> Result<()> {
        let meta = &secret.meta;
        if let Some(current) = self.credential(&meta.id).await? {
            if current.meta.revoked_at.is_some() {
                return Err(Error::Invalid(
                    "credential is revoked; its id cannot be reissued",
                ));
            }
            let mut offered = meta.clone();
            offered.revision = current.meta.revision;
            if offered == current.meta && secret.secret == current.secret {
                return Ok(());
            }
            return Err(Error::Invalid("credential id is occupied"));
        }
        if meta.slot > 1 {
            return Err(Error::Invalid("credential slot must be 0 or 1"));
        }
        let previous = self.index(slot(meta)?).await?;
        let old = if let Some(id) = &previous {
            let old = self.meta(id).await?.ok_or_else(corrupt)?;
            if slot(&old)? != slot(meta)? {
                return Err(corrupt());
            }
            if old.revoked_at.is_none() {
                return Err(Error::Invalid("credential slot is occupied"));
            }
            Some(old)
        } else {
            None
        };
        if let Some(id) = self.index(public(meta)?).await? {
            if previous.as_ref() != Some(&id) {
                return Err(Error::Invalid("credential public identifier is occupied"));
            }
        }
        if let Some(old) = old {
            self.remove(public(&old)?);
            self.superseded.insert(
                old.id.clone(),
                CredentialSecret {
                    meta: old,
                    secret: String::new(),
                },
            );
        }
        self.put(
            slot(meta)?,
            encode(&Index {
                id: meta.id.clone(),
            })?,
        );
        self.put(
            public(meta)?,
            encode(&Index {
                id: meta.id.clone(),
            })?,
        );
        let mut meta = meta.clone();
        if meta.revoked_at.is_some() {
            meta.secret_form = SecretForm::None;
        }
        self.write_credential(
            &meta,
            if meta.revoked_at.is_some() {
                &[]
            } else {
                secret.secret.as_bytes()
            },
            0,
        )
    }
    fn committed(&self, changed: bool) -> Result<IdentityCommit> {
        let mut result = IdentityCommit {
            changed,
            revision: self.revision,
            keys: self.observed_keys.values().cloned().collect(),
            credentials: self.superseded.values().cloned().collect(),
            denied: Vec::new(),
        };
        for (address, value) in &self.changes {
            let Some(value) = value else {
                continue;
            };
            if address.namespace != NAMESPACE.0 {
                continue;
            }
            match address.key.first() {
                Some(b'K') => result.keys.push(key_decode(value)?),
                Some(b'C') => {
                    let meta = meta_decode(value)?;
                    let secret = self
                        .changes
                        .get(&confidential(&meta.id)?)
                        .and_then(Option::as_ref)
                        .ok_or_else(corrupt)?;
                    let secret = std::str::from_utf8(secret.expose(&crate::seal::lend()))
                        .map_err(|_| corrupt())?
                        .to_owned();
                    result.credentials.push(CredentialSecret { meta, secret });
                }
                Some(b'D') => result
                    .denied
                    .push(decode::<Denied>(value, None, false)?.subject),
                _ => {}
            }
        }
        Ok(result)
    }

    async fn commit(mut self) -> Result<()> {
        if self.changes.is_empty() {
            self.read(vec![]).await?;
            return Ok(());
        }
        let at = address(b'V', &[])?;
        self.put(at.clone(), revision_encode(self.revision));
        let candidate = PreparedCandidate::new(Candidate {
            codec: CANDIDATE_VERSION,
            id: self.store.next_id()?,
            time: None,
            predicates: vec![Predicate {
                address: at,
                expected: self
                    .observed
                    .map_or(ExpectedValue::Absent, ExpectedValue::Exact),
            }],
            mutations: self
                .changes
                .into_iter()
                .map(|(address, value)| match value {
                    Some(value) => Mutation::Put { address, value },
                    None => Mutation::Delete(address),
                })
                .collect(),
            result: Secret::new(Vec::new()),
        })
        .map_err(|_| corrupt())?;
        let submission = self.store.submit_identity(candidate).await?;
        match submission.result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(()),
                Decision::ConditionConflict => Err(Error::Conflict),
                _ => Err(Error::Invalid("identity commit refused")),
            },
            SubmitResult::NoEffect(failure) => Err(Error::Backend(failure)),
            SubmitResult::Uncertain | SubmitResult::Reconcile | SubmitResult::Busy => {
                Err(Error::Pending(submission.id))
            }
        }
    }
}

enum Change<'a> {
    PutKey(&'a VirtualKey),
    CompareKey(Option<&'a VirtualKey>, &'a VirtualKey),
    CompareSelfKey(Option<&'a VirtualKey>, &'a VirtualKey),
    ReplaceKey(&'a VirtualKey, &'a VirtualKey),
    DeleteKey(&'a str),
    PutCredential(&'a CredentialSecret, Option<&'a VirtualKey>),
    Rewrap(&'a CredentialSecret, &'a str),
    Revoke(&'a str, &'a str),
    Deny(&'a str, &'a str),
}
impl Identity<'_> {
    /// Retry only inactive original attempts retained by this identity owner.
    /// Cancellation and uncertainty keep their exact native candidate in CoreStore;
    /// this method never replans, encrypts, or publishes a projected identity delta.
    pub async fn settle_pending(&self) -> RecordStoreResult<()> {
        if self
            .store
            .settle_identity_pending()
            .await
            .map_err(Error::from)?
        {
            Ok(())
        } else {
            Err(RecordStoreError(
                "identity settlement deferred: active or unresolved native operation".into(),
            ))
        }
    }

    async fn change(&self, change: Change<'_>) -> RecordStoreResult<IdentityCommit> {
        for retry in 0..=self.store.limits().conflict_retries {
            self.guard_change(&change)?;
            let result = self.attempt(&change).await;
            if matches!(result, Err(Error::Conflict))
                && retry < self.store.limits().conflict_retries
            {
                continue;
            }
            return result.map_err(Into::into);
        }
        unreachable!()
    }
    async fn attempt(&self, change: &Change<'_>) -> Result<IdentityCommit> {
        let mut tx = Tx::start(self.store).await?;
        let result = self.plan(&mut tx, change).await;
        // Even definitive semantic rejection must be based on one identity revision.
        tx.read(vec![]).await?;
        let result = result?;
        let committed = tx.committed(result)?;
        self.guard_commit(&committed).map_err(|_| {
            Error::Invalid("identity mutation deferred: same-key native outcome unresolved")
        })?;
        tx.commit().await?;
        Ok(committed)
    }
    async fn plan(&self, tx: &mut Tx<'_>, change: &Change<'_>) -> Result<bool> {
        match change {
            Change::PutKey(key) => tx.put_key(key).await?,
            Change::CompareKey(expected, replacement)
            | Change::CompareSelfKey(expected, replacement) => {
                if matches!(change, Change::CompareSelfKey(_, _))
                    && tx.one(row(b'D', &replacement.id)?).await?.is_some()
                {
                    return Err(Error::Invalid("self binding is revoked"));
                }
                if tx.key(&replacement.id).await?.as_ref() != *expected {
                    return Err(Error::Invalid(
                        "identity key changed; retry the exact requested mutation",
                    ));
                }
                tx.put_key(replacement).await?;
            }
            Change::ReplaceKey(expected, replacement) => {
                if tx.one(row(b'D', &expected.id)?).await?.is_some()
                    || tx.one(row(b'D', &replacement.id)?).await?.is_some()
                {
                    return Err(Error::Invalid("self binding is revoked"));
                }
                let mut previous = tx
                    .key(&expected.id)
                    .await?
                    .ok_or(Error::Invalid("self binding disappeared"))?;
                if &previous != *expected || previous.deleted_at.is_some() {
                    return Err(Error::Invalid("self binding changed; retry the request"));
                }
                if expected.id == replacement.id
                    || replacement.deleted_at.is_some()
                    || tx.key(&replacement.id).await?.is_some()
                {
                    return Err(Error::Invalid(
                        "replacement binding id is occupied or invalid",
                    ));
                }
                tx.put_key(replacement).await?;
                previous.enabled = false;
                previous.deleted_at = Some(tx.now);
                tx.cascade(&previous.id).await?;
                let old = previous.revision;
                tx.write_key(&previous, old)?;
            }
            Change::DeleteKey(id) => {
                let mut key = tx
                    .key(id)
                    .await?
                    .ok_or(Error::Invalid("delete_key: unknown id"))?;
                if key.deleted_at.is_none() {
                    key.enabled = false;
                    key.deleted_at = Some(tx.now);
                    tx.cascade(id).await?;
                    let old = key.revision;
                    tx.write_key(&key, old)?;
                }
            }
            Change::PutCredential(secret, key) => {
                if let Some(key) = key {
                    if key.id != secret.meta.key_id || key.deleted_at.is_some() {
                        return Err(Error::Invalid("credential owner does not match a live key"));
                    }
                    tx.put_key(key).await?;
                } else {
                    let owner = tx
                        .key(&secret.meta.key_id)
                        .await?
                        .filter(|key| key.deleted_at.is_none())
                        .ok_or(Error::Invalid("credential owner is missing or tombstoned"))?;
                    tx.observed_keys.insert(owner.id.clone(), owner);
                }
                tx.put_credential(secret).await?;
            }
            Change::Rewrap(expected, replacement) => {
                let owner = tx.key(&expected.meta.key_id).await?;
                if owner.as_ref().is_none_or(|k| k.deleted_at.is_some())
                    || expected.meta.revoked_at.is_some()
                    || expected.meta.secret_form != SecretForm::Recoverable
                    || expected.secret == *replacement
                {
                    return Ok(false);
                }
                if tx.credential(&expected.meta.id).await?.as_ref() != Some(*expected) {
                    return Ok(false);
                }
                let owner = owner.ok_or_else(corrupt)?;
                tx.observed_keys.insert(owner.id.clone(), owner);
                tx.write_credential(
                    &expected.meta,
                    replacement.as_bytes(),
                    expected.meta.revision,
                )?;
            }
            Change::Revoke(id, reason) => {
                let meta = tx
                    .meta(id)
                    .await?
                    .ok_or(Error::Invalid("revoke_credential: unknown id"))?;
                // Read owner in the same guarded revision as the credential.
                let owner = tx.key(&meta.key_id).await?.ok_or_else(corrupt)?;
                tx.observed_keys.insert(owner.id.clone(), owner);
                tx.revoke(meta, reason).await?;
            }
            Change::Deny(subject, reason) => {
                let at = row(b'D', subject)?;
                if let Some(current) = tx.one(at.clone()).await? {
                    let denied: Denied = decode(&current, None, false)?;
                    if denied.subject != *subject {
                        return Err(corrupt());
                    }
                } else {
                    let revision = tx.bump()?;
                    tx.put(
                        at,
                        encode(&Denied {
                            subject: (*subject).into(),
                            reason: (*reason).into(),
                            created_at: tx.now,
                            revision,
                        })?,
                    );
                }
            }
        }
        Ok(true)
    }
    pub async fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::PutKey(key)).await
    }
    /// Rotate a deterministic self binding in one confirmed identity transaction.
    pub async fn replace_key(
        &self,
        expected: &VirtualKey,
        replacement: &VirtualKey,
    ) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::ReplaceKey(expected, replacement)).await
    }
    pub async fn delete_key(&self, id: &str) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::DeleteKey(id)).await
    }
    pub async fn put_credential(
        &self,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::PutCredential(secret, None)).await
    }
    pub async fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::PutCredential(secret, Some(key))).await
    }
    pub async fn rewrap_committed(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::Rewrap(expected, replacement)).await
    }
    pub async fn compare_self_key(
        &self,
        expected: Option<&VirtualKey>,
        replacement: &VirtualKey,
    ) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::CompareSelfKey(expected, replacement))
            .await
    }
    pub async fn compare_key(
        &self,
        expected: Option<&VirtualKey>,
        replacement: &VirtualKey,
    ) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::CompareKey(expected, replacement)).await
    }
    pub async fn is_denied(&self, subject: &str) -> RecordStoreResult<bool> {
        self.query(Query::Denied(subject))
            .await
            .map(|output| match output {
                Output::Denied(subjects) => !subjects.is_empty(),
                _ => unreachable!(),
            })
    }
    pub async fn self_keys(&self, subject: &str) -> RecordStoreResult<Vec<VirtualKey>> {
        self.query(Query::SelfKeys(subject))
            .await
            .map(|output| match output {
                Output::Keys(keys) => keys,
                _ => unreachable!(),
            })
    }
    pub async fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.change(Change::Rewrap(expected, replacement))
            .await
            .map(|commit| commit.changed)
    }
    pub async fn revoke_credential(
        &self,
        id: &str,
        reason: &str,
    ) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::Revoke(id, reason)).await
    }
    pub async fn add_denylist(
        &self,
        subject: &str,
        reason: &str,
    ) -> RecordStoreResult<IdentityCommit> {
        self.change(Change::Deny(subject, reason)).await
    }
    pub async fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.query(Query::Key(id)).await.map(|v| match v {
            Output::Keys(mut keys) => keys.pop(),
            _ => unreachable!(),
        })
    }
    pub async fn snapshot(&self) -> RecordStoreResult<IdentitySnapshot> {
        if self
            .store
            .has_pending_namespace(NAMESPACE)
            .map_err(Error::from)?
        {
            return Err(RecordStoreError(
                "identity snapshot deferred: active or unresolved native operation".into(),
            ));
        }
        let output = self.query(Query::Snapshot).await.map(|v| match v {
            Output::Snapshot(snapshot) => snapshot,
            _ => unreachable!(),
        })?;
        if self
            .store
            .has_pending_namespace(NAMESPACE)
            .map_err(Error::from)?
        {
            return Err(RecordStoreError(
                "identity snapshot deferred: active or unresolved native operation".into(),
            ));
        }
        Ok(output)
    }
    pub async fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.query(Query::Keys(None)).await.map(|v| match v {
            Output::Keys(keys) => keys,
            _ => unreachable!(),
        })
    }
    pub async fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.query(Query::Keys(Some(since))).await.map(|v| match v {
            Output::Keys(keys) => keys,
            _ => unreachable!(),
        })
    }
    pub async fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.query(Query::Credentials(key_id))
            .await
            .map(|v| match v {
                Output::Metadata(meta) => meta,
                _ => unreachable!(),
            })
    }
    pub async fn list_credentials_since(
        &self,
        since: u64,
    ) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.query(Query::CredentialsSince(since))
            .await
            .map(|v| match v {
                Output::Credentials(credentials) => credentials,
                _ => unreachable!(),
            })
    }
    pub async fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.query(Query::Denylist).await.map(|v| match v {
            Output::Denied(subjects) => subjects,
            _ => unreachable!(),
        })
    }
    fn guard_targets(
        &self,
        keys: &[&str],
        credential: Option<&str>,
        subject: Option<&str>,
    ) -> RecordStoreResult<()> {
        let blocked = self
            .store
            .unresolved_matches(|candidate| {
                candidate.mutations.iter().any(|mutation| {
                    if matches!(mutation, Mutation::DeleteRange { namespace, .. } if *namespace == NAMESPACE) { return true; }
                    let Mutation::Put { address, value } = mutation else {
                        return false;
                    };
                    if address.namespace != NAMESPACE.0 {
                        return false;
                    }
                    match address.key.first() {
                        Some(b'K') => match key_decode(value) {
                            Ok(key) => {
                                keys.contains(&key.id.as_str())
                                    || subject.is_some_and(|subject| {
                                        key.idp_subject.as_deref() == Some(subject)
                                            || key.group.as_deref()
                                                == Some(
                                                    format!(
                                                        "{}{}",
                                                        crate::governance::SELF_KEY_GROUP_PREFIX,
                                                        subject
                                                    )
                                                    .as_str(),
                                                )
                                    })
                            }
                            Err(_) => true,
                        },
                        Some(b'C') => match meta_decode(value) {
                            Ok(meta) => {
                                keys.contains(&meta.key_id.as_str())
                                    || credential == Some(meta.id.as_str())
                            }
                            Err(_) => true,
                        },
                        Some(b'D') => match decode::<Denied>(value, None, false) {
                            Ok(denied) => keys.contains(&denied.subject.as_str()),
                            Err(_) => true,
                        },
                        _ => false,
                    }
                })
            })
            .map_err(Error::from)?;
        if blocked {
            Err(RecordStoreError(
                "identity operation deferred: same-key native outcome unresolved".into(),
            ))
        } else {
            Ok(())
        }
    }
    fn guard_change(&self, change: &Change<'_>) -> RecordStoreResult<()> {
        match change {
            Change::PutKey(key) | Change::CompareKey(_, key) | Change::CompareSelfKey(_, key) => {
                self.guard_targets(&[&key.id], None, None)
            }
            Change::ReplaceKey(old, new) => self.guard_targets(&[&old.id, &new.id], None, None),
            Change::DeleteKey(id) | Change::Deny(id, _) => self.guard_targets(&[id], None, None),
            Change::PutCredential(credential, _) | Change::Rewrap(credential, _) => {
                self.guard_targets(&[&credential.meta.key_id], Some(&credential.meta.id), None)
            }
            Change::Revoke(id, _) => self.guard_targets(&[], Some(id), None),
        }
    }
    fn guard_commit(&self, commit: &IdentityCommit) -> RecordStoreResult<()> {
        let mut keys = commit
            .keys
            .iter()
            .map(|key| key.id.as_str())
            .collect::<Vec<_>>();
        keys.extend(
            commit
                .credentials
                .iter()
                .map(|credential| credential.meta.key_id.as_str()),
        );
        keys.extend(commit.denied.iter().map(String::as_str));
        self.guard_targets(&keys, None, None)
    }
    fn guard_query(&self, query: &Query<'_>, output: Option<&Output>) -> RecordStoreResult<()> {
        match query {
            Query::Key(id) | Query::Denied(id) | Query::Credentials(id) => {
                self.guard_targets(&[id], None, None)
            }
            Query::SelfKeys(subject) => {
                let keys = match output {
                    Some(Output::Keys(keys)) => {
                        keys.iter().map(|key| key.id.as_str()).collect::<Vec<_>>()
                    }
                    _ => Vec::new(),
                };
                self.guard_targets(&keys, None, Some(subject))
            }
            _ => {
                if self
                    .store
                    .has_unresolved_namespace(NAMESPACE)
                    .map_err(Error::from)?
                {
                    Err(RecordStoreError(
                        "identity publication deferred: unresolved native operation".into(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }
    async fn query(&self, query: Query<'_>) -> RecordStoreResult<Output> {
        self.guard_query(&query, None)?;
        for retry in 0..=self.store.limits().conflict_retries {
            let result = self.query_attempt(&query).await;
            if matches!(result, Err(Error::Conflict))
                && retry < self.store.limits().conflict_retries
            {
                continue;
            }
            return result.map_err(Into::into);
        }
        unreachable!()
    }
    async fn query_attempt(&self, query: &Query<'_>) -> Result<Output> {
        let tx = Tx::start(self.store).await?;
        let output = match query {
            Query::Snapshot => {
                let mut keys = Vec::new();
                for (at, value) in tx.scan(vec![b'K']).await? {
                    let key = key_decode(&value)?;
                    if row(b'K', &key.id)? != at {
                        return Err(corrupt());
                    }
                    keys.push(key);
                }
                let mut credentials = Vec::new();
                for (at, value) in tx.scan(vec![b'C']).await? {
                    let meta = meta_decode(&value)?;
                    if row(b'C', &meta.id)? != at {
                        return Err(corrupt());
                    }
                    credentials.push(tx.credential(&meta.id).await?.ok_or_else(corrupt)?);
                }
                let mut denied = Vec::new();
                for (at, value) in tx.scan(vec![b'D']).await? {
                    let entry: Denied = decode(&value, None, false)?;
                    if row(b'D', &entry.subject)? != at {
                        return Err(corrupt());
                    }
                    denied.push(entry.subject);
                }
                Output::Snapshot(IdentitySnapshot {
                    revision: tx.revision,
                    keys,
                    credentials,
                    denied,
                })
            }
            Query::Denied(subject) => {
                let denied = tx
                    .one(row(b'D', subject)?)
                    .await?
                    .map(|bytes| decode::<Denied>(&bytes, None, false))
                    .transpose()?;
                if denied
                    .as_ref()
                    .is_some_and(|entry| entry.subject != *subject)
                {
                    return Err(corrupt());
                }
                Output::Denied(denied.into_iter().map(|entry| entry.subject).collect())
            }
            Query::SelfKeys(subject) => {
                let mut keys = Vec::new();
                let group = format!("{}{}", crate::governance::SELF_KEY_GROUP_PREFIX, subject);
                for (address, value) in tx.scan(vec![b'K']).await? {
                    let key = key_decode(&value)?;
                    if row(b'K', &key.id)? != address {
                        return Err(corrupt());
                    }
                    if key.group.as_deref() == Some(group.as_str())
                        || key.idp_subject.as_deref() == Some(*subject)
                    {
                        keys.push(key);
                    }
                }
                Output::Keys(keys)
            }
            Query::Key(id) => Output::Keys(tx.key(id).await?.into_iter().collect()),
            Query::Keys(since) => {
                let mut keys = Vec::new();
                if let Some(since) = since {
                    for (id, revision) in tx.since(b'K', *since).await? {
                        let key = tx.key(&id).await?.ok_or_else(corrupt)?;
                        if key.revision != revision {
                            return Err(corrupt());
                        }
                        keys.push(key);
                    }
                    keys.sort_by_key(|key| key.revision);
                } else {
                    for (at, value) in tx.scan(vec![b'K']).await? {
                        let key = key_decode(&value)?;
                        if row(b'K', &key.id)? != at {
                            return Err(corrupt());
                        }
                        keys.push(key);
                    }
                    keys.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
                }
                Output::Keys(keys)
            }
            Query::Credentials(id) => {
                let mut metas = Vec::new();
                for (at, value) in tx.scan(keys::framed(b'S', &[id.as_bytes()])?).await? {
                    let index: Index = decode(&value, None, false)?;
                    let meta = tx.meta(&index.id).await?.ok_or_else(corrupt)?;
                    if meta.key_id != *id || slot(&meta)? != at {
                        return Err(corrupt());
                    }
                    metas.push(meta);
                }
                metas.sort_by(|a, b| (&a.kind, a.slot).cmp(&(&b.kind, b.slot)));
                Output::Metadata(metas)
            }
            Query::CredentialsSince(since) => {
                let mut credentials = Vec::new();
                for (id, revision) in tx.since(b'C', *since).await? {
                    let credential = tx.credential(&id).await?.ok_or_else(corrupt)?;
                    if credential.meta.revision != revision {
                        return Err(corrupt());
                    }
                    credentials.push(credential);
                }
                credentials.sort_by_key(|c| c.meta.revision);
                Output::Credentials(credentials)
            }
            Query::Denylist => {
                let mut subjects = Vec::new();
                for (at, value) in tx.scan(vec![b'D']).await? {
                    let denied: Denied = decode(&value, None, false)?;
                    if row(b'D', &denied.subject)? != at {
                        return Err(corrupt());
                    }
                    subjects.push(denied.subject);
                }
                subjects.sort();
                Output::Denied(subjects)
            }
        };
        tx.read(vec![]).await?;
        self.guard_query(query, Some(&output))
            .map_err(|_| Error::Invalid("identity query deferred: native outcome unresolved"))?;
        Ok(output)
    }
}
enum Query<'a> {
    Denied(&'a str),
    SelfKeys(&'a str),
    Snapshot,
    Key(&'a str),
    Keys(Option<u64>),
    Credentials(&'a str),
    CredentialsSince(u64),
    Denylist,
}
enum Output {
    Snapshot(IdentitySnapshot),
    Keys(Vec<VirtualKey>),
    Metadata(Vec<CredentialMeta>),
    Credentials(Vec<CredentialSecret>),
    Denied(Vec<String>),
}
impl Tx<'_> {
    async fn since(&self, family: u8, since: u64) -> Result<Vec<(String, u64)>> {
        let mut result = Vec::new();
        let Some(first) = since.checked_add(1) else {
            return Ok(result);
        };
        // A prefix ending at the first eligible revision sorts before every id
        // at that revision, preserving the complete delta without scanning history.
        let after = keys::framed(b'R', &[&[family], &first.to_be_bytes()])?;
        for (at, value) in self
            .scan_after(keys::framed(b'R', &[&[family]])?, Some(after))
            .await?
        {
            let parts = keys::components(&at.key, b'R')?;
            if parts.len() != 3 || parts[0] != [family] {
                return Err(corrupt());
            }
            let revision = u64::from_be_bytes(parts[1].try_into().map_err(|_| corrupt())?);
            let index: Index = decode(&value, None, false)?;
            if index.id.as_bytes() != parts[2] || revision == 0 {
                return Err(corrupt());
            }
            if revision > since {
                result.push((index.id, revision));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;

/// Encode imported identity evidence without dispatching a business mutation.
/// The importer owns global revision high-water and duplicate/index validation.
pub(crate) fn migration_key(
    key: &VirtualKey,
) -> RecordStoreResult<Vec<(Address, Secret<Vec<u8>>)>> {
    let mut rows = vec![(row(b'K', &key.id)?, Secret::new(encode(key)?))];
    if key.revision != 0 {
        rows.push((
            revision_key(b'K', key.revision, &key.id)?,
            Secret::new(encode(&Index { id: key.id.clone() })?),
        ));
    }
    Ok(rows)
}

pub(crate) fn migration_credential_rows(
    meta: &CredentialMeta,
    envelope: &[u8],
    owner_tombstoned: bool,
) -> RecordStoreResult<Vec<(Address, Secret<Vec<u8>>)>> {
    if meta.slot > 1 {
        return Err(Error::Invalid("credential slot must be 0 or 1").into());
    }
    if owner_tombstoned && (meta.revoked_at.is_none() || !envelope.is_empty()) {
        return Err(
            Error::Invalid("tombstoned owner cannot retain a live credential or envelope").into(),
        );
    }
    if meta.revoked_at.is_some() && !envelope.is_empty() {
        return Err(Error::Invalid(
            "revoked envelope must be retained as separate migration evidence",
        )
        .into());
    }
    let mut rows = vec![
        (row(b'C', &meta.id)?, Secret::new(encode(meta)?)),
        (confidential(&meta.id)?, Secret::new(envelope.to_vec())),
    ];
    if meta.revision != 0 {
        rows.push((
            revision_key(b'C', meta.revision, &meta.id)?,
            Secret::new(encode(&Index {
                id: meta.id.clone(),
            })?),
        ));
    }
    if !owner_tombstoned {
        rows.push((
            slot(meta)?,
            Secret::new(encode(&Index {
                id: meta.id.clone(),
            })?),
        ));
        rows.push((
            public(meta)?,
            Secret::new(encode(&Index {
                id: meta.id.clone(),
            })?),
        ));
    }
    Ok(rows)
}

pub(crate) fn migration_revision(revision: u64) -> RecordStoreResult<(Address, Secret<Vec<u8>>)> {
    Ok((address(b'V', &[])?, Secret::new(revision_encode(revision))))
}

pub(crate) fn migration_denied(
    subject: &str,
    reason: &str,
    created_at: u64,
) -> RecordStoreResult<(Address, Secret<Vec<u8>>)> {
    Ok((
        row(b'D', subject)?,
        Secret::new(encode(&Denied {
            subject: subject.into(),
            reason: reason.into(),
            created_at,
            // The legacy denylist has no revision. Zero preserves that absence.
            revision: 0,
        })?),
    ))
}

/// Classify only exact canonical identity addresses for migration authorization.
pub(crate) fn migration_authorizes(at: &Address) -> bool {
    let Some(&tag) = at.key.first() else {
        return false;
    };
    let Ok(parts) = keys::components(&at.key, tag) else {
        return false;
    };
    if at.namespace == CONFIDENTIAL.0 {
        return tag == b'C' && parts.len() == 1;
    }
    if at.namespace != NAMESPACE.0 {
        return false;
    }
    match tag {
        b'K' | b'C' | b'D' => parts.len() == 1,
        b'S' => parts.len() == 3 && parts[2].len() == 1 && parts[2][0] <= 1,
        b'P' => parts.len() == 2,
        b'R' => parts.len() == 3 && matches!(parts[0], [b'K'] | [b'C']) && parts[1].len() == 8,
        b'V' => parts.is_empty(),
        _ => false,
    }
}
