// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_contract::host_records::conditional::{
    Decision, Expected, Mutation, Predicate, Request,
};
use busbar_contract::Secret;
use busbar_kernel::persistence::facade::PendingId;
use busbar_kernel::persistence::scoped::{self, ScopedStore};
use oauth_as::authorization::{AuthorizationCodeRecord, AuthorizationCodeState};
use oauth_as::client::{Client, ClientId};
use oauth_as::consent::ConsentRecord;
use oauth_as::device::{normalize_user_code, DeviceGrant, DeviceGrantState};
use oauth_as::par::PushedAuthorizationRequest;
use oauth_as::store::{RevocationWindow, Storage, StorageError, WriteOutcome};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub(crate) const LABEL: &str = "\u{1}oauth_as\u{1}";

pub(crate) const VERSION_CLAIM_SECS: u64 = 120;

pub(crate) const CLOCK_SKEW_SECS: u64 = 30;

pub(crate) const RETIRE_AFTER_SECS: u64 = VERSION_CLAIM_SECS + CLOCK_SKEW_SECS;

pub(crate) const INDEX_GRACE_SECS: u64 = 600;

pub(crate) const SWAP_ATTEMPTS: u32 = 64;

// Preserve the OAuth logical-cell admission boundary that preceded the native
// port. This is a domain budget, independent of plane and generic Store bounds.
const MAX_LOGICAL_CELL_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn kind(name: &str) -> String {
    format!("{LABEL}{name}")
}

fn atomic_kind(name: &str) -> bool {
    matches!(name, "bucket" | "family" | "uc" | "key") || name.starts_with("ix.")
}

pub(crate) fn atomic_schema(name: &str) -> String {
    format!("{}.atomic.v1", kind(name))
}

pub(crate) fn authority_body(value: &[u8]) -> Result<Option<&[u8]>, StorageError> {
    match value.split_first() {
        Some((b'-', nonce)) if nonce.len() == 32 => Ok(None),
        Some((b'-', _)) | None => Err(StorageError::new(
            "oauth_as store: invalid authoritative record",
        )),
        _ => Ok(Some(value)),
    }
}

/// A retired cell's body: `-` and a fresh nonce, in the nonce's own allocation.
pub(crate) fn tombstone() -> Result<Vec<u8>, StorageError> {
    let mut body = nonce()?.into_bytes();
    body.insert(0, b'-');
    Ok(body)
}

pub(crate) fn digest(value: &str) -> String {
    hex::encode(busbar_contract::crypto::sha256(value.as_bytes()))
}

fn nonce() -> Result<String, StorageError> {
    let mut bytes = [0u8; 16];
    busbar_contract::crypto::fill(&mut bytes).map_err(|_| {
        StorageError::new("oauth_as store: the system's random source gave nothing")
    })?;
    Ok(hex::encode(bytes))
}

/// The node clock's one wall reading, as a [`SystemTime`].
pub(crate) fn now_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(busbar_kernel::store::now_ns())
}

pub(crate) fn now_secs() -> u64 {
    busbar_kernel::store::now_ns() / 1_000_000_000
}

pub(crate) fn secs_of(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub(crate) fn failed(what: &str, f: impl std::fmt::Debug) -> StorageError {
    super::cold::store_failed(what, f)
}

fn decode_failed(what: &str, e: &busbar_contract::json::Error) -> StorageError {
    super::cold::store_decode_failed(what, e)
}

pub(crate) fn encode<T: Serialize>(what: &str, value: &T) -> Result<Vec<u8>, StorageError> {
    busbar_contract::json::to_vec(value).map_err(|e| decode_failed(what, &e))
}

pub(crate) fn decode<T: DeserializeOwned>(what: &str, body: &[u8]) -> Result<T, StorageError> {
    busbar_contract::json::parse(body).map_err(|e| decode_failed(what, &e))
}

fn user_code(d: &DeviceGrant) -> (String, String) {
    (normalize_user_code(&d.user_code), d.device_code.clone())
}

/// A revocation barrier's two instants (`oauth_as::store::RevocationWindow`, kept).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Times {
    pub(crate) recorded_at: SystemTime,
    pub(crate) until: SystemTime,
}

impl Times {
    fn merge(slot: &mut Option<Times>, w: RevocationWindow) {
        let t = slot.get_or_insert(Times {
            recorded_at: w.recorded_at,
            until: w.until,
        });
        t.until = t.until.max(w.until);
        t.recorded_at = t.recorded_at.max(w.recorded_at);
    }

    fn covers(&self, established: SystemTime) -> bool {
        established <= self.recorded_at
    }
}

/// EVERYTHING ONE CLIENT HOLDS, swapped whole.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Bucket {
    /// The client this bucket is for, as written: what the sweep walks the buckets by.
    pub(crate) id: String,
    pub(crate) client: Option<Client>,
    pub(crate) client_barrier: Option<Times>,
    pub(crate) consent_barriers: BTreeMap<String, Times>,
    pub(crate) tokens: BTreeMap<String, IssuedToken>,
    pub(crate) refresh: BTreeMap<String, RefreshTokenRecord>,
    pub(crate) codes: BTreeMap<String, AuthorizationCodeRecord>,
    pub(crate) pushed: BTreeMap<String, PushedAuthorizationRequest>,
    pub(crate) devices: BTreeMap<String, DeviceGrant>,
    pub(crate) consents: BTreeMap<String, ConsentRecord>,
}

impl Bucket {
    fn barred(&self, subject: Option<&str>, established: SystemTime) -> bool {
        if self
            .client_barrier
            .is_some_and(|t| t.covers(established) || self.client.is_none())
        {
            return true;
        }
        subject.is_some_and(|s| {
            self.consent_barriers
                .get(s)
                .is_some_and(|t| t.covers(established))
        })
    }

    pub(crate) fn records(&self) -> usize {
        self.tokens.len() + self.refresh.len() + self.codes.len() + self.devices.len()
    }

    pub(crate) fn idle(&self) -> bool {
        self.records() == 0 && self.pushed.is_empty() && self.consents.is_empty()
    }

    pub(crate) fn holds_nothing(&self) -> bool {
        self.client.is_none()
            && self.client_barrier.is_none()
            && self.consent_barriers.is_empty()
            && self.idle()
    }
}

/// The versioned envelope a bucket is kept in.
#[derive(Serialize, Deserialize)]
pub(crate) struct Cell<T> {
    pub(crate) v: u64,
    pub(crate) b: T,
    /// When this version was written (Unix seconds): what the sweep retires a cell by.
    #[serde(default)]
    pub(crate) at: u64,
    /// The cell's own id, so the sweep can name it again.
    #[serde(default)]
    pub(crate) id: String,
    /// The cell's epoch, picked by the write that created it.
    #[serde(default)]
    pub(crate) e: String,
}

/// A [`Cell`] as it is written: the same fields in the same order, its id and epoch lent.
#[derive(Serialize)]
struct CellOut<'a, T> {
    v: u64,
    b: T,
    at: u64,
    id: &'a str,
    e: &'a str,
}

pub(crate) enum Swap<R> {
    Write(R),

    Keep(R),

    Retire(R, bool),
}

impl<R> Swap<R> {
    pub(crate) fn when(changed: bool, r: R) -> Self {
        if changed {
            Swap::Write(r)
        } else {
            Swap::Keep(r)
        }
    }
}

struct Pending {
    state: tokio::sync::Mutex<PendingState>,
    request: Arc<scoped::Request>,
    addresses: Vec<(String, Vec<u8>)>,
}

#[derive(Default)]
struct PendingState {
    id: Option<PendingId>,
    decision: Option<Decision>,
}

type ClaimAddress = (String, String);
struct ClaimState {
    expires_at: u64,
    pending: Option<scoped::PendingClaim>,
    terminal: bool,
}
type ClaimCell = Arc<tokio::sync::Mutex<ClaimState>>;
type ClaimEntries = Mutex<BTreeMap<ClaimAddress, ClaimCell>>;

struct ClaimLease<'a> {
    entries: &'a ClaimEntries,
    address: ClaimAddress,
    state: ClaimCell,
}
impl Drop for ClaimLease<'_> {
    fn drop(&mut self) {
        // Keep one gate while any caller can still use it. The last waiter also
        // cleans a terminal entry when cancellation prevents a normal return.
        let mut claims = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if claims
            .get(&self.address)
            .is_some_and(|current| Arc::ptr_eq(current, &self.state))
            && Arc::strong_count(&self.state) == 2
            && self.state.try_lock().is_ok_and(|state| state.terminal)
        {
            claims.remove(&self.address);
        }
    }
}

pub(crate) struct Shared {
    pub(crate) store: Arc<ScopedStore>,
    pending: Mutex<Vec<Arc<Pending>>>,
    claims: ClaimEntries,
}

impl Shared {
    pub(crate) fn new(store: Arc<ScopedStore>) -> Self {
        Self {
            store,
            pending: Mutex::new(Vec::new()),
            claims: Mutex::new(BTreeMap::new()),
        }
    }

    fn decision(outcome: scoped::Outcome) -> Result<Decision, StorageError> {
        match outcome {
            scoped::Outcome::Applied => Ok(Decision::Applied),
            scoped::Outcome::ConditionConflict => Ok(Decision::ConditionConflict),
            other => Err(failed("unresolved conditional record", other)),
        }
    }

    pub(crate) async fn submit(&self, request: Arc<Request>) -> Result<Decision, StorageError> {
        let oversized = request.mutations.iter().any(|mutation| matches!(mutation,
            Mutation::Put {schema,value,..} if schema.ends_with(".atomic.v1") && value.len()>MAX_LOGICAL_CELL_BYTES
        )) || request.predicates.iter().any(|predicate| matches!(&predicate.expected,
            Expected::Bytes(value) if predicate.schema.ends_with(".atomic.v1") && value.len()>MAX_LOGICAL_CELL_BYTES
        ));
        if oversized {
            return Err(StorageError::new(
                "oauth_as store: logical cell exceeds byte budget",
            ));
        }
        // The candidate is this call's own: its parts move into the store's request, uncopied.
        let mut request = request;
        let owned: &mut Request = Arc::make_mut(&mut request);
        let request = scoped::Request {
            op_id: owned.op_id.0,
            predicates: owned
                .predicates
                .drain(..)
                .map(|p| scoped::Predicate {
                    schema: p.schema,
                    key: p.key,
                    expected: match p.expected {
                        Expected::Absent => scoped::Expected::Absent,
                        Expected::Bytes(bytes) => scoped::Expected::Exact(Secret::new(bytes)),
                    },
                })
                .collect(),
            mutations: owned
                .mutations
                .drain(..)
                .map(|m| match m {
                    Mutation::Put { schema, key, value } => scoped::Mutation::Put {
                        schema,
                        key,
                        value: Secret::new(value),
                    },
                    Mutation::Delete { schema, key } => scoped::Mutation::Delete { schema, key },
                    Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => scoped::Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    },
                })
                .collect(),
        };
        let request = Arc::new(request);
        let mut addresses: Vec<_> = request
            .predicates
            .iter()
            .map(|p| (p.schema.clone(), p.key.clone()))
            .collect();
        addresses.extend(request.mutations.iter().map(|m| match m {
            scoped::Mutation::Put { schema, key, .. }
            | scoped::Mutation::Delete { schema, key } => (schema.clone(), key.clone()),
            scoped::Mutation::DeleteRange { schema, prefix, .. } => {
                (schema.clone(), prefix.clone())
            }
        }));
        let pending = Arc::new(Pending {
            state: tokio::sync::Mutex::new(PendingState::default()),
            request,
            addresses,
        });
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(pending.clone());
        self.submit_pending(pending).await
    }

    async fn submit_pending(&self, pending: Arc<Pending>) -> Result<Decision, StorageError> {
        // Every waiter shares the definitive answer. Cancellation releases this
        // gate while the immutable request and CoreStore attempt remain owned.
        let mut state = pending.state.lock().await;
        if let Some(decision) = state.decision {
            return Ok(decision);
        }
        let outcome = match state.id {
            Some(id) => self.store.retry(id).await,
            None => self.store.conditional_native(&pending.request).await,
        }
        .map_err(|e| failed("conditional record", e))?;
        match outcome {
            scoped::Outcome::Pending(id)
            | scoped::Outcome::Reconcile(id)
            | scoped::Outcome::Busy(Some(id)) => state.id = Some(id),
            scoped::Outcome::Busy(None) => {}
            _ => {
                state.decision = Self::decision(outcome).ok();
                self.pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .retain(|p| !Arc::ptr_eq(p, &pending));
            }
        }
        Self::decision(outcome)
    }

    async fn settle(&self, schema: &str, key: Option<&[u8]>) -> Result<(), StorageError> {
        let pending: Vec<_> = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|p| {
                p.addresses
                    .iter()
                    .any(|(s, k)| s == schema && key.is_none_or(|key| k == key))
            })
            .cloned()
            .collect();
        for pending in pending {
            self.submit_pending(pending).await?;
        }
        Ok(())
    }

    pub(crate) fn candidate(
        schema: &str,
        id: &str,
        expected: Option<Vec<u8>>,
        value: Vec<u8>,
    ) -> Arc<Request> {
        Arc::new(Request {
            version: busbar_contract::host_records::conditional::VERSION,
            op_id: busbar_kernel::door::op_id(),
            predicates: vec![Predicate {
                schema: schema.to_string(),
                key: id.as_bytes().to_vec(),
                expected: expected.map_or(Expected::Absent, Expected::Bytes),
            }],
            mutations: vec![Mutation::Put {
                schema: schema.to_string(),
                key: id.as_bytes().to_vec(),
                value,
            }],
        })
    }

    async fn bucket_indexes(
        &self,
        request: &mut Request,
        bucket: &Bucket,
        now: u64,
    ) -> Result<(), StorageError> {
        let mut indexes = BTreeMap::new();
        for (ix, keys) in [
            ("tok", bucket.tokens.keys().collect::<Vec<_>>()),
            ("rt", bucket.refresh.keys().collect()),
            ("code", bucket.codes.keys().collect()),
            ("par", bucket.pushed.keys().collect()),
            ("dev", bucket.devices.keys().collect()),
            ("cons", bucket.consents.keys().collect()),
        ] {
            for key in keys {
                indexes.insert((ix, digest(key)), ());
            }
        }
        for family in bucket
            .tokens
            .values()
            .filter_map(|t| t.family_id.as_deref())
            .chain(bucket.refresh.values().map(|r| r.family_id.as_str()))
        {
            indexes.insert(("fam", digest(family)), ());
        }
        for ((ix, id), ()) in indexes {
            let row = IndexRow {
                client: bucket.id.as_str(),
                key: id.as_str(),
                at: now,
            };
            let value = encode("index", &row)?;
            request.mutations.push(Mutation::Put {
                schema: atomic_schema(&format!("ix.{ix}")),
                key: id.into_bytes(),
                value,
            });
        }
        let mut subjects = BTreeMap::new();
        for consent in bucket.consents.values() {
            subjects.insert(digest(&consent.subject), ());
        }
        for (id, ()) in subjects {
            let raw = self.authority(SUBJECT_INDEX, &id).await?;
            let cell: Option<Cell<SubjectIndex>> = raw
                .as_deref()
                .map(authority_body)
                .transpose()?
                .flatten()
                .map(|body| decode(SUBJECT_INDEX, body))
                .transpose()?;
            let mut cell = cell.unwrap_or(Cell {
                v: 0,
                b: SubjectIndex::default(),
                at: 0,
                id: id.clone(),
                e: nonce()?,
            });
            cell.v = cell.v.checked_add(1).ok_or_else(|| {
                StorageError::new("oauth_as store: subject index version exhausted")
            })?;
            cell.at = now;
            cell.id.clone_from(&id);
            if cell
                .b
                .clients
                .get(&bucket.id)
                .is_none_or(|i| now.saturating_sub(i.at) > INDEX_GRACE_SECS / 2)
            {
                cell.b
                    .clients
                    .insert(bucket.id.clone(), Indexed { at: now });
            }
            let schema = atomic_schema(SUBJECT_INDEX);
            request.predicates.push(Predicate {
                schema: schema.clone(),
                key: id.as_bytes().to_vec(),
                expected: raw.map_or(Expected::Absent, Expected::Bytes),
            });
            request.mutations.push(Mutation::Put {
                schema,
                key: id.into_bytes(),
                value: encode(SUBJECT_INDEX, &cell)?,
            });
        }
        let mut codes = BTreeMap::new();
        for grant in bucket.devices.values() {
            let (code, owner) = user_code(grant);
            codes.insert(digest(&code), owner);
        }
        let previous: Option<Cell<Bucket>> = request
            .predicates
            .iter()
            .find(|p| p.schema == atomic_schema("bucket"))
            .and_then(|p| match &p.expected {
                Expected::Bytes(body) => Some(body.as_slice()),
                Expected::Absent => None,
            })
            .map(authority_body)
            .transpose()?
            .flatten()
            .map(|body| decode("bucket", body))
            .transpose()?;
        let mut released = BTreeMap::new();
        if let Some(previous) = previous {
            for grant in previous.b.devices.values() {
                let (code, owner) = user_code(grant);
                let id = digest(&code);
                if !codes.contains_key(&id) {
                    released.insert(id, owner);
                }
            }
        }
        for (id, owner) in released {
            let raw = self.authority("uc", &id).await?;
            let cell: Option<Cell<Option<String>>> = raw
                .as_deref()
                .map(authority_body)
                .transpose()?
                .flatten()
                .map(|body| decode("uc", body))
                .transpose()?;
            let Some(mut cell) = cell else {
                continue;
            };
            if cell.b.as_deref() != Some(owner.as_str()) {
                continue;
            }
            let value = if now.saturating_sub(cell.at) > RETIRE_AFTER_SECS {
                tombstone()?
            } else {
                cell.v = cell.v.checked_add(1).ok_or_else(|| {
                    StorageError::new("oauth_as store: user-code index version exhausted")
                })?;
                cell.b = None;
                cell.at = now;
                cell.id.clone_from(&id);
                encode("uc", &cell)?
            };
            let schema = atomic_schema("uc");
            request.predicates.push(Predicate {
                schema: schema.clone(),
                key: id.as_bytes().to_vec(),
                expected: raw.map_or(Expected::Absent, Expected::Bytes),
            });
            request.mutations.push(Mutation::Put {
                schema,
                key: id.into_bytes(),
                value,
            });
        }
        for (id, owner) in codes {
            let raw = self.authority("uc", &id).await?;
            let cell: Option<Cell<Option<String>>> = raw
                .as_deref()
                .map(authority_body)
                .transpose()?
                .flatten()
                .map(|body| decode("uc", body))
                .transpose()?;
            let mut cell = cell.unwrap_or(Cell {
                v: 0,
                b: None,
                at: 0,
                id: id.clone(),
                e: nonce()?,
            });
            if cell.b.as_deref().is_some_and(|held| held != owner) {
                return Err(StorageError::new(
                    "user code is already indexed for a different device_code",
                ));
            }
            cell.v = cell.v.checked_add(1).ok_or_else(|| {
                StorageError::new("oauth_as store: user-code index version exhausted")
            })?;
            cell.at = now;
            cell.id.clone_from(&id);
            cell.b = Some(owner);
            let schema = atomic_schema("uc");
            request.predicates.push(Predicate {
                schema: schema.clone(),
                key: id.as_bytes().to_vec(),
                expected: raw.map_or(Expected::Absent, Expected::Bytes),
            });
            request.mutations.push(Mutation::Put {
                schema,
                key: id.into_bytes(),
                value: encode("uc", &cell)?,
            });
        }
        Ok(())
    }

    async fn read_record(&self, schema: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.store
            .get(schema, key)
            .await
            .map(|v| v.map(|v| v.expose(&busbar_kernel::seal::lend()).clone()))
            .map_err(|e| failed("read record", e))
    }

    pub(crate) async fn authority(
        &self,
        name: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let schema = atomic_schema(name);
        self.settle(&schema, Some(id.as_bytes())).await?;
        let value = self.read_record(&schema, id.as_bytes()).await?;
        if let Some(value) = &value {
            authority_body(value)?;
        }
        Ok(value)
    }

    pub(crate) fn schema(name: &str) -> String {
        if atomic_kind(name) {
            atomic_schema(name)
        } else {
            kind(name)
        }
    }

    async fn get_body(&self, name: &str, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        if atomic_kind(name) {
            // A live authoritative body is the whole record: hand the read back, uncopied.
            return match self.authority(name, id).await? {
                Some(v) => {
                    let live = authority_body(&v)?.is_some();
                    Ok(live.then_some(v))
                }
                None => Ok(None),
            };
        }
        let schema = Self::schema(name);
        self.settle(&schema, Some(id.as_bytes())).await?;
        self.read_record(&schema, id.as_bytes()).await
    }

    async fn get<T: DeserializeOwned>(
        &self,
        name: &str,
        id: &str,
    ) -> Result<Option<T>, StorageError> {
        self.get_body(name, id)
            .await?
            .map(|body| decode(name, &body))
            .transpose()
    }

    async fn put_body(&self, name: &str, id: &str, body: Vec<u8>) -> Result<(), StorageError> {
        if atomic_kind(name) {
            return Err(StorageError::new(
                "oauth_as store: authoritative records require an exact candidate",
            ));
        }
        let schema = Self::schema(name);
        self.settle(&schema, Some(id.as_bytes())).await?;
        self.submit(Arc::new(Request {
            version: busbar_contract::host_records::conditional::VERSION,
            op_id: busbar_kernel::door::op_id(),
            predicates: vec![],
            mutations: vec![Mutation::Put {
                schema,
                key: id.as_bytes().to_vec(),
                value: body,
            }],
        }))
        .await
        .map(drop)
    }

    async fn put<T: Serialize>(&self, name: &str, id: &str, value: &T) -> Result<(), StorageError> {
        self.put_body(name, id, encode(name, value)?).await
    }

    pub(crate) async fn list<T: DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Vec<T>, StorageError> {
        let schema = Self::schema(name);
        self.settle(&schema, None).await?;
        let mut after = None;
        let mut rows = Vec::new();
        loop {
            let page = self
                .store
                .page(&schema, b"", after.as_ref())
                .await
                .map_err(|e| failed("scan records", e))?;
            for (_, value) in page.rows {
                let seal = busbar_kernel::seal::lend();
                let bytes = value.expose(&seal);
                let body = if atomic_kind(name) {
                    authority_body(bytes)?
                } else {
                    Some(bytes.as_slice())
                };
                if let Some(body) = body {
                    rows.push(decode(name, body)?);
                }
            }
            after = page.next;
            if after.is_none() {
                break;
            }
        }
        Ok(rows)
    }

    pub(crate) async fn delete(&self, name: &str, id: &str) -> Result<(), StorageError> {
        if atomic_kind(name) {
            return Err(StorageError::new(
                "oauth_as store: authoritative records retire through CAS",
            ));
        }
        let schema = Self::schema(name);
        self.settle(&schema, Some(id.as_bytes())).await?;
        self.submit(Arc::new(Request {
            version: busbar_contract::host_records::conditional::VERSION,
            op_id: busbar_kernel::door::op_id(),
            predicates: vec![],
            mutations: vec![Mutation::Delete {
                schema,
                key: id.as_bytes().to_vec(),
            }],
        }))
        .await
        .map(drop)
    }

    async fn claim(&self, name: &str, token: &str, expires_at: u64) -> Result<bool, StorageError> {
        let kind = kind(name);
        self.store
            .register_claims(&kind)
            .map_err(|error| failed("register claim cleanup", error))?;
        let address = (kind.clone(), token.to_string());
        let state = {
            let mut claims = self.claims.lock().unwrap_or_else(|p| p.into_inner());
            claims
                .entry(address.clone())
                .or_insert_with(|| {
                    Arc::new(tokio::sync::Mutex::new(ClaimState {
                        expires_at,
                        pending: None,
                        terminal: false,
                    }))
                })
                .clone()
        };
        let lease = ClaimLease {
            entries: &self.claims,
            address,
            state,
        };
        // One delivery owner resolves this address at a time. A competing caller
        // observes the durable consumed claim after the first owner finishes;
        // cancellation keeps the same expiry and native attempt available to retry.
        let mut claim = lease.state.lock().await;
        if claim.terminal {
            claim.expires_at = expires_at;
            claim.terminal = false;
        }
        if claim.expires_at != expires_at {
            return Err(StorageError::new(
                "oauth_as store: pending claim expiry changed",
            ));
        }
        let outcome = match claim.pending {
            Some(claim) => self.store.retry_claim(&kind, claim).await,
            None => self.store.redeem(&kind, token, expires_at).await,
        }
        .map_err(|e| failed("redeem", e))?;
        match outcome {
            scoped::ClaimOutcome::Claimed
            | scoped::ClaimOutcome::AlreadyClaimed
            | scoped::ClaimOutcome::Expired => {
                claim.pending = None;
                claim.terminal = true;
                Ok(matches!(outcome, scoped::ClaimOutcome::Claimed))
            }
            scoped::ClaimOutcome::Pending(pending)
            | scoped::ClaimOutcome::Reconcile(pending)
            | scoped::ClaimOutcome::Busy(pending) => {
                claim.pending = Some(pending);
                Err(failed("unresolved claim", outcome))
            }
        }
    }

    async fn read_cell<T: DeserializeOwned + Default>(
        &self,
        kind_name: &str,
        id: &str,
    ) -> Result<(u64, u64, String, T), StorageError> {
        Ok(match self.get::<Cell<T>>(kind_name, id).await? {
            None => (0, 0, String::new(), T::default()),
            Some(c) => (c.v, c.at, c.e, c.b),
        })
    }

    pub(crate) async fn cas_cell<T, R>(
        &self,
        kind_name: &str,
        id: &str,
        now: u64,
        f: impl FnMut(&mut T, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError>
    where
        T: Serialize + DeserializeOwned + Default,
    {
        self.cas_cell_guarded(kind_name, id, None, now, f)
            .await?
            .ok_or_else(|| StorageError::new("oauth_as store: unexpected family guard"))
    }

    async fn cas_cell_guarded<T, R>(
        &self,
        kind_name: &str,
        id: &str,
        family: Option<&str>,
        now: u64,
        mut f: impl FnMut(&mut T, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<Option<R>, StorageError>
    where
        T: Serialize + DeserializeOwned + Default,
    {
        let schema = atomic_schema(kind_name);
        for attempt in 0..SWAP_ATTEMPTS {
            let family_guard = if let Some(family) = family {
                let family_id = digest(family);
                let raw = self.authority("family", &family_id).await?;
                let cell: Option<Cell<FamilyBar>> = raw
                    .as_deref()
                    .map(authority_body)
                    .transpose()?
                    .flatten()
                    .map(|body| decode("family", body))
                    .transpose()?;
                if cell.is_some_and(|c| c.b.times.is_some()) {
                    return Ok(None);
                }
                Some(Predicate {
                    schema: atomic_schema("family"),
                    key: family_id.into_bytes(),
                    expected: raw.map_or(Expected::Absent, Expected::Bytes),
                })
            } else {
                None
            };
            let raw = self.authority(kind_name, id).await?;
            let cell: Option<Cell<T>> = raw
                .as_deref()
                .map(authority_body)
                .transpose()?
                .flatten()
                .map(|body| decode(kind_name, body))
                .transpose()?;
            let (v, at, epoch, mut value) = match cell {
                Some(c) => (c.v, c.at, c.e, c.b),
                None => (0, 0, String::new(), T::default()),
            };
            let (answer, retire) = match f(&mut value, at)? {
                Swap::Keep(r) => return Ok(Some(r)),
                Swap::Write(r) => (r, false),
                Swap::Retire(r, changed) => {
                    if v != 0 && now.saturating_sub(at) > RETIRE_AFTER_SECS {
                        (r, true)
                    } else if changed && v != 0 {
                        (r, false)
                    } else {
                        return Ok(Some(r));
                    }
                }
            };
            let next = v
                .checked_add(1)
                .ok_or_else(|| StorageError::new("oauth_as store: cell version exhausted"))?;

            let epoch = if v == 0 { nonce()? } else { epoch };
            let body = if retire {
                tombstone()?
            } else {
                let cell = CellOut {
                    v: next,
                    b: &value,
                    at: now,
                    id,
                    e: &epoch,
                };
                encode(kind_name, &cell)?
            };
            let mut candidate = Self::candidate(&schema, id, raw, body);
            let request = Arc::make_mut(&mut candidate);
            if let Some(guard) = family_guard {
                request.predicates.push(guard);
            }
            if kind_name == "bucket" {
                let body = encode(kind_name, &value)?;
                let bucket = decode::<Bucket>(kind_name, &body)?;
                self.bucket_indexes(request, &bucket, now).await?;
            }
            match self.submit(candidate).await? {
                Decision::Applied => return Ok(Some(answer)),
                Decision::ConditionConflict => {}
            }

            tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(20)))).await;
        }
        Err(super::cold::no_version_won(kind_name, SWAP_ATTEMPTS))
    }

    pub(crate) async fn bucket(&self, client_id: &str) -> Result<Bucket, StorageError> {
        Ok(self
            .read_cell::<Bucket>("bucket", &digest(client_id))
            .await?
            .3)
    }

    pub(crate) async fn update<R>(
        &self,
        client_id: &str,
        now: u64,
        mut f: impl FnMut(&mut Bucket, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError> {
        self.cas_cell("bucket", &digest(client_id), now, |b: &mut Bucket, at| {
            if b.id != client_id {
                b.id.clear();
                b.id.push_str(client_id);
            }
            f(b, at)
        })
        .await
    }

    async fn update_guarded<R>(
        &self,
        client_id: &str,
        family: Option<&str>,
        now: u64,
        mut f: impl FnMut(&mut Bucket, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<Option<R>, StorageError> {
        self.cas_cell_guarded(
            "bucket",
            &digest(client_id),
            family,
            now,
            |b: &mut Bucket, at| {
                if b.id != client_id {
                    b.id.clear();
                    b.id.push_str(client_id);
                }
                f(b, at)
            },
        )
        .await
    }

    async fn index(
        &self,
        ix: &str,
        key: &str,
        client_id: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        let id = digest(key);
        let row = IndexRow {
            client: client_id,
            key: id.as_str(),
            at: now,
        };
        let name = format!("ix.{ix}");
        for _ in 0..SWAP_ATTEMPTS {
            let raw = self.authority(&name, &id).await?;
            let candidate = Self::candidate(&atomic_schema(&name), &id, raw, encode(&name, &row)?);
            if self.submit(candidate).await? == Decision::Applied {
                return Ok(());
            }
        }
        Err(StorageError::new(
            "oauth_as store: index repeatedly conflicted",
        ))
    }

    async fn client_of(&self, ix: &str, key: &str) -> Result<Option<String>, StorageError> {
        let Some(body) = self.get_body(&format!("ix.{ix}"), &digest(key)).await? else {
            return Ok(None);
        };
        decode::<IndexRow>(ix, &body).map(|row| Some(row.client))
    }

    async fn lookup<R>(
        &self,
        ix: &str,
        key: &str,
        pick: impl FnOnce(Bucket) -> Option<R>,
    ) -> Result<Option<R>, StorageError> {
        let Some(client) = self.client_of(ix, key).await? else {
            return Ok(None);
        };
        Ok(pick(self.bucket(&client).await?))
    }

    async fn take<R>(
        &self,
        ix: &str,
        key: &str,
        mut pick: impl FnMut(&mut Bucket) -> Option<R>,
    ) -> Result<Option<R>, StorageError> {
        let Some(client) = self.client_of(ix, key).await? else {
            return Ok(None);
        };
        self.update(&client, now_secs(), |b, _| {
            let taken = pick(b);
            Ok(Swap::when(taken.is_some(), taken))
        })
        .await
    }

    async fn index_subject(
        &self,
        key: &str,
        client_id: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        self.cas_cell::<SubjectIndex, ()>(SUBJECT_INDEX, &digest(key), now, |ix, _| {
            if ix
                .clients
                .get(client_id)
                .is_some_and(|i| now.saturating_sub(i.at) <= INDEX_GRACE_SECS / 2)
            {
                return Ok(Swap::Keep(()));
            }
            ix.clients
                .insert(client_id.to_string(), Indexed { at: now });
            Ok(Swap::Write(()))
        })
        .await
    }

    async fn family_barred(&self, family_id: Option<&str>) -> Result<bool, StorageError> {
        let Some(family) = family_id else {
            return Ok(false);
        };
        let (_, _, _, bar) = self
            .read_cell::<FamilyBar>("family", &digest(family))
            .await?;
        Ok(bar.times.is_some())
    }

    async fn revoke_family(
        &self,
        family_id: &str,
        window: RevocationWindow,
    ) -> Result<u64, StorageError> {
        let id = digest(family_id);
        let now = now_secs();
        for attempt in 0..SWAP_ATTEMPTS {
            let raw = self.authority("family", &id).await?;
            let cell: Option<Cell<FamilyBar>> = raw
                .as_deref()
                .map(authority_body)
                .transpose()?
                .flatten()
                .map(|body| decode("family", body))
                .transpose()?;
            let mut cell = cell.unwrap_or(Cell {
                v: 0,
                b: FamilyBar::default(),
                at: 0,
                id: id.clone(),
                e: nonce()?,
            });
            cell.v = cell
                .v
                .checked_add(1)
                .ok_or_else(|| StorageError::new("oauth_as store: family version exhausted"))?;
            cell.at = now;
            cell.id.clone_from(&id);
            cell.b.id.clone_from(&id);
            Times::merge(&mut cell.b.times, window);
            let mut request =
                Self::candidate(&atomic_schema("family"), &id, raw, encode("family", &cell)?);
            let request_body = Arc::make_mut(&mut request);

            let index = self.authority("ix.fam", &id).await?;
            let owner: Option<IndexRow> = index
                .as_deref()
                .map(authority_body)
                .transpose()?
                .flatten()
                .map(|body| decode("ix.fam", body))
                .transpose()?;
            request_body.predicates.push(Predicate {
                schema: atomic_schema("ix.fam"),
                key: id.as_bytes().to_vec(),
                expected: index.map_or(Expected::Absent, Expected::Bytes),
            });
            let mut removed = 0;
            if let Some(owner) = owner {
                let bucket_id = digest(&owner.client);
                let bucket_raw = self.authority("bucket", &bucket_id).await?;
                let bucket: Option<Cell<Bucket>> = bucket_raw
                    .as_deref()
                    .map(authority_body)
                    .transpose()?
                    .flatten()
                    .map(|body| decode("bucket", body))
                    .transpose()?;
                if let Some(mut bucket) = bucket {
                    bucket.b.id.clone_from(&owner.client);
                    let before = bucket.b.tokens.len() + bucket.b.refresh.len();
                    bucket
                        .b
                        .tokens
                        .retain(|_, t| t.family_id.as_deref() != Some(family_id));
                    bucket.b.refresh.retain(|_, r| r.family_id != family_id);
                    removed = (before - bucket.b.tokens.len() - bucket.b.refresh.len()) as u64;
                    request_body.predicates.push(Predicate {
                        schema: atomic_schema("bucket"),
                        key: bucket_id.as_bytes().to_vec(),
                        expected: bucket_raw.map_or(Expected::Absent, Expected::Bytes),
                    });
                    if removed != 0 {
                        bucket.v = bucket.v.checked_add(1).ok_or_else(|| {
                            StorageError::new("oauth_as store: bucket version exhausted")
                        })?;
                        bucket.at = now;
                        bucket.id.clone_from(&bucket_id);
                        request_body.mutations.push(Mutation::Put {
                            schema: atomic_schema("bucket"),
                            key: bucket_id.into_bytes(),
                            value: encode("bucket", &bucket)?,
                        });
                        self.bucket_indexes(request_body, &bucket.b, now).await?;
                    }
                } else {
                    request_body.predicates.push(Predicate {
                        schema: atomic_schema("bucket"),
                        key: bucket_id.into_bytes(),
                        expected: bucket_raw.map_or(Expected::Absent, Expected::Bytes),
                    });
                }
            }
            match self.submit(request).await? {
                Decision::Applied => return Ok(removed),
                Decision::ConditionConflict => {
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(20)))).await
                }
            }
        }
        Err(StorageError::new(
            "oauth_as store: family revocation repeatedly conflicted",
        ))
    }

    async fn hold_user_code(
        &self,
        normalized: &str,
        device_code: &str,
    ) -> Result<(), StorageError> {
        self.cas_cell::<Option<String>, ()>("uc", &digest(normalized), now_secs(), |held, _| {
            match held.as_deref() {
                Some(owner) if owner != device_code => Err(StorageError::new(
                    "user code is already indexed for a different device_code",
                )),
                Some(_) => Ok(Swap::Keep(())),
                None => {
                    *held = Some(device_code.to_string());
                    Ok(Swap::Write(()))
                }
            }
        })
        .await
    }

    async fn user_code_owner(&self, normalized: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .read_cell::<Option<String>>("uc", &digest(normalized))
            .await?
            .3)
    }

    pub(crate) async fn open_session(
        &self,
        id: &str,
        subject: &str,
        ttl: Duration,
    ) -> Result<(), StorageError> {
        let row = SessionRow {
            subject: subject.to_string(),
            until: now_secs() + ttl.as_secs(),
            id: digest(id),
        };
        self.put("session", &digest(id), &row).await
    }

    pub(crate) async fn session_subject(&self, id: &str) -> Result<Option<String>, StorageError> {
        self.session_subject_at(id, now_secs()).await
    }

    async fn session_subject_at(&self, id: &str, now: u64) -> Result<Option<String>, StorageError> {
        Ok(self
            .get::<SessionRow>("session", &digest(id))
            .await?
            .filter(|row| row.until > now)
            .map(|row| row.subject))
    }

    pub(crate) async fn stake(
        &self,
        id: &str,
        key: &str,
        approve: bool,
        ttl: Duration,
    ) -> Result<(), StorageError> {
        let now = now_secs();
        if self.session_subject_at(id, now).await?.is_none() {
            return Ok(());
        }
        let row_id = format!("{}:{}", digest(id), digest(key));
        let row = StakeRow {
            approve,
            until: now + ttl.as_secs(),
            id: row_id,
            nonce: nonce()?,
        };
        self.put("stake", &row.id, &row).await
    }

    async fn stake_row(&self, id: &str, key: &str) -> Result<Option<StakeRow>, StorageError> {
        Ok(self
            .get::<StakeRow>("stake", &format!("{}:{}", digest(id), digest(key)))
            .await?
            .filter(|row| row.until > now_secs()))
    }

    pub(crate) async fn is_staked(&self, id: &str, key: &str) -> Result<bool, StorageError> {
        Ok(self.stake_row(id, key).await?.is_some())
    }

    pub(crate) async fn spend(&self, id: &str, key: &str) -> Result<Option<bool>, StorageError> {
        let Some(row) = self.stake_row(id, key).await? else {
            return Ok(None);
        };
        let mut token = format!("{}:{}", digest(id), digest(key));
        if !row.nonce.is_empty() {
            token = format!("{token}:{}", row.nonce);
        }
        Ok(self
            .claim("spent", &token, row.until)
            .await?
            .then_some(row.approve))
    }

    pub(crate) async fn pushed(
        &self,
        request_uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, StorageError> {
        let now = now_time();
        self.lookup("par", request_uri, |mut b| {
            b.pushed.remove(request_uri).filter(|p| p.expires_at > now)
        })
        .await
    }

    pub(crate) async fn mark_pushed_shown(
        &self,
        request_uri: &str,
        until: SystemTime,
    ) -> Result<bool, StorageError> {
        Ok(!self
            .claim("shown", &digest(request_uri), secs_of(until))
            .await?)
    }

    async fn stored_key(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(body) = self.get_body("key", "signing").await? else {
            return Ok(None);
        };
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&body)
            .map(Some)
            .map_err(|_| StorageError::new("oauth_as store: the kept signing key did not decode"))
    }

    pub(crate) async fn signing_key(
        &self,
        mint: impl FnOnce() -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, String> {
        let read = || async { self.stored_key().await.map_err(|e| e.0) };
        if let Some(held) = read().await? {
            return Ok(held);
        }
        let der = mint()?;
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(&der);

        match self
            .submit(Self::candidate(
                &atomic_schema("key"),
                "signing",
                None,
                body.into_bytes(),
            ))
            .await
            .map_err(|e| e.0)?
        {
            Decision::Applied => Ok(der),
            Decision::ConditionConflict => {
                read().await?.ok_or_else(super::cold::signing_key_not_kept)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SessionRow {
    pub(crate) subject: String,
    pub(crate) until: u64,
    /// The row's own id, so the sweep can delete it.
    #[serde(default)]
    pub(crate) id: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StakeRow {
    pub(crate) approve: bool,
    pub(crate) until: u64,
    /// The row's own id, so the sweep can delete it.
    #[serde(default)]
    pub(crate) id: String,
    /// This answer's own nonce: its spend claim names it, so each answer is spent once.
    #[serde(default)]
    pub(crate) nonce: String,
}

pub(crate) const LOST_ROW: &str = "oauth_as: a lapsed row was not reclaimed this tick";
pub(crate) const LOST_REPLAY: &str = "oauth_as: a lapsed replay row was not reclaimed this tick";

/// One claimed replay id, kept beside its claim so the sweep can count what it reclaims.
#[derive(Serialize, Deserialize)]
pub(crate) struct ReplayRow {
    pub(crate) id: String,
    pub(crate) until: u64,
}

pub(crate) const SUBJECT_INDEX: &str = "ix.subj";

/// A SUBJECT'S INDEX: every client the subject consented to, by client id.
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct SubjectIndex {
    #[serde(default)]
    pub(crate) clients: BTreeMap<String, Indexed>,
}

/// When a client was indexed under a subject (Unix seconds).
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Indexed {
    pub(crate) at: u64,
}

/// One credential's index row: the client it was minted for, the credential's digest (the row's
/// id) and when the row was written.
#[derive(Serialize, Deserialize)]
pub(crate) struct IndexRow<S = String> {
    pub(crate) client: S,
    pub(crate) key: S,
    pub(crate) at: u64,
}

pub(crate) fn bucket_holds(b: &Bucket, ix: &str, key: &str) -> bool {
    let is = |value: &str| digest(value) == key;
    match ix {
        "tok" => b.tokens.keys().any(|k| is(k)),
        "rt" => b.refresh.keys().any(|k| is(k)),
        "code" => b.codes.keys().any(|k| is(k)),
        "par" => b.pushed.keys().any(|k| is(k)),
        "dev" => b.devices.keys().any(|k| is(k)),
        "cons" => b.consents.keys().any(|k| is(k)),
        _ => {
            b.tokens
                .values()
                .any(|t| t.family_id.as_deref().is_some_and(is))
                || b.refresh.values().any(|r| is(&r.family_id))
        }
    }
}

/// A token family's barrier, named by its family's digest so the sweep can find it again.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct FamilyBar {
    pub(crate) id: String,
    pub(crate) times: Option<Times>,
}

pub(crate) struct SharedStorage {
    shared: Arc<Shared>,
}

struct Guarded<'a> {
    client: &'a str,
    ix: &'a str,
    key: &'a str,
    family: Option<&'a str>,
    subject: Option<&'a str>,
    established: SystemTime,
}

impl SharedStorage {
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    async fn put_guarded(
        &self,
        g: Guarded<'_>,
        insert: impl Fn(&mut Bucket),
        remove: impl Fn(&mut Bucket) -> bool,
    ) -> Result<WriteOutcome, StorageError> {
        let now = now_secs();
        let s = &self.shared;
        if let Some(f) = g.family {
            s.index("fam", f, g.client, now).await?;
        }
        s.index(g.ix, g.key, g.client, now).await?;
        let applied = s
            .update_guarded(g.client, g.family, now, |b, _| {
                if b.barred(g.subject, g.established) {
                    return Ok(Swap::Keep(false));
                }
                insert(b);
                Ok(Swap::Write(true))
            })
            .await?
            .unwrap_or(false);
        if !applied {
            return Ok(WriteOutcome::RefusedRevoked);
        }
        if s.family_barred(g.family).await? {
            s.update(g.client, now, |b, _| Ok(Swap::when(remove(b), ())))
                .await?;
            return Ok(WriteOutcome::RefusedRevoked);
        }
        Ok(WriteOutcome::Applied)
    }
}

impl Storage for SharedStorage {
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Arc<Client>>, StorageError> {
        Ok(self
            .shared
            .bucket(client_id.as_str())
            .await?
            .client
            .map(Arc::new))
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        let id = client.client_id.as_str();
        self.shared
            .update(id, now_secs(), |b, _| {
                b.client = Some(client.clone());
                Ok(Swap::Write(()))
            })
            .await
    }

    async fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> Result<bool, StorageError> {
        let id = updated.client_id.as_str();
        self.shared
            .update(id, now_secs(), |b, _| {
                if b.client.as_ref() != Some(expected) {
                    return Ok(Swap::Keep(false));
                }
                b.client = Some(updated.clone());
                Ok(Swap::Write(true))
            })
            .await
    }

    async fn delete_client(
        &self,
        client_id: &ClientId,
        window: RevocationWindow,
    ) -> Result<bool, StorageError> {
        if client_id.as_str().is_empty() {
            return Err(StorageError::new(
                "a revocation needs a non-empty client_id; the empty string does not name an \
                 identity a barrier can be recorded for",
            ));
        }
        let existed = self
            .shared
            .update(client_id.as_str(), now_secs(), |b, _| {
                let existed = b.client.take().is_some();
                Times::merge(&mut b.client_barrier, window);
                b.tokens.clear();
                b.refresh.clear();
                b.codes.clear();
                b.pushed.clear();
                b.devices.clear();
                b.consents.clear();
                Ok(Swap::Write(existed))
            })
            .await?;
        Ok(existed)
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let now = now_secs();
        let s = &self.shared;
        let normalized = normalize_user_code(&grant.user_code);
        s.hold_user_code(&normalized, &grant.device_code).await?;
        let client = grant.client_id.as_str();
        s.index("dev", &grant.device_code, client, now).await?;
        s.update(client, now, |b, _| {
            b.devices.insert(grant.device_code.clone(), grant.clone());
            Ok(Swap::Write(()))
        })
        .await?;
        Ok(())
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.shared
            .lookup("dev", device_code, |mut b| b.devices.remove(device_code))
            .await
    }

    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let Some(device_code) = self.shared.user_code_owner(normalized_user_code).await? else {
            return Ok(None);
        };
        self.get_device_grant(&device_code).await
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.shared
            .take("dev", device_code, |b| b.devices.remove(device_code))
            .await
    }

    async fn compare_and_swap_device_grant(
        &self,
        expected: &DeviceGrantState,
        updated: DeviceGrant,
    ) -> Result<bool, StorageError> {
        let s = &self.shared;
        let Some(client) = s.client_of("dev", &updated.device_code).await? else {
            return Ok(false);
        };
        let is_expected = |b: &Bucket| {
            b.devices
                .get(&updated.device_code)
                .is_some_and(|current| current.state == *expected)
        };

        if !is_expected(&s.bucket(&client).await?) {
            return Ok(false);
        }
        let normalized = normalize_user_code(&updated.user_code);
        if let Some(owner) = s.user_code_owner(&normalized).await? {
            if owner != updated.device_code {
                return Err(StorageError::new(
                    "user code is already indexed for a different device_code",
                ));
            }
        }
        let swapped = s
            .update(&client, now_secs(), |b, _| {
                if !is_expected(b) {
                    return Ok(Swap::Keep(false));
                }
                b.devices
                    .insert(updated.device_code.clone(), updated.clone());
                Ok(Swap::Write(true))
            })
            .await?;
        Ok(swapped)
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        let now = now_secs();
        let client = record.client_id.as_str();
        self.shared.index("code", &record.code, client, now).await?;
        self.shared
            .update(client, now, |b, _| {
                b.codes.insert(record.code.clone(), record.clone());
                Ok(Swap::Write(()))
            })
            .await
    }

    async fn compare_and_swap_authorization_code(
        &self,
        expected: &AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> Result<bool, StorageError> {
        let Some(client) = self.shared.client_of("code", &updated.code).await? else {
            return Ok(false);
        };
        self.shared
            .update(&client, now_secs(), |b, _| {
                match b.codes.get(&updated.code) {
                    Some(current) if current.state == *expected => {}
                    _ => return Ok(Swap::Keep(false)),
                }
                b.codes.insert(updated.code.clone(), updated.clone());
                Ok(Swap::Write(true))
            })
            .await
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        self.shared
            .take("code", code, |b| b.codes.remove(code))
            .await
    }

    async fn put_pushed_authorization_request(
        &self,
        record: PushedAuthorizationRequest,
    ) -> Result<WriteOutcome, StorageError> {
        let now = now_secs();
        let client = record.client_id.as_str();
        self.shared
            .index("par", &record.request_uri, client, now)
            .await?;
        self.shared
            .update(client, now, |b, _| {
                if b.barred(None, record.pushed_at) {
                    return Ok(Swap::Keep(WriteOutcome::RefusedRevoked));
                }
                b.pushed.insert(record.request_uri.clone(), record.clone());
                Ok(Swap::Write(WriteOutcome::Applied))
            })
            .await
    }

    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, StorageError> {
        self.shared
            .take("par", request_uri, |b| b.pushed.remove(request_uri))
            .await
    }

    async fn put_token(&self, token: IssuedToken) -> Result<WriteOutcome, StorageError> {
        let client = token.client_id.as_str();
        let access = token.access_token.as_str();
        let g = Guarded {
            client,
            ix: "tok",
            key: access,
            family: token.family_id.as_deref(),
            subject: token.subject.as_deref(),
            established: token.grant_established_at,
        };
        self.put_guarded(
            g,
            |b| {
                b.tokens.insert(access.to_string(), token.clone());
            },
            |b| b.tokens.remove(access).is_some(),
        )
        .await
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Arc<IssuedToken>>, StorageError> {
        self.shared
            .lookup("tok", access_token, |mut b| {
                b.tokens.remove(access_token).map(Arc::new)
            })
            .await
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        self.shared
            .take("tok", access_token, |b| b.tokens.remove(access_token))
            .await
            .map(drop)
    }

    async fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> Result<WriteOutcome, StorageError> {
        let rt = record.refresh_token.as_str();
        let g = Guarded {
            client: record.client_id.as_str(),
            ix: "rt",
            key: rt,
            family: Some(&record.family_id),
            subject: record.subject.as_deref(),
            established: record.grant_established_at,
        };
        self.put_guarded(
            g,
            |b| {
                b.refresh.insert(rt.to_string(), record.clone());
            },
            |b| b.refresh.remove(rt).is_some(),
        )
        .await
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Arc<RefreshTokenRecord>>, StorageError> {
        self.shared
            .lookup("rt", refresh_token, |mut b| {
                b.refresh.remove(refresh_token).map(Arc::new)
            })
            .await
    }

    async fn rotate_refresh_token(
        &self,
        expected: &RefreshTokenRecord,
        spent: &RefreshTokenRecord,
        access: &IssuedToken,
        next: Option<&RefreshTokenRecord>,
    ) -> Result<bool, StorageError> {
        let now = now_secs();
        let s = &self.shared;
        let client = expected.client_id.as_str();
        if s.family_barred(Some(&expected.family_id)).await? {
            return Ok(false);
        }
        s.index("tok", &access.access_token, client, now).await?;
        if let Some(f) = &access.family_id {
            s.index("fam", f, client, now).await?;
        }
        if let Some(n) = next {
            s.index("rt", &n.refresh_token, client, now).await?;
            s.index("fam", &n.family_id, client, now).await?;
        }
        let rotated = s
            .update_guarded(client, Some(&expected.family_id), now, |b, _| {
                if b.refresh.get(&expected.refresh_token) != Some(expected)
                    || b.barred(expected.subject.as_deref(), expected.grant_established_at)
                {
                    return Ok(Swap::Keep(false));
                }
                b.refresh.insert(spent.refresh_token.clone(), spent.clone());
                b.tokens.insert(access.access_token.clone(), access.clone());
                if let Some(n) = next {
                    b.refresh.insert(n.refresh_token.clone(), n.clone());
                }
                Ok(Swap::Write(true))
            })
            .await?
            .unwrap_or(false);
        if rotated && s.family_barred(Some(&expected.family_id)).await? {
            s.update(client, now, |b, _| {
                b.tokens.remove(&access.access_token);
                if let Some(n) = next {
                    b.refresh.remove(&n.refresh_token);
                }
                Ok(Swap::Write(()))
            })
            .await?;
            return Ok(false);
        }
        Ok(rotated)
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        self.shared
            .take("rt", refresh_token, |b| b.refresh.remove(refresh_token))
            .await
    }

    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: RevocationWindow,
    ) -> Result<u64, StorageError> {
        if family_id.is_empty() {
            return Err(StorageError::new(
                "a revocation needs a non-empty family_id; the empty string does not name an \
                 identity a barrier can be recorded for",
            ));
        }
        self.shared.revoke_family(family_id, window).await
    }

    async fn put_consent(&self, record: ConsentRecord) -> Result<(), StorageError> {
        let now = now_secs();
        let s = &self.shared;
        let client = record.client_id.as_str();
        s.index("cons", &record.consent_id, client, now).await?;
        s.index_subject(&record.subject, client, now).await?;
        s.update(client, now, |b, _| {
            b.consents
                .insert(record.consent_id.to_string(), record.clone());
            Ok(Swap::Write(()))
        })
        .await
    }

    async fn compare_and_swap_consent(
        &self,
        expected: Option<&ConsentRecord>,
        updated: ConsentRecord,
    ) -> Result<bool, StorageError> {
        let now = now_secs();
        let s = &self.shared;
        let client = updated.client_id.as_str();
        s.index("cons", &updated.consent_id, client, now).await?;
        s.index_subject(&updated.subject, client, now).await?;
        s.update(client, now, |b, _| {
            let current = b
                .consents
                .values()
                .find(|c| c.client_id == updated.client_id && c.subject == updated.subject);
            match (current, expected) {
                (Some(live), Some(expected)) if live == expected => {}
                (None, None) => {}
                _ => return Ok(Swap::Keep(false)),
            }
            b.consents
                .insert(updated.consent_id.to_string(), updated.clone());
            Ok(Swap::Write(true))
        })
        .await
    }

    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<Arc<ConsentRecord>>, StorageError> {
        self.shared
            .lookup("cons", consent_id, |mut b| {
                b.consents.remove(consent_id).map(Arc::new)
            })
            .await
    }

    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<Arc<ConsentRecord>>, StorageError> {
        Ok(self
            .shared
            .bucket(client_id.as_str())
            .await?
            .consents
            .into_values()
            .find(|c| &c.client_id == client_id && c.subject.as_ref() == subject)
            .map(Arc::new))
    }

    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<Arc<ConsentRecord>>, StorageError> {
        let (_, _, _, ix) = self
            .shared
            .read_cell::<SubjectIndex>(SUBJECT_INDEX, &digest(subject))
            .await?;
        let mut out = Vec::new();
        for client in ix.clients.into_keys() {
            out.extend(
                self.shared
                    .bucket(&client)
                    .await?
                    .consents
                    .into_values()
                    .filter(|c| c.subject.as_ref() == subject)
                    .map(Arc::new),
            );
        }
        Ok(out)
    }

    async fn revoke_consent(
        &self,
        consent_id: &str,
        window: RevocationWindow,
    ) -> Result<u64, StorageError> {
        let Some(client) = self.shared.client_of("cons", consent_id).await? else {
            return Ok(0);
        };
        let removed = self
            .shared
            .update(&client, now_secs(), |b, _| {
                let Some(peek) = b.consents.get(consent_id) else {
                    return Ok(Swap::Keep(0));
                };
                if peek.client_id.as_str().is_empty() || peek.subject.is_empty() {
                    return Err(StorageError::new(
                        "a revocation needs a non-empty client_id and subject; the empty string \
                         does not name an identity a barrier can be recorded for",
                    ));
                }
                let consent = b
                    .consents
                    .remove(consent_id)
                    .expect("the peek above read the same bucket");
                let cid = consent.client_id;
                let subject = consent.subject.into_string();
                let mut slot = b.consent_barriers.get(&subject).copied();
                Times::merge(&mut slot, window);
                let before = b.records();
                let of_grant = |client: &ClientId, s: Option<&str>| *client == cid && s == Some(subject.as_str());
                b.tokens
                    .retain(|_, t| !of_grant(&t.client_id, t.subject.as_deref()));
                b.refresh
                    .retain(|_, r| !of_grant(&r.client_id, r.subject.as_deref()));
                b.codes
                    .retain(|_, c| !of_grant(&c.client_id, Some(c.subject.as_str())));
                b.devices.retain(|_, d| {
                    let gone = d.client_id == cid
                        && matches!(&d.state, DeviceGrantState::Approved { subject: s } if *s == subject);
                    !gone
                });
                if let Some(t) = slot {
                    b.consent_barriers.insert(subject, t);
                }
                Ok(Swap::Write((before - b.records()) as u64))
            })
            .await?;
        Ok(removed)
    }

    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, StorageError> {
        let s = &self.shared;
        let key = digest(id);
        let won = s.claim("replay", &key, secs_of(expires_at)).await?;
        if won {
            let row = ReplayRow {
                id: key.clone(),
                until: secs_of(expires_at),
            };
            s.put("replay", &key, &row).await?;
        }
        Ok(won)
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        self.shared.sweep_expired(now).await
    }
}

#[cfg(test)]
#[path = "tests/shared_tests.rs"]
mod shared_tests;
