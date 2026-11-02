// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE AUTHORIZATION SERVER HOLDS, KEPT IN THE DEPLOYMENT'S STORE, so every node behind one
//! store serves one server (THE DESIGN §1: "Multi-node is the design ... Nodes share one store").
//!
//! Versioned cells and the signing key use the store's negotiated conditional-record operation.
//! The comparison, mutation and applied receipt commit together. Client cancellation never
//! authorizes a late unconditional overwrite. Other records retain their plane-record verbs.
//!
//! * **One record per client, versioned.** Everything a client holds — its registration, the
//!   revocation barriers recorded against it, its codes, tokens, refresh tokens, pushed requests,
//!   device grants and consents — is one [`Bucket`]. A write is a COMPARE-AND-SWAP on the bucket's
//!   exact stored bytes: read version `v`, compare those bytes and write `v + 1` atomically.
//!   Every condition loser reads again. So the
//!   library's atomic steps (`take_*`, the compare-and-swaps, a client deletion and its cascade)
//!   are one bucket swap each, and hold across nodes exactly as `MemoryStorage`'s mutex holds them
//!   inside one process.
//! * **Unknown outcomes retain the exact candidate.** Before submission, the operation id,
//!   predicates and mutations are retained in [`Shared`], independently of its caller's future.
//!   The next access replays that candidate; only a definitive condition conflict replans.
//!   This in-process retention is not a durable journal: restart can lose the candidate, but its
//!   backend comparison still prevents it overwriting newer state, however late it decides.
//! * **Legacy state is imported once.** A raw authoritative record wins over a legacy plane row.
//!   Its first import compares raw absence. Retirement keeps a unique credential-free tombstone
//!   in that same record, so neither a late legacy write nor an old creation candidate resurrects
//!   retired state. New nodes ignore subsequent legacy writes. Running old binaries still use
//!   their old storage semantics; this does not make mixed-version writers honor new authority.
//! * **`take_*` = compare and remove.** A take is a swap that removes the record: exactly one
//!   taker wins the version, every other sees the record gone.
//! * **Deletion and revocation are tombstones while they bar anything.** A bucket keeps its
//!   barriers until they lapse. A cell holding nothing (an empty bucket, a lapsed family barrier, a
//!   released user code) is RETIRED by the sweep after [`RETIRE_AFTER_SECS`], under an exact
//!   comparison, leaving only its unique authority tombstone. A writer creates a fresh epoch by
//!   comparing that tombstone.
//! * **A self-registered client that holds nothing is reclaimed.** RFC 7591 registration takes no
//!   credential, so a registered client whose bucket has held no record (code, token, refresh
//!   token, pushed request, device grant, consent) for [`crate::policy::REGISTERED_CLIENT_IDLE`] is
//!   deleted by the sweep and its bucket retired. A client the operator provisioned is never in the
//!   store, and is never reclaimed.
//! * **Lookups by a credential** (an access token, a refresh token, a code, a pushed handle, a
//!   device code, a consent id or a family) go through index records naming the client, one per
//!   credential; required indexes are also written atomically with every bucket mutation, so a
//!   record the bucket holds is always reachable. The sweep retires an index row whose credential
//!   its client no longer holds after [`INDEX_GRACE_SECS`], comparing that bucket atomically.
//!   A subject's index is
//!   one cell naming every client it consented to, each with when it was indexed: the sweep drops a
//!   client whose bucket no longer holds a consent of that subject once its entry is past the same
//!   grace, under the cell's exact comparison, and retires the cell once it names no client.
//! * **The token-family barrier** is the one barrier that names no client: it is its own record,
//!   committed atomically with its client's token cascade. Guarded token/refresh writes and
//!   rotations compare the barrier's exact bytes; a delayed candidate cannot bypass it.
//!
//! Cells, indexes and the key live in raw record schemas with a fixed private label. Legacy
//! plane rows and auxiliary sessions/stakes live at sequence 0 with no parent, where every store
//! reads `get_plane_record` back from. A store deletes a plane record by its identity, which
//! for a parented record is its parent, so no record here hangs off one: each is reclaimed alone.
//! The sweep deletes lapsed sessions and staked answers.
//!
//! One sweep pass that cannot read or delete one record says so and goes on to the next: a client
//! whose records will not read keeps its index rows until a later tick reads them.
//!
//! The consent screen's sessions and staked answers, the pushed-request notes and the minted
//! signing key ride the same records ([`Shared`]).
//!
//! THE MINTED SIGNING KEY is kept as THE DESIGN rules the deployment keyset is kept: "sealed in the
//! store", which is to say minted once for the deployment, under an atomic absent comparison, and
//! kept in the store for every node to read back (the keyset itself is kept the same way, as its
//! seed, in the store's record slots). Whoever reads the store reads it, as they read the
//! deployment keyset and every live token the buckets hold. An operator who wants the key outside
//! the store's reach configures `oauth_as.signing_key`, a secret reference, and nothing is minted;
//! the build says so at `warn` when it signs with the kept key.

mod records;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request,
};
use busbar_contract::records::{PlaneDisposition, PlaneRecordRef, PlaneSelector};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};
use oauth_as::authorization::{AuthorizationCodeRecord, AuthorizationCodeState};
use oauth_as::client::{Client, ClientId};
use oauth_as::consent::ConsentRecord;
use oauth_as::device::{normalize_user_code, DeviceGrant, DeviceGrantState};
use oauth_as::par::PushedAuthorizationRequest;
use oauth_as::store::{RevocationWindow, Storage, StorageError, WriteOutcome};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The fixed kernel label every record kind of the authorization server lives under. It begins
/// with a control character, which no admitted instance label or plane record kind holds, so no
/// plane can name or reach these records.
pub(crate) const LABEL: &str = "\u{1}oauth_as\u{1}";

/// The previous version-claim lifetime, retained as the retirement grace for existing cells.
pub(crate) const VERSION_CLAIM_SECS: u64 = 120;

/// The previous clock-skew allowance, retained only as part of retirement grace.
pub(crate) const CLOCK_SKEW_SECS: u64 = 30;

/// How old a cell's last write must be before the sweep retires its payload.
pub(crate) const RETIRE_AFTER_SECS: u64 = VERSION_CLAIM_SECS + CLOCK_SKEW_SECS;

/// How old an unused index row must be before the sweep may retire it. Correctness rests on
/// atomic comparisons and index restoration in bucket commits, not a bound on in-flight time.
pub(crate) const INDEX_GRACE_SECS: u64 = 600;

/// How many times one write reads again after losing a version to another writer.
const SWAP_ATTEMPTS: u32 = 64;

/// The record kind `kind` of the authorization server.
fn kind(name: &str) -> String {
    format!("{LABEL}{name}")
}

fn atomic_kind(name: &str) -> bool {
    matches!(name, "bucket" | "family" | "uc" | "key") || name.starts_with("ix.")
}

fn atomic_schema(name: &str) -> String {
    format!("{}.atomic.v1", kind(name))
}

/// Live bytes remain exact legacy bytes, preserving the existing per-record size bound. Retired
/// records start with `-`, which neither a JSON cell/index nor a standard-base64 key can start
/// with, followed by a fresh nonce. The nonce prevents ABA across create/retire cycles.
fn live_body(body: &[u8]) -> Vec<u8> {
    body.to_vec()
}

fn authority_body(value: &[u8]) -> Result<Option<&[u8]>, StorageError> {
    match value.split_first() {
        Some((b'-', nonce)) if nonce.len() == 32 => Ok(None),
        Some((b'-', _)) | None => Err(StorageError::new(
            "oauth_as store: invalid authoritative record",
        )),
        _ => Ok(Some(value)),
    }
}

/// A record id for `value`: its SHA-256, hex. Credentials never appear as store keys.
fn digest(value: &str) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, value.as_bytes()).as_ref())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// A fresh random value, hex: a cell's epoch, a staked answer's nonce.
fn nonce() -> Result<String, StorageError> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| {
            StorageError::new("oauth_as store: the system's random source gave nothing")
        })?;
    Ok(hex(&bytes))
}

fn now_secs() -> u64 {
    secs_of(SystemTime::now())
}

fn secs_of(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A store failure as the library's error. The store's text names no credential: every key this
/// module hands the store is a digest.
fn failed(what: &str, f: StoreFailure) -> StorageError {
    StorageError::new(format!("oauth_as store: {what}: {f:?}"))
}

fn decode_failed(what: &str, e: serde_json::Error) -> StorageError {
    StorageError::new(format!("oauth_as store: {what} did not decode: {e}"))
}

/// THE ONE RECORD CODEC: every record this module keeps is one JSON value.
fn encode<T: Serialize>(what: &str, value: &T) -> Result<Vec<u8>, StorageError> {
    serde_json::to_vec(value).map_err(|e| decode_failed(what, e))
}

fn decode<T: DeserializeOwned>(what: &str, body: &[u8]) -> Result<T, StorageError> {
    serde_json::from_slice(body).map_err(|e| decode_failed(what, e))
}

/// A device grant's user code, normalized, and its device code: what its user-code cell holds.
fn user_code(d: &DeviceGrant) -> (String, String) {
    (normalize_user_code(&d.user_code), d.device_code.clone())
}

/// Run `fut` to completion on this thread, parking until it is woken. For the one synchronous
/// caller (the build, minting the signing key), off any runtime worker it may be on.
pub(crate) fn wait_for<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Wake, Waker};
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let run = move || {
        let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
            std::thread::park();
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(run)
        }
        _ => run(),
    }
}

/// A revocation barrier's two instants (`oauth_as::store::RevocationWindow`, kept).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Times {
    recorded_at: SystemTime,
    until: SystemTime,
}

impl Times {
    /// The later of each instant, as `MemoryStorage` merges a second barrier into a first.
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
struct Bucket {
    /// The client this bucket is for, as written: what the sweep walks the buckets by.
    id: String,
    client: Option<Client>,
    client_barrier: Option<Times>,
    consent_barriers: BTreeMap<String, Times>,
    tokens: BTreeMap<String, IssuedToken>,
    refresh: BTreeMap<String, RefreshTokenRecord>,
    codes: BTreeMap<String, AuthorizationCodeRecord>,
    pushed: BTreeMap<String, PushedAuthorizationRequest>,
    devices: BTreeMap<String, DeviceGrant>,
    consents: BTreeMap<String, ConsentRecord>,
}

impl Bucket {
    /// `MemoryStorage::is_revoked`'s client and consent arms, for this bucket's client. The family
    /// arm is [`Shared::family_barred`].
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

    fn records(&self) -> usize {
        self.tokens.len() + self.refresh.len() + self.codes.len() + self.devices.len()
    }

    /// Whether this bucket holds no record a client keeps alive by.
    fn idle(&self) -> bool {
        self.records() == 0 && self.pushed.is_empty() && self.consents.is_empty()
    }

    /// Whether this bucket holds nothing at all: no client, no barrier and no record.
    fn holds_nothing(&self) -> bool {
        self.client.is_none()
            && self.client_barrier.is_none()
            && self.consent_barriers.is_empty()
            && self.idle()
    }
}

/// The versioned envelope a bucket is kept in.
#[derive(Serialize, Deserialize)]
struct Cell<T> {
    v: u64,
    b: T,
    /// When this version was written (Unix seconds): what the sweep retires a cell by.
    #[serde(default)]
    at: u64,
    /// The cell's own id, so the sweep can name it again.
    #[serde(default)]
    id: String,
    /// The cell's epoch, picked by the write that created it.
    #[serde(default)]
    e: String,
}

/// The one write a swap made, or that it made none.
enum Swap<R> {
    /// Write the bucket and answer `R`.
    Write(R),
    /// Answer `R` without writing.
    Keep(R),
    /// The cell now holds nothing: retire its payload once its last write is older than
    /// [`RETIRE_AFTER_SECS`]; until then write it when `changed`, else keep it. Answer `R`.
    Retire(R, bool),
}

impl<R> Swap<R> {
    /// Write when `changed`, else keep; answer `r` either way.
    fn when(changed: bool, r: R) -> Self {
        if changed {
            Swap::Write(r)
        } else {
            Swap::Keep(r)
        }
    }
}

/// THE STORE THE AUTHORIZATION SERVER SHARES with every node on the deployment's store.
pub(crate) struct Shared {
    calls: Arc<dyn StoreCalls>,
    /// Registered before the first submission and removed only on a definitive decision. A
    /// dropped caller does not drop this retained candidate. It is deliberately in process:
    /// atomic predicates protect against late backend decisions even after process restart.
    pending: Mutex<Vec<Arc<Request>>>,
}

impl Shared {
    pub(crate) fn new(calls: Arc<dyn StoreCalls>) -> Self {
        Self {
            calls,
            pending: Mutex::new(Vec::new()),
        }
    }

    /// A configured store must provide the negotiated atomic primitive; there is no emulation
    /// with claims or unconditional writes. The plane also checks this before publishing a build.
    pub(crate) fn require_atomic(calls: &dyn StoreCalls) -> Result<(), String> {
        if calls.supports_record_transaction() {
            Ok(())
        } else {
            Err("oauth_as requires a store with atomic conditional-record transactions".into())
        }
    }

    async fn submit(&self, request: Arc<Request>) -> Result<Decision, StorageError> {
        Self::require_atomic(self.calls.as_ref()).map_err(StorageError::new)?;
        let mut request = request;
        // Blind index publication also compares its observed root. This lets replacement reclaim
        // precisely the old chunk generation, without deleting a concurrent writer's chunks.
        let mut observed = Vec::new();
        for mutation in &request.mutations {
            if let Mutation::Put { schema, key, .. } = mutation {
                if schema.ends_with(".atomic.v1")
                    && !request
                        .predicates
                        .iter()
                        .any(|p| p.schema == *schema && p.key == *key)
                {
                    observed.push(Predicate {
                        schema: schema.clone(),
                        key: key.clone(),
                        expected: self
                            .read_record(schema, key)
                            .await?
                            .map_or(Expected::Absent, Expected::Bytes),
                    });
                }
            }
        }
        if !observed.is_empty() {
            Arc::make_mut(&mut request).predicates.extend(observed);
        }
        self.submit_physical(records::physical(request)?).await
    }

    /// Retain and replay exactly this validated wire candidate, never plan its chunks again.
    async fn submit_physical(&self, request: Arc<Request>) -> Result<Decision, StorageError> {
        request
            .encode()
            .map_err(|e| StorageError::new(format!("oauth_as store: {e}")))?;
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            if !pending.iter().any(|r| r.op_id == request.op_id) {
                pending.push(Arc::clone(&request));
            }
        }
        let decision = self
            .calls
            .record_transaction(&request)
            .await
            .map_err(|f| failed("conditional record", f))?;
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|r| r.op_id != request.op_id);
        Ok(decision)
    }

    async fn settle(&self, schema: &str, key: Option<&[u8]>) -> Result<(), StorageError> {
        Self::require_atomic(self.calls.as_ref()).map_err(StorageError::new)?;
        let pending: Vec<_> =
            self.pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .filter(|r| {
                    r.predicates.iter().any(|p| {
                        p.schema == schema && key.is_none_or(|key| p.key.as_slice() == key)
                    }) || r.mutations.iter().any(|m| {
                        let (s, k) = m.address();
                        s == schema && key.is_none_or(|key| k == key)
                    })
                })
                .cloned()
                .collect();
        for request in pending {
            self.submit_physical(request).await?;
        }
        Ok(())
    }

    fn candidate(
        schema: &str,
        id: &str,
        expected: Option<Vec<u8>>,
        value: Vec<u8>,
    ) -> Arc<Request> {
        Arc::new(Request {
            version: busbar_contract::abi::sdk::store::conditional::VERSION,
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

    /// Reachability is part of the bucket commit. A prewritten index alone is insufficient: a
    /// sweep may reclaim it while an accepted backend mutation remains pending indefinitely.
    async fn bucket_indexes(
        &self,
        request: &mut Request,
        bucket: &Bucket,
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
                client: bucket.id.clone(),
                key: id.clone(),
                at: now_secs(),
            };
            request.mutations.push(Mutation::Put {
                schema: atomic_schema(&format!("ix.{ix}")),
                key: id.into_bytes(),
                value: live_body(&encode("index", &row)?),
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
            cell.at = now_secs();
            cell.id.clone_from(&id);
            let now = now_secs();
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
                value: live_body(&encode(SUBJECT_INDEX, &cell)?),
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
            let value = if now_secs().saturating_sub(cell.at) > RETIRE_AFTER_SECS {
                format!("-{}", nonce()?).into_bytes()
            } else {
                cell.v = cell.v.checked_add(1).ok_or_else(|| {
                    StorageError::new("oauth_as store: user-code index version exhausted")
                })?;
                cell.b = None;
                cell.at = now_secs();
                cell.id.clone_from(&id);
                live_body(&encode("uc", &cell)?)
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
            cell.at = now_secs();
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
                value: live_body(&encode("uc", &cell)?),
            });
        }
        Ok(())
    }

    /// Reconstruct a bounded logical cell; concurrent replacement may remove an old generation.
    /// Re-read its exact descriptor before accepting either data or a corruption diagnosis.
    async fn read_record(&self, schema: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        for _ in 0..SWAP_ATTEMPTS {
            let Some(root) = self
                .calls
                .record_get(schema, key)
                .await
                .map_err(|f| failed("record root", f))?
            else {
                return Ok(None);
            };
            let Some(descriptor) = records::Descriptor::decode(root.as_slice())? else {
                return Ok(Some(root.as_slice().to_vec()));
            };
            let mut bytes = Vec::new();
            let parts_schema = records::parts_schema(schema);
            for part in 0..descriptor.parts() {
                let part_key = descriptor.key(key, part);
                let Some(part) = self
                    .calls
                    .record_get(&parts_schema, &part_key)
                    .await
                    .map_err(|f| failed("record chunk", f))?
                else {
                    break;
                };
                bytes.extend_from_slice(part.as_slice());
            }
            let current = self
                .calls
                .record_get(schema, key)
                .await
                .map_err(|f| failed("record root", f))?;
            if current.as_ref().map(|r| r.as_slice()) != Some(root.as_slice()) {
                continue;
            }
            if !descriptor.check(&bytes) {
                return Err(StorageError::new(
                    "oauth_as store: incomplete or corrupt chunked record",
                ));
            }
            return Ok(Some(bytes));
        }
        Err(StorageError::new(
            "oauth_as store: chunked record repeatedly changed",
        ))
    }

    /// Read raw authority, importing a legacy row once under an absent comparison. Never fall
    /// back after raw retirement: legacy writes can finish arbitrarily late.
    async fn authority(&self, name: &str, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let schema = atomic_schema(name);
        self.settle(&schema, Some(id.as_bytes())).await?;
        for _ in 0..SWAP_ATTEMPTS {
            if let Some(value) = self.read_record(&schema, id.as_bytes()).await? {
                authority_body(value.as_slice())?;
                if name == "key" {
                    self.cleanup_legacy(name, id).await;
                }
                return Ok(Some(value.as_slice().to_vec()));
            }
            let Some(legacy) = self
                .calls
                .get_plane_record(&kind(name), id)
                .await
                .map_err(|f| failed(name, f))?
            else {
                return Ok(None);
            };
            let value = live_body(&legacy);
            match self
                .submit(Self::candidate(&schema, id, None, value.clone()))
                .await?
            {
                Decision::Applied => {
                    self.cleanup_legacy(name, id).await;
                    return Ok(Some(value));
                }
                Decision::ConditionConflict => continue,
            }
        }
        Err(StorageError::new(
            "oauth_as store: legacy import repeatedly conflicted",
        ))
    }

    /// Raw authority is already durable before removing its superseded legacy copy. Cleanup
    /// failure never falls back or rolls authority back; a subsequent listing retries it.
    async fn cleanup_legacy(&self, name: &str, id: &str) {
        if let Err(f) = self.calls.delete_plane_record(&kind(name), id).await {
            tracing::warn!(error = %failed(name, f), "oauth_as: a superseded legacy row was not reclaimed");
        }
    }

    async fn get_body(&self, kind_name: &str, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Self::require_atomic(self.calls.as_ref()).map_err(StorageError::new)?;
        if atomic_kind(kind_name) {
            return self
                .authority(kind_name, id)
                .await?
                .map(|v| authority_body(&v).map(|b| b.map(<[u8]>::to_vec)))
                .transpose()
                .map(Option::flatten);
        }
        self.calls
            .get_plane_record(&kind(kind_name), id)
            .await
            .map_err(|f| failed(kind_name, f))
    }

    async fn get<T: DeserializeOwned>(
        &self,
        kind_name: &str,
        id: &str,
    ) -> Result<Option<T>, StorageError> {
        match self.get_body(kind_name, id).await? {
            Some(body) => decode(kind_name, &body).map(Some),
            None => Ok(None),
        }
    }

    /// Point-read records live at sequence 0 with no parent: that is where every store reads
    /// `get_plane_record` back from.
    async fn put_body(&self, kind_name: &str, id: &str, body: &[u8]) -> Result<(), StorageError> {
        Self::require_atomic(self.calls.as_ref()).map_err(StorageError::new)?;
        if atomic_kind(kind_name) {
            return Err(StorageError::new(
                "oauth_as store: authoritative records require an exact candidate",
            ));
        }
        let k = kind(kind_name);
        self.calls
            .upsert_plane_record(PlaneRecordRef {
                kind: &k,
                id,
                parent: None,
                seq: 0,
                ts: now_secs(),
                disposition: PlaneDisposition::Active,
                body,
            })
            .await
            .map_err(|f| failed(kind_name, f))
    }

    async fn put<T: Serialize>(
        &self,
        kind_name: &str,
        id: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        self.put_body(kind_name, id, &encode(kind_name, value)?)
            .await
    }

    /// Every record of `kind_name` that decodes as a `T`.
    async fn list<T: DeserializeOwned>(&self, kind_name: &str) -> Result<Vec<T>, StorageError> {
        Self::require_atomic(self.calls.as_ref()).map_err(StorageError::new)?;
        let mut rows = self
            .calls
            .list_plane_records(&kind(kind_name), &PlaneSelector::All)
            .await
            .map_err(|f| failed(kind_name, f))?;
        if atomic_kind(kind_name) {
            let schema = atomic_schema(kind_name);
            self.settle(&schema, None).await?;
            let raw: BTreeMap<_, _> = self
                .calls
                .record_scan(&schema, b"", u32::MAX)
                .await
                .map_err(|f| failed(kind_name, f))?
                .into_iter()
                .collect();
            // Every current cell stores its id. Older buckets/family barriers also store the
            // identifying value inside their payload; rows older than that remain point-readable
            // and retain the previous sweep's behavior for unidentifiable legacy bodies.
            let mut superseded = Vec::new();
            rows.retain(|body| {
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
                    return true;
                };
                let id = value
                    .get("id")
                    .or_else(|| value.get("key"))
                    .and_then(|v| v.as_str())
                    .filter(|id| !id.is_empty())
                    .map(str::to_string)
                    .or_else(|| {
                        value
                            .get("b")
                            .and_then(|b| b.get("id"))
                            .and_then(|v| v.as_str())
                            .map(|id| {
                                if kind_name == "bucket" {
                                    digest(id)
                                } else {
                                    id.to_string()
                                }
                            })
                    });
                if let Some(id) = id.filter(|id| raw.contains_key(id.as_bytes())) {
                    superseded.push(id);
                    false
                } else {
                    true
                }
            });
            for id in superseded {
                self.cleanup_legacy(kind_name, &id).await;
            }
            for key in raw.keys() {
                if let Some(value) = self.read_record(&schema, key).await? {
                    if let Some(body) = authority_body(&value)? {
                        rows.push(body.to_vec());
                    }
                }
            }
        }
        Ok(rows
            .iter()
            .filter_map(|body| serde_json::from_slice(body).ok())
            .collect())
    }

    async fn delete(&self, kind_name: &str, id: &str) -> Result<(), StorageError> {
        Self::require_atomic(self.calls.as_ref()).map_err(StorageError::new)?;
        if atomic_kind(kind_name) {
            return Err(StorageError::new(
                "oauth_as store: authoritative records retire through CAS",
            ));
        }
        self.calls
            .delete_plane_record(&kind(kind_name), id)
            .await
            .map_err(|f| failed(kind_name, f))
    }

    /// Redeem the single-use `token` of `kind_name`, standing until `expires_at` (Unix seconds):
    /// `true` when this call was its first redemption.
    async fn claim(
        &self,
        kind_name: &str,
        token: &str,
        expires_at: u64,
    ) -> Result<bool, StorageError> {
        Self::require_atomic(self.calls.as_ref()).map_err(StorageError::new)?;
        let now = now_secs();
        self.calls
            .redeem_plane_token(&kind(kind_name), token, expires_at, now)
            .await
            .map_err(|f| failed(kind_name, f))
    }

    /// The cell's version, when that version was written, its epoch, and its value.
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

    /// COMPARE-AND-SET the store cell `(kind_name, id)`, never an `AppHandle`: `f` reads the current
    /// value and when that version was written (Unix seconds), and says what to write. The store
    /// compares its exact bytes with the mutation, and a condition conflict reads again.
    async fn cas_cell<T, R>(
        &self,
        kind_name: &str,
        id: &str,
        f: impl FnMut(&mut T, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError>
    where
        T: Serialize + DeserializeOwned + Default,
    {
        self.cas_cell_guarded(kind_name, id, None, f)
            .await?
            .ok_or_else(|| StorageError::new("oauth_as store: unexpected family guard"))
    }

    async fn cas_cell_guarded<T, R>(
        &self,
        kind_name: &str,
        id: &str,
        family: Option<&str>,
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
                    if v != 0 && now_secs().saturating_sub(at) > RETIRE_AFTER_SECS {
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
            // A cell made now gets an epoch of its own; every version after carries it on.
            let epoch = if v == 0 { nonce()? } else { epoch };
            let body = if retire {
                format!("-{}", nonce()?).into_bytes()
            } else {
                let cell = Cell {
                    v: next,
                    b: &value,
                    at: now_secs(),
                    id: id.to_string(),
                    e: epoch,
                };
                live_body(&encode(kind_name, &cell)?)
            };
            let mut candidate = Self::candidate(&schema, id, raw, body);
            let request = Arc::make_mut(&mut candidate);
            if let Some(guard) = family_guard {
                request.predicates.push(guard);
            }
            if kind_name == "bucket" {
                let body = encode(kind_name, &value)?;
                let bucket = decode::<Bucket>(kind_name, &body)?;
                self.bucket_indexes(request, &bucket).await?;
            }
            match self.submit(candidate).await? {
                Decision::Applied => return Ok(Some(answer)),
                Decision::ConditionConflict => {}
            }
            // Another writer holds this version: read again, after a short, growing pause.
            tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(20)))).await;
        }
        Err(StorageError::new(format!(
            "oauth_as store: {kind_name}: no version won in {SWAP_ATTEMPTS} attempts"
        )))
    }

    async fn bucket(&self, client_id: &str) -> Result<Bucket, StorageError> {
        Ok(self
            .read_cell::<Bucket>("bucket", &digest(client_id))
            .await?
            .3)
    }

    /// Swap `client_id`'s bucket: `f` is told when its current version was written.
    async fn update<R>(
        &self,
        client_id: &str,
        mut f: impl FnMut(&mut Bucket, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError> {
        self.cas_cell("bucket", &digest(client_id), |b: &mut Bucket, at| {
            b.id = client_id.to_string();
            f(b, at)
        })
        .await
    }

    async fn update_guarded<R>(
        &self,
        client_id: &str,
        family: Option<&str>,
        mut f: impl FnMut(&mut Bucket, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<Option<R>, StorageError> {
        self.cas_cell_guarded(
            "bucket",
            &digest(client_id),
            family,
            |b: &mut Bucket, at| {
                b.id = client_id.to_string();
                f(b, at)
            },
        )
        .await
    }

    /// Index the credential (or family) `key` of kind `ix` to the one client it was minted for.
    async fn index(&self, ix: &str, key: &str, client_id: &str) -> Result<(), StorageError> {
        let id = digest(key);
        let row = IndexRow {
            client: client_id.to_string(),
            key: id.clone(),
            at: now_secs(),
        };
        let name = format!("ix.{ix}");
        for _ in 0..SWAP_ATTEMPTS {
            let raw = self.authority(&name, &id).await?;
            let candidate = Self::candidate(
                &atomic_schema(&name),
                &id,
                raw,
                live_body(&encode(&name, &row)?),
            );
            if self.submit(candidate).await? == Decision::Applied {
                return Ok(());
            }
        }
        Err(StorageError::new(
            "oauth_as store: index repeatedly conflicted",
        ))
    }

    /// The one client the index `ix` names for `key`.
    async fn client_of(&self, ix: &str, key: &str) -> Result<Option<String>, StorageError> {
        let Some(body) = self.get_body(&format!("ix.{ix}"), &digest(key)).await? else {
            return Ok(None);
        };
        decode::<IndexRow>(ix, &body).map(|row| Some(row.client))
    }

    /// What `pick` reads from the bucket of the client the index `ix` names for `key`.
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

    /// TAKE, in one swap of the bucket of the client the index `ix` names for `key`, the record
    /// `pick` removes: exactly one taker wins it.
    async fn take<R>(
        &self,
        ix: &str,
        key: &str,
        mut pick: impl FnMut(&mut Bucket) -> Option<R>,
    ) -> Result<Option<R>, StorageError> {
        let Some(client) = self.client_of(ix, key).await? else {
            return Ok(None);
        };
        self.update(&client, |b, _| {
            let taken = pick(b);
            Ok(Swap::when(taken.is_some(), taken))
        })
        .await
    }

    /// Index `subject` to `client_id`: a subject's one index cell names every client it consented
    /// to, each with when it was indexed. Written before the bucket, as every index is; an entry
    /// indexed within half the grace is left as it is, so a consent's every write is not a swap.
    async fn index_subject(&self, key: &str, client_id: &str) -> Result<(), StorageError> {
        let now = now_secs();
        self.cas_cell::<SubjectIndex, ()>(SUBJECT_INDEX, &digest(key), |ix, _| {
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

    /// Barrier and cascade are one candidate. A caller disappearing after the barrier's decision
    /// must not strand existing live credentials behind a partially completed revocation.
    async fn revoke_family(
        &self,
        family_id: &str,
        window: RevocationWindow,
    ) -> Result<u64, StorageError> {
        let id = digest(family_id);
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
            cell.at = now_secs();
            cell.id.clone_from(&id);
            cell.b.id.clone_from(&id);
            Times::merge(&mut cell.b.times, window);
            let mut request = Self::candidate(
                &atomic_schema("family"),
                &id,
                raw,
                live_body(&encode("family", &cell)?),
            );
            let request_body = Arc::make_mut(&mut request);
            // Comparing the index also covers an absent owner: a newly committed bucket installs
            // its family index in the same batch, so a concurrent first issuance forces a retry.
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
                        bucket.at = now_secs();
                        bucket.id.clone_from(&bucket_id);
                        request_body.mutations.push(Mutation::Put {
                            schema: atomic_schema("bucket"),
                            key: bucket_id.into_bytes(),
                            value: live_body(&encode("bucket", &bucket)?),
                        });
                        self.bucket_indexes(request_body, &bucket.b).await?;
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
        self.cas_cell::<Option<String>, ()>("uc", &digest(normalized), |held, _| {
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

    /// Record that the browser holding session `id` is `subject`, until `ttl` from now.
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

    /// The subject of a live session, or `None`.
    pub(crate) async fn session_subject(&self, id: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .get::<SessionRow>("session", &digest(id))
            .await?
            .filter(|row| row.until > now_secs())
            .map(|row| row.subject))
    }

    /// Stake one answer for `key` on session `id`. A second answer for the same request on the same
    /// session REPLACES one not yet spent, and is spent once on its own: each answer carries a nonce
    /// its spend claim names. The in-process table keeps answers the same way
    /// (`consent::Sessions::stake`).
    pub(crate) async fn stake(
        &self,
        id: &str,
        key: &str,
        approve: bool,
        ttl: Duration,
    ) -> Result<(), StorageError> {
        if self.session_subject(id).await?.is_none() {
            return Ok(());
        }
        let row_id = format!("{}:{}", digest(id), digest(key));
        let row = StakeRow {
            approve,
            until: now_secs() + ttl.as_secs(),
            id: row_id.clone(),
            nonce: nonce()?,
        };
        self.put("stake", &row_id, &row).await
    }

    async fn stake_row(&self, id: &str, key: &str) -> Result<Option<StakeRow>, StorageError> {
        Ok(self
            .get::<StakeRow>("stake", &format!("{}:{}", digest(id), digest(key)))
            .await?
            .filter(|row| row.until > now_secs()))
    }

    /// Whether an answer is staked for `key` on session `id`, without spending it.
    pub(crate) async fn is_staked(&self, id: &str, key: &str) -> Result<bool, StorageError> {
        Ok(self.stake_row(id, key).await?.is_some())
    }

    /// SPEND the answer staked for `key` on session `id`: `Some(approve)` for exactly one caller
    /// across every node, `None` for every other and when nothing is staked.
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

    /// The pushed request a `request_uri` names, while it is live.
    pub(crate) async fn pushed(
        &self,
        request_uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, StorageError> {
        let now = SystemTime::now();
        self.lookup("par", request_uri, |mut b| {
            b.pushed.remove(request_uri).filter(|p| p.expires_at > now)
        })
        .await
    }

    /// Mark a pushed request shown on the consent screen, answering whether it had been already.
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

    /// THE DEPLOYMENT'S AUTHORIZATION-SERVER SIGNING KEY (PKCS#8 DER): the one the store keeps, or
    /// `mint()`'s, kept by one atomic absent comparison. A loser takes the winner's key.
    /// Kept as THE DESIGN rules
    /// the deployment keyset is kept, sealed in the store: once for the deployment, in a record kind
    /// no plane can name ([`LABEL`]), read by every node on the store (see the module docs for who
    /// else reads it, and how an operator keeps the key out of the store).
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
        // Keep the candidate intact across unknown answers. A comparison loser reads the kept
        // key; current-row readback never substitutes for an unknown transaction decision.
        match self
            .submit(Self::candidate(
                &atomic_schema("key"),
                "signing",
                None,
                live_body(body.as_bytes()),
            ))
            .await
            .map_err(|e| e.0)?
        {
            Decision::Applied => Ok(der),
            Decision::ConditionConflict => read()
                .await?
                .ok_or_else(|| "the store did not keep the signing key".to_string()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SessionRow {
    subject: String,
    until: u64,
    /// The row's own id, so the sweep can delete it.
    #[serde(default)]
    id: String,
}

#[derive(Serialize, Deserialize)]
struct StakeRow {
    approve: bool,
    until: u64,
    /// The row's own id, so the sweep can delete it.
    #[serde(default)]
    id: String,
    /// This answer's own nonce: its spend claim names it, so each answer is spent once.
    #[serde(default)]
    nonce: String,
}

const LOST_ROW: &str = "oauth_as: a lapsed row was not reclaimed this tick";
const LOST_REPLAY: &str = "oauth_as: a lapsed replay row was not reclaimed this tick";

/// One claimed replay id, kept beside its claim so the sweep can count what it reclaims.
#[derive(Serialize, Deserialize)]
struct ReplayRow {
    id: String,
    until: u64,
}

/// The record kind a subject's index cell is kept under, by the subject's digest.
const SUBJECT_INDEX: &str = "ix.subj";

/// A SUBJECT'S INDEX: every client the subject consented to, by client id.
#[derive(Default, Serialize, Deserialize)]
struct SubjectIndex {
    #[serde(default)]
    clients: BTreeMap<String, Indexed>,
}

/// When a client was indexed under a subject (Unix seconds).
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct Indexed {
    at: u64,
}

/// One credential's index row: the client it was minted for, the credential's digest (the row's
/// id) and when the row was written.
#[derive(Serialize, Deserialize)]
struct IndexRow {
    client: String,
    key: String,
    at: u64,
}

fn bucket_holds(b: &Bucket, ix: &str, key: &str) -> bool {
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
struct FamilyBar {
    id: String,
    times: Option<Times>,
}

/// THE SERVER'S `Storage` OVER [`Shared`]: `MemoryStorage`'s rules, record for record, with the
/// mutex replaced by the per-client bucket swap.
pub(crate) struct SharedStorage {
    shared: Arc<Shared>,
}

/// One credential [`SharedStorage::put_guarded`] writes: its index, its family, and the grant the
/// barriers are judged against.
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

    /// Write a token or refresh token into its client's bucket (`insert`) unless a barrier stands;
    /// compare the family barrier atomically too. A barrier landing after the commit also triggers
    /// the existing immediate cleanup (`remove`) while its cascade proceeds.
    async fn put_guarded(
        &self,
        g: Guarded<'_>,
        insert: impl Fn(&mut Bucket),
        remove: impl Fn(&mut Bucket) -> bool,
    ) -> Result<WriteOutcome, StorageError> {
        let s = &self.shared;
        if let Some(f) = g.family {
            s.index("fam", f, g.client).await?;
        }
        s.index(g.ix, g.key, g.client).await?;
        let applied = s
            .update_guarded(g.client, g.family, |b, _| {
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
            s.update(g.client, |b, _| Ok(Swap::when(remove(b), ())))
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
        let id = client.client_id.as_str().to_string();
        self.shared
            .update(&id, |b, _| {
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
        let id = updated.client_id.as_str().to_string();
        self.shared
            .update(&id, |b, _| {
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
            .update(client_id.as_str(), |b, _| {
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
        let s = &self.shared;
        let normalized = normalize_user_code(&grant.user_code);
        s.hold_user_code(&normalized, &grant.device_code).await?;
        let client = grant.client_id.as_str().to_string();
        s.index("dev", &grant.device_code, &client).await?;
        s.update(&client, |b, _| {
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
        // `MemoryStorage`'s order: a state that moved on answers `false` before the index is asked.
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
            .update(&client, |b, _| {
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
        let client = record.client_id.as_str().to_string();
        self.shared.index("code", &record.code, &client).await?;
        self.shared
            .update(&client, |b, _| {
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
            .update(&client, |b, _| {
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
        let client = record.client_id.as_str().to_string();
        self.shared
            .index("par", &record.request_uri, &client)
            .await?;
        self.shared
            .update(&client, |b, _| {
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
        let s = &self.shared;
        let client = expected.client_id.as_str().to_string();
        if s.family_barred(Some(&expected.family_id)).await? {
            return Ok(false);
        }
        s.index("tok", &access.access_token, &client).await?;
        if let Some(f) = &access.family_id {
            s.index("fam", f, &client).await?;
        }
        if let Some(n) = next {
            s.index("rt", &n.refresh_token, &client).await?;
            s.index("fam", &n.family_id, &client).await?;
        }
        let rotated = s
            .update_guarded(&client, Some(&expected.family_id), |b, _| {
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
            // A family revocation landed between the check and the write: its cascade may have
            // listed the family before this write; take back what this rotation issued.
            s.update(&client, |b, _| {
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
        let s = &self.shared;
        let client = record.client_id.as_str().to_string();
        s.index("cons", &record.consent_id, &client).await?;
        s.index_subject(&record.subject, &client).await?;
        s.update(&client, |b, _| {
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
        let s = &self.shared;
        let client = updated.client_id.as_str().to_string();
        s.index("cons", &updated.consent_id, &client).await?;
        s.index_subject(&updated.subject, &client).await?;
        s.update(&client, |b, _| {
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
            .update(&client, |b, _| {
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
                let cid = consent.client_id.clone();
                let subject: String = consent.subject.to_string();
                let mut slot = b.consent_barriers.get(&subject).copied();
                Times::merge(&mut slot, window);
                if let Some(t) = slot {
                    b.consent_barriers.insert(subject.clone(), t);
                }
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
            // Kept beside the claim so the sweep can count what it reclaims.
            let row = ReplayRow {
                id: key.clone(),
                until: secs_of(expires_at),
            };
            s.put("replay", &key, &row).await?;
        }
        Ok(won)
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        let s = &self.shared;
        let mut removed = 0u64;
        let cells = s.list::<Cell<Bucket>>("bucket").await?;
        for mut cell in cells.into_iter().filter(|cell| !cell.b.id.is_empty()) {
            // Judged first on the body the listing already read: a client with nothing to reclaim
            // is not read again. Every node sweeps every client each minute, so a second read of
            // each would be a store read per client per node per minute, to change nothing.
            let acts = match sweep_bucket(&mut cell.b, cell.at, now) {
                Swap::Keep(_) => false,
                Swap::Write(_) => true,
                Swap::Retire(_, changed) => {
                    changed || now_secs().saturating_sub(cell.at) > RETIRE_AFTER_SECS
                }
            };
            if !acts {
                continue;
            }
            // One bucket that will not swap (a held version, a store fault) is skipped and said,
            // never the end of the sweep: the next tick tries it again.
            let swept = s
                .update(&cell.b.id, |b, at| Ok(sweep_bucket(b, at, now)))
                .await;
            match swept {
                Ok(n) => removed += n,
                Err(e) => {
                    tracing::warn!(error = %e, "oauth_as: a client's records were not swept this tick; the next tick tries them again");
                    continue;
                }
            }
        }
        // Each pass below stands alone: one that fails is said and the sweep goes on.
        match s.sweep_family_barriers(now).await {
            Ok(n) => removed += n,
            Err(e) => {
                tracing::warn!(error = %e, "oauth_as: lapsed family barriers were not swept this tick")
            }
        }
        let now_s = secs_of(now);
        let replays = s.sweep_rows::<ReplayRow>("replay", now_s, LOST_REPLAY, |r| (r.until, &r.id));
        match replays.await {
            Ok(n) => removed += n,
            Err(e) => {
                tracing::warn!(error = %e, "oauth_as: lapsed replay rows were not swept this tick")
            }
        }
        let reclaimed = [
            s.sweep_user_codes().await,
            s.sweep_indexes().await,
            s.sweep_subjects().await,
            s.sweep_rows::<SessionRow>("session", now_s, LOST_ROW, |r| (r.until, &r.id))
                .await
                .map(drop),
            s.sweep_rows::<StakeRow>("stake", now_s, LOST_ROW, |r| (r.until, &r.id))
                .await
                .map(drop),
        ];
        for r in reclaimed {
            if let Err(e) = r {
                tracing::warn!(error = %e, "oauth_as: lapsed store rows were not reclaimed this tick");
            }
        }
        Ok(removed)
    }
}

/// Reclaim what has lapsed by `now` in one client's records, whose current version was written at
/// `at`: the sweep's one change to a bucket, judged on the listed body and then made under the
/// version the swap reads. Its user-code releases commit in the same conditional transaction.
fn sweep_bucket(b: &mut Bucket, at: u64, now: SystemTime) -> Swap<u64> {
    fn lapse<V>(map: &mut BTreeMap<String, V>, mut live: impl FnMut(&V) -> bool) -> u64 {
        let before = map.len();
        map.retain(|_, v| live(v));
        (before - map.len()) as u64
    }
    let mut n = lapse(&mut b.devices, |g| now < g.expires_at);
    n += lapse(&mut b.codes, |c| now < c.expires_at);
    n += lapse(&mut b.pushed, |p| now < p.expires_at);
    n += lapse(&mut b.tokens, |t| now < t.expires_at);
    n += lapse(&mut b.refresh, |r| r.expires_at.is_none_or(|exp| now < exp));
    if b.client_barrier.is_some_and(|t| now >= t.until) {
        b.client_barrier = None;
        n += 1;
    }
    n += lapse(&mut b.consent_barriers, |t| now < t.until);
    // A SELF-REGISTERED client that has held nothing for the idle period goes: registration takes
    // no credential, and nothing else would ever reclaim it.
    if b.client.as_ref().is_some_and(|c| c.registration.is_some())
        && b.idle()
        && secs_of(now).saturating_sub(at) > crate::policy::REGISTERED_CLIENT_IDLE.as_secs()
    {
        b.client = None;
        n += 1;
    }
    if b.holds_nothing() {
        Swap::Retire(n, n > 0)
    } else {
        Swap::when(n != 0, n)
    }
}

impl Shared {
    /// Clear every lapsed family barrier: one swap each, counted as `MemoryStorage` counts it.
    async fn sweep_family_barriers(&self, now: SystemTime) -> Result<u64, StorageError> {
        let mut removed = 0u64;
        for cell in self.list::<Cell<FamilyBar>>("family").await? {
            if cell.b.id.is_empty() || cell.b.times.is_some_and(|t| now < t.until) {
                continue;
            }
            // A lapsed barrier is cleared, and a cleared one retired once it is old enough. One
            // that will not swap is said and left for the next tick.
            let swept = self.cas_cell::<FamilyBar, u64>("family", &cell.b.id, |bar, _| {
                Ok(match bar.times {
                    Some(t) if now >= t.until => {
                        bar.times = None;
                        Swap::Retire(1, true)
                    }
                    Some(_) => Swap::Keep(0),
                    None => Swap::Retire(0, false),
                })
            });
            match swept.await {
                Ok(n) => removed += n,
                Err(e) => {
                    tracing::warn!(error = %e, "oauth_as: a lapsed family barrier was not swept this tick");
                }
            }
        }
        Ok(removed)
    }

    /// Retire every released user-code cell old enough to go.
    async fn sweep_user_codes(&self) -> Result<(), StorageError> {
        for cell in self.list::<Cell<Option<String>>>("uc").await? {
            if cell.id.is_empty() || cell.b.is_some() {
                continue;
            }
            let retired = self.cas_cell::<Option<String>, ()>("uc", &cell.id, |held, _| {
                Ok(if held.is_none() {
                    Swap::Retire((), false)
                } else {
                    Swap::Keep(())
                })
            });
            if let Err(e) = retired.await {
                tracing::warn!(error = %e, "oauth_as: a released user code was not retired this tick");
            }
        }
        Ok(())
    }

    /// Retire unused credential indexes after [`INDEX_GRACE_SECS`], comparing both the exact index
    /// and bucket snapshots. A delayed bucket commit restores its required indexes atomically.
    async fn sweep_indexes(&self) -> Result<(), StorageError> {
        let mut buckets: BTreeMap<String, Option<Bucket>> = BTreeMap::new();
        let now_s = now_secs();
        for ix in ["tok", "rt", "code", "par", "dev", "cons", "fam"] {
            let name = format!("ix.{ix}");
            for row in self.list::<IndexRow>(&name).await? {
                if row.key.is_empty() || now_s.saturating_sub(row.at) <= INDEX_GRACE_SECS {
                    continue;
                }
                if !buckets.contains_key(&row.client) {
                    // A client whose records will not read is said and left: its rows are judged
                    // on a later tick, and every other client's rows are judged now.
                    let bucket = self.bucket(&row.client).await.inspect_err(|e| {
                        tracing::warn!(error = %e, "oauth_as: a client's index rows were not swept this tick");
                    });
                    buckets.insert(row.client.clone(), bucket.ok());
                }
                let Some(b) = &buckets[&row.client] else {
                    continue;
                };
                let held = bucket_holds(b, ix, &row.key);
                if !held {
                    let retired = async {
                        let raw = self.authority(&name, &row.key).await?;
                        let Some(body) = raw.as_deref().map(authority_body).transpose()?.flatten()
                        else {
                            return Ok::<_, StorageError>(());
                        };
                        let current: IndexRow = decode(&name, body)?;
                        // A bucket commit refreshed this index after the sweep listed it.
                        if current.at != row.at || current.client != row.client {
                            return Ok(());
                        }
                        let bucket_id = digest(&row.client);
                        let bucket = self.authority("bucket", &bucket_id).await?;
                        // Rejudge against the exact snapshot guarded by the deletion. The cached
                        // bucket is only an initial filter; a newer bucket must keep its index.
                        let current_bucket: Option<Cell<Bucket>> = bucket
                            .as_deref()
                            .map(authority_body)
                            .transpose()?
                            .flatten()
                            .map(|body| decode("bucket", body))
                            .transpose()?;
                        let held = current_bucket
                            .as_ref()
                            .is_some_and(|c| bucket_holds(&c.b, ix, &row.key));
                        if held {
                            return Ok(());
                        }
                        let mut request = Self::candidate(
                            &atomic_schema(&name),
                            &row.key,
                            raw,
                            format!("-{}", nonce()?).into_bytes(),
                        );
                        Arc::make_mut(&mut request).predicates.push(Predicate {
                            schema: atomic_schema("bucket"),
                            key: bucket_id.into_bytes(),
                            expected: bucket.map_or(Expected::Absent, Expected::Bytes),
                        });
                        self.submit(request).await.map(drop)
                    }
                    .await;
                    if let Err(e) = retired {
                        tracing::warn!(error = %e, "oauth_as: an index row was not reclaimed this tick");
                    }
                }
            }
        }
        Ok(())
    }

    /// Drop from every subject's index each client that no longer holds a consent of that subject,
    /// once its entry is older than [`INDEX_GRACE_SECS`]; bucket commits also refresh their subject
    /// entries atomically. A subject whose index names no client is retired. A client whose
    /// records will not read is kept, and one entry indexed again meanwhile is kept.
    async fn sweep_subjects(&self) -> Result<(), StorageError> {
        self.sweep_subjects_at(now_secs()).await
    }

    async fn sweep_subjects_at(&self, now_s: u64) -> Result<(), StorageError> {
        let mut buckets: BTreeMap<String, Option<Bucket>> = BTreeMap::new();
        for cell in self.list::<Cell<SubjectIndex>>(SUBJECT_INDEX).await? {
            if cell.id.is_empty() {
                continue;
            }
            let mut gone: BTreeMap<String, Indexed> = BTreeMap::new();
            for (client, indexed) in &cell.b.clients {
                if now_s.saturating_sub(indexed.at) <= INDEX_GRACE_SECS {
                    continue;
                }
                if !buckets.contains_key(client) {
                    let bucket = self.bucket(client).await.inspect_err(|e| {
                        tracing::warn!(error = %e, "oauth_as: a client's subject index entries were not swept this tick");
                    });
                    buckets.insert(client.clone(), bucket.ok());
                }
                let held = buckets[client]
                    .as_ref()
                    .is_none_or(|b| b.consents.values().any(|c| digest(&c.subject) == cell.id));
                if !held {
                    gone.insert(client.clone(), *indexed);
                }
            }
            if gone.is_empty() && !cell.b.clients.is_empty() {
                continue;
            }
            let swept = self.sweep_subject(&cell.id, &gone);
            if let Err(e) = swept.await {
                tracing::warn!(error = %e, "oauth_as: a subject's index was not swept this tick");
            }
        }
        Ok(())
    }

    async fn sweep_subject(
        &self,
        id: &str,
        gone: &BTreeMap<String, Indexed>,
    ) -> Result<(), StorageError> {
        for attempt in 0..SWAP_ATTEMPTS {
            let raw = self.authority(SUBJECT_INDEX, id).await?;
            let cell: Option<Cell<SubjectIndex>> = raw
                .as_deref()
                .map(authority_body)
                .transpose()?
                .flatten()
                .map(|body| decode(SUBJECT_INDEX, body))
                .transpose()?;
            let Some(mut cell) = cell else {
                return Ok(());
            };
            let mut guards = Vec::new();
            let mut changed = false;
            for (client, indexed) in gone {
                if cell.b.clients.get(client) != Some(indexed) {
                    continue;
                }
                let bucket_id = digest(client);
                let snapshot = match self.authority("bucket", &bucket_id).await {
                    Ok(raw) => raw,
                    Err(e) => {
                        tracing::warn!(error = %e, "oauth_as: a client's subject entry could not be rejudged");
                        continue;
                    }
                };
                let bucket: Option<Cell<Bucket>> = match snapshot
                    .as_deref()
                    .map(authority_body)
                    .transpose()?
                    .flatten()
                    .map(|body| decode("bucket", body))
                    .transpose()
                {
                    Ok(bucket) => bucket,
                    Err(e) => {
                        tracing::warn!(error = %e, "oauth_as: a client's subject entry could not be rejudged");
                        continue;
                    }
                };
                if bucket.is_some_and(|b| b.b.consents.values().any(|c| digest(&c.subject) == id)) {
                    continue;
                }
                cell.b.clients.remove(client);
                changed = true;
                guards.push(Predicate {
                    schema: atomic_schema("bucket"),
                    key: bucket_id.into_bytes(),
                    expected: snapshot.map_or(Expected::Absent, Expected::Bytes),
                });
            }
            let retired =
                cell.b.clients.is_empty() && now_secs().saturating_sub(cell.at) > RETIRE_AFTER_SECS;
            if !changed && !retired {
                return Ok(());
            }
            let value = if retired {
                format!("-{}", nonce()?).into_bytes()
            } else {
                cell.v = cell.v.checked_add(1).ok_or_else(|| {
                    StorageError::new("oauth_as store: subject index version exhausted")
                })?;
                cell.at = now_secs();
                cell.id = id.to_string();
                live_body(&encode(SUBJECT_INDEX, &cell)?)
            };
            let mut request = Self::candidate(&atomic_schema(SUBJECT_INDEX), id, raw, value);
            Arc::make_mut(&mut request).predicates.extend(guards);
            match self.submit(request).await? {
                Decision::Applied => return Ok(()),
                Decision::ConditionConflict => {
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(20)))).await
                }
            }
        }
        Err(StorageError::new(
            "oauth_as store: subject sweep repeatedly conflicted",
        ))
    }

    /// Delete every row of `kind_name` whose `until` (read by `of`, with the row's own id) has
    /// passed `now_s`, answering how many went.
    async fn sweep_rows<R: DeserializeOwned>(
        &self,
        kind_name: &str,
        now_s: u64,
        lost: &str,
        of: impl Fn(&R) -> (u64, &String),
    ) -> Result<u64, StorageError> {
        let mut removed = 0u64;
        for row in self.list::<R>(kind_name).await? {
            let (until, id) = of(&row);
            if until > now_s || id.is_empty() {
                continue;
            }
            match self.delete(kind_name, id).await {
                Ok(()) => removed += 1,
                Err(e) => tracing::warn!(error = %e, "{lost}"),
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
#[path = "tests/shared_tests.rs"]
mod shared_tests;

#[cfg(test)]
pub(crate) fn test_store_calls() -> Arc<dyn StoreCalls> {
    shared_tests::test_store_calls()
}
