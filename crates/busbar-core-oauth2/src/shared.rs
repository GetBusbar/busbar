// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE AUTHORIZATION SERVER HOLDS, KEPT IN THE DEPLOYMENT'S STORE, so every node behind one
//! store serves one server (THE DESIGN §1: "Multi-node is the design ... Nodes share one store").
//!
//! The server's records live as kernel-owned plane-record kinds under one fixed kernel label
//! ([`LABEL`]), written through the store's existing plane-record verbs and its one atomic step,
//! the single-use token redemption (`redeem_plane_token`). No store ABI is added (ARCHITECT ruling,
//! core-oauth2 #2, option A):
//!
//! * **One record per client, versioned.** Everything a client holds — its registration, the
//!   revocation barriers recorded against it, its codes, tokens, refresh tokens, pushed requests,
//!   device grants and consents — is one [`Bucket`]. A write is a COMPARE-AND-SWAP on the bucket's
//!   version: read version `v`, redeem the claim `(bucket, v + 1)`, and only the redeemer writes
//!   `v + 1`. Every other writer of that version loses the redemption and reads again. So the
//!   library's atomic steps (`take_*`, the compare-and-swaps, a client deletion and its cascade)
//!   are one bucket swap each, and hold across nodes exactly as `MemoryStorage`'s mutex holds them
//!   inside one process.
//! * **`take_*` = read + claim the spend.** A take is a swap that removes the record: exactly one
//!   taker wins the version, every other sees the record gone.
//! * **Deletion and revocation are tombstones.** A bucket is never deleted while it carries a
//!   barrier, and its version only grows, so a stale writer can never win a version that already
//!   exists.
//! * **Lookups by a credential** (an access token, a refresh token, a code, a pushed handle, a
//!   device code, a consent id, a family or a subject) go through write-once index records naming
//!   the client; the index is written before the bucket, so a record the bucket holds is always
//!   reachable.
//! * **The token-family barrier** is the one barrier that names no client: it is its own record,
//!   written before the family's cascade, and a token or refresh write checks it AFTER its own
//!   write and undoes itself when it finds one. Either the writer sees the barrier, or the
//!   cascade (which lists the family's index after recording the barrier) sees the record.
//!
//! What a crash between a won version claim and its write costs: that bucket refuses writes until
//! the claim lapses ([`VERSION_CLAIM_SECS`], two minutes); nothing is lost and nothing is
//! double-spent.
//!
//! Where each record sits: a point-read record (a bucket, a cell, a session, a stake, the key) at
//! sequence 0 with no parent, where every store reads `get_plane_record` back from; an index row as a
//! child of its key's digest, one sequence position per client, so a store that files a parented
//! record by `(parent, seq)` keeps one per client and lists them by parent.
//!
//! The consent screen's sessions and staked answers, the pushed-request notes and the minted
//! signing key ride the same records ([`Shared`]).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_contract::records::{PlaneDisposition, PlaneRecordRef, PlaneSelector};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};
use oauth_as::authorization::{AuthorizationCodeRecord, AuthorizationCodeState};
use oauth_as::client::{Client, ClientId};
use oauth_as::consent::ConsentRecord;
use oauth_as::device::{DeviceGrant, DeviceGrantState};
use oauth_as::par::PushedAuthorizationRequest;
use oauth_as::store::{RevocationWindow, Storage, StorageError, WriteOutcome};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};
use serde::{Deserialize, Serialize};

/// The fixed kernel label every record kind of the authorization server lives under. It begins
/// with a control character, which no admitted instance label or plane record kind holds, so no
/// plane can name or reach these records.
pub(crate) const LABEL: &str = "\u{1}oauth_as\u{1}";

/// How long a won version claim stands: past it, a bucket whose winner never wrote is writable
/// again.
pub(crate) const VERSION_CLAIM_SECS: u64 = 120;

/// How many times one write reads again after losing a version to another writer.
const SWAP_ATTEMPTS: u32 = 64;

/// The period a signing-key minting claim is for (the deployment keyset's discipline).
pub(crate) const MINT_CLAIM_SECS: u64 = 60;

/// How long a build that lost the minting claim waits for the winner's key before it refuses.
#[cfg(not(test))]
pub(crate) const MINT_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub(crate) const MINT_WAIT: Duration = Duration::from_millis(400);

/// The record kind `kind` of the authorization server.
fn kind(name: &str) -> String {
    format!("{LABEL}{name}")
}

/// A record id for `value`: its SHA-256, hex. Credentials never appear as store keys.
fn digest(value: &str) -> String {
    use std::fmt::Write as _;
    let d = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
    d.as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
    fn of(w: RevocationWindow) -> Self {
        Self {
            recorded_at: w.recorded_at,
            until: w.until,
        }
    }

    /// The later of each instant, as `MemoryStorage` merges a second barrier into a first.
    fn merge(slot: &mut Option<Times>, w: RevocationWindow) {
        match slot {
            Some(t) => {
                t.until = t.until.max(w.until);
                t.recorded_at = t.recorded_at.max(w.recorded_at);
            }
            None => *slot = Some(Self::of(w)),
        }
    }

    fn covers(&self, established: SystemTime) -> bool {
        established <= self.recorded_at
    }
}

/// EVERYTHING ONE CLIENT HOLDS, swapped whole.
#[derive(Default, Serialize, Deserialize)]
struct Bucket {
    /// The client this bucket is for, as written: what the sweep walks the buckets by.
    #[serde(default)]
    id: String,
    #[serde(default)]
    client: Option<Client>,
    #[serde(default)]
    client_barrier: Option<Times>,
    #[serde(default)]
    consent_barriers: BTreeMap<String, Times>,
    #[serde(default)]
    tokens: BTreeMap<String, IssuedToken>,
    #[serde(default)]
    refresh: BTreeMap<String, RefreshTokenRecord>,
    #[serde(default)]
    codes: BTreeMap<String, AuthorizationCodeRecord>,
    #[serde(default)]
    pushed: BTreeMap<String, PushedAuthorizationRequest>,
    #[serde(default)]
    devices: BTreeMap<String, DeviceGrant>,
    #[serde(default)]
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
}

/// The versioned envelope a bucket is kept in.
#[derive(Serialize, Deserialize)]
struct Cell<T> {
    v: u64,
    b: T,
}

/// The one write a swap made, or that it made none.
enum Swap<R> {
    /// Write the bucket and answer `R`.
    Write(R),
    /// Answer `R` without writing.
    Keep(R),
}

/// THE STORE THE AUTHORIZATION SERVER SHARES with every node on the deployment's store.
pub(crate) struct Shared {
    calls: Arc<dyn StoreCalls>,
}

impl Shared {
    pub(crate) fn new(calls: Arc<dyn StoreCalls>) -> Self {
        Self { calls }
    }

    async fn get_body(&self, kind_name: &str, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.calls
            .get_plane_record(&kind(kind_name), id)
            .await
            .map_err(|f| failed(kind_name, f))
    }

    async fn put_body(
        &self,
        kind_name: &str,
        id: &str,
        parent: Option<&str>,
        seq: u64,
        body: &[u8],
    ) -> Result<(), StorageError> {
        let k = kind(kind_name);
        self.calls
            .upsert_plane_record(PlaneRecordRef {
                kind: &k,
                id,
                parent,
                seq,
                ts: now_secs(),
                disposition: PlaneDisposition::Active,
                body,
            })
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
        let now = now_secs();
        self.calls
            .redeem_plane_token(&kind(kind_name), token, expires_at.max(now + 1), now)
            .await
            .map_err(|f| failed(kind_name, f))
    }

    async fn read_cell<T: for<'de> Deserialize<'de> + Default>(
        &self,
        kind_name: &str,
        id: &str,
    ) -> Result<(u64, T), StorageError> {
        match self.get_body(kind_name, id).await? {
            None => Ok((0, T::default())),
            Some(body) => serde_json::from_slice::<Cell<T>>(&body)
                .map(|c| (c.v, c.b))
                .map_err(|e| decode_failed(kind_name, e)),
        }
    }

    /// SWAP the cell `(kind_name, id)`: `f` reads the current value and says what to write; the
    /// write lands only under the version this call redeemed, and a lost version reads again.
    async fn swap<T, R>(
        &self,
        kind_name: &str,
        id: &str,
        mut f: impl FnMut(&mut T) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError>
    where
        T: Serialize + for<'de> Deserialize<'de> + Default,
    {
        for attempt in 0..SWAP_ATTEMPTS {
            let (v, mut value) = self.read_cell::<T>(kind_name, id).await?;
            let answer = match f(&mut value)? {
                Swap::Keep(r) => return Ok(r),
                Swap::Write(r) => r,
            };
            let next = v + 1;
            let token = format!("{id}@{next}");
            if self
                .claim(
                    &format!("{kind_name}.v"),
                    &token,
                    now_secs() + VERSION_CLAIM_SECS,
                )
                .await?
            {
                let body = serde_json::to_vec(&Cell { v: next, b: &value })
                    .map_err(|e| decode_failed(kind_name, e))?;
                // Point-read records live at sequence 0 with no parent: that is where every store
                // reads `get_plane_record` back from. The version rides in the cell itself.
                self.put_body(kind_name, id, None, 0, &body).await?;
                return Ok(answer);
            }
            // Another writer holds this version: read again, after a short, growing pause.
            tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(20)))).await;
        }
        Err(StorageError::new(format!(
            "oauth_as store: {kind_name}: no version won in {SWAP_ATTEMPTS} attempts"
        )))
    }

    // ── the per-client bucket ─────────────────────────────────────────────────────────────

    async fn bucket(&self, client_id: &str) -> Result<Bucket, StorageError> {
        Ok(self
            .read_cell::<Bucket>("bucket", &digest(client_id))
            .await?
            .1)
    }

    async fn update<R>(
        &self,
        client_id: &str,
        mut f: impl FnMut(&mut Bucket) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError> {
        self.swap("bucket", &digest(client_id), |b: &mut Bucket| {
            b.id = client_id.to_string();
            f(b)
        })
        .await
    }

    // ── the write-once indexes: a credential (or family, subject) to the client holding it ──

    async fn index(&self, ix: &str, key: &str, client_id: &str) -> Result<(), StorageError> {
        let parent = digest(key);
        let client = digest(client_id);
        let id = format!("{parent}:{client}");
        // A child of the key's parent, one position per client: a store files a parented record by
        // `(parent, seq)`, so each client the key names needs its own sequence number.
        let seq = u64::from_str_radix(&client[..15], 16).unwrap_or(0) + 1;
        self.put_body(
            &format!("ix.{ix}"),
            &id,
            Some(&parent),
            seq,
            client_id.as_bytes(),
        )
        .await
    }

    /// Every client the index `ix` names for `key`.
    async fn clients_of(&self, ix: &str, key: &str) -> Result<Vec<String>, StorageError> {
        let parent = digest(key);
        let selector = PlaneSelector::Parent(std::borrow::Cow::Borrowed(parent.as_str()));
        let k = kind(&format!("ix.{ix}"));
        let rows = self
            .calls
            .list_plane_records(&k, &selector)
            .await
            .map_err(|f| failed(ix, f))?;
        let mut out: Vec<String> = rows
            .into_iter()
            .filter_map(|b| String::from_utf8(b).ok())
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// The one client a credential's index names (a credential is minted for one client).
    async fn client_of(&self, ix: &str, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self.clients_of(ix, key).await?.into_iter().next())
    }

    // ── the token-family barrier ──────────────────────────────────────────────────────────

    async fn family_barred(&self, family_id: Option<&str>) -> Result<bool, StorageError> {
        let Some(family) = family_id else {
            return Ok(false);
        };
        let (_, bar) = self
            .read_cell::<FamilyBar>("family", &digest(family))
            .await?;
        Ok(bar.times.is_some())
    }

    // ── the device user-code index (global: one live grant per user code) ───────────────────

    async fn hold_user_code(
        &self,
        normalized: &str,
        device_code: &str,
    ) -> Result<(), StorageError> {
        self.swap::<Option<String>, ()>("uc", &digest(normalized), |held| {
            let owner = held.clone();
            match owner.as_deref() {
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

    async fn release_user_code(
        &self,
        normalized: &str,
        device_code: &str,
    ) -> Result<(), StorageError> {
        self.swap::<Option<String>, ()>("uc", &digest(normalized), |held| {
            if held.as_deref() == Some(device_code) {
                *held = None;
                Ok(Swap::Write(()))
            } else {
                Ok(Swap::Keep(()))
            }
        })
        .await
    }

    async fn user_code_owner(&self, normalized: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .read_cell::<Option<String>>("uc", &digest(normalized))
            .await?
            .1)
    }

    // ── the consent screen's records ─────────────────────────────────────────────────────

    /// Record that the browser holding session `id` is `subject`, until `ttl` from now.
    pub(crate) async fn open_session(
        &self,
        id: &str,
        subject: &str,
        ttl: Duration,
    ) -> Result<(), StorageError> {
        let body = serde_json::to_vec(&SessionRow {
            subject: subject.to_string(),
            until: now_secs() + ttl.as_secs(),
        })
        .map_err(|e| decode_failed("session", e))?;
        self.put_body("session", &digest(id), None, 0, &body).await
    }

    /// The subject of a live session, or `None`.
    pub(crate) async fn session_subject(&self, id: &str) -> Result<Option<String>, StorageError> {
        let Some(body) = self.get_body("session", &digest(id)).await? else {
            return Ok(None);
        };
        let row: SessionRow =
            serde_json::from_slice(&body).map_err(|e| decode_failed("session", e))?;
        Ok((row.until > now_secs()).then_some(row.subject))
    }

    /// Stake one answer for `key` on session `id`.
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
        let body = serde_json::to_vec(&StakeRow {
            approve,
            until: now_secs() + ttl.as_secs(),
        })
        .map_err(|e| decode_failed("stake", e))?;
        self.put_body(
            "stake",
            &format!("{}:{}", digest(id), digest(key)),
            None,
            0,
            &body,
        )
        .await
    }

    async fn stake_row(&self, id: &str, key: &str) -> Result<Option<StakeRow>, StorageError> {
        let Some(body) = self
            .get_body("stake", &format!("{}:{}", digest(id), digest(key)))
            .await?
        else {
            return Ok(None);
        };
        let row: StakeRow = serde_json::from_slice(&body).map_err(|e| decode_failed("stake", e))?;
        Ok((row.until > now_secs()).then_some(row))
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
        let token = format!("{}:{}", digest(id), digest(key));
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
        let Some(client) = self.client_of("par", request_uri).await? else {
            return Ok(None);
        };
        let now = SystemTime::now();
        Ok(self
            .bucket(&client)
            .await?
            .pushed
            .remove(request_uri)
            .filter(|p| p.expires_at > now))
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

    // ── the signing key, minted once per deployment ───────────────────────────────────────

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
    /// `mint()`'s, kept now by the build that wins this period's minting claim. A build that lost
    /// the claim takes the winner's and never signs with a key of its own. Kept as the deployment
    /// keyset is kept: unsealed, in the store's own records.
    pub(crate) async fn signing_key(
        &self,
        mint: impl FnOnce() -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, String> {
        let read = || async { self.stored_key().await.map_err(|e| e.0) };
        if let Some(held) = read().await? {
            return Ok(held);
        }
        // ONE minting claim, standing for one period: two builds can never both hold it, and a
        // winner that died before keeping its key frees it when the period ends.
        let won = self
            .claim("mint", "signing", now_secs() + MINT_CLAIM_SECS)
            .await
            .map_err(|e| e.0)?;
        if !won {
            let deadline = std::time::Instant::now() + MINT_WAIT;
            loop {
                if let Some(held) = read().await? {
                    return Ok(held);
                }
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "another node holds the store's claim to mint the authorization server's \
                         signing key and has not kept it; refusing rather than signing with a \
                         second key (the claim is free again within {MINT_CLAIM_SECS} s)"
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        // A build that won after a slow earlier winner's claim lapsed finds that one's key.
        if let Some(held) = read().await? {
            return Ok(held);
        }
        let der = mint()?;
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(&der);
        self.put_body("key", "signing", None, 0, body.as_bytes())
            .await
            .map_err(|e| e.0)?;
        read()
            .await?
            .ok_or_else(|| "the store did not keep the signing key".to_string())
    }
}

#[derive(Serialize, Deserialize)]
struct SessionRow {
    subject: String,
    until: u64,
}

#[derive(Serialize, Deserialize)]
struct StakeRow {
    approve: bool,
    until: u64,
}

/// THE SERVER'S `Storage` OVER [`Shared`]: `MemoryStorage`'s rules, record for record, with the
/// mutex replaced by the per-client bucket swap.
pub(crate) struct SharedStorage {
    shared: Arc<Shared>,
}

impl SharedStorage {
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    /// Write `token` into its client's bucket unless a barrier stands; then the family barrier,
    /// read after the write, undoes it.
    async fn put_issued(&self, token: IssuedToken) -> Result<WriteOutcome, StorageError> {
        let s = &self.shared;
        let client = token.client_id.as_str().to_string();
        let access = token.access_token.clone();
        let family = token.family_id.clone();
        if let Some(f) = &family {
            s.index("fam", f, &client).await?;
        }
        s.index("tok", &access, &client).await?;
        let applied = s
            .update(&client, |b| {
                if b.barred(token.subject.as_deref(), token.grant_established_at) {
                    return Ok(Swap::Keep(false));
                }
                b.tokens.insert(token.access_token.clone(), token.clone());
                Ok(Swap::Write(true))
            })
            .await?;
        if !applied {
            return Ok(WriteOutcome::RefusedRevoked);
        }
        if s.family_barred(family.as_deref()).await? {
            s.update(&client, |b| {
                Ok(match b.tokens.remove(&access) {
                    Some(_) => Swap::Write(()),
                    None => Swap::Keep(()),
                })
            })
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
            .update(&id, |b| {
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
            .update(&id, |b| {
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
        let mut freed: Vec<(String, String)> = Vec::new();
        let existed = self
            .shared
            .update(client_id.as_str(), |b| {
                let existed = b.client.take().is_some();
                Times::merge(&mut b.client_barrier, window);
                freed = b
                    .devices
                    .values()
                    .map(|d| {
                        (
                            oauth_as::device::normalize_user_code(&d.user_code),
                            d.device_code.clone(),
                        )
                    })
                    .collect();
                b.tokens.clear();
                b.refresh.clear();
                b.codes.clear();
                b.pushed.clear();
                b.devices.clear();
                b.consents.clear();
                Ok(Swap::Write(existed))
            })
            .await?;
        for (uc, dc) in freed {
            self.shared.release_user_code(&uc, &dc).await?;
        }
        Ok(existed)
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let s = &self.shared;
        let normalized = oauth_as::device::normalize_user_code(&grant.user_code);
        s.hold_user_code(&normalized, &grant.device_code).await?;
        let client = grant.client_id.as_str().to_string();
        s.index("dev", &grant.device_code, &client).await?;
        let mut previous = None;
        s.update(&client, |b| {
            previous = b
                .devices
                .insert(grant.device_code.clone(), grant.clone())
                .map(|p| oauth_as::device::normalize_user_code(&p.user_code));
            Ok(Swap::Write(()))
        })
        .await?;
        if let Some(old) = previous.filter(|old| *old != normalized) {
            s.release_user_code(&old, &grant.device_code).await?;
        }
        Ok(())
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let Some(client) = self.shared.client_of("dev", device_code).await? else {
            return Ok(None);
        };
        Ok(self
            .shared
            .bucket(&client)
            .await?
            .devices
            .remove(device_code))
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
        let Some(client) = self.shared.client_of("dev", device_code).await? else {
            return Ok(None);
        };
        let taken = self
            .shared
            .update(&client, |b| {
                Ok(match b.devices.remove(device_code) {
                    Some(g) => Swap::Write(Some(g)),
                    None => Swap::Keep(None),
                })
            })
            .await?;
        if let Some(g) = &taken {
            self.shared
                .release_user_code(
                    &oauth_as::device::normalize_user_code(&g.user_code),
                    device_code,
                )
                .await?;
        }
        Ok(taken)
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
        // `MemoryStorage`'s order: a state that moved on answers `false` before the index is asked.
        match s.bucket(&client).await?.devices.get(&updated.device_code) {
            Some(current) if current.state == *expected => {}
            _ => return Ok(false),
        }
        let normalized = oauth_as::device::normalize_user_code(&updated.user_code);
        if let Some(owner) = s.user_code_owner(&normalized).await? {
            if owner != updated.device_code {
                return Err(StorageError::new(
                    "user code is already indexed for a different device_code",
                ));
            }
        }
        let mut previous = None;
        let swapped = s
            .update(&client, |b| {
                match b.devices.get(&updated.device_code) {
                    Some(current) if current.state == *expected => {}
                    _ => return Ok(Swap::Keep(false)),
                }
                previous = b
                    .devices
                    .insert(updated.device_code.clone(), updated.clone())
                    .map(|p| oauth_as::device::normalize_user_code(&p.user_code));
                Ok(Swap::Write(true))
            })
            .await?;
        if swapped {
            s.hold_user_code(&normalized, &updated.device_code).await?;
            if let Some(old) = previous.filter(|old| *old != normalized) {
                s.release_user_code(&old, &updated.device_code).await?;
            }
        }
        Ok(swapped)
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        let client = record.client_id.as_str().to_string();
        self.shared.index("code", &record.code, &client).await?;
        self.shared
            .update(&client, |b| {
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
            .update(&client, |b| {
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
        let Some(client) = self.shared.client_of("code", code).await? else {
            return Ok(None);
        };
        self.shared
            .update(&client, |b| {
                Ok(match b.codes.remove(code) {
                    Some(c) => Swap::Write(Some(c)),
                    None => Swap::Keep(None),
                })
            })
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
            .update(&client, |b| {
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
        let Some(client) = self.shared.client_of("par", request_uri).await? else {
            return Ok(None);
        };
        self.shared
            .update(&client, |b| {
                Ok(match b.pushed.remove(request_uri) {
                    Some(p) => Swap::Write(Some(p)),
                    None => Swap::Keep(None),
                })
            })
            .await
    }

    async fn put_token(&self, token: IssuedToken) -> Result<WriteOutcome, StorageError> {
        self.put_issued(token).await
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Arc<IssuedToken>>, StorageError> {
        let Some(client) = self.shared.client_of("tok", access_token).await? else {
            return Ok(None);
        };
        Ok(self
            .shared
            .bucket(&client)
            .await?
            .tokens
            .remove(access_token)
            .map(Arc::new))
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        let Some(client) = self.shared.client_of("tok", access_token).await? else {
            return Ok(());
        };
        self.shared
            .update(&client, |b| {
                Ok(match b.tokens.remove(access_token) {
                    Some(_) => Swap::Write(()),
                    None => Swap::Keep(()),
                })
            })
            .await
    }

    async fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> Result<WriteOutcome, StorageError> {
        let s = &self.shared;
        let client = record.client_id.as_str().to_string();
        let rt = record.refresh_token.clone();
        let family = record.family_id.clone();
        s.index("fam", &family, &client).await?;
        s.index("rt", &rt, &client).await?;
        let applied = s
            .update(&client, |b| {
                if b.barred(record.subject.as_deref(), record.grant_established_at) {
                    return Ok(Swap::Keep(false));
                }
                b.refresh
                    .insert(record.refresh_token.clone(), record.clone());
                Ok(Swap::Write(true))
            })
            .await?;
        if !applied {
            return Ok(WriteOutcome::RefusedRevoked);
        }
        if s.family_barred(Some(&family)).await? {
            s.update(&client, |b| {
                Ok(match b.refresh.remove(&rt) {
                    Some(_) => Swap::Write(()),
                    None => Swap::Keep(()),
                })
            })
            .await?;
            return Ok(WriteOutcome::RefusedRevoked);
        }
        Ok(WriteOutcome::Applied)
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Arc<RefreshTokenRecord>>, StorageError> {
        let Some(client) = self.shared.client_of("rt", refresh_token).await? else {
            return Ok(None);
        };
        Ok(self
            .shared
            .bucket(&client)
            .await?
            .refresh
            .remove(refresh_token)
            .map(Arc::new))
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
            .update(&client, |b| {
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
            .await?;
        if rotated && s.family_barred(Some(&expected.family_id)).await? {
            // A family revocation landed between the check and the write: its cascade may have
            // listed the family before this write; take back what this rotation issued.
            s.update(&client, |b| {
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
        let Some(client) = self.shared.client_of("rt", refresh_token).await? else {
            return Ok(None);
        };
        self.shared
            .update(&client, |b| {
                Ok(match b.refresh.remove(refresh_token) {
                    Some(r) => Swap::Write(Some(r)),
                    None => Swap::Keep(None),
                })
            })
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
        let s = &self.shared;
        // The barrier first, then the cascade over every client the family's index names.
        let id = digest(family_id);
        s.swap::<FamilyBar, ()>("family", &id, |bar| {
            bar.id.clone_from(&id);
            Times::merge(&mut bar.times, window);
            Ok(Swap::Write(()))
        })
        .await?;
        let mut removed = 0u64;
        for client in s.clients_of("fam", family_id).await? {
            removed += s
                .update(&client, |b| {
                    let before = b.tokens.len() + b.refresh.len();
                    b.tokens
                        .retain(|_, t| t.family_id.as_deref() != Some(family_id));
                    b.refresh.retain(|_, r| r.family_id != family_id);
                    let gone = (before - (b.tokens.len() + b.refresh.len())) as u64;
                    Ok(if gone == 0 {
                        Swap::Keep(0)
                    } else {
                        Swap::Write(gone)
                    })
                })
                .await?;
        }
        Ok(removed)
    }

    async fn put_consent(&self, record: ConsentRecord) -> Result<(), StorageError> {
        let s = &self.shared;
        let client = record.client_id.as_str().to_string();
        s.index("cons", &record.consent_id, &client).await?;
        s.index("subj", &record.subject, &client).await?;
        s.update(&client, |b| {
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
        s.index("subj", &updated.subject, &client).await?;
        s.update(&client, |b| {
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
        let Some(client) = self.shared.client_of("cons", consent_id).await? else {
            return Ok(None);
        };
        Ok(self
            .shared
            .bucket(&client)
            .await?
            .consents
            .remove(consent_id)
            .map(Arc::new))
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
        let mut out = Vec::new();
        for client in self.shared.clients_of("subj", subject).await? {
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
        let mut freed: Vec<(String, String)> = Vec::new();
        let removed = self
            .shared
            .update(&client, |b| {
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
                b.tokens
                    .retain(|_, t| !(t.client_id == cid && t.subject.as_deref() == Some(subject.as_str())));
                b.refresh
                    .retain(|_, r| !(r.client_id == cid && r.subject.as_deref() == Some(subject.as_str())));
                b.codes
                    .retain(|_, c| !(c.client_id == cid && c.subject == subject));
                freed = Vec::new();
                b.devices.retain(|_, d| {
                    let gone = d.client_id == cid
                        && matches!(&d.state, DeviceGrantState::Approved { subject: s } if *s == subject);
                    if gone {
                        freed.push((
                            oauth_as::device::normalize_user_code(&d.user_code),
                            d.device_code.clone(),
                        ));
                    }
                    !gone
                });
                Ok(Swap::Write((before - b.records()) as u64))
            })
            .await?;
        for (uc, dc) in freed {
            self.shared.release_user_code(&uc, &dc).await?;
        }
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
            let row = serde_json::to_vec(&ReplayRow {
                id: key.clone(),
                until: secs_of(expires_at),
            })
            .map_err(|e| decode_failed("replay", e))?;
            s.put_body("replay", &key, None, 0, &row).await?;
        }
        Ok(won)
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        let s = &self.shared;
        let mut removed = 0u64;
        let k = kind("bucket");
        let rows = s
            .calls
            .list_plane_records(&k, &PlaneSelector::All)
            .await
            .map_err(|f| failed("bucket", f))?;
        let clients: Vec<String> = rows
            .iter()
            .filter_map(|body| serde_json::from_slice::<Cell<Bucket>>(body).ok())
            .map(|cell| cell.b.id)
            .filter(|id| !id.is_empty())
            .collect();
        for client in clients {
            let mut freed: Vec<(String, String)> = Vec::new();
            // One bucket that will not swap (a held version, a store fault) is skipped and said,
            // never the end of the sweep: the next tick tries it again.
            let swept = s
                .update(&client, |b| {
                    let mut n = 0u64;
                    freed = Vec::new();
                    b.devices.retain(|_, g| {
                        let keep = now < g.expires_at;
                        if !keep {
                            freed.push((
                                oauth_as::device::normalize_user_code(&g.user_code),
                                g.device_code.clone(),
                            ));
                        }
                        keep
                    });
                    n += freed.len() as u64;
                    let before = b.codes.len();
                    b.codes.retain(|_, c| now < c.expires_at);
                    n += (before - b.codes.len()) as u64;
                    let before = b.pushed.len();
                    b.pushed.retain(|_, p| now < p.expires_at);
                    n += (before - b.pushed.len()) as u64;
                    let before = b.tokens.len();
                    b.tokens.retain(|_, t| now < t.expires_at);
                    n += (before - b.tokens.len()) as u64;
                    let before = b.refresh.len();
                    b.refresh
                        .retain(|_, r| r.expires_at.is_none_or(|exp| now < exp));
                    n += (before - b.refresh.len()) as u64;
                    if b.client_barrier.is_some_and(|t| now >= t.until) {
                        b.client_barrier = None;
                        n += 1;
                    }
                    let before = b.consent_barriers.len();
                    b.consent_barriers.retain(|_, t| now < t.until);
                    n += (before - b.consent_barriers.len()) as u64;
                    Ok(if n == 0 {
                        Swap::Keep(0)
                    } else {
                        Swap::Write(n)
                    })
                })
                .await;
            match swept {
                Ok(n) => removed += n,
                Err(e) => {
                    tracing::debug!(error = %e, "oauth_as: a client's records were not swept this tick");
                    continue;
                }
            }
            for (uc, dc) in freed {
                s.release_user_code(&uc, &dc).await?;
            }
        }
        removed += s.sweep_family_barriers(now).await?;
        removed += s.sweep_replays(secs_of(now)).await?;
        Ok(removed)
    }
}

impl Shared {
    /// Clear every lapsed family barrier: one swap each, counted as `MemoryStorage` counts it.
    async fn sweep_family_barriers(&self, now: SystemTime) -> Result<u64, StorageError> {
        let rows = self
            .calls
            .list_plane_records(&kind("family"), &PlaneSelector::All)
            .await
            .map_err(|f| failed("family", f))?;
        let mut removed = 0u64;
        for body in rows {
            let Ok(cell) = serde_json::from_slice::<Cell<FamilyBar>>(&body) else {
                continue;
            };
            if cell.b.id.is_empty() || !cell.b.times.is_some_and(|t| now >= t.until) {
                continue;
            }
            removed += self
                .swap::<FamilyBar, u64>("family", &cell.b.id.clone(), |bar| {
                    Ok(match bar.times {
                        Some(t) if now >= t.until => {
                            bar.times = None;
                            Swap::Write(1)
                        }
                        _ => Swap::Keep(0),
                    })
                })
                .await?;
        }
        Ok(removed)
    }

    /// Count and delete the replay rows whose claim has lapsed (the claim itself lapses with the
    /// store's own expiry).
    async fn sweep_replays(&self, now_s: u64) -> Result<u64, StorageError> {
        let k = kind("replay");
        let rows = self
            .calls
            .list_plane_records(&k, &PlaneSelector::All)
            .await
            .map_err(|f| failed("replay", f))?;
        let mut removed = 0u64;
        for body in rows {
            let Ok(row) = serde_json::from_slice::<ReplayRow>(&body) else {
                continue;
            };
            if row.until <= now_s {
                self.calls
                    .delete_plane_record(&k, &row.id)
                    .await
                    .map_err(|f| failed("replay", f))?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// A token family's barrier, named by its family's digest so the sweep can find it again.
#[derive(Default, Serialize, Deserialize)]
struct FamilyBar {
    #[serde(default)]
    id: String,
    #[serde(default)]
    times: Option<Times>,
}

/// One claimed replay id, kept beside its claim so the sweep can count what it reclaims.
#[derive(Serialize, Deserialize)]
struct ReplayRow {
    id: String,
    until: u64,
}

#[cfg(test)]
#[path = "tests/shared_tests.rs"]
mod shared_tests;
