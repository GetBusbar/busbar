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
//! * **The claim is a lease, and the write is fenced by it.** A version claim lapses
//!   ([`VERSION_CLAIM_SECS`]) so that a writer that died never blocks its bucket for good. So a
//!   writer issues its write only while [`WRITE_BUDGET`] has not passed since the READ its write is
//!   computed from, and otherwise writes nothing and answers an error. A store call is cancelled at
//!   its deadline (THE DESIGN Appendix A.4, the `call` class), so every write lands within
//!   [`STORE_CALL_SECS`] of being issued; with clocks within [`CLOCK_SKEW_SECS`] of each other, a
//!   write lands before any other node can see its claim lapse, and a writer that read a version
//!   cannot claim the next one after an earlier claimant of it could still write. That is the
//!   fence's whole assumption: the store honours its call deadline, and nodes' clocks agree within
//!   the skew.
//! * **A version is claimed once, for good.** The claim on version `v + 1` names the cell's EPOCH
//!   ([`version_token`]): a random value the writer that CREATES a cell (the write of version 1)
//!   picks, and every version after carries on. A retired cell's epoch dies with it, so its claims,
//!   the retirement's own on the version after its last included, can never stand in the way of the
//!   cell made again under the same id. The creating write's claim names no epoch (no writer knows
//!   one yet, and every creator must race on one token); it is free whenever a cell is absent,
//!   because a cell is retired only once its last write, and so its own creation, is older than any
//!   claim can stand.
//! * **`take_*` = read + claim the spend.** A take is a swap that removes the record: exactly one
//!   taker wins the version, every other sees the record gone.
//! * **Deletion and revocation are tombstones while they bar anything.** A bucket keeps its
//!   barriers until they lapse. A cell holding nothing (an empty bucket, a lapsed family barrier, a
//!   released user code) is RETIRED by the sweep: deleted under a won version claim, and only once
//!   its last write is older than every claim of its versions can be ([`RETIRE_AFTER_SECS`]). A
//!   writer that finds it gone creates it again, under a new epoch.
//! * **A self-registered client that holds nothing is reclaimed.** RFC 7591 registration takes no
//!   credential, so a registered client whose bucket has held no record (code, token, refresh
//!   token, pushed request, device grant, consent) for [`crate::policy::REGISTERED_CLIENT_IDLE`] is
//!   deleted by the sweep and its bucket retired. A client the operator provisioned is never in the
//!   store, and is never reclaimed.
//! * **Lookups by a credential** (an access token, a refresh token, a code, a pushed handle, a
//!   device code, a consent id or a family) go through index records naming the client, one per
//!   credential; the index is written before the bucket, so a record the bucket holds is always
//!   reachable. The sweep deletes an index row whose credential its client no longer holds, once
//!   the row is older than any write in flight can be ([`INDEX_GRACE_SECS`]). A subject's index
//!   (one row per client it consented to) is kept.
//! * **The token-family barrier** is the one barrier that names no client: it is its own record,
//!   written before the family's cascade, and a token or refresh write checks it AFTER its own
//!   write and undoes itself when it finds one. Either the writer sees the barrier, or the
//!   cascade (which lists the family's index after recording the barrier) sees the record.
//!
//! What a crash between a won version claim and its write costs: that bucket refuses writes until
//! the claim lapses ([`VERSION_CLAIM_SECS`], two minutes); nothing is lost, and the fence above
//! keeps a late writer from double-spending.
//!
//! Where each record sits: a point-read record (a bucket, a cell, a session, a stake, the key, a
//! credential's index row) at sequence 0 with no parent, where every store reads `get_plane_record`
//! back from; a subject's index row as a child of the subject's digest, one sequence position per
//! client, so a store that files a parented record by `(parent, seq)` keeps one per client and
//! lists them by parent. The sweep deletes lapsed sessions and staked answers.
//!
//! The consent screen's sessions and staked answers, the pushed-request notes and the minted
//! signing key ride the same records ([`Shared`]).
//!
//! THE MINTED SIGNING KEY is kept as THE DESIGN rules the deployment keyset is kept: "sealed in the
//! store", which is to say minted once for the deployment, under the store's minting claim, and
//! kept in the store for every node to read back (the keyset itself is kept the same way, as its
//! seed, in the store's record slots). Whoever reads the store reads it, as they read the
//! deployment keyset and every live token the buckets hold. An operator who wants the key outside
//! the store's reach configures `oauth_as.signing_key`, a secret reference, and nothing is minted;
//! the build says so at `warn` when it signs with the kept key.

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

/// The longest a store call runs before the host cancels it (THE DESIGN Appendix A.4: a `call`
/// class op is cancelled at its deadline; the store loader's deadline is 30 s).
pub(crate) const STORE_CALL_SECS: u64 = 30;

/// How far apart two nodes' clocks may be: a claim's lapse is judged by the clock of the node that
/// asks.
pub(crate) const CLOCK_SKEW_SECS: u64 = 30;

/// How long after the READ a write is computed from it may still be issued under the claim it won.
/// A write issued later is not issued at all. Twice this, plus a store call and the skew, stays
/// inside a version claim, so no write lands under a claim another node can see as lapsed, and no
/// writer claims a version after its earlier claimant could still write it.
pub(crate) const WRITE_BUDGET: Duration = Duration::from_secs(20);

const _: () = assert!(
    2 * WRITE_BUDGET.as_secs() + STORE_CALL_SECS + CLOCK_SKEW_SECS < VERSION_CLAIM_SECS
        && WRITE_BUDGET.as_secs() + STORE_CALL_SECS + CLOCK_SKEW_SECS < MINT_CLAIM_SECS
);

/// How old a cell's last write must be before the sweep retires it: past every claim on its
/// versions, on any node's clock.
pub(crate) const RETIRE_AFTER_SECS: u64 = VERSION_CLAIM_SECS + CLOCK_SKEW_SECS;

/// How old an index row must be before the sweep may delete it for a credential its client does
/// not hold: past any write in flight (the index is written before its bucket).
pub(crate) const INDEX_GRACE_SECS: u64 = 600;

/// How many times one write reads again after losing a version to another writer.
const SWAP_ATTEMPTS: u32 = 64;

/// The period a signing-key minting claim is for (the deployment keyset's discipline).
pub(crate) const MINT_CLAIM_SECS: u64 = 120;

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

/// The claim on version `next` of the cell `id` whose epoch is `epoch`. The creating write
/// (`next == 1`) and a cell written before epochs were kept (`epoch` empty) claim `{id}@{next}`;
/// every other version names its epoch, so no claim of a retired cell names a version of the cell
/// made again in its place.
fn version_token(id: &str, epoch: &str, next: u64) -> String {
    if next == 1 || epoch.is_empty() {
        format!("{id}@{next}")
    } else {
        format!("{id}@{epoch}.{next}")
    }
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

/// The fence: a write computed from a read at `read_at` may be issued only within [`WRITE_BUDGET`].
fn within_budget(what: &str, read_at: tokio::time::Instant) -> Result<(), StorageError> {
    if read_at.elapsed() > WRITE_BUDGET {
        return Err(StorageError::new(format!(
            "oauth_as store: {what}: the claim was won {} s after the read it rests on, past the \
             {} s a write may follow it; nothing was written",
            read_at.elapsed().as_secs(),
            WRITE_BUDGET.as_secs()
        )));
    }
    Ok(())
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

    /// Whether this bucket holds nothing at all: no client, no barrier and no record.
    fn holds_nothing(&self) -> bool {
        self.client.is_none()
            && self.client_barrier.is_none()
            && self.consent_barriers.is_empty()
            && self.records() == 0
            && self.pushed.is_empty()
            && self.consents.is_empty()
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
    /// The cell's epoch, picked by the write that created it ([`version_token`]).
    #[serde(default)]
    e: String,
}

/// The one write a swap made, or that it made none.
enum Swap<R> {
    /// Write the bucket and answer `R`.
    Write(R),
    /// Answer `R` without writing.
    Keep(R),
    /// The cell now holds nothing: delete it once its last write is older than
    /// [`RETIRE_AFTER_SECS`]; until then write it when `changed`, else keep it. Answer `R`.
    Retire(R, bool),
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
        self.read_cell_at(kind_name, id)
            .await
            .map(|(v, _, _, value)| (v, value))
    }

    /// The cell's version, when that version was written, its epoch, and its value.
    async fn read_cell_at<T: for<'de> Deserialize<'de> + Default>(
        &self,
        kind_name: &str,
        id: &str,
    ) -> Result<(u64, u64, String, T), StorageError> {
        match self.get_body(kind_name, id).await? {
            None => Ok((0, 0, String::new(), T::default())),
            Some(body) => serde_json::from_slice::<Cell<T>>(&body)
                .map(|c| (c.v, c.at, c.e, c.b))
                .map_err(|e| decode_failed(kind_name, e)),
        }
    }

    /// COMPARE-AND-SET the store cell `(kind_name, id)`, never an `AppHandle`: `f` reads the current
    /// value and says what to write; the write lands only under the version this call redeemed, and
    /// a lost version reads again.
    async fn cas_cell<T, R>(
        &self,
        kind_name: &str,
        id: &str,
        mut f: impl FnMut(&mut T) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError>
    where
        T: Serialize + for<'de> Deserialize<'de> + Default,
    {
        self.cas_cell_at(kind_name, id, move |value, _| f(value))
            .await
    }

    /// [`Self::cas_cell`], with `f` told when the version it reads was written (Unix seconds).
    async fn cas_cell_at<T, R>(
        &self,
        kind_name: &str,
        id: &str,
        mut f: impl FnMut(&mut T, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError>
    where
        T: Serialize + for<'de> Deserialize<'de> + Default,
    {
        for attempt in 0..SWAP_ATTEMPTS {
            let read_at = tokio::time::Instant::now();
            let (v, at, epoch, mut value) = self.read_cell_at::<T>(kind_name, id).await?;
            let (answer, retire) = match f(&mut value, at)? {
                Swap::Keep(r) => return Ok(r),
                Swap::Write(r) => (r, false),
                Swap::Retire(r, changed) => {
                    if v != 0 && now_secs().saturating_sub(at) > RETIRE_AFTER_SECS {
                        (r, true)
                    } else if changed && v != 0 {
                        (r, false)
                    } else {
                        return Ok(r);
                    }
                }
            };
            let next = v + 1;
            // A cell made now gets an epoch of its own; every version after carries it on.
            let epoch = if v == 0 { nonce()? } else { epoch };
            let token = version_token(id, &epoch, next);
            if self
                .claim(
                    &format!("{kind_name}.v"),
                    &token,
                    now_secs() + VERSION_CLAIM_SECS,
                )
                .await?
            {
                within_budget(kind_name, read_at)?;
                if retire {
                    // Retired under the won claim: a writer that read this version loses it and
                    // reads the cell gone, and creates it again under a new epoch, which no claim
                    // of this one names.
                    self.calls
                        .delete_plane_record(&kind(kind_name), id)
                        .await
                        .map_err(|f| failed(kind_name, f))?;
                    return Ok(answer);
                }
                let body = serde_json::to_vec(&Cell {
                    v: next,
                    b: &value,
                    at: now_secs(),
                    id: id.to_string(),
                    e: epoch,
                })
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
        self.update_at(client_id, move |b, _| f(b)).await
    }

    /// [`Self::update`], with `f` told when the bucket's current version was written.
    async fn update_at<R>(
        &self,
        client_id: &str,
        mut f: impl FnMut(&mut Bucket, u64) -> Result<Swap<R>, StorageError>,
    ) -> Result<R, StorageError> {
        self.cas_cell_at("bucket", &digest(client_id), |b: &mut Bucket, at| {
            b.id = client_id.to_string();
            f(b, at)
        })
        .await
    }

    // ── the indexes: a credential (or family, subject) to the client holding it ──────────────

    /// Index the credential (or family) `key` of kind `ix` to the one client it was minted for.
    async fn index(&self, ix: &str, key: &str, client_id: &str) -> Result<(), StorageError> {
        let id = digest(key);
        let body = serde_json::to_vec(&IndexRow {
            client: client_id.to_string(),
            key: id.clone(),
            at: now_secs(),
        })
        .map_err(|e| decode_failed(ix, e))?;
        self.put_body(&format!("ix.{ix}"), &id, None, 0, &body)
            .await
    }

    /// The one client the index `ix` names for `key`.
    async fn client_of(&self, ix: &str, key: &str) -> Result<Option<String>, StorageError> {
        let Some(body) = self.get_body(&format!("ix.{ix}"), &digest(key)).await? else {
            return Ok(None);
        };
        serde_json::from_slice::<IndexRow>(&body)
            .map(|row| Some(row.client))
            .map_err(|e| decode_failed(ix, e))
    }

    /// Index `subject` to `client_id`: a subject names every client it consented to.
    async fn index_subject(&self, key: &str, client_id: &str) -> Result<(), StorageError> {
        let ix = "subj";
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

    /// Every client the subject index names for `key`.
    async fn clients_of_subject(&self, key: &str) -> Result<Vec<String>, StorageError> {
        let ix = "subj";
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
        self.cas_cell::<Option<String>, ()>("uc", &digest(normalized), |held| {
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
        self.cas_cell::<Option<String>, ()>("uc", &digest(normalized), |held| {
            if held.as_deref() == Some(device_code) {
                *held = None;
                Ok(Swap::Retire((), true))
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
            id: digest(id),
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
        let body = serde_json::to_vec(&StakeRow {
            approve,
            until: now_secs() + ttl.as_secs(),
            id: row_id.clone(),
            nonce: nonce()?,
        })
        .map_err(|e| decode_failed("stake", e))?;
        self.put_body("stake", &row_id, None, 0, &body).await
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
    /// the claim takes the winner's and never signs with a key of its own. Kept as THE DESIGN rules
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
        // ONE minting claim, standing for one period: two builds can never both hold it, and a
        // winner that died before keeping its key frees it when the period ends. The key is
        // written under the claim's fence ([`within_budget`]), measured from before the claim, so
        // a winner never keeps a key after another node can see its claim lapse.
        let claimed_at = tokio::time::Instant::now();
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
        within_budget("key", claimed_at).map_err(|e| e.0)?;
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

/// One credential's index row: the client it was minted for, the credential's digest (the row's
/// id) and when the row was written.
#[derive(Serialize, Deserialize)]
struct IndexRow {
    client: String,
    key: String,
    at: u64,
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
        s.cas_cell::<FamilyBar, ()>("family", &id, |bar| {
            bar.id.clone_from(&id);
            Times::merge(&mut bar.times, window);
            Ok(Swap::Write(()))
        })
        .await?;
        let mut removed = 0u64;
        // A family is minted for one client: its index names that one.
        if let Some(client) = s.client_of("fam", family_id).await? {
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
        s.index_subject(&record.subject, &client).await?;
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
        s.index_subject(&updated.subject, &client).await?;
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
        for client in self.shared.clients_of_subject(subject).await? {
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
        let cells: Vec<Cell<Bucket>> = rows
            .iter()
            .filter_map(|body| serde_json::from_slice::<Cell<Bucket>>(body).ok())
            .filter(|cell| !cell.b.id.is_empty())
            .collect();
        for mut cell in cells {
            // Judged first on the body the listing already read: a client with nothing to reclaim
            // is not read again. Every node sweeps every client each minute, so a second read of
            // each would be a store read per client per node per minute, to change nothing.
            let listed = sweep_bucket(&mut cell.b, cell.at, now, &mut Vec::new());
            let acts = match listed {
                Swap::Keep(_) => false,
                Swap::Write(_) => true,
                Swap::Retire(_, changed) => {
                    changed || now_secs().saturating_sub(cell.at) > RETIRE_AFTER_SECS
                }
            };
            if !acts {
                continue;
            }
            let client = cell.b.id;
            let mut freed: Vec<(String, String)> = Vec::new();
            // One bucket that will not swap (a held version, a store fault) is skipped and said,
            // never the end of the sweep: the next tick tries it again.
            let swept = s
                .update_at(&client, |b, at| Ok(sweep_bucket(b, at, now, &mut freed)))
                .await;
            match swept {
                Ok(n) => removed += n,
                Err(e) => {
                    tracing::warn!(error = %e, "oauth_as: a client's records were not swept this tick; the next tick tries them again");
                    continue;
                }
            }
            for (uc, dc) in freed {
                if let Err(e) = s.release_user_code(&uc, &dc).await {
                    tracing::warn!(error = %e, "oauth_as: a lapsed device grant's user code was not released this tick");
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
        match s.sweep_replays(secs_of(now)).await {
            Ok(n) => removed += n,
            Err(e) => {
                tracing::warn!(error = %e, "oauth_as: lapsed replay rows were not swept this tick")
            }
        }
        let reclaimed = [
            s.sweep_user_codes().await,
            s.sweep_indexes().await,
            s.sweep_rows::<SessionRow>("session", secs_of(now), |r| (r.until, &r.id))
                .await,
            s.sweep_rows::<StakeRow>("stake", secs_of(now), |r| (r.until, &r.id))
                .await,
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
/// `at`, noting each lapsed device grant's user code in `freed`: the sweep's one change to a
/// bucket, judged on the listed body and then made under the version the swap reads.
fn sweep_bucket(
    b: &mut Bucket,
    at: u64,
    now: SystemTime,
    freed: &mut Vec<(String, String)>,
) -> Swap<u64> {
    let mut n = 0u64;
    freed.clear();
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
    // A SELF-REGISTERED client that has held nothing for the idle period goes: registration takes
    // no credential, and nothing else would ever reclaim it.
    if b.client.as_ref().is_some_and(|c| c.registration.is_some())
        && b.records() == 0
        && b.pushed.is_empty()
        && b.consents.is_empty()
        && secs_of(now).saturating_sub(at) > crate::policy::REGISTERED_CLIENT_IDLE.as_secs()
    {
        b.client = None;
        n += 1;
    }
    if b.holds_nothing() {
        Swap::Retire(n, n > 0)
    } else if n == 0 {
        Swap::Keep(0)
    } else {
        Swap::Write(n)
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
            if cell.b.id.is_empty() || cell.b.times.is_some_and(|t| now < t.until) {
                continue;
            }
            // A lapsed barrier is cleared, and a cleared one retired once it is old enough. One
            // that will not swap is said and left for the next tick.
            match self
                .cas_cell::<FamilyBar, u64>("family", &cell.b.id.clone(), |bar| {
                    Ok(match bar.times {
                        Some(t) if now >= t.until => {
                            bar.times = None;
                            Swap::Retire(1, true)
                        }
                        Some(_) => Swap::Keep(0),
                        None => Swap::Retire(0, false),
                    })
                })
                .await
            {
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
        let rows = self
            .calls
            .list_plane_records(&kind("uc"), &PlaneSelector::All)
            .await
            .map_err(|f| failed("uc", f))?;
        for body in rows {
            let Ok(cell) = serde_json::from_slice::<Cell<Option<String>>>(&body) else {
                continue;
            };
            if cell.id.is_empty() || cell.b.is_some() {
                continue;
            }
            self.cas_cell::<Option<String>, ()>("uc", &cell.id, |held| {
                Ok(if held.is_none() {
                    Swap::Retire((), false)
                } else {
                    Swap::Keep(())
                })
            })
            .await?;
        }
        Ok(())
    }

    /// Delete every credential index row whose client no longer holds the credential, once the row
    /// is older than [`INDEX_GRACE_SECS`] (its bucket write may still be in flight before that).
    async fn sweep_indexes(&self) -> Result<(), StorageError> {
        let mut buckets: BTreeMap<String, Bucket> = BTreeMap::new();
        let now_s = now_secs();
        for ix in ["tok", "rt", "code", "par", "dev", "cons", "fam"] {
            let k = kind(&format!("ix.{ix}"));
            let rows = self
                .calls
                .list_plane_records(&k, &PlaneSelector::All)
                .await
                .map_err(|f| failed(ix, f))?;
            for body in rows {
                let Ok(row) = serde_json::from_slice::<IndexRow>(&body) else {
                    continue;
                };
                if row.key.is_empty() || now_s.saturating_sub(row.at) <= INDEX_GRACE_SECS {
                    continue;
                }
                if !buckets.contains_key(&row.client) {
                    let bucket = self.bucket(&row.client).await?;
                    buckets.insert(row.client.clone(), bucket);
                }
                let b = &buckets[&row.client];
                let is = |key: &str| digest(key) == row.key;
                let held = match ix {
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
                };
                if !held {
                    self.calls
                        .delete_plane_record(&k, &row.key)
                        .await
                        .map_err(|f| failed(ix, f))?;
                }
            }
        }
        Ok(())
    }

    /// Delete every row of `kind_name` whose `until` (read by `of`, with the row's own id) has
    /// passed `now_s`.
    async fn sweep_rows<R: for<'de> Deserialize<'de>>(
        &self,
        kind_name: &str,
        now_s: u64,
        of: impl Fn(&R) -> (u64, &String),
    ) -> Result<(), StorageError> {
        let k = kind(kind_name);
        let rows = self
            .calls
            .list_plane_records(&k, &PlaneSelector::All)
            .await
            .map_err(|f| failed(kind_name, f))?;
        for body in rows {
            let Ok(row) = serde_json::from_slice::<R>(&body) else {
                continue;
            };
            let (until, id) = of(&row);
            if until <= now_s && !id.is_empty() {
                self.calls
                    .delete_plane_record(&k, id)
                    .await
                    .map_err(|f| failed(kind_name, f))?;
            }
        }
        Ok(())
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
