// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The node identity and deployment signing key, owned by the configured Store.
//!
//! ## The node's identity
//!
//! A journal record is named `(node, node_seq)`, and the store keys every record by that pair. Two
//! nodes numbering under one identity would overwrite each other's records in a shared store, so
//! each node journals under an identity no other LIVE node holds (nodes share one store, and a money
//! record never vanishes silently). There is no `node_id` configuration key: adding one changes the frozen
//! configuration schema.
//!
//! The identity is the stable one the Store registry keeps for this host, regardless of
//! `data_dir`. The host name is held under a lease: a restart takes a free or expired lease and
//! resumes its chain; a concurrent live process receives a fresh registered id. A clean shutdown
//! releases the lease; a crash restart watches for at most one lease period before deciding.
//!
//! The host is the operating system's host name ([`host_identity`]), a label: two processes with one
//! name, or two with none, never journal under one identity while both are live. A deployment whose
//! host name changes on every restart mints a new identity each time, and its predecessor's chain
//! stays in the store under the old one, readable and verified by `/admin/verify`
//! ([`walk_stored_chains`]) but not resumed, and so does a
//! process that restarts while its predecessor still refreshes the lease ([`LEASE_TTL_MS`]).
//!
//! ## The deployment keyset
//!
//! The one key that signs the audit chain and the checkpoints is the DEPLOYMENT's (spec #82(a)), so
//! it is kept once in the store ([`KEYSET_SCHEMA`]) and every node on that store signs with it. A
//! node mints it once and reads it back on every boot, so `/admin/verify` verifies the records a
//! predecessor signed. There is no filesystem cache.
//!
//! ## Atomic ownership
//!
//! The configured Store must negotiate conditional record transactions. The host pointer and
//! deployment key are inserted only when absent. Lease take, refresh and release compare exact
//! observed bytes, and every leased journal mutation compares that same lease in its transaction.
//! A delayed predecessor cannot publish after a successor takes the identity. Unknown outcomes
//! retain their immutable operation id/body until a definitive Store decision.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Predicate};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel_audit::{AuditChain, AuditKeySet, AuditRecord};

use super::store_chain::{off_runtime, read_chain, read_chain_beside, wait_for, JournalLane};

/// The record schema of the node registry: host to node id.
pub(super) const NODE_SCHEMA: &str = "busbar.node.v1";

/// The record schema the deployment keyset is kept under.
pub(super) const KEYSET_SCHEMA: &str = "busbar.keyset.v1";

/// The one key the deployment keyset is kept at.
const KEYSET_KEY: &[u8] = b"deployment";

/// The most registry rows one scan reads.
const REGISTRY_LIMIT: u32 = 1 << 16;

/// The kind every minting claim is redeemed under (`redeem_plane_token`).
pub(super) const MINT_CLAIM_KIND: &str = "busbar.mint.v1";

/// The most candidate node ids one boot tries to claim before it refuses.
const ID_ATTEMPTS: usize = 16;

/// The claim that holds node id `id` for the one host that took it, for good.
fn id_claim(id: u64) -> String {
    format!("node-id:{id:016x}")
}

/// Now, in whole Unix seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// REDEEM the single-use minting claim `token`, standing until `expires_at`: `true` when this call
/// was its first redemption, so this boot is the one that mints.
///
/// # Errors
///
/// The store refused or failed the redemption.
fn claim(calls: &dyn StoreCalls, token: &str, expires_at: u64) -> Result<bool, String> {
    wait_for(calls.redeem_plane_token(MINT_CLAIM_KIND, token, expires_at, now_secs()))
        .map_err(|f| format!("the store would not answer the minting claim `{token}`: {f}"))
}

/// This host's name, as the node registry keys it: `HOSTNAME`, else the kernel's host name, else
/// `/etc/hostname`, else empty (one identity for every such host).
#[must_use]
pub fn host_identity() -> String {
    let clean = |s: String| {
        let s = s.trim().to_string();
        (!s.is_empty()).then_some(s)
    };
    std::env::var("HOSTNAME")
        .ok()
        .and_then(clean)
        .or_else(|| {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .and_then(clean)
        })
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .and_then(clean)
        })
        .unwrap_or_default()
}

/// The registry key of `host`.
fn host_key(host: &str) -> Vec<u8> {
    let mut key = b"host:".to_vec();
    key.extend_from_slice(host.as_bytes());
    key
}

/// A registry value as a node id.
fn id_of(value: &RecordBytes) -> Option<u64> {
    let bytes: [u8; 8] = value.as_slice().try_into().ok()?;
    Some(u64::from_be_bytes(bytes)).filter(|&id| id != 0)
}

/// THIS HOST'S NODE ID: the one the registry holds for `host`, or one conditionally inserted now.
/// A concurrent loser reads the winning pointer. Each minted id is claimed for good before use,
/// so it is
/// never zero and never an id another host holds.
///
/// # Errors
///
/// The store refused or failed a read, a claim or the write, did not keep what it took, or another
/// boot holds the claim and kept nothing in time.
pub fn node_id(calls: &dyn StoreCalls, host: &str) -> Result<u64, String> {
    let key = host_key(host);
    let get = || registry_get(calls, &key);
    if let Some(id) = get()? {
        return Ok(id);
    }
    let id = mint_id(calls)?;
    // The host pointer is immutable. A delayed first boot can never overwrite its winner,
    // regardless of elapsed time or any earlier ambiguous answer.
    let request = super::conditional::candidate(
        vec![Predicate {
            schema: NODE_SCHEMA.into(),
            key: key.clone(),
            expected: Expected::Absent,
        }],
        vec![Mutation::Put {
            schema: NODE_SCHEMA.into(),
            key: key.clone(),
            value: id.to_be_bytes().to_vec(),
        }],
    );
    super::conditional::decide(calls, &request)?;
    get()?.ok_or_else(|| "the store did not keep this node's id".to_string())
}

/// The node id the registry keeps at `key`, if any.
///
/// # Errors
///
/// The store refused or failed the read.
fn registry_get(calls: &dyn StoreCalls, key: &[u8]) -> Result<Option<u64>, String> {
    wait_for(calls.record_get(NODE_SCHEMA, key))
        .map(|value| value.as_ref().and_then(id_of))
        .map_err(|f| format!("the store would not read the node registry: {f}"))
}

/// A node id no registered node holds, claimed for good before it is handed back: never zero.
///
/// # Errors
///
/// The random source or the store failed, or the store granted none of the ids tried.
fn mint_id(calls: &dyn StoreCalls) -> Result<u64, String> {
    let taken: Vec<u64> = registered(calls)?.into_iter().map(|(_, id)| id).collect();
    for _ in 0..ID_ATTEMPTS {
        let id = u64::from_be_bytes(random()?);
        // ONE HOST PER ID: the id is claimed for good before it is kept.
        if id != 0 && !taken.contains(&id) && claim(calls, &id_claim(id), u64::MAX)? {
            return Ok(id);
        }
    }
    Err(format!(
        "the store granted none of {ID_ATTEMPTS} node ids this boot tried to claim"
    ))
}

/// Keep `id` in the registry at `key`.
///
/// # Errors
///
/// The store refused or failed the write.
fn keep_id(calls: &dyn StoreCalls, key: &[u8], id: u64) -> Result<(), String> {
    let value = RecordBytes::new(id.to_be_bytes().to_vec())
        .map_err(|n| format!("a {n}-byte node id is over the slot's bound"))?;
    wait_for(calls.record_put(NODE_SCHEMA, key, &value))
        .map_err(|f| format!("the store would not keep this node's id: {f}"))
}

/// `N` bytes from the operating system's random source.
///
/// # Errors
///
/// The source gave none.
fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut raw = [0u8; N];
    getrandom::fill(&mut raw).map_err(|_| {
        "the operating system's random source gave no bytes for a node id".to_string()
    })?;
    Ok(raw)
}

/// AN ID OF THIS PROCESS'S OWN, for a node that may not journal under its host's: minted as a host's
/// is, and registered under the host's name AND the id, so `/admin/verify` walks its chain too
/// ([`registered`] reads every `host:` row) while the host's own row is left to its holder.
///
/// # Errors
///
/// As [`mint_id`] and [`keep_id`].
fn fresh_node_id(calls: &dyn StoreCalls, host: &str) -> Result<u64, String> {
    let id = mint_id(calls)?;
    let mut key = host_key(host);
    // A host name never holds a NUL, so this row is never another host's.
    key.push(0);
    key.extend_from_slice(format!("{id:016x}").as_bytes());
    keep_id(calls, &key, id)?;
    Ok(id)
}

/// The tick every lease constant is derived from: the checkpoint flush tick the lease is refreshed
/// on (`root::serve`'s `Checkpoints::tick`, every [`busbar_kernel::host_records::FLUSH_INTERVAL`]).
#[cfg(not(test))]
const LEASE_TICK: Duration = busbar_kernel::host_records::FLUSH_INTERVAL;
#[cfg(test)]
const LEASE_TICK: Duration = Duration::from_millis(20);

/// The lease is refreshed on every this-many-th checkpoint flush tick.
pub(super) const LEASE_REFRESH_TICKS: u32 = 3;

/// How long a node's lease on its host name holds without a refresh, in milliseconds: three of its
/// refresh periods, each [`LEASE_REFRESH_TICKS`] flush ticks.
pub const LEASE_TTL_MS: u64 = 3
    * LEASE_REFRESH_TICKS as u64
    * (LEASE_TICK.as_secs() * 1_000 + LEASE_TICK.subsec_millis() as u64);

/// How long a boot that finds its host name's lease held WATCHES it before it decides: one lease
/// period, enough for a live holder to refresh it and for a dead one's to lapse.
const LEASE_WATCH: Duration = Duration::from_millis(LEASE_TTL_MS);

/// How often a watching boot reads the lease again: one flush tick.
const LEASE_POLL: Duration = LEASE_TICK;

// A lease that lapses the moment it is taken holds nothing.
const _: () = assert!(LEASE_TTL_MS > 0);

/// Now, in Unix milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The registry key of `host`'s lease.
fn lease_key(host: &str) -> Vec<u8> {
    let mut key = b"lease:".to_vec();
    key.extend_from_slice(host.as_bytes());
    key
}

/// A lease row: the holding process's random token, and when the lease lapses (Unix ms; 0 =
/// released).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeaseRow {
    holder: [u8; 16],
    expires_ms: u64,
}

impl LeaseRow {
    fn bytes(self) -> Vec<u8> {
        let mut out = self.holder.to_vec();
        out.extend_from_slice(&self.expires_ms.to_be_bytes());
        out
    }

    fn parse(value: &RecordBytes) -> Option<Self> {
        let raw = value.as_slice();
        if raw.len() != 24 {
            return None;
        }
        Some(LeaseRow {
            holder: raw.get(..16)?.try_into().ok()?,
            expires_ms: u64::from_be_bytes(raw.get(16..24)?.try_into().ok()?),
        })
    }
}

/// The lease row `host`'s name is held under, if any.
///
/// # Errors
///
/// The store refused or failed the read.
fn read_lease(calls: &dyn StoreCalls, host: &str) -> Result<Option<LeaseRow>, String> {
    wait_for(calls.record_get(NODE_SCHEMA, &lease_key(host)))
        .map_err(|f| format!("the store would not read this host's lease: {f}"))
        .and_then(|value| {
            value
                .map(|value| {
                    LeaseRow::parse(&value)
                        .ok_or_else(|| "the store's host lease is malformed".to_string())
                })
                .transpose()
        })
}

/// Put `row` as `host`'s lease.
///
/// # Errors
///
/// The store refused or failed the write.
#[cfg(test)]
fn put_lease(calls: &dyn StoreCalls, host: &str, row: LeaseRow) -> Result<(), String> {
    let value = RecordBytes::new(row.bytes())
        .map_err(|n| format!("a {n}-byte lease is over the slot's bound"))?;
    wait_for(calls.record_put(NODE_SCHEMA, &lease_key(host), &value))
        .map_err(|f| format!("the store would not keep this host's lease: {f}"))
}

/// `host`'s lease row as the store holds it: its holder and when it lapses (0 = released). A
/// test-only read, so a cell asserts what a hand-driven refresh or release left in the store.
#[cfg(test)]
pub(super) fn lease_row(calls: &dyn StoreCalls, host: &str) -> Option<([u8; 16], u64)> {
    read_lease(calls, host)
        .expect("the lease reads")
        .map(|row| (row.holder, row.expires_ms))
}

/// Put `host`'s held lease back to lapse at `expires_ms`, its holder kept: a test-only write, so a
/// cell tells a refresh by the expiry it moves without reading the wall clock.
#[cfg(test)]
pub(super) fn set_lease_expiry(calls: &dyn StoreCalls, host: &str, expires_ms: u64) {
    let (holder, _) = lease_row(calls, host).expect("a lease is held");
    put_lease(calls, host, LeaseRow { holder, expires_ms }).expect("the lease is kept");
}

/// Whether another process holds `host`'s lease live now.
fn held_live(row: Option<LeaseRow>, holder: &[u8; 16], now: u64) -> bool {
    row.is_some_and(|row| row.holder != *holder && row.expires_ms > now)
}

/// A process's lease on its host name: held while it is refreshed, given up on a clean shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLease {
    host: String,
    holder: [u8; 16],
}

impl NodeLease {
    /// Exact ownership predicate for the same atomic transaction as the journal mutation.
    /// A local expiry check is never a server fence: a successor's conditional take changes
    /// these bytes before it reads the chain it will resume.
    fn predicate(&self, calls: &dyn StoreCalls) -> Result<Option<Predicate>, String> {
        Ok(read_lease(calls, &self.host)?
            .filter(|row| row.holder == self.holder && row.expires_ms != 0)
            .map(|row| Predicate {
                schema: NODE_SCHEMA.into(),
                key: lease_key(&self.host),
                expected: Expected::Bytes(row.bytes()),
            }))
    }

    /// REFRESH the lease for another [`LEASE_TTL_MS`]. `false` when another process holds it now
    /// (this one went unrefreshed past its lapse): it is left to that holder.
    ///
    /// # Errors
    ///
    /// The store refused or failed the read or the write.
    pub fn refresh(&self, calls: &dyn StoreCalls) -> Result<bool, String> {
        loop {
            let Some(predicate) = self.predicate(calls)? else {
                return Ok(false);
            };
            let request = super::conditional::candidate(
                vec![predicate],
                vec![Mutation::Put {
                    schema: NODE_SCHEMA.into(),
                    key: lease_key(&self.host),
                    value: LeaseRow {
                        holder: self.holder,
                        expires_ms: now_ms().saturating_add(LEASE_TTL_MS),
                    }
                    .bytes(),
                }],
            );
            match super::conditional::decide(calls, &request)? {
                Decision::Applied => return Ok(true),
                Decision::ConditionConflict => continue,
            }
        }
    }

    /// RELEASE the lease, if this process still holds it, so the next boot of the host resumes at
    /// once.
    ///
    /// # Errors
    ///
    /// The store refused or failed the read or the write.
    pub fn release(&self, calls: &dyn StoreCalls) -> Result<(), String> {
        loop {
            let Some(predicate) = self.predicate(calls)? else {
                return Ok(());
            };
            let request = super::conditional::candidate(
                vec![predicate],
                vec![Mutation::Put {
                    schema: NODE_SCHEMA.into(),
                    key: lease_key(&self.host),
                    value: LeaseRow {
                        holder: self.holder,
                        expires_ms: 0,
                    }
                    .bytes(),
                }],
            );
            match super::conditional::decide(calls, &request)? {
                Decision::Applied => return Ok(()),
                Decision::ConditionConflict => continue,
            }
        }
    }
}

/// THE ONE DECISION ON A HOST NAME'S LEASE: `true` when this boot, as `holder`, now holds `host`'s
/// lease (it was free, released or lapsed, and this boot won the store's claim on taking it), and
/// `false` when another live process holds it or won that claim.
///
/// A lease found held is WATCHED for up to [`LEASE_WATCH`] before deciding: refreshed (or taken)
/// meanwhile, its holder is live and this boot clashes with it; released, or left to lapse, its
/// holder is gone (a crash), and this boot takes it and resumes the chain, recovering its holds.
///
/// Taking the lease conditionally replaces the exact observed row. Time only permits a take
/// attempt; the atomic Store comparison fences a delayed refresh, release or journal mutation.
///
/// # Errors
///
/// The store refused or failed a read, the claim or the write.
fn take_lease(calls: &dyn StoreCalls, host: &str, holder: [u8; 16]) -> Result<bool, String> {
    let mut seen = read_lease(calls, host)?;
    if held_live(seen, &holder, now_ms()) {
        let deadline = Instant::now() + LEASE_WATCH + LEASE_POLL;
        loop {
            std::thread::sleep(LEASE_POLL);
            let now = read_lease(calls, host)?;
            let live = held_live(now, &holder, now_ms());
            if now != seen {
                // Refreshed or taken by another: a live holder. Released: free.
                if live {
                    return Ok(false);
                }
                seen = now;
                break;
            }
            if !live {
                // Never refreshed, and lapsed: its holder is gone.
                break;
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }
    let key = lease_key(host);
    let request = super::conditional::candidate(
        vec![Predicate {
            schema: NODE_SCHEMA.into(),
            key: key.clone(),
            expected: seen.map_or(Expected::Absent, |row| Expected::Bytes(row.bytes())),
        }],
        vec![Mutation::Put {
            schema: NODE_SCHEMA.into(),
            key,
            value: LeaseRow {
                holder,
                expires_ms: now_ms().saturating_add(LEASE_TTL_MS),
            }
            .bytes(),
        }],
    );
    Ok(super::conditional::decide(calls, &request)? == Decision::Applied)
}

/// The identity a node with no data directory journals under, and the lease it holds for it.
#[derive(Debug)]
pub struct TakenNode {
    /// The node id its journal is keyed by.
    pub id: u64,
    /// The lease on its host name, when it journals under the host's id; `None` when another live
    /// process held the name and this one took a fresh id.
    pub lease: Option<NodeLease>,
}

/// THE IDENTITY OF A NODE WITH NO DATA DIRECTORY: the host's stable id from the registry
/// ([`node_id`]) when this boot takes the host name's lease, so a restart resumes its chain and
/// recovers its holds; otherwise — another live process holds the name, nameless or not — a fresh
/// id of this process's own ([`fresh_node_id`]), logged once. Never a refusal.
///
/// # Errors
///
/// The store refused or failed a read, a claim or a write ([`node_id`]).
pub fn take_node(calls: &dyn StoreCalls, host: &str) -> Result<TakenNode, String> {
    let holder = random::<16>()?;
    if take_lease(calls, host, holder)? {
        return Ok(TakenNode {
            id: node_id(calls, host)?,
            lease: Some(NodeLease {
                host: host.to_string(),
                holder,
            }),
        });
    }
    let id = fresh_node_id(calls, host)?;
    tracing::warn!(
        host = %host,
        node = id,
        "another live process on this store holds this host name's node identity; this process \
         journals under a fresh node id of its own"
    );
    Ok(TakenNode { id, lease: None })
}

/// THE LEASE A BOOK'S LANE HOLDS on its host name (`JournalLane::hold_lease`): taken by the boot
/// that opened the lane, refreshed on the checkpoint flush tick, released on a clean shutdown. It is
/// kept on the lane to the store it is held in, the value the boot hands the book, never in a
/// process-wide static.
#[derive(Debug, Default)]
pub struct HeldLease {
    lease: std::sync::Mutex<Option<NodeLease>>,
    /// The checkpoint flush ticks counted since the lease was last refreshed.
    ticks: std::sync::atomic::AtomicU32,
    lost: std::sync::atomic::AtomicBool,
}

impl HeldLease {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<NodeLease>> {
        self.lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Keep `lease` as the one [`HeldLease::refresh`] and [`HeldLease::release`] act on.
    pub fn hold(&self, lease: NodeLease) {
        *self.lock() = Some(lease);
    }

    pub(super) fn lost(&self) -> bool {
        self.lost.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(super) fn predicate(&self, calls: &dyn StoreCalls) -> Result<Option<Predicate>, String> {
        if self.lost() {
            return Err("this node no longer owns its journal identity".into());
        }
        let Some(lease) = self.lock().clone() else {
            return Ok(None);
        };
        match lease.predicate(calls)? {
            Some(predicate) => Ok(Some(predicate)),
            None => {
                self.lost.store(true, std::sync::atomic::Ordering::Release);
                Err("this node no longer owns its journal identity".into())
            }
        }
    }

    /// REFRESH the lease in `calls`, if one is held, on every [`LEASE_REFRESH_TICKS`]-th call: run
    /// on the checkpoint flush tick, off any runtime worker. A lease another process took (this one
    /// went unrefreshed past its lapse) is logged. The lease is cloned out of the lock, so no store
    /// call waits under it.
    pub fn refresh(&self, calls: &dyn StoreCalls) {
        let tick = self
            .ticks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !tick.wrapping_add(1).is_multiple_of(LEASE_REFRESH_TICKS) {
            return;
        }
        let Some(lease) = self.lock().clone() else {
            return;
        };
        match lease.refresh(calls) {
            Ok(true) => {}
            Ok(false) => {
                self.lost.store(true, std::sync::atomic::Ordering::Release);
                tracing::error!(
                    host = %lease.host,
                    "this node's lease on its host name lapsed and another process took it"
                );
            }
            Err(why) => tracing::warn!(reason = %why, "this node's lease was not refreshed"),
        }
    }

    /// RELEASE the lease in `calls`, if one is held: run on a clean shutdown once the journal's lane
    /// drained, so the next boot of the host resumes the whole chain at once.
    pub fn release(&self, calls: &dyn StoreCalls) {
        let Some(lease) = self.lock().take() else {
            return;
        };
        if let Err(why) = lease.release(calls) {
            tracing::warn!(reason = %why, "this node's lease was not released");
        }
    }
}

/// Every readable node the registry names: `(host, node id)`, in key order. The verification and
/// migration readers also report unreadable rows through their existing diagnostic channels.
///
/// # Errors
///
/// The store refused or failed the scan.
pub(super) fn registered(calls: &dyn StoreCalls) -> Result<Vec<(String, u64)>, String> {
    scan_registry(calls).map(|scan| scan.nodes)
}

struct RegistryScan {
    nodes: Vec<(String, u64)>,
    unreadable: usize,
}

fn scan_registry(calls: &dyn StoreCalls) -> Result<RegistryScan, String> {
    scan_registry_with_limit(calls, REGISTRY_LIMIT)
}

/// Saturated pages are subdivided by raw key prefix, including a row equal to that prefix.
/// The byte alphabet partitions the remaining keys completely; no fleet-size limit is imposed.
fn scan_registry_with_limit(calls: &dyn StoreCalls, limit: u32) -> Result<RegistryScan, String> {
    if limit == 0 {
        return Err("a node-registry scan needs a nonzero page size".into());
    }
    let mut pending = vec![b"host:".to_vec()];
    let mut rows = Vec::new();
    while let Some(prefix) = pending.pop() {
        let page = wait_for(calls.record_scan(NODE_SCHEMA, &prefix, limit))
            .map_err(|f| format!("the store would not list the node registry: {f}"))?;
        if page.len() > limit as usize
            || page.iter().any(|(key, _)| !key.starts_with(&prefix))
            || page.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(
                "the store returned an invalid node-registry page; verification is incomplete"
                    .into(),
            );
        }
        if page.len() < limit as usize {
            rows.extend(page);
            continue;
        }
        if let Some((key, value)) = page.first().filter(|(key, _)| key == &prefix) {
            rows.push((key.clone(), value.clone()));
        }
        for byte in 0..=u8::MAX {
            let mut child = prefix.clone();
            child.push(byte);
            pending.push(child);
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut scan = RegistryScan {
        nodes: Vec::new(),
        unreadable: 0,
    };
    for (key, value) in rows {
        let host = key.get(5..).and_then(|host| std::str::from_utf8(host).ok());
        match (host, id_of(&value)) {
            (Some(host), Some(id)) => scan.nodes.push((host.to_string(), id)),
            _ => scan.unreadable += 1,
        }
    }
    Ok(scan)
}

/// The deployment keyset's seed as the store keeps it (64 hex characters), or `None`.
///
/// # Errors
///
/// The store refused or failed the read, or the present row is not UTF-8 keyset text.
pub fn stored_keyset(calls: &dyn StoreCalls) -> Result<Option<String>, String> {
    wait_for(calls.record_get(KEYSET_SCHEMA, KEYSET_KEY))
        .map_err(|f| format!("the store would not read the deployment keyset: {f}"))
        .and_then(|value| {
            value
                .map(|v| {
                    String::from_utf8(v.as_slice().to_vec())
                        .map_err(|_| "the store's deployment keyset is not valid UTF-8".to_string())
                })
                .transpose()
        })
}

/// The immutable deployment keyset: insert `seed_hex` only when absent; a concurrent loser reads
/// the winning seed. No elapsed-time claim can authorize replacing an existing key.
///
/// # Errors
///
/// The store refused or failed a read, the claim or the write, kept nothing, or another boot holds
/// the claim and kept nothing in time.
pub fn keep_keyset(calls: &dyn StoreCalls, seed_hex: &str) -> Result<String, String> {
    if let Some(held) = stored_keyset(calls)? {
        return Ok(held);
    }
    let request = super::conditional::candidate(
        vec![Predicate {
            schema: KEYSET_SCHEMA.into(),
            key: KEYSET_KEY.to_vec(),
            expected: Expected::Absent,
        }],
        vec![Mutation::Put {
            schema: KEYSET_SCHEMA.into(),
            key: KEYSET_KEY.to_vec(),
            value: seed_hex.as_bytes().to_vec(),
        }],
    );
    super::conditional::decide(calls, &request)?;
    stored_keyset(calls)?.ok_or_else(|| "the store did not keep the deployment keyset".to_string())
}

/// What a walk of every chain the store keeps found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StoredWalk {
    /// The node ids whose chains were walked.
    pub chains: Vec<u64>,
    /// What did not hold: a chain that does not verify, an audit record that does not decode, whose
    /// digest or link does not hold, or whose signature does not verify under the deployment
    /// keyset, and an unsigned one journalled after its chain's `Bootstrap`.
    pub findings: Vec<String>,
}

/// WALK EVERY CHAIN THE STORE KEEPS — every node the registry names, and `own` — verifying each
/// journal chain and the audit records on it, signatures included, against `keys`. Off any runtime
/// worker where one is waiting: this reads the whole of every chain. `own`'s chain is read beside
/// `lane`, which may be putting to it ([`read_chain_beside`]): its record mid-put is not torn.
/// Another node's chain has no lane here, so a record missing a part there is.
#[must_use]
pub fn walk_stored_chains(lane: &JournalLane, own: u64, keys: &AuditKeySet) -> StoredWalk {
    let calls = lane.calls();
    let calls = calls.as_ref();
    off_runtime(|| {
        let mut walk = StoredWalk::default();
        let mut nodes = match scan_registry(calls) {
            Ok(scan) => {
                if scan.unreadable > 0 {
                    walk.findings.push(format!(
                        "the node registry contains {} unreadable row(s); their chains were not verified",
                        scan.unreadable
                    ));
                }
                scan.nodes.into_iter().map(|(_, id)| id).collect::<Vec<_>>()
            }
            Err(why) => {
                walk.findings.push(why);
                Vec::new()
            }
        };
        nodes.push(own);
        nodes.sort_unstable();
        nodes.dedup();
        for node in nodes {
            walk.chains.push(node);
            let read = if node == own {
                read_chain_beside(lane, node)
            } else {
                read_chain(calls, node)
            };
            let records = match read {
                Ok(records) => records,
                Err(why) => {
                    walk.findings.push(format!("node {node}: {why}"));
                    continue;
                }
            };
            let decoded = match busbar_kernel_wal::decode_run(&records)
                .and_then(|d| busbar_kernel_wal::verify_journal(&d).map(|()| d))
            {
                Ok(decoded) => decoded,
                Err(broken) => {
                    walk.findings.push(format!(
                        "node {node}: the journal does not verify: {broken}"
                    ));
                    continue;
                }
            };
            // As the boot resumes a chain (`resume_audit`): a record that will not read back is a
            // finding, and the first record journalled after this chain's `Bootstrap` is where
            // its signatures start.
            let mut audits: Vec<AuditRecord> = Vec::new();
            let mut keyed = false;
            let mut signed_from = None;
            for record in &decoded {
                keyed |= record.class == busbar_kernel_wal::RecordClass::Bootstrap;
                match super::decode_audit(record) {
                    Ok(Some(audit)) => {
                        if keyed && signed_from.is_none() {
                            signed_from = Some(audit.seq);
                        }
                        audits.push(audit);
                    }
                    Ok(None) => {}
                    Err(why) => walk
                        .findings
                        .push(format!("node {node}: record {}: {why}", record.node_seq)),
                }
            }
            if let Err(broken) = AuditChain::verify_window(&audits) {
                walk.findings
                    .push(format!("node {node}: audit chain: {broken:?}"));
            }
            for record in &audits {
                let Some(key_id) = record.key_id.as_deref() else {
                    // The signature is not in the digest: stripped, it leaves the chain whole and
                    // only this rule sees it.
                    if signed_from.is_some_and(|from| record.seq >= from) {
                        walk.findings.push(format!(
                            "node {node}: audit record {} is unsigned, sealed after the keyset \
                             was bound",
                            record.seq
                        ));
                    }
                    continue;
                };
                let verified = keys
                    .get(key_id)
                    .ok_or(busbar_kernel_audit::KeyError::Unsigned)
                    .and_then(|key| AuditChain::verify_signature(record, key));
                if let Err(e) = verified {
                    walk.findings.push(format!(
                        "node {node}: audit record {} signed by {key_id}: {e:?}",
                        record.seq
                    ));
                }
            }
        }
        walk
    })
}

/// EVERY OTHER NODE'S CHAIN THE STORE KEEPS, decoded: `(node, its records in chain order)` for each
/// node the registry names but `own`. A chain that will not read or verify is left out, named in a
/// warning. Read by the rate-card migration (MONEY-DESIGN section 3a), which copies every chain's card
/// records into the fleet-shared history.
///
/// # Errors
///
/// The store would not list its node registry.
pub fn stored_chains(
    calls: &dyn StoreCalls,
    own: u64,
) -> Result<Vec<(u64, Vec<busbar_kernel_wal::JournalRecord>)>, String> {
    let registry = scan_registry(calls)?;
    if registry.unreadable > 0 {
        tracing::warn!(
            unreadable = registry.unreadable,
            "unreadable node registry rows were left out of the rate-card migration"
        );
    }
    let mut nodes: Vec<u64> = registry.nodes.into_iter().map(|(_, id)| id).collect();
    nodes.sort_unstable();
    nodes.dedup();
    let mut out = Vec::new();
    for node in nodes.into_iter().filter(|n| *n != own) {
        let decoded = read_chain(calls, node).and_then(|records| {
            busbar_kernel_wal::decode_run(&records)
                .and_then(|d| busbar_kernel_wal::verify_journal(&d).map(|()| d))
                .map_err(|broken| format!("the journal does not verify: {broken}"))
        });
        match decoded {
            Ok(records) => out.push((node, records)),
            Err(why) => tracing::warn!(
                node,
                "a stored journal was left out of the rate-card migration: {why}"
            ),
        }
    }
    Ok(out)
}
