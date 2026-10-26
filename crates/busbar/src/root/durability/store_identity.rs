// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHO A NODE IS, AND THE KEY IT SIGNS WITH, KEPT IN THE CONFIGURED STORE (ARCHITECT 2026-10-07 H3
//! ruling, follow-up): two facts a node with no data directory has nowhere else to keep.
//!
//! ## The node's identity
//!
//! A journal record is named `(node, node_seq)`, and the store keys every record by that pair. Two
//! nodes numbering under one identity would overwrite each other's records in a shared store, so
//! each node journals under an identity no other LIVE node holds (Q128 root part 12 HIGH 2;
//! BUSBAR-1.6.0.md l.206 "Nodes share one store"; THE DESIGN §7, l.1056-1059: a money record never
//! vanishes silently). There is no `node_id` configuration key: adding one changes the frozen
//! configuration schema.
//!
//! * WITH A DATA DIRECTORY the identity is the node's own: a 128-bit random id generated at its
//!   first boot and kept in the directory ([`NODE_ID_FILE`], written atomically), read back on every
//!   later boot ([`persisted_node`]); the journal is keyed by its low 64 bits. A directory with no id
//!   file yet ADOPTS the id the store's registry holds under this host's name, so one node
//!   continuing on its host keeps its chain (unless another live node holds that name's lease),
//!   and then holds that name's lease as a node with no data directory does.
//! * WITH NO DATA DIRECTORY there is nowhere of its own to keep one (PB-13: no data-dir files), so
//!   the identity is the STABLE one the store's node registry ([`NODE_SCHEMA`]) keeps for this host,
//!   minted the first time it booted, and a restart resumes that chain and recovers the holds it
//!   left open. The host name is held under a LEASE ([`take_node`]): a boot that finds the name's
//!   lease free or expired takes it and resumes; one that finds it held by another live process
//!   journals under a fresh id of its own and logs the clash. A boot that finds it held WATCHES it
//!   for up to one lease period first: a holder that never refreshes it is a crashed predecessor,
//!   and the boot takes the lease once it lapses and resumes. The lease is refreshed on every
//!   [`LEASE_REFRESH_TICKS`]-th checkpoint flush tick and released on a clean shutdown, so a clean
//!   restart resumes at once and a crash-restart waits at most one lease period.
//!
//! The host is the operating system's host name ([`host_identity`]), a label: two processes with one
//! name, or two with none, never journal under one identity while both are live. A deployment whose
//! host name changes on every restart mints a new identity each time, and its predecessor's chain
//! stays in the store under the old one, readable and verified by `/admin/verify`
//! ([`walk_stored_chains`]) but not resumed (a known limit, ARCHITECT 2026-10-07), and so does a
//! process that restarts while its predecessor still refreshes the lease ([`LEASE_TTL_MS`]).
//!
//! ## The deployment keyset
//!
//! The one key that signs the audit chain and the checkpoints is the DEPLOYMENT's (spec #82(a)), so
//! it is kept once in the store ([`KEYSET_SCHEMA`]) and every node on that store signs with it. A
//! node with no data directory mints it once and reads it back on every boot, so `/admin/verify`
//! verifies the records a predecessor signed; with a data directory the file beside the journal is a
//! cache of the same key (see `root::keyset`).
//!
//! ## Minting races on the store's one atomic step
//!
//! The store ABI has no compare-and-set. Its one atomic step is `redeem_plane_token`, a single-use
//! TEST-AND-SET: exactly one caller is told it was first (the construction `oauth_as`'s store and
//! the kernel's own claims use). So two first boots racing on an empty store never keep two
//! keysets or two ids for one host (ARCHITECT 2026-10-07 H3 ruling):
//!
//! * Minting the deployment keyset, and minting a host's node id, each REDEEMS a claim first
//!   ([`MINT_CLAIM_KIND`]). Only the boot the store answers `true` mints and keeps; every other
//!   boot waits for the winner's write and takes it ([`MINT_WAIT`]), and refuses if it has not
//!   appeared.
//! * A node id is claimed for good before it is kept, so no two hosts can hold one id.
//! * A minting claim is a claim FOR ONE PERIOD ([`MINT_CLAIM_SECS`]): its token names the period
//!   it was redeemed in. A boot that won it and died before keeping what it minted leaves the
//!   store with nothing until the period ends; the next period's claim is a new token, so a boot
//!   then claims again. (A losing redemption cannot push the claim out: a store may re-stamp a
//!   token's expiry on every redemption, and the period's token is never redeemed after it ends.)
//!   That is liveness, bounded by one period. The window left is two first boots that both win
//!   because they straddle a period boundary within the milliseconds between a claim and its
//!   write; each reads back what the store holds after its own write.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// The period a minting claim is for, in seconds: a claim nobody kept a value for is free again
/// once its period ends.
#[cfg(not(test))]
pub(super) const MINT_CLAIM_SECS: u64 = 60;
#[cfg(test)]
pub(super) const MINT_CLAIM_SECS: u64 = 2;

/// How long a boot that lost a minting claim waits for the winner's write before it refuses.
#[cfg(not(test))]
pub(super) const MINT_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub(super) const MINT_WAIT: Duration = Duration::from_millis(400);

/// How often a waiting boot reads the store again.
const MINT_POLL: Duration = Duration::from_millis(20);

/// The most candidate node ids one boot tries to claim before it refuses.
const ID_ATTEMPTS: usize = 16;

/// The claim on minting the deployment keyset, for the period `now` falls in.
pub(super) fn keyset_claim(now: u64) -> String {
    format!("keyset:deployment@{}", now / MINT_CLAIM_SECS)
}

/// The claim on minting `host`'s node id, for the period `now` falls in.
pub(super) fn host_claim(host: &str, now: u64) -> String {
    format!("host:{host}@{}", now / MINT_CLAIM_SECS)
}

/// When a claim redeemed at `now` may be dropped: after the end of the period after its own.
fn claim_lapses(now: u64) -> u64 {
    (now / MINT_CLAIM_SECS)
        .saturating_add(2)
        .saturating_mul(MINT_CLAIM_SECS)
}

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

/// A boot that lost the claim on minting `what`: the winner's write, read back as soon as it is
/// there, for at most [`MINT_WAIT`].
///
/// # Errors
///
/// The read failed, or nothing was kept in time: this boot refuses rather than mint a second one.
fn take_winners<T>(what: &str, read: impl Fn() -> Result<Option<T>, String>) -> Result<T, String> {
    let deadline = Instant::now() + MINT_WAIT;
    loop {
        if let Some(kept) = read()? {
            return Ok(kept);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "another boot holds the store's claim to mint {what} and has not kept it; this boot \
                 refuses rather than mint a second one (the claim is free again within \
                 {MINT_CLAIM_SECS} s)"
            ));
        }
        std::thread::sleep(MINT_POLL);
    }
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

/// THIS HOST'S NODE ID: the one the registry holds for `host`, or one minted now and kept. Only the
/// boot that wins the store's claim on minting this host's id mints it; a concurrent first boot of
/// the same host takes the winner's. The minted id is claimed for good before it is kept, so it is
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
    // ONE MINTER PER HOST: the boot the store answers first mints; every other takes its id.
    let now = now_secs();
    if !claim(calls, &host_claim(host, now), claim_lapses(now))? {
        return take_winners("this host's node id", get);
    }
    // A boot that claimed a later period than a slow earlier claimant finds that claimant's id.
    if let Some(id) = get()? {
        return Ok(id);
    }
    let id = mint_id(calls)?;
    keep_id(calls, &key, id)?;
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
        .map(|value| value.as_ref().and_then(LeaseRow::parse))
        .map_err(|f| format!("the store would not read this host's lease: {f}"))
}

/// Put `row` as `host`'s lease.
///
/// # Errors
///
/// The store refused or failed the write.
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
    /// REFRESH the lease for another [`LEASE_TTL_MS`]. `false` when another process holds it now
    /// (this one went unrefreshed past its lapse): it is left to that holder.
    ///
    /// # Errors
    ///
    /// The store refused or failed the read or the write.
    pub fn refresh(&self, calls: &dyn StoreCalls) -> Result<bool, String> {
        match read_lease(calls, &self.host)? {
            Some(row) if row.holder != self.holder => Ok(false),
            _ => put_lease(
                calls,
                &self.host,
                LeaseRow {
                    holder: self.holder,
                    expires_ms: now_ms().saturating_add(LEASE_TTL_MS),
                },
            )
            .map(|()| true),
        }
    }

    /// RELEASE the lease, if this process still holds it, so the next boot of the host resumes at
    /// once.
    ///
    /// # Errors
    ///
    /// The store refused or failed the read or the write.
    pub fn release(&self, calls: &dyn StoreCalls) -> Result<(), String> {
        match read_lease(calls, &self.host)? {
            Some(row) if row.holder == self.holder => put_lease(
                calls,
                &self.host,
                LeaseRow {
                    holder: self.holder,
                    expires_ms: 0,
                },
            ),
            _ => Ok(()),
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
/// The store has no compare-and-set, so taking a lease REDEEMS a claim named after the lease row
/// this boot read (and the period it is in, so a claimant that died before writing frees it within
/// [`MINT_CLAIM_SECS`]): two boots that read one row race on one claim, and only the first writes.
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
    let observed = seen.map_or_else(
        || "free".to_string(),
        |row| format!("{}:{}", hex::encode(row.holder), row.expires_ms),
    );
    let now = now_secs();
    let token = format!("lease:{host}@{observed}@{}", now / MINT_CLAIM_SECS);
    if !claim(calls, &token, claim_lapses(now))? {
        return Ok(false);
    }
    put_lease(
        calls,
        host,
        LeaseRow {
            holder,
            expires_ms: now_ms().saturating_add(LEASE_TTL_MS),
        },
    )?;
    Ok(read_lease(calls, host)?.is_some_and(|row| row.holder == holder))
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
            Ok(false) => tracing::error!(
                host = %lease.host,
                "this node's lease on its host name lapsed and another process took it"
            ),
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

/// The file in a node's data directory its identity is kept in.
pub const NODE_ID_FILE: &str = "node_id";

/// THE IDENTITY OF A NODE WITH A DATA DIRECTORY: the 128-bit id kept in `dir` ([`NODE_ID_FILE`]),
/// its low 64 bits being the journal's key. A directory with none yet takes one now and keeps it:
/// the id the store's registry holds under `host`'s name when this boot takes that name's lease
/// (MIGRATION: one node continuing on its host keeps its chain), otherwise a fresh one. An id file
/// that does not read back is replaced the same way; a chain the directory already holds keeps the
/// identity it was written under regardless (the journal adopts it).
///
/// A node whose id IS the host name's registry id (it adopted it) holds that name's lease on every
/// boot, as a node with no data directory does, so a live node with no data directory and the same
/// name takes a fresh id rather than the adopted one. A node whose id is its own holds none.
///
/// # Errors
///
/// The store refused or failed a read, a claim or a write, or the directory would not keep the file.
pub fn persisted_node(
    calls: &dyn StoreCalls,
    dir: &std::path::Path,
    host: &str,
) -> Result<TakenNode, String> {
    let path = dir.join(NODE_ID_FILE);
    let kept = match std::fs::read_to_string(&path) {
        Ok(text) => {
            let id = u128::from_str_radix(text.trim(), 16)
                .ok()
                .and_then(|full| u64::try_from(full & u128::from(u64::MAX)).ok())
                .filter(|&id| id != 0);
            if id.is_none() {
                tracing::warn!(
                    path = %path.display(),
                    "this node's id file does not hold an id; it is kept again"
                );
            }
            id
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(format!(
                "this node's id file {} would not read: {e}",
                path.display()
            ))
        }
    };
    let registry = registry_get(calls, &host_key(host))?;
    let holder = random::<16>()?;
    let lease = || NodeLease {
        host: host.to_string(),
        holder,
    };
    if let Some(id) = kept {
        // An adopted id is the host name's: held under its lease, as a node with no data
        // directory holds it.
        if registry != Some(id) {
            return Ok(TakenNode { id, lease: None });
        }
        if take_lease(calls, host, holder)? {
            return Ok(TakenNode {
                id,
                lease: Some(lease()),
            });
        }
        tracing::warn!(
            host = %host,
            node = id,
            "another live process on this store holds this host name's lease; this node's data \
             directory keeps the id it adopted"
        );
        return Ok(TakenNode { id, lease: None });
    }
    let taken = match registry {
        Some(id) if take_lease(calls, host, holder)? => TakenNode {
            id,
            lease: Some(lease()),
        },
        _ => TakenNode {
            id: fresh_node_id(calls, host)?,
            lease: None,
        },
    };
    let high = u64::from_be_bytes(random()?);
    let full = (u128::from(high) << 64) | u128::from(taken.id);
    write_atomically(dir, &path, format!("{full:032x}\n").as_bytes())
        .map_err(|e| format!("this node's id file {} was not kept: {e}", path.display()))?;
    Ok(taken)
}

/// Write `bytes` to `path` in `dir` ATOMICALLY AND DURABLY, through the one durable-write owner
/// (`durable::create_dir_all`, then `durable::write`: a sibling temp fsynced, renamed over `path`,
/// and the directory fsynced so the rename is kept).
///
/// # Errors
///
/// The directory would not take the file.
fn write_atomically(
    dir: &std::path::Path,
    path: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    crate::root::loader::durable::create_dir_all(dir)?;
    crate::root::loader::durable::write(path, bytes)
}

/// Every node the registry names: `(host, node id)`, in key order.
///
/// # Errors
///
/// The store refused or failed the scan.
pub(super) fn registered(calls: &dyn StoreCalls) -> Result<Vec<(String, u64)>, String> {
    let rows = wait_for(calls.record_scan(NODE_SCHEMA, b"host:", REGISTRY_LIMIT))
        .map_err(|f| format!("the store would not list the node registry: {f}"))?;
    Ok(rows
        .into_iter()
        .filter_map(|(key, value)| {
            let host = String::from_utf8(key.get(5..)?.to_vec()).ok()?;
            Some((host, id_of(&value)?))
        })
        .collect())
}

/// The deployment keyset's seed as the store keeps it (64 hex characters), or `None`.
///
/// # Errors
///
/// The store refused or failed the read.
pub fn stored_keyset(calls: &dyn StoreCalls) -> Result<Option<String>, String> {
    wait_for(calls.record_get(KEYSET_SCHEMA, KEYSET_KEY))
        .map_err(|f| format!("the store would not read the deployment keyset: {f}"))
        .map(|value| value.and_then(|v| String::from_utf8(v.as_slice().to_vec()).ok()))
}

/// THE DEPLOYMENT KEYSET, minted once: the seed the store keeps, or `seed_hex` kept now by the
/// boot that wins the store's claim on minting it. A concurrent first boot that lost the claim
/// takes the winner's, so every node on the store signs with one key.
///
/// # Errors
///
/// The store refused or failed a read, the claim or the write, kept nothing, or another boot holds
/// the claim and kept nothing in time.
pub fn keep_keyset(calls: &dyn StoreCalls, seed_hex: &str) -> Result<String, String> {
    if let Some(held) = stored_keyset(calls)? {
        return Ok(held);
    }
    let now = now_secs();
    if !claim(calls, &keyset_claim(now), claim_lapses(now))? {
        return take_winners("the deployment keyset", || stored_keyset(calls));
    }
    // A boot that claimed a later period than a slow earlier claimant finds that claimant's key.
    if let Some(held) = stored_keyset(calls)? {
        return Ok(held);
    }
    let value = RecordBytes::new(seed_hex.as_bytes().to_vec())
        .map_err(|n| format!("a {n}-byte keyset is over the slot's bound"))?;
    wait_for(calls.record_put(KEYSET_SCHEMA, KEYSET_KEY, &value))
        .map_err(|f| format!("the store would not keep the deployment keyset: {f}"))?;
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
        let mut nodes = match registered(calls) {
            Ok(nodes) => nodes.into_iter().map(|(_, id)| id).collect::<Vec<_>>(),
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
    let mut nodes: Vec<u64> = registered(calls)?.into_iter().map(|(_, id)| id).collect();
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
