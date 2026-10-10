// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHO A NODE IS, AND THE KEY IT SIGNS WITH, KEPT IN THE CONFIGURED STORE (ARCHITECT 2026-10-07 H3
//! ruling, follow-up): two facts a node with no data directory has nowhere else to keep.
//!
//! ## The node's identity
//!
//! A journal record is named `(node, node_seq)`, and the store keys every record by that pair. Two
//! nodes numbering under one identity would overwrite each other's records in a shared store, so
//! each node takes a STABLE identity of its own from the store's node registry
//! ([`NODE_SCHEMA`]): one record per host, holding the id minted for that host the first time it
//! booted. A restart on the same host reads the same id back and resumes its own chain. There is no
//! `node_id` configuration key: adding one changes the frozen configuration schema, so the minted
//! id is the only source.
//!
//! The host is the operating system's host name ([`host_identity`]). A deployment whose host name
//! changes on every restart therefore mints a new identity each time, and its predecessor's chain
//! stays in the store under the old one, readable and verified by `/admin/verify`
//! ([`walk_stored_chains`]) but not resumed: the holds that chain left open are not recovered
//! (a known limit, ARCHITECT 2026-10-07).
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

use super::store_chain::{off_runtime, read_chain, wait_for};

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
    let get = || -> Result<Option<u64>, String> {
        wait_for(calls.record_get(NODE_SCHEMA, &key))
            .map(|value| value.as_ref().and_then(id_of))
            .map_err(|f| format!("the store would not read the node registry: {f}"))
    };
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
    let taken: Vec<u64> = registered(calls)?.into_iter().map(|(_, id)| id).collect();
    let mut minted = None;
    for _ in 0..ID_ATTEMPTS {
        let mut raw = [0u8; 8];
        getrandom::fill(&mut raw).map_err(|_| {
            "the operating system's random source gave no bytes for a node id".to_string()
        })?;
        let id = u64::from_be_bytes(raw);
        // ONE HOST PER ID: the id is claimed for good before it is kept.
        if id != 0 && !taken.contains(&id) && claim(calls, &id_claim(id), u64::MAX)? {
            minted = Some(id);
            break;
        }
    }
    let id = minted.ok_or_else(|| {
        format!("the store granted none of {ID_ATTEMPTS} node ids this boot tried to claim")
    })?;
    let value = RecordBytes::new(id.to_be_bytes().to_vec())
        .map_err(|n| format!("a {n}-byte node id is over the slot's bound"))?;
    wait_for(calls.record_put(NODE_SCHEMA, &key, &value))
        .map_err(|f| format!("the store would not keep this node's id: {f}"))?;
    get()?.ok_or_else(|| "the store did not keep this node's id".to_string())
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
    /// What did not hold: a chain that does not verify, an audit record whose digest or link does
    /// not hold, or whose signature does not verify under the deployment keyset.
    pub findings: Vec<String>,
}

/// WALK EVERY CHAIN THE STORE KEEPS — every node the registry names, and `own` — verifying each
/// journal chain and the audit records on it, signatures included, against `keys`. Off any runtime
/// worker where one is waiting: this reads the whole of every chain.
#[must_use]
pub fn walk_stored_chains(calls: &dyn StoreCalls, own: u64, keys: &AuditKeySet) -> StoredWalk {
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
            let records = match read_chain(calls, node) {
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
            let audits: Vec<AuditRecord> = decoded
                .iter()
                .filter_map(|r| super::decode_audit(r).ok().flatten())
                .collect();
            if let Err(broken) = AuditChain::verify_window(&audits) {
                walk.findings
                    .push(format!("node {node}: audit chain: {broken:?}"));
            }
            for record in &audits {
                let Some(key_id) = record.key_id.as_deref() else {
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
