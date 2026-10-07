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
//! ([`walk_stored_chains`]) but not resumed.
//!
//! ## The deployment keyset
//!
//! The one key that signs the audit chain and the checkpoints is the DEPLOYMENT's (spec #82(a)), so
//! it is kept once in the store ([`KEYSET_SCHEMA`]) and every node on that store signs with it. A
//! node with no data directory mints it once and reads it back on every boot, so `/admin/verify`
//! verifies the records a predecessor signed; with a data directory the file beside the journal is a
//! cache of the same key (see `root::keyset`).

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

/// THIS HOST'S NODE ID: the one the registry holds for `host`, or one minted now, kept, and read
/// back (a concurrent first boot of the same host that kept its own first wins, and both take it).
/// Never zero, and never an id the registry already gives another host.
///
/// # Errors
///
/// The store refused or failed a read or the write, or did not keep what it took.
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
    let taken: Vec<u64> = registered(calls)?.into_iter().map(|(_, id)| id).collect();
    let id = loop {
        let mut raw = [0u8; 8];
        getrandom::fill(&mut raw).map_err(|_| {
            "the operating system's random source gave no bytes for a node id".to_string()
        })?;
        let id = u64::from_be_bytes(raw);
        if id != 0 && !taken.contains(&id) {
            break id;
        }
    };
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

/// Keep the deployment keyset's seed in the store, then read back what it holds: a concurrent first
/// boot that kept its own first is the one every node takes.
///
/// # Errors
///
/// The store refused or failed the write or the read, or kept nothing.
pub fn keep_keyset(calls: &dyn StoreCalls, seed_hex: &str) -> Result<String, String> {
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
