// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Predicate};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel_audit::{AuditChain, AuditKeySet, AuditRecord};

use super::store_chain::{off_runtime, read_chain, read_chain_beside, wait_for, JournalLane};

pub(super) const NODE_SCHEMA: &str = "busbar.node.v1";

pub(super) const KEYSET_SCHEMA: &str = "busbar.keyset.v1";

const KEYSET_KEY: &[u8] = b"deployment";

const REGISTRY_LIMIT: u32 = 1 << 16;

pub(super) const MINT_CLAIM_KIND: &str = "busbar.mint.v1";

const ID_ATTEMPTS: usize = 16;

fn id_claim(id: u64) -> String {
    format!("node-id:{id:016x}")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn claim(calls: &dyn StoreCalls, token: &str, expires_at: u64) -> Result<bool, String> {
    wait_for(calls.redeem_plane_token(MINT_CLAIM_KIND, token, expires_at, now_secs()))
        .map_err(|f| format!("the store would not answer the minting claim `{token}`: {f}"))
}

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

fn host_key(host: &str) -> Vec<u8> {
    let mut key = b"host:".to_vec();
    key.extend_from_slice(host.as_bytes());
    key
}

fn id_of(value: &RecordBytes) -> Option<u64> {
    let bytes: [u8; 8] = value.as_slice().try_into().ok()?;
    Some(u64::from_be_bytes(bytes)).filter(|&id| id != 0)
}

pub fn node_id(calls: &dyn StoreCalls, host: &str) -> Result<u64, String> {
    let key = host_key(host);
    let get = || registry_get(calls, &key);
    if let Some(id) = get()? {
        return Ok(id);
    }
    let id = mint_id(calls)?;

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

fn registry_get(calls: &dyn StoreCalls, key: &[u8]) -> Result<Option<u64>, String> {
    wait_for(calls.record_get(NODE_SCHEMA, key))
        .map(|value| value.as_ref().and_then(id_of))
        .map_err(|f| format!("the store would not read the node registry: {f}"))
}

fn mint_id(calls: &dyn StoreCalls) -> Result<u64, String> {
    let taken: Vec<u64> = registered(calls)?.into_iter().map(|(_, id)| id).collect();
    for _ in 0..ID_ATTEMPTS {
        let id = u64::from_be_bytes(random()?);

        if id != 0 && !taken.contains(&id) && claim(calls, &id_claim(id), u64::MAX)? {
            return Ok(id);
        }
    }
    Err(format!(
        "the store granted none of {ID_ATTEMPTS} node ids this boot tried to claim"
    ))
}

fn keep_id(calls: &dyn StoreCalls, key: &[u8], id: u64) -> Result<(), String> {
    let value = RecordBytes::new(id.to_be_bytes().to_vec())
        .map_err(|n| format!("a {n}-byte node id is over the slot's bound"))?;
    wait_for(calls.record_put(NODE_SCHEMA, key, &value))
        .map_err(|f| format!("the store would not keep this node's id: {f}"))
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut raw = [0u8; N];
    getrandom::fill(&mut raw).map_err(|_| {
        "the operating system's random source gave no bytes for a node id".to_string()
    })?;
    Ok(raw)
}

fn fresh_node_id(calls: &dyn StoreCalls, host: &str) -> Result<u64, String> {
    let id = mint_id(calls)?;
    let mut key = host_key(host);

    key.push(0);
    key.extend_from_slice(format!("{id:016x}").as_bytes());
    keep_id(calls, &key, id)?;
    Ok(id)
}

#[cfg(not(test))]
const LEASE_TICK: Duration = busbar_kernel::host_records::FLUSH_INTERVAL;
#[cfg(test)]
const LEASE_TICK: Duration = Duration::from_millis(20);

pub(super) const LEASE_REFRESH_TICKS: u32 = 3;

pub const LEASE_TTL_MS: u64 = 3
    * LEASE_REFRESH_TICKS as u64
    * (LEASE_TICK.as_secs() * 1_000 + LEASE_TICK.subsec_millis() as u64);

const LEASE_WATCH: Duration = Duration::from_millis(LEASE_TTL_MS);

const LEASE_POLL: Duration = LEASE_TICK;

const _: () = assert!(LEASE_TTL_MS > 0);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

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

#[cfg(test)]
fn put_lease(calls: &dyn StoreCalls, host: &str, row: LeaseRow) -> Result<(), String> {
    let value = RecordBytes::new(row.bytes())
        .map_err(|n| format!("a {n}-byte lease is over the slot's bound"))?;
    wait_for(calls.record_put(NODE_SCHEMA, &lease_key(host), &value))
        .map_err(|f| format!("the store would not keep this host's lease: {f}"))
}

#[cfg(test)]
pub(super) fn lease_row(calls: &dyn StoreCalls, host: &str) -> Option<([u8; 16], u64)> {
    read_lease(calls, host)
        .expect("the lease reads")
        .map(|row| (row.holder, row.expires_ms))
}

#[cfg(test)]
pub(super) fn set_lease_expiry(calls: &dyn StoreCalls, host: &str, expires_ms: u64) {
    let (holder, _) = lease_row(calls, host).expect("a lease is held");
    put_lease(calls, host, LeaseRow { holder, expires_ms }).expect("the lease is kept");
}

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
    fn predicate(&self, calls: &dyn StoreCalls) -> Result<Option<Predicate>, String> {
        Ok(read_lease(calls, &self.host)?
            .filter(|row| row.holder == self.holder && row.expires_ms != 0)
            .map(|row| Predicate {
                schema: NODE_SCHEMA.into(),
                key: lease_key(&self.host),
                expected: Expected::Bytes(row.bytes()),
            }))
    }

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

fn take_lease(calls: &dyn StoreCalls, host: &str, holder: [u8; 16]) -> Result<bool, String> {
    let mut seen = read_lease(calls, host)?;
    if held_live(seen, &holder, now_ms()) {
        let deadline = Instant::now() + LEASE_WATCH + LEASE_POLL;
        loop {
            std::thread::sleep(LEASE_POLL);
            let now = read_lease(calls, host)?;
            let live = held_live(now, &holder, now_ms());
            if now != seen {
                if live {
                    return Ok(false);
                }
                seen = now;
                break;
            }
            if !live {
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

    pub fn release(&self, calls: &dyn StoreCalls) {
        let Some(lease) = self.lock().take() else {
            return;
        };
        if let Err(why) = lease.release(calls) {
            tracing::warn!(reason = %why, "this node's lease was not released");
        }
    }
}

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
