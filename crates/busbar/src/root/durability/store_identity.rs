// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel_audit::{AuditChain, AuditKeySet, AuditRecord};

pub use busbar_kernel::persistence::boot_identity::{BootIdentity, TakenNode as NativeTakenNode};

pub async fn take_node(
    owner: &std::sync::Arc<BootIdentity>,
    host: &str,
) -> Result<NativeTakenNode, String> {
    owner.take_node(host).await
}
#[cfg(test)]
pub async fn stored_keyset(owner: &BootIdentity) -> Result<Option<String>, String> {
    owner.stored_keyset().await
}
#[must_use]
pub fn host_identity() -> String {
    let clean = |s: String| {
        let s = s.trim().to_string();
        (!s.is_empty()).then_some(s)
    };
    let identity = std::env::var("HOSTNAME")
        .ok()
        .and_then(clean)
        .or_else(|| std::env::var("COMPUTERNAME").ok().and_then(clean))
        .or_else(|| {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .and_then(clean)
        })
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .and_then(clean)
        });
    #[cfg(target_os = "macos")]
    let identity = identity.or_else(|| {
        let output = std::process::Command::new("/bin/hostname").output().ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout).ok().and_then(clean)
    });
    identity.unwrap_or_default()
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

pub async fn walk_stored_chains(
    lane: &std::sync::Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
    own: u64,
    keys: &AuditKeySet,
    budget: busbar_kernel::persistence::journal::runtime::BufferBudget,
) -> StoredWalk {
    let mut walk = StoredWalk::default();
    let mut nodes = match lane.registered_nodes().await {
        Ok(nodes) => nodes,
        Err(error) => {
            walk.findings
                .push(format!("native node registry was not verified: {error:?}"));
            Vec::new()
        }
    };
    nodes.push(own);
    nodes.sort_unstable();
    nodes.dedup();
    for node in nodes {
        walk.chains.push(node);
        match lane.read_node_records(node, budget).await {
            Ok(decoded) => verify_native_audits(node, &decoded, keys, &mut walk),
            Err(error) => walk.findings.push(format!(
                "node {node}: native journal was not verified: {error:?}"
            )),
        }
    }
    walk
}

fn verify_native_audits(
    node: u64,
    decoded: &[busbar_kernel_wal::JournalRecord],
    keys: &AuditKeySet,
    walk: &mut StoredWalk,
) {
    let mut audits: Vec<AuditRecord> = Vec::new();
    let mut keyed = false;
    let mut signed_from = None;
    for record in decoded {
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
