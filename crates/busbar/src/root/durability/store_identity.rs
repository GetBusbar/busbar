// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel_audit::{AuditChain, AuditKeySet, AuditRecord};

pub use busbar_kernel::persistence::boot_identity::{BootIdentity, TakenNode as NativeTakenNode};

pub(crate) async fn take_node(
    owner: &std::sync::Arc<BootIdentity>,
    host: &str,
) -> Result<NativeTakenNode, String> {
    owner.take_node(host).await
}
#[cfg(test)]
pub(crate) async fn stored_keyset(owner: &BootIdentity) -> Result<Option<String>, String> {
    owner.stored_keyset().await
}
#[must_use]
pub(crate) fn host_identity() -> String {
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
pub(crate) struct StoredWalk {
    /// The node ids whose chains were walked.
    pub chains: Vec<u64>,
    /// What did not hold: a chain that does not verify, an audit record that does not decode, whose
    /// digest or link does not hold, or whose signature does not verify under the deployment
    /// keyset, and an unsigned one journalled after its chain's `Bootstrap`.
    pub findings: Vec<String>,
}

pub(crate) async fn walk_stored_chains(
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
    nodes.sort();
    nodes.dedup();
    for node in nodes {
        walk.chains.push(node);
        // Each record is proved by its own version's rule, so the kept rows of an Ephemeral
        // journal cut (SEALING-FIX §3.9) are not needed to judge it.
        match lane.read_node_walk(node, budget).await {
            Ok(walked) => verify_native_audits(node, &walked.rows, keys, &mut walk),
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
    for record in decoded {
        match super::decode_audit(record) {
            Ok(Some(audit)) => audits.push(audit),
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
    // A record proves itself by its version's rule: version 2 (chained, unsigned: every line this
    // build seals) by the window's links above up to a signed head; version 1 by its own signature.
    for record in &audits {
        let key_id = match (record.record_version(), record.key_id.as_deref()) {
            (Some(busbar_kernel_audit::RecordVersion::SignedHead), _) => continue,
            (Some(busbar_kernel_audit::RecordVersion::SignedLine), Some(key_id)) => key_id,
            _ => {
                walk.findings.push(format!(
                    "node {node}: audit record {} carries a signature without its key or a key \
                     without its signature",
                    record.seq
                ));
                continue;
            }
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
