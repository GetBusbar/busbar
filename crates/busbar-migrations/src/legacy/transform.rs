// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Logical migration rules and native output proof obligations. Source owners
//! supply interpreted facts; physical formats never select core behavior.
use super::super::{Bounds, CORE_FORMAT, Edge, Family, Format, Registry, TargetRow};
use super::*;
use busbar_contract::{Secret, persistence::Address};
use busbar_kernel::persistence::import_target::records::history::{HistoryCollection, HistoryMode};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const IDENTITY: [u8; 16] = *b"legacy.identity1";
pub const ACCOUNTING: [u8; 16] = *b"legacy.account1\0";
pub const ARCHIVAL: [u8; 16] = *b"legacy.archive1\0";
pub const AUDIT: [u8; 16] = *b"legacy.audit.v1\0";

type OutputValue = (Secret<Vec<u8>>, Option<u32>, bool);

#[derive(Clone)]
pub struct RecordBinding {
    pub schema: String,
    pub instance: String,
    pub private: bool,
    pub source_scope: archive::Scope,
}
#[derive(Clone)]
pub struct TokenBinding {
    pub source_kind: String,
    pub instance: String,
    pub kind: String,
}
#[derive(Clone)]
pub struct Collection {
    pub kind: String,
    pub mode: HistoryMode,
    pub retention: busbar_contract::records::Retention,
    pub parent: Option<String>,
}
#[derive(Clone)]
pub struct HistoryBinding {
    pub owner: String,
    pub collections: Vec<Collection>,
}
impl HistoryBinding {
    pub(crate) fn declarations(&self) -> impl Iterator<Item = HistoryCollection<'_>> {
        self.collections.iter().map(|c| HistoryCollection {
            kind: &c.kind,
            mode: c.mode,
            retention: c.retention,
            parent: c.parent.as_deref(),
        })
    }
}
/// Physical adapters use this stable envelope for native PK identities. Values
/// stay the original protected legacy_row frame; no secret is placed in Debug.
pub fn source_key(table: &str, native_key: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    busbar_kernel::persistence::import_target::records::keys::framed(
        b'L',
        &[table.as_bytes(), native_key],
    )
    .map(zeroize::Zeroizing::new)
    .map_err(|_| Error::Range)
}
pub(super) fn source_parts(key: &[u8]) -> Result<(&str, &[u8]), Error> {
    let parts = busbar_kernel::persistence::import_target::records::keys::components(key, b'L')
        .map_err(|_| Error::Invalid)?;
    if parts.len() != 2 {
        return Err(Error::Invalid);
    }
    Ok((
        std::str::from_utf8(parts[0]).map_err(|_| Error::Type)?,
        parts[1],
    ))
}
pub(super) fn hash_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}
pub(crate) fn code_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    for bytes in [
        include_bytes!("mod.rs").as_slice(),
        include_bytes!("group.rs"),
        include_bytes!("journal_binding.rs"),
        include_bytes!("journal.rs"),
        include_bytes!("projection.rs"),
        include_bytes!("recovery.rs"),
        include_bytes!("receipt_codec.rs"),
        include_bytes!("overlay.rs"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/config/overlay_native.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/persistence/recovery_import.rs"
        )),
        include_bytes!("../routes.rs"),
        include_bytes!("../routes/parents.rs"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel-audit/src/digest.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/journal/migration.rs"
        )),
        include_bytes!("../archive_source.rs"),
        include_bytes!("../source_interpretation.rs"),
        include_bytes!("../source_facts.rs"),
        include_bytes!("../source_facts/grouping.rs"),
        include_bytes!("../source_facts/accounting.rs"),
        include_bytes!("fact_transform.rs"),
        include_bytes!("../native_source/interpretation.rs"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/src/persistence/lifecycle/source.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/src/persistence/lifecycle/codec/source.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/src/persistence/archive.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/src/persistence/legacy_row.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/keys.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/partition.rs"
        )),
        include_bytes!("archive.rs"),
        include_bytes!("transform.rs"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/import_target/records.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/raw_recovery.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/ledger_correction.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/ledger_correction_recovery.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/exact_debt.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/src/records/correction.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/audit/mod.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/audit/auditlog.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/audit/stream_registry.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/persistence/identity.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/persistence/ledger.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/persistence/recovery.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/history.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/scoped.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/claims.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/host_records.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/host_record_bootstrap.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/tickets.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/trust/demotion.rs"
        )),
    ] {
        hash_field(&mut hash, bytes);
    }
    hash.finalize().into()
}
pub(crate) fn bind_config(
    hash: &mut Sha256,
    records: &[RecordBinding],
    histories: &[HistoryBinding],
    tokens: &[TokenBinding],
) {
    hash_field(hash, b"compiled-owner-bindings/1");
    hash_field(hash, &(records.len() as u64).to_le_bytes());
    for binding in records {
        hash_field(hash, binding.schema.as_bytes());
        hash_field(hash, binding.instance.as_bytes());
        hash_field(
            hash,
            &[
                u8::from(binding.private),
                u8::from(matches!(binding.source_scope, archive::Scope::Instance)),
            ],
        );
    }
    hash_field(hash, &(tokens.len() as u64).to_le_bytes());
    for token in tokens {
        hash_field(hash, token.source_kind.as_bytes());
        hash_field(hash, token.instance.as_bytes());
        hash_field(hash, token.kind.as_bytes());
    }
    hash_field(hash, &(histories.len() as u64).to_le_bytes());
    for history in histories {
        hash_field(hash, history.owner.as_bytes());
        hash_field(hash, &(history.collections.len() as u64).to_le_bytes());
        for collection in &history.collections {
            hash_field(hash, collection.kind.as_bytes());
            hash_field(hash, &[u8::from(collection.mode == HistoryMode::Append)]);
            hash_field(hash, &collection.retention.code().to_le_bytes());
            hash_field(hash, collection.parent.as_deref().unwrap_or("").as_bytes());
        }
    }
    hash_field(
        hash,
        busbar_kernel::persistence::import_target::records::AUDIT_OWNER.as_bytes(),
    );
}
pub(super) fn archival_authorizes(
    records: &[RecordBinding],
    histories: &[HistoryBinding],
    tokens: &[TokenBinding],
    address: &Address,
) -> bool {
    busbar_kernel::persistence::import_target::journal::authorizes(address)
        || busbar_kernel::persistence::import_target::records::trust::migration_trust_authorizes(address)
        || busbar_kernel::persistence::import_target::records::ticket::legacy_ticket_authorizes(address)
        || busbar_kernel::persistence::import_target::records::recovery::legacy_head_authorizes(address)
        || busbar_kernel::persistence::import_target::records::bootstrap::migration_receipt_authorizes(address)
        || [
            (
                "busbar.principal-transition",
                "busbar.principal-transition.v1",
            ),
            ("busbar.config.overlay", "busbar.config.overlay.v1"),
            ("busbar.admin", "busbar.admin-idempotency"),
        ]
        .iter()
        .any(|(instance, schema)| {
            busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(true, instance, schema, address)
        })
        || [
            "busbar.node.v1",
            "busbar.keyset.v1",
            "busbar.plugin_floor.v1",
            "busbar.release_keys_floor.v1",
        ]
        .iter()
        .any(|schema| {
            busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(true, "busbar.boot", schema, address)
        })
        || busbar_kernel::persistence::import_target::records::scoped::migration_claim_authorizes(
            "busbar.auth-replay",
            "auth-replay",
            address,
        )
        || busbar_kernel::persistence::import_target::records::scoped::migration_claim_authorizes(
            "busbar.admin",
            "busbar.admin-idempotency",
            address,
        )
        || tokens.iter().any(|token| {
            busbar_kernel::persistence::import_target::records::scoped::migration_claim_authorizes(
                &token.instance,
                &token.kind,
                address,
            )
        })
        || records.iter().any(|b| {
            busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(
                b.private,
                &b.instance,
                &b.schema,
                address,
            )
        })
        || histories.iter().any(|h| {
            busbar_kernel::persistence::import_target::records::history::migration_authorizes(&h.owner, h.declarations(), address)
        })
}
pub(super) fn registered_edge(
    source: Format,
    preconditions_digest: [u8; 32],
    families: Vec<Family>,
    bounds: Bounds,
) -> Result<Edge, super::super::Error> {
    let code_digest = code_digest();
    let verification_rule_digest=Sha256::digest(b"busbar.legacy/native-readback+all-source-coverage+exact-mirror+graph+original-receipt-fenced-resolution/1").into();
    let mut identity = Sha256::new();
    hash_field(&mut identity, &code_digest);
    hash_field(&mut identity, &preconditions_digest);
    hash_field(&mut identity, &bounds.items.to_le_bytes());
    hash_field(&mut identity, &bounds.bytes.to_le_bytes());
    hash_field(&mut identity, &source.owner);
    hash_field(&mut identity, &source.physical.to_le_bytes());
    let digest = identity.finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| super::super::Error::Corrupt)?;
    let edge = Edge {
        id,
        source,
        target: CORE_FORMAT,
        code_digest,
        preconditions_digest,
        verification_rule_digest,
        bounds,
        families,
    };
    Registry::new(vec![edge.clone()])?;
    Ok(edge)
}
pub(crate) struct Output {
    rows: BTreeMap<Address, OutputValue>,
    bytes: usize,
    bounds: Bounds,
}
impl Output {
    pub(crate) fn new(bounds: Bounds) -> Self {
        Self {
            rows: BTreeMap::new(),
            bytes: 0,
            bounds,
        }
    }
    pub(crate) fn put(
        &mut self,
        address: Address,
        value: Secret<Vec<u8>>,
        source: Option<u32>,
        shared: bool,
    ) -> Result<(), super::super::Error> {
        let seal = crate::seal::lend();
        if let Some((previous, _, previous_shared)) = self.rows.get(&address) {
            if shared && *previous_shared && previous.expose(&seal) == value.expose(&seal) {
                return Ok(());
            }
            return Err(super::super::Error::Verification);
        }
        self.bytes = self
            .bytes
            .checked_add(16 + address.key.len())
            .and_then(|n| n.checked_add(value.expose(&seal).len()))
            .ok_or(super::super::Error::Bounds)?;
        if self.rows.len() >= self.bounds.items as usize || self.bytes > self.bounds.bytes as usize
        {
            return Err(super::super::Error::Bounds);
        }
        self.rows.insert(address, (value, source, shared));
        Ok(())
    }
    pub(crate) fn canonical(
        &mut self,
        rows: CanonicalRows,
        shared_indices: bool,
    ) -> Result<(), super::super::Error> {
        for (i, (at, value)) in rows.into_iter().enumerate() {
            self.put(at, value, None, shared_indices && i > 0)?;
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Vec<TargetRow> {
        self.rows
            .into_iter()
            .map(|(address, (value, preserved_source, _))| TargetRow {
                address,
                value,
                preserved_source,
            })
            .collect()
    }
}

pub trait NativeProofs: archive::HistoricalReceiptResolution {
    fn parent_present(
        &self,
        provenance: archive::Provenance,
        owner: &str,
        kind: &str,
        id: &str,
    ) -> Result<[u8; 32], super::super::Error>;
    fn historical_audit(
        &self,
        provenance: archive::Provenance,
        record: &busbar_contract::records::AuditRecord,
    ) -> Result<[u8; 32], super::super::Error>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageVerification {
    pub source_rows: u64,
    pub target_rows: u64,
    pub source_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub semantics_digest: [u8; 32],
}
/// Proof provider for a complete owner-interpreted audit inventory. Every
/// original hash, link and sequence is validated; counts alone are insufficient.
pub struct ReleasedProofs {
    provenance: archive::Provenance,
    audit: BTreeMap<u64, busbar_contract::records::AuditRecord>,
    digest: [u8; 32],
}
pub type CompleteAuditProofs = ReleasedProofs;
impl ReleasedProofs {
    pub fn from_complete_facts(
        provenance: archive::Provenance,
        records: Vec<busbar_contract::records::AuditRecord>,
        source_count: u64,
    ) -> Result<Self, crate::Error> {
        if u64::try_from(records.len()).ok() != Some(source_count) {
            return Err(crate::Error::Verification);
        }
        Self::complete(provenance, records)
    }
    fn complete(
        provenance: archive::Provenance,
        records: Vec<busbar_contract::records::AuditRecord>,
    ) -> Result<Self, super::super::Error> {
        let mut audit = BTreeMap::new();
        for record in records {
            if audit.insert(record.seq, record).is_some() {
                return Err(super::super::Error::Verification);
            }
        }
        busbar_kernel::persistence::import_target::records::verify_audit_chain(audit.values())
            .map_err(|_| super::super::Error::Verification)?;
        let mut hash = Sha256::new();
        hash_field(&mut hash, &provenance.dataset);
        hash_field(&mut hash, &provenance.catalogue);
        for record in audit.values() {
            hash_field(&mut hash, &record.seq.to_le_bytes());
            hash_field(&mut hash, record.hash.as_bytes());
            hash_field(&mut hash, record.prev_hash.as_bytes());
        }
        Ok(Self {
            provenance,
            audit,
            digest: hash.finalize().into(),
        })
    }
}
impl archive::HistoricalReceiptResolution for ReleasedProofs {
    fn resolve_original(
        &self,
        _provenance: archive::Provenance,
        _address: &Address,
        _receipt: &archive::Receipt<'_>,
    ) -> Result<[u8; 32], super::super::Error> {
        Err(super::super::Error::ReconciliationRequired)
    }
}
impl NativeProofs for ReleasedProofs {
    fn parent_present(
        &self,
        _provenance: archive::Provenance,
        _owner: &str,
        _kind: &str,
        _id: &str,
    ) -> Result<[u8; 32], super::super::Error> {
        Err(super::super::Error::MissingCapability)
    }
    fn historical_audit(
        &self,
        provenance: archive::Provenance,
        record: &busbar_contract::records::AuditRecord,
    ) -> Result<[u8; 32], super::super::Error> {
        if provenance.dataset != self.provenance.dataset
            || provenance.catalogue != self.provenance.catalogue
            || self.audit.get(&record.seq) != Some(record)
        {
            return Err(super::super::Error::Verification);
        }
        Ok(self.digest)
    }
}
