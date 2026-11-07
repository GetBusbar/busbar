// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Frozen recovery-head inventory backed by verified original journal runs.
//! Only protected group keys and head hashes remain resident; original frames
//! and head values are reread individually. This proves ancestry, never a new
//! executable receipt, business outcome, or append-custody grant.
use super::{
    journal::{JournalPlan, Layout},
    transform::ARCHIVAL,
};
use crate::{archive_source::ArchiveSource, Bounds, Error, Record};
use busbar_contract::{
    persistence::{
        legacy_row::{Cell, Row},
        Address,
    },
    Secret,
};
use busbar_kernel::persistence::import_target::{journal::VerifiedNode, records, recovery::*};
use busbar_kernel_wal::JournalRecord;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Seek},
    sync::Arc,
};

const HEAD_SCHEMA: &[u8] = b"busbar.usage-recovery-head.v1";
struct HeadFact {
    group: Secret<Vec<u8>>,
    digest: [u8; 32],
}
pub struct FrozenRecovery<R> {
    source: Arc<ArchiveSource<R>>,
    journal: Arc<JournalPlan<R>>,
    layout: Layout,
    bounds: Bounds,
    frame_bytes: usize,
    heads: BTreeMap<[u8; 16], HeadFact>,
    digest: [u8; 32],
}
struct ReceiptFact {
    address: Address,
    evidence_digest: [u8; 32],
    historical_digest: Option<[u8; 32]>,
}
/// Comparison-only historical evidence. This type cannot encode or submit a
/// current executable receipt and cannot grant live journal ownership.
pub struct FencedReceiptProofs {
    provenance: super::archive::Provenance,
    receipts: BTreeMap<[u8; 16], ReceiptFact>,
    applied: BTreeMap<Address, (Secret<Vec<u8>>, records::Rows)>,
    digest: [u8; 32],
}
fn bytes(cell: Cell<'_>) -> Option<&[u8]> {
    match cell {
        Cell::Text(v) | Cell::Blob(v) => Some(v),
        _ => None,
    }
}
fn operation(layout: Layout, group: &[u8]) -> Result<Option<[u8; 16]>, Error> {
    let fields = records::keys::components(group, b'G').map_err(|_| Error::Corrupt)?;
    let key = match layout {
        Layout::Sql(profile) => {
            let table = if matches!(
                profile,
                super::Profile::SqliteDev7
                    | super::Profile::SqliteDev8
                    | super::Profile::SqliteDev9
            ) {
                b"schema_records".as_slice()
            } else {
                b"store_records".as_slice()
            };
            if fields.len() != 3 || fields[0] != b"X" || fields[1] != table {
                return Ok(None);
            }
            let native = Row::decode(fields[2]).map_err(|_| Error::Corrupt)?;
            let mut cells = native.cells();
            if cells.len() != 2 {
                return Err(Error::Corrupt);
            }
            if bytes(cells.next().ok_or(Error::Corrupt)?) != Some(HEAD_SCHEMA) {
                return Ok(None);
            }
            bytes(cells.next().ok_or(Error::Corrupt)?).ok_or(Error::Corrupt)?
        }
        Layout::Valkey { .. } => {
            if fields.len() != 3 || fields[0] != b"R" || fields[1] != HEAD_SCHEMA {
                return Ok(None);
            }
            fields[2]
        }
    };
    Ok(Some(key.try_into().map_err(|_| Error::Corrupt)?))
}
impl<R: Read + Seek + Send> FrozenRecovery<R> {
    pub fn verify(
        source: Arc<ArchiveSource<R>>,
        journal: Arc<JournalPlan<R>>,
        layout: Layout,
        bounds: Bounds,
        metadata_bytes: usize,
        frame_bytes: usize,
    ) -> Result<Self, Error> {
        use super::journal_binding::JournalMigration;
        if !super::journal_binding::matches(
            journal.as_ref(),
            super::archive::Provenance {
                dataset: source.identity().dataset,
                catalogue: source.identity().schema_digest,
            },
        ) {
            return Err(Error::IdentityMismatch);
        }
        bounds.validate()?;
        if frame_bytes == 0 || metadata_bytes == 0 {
            return Err(Error::Bounds);
        }
        let mut heads = BTreeMap::new();
        let mut charge = 0usize;
        source.visit_group_keys(ARCHIVAL, &mut |key| {
            let Some(op) = operation(layout, key.expose(&crate::seal::lend()))? else {
                return Ok(());
            };
            charge = charge
                .checked_add(key.expose(&crate::seal::lend()).len())
                .and_then(|v| v.checked_add(256))
                .ok_or(Error::Bounds)?;
            if charge > metadata_bytes {
                return Err(Error::Bounds);
            }
            let value = read_head(&source, layout, key, op, bounds)?;
            let digest = Sha256::digest(value.expose(&crate::seal::lend())).into();
            if heads
                .insert(
                    op,
                    HeadFact {
                        group: Secret::new(key.expose(&crate::seal::lend()).clone()),
                        digest,
                    },
                )
                .is_some()
            {
                return Err(Error::Verification);
            }
            Ok(())
        })?;
        let mut hash = Sha256::new();
        super::transform::hash_field(&mut hash, &journal.descriptor_digest());
        super::transform::hash_field(&mut hash, &source.identity().artifact_digest);
        for (op, fact) in &heads {
            super::transform::hash_field(&mut hash, op);
            super::transform::hash_field(&mut hash, &fact.digest);
        }
        let mut inventory = Self {
            source,
            journal,
            layout,
            bounds,
            frame_bytes,
            heads,
            digest: hash.finalize().into(),
        };
        inventory.visit_selections(&mut |_| Ok(()))?;
        Ok(inventory)
    }
    pub fn descriptor_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn operation_count(&self) -> usize {
        self.heads.len()
    }
    pub fn fenced_receipt_proofs(
        &mut self,
        fence: &crate::CheckedNativeFence,
        metadata_bytes: usize,
    ) -> Result<FencedReceiptProofs, Error> {
        use busbar_kernel::governance::recovery::RecoveryState;
        let source = self.source.identity().clone();
        if !self.source.matches_native_fence(fence)
            || fence.source().dataset.0 != source.dataset
            || fence.source().native_anchor != self.source.header().native_anchor_digest
            || fence.snapshot() != self.source.snapshot().snapshot
            || fence.route_digest() == [0; 32]
            || metadata_bytes == 0
        {
            return Err(Error::FenceRequired);
        }
        let provenance = super::archive::Provenance {
            dataset: source.dataset,
            catalogue: source.schema_digest,
        };
        let mut candidates = BTreeMap::new();
        let mut charge = 0usize;
        self.visit_selections(&mut |selection| {
            if selection.selected.state == RecoveryState::Settled {
                return Ok(());
            }
            charge = charge.checked_add(512).ok_or(Error::Bounds)?;
            if charge > metadata_bytes {
                return Err(Error::Bounds);
            }
            let original = records::original_accounting(&selection.initial)
                .map_err(|_| Error::ReconciliationRequired)?;
            let digests = super::receipt_codec::recognized_digests(&original)?;
            let initial_bytes = zeroize::Zeroizing::new(
                serde_json::to_vec(&selection.initial).map_err(|_| Error::Corrupt)?,
            );
            let selected_bytes = zeroize::Zeroizing::new(
                serde_json::to_vec(&selection.selected).map_err(|_| Error::Corrupt)?,
            );
            let decoded_charge = initial_bytes
                .len()
                .checked_add(selected_bytes.len())
                .and_then(|v| v.checked_mul(64))
                .and_then(|v| v.checked_add(1024))
                .ok_or(Error::Bounds)?;
            charge = charge.checked_add(decoded_charge).ok_or(Error::Bounds)?;
            if charge > metadata_bytes {
                return Err(Error::Bounds);
            }
            if candidates
                .insert(selection.initial.operation_id, (digests, selection.clone()))
                .is_some()
            {
                return Err(Error::Verification);
            }
            Ok(())
        })?;
        let mut receipts = BTreeMap::new();
        self.source.visit_group_keys(ARCHIVAL, &mut |key| {
            if !is_receipt(self.layout, key.expose(&crate::seal::lend()))? {
                return Ok(());
            }
            with_receipt(
                &self.source,
                self.layout,
                key,
                provenance,
                self.bounds,
                &mut |address, receipt| {
                    // Nonjournalled admin/record operations also used store_ops.
                    // Their exact rows are evidence only. Only actual selected
                    // pending debt requires a recognized matching original hash.
                    if let Some((known, _)) = candidates.get(receipt.operation) {
                        if !receipt.completed_shape
                            || !receipt
                                .historical_digest
                                .is_some_and(|actual| known.contains(&actual))
                        {
                            return Err(Error::ReconciliationRequired);
                        }
                    }
                    charge = charge
                        .checked_add(address.key.len())
                        .and_then(|v| v.checked_add(512))
                        .ok_or(Error::Bounds)?;
                    if charge > metadata_bytes {
                        return Err(Error::Bounds);
                    }
                    let evidence_digest = receipt_digest(provenance, &address, &receipt);
                    if receipts
                        .insert(
                            *receipt.operation,
                            ReceiptFact {
                                address,
                                evidence_digest,
                                historical_digest: receipt.historical_digest,
                            },
                        )
                        .is_some()
                    {
                        return Err(Error::Verification);
                    }
                    Ok(())
                },
            )
        })?;
        let mut applied = BTreeMap::new();
        for (_, selection) in candidates.values() {
            let op = selection.initial.operation_id;
            let fact = receipts.get(&op).ok_or(Error::ReconciliationRequired)?;
            let head_fact = self.heads.get(&op).ok_or(Error::Verification)?;
            let head = read_head(&self.source, self.layout, &head_fact.group, op, self.bounds)?;
            if <[u8; 32]>::from(Sha256::digest(head.expose(&crate::seal::lend())))
                != head_fact.digest
            {
                return Err(Error::Verification);
            }
            let evidence = AppliedImportEvidence {
                source_dataset: source.dataset,
                source_snapshot: fence.snapshot(),
                source_content_digest: source.artifact_digest,
                source_schema_digest: source.schema_digest,
                upgrade: fence.upgrade_id(),
                fence_enforcement: fence.enforcement_digest(),
                route: fence.route_digest(),
                receipt_evidence: fact.evidence_digest,
                historical_body_digest: fact
                    .historical_digest
                    .ok_or(Error::ReconciliationRequired)?,
                recovery_closure_digest: self.digest,
            };
            let rows = applied_disposition_rows(
                &selection.initial,
                &selection.selected,
                head.expose(&crate::seal::lend()),
                &evidence,
            )
            .map_err(|_| Error::ReconciliationRequired)?;
            let address =
                records::recovery::legacy_head_address(&op, head.expose(&crate::seal::lend()))
                    .map_err(|_| Error::Verification)?;
            charge = charge
                .checked_add(address.key.len())
                .and_then(|v| v.checked_add(512))
                .ok_or(Error::Bounds)?;
            for (at, value) in &rows {
                charge = charge
                    .checked_add(at.key.len())
                    .and_then(|v| v.checked_add(value.expose(&crate::seal::lend()).len()))
                    .and_then(|v| v.checked_add(256))
                    .ok_or(Error::Bounds)?;
            }
            charge = charge
                .checked_add(head.expose(&crate::seal::lend()).len())
                .ok_or(Error::Bounds)?;
            if charge > metadata_bytes {
                return Err(Error::Bounds);
            }
            if applied.insert(address, (head, rows)).is_some() {
                return Err(Error::Verification);
            }
        }
        let mut hash = Sha256::new();
        super::transform::hash_field(&mut hash, &self.digest);
        super::transform::hash_field(&mut hash, &fence.enforcement_digest());
        // The checked capability requires a fresh native observation. Its
        // challenge/session digest is not a stable semantic checksum across
        // resume; immutable source, enforcement, upgrade and route are.
        super::transform::hash_field(&mut hash, &fence.upgrade_id());
        super::transform::hash_field(&mut hash, &fence.snapshot());
        super::transform::hash_field(&mut hash, &fence.route_digest());
        for (op, fact) in &receipts {
            super::transform::hash_field(&mut hash, op);
            super::transform::hash_field(&mut hash, &fact.evidence_digest);
        }
        Ok(FencedReceiptProofs {
            provenance,
            receipts,
            applied,
            digest: hash.finalize().into(),
        })
    }
    pub fn visit_selections(
        &mut self,
        visitor: &mut dyn FnMut(&RecoverySelection) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut next = self.heads.keys().next().copied();
        while let Some(op) = next {
            let head = self
                .selected_head(&op)
                .map_err(|_| Error::Verification)?
                .ok_or(Error::Verification)?;
            let selection = inspect_recovery_operation(op, head.expose(&crate::seal::lend()), self)
                .map_err(|_| Error::Verification)?;
            visitor(&selection)?;
            next = self
                .heads
                .range((std::ops::Bound::Excluded(op), std::ops::Bound::Unbounded))
                .next()
                .map(|(op, _)| *op);
        }
        Ok(())
    }
}
fn read_head<R: Read + Seek + Send>(
    source: &ArchiveSource<R>,
    layout: Layout,
    key: &Secret<Vec<u8>>,
    operation: [u8; 16],
    bounds: Bounds,
) -> Result<Secret<Vec<u8>>, Error> {
    let mut value = None;
    source.visit_group_rows(
        ARCHIVAL,
        key,
        bounds.bytes as usize,
        &mut |record: &Record| {
            let seal = crate::seal::lend();
            let (table, _) =
                super::transform::source_parts(&record.key).map_err(|_| Error::Corrupt)?;
            let row = Row::decode(record.value.expose(&seal)).map_err(|_| Error::Corrupt)?;
            let bytes = match layout {
                Layout::Sql(_) => {
                    let columns = source
                        .header()
                        .tables
                        .iter()
                        .find(|t| t.name == table)
                        .ok_or(Error::Corrupt)?
                        .columns
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    let mysql = matches!(
                        layout,
                        Layout::Sql(
                            super::Profile::MysqlDev4
                                | super::Profile::MysqlDev5
                                | super::Profile::MysqlDev7
                        )
                    );
                    let (schema, keycol) = if table == "schema_records" {
                        ("schema", "record_key")
                    } else {
                        ("schema_id", if mysql { "rkey" } else { "key" })
                    };
                    let cells =
                        super::Columns::new(mysql, &columns, row, &[schema, keycol, "value"])
                            .map_err(|_| Error::Corrupt)?;
                    if cells.bytes(schema).map_err(|_| Error::Corrupt)? != HEAD_SCHEMA
                        || cells.bytes(keycol).map_err(|_| Error::Corrupt)? != operation
                    {
                        return Err(Error::Verification);
                    }
                    cells.bytes("value").map_err(|_| Error::Corrupt)?
                }
                Layout::Valkey { database, .. } => {
                    let cell = super::valkey::physical(row).map_err(|_| Error::Corrupt)?;
                    if cell.database != database
                        || cell.position != operation
                        || cell.expires_at_ms.is_some()
                    {
                        return Err(Error::Verification);
                    }
                    match cell.kind {
                        super::valkey::PhysicalKind::Hash => cell.value,
                        super::valkey::PhysicalKind::SortedSet if cell.value == b"0" => {
                            return Ok(())
                        }
                        _ => return Err(Error::Verification),
                    }
                }
            };
            records::recovery::legacy_head_address(&operation, bytes)
                .map_err(|_| Error::Verification)?;
            if value.replace(Secret::new(bytes.to_vec())).is_some() {
                return Err(Error::Verification);
            }
            Ok(())
        },
    )?;
    value.ok_or(Error::Verification)
}
impl<R: Read + Seek + Send> RecoveryHistory for FrozenRecovery<R> {
    fn verified_node(&self, node: u64) -> Option<&VerifiedNode> {
        self.journal.verified_node(node)
    }
    fn original(&mut self, node: u64, sequence: u64) -> Result<JournalRecord, RecoveryError> {
        let original = self
            .journal
            .source_frame(node, sequence, self.frame_bytes)
            .map_err(|e| RecoveryError::Invalid(format!("frozen original: {e:?}")))?;
        JournalRecord::decode(&original.body)
            .map_err(|e| RecoveryError::Invalid(format!("frozen BJRN: {e:?}")))
    }
    fn selected_head(
        &mut self,
        operation: &[u8; 16],
    ) -> Result<Option<Secret<Vec<u8>>>, RecoveryError> {
        let Some(fact) = self.heads.get(operation) else {
            return Ok(None);
        };
        let head = read_head(
            &self.source,
            self.layout,
            &fact.group,
            *operation,
            self.bounds,
        )
        .map_err(|e| RecoveryError::Invalid(format!("frozen head: {e:?}")))?;
        if <[u8; 32]>::from(Sha256::digest(head.expose(&crate::seal::lend()))) != fact.digest {
            return Err(RecoveryError::Invalid("frozen head changed".into()));
        }
        Ok(Some(head))
    }
}

fn is_receipt(layout: Layout, group: &[u8]) -> Result<bool, Error> {
    let fields = records::keys::components(group, b'G').map_err(|_| Error::Corrupt)?;
    Ok(match layout {
        Layout::Sql(_) => fields.len() == 3 && fields[0] == b"X" && fields[1] == b"store_ops",
        Layout::Valkey { .. } => {
            fields.len() == 2 && fields[0] == b"T" && fields[1].starts_with(b"busbar:op:")
        }
    })
}
fn with_receipt<R: Read + Seek + Send>(
    source: &ArchiveSource<R>,
    layout: Layout,
    key: &Secret<Vec<u8>>,
    provenance: super::archive::Provenance,
    bounds: Bounds,
    visitor: &mut dyn FnMut(Address, super::archive::Receipt<'_>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut rows = Vec::new();
    source.visit_group_rows(ARCHIVAL, key, bounds.bytes as usize, &mut |row| {
        // Known SQL receipts have one physical row; known Valkey receipts have
        // exactly one header and one hash field. Additional data is unresolved.
        if rows.len() >= 2 {
            return Err(Error::ReconciliationRequired);
        }
        rows.push(Record {
            key: row.key.clone(),
            value: Secret::new(row.value.expose(&crate::seal::lend()).clone()),
            preserve_exact: true,
        });
        Ok(())
    })?;
    let seal = crate::seal::lend();
    match layout {
        Layout::Sql(profile) => {
            if rows.len() != 1 {
                return Err(Error::Verification);
            }
            let (table, native) =
                super::transform::source_parts(&rows[0].key).map_err(|_| Error::Corrupt)?;
            let columns = source
                .header()
                .tables
                .iter()
                .find(|t| t.name == table)
                .ok_or(Error::Corrupt)?
                .columns
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let retained = super::archive::sql(
                profile,
                provenance,
                table,
                &columns,
                native,
                rows[0].value.expose(&seal),
                &[],
            )
            .map_err(|_| Error::Corrupt)?;
            let super::archive::Route::Receipt(receipt) = retained.route else {
                return Err(Error::Verification);
            };
            visitor(retained.address, receipt)
        }
        Layout::Valkey { database, .. } => {
            let mut cells = Vec::new();
            let mut address = None;
            for row in &rows {
                let (table, native) =
                    super::transform::source_parts(&row.key).map_err(|_| Error::Corrupt)?;
                if table != "valkey" {
                    return Err(Error::Corrupt);
                }
                let cell = super::valkey::physical(
                    Row::decode(row.value.expose(&seal)).map_err(|_| Error::Corrupt)?,
                )
                .map_err(|_| Error::Corrupt)?;
                if cell.database != database {
                    return Err(Error::Verification);
                }
                if cell.kind == super::valkey::PhysicalKind::Hash && cell.position == b"b" {
                    address = Some(Address {
                        namespace: super::archive::NAMESPACE.0,
                        key: records::keys::framed(
                            b'E',
                            &[
                                &provenance.dataset,
                                &provenance.catalogue,
                                b"valkey",
                                native,
                            ],
                        )
                        .map_err(|_| Error::Bounds)?,
                    });
                }
                cells.push(cell);
            }
            let receipt = super::valkey_transform::receipt_group(
                &cells,
                Bounds {
                    items: 2,
                    bytes: bounds.bytes,
                },
            )?;
            visitor(address.ok_or(Error::Verification)?, receipt.borrowed())
        }
    }
}
fn receipt_digest(
    provenance: super::archive::Provenance,
    address: &Address,
    receipt: &super::archive::Receipt<'_>,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    for field in [
        b"busbar.original-receipt-evidence/1".as_slice(),
        &provenance.dataset,
        &provenance.catalogue,
        &address.namespace,
        &address.key,
        receipt.operation,
        receipt.body,
        receipt.answer,
    ] {
        super::transform::hash_field(&mut hash, field);
    }
    match receipt.recorded_at {
        Some(v) => {
            hash.update([1]);
            hash.update(v.to_le_bytes());
        }
        None => hash.update([0]),
    }
    match receipt.expires_at_ms {
        Some(v) => {
            hash.update([1]);
            hash.update(v.to_le_bytes());
        }
        None => hash.update([0]),
    }
    hash.finalize().into()
}
impl FencedReceiptProofs {
    pub fn provenance(&self) -> super::archive::Provenance {
        self.provenance
    }
    pub fn descriptor_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn authorizes(&self, address: &Address) -> bool {
        self.applied
            .values()
            .any(|(_, rows)| rows.iter().any(|(at, _)| at == address))
    }
    /// Preserve the selected head exactly and add its owner-encoded Applied
    /// disposition atomically. This never settles a remainder or issues a receipt.
    pub fn record_rows(&self, address: Address, value: &[u8]) -> Result<records::Rows, Error> {
        let seal = crate::seal::lend();
        if let Some((head, rows)) = self.applied.get(&address) {
            if head.expose(&seal).as_slice() != value {
                return Err(Error::Verification);
            }
            return Ok(rows
                .iter()
                .map(|(at, value)| (at.clone(), Secret::new(value.expose(&seal).clone())))
                .collect());
        }
        Ok(vec![(address, Secret::new(value.to_vec()))])
    }
}
impl super::archive::HistoricalReceiptResolution for FencedReceiptProofs {
    fn resolve_original(
        &self,
        provenance: super::archive::Provenance,
        address: &Address,
        receipt: &super::archive::Receipt<'_>,
    ) -> Result<[u8; 32], Error> {
        if provenance.dataset != self.provenance.dataset
            || provenance.catalogue != self.provenance.catalogue
        {
            return Err(Error::IdentityMismatch);
        }
        let fact = self
            .receipts
            .get(receipt.operation)
            .ok_or(Error::ReconciliationRequired)?;
        if &fact.address != address
            || fact.evidence_digest != receipt_digest(provenance, address, receipt)
        {
            return Err(Error::Verification);
        }
        Ok(self.digest)
    }
}
impl super::transform::NativeProofs for FencedReceiptProofs {
    fn parent_present(
        &self,
        _: super::archive::Provenance,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<[u8; 32], Error> {
        Err(Error::MissingCapability)
    }
    fn historical_audit(
        &self,
        _: super::archive::Provenance,
        _: &busbar_contract::records::AuditRecord,
    ) -> Result<[u8; 32], Error> {
        Err(Error::MissingCapability)
    }
}

#[cfg(test)]
mod tests {
    use super::super::archive::{HistoricalReceiptResolution, Receipt};
    use super::*;
    #[test]
    fn nonjournalled_admin_receipt_is_only_exact_opaque_archive_evidence() {
        let provenance = super::super::archive::Provenance {
            dataset: [1; 16],
            catalogue: [2; 32],
        };
        let operation = [3; 16];
        let address = Address {
            namespace: super::super::archive::NAMESPACE.0,
            key: b"exact-native-address".to_vec(),
        };
        let receipt = Receipt {
            operation: &operation,
            body: b"historical-admin-body",
            answer: b"old-record-answer",
            recorded_at: Some(8),
            expires_at_ms: None,
            historical_digest: None,
            completed_shape: false,
        };
        let digest = receipt_digest(provenance, &address, &receipt);
        let proofs = FencedReceiptProofs {
            provenance,
            receipts: BTreeMap::from([(
                operation,
                ReceiptFact {
                    address: address.clone(),
                    evidence_digest: digest,
                    historical_digest: None,
                },
            )]),
            applied: BTreeMap::new(),
            digest: [9; 32],
        };
        assert_eq!(
            proofs
                .resolve_original(provenance, &address, &receipt)
                .unwrap(),
            [9; 32]
        );
        let changed = Receipt {
            answer: b"different-answer",
            ..receipt
        };
        assert!(matches!(
            proofs.resolve_original(provenance, &address, &changed),
            Err(Error::Verification)
        ));
        assert!(!proofs.authorizes(&address));
    }
}
