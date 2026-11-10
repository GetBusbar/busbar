// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Small immutable group references for the logical phase. Physical evidence
//! has its own bounded pages, so a legal source group need not fit a copy page.
use super::archive::Provenance;
use crate::{Bounds, Error, Record, TargetRow};
use busbar_contract::{
    persistence::{legacy_row::Row, Address},
    Secret,
};
use sha2::{Digest, Sha256};

pub const PHYSICAL: [u8; 16] = *b"legacy.physical1";
const TAG: &[u8; 8] = b"BBLPROJ1";

/// Public commitment to a complete ordered group inventory, never its protected rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryDigest(pub [u8; 32]);

/// The frozen source implementation binds its full artifact and each ordered
/// original member ordinal/frame hash. This interface never accepts a report's
/// claimed inventory or an independent mutable source connection.
pub trait ProjectionSource: Send + Sync {
    fn fact_view(&self) -> Option<&crate::source_facts::View> {
        None
    }
    fn fact_origin_digest(
        &self,
        _fact: &crate::source_facts::FactRow,
        _budget: usize,
    ) -> Result<crate::source_facts::SourceProofDigest, Error> {
        Err(Error::MissingCapability)
    }

    fn provenance(&self) -> Provenance;
    /// Explicit host memory budget for one logical decoded projection. This is
    /// independent of physical page and destination candidate item limits.
    fn semantic_bytes(&self) -> usize;
    fn inventory_digest(
        &self,
        family: [u8; 16],
        key: &Secret<Vec<u8>>,
    ) -> Result<InventoryDigest, Error>;
    fn visit(
        &self,
        family: [u8; 16],
        key: &Secret<Vec<u8>>,
        row_bytes: usize,
        visitor: &mut dyn FnMut(&Record) -> Result<(), Error>,
    ) -> Result<u64, Error>;
}

pub fn encode_marker(
    group_key: &Secret<Vec<u8>>,
    inventory_digest: [u8; 32],
) -> Result<Secret<Vec<u8>>, Error> {
    let key = group_key.expose(&crate::seal::lend());
    if key.is_empty() || inventory_digest == [0; 32] {
        return Err(Error::Corrupt);
    }
    let mut value = Vec::new();
    value.try_reserve_exact(72).map_err(|_| Error::Bounds)?;
    value.extend_from_slice(TAG);
    value.extend_from_slice(&Sha256::digest(key));
    value.extend_from_slice(&inventory_digest);
    Ok(Secret::new(value))
}

pub fn decode_marker(record: &Record) -> Result<[u8; 32], Error> {
    let seal = crate::seal::lend();
    let value = record.value.expose(&seal);
    let key = &record.key;
    if value.len() != 72
        || value.get(..8) != Some(TAG.as_slice())
        || key.is_empty()
        || value[8..40] != Sha256::digest(key)[..]
        || value[40..] == [0; 32]
    {
        return Err(Error::Corrupt);
    }
    value[40..].try_into().map_err(|_| Error::Corrupt)
}

pub fn verify_marker(
    source: &dyn ProjectionSource,
    family: [u8; 16],
    record: &Record,
) -> Result<(), Error> {
    let key = Secret::new(record.key.clone());
    if decode_marker(record)? != source.inventory_digest(family, &key)?.0 {
        return Err(Error::IdentityMismatch);
    }
    Ok(())
}

pub fn is_marker_page(records: &[Record]) -> bool {
    records
        .first()
        .is_some_and(|record| record.key.first() == Some(&b'G'))
}

pub fn materialize(
    source: &dyn ProjectionSource,
    family: [u8; 16],
    marker: &Record,
    bounds: Bounds,
) -> Result<Vec<Record>, Error> {
    verify_marker(source, family, marker)?;
    let key = Secret::new(marker.key.clone());
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    let count = source.visit(family, &key, bounds.bytes as usize, &mut |row| {
        bytes = bytes
            .checked_add(row.key.len())
            .and_then(|n| n.checked_add(row.value.expose(&crate::seal::lend()).len()))
            .ok_or(Error::Bounds)?;
        if rows.len() >= bounds.items as usize || bytes > bounds.bytes as usize {
            return Err(Error::Bounds);
        }
        rows.try_reserve(1).map_err(|_| Error::Bounds)?;
        rows.push(Record {
            key: row.key.clone(),
            value: Secret::new(row.value.expose(&crate::seal::lend()).clone()),
            preserve_exact: row.preserve_exact,
        });
        Ok(())
    })?;
    if count == 0 || count != rows.len() as u64 {
        return Err(Error::Verification);
    }
    Ok(rows)
}

fn journal_identity(marker: &Record) -> Result<Option<(u64, u64)>, Error> {
    let parts =
        busbar_kernel::persistence::import_target::records::keys::components(&marker.key, b'G')
            .map_err(|_| Error::Corrupt)?;
    if parts.first().copied() != Some(b"J".as_slice()) {
        return Ok(None);
    }
    if parts.len() != 3 {
        return Err(Error::Corrupt);
    }
    let node = u64::from_be_bytes(parts[1].try_into().map_err(|_| Error::Corrupt)?);
    let sequence = u64::from_be_bytes(parts[2].try_into().map_err(|_| Error::Corrupt)?);
    if node == 0 || sequence == 0 {
        return Err(Error::Corrupt);
    }
    Ok(Some((node, sequence)))
}
pub fn is_journal_marker(marker: &Record) -> Result<bool, Error> {
    Ok(journal_identity(marker)?.is_some())
}

/// Pack disjoint logical outputs. An overlapping destination is explicit;
/// callers can end their candidate before that marker and retry it next page.
pub fn project_rows(
    source: &dyn ProjectionSource,
    provenance: Provenance,
    journal: Option<&dyn super::journal_binding::JournalMigration>,
    family: &crate::Family,
    markers: &[Record],
    bounds: Bounds,
    mut convert: impl FnMut(&Record) -> Result<Vec<TargetRow>, Error>,
) -> Result<Vec<TargetRow>, Error> {
    bounds.validate()?;
    let actual = source.provenance();
    if actual.dataset != provenance.dataset || actual.catalogue != provenance.catalogue {
        return Err(Error::IdentityMismatch);
    }
    if markers.len() > bounds.items as usize {
        return Err(Error::Bounds);
    }
    let mut out = super::transform::Output::new(bounds);
    for marker in markers {
        verify_marker(source, family.id, marker)?;
        if marker.preserve_exact {
            return Err(Error::Verification);
        }
        let rows = if let Some((node, sequence)) = journal_identity(marker)? {
            if family.id != super::transform::ARCHIVAL {
                return Err(Error::EdgeMismatch);
            }
            journal
                .ok_or(Error::MissingCapability)?
                .copy_source_group(node, sequence, bounds.bytes as usize)?
                .into_iter()
                .map(|(address, value)| TargetRow {
                    address,
                    value,
                    preserved_source: None,
                })
                .collect()
        } else {
            convert(marker)?
        };
        for row in rows {
            if row.preserved_source.is_some() {
                return Err(Error::Verification);
            }
            out.put(row.address, row.value, None, false)?;
        }
    }
    Ok(out.finish())
}

pub fn physical_rows(
    provenance: Provenance,
    records: &[Record],
    bounds: Bounds,
    mut admit: impl FnMut(&str, &[u8], Row<'_>) -> Result<(), Error>,
) -> Result<Vec<TargetRow>, Error> {
    bounds.validate()?;
    if records.len() > bounds.items as usize {
        return Err(Error::Bounds);
    }
    let seal = crate::seal::lend();
    let mut out = super::transform::Output::new(bounds);
    for (ordinal, record) in records.iter().enumerate() {
        if !record.preserve_exact {
            return Err(Error::Verification);
        }
        let (table, native) =
            super::transform::source_parts(&record.key).map_err(|_| Error::Corrupt)?;
        let row = Row::decode(record.value.expose(&seal)).map_err(|_| Error::Corrupt)?;
        admit(table, native, row)?;
        let address = Address {
            namespace: super::archive::NAMESPACE.0,
            key: busbar_kernel::persistence::import_target::records::keys::framed(
                b'E',
                &[
                    &provenance.dataset,
                    &provenance.catalogue,
                    table.as_bytes(),
                    native,
                ],
            )
            .map_err(|_| Error::Bounds)?,
        };
        out.put(
            address,
            Secret::new(record.value.expose(&seal).clone()),
            Some(ordinal.try_into().map_err(|_| Error::Bounds)?),
            false,
        )?;
    }
    Ok(out.finish())
}

pub fn verify_physical(
    records: &[Record],
    expected: &[TargetRow],
    actual: &[(Address, Secret<Vec<u8>>)],
    rule: &[u8; 32],
) -> Result<super::transform::PageVerification, Error> {
    use super::transform::hash_field;
    use std::collections::BTreeMap;
    if expected.len() != actual.len() {
        return Err(Error::Verification);
    }
    let mut native = BTreeMap::new();
    for (key, value) in actual {
        if native.insert(key, value).is_some() {
            return Err(Error::Verification);
        }
    }
    let seal = crate::seal::lend();
    let mut target = Sha256::new();
    for row in expected {
        if native.get(&row.address).map(|v| v.expose(&seal)) != Some(row.value.expose(&seal)) {
            return Err(Error::Verification);
        }
        hash_field(&mut target, &row.address.namespace);
        hash_field(&mut target, &row.address.key);
        hash_field(&mut target, row.value.expose(&seal));
    }
    let mut source = Sha256::new();
    for row in records {
        hash_field(&mut source, &row.key);
        hash_field(&mut source, row.value.expose(&seal));
    }
    let mut semantics = Sha256::new();
    hash_field(&mut semantics, rule);
    hash_field(&mut semantics, b"exact-physical-evidence/1");
    Ok(super::transform::PageVerification {
        source_rows: records.len() as u64,
        target_rows: expected.len() as u64,
        source_digest: source.finalize().into(),
        target_digest: target.finalize().into(),
        semantics_digest: semantics.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn marker_binds_group_identity_and_original_inventory() {
        let key = Secret::new(b"group-one".to_vec());
        let value = encode_marker(&key, [7; 32]).unwrap();
        let record = Record {
            key: key.expose(&crate::seal::lend()).clone(),
            value,
            preserve_exact: false,
        };
        assert_eq!(decode_marker(&record).unwrap(), [7; 32]);
        let aliased = Record {
            key: b"group-two".to_vec(),
            value: record.value,
            preserve_exact: false,
        };
        assert!(decode_marker(&aliased).is_err());
    }
}
