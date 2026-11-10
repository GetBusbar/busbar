// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Assemble the core-owned overlay protocol from admitted record facts.
//! Root receives only the exact protected document from the frozen capture.
use crate::{archive_source::ArchiveRows, Error, Identity};
use busbar_contract::Secret;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SCHEMA: &str = "busbar.config.overlay.v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u32,
    generation: [u8; 16],
    length: u64,
    digest: [u8; 32],
}
/// Exact active historical document, bound to its frozen source artifact.
/// Unpublished and superseded chunks are never mistaken for the active document.
pub struct FrozenOverlay {
    source: Identity,
    bytes: Secret<Vec<u8>>,
    digest: [u8; 32],
    head_digest: [u8; 32],
}
impl FrozenOverlay {
    pub fn bytes(&self) -> &Secret<Vec<u8>> {
        &self.bytes
    }
    pub fn source(&self) -> &Identity {
        &self.source
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
/// Assemble the active core-owned overlay from admitted logical record facts.
/// The owning reader validates native collections; this consumer understands
/// only the overlay's own head/chunk protocol.
pub fn frozen_overlay_from_facts(
    source: &mut dyn ArchiveRows,
    identity: &Identity,
    budget: usize,
) -> Result<Option<FrozenOverlay>, Error> {
    use busbar_contract::persistence::lifecycle::source::HistoricalFact;
    if budget == 0
        || source.header().owner != identity.format.owner
        || source.header().physical != identity.format.physical
        || source.header().catalogue_digest != identity.schema_digest
    {
        return Err(Error::IdentityMismatch);
    }
    // Public hash metadata indexes guarded original keys. Keeping those keys
    // allows explicit collision refusal without retaining document bytes raw.
    struct Entry {
        key: Secret<Vec<u8>>,
        value: Secret<Vec<u8>>,
    }
    let mut entries = BTreeMap::<[u8; 32], Entry>::new();
    let mut charge = 0usize;
    let seal = crate::seal::lend();
    crate::source_facts::visit(source, budget, &mut |_, fact| {
        let HistoricalFact::Record { schema, key, value } = fact.fact() else {
            return Ok(());
        };
        if schema != SCHEMA {
            return Ok(());
        }
        charge = charge
            .checked_add(key.expose(&seal).len())
            .and_then(|n| n.checked_add(value.expose(&seal).len()))
            .and_then(|n| n.checked_add(256))
            .ok_or(Error::Bounds)?;
        if charge > budget {
            return Err(Error::Bounds);
        }
        let digest: [u8; 32] = Sha256::digest(key.expose(&seal)).into();
        if entries
            .insert(
                digest,
                Entry {
                    key: key.clone(),
                    value: value.clone(),
                },
            )
            .is_some()
        {
            return Err(Error::Verification);
        }
        Ok(())
    })?;
    let lookup = |key: &[u8]| -> Result<Option<&Secret<Vec<u8>>>, Error> {
        let digest: [u8; 32] = Sha256::digest(key).into();
        let Some(entry) = entries.get(&digest) else {
            return Ok(None);
        };
        if entry.key.expose(&seal).as_slice() != key {
            return Err(Error::Verification);
        }
        Ok(Some(&entry.value))
    };
    let Some(raw) = lookup(b"head")? else {
        return Ok(None);
    };
    let head: Head = serde_json::from_slice(raw.expose(&seal)).map_err(|_| Error::Corrupt)?;
    if head.version != 1 || head.length == 0 {
        return Err(Error::Corrupt);
    }
    let length = usize::try_from(head.length).map_err(|_| Error::Bounds)?;
    if charge.checked_add(length).is_none_or(|n| n > budget) {
        return Err(Error::Bounds);
    }
    let mut output = zeroize::Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(length)
        .map_err(|_| Error::Bounds)?;
    for index in 0..length.div_ceil(busbar_contract::MAX_RECORD_BYTES) {
        let mut key = b"chunk:".to_vec();
        key.extend_from_slice(&head.generation);
        key.extend_from_slice(&(index as u64).to_be_bytes());
        let chunk = lookup(&key)?.ok_or(Error::Verification)?.expose(&seal);
        if chunk.len() != (length - output.len()).min(busbar_contract::MAX_RECORD_BYTES) {
            return Err(Error::Verification);
        }
        output.extend_from_slice(chunk);
    }
    if <[u8; 32]>::from(Sha256::digest(&output)) != head.digest {
        return Err(Error::Verification);
    }
    Ok(Some(FrozenOverlay {
        source: identity.clone(),
        bytes: Secret::new(std::mem::take(&mut *output)),
        digest: head.digest,
        head_digest: Sha256::digest(raw.expose(&seal)).into(),
    }))
}

pub const FAMILY: [u8; 16] = *b"legacy.overlay1\0";
/// Immutable derived output. Its original physical evidence is copied separately;
/// each converted chunk and the final head has its own bounded projection marker.
pub struct PreparedOverlay {
    source: Identity,
    rows: Vec<(busbar_contract::persistence::Address, Secret<Vec<u8>>)>,
    digest: [u8; 32],
}
impl PreparedOverlay {
    pub fn prepare(
        original: FrozenOverlay,
        converted: Secret<Vec<u8>>,
        conversion_code_digest: [u8; 32],
        budget: usize,
    ) -> Result<Self, Error> {
        if conversion_code_digest == [0; 32] || budget == 0 {
            return Err(Error::Bounds);
        }
        let seal = crate::seal::lend();
        let mut hash = Sha256::new();
        for field in [
            b"busbar.derived-overlay/1".as_slice(),
            &original.source.dataset,
            &original.source.artifact_digest,
            &original.source.schema_digest,
            &original.digest,
            &original.head_digest,
            &conversion_code_digest,
            &super::transform::code_digest(),
            converted.expose(&seal).as_slice(),
        ] {
            super::transform::hash_field(&mut hash, field);
        }
        let identity: [u8; 32] = hash.finalize().into();
        let generation = identity[..16].try_into().map_err(|_| Error::Corrupt)?;
        let mut rows = Vec::new();
        let mut charge = converted.expose(&seal).len();
        let encoded = busbar_kernel::config::overlay::migration_rows(&converted, generation)
            .map_err(|_| Error::Corrupt)?;
        let mut hash = Sha256::new();
        super::transform::hash_field(&mut hash, &identity);
        for row in encoded {
            let (address, value) = row.map_err(|_| Error::Corrupt)?;
            charge = charge
                .checked_add(address.key.len())
                .and_then(|n| n.checked_add(value.expose(&seal).len()))
                .and_then(|n| n.checked_add(256))
                .ok_or(Error::Bounds)?;
            if charge > budget {
                return Err(Error::Bounds);
            }
            super::transform::hash_field(&mut hash, &address.namespace);
            super::transform::hash_field(&mut hash, &address.key);
            super::transform::hash_field(&mut hash, value.expose(&seal));
            rows.try_reserve(1).map_err(|_| Error::Bounds)?;
            rows.push((address, value));
        }
        super::transform::hash_field(&mut hash, &(rows.len() as u64).to_le_bytes());
        Ok(Self {
            source: original.source,
            rows,
            digest: hash.finalize().into(),
        })
    }
    pub fn source(&self) -> &Identity {
        &self.source
    }
    pub fn descriptor_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn part_count(&self) -> u64 {
        self.rows.len() as u64
    }
    pub fn replaces(&self, address: &busbar_contract::persistence::Address) -> bool {
        busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(
            true,
            "busbar.config.overlay",
            SCHEMA,
            address,
        )
    }
    pub fn authorizes(&self, address: &busbar_contract::persistence::Address) -> bool {
        self.rows.iter().any(|(at, _)| at == address)
    }
    pub fn marker(&self, part: u64) -> Result<crate::Record, Error> {
        if part >= self.part_count() {
            return Err(Error::Bounds);
        }
        let key = overlay_key(part)?;
        let group = Secret::new(key.clone());
        Ok(crate::Record {
            key: key.into(),
            value: super::projection::encode_marker(&group, self.digest)?,
            preserve_exact: false,
        })
    }
    pub fn transform(
        &self,
        markers: &[crate::Record],
        bounds: crate::Bounds,
    ) -> Result<Vec<crate::TargetRow>, Error> {
        bounds.validate()?;
        let mut output = super::transform::Output::new(bounds);
        for marker in markers {
            let parts = busbar_kernel::persistence::import_target::records::keys::components(
                &marker.key,
                b'G',
            )
            .map_err(|_| Error::Corrupt)?;
            if marker.preserve_exact
                || parts.len() != 2
                || parts[0] != b"C"
                || super::projection::decode_marker(marker)? != self.digest
            {
                return Err(Error::Verification);
            }
            let part = u64::from_be_bytes(parts[1].try_into().map_err(|_| Error::Corrupt)?);
            let (address, value) = self
                .rows
                .get(usize::try_from(part).map_err(|_| Error::Bounds)?)
                .ok_or(Error::Bounds)?;
            output.put(
                address.clone(),
                Secret::new(value.expose(&crate::seal::lend()).clone()),
                None,
                false,
            )?;
        }
        Ok(output.finish())
    }
}
fn overlay_key(part: u64) -> Result<Vec<u8>, Error> {
    busbar_kernel::persistence::import_target::records::keys::framed(
        b'G',
        &[b"C", &part.to_be_bytes()],
    )
    .map_err(|_| Error::Bounds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::persistence::{
        archive::{ArchiveRow, Header, Table},
        legacy_row::{self, Cell},
        lifecycle::{
            self as l,
            source::{HistoricalFact, HistoricalFamily, SourceChunk},
        },
    };
    busbar_contract::own_seal!(Own);
    struct Rows {
        header: Header,
        view: crate::source_facts::View,
        rows: Vec<(Vec<u8>, Secret<Vec<u8>>)>,
    }
    impl ArchiveRows for Rows {
        fn interpretation(&self) -> Option<&crate::source_facts::View> {
            Some(&self.view)
        }
        fn row_frame_bytes(&self, ordinal: u64) -> Result<usize, Error> {
            Ok(self.rows[ordinal as usize]
                .1
                .expose(&crate::seal::lend())
                .len())
        }
        fn row_table(&mut self, _: u64) -> Result<u32, Error> {
            Ok(1)
        }
        fn header(&self) -> &Header {
            &self.header
        }
        fn row_count(&self) -> u64 {
            self.rows.len() as u64
        }
        fn read_row(&mut self, ordinal: u64) -> Result<ArchiveRow, Error> {
            let (key, value) = &self.rows[ordinal as usize];
            Ok(ArchiveRow {
                table: 1,
                native_key: Secret::new(key.clone()),
                value: Secret::new(value.expose(&crate::seal::lend()).clone()),
            })
        }
        fn find_native(&self, _: u32, _: &[u8]) -> Result<Option<u64>, Error> {
            Err(Error::UnsupportedPath)
        }
    }
    fn identity() -> Identity {
        Identity {
            dataset: [1; 16],
            format: crate::Format {
                owner: *b"fixture.source01",
                physical: 1,
                logical: 1,
                codec: 1,
            },
            artifact_digest: [2; 32],
            schema_digest: [3; 32],
            product_release: [0; 3],
        }
    }
    fn fixture() -> Rows {
        let bytes = b"{\"version\":1,\"deleted\":[\"removed-owner\"]}";
        let generation = [4; 16];
        let head = serde_json::to_vec(&serde_json::json!({"version":1,"generation":generation,"length":bytes.len(),"digest":<[u8;32]>::from(Sha256::digest(bytes))})).unwrap();
        let mut chunk = b"chunk:".to_vec();
        chunk.extend_from_slice(&generation);
        chunk.extend_from_slice(&0u64.to_be_bytes());
        let reader = l::SourceReader::new(
            l::SourceCodec::HistoricalV1,
            l::DocumentSemantics::Current,
            [9; 32],
        )
        .unwrap();
        let rows = [(b"head".to_vec(), head), (chunk, bytes.to_vec())]
            .into_iter()
            .map(|(key, value)| {
                let fact = l::codec::encode_source_chunk(
                    &SourceChunk {
                        reader,
                        family: HistoricalFamily::Archival,
                        group: Secret::new(key.clone()),
                        sequence: 0,
                        complete: false,
                        evidence: vec![],
                        facts: vec![HistoricalFact::Record {
                            schema: SCHEMA.into(),
                            key: Secret::new(key.clone()),
                            value: Secret::new(value),
                        }],
                    },
                    l::Bounds {
                        items: 16,
                        bytes: 65536,
                    },
                )
                .unwrap();
                let encoded = legacy_row::encode::<Own>(
                    &[Cell::Blob(fact.expose(&crate::seal::lend()))],
                    65536,
                )
                .unwrap();
                (key, Secret::new(encoded.expose_own(&Own::here()).clone()))
            })
            .collect();
        Rows {
            header: Header {
                owner: identity().format.owner,
                physical: 1,
                catalogue_digest: [3; 32],
                native_anchor_digest: [5; 32],
                capture: None,
                tables: ["original", "facts", "chunks"]
                    .into_iter()
                    .map(|name| Table {
                        name: name.into(),
                        columns: vec!["frame".into()],
                        native_layout: vec![],
                    })
                    .collect(),
            },
            view: crate::source_facts::View::new(reader, 2, 1, vec![0]).unwrap(),
            rows,
        }
    }
    #[test]
    fn frozen_overlay_checks_unique_complete_active_generation() {
        let mut source = fixture();
        let original = frozen_overlay_from_facts(&mut source, &identity(), 65536)
            .unwrap()
            .unwrap();
        assert_eq!(
            original.bytes().expose(&crate::seal::lend()).as_slice(),
            b"{\"version\":1,\"deleted\":[\"removed-owner\"]}"
        );
        source.rows.pop();
        assert!(matches!(
            frozen_overlay_from_facts(&mut source, &identity(), 65536),
            Err(Error::Verification)
        ));
        let mut source = fixture();
        let row = &source.rows[0];
        source.rows.push((
            row.0.clone(),
            Secret::new(row.1.expose(&crate::seal::lend()).clone()),
        ));
        assert!(matches!(
            frozen_overlay_from_facts(&mut source, &identity(), 65536),
            Err(Error::Verification)
        ));
    }
    #[test]
    fn converted_overlay_parts_are_bounded_and_head_last() {
        let original = frozen_overlay_from_facts(&mut fixture(), &identity(), 65536)
            .unwrap()
            .unwrap();
        let converted = Secret::new(
            serde_json::to_vec(&serde_json::json!({"version":2,"deleted":["x".repeat(2048)]}))
                .unwrap(),
        );
        let prepared = PreparedOverlay::prepare(original, converted, [7; 32], 65536).unwrap();
        assert!(prepared.part_count() > 3);
        let bounds = crate::Bounds {
            items: 1,
            bytes: 4096,
        };
        for part in 0..prepared.part_count() {
            let marker = prepared.marker(part).unwrap();
            let rows = prepared.transform(&[marker], bounds).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].address.key.ends_with(b"head"),
                part + 1 == prepared.part_count()
            );
        }
        let mut marker = prepared.marker(0).unwrap();
        marker.key = overlay_key(1).unwrap().into();
        assert!(matches!(
            prepared.transform(&[marker], bounds),
            Err(Error::Corrupt) | Err(Error::Verification)
        ));
    }
}
