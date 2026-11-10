// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-derived logical rows retain their verified source-chunk provenance.
//! Native tables and column layouts are opaque throughout this view.
use crate::{archive_source::ArchiveRows, Error};
use busbar_contract::{
    persistence::{
        archive,
        legacy_row::{Cell, Row},
        lifecycle::{
            self as l,
            source::{HistoricalFact, SourceChunk},
        },
    },
    Secret,
};
use std::sync::Arc;
pub(crate) mod accounting;
pub mod grouping;

#[derive(Clone, Debug)]
pub struct View {
    reader: l::SourceReader,
    chunks: u32,
    facts: u32,
    original_tables: Arc<[u32]>,
}
impl View {
    pub(crate) fn new(
        reader: l::SourceReader,
        chunks: u32,
        facts: u32,
        original_tables: Vec<u32>,
    ) -> Result<Self, Error> {
        if chunks == facts
            || original_tables
                .iter()
                .any(|table| *table == chunks || *table == facts)
        {
            return Err(Error::Corrupt);
        }
        let mut unique = std::collections::BTreeSet::new();
        if original_tables.iter().any(|table| !unique.insert(*table)) {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            reader,
            chunks,
            facts,
            original_tables: original_tables.into(),
        })
    }
    pub fn reader(&self) -> l::SourceReader {
        self.reader
    }
    pub fn facts_table(&self) -> u32 {
        self.facts
    }
    pub fn chunks_table(&self) -> u32 {
        self.chunks
    }
    pub fn is_original(&self, table: u32) -> bool {
        self.original_tables.contains(&table)
    }
    pub fn original_table(&self, table: u32) -> Result<u32, Error> {
        self.original_tables
            .get(table as usize)
            .copied()
            .ok_or(Error::Corrupt)
    }
    /// Decode only the host's fact projection, never a native plugin row.
    pub fn decode(&self, bytes: &[u8], budget: usize) -> Result<FactRow, Error> {
        self.decode_row(Row::decode(bytes).map_err(|_| Error::Corrupt)?, budget)
    }
    pub fn decode_row(&self, row: Row<'_>, budget: usize) -> Result<FactRow, Error> {
        let mut cells = row.cells();
        let Some(Cell::Blob(encoded)) = cells.next() else {
            return Err(Error::Corrupt);
        };
        if cells.next().is_some() {
            return Err(Error::Corrupt);
        }
        let chunk = l::codec::decode_source_chunk(
            encoded,
            l::Bounds {
                items: u32::MAX,
                bytes: u32::try_from(budget).map_err(|_| Error::Bounds)?,
            },
        )
        .map_err(|error| {
            if error == l::Error::Bounds {
                Error::Bounds
            } else {
                Error::Corrupt
            }
        })?;
        if chunk.reader != self.reader
            || chunk.facts.len() != 1
            || !chunk.evidence.is_empty()
            || chunk.complete
        {
            return Err(Error::Corrupt);
        }
        Ok(FactRow { chunk })
    }
}
/// One projected fact and the source group/sequence which originally supplied it.
pub struct FactRow {
    chunk: SourceChunk,
}
impl FactRow {
    pub fn fact(&self) -> &HistoricalFact {
        &self.chunk.facts[0]
    }
    pub fn into_fact(mut self) -> HistoricalFact {
        self.chunk.facts.remove(0)
    }
    pub fn group(&self) -> &Secret<Vec<u8>> {
        &self.chunk.group
    }
    pub fn sequence(&self) -> u64 {
        self.chunk.sequence
    }
}
/// Traverse only admitted host fact rows. Original physical evidence remains in
/// its distinct tables and never enters the logical decoder.
pub fn visit(
    source: &mut dyn ArchiveRows,
    budget: usize,
    visitor: &mut dyn FnMut(u64, &FactRow) -> Result<(), Error>,
) -> Result<(), Error> {
    let view = source
        .interpretation()
        .ok_or(Error::MissingCapability)?
        .clone();
    let seal = crate::seal::lend();
    for ordinal in 0..source.row_count() {
        if source.row_table(ordinal)? != view.facts {
            continue;
        }
        if source.row_frame_bytes(ordinal)? > budget {
            return Err(Error::Bounds);
        }
        let original = source.read_row(ordinal)?;
        let fact = view.decode(original.value.expose(&seal), budget)?;
        visitor(ordinal, &fact)?;
    }
    Ok(())
}
/// Exact frozen native evidence referenced by a verified source group.
pub struct EvidenceRow {
    pub table: u32,
    pub native_key: Secret<Vec<u8>>,
    pub value_digest: [u8; 32],
}
impl View {
    pub fn evidence(
        &self,
        source: &mut dyn ArchiveRows,
        origin: &FactRow,
        budget: usize,
        visitor: &mut dyn FnMut(EvidenceRow) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let seal = crate::seal::lend();
        let group = origin.group().expose(&seal);
        let mut key = zeroize::Zeroizing::new(Vec::with_capacity(
            group.len().checked_add(17).ok_or(Error::Bounds)?,
        ));
        key.push(match origin.chunk.family {
            l::source::HistoricalFamily::Identity => 0,
            l::source::HistoricalFamily::Accounting => 1,
            l::source::HistoricalFamily::Archival => 2,
            l::source::HistoricalFamily::Audit => 3,
            l::source::HistoricalFamily::Evidence => 4,
        });
        key.extend_from_slice(&(group.len() as u64).to_le_bytes());
        key.extend_from_slice(group);
        let prefix = key.len();
        let mut count = 0u64;
        for sequence in 0..source.row_count() {
            key.truncate(prefix);
            key.extend_from_slice(&sequence.to_le_bytes());
            let ordinal = source
                .find_native(self.chunks, &key)?
                .ok_or(Error::Verification)?;
            if source.row_frame_bytes(ordinal)? > budget {
                return Err(Error::Bounds);
            }
            let original = source.read_row(ordinal)?;
            let row = Row::decode(original.value.expose(&seal)).map_err(|_| Error::Corrupt)?;
            let mut cells = row.cells();
            let Some(Cell::Blob(encoded)) = cells.next() else {
                return Err(Error::Corrupt);
            };
            if cells.next().is_some() {
                return Err(Error::Corrupt);
            }
            let chunk = l::codec::decode_source_chunk(
                encoded,
                l::Bounds {
                    items: u32::MAX,
                    bytes: u32::try_from(budget).map_err(|_| Error::Bounds)?,
                },
            )
            .map_err(|_| Error::Corrupt)?;
            if chunk.reader != self.reader
                || chunk.group != origin.chunk.group
                || chunk.family != origin.chunk.family
                || chunk.sequence != sequence
            {
                return Err(Error::Verification);
            }
            for evidence in chunk.evidence {
                let table = self.original_table(evidence.table)?;
                let at = source
                    .find_native(table, evidence.native_key.expose(&seal))?
                    .ok_or(Error::Verification)?;
                if source.row_frame_bytes(at)? > budget {
                    return Err(Error::Bounds);
                }
                let original = source.read_row(at)?;
                if original.native_key != evidence.native_key
                    || archive::digest(original.value.expose(&seal)) != evidence.value_digest
                {
                    return Err(Error::Verification);
                }
                visitor(EvidenceRow {
                    table,
                    native_key: evidence.native_key,
                    value_digest: evidence.value_digest,
                })?;
                count = count.checked_add(1).ok_or(Error::Bounds)?;
            }
            if chunk.complete {
                return if count != 0 {
                    Ok(())
                } else {
                    Err(Error::Verification)
                };
            }
        }
        Err(Error::Verification)
    }
}

/// Public commitment to the original native evidence and exact interpreted fact.
pub struct SourceProofDigest(pub [u8; 32]);
impl View {
    pub fn origin_digest(
        &self,
        source: &mut dyn ArchiveRows,
        origin: &FactRow,
        budget: usize,
    ) -> Result<SourceProofDigest, Error> {
        let seal = crate::seal::lend();
        let mut digest = archive::Hasher::new();
        digest.update(b"busbar.source.fact-proof/1\0");
        digest.update(&self.reader.decoder_digest());
        let encoded = l::codec::encode_source_chunk(
            &origin.chunk,
            l::Bounds {
                items: u32::MAX,
                bytes: u32::try_from(budget).map_err(|_| Error::Bounds)?,
            },
        )
        .map_err(|_| Error::Bounds)?;
        digest.update(encoded.expose(&seal));
        self.evidence(source, origin, budget, &mut |row| {
            digest.update(&row.table.to_le_bytes());
            digest.update(&(row.native_key.expose(&seal).len() as u64).to_le_bytes());
            digest.update(row.native_key.expose(&seal));
            digest.update(&row.value_digest);
            Ok(())
        })?;
        Ok(SourceProofDigest(digest.finish()))
    }
}

/// Logical-consumer fixture: native admission is exercised separately by the
/// retained-source tests. No plugin format is interpreted by this fixture.
#[cfg(test)]
pub(crate) fn test_archive(
    facts: Vec<HistoricalFact>,
    budget: usize,
) -> Arc<crate::archive_source::ArchiveSource<std::io::Cursor<zeroize::Zeroizing<Vec<u8>>>>> {
    use busbar_contract::persistence::legacy_row;
    busbar_contract::own_seal!(Fixture);
    let reader = l::SourceReader::new(
        l::SourceCodec::HistoricalV1,
        l::DocumentSemantics::Current,
        [9; 32],
    )
    .unwrap();
    let limits = archive::Limits {
        frame_bytes: budget,
        total_bytes: 1 << 24,
        rows: 1000,
        tables: 3,
        columns: 1,
        index_bytes: budget,
    };
    let header = archive::Header {
        owner: *b"fixture.source01",
        physical: 1,
        catalogue_digest: [3; 32],
        native_anchor_digest: [0; 32],
        capture: None,
        tables: ["chunks", "facts", "source"]
            .into_iter()
            .map(|name| archive::Table {
                name: name.into(),
                columns: vec!["frame".into()],
                native_layout: vec![1],
            })
            .collect(),
    };
    let mut writer = archive::Writer::new(Vec::new(), header, limits).unwrap();
    for (ordinal, fact) in facts.into_iter().enumerate() {
        let key = (ordinal as u64).to_be_bytes();
        let chunk = SourceChunk {
            reader,
            family: fact.family(),
            group: Secret::new(key.to_vec()),
            sequence: 0,
            complete: false,
            evidence: vec![],
            facts: vec![fact],
        };
        let encoded = l::codec::encode_source_chunk(
            &chunk,
            l::Bounds {
                items: u32::MAX,
                bytes: budget.try_into().unwrap(),
            },
        )
        .unwrap();
        let row = legacy_row::encode::<Fixture>(
            &[Cell::Blob(encoded.expose(&crate::seal::lend()))],
            budget,
        )
        .unwrap();
        writer
            .write_row(1, &key, row.expose_own(&Fixture::here()))
            .unwrap();
    }
    let bytes = zeroize::Zeroizing::new(writer.finish().unwrap().0);
    let source = archive::read(std::io::Cursor::new(bytes), limits).unwrap();
    let view = View::new(reader, 0, 1, vec![2]).unwrap();
    Arc::new(
        crate::archive_source::ArchiveSource::open(
            source,
            Arc::new(grouping::FactGroups::new(view, budget).unwrap()),
            budget,
            [0; 3],
        )
        .unwrap()
        .with_semantic_budget(budget)
        .unwrap(),
    )
}
