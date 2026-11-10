// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Capture the declared logical stream beside independently verified original rows.
use super::*;
use busbar_contract::persistence::{
    legacy_row::{self, Cell},
    lifecycle::{codec, source::SourceChunk},
};
use zeroize::Zeroizing;
busbar_contract::own_seal!(SpoolOwner);

impl NativeSnapshot {
    /// The host-added interpreted table ordinal, available only after complete evidence admission.
    pub fn interpreted_table(&self) -> Option<usize> {
        self.interpretation
            .as_ref()
            .map(|view| view.chunks_table() as usize)
    }

    /// Capture bounded facts from this same retained native source, and admit complete original
    /// coverage before exposing the resulting immutable archive to logical migration.
    #[allow(clippy::too_many_arguments)]
    pub async fn interpret(
        mut self,
        upgrade: &native::Upgrade,
        reader: native::SourceReader,
        bounds: native::Bounds,
        interpretation: native::InterpretationBounds,
        spool: &dyn SpoolFactory,
        limits: archive::Limits,
    ) -> Result<Self, Error> {
        interpretation.validate().map_err(native_error)?;
        if self.interpretation.is_some()
            || self.source != upgrade.source
            || self.snapshot.snapshot != upgrade.snapshot
            || bounds.items == 0
            || bounds.bytes == 0
        {
            return Err(Error::IdentityMismatch);
        }
        let before = fence(self.prepared.as_ref(), upgrade).await?;
        let extra_metadata = self
            .header
            .tables
            .len()
            .checked_mul(24)
            .and_then(|n| n.checked_add(2048))
            .ok_or(Error::Bounds)?;
        let catalogue_budget = limits
            .index_bytes
            .checked_sub(extra_metadata)
            .ok_or(Error::Bounds)?;
        let mut header = Header {
            owner: self.header.owner,
            physical: self.header.physical,
            catalogue_digest: self.source.catalogue_digest,
            native_anchor_digest: [0; 32],
            capture: None,
            tables: copy_catalogue(&self.header.tables, catalogue_budget)?,
        };
        let mut ordinal = 0u64;
        let name = loop {
            let name = format!("busbar_interpreted_{ordinal}");
            if !header.tables.iter().any(|table| table.name == name) {
                break name;
            }
            ordinal = ordinal.checked_add(1).ok_or(Error::Bounds)?;
        };
        let mut layout = Vec::with_capacity(33);
        layout.push(1);
        layout.extend_from_slice(&reader.decoder_digest());
        header.tables.push(Table {
            name: name.clone(),
            columns: vec!["chunk".into()],
            native_layout: layout,
        });
        let mut fact_ordinal = 0u64;
        let fact_name = loop {
            let candidate = format!("busbar_facts_{fact_ordinal}");
            if !header.tables.iter().any(|table| table.name == candidate) {
                break candidate;
            }
            fact_ordinal = fact_ordinal.checked_add(1).ok_or(Error::Bounds)?;
        };
        let mut fact_layout = Vec::with_capacity(33);
        fact_layout.push(2);
        fact_layout.extend_from_slice(&reader.decoder_digest());
        header.tables.push(Table {
            name: fact_name.clone(),
            columns: vec!["fact".into()],
            native_layout: fact_layout,
        });
        header
            .tables
            .sort_by(|left, right| left.name.cmp(&right.name));
        let interpreted = header
            .tables
            .iter()
            .position(|table| table.name == name)
            .ok_or(Error::Corrupt)?;
        let facts_table = header
            .tables
            .iter()
            .position(|table| table.name == fact_name)
            .ok_or(Error::Corrupt)?;
        let mapping = self
            .header
            .tables
            .iter()
            .map(|original| {
                header
                    .tables
                    .binary_search_by(|table| table.name.cmp(&original.name))
                    .map_err(|_| Error::Corrupt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output = spool
            .create()
            .map_err(|_| Error::Backend(busbar_contract::persistence::Failure::Unavailable))?;
        let mut writer = Writer::new(output, header.clone(), limits).map_err(err)?;
        let seal = crate::seal::lend();
        for ordinal in 0..self.archive.summary().rows {
            let original = self.archive.read_row(ordinal).map_err(err)?;
            let table = u32::try_from(*mapping.get(original.table as usize).ok_or(Error::Corrupt)?)
                .map_err(|_| Error::Bounds)?;
            writer
                .write_row(
                    table,
                    original.native_key.expose(&seal),
                    original.value.expose(&seal),
                )
                .map_err(err)?;
        }
        let mut admitted = crate::source_interpretation::SourceCoverage::new(
            reader,
            self.archive.summary().rows,
            interpretation.index_bytes as usize,
        )?;
        let mut coverage = archive::Hasher::new();
        coverage.update(b"busbar.native.interpreted/1\0");
        coverage.update(&self.snapshot.coverage_digest);
        coverage.update(&reader.decoder_digest());
        let mut cursor = None;
        loop {
            let response = call_retained(
                self.prepared.as_ref(),
                Arc::new(native::Request::SourcePage {
                    upgrade: upgrade.reference.clone(),
                    snapshot: upgrade.snapshot,
                    family: native::INTERPRETED_SOURCE,
                    selector: native::SourceSelector::Interpret {
                        reader,
                        bounds: interpretation,
                    },
                    cursor: cursor.clone(),
                    bounds,
                }),
            )
            .await?;
            let native::Response::SourcePage(page) = response.as_ref() else {
                return Err(Error::Corrupt);
            };
            if page.snapshot != upgrade.snapshot
                || page.family != native::INTERPRETED_SOURCE
                || page.source_digest != self.source_digest
                || page.coverage_digest == [0; 32]
                || page.rows.len() > bounds.items as usize
                || (page.rows.is_empty() && page.next.is_some())
                || page
                    .next
                    .as_ref()
                    .is_some_and(|next| cursor.as_ref() == Some(next))
            {
                return Err(Error::IdentityMismatch);
            }
            let mut charge = page
                .rows
                .capacity()
                .checked_mul(std::mem::size_of::<native::SourceRow>())
                .ok_or(Error::Bounds)?;
            for row in &page.rows {
                charge = charge
                    .checked_add(row.native_key.expose(&seal).len())
                    .and_then(|n| n.checked_add(row.value.expose(&seal).len()))
                    .ok_or(Error::Bounds)?;
                if charge > bounds.bytes as usize || row.table != 0 {
                    return Err(Error::Bounds);
                }
                let chunk: SourceChunk = codec::decode_source_chunk(
                    row.value.expose(&seal),
                    native::Bounds {
                        items: u32::MAX,
                        bytes: interpretation.semantic_bytes,
                    },
                )
                .map_err(native_error)?;
                admitted.admit(&mut self, &chunk)?;
                let length = chunk.group.expose(&seal).len();
                let mut key = Zeroizing::new(Vec::with_capacity(
                    length.checked_add(25).ok_or(Error::Bounds)?,
                ));
                key.push(match chunk.family {
                    native::source::HistoricalFamily::Identity => 0,
                    native::source::HistoricalFamily::Accounting => 1,
                    native::source::HistoricalFamily::Archival => 2,
                    native::source::HistoricalFamily::Audit => 3,
                    native::source::HistoricalFamily::Evidence => 4,
                });
                key.extend_from_slice(
                    &u64::try_from(length)
                        .map_err(|_| Error::Bounds)?
                        .to_le_bytes(),
                );
                key.extend_from_slice(chunk.group.expose(&seal));
                key.extend_from_slice(&chunk.sequence.to_le_bytes());
                let encoded = legacy_row::encode::<SpoolOwner>(
                    &[Cell::Blob(row.value.expose(&seal))],
                    limits.frame_bytes,
                )
                .map_err(|_| Error::Bounds)?;
                writer
                    .write_row(
                        u32::try_from(interpreted).map_err(|_| Error::Bounds)?,
                        &key,
                        encoded.expose_own(&SpoolOwner::here()),
                    )
                    .map_err(err)?;
                let prefix = key.len();
                for (index, fact) in chunk.facts.into_iter().enumerate() {
                    key.truncate(prefix);
                    key.extend_from_slice(&(index as u64).to_le_bytes());
                    // This host projection is kept separate from the exact received source chunk.
                    let projected = SourceChunk {
                        reader: chunk.reader,
                        family: chunk.family,
                        group: chunk.group.clone(),
                        sequence: chunk.sequence,
                        complete: false,
                        evidence: vec![],
                        facts: vec![fact],
                    };
                    let encoded = codec::encode_source_chunk(
                        &projected,
                        native::Bounds {
                            items: u32::MAX,
                            bytes: interpretation.semantic_bytes,
                        },
                    )
                    .map_err(native_error)?;
                    let wrapped = legacy_row::encode::<SpoolOwner>(
                        &[Cell::Blob(encoded.expose(&seal))],
                        limits.frame_bytes,
                    )
                    .map_err(|_| Error::Bounds)?;
                    writer
                        .write_row(
                            u32::try_from(facts_table).map_err(|_| Error::Bounds)?,
                            &key,
                            wrapped.expose_own(&SpoolOwner::here()),
                        )
                        .map_err(err)?;
                }
            }
            coverage.update(&page.coverage_digest);
            coverage.update(&(page.rows.len() as u64).to_le_bytes());
            tokio::task::yield_now().await;
            match &page.next {
                Some(next) => cursor = Some(next.clone()),
                None => break,
            }
        }
        admitted.finish()?;
        let after = fence(self.prepared.as_ref(), upgrade).await?;
        if before.enforcement_digest != after.enforcement_digest {
            return Err(Error::FenceRequired);
        }
        let (output, summary) = writer.finish().map_err(err)?;
        let output = output
            .finish()
            .map_err(|_| Error::Backend(busbar_contract::persistence::Failure::Unavailable))?;
        let archive = archive::read(output, limits).map_err(err)?;
        if archive.summary() != summary {
            return Err(Error::Corrupt);
        }
        coverage.update(&summary.digest);
        coverage.update(&summary.rows.to_le_bytes());
        coverage.update(&after.enforcement_digest);
        self.archive = archive;
        self.header = header;
        self.header.native_anchor_digest = self.source.native_anchor;
        self.interpretation = Some(crate::source_facts::View::new(
            reader,
            u32::try_from(interpreted).map_err(|_| Error::Bounds)?,
            u32::try_from(facts_table).map_err(|_| Error::Bounds)?,
            mapping
                .into_iter()
                .map(|table| u32::try_from(table).map_err(|_| Error::Bounds))
                .collect::<Result<Vec<_>, _>>()?,
        )?);
        self.snapshot.content_digest = summary.digest;
        self.snapshot.coverage_digest = coverage.finish();
        Ok(self)
    }
}
