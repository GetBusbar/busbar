// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete logical migration groups, independent of native representation.
use super::{HistoricalFact, View};
use crate::{
    archive_source::{ArchiveRows, Grouping},
    legacy::{
        group::LogicalGroup,
        transform::{ACCOUNTING, ARCHIVAL, AUDIT, IDENTITY},
    },
    Error,
};
use busbar_contract::{
    persistence::{
        archive::{Header, Table},
        legacy_row::Row,
    },
    Secret,
};

pub struct FactGroups {
    view: View,
    budget: usize,
}
impl FactGroups {
    pub fn new(view: View, budget: usize) -> Result<Self, Error> {
        if budget == 0 {
            return Err(Error::Bounds);
        }
        Ok(Self { view, budget })
    }
}
fn framed(parts: &[&[u8]]) -> Result<Secret<Vec<u8>>, Error> {
    busbar_kernel::persistence::import_target::records::keys::framed(b'G', parts)
        .map(Secret::new)
        .map_err(|_| Error::Bounds)
}
impl Grouping for FactGroups {
    fn interpretation(&self) -> Option<&View> {
        Some(&self.view)
    }
    fn includes(&self, table: u32) -> bool {
        table == self.view.facts_table()
    }
    fn verify_inventory(&self, source: &mut dyn ArchiveRows, _: usize) -> Result<(), Error> {
        let mut highest = 0;
        let mut allocator = None;
        let seal = crate::seal::lend();
        for ordinal in 0..source.row_count() {
            if source.row_table(ordinal)? != self.view.facts_table() {
                continue;
            }
            if source.row_frame_bytes(ordinal)? > self.budget {
                return Err(Error::Bounds);
            }
            let row = source.read_row(ordinal)?;
            let fact = self.view.decode(row.value.expose(&seal), self.budget)?;
            match fact.fact() {
                HistoricalFact::Key { value, .. } => highest = highest.max(value.revision),
                HistoricalFact::Credential { meta, .. } => highest = highest.max(meta.revision),
                HistoricalFact::Revision(value) if allocator.replace(*value).is_some() => {
                    return Err(Error::Verification);
                }
                _ => {}
            }
        }
        if allocator.unwrap_or(0) < highest {
            return Err(Error::Verification);
        }
        Ok(())
    }
    fn classify(
        &self,
        _: &Header,
        _: &Table,
        native_key: &[u8],
        row: Row<'_>,
    ) -> Result<LogicalGroup, Error> {
        let fact = self.view.decode_row(row, self.budget)?;
        classify(fact.fact(), native_key)
    }
}
pub fn classify(fact: &HistoricalFact, native_key: &[u8]) -> Result<LogicalGroup, Error> {
    let seal = crate::seal::lend();
    let (family, key) = match fact {
        HistoricalFact::Key { value, .. } => (IDENTITY, framed(&[b"O", value.id.as_bytes()])?),
        HistoricalFact::Credential { meta, .. } => {
            (IDENTITY, framed(&[b"O", meta.key_id.as_bytes()])?)
        }
        HistoricalFact::Denial { subject, .. } => (IDENTITY, framed(&[b"D", subject.as_bytes()])?),
        HistoricalFact::Revision(_) => (IDENTITY, framed(&[b"V"])?),
        HistoricalFact::Usage { bucket, window, .. }
        | HistoricalFact::UsageUnit { bucket, window, .. } => (
            ACCOUNTING,
            framed(&[b"U", bucket.as_bytes(), &window.to_be_bytes()])?,
        ),
        HistoricalFact::Metering { bucket, row, .. } => (
            ACCOUNTING,
            framed(&[
                b"M",
                &bucket.to_be_bytes(),
                row.key_id.as_bytes(),
                row.provider.as_bytes(),
                row.model.as_bytes(),
                &row.priced_from_ms.to_be_bytes(),
            ])?,
        ),
        HistoricalFact::MeteringUnit {
            bucket,
            key_id,
            provider,
            model,
            priced_from_ms,
            ..
        } => (
            ACCOUNTING,
            framed(&[
                b"M",
                &bucket.to_be_bytes(),
                key_id.as_bytes(),
                provider.as_bytes(),
                model.as_bytes(),
                &priced_from_ms.to_be_bytes(),
            ])?,
        ),
        HistoricalFact::Audit(record) => (AUDIT, framed(&[b"A", &record.seq.to_be_bytes()])?),
        HistoricalFact::Record { schema, key, .. } if schema == "busbar.journal.v1" => (
            ARCHIVAL,
            crate::legacy::group::journal_group_key(key.expose(&seal))
                .map_err(|_| Error::Corrupt)?,
        ),
        HistoricalFact::Record { schema, key, .. } => (
            ARCHIVAL,
            framed(&[b"R", schema.as_bytes(), key.expose(&seal)])?,
        ),
        HistoricalFact::History {
            kind,
            id,
            parent,
            sequence,
            ..
        } => (
            ARCHIVAL,
            framed(&[
                b"H",
                kind.as_bytes(),
                id.as_bytes(),
                parent.as_deref().unwrap_or("").as_bytes(),
                &sequence.to_be_bytes(),
            ])?,
        ),
        HistoricalFact::Token { kind, token, .. } => (
            ARCHIVAL,
            framed(&[b"T", kind.as_bytes(), token.expose(&seal)])?,
        ),
        HistoricalFact::Receipt { operation, .. } => (ARCHIVAL, framed(&[b"C", operation])?),
        HistoricalFact::EvidenceOnly => (ARCHIVAL, framed(&[b"E", native_key])?),
    };
    Ok(LogicalGroup { family, key })
}
