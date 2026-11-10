// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Offline source capability over a fully verified seekable archive. Only
//! bounded offsets and protected logical-group keys remain resident. No paths,
//! source settings or whole-dataset row payloads enter this adapter.

use super::legacy::group::LogicalGroup;
use super::{
    Bounds, Error, Family, Format, Identity, Record, SnapshotEvidence, SourcePage, SourceReader,
    Transform,
};
use async_trait::async_trait;
use busbar_contract::{
    Secret,
    persistence::{
        archive::{self, Header, Table, VerifiedArchive},
        legacy_row::Row,
    },
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek},
    sync::{Arc, Mutex, Weak},
};

/// Compiled grouping policy. Operator documents never select executable code.
pub trait ArchiveRows {
    fn row_frame_bytes(&self, _ordinal: u64) -> Result<usize, Error> {
        Err(Error::MissingCapability)
    }
    fn interpretation(&self) -> Option<&crate::source_facts::View> {
        None
    }
    fn row_table(&mut self, ordinal: u64) -> Result<u32, Error> {
        Ok(self.read_row(ordinal)?.table)
    }
    fn header(&self) -> &Header;
    fn row_count(&self) -> u64;
    fn read_row(&mut self, ordinal: u64) -> Result<archive::ArchiveRow, Error>;
    fn find_native(&self, table: u32, native_key: &[u8]) -> Result<Option<u64>, Error>;
}
fn archive_error(error: archive::Error) -> Error {
    match error {
        archive::Error::Budget | archive::Error::Allocation => Error::Bounds,
        _ => Error::Corrupt,
    }
}
impl<R: Read + Seek> ArchiveRows for VerifiedArchive<R> {
    fn row_frame_bytes(&self, ordinal: u64) -> Result<usize, Error> {
        VerifiedArchive::row_frame_bytes(self, ordinal).map_err(archive_error)
    }
    fn row_table(&mut self, ordinal: u64) -> Result<u32, Error> {
        VerifiedArchive::row_table(self, ordinal).map_err(archive_error)
    }
    fn header(&self) -> &Header {
        self.header()
    }
    fn row_count(&self) -> u64 {
        self.summary().rows
    }
    fn read_row(&mut self, ordinal: u64) -> Result<archive::ArchiveRow, Error> {
        self.read_row(ordinal).map_err(archive_error)
    }
    fn find_native(&self, table: u32, key: &[u8]) -> Result<Option<u64>, Error> {
        self.find_native(table, key).map_err(archive_error)
    }
}
pub trait Grouping: Send + Sync {
    fn interpretation(&self) -> Option<&crate::source_facts::View> {
        None
    }
    fn includes(&self, _table: u32) -> bool {
        true
    }
    fn verify_inventory(
        &self,
        _source: &mut dyn ArchiveRows,
        _metadata_bytes: usize,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn classify(
        &self,
        header: &Header,
        table: &Table,
        native_key: &[u8],
        row: Row<'_>,
    ) -> Result<LogicalGroup, Error>;
}
fn copy_header(header: &Header, budget: usize) -> Result<(Header, usize), Error> {
    let mut charge = std::mem::size_of::<Header>();
    charge = charge
        .checked_add(
            header
                .tables
                .len()
                .checked_mul(std::mem::size_of::<Table>())
                .ok_or(Error::Bounds)?,
        )
        .ok_or(Error::Bounds)?;
    for table in &header.tables {
        charge = charge
            .checked_add(table.name.len())
            .and_then(|n| n.checked_add(table.native_layout.len()))
            .and_then(|n| {
                n.checked_add(
                    table
                        .columns
                        .len()
                        .checked_mul(std::mem::size_of::<String>())?,
                )
            })
            .ok_or(Error::Bounds)?;
        for column in &table.columns {
            charge = charge.checked_add(column.len()).ok_or(Error::Bounds)?;
        }
    }
    if charge > budget {
        return Err(Error::Bounds);
    }
    let string = |s: &str| -> Result<String, Error> {
        let mut out = String::new();
        out.try_reserve_exact(s.len()).map_err(|_| Error::Bounds)?;
        out.push_str(s);
        Ok(out)
    };
    let mut tables = Vec::new();
    tables
        .try_reserve_exact(header.tables.len())
        .map_err(|_| Error::Bounds)?;
    for table in &header.tables {
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(table.columns.len())
            .map_err(|_| Error::Bounds)?;
        for column in &table.columns {
            columns.push(string(column)?);
        }
        let mut native_layout = Vec::new();
        native_layout
            .try_reserve_exact(table.native_layout.len())
            .map_err(|_| Error::Bounds)?;
        native_layout.extend_from_slice(&table.native_layout);
        tables.push(Table {
            name: string(&table.name)?,
            columns,
            native_layout,
        });
    }
    Ok((
        Header {
            owner: header.owner,
            physical: header.physical,
            catalogue_digest: header.catalogue_digest,
            native_anchor_digest: header.native_anchor_digest,
            capture: header.capture.clone(),
            tables,
        },
        charge,
    ))
}
struct Member {
    family: [u8; 16],
    group: Secret<Vec<u8>>,
    ordinal: u64,
}

type GroupVisitor<'a> = dyn FnMut(&Secret<Vec<u8>>) -> Result<(), Error> + 'a;

pub struct ArchiveSource<R> {
    archive: Mutex<VerifiedArchive<R>>,
    interpretation: Option<crate::source_facts::View>,
    header: Header,
    members: Vec<Member>,
    identity: Identity,
    snapshot: SnapshotEvidence,
    output_budget: Mutex<Option<Weak<dyn Transform>>>,
    semantic_bytes: usize,
    overlay: Mutex<Option<Arc<super::legacy::overlay::PreparedOverlay>>>,
    /// RAII ownership keeps actual native fences/connections alive through projection.
    _native_owner: Option<Arc<dyn busbar_contract::persistence::lifecycle::PreparedStore>>,
    native_identity: Option<busbar_contract::persistence::lifecycle::SourceIdentity>,
}
impl<R> std::fmt::Debug for ArchiveSource<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveSource")
            .field("identity", &self.identity)
            .field("rows", &self.members.len())
            .finish_non_exhaustive()
    }
}
impl<R: Read + Seek + Send> ArchiveSource<R> {
    /// The archive has already verified its whole stream. Each source row is
    /// read under wiping custody only while computing one protected group key.
    /// `group_index_bytes` is additional to archive Limits::index_bytes.
    pub fn open(
        mut archive: VerifiedArchive<R>,
        grouping: Arc<dyn Grouping>,
        group_index_bytes: usize,
        product_release: [u32; 3],
    ) -> Result<Self, Error> {
        let summary = archive.summary();
        let (header, mut charge) = copy_header(archive.header(), group_index_bytes)?;
        grouping.verify_inventory(&mut archive, group_index_bytes - charge)?;
        let format = Format {
            owner: header.owner,
            physical: header.physical,
            logical: 1,
            codec: archive::VERSION,
        };
        let mut members = Vec::new();
        let seal = crate::seal::lend();
        for ordinal in 0..summary.rows {
            if !grouping.includes(archive.row_table(ordinal).map_err(archive_error)?) {
                continue;
            }
            // Admit metadata bookkeeping before allocating it; row/group scratch
            // is separately bounded by the archive's one-frame limit.
            charge = charge
                .checked_add(std::mem::size_of::<Member>())
                .ok_or(Error::Bounds)?;
            if charge > group_index_bytes {
                return Err(Error::Bounds);
            }
            let row = archive.read_row(ordinal).map_err(|_| Error::Corrupt)?;
            let table = header
                .tables
                .get(row.table as usize)
                .ok_or(Error::Corrupt)?;
            let group = grouping.classify(
                &header,
                table,
                row.native_key.expose(&seal),
                Row::decode(row.value.expose(&seal)).map_err(|_| Error::Corrupt)?,
            )?;
            if group.family == [0; 16] {
                return Err(Error::Corrupt);
            }
            charge = charge
                .checked_add(group.key.expose(&seal).capacity())
                .ok_or(Error::Bounds)?;
            if charge > group_index_bytes {
                return Err(Error::Bounds);
            }
            members.try_reserve_exact(1).map_err(|_| Error::Bounds)?;
            members.push(Member {
                family: group.family,
                group: group.key,
                ordinal,
            });
        }
        members.sort_unstable_by(|a, b| {
            a.family
                .cmp(&b.family)
                .then_with(|| a.group.expose(&seal).cmp(b.group.expose(&seal)))
                .then_with(|| a.ordinal.cmp(&b.ordinal))
        });
        let mut coverage = Sha256::new();
        coverage.update(b"busbar.archive.groups.v1\0");
        coverage.update(summary.digest);
        for member in &members {
            coverage.update(member.family);
            coverage.update((member.group.expose(&seal).len() as u64).to_le_bytes());
            coverage.update(member.group.expose(&seal));
            coverage.update(member.ordinal.to_le_bytes());
        }
        let dataset: [u8; 16] = summary.digest[..16]
            .try_into()
            .map_err(|_| Error::Corrupt)?;
        if dataset == [0; 16] {
            return Err(Error::Corrupt);
        }
        let identity = Identity {
            dataset,
            format,
            artifact_digest: summary.digest,
            schema_digest: summary.layout_digest,
            product_release,
        };
        let snapshot = SnapshotEvidence {
            source: dataset,
            snapshot: dataset,
            content_digest: summary.digest,
            coverage_digest: coverage.finalize().into(),
        };
        Ok(Self {
            archive: Mutex::new(archive),
            interpretation: grouping.interpretation().cloned(),
            header,
            members,
            identity,
            snapshot,
            output_budget: Mutex::new(None),
            semantic_bytes: 0,
            overlay: Mutex::new(None),
            _native_owner: None,
            native_identity: None,
        })
    }
    /// Bind batching to the same compiled deterministic transform used by migration.
    /// Costing runs before candidate preparation and never splits a logical group.
    pub fn with_output_budget(self, transform: &Arc<dyn Transform>) -> Result<Self, Error> {
        self.bind_output_budget(Arc::downgrade(transform))?;
        Ok(self)
    }
    pub fn bind_output_budget(&self, transform: Weak<dyn Transform>) -> Result<(), Error> {
        let strong = transform.upgrade().ok_or(Error::MissingCapability)?;
        if strong.edge().source != self.identity.format {
            return Err(Error::IdentityMismatch);
        }
        strong.edge().bounds.validate()?;
        let mut current = self.output_budget.lock().map_err(|_| Error::Corrupt)?;
        if let Some(previous) = current.as_ref() {
            if !Weak::ptr_eq(previous, &transform) {
                return Err(Error::IdentityMismatch);
            }
        } else {
            *current = Some(transform);
        }
        Ok(())
    }
    fn output_transform(&self) -> Result<Option<Arc<dyn Transform>>, Error> {
        self.output_budget
            .lock()
            .map_err(|_| Error::Corrupt)?
            .as_ref()
            .map(|weak| weak.upgrade().ok_or(Error::MissingCapability))
            .transpose()
    }
    pub fn bind_overlay(
        &self,
        overlay: Arc<super::legacy::overlay::PreparedOverlay>,
    ) -> Result<(), Error> {
        if overlay.source() != &self.identity {
            return Err(Error::IdentityMismatch);
        }
        let mut existing = self.overlay.lock().map_err(|_| Error::Corrupt)?;
        if existing
            .as_ref()
            .is_some_and(|old| old.descriptor_digest() != overlay.descriptor_digest())
        {
            return Err(Error::IdentityMismatch);
        }
        *existing = Some(overlay);
        Ok(())
    }
    pub fn with_semantic_budget(mut self, bytes: usize) -> Result<Self, Error> {
        if bytes == 0 {
            return Err(Error::Bounds);
        }
        self.semantic_bytes = bytes;
        Ok(self)
    }
    pub(crate) fn with_native_binding(
        mut self,
        source: busbar_contract::persistence::lifecycle::SourceIdentity,
        snapshot: SnapshotEvidence,
        owner: Arc<dyn busbar_contract::persistence::lifecycle::PreparedStore>,
    ) -> Result<Self, Error> {
        let format = source.format.ok_or(Error::IdentityMismatch)?;
        if source.dataset.0 == [0; 16]
            || source.native_anchor == [0; 32]
            || snapshot.source != source.dataset.0
            || snapshot.snapshot == [0; 16]
            || snapshot.content_digest != self.identity.artifact_digest
            || format.owner != self.header.owner
            || format.physical != self.header.physical
            || format.codec != 1
            || !matches!(format.logical, 0 | 1)
        {
            return Err(Error::IdentityMismatch);
        }
        self.identity.dataset = source.dataset.0;
        self.identity.schema_digest = self.header.catalogue_digest;
        self.snapshot = snapshot;
        self.header.native_anchor_digest = source.native_anchor;
        self.native_identity = Some(source);
        self._native_owner = Some(owner);
        Ok(self)
    }
    pub(crate) fn matches_native_fence(&self, fence: &crate::CheckedNativeFence) -> bool {
        self.native_identity.as_ref() == Some(fence.source())
            && self.snapshot.snapshot == fence.snapshot()
            && self._native_owner.is_some()
    }
    pub fn interpretation(&self) -> Option<&crate::source_facts::View> {
        self.interpretation.as_ref()
    }
    pub fn fact_origin_digest(
        &self,
        fact: &crate::source_facts::FactRow,
        budget: usize,
    ) -> Result<crate::source_facts::SourceProofDigest, Error> {
        let view = self
            .interpretation
            .as_ref()
            .ok_or(Error::MissingCapability)?;
        let mut archive = self.archive.lock().map_err(|_| Error::Corrupt)?;
        view.origin_digest(&mut *archive, fact, budget)
    }
    pub fn visit_fact_evidence(
        &self,
        fact: &crate::source_facts::FactRow,
        budget: usize,
        visitor: &mut dyn FnMut(crate::source_facts::EvidenceRow) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let view = self
            .interpretation
            .as_ref()
            .ok_or(Error::MissingCapability)?;
        let mut archive = self.archive.lock().map_err(|_| Error::Corrupt)?;
        view.evidence(&mut *archive, fact, budget, visitor)
    }
    pub fn identity(&self) -> Identity {
        self.identity.clone()
    }
    pub fn snapshot(&self) -> SnapshotEvidence {
        self.snapshot.clone()
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    /// Visit each distinct protected group key without allocating a second index.
    pub fn visit_group_keys(
        &self,
        family: [u8; 16],
        visitor: &mut GroupVisitor<'_>,
    ) -> Result<(), Error> {
        let seal = crate::seal::lend();
        let begin = self.members.partition_point(|m| m.family < family);
        let end = self.members.partition_point(|m| m.family <= family);
        let mut previous: Option<&Secret<Vec<u8>>> = None;
        for member in &self.members[begin..end] {
            if previous.is_none_or(|key| key.expose(&seal) != member.group.expose(&seal)) {
                visitor(&member.group)?;
                previous = Some(&member.group);
            }
        }
        Ok(())
    }
    /// Stream a complete logical group using one explicitly bounded wiping row.
    /// No whole-group payload count/byte cap is imposed; the metadata index remains bounded.
    pub fn visit_group_rows(
        &self,
        family: [u8; 16],
        key: &Secret<Vec<u8>>,
        row_bytes: usize,
        visitor: &mut dyn FnMut(&Record) -> Result<(), Error>,
    ) -> Result<u64, Error> {
        if row_bytes == 0 {
            return Err(Error::Bounds);
        }
        let seal = crate::seal::lend();
        let compare = |member: &Member| {
            member
                .family
                .cmp(&family)
                .then_with(|| member.group.expose(&seal).cmp(key.expose(&seal)))
        };
        let begin = self.members.partition_point(|m| compare(m).is_lt());
        let end = self.members.partition_point(|m| !compare(m).is_gt());
        let mut count = 0u64;
        for member in &self.members[begin..end] {
            let row = {
                let mut archive = self.archive.lock().map_err(|_| Error::Corrupt)?;
                let table = archive.row_table(member.ordinal).map_err(archive_error)?;
                let table = self
                    .header
                    .tables
                    .get(table as usize)
                    .ok_or(Error::Corrupt)?;
                let charge = archive
                    .row_frame_bytes(member.ordinal)
                    .map_err(archive_error)?
                    .checked_add(table.name.len())
                    .and_then(|n| n.checked_add(std::mem::size_of::<Record>()))
                    .ok_or(Error::Bounds)?;
                if charge > row_bytes {
                    return Err(Error::Bounds);
                }
                archive.read_row(member.ordinal).map_err(archive_error)?
            };
            let table = self
                .header
                .tables
                .get(row.table as usize)
                .ok_or(Error::Corrupt)?;
            let record = Record {
                key: super::legacy::transform::source_key(
                    &table.name,
                    row.native_key.expose(&seal),
                )
                .map_err(|_| Error::Corrupt)?,
                value: row.value,
                preserve_exact: true,
            };
            visitor(&record)?;
            count = count.checked_add(1).ok_or(Error::Bounds)?;
        }
        Ok(count)
    }
    /// Reread one complete logical group from its immutable indexed row frames.
    pub fn read_group_sync(
        &self,
        family: [u8; 16],
        key: &Secret<Vec<u8>>,
        bounds: Bounds,
    ) -> Result<Vec<Record>, Error> {
        bounds.validate()?;
        let seal = crate::seal::lend();
        let compare = |member: &Member| {
            member
                .family
                .cmp(&family)
                .then_with(|| member.group.expose(&seal).cmp(key.expose(&seal)))
        };
        let begin = self.members.partition_point(|m| compare(m).is_lt());
        let end = self.members.partition_point(|m| !compare(m).is_gt());
        let members = &self.members[begin..end];
        if members.len() > bounds.items as usize {
            return Err(Error::Bounds);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(members.len())
            .map_err(|_| Error::Bounds)?;
        let mut bytes = 0usize;
        let mut archive = self.archive.lock().map_err(|_| Error::Corrupt)?;
        for member in members {
            let row = archive.read_row(member.ordinal).map_err(archive_error)?;
            let table = self
                .header
                .tables
                .get(row.table as usize)
                .ok_or(Error::Corrupt)?;
            let key =
                super::legacy::transform::source_key(&table.name, row.native_key.expose(&seal))
                    .map_err(|_| Error::Corrupt)?;
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(row.value.expose(&seal).len()))
                .ok_or(Error::Bounds)?;
            if bytes > bounds.bytes as usize {
                return Err(Error::Bounds);
            }
            records.push(Record {
                key,
                value: row.value,
                preserve_exact: true,
            });
        }
        Ok(records)
    }
}
impl<R: Read + Seek + Send> ArchiveSource<R> {
    fn target_cost(
        &self,
        transform: &dyn Transform,
        family: &Family,
        rows: &Vec<super::TargetRow>,
        bounds: Bounds,
    ) -> Result<usize, Error> {
        let seal = crate::seal::lend();
        let mut bytes = rows
            .capacity()
            .checked_mul(std::mem::size_of::<super::TargetRow>())
            .ok_or(Error::Bounds)?;
        for row in rows {
            if !transform.authorize(family, &row.address) {
                return Err(Error::Verification);
            }
            bytes = bytes
                .checked_add(row.address.key.capacity())
                .and_then(|n| n.checked_add(row.value.expose(&seal).capacity()))
                .ok_or(Error::Bounds)?;
        }
        if rows.len() > bounds.items as usize || bytes > bounds.bytes as usize {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }
    fn page_cost(
        &self,
        family: &Family,
        records: &Vec<Record>,
        bounds: Bounds,
        output_budget: Option<&dyn Transform>,
    ) -> Result<(), Error> {
        let seal = crate::seal::lend();
        let mut bytes = records
            .capacity()
            .checked_mul(std::mem::size_of::<Record>())
            .ok_or(Error::Bounds)?;
        for record in records {
            bytes = bytes
                .checked_add(record.key.capacity())
                .and_then(|n| n.checked_add(record.value.expose(&seal).capacity()))
                .ok_or(Error::Bounds)?;
        }
        if let Some(transform) = output_budget {
            let rows = transform.transform(family, records, bounds)?;
            bytes = bytes
                .checked_add(self.target_cost(transform, family, &rows, bounds)?)
                .ok_or(Error::Bounds)?;
        }
        if records.len() > bounds.items as usize || bytes > bounds.bytes as usize {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    fn physical_page(
        &self,
        snapshot: &SnapshotEvidence,
        family: &Family,
        after: u64,
        bounds: Bounds,
        output_budget: Option<&dyn Transform>,
    ) -> Result<SourcePage, Error> {
        let total = self
            .archive
            .lock()
            .map_err(|_| Error::Corrupt)?
            .summary()
            .rows;
        if after > total {
            return Err(Error::Bounds);
        }
        let seal = crate::seal::lend();
        let mut records = Vec::new();
        let mut next = after;
        while next < total && records.len() < bounds.items as usize {
            let row = {
                let mut archive = self.archive.lock().map_err(|_| Error::Corrupt)?;
                let table = archive.row_table(next).map_err(archive_error)?;
                if self
                    .interpretation
                    .as_ref()
                    .is_some_and(|view| !view.is_original(table))
                {
                    next += 1;
                    continue;
                }
                let table = self
                    .header
                    .tables
                    .get(table as usize)
                    .ok_or(Error::Corrupt)?;
                let row_bytes = archive
                    .row_frame_bytes(next)
                    .map_err(archive_error)?
                    .checked_add(table.name.len())
                    .and_then(|n| n.checked_add(std::mem::size_of::<Record>()))
                    .ok_or(Error::Bounds)?;
                if row_bytes > bounds.bytes as usize {
                    if records.is_empty() {
                        return Err(Error::Bounds);
                    }
                    break;
                }
                archive.read_row(next).map_err(archive_error)?
            };
            let table = self
                .header
                .tables
                .get(row.table as usize)
                .ok_or(Error::Corrupt)?;
            records.try_reserve_exact(1).map_err(|_| Error::Bounds)?;
            records.push(Record {
                key: super::legacy::transform::source_key(
                    &table.name,
                    row.native_key.expose(&seal),
                )
                .map_err(|_| Error::Corrupt)?,
                value: row.value,
                preserve_exact: true,
            });
            match self.page_cost(family, &records, bounds, output_budget) {
                Ok(()) => next += 1,
                Err(Error::Bounds) if records.len() > 1 => {
                    records.pop();
                    records.shrink_to_fit();
                    self.page_cost(family, &records, bounds, output_budget)?;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(SourcePage {
            snapshot: snapshot.snapshot,
            family: family.id,
            after,
            next,
            complete: next == total,
            records,
        })
    }
}
impl<R: Read + Seek + Send> super::legacy::projection::ProjectionSource for ArchiveSource<R> {
    fn fact_view(&self) -> Option<&crate::source_facts::View> {
        self.interpretation()
    }
    fn fact_origin_digest(
        &self,
        fact: &crate::source_facts::FactRow,
        budget: usize,
    ) -> Result<crate::source_facts::SourceProofDigest, Error> {
        ArchiveSource::fact_origin_digest(self, fact, budget)
    }

    fn semantic_bytes(&self) -> usize {
        self.semantic_bytes
    }
    fn provenance(&self) -> super::legacy::archive::Provenance {
        super::legacy::archive::Provenance {
            dataset: self.identity.dataset,
            catalogue: self.header.catalogue_digest,
        }
    }
    fn inventory_digest(
        &self,
        family: [u8; 16],
        key: &Secret<Vec<u8>>,
    ) -> Result<super::legacy::projection::InventoryDigest, Error> {
        let seal = crate::seal::lend();
        let compare = |member: &Member| {
            member
                .family
                .cmp(&family)
                .then_with(|| member.group.expose(&seal).cmp(key.expose(&seal)))
        };
        let begin = self.members.partition_point(|m| compare(m).is_lt());
        let end = self.members.partition_point(|m| !compare(m).is_gt());
        if begin == end {
            return Err(Error::Corrupt);
        }
        let archive = self.archive.lock().map_err(|_| Error::Corrupt)?;
        let mut hash = Sha256::new();
        hash.update(b"busbar.archive.projection.inventory.v1\0");
        hash.update(self.identity.artifact_digest);
        hash.update(family);
        hash.update((key.expose(&seal).len() as u64).to_le_bytes());
        hash.update(key.expose(&seal));
        hash.update(((end - begin) as u64).to_le_bytes());
        for member in &self.members[begin..end] {
            hash.update(member.ordinal.to_le_bytes());
            hash.update(
                archive
                    .row_frame_digest(member.ordinal)
                    .map_err(archive_error)?,
            );
        }
        Ok(super::legacy::projection::InventoryDigest(
            hash.finalize().into(),
        ))
    }
    fn visit(
        &self,
        family: [u8; 16],
        key: &Secret<Vec<u8>>,
        row_bytes: usize,
        visitor: &mut dyn FnMut(&Record) -> Result<(), Error>,
    ) -> Result<u64, Error> {
        self.visit_group_rows(family, key, row_bytes, visitor)
    }
}
#[async_trait]
impl<R: Read + Seek + Send> SourceReader for ArchiveSource<R> {
    async fn identify(&self) -> Result<Identity, Error> {
        Ok(self.identity())
    }
    async fn read_group(
        &self,
        family: [u8; 16],
        key: &Secret<Vec<u8>>,
        bounds: Bounds,
    ) -> Result<Vec<Record>, Error> {
        self.read_group_sync(family, key, bounds)
    }
    async fn page(
        &self,
        snapshot: &SnapshotEvidence,
        family: &Family,
        after: u64,
        bounds: Bounds,
    ) -> Result<SourcePage, Error> {
        bounds.validate()?;
        if snapshot != &self.snapshot || family.source_schema != self.identity.format.physical {
            return Err(Error::IdentityMismatch);
        }
        let output_budget = self.output_transform()?;
        if let Some(transform) = &output_budget {
            let edge = transform.edge();
            if !edge.families.contains(family)
                || bounds.items > edge.bounds.items
                || bounds.bytes > edge.bounds.bytes
            {
                return Err(Error::IdentityMismatch);
            }
        }
        if family.id == super::legacy::projection::PHYSICAL {
            return self.physical_page(snapshot, family, after, bounds, output_budget.as_deref());
        }
        if family.id == super::legacy::overlay::FAMILY {
            let overlay = self
                .overlay
                .lock()
                .map_err(|_| Error::Corrupt)?
                .clone()
                .ok_or(Error::MissingCapability)?;
            if after > overlay.part_count() {
                return Err(Error::Bounds);
            }
            let mut next = after;
            let mut records = Vec::new();
            while next < overlay.part_count() && records.len() < bounds.items as usize {
                records.push(overlay.marker(next)?);
                match self.page_cost(family, &records, bounds, output_budget.as_deref()) {
                    Ok(()) => next += 1,
                    Err(Error::Bounds) if records.len() > 1 => {
                        records.pop();
                        records.shrink_to_fit();
                        self.page_cost(family, &records, bounds, output_budget.as_deref())?;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            return Ok(SourcePage {
                snapshot: snapshot.snapshot,
                family: family.id,
                after,
                next,
                complete: next == overlay.part_count(),
                records,
            });
        }
        let begin = self.members.partition_point(|m| m.family < family.id);
        let end = self.members.partition_point(|m| m.family <= family.id);
        let family_members = &self.members[begin..end];
        let after = usize::try_from(after).map_err(|_| Error::Bounds)?;
        if after > family_members.len() {
            return Err(Error::Bounds);
        }
        let seal = crate::seal::lend();
        let same = |a: &Member, b: &Member| a.group.expose(&seal) == b.group.expose(&seal);
        if after != 0
            && after < family_members.len()
            && same(&family_members[after - 1], &family_members[after])
        {
            return Err(Error::Corrupt);
        }
        let mut next = after;
        let mut records = Vec::new();
        while next < family_members.len() {
            let mut group_end = next + 1;
            while group_end < family_members.len()
                && same(&family_members[next], &family_members[group_end])
            {
                group_end += 1;
            }
            let member = &family_members[next];
            let marker_bytes = member
                .group
                .expose(&seal)
                .len()
                .checked_add(72)
                .and_then(|n| n.checked_add(std::mem::size_of::<Record>()))
                .ok_or(Error::Bounds)?;
            if marker_bytes > bounds.bytes as usize {
                if records.is_empty() {
                    return Err(Error::Bounds);
                }
                break;
            }
            let digest = super::legacy::projection::ProjectionSource::inventory_digest(
                self,
                family.id,
                &member.group,
            )?;
            let marker = Record {
                key: zeroize::Zeroizing::new(member.group.expose(&seal).clone()),
                value: super::legacy::projection::encode_marker(&member.group, digest.0)?,
                preserve_exact: false,
            };
            // Validate each group independently before treating an overlap as a page boundary.
            // Corruption/verification errors must never be hidden by batching.
            if let Some(transform) = &output_budget {
                let single = transform.transform(family, std::slice::from_ref(&marker), bounds)?;
                self.target_cost(transform.as_ref(), family, &single, bounds)?;
                if !records.is_empty() {
                    let prior = transform.transform(family, &records, bounds)?;
                    self.target_cost(transform.as_ref(), family, &prior, bounds)?;
                    if single
                        .iter()
                        .any(|a| prior.iter().any(|b| a.address == b.address))
                    {
                        break;
                    }
                }
            }
            if records.len() >= bounds.items as usize {
                break;
            }
            records.try_reserve_exact(1).map_err(|_| Error::Bounds)?;
            records.push(marker);
            let cost = self.page_cost(family, &records, bounds, output_budget.as_deref());
            match cost {
                Ok(()) => next = group_end,
                Err(Error::Bounds) if records.len() > 1 => {
                    records.pop();
                    records.shrink_to_fit();
                    self.page_cost(family, &records, bounds, output_budget.as_deref())?;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(SourcePage {
            snapshot: snapshot.snapshot,
            family: family.id,
            after: after as u64,
            next: next as u64,
            complete: next == family_members.len(),
            records,
        })
    }
}
