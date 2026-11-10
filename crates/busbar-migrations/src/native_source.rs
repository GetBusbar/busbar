// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Automatic native snapshot capture into a caller-owned protected transient spool.
//! The inner archive proves immutable bytes only. Actual live native authority is
//! retained separately and never invented as offline CaptureFence evidence.

use crate::{
    archive_source::{ArchiveRows, ArchiveSource, Grouping},
    Error, Format, Identity, SnapshotEvidence,
};
use busbar_contract::{
    persistence::{
        archive::{self, Header, Table, VerifiedArchive, Writer},
        lifecycle as native,
    },
    Secret,
};
use std::{
    io::{self, Read, Seek, Write},
    sync::Arc,
};

/// An immutable seekable source capability, without a filesystem path.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}
/// A private transient sequential writer which seals into an immutable reader.
pub trait SourceSpool: Write + Send {
    /// Seal all protected chunks and return their authenticated seekable reader.
    fn finish(self: Box<Self>) -> io::Result<Box<dyn ReadSeek + Send>>;
}
/// Root-owned protected spool creation. No migration-to-loader dependency.
pub trait SpoolFactory: Send + Sync {
    /// Create one fresh private transient source artifact.
    fn create(&self) -> io::Result<Box<dyn SourceSpool>>;
}
/// One immutable native capture and the live native session which owns its origin.
pub struct NativeSnapshot {
    archive: VerifiedArchive<Box<dyn ReadSeek + Send>>,
    header: Header,
    prepared: Arc<dyn native::PreparedStore>,
    source: native::SourceIdentity,
    snapshot: SnapshotEvidence,
    source_digest: native::Digest,
    interpretation: Option<crate::source_facts::View>,
}
mod interpretation;
impl std::fmt::Debug for NativeSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSnapshot")
            .field("source", &self.source)
            .field("rows", &self.archive.summary().rows)
            .finish_non_exhaustive()
    }
}
fn err(error: archive::Error) -> Error {
    match error {
        archive::Error::Budget | archive::Error::Allocation => Error::Bounds,
        _ => Error::Corrupt,
    }
}
fn native_error(error: native::Error) -> Error {
    crate::startup::native_error(error)
}
fn copy_catalogue(tables: &[Table], budget: usize) -> Result<Vec<Table>, Error> {
    let mut charge = tables
        .len()
        .checked_mul(std::mem::size_of::<Table>())
        .ok_or(Error::Bounds)?;
    for table in tables {
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
    fn bytes(source: &[u8]) -> Result<Vec<u8>, Error> {
        let mut value = Vec::new();
        value
            .try_reserve_exact(source.len())
            .map_err(|_| Error::Bounds)?;
        value.extend_from_slice(source);
        Ok(value)
    }
    fn text(source: &str) -> Result<String, Error> {
        String::from_utf8(bytes(source.as_bytes())?).map_err(|_| Error::Corrupt)
    }
    let mut copy = Vec::new();
    copy.try_reserve_exact(tables.len())
        .map_err(|_| Error::Bounds)?;
    for table in tables {
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(table.columns.len())
            .map_err(|_| Error::Bounds)?;
        for column in &table.columns {
            columns.push(text(column)?);
        }
        copy.push(Table {
            name: text(&table.name)?,
            columns,
            native_layout: bytes(&table.native_layout)?,
        });
    }
    Ok(copy)
}
async fn call_retained(
    prepared: &dyn native::PreparedStore,
    request: Arc<native::Request>,
) -> Result<Arc<native::Response>, Error> {
    loop {
        match prepared.bootstrap(request.clone()).await {
            Ok(response) => return Ok(response),
            Err(native::Error::Pending | native::Error::Busy | native::Error::Unknown) => {
                // Read-only capture/recheck retries retain the identical request;
                // no private executor, new candidate or changed cursor is introduced.
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            Err(error) => return Err(native_error(error)),
        }
    }
}
async fn fence(
    prepared: &dyn native::PreparedStore,
    upgrade: &native::Upgrade,
) -> Result<native::Fence, Error> {
    let response = call_retained(
        prepared,
        Arc::new(native::Request::CheckFence {
            upgrade: upgrade.reference.clone(),
        }),
    )
    .await?;
    let native::Response::Fence(fence) = response.as_ref() else {
        return Err(Error::Corrupt);
    };
    if fence.upgrade != upgrade.reference.id
        || fence.source != upgrade.source
        || fence.snapshot != upgrade.snapshot
        || fence.enforcement_digest == [0; 32]
        || fence.observation_digest == [0; 32]
    {
        return Err(Error::IdentityMismatch);
    }
    Ok(fence.clone())
}
impl NativeSnapshot {
    /// Capture only from the actual retained native session, using bounded pages.
    /// No caller-supplied archive/report can manufacture this live source binding.
    pub async fn capture(
        prepared: Arc<dyn native::PreparedStore>,
        upgrade: &native::Upgrade,
        bounds: native::Bounds,
        spool: &dyn SpoolFactory,
        limits: archive::Limits,
    ) -> Result<Self, Error> {
        let format = upgrade.source.format.ok_or(Error::UnsupportedPath)?;
        if upgrade.reference.id == [0; 16]
            || upgrade.source.dataset.0 == [0; 16]
            || upgrade.source.native_anchor == [0; 32]
            || upgrade.source.catalogue_digest == [0; 32]
            || upgrade.source.layout_digest == [0; 32]
            || upgrade.snapshot == [0; 16]
            || bounds.items == 0
            || bounds.bytes == 0
            || format.codec != 1
            || !matches!(format.logical, 0 | 1)
            || upgrade.catalogue.is_empty()
        {
            return Err(Error::IdentityMismatch);
        }
        let before = fence(prepared.as_ref(), upgrade).await?;
        let catalogue = copy_catalogue(&upgrade.catalogue, limits.index_bytes)?;
        let catalogue_digest = upgrade.source.catalogue_digest;
        let header = Header {
            owner: format.owner,
            physical: format.physical,
            catalogue_digest,
            native_anchor_digest: [0; 32],
            capture: None,
            tables: catalogue,
        };
        let output = spool
            .create()
            .map_err(|_| Error::Backend(busbar_contract::persistence::Failure::Unavailable))?;
        let mut writer = Writer::new(output, header, limits).map_err(err)?;
        let seal = crate::seal::lend();
        let mut coverage = archive::Hasher::new();
        coverage.update(b"busbar.native.snapshot/1\0");
        coverage.update(&upgrade.source.native_anchor);
        coverage.update(&upgrade.source.dataset.0);
        coverage.update(&upgrade.snapshot);
        let mut source_digest = None;
        for table in 0..upgrade.catalogue.len() {
            let table = u32::try_from(table).map_err(|_| Error::Bounds)?;
            let mut cursor: Option<Secret<Vec<u8>>> = None;
            loop {
                let request = Arc::new(native::Request::SourcePage {
                    upgrade: upgrade.reference.clone(),
                    snapshot: upgrade.snapshot,
                    // This is the native physical source owner. PHYSICAL is
                    // the later core archive/grouping family, not a native
                    // lifecycle selector understood by the Store.
                    family: format.owner,
                    selector: native::SourceSelector::Scan { table },
                    cursor: cursor.clone(),
                    bounds,
                });
                let response = call_retained(prepared.as_ref(), request).await?;
                let native::Response::SourcePage(page) = response.as_ref() else {
                    return Err(Error::Corrupt);
                };
                if page.snapshot != upgrade.snapshot
                    || page.family != format.owner
                    || page.rows.len() > bounds.items as usize
                    || page.source_digest == [0; 32]
                    || page.coverage_digest == [0; 32]
                    || (page.rows.is_empty() && page.next.is_some())
                    || page
                        .next
                        .as_ref()
                        .is_some_and(|next| cursor.as_ref() == Some(next))
                {
                    return Err(Error::Corrupt);
                }
                if source_digest.is_some_and(|digest| digest != page.source_digest) {
                    return Err(Error::IdentityMismatch);
                }
                source_digest = Some(page.source_digest);
                let mut charge = page
                    .rows
                    .capacity()
                    .checked_mul(std::mem::size_of::<native::SourceRow>())
                    .ok_or(Error::Bounds)?;
                for row in &page.rows {
                    if row.table != table {
                        return Err(Error::Corrupt);
                    }
                    charge = charge
                        .checked_add(row.native_key.expose(&seal).len())
                        .and_then(|n| n.checked_add(row.value.expose(&seal).len()))
                        .ok_or(Error::Bounds)?;
                    if charge > bounds.bytes as usize {
                        return Err(Error::Bounds);
                    }
                    writer
                        .write_row(table, row.native_key.expose(&seal), row.value.expose(&seal))
                        .map_err(err)?;
                }
                coverage.update(&table.to_le_bytes());
                coverage.update(&page.source_digest);
                coverage.update(&page.coverage_digest);
                coverage.update(&(page.rows.len() as u64).to_le_bytes());
                tokio::task::yield_now().await;
                match &page.next {
                    Some(next) => cursor = Some(next.clone()),
                    None => break,
                }
            }
        }
        let after = fence(prepared.as_ref(), upgrade).await?;
        if before.enforcement_digest != after.enforcement_digest {
            return Err(Error::FenceRequired);
        }
        let (writer, summary) = writer.finish().map_err(err)?;
        coverage.update(&summary.digest);
        coverage.update(&summary.rows.to_le_bytes());
        // Fresh fence observations validate this capture but are not stable
        // source inventory. Resume must reproduce the same immutable coverage.
        coverage.update(&before.enforcement_digest);
        let reader = writer
            .finish()
            .map_err(|_| Error::Backend(busbar_contract::persistence::Failure::Unavailable))?;
        let archive = archive::read(reader, limits).map_err(err)?;
        if archive.summary() != summary {
            return Err(Error::Corrupt);
        }
        let mut header = Header {
            owner: format.owner,
            physical: format.physical,
            catalogue_digest,
            native_anchor_digest: upgrade.source.native_anchor,
            capture: None,
            tables: copy_catalogue(&upgrade.catalogue, limits.index_bytes)?,
        };
        // This effective origin comes only from the retained live capability. The
        // inner stream still truthfully records snapshot-only origin and no CaptureFence.
        header.native_anchor_digest = upgrade.source.native_anchor;
        Ok(Self {
            archive,
            header,
            prepared,
            source: upgrade.source.clone(),
            snapshot: SnapshotEvidence {
                source: upgrade.source.dataset.0,
                snapshot: upgrade.snapshot,
                content_digest: summary.digest,
                coverage_digest: coverage.finish(),
            },
            source_digest: source_digest.ok_or(Error::Corrupt)?,
            interpretation: None,
        })
    }
    /// Actual native dataset with immutable complete artifact/catalogue identities.
    pub fn identity(&self) -> Identity {
        Identity {
            dataset: self.source.dataset.0,
            format: Format {
                owner: self.header.owner,
                physical: self.header.physical,
                logical: 1,
                codec: 1,
            },
            artifact_digest: self.archive.summary().digest,
            schema_digest: self.header.catalogue_digest,
            // Native physical metadata does not record the historical binary release.
            product_release: [0, 0, 0],
        }
    }
    /// Retained native snapshot and full captured physical coverage.
    pub fn snapshot(&self) -> SnapshotEvidence {
        self.snapshot.clone()
    }
    /// Effective header bound to this live native origin, never an offline proof claim.
    pub fn header(&self) -> &Header {
        &self.header
    }
    /// Exact native snapshot catalogue with original declared column order.
    pub fn catalogue(&self) -> &[Table] {
        &self.header.tables
    }
    /// Complete physical source capability for proof extraction before indexing.
    pub fn rows(&mut self) -> &mut dyn ArchiveRows {
        self
    }
    /// Index the same immutable capture while retaining its actual native session owner.
    pub fn into_source(
        self,
        grouping: Arc<dyn Grouping>,
        index_bytes: usize,
        semantic_bytes: usize,
        release: [u32; 3],
    ) -> Result<Arc<ArchiveSource<Box<dyn ReadSeek + Send>>>, Error> {
        let grouped = Arc::new(NativeGrouping {
            inner: grouping,
            anchor: self.source.native_anchor,
        });
        let source = ArchiveSource::open(self.archive, grouped, index_bytes, release)?
            .with_semantic_budget(semantic_bytes)?
            .with_native_binding(self.source, self.snapshot, self.prepared)?;
        Ok(Arc::new(source))
    }
}
impl ArchiveRows for NativeSnapshot {
    fn row_frame_bytes(&self, ordinal: u64) -> Result<usize, Error> {
        self.archive.row_frame_bytes(ordinal).map_err(err)
    }
    fn interpretation(&self) -> Option<&crate::source_facts::View> {
        self.interpretation.as_ref()
    }
    fn row_table(&mut self, ordinal: u64) -> Result<u32, Error> {
        self.archive.row_table(ordinal).map_err(err)
    }
    fn header(&self) -> &Header {
        &self.header
    }
    fn row_count(&self) -> u64 {
        self.archive.summary().rows
    }
    fn read_row(&mut self, ordinal: u64) -> Result<archive::ArchiveRow, Error> {
        self.archive.read_row(ordinal).map_err(err)
    }
    fn find_native(&self, table: u32, key: &[u8]) -> Result<Option<u64>, Error> {
        self.archive.find_native(table, key).map_err(err)
    }
}
struct NativeGrouping {
    inner: Arc<dyn Grouping>,
    anchor: [u8; 32],
}
struct EffectiveRows<'a> {
    source: &'a mut dyn ArchiveRows,
    header: Header,
}
impl ArchiveRows for EffectiveRows<'_> {
    fn row_frame_bytes(&self, ordinal: u64) -> Result<usize, Error> {
        self.source.row_frame_bytes(ordinal)
    }
    fn row_table(&mut self, ordinal: u64) -> Result<u32, Error> {
        self.source.row_table(ordinal)
    }
    fn interpretation(&self) -> Option<&crate::source_facts::View> {
        self.source.interpretation()
    }
    fn header(&self) -> &Header {
        &self.header
    }
    fn row_count(&self) -> u64 {
        self.source.row_count()
    }
    fn read_row(&mut self, ordinal: u64) -> Result<archive::ArchiveRow, Error> {
        self.source.read_row(ordinal)
    }
    fn find_native(&self, table: u32, key: &[u8]) -> Result<Option<u64>, Error> {
        self.source.find_native(table, key)
    }
}
impl Grouping for NativeGrouping {
    fn interpretation(&self) -> Option<&crate::source_facts::View> {
        self.inner.interpretation()
    }
    fn includes(&self, table: u32) -> bool {
        self.inner.includes(table)
    }
    fn verify_inventory(
        &self,
        source: &mut dyn ArchiveRows,
        metadata_bytes: usize,
    ) -> Result<(), Error> {
        let raw = source.header();
        let mut header = Header {
            owner: raw.owner,
            physical: raw.physical,
            catalogue_digest: raw.catalogue_digest,
            native_anchor_digest: self.anchor,
            capture: None,
            tables: copy_catalogue(&raw.tables, metadata_bytes)?,
        };
        header.native_anchor_digest = self.anchor;
        let mut charged = std::mem::size_of::<Header>();
        for table in &header.tables {
            charged = charged
                .checked_add(std::mem::size_of::<Table>())
                .and_then(|n| n.checked_add(table.name.capacity()))
                .and_then(|n| n.checked_add(table.native_layout.capacity()))
                .and_then(|n| {
                    n.checked_add(
                        table
                            .columns
                            .capacity()
                            .checked_mul(std::mem::size_of::<String>())?,
                    )
                })
                .ok_or(Error::Bounds)?;
            for column in &table.columns {
                charged = charged
                    .checked_add(column.capacity())
                    .ok_or(Error::Bounds)?;
            }
        }
        let budget = metadata_bytes.checked_sub(charged).ok_or(Error::Bounds)?;
        self.inner
            .verify_inventory(&mut EffectiveRows { source, header }, budget)
    }
    fn classify(
        &self,
        header: &Header,
        table: &Table,
        key: &[u8],
        row: busbar_contract::persistence::legacy_row::Row<'_>,
    ) -> Result<crate::legacy::group::LogicalGroup, Error> {
        self.inner.classify(header, table, key, row)
    }
}

#[cfg(test)]
#[path = "native_source_tests.rs"]
mod tests;
