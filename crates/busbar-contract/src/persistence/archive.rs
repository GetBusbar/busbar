// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit offline historical source archives. The caller owns the immutable
//! seekable capability and its filesystem permissions. No runtime Store fallback.
//! Row/key buffers wipe on drop; catalogue metadata must contain no secret values.

use super::{legacy_row, source_fence::CaptureFence};
use crate::Secret;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, Zeroizing};

/// Initial archive envelope version; independent of the source physical schema.
pub const VERSION: u32 = 1;
const MAGIC: &[u8; 8] = b"BBLSRC01";
const ROW: u8 = 1;
const FOOTER: u8 = 255;

#[derive(Debug, Clone, Copy)]
/// Explicit allocation, source-size and metadata admission limits.
pub struct Limits {
    /// Maximum encoded header or row frame bytes.
    pub frame_bytes: usize,
    /// Maximum complete artifact bytes including its footer.
    pub total_bytes: u64,
    /// Maximum row frames admitted.
    pub rows: u64,
    /// Maximum catalogue tables admitted.
    pub tables: u32,
    /// Maximum columns in one table.
    pub columns: u32,
    /// Includes owned catalogue metadata and the complete offset/hash index.
    pub index_bytes: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Content-free framing, integrity and resource failures.
pub enum Error {
    /// The supplied capability could not complete I/O.
    Io,
    /// Invalid, truncated, duplicate or extra framing.
    Malformed,
    /// Unsupported envelope version.
    Version,
    /// An explicit bound would be exceeded.
    Budget,
    /// A fallible allocation failed.
    Allocation,
    /// A digest, count or immutable frame identity changed.
    Integrity,
}
#[derive(Clone, PartialEq, Eq)]
/// Ordered native column layout and complete public catalogue facts.
pub struct Table {
    /// Original native table name.
    pub name: String,
    /// Original declared ordinal order, never alphabetically reordered.
    pub columns: Vec<String>,
    /// Exact reproducible public native catalogue facts, including constraints.
    pub native_layout: Vec<u8>,
}
impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveTable")
            .field("name", &self.name)
            .field("columns", &self.columns)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone)]
/// Importer identity and exact admitted native catalogue.
pub struct Header {
    /// Registered importer discriminator, not a historical database field.
    pub owner: [u8; 16],
    /// Actual source physical schema version.
    pub physical: u32,
    /// Digest supplied by the admitted native reader, not a report assertion.
    pub catalogue_digest: [u8; 32],
    /// Actual native instance/database origin; zero denotes snapshot-only evidence.
    /// Activation must compare a nonzero anchor with a fresh native fence probe.
    pub native_anchor_digest: [u8; 32],
    /// Native enforcement observations taken before opening the capture snapshot.
    pub capture: Option<CaptureFence>,
    /// Canonically sorted tables; column order remains native.
    pub tables: Vec<Table>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Computed complete artifact identity, never a caller assertion.
pub struct Summary {
    /// Exact number of complete row frames.
    pub rows: u64,
    /// Exact complete artifact byte count.
    pub bytes: u64,
    /// SHA256 of the entire artifact, including its complete footer.
    pub digest: [u8; 32],
    /// Exact native catalogue digest bound by the archive.
    pub catalogue_digest: [u8; 32],
    /// Hash of the canonical header, binding all catalogue facts.
    pub layout_digest: [u8; 32],
    /// Hash of the immutable header and all row frames, before the footer.
    pub content_digest: [u8; 32],
    /// Native post-capture observation bound to content_digest, absent for snapshots.
    pub post_observation_sha256: Option<[u8; 32]>,
}
/// Constant-memory SHA256 state for bounded native capture streams.
#[derive(Clone, Default)]
pub struct Hasher(Sha256);
impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchiveHasher(..)")
    }
}
impl Hasher {
    /// Start an empty source stream digest without collecting any input bytes.
    pub fn new() -> Self {
        Self(Sha256::new())
    }
    /// Include the next exact native stream bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    /// Finish the exact complete stream digest.
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}
/// Compute SHA256 for public native inventory metadata.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn io(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Malformed
    } else {
        Error::Io
    }
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn validate(header: &Header, limits: Limits) -> Result<(), Error> {
    if limits.frame_bytes == 0
        || limits.total_bytes == 0
        || limits.rows == 0
        || limits.index_bytes == 0
        || header.owner == [0; 16]
        || header.physical == 0
        || header.catalogue_digest == [0; 32]
        || header.tables.is_empty()
        || header.tables.len() > limits.tables as usize
    {
        return Err(Error::Budget);
    }
    if let Some(capture) = &header.capture {
        if header.native_anchor_digest == [0; 32]
            || capture.writer_inventory_sha256 == [0; 32]
            || capture.enforcement_policy_sha256 == [0; 32]
            || capture.prefence_observation_sha256 == [0; 32]
        {
            return Err(Error::Integrity);
        }
    }
    for (i, table) in header.tables.iter().enumerate() {
        if !name(&table.name)
            || table.columns.is_empty()
            || table.native_layout.is_empty()
            || table.columns.len() > limits.columns as usize
            || (i > 0 && header.tables[i - 1].name >= table.name)
        {
            return Err(Error::Malformed);
        }
        for (j, column) in table.columns.iter().enumerate() {
            if !name(column) || table.columns[..j].contains(column) {
                return Err(Error::Malformed);
            }
        }
    }
    Ok(())
}
fn append(out: &mut Vec<u8>, bytes: &[u8], budget: usize) -> Result<(), Error> {
    if out.len().checked_add(bytes.len()).ok_or(Error::Budget)? > budget {
        return Err(Error::Budget);
    }
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Allocation)?;
    out.extend_from_slice(bytes);
    Ok(())
}
fn text(out: &mut Vec<u8>, value: &str, budget: usize) -> Result<(), Error> {
    append(
        out,
        &u32::try_from(value.len())
            .map_err(|_| Error::Budget)?
            .to_le_bytes(),
        budget,
    )?;
    append(out, value.as_bytes(), budget)
}
fn encode_header(header: &Header, limits: Limits) -> Result<Vec<u8>, Error> {
    validate(header, limits)?;
    let mut out = Vec::new();
    let budget = limits.frame_bytes.min(limits.index_bytes);
    append(&mut out, &header.owner, budget)?;
    append(&mut out, &header.physical.to_le_bytes(), budget)?;
    append(&mut out, &header.catalogue_digest, budget)?;
    append(&mut out, &header.native_anchor_digest, budget)?;
    match &header.capture {
        None => append(&mut out, &[0], budget)?,
        Some(capture) => {
            append(&mut out, &[1], budget)?;
            append(&mut out, &capture.writer_inventory_sha256, budget)?;
            append(&mut out, &capture.enforcement_policy_sha256, budget)?;
            append(&mut out, &capture.prefence_observation_sha256, budget)?;
        }
    }
    append(
        &mut out,
        &(header.tables.len() as u32).to_le_bytes(),
        budget,
    )?;
    for table in &header.tables {
        text(&mut out, &table.name, budget)?;
        append(
            &mut out,
            &(table.columns.len() as u32).to_le_bytes(),
            budget,
        )?;
        for column in &table.columns {
            text(&mut out, column, budget)?;
        }
        append(
            &mut out,
            &(table.native_layout.len() as u64).to_le_bytes(),
            budget,
        )?;
        append(&mut out, &table.native_layout, budget)?;
    }
    Ok(out)
}
struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let value = self.0.get(..n).ok_or(Error::Malformed)?;
        self.0 = &self.0[n..];
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Malformed)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Malformed)?,
        ))
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.u64()?).map_err(|_| Error::Budget)?;
        self.take(n)
    }
    fn text(&mut self) -> Result<String, Error> {
        let n = self.u32()? as usize;
        let bytes = self.take(n)?;
        let value = std::str::from_utf8(bytes).map_err(|_| Error::Malformed)?;
        if !name(value) {
            return Err(Error::Malformed);
        }
        let mut owned = String::new();
        owned.try_reserve_exact(n).map_err(|_| Error::Allocation)?;
        owned.push_str(value);
        Ok(owned)
    }
}
fn decode_header(bytes: &[u8], limits: Limits) -> Result<Header, Error> {
    let mut f = Fields(bytes);
    let owner = f.take(16)?.try_into().map_err(|_| Error::Malformed)?;
    let physical = f.u32()?;
    let catalogue_digest = f.take(32)?.try_into().map_err(|_| Error::Malformed)?;
    let native_anchor_digest = f.take(32)?.try_into().map_err(|_| Error::Malformed)?;
    let capture = match f.take(1)?[0] {
        0 => None,
        1 => Some(CaptureFence {
            writer_inventory_sha256: f.take(32)?.try_into().map_err(|_| Error::Malformed)?,
            enforcement_policy_sha256: f.take(32)?.try_into().map_err(|_| Error::Malformed)?,
            prefence_observation_sha256: f.take(32)?.try_into().map_err(|_| Error::Malformed)?,
        }),
        _ => return Err(Error::Malformed),
    };
    let count = f.u32()? as usize;
    if count == 0 || count > limits.tables as usize {
        return Err(Error::Budget);
    }
    let mut charge = bytes
        .len()
        .checked_add(
            count
                .checked_mul(std::mem::size_of::<Table>())
                .ok_or(Error::Budget)?,
        )
        .ok_or(Error::Budget)?;
    if charge > limits.index_bytes {
        return Err(Error::Budget);
    }
    let mut tables = Vec::new();
    tables
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    for _ in 0..count {
        let name = f.text()?;
        let count = f.u32()? as usize;
        if count == 0 || count > limits.columns as usize {
            return Err(Error::Budget);
        }
        charge = charge
            .checked_add(
                count
                    .checked_mul(std::mem::size_of::<String>())
                    .ok_or(Error::Budget)?,
            )
            .ok_or(Error::Budget)?;
        if charge > limits.index_bytes {
            return Err(Error::Budget);
        }
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for _ in 0..count {
            columns.push(f.text()?);
        }
        let raw = f.blob()?;
        let mut native_layout = Vec::new();
        native_layout
            .try_reserve_exact(raw.len())
            .map_err(|_| Error::Allocation)?;
        native_layout.extend_from_slice(raw);
        tables.push(Table {
            name,
            columns,
            native_layout,
        });
    }
    if !f.0.is_empty() {
        return Err(Error::Malformed);
    }
    let header = Header {
        owner,
        physical,
        catalogue_digest,
        native_anchor_digest,
        capture,
        tables,
    };
    validate(&header, limits)?;
    Ok(header)
}
fn row_parts<'a>(bytes: &'a [u8], header: &Header) -> Result<(u32, &'a [u8], &'a [u8]), Error> {
    let mut f = Fields(bytes);
    let table = f.u32()?;
    let layout = header.tables.get(table as usize).ok_or(Error::Malformed)?;
    let key = f.blob()?;
    let value = f.blob()?;
    let row = legacy_row::Row::decode(value).map_err(|_| Error::Malformed)?;
    if row.cells().len() != layout.columns.len() || !f.0.is_empty() {
        return Err(Error::Malformed);
    }
    Ok((table, key, value))
}

/// Streaming writer; rows remain borrowed under their original wiping ownership.
pub struct Writer<W> {
    output: W,
    header: Header,
    limits: Limits,
    hash: Sha256,
    rows: u64,
    bytes: u64,
    layout_digest: [u8; 32],
    failed: bool,
}
impl<W> std::fmt::Debug for Writer<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveWriter")
            .field("rows", &self.rows)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}
impl<W: Write> Writer<W> {
    /// Start a bounded archive and serialize its exact catalogue.
    pub fn new(output: W, header: Header, limits: Limits) -> Result<Self, Error> {
        let encoded = encode_header(&header, limits)?;
        let layout_digest = digest(&encoded);
        let mut writer = Self {
            output,
            header,
            limits,
            hash: Sha256::new(),
            rows: 0,
            bytes: 0,
            layout_digest,
            failed: false,
        };
        writer.put(MAGIC)?;
        writer.put(&VERSION.to_le_bytes())?;
        writer.put(&(encoded.len() as u64).to_le_bytes())?;
        writer.put(&encoded)?;
        Ok(writer)
    }
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Io);
        }
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Budget)?;
        if next > self.limits.total_bytes {
            self.failed = true;
            return Err(Error::Budget);
        }
        if self.output.write_all(bytes).is_err() {
            self.failed = true;
            return Err(Error::Io);
        }
        self.hash.update(bytes);
        self.bytes = next;
        Ok(())
    }
    /// Append one native identity and untouched validated physical row.
    pub fn write_row(&mut self, table: u32, native_key: &[u8], value: &[u8]) -> Result<(), Error> {
        if self.rows >= self.limits.rows {
            return Err(Error::Budget);
        }
        let layout = self
            .header
            .tables
            .get(table as usize)
            .ok_or(Error::Malformed)?;
        if legacy_row::Row::decode(value)
            .map_err(|_| Error::Malformed)?
            .cells()
            .len()
            != layout.columns.len()
        {
            return Err(Error::Malformed);
        }
        let length = 20usize
            .checked_add(native_key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(Error::Budget)?;
        if length > self.limits.frame_bytes {
            return Err(Error::Budget);
        }
        // Refuse before writing a partial row when the aggregate budget cannot carry it and footer.
        if self
            .bytes
            .checked_add(length as u64)
            .and_then(|n| {
                n.checked_add(
                    9 + if self.header.capture.is_some() {
                        74
                    } else {
                        42
                    },
                )
            })
            .ok_or(Error::Budget)?
            > self.limits.total_bytes
        {
            return Err(Error::Budget);
        }
        self.put(&[ROW])?;
        self.put(&(length as u64).to_le_bytes())?;
        self.put(&table.to_le_bytes())?;
        self.put(&(native_key.len() as u64).to_le_bytes())?;
        self.put(native_key)?;
        self.put(&(value.len() as u64).to_le_bytes())?;
        self.put(value)?;
        self.rows += 1;
        Ok(())
    }
    /// Hash the immutable capture bytes for a live post-capture probe. Calling
    /// this does not complete the artifact or release native capture guards.
    pub fn content_digest(&self) -> [u8; 32] {
        self.hash.clone().finalize().into()
    }
    /// Finish an explicitly snapshot-only archive with no claimed live origin.
    pub fn finish(self) -> Result<(W, Summary), Error> {
        self.complete(None)
    }
    /// Complete a fenced capture only after a native post-probe has verified the
    /// same origin/inventory/policy and bound its observation to content_digest.
    pub fn finish_captured(self, post_observation_sha256: [u8; 32]) -> Result<(W, Summary), Error> {
        self.complete(Some(post_observation_sha256))
    }
    fn complete(mut self, post: Option<[u8; 32]>) -> Result<(W, Summary), Error> {
        match (&self.header.capture, post) {
            (None, None) if self.header.native_anchor_digest == [0; 32] => {}
            (Some(_), Some(digest)) if digest != [0; 32] => {}
            _ => return Err(Error::Integrity),
        }
        let prefix = self.content_digest();
        self.put(&[FOOTER])?;
        self.put(&self.rows.to_le_bytes())?;
        self.put(&prefix)?;
        self.put(&[u8::from(post.is_some())])?;
        if let Some(digest) = post {
            self.put(&digest)?;
        }
        self.output.flush().map_err(io)?;
        let summary = Summary {
            rows: self.rows,
            bytes: self.bytes,
            digest: self.hash.finalize().into(),
            catalogue_digest: self.header.catalogue_digest,
            layout_digest: self.layout_digest,
            content_digest: prefix,
            post_observation_sha256: post,
        };
        Ok((self.output, summary))
    }
}

/// Per-row immutable index storage, including its native-identity lookup ordinal.
/// Catalogue storage is additional; payload bytes never live in this index.
pub fn index_entry_bytes() -> usize {
    std::mem::size_of::<RowIndex>() + std::mem::size_of::<usize>()
}
struct RowIndex {
    table: u32,
    offset: u64,
    length: usize,
    hash: [u8; 32],
    key_hash: [u8; 32],
}
impl Drop for RowIndex {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.key_hash.zeroize();
    }
}
/// Payload-free immutable capability index. Each later read checks the original frame hash.
pub struct VerifiedArchive<R> {
    source: R,
    header: Header,
    summary: Summary,
    index: Vec<RowIndex>,
    lookup: Vec<usize>,
    limits: Limits,
}
impl<R> std::fmt::Debug for VerifiedArchive<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedArchive")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}
/// Complete frame copies remain in wiping ownership. Never derive payload Debug.
#[derive(Debug)]
pub struct ArchiveRow {
    /// Ordinal into the archive catalogue.
    pub table: u32,
    /// Untouched native identity under wiping custody.
    pub native_key: Secret<Vec<u8>>,
    /// Untouched legacy_row frame under wiping custody.
    pub value: Secret<Vec<u8>>,
}
impl<R: Read + Seek> VerifiedArchive<R> {
    /// The validated public native catalogue.
    pub fn header(&self) -> &Header {
        &self.header
    }
    /// Full-stream identity computed during admission.
    pub fn summary(&self) -> Summary {
        self.summary
    }
    /// Table ordinal from the bounded immutable metadata index.
    pub fn row_table(&self, ordinal: u64) -> Result<u32, Error> {
        self.index
            .get(usize::try_from(ordinal).map_err(|_| Error::Budget)?)
            .map(|i| i.table)
            .ok_or(Error::Malformed)
    }
    /// Encoded native row bytes from the immutable index, before payload allocation.
    pub fn row_frame_bytes(&self, ordinal: u64) -> Result<usize, Error> {
        self.index
            .get(usize::try_from(ordinal).map_err(|_| Error::Budget)?)
            .map(|entry| entry.length)
            .ok_or(Error::Malformed)
    }
    /// Original frame hash from the validated immutable metadata index; no payload read.
    pub fn row_frame_digest(&self, ordinal: u64) -> Result<[u8; 32], Error> {
        self.index
            .get(usize::try_from(ordinal).map_err(|_| Error::Budget)?)
            .map(|entry| entry.hash)
            .ok_or(Error::Malformed)
    }
    /// Locate one exact native identity through the bounded hash index. Later
    /// read_row still verifies the original frame bytes before exposing a value.
    pub fn find_native(&self, table: u32, native_key: &[u8]) -> Result<Option<u64>, Error> {
        if table as usize >= self.header.tables.len() {
            return Err(Error::Malformed);
        }
        let wanted = (table, digest(native_key));
        Ok(self
            .lookup
            .binary_search_by(|ordinal| {
                let entry = &self.index[*ordinal];
                (entry.table, entry.key_hash).cmp(&wanted)
            })
            .ok()
            .map(|at| self.lookup[at] as u64))
    }
    /// Seek and revalidate one original frame before copying protected cells.
    pub fn read_row(&mut self, ordinal: u64) -> Result<ArchiveRow, Error> {
        let entry = self
            .index
            .get(usize::try_from(ordinal).map_err(|_| Error::Budget)?)
            .ok_or(Error::Malformed)?;
        self.source
            .seek(SeekFrom::Start(entry.offset))
            .map_err(io)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(entry.length)
            .map_err(|_| Error::Allocation)?;
        bytes.resize(entry.length, 0);
        self.source.read_exact(&mut bytes).map_err(io)?;
        if digest(&bytes) != entry.hash {
            return Err(Error::Integrity);
        }
        let (table, key, value) = row_parts(&bytes, &self.header)?;
        let copy = |src: &[u8]| -> Result<Secret<Vec<u8>>, Error> {
            let mut out = Zeroizing::new(Vec::new());
            out.try_reserve_exact(src.len())
                .map_err(|_| Error::Allocation)?;
            out.extend_from_slice(src);
            Ok(Secret::new(std::mem::take(&mut *out)))
        };
        Ok(ArchiveRow {
            table,
            native_key: copy(key)?,
            value: copy(value)?,
        })
    }
    /// The explicit bounds under which this capability was admitted.
    pub fn limits(&self) -> Limits {
        self.limits
    }
}
fn get<R: Read>(
    source: &mut R,
    hash: &mut Sha256,
    count: &mut u64,
    length: usize,
    limits: Limits,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let next = count.checked_add(length as u64).ok_or(Error::Budget)?;
    if next > limits.total_bytes || length > limits.frame_bytes.max(41) {
        return Err(Error::Budget);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::Allocation)?;
    bytes.resize(length, 0);
    source.read_exact(&mut bytes).map_err(io)?;
    hash.update(&bytes);
    *count = next;
    Ok(bytes)
}
/// Verify the entire stream before returning an admitted capability. Index memory
/// is explicitly bounded; payload memory is at most a frame plus its protected copies.
pub fn read<R: Read + Seek + Send>(
    mut source: R,
    limits: Limits,
) -> Result<VerifiedArchive<R>, Error> {
    if source.stream_position().map_err(io)? != 0 {
        return Err(Error::Malformed);
    }
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    if get(&mut source, &mut hash, &mut bytes, 8, limits)?.as_slice() != MAGIC {
        return Err(Error::Malformed);
    }
    let version = get(&mut source, &mut hash, &mut bytes, 4, limits)?;
    if version.as_slice() != VERSION.to_le_bytes() {
        return Err(Error::Version);
    }
    let size = get(&mut source, &mut hash, &mut bytes, 8, limits)?;
    let size = usize::try_from(u64::from_le_bytes(
        size.as_slice().try_into().map_err(|_| Error::Malformed)?,
    ))
    .map_err(|_| Error::Budget)?;
    if size > limits.index_bytes {
        return Err(Error::Budget);
    }
    let encoded = get(&mut source, &mut hash, &mut bytes, size, limits)?;
    let header = decode_header(&encoded, limits)?;
    let layout_digest = digest(&encoded);
    let metadata = encode_header(&header, limits)?
        .len()
        .checked_add(
            header
                .tables
                .len()
                .checked_mul(std::mem::size_of::<Table>())
                .ok_or(Error::Budget)?,
        )
        .ok_or(Error::Budget)?;
    let metadata = header.tables.iter().try_fold(metadata, |n, t| {
        n.checked_add(
            t.columns
                .len()
                .checked_mul(std::mem::size_of::<String>())
                .ok_or(Error::Budget)?,
        )
        .ok_or(Error::Budget)
    })?;
    let mut index: Vec<RowIndex> = Vec::new();
    loop {
        let prefix: [u8; 32] = hash.clone().finalize().into();
        let tag = get(&mut source, &mut hash, &mut bytes, 1, limits)?[0];
        if tag == FOOTER {
            let footer = get(&mut source, &mut hash, &mut bytes, 40, limits)?;
            if u64::from_le_bytes(footer[..8].try_into().map_err(|_| Error::Malformed)?)
                != index.len() as u64
                || footer[8..] != prefix
            {
                return Err(Error::Integrity);
            }
            let post = match get(&mut source, &mut hash, &mut bytes, 1, limits)?[0] {
                0 => None,
                1 => Some(
                    get(&mut source, &mut hash, &mut bytes, 32, limits)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Malformed)?,
                ),
                _ => return Err(Error::Malformed),
            };
            match (&header.capture, post) {
                (None, None) if header.native_anchor_digest == [0; 32] => {}
                (Some(_), Some(digest)) if digest != [0; 32] => {}
                _ => return Err(Error::Integrity),
            }
            let mut extra = [0];
            if source.read(&mut extra).map_err(io)? != 0 {
                return Err(Error::Malformed);
            }
            let summary = Summary {
                rows: index.len() as u64,
                bytes,
                digest: hash.finalize().into(),
                catalogue_digest: header.catalogue_digest,
                layout_digest,
                content_digest: prefix,
                post_observation_sha256: post,
            };
            let mut lookup = Vec::new();
            lookup
                .try_reserve_exact(index.len())
                .map_err(|_| Error::Allocation)?;
            lookup.extend(0..index.len());
            lookup.sort_unstable_by_key(|ordinal| {
                let entry = &index[*ordinal];
                (entry.table, entry.key_hash)
            });
            if lookup.windows(2).any(|pair| {
                let a = &index[pair[0]];
                let b = &index[pair[1]];
                a.table == b.table && a.key_hash == b.key_hash
            }) {
                return Err(Error::Integrity);
            }
            return Ok(VerifiedArchive {
                source,
                header,
                summary,
                index,
                lookup,
                limits,
            });
        }
        if tag != ROW {
            return Err(Error::Malformed);
        }
        if index.len() as u64 >= limits.rows
            || metadata
                .checked_add(
                    (index.len() + 1)
                        .checked_mul(std::mem::size_of::<RowIndex>() + std::mem::size_of::<usize>())
                        .ok_or(Error::Budget)?,
                )
                .ok_or(Error::Budget)?
                > limits.index_bytes
        {
            return Err(Error::Budget);
        }
        let size = get(&mut source, &mut hash, &mut bytes, 8, limits)?;
        let length = usize::try_from(u64::from_le_bytes(
            size.as_slice().try_into().map_err(|_| Error::Malformed)?,
        ))
        .map_err(|_| Error::Budget)?;
        let offset = bytes;
        let frame = get(&mut source, &mut hash, &mut bytes, length, limits)?;
        let (table, key, _) = row_parts(&frame, &header)?;
        index.try_reserve_exact(1).map_err(|_| Error::Allocation)?;
        index.push(RowIndex {
            table,
            offset,
            length,
            hash: digest(&frame),
            key_hash: digest(key),
        });
    }
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
