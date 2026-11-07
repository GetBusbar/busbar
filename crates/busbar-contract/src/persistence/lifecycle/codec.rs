// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Strict version-one native bootstrap framing. Integers and lengths are little endian.
//! The 16-byte header is magic, u32 version, kind, tag and two zero reserved bytes.
//! Kinds 1/2/3 carry requests/responses/OPEN bindings; response tags 128..137
//! carry content-free typed failures. Blobs and vector counts use u32 lengths.

use super::*;
use crate::persistence::{Address, AttemptId, Durability};
use crate::redacted::OwnerSeal;
use std::mem::size_of;

const MAGIC: &[u8; 8] = b"BBBOOT01";
const COMPLETION_MAGIC: &[u8; 8] = b"BBCOMP01";

fn valid(ok: bool) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::Corrupt)
    }
}
fn nonzero(bytes: &[u8]) -> Result<(), Error> {
    valid(bytes.iter().any(|b| *b != 0))
}
fn name(s: &str) -> Result<(), Error> {
    valid(!s.is_empty())
}

#[derive(Clone, Copy)]
struct Budget {
    bounds: Bounds,
    bytes: usize,
    items: usize,
}
impl Budget {
    fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            bytes: 0,
            items: 0,
        }
    }
    fn charge(&mut self, items: usize, bytes: usize) -> Result<(), Error> {
        self.items = self.items.checked_add(items).ok_or(Error::Bounds)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(Error::Bounds)?;
        if self.items > self.bounds.items as usize || self.bytes > self.bounds.bytes as usize {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    fn vector<T>(&mut self, count: usize) -> Result<(), Error> {
        self.charge(
            count,
            count.checked_mul(size_of::<T>()).ok_or(Error::Bounds)?,
        )
    }
}
struct Writer {
    out: Secret<Vec<u8>>,
    budget: Budget,
}
impl Writer {
    fn new(bounds: Bounds, kind: u8, tag: u8) -> Result<Self, Error> {
        Self::with_magic(bounds, MAGIC, kind, tag)
    }
    fn with_magic(bounds: Bounds, magic: &[u8; 8], kind: u8, tag: u8) -> Result<Self, Error> {
        let mut w = Self {
            out: Secret::new(Vec::new()),
            budget: Budget::new(bounds),
        };
        w.put(magic)?;
        w.u32(VERSION)?;
        w.put(&[kind, tag, 0, 0])?;
        Ok(w)
    }
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let n = self
            .out
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::Bounds)?;
        if n > self.budget.bounds.bytes as usize {
            return Err(Error::Bounds);
        }
        self.out
            .0
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Bounds)?;
        self.out.0.extend_from_slice(bytes);
        Ok(())
    }
    fn byte(&mut self, n: u8) -> Result<(), Error> {
        self.put(&[n])
    }
    fn u32(&mut self, n: u32) -> Result<(), Error> {
        self.put(&n.to_le_bytes())
    }
    fn u64(&mut self, n: u64) -> Result<(), Error> {
        self.put(&n.to_le_bytes())
    }
    fn count(&mut self, n: usize) -> Result<(), Error> {
        self.u32(u32::try_from(n).map_err(|_| Error::Bounds)?)
    }
    fn blob(&mut self, b: &[u8]) -> Result<(), Error> {
        self.budget.charge(0, b.len())?;
        self.count(b.len())?;
        self.put(b)
    }
    fn secret<O>(&mut self, s: &Secret<Vec<u8>, O>) -> Result<(), Error> {
        self.blob(&s.0)
    }
    fn optional<O>(&mut self, s: &Option<Secret<Vec<u8>, O>>) -> Result<(), Error> {
        self.byte(u8::from(s.is_some()))?;
        if let Some(s) = s {
            self.secret(s)?;
        }
        Ok(())
    }
    fn bounds(&mut self, b: Bounds) -> Result<(), Error> {
        self.u32(b.items)?;
        self.u32(b.bytes)
    }
    fn id(&mut self, id: &[u8]) -> Result<(), Error> {
        nonzero(id)?;
        self.put(id)
    }
    fn format(&mut self, f: &Format) -> Result<(), Error> {
        self.id(&f.owner)?;
        // Zero logical records the absence of any historical logical envelope.
        valid(f.physical != 0 && f.codec != 0)?;
        self.u32(f.physical)?;
        self.u32(f.logical)?;
        self.u32(f.codec)
    }
    fn source(&mut self, s: &SourceIdentity) -> Result<(), Error> {
        self.id(&s.native_anchor)?;
        self.id(&s.dataset.0)?;
        self.byte(u8::from(s.format.is_some()))?;
        if let Some(f) = &s.format {
            self.format(f)?;
        }
        self.id(&s.catalogue_digest)?;
        self.id(&s.layout_digest)
    }
    fn info(&mut self, i: &BackendInfo) -> Result<(), Error> {
        self.id(&i.dataset.0)?;
        self.id(&i.atomic_domain)?;
        self.id(&i.clock_authority)?;
        valid(i.physical_version != 0)?;
        self.u32(i.physical_version)?;
        self.byte(match i.durability {
            Durability::Ephemeral => 0,
            Durability::Local => 1,
            Durability::Quorum => 2,
        })
    }
    fn upgrade<O>(&mut self, u: &UpgradeRef<O>) -> Result<(), Error> {
        self.id(&u.id)?;
        valid(!u.authority.0.is_empty())?;
        self.secret(&u.authority)
    }
    fn selector<O>(&mut self, s: &SourceSelector<O>) -> Result<(), Error> {
        match s {
            SourceSelector::Scan { table } => {
                self.byte(0)?;
                self.u32(*table)
            }
            SourceSelector::Exact { table, key } => {
                self.byte(1)?;
                self.u32(*table)?;
                self.secret(key)
            }
            SourceSelector::IndexPrefix {
                table,
                index,
                prefix,
            } => {
                self.byte(2)?;
                self.u32(*table)?;
                self.u32(*index)?;
                self.secret(prefix)
            }
        }
    }
    fn recovery(&mut self, r: &RecoveryReady) -> Result<(), Error> {
        self.id(&r.upgrade)?;
        self.id(&r.target.0)?;
        self.id(&r.activation_receipt_digest)?;
        self.id(&r.selector_digest)
    }
    fn receipt<O>(&mut self, r: &ActivationReceipt<O>) -> Result<(), Error> {
        self.id(&r.attempt.dataset.0)?;
        valid(r.attempt.writer_epoch != 0 && r.attempt.execution_epoch != 0)?;
        self.u64(r.attempt.writer_epoch)?;
        self.id(&r.attempt.writer)?;
        self.u64(r.attempt.execution_epoch)?;
        self.id(&r.attempt.operation)?;
        self.id(&r.candidate_fingerprint)?;
        // Primitive Applied receipts may carry an empty result. Preserve those
        // exact bytes; identity, fingerprint and checkpoint remain mandatory.
        self.secret(&r.original_result)?;
        self.id(&r.checkpoint_address.namespace)?;
        valid(!r.checkpoint_address.key.is_empty())?;
        self.blob(&r.checkpoint_address.key)?;
        self.id(&r.checkpoint_value_digest)?;
        self.byte(match r.phase {
            CompletionPhase::Activation => 0,
            CompletionPhase::Complete => 1,
        })
    }
    fn catalogue(&mut self, catalogue: &[super::super::archive::Table]) -> Result<(), Error> {
        self.budget
            .vector::<super::super::archive::Table>(catalogue.len())?;
        self.count(catalogue.len())?;
        for (at, t) in catalogue.iter().enumerate() {
            name(&t.name)?;
            valid(at == 0 || catalogue[at - 1].name < t.name)?;
            valid(!t.columns.is_empty() && !t.native_layout.is_empty())?;
            self.blob(t.name.as_bytes())?;
            self.budget.vector::<String>(t.columns.len())?;
            self.count(t.columns.len())?;
            for (j, c) in t.columns.iter().enumerate() {
                name(c)?;
                valid(!t.columns[..j].contains(c))?;
                self.blob(c.as_bytes())?;
            }
            self.blob(&t.native_layout)?;
        }
        Ok(())
    }
    fn inspection<O>(&mut self, i: &Inspection<O>) -> Result<(), Error> {
        inspection_valid(i)?;
        self.byte(state_tag(i.state))?;
        self.byte(u8::from(i.source.is_some()))?;
        if let Some(s) = &i.source {
            self.source(s)?;
        }
        self.optional(&i.admission_marker)?;
        self.catalogue(&i.catalogue)?;
        self.budget
            .vector::<NativeCapability>(i.capabilities.len())?;
        self.count(i.capabilities.len())?;
        for (at, c) in i.capabilities.iter().enumerate() {
            valid(!i.capabilities[..at].contains(c))?;
            self.byte(cap_tag(*c))?;
        }
        Ok(())
    }
}
fn state_tag(s: InspectionState) -> u8 {
    match s {
        InspectionState::Empty => 0,
        InspectionState::Current => 1,
        InspectionState::Legacy => 2,
        InspectionState::InProgress => 3,
        InspectionState::Unsupported => 4,
        InspectionState::Busy => 5,
    }
}
fn cap_tag(c: NativeCapability) -> u8 {
    match c {
        NativeCapability::Snapshot => 0,
        NativeCapability::PersistentFence => 1,
        NativeCapability::Resume => 2,
        NativeCapability::InactiveTarget => 3,
        NativeCapability::CurrentOpen => 4,
    }
}
fn inspection_valid<O>(i: &Inspection<O>) -> Result<(), Error> {
    valid((i.state == InspectionState::Empty) == i.source.is_none())?;
    if i.state == InspectionState::Empty {
        valid(i.catalogue.is_empty() && i.admission_marker.is_none())?;
    }
    if i.state == InspectionState::Legacy {
        valid(i.source.as_ref().is_some_and(|s| s.format.is_some()))?;
    }
    if i.state == InspectionState::Current {
        valid(i.admission_marker.as_ref().is_some_and(|s| !s.0.is_empty()))?;
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    budget: Budget,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], bounds: Bounds, kind: u8) -> Result<(Self, u8), Error> {
        Self::with_magic(bytes, bounds, MAGIC, kind)
    }
    fn with_magic(
        bytes: &'a [u8],
        bounds: Bounds,
        magic: &[u8; 8],
        kind: u8,
    ) -> Result<(Self, u8), Error> {
        if bytes.len() > bounds.bytes as usize {
            return Err(Error::Bounds);
        }
        let mut r = Self {
            bytes,
            budget: Budget::new(bounds),
        };
        valid(r.take(8)? == magic)?;
        valid(r.u32()? == VERSION)?;
        valid(r.byte()? == kind)?;
        let tag = r.byte()?;
        valid(r.take(2)? == [0, 0])?;
        Ok((r, tag))
    }
    fn end(self) -> Result<(), Error> {
        valid(self.bytes.is_empty())
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let b = self.bytes.get(..n).ok_or(Error::Corrupt)?;
        self.bytes = &self.bytes[n..];
        Ok(b)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }
    fn presence(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Corrupt),
        }
    }
    fn id<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let b = self.take(N)?;
        nonzero(b)?;
        b.try_into().map_err(|_| Error::Corrupt)
    }
    fn bounds(&mut self) -> Result<Bounds, Error> {
        Ok(Bounds {
            items: self.u32()?,
            bytes: self.u32()?,
        })
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.budget.charge(0, n)?;
        self.take(n)
    }
    fn secret<O>(
        &mut self,
        make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
    ) -> Result<Secret<Vec<u8>, O>, Error> {
        let b = self.blob()?;
        let mut s = make(Vec::new());
        s.0.try_reserve_exact(b.len()).map_err(|_| Error::Bounds)?;
        s.0.extend_from_slice(b);
        Ok(s)
    }
    fn optional<O>(
        &mut self,
        make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
    ) -> Result<Option<Secret<Vec<u8>, O>>, Error> {
        if self.presence()? {
            Ok(Some(self.secret(make)?))
        } else {
            Ok(None)
        }
    }
    fn public_blob(&mut self) -> Result<Vec<u8>, Error> {
        let b = self.blob()?;
        let mut out = Vec::new();
        out.try_reserve_exact(b.len()).map_err(|_| Error::Bounds)?;
        out.extend_from_slice(b);
        Ok(out)
    }
    fn text(&mut self) -> Result<String, Error> {
        let b = self.blob()?;
        let s = std::str::from_utf8(b).map_err(|_| Error::Corrupt)?;
        name(s)?;
        let mut out = String::new();
        out.try_reserve_exact(b.len()).map_err(|_| Error::Bounds)?;
        out.push_str(s);
        Ok(out)
    }
    fn vector<T>(&mut self) -> Result<(Vec<T>, usize), Error> {
        let n = self.u32()? as usize;
        self.budget.vector::<T>(n)?;
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Error::Bounds)?;
        Ok((v, n))
    }
    fn format(&mut self) -> Result<Format, Error> {
        let f = Format {
            owner: self.id()?,
            physical: self.u32()?,
            logical: self.u32()?,
            codec: self.u32()?,
        };
        // Zero logical records the absence of any historical logical envelope.
        valid(f.physical != 0 && f.codec != 0)?;
        Ok(f)
    }
    fn source(&mut self) -> Result<SourceIdentity, Error> {
        Ok(SourceIdentity {
            native_anchor: self.id()?,
            dataset: DatasetId(self.id()?),
            format: if self.presence()? {
                Some(self.format()?)
            } else {
                None
            },
            catalogue_digest: self.id()?,
            layout_digest: self.id()?,
        })
    }
    fn info(&mut self) -> Result<BackendInfo, Error> {
        let dataset = DatasetId(self.id()?);
        let atomic_domain = self.id()?;
        let clock_authority = self.id()?;
        let physical_version = self.u32()?;
        valid(physical_version != 0)?;
        let durability = match self.byte()? {
            0 => Durability::Ephemeral,
            1 => Durability::Local,
            2 => Durability::Quorum,
            _ => return Err(Error::Corrupt),
        };
        Ok(BackendInfo {
            dataset,
            atomic_domain,
            clock_authority,
            physical_version,
            durability,
        })
    }
    fn upgrade<O>(
        &mut self,
        make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
    ) -> Result<UpgradeRef<O>, Error> {
        let id = self.id()?;
        let authority = self.secret(make)?;
        valid(!authority.0.is_empty())?;
        Ok(UpgradeRef { id, authority })
    }
    fn selector<O>(
        &mut self,
        make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
    ) -> Result<SourceSelector<O>, Error> {
        Ok(match self.byte()? {
            0 => SourceSelector::Scan { table: self.u32()? },
            1 => SourceSelector::Exact {
                table: self.u32()?,
                key: self.secret(make)?,
            },
            2 => SourceSelector::IndexPrefix {
                table: self.u32()?,
                index: self.u32()?,
                prefix: self.secret(make)?,
            },
            _ => return Err(Error::Corrupt),
        })
    }
    fn recovery(&mut self) -> Result<RecoveryReady, Error> {
        Ok(RecoveryReady {
            upgrade: self.id()?,
            target: DatasetId(self.id()?),
            activation_receipt_digest: self.id()?,
            selector_digest: self.id()?,
        })
    }
    fn receipt<O>(
        &mut self,
        make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
    ) -> Result<ActivationReceipt<O>, Error> {
        let attempt = AttemptId {
            dataset: DatasetId(self.id()?),
            writer_epoch: self.u64()?,
            writer: self.id()?,
            execution_epoch: self.u64()?,
            operation: self.id()?,
        };
        valid(attempt.writer_epoch != 0 && attempt.execution_epoch != 0)?;
        let candidate_fingerprint = self.id()?;
        let original_result = self.secret(make)?;
        let namespace = self.id()?;
        let key = self.public_blob()?;
        valid(!key.is_empty())?;
        let checkpoint_value_digest = self.id()?;
        let phase = match self.byte()? {
            0 => CompletionPhase::Activation,
            1 => CompletionPhase::Complete,
            _ => return Err(Error::Corrupt),
        };
        Ok(ActivationReceipt {
            attempt,
            candidate_fingerprint,
            original_result,
            checkpoint_address: Address { namespace, key },
            checkpoint_value_digest,
            phase,
        })
    }
    fn catalogue(&mut self) -> Result<Vec<super::super::archive::Table>, Error> {
        let (mut catalogue, count) = self.vector::<super::super::archive::Table>()?;
        for _ in 0..count {
            let name = self.text()?;
            valid(catalogue.last().is_none_or(|t| t.name < name))?;
            let (mut columns, n) = self.vector::<String>()?;
            valid(n != 0)?;
            for _ in 0..n {
                let c = self.text()?;
                valid(!columns.contains(&c))?;
                columns.push(c);
            }
            let native_layout = self.public_blob()?;
            valid(!native_layout.is_empty())?;
            catalogue.push(super::super::archive::Table {
                name,
                columns,
                native_layout,
            });
        }
        Ok(catalogue)
    }
    fn inspection<O>(
        &mut self,
        make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
    ) -> Result<Inspection<O>, Error> {
        let state = match self.byte()? {
            0 => InspectionState::Empty,
            1 => InspectionState::Current,
            2 => InspectionState::Legacy,
            3 => InspectionState::InProgress,
            4 => InspectionState::Unsupported,
            5 => InspectionState::Busy,
            _ => return Err(Error::Corrupt),
        };
        let source = if self.presence()? {
            Some(self.source()?)
        } else {
            None
        };
        let admission_marker = self.optional(make)?;
        let catalogue = self.catalogue()?;
        let (mut capabilities, count) = self.vector::<NativeCapability>()?;
        for _ in 0..count {
            let c = match self.byte()? {
                0 => NativeCapability::Snapshot,
                1 => NativeCapability::PersistentFence,
                2 => NativeCapability::Resume,
                3 => NativeCapability::InactiveTarget,
                4 => NativeCapability::CurrentOpen,
                _ => return Err(Error::Corrupt),
            };
            valid(!capabilities.contains(&c))?;
            capabilities.push(c);
        }
        let i = Inspection {
            state,
            source,
            admission_marker,
            catalogue,
            capabilities,
        };
        inspection_valid(&i)?;
        Ok(i)
    }
}

/// Encode one exact request in protected ownership with aggregate allocation limits.
pub fn encode_request<O>(request: &Request<O>, bounds: Bounds) -> Result<Secret<Vec<u8>>, Error> {
    let tag = match request {
        Request::Inspect { .. } => 0,
        Request::BeginOrResume { .. } => 1,
        Request::SourcePage { .. } => 2,
        Request::Target { .. } => 3,
        Request::CheckFence { .. } => 4,
        Request::Finish { .. } => 5,
    };
    let mut w = Writer::new(bounds, 1, tag)?;
    match request {
        Request::Inspect { bounds } => w.bounds(*bounds)?,
        Request::BeginOrResume {
            expected_source,
            route_digest,
            target_format,
            operation_id,
        } => {
            w.source(expected_source)?;
            w.id(route_digest)?;
            w.format(target_format)?;
            w.id(operation_id)?;
        }
        Request::SourcePage {
            upgrade,
            snapshot,
            family,
            selector,
            cursor,
            bounds,
        } => {
            w.upgrade(upgrade)?;
            w.id(snapshot)?;
            w.id(family)?;
            w.budget.charge(1, 0)?;
            w.selector(selector)?;
            w.optional(cursor)?;
            w.bounds(*bounds)?;
        }
        Request::Target { upgrade } | Request::CheckFence { upgrade } => w.upgrade(upgrade)?,
        Request::Finish {
            upgrade,
            activation_receipt,
        } => {
            w.upgrade(upgrade)?;
            w.receipt(activation_receipt)?;
        }
    }
    Ok(w.out)
}
fn request_with<O>(
    bytes: &[u8],
    bounds: Bounds,
    make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
) -> Result<Request<O>, Error> {
    let (mut r, tag) = Reader::new(bytes, bounds, 1)?;
    let out = match tag {
        0 => Request::Inspect {
            bounds: r.bounds()?,
        },
        1 => Request::BeginOrResume {
            expected_source: r.source()?,
            route_digest: r.id()?,
            target_format: r.format()?,
            operation_id: r.id()?,
        },
        2 => {
            let upgrade = r.upgrade(make)?;
            let snapshot = r.id()?;
            let family = r.id()?;
            r.budget.charge(1, 0)?;
            Request::SourcePage {
                upgrade,
                snapshot,
                family,
                selector: r.selector(make)?,
                cursor: r.optional(make)?,
                bounds: r.bounds()?,
            }
        }
        3 => Request::Target {
            upgrade: r.upgrade(make)?,
        },
        4 => Request::CheckFence {
            upgrade: r.upgrade(make)?,
        },
        5 => Request::Finish {
            upgrade: r.upgrade(make)?,
            activation_receipt: r.receipt(make)?,
        },
        _ => return Err(Error::Corrupt),
    };
    r.end()?;
    Ok(out)
}
/// Decode one complete bounded request into kernel-owned protected buffers.
pub fn decode_request(bytes: &[u8], bounds: Bounds) -> Result<Request, Error> {
    request_with(bytes, bounds, Secret::new)
}
/// Decode one complete bounded request into the native owner's protected buffers.
pub fn decode_request_owned<O: OwnerSeal>(
    bytes: &[u8],
    bounds: Bounds,
) -> Result<Request<O>, Error> {
    request_with(bytes, bounds, Secret::held)
}
fn error_tag(e: Error) -> u8 {
    128 + match e {
        Error::Busy => 0,
        Error::Pending => 1,
        Error::UnsupportedFormat => 2,
        Error::MissingCapability => 3,
        Error::SourceChanged => 4,
        Error::Corrupt => 5,
        Error::Refused => 6,
        Error::Unavailable => 7,
        Error::Unknown => 8,
        Error::Bounds => 9,
    }
}
fn tagged_error(tag: u8) -> Result<Error, Error> {
    Ok(match tag {
        128 => Error::Busy,
        129 => Error::Pending,
        130 => Error::UnsupportedFormat,
        131 => Error::MissingCapability,
        132 => Error::SourceChanged,
        133 => Error::Corrupt,
        134 => Error::Refused,
        135 => Error::Unavailable,
        136 => Error::Unknown,
        137 => Error::Bounds,
        _ => return Err(Error::Corrupt),
    })
}
/// Encode a definitive response or a content-free typed native failure.
pub fn encode_response<O>(
    response: &Result<Response<O>, Error>,
    bounds: Bounds,
) -> Result<Secret<Vec<u8>>, Error> {
    let response = match response {
        Err(e) => return Ok(Writer::new(bounds, 2, error_tag(*e))?.out),
        Ok(r) => r,
    };
    let tag = match response {
        Response::Inspected(_) => 0,
        Response::Begun(_) => 1,
        Response::SourcePage(_) => 2,
        Response::Target(_) => 3,
        Response::Fence(_) => 4,
        Response::RecoveryReady(_) => 5,
        Response::ServingReady(_) => 6,
    };
    let mut w = Writer::new(bounds, 2, tag)?;
    match response {
        Response::Inspected(i) => w.inspection(i)?,
        Response::Begun(u) => {
            w.upgrade(&u.reference)?;
            w.source(&u.source)?;
            w.id(&u.snapshot)?;
            w.info(&u.target)?;
            w.u64(u.native_step)?;
            w.catalogue(&u.catalogue)?;
        }
        Response::SourcePage(p) => {
            w.id(&p.snapshot)?;
            w.id(&p.family)?;
            w.budget.vector::<SourceRow<O>>(p.rows.len())?;
            w.count(p.rows.len())?;
            for row in &p.rows {
                super::super::legacy_row::Row::decode(&row.value.0).map_err(|_| Error::Corrupt)?;
                w.u32(row.table)?;
                w.secret(&row.native_key)?;
                w.secret(&row.value)?;
            }
            w.optional(&p.next)?;
            w.id(&p.source_digest)?;
            w.id(&p.coverage_digest)?;
        }
        Response::Target(t) => {
            w.id(&t.upgrade)?;
            w.info(&t.info)?;
            valid(!t.binding.0.is_empty())?;
            w.secret(&t.binding)?;
        }
        Response::Fence(f) => {
            w.id(&f.upgrade)?;
            w.source(&f.source)?;
            w.id(&f.enforcement_digest)?;
            w.id(&f.observation_digest)?;
            w.id(&f.snapshot)?;
        }
        Response::RecoveryReady(r) => w.recovery(r)?,
        Response::ServingReady(r) => {
            w.recovery(&r.recovery)?;
            w.id(&r.completed_checkpoint_digest)?;
        }
    }
    Ok(w.out)
}
fn response_with<O>(
    bytes: &[u8],
    bounds: Bounds,
    make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
) -> Result<Response<O>, Error> {
    let (mut r, tag) = Reader::new(bytes, bounds, 2)?;
    if tag >= 128 {
        let e = tagged_error(tag)?;
        r.end()?;
        return Err(e);
    }
    let out = match tag {
        0 => Response::Inspected(r.inspection(make)?),
        1 => Response::Begun(Upgrade {
            reference: r.upgrade(make)?,
            source: r.source()?,
            snapshot: r.id()?,
            target: r.info()?,
            native_step: r.u64()?,
            catalogue: r.catalogue()?,
        }),
        2 => {
            let snapshot = r.id()?;
            let family = r.id()?;
            let (mut rows, n) = r.vector::<SourceRow<O>>()?;
            for _ in 0..n {
                let table = r.u32()?;
                let native_key = r.secret(make)?;
                let value = r.secret(make)?;
                super::super::legacy_row::Row::decode(&value.0).map_err(|_| Error::Corrupt)?;
                rows.push(SourceRow {
                    table,
                    native_key,
                    value,
                });
            }
            Response::SourcePage(SourcePage {
                snapshot,
                family,
                rows,
                next: r.optional(make)?,
                source_digest: r.id()?,
                coverage_digest: r.id()?,
            })
        }
        3 => {
            let upgrade = r.id()?;
            let info = r.info()?;
            let binding = r.secret(make)?;
            valid(!binding.0.is_empty())?;
            Response::Target(TargetBinding {
                upgrade,
                info,
                binding,
            })
        }
        4 => Response::Fence(Fence {
            upgrade: r.id()?,
            source: r.source()?,
            enforcement_digest: r.id()?,
            observation_digest: r.id()?,
            snapshot: r.id()?,
        }),
        5 => Response::RecoveryReady(r.recovery()?),
        6 => Response::ServingReady(ServingReady {
            recovery: r.recovery()?,
            completed_checkpoint_digest: r.id()?,
        }),
        _ => return Err(Error::Corrupt),
    };
    r.end()?;
    Ok(out)
}
/// Decode a complete response; a typed native failure is returned as `Err`.
pub fn decode_response(bytes: &[u8], bounds: Bounds) -> Result<Response, Error> {
    response_with(bytes, bounds, Secret::new)
}
/// Decode a complete response into the native owner's protected buffers.
pub fn decode_response_owned<O: OwnerSeal>(
    bytes: &[u8],
    bounds: Bounds,
) -> Result<Response<O>, Error> {
    response_with(bytes, bounds, Secret::held)
}
/// Encode the exact empty/current/checkpoint-bound recovery OPEN binding.
pub fn encode_open_binding(
    binding: &OpenBinding,
    bounds: Bounds,
) -> Result<Secret<Vec<u8>>, Error> {
    let mut w = Writer::new(
        bounds,
        3,
        match binding {
            OpenBinding::Empty => 0,
            OpenBinding::Current { .. } => 1,
            OpenBinding::Recovery(_) => 2,
        },
    )?;
    match binding {
        OpenBinding::Empty => {}
        OpenBinding::Current {
            source,
            admission_marker_digest,
        } => {
            w.source(source)?;
            w.id(admission_marker_digest)?;
        }
        OpenBinding::Recovery(r) => w.recovery(r)?,
    }
    Ok(w.out)
}
/// Decode one complete OPEN binding, rejecting extra or unknown framing.
pub fn decode_open_binding(bytes: &[u8], bounds: Bounds) -> Result<OpenBinding, Error> {
    let (mut r, tag) = Reader::new(bytes, bounds, 3)?;
    let out = match tag {
        0 => OpenBinding::Empty,
        1 => OpenBinding::Current {
            source: r.source()?,
            admission_marker_digest: r.id()?,
        },
        2 => OpenBinding::Recovery(r.recovery()?),
        _ => return Err(Error::Corrupt),
    };
    r.end()?;
    Ok(out)
}

/// Encode a neutral completion witness with distinct `BBCOMP01` magic and kind 4.
/// The header version is the marker version; tags 0/1 mean Activation/Complete.
/// Native owners must separately verify atomic receipt/checkpoint/marker evidence.
pub fn encode_completion_marker(
    marker: &CompletionMarker,
    bounds: Bounds,
) -> Result<Secret<Vec<u8>>, Error> {
    valid(marker.version == VERSION)?;
    let tag = match marker.phase {
        CompletionPhase::Activation => 0,
        CompletionPhase::Complete => 1,
    };
    let mut w = Writer::with_magic(bounds, COMPLETION_MAGIC, 4, tag)?;
    w.id(&marker.upgrade)?;
    w.id(&marker.source.0)?;
    w.id(&marker.target.0)?;
    w.id(&marker.checkpoint_address.namespace)?;
    valid(!marker.checkpoint_address.key.is_empty())?;
    w.blob(&marker.checkpoint_address.key)?;
    w.id(&marker.checkpoint_value_digest)?;
    Ok(w.out)
}
/// Decode exact bounded completion-witness framing, without granting native authority.
pub fn decode_completion_marker(bytes: &[u8], bounds: Bounds) -> Result<CompletionMarker, Error> {
    let (mut r, tag) = Reader::with_magic(bytes, bounds, COMPLETION_MAGIC, 4)?;
    let phase = match tag {
        0 => CompletionPhase::Activation,
        1 => CompletionPhase::Complete,
        _ => return Err(Error::Corrupt),
    };
    let upgrade = r.id()?;
    let source = DatasetId(r.id()?);
    let target = DatasetId(r.id()?);
    let namespace = r.id()?;
    let key = r.public_blob()?;
    valid(!key.is_empty())?;
    let checkpoint_value_digest = r.id()?;
    r.end()?;
    Ok(CompletionMarker {
        version: VERSION,
        phase,
        upgrade,
        source,
        target,
        checkpoint_address: Address { namespace, key },
        checkpoint_value_digest,
    })
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
