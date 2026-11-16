// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORD-FORMAT CHAIN (MIGRATE-ON-BOOT §6a, §A6a; AGREED 268). Core's native records carry
//! one version, the kernel manifest's format. Any change to a record's layout or payload codec
//! bumps [`RECORD_FORMAT`] by one and ships exactly one step N → N+1 here; format N is decoded only
//! inside that step. 1.6.0 ships [`RECORD_STEPS`] empty: its only records step is R0
//! ([`super::run`]), which always encodes at the current format.
//!
//! A step runs in pages under the manifest's `migrating_to` tail and a cursor record beside the
//! manifest: an open commit (manifest (f, 0) → (f, f+1), cursor), one commit per page (exact on
//! the manifest, the cursor and every old row; the converted rows; the cursor advanced), and the
//! final page is the flip (manifest (f+1, 0), cursor deleted, RECORDS_EVOLVED) in one commit.
//! Nothing serves until the manifest is current, so mixed-format rows are read only here.

use busbar_contract::persistence::cells::{self, Cell};
use busbar_contract::persistence::NamespaceId;
use busbar_contract::secure::SecureVec;

use super::{Audit, Candidate, Committed, RecordStore, Refusal, PAGE};

/// The record format this busbar reads and writes (the kernel manifest's).
pub const RECORD_FORMAT: u32 = 1;

/// One record-format step, `from` → `from + 1`.
#[derive(Clone, Copy)]
pub struct RecordStep {
    /// The format it reads.
    pub from: u32,
    /// The namespaces whose rows it rewrites, in order.
    pub namespaces: &'static [NamespaceId],
    /// One row at format `from` in, the same row at `from + 1` out.
    pub convert: Convert,
}

/// One record conversion: a row at format `from` (its namespace, key and value) to `from + 1`.
pub type Convert = fn(NamespaceId, &[u8], &[u8]) -> Result<SecureVec, Refusal>;

/// The production steps: none in 1.6.0.
pub const RECORD_STEPS: &[RecordStep] = &[];

/// Whether the production chain has a step from format `from` (admission's Older/Migrating test).
#[must_use]
pub fn has_step(from: u32) -> bool {
    RECORD_STEPS.iter().any(|step| step.from == from)
}

/// The cursor record's key, beside the manifest.
pub const CURSOR_KEY: &[u8] = b"step";

/// The kernel manifest, as the seam reads it: where it lives, its bytes and its two numbers, and
/// the kernel's own encoder for the same manifest at another format and tail.
pub struct Manifest<'a> {
    /// Its namespace.
    pub ns: NamespaceId,
    /// Its key.
    pub key: &'a [u8],
    /// Its bytes as read.
    pub bytes: &'a [u8],
    /// The format its rows are at.
    pub format: u32,
    /// The format a step under way converts them to (0 = none).
    pub migrating_to: u32,
    /// The same manifest at `(format, migrating_to)`.
    pub encode: &'a dyn Fn(u32, u32) -> Vec<u8>,
}

/// Where a step is: the namespace index, the last key done in it, the rows done.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cursor {
    ns: usize,
    last: Vec<u8>,
    rows: u64,
}

impl Cursor {
    fn encode(&self) -> SecureVec {
        let int = |v: u64| Cell::Int(i64::try_from(v).unwrap_or(i64::MAX));
        SecureVec::from(cells::value(&[
            int(self.ns as u64),
            Cell::Blob(&self.last),
            int(self.rows),
        ]))
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        match cells::decode(bytes).ok()?.as_slice() {
            [Cell::Int(ns), Cell::Blob(last), Cell::Int(rows)] => Some(Self {
                ns: usize::try_from(*ns).ok()?,
                last: last.to_vec(),
                rows: u64::try_from(*rows).ok()?,
            }),
            _ => None,
        }
    }
}

/// [`evolve_with`] over the production chain to [`RECORD_FORMAT`].
///
/// # Errors
/// As [`evolve_with`].
#[cold]
#[inline(never)]
pub fn evolve(store: &dyn RecordStore, manifest: &Manifest<'_>) -> Result<Option<u64>, Refusal> {
    evolve_with(store, RECORD_STEPS, RECORD_FORMAT, manifest)
}

fn newer() -> Refusal {
    Refusal::Newer(
        "a newer busbar wrote or began migrating this store's records; run that version".to_owned(),
    )
}

/// Run `steps` from the manifest's format to `current`, each in pages, resuming a step under way.
/// `Ok(None)` for a current manifest (no read made); otherwise the rows converted.
///
/// # Errors
/// NEWER for a format or tail above `current`; UNSUPPORTED for a format no step reads; VERIFY when
/// a commit loses its predicates (another owner, or the manifest moved); a step's own refusal.
pub fn evolve_with(
    store: &dyn RecordStore,
    steps: &[RecordStep],
    current: u32,
    manifest: &Manifest<'_>,
) -> Result<Option<u64>, Refusal> {
    let (mut format, mut tail) = (manifest.format, manifest.migrating_to);
    if format == current && tail == 0 {
        return Ok(None);
    }
    if format > current || tail > current {
        return Err(newer());
    }
    let unsupported = |f: u32| {
        Refusal::Unsupported(format!(
            "these records are at format {f}, which this busbar does not convert; upgrade \
             through the release that last read this store first"
        ))
    };
    let mut held = manifest.bytes.to_vec();
    let mut total = 0u64;
    while format < current {
        let step = steps
            .iter()
            .find(|s| s.from == format)
            .ok_or_else(|| unsupported(format))?;
        let mut cursor;
        let mut cursor_bytes;
        if tail == 0 {
            store.register()?;
            let next = (manifest.encode)(format, format + 1);
            cursor = Cursor {
                ns: 0,
                last: Vec::new(),
                rows: 0,
            };
            cursor_bytes = cursor.encode();
            let mut c = Candidate::default();
            c.exact.push((
                manifest.ns,
                manifest.key.to_vec(),
                SecureVec::from(held.clone()),
            ));
            c.absent.push((manifest.ns, CURSOR_KEY.to_vec()));
            c.put.push((
                manifest.ns,
                manifest.key.to_vec(),
                SecureVec::from(next.clone()),
            ));
            c.put
                .push((manifest.ns, CURSOR_KEY.to_vec(), cursor_bytes.clone()));
            commit(store, c)?;
            held = next;
        } else {
            if tail != format + 1 {
                return Err(unsupported(format));
            }
            let found = store
                .scan(manifest.ns, b"", 16)?
                .into_iter()
                .find(|(key, _)| key.as_slice() == CURSOR_KEY)
                .ok_or_else(|| {
                    Refusal::Verify(format!(
                        "the records are migrating from format {format} but the step's cursor \
                         is missing"
                    ))
                })?;
            cursor = Cursor::decode(&found.1).ok_or_else(|| {
                Refusal::Verify("the record-format step's cursor is malformed".to_owned())
            })?;
            cursor_bytes = found.1;
        }
        loop {
            let mut c = Candidate::default();
            c.exact.push((
                manifest.ns,
                manifest.key.to_vec(),
                SecureVec::from(held.clone()),
            ));
            c.exact
                .push((manifest.ns, CURSOR_KEY.to_vec(), cursor_bytes.clone()));
            let mut next = cursor.clone();
            let exhausted = match step.namespaces.get(cursor.ns) {
                None => true,
                Some(&ns) => {
                    let page = store.scan(ns, &cursor.last, PAGE)?;
                    for (key, value) in &page {
                        let converted = (step.convert)(ns, key, value)?;
                        c.exact.push((ns, key.clone(), value.clone()));
                        c.put.push((ns, key.clone(), converted));
                    }
                    next.rows += page.len() as u64;
                    if let Some((last, _)) = page.last() {
                        next.last.clone_from(last);
                    }
                    page.len() < PAGE as usize
                }
            };
            if exhausted {
                next.ns += 1;
                next.last.clear();
            }
            if next.ns >= step.namespaces.len() {
                let flipped = (manifest.encode)(format + 1, 0);
                c.put.push((
                    manifest.ns,
                    manifest.key.to_vec(),
                    SecureVec::from(flipped.clone()),
                ));
                c.delete.push((manifest.ns, CURSOR_KEY.to_vec()));
                c.audit.push(Audit::RecordsEvolved {
                    from: format,
                    to: format + 1,
                    rows: next.rows,
                });
                commit(store, c)?;
                total += next.rows;
                held = flipped;
                break;
            }
            let encoded = next.encode();
            c.put
                .push((manifest.ns, CURSOR_KEY.to_vec(), encoded.clone()));
            commit(store, c)?;
            cursor = next;
            cursor_bytes = encoded;
        }
        format += 1;
        tail = 0;
    }
    Ok(Some(total))
}

fn commit(store: &dyn RecordStore, c: Candidate) -> Result<(), Refusal> {
    match store.commit(c)? {
        Committed::Applied => Ok(()),
        Committed::Conflict => Err(Refusal::Verify(
            "a record-format step lost its predicates (another owner, or the manifest moved); \
             nothing of the page was written"
                .to_owned(),
        )),
    }
}
