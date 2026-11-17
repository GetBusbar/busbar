// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORD-FORMAT CHAIN (MIGRATE-ON-BOOT §6a, §A6a; AGREED 268; #319 r4 §7). Core's native
//! records carry one version, the kernel manifest's format. Any change to a record's layout or
//! payload codec bumps [`RECORD_FORMAT`] by one and ships exactly one step N → N+1 here; format N
//! is decoded only inside that step. 1.6.0 ships [`RECORD_STEPS`] empty: its only records step is
//! R0 ([`super::run`]), which always encodes at the current format.
//!
//! A chain runs under the manifest's `migrating_to` tail and a cursor record beside the manifest:
//! - the opening (manifest (f, 0) → (f, f+1), the step's initial cursor), which is the kernel's
//!   admission's, atomically with a dataset epoch advance and a fresh migration owner (r4 §6);
//! - payload pages (exact on the manifest, the cursor and every old row; the converted rows; the
//!   cursor at the last committed source key, with checked per-namespace counts);
//! - a zero-payload namespace advance once a namespace is explicitly exhausted (every row of a page
//!   committed and the store's continuation absent; a page shorter than asked is not the end);
//! - a zero-payload step completion: between steps the manifest moves (f, f+1) → (f+1, f+2) with
//!   the next step's initial cursor, so a chain never publishes an intermediate tail of zero; the
//!   last step's completion is the final publication ([`FormatStore::finalize`]): (T, 0) under a
//!   fresh registrar and an advanced dataset epoch, the cursor deleted. Each completion carries
//!   its RECORDS_EVOLVED.
//!
//! Nothing serves while the tail is nonzero (r4 §5), and the operational full-fleet stop keeps
//! every reader away (r4 §3), so mixed-format rows are read only here.

use busbar_contract::persistence::cells::{self, Cell};
use busbar_contract::persistence::NamespaceId;
use busbar_contract::secure::SecureVec;

use super::{continuation, Audit, Candidate, Committed, FormatStore, Refusal, PAGE};

/// The record format this busbar reads and writes (the kernel manifest's).
pub const RECORD_FORMAT: u32 = 1;

/// One record-format step, `from` → `from + 1`.
#[derive(Clone, Copy)]
pub struct RecordStep {
    /// The format it reads.
    pub from: u32,
    /// The namespaces whose rows it rewrites, in order. Frozen with the step: the cursor's counts
    /// are one per namespace of this list.
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

/// The cursor codec's version (r4 §7.3).
const CURSOR_VERSION: i64 = 1;

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

/// Where a step is (r4 §7.3): the namespace ordinal, the last committed source key in it (`None`:
/// from the beginning; `Some` may be the empty key), and the rows committed per namespace of the
/// step's list. Encoded `[Int(1), Int(ordinal), Int(last_present), Blob(last), Blob(counts)]`,
/// counts one little-endian u64 per namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cursor {
    ns: usize,
    last: Option<Vec<u8>>,
    counts: Vec<u64>,
}

fn malformed() -> Refusal {
    Refusal::Verify("the record-format step's cursor is malformed".to_owned())
}

fn overflow() -> Refusal {
    Refusal::Verify("the record-format step's row count does not fit".to_owned())
}

impl Cursor {
    /// The step's initial cursor: the first namespace, from its beginning, every count zero (the
    /// canonical empty-step cursor when the step names no namespace).
    fn initial(step: &RecordStep) -> Self {
        Self {
            ns: 0,
            last: None,
            counts: vec![0; step.namespaces.len()],
        }
    }

    fn encode(&self) -> Result<SecureVec, Refusal> {
        let ns = i64::try_from(self.ns).map_err(|_| malformed())?;
        let counts: Vec<u8> = self.counts.iter().flat_map(|c| c.to_le_bytes()).collect();
        Ok(SecureVec::from(cells::value(&[
            Cell::Int(CURSOR_VERSION),
            Cell::Int(ns),
            Cell::Int(i64::from(self.last.is_some())),
            Cell::Blob(self.last.as_deref().unwrap_or_default()),
            Cell::Blob(&counts),
        ])))
    }

    /// The cursor of `step`, exactly as [`Self::encode`] writes it; anything else (the prototype
    /// three-cell cursor, another version, a count list of another length) is VERIFY.
    fn decode(bytes: &[u8], step: &RecordStep) -> Result<Self, Refusal> {
        let decoded = cells::decode(bytes).map_err(|_| malformed())?;
        let [Cell::Int(CURSOR_VERSION), Cell::Int(ns), Cell::Int(present), Cell::Blob(last), Cell::Blob(counts)] =
            decoded.as_slice()
        else {
            return Err(malformed());
        };
        let ns = usize::try_from(*ns).map_err(|_| malformed())?;
        let last = match *present {
            0 if last.is_empty() => None,
            1 => Some(last.to_vec()),
            _ => return Err(malformed()),
        };
        let width = step.namespaces.len();
        let in_range = if width == 0 {
            ns == 0 && last.is_none()
        } else {
            ns < width
        };
        if !in_range || counts.len() != width * 8 {
            return Err(malformed());
        }
        let counts = counts
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap_or_default()))
            .collect();
        Ok(Self { ns, last, counts })
    }

    fn rows(&self) -> Result<u64, Refusal> {
        self.counts
            .iter()
            .try_fold(0u64, |sum, c| sum.checked_add(*c))
            .ok_or_else(overflow)
    }
}

/// The cursor the step from `from` in `steps` starts at: what the kernel's opening writes for it
/// (#319 r4 §6). `None` when no step reads `from`.
#[must_use]
pub fn initial_cursor(steps: &[RecordStep], from: u32) -> Option<Vec<u8>> {
    let step = steps.iter().find(|step| step.from == from)?;
    Cursor::initial(step)
        .encode()
        .ok()
        .map(|bytes| bytes.to_vec())
}

fn newer() -> Refusal {
    Refusal::Newer(
        "a newer busbar wrote or began migrating this store's records; run that version".to_owned(),
    )
}

/// The manifest and cursor a commit is exact on, as last committed.
struct Held {
    manifest: Vec<u8>,
    cursor: SecureVec,
}

impl Held {
    fn candidate(&self, manifest: &Manifest<'_>) -> Candidate {
        let mut c = Candidate::default();
        c.exact.push((
            manifest.ns,
            manifest.key.to_vec(),
            SecureVec::from(self.manifest.clone()),
        ));
        c.exact
            .push((manifest.ns, CURSOR_KEY.to_vec(), self.cursor.clone()));
        c
    }
}

/// Run `steps` from the manifest's format to `current`, resuming the step under way. `Ok(None)`
/// for a current manifest (no read made); otherwise the rows converted, every step's counts
/// summed. The kernel's admission opened the step (or claimed it from a stalled owner) before
/// this runs: the manifest's tail is nonzero and `store` commits under the migration owner.
///
/// # Errors
/// NEWER for a format or tail above `current`; UNSUPPORTED for a format no step reads; VERIFY when
/// the step was not opened, a commit loses its predicates or is fenced (another owner), the cursor
/// is missing or malformed, or a store page does not progress; STORE when the store refuses a
/// one-row page or a zero-payload transition; a step's own refusal.
#[cold]
#[inline(never)]
pub fn evolve_with(
    store: &dyn FormatStore,
    steps: &[RecordStep],
    current: u32,
    manifest: &Manifest<'_>,
) -> Result<Option<u64>, Refusal> {
    let (mut format, tail) = (manifest.format, manifest.migrating_to);
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
    let step_from = |f: u32| {
        steps
            .iter()
            .find(|s| s.from == f)
            .ok_or_else(|| unsupported(f))
    };
    // The whole chain to `current` must be supported before anything is read or written.
    for f in format..current {
        step_from(f)?;
    }
    if tail == 0 {
        return Err(Refusal::Verify(format!(
            "the records are at format {format} and no step is open: the store's admission opens \
             it (advancing the dataset epoch) before conversion; nothing was written"
        )));
    }
    if tail != format + 1 {
        return Err(unsupported(format));
    }
    let mut step = step_from(format)?;
    let found = store.read(manifest.ns, CURSOR_KEY)?.ok_or_else(|| {
        Refusal::Verify(format!(
            "the records are migrating from format {format} but the step's cursor is missing"
        ))
    })?;
    let mut cursor = Cursor::decode(&found, step)?;
    let mut held = Held {
        manifest: manifest.bytes.to_vec(),
        cursor: found,
    };
    let mut total = 0u64;
    loop {
        let exhausted = match step.namespaces.get(cursor.ns) {
            None => true,
            Some(&ns) => page(store, manifest, step, ns, &mut cursor, &mut held)?,
        };
        if !exhausted {
            continue;
        }
        let last_namespace = cursor.ns + 1 >= step.namespaces.len();
        if !last_namespace {
            // Zero-payload namespace advance: the key resets, the counts stay.
            let next = Cursor {
                ns: cursor.ns + 1,
                last: None,
                counts: cursor.counts.clone(),
            };
            let encoded = next.encode()?;
            let mut c = held.candidate(manifest);
            c.put
                .push((manifest.ns, CURSOR_KEY.to_vec(), encoded.clone()));
            settle(store.commit(c)?, "a record-format namespace advance")?;
            cursor = next;
            held.cursor = encoded;
            continue;
        }
        // Zero-payload step completion, with this step's evidence.
        let rows = cursor.rows()?;
        let mut c = held.candidate(manifest);
        c.audit.push(Audit::RecordsEvolved {
            from: format,
            to: format + 1,
            rows,
        });
        total = total.checked_add(rows).ok_or_else(overflow)?;
        if format + 1 == current {
            // The final publication: the kernel adds the fresh registrar, the dataset epoch and
            // the Current manifest to this completion, in one transaction (r4 §9).
            c.delete.push((manifest.ns, CURSOR_KEY.to_vec()));
            settle(store.finalize(c, current)?, "the record-format publication")?;
            return Ok(Some(total));
        }
        let next_step = step_from(format + 1)?;
        let next = Cursor::initial(next_step);
        let encoded = next.encode()?;
        let moved = (manifest.encode)(format + 1, format + 2);
        c.put.push((
            manifest.ns,
            manifest.key.to_vec(),
            SecureVec::from(moved.clone()),
        ));
        c.put
            .push((manifest.ns, CURSOR_KEY.to_vec(), encoded.clone()));
        settle(store.commit(c)?, "a record-format step completion")?;
        format += 1;
        step = next_step;
        cursor = next;
        held = Held {
            manifest: moved,
            cursor: encoded,
        };
    }
}

/// One payload page of `ns` after the cursor (#319 r4 §7.2-§7.3). Its first candidate carries
/// every row the store returned; a never-uncertain refusal retries the first half of them as a
/// fresh candidate, down to one row (at most 1 + floor(log2 n) candidates), and a refused single
/// row stops the conversion with the committed cursor kept. The cursor records only the rows
/// that committed. `Ok(true)` when the namespace is explicitly exhausted: every row of the page
/// committed and the store's continuation absent.
fn page(
    store: &dyn FormatStore,
    manifest: &Manifest<'_>,
    step: &RecordStep,
    ns: NamespaceId,
    cursor: &mut Cursor,
    held: &mut Held,
) -> Result<bool, Refusal> {
    let found = store.scan(ns, cursor.last.as_deref(), PAGE)?;
    let more = continuation(&found)?;
    if found.rows.is_empty() {
        return Ok(true);
    }
    let mut converted = Vec::with_capacity(found.rows.len());
    for (key, value) in &found.rows {
        converted.push((step.convert)(ns, key, value)?);
    }
    let mut size = found.rows.len();
    loop {
        let prefix = &found.rows[..size];
        let mut next = cursor.clone();
        next.last = prefix.last().map(|(key, _)| key.clone());
        let added = u64::try_from(size).map_err(|_| overflow())?;
        let count = next.counts.get_mut(cursor.ns).ok_or_else(malformed)?;
        *count = count.checked_add(added).ok_or_else(overflow)?;
        let encoded = next.encode()?;
        let mut c = held.candidate(manifest);
        for ((key, value), new) in prefix.iter().zip(&converted) {
            c.exact.push((ns, key.clone(), value.clone()));
            c.put.push((ns, key.clone(), new.clone()));
        }
        c.put
            .push((manifest.ns, CURSOR_KEY.to_vec(), encoded.clone()));
        match store.commit(c)? {
            Committed::Applied => {
                *cursor = next;
                held.cursor = encoded;
                return Ok(size == found.rows.len() && more.is_none());
            }
            Committed::Refused if size > 1 => size /= 2,
            Committed::Refused => {
                return Err(Refusal::Store(format!(
                    "the store refused a one-row record-format page in step {} -> {}; the \
                     conversion stops with its committed cursor and the tail kept",
                    step.from,
                    step.from + 1
                )));
            }
            lost => return Err(unapplied(lost, "a record-format page")),
        }
    }
}

/// An outcome that must have applied: a lost predicate or a fence is VERIFY (another owner, or the
/// manifest moved), a refusal is STORE; nothing of the commit was written either way.
fn settle(outcome: Committed, what: &str) -> Result<(), Refusal> {
    match outcome {
        Committed::Applied => Ok(()),
        lost => Err(unapplied(lost, what)),
    }
}

/// The refusal for an outcome that applied nothing.
fn unapplied(outcome: Committed, what: &str) -> Refusal {
    match outcome {
        Committed::Conflict => Refusal::Verify(format!(
            "{what} lost its predicates (another owner, or the manifest moved); nothing of it was \
             written"
        )),
        other => other.unapplied(what),
    }
}
