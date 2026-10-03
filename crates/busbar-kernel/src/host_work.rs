// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WORK BOOK behind `work.open` / `work.find` / `work.settle` / `work.resume`
//! (`BUSBAR-1.6.0.md` THE DESIGN §11.12, the work family; §1 "Admission bounds live work; nothing
//! evicts it"; ARCHITECT H3): the durable work handles a plugin opens, finds by reference, settles
//! and resumes, kept by the kernel and written through the store's typed records, so a handle
//! outlives the process that opened it.
//!
//! * **A handle and its reference.** `work.open` mints a 128-bit REFERENCE from the OS CSPRNG (the
//!   name the plugin hands its caller) and a process-local HANDLE (the number the plugin calls
//!   with). The reference is durable; a handle is re-minted when a reference is found again after a
//!   restart.
//! * **Scoped lookup.** A handle is kept under the calling instance's LABEL and the digest of the
//!   principal of the unit that opened it ([`owner_of`]). `work.find` answers only within both,
//!   and every denial is the same READY absent answer.
//! * **The bound refuses at admission; nothing evicts.** At [`WorkBounds::max_live`] live handles
//!   an instance's next `work.open` is refused; a live handle is never dropped. Retention bounds
//!   only settled handles ([`WorkBounds::retain_ms`]), and the sweep runs from a `work.open` (a
//!   submit), never from a read or a timer.
//! * **Durable before answered.** Every open and settle is written to the store before it is
//!   answered; a write the store refuses answers FAILED and leaves the book as it was.
//! * **Across a restart.** A reference not in memory is read from the store, and an instance's
//!   rows are read once ([`WorkBook::load`]) before its first open, so the bound counts the live
//!   handles an earlier process left.
//!
//! The row is at most [`busbar_contract::bounded::MAX_RECORD_BYTES`]: the handle's record is capped
//! at [`MAX_WORK_RECORD`] (the body lives in the plugin's own records; the handle's record names it).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::abi::host::service::{MAX_WORK_RECORD, WORK_LIVE, WORK_SETTLED};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use ring::digest;

use crate::host_records::{record_key, RecordRows};

/// The record kind every work row is kept under.
pub const WORK_SCHEMA: RecordSchemaId = RecordSchemaId::new("kernel-work");

/// A reference's bytes: 128 bits.
pub type Reference = [u8; 16];

/// The digest a handle's owner is kept as.
pub type Owner = [u8; 32];

/// The bounds of one instance's work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkBounds {
    /// The most live handles one instance holds; the next open is refused.
    pub max_live: usize,
    /// How long a settled handle is retained, in milliseconds.
    pub retain_ms: u64,
}

impl Default for WorkBounds {
    /// The legacy work registries' bounds (`busbar-mcp` `tasks.rs`, `busbar-a2a` `taskstore.rs`):
    /// 4096 retained, a terminal one kept five minutes.
    fn default() -> Self {
        WorkBounds {
            max_live: 4096,
            retain_ms: 300_000,
        }
    }
}

/// The owner digest of a unit's principal: its key's id, or the ungoverned principal.
#[must_use]
pub fn owner_of(principal: Option<&str>) -> Owner {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"busbar work owner\0");
    match principal {
        Some(id) => {
            ctx.update(&[1]);
            ctx.update(id.as_bytes());
        }
        None => ctx.update(&[0]),
    }
    let mut owner = Owner::default();
    owner.copy_from_slice(ctx.finish().as_ref());
    owner
}

/// A reference as the plugin holds it: lowercase hex.
#[must_use]
pub fn reference_text(r: &Reference) -> String {
    hex::encode(r)
}

/// A reference the plugin handed back, or `None` for anything but [`reference_text`]'s form.
#[must_use]
pub fn parse_reference(text: &[u8]) -> Option<Reference> {
    if text.len() != 32 || !text.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut r = [0u8; 16];
    hex::decode_to_slice(text, &mut r).ok()?;
    Some(r)
}

/// One handle, as the book and its row hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Work {
    /// The instance it belongs to.
    pub instance: Arc<str>,
    /// Its reference.
    pub reference: Reference,
    /// Its kind.
    pub kind: String,
    /// Its owner.
    pub owner: Owner,
    /// Live (`true`) or settled.
    pub live: bool,
    /// When it was opened, ms on the wall clock.
    pub opened_ms: u64,
    /// When it was settled; `0` while live.
    pub settled_ms: u64,
    /// Its record.
    pub record: Vec<u8>,
    /// The unit it was last resumed by.
    pub bound: Option<u64>,
}

impl Work {
    /// The state byte `work.find` and `work.resume` answer.
    #[must_use]
    pub fn state(&self) -> u8 {
        if self.live {
            WORK_LIVE
        } else {
            WORK_SETTLED
        }
    }

    /// The row this handle is written as; `None` when it does not fit a record.
    #[must_use]
    pub fn row(&self) -> Option<RecordBytes> {
        let kind = self.kind.as_bytes();
        if kind.len() > usize::from(u8::MAX) || self.record.len() > MAX_WORK_RECORD {
            return None;
        }
        let mut b = Vec::with_capacity(53 + kind.len() + self.record.len());
        b.push(ROW_VERSION);
        b.push(self.state());
        b.extend_from_slice(&self.opened_ms.to_be_bytes());
        b.extend_from_slice(&self.settled_ms.to_be_bytes());
        b.extend_from_slice(&self.owner);
        b.push(u8::try_from(kind.len()).ok()?);
        b.extend_from_slice(kind);
        b.extend_from_slice(&u16::try_from(self.record.len()).ok()?.to_be_bytes());
        b.extend_from_slice(&self.record);
        RecordBytes::new(b).ok()
    }

    /// The handle a row describes, or `None` for a row that does not decode (a tombstone
    /// included).
    #[must_use]
    pub fn read(instance: &Arc<str>, reference: Reference, row: &[u8]) -> Option<Self> {
        let (&version, rest) = row.split_first()?;
        if version != ROW_VERSION {
            return None;
        }
        let (&state, rest) = rest.split_first()?;
        let u64_at =
            |b: &[u8]| -> Option<u64> { Some(u64::from_be_bytes(b.get(..8)?.try_into().ok()?)) };
        let opened_ms = u64_at(rest)?;
        let settled_ms = u64_at(rest.get(8..)?)?;
        let owner: Owner = rest.get(16..48)?.try_into().ok()?;
        let rest = rest.get(48..)?;
        let (&kind_len, rest) = rest.split_first()?;
        let kind = std::str::from_utf8(rest.get(..usize::from(kind_len))?).ok()?;
        let rest = rest.get(usize::from(kind_len)..)?;
        let len = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
        let record = rest.get(2..)?;
        if record.len() != len {
            return None;
        }
        let live = match state {
            WORK_LIVE => true,
            WORK_SETTLED => false,
            _ => return None,
        };
        Some(Work {
            instance: Arc::clone(instance),
            reference,
            kind: kind.to_string(),
            owner,
            live,
            opened_ms,
            settled_ms,
            record: record.to_vec(),
            bound: None,
        })
    }
}

/// The version byte every row leads with.
const ROW_VERSION: u8 = 1;

/// The store key of `reference` under `instance`.
#[must_use]
pub fn work_key(instance: &str, reference: &Reference) -> Vec<u8> {
    record_key(instance, reference)
}

#[derive(Debug, Default)]
struct Book {
    next: u64,
    handles: HashMap<u64, Work>,
    by_ref: HashMap<(Arc<str>, Reference), u64>,
    loaded: HashSet<Arc<str>>,
}

impl Book {
    fn insert(&mut self, work: Work) -> u64 {
        let key = (Arc::clone(&work.instance), work.reference);
        if let Some(h) = self.by_ref.get(&key) {
            return *h;
        }
        self.next += 1;
        let h = self.next;
        self.by_ref.insert(key, h);
        self.handles.insert(h, work);
        h
    }

    fn remove(&mut self, handle: u64) -> Option<Work> {
        let w = self.handles.remove(&handle)?;
        self.by_ref.remove(&(Arc::clone(&w.instance), w.reference));
        Some(w)
    }
}

/// Why a work call was refused, in the words the service answers.
pub mod refusal {
    /// `work.open` at the instance's bound of live handles.
    pub const AT_BOUND: &str = "the instance holds its bound of live work handles";
    /// A handle that is not one of the caller's, or whose principal is not the calling unit's.
    pub const NOT_A_HANDLE: &str = "not a work handle of the caller";
    /// `work.settle` of a handle already settled.
    pub const SETTLED: &str = "the work handle is already settled";
    /// A record past `MAX_WORK_RECORD`, or a kind too long to keep.
    pub const TOO_LONG: &str = "the work record is longer than MAX_WORK_RECORD";
    /// A work call from a crossing that serves no unit in flight.
    pub const NO_UNIT: &str = "the crossing serves no unit in flight";
}

/// THE KERNEL'S WORK BOOK: every live handle and every settled one still retained, by handle and by
/// (instance, reference). The store is the durable copy; this is the index over it.
#[derive(Debug, Default)]
pub struct WorkBook {
    inner: Mutex<Book>,
}

impl WorkBook {
    fn lock(&self) -> MutexGuard<'_, Book> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `instance`'s rows have been read from the store in this process.
    #[must_use]
    pub fn loaded(&self, instance: &str) -> bool {
        self.lock().loaded.contains(instance)
    }

    /// Read `instance`'s rows once (an earlier process's handles), adopting every row not yet in
    /// the book. `Err` when the store did not answer; the instance stays unloaded.
    ///
    /// # Errors
    ///
    /// The store's.
    pub fn load(&self, rows: &dyn RecordRows, instance: &Arc<str>) -> Result<(), StoreError> {
        if self.loaded(instance) {
            return Ok(());
        }
        let scope = record_key(instance, &[]);
        let found = rows.record_scan(WORK_SCHEMA, &scope, u32::MAX)?;
        let mut book = self.lock();
        for (key, row) in found {
            let Some(reference) = key
                .get(scope.len()..)
                .and_then(|r| <Reference>::try_from(r).ok())
            else {
                continue;
            };
            if let Some(w) = Work::read(instance, reference, row.as_slice()) {
                book.insert(w);
            }
        }
        book.loaded.insert(Arc::clone(instance));
        Ok(())
    }

    /// THE SWEEP, run from a submit: every settled handle of `instance` settled at or before
    /// `now_ms - retain_ms` leaves the book; their references are answered, for the caller to strike
    /// from the store.
    pub fn sweep(&self, instance: &str, now_ms: u64, retain_ms: u64) -> Vec<Reference> {
        let mut book = self.lock();
        let gone: Vec<u64> = book
            .handles
            .iter()
            .filter(|(_, w)| {
                *w.instance == *instance
                    && !w.live
                    && w.settled_ms.saturating_add(retain_ms) <= now_ms
            })
            .map(|(h, _)| *h)
            .collect();
        gone.into_iter()
            .filter_map(|h| book.remove(h).map(|w| w.reference))
            .collect()
    }

    /// Reserve a live handle for `work` unless `instance` already holds `max_live`: the handle, or
    /// `None` at the bound. The reservation is the bound's: two racing opens never both pass it.
    #[must_use]
    pub fn reserve(&self, work: Work, max_live: usize) -> Option<u64> {
        let mut book = self.lock();
        let live = book
            .handles
            .values()
            .filter(|w| w.live && w.instance == work.instance)
            .count();
        if live >= max_live {
            return None;
        }
        Some(book.insert(work))
    }

    /// Drop a reservation the store refused.
    pub fn unreserve(&self, handle: u64) {
        self.lock().remove(handle);
    }

    /// The handle `reference` names under `instance`, if the book holds it.
    #[must_use]
    pub fn by_reference(&self, instance: &str, reference: &Reference) -> Option<(u64, Work)> {
        let book = self.lock();
        let h = *book.by_ref.get(&(Arc::from(instance), *reference))?;
        book.handles.get(&h).map(|w| (h, w.clone()))
    }

    /// Adopt a handle read from the store; its handle (an existing one when the book already holds
    /// the reference).
    pub fn adopt(&self, work: Work) -> u64 {
        self.lock().insert(work)
    }

    /// Handle `handle`, when it is `instance`'s.
    #[must_use]
    pub fn get(&self, instance: &str, handle: u64) -> Option<Work> {
        self.lock()
            .handles
            .get(&handle)
            .filter(|w| *w.instance == *instance)
            .cloned()
    }

    /// Mark `instance`'s live handle `handle` settled with `record` at `now_ms`, answering the
    /// handle as it stood (to restore if the store refuses), or the refusal.
    ///
    /// # Errors
    ///
    /// [`refusal::NOT_A_HANDLE`] or [`refusal::SETTLED`].
    pub fn settle(
        &self,
        instance: &str,
        handle: u64,
        record: Vec<u8>,
        now_ms: u64,
    ) -> Result<(Work, Work), &'static str> {
        let mut book = self.lock();
        let w = book
            .handles
            .get_mut(&handle)
            .filter(|w| *w.instance == *instance)
            .ok_or(refusal::NOT_A_HANDLE)?;
        if !w.live {
            return Err(refusal::SETTLED);
        }
        let before = w.clone();
        w.live = false;
        w.settled_ms = now_ms;
        w.record = record;
        Ok((before, w.clone()))
    }

    /// Put `work` back as it stood before a settle the store refused.
    pub fn restore(&self, handle: u64, work: Work) {
        if let Some(w) = self.lock().handles.get_mut(&handle) {
            *w = work;
        }
    }

    /// Bind `instance`'s handle `handle` to `unit`, when `owner` is the handle's: the handle as it
    /// now stands.
    ///
    /// # Errors
    ///
    /// [`refusal::NOT_A_HANDLE`].
    pub fn bind(
        &self,
        instance: &str,
        handle: u64,
        owner: &Owner,
        unit: u64,
    ) -> Result<Work, &'static str> {
        let mut book = self.lock();
        let w = book
            .handles
            .get_mut(&handle)
            .filter(|w| *w.instance == *instance && w.owner == *owner)
            .ok_or(refusal::NOT_A_HANDLE)?;
        w.bound = Some(unit);
        Ok(w.clone())
    }

    /// How many handles the book holds, live and settled.
    #[must_use]
    pub fn held(&self) -> usize {
        self.lock().handles.len()
    }
}

#[cfg(test)]
#[path = "tests/host_work_tests.rs"]
mod tests;
