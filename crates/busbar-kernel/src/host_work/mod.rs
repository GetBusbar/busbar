// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::abi::host::service::{MAX_WORK_RECORD, WORK_LIVE, WORK_SETTLED};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use ring::digest;

use crate::host_records::{record_key, RecordRows};

pub const WORK_SCHEMA: RecordSchemaId = RecordSchemaId::new("kernel-work");

pub type Reference = [u8; 16];

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
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl WorkBounds {
    pub const DEFAULT: Self = Self {
        max_live: 4096,
        retain_ms: 300_000,
    };

    const MILLIS_PER_SECOND: u64 = 1_000;

    pub fn of_section(
        section: &str,
        value: &serde_yaml::Value,
        fallback: Self,
    ) -> Result<Self, String> {
        use busbar_contract::section::{RESERVED_WORK_KEY, WORK_MAX_LIVE_KEY, WORK_RETAIN_S_KEY};
        let Some(work) = value.get(RESERVED_WORK_KEY) else {
            return Ok(fallback);
        };
        let at = format!("`{section}.{RESERVED_WORK_KEY}`");
        let map = work.as_mapping().ok_or_else(|| {
            format!(
                "{at}: the reserved work bounds must be a map of \
                 `{WORK_MAX_LIVE_KEY}` and `{WORK_RETAIN_S_KEY}`"
            )
        })?;
        let mut bounds = fallback;
        for (key, v) in map {
            match key.as_str() {
                Some(WORK_MAX_LIVE_KEY) => {
                    bounds.max_live = v
                        .as_u64()
                        .filter(|n| *n > 0)
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or_else(|| {
                            format!("{at}.{WORK_MAX_LIVE_KEY}: must be a whole number above zero")
                        })?;
                }
                Some(WORK_RETAIN_S_KEY) => {
                    bounds.retain_ms = v
                        .as_u64()
                        .and_then(|s| s.checked_mul(Self::MILLIS_PER_SECOND))
                        .ok_or_else(|| {
                            format!("{at}.{WORK_RETAIN_S_KEY}: must be a whole number of seconds")
                        })?;
                }
                _ => {
                    let named = key.as_str().unwrap_or("?");
                    return Err(format!(
                        "{at}: `{named}` is not a work bound \
                         (`{WORK_MAX_LIVE_KEY}`, `{WORK_RETAIN_S_KEY}`)"
                    ));
                }
            }
        }
        Ok(bounds)
    }
}

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

#[must_use]
pub fn reference_text(r: &Reference) -> String {
    hex::encode(r)
}

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
    /// The unit that opened it, in this process; `None` for a handle read from the store (no
    /// unit outlives the process that admitted it). Not part of the row.
    pub opened_by: Option<u64>,
}

impl Work {
    #[must_use]
    pub fn state(&self) -> u8 {
        if self.live {
            WORK_LIVE
        } else {
            WORK_SETTLED
        }
    }

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
            opened_by: None,
        })
    }
}

const ROW_VERSION: u8 = 1;

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
    /// A settlement owns its handle until its Store call confirms or retires. The published
    /// Work stays live during that interval, retaining its capacity and excluding it from sweep.
    settling: HashSet<u64>,
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
        self.settling.remove(&handle);
        Some(w)
    }
}

pub mod refusal {

    pub const AT_BOUND: &str = "the instance holds its bound of live work handles";

    pub const NOT_A_HANDLE: &str = "not a work handle of the caller";

    pub const SETTLED: &str = "the work handle is already settled";

    pub const TOO_LONG: &str = "the work record is longer than MAX_WORK_RECORD";

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

    #[must_use]
    pub fn loaded(&self, instance: &str) -> bool {
        self.lock().loaded.contains(instance)
    }

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

    #[must_use]
    pub fn reserve(&self, work: Work, max_live: usize) -> Option<u64> {
        let mut book = self.lock();
        let live = book
            .handles
            .values()
            .filter(|w| w.live && w.opened_by.is_some() && w.instance == work.instance)
            .count();
        if live >= max_live {
            return None;
        }
        Some(book.insert(work))
    }

    pub fn unreserve(&self, handle: u64) {
        self.lock().remove(handle);
    }

    #[must_use]
    pub fn by_reference(&self, instance: &str, reference: &Reference) -> Option<(u64, Work)> {
        let book = self.lock();
        let h = *book.by_ref.get(&(Arc::from(instance), *reference))?;
        book.handles.get(&h).map(|w| (h, w.clone()))
    }

    pub fn adopt(&self, work: Work) -> u64 {
        self.lock().insert(work)
    }

    #[must_use]
    pub fn get(&self, instance: &str, handle: u64) -> Option<Work> {
        self.lock()
            .handles
            .get(&handle)
            .filter(|w| *w.instance == *instance)
            .cloned()
    }

    pub fn settle(
        &self,
        instance: &str,
        handle: u64,
        owner: Option<&Owner>,
        in_flight: &dyn Fn(u64) -> bool,
        record: Vec<u8>,
        now_ms: u64,
    ) -> Result<Work, &'static str> {
        let mut book = self.lock();
        let settling = book.settling.contains(&handle);
        let w = book
            .handles
            .get_mut(&handle)
            .filter(|w| *w.instance == *instance)
            .ok_or(refusal::NOT_A_HANDLE)?;
        let unit_runs = w.opened_by.into_iter().chain(w.bound).any(in_flight);
        if unit_runs && owner != Some(&w.owner) {
            return Err(refusal::NOT_A_HANDLE);
        }
        if !w.live || settling {
            return Err(refusal::SETTLED);
        }
        let mut settled = w.clone();
        settled.live = false;
        settled.settled_ms = now_ms;
        settled.record = record;
        book.settling.insert(handle);
        Ok(settled)
    }

    pub fn commit_settle(&self, handle: u64, settled: Work) {
        let mut book = self.lock();
        if !book.settling.remove(&handle) {
            return;
        }
        if let Some(w) = book.handles.get_mut(&handle) {
            w.live = settled.live;
            w.settled_ms = settled.settled_ms;
            w.record = settled.record;
        }
    }

    pub fn cancel_settle(&self, handle: u64) {
        self.lock().settling.remove(&handle);
    }

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

    pub fn found(&self, handle: u64, unit: u64, in_flight: &dyn Fn(u64) -> bool) {
        if let Some(w) = self.lock().handles.get_mut(&handle) {
            if w.live && !w.bound.is_some_and(in_flight) {
                w.bound = Some(unit);
            }
        }
    }

    #[must_use]
    pub fn held(&self) -> usize {
        self.lock().handles.len()
    }
}

#[cfg(test)]
#[path = "tests/host_work_tests.rs"]
mod tests;
