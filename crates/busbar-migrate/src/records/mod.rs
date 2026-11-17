// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S RECORDS STEP (MIGRATE-ON-BOOT §3 4a, §6, §6a, §A6): the boot's one-time conversion of the
//! 1.5.5 logical rows a store's data step left under IMPORT (R0, `persistence::cells`) into native
//! records, and the record-format chain ([`evolve`]).
//!
//! The crate reaches the store only through [`RecordStore`]: four calls (scan, read, commit,
//! register) that the gateway's seam implements over the opened store under the boot's owner
//! authority, with the kernel's own candidate encoders. It links no loader, no store driver and no
//! kernel. Every page is one commit: exact predicates on every IMPORT row it consumes and on
//! SUMMARY, an absent predicate on every native record it writes, so a page applies exactly once, a
//! crash resumes where IMPORT still has rows, and a stale or concurrent owner loses on the
//! predicates.
//!
//! Cold code: a stamped boot whose IMPORT is empty and whose manifest is current enters none of it.

use std::fmt;

use busbar_contract::persistence::cells::{self, table, Cell, IMPORT_NS};
use busbar_contract::persistence::NamespaceId;
use busbar_contract::records::{CredentialMeta, CredentialSecret, VirtualKey};
use busbar_contract::secure::SecureVec;

pub mod attempts;
mod convert;
pub mod evolve;
pub mod self_keys;

pub use convert::{scale6, MAX_WHOLE_UNITS};
pub use evolve::{
    evolve, evolve_with, has_step, Manifest, RecordStep, CURSOR_KEY, RECORD_FORMAT, RECORD_STEPS,
};

/// The most rows one page (one commit) carries.
pub const PAGE: u32 = 4096;

/// The SUMMARY row's key.
pub const SUMMARY_KEY: &[u8] = &[table::SUMMARY];

/// The key prefix of an upgrade attempt under IMPORT ([`attempts`]); [`run`] skips them.
pub const ATTEMPT_PREFIX: &[u8] = b"attempt/";

/// A store call that did not answer (no secret in the text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFail(pub String);

/// How a commit ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Committed {
    /// Every predicate held; every effect applied, atomically.
    Applied,
    /// A predicate failed (a row changed, a native record exists, another owner moved first);
    /// nothing applied.
    Conflict,
}

/// One commit, built by the records step and executed by the seam.
#[derive(Debug, Default)]
pub struct Candidate {
    /// `(namespace, key, value)` that must hold exactly these bytes (PREDICATE_EXACT).
    pub exact: Vec<(NamespaceId, Vec<u8>, SecureVec)>,
    /// `(namespace, key)` that must be absent (PREDICATE_ABSENT), besides every native record.
    pub absent: Vec<(NamespaceId, Vec<u8>)>,
    /// Records put as given (SUMMARY rewritten, a cursor, a manifest).
    pub put: Vec<(NamespaceId, Vec<u8>, SecureVec)>,
    /// Records deleted.
    pub delete: Vec<(NamespaceId, Vec<u8>)>,
    /// Native records, each written at its own address, which must be absent: the seam encodes
    /// them with the kernel's current encoders.
    pub records: Vec<Native>,
    /// Audit records, committed with the effects.
    pub audit: Vec<Audit>,
}

/// One page of a scan: its rows in key order and the store's own continuation. A page may hold
/// fewer rows than asked (a byte or item bound) and still not be the namespace's end: only an
/// absent [`Page::next`] says no row follows (#319 r4 §7.3).
#[derive(Debug, Default)]
pub struct Page {
    /// The rows, in key order.
    pub rows: Vec<(Vec<u8>, SecureVec)>,
    /// `Some(key)`: more rows may follow; the next page starts after `key`, the last row's key.
    /// `None`: no row of the namespace follows this page.
    pub next: Option<Vec<u8>>,
}

/// THE STORE, as the records step reaches it.
pub trait RecordStore {
    /// Up to `limit` rows of `ns` whose keys sort after `after` (`None`: from the first; `Some`
    /// may name the empty key), in key order, with the store's continuation.
    ///
    /// # Errors
    /// The store's failure.
    fn scan(&self, ns: NamespaceId, after: Option<&[u8]>, limit: u32) -> Result<Page, StoreFail>;
    /// The record at `(ns, key)`, `None` when absent.
    ///
    /// # Errors
    /// The store's failure.
    fn read(&self, ns: NamespaceId, key: &[u8]) -> Result<Option<SecureVec>, StoreFail>;
    /// Apply `c` atomically, or nothing.
    ///
    /// # Errors
    /// The store's failure (the outcome is then unknown; the next boot resumes).
    fn commit(&self, c: Candidate) -> Result<Committed, StoreFail>;
    /// Register a new writer authority, fencing every earlier writer at its next commit.
    ///
    /// # Errors
    /// The store's failure.
    fn register(&self) -> Result<(), StoreFail>;
}

/// The counters of one R0 row: request counts whole, token counts in scale 6 (whole units ×
/// 10^6), as the native ledger and its usage units keep them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Units {
    /// Requests (whole).
    pub requests: u64,
    /// Billable requests (whole).
    pub billable_requests: u64,
    /// Input tokens.
    pub tokens_input: u64,
    /// Output tokens.
    pub tokens_output: u64,
    /// Cache-read tokens.
    pub tokens_cache_read: u64,
    /// Cache-write tokens.
    pub tokens_cache_write: u64,
}

/// One 1.5.5 usage read key, converted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageCell {
    /// The bucket.
    pub bucket: String,
    /// The window's start (Unix seconds).
    pub window_start: i64,
    /// The cell had no head row; its head reads as zero.
    pub headless: bool,
    /// The head: requests and billable requests (token fields 0).
    pub head: Units,
    /// Per model, in the store's order.
    pub models: Vec<(String, Units)>,
}

/// One 1.5.5 metering row, converted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metering {
    /// The billing bucket.
    pub bucket: String,
    /// The key charged.
    pub key_id: String,
    /// The provider.
    pub provider: String,
    /// The model.
    pub model: String,
    /// The key's group when it was used.
    pub key_group_at_use: String,
    /// The pricing version.
    pub pricing_version: String,
    /// The counters.
    pub units: Units,
}

/// One 1.5.5 audit row, byte-exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// Its sequence number.
    pub seq: i64,
    /// Its time.
    pub ts: i64,
    /// The action.
    pub action: String,
    /// The resource.
    pub resource: String,
    /// The outcome.
    pub outcome: String,
    /// The principal.
    pub principal: String,
    /// The previous row's hash.
    pub prev_hash: String,
    /// This row's hash.
    pub hash: String,
}

/// A native record the records step writes.
#[derive(Debug, Clone, PartialEq)]
pub enum Native {
    /// A key (live or tombstoned), self-serve keys converted ([`self_keys`]).
    Key(VirtualKey),
    /// A credential, its recoverable secret sealed under the boot's at-rest key.
    Credential(CredentialSecret),
    /// The store revision.
    Revision(u64),
    /// A denied subject.
    Deny {
        /// The subject.
        sub: String,
        /// Why.
        reason: String,
        /// When.
        created_at: u64,
    },
    /// A usage cell.
    Usage(UsageCell),
    /// A metering row.
    Metering(Metering),
    /// A 1.5.5 audit row, as a history record of its own.
    Audit(AuditRow),
}

/// What the records step did, audited and returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The store's physical format before its data step.
    pub physical_from: i64,
    /// The store's physical format after it.
    pub physical_to: i64,
    /// Rows converted, per R0 table tag 1-7 (index 0 unused).
    pub rows: [u64; 8],
    /// Usage cells that had no head row.
    pub headless_cells: u64,
    /// Rows 1.5.5's own read skips, counted by the store.
    pub ignored: u64,
    /// 1.5.5 audit rows whose `prev_hash` does not name the previous row's hash (kept as is).
    pub audit_breaks: u64,
    /// Self-serve-looking keys that could not be verified and keep their 1.5.5 shape.
    pub self_keys_unverified: u64,
    /// The store's digest of its 1.5.5 source.
    pub digest: Vec<u8>,
}

/// An audit record the records step writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audit {
    /// An unstamped boot's records were migrated (its config's MIGRATION_COMPLETED comes at 5C).
    RecordsMigrated(Report),
    /// A stamped boot's records were migrated: the upgrade is complete.
    MigrationCompleted(Report),
    /// The record format moved `from` → `to`, `rows` rows converted.
    RecordsEvolved {
        /// The format before.
        from: u32,
        /// The format after.
        to: u32,
        /// Rows converted.
        rows: u64,
    },
    /// An upgrade attempt settled ([`attempts`]).
    Attempt(attempts::Settled),
}

/// Why the records step refused. Every text starts with its word; on every refusal before the
/// first page, core has written nothing native and IMPORT is untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The counts do not close, or a page lost its predicates.
    Verify(String),
    /// A 1.5.5 counter does not fit what 1.6.0 stores.
    Bounds(String),
    /// The config must change first (an at-rest key).
    Config(String),
    /// A row 1.5.5's own read could not have returned.
    Unknown(String),
    /// A newer busbar wrote or began migrating these records.
    Newer(String),
    /// A record format no step reads.
    Unsupported(String),
    /// The store failed.
    Store(String),
}

impl Refusal {
    /// The precise word the text starts with.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Self::Verify(_) => "VERIFY",
            Self::Bounds(_) => "BOUNDS",
            Self::Config(_) => "CONFIG",
            Self::Unknown(_) => "UNKNOWN",
            Self::Newer(_) => "NEWER",
            Self::Unsupported(_) => "UNSUPPORTED",
            Self::Store(_) => "STORE",
        }
    }

    fn text(&self) -> &str {
        match self {
            Self::Verify(t)
            | Self::Bounds(t)
            | Self::Config(t)
            | Self::Unknown(t)
            | Self::Newer(t)
            | Self::Unsupported(t)
            | Self::Store(t) => t,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.word(), self.text())
    }
}

impl std::error::Error for Refusal {}

impl From<StoreFail> for Refusal {
    fn from(fail: StoreFail) -> Self {
        Self::Store(fail.0)
    }
}

/// Seal one recoverable secret under the boot's at-rest key (`AtRestKeys::seal`): the envelope.
pub type Seal<'a> = &'a dyn Fn(&CredentialMeta, &[u8]) -> Result<String, String>;

/// A self-serve key id from its subject and epoch (`derive_self_subject` over the signing key).
pub type SelfId<'a> = &'a dyn Fn(&str, u64) -> String;

/// What [`run`] is given.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    /// The boot's at-rest key, `None` when no key is configured.
    pub seal: Option<Seal<'a>>,
    /// The self-serve key id derivation, `None` when no signing key is configured.
    pub self_id: Option<SelfId<'a>>,
    /// Whether config.yaml is stamped: the final commit then carries MIGRATION_COMPLETED, else
    /// RECORDS_MIGRATED.
    pub stamped: bool,
}

/// The CONFIG refusal when plain rows reach the records step and no at-rest key is configured
/// (the backstop: a stamped, records-pending boot whose key was removed, or a store that skipped
/// its gate).
#[must_use]
pub fn already_migrated_text(n: u64) -> String {
    format!(
        "1.5.5 stored {n} recoverable credentials in the clear; 1.6.0 stores them only sealed. \
         The store is already migrated by its plugin and IMPORT is untouched: restore \
         `auth.signing_key` (the key 1.6.0 derives the at-rest key from) and boot again, or roll back the store (docs/migration-1.6)"
    )
}

/// The R0 SUMMARY row, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) physical_from: i64,
    pub(crate) physical_to: i64,
    /// Per tag 1-7 (index 0 unused): `(source_rows, emitted, consumed folds, consumed rows)`.
    pub(crate) tags: [[u64; 4]; 8],
    pub(crate) headless_cells: u64,
    pub(crate) ignored: u64,
    pub(crate) digest: Vec<u8>,
}

impl Summary {
    pub(crate) fn decode(value: &[u8]) -> Result<Self, Refusal> {
        let bad = || Refusal::Unknown("the IMPORT SUMMARY row is malformed".to_owned());
        let cells = cells::decode(value).map_err(|_| bad())?;
        let last = usize::from(table::LAST);
        if cells.len() != cells::SUMMARY_CELLS && cells.len() != cells::SUMMARY_CELLS + last {
            return Err(bad());
        }
        let count = |i: usize| match cells.get(i) {
            None => Ok(0),
            Some(Cell::Int(v)) => u64::try_from(*v).map_err(|_| bad()),
            Some(_) => Err(bad()),
        };
        let mut tags = [[0u64; 4]; 8];
        for (tag, slot) in tags.iter_mut().enumerate().take(last + 1).skip(1) {
            let at = 2 + 3 * (tag - 1);
            *slot = [
                count(at)?,
                count(at + 1)?,
                count(at + 2)?,
                count(cells::SUMMARY_CELLS + tag - 1)?,
            ];
        }
        let base = 2 + 3 * last;
        let digest = match cells.get(base + 2) {
            Some(Cell::Blob(bytes)) => bytes.to_vec(),
            _ => return Err(bad()),
        };
        let version = |i: usize| match cells.get(i) {
            Some(Cell::Int(v)) => Ok(*v),
            _ => Err(bad()),
        };
        Ok(Self {
            physical_from: version(0)?,
            physical_to: version(1)?,
            tags,
            headless_cells: count(base)?,
            ignored: count(base + 1)?,
            digest,
        })
    }

    pub(crate) fn encode(&self) -> SecureVec {
        let int = |v: u64| Cell::Int(i64::try_from(v).unwrap_or(i64::MAX));
        let last = usize::from(table::LAST);
        let mut out = vec![Cell::Int(self.physical_from), Cell::Int(self.physical_to)];
        for tag in 1..=last {
            out.extend([
                int(self.tags[tag][0]),
                int(self.tags[tag][1]),
                int(self.tags[tag][2]),
            ]);
        }
        out.extend([
            int(self.headless_cells),
            int(self.ignored),
            Cell::Blob(&self.digest),
        ]);
        for tag in 1..=last {
            out.push(int(self.tags[tag][3]));
        }
        SecureVec::from(cells::value(&out))
    }
}

/// What the read-only pass over IMPORT found.
struct Survey {
    summary: Option<(Summary, SecureVec)>,
    /// Per tag: folds and rows still under IMPORT.
    remaining: [[u64; 2]; 8],
    plain: u64,
    /// AUDIT rows whose `prev_hash` is not the hash of the row before them (seq - 1).
    audit_breaks: u64,
}

/// The IMPORT rows of one table tag 1-7; SUMMARY and attempts are not.
fn is_row(key: &[u8]) -> bool {
    matches!(cells::tag_of(key), Some(t) if (1..=table::LAST).contains(&t))
        && !key.starts_with(ATTEMPT_PREFIX)
}

/// Where the scan after `page` starts: `None` at the namespace's explicit end. A continuation must
/// be the page's last row key, so a page that names one always progresses.
///
/// # Errors
/// VERIFY for an empty page that is not the end, or a continuation that is not its last row.
pub(crate) fn continuation(page: &Page) -> Result<Option<Vec<u8>>, Refusal> {
    match (&page.next, page.rows.last()) {
        (None, _) => Ok(None),
        (Some(next), Some((last, _))) if next == last => Ok(Some(next.clone())),
        (Some(_), _) => Err(Refusal::Verify(
            "the store answered a scan page that does not progress (its continuation is not its \
             last row)"
                .to_owned(),
        )),
    }
}

/// The closure pre-check (§A6): one read-only pass over IMPORT, before any core write, on the
/// first run and on every resume. Every row is converted (without sealing) so a value 1.5.5 could
/// not have returned, or a counter 1.6.0 cannot store, refuses here and not mid-way.
fn pass(store: &dyn RecordStore) -> Result<Survey, Refusal> {
    let mut found = Survey {
        summary: None,
        remaining: [[0; 2]; 8],
        plain: 0,
        audit_breaks: 0,
    };
    let mut chain: std::collections::BTreeMap<i64, (String, String)> = Default::default();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = store.scan(IMPORT_NS, after.as_deref(), PAGE)?;
        for (key, value) in &page.rows {
            if key.as_slice() == SUMMARY_KEY {
                found.summary = Some((Summary::decode(value)?, value.clone()));
            } else if is_row(key) {
                let row = convert::row(key, value, None, None)?;
                let tag = usize::from(cells::tag_of(key).unwrap_or(0));
                found.remaining[tag][0] += row.fold;
                found.remaining[tag][1] += 1;
                found.plain += u64::from(row.plain);
                if let Native::Audit(audit) = row.native {
                    chain.insert(audit.seq, (audit.prev_hash, audit.hash));
                }
            }
        }
        after = match continuation(&page)? {
            Some(next) => Some(next),
            None => break,
        };
    }
    found.audit_breaks = chain
        .iter()
        .filter(|(seq, (prev, _))| {
            seq.checked_sub(1)
                .and_then(|before| chain.get(&before))
                .is_some_and(|(_, hash)| hash != prev)
        })
        .count() as u64;
    Ok(found)
}

/// THE RECORDS STEP (§3 4a, §6). `Ok(None)` when IMPORT holds nothing to convert. Otherwise every
/// R0 row becomes its native record, page by page, and the final commit consumes SUMMARY and
/// writes RECORDS_MIGRATED (unstamped) or MIGRATION_COMPLETED (stamped).
///
/// # Errors
/// VERIFY when the counts do not close (before any core write) or a page loses its predicates;
/// BOUNDS for a counter 1.6.0 cannot store; UNKNOWN for a row 1.5.5 could not have returned; CONFIG
/// when plain credentials reach the step and no at-rest key is configured; STORE for a store fault.
#[cold]
#[inline(never)]
pub fn run(store: &dyn RecordStore, inputs: &Inputs<'_>) -> Result<Option<Report>, Refusal> {
    let found = pass(store)?;
    let rows: u64 = found.remaining.iter().map(|r| r[1]).sum();
    let Some((mut summary, mut held)) = found.summary else {
        if rows == 0 {
            return Ok(None);
        }
        return Err(Refusal::Verify(format!(
            "IMPORT holds {rows} 1.5.5 rows and no SUMMARY row; nothing was written"
        )));
    };
    for tag in 1..=usize::from(table::LAST) {
        let [source, emitted, folds, consumed] = summary.tags[tag];
        let [left_folds, left_rows] = found.remaining[tag];
        if folds + left_folds != source || consumed + left_rows != emitted {
            return Err(Refusal::Verify(format!(
                "R0 table {tag}: the store counted {source} source rows and wrote {emitted} \
                 IMPORT rows, but {folds} + {left_folds} were found ({consumed} + {left_rows} \
                 IMPORT rows); nothing native was written and IMPORT is untouched"
            )));
        }
    }
    if found.plain > 0 && inputs.seal.is_none() {
        return Err(Refusal::Config(already_migrated_text(found.plain)));
    }
    store.register()?;
    let mut report = Report {
        physical_from: summary.physical_from,
        physical_to: summary.physical_to,
        headless_cells: summary.headless_cells,
        ignored: summary.ignored,
        digest: summary.digest.clone(),
        audit_breaks: found.audit_breaks,
        ..Report::default()
    };
    loop {
        let page: Vec<(Vec<u8>, SecureVec)> = store
            .scan(IMPORT_NS, Some(SUMMARY_KEY), PAGE)?
            .rows
            .into_iter()
            .filter(|(key, _)| is_row(key))
            .collect();
        if page.is_empty() {
            break;
        }
        let mut c = Candidate::default();
        let mut next = summary.clone();
        for (key, value) in &page {
            let row = convert::row(key, value, inputs.seal, inputs.self_id)?;
            let tag = usize::from(cells::tag_of(key).unwrap_or(0));
            next.tags[tag][2] += row.fold;
            next.tags[tag][3] += 1;
            report.rows[tag] += 1;
            report.self_keys_unverified += u64::from(row.self_unverified);
            c.exact.push((IMPORT_NS, key.clone(), value.clone()));
            c.delete.push((IMPORT_NS, key.clone()));
            c.records.push(row.native);
        }
        c.exact
            .push((IMPORT_NS, SUMMARY_KEY.to_vec(), held.clone()));
        let encoded = next.encode();
        c.put
            .push((IMPORT_NS, SUMMARY_KEY.to_vec(), encoded.clone()));
        commit(store, c)?;
        summary = next;
        held = encoded;
    }
    for tag in 1..=usize::from(table::LAST) {
        let [source, emitted, folds, consumed] = summary.tags[tag];
        if folds != source || consumed != emitted {
            return Err(Refusal::Verify(format!(
                "R0 table {tag}: {folds} of {source} source rows converted at the end"
            )));
        }
    }
    let mut c = Candidate::default();
    c.exact.push((IMPORT_NS, SUMMARY_KEY.to_vec(), held));
    c.delete.push((IMPORT_NS, SUMMARY_KEY.to_vec()));
    c.audit.push(if inputs.stamped {
        Audit::MigrationCompleted(report.clone())
    } else {
        Audit::RecordsMigrated(report.clone())
    });
    commit(store, c)?;
    Ok(Some(report))
}

/// One commit; a lost predicate is VERIFY with nothing of the page written.
fn commit(store: &dyn RecordStore, c: Candidate) -> Result<(), Refusal> {
    match store.commit(c)? {
        Committed::Applied => Ok(()),
        Committed::Conflict => Err(Refusal::Verify(
            "a page of the records step lost its predicates: a native record already exists \
             where a 1.5.5 row lands, or another busbar moved first; nothing of the page was \
             written"
                .to_owned(),
        )),
    }
}

#[cfg(test)]
#[path = "../tests/records_tests.rs"]
mod tests;
