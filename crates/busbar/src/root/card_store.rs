// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE-CARD HISTORY IN THE STORE: the fleet-shared record schema `busbar.card.v1`
//! (MONEY-DESIGN section 3a).
//!
//! ## Records
//!
//! - An ENTRY is keyed `t_ms (u64 BE) ++ node_rand (8 bytes, per boot) ++ counter (u32 BE)`
//!   ([`EntryKey`]). Its value is split into PARTS under `key ++ part (u16 BE)`, each at most
//!   [`busbar_contract::MAX_RECORD_BYTES`], and a COMMIT part under `key ++ COMMIT_PART` is written
//!   LAST: it carries the part count and the digest of the whole value. A reader ignores an entry
//!   whose commit part is missing or does not match its parts.
//! - Every entry carries a WHOLE card ([`CardFields`]), its `effective_from`/`effective_until`, when
//!   it was appended, its author, the key of the head it extended (its BASE), the writer's durable
//!   node id, the fields a PUT set, and an optional signed-correction envelope. It is immutable.
//! - A VOID is its own record under `voided_key ++ 0xFF ++ voider node (u64 BE)`. The tag byte
//!   `0xFF` is never a part number's first byte (parts stop below `COMMIT_PART`).
//!
//! ## Writes
//!
//! Every part and the commit are put and each ack awaited ([`put_all`]). A put is an upsert of the
//! same bytes, so a doubtful write is re-put with the same bytes until READY. A first-attempt
//! REFUSED is the store saying no before anything landed; anything else after the first attempt is
//! doubtful.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::{StoreCalls, StoreFailure};
use busbar_kernel::config::card::CardFields;
use busbar_kernel_ledger::cost::{EntryKey, ENTRY_KEY_LEN};
use serde::{Deserialize, Serialize};

/// The record schema the history is kept under.
pub const CARD_SCHEMA: &str = "busbar.card.v1";

/// The part number of an entry's commit part. Data parts are numbered below it.
pub const COMMIT_PART: u16 = 0xFE00;

/// The tag byte that follows a voided key in a VOID record's key.
pub const VOID_TAG: u8 = 0xFF;

/// The clock skew a writer tolerates in the history's head (MONEY-DESIGN section 3a).
pub const SKEW_MS: u64 = 5 * 60 * 1000;

/// How long a card write waits for READY inside the config lock before it goes pending.
pub const IN_LOCK_BOUND: Duration = Duration::from_secs(2);

/// The bytes one data part carries.
const PART_BYTES: usize = busbar_contract::MAX_RECORD_BYTES;

/// The local file a node keeps its pending and abandoned entries in, under its data directory.
pub const PENDING_FILE: &str = "card-pending.json";

/// Why an entry exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryAuthor {
    /// The opening entry, written only when the history is empty: the seed card, effective from
    /// instant zero. Records the MERGED seed's digest (the card) and the FILE-ONLY seed's.
    Opening {
        /// Hex SHA-256 of the merged seed card.
        seed: String,
        /// Hex SHA-256 of the file-only seed card.
        file_seed: String,
    },
    /// A `PUT /config/settings`.
    Put,
    /// A bounded amend (the audited admin verb).
    Amend {
        /// Hex SHA-256 of the stated reason.
        reason: String,
    },
    /// Copied from a node's journal by the PR-B first-boot migration.
    Migrated {
        /// The journal node it was copied from.
        node: u64,
        /// Its sequence number on that node's chain.
        node_seq: u64,
        /// Whether it was that chain's opening entry.
        opening: bool,
        /// A migrated amendment's reason digest, hex; `None` for a configured card.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// One entry of the fleet-shared history, as the store holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEntry {
    /// The entry's key: its identity.
    pub key: EntryKey,
    /// The first instant it prices, inclusive.
    pub effective_from: u64,
    /// The first instant it does not, exclusive; `None` is open-ended.
    pub effective_until: Option<u64>,
    /// When it was appended, wall-clock milliseconds.
    pub appended_at: u64,
    /// Why it exists.
    pub author: EntryAuthor,
    /// Who asked for it (the admin actor), or the system.
    pub actor: String,
    /// The key of the head it extended.
    pub base: Option<EntryKey>,
    /// The writer's durable node id.
    pub writer: u64,
    /// The card fields a PUT set (`rate_card`, `per_request_fee`, `planes.<p>.rate_card`, ...).
    pub set_fields: Vec<String>,
    /// The whole card.
    pub card: CardFields,
    /// An optional signed-correction envelope, as opaque bytes.
    pub correction: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryJson {
    v: u32,
    from: u64,
    #[serde(default)]
    until: Option<u64>,
    appended_at: u64,
    author: EntryAuthor,
    actor: String,
    #[serde(default)]
    base: Option<String>,
    writer: u64,
    #[serde(default)]
    set: Vec<String>,
    card: serde_json::Value,
    #[serde(default)]
    correction: Option<String>,
}

impl StoredEntry {
    /// The entry's value, as one byte string before it is split into parts.
    #[must_use]
    pub fn value(&self) -> Vec<u8> {
        let card: serde_json::Value =
            serde_json::from_slice(&self.card.to_bytes()).unwrap_or(serde_json::Value::Null);
        let json = EntryJson {
            v: 1,
            from: self.effective_from,
            until: self.effective_until,
            appended_at: self.appended_at,
            author: self.author.clone(),
            actor: self.actor.clone(),
            base: self.base.map(|k| k.hex()),
            writer: self.writer,
            set: self.set_fields.clone(),
            card,
            correction: self.correction.as_deref().map(hex::encode),
        };
        serde_json::to_vec(&json).unwrap_or_default()
    }

    /// The entry from its key and value.
    ///
    /// # Errors
    ///
    /// The value is not an entry.
    pub fn from_value(key: EntryKey, value: &[u8]) -> Result<Self, String> {
        let json: EntryJson = serde_json::from_slice(value)
            .map_err(|e| format!("card entry {key}: not an entry: {e}"))?;
        if json.v != 1 {
            return Err(format!("card entry {key}: version {} is not known", json.v));
        }
        let card = CardFields::from_bytes(
            &serde_json::to_vec(&json.card).map_err(|e| format!("card entry {key}: {e}"))?,
        )?;
        let base = match json.base {
            Some(hex) => Some(
                EntryKey::parse_hex(&hex)
                    .ok_or_else(|| format!("card entry {key}: base `{hex}` is not a key"))?,
            ),
            None => None,
        };
        let correction = match json.correction {
            Some(h) => Some(
                hex::decode(&h)
                    .map_err(|e| format!("card entry {key}: correction envelope: {e}"))?,
            ),
            None => None,
        };
        Ok(StoredEntry {
            key,
            effective_from: json.from,
            effective_until: json.until,
            appended_at: json.appended_at,
            author: json.author,
            actor: json.actor,
            base,
            writer: json.writer,
            set_fields: json.set,
            card,
            correction,
        })
    }

    /// The records this entry is written as: its data parts in order, then its commit part.
    ///
    /// # Errors
    ///
    /// The entry is too large to number its parts below [`COMMIT_PART`].
    pub fn records(&self) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        let value = self.value();
        let chunks: Vec<&[u8]> = if value.is_empty() {
            vec![&[][..]]
        } else {
            value.chunks(PART_BYTES).collect()
        };
        let count = u16::try_from(chunks.len())
            .ok()
            .filter(|n| *n < COMMIT_PART)
            .ok_or_else(|| format!("card entry {} is too large to write", self.key))?;
        let mut out = Vec::with_capacity(chunks.len() + 1);
        for (part, chunk) in chunks.into_iter().enumerate() {
            let part = u16::try_from(part).unwrap_or(u16::MAX);
            out.push((
                part_key(&self.key, part),
                RecordBytes::new(chunk.to_vec()).map_err(|n| format!("a {n}-byte part"))?,
            ));
        }
        let mut commit = Vec::with_capacity(34);
        commit.extend_from_slice(&count.to_be_bytes());
        commit.extend_from_slice(&sha256(&value));
        out.push((
            part_key(&self.key, COMMIT_PART),
            RecordBytes::new(commit).map_err(|n| format!("a {n}-byte commit"))?,
        ));
        Ok(out)
    }
}

/// A VOID: the entry `voided` is never in force, and its id stays known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoidRecord {
    /// The voided entry's key, hex.
    pub voided: String,
    /// The voiding node's durable id.
    pub voider: u64,
    /// When it was voided, wall-clock milliseconds.
    pub at_ms: u64,
    /// Who voided it.
    pub actor: String,
    /// Why: `void` (the operator's `card void`) or `abandon` (`card abandon`).
    pub why: String,
}

impl VoidRecord {
    /// The key it is written under.
    #[must_use]
    pub fn record_key(&self) -> Vec<u8> {
        let mut key = EntryKey::parse_hex(&self.voided)
            .map(|k| k.0.to_vec())
            .unwrap_or_default();
        key.push(VOID_TAG);
        key.extend_from_slice(&self.voider.to_be_bytes());
        key
    }

    /// The record it is written as.
    ///
    /// # Errors
    ///
    /// The record does not fit one record.
    pub fn record(&self) -> Result<(Vec<u8>, RecordBytes), String> {
        let value = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok((
            self.record_key(),
            RecordBytes::new(value).map_err(|n| format!("a {n}-byte void record"))?,
        ))
    }
}

/// The store key of `part` of entry `key`.
#[must_use]
pub fn part_key(key: &EntryKey, part: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTRY_KEY_LEN + 2);
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(&part.to_be_bytes());
    out
}

use busbar_kernel::config::card::sha256;

/// One entry's data parts by number, and its commit part, as a scan found them.
type Parts = (BTreeMap<u16, Vec<u8>>, Option<Vec<u8>>);

/// The records one write puts, in order: `(store key, value)`.
pub type Records = Vec<(Vec<u8>, RecordBytes)>;

/// What a full scan of the schema read.
#[derive(Debug, Default, Clone)]
pub struct Scanned {
    /// Every committed entry, in key order.
    pub entries: Vec<StoredEntry>,
    /// Every VOID.
    pub voids: Vec<VoidRecord>,
    /// Keys with parts and no matching commit: never READY, ignored.
    pub uncommitted: Vec<EntryKey>,
    /// Committed entries whose value does not read, by key and reason.
    pub unreadable: Vec<(EntryKey, String)>,
}

impl Scanned {
    /// Read the scan's records.
    #[must_use]
    pub fn of(records: Vec<(Vec<u8>, RecordBytes)>) -> Self {
        let mut grouped: BTreeMap<EntryKey, Parts> = BTreeMap::new();
        let mut scanned = Scanned::default();
        for (key, value) in records {
            let Some(entry_key) = key.get(..ENTRY_KEY_LEN).and_then(EntryKey::from_slice) else {
                continue;
            };
            let rest = &key[ENTRY_KEY_LEN..];
            if rest.len() == 9 && rest[0] == VOID_TAG {
                if let Ok(void) = serde_json::from_slice::<VoidRecord>(value.as_slice()) {
                    if void.voided == entry_key.hex() {
                        scanned.voids.push(void);
                    }
                }
                continue;
            }
            let Some(part) = <[u8; 2]>::try_from(rest).ok().map(u16::from_be_bytes) else {
                continue;
            };
            let slot = grouped.entry(entry_key).or_default();
            if part == COMMIT_PART {
                slot.1 = Some(value.as_slice().to_vec());
            } else if part < COMMIT_PART {
                slot.0.insert(part, value.as_slice().to_vec());
            }
        }
        for (key, (parts, commit)) in grouped {
            let Some(commit) = commit.filter(|c| c.len() == 34) else {
                scanned.uncommitted.push(key);
                continue;
            };
            let count = u16::from_be_bytes([commit[0], commit[1]]);
            let mut value = Vec::new();
            let whole = (0..count).all(|p| match parts.get(&p) {
                Some(chunk) => {
                    value.extend_from_slice(chunk);
                    true
                }
                None => false,
            });
            if !whole || sha256(&value)[..] != commit[2..] {
                scanned.uncommitted.push(key);
                continue;
            }
            match StoredEntry::from_value(key, &value) {
                Ok(entry) => scanned.entries.push(entry),
                Err(why) => scanned.unreadable.push((key, why)),
            }
        }
        scanned
    }
}

/// Wait for `fut` on this thread until `deadline`; `None` past it (the future is dropped).
pub fn wait_until<F: Future>(fut: F, deadline: Option<Instant>) -> Option<F::Output> {
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return Some(out);
        }
        match deadline {
            None => std::thread::park(),
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    return None;
                }
                std::thread::park_timeout(deadline - now);
            }
        }
    }
}

/// Read the whole history: every record of the schema.
///
/// # Errors
///
/// The store failed or refused the scan, or did not answer by `deadline`.
pub fn scan(calls: &dyn StoreCalls, deadline: Option<Instant>) -> Result<Scanned, String> {
    match wait_until(calls.record_scan(CARD_SCHEMA, b"", u32::MAX), deadline) {
        Some(Ok(records)) => Ok(Scanned::of(records)),
        Some(Err(failure)) => Err(format!(
            "the store would not read the rate-card history: {failure}"
        )),
        None => Err("the store did not read the rate-card history back in time".to_string()),
    }
}

/// How a write ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    /// Every record is acknowledged.
    Ready,
    /// The store REFUSED the first attempt before anything landed.
    Refused(String),
    /// Anything else: the write may or may not have landed.
    Doubtful(String),
}

/// Put `records` in order, awaiting each ack, until `deadline`. `first` says whether this is the
/// write's first attempt: only a first attempt's REFUSED is a refusal.
#[must_use]
pub fn put_all(
    calls: &dyn StoreCalls,
    records: &[(Vec<u8>, RecordBytes)],
    deadline: Option<Instant>,
    first: bool,
) -> PutOutcome {
    for (i, (key, value)) in records.iter().enumerate() {
        match wait_until(calls.record_put(CARD_SCHEMA, key, value), deadline) {
            Some(Ok(())) => {}
            Some(Err(StoreFailure::Refused(why))) if first && i == 0 => {
                return PutOutcome::Refused(why)
            }
            Some(Err(failure)) => return PutOutcome::Doubtful(failure.to_string()),
            None => {
                return PutOutcome::Doubtful(
                    "the store did not acknowledge the write in time".to_string(),
                )
            }
        }
    }
    PutOutcome::Ready
}

/// THE LOCAL SPOOL OF CARD WRITES the store has not confirmed: the pending entry's bytes (written
/// BEFORE its first put, so a restart re-puts them before admissions open), and each abandoned
/// entry's VOID until the store has it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spool {
    /// The pending entry, if any: its key and every record, hex.
    #[serde(default)]
    pub pending: Option<SpooledWrite>,
    /// Abandoned entries whose VOID is not READY yet.
    #[serde(default)]
    pub abandoned: Vec<SpooledWrite>,
}

/// One spooled write: the entry's key and the records to put, hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpooledWrite {
    /// The entry's key, hex.
    pub key: String,
    /// `(record key, value)`, hex, in put order.
    pub records: Vec<(String, String)>,
}

impl SpooledWrite {
    /// The spooled form of `records` for entry `key`.
    #[must_use]
    pub fn of(key: &EntryKey, records: &[(Vec<u8>, RecordBytes)]) -> Self {
        SpooledWrite {
            key: key.hex(),
            records: records
                .iter()
                .map(|(k, v)| (hex::encode(k), hex::encode(v.as_slice())))
                .collect(),
        }
    }

    /// The records to put.
    ///
    /// # Errors
    ///
    /// The spool's bytes do not read.
    pub fn records(&self) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        self.records
            .iter()
            .map(|(k, v)| {
                let k = hex::decode(k).map_err(|e| e.to_string())?;
                let v = hex::decode(v).map_err(|e| e.to_string())?;
                Ok((
                    k,
                    RecordBytes::new(v).map_err(|n| format!("a {n}-byte record"))?,
                ))
            })
            .collect()
    }
}

impl Spool {
    /// The spool's file under `dir`.
    #[must_use]
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(PENDING_FILE)
    }

    /// Read the spool under `dir`; an absent file is an empty spool.
    ///
    /// # Errors
    ///
    /// The file exists and does not read.
    pub fn load(dir: &Path) -> Result<Spool, String> {
        let path = Self::path(dir);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("{}: not a card spool: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Spool::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Write the spool under `dir`, durably: a temporary file synced, renamed over the old one,
    /// and the directory synced.
    ///
    /// # Errors
    ///
    /// The disk refused a step.
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        use std::io::Write as _;
        let path = Self::path(dir);
        let tmp = dir.join(format!("{PENDING_FILE}.tmp"));
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let step = |e: std::io::Error| format!("{}: {e}", path.display());
        let mut file = std::fs::File::create(&tmp).map_err(step)?;
        file.write_all(&bytes).map_err(step)?;
        file.sync_all().map_err(step)?;
        std::fs::rename(&tmp, &path).map_err(step)?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Whether nothing is spooled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_none() && self.abandoned.is_empty()
    }
}

/// This boot's random key half: fresh entropy every boot, so keys never collide across nodes or
/// restarts.
#[must_use]
pub fn boot_rand() -> [u8; 8] {
    let mut rand = [0u8; 8];
    if getrandom::fill(&mut rand).is_err() {
        // No entropy: the boot's wall clock in nanoseconds still separates boots and nodes far
        // better than a constant.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        rand = (nanos as u64).to_be_bytes();
    }
    rand
}

#[cfg(test)]
#[path = "tests/card_store.rs"]
mod tests;
