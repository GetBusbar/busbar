// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store-owned rate-card history. Legacy `busbar.card.v1` entries remain readable;
//! new entries use `busbar.card.v2`: original EntryKey, tagged u64 data indices,
//! then an INTENT and canonical COMMIT with identical version/ownership/count/length/digest
//! metadata. Existing v2 commits remain active; new own-card metadata version 3 additionally
//! requires a matching activation intent and commit. A complete candidate intent
//! preserves the exact original and own-selection for restart retry, without a host file.
//! Physical durability is the configured Store's responsibility (memory Store is ephemeral).

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::{StoreCalls, StoreFailure};
use busbar_kernel::config::card::CardFields;
use busbar_kernel_ledger::cost::{EntryKey, ENTRY_KEY_LEN};
use serde::{Deserialize, Serialize};

/// The record schema the history is kept under.
pub const CARD_SCHEMA: &str = "busbar.card.v2";
/// The legacy Store schema, read but never newly written.
pub const LEGACY_CARD_SCHEMA: &str = "busbar.card.v1";

const DATA_TAG: u8 = 0;
const INTENT_TAG: u8 = 1;
const COMMIT_TAG: u8 = 2;
const ACTIVATION_TAG: u8 = 3;
const ACTIVATION_COMMIT_TAG: u8 = 4;
const RETIREMENT_TAG: u8 = 5;
const RETIREMENT_COMMIT_TAG: u8 = 6;
const RETIREMENT_VERSION: u8 = 1;
const RECORD_VERSION: u8 = 2;
/// Own-card candidates require a separate authorized activation. Version two remains readable.
const PREPARED_RECORD_VERSION: u8 = 3;
const ACTIVATION_VERSION: u8 = 1;
const ACTIVATION_TIME_OFFSET: usize = 1;
const ACTIVATION_DIGEST_OFFSET: usize = ACTIVATION_TIME_OFFSET + std::mem::size_of::<u64>();
const ACTIVATION_BYTES: usize = ACTIVATION_DIGEST_OFFSET + 32;
const META_BYTES: usize = 50;

/// The legacy part number of an entry's commit part. New entries use u64 indices.
pub const COMMIT_PART: u16 = 0xFE00;

/// The tag byte that follows a voided key in a VOID record's key.
pub const VOID_TAG: u8 = 0xFF;

/// The clock skew a writer tolerates in the history's head (MONEY-DESIGN section 3a).
pub const SKEW_MS: u64 = 5 * 60 * 1000;

/// How long a card write waits for READY before it goes pending; no host lock is held.
pub const IN_LOCK_BOUND: Duration = Duration::from_secs(2);

/// The bytes one data part carries.
const PART_BYTES: usize = busbar_contract::MAX_RECORD_BYTES;

/// Why an entry exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryAuthor {
    /// The opening entry, written only when the history is empty: the booting node's card,
    /// effective from instant zero.
    Opening {},
    /// A change of the card a configuration resolved (boot, reload, apply, settings, plugin reload
    /// or rollback, overlay or named-map write); the entry's `actor` names which, and who.
    Change,
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
    /// Who or what wrote it: "config/reload by <actor>", "boot of node <id>", ... The entry is
    /// the audited record of a card change.
    pub actor: String,
    /// The key of the head it extended.
    pub base: Option<EntryKey>,
    /// The writer's durable node id.
    pub writer: u64,
    /// The card fields that changed from the entry it extended (`rate_card`, `per_request_fee`,
    /// `planes.<p>.rate_card`, ...).
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

    /// Data chunks, the immutable intent, then the canonical commit, in put order.
    ///
    /// # Errors
    ///
    /// A size cannot be represented on this platform. There is no card admission-size cap.
    pub fn records(&self) -> Result<Records, String> {
        self.records_for(false)
    }

    /// Encode this exact original and whether it selects its writer's own card.
    pub(crate) fn records_for(&self, own: bool) -> Result<Records, String> {
        value_records(self.key, &self.value(), own)
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
    /// Why it was voided (`void`).
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

/// The records one write puts, in order: `(store key, value)`.
pub type Records = Vec<(Vec<u8>, RecordBytes)>;

/// A complete Store intent. Its bytes and identity remain immutable across retries.
#[derive(Debug, Clone)]
pub struct StoredIntent {
    /// The original, including all provenance and correction fields.
    pub entry: StoredEntry,
    /// Whether this entry selects its writer's own card; amendments do not.
    pub own: bool,
    /// Exact data and metadata, including the canonical commit still owed, in put order.
    pub records: Arc<Records>,
    /// Whether the canonical commit is complete and valid as well.
    pub committed: bool,
    /// New own-card candidates require matching activation intent and commit records.
    pub activation_required: bool,
    /// The immutable authorized cutover, when present.
    pub activation: Option<Activation>,
    /// The activation has its matching canonical confirmation marker.
    pub activation_confirmed: bool,
    /// An inert original retired before activation could commit.
    pub retired: bool,
    /// Retirement intent custody survives an unknown final marker without authorizing activation.
    pub retiring: bool,
}

/// Activation is a raw historical fact, separate from the immutable candidate's authored time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    /// The era this configuration starts pricing. An opening still covers instant zero.
    pub effective_from: u64,
}

impl Activation {
    /// Bounded intent and commit records bind this cutover to the exact original candidate.
    pub fn records(&self, entry: &StoredEntry) -> Result<Records, String> {
        let mut value = vec![ACTIVATION_VERSION];
        value.extend_from_slice(&self.effective_from.to_be_bytes());
        value.extend_from_slice(&sha256(&entry.value()));
        let value = RecordBytes::new(value).map_err(|error| error.to_string())?;
        Ok(vec![
            (tagged_key(entry.key, ACTIVATION_TAG), value.clone()),
            (tagged_key(entry.key, ACTIVATION_COMMIT_TAG), value),
        ])
    }

    fn read(
        value: &[u8],
        entry: &StoredEntry,
        candidate_digest: &[u8; 32],
    ) -> Result<Self, &'static str> {
        if value.len() != ACTIVATION_BYTES
            || value[0] != ACTIVATION_VERSION
            || value[ACTIVATION_DIGEST_OFFSET..] != *candidate_digest
        {
            return Err("invalid card activation binding");
        }
        let effective_from = u64::from_be_bytes(
            value[ACTIVATION_TIME_OFFSET..ACTIVATION_DIGEST_OFFSET]
                .try_into()
                .map_err(|_| "invalid card activation time")?,
        );
        if is_opening_author(&entry.author) != (effective_from == 0) {
            return Err("invalid opening or change activation time");
        }
        Ok(Self { effective_from })
    }
}

fn is_opening_author(author: &EntryAuthor) -> bool {
    matches!(
        author,
        EntryAuthor::Opening { .. } | EntryAuthor::Migrated { opening: true, .. }
    )
}

/// Bind retirement to the exact saved candidate, never an overwrite or deletion of it.
pub(crate) fn retirement_records(entry: &StoredEntry) -> Result<Records, String> {
    let mut value = vec![RETIREMENT_VERSION];
    value.extend_from_slice(&sha256(&entry.value()));
    let value = RecordBytes::new(value).map_err(|error| error.to_string())?;
    Ok(vec![
        (tagged_key(entry.key, RETIREMENT_TAG), value.clone()),
        (tagged_key(entry.key, RETIREMENT_COMMIT_TAG), value),
    ])
}

#[derive(Default)]
struct Parts {
    legacy: BTreeMap<u16, Vec<u8>>,
    legacy_commit: Option<Vec<u8>>,
    data: BTreeMap<u64, Vec<u8>>,
    intent: Option<Vec<u8>>,
    commit: Option<Vec<u8>>,
    activation: Option<Vec<u8>>,
    activation_commit: Option<Vec<u8>>,
    retirement: Option<Vec<u8>>,
    retirement_commit: Option<Vec<u8>>,
    invalid: bool,
}

/// What a full scan read. Validation finishes before any caller publishes or replays it.
#[derive(Debug, Default, Clone)]
pub struct Scanned {
    /// Every active entry confirmed by its protocol, in key order.
    pub entries: Vec<StoredEntry>,
    /// Every validated intent, including already committed ones.
    pub intents: Vec<StoredIntent>,
    /// Authorized cutovers for the active entries that require one.
    pub activations: BTreeMap<EntryKey, Activation>,
    /// Every valid VOID.
    pub voids: Vec<VoidRecord>,
    /// Incomplete entries: never confirmation.
    pub uncommitted: Vec<EntryKey>,
    /// Corrupt or unsupported entries/VOID records, by immutable identity and structural reason.
    pub unreadable: Vec<(EntryKey, String)>,
}

fn tagged_key(key: EntryKey, tag: u8) -> Vec<u8> {
    let mut out = key.as_bytes().to_vec();
    out.push(tag);
    out
}

fn data_key(key: EntryKey, part: u64) -> Vec<u8> {
    let mut out = tagged_key(key, DATA_TAG);
    out.extend_from_slice(&part.to_be_bytes());
    out
}

fn value_records(key: EntryKey, value: &[u8], own: bool) -> Result<Records, String> {
    let length = u64::try_from(value.len()).map_err(|_| "card value length overflow")?;
    let count = length.div_ceil(PART_BYTES as u64);
    let mut records = Vec::new();
    for (index, part) in value.chunks(PART_BYTES).enumerate() {
        let index = u64::try_from(index).map_err(|_| "card chunk index overflow")?;
        records.push((
            data_key(key, index),
            RecordBytes::new(part.to_vec()).map_err(|_| "card chunk length overflow")?,
        ));
    }
    let version = if own {
        PREPARED_RECORD_VERSION
    } else {
        RECORD_VERSION
    };
    let mut meta = vec![version, u8::from(own)];
    meta.extend_from_slice(&count.to_be_bytes());
    meta.extend_from_slice(&length.to_be_bytes());
    meta.extend_from_slice(&sha256(value));
    let meta = RecordBytes::new(meta).map_err(|_| "card metadata length overflow")?;
    records.push((tagged_key(key, INTENT_TAG), meta.clone()));
    records.push((tagged_key(key, COMMIT_TAG), meta));
    Ok(records)
}

/// Validate all metadata and every chunk, including extra and empty chunks, before decoding.
fn assemble(parts: &BTreeMap<u64, Vec<u8>>, meta: &[u8]) -> Result<(Vec<u8>, bool), &'static str> {
    if meta.len() != META_BYTES
        || !matches!(meta[0], RECORD_VERSION | PREPARED_RECORD_VERSION)
        || meta[1] > 1
        || (meta[0] == PREPARED_RECORD_VERSION && meta[1] != 1)
    {
        return Err("unsupported or malformed card metadata");
    }
    let count = u64::from_be_bytes(meta[2..10].try_into().map_err(|_| "invalid chunk count")?);
    let length = u64::from_be_bytes(
        meta[10..18]
            .try_into()
            .map_err(|_| "invalid value length")?,
    );
    if count != length.div_ceil(PART_BYTES as u64) || u64::try_from(parts.len()).ok() != Some(count)
    {
        return Err("card chunk count does not match its value length");
    }
    let mut value = Vec::new();
    for (expected, (&index, chunk)) in (0..count).zip(parts.iter()) {
        if index != expected {
            return Err("missing or out-of-order card chunk");
        }
        let expected_len = if expected + 1 == count {
            ((length - 1) % PART_BYTES as u64 + 1) as usize
        } else {
            PART_BYTES
        };
        if chunk.len() != expected_len {
            return Err("missing, extra, empty or mis-sized card chunk");
        }
        value.extend_from_slice(chunk);
    }
    if sha256(&value)[..] != meta[18..] {
        return Err("card value digest does not match");
    }
    Ok((value, meta[1] == 1))
}

impl Scanned {
    /// Decode either record protocol. Conflicting duplicate keys invalidate their owner,
    /// independent of row order; identical duplicates are harmless.
    #[must_use]
    pub fn of(records: Records) -> Self {
        let mut grouped: BTreeMap<EntryKey, Parts> = BTreeMap::new();
        let mut unique: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut scanned = Self::default();
        let mut voids = Vec::new();
        for (key, value) in records {
            let Some(entry_key) = key.get(..ENTRY_KEY_LEN).and_then(EntryKey::from_slice) else {
                continue;
            };
            let slot = grouped.entry(entry_key).or_default();
            let value = value.as_slice().to_vec();
            if let Some(previous) = unique.get(&key) {
                if *previous != value {
                    slot.invalid = true;
                }
                continue;
            }
            unique.insert(key.clone(), value.clone());
            let rest = &key[ENTRY_KEY_LEN..];
            match rest {
                [VOID_TAG, voider @ ..] if voider.len() == 8 => {
                    match serde_json::from_slice::<VoidRecord>(&value) {
                        Ok(void)
                            if void.voided == entry_key.hex()
                                && void.voider.to_be_bytes().as_slice() == voider =>
                        {
                            voids.push((entry_key, void));
                        }
                        _ => scanned
                            .unreadable
                            .push((entry_key, "invalid VOID record".into())),
                    }
                }
                [DATA_TAG, index @ ..] if index.len() == 8 => {
                    let index = u64::from_be_bytes(index.try_into().expect("eight-byte index"));
                    slot.data.insert(index, value);
                }
                [INTENT_TAG] => slot.intent = Some(value),
                [COMMIT_TAG] => slot.commit = Some(value),
                [ACTIVATION_TAG] => slot.activation = Some(value),
                [ACTIVATION_COMMIT_TAG] => slot.activation_commit = Some(value),
                [RETIREMENT_TAG] => slot.retirement = Some(value),
                [RETIREMENT_COMMIT_TAG] => slot.retirement_commit = Some(value),
                [hi, lo] => {
                    let part = u16::from_be_bytes([*hi, *lo]);
                    if part == COMMIT_PART {
                        slot.legacy_commit = Some(value);
                    } else if part < COMMIT_PART {
                        slot.legacy.insert(part, value);
                    } else {
                        slot.invalid = true;
                    }
                }
                _ => slot.invalid = true,
            }
        }
        for (key, parts) in grouped {
            if parts.invalid {
                scanned
                    .unreadable
                    .push((key, "conflicting duplicate or unknown card record".into()));
                continue;
            }
            scanned.voids.extend(
                voids
                    .iter()
                    .filter(|(owner, _)| *owner == key)
                    .map(|(_, v)| v.clone()),
            );
            let legacy = !parts.legacy.is_empty() || parts.legacy_commit.is_some();
            let modern = !parts.data.is_empty()
                || parts.intent.is_some()
                || parts.commit.is_some()
                || parts.activation.is_some();
            let modern = modern
                || parts.activation_commit.is_some()
                || parts.retirement.is_some()
                || parts.retirement_commit.is_some();
            if legacy && modern {
                scanned
                    .unreadable
                    .push((key, "overlapping card record protocols".into()));
                continue;
            }
            if legacy {
                let Some(commit) = parts.legacy_commit else {
                    scanned.uncommitted.push(key);
                    continue;
                };
                if commit.len() != 34 {
                    scanned
                        .unreadable
                        .push((key, "invalid legacy card commit".into()));
                    continue;
                }
                let count = u16::from_be_bytes([commit[0], commit[1]]);
                let complete = count > 0
                    && count < COMMIT_PART
                    && parts.legacy.len() == usize::from(count)
                    && (0..count).all(|index| {
                        parts.legacy.get(&index).is_some_and(|chunk| {
                            !chunk.is_empty() && (index + 1 == count || chunk.len() == PART_BYTES)
                        })
                    });
                let value: Vec<u8> = parts.legacy.values().flatten().copied().collect();
                if !complete || sha256(&value)[..] != commit[2..] {
                    scanned
                        .unreadable
                        .push((key, "legacy card commit does not match its chunks".into()));
                    continue;
                }
                match StoredEntry::from_value(key, &value) {
                    Ok(entry) => scanned.entries.push(entry),
                    Err(_) => scanned
                        .unreadable
                        .push((key, "invalid legacy card entry".into())),
                }
            } else if modern {
                let Some(intent) = parts.intent else {
                    if parts.commit.is_some()
                        || parts.activation.is_some()
                        || parts.activation_commit.is_some()
                        || parts.retirement.is_some()
                        || parts.retirement_commit.is_some()
                    {
                        scanned
                            .unreadable
                            .push((key, "card commit has no intent".into()));
                    } else {
                        scanned.uncommitted.push(key);
                    }
                    continue;
                };
                if parts
                    .commit
                    .as_ref()
                    .is_some_and(|commit| *commit != intent)
                {
                    scanned
                        .unreadable
                        .push((key, "card intent and commit disagree".into()));
                    continue;
                }
                let (value, own) = match assemble(&parts.data, &intent) {
                    Ok(value) => value,
                    Err(why) => {
                        scanned.unreadable.push((key, why.into()));
                        continue;
                    }
                };
                let entry = match StoredEntry::from_value(key, &value) {
                    Ok(entry) => entry,
                    Err(_) => {
                        scanned.unreadable.push((key, "invalid card entry".into()));
                        continue;
                    }
                };
                let candidate_digest = sha256(&value);
                if own && matches!(entry.author, EntryAuthor::Amend { .. }) {
                    scanned
                        .unreadable
                        .push((key, "amendment cannot select the node card".into()));
                    continue;
                }
                let committed = parts.commit.is_some();
                let activation_required = intent[0] == PREPARED_RECORD_VERSION;
                let activation_confirmed = parts.activation_commit.is_some();
                let retired = parts.retirement_commit.is_some();
                if parts
                    .retirement_commit
                    .as_ref()
                    .is_some_and(|commit| Some(commit) != parts.retirement.as_ref())
                {
                    scanned
                        .unreadable
                        .push((key, "card retirement intent and commit disagree".into()));
                    continue;
                }
                if let Some(value) = &parts.retirement {
                    if !committed
                        || !activation_required
                        || (retired && activation_confirmed)
                        || value.len() != 1 + candidate_digest.len()
                        || value[0] != RETIREMENT_VERSION
                        || value[1..] != candidate_digest
                    {
                        scanned
                            .unreadable
                            .push((key, "invalid or conflicting card retirement".into()));
                        continue;
                    }
                }
                let retiring = parts.retirement.is_some() && !retired && !activation_confirmed;
                if parts
                    .activation_commit
                    .as_ref()
                    .is_some_and(|commit| Some(commit) != parts.activation.as_ref())
                {
                    scanned
                        .unreadable
                        .push((key, "card activation intent and commit disagree".into()));
                    continue;
                }
                let activation = match parts.activation {
                    Some(value) if committed && activation_required => {
                        match Activation::read(&value, &entry, &candidate_digest) {
                            Ok(activation) => Some(activation),
                            Err(why) => {
                                scanned.unreadable.push((key, why.into()));
                                continue;
                            }
                        }
                    }
                    Some(_) => {
                        scanned
                            .unreadable
                            .push((key, "card activation has no prepared commit".into()));
                        continue;
                    }
                    None => None,
                };
                let mut records: Records = parts
                    .data
                    .into_iter()
                    .map(|(index, value)| {
                        (
                            data_key(key, index),
                            RecordBytes::new(value).expect("scanned RecordBytes"),
                        )
                    })
                    .collect();
                let meta = RecordBytes::new(intent).expect("validated metadata");
                records.push((tagged_key(key, INTENT_TAG), meta.clone()));
                records.push((tagged_key(key, COMMIT_TAG), meta));
                if !retired && committed && (!activation_required || activation_confirmed) {
                    scanned.entries.push(entry.clone());
                    if let Some(activation) = &activation {
                        scanned.activations.insert(key, activation.clone());
                    }
                } else {
                    scanned.uncommitted.push(key);
                }
                scanned.intents.push(StoredIntent {
                    entry,
                    own,
                    records: Arc::new(records),
                    committed,
                    activation_required,
                    activation,
                    activation_confirmed,
                    retired,
                    retiring,
                });
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
    let mut records = scan_records(calls, LEGACY_CARD_SCHEMA, deadline)?;
    records.extend(scan_records(calls, CARD_SCHEMA, deadline)?);
    if records.iter().any(|(key, _)| {
        key.get(..ENTRY_KEY_LEN)
            .and_then(EntryKey::from_slice)
            .is_none()
    }) {
        return Err("rate-card Store contains a malformed record key".into());
    }
    Ok(Scanned::of(records))
}

fn scan_records(
    calls: &dyn StoreCalls,
    schema: &str,
    deadline: Option<Instant>,
) -> Result<Records, String> {
    let mut prefixes = vec![Vec::new()];
    let mut records = Vec::new();
    while let Some(prefix) = prefixes.pop() {
        let rows = match wait_until(calls.record_scan(schema, &prefix, u32::MAX), deadline) {
            Some(Ok(rows)) => rows,
            Some(Err(_)) => return Err("the store would not read the rate-card history".into()),
            None => return Err("the store did not read the rate-card history back in time".into()),
        };
        if rows.iter().any(|(key, _)| !key.starts_with(&prefix)) {
            return Err("rate-card scan returned a key outside its prefix".into());
        }
        if u32::try_from(rows.len()).ok() == Some(u32::MAX) {
            // Keep a possible row exactly at this prefix, then partition every longer key.
            records.extend(rows.into_iter().filter(|(key, _)| *key == prefix));
            for byte in (0..=u8::MAX).rev() {
                let mut next = prefix.clone();
                next.push(byte);
                prefixes.push(next);
            }
        } else {
            records.extend(rows);
        }
    }
    Ok(records)
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
    let progress = std::sync::atomic::AtomicUsize::new(0);
    put_from(calls, records, &progress, deadline, first)
}

/// Resume a candidate at its first unacknowledged record. A timeout or unknown outcome leaves
/// that exact record owed. Progress is per immutable owner, never a new key or an entry-size cap.
pub(crate) fn put_from(
    calls: &dyn StoreCalls,
    records: &[(Vec<u8>, RecordBytes)],
    progress: &std::sync::atomic::AtomicUsize,
    deadline: Option<Instant>,
    first: bool,
) -> PutOutcome {
    use std::sync::atomic::Ordering;
    let start = progress.load(Ordering::Acquire);
    for (i, (key, value)) in records.iter().enumerate().skip(start) {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return PutOutcome::Doubtful("rate-card write deadline elapsed".into());
        }
        // Generic record_put is an upsert. Never overwrite a different immutable original,
        // including during retry after an unknown outcome. Callbacks run without host locks.
        match wait_until(calls.record_get(CARD_SCHEMA, key), deadline) {
            Some(Ok(Some(held))) if held != *value => {
                return PutOutcome::Doubtful("conflicting immutable rate-card Store record".into());
            }
            Some(Ok(Some(_))) => {
                // An exact immutable readback positively confirms a previously unknown put.
                // Reissuing an upsert is unnecessary and cannot improve this confirmation.
                progress.store(i + 1, Ordering::Release);
                continue;
            }
            Some(Ok(_)) => {}
            Some(Err(_)) => {
                return PutOutcome::Doubtful("the Store would not check a rate-card record".into())
            }
            None => {
                return PutOutcome::Doubtful(
                    "the Store did not check a rate-card record in time".into(),
                )
            }
        }
        match wait_until(calls.record_put(CARD_SCHEMA, key, value), deadline) {
            Some(Ok(())) => {
                progress.store(i + 1, Ordering::Release);
            }
            Some(Err(StoreFailure::Refused(_))) if first && i == 0 => {
                return PutOutcome::Refused("the Store refused the first rate-card record".into())
            }
            Some(Err(_)) => {
                return PutOutcome::Doubtful(
                    "the Store did not acknowledge a rate-card record".into(),
                )
            }
            None => {
                return PutOutcome::Doubtful(
                    "the store did not acknowledge the write in time".to_string(),
                )
            }
        }
    }
    PutOutcome::Ready
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
