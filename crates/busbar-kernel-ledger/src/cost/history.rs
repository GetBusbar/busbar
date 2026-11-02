// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated rate-card history: what things cost, and since when.

use crate::cost::rate::RateCard;

/// An entry's own number: dense, monotone, assigned on append.
///
/// THIS IS THE CARD IDENTITY, and it is the only one. It replaces the free-text version name the
/// card used to carry and the bare `u64` the journal, the migration marker and the opening balance
/// each spelled separately — one number, meaning one thing, readable by all of them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HistorySeq(pub u64);

impl HistorySeq {
    /// The opening entry's number. A migration seals a single-entry history at this seq, effective

    pub const OPENING: HistorySeq = HistorySeq(0);

    /// The number as the journal, the marker and the store all spell it.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for HistorySeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The length of an entry's KEY in the store's `busbar.card.v1` schema:

pub const ENTRY_KEY_LEN: usize = 20;

/// **AN ENTRY'S IDENTITY**: its key in the fleet-shared history (MONEY-DESIGN section 3a).
///
/// Keys are unique across nodes (the writer's per-boot random half) and ordered by their bytes,
/// which is time first. The resolution rule names the KEY, never a list position: among the live
/// entries covering an instant, the highest key wins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EntryKey(pub [u8; ENTRY_KEY_LEN]);

impl EntryKey {
    /// The key for `t_ms`, written by the boot whose random half is `node_rand`, `counter`th.
    pub fn new(t_ms: u64, node_rand: [u8; 8], counter: u32) -> Self {
        let mut key = [0u8; ENTRY_KEY_LEN];
        key[..8].copy_from_slice(&t_ms.to_be_bytes());
        key[8..16].copy_from_slice(&node_rand);
        key[16..].copy_from_slice(&counter.to_be_bytes());
        EntryKey(key)
    }

    /// The key from its stored bytes, or `None` when they are not exactly a key.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; ENTRY_KEY_LEN]>::try_from(bytes).ok().map(EntryKey)
    }

    /// The commit time the key was minted at, in wall-clock milliseconds.
    pub fn t_ms(&self) -> u64 {
        let mut t = [0u8; 8];
        t.copy_from_slice(&self.0[..8]);
        u64::from_be_bytes(t)
    }

    /// The writer boot's random half.
    pub fn node_rand(&self) -> [u8; 8] {
        let mut r = [0u8; 8];
        r.copy_from_slice(&self.0[8..16]);
        r
    }

    /// The key's bytes, as the store holds them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The short id a count segment carries.
    pub fn id(&self) -> EntryId {
        EntryId::of(self)
    }

    /// The key as lowercase hex (40 characters), the spelling the admin verbs take.
    pub fn hex(&self) -> String {
        hex(&self.0)
    }

    /// The key from its 40-character hex spelling.
    pub fn parse_hex(text: &str) -> Option<Self> {
        unhex(text).and_then(|b| Self::from_slice(&b))
    }
}

impl std::fmt::Display for EntryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

/// The byte length of an [`EntryId`].
pub const ENTRY_ID_LEN: usize = 12;

/// **THE ID A COUNT SEGMENT CARRIES**: the first 12 bytes of SHA-256 of the entry's [`EntryKey`]
/// (MONEY-DESIGN section 3b). Spelled as 24 lowercase hex characters; the pseudo-model prefix of a
/// sibling era row is that spelling followed by `U+001F`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EntryId(pub [u8; ENTRY_ID_LEN]);

/// The raw provenance of counts: the era's date and, when recorded, its exact entry identity.
///
/// Historical rows without an identity retain their original dating semantics. In particular,
/// legacy zero is undated; it cannot establish that the opening entry served those counts.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RawRateEra {
    /// The original entry's inclusive start, in wall-clock milliseconds.
    pub effective_from: u64,
    /// The entry actually serving the counts, absent in legacy records.
    pub entry_id: Option<EntryId>,
}

impl RawRateEra {
    /// A historical timestamp without an entry identity.
    pub const fn legacy(effective_from: u64) -> Self {
        Self {
            effective_from,
            entry_id: None,
        }
    }

    /// An entry known to have served the counts, including an opening entry dated zero.
    pub const fn entry(effective_from: u64, entry_id: EntryId) -> Self {
        Self {
            effective_from,
            entry_id: Some(entry_id),
        }
    }
}

impl From<u64> for RawRateEra {
    fn from(effective_from: u64) -> Self {
        Self::legacy(effective_from)
    }
}

impl EntryId {
    /// The versioned metering provenance prefix. Other historical version names remain legacy.
    pub const METERING_VERSION_PREFIX: &'static str = "busbar.card.entry.v1:";

    /// The exact entry identity as a metering row's existing `pricing_version` field.
    pub fn metering_version(&self) -> String {
        format!("{}{self}", Self::METERING_VERSION_PREFIX)
    }

    /// Parse an exact metering identity. `None` denotes a legacy name; `Some(None)` denotes a

    pub fn parse_metering_version(version: &str) -> Option<Option<Self>> {
        version
            .strip_prefix(Self::METERING_VERSION_PREFIX)
            .map(Self::parse_hex)
    }

    /// The separator between an id and the model name in a pseudo-model key.
    pub const SEPARATOR: char = '\u{1f}';

    /// The id of `key`.
    pub fn of(key: &EntryKey) -> Self {
        let digest = busbar_contract::abi::sdk::digest::sha256(key.as_bytes());
        let mut id = [0u8; ENTRY_ID_LEN];
        id.copy_from_slice(&digest[..ENTRY_ID_LEN]);
        EntryId(id)
    }

    /// The 24-character lowercase hex spelling.
    pub fn hex(&self) -> String {
        hex(&self.0)
    }

    /// The id from its 24-character hex spelling.
    pub fn parse_hex(text: &str) -> Option<Self> {
        let bytes = unhex(text)?;
        <[u8; ENTRY_ID_LEN]>::try_from(bytes.as_slice())
            .ok()
            .map(EntryId)
    }

    /// The pseudo-model prefix `"<24hex>\u{1f}"`: alone it keys the entry's fee count, followed by

    pub fn pseudo_prefix(&self) -> String {
        let mut prefix = self.hex();
        prefix.push(Self::SEPARATOR);
        prefix
    }

    /// Split a pseudo-model key into its entry id and the model name after the separator (empty

    pub fn split_pseudo(key: &str) -> Option<(EntryId, &str)> {
        let (id, model) = key.split_once(Self::SEPARATOR)?;
        (id.len() == 2 * ENTRY_ID_LEN)
            .then(|| EntryId::parse_hex(id))
            .flatten()
            .map(|id| (id, model))
    }
}

impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// Why an entry exists. The distinction is the whole audit trail: an operator reading the history
/// can tell an ordinary price change from a correction of the past without comparing timestamps.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Author {
    /// Sealed at bootstrap or migration: the opening entry, effective from instant zero.
    Opening,
    /// A configuration write, or a reload. Effective from the moment it was appended, never before.
    Config {
        /// The policy epoch the configuration that produced it belonged to.
        policy_epoch: u64,
    },
    /// The amendment verb. Effective from an instant the operator named, which is in the past —
    /// that is what makes it an amendment rather than a configuration write. It names no signer:
    /// no admin verb carries an operator signature (#77(9), BUSBAR-1.6.0.md l.2279).
    Amend {
        /// The digest of the stated reason. The reason itself is free text and is not the record;
        /// its hash is, so the record is fixed-width and the text cannot be edited under it.
        reason_hash: [u8; 32],
    },
}

/// One entry of the history: a card, and the window of instants it prices.
#[derive(Clone, Debug)]
pub struct CardEntry {
    seq: HistorySeq,
    key: EntryKey,
    voided: bool,
    effective_from: u64,
    effective_until: Option<u64>,
    card: RateCard,
    appended_at: u64,
    author: Author,
}

impl CardEntry {
    /// This entry's number. Assigned on append and never changed.
    pub fn seq(&self) -> HistorySeq {
        self.seq
    }

    /// This entry's identity in the fleet-shared history.
    pub fn key(&self) -> EntryKey {
        self.key
    }

    /// The id a count segment priced with this entry carries.
    pub fn id(&self) -> EntryId {
        self.key.id()
    }

    /// The first instant this entry prices, inclusive, in wall-clock milliseconds.
    pub fn effective_from(&self) -> u64 {
        self.effective_from
    }

    /// The first instant it does NOT price, exclusive. `None` is open-ended.
    pub fn effective_until(&self) -> Option<u64> {
        self.effective_until
    }

    /// The card itself.
    pub fn card(&self) -> &RateCard {
        &self.card
    }

    /// When the entry was WRITTEN, in wall-clock milliseconds.

    pub fn appended_at(&self) -> u64 {
        self.appended_at
    }

    /// Why this entry exists.
    pub fn author(&self) -> &Author {
        &self.author
    }

    /// Whether this entry's interval covers `t`: `effective_from <= t < effective_until`.
    pub fn covers(&self, t: u64) -> bool {
        t >= self.effective_from && self.effective_until.is_none_or(|until| t < until)
    }

    /// Whether a VOID record names this entry: it is never in force, but its id stays KNOWN, so a

    pub fn is_voided(&self) -> bool {
        self.voided
    }

    /// Whether this entry prices `t`: live, and covering it.
    fn prices(&self, t: u64) -> bool {
        !self.voided && self.covers(t)
    }
}

/// An entry before it has a number. The number is the history's to assign, never the caller's — a
/// caller that could choose a `seq` could write over an entry that already exists.
#[derive(Clone, Debug)]
pub struct CardEntryDraft {
    /// The first instant the new entry prices, inclusive.
    pub effective_from: u64,
    /// The first instant it does not, exclusive. `None` is open-ended.
    pub effective_until: Option<u64>,
    /// The card.
    pub card: RateCard,
    /// When the entry is being written.
    pub appended_at: u64,
    /// Why.
    pub author: Author,
}

/// The whole history: append-only, ordered by `seq`, NEVER by `effective_from`.
///
/// Sorting by date would be the natural-looking thing and it would destroy the design: two entries
/// covering the same instant are precisely how a correction is expressed, and the one that wins is
/// the one that was written LAST, not the one that starts latest.
#[derive(Clone, Debug, Default)]
pub struct History {
    entries: Vec<CardEntry>,
}

impl History {
    /// An empty history. Nothing is priceable against it — every instant is a hole — which is the

    pub fn new() -> Self {
        History {
            entries: Vec::new(),
        }
    }

    /// **A SINGLE-ENTRY HISTORY**: the operator's card, effective from instant zero, open-ended,

    pub fn opening(card: RateCard, appended_at: u64) -> Self {
        let mut history = History::new();
        history.append(CardEntryDraft {
            effective_from: 0,
            effective_until: None,
            card,
            appended_at,
            author: Author::Opening,
        });
        history
    }

    /// The newest entry's number, or `None` for a history nothing has been appended to.

    pub fn head(&self) -> Option<HistorySeq> {
        self.entries.last().map(CardEntry::seq)
    }

    /// Every entry, in `seq` order.
    pub fn entries(&self) -> &[CardEntry] {
        &self.entries
    }

    /// How many entries there are.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// **THE REPRODUCIBILITY PRIMITIVE.** Everything with `seq <= at`.

    pub fn snapshot(&self, at: HistorySeq) -> HistoryView<'_> {
        let count = self.entries.partition_point(|e| e.seq <= at);
        HistoryView {
            entries: &self.entries[..count],
            at: Some(at),
        }
    }

    /// The whole history as it stands. Equivalent to snapshotting at the head, and naming no

    pub fn current(&self) -> HistoryView<'_> {
        HistoryView {
            entries: &self.entries,
            at: self.head(),
        }
    }

    /// **THE ONLY MUTATOR.** Append an entry and return its number.

    pub fn append(&mut self, draft: CardEntryDraft) -> HistorySeq {
        let seq = HistorySeq(self.entries.len() as u64);

        let t_ms = self.entries.last().map_or(draft.appended_at, |head| {
            draft.appended_at.max(head.key.t_ms().saturating_add(1))
        });
        let key = EntryKey::new(t_ms, [0; 8], seq.0 as u32);
        self.entries.push(CardEntry {
            seq,
            key,
            voided: false,
            effective_from: draft.effective_from,
            effective_until: draft.effective_until,
            card: draft.card,
            appended_at: draft.appended_at,
            author: draft.author,
        });
        seq
    }
}

impl History {
    /// **ORDERED INSERT** of an entry read from (or written to) the fleet-shared history under its

    pub fn insert(&mut self, key: EntryKey, draft: CardEntryDraft) -> HistorySeq {
        match self.entries.binary_search_by(|e| e.key.cmp(&key)) {
            Ok(at) => HistorySeq(at as u64),
            Err(at) => {
                self.entries.insert(
                    at,
                    CardEntry {
                        seq: HistorySeq(at as u64),
                        key,
                        voided: false,
                        effective_from: draft.effective_from,
                        effective_until: draft.effective_until,
                        card: draft.card,
                        appended_at: draft.appended_at,
                        author: draft.author,
                    },
                );
                for (i, e) in self.entries.iter_mut().enumerate().skip(at) {
                    e.seq = HistorySeq(i as u64);
                }
                HistorySeq(at as u64)
            }
        }
    }

    /// Mark the entry `key` VOID. Answers whether this history holds it.
    pub fn void(&mut self, key: &EntryKey) -> bool {
        match self.entries.iter_mut().find(|e| e.key == *key) {
            Some(entry) => {
                entry.voided = true;
                true
            }
            None => false,
        }
    }

    /// The entry whose key is `key`, voided or not.
    pub fn entry(&self, key: &EntryKey) -> Option<&CardEntry> {
        self.entries.iter().find(|e| e.key == *key)
    }

    /// The highest commit time among the LIVE entries (`head_t_ms`): a voided entry never counts.
    pub fn head_t_ms(&self) -> Option<u64> {
        self.entries
            .iter()
            .rev()
            .find(|e| !e.voided)
            .map(|e| e.key.t_ms())
    }

    /// The highest-keyed LIVE entry: the head a new entry extends.
    pub fn live_head(&self) -> Option<&CardEntry> {
        self.entries.iter().rev().find(|e| !e.voided)
    }

    /// **THE ANSWER AT `instant`** (seam for the poster): the id and card of the highest-keyed live

    pub fn entry_at(&self, instant: u64) -> Option<(EntryId, &RateCard)> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.prices(instant))
            .map(|entry| (entry.id(), &entry.card))
    }

    /// The card of the entry whose id is `id`, voided or not: a count posted under an entry keeps

    pub fn card_of(&self, id: &EntryId) -> Option<&RateCard> {
        self.entries
            .iter()
            .find(|entry| entry.id() == *id)
            .map(|entry| &entry.card)
    }
}

/// The history as one snapshot saw it: the entries with `seq <= at`, borrowed.
///
/// A view is a borrowed slice and a number. It reads no clock and owns nothing, so a lookup through
/// it allocates nothing and an auditor holding the postings and the history re-derives every invoice
/// by hand.
#[derive(Clone, Copy, Debug)]
pub struct HistoryView<'a> {
    entries: &'a [CardEntry],
    at: Option<HistorySeq>,
}

impl HistoryView<'_> {
    /// Resolve counts served by one exact entry, then apply deliberate later amendments at their

    pub fn card_for_entry_era(&self, id: EntryId, wall_at: u64) -> Option<(HistorySeq, &RateCard)> {
        let original = self.entries.iter().find(|entry| entry.id() == id)?;
        Some(self.card_after_amendments(original, wall_at))
    }

    /// Resolve a historical timestamp era. Zero retains its undated wall lookup; a nonzero era

    pub fn card_for_config_era(&self, era: u64, wall_at: u64) -> Option<(HistorySeq, &RateCard)> {
        if era == 0 {
            return self.card_at(wall_at);
        }
        let mut matching = self
            .entries
            .iter()
            .filter(|entry| entry.effective_from == era);
        let original = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        Some(self.card_after_amendments(original, wall_at))
    }

    /// Resolve raw provenance without losing the distinction between a known opening and legacy

    pub fn card_for_raw_era(
        &self,
        era: RawRateEra,
        wall_at: u64,
    ) -> Option<(HistorySeq, &RateCard)> {
        match era.entry_id {
            Some(id) => {
                let original = self.entries.iter().find(|entry| entry.id() == id)?;
                if original.effective_from != era.effective_from {
                    return None;
                }
                Some(self.card_after_amendments(original, wall_at))
            }
            None => self.card_for_config_era(era.effective_from, wall_at),
        }
    }

    fn card_after_amendments<'v>(
        &'v self,
        original: &'v CardEntry,
        wall_at: u64,
    ) -> (HistorySeq, &'v RateCard) {
        let entry = self
            .entries
            .iter()
            .rev()
            .find(|entry| {
                entry.seq > original.seq
                    && matches!(entry.author, Author::Amend { .. })
                    && entry.prices(wall_at)
            })
            .unwrap_or(original);
        (entry.seq, &entry.card)
    }

    /// **THE RESOLUTION RULE.** Among the entries this snapshot can see whose interval covers `t`,

    pub fn card_at(&self, t: u64) -> Option<(HistorySeq, &RateCard)> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.prices(t))
            .map(|e| (e.seq, &e.card))
    }

    /// The entry this view resolved to at `t`, whole.
    pub fn entry_at(&self, t: u64) -> Option<&CardEntry> {
        self.entries.iter().rev().find(|e| e.prices(t))
    }

    /// **THE ONE ENTRY THAT PRICES EVERY INSTANT OF `[from, until)`** (`until` `None` is open-ended),

    pub fn sole_entry_over(&self, from: u64, until: Option<u64>) -> Option<&CardEntry> {
        let base = self.entry_at(from)?;
        let base_reaches_end = match (base.effective_until, until) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(ends), Some(until)) => until <= ends,
        };

        let outranked = self.entries.iter().any(|e| {
            !e.voided
                && e.seq > base.seq
                && e.effective_until.is_none_or(|ends| from < ends)
                && until.is_none_or(|until| e.effective_from < until)
        });
        (base_reaches_end && !outranked).then_some(base)
    }

    /// **THE BOUNDARY OF A CORRECTION THAT WOULD CUT INSIDE A ROW** (OWNER ruling #32, 2026-09-29),

    pub fn correction_cut(
        &self,
        from: u64,
        until: Option<u64>,
        _stored_before: u64,
        bucket_ms: u64,
    ) -> Option<u64> {
        let cuts = |boundary: u64| !boundary.is_multiple_of(bucket_ms.max(1));
        if cuts(from) {
            return Some(from);
        }
        let until = until?;
        cuts(until).then_some(until)
    }

    /// The snapshot this view is: the seq it was taken at, or `None` for the current view of a

    pub fn seq(&self) -> Option<HistorySeq> {
        self.at
    }

    /// The entries the snapshot can see.
    pub fn entries(&self) -> &[CardEntry] {
        self.entries
    }

    /// Whether the snapshot can see nothing at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
