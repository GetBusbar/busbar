// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated rate-card history: what things cost, and since when.

use crate::cost::rate::RateCard;

/// A local dense position; ordered peer insertion can move it. Identity is [`EntryKey`].
///
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
        hex::encode(self.0)
    }

    /// The key from its 40-character hex spelling.
    pub fn parse_hex(text: &str) -> Option<Self> {
        unhex(text).map(EntryKey)
    }
}

impl std::fmt::Display for EntryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut spelled = [0u8; 2 * ENTRY_KEY_LEN];
        f.write_str(hex_into(&self.0, &mut spelled))
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

    #[cfg(test)]
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
        hex::encode(self.0)
    }

    /// The id from its 24-character hex spelling.
    pub fn parse_hex(text: &str) -> Option<Self> {
        unhex(text).map(EntryId)
    }

    #[cfg(test)]
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
        let mut spelled = [0u8; 2 * ENTRY_ID_LEN];
        f.write_str(hex_into(&self.0, &mut spelled))
    }
}

/// `bytes` as lowercase hex, spelled into `out` (exactly twice their length) and borrowed back.
fn hex_into<'o>(bytes: &[u8], out: &'o mut [u8]) -> &'o str {
    if hex::encode_to_slice(bytes, out).is_err() {
        return "";
    }
    std::str::from_utf8(out).unwrap_or_default()
}

/// The `N` bytes spelled by exactly `2 * N` hex digits, or `None`.
fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
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
    /// This entry's current local position, not its fleet identity.
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
#[derive(Clone, Default)]
pub struct History {
    entries: Vec<CardEntry>,
    index: Index,
}

impl std::fmt::Debug for History {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("History")
            .field("entries", &self.entries)
            .finish()
    }
}

/// The history's lookups by an entry's id and by its `effective_from`, kept up to date by the two
/// mutators, so a lookup is one hash rather than a walk of the entries (and a SHA-256 of each
/// entry's key along the way). Entries themselves are found by key with a binary search: they are
/// held in key order.
#[derive(Clone, Default)]
struct Index {
    /// Every entry's id, to the lowest key carrying it.
    ids: foldhash::HashMap<EntryId, EntryKey>,
    /// Every entry's key by its `effective_from`, in key order.
    eras: foldhash::HashMap<u64, Vec<EntryKey>>,
}

impl Index {
    fn add(&mut self, key: EntryKey, effective_from: u64) {
        self.ids
            .entry(key.id())
            .and_modify(|lowest| *lowest = (*lowest).min(key))
            .or_insert(key);
        let keys = self.eras.entry(effective_from).or_default();
        if let Err(at) = keys.binary_search(&key) {
            keys.insert(at, key);
        }
    }
}

/// The entry keyed `key` in `entries` (held in key order), voided or not.
fn by_key<'e>(entries: &'e [CardEntry], key: &EntryKey) -> Option<&'e CardEntry> {
    entries
        .binary_search_by(|e| e.key.cmp(key))
        .ok()
        .map(|at| &entries[at])
}

impl History {
    /// An empty history. Nothing is priceable against it — every instant is a hole — which is the
    pub fn new() -> Self {
        History {
            entries: Vec::new(),
            index: Index::default(),
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

    /// The highest entry key, or `None` for an empty history.
    pub fn head_key(&self) -> Option<EntryKey> {
        self.entries.last().map(CardEntry::key)
    }

    /// Every entry, in key order.
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

    /// The history through this entry key, including later arrivals below the same boundary.
    pub fn snapshot(&self, at: EntryKey) -> HistoryView<'_> {
        let count = self.entries.partition_point(|e| e.key <= at);
        HistoryView {
            entries: &self.entries[..count],
            at: Some(at),
            index: &self.index,
        }
    }

    /// The whole history as it stands. Equivalent to snapshotting at the head, and naming no
    pub fn current(&self) -> HistoryView<'_> {
        HistoryView {
            entries: &self.entries,
            at: self.head_key(),
            index: &self.index,
        }
    }

    /// **THE ONLY MUTATOR.** Append an entry and return its number.
    pub fn append(&mut self, draft: CardEntryDraft) -> HistorySeq {
        let seq = HistorySeq(self.entries.len() as u64);

        let t_ms = self.entries.last().map_or(draft.appended_at, |head| {
            draft.appended_at.max(head.key.t_ms().saturating_add(1))
        });
        let key = EntryKey::new(t_ms, [0; 8], seq.0 as u32);
        self.index.add(key, draft.effective_from);
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
                self.index.add(key, draft.effective_from);
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
        match self.entries.binary_search_by(|e| e.key.cmp(key)) {
            Ok(at) => {
                self.entries[at].voided = true;
                true
            }
            Err(_) => false,
        }
    }

    /// The entry whose key is `key`, voided or not.
    pub fn entry(&self, key: &EntryKey) -> Option<&CardEntry> {
        by_key(&self.entries, key)
    }

    /// **THE ANSWER AT `instant`** (seam for the poster): the id and card of the highest-keyed live
    pub fn entry_at(&self, instant: u64) -> Option<(EntryId, &RateCard)> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.prices(instant))
            .map(|entry| (entry.id(), &entry.card))
    }

    #[cfg(test)]
    /// The card of the entry whose id is `id`, voided or not: a count posted under an entry keeps
    pub fn card_of(&self, id: &EntryId) -> Option<&RateCard> {
        let key = self.index.ids.get(id)?;
        self.entry(key).map(|entry| &entry.card)
    }
}

/// A borrowed history prefix ending at an entry-key boundary.
///
/// A view is a borrowed slice and a number. It reads no clock and owns nothing, so a lookup through
/// it allocates nothing and an auditor holding the postings and the history re-derives every invoice
/// by hand.
#[derive(Clone, Copy)]
pub struct HistoryView<'a> {
    entries: &'a [CardEntry],
    at: Option<EntryKey>,
    index: &'a Index,
}

impl std::fmt::Debug for HistoryView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryView")
            .field("entries", &self.entries)
            .field("at", &self.at)
            .finish()
    }
}

impl HistoryView<'_> {
    /// The entry this view can see whose id is `id`, voided or not: one hash and one binary search.
    fn by_id(&self, id: &EntryId) -> Option<&CardEntry> {
        by_key(self.entries, self.index.ids.get(id)?)
    }

    /// Resolve counts served by one exact entry, then apply deliberate later amendments at their
    pub fn card_for_entry_era(&self, id: EntryId, wall_at: u64) -> Option<(EntryKey, &RateCard)> {
        let original = self.by_id(&id)?;
        Some(self.card_after_amendments(original, wall_at))
    }

    /// Resolve a historical timestamp era. Zero retains its undated wall lookup; a nonzero era
    pub fn card_for_config_era(&self, era: u64, wall_at: u64) -> Option<(EntryKey, &RateCard)> {
        if era == 0 {
            return self.card_at(wall_at);
        }
        let mut matching = self
            .index
            .eras
            .get(&era)?
            .iter()
            .map_while(|key| by_key(self.entries, key));
        let original = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        Some(self.card_after_amendments(original, wall_at))
    }

    /// Resolve raw provenance without losing the distinction between a known opening and legacy
    pub fn card_for_raw_era(&self, era: RawRateEra, wall_at: u64) -> Option<(EntryKey, &RateCard)> {
        match era.entry_id {
            Some(id) => {
                let original = self.by_id(&id)?;
                if original.effective_from != era.effective_from {
                    return None;
                }
                Some(self.card_after_amendments(original, wall_at))
            }
            None => self.card_for_config_era(era.effective_from, wall_at),
        }
    }

    /// The entry this view holds under `key`, voided or not: the entry a sealed record names.
    pub fn entry_keyed(&self, key: &EntryKey) -> Option<&CardEntry> {
        by_key(self.entries, key)
    }
}

/// **THE ONE PRICING RULE `/usage` AND `/records` SHARE** (ADMIN-API-1.6 §3.2): the card that
/// prices counts accrued under the entry `entry_id` (effective from `effective_from`) at the
/// instant `wall_at`. The original entry is found by id, voided or not, and any later amendment
/// that prices `wall_at` is applied, so a back-dated amendment, or its void, moves both reads
/// together. `entry_id` `None` is a legacy era without an entry identity.
pub fn price_era<'v>(
    view: &'v HistoryView<'_>,
    entry_id: Option<EntryId>,
    effective_from: u64,
    wall_at: u64,
) -> Option<(EntryKey, &'v RateCard)> {
    let era = match entry_id {
        Some(id) => RawRateEra::entry(effective_from, id),
        None => RawRateEra::legacy(effective_from),
    };
    view.card_for_raw_era(era, wall_at)
}

impl HistoryView<'_> {
    fn card_after_amendments<'v>(
        &'v self,
        original: &'v CardEntry,
        wall_at: u64,
    ) -> (EntryKey, &'v RateCard) {
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
        (entry.key, &entry.card)
    }

    /// **THE RESOLUTION RULE.** Among the entries this snapshot can see whose interval covers `t`,
    pub fn card_at(&self, t: u64) -> Option<(EntryKey, &RateCard)> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.prices(t))
            .map(|e| (e.key, &e.card))
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

        // Only an entry written after the base can outrank it: those are the entries above it in key
        // order, typically none at all.
        let above = self
            .entries
            .binary_search_by(|e| e.key.cmp(&base.key))
            .map_or(self.entries.len(), |at| at + 1);
        let later = &self.entries[above..];
        let outranked = later.iter().any(|e| {
            !e.voided
                && e.seq > base.seq
                && e.effective_until.is_none_or(|ends| from < ends)
                && until.is_none_or(|until| e.effective_from < until)
        });
        (base_reaches_end && !outranked).then_some(base)
    }

    /// The boundary of a correction that would cut inside a row.
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

    /// The entry-key boundary of this view, or `None` for an empty current history.
    pub fn seq(&self) -> Option<EntryKey> {
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
