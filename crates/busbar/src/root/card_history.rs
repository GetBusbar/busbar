// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FLEET-SHARED RATE-CARD HISTORY, as this node holds it (MONEY-DESIGN section 3a; owner
//! rulings 2026-10-25 and 2026-10-26: money is ledger counts x rate card, the store keeps only
//! counts and the card with its history, and the configuration is the source of the card, as in
//! 1.5.5).
//!
//! [`CardStore`] reads the history from the store (`busbar.card.v2`, [`super::card_store`]) and
//! resolves it: the highest-keyed LIVE entry covering an instant prices it.
//!
//! - **The opening entry** is written at boot only when the history is empty: the node's card from
//!   instant zero. The fleet's lowest key wins. Each node still prices its own counts with its
//!   confirmed own opening until it adopts or appends another card.
//! - **Every change of the card a configuration resolves** (boot, reload, apply, settings, plugin
//!   reload or rollback, overlay and named-map writes) appends a WHOLE-card entry, effective from
//!   its authorized activation, recording who or what changed it ([`CardStore::prepare`]).
//!   Store refusal or uncertainty retains the old effective card and the exact candidate.
//! - **This node prices with its OWN entry** ([`CardStore::own`]): the one it appended or adopted.
//!   A rescan records other nodes' entries and never moves it, so two nodes running different
//!   cards each price their own counts with their own card; a time-based read takes the later
//!   change on any node.
//! - **Store-owned custody:** chunks and a validated immutable intent precede the canonical
//!   candidate commit. Own-card entries also require an authorized activation intent and commit;
//!   saved candidates alone never appear in active history. Pending writes retain the exact
//!   original, identity and per-record progress; a complete Store intent survives host restart.
//!   No host file or data-directory setting participates. A Store outage before intent completion
//!   leaves RAM-only pending ownership, and memory Store is explicitly ephemeral.
//! - **There is no WITHDRAW.** An entry that landed stays. [`CardStore::void`] keeps an entry
//!   known but out of force; no operator verb reaches it, because a later change already keys
//!   above a far-future entry and prices from its own start.
//! - **Clock skew** never delays a change: an entry is effective from the writer's own now, whatever
//!   its key; a head more than [`super::card_store::SKEW_MS`] ahead alarms.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use busbar_contract::store_calls::StoreCalls;
use busbar_kernel::config::card::CardFields;
use busbar_kernel_ledger::cost::{Author, CardEntryDraft, EntryKey, History};

use super::card_store::{
    put_all, put_from, scan, Activation, EntryAuthor, PutOutcome, Scanned, StoredEntry, VoidRecord,
    IN_LOCK_BOUND, SKEW_MS,
};

/// How often a node rescans the history for other nodes' entries.
pub const RESCAN_INTERVAL: Duration = Duration::from_secs(5);

/// How long the boot waits on the store for each read or write before it refuses.
const BOOT_DEADLINE: Duration = Duration::from_secs(30);

/// The alarm counter every history alarm increments.
pub const CARD_ALARMS_TOTAL: &str = "busbar_card_history_alarms_total";

fn now_ms() -> u64 {
    busbar_kernel::store::now_ms()
}

/// The digest of a card, hex.
#[must_use]
pub fn digest_hex(card: &CardFields) -> String {
    hex::encode(card.digest())
}

/// The card one entry prices with, built through the same constructors a live apply builds it.
#[must_use]
pub fn rate_card_of(card: &CardFields) -> busbar_kernel_ledger::cost::RateCard {
    let rates = card.rates();
    crate::root::kernel::register_classes(&rates.raw());
    crate::root::kernel::card_from_raw(&rates.raw())
}

/// The node's history in the store.
pub struct CardStore {
    calls: Arc<dyn StoreCalls>,
    node: u64,
    rand: [u8; 8],
    counter: AtomicU32,
    state: Mutex<State>,
    published: arc_swap::ArcSwapOption<History>,
    /// The history as THIS NODE prices with it: the fleet history, with every other node's
    /// change keyed above this node's own entry left known but out of force, so this node's own
    /// entry prices its instants from its start ([`Self::node_history`]).
    node_published: arc_swap::ArcSwapOption<History>,
    loaded: AtomicBool,
    rescanning: AtomicBool,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<EntryKey, StoredEntry>,
    voids: Vec<VoidRecord>,
    /// Immutable candidates awaiting custody confirmation or their generation's publication.
    pending: Vec<(EntryKey, PendingWrite)>,
    reputting: bool,
    /// A logical preparation owner, never a host lock held across Store calls.
    preparing: bool,
    alarmed: BTreeSet<String>,
    /// The entry this node prices with: the one it appended or adopted.
    own: Option<EntryKey>,
    activations: BTreeMap<EntryKey, Activation>,
}

#[derive(Clone)]
struct PendingWrite {
    /// Always retain the original, even if encoding failed before any Store call.
    entry: Arc<StoredEntry>,
    own: bool,
    records: Option<Arc<super::card_store::Records>>,
    progress: Arc<AtomicUsize>,
    confirmed: Arc<AtomicBool>,
    activation: Arc<Mutex<Option<Activation>>>,
    activation_confirmed: Arc<AtomicBool>,
    activation_required: bool,
    retiring: Arc<AtomicBool>,
}

impl PendingWrite {
    /// Serialize one immutable candidate outside every history lock.
    fn prepare(entry: StoredEntry, own: bool) -> Self {
        let records = entry.records_for(own).ok().map(Arc::new);
        Self {
            entry: Arc::new(entry),
            own,
            records,
            progress: Arc::new(AtomicUsize::new(0)),
            confirmed: Arc::new(AtomicBool::new(false)),
            activation: Arc::new(Mutex::new(None)),
            activation_confirmed: Arc::new(AtomicBool::new(false)),
            activation_required: own,
            retiring: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// A confirmed card reserved for one generation commit. Dropping it releases only the
/// preparation lease; the immutable pending candidate remains held for an exact retry.
pub struct PreparedCard {
    book: Arc<CardStore>,
    key: Option<EntryKey>,
    owns_lease: bool,
}

impl PreparedCard {
    /// Confirm activation only under the generation transaction's explicit authority.
    /// Background custody retries never call this operation.
    pub fn confirm_activation(self) -> Result<ConfirmedCard, String> {
        let key = self.key.expect("a prepared card has a key");
        let pending = {
            let state = self.book.lock();
            state
                .pending
                .iter()
                .find(|(held, _)| *held == key)
                .map(|(_, pending)| pending.clone())
        };
        if let Some(pending) = pending.filter(|pending| pending.activation_required) {
            if pending.retiring.load(Ordering::Acquire) {
                return Err(format!(
                    "retirement of rate-card entry {key} requires explicit reload recovery"
                ));
            }
            let activation = {
                let mut held = pending.activation.lock().unwrap_or_else(|p| p.into_inner());
                held.get_or_insert_with(|| Activation {
                    effective_from: if is_opening(&pending.entry) {
                        0
                    } else {
                        now_ms()
                    },
                })
                .clone()
            };
            if !pending.activation_confirmed.load(Ordering::Acquire) {
                let records = activation.records(&pending.entry)?;
                if put_all(
                    self.book.calls.as_ref(),
                    &records,
                    Some(Instant::now() + IN_LOCK_BOUND),
                    false,
                ) != PutOutcome::Ready
                {
                    return Err(format!("the Store has not confirmed activation of rate-card entry {key}; the previous prices remain active"));
                }
                pending.activation_confirmed.store(true, Ordering::Release);
            }
        }
        Ok(ConfirmedCard { prepared: self })
    }
}

/// An activation confirmed by the Store, ready for Store-free publication with its App.
pub struct ConfirmedCard {
    prepared: PreparedCard,
}

impl ConfirmedCard {
    /// Activate this exact confirmed candidate without calling the Store.
    pub fn commit(mut self) -> EntryKey {
        let key = self
            .prepared
            .key
            .take()
            .expect("a confirmed card has a key");
        {
            let mut state = self.prepared.book.lock();
            let confirmed: Vec<_> = state
                .pending
                .iter()
                .filter(|(held, pending)| {
                    *held <= key
                        && pending.own
                        && pending.entry.writer == self.prepared.book.node
                        && pending.confirmed.load(Ordering::Acquire)
                        && (!pending.activation_required
                            || pending.activation_confirmed.load(Ordering::Acquire))
                })
                .cloned()
                .collect();
            for (confirmed_key, pending) in confirmed {
                assert!(pending.confirmed.load(Ordering::Acquire));
                if pending.activation_required {
                    assert!(pending.activation_confirmed.load(Ordering::Acquire));
                    let activation = pending
                        .activation
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone()
                        .expect("a confirmed activation is retained");
                    state.activations.insert(confirmed_key, activation);
                }
                state
                    .entries
                    .insert(confirmed_key, (*pending.entry).clone());
                state.pending.retain(|(held, _)| *held != confirmed_key);
            }
            state.own = Some(key);
            self.prepared.book.publish(&state);
        }
        key
    }
}

impl Drop for PreparedCard {
    fn drop(&mut self) {
        if self.owns_lease {
            self.book.lock().preparing = false;
        }
    }
}

struct Reputting {
    book: Weak<CardStore>,
    armed: bool,
}

impl Reputting {
    fn finish(&mut self, state: &mut State) {
        state.reputting = false;
        self.armed = false;
    }
}

impl Drop for Reputting {
    fn drop(&mut self) {
        if self.armed {
            if let Some(book) = self.book.upgrade() {
                book.lock().reputting = false;
            }
        }
    }
}

impl std::fmt::Debug for CardStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardStore")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

/// Whether `entry` is an opening entry (written at boot, or a chain's opening copied by the
/// migration).
fn is_opening(entry: &StoredEntry) -> bool {
    matches!(
        entry.author,
        EntryAuthor::Opening { .. } | EntryAuthor::Migrated { opening: true, .. }
    )
}

impl CardStore {
    /// A history kept entirely in `calls`' Store by node `node`.
    #[must_use]
    pub fn new(calls: Arc<dyn StoreCalls>, node: u64) -> Arc<Self> {
        Arc::new(CardStore {
            calls,
            node,
            rand: super::card_store::boot_rand(),
            counter: AtomicU32::new(0),
            state: Mutex::new(State::default()),
            published: arc_swap::ArcSwapOption::empty(),
            node_published: arc_swap::ArcSwapOption::empty(),
            loaded: AtomicBool::new(false),
            rescanning: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether the boot has loaded the history.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }

    /// The FLEET history, resolved by time: the latest change on any node prices an instant. The
    /// read every view and budget derivation takes (MONEY-DESIGN section 3a, item 17).
    #[must_use]
    pub fn history(&self) -> Option<Arc<History>> {
        self.published.load_full()
    }

    /// **THE HISTORY THIS NODE PRICES WITH**: the fleet history, with every OTHER node's change
    /// keyed above this node's own entry left known (its id still finds its card) but out of
    /// force, so this node's own card prices every instant from its own entry's start, whatever
    /// another node loaded since. What [`crate::root::kernel::RootHistory::pin`] hands a unit.
    #[must_use]
    pub fn node_history(&self) -> Option<Arc<History>> {
        self.node_published.load_full()
    }

    /// This node's durable id.
    #[must_use]
    pub fn node(&self) -> u64 {
        self.node
    }

    /// The store the history is kept in.
    #[must_use]
    pub fn calls(&self) -> &Arc<dyn StoreCalls> {
        &self.calls
    }

    /// Every entry this node holds, in key order.
    #[must_use]
    pub fn entries(&self) -> Vec<StoredEntry> {
        self.lock().entries.values().cloned().collect()
    }

    /// One immutable original by key, for a caller preparing a correction over a pinned snapshot.
    pub(crate) fn entry(&self, key: &EntryKey) -> Option<StoredEntry> {
        self.lock().entries.get(key).cloned()
    }

    /// Every alarm this node has raised over the history, in the order raised (each once).
    #[must_use]
    pub fn alarms(&self) -> Vec<String> {
        self.lock().alarmed.iter().cloned().collect()
    }

    /// The key of the oldest entry pending confirmation on this node, if any.
    #[must_use]
    pub fn pending(&self) -> Option<EntryKey> {
        self.lock()
            .pending
            .iter()
            .find(|(_, pending)| pending.entry.writer == self.node)
            .map(|(key, _)| *key)
    }

    /// **THE ENTRY THIS NODE PRICES WITH**: its key (whose id a count carries) and its card. Set by
    /// every [`Self::apply`]; a rescan never moves it.
    #[must_use]
    pub fn own(&self) -> Option<(EntryKey, CardFields)> {
        let state = self.lock();
        let key = state.own?;
        state.entries.get(&key).map(|e| (key, e.card.clone()))
    }

    /// Rebuild the resolved histories from what this node holds, and publish them: the fleet's,
    /// and this node's own ([`Self::node_history`]).
    fn publish(&self, state: &State) {
        let fleet = Self::resolve_activated(&state.entries, &state.voids, &state.activations);
        let own_opening = state
            .own
            .and_then(|key| state.entries.get(&key))
            .filter(|entry| is_opening(entry))
            .map(|entry| entry.key);
        let mut node = if own_opening.is_some() {
            Self::resolve_with_opening(
                &state.entries,
                &state.voids,
                &state.activations,
                own_opening,
            )
        } else {
            fleet.clone()
        };
        if let Some(own) = state.own {
            for entry in state.entries.range(own..).skip(1).map(|(_, e)| e) {
                if entry.writer != self.node && matches!(entry.author, EntryAuthor::Change) {
                    node.void(&entry.key);
                }
            }
        }
        self.published.store(Some(Arc::new(fleet)));
        self.node_published.store(Some(Arc::new(node)));
    }

    /// The opening entry that won: the lowest-keyed one.
    fn opening(entries: &BTreeMap<EntryKey, StoredEntry>) -> Option<&StoredEntry> {
        entries.values().find(|e| is_opening(e))
    }

    /// **THE FLEET HISTORY**, resolved: every entry by key, an opening that lost its race and every
    /// voided entry KNOWN (its card still answers its id) but never in force in the fleet view.
    #[must_use]
    pub fn resolve(entries: &BTreeMap<EntryKey, StoredEntry>, voids: &[VoidRecord]) -> History {
        Self::resolve_activated(entries, voids, &BTreeMap::new())
    }

    fn resolve_activated(
        entries: &BTreeMap<EntryKey, StoredEntry>,
        voids: &[VoidRecord],
        activations: &BTreeMap<EntryKey, Activation>,
    ) -> History {
        Self::resolve_with_opening(entries, voids, activations, None)
    }

    fn resolve_with_opening(
        entries: &BTreeMap<EntryKey, StoredEntry>,
        voids: &[VoidRecord],
        activations: &BTreeMap<EntryKey, Activation>,
        own_opening: Option<EntryKey>,
    ) -> History {
        let winner = own_opening.or_else(|| Self::opening(entries).map(|e| e.key));
        let mut history = History::new();
        let mut lost = Vec::new();
        for entry in entries.values() {
            let author = match &entry.author {
                EntryAuthor::Opening { .. } | EntryAuthor::Migrated { opening: true, .. } => {
                    Author::Opening
                }
                EntryAuthor::Amend { reason }
                | EntryAuthor::Migrated {
                    reason: Some(reason),
                    ..
                } => Author::Amend {
                    reason_hash: hex::decode(reason)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                        .unwrap_or([0; 32]),
                },
                EntryAuthor::Change | EntryAuthor::Migrated { .. } => {
                    Author::Config { policy_epoch: 0 }
                }
            };
            history.insert(
                entry.key,
                CardEntryDraft {
                    effective_from: activations
                        .get(&entry.key)
                        .map_or(entry.effective_from, |activation| activation.effective_from),
                    effective_until: entry.effective_until,
                    card: rate_card_of(&entry.card),
                    appended_at: entry.appended_at,
                    author,
                },
            );
            if is_opening(entry) && Some(entry.key) != winner {
                lost.push(entry.key);
            }
        }
        for key in lost {
            history.void(&key);
        }
        for void in voids {
            if let Some(key) = EntryKey::parse_hex(&void.voided) {
                history.void(&key);
            }
        }
        history
    }

    /// The entry in force at `t`: the highest-keyed live entry covering it.
    fn in_force_at(state: &State, t: u64) -> Option<StoredEntry> {
        let history = Self::resolve_activated(&state.entries, &state.voids, &state.activations);
        let key = history.current().entry_at(t)?.key();
        state.entries.get(&key).cloned()
    }

    /// The card in force now, if the history holds one.
    #[must_use]
    pub fn in_force(&self) -> Option<CardFields> {
        if !self.is_loaded() {
            return None;
        }
        let history = self.history()?;
        let key = history.current().entry_at(now_ms())?.key();
        self.lock().entries.get(&key).map(|e| e.card.clone())
    }

    /// A retained candidate awaiting confirmation or generation commit. The previous confirmed
    /// card remains active while this is reported.
    #[must_use]
    pub fn pending_refusal(&self) -> Option<String> {
        self.pending().map(|key| {
            format!(
                "rate-card entry {key} is pending Store confirmation or generation commit; the \
                 previous confirmed prices remain active"
            )
        })
    }

    /// Raise an alarm once per distinct message: an error line and the alarm counter.
    fn alarm(&self, state: &mut State, message: String) {
        if state.alarmed.insert(message.clone()) {
            tracing::error!(alarm = "card_history", "{message}");
            metrics::counter!(CARD_ALARMS_TOTAL).increment(1);
        }
    }

    /// The readers' alarms over what this node holds: far-future entries, nodes running different
    /// cards (two changes extending one head; time-based reads take the later), and entries
    /// extending a voided one.
    fn check_alarms(&self, state: &mut State) {
        let now = now_ms();
        let voided: BTreeSet<String> = state.voids.iter().map(|v| v.voided.clone()).collect();
        let mut messages = Vec::new();
        // THIS NODE'S CARD IS NOT THE FLEET'S: its configuration loaded another card than the one
        // a time-based read now takes.
        if let (Some(own), Some(in_force)) = (
            state.own.and_then(|k| state.entries.get(&k)),
            Self::in_force_at(state, now),
        ) {
            if own.key != in_force.key && own.card != in_force.card {
                messages.push(format!(
                    "this node prices with rate card entry {} ({}) and the fleet's card in force is \
                     entry {} (node {}, {}); they differ in [{}]. Make the nodes' configuration \
                     agree",
                    own.key,
                    own.actor,
                    in_force.key,
                    in_force.writer,
                    in_force.actor,
                    own.card.differing_fields(&in_force.card).join(", ")
                ));
            }
        }
        for entry in state.entries.values() {
            let effective_from = state
                .activations
                .get(&entry.key)
                .map_or(entry.effective_from, |activation| activation.effective_from);
            if effective_from > now.saturating_add(SKEW_MS) && !voided.contains(&entry.key.hex()) {
                messages.push(format!(
                    "rate card entry {} written by node {} starts {} ms ahead of this node's \
                     clock; it prices only instants from its own start, and any later change on \
                     any node keys above it and takes precedence",
                    entry.key,
                    entry.writer,
                    effective_from - now,
                ));
            }
            if let Some(base) = entry.base {
                if voided.contains(&base.hex()) {
                    messages.push(format!(
                        "rate card entry {} (node {}) extends the voided entry {base}: it still \
                         carries that entry's fields; correct the configuration and reload",
                        entry.key, entry.writer
                    ));
                }
            }
        }
        let puts: Vec<&StoredEntry> = state
            .entries
            .values()
            .filter(|e| matches!(e.author, EntryAuthor::Change) && !voided.contains(&e.key.hex()))
            .collect();
        for (i, lower) in puts.iter().enumerate() {
            for higher in &puts[i + 1..] {
                if lower.base.is_some() && lower.base == higher.base {
                    let differ: Vec<String> = lower.card.differing_fields(&higher.card);
                    messages.push(format!(
                        "nodes run different rate cards: entries {} (node {}, {}) and {} (node \
                         {}, {}) both extend {}; each node prices its own counts with its own \
                         card, and a time-based read takes the later ({}), whose card differs in \
                         [{}]. Make the nodes' configuration agree",
                        lower.key,
                        lower.writer,
                        lower.actor,
                        higher.key,
                        higher.writer,
                        higher.actor,
                        lower.base.map(|b| b.hex()).unwrap_or_default(),
                        higher.key,
                        differ.join(", "),
                    ));
                }
            }
        }
        for m in messages {
            self.alarm(state, m);
        }
    }

    /// Merge a scan into what this node holds, and publish. Answers whether anything changed.
    fn merge(&self, scanned: Scanned) -> Result<bool, String> {
        let mut state = self.lock();
        // Check the entire immutable union before installing any part of this snapshot.
        for entry in scanned
            .entries
            .iter()
            .chain(scanned.intents.iter().map(|i| &i.entry))
        {
            if state
                .entries
                .get(&entry.key)
                .is_some_and(|held| held != entry)
                || state
                    .pending
                    .iter()
                    .any(|(key, held)| *key == entry.key && held.entry.as_ref() != entry)
            {
                return Err(format!(
                    "conflicting immutable rate-card entry {}",
                    entry.key
                ));
            }
        }
        for intent in &scanned.intents {
            if state.pending.iter().any(|(key, held)| {
                *key == intent.entry.key
                    && (held.own != intent.own
                        || held.activation_required != intent.activation_required
                        || held
                            .records
                            .as_ref()
                            .is_some_and(|r| **r != *intent.records))
            }) {
                return Err(format!(
                    "conflicting immutable rate-card intent {}",
                    intent.entry.key
                ));
            }
        }
        for (key, activation) in &scanned.activations {
            if state
                .activations
                .get(key)
                .is_some_and(|held| held != activation)
                || state.pending.iter().any(|(held, pending)| {
                    held == key
                        && pending
                            .activation
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .as_ref()
                            .is_some_and(|held| held != activation)
                })
            {
                return Err(format!("conflicting immutable rate-card activation {key}"));
            }
        }
        let mut changed = false;
        for (key, activation) in scanned.activations {
            if !state.pending.iter().any(|(held, pending)| {
                *held == key && pending.own && pending.entry.writer == self.node
            }) {
                state.activations.insert(key, activation);
            }
        }
        for entry in scanned.entries {
            // A local prepared candidate is confirmed in the Store but belongs to a generation
            // that has not committed yet. Neither a rescan nor a lost-ack read may activate it.
            if state
                .pending
                .iter()
                .any(|(key, pending)| *key == entry.key && pending.own && entry.writer == self.node)
            {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(slot) = state.entries.entry(entry.key)
            {
                slot.insert(entry);
                changed = true;
            }
        }
        for void in scanned.voids {
            if !state.voids.iter().any(|v| v.voided == void.voided) {
                state.voids.push(void);
                changed = true;
            }
        }
        for (key, why) in scanned.unreadable {
            let msg = format!("rate card entry {key} does not read: {why}");
            self.alarm(&mut state, msg);
        }
        if changed {
            self.publish(&state);
        }
        self.check_alarms(&mut state);
        Ok(changed)
    }

    fn validate_scan(scanned: &Scanned) -> Result<(), String> {
        if let Some((key, _)) = scanned.unreadable.first() {
            return Err(format!("rate-card Store records for {key} are corrupt or unsupported; no history was published"));
        }
        Ok(())
    }

    /// Rescan the store, and publish what is new.
    ///
    /// # Errors
    ///
    /// The store failed or refused the scan.
    pub fn rescan(&self, deadline: Option<Instant>) -> Result<bool, String> {
        let scanned = scan(self.calls.as_ref(), deadline)?;
        Self::validate_scan(&scanned)?;
        self.merge(scanned)
    }

    /// The next key this node writes: `t_ms = max(now, head + 1)`.
    fn next_key(&self, state: &State) -> EntryKey {
        let head = state
            .entries
            .keys()
            .chain(state.pending.iter().map(|(key, _)| key))
            .map(EntryKey::t_ms)
            .max();
        let t = head.map_or(now_ms(), |h| now_ms().max(h.saturating_add(1)));
        EntryKey::new(t, self.rand, self.counter.fetch_add(1, Ordering::Relaxed))
    }

    /// **THE BOOT.** Validate and recover Store intents, read the history, copy the journal's
    /// card records into it (`migrated`, every chain's), open it with this node's card when it is
    /// still empty, and otherwise apply this node's card ([`Self::apply`]): unchanged, it adopts
    /// the entry in force; changed, it appends one, effective now.
    ///
    /// # Errors
    ///
    /// The store would not read the history back, or would not take the opening entry or a
    /// migrated one.
    pub fn boot(
        self: &Arc<Self>,
        card: &CardFields,
        origin: &str,
        migrated: Vec<StoredEntry>,
    ) -> Result<(), String> {
        let deadline = || Some(Instant::now() + BOOT_DEADLINE);
        // Validate the entire Store snapshot before any recovery put or publication. Intent
        // metadata never implies canonical confirmation, even when the intent's own ack was lost.
        let scanned = scan(self.calls.as_ref(), deadline())?;
        Self::validate_scan(&scanned)?;
        let intents = scanned.intents.clone();
        self.merge(scanned)?;
        for intent in intents {
            if intent.retired {
                continue;
            }
            let key = intent.entry.key;
            let pending = PendingWrite {
                entry: Arc::new(intent.entry.clone()),
                own: intent.own,
                records: Some(intent.records.clone()),
                progress: Arc::new(AtomicUsize::new(intent.records.len() - 1)),
                confirmed: Arc::new(AtomicBool::new(intent.committed)),
                activation: Arc::new(Mutex::new(intent.activation.clone())),
                activation_confirmed: Arc::new(AtomicBool::new(intent.activation_confirmed)),
                activation_required: intent.activation_required,
                retiring: Arc::new(AtomicBool::new(intent.retiring)),
            };
            if !intent.committed || (intent.activation_required && !intent.activation_confirmed) {
                let pending = {
                    let mut state = self.lock();
                    match state.pending.iter().find(|(held, _)| *held == key) {
                        Some((_, held)) => held.clone(),
                        None => {
                            state.pending.push((key, pending.clone()));
                            pending
                        }
                    }
                };
                let confirmed = intent.committed
                    || put_from(
                        self.calls.as_ref(),
                        &intent.records,
                        &pending.progress,
                        deadline(),
                        false,
                    ) == PutOutcome::Ready;
                pending.confirmed.store(confirmed, Ordering::Release);
                // The shared Store also contains peer intents. An unconfirmed peer operation
                // cannot select this node's prices or make its admissions pending.
                if confirmed && !intent.activation_required {
                    self.lock().pending.retain(|(held, _)| *held != key);
                    self.lock().entries.insert(key, intent.entry.clone());
                }
            }
            // Another node's intent is safe to retry but cannot select this node's own card.
            // An amendment's explicit own=false survives restart even if its card equals config.
            if intent.committed
                && (!intent.activation_required || intent.activation_confirmed)
                && intent.own
                && intent.entry.writer == self.node
            {
                let mut state = self.lock();
                if state.entries.contains_key(&key) {
                    state.own = Some(key);
                }
            }
        }
        let unconfirmed = {
            let state = self.lock();
            state.pending.iter().find_map(|(key, pending)| {
                (pending.own
                    && pending.entry.writer == self.node
                    && !pending.confirmed.load(Ordering::Acquire))
                .then_some(*key)
            })
        };
        if let Some(key) = unconfirmed {
            self.spawn_reput();
            return Err(format!("the Store has not confirmed recovered rate-card entry {key}; boot cannot activate its prices"));
        }
        // THE MIGRATION, before the opening rule: every chain's card records, under time keys, an
        // idempotent union (a key the store holds is not written again).
        let held: BTreeSet<EntryKey> = self.lock().entries.keys().copied().collect();
        for entry in migrated.into_iter().filter(|e| !held.contains(&e.key)) {
            match put_all(self.calls.as_ref(), &entry.records()?, deadline(), true) {
                PutOutcome::Ready => {}
                PutOutcome::Refused(why) | PutOutcome::Doubtful(why) => {
                    return Err(format!(
                        "the store would not take the rate card entry {} migrated from node \
                         journals: {why}",
                        entry.key
                    ))
                }
            }
            self.lock().entries.insert(entry.key, entry);
        }
        // THE OPENING RULE: an empty history is opened with this node's card, from instant zero.
        let needs_opening = {
            let state = self.lock();
            state.entries.is_empty()
                && !state
                    .pending
                    .iter()
                    .any(|(_, pending)| pending.own && pending.entry.writer == self.node)
        };
        if needs_opening {
            let entry = {
                let state = self.lock();
                StoredEntry {
                    key: self.next_key(&state),
                    effective_from: 0,
                    effective_until: None,
                    appended_at: now_ms(),
                    author: EntryAuthor::Opening {},
                    actor: origin.to_string(),
                    base: None,
                    writer: self.node,
                    set_fields: Vec::new(),
                    card: card.clone(),
                    correction: None,
                }
            };
            let pending = PendingWrite::prepare(entry, true);
            let key = pending.entry.key;
            self.lock().pending.push((key, pending.clone()));
            let records = pending
                .records
                .as_ref()
                .ok_or("opening card encoding failed; original held in RAM")?;
            match put_from(
                self.calls.as_ref(),
                records,
                &pending.progress,
                deadline(),
                true,
            ) {
                PutOutcome::Ready => {
                    pending.confirmed.store(true, Ordering::Release);
                }
                PutOutcome::Refused(_) | PutOutcome::Doubtful(_) => {
                    // A boot failure has not activated prices. Retain the original owner, rather
                    // than replacing an uncertain opening with a fresh identity.
                    self.spawn_reput();
                    return Err(format!(
                        "the Store has not confirmed opening rate-card entry {key}"
                    ));
                }
            }
            // Another node may have opened it at the same time: the lowest key wins.
            let _ = self.rescan(deadline());
        }
        self.loaded.store(true, Ordering::Release);
        match self
            .prepare_recovery(card, origin)
            .and_then(PreparedCard::confirm_activation)
        {
            Ok(confirmed) => {
                confirmed.commit();
            }
            Err(why) => {
                self.loaded.store(false, Ordering::Release);
                return Err(why);
            }
        }
        self.spawn_reput();
        self.spawn_rescan();
        let mut state = self.lock();
        self.check_alarms(&mut state);
        Ok(())
    }

    /// **A CONFIGURATION RESOLVED `card`** (boot, reload, apply, settings, plugin reload or
    /// rollback, overlay and named-map writes; `origin` names which, and who). Equal to this
    /// node's own card: nothing. Equal to the card in force: this node adopts that entry.
    /// Otherwise a WHOLE-card entry is appended, effective now, recording `origin` and the fields
    /// that changed. An unconfirmed write leaves the previous prices active.
    /// Answers the entry this node now prices with, or `None` if preparation failed.
    pub fn apply(self: &Arc<Self>, card: &CardFields, origin: &str) -> Option<EntryKey> {
        let key = self
            .prepare(card, origin)
            .ok()?
            .confirm_activation()
            .ok()
            .map(ConfirmedCard::commit)?;
        let mut state = self.lock();
        self.check_alarms(&mut state);
        Some(key)
    }

    /// Confirm one immutable candidate while retaining the old card until the returned commit.
    /// Concurrent or reentrant preparations refuse without replacing the pending owner.
    pub fn prepare(
        self: &Arc<Self>,
        card: &CardFields,
        origin: &str,
    ) -> Result<PreparedCard, String> {
        self.prepare_with(card, origin, false)
    }

    /// Authoritative reload recovery may retire an inert candidate or reconcile confirmed
    /// activation effects before appending the desired card. Neither is a silent rollback.
    pub fn prepare_recovery(
        self: &Arc<Self>,
        card: &CardFields,
        origin: &str,
    ) -> Result<PreparedCard, String> {
        self.prepare_with(card, origin, true)
    }

    fn prepare_with(
        self: &Arc<Self>,
        card: &CardFields,
        origin: &str,
        recovery: bool,
    ) -> Result<PreparedCard, String> {
        if !self.is_loaded() {
            return Err("the rate-card history is not loaded".into());
        }
        {
            let mut state = self.lock();
            if state.preparing {
                return Err("a rate-card preparation is already in progress".into());
            }
            state.preparing = true;
        }
        let mut prepared = PreparedCard {
            book: self.clone(),
            key: None,
            owns_lease: true,
        };
        let mut superseding = None;
        loop {
            let pending = {
                let state = self.lock();
                state
                    .pending
                    .iter()
                    .rev()
                    .find(|(_, pending)| pending.own && pending.entry.writer == self.node)
                    .map(|(_, pending)| pending.clone())
            };
            let Some(pending) = pending else { break };
            if pending.entry.card == *card && !pending.retiring.load(Ordering::Acquire) {
                break;
            }
            if !recovery {
                return Err(format!("rate-card entry {} remains pending; retry its exact configuration or explicitly reload for recovery", pending.entry.key));
            }
            self.confirm_candidate(&pending)?;
            let attempted = !pending.retiring.load(Ordering::Acquire)
                && pending
                    .activation
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .is_some();
            if !attempted {
                pending.retiring.store(true, Ordering::Release);
                let records = super::card_store::retirement_records(&pending.entry)?;
                if put_all(
                    self.calls.as_ref(),
                    &records,
                    Some(Instant::now() + IN_LOCK_BOUND),
                    false,
                ) != PutOutcome::Ready
                {
                    return Err(format!(
                        "retirement of inactive rate-card entry {} remains pending",
                        pending.entry.key
                    ));
                }
                self.lock()
                    .pending
                    .retain(|(held, _)| *held != pending.entry.key);
                continue;
            }
            // Preserve a Store-confirmed activation even when the desired reload is the old
            // local card. Its successor must be a new confirmed Store fact, not a RAM no-op.
            let confirmed = PreparedCard {
                book: self.clone(),
                key: Some(pending.entry.key),
                owns_lease: false,
            }
            .confirm_activation()?;
            drop(confirmed);
            superseding = Some((*pending.entry).clone());
            break;
        }
        let now = now_ms();
        let candidate = {
            let mut state = self.lock();
            let retained = if superseding.is_none() {
                state
                    .pending
                    .iter()
                    .rev()
                    .find(|(_, pending)| pending.own && pending.entry.writer == self.node)
                    .map(|(_, pending)| pending.clone())
            } else {
                None
            };
            if let Some(pending) = retained {
                if pending.entry.card != *card {
                    return Err(format!(
                        "rate-card entry {} remains pending; retry its exact configuration before another change",
                        pending.entry.key
                    ));
                }
                Some(pending.clone())
            } else {
                let own = state.own.and_then(|k| state.entries.get(&k).cloned());
                if let Some(own) = own
                    .as_ref()
                    .filter(|e| superseding.is_none() && e.card == *card)
                {
                    prepared.key = Some(own.key);
                    return Ok(prepared);
                }
                if let Some(in_force) = Self::in_force_at(&state, now)
                    .filter(|e| superseding.is_none() && e.card == *card)
                {
                    prepared.key = Some(in_force.key);
                    return Ok(prepared);
                }
                self.skew_alarm(&mut state, now);
                let previous = superseding
                    .or(own)
                    .or_else(|| Self::in_force_at(&state, now));
                let key = self.next_key(&state);
                let entry = StoredEntry {
                    key,
                    // Effective from this node's own now, whatever the key: a skewed head never
                    // delays a change.
                    effective_from: now,
                    effective_until: None,
                    appended_at: now,
                    author: EntryAuthor::Change,
                    actor: origin.to_string(),
                    base: previous.as_ref().map(|e| e.key),
                    writer: self.node,
                    set_fields: previous
                        .as_ref()
                        .map(|e| e.card.differing_fields(card))
                        .unwrap_or_default(),
                    card: card.clone(),
                    correction: None,
                };
                // Encoding happens outside the mutex; the logical preparation lease prevents a
                // concurrent configuration from selecting another original in the meantime.
                drop(state);
                let pending = PendingWrite::prepare(entry, true);
                self.lock()
                    .pending
                    .push((pending.entry.key, pending.clone()));
                Some(pending)
            }
        };
        let pending = candidate.expect("a changed card has a pending owner");
        let key = pending.entry.key;
        self.confirm_candidate(&pending)?;
        prepared.key = Some(key);
        Ok(prepared)
    }

    fn confirm_candidate(self: &Arc<Self>, pending: &PendingWrite) -> Result<(), String> {
        if pending.confirmed.load(Ordering::Acquire) {
            return Ok(());
        }
        let outcome = pending.records.as_ref().map(|records| {
            put_from(
                self.calls.as_ref(),
                records,
                &pending.progress,
                Some(Instant::now() + IN_LOCK_BOUND),
                true,
            )
        });
        if outcome != Some(PutOutcome::Ready) {
            self.spawn_reput();
            return Err(format!(
                "the Store has not confirmed rate-card entry {}; the previous prices remain active",
                pending.entry.key
            ));
        }
        pending.confirmed.store(true, Ordering::Release);
        Ok(())
    }

    /// A head more than the skew bound ahead of this node's clock is alarmed, naming it and its
    /// writer. It never delays a change (see [`Self::apply`]).
    fn skew_alarm(&self, state: &mut State, _now: u64) {
        self.check_alarms(state);
    }

    /// Prepare one immutable owner before its first put. The Store writes the complete intent
    /// before the canonical commit. Own-card confirmation remains pending generation activation.
    /// Encoding failure preserves the original in RAM and never claims restart durability.
    fn write(self: &Arc<Self>, entry: StoredEntry, own: bool) -> Result<EntryKey, String> {
        let key = entry.key;
        let pending = {
            let state = self.lock();
            state
                .pending
                .iter()
                .find(|(held, _)| *held == key)
                .map(|(_, held)| held.clone())
        }
        .unwrap_or_else(|| PendingWrite::prepare(entry, own));
        {
            let mut state = self.lock();
            if !state.pending.iter().any(|(held, _)| *held == key) {
                state.pending.push((key, pending.clone()));
            }
            if pending.records.is_none() {
                self.alarm(
                    &mut state,
                    format!(
                    "rate card entry {key} cannot be encoded; its original remains pending in RAM; \
                     restart recovery is unavailable until the Store accepts its complete intent"
                ),
                );
            }
        }
        let outcome = pending.records.as_ref().map(|records| {
            put_from(
                self.calls.as_ref(),
                records,
                &pending.progress,
                Some(Instant::now() + IN_LOCK_BOUND),
                true,
            )
        });
        if outcome == Some(PutOutcome::Ready) {
            let mut state = self.lock();
            pending.confirmed.store(true, Ordering::Release);
            if own {
                // Candidate confirmation is not authority to activate a generation.
                return Ok(key);
            }
            state.entries.insert(key, (*pending.entry).clone());
            state.pending.retain(|(held, _)| *held != key);
            self.publish(&state);
            self.check_alarms(&mut state);
            return Ok(key);
        }
        tracing::error!(
            "rate card entry {key} is pending canonical Store confirmation; incomplete Store \
             intent or an unavailable/ephemeral Store does not establish restart durability"
        );
        self.spawn_reput();
        Err(format!("the Store has not confirmed rate-card entry {key}; its immutable candidate remains pending"))
    }

    /// A BOUNDED AMEND: `card` priced over `[from, until)`, written like a change.
    ///
    /// # Errors
    ///
    /// The history is not loaded.
    pub fn amend(
        self: &Arc<Self>,
        from: u64,
        until: u64,
        card: CardFields,
        reason_hash: [u8; 32],
        actor: &str,
    ) -> Result<EntryKey, String> {
        let base = self.card_at(from).map(|(key, _)| key);
        self.amend_from((from, until), base, card, reason_hash, actor)
    }

    /// Prepare over the exact base a caller pinned before its seal, without a global money lock.
    pub(crate) fn amend_from(
        self: &Arc<Self>,
        window: (u64, u64),
        base: Option<EntryKey>,
        card: CardFields,
        reason_hash: [u8; 32],
        actor: &str,
    ) -> Result<EntryKey, String> {
        if !self.is_loaded() {
            return Err("the rate-card history is not loaded".to_string());
        }
        let (from, until) = window;
        let reason = hex::encode(reason_hash);
        let confirmed = {
            let state = self.lock();
            state
                .entries
                .values()
                .rev()
                .find(|entry| {
                    entry.writer == self.node
                        && !state
                            .voids
                            .iter()
                            .any(|void| void.voided == entry.key.hex())
                        && entry.effective_from == from
                        && entry.effective_until == Some(until)
                        && entry.card == card
                        && entry.actor == actor
                        && entry.author
                            == EntryAuthor::Amend {
                                reason: reason.clone(),
                            }
                })
                .map(|entry| entry.key)
        };
        if let Some(key) = confirmed {
            return Ok(key);
        }
        let retained = {
            let state = self.lock();
            state.pending.iter().find_map(|(_, pending)| {
                let entry = pending.entry.as_ref();
                (!pending.own
                    && entry.writer == self.node
                    && entry.effective_from == from
                    && entry.effective_until == Some(until)
                    && entry.base == base
                    && entry.card == card
                    && entry.actor == actor
                    && entry.author
                        == EntryAuthor::Amend {
                            reason: reason.clone(),
                        })
                .then(|| entry.clone())
            })
        };
        if let Some(entry) = retained {
            return self.write(entry, false);
        }
        let entry = {
            let mut state = self.lock();
            self.skew_alarm(&mut state, now_ms());
            StoredEntry {
                key: self.next_key(&state),
                effective_from: from,
                effective_until: Some(until),
                appended_at: now_ms(),
                author: EntryAuthor::Amend { reason },
                actor: actor.to_string(),
                base,
                writer: self.node,
                set_fields: Vec::new(),
                card,
                correction: None,
            }
        };
        self.write(entry, false)
    }

    /// The card of the entry covering `t`, as fields, with its key.
    #[must_use]
    pub fn card_at(&self, t: u64) -> Option<(EntryKey, CardFields)> {
        let state = self.lock();
        Self::in_force_at(&state, t).map(|e| (e.key, e.card))
    }

    /// Void an entry whose start is still in the future by this node's clock: known, never in
    /// force. The VOID is written and acked before it is answered.
    ///
    /// # Errors
    ///
    /// The entry is unknown, already in force, or the store did not take the VOID.
    pub fn void(&self, key: EntryKey, actor: &str) -> Result<(), String> {
        let effective_from = {
            let state = self.lock();
            let entry = state
                .entries
                .get(&key)
                .ok_or_else(|| format!("no rate card entry {key} is known to this node"))?;
            state
                .activations
                .get(&key)
                .map_or(entry.effective_from, |activation| activation.effective_from)
        };
        if effective_from <= now_ms() {
            return Err(format!(
                "rate card entry {key} is already in force by this node's clock; only an entry \
                 whose start is still in the future can be voided"
            ));
        }
        let void = VoidRecord {
            voided: key.hex(),
            voider: self.node,
            at_ms: now_ms(),
            actor: actor.to_string(),
            why: "void".to_string(),
        };
        match put_all(
            self.calls.as_ref(),
            &[void.record()?],
            Some(Instant::now() + IN_LOCK_BOUND),
            true,
        ) {
            PutOutcome::Ready => {
                let mut state = self.lock();
                state.voids.push(void);
                self.publish(&state);
                Ok(())
            }
            PutOutcome::Refused(why) | PutOutcome::Doubtful(why) => {
                Err(format!("the store did not take the VOID for {key}: {why}"))
            }
        }
    }

    /// Re-put every pending entry, oldest first, until each is READY. Repeatedly unconfirmed
    /// owners alarm and remain held, including refusals after an earlier unknown outcome.
    fn spawn_reput(self: &Arc<Self>) {
        {
            let mut state = self.lock();
            if state.reputting || state.pending.is_empty() {
                return;
            }
            state.reputting = true;
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        let mut ownership = Reputting {
            book: weak.clone(),
            armed: true,
        };
        if let Err(why) = std::thread::Builder::new()
            .name("card-reput".into())
            .spawn(move || {
                let mut pause = Duration::from_millis(100);
                let mut unconfirmed: BTreeMap<EntryKey, u32> = BTreeMap::new();
                loop {
                    std::thread::sleep(pause);
                    pause = (pause * 2).min(Duration::from_secs(5));
                    let Some(this) = weak.upgrade() else { return };
                    let pending = {
                        let mut state = this.lock();
                        if state.pending.is_empty() {
                            ownership.finish(&mut state);
                            return;
                        }
                        if state.pending.iter().all(|(_, pending)| pending.confirmed.load(Ordering::Acquire)) {
                            ownership.finish(&mut state);
                            return;
                        }
                        state.pending.clone()
                    };
                    for (key, pending) in pending {
                        if pending.confirmed.load(Ordering::Acquire) {
                            continue;
                        }
                        let records = match pending.records {
                            Some(records) => records,
                            None => {
                                let Ok(records) = pending.entry.records_for(pending.own) else {
                                    continue;
                                };
                                let records = Arc::new(records);
                                let mut state = this.lock();
                                if let Some((_, held)) =
                                    state.pending.iter_mut().find(|(held, _)| *held == key)
                                {
                                    held.records = Some(records.clone());
                                }
                                records
                            }
                        };
                        match put_from(
                            this.calls.as_ref(),
                            &records,
                            &pending.progress,
                            Some(Instant::now() + Duration::from_secs(10)),
                            false,
                        ) {
                            PutOutcome::Ready => {
                                {
                                    let mut state = this.lock();
                                    pending.confirmed.store(true, Ordering::Release);
                                    if !pending.own {
                                        state.entries.insert(key, (*pending.entry).clone());
                                        state.pending.retain(|(held, _)| *held != key);
                                        this.publish(&state);
                                    }
                                }
                                unconfirmed.remove(&key);
                                tracing::warn!("rate card entry {key} is confirmed by the store");
                            }
                            PutOutcome::Refused(why) | PutOutcome::Doubtful(why) => {
                                let n = unconfirmed.entry(key).or_insert(0);
                                *n += 1;
                                if *n == 3 {
                                    let mut state = this.lock();
                                    this.alarm(
                                        &mut state,
                                        format!(
                                            "the Store has not confirmed rate card entry {key} \
                                             after repeated retries: {why}; its immutable owner remains pending"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            })
        {
            tracing::error!("the rate card re-put worker could not start: {why}");
        }
    }

    /// Rescan on the history's tick, for the life of the store.
    fn spawn_rescan(self: &Arc<Self>) {
        if self.rescanning.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        let _ = std::thread::Builder::new()
            .name("card-rescan".into())
            .spawn(move || loop {
                std::thread::sleep(RESCAN_INTERVAL);
                let Some(this) = weak.upgrade() else { return };
                if let Err(why) = this.rescan(Some(Instant::now() + RESCAN_INTERVAL)) {
                    tracing::warn!("{why}");
                }
                this.spawn_reput();
            });
    }
}

#[cfg(test)]
#[path = "tests/card_history.rs"]
mod tests;

/// One chain's card records, as the PR-B first-boot migration copies them: `(journal node, its
/// records in chain order)`.
pub type Chain = (u64, Vec<busbar_kernel_wal::JournalRecord>);

/// **THE MIGRATION** (MONEY-DESIGN section 3a, before the opening rule): every chain's history AS
/// DEV'S BOOT REBUILT IT (`RootHistory::restore`): the opening entry first, then every other card
/// record in chain order, each correction rebuilt over the entry its chain sealed it over and LEFT
/// OUT when that rebuild refuses it (dev never priced a refused correction). Each entry is copied
/// under a TIME key (`appended_at_ms ++ journal node ++ node_seq`). Duplicates by (card, window)
/// collapse to the lowest key, and only the oldest opening entry is kept.
#[must_use]
pub fn migrated(chains: &[Chain], writer: u64) -> Vec<StoredEntry> {
    use crate::root::kernel::JournalledCard;
    let mut out: Vec<StoredEntry> = Vec::new();
    for (node, records) in chains {
        // The order `restore` rebuilds in: the first configured card from instant zero opens it,
        // and every other record follows in chain order.
        let mut opening = None;
        let mut rest = Vec::new();
        for (seq, body, card) in crate::root::kernel::journalled_cards_at(records) {
            match card {
                JournalledCard::Applied(applied)
                    if applied.effective_from == 0 && opening.is_none() =>
                {
                    opening = Some((seq, body, JournalledCard::Applied(applied)));
                }
                other => rest.push((seq, body, other)),
            }
        }
        let has_opening = opening.is_some();
        let mut history = History::new();
        // The card of each entry `history` holds, by its number.
        let mut cards: Vec<CardFields> = Vec::new();
        for (index, (seq, body, card)) in opening.into_iter().chain(rest).enumerate() {
            let key = |at: u64| EntryKey::new(at, node.to_be_bytes(), seq as u32);
            let migrated = |reason: Option<String>| EntryAuthor::Migrated {
                node: *node,
                node_seq: seq,
                opening: has_opening && index == 0 && reason.is_none(),
                reason,
            };
            let (draft, fields, reason) = match card {
                JournalledCard::Applied(applied) => {
                    // The chain's own history holds the card exactly as dev's rebuild did, so a
                    // correction's base digest matches it as it did there.
                    (applied.draft(), applied.form.to_fields(), None)
                }
                JournalledCard::Corrected(correction, sealed_over) => {
                    let draft = match correction.rebuild_over(history.current(), sealed_over) {
                        Ok(draft) => draft,
                        Err(cause) => {
                            tracing::warn!(
                                node,
                                node_seq = seq,
                                ?cause,
                                "a journalled rate correction its chain's rebuild refuses is not \
                                 migrated (it never priced an instant)"
                            );
                            continue;
                        }
                    };
                    let base = usize::try_from(sealed_over.seq.get())
                        .ok()
                        .and_then(|i| cards.get(i))
                        .cloned()
                        .unwrap_or_default();
                    let cells: Vec<(String, String, u64)> = correction
                        .cells
                        .iter()
                        .map(|(cell, nanos)| (cell.lane.clone(), cell.class.clone(), *nanos))
                        .collect();
                    let fields = crate::root::kernel::cells_onto(&base, &cells, correction.fee);
                    let reason = match &draft.author {
                        Author::Amend { reason_hash } => Some(hex::encode(reason_hash)),
                        _ => Some(String::new()),
                    };
                    (draft, fields, reason)
                }
                JournalledCard::Amended(draft) => {
                    // A `v1`/`v2` correction: the cells and the fee were the whole card it sealed.
                    let fields = amended_fields(&body);
                    let reason = match &draft.author {
                        Author::Amend { reason_hash } => Some(hex::encode(reason_hash)),
                        _ => Some(String::new()),
                    };
                    (draft, fields, reason)
                }
            };
            history.append(draft.clone());
            cards.push(fields.clone());
            out.push(StoredEntry {
                key: key(draft.appended_at),
                effective_from: draft.effective_from,
                effective_until: draft.effective_until,
                appended_at: draft.appended_at,
                author: migrated(reason),
                actor: format!("migrated from node {node}'s journal"),
                base: None,
                writer,
                set_fields: Vec::new(),
                card: fields,
                correction: None,
            });
        }
    }
    // Lowest key first, so each collapse keeps the lowest.
    out.sort_by_key(|e| e.key);
    let mut seen: BTreeSet<(String, u64, Option<u64>)> = BTreeSet::new();
    let mut opened = false;
    out.retain(|e| {
        if matches!(e.author, EntryAuthor::Migrated { opening: true, .. }) {
            if opened {
                return false;
            }
            opened = true;
        }
        seen.insert((digest_hex(&e.card), e.effective_from, e.effective_until))
    });
    out
}

/// The card a `v1`/`v2` correction record sealed whole: its cells and its fee.
#[cfg(feature = "root-admin")]
fn amended_fields(body: &[u8]) -> CardFields {
    let Some(amendment) = crate::root::units_admin::amendment_from_body(body) else {
        return CardFields::default();
    };
    let cells: Vec<(String, String, u64)> = amendment
        .rates
        .iter()
        .filter_map(|(l, c, n)| n.map(|n| (l.clone(), c.clone(), n)))
        .collect();
    crate::root::kernel::cells_onto(
        &CardFields {
            rate_card: Some(BTreeMap::new()),
            ..CardFields::default()
        },
        &cells,
        Some(amendment.sealed_fee),
    )
}

/// A build without the admin plane journals no correction.
#[cfg(not(feature = "root-admin"))]
fn amended_fields(_body: &[u8]) -> CardFields {
    CardFields::default()
}
