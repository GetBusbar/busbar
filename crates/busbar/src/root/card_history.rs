// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FLEET-SHARED RATE-CARD HISTORY, as this node holds it (MONEY-DESIGN section 3a; owner
//! rulings 2026-10-25 and 2026-10-26: money is ledger counts x rate card, the store keeps only
//! counts and the card with its history, and the configuration is the source of the card, as in
//! 1.5.5).
//!
//! [`CardStore`] reads the history from the store (`busbar.card.v1`, [`super::card_store`]) and
//! resolves it: the highest-keyed LIVE entry covering an instant prices it.
//!
//! - **The opening entry** is written at boot only when the history is empty: the node's card from
//!   instant zero. Racing nodes each write one; the LOWEST key wins and the others are never in
//!   force.
//! - **Every change of the card a configuration resolves** (boot, reload, apply, settings, plugin
//!   reload or rollback, overlay and named-map writes) appends a WHOLE-card entry, effective from
//!   that moment, recording who or what changed it ([`CardStore::apply`]). Nothing is refused.
//! - **This node prices with its OWN entry** ([`CardStore::own`]): the one it appended or adopted.
//!   A rescan records other nodes' entries and never moves it, so two nodes running different
//!   cards each price their own counts with their own card; a time-based read takes the later
//!   change on any node.
//! - **Write-before-apply on the config plane:** the entry's bytes go to the local spool first
//!   (with a data directory), then every part and the commit are put and acked within
//!   [`super::card_store::IN_LOCK_BOUND`]. Anything else is PENDING: the node prices with the
//!   pending entry's locally computed id and re-puts the same bytes until READY (strict mode, PR-B2,
//!   refuses admissions meanwhile: [`CardStore::pending_refusal`]).
//! - **There is no WITHDRAW.** An entry that landed stays. [`CardStore::void`] keeps an entry
//!   known but out of force; no operator verb reaches it, because a later change already keys
//!   above a far-future entry and prices from its own start.
//! - **Clock skew** never delays a change: an entry is effective from the writer's own now, whatever
//!   its key; a head more than [`super::card_store::SKEW_MS`] ahead alarms.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use busbar_contract::store_calls::StoreCalls;
use busbar_kernel::config::card::CardFields;
use busbar_kernel_ledger::cost::{Author, CardEntryDraft, EntryKey, History};

use super::card_store::{
    put_all, scan, EntryAuthor, PutOutcome, Scanned, Spool, SpooledWrite, StoredEntry, VoidRecord,
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
    data_dir: Option<PathBuf>,
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
    /// Entries written and not yet confirmed by the store, oldest first.
    pending: Vec<(EntryKey, super::card_store::Records)>,
    reputting: bool,
    alarmed: BTreeSet<String>,
    /// The entry this node prices with: the one it appended or adopted.
    own: Option<EntryKey>,
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
    /// A history kept in `calls`' store by node `node`, with its spool under `data_dir`.
    #[must_use]
    pub fn new(calls: Arc<dyn StoreCalls>, node: u64, data_dir: Option<PathBuf>) -> Arc<Self> {
        Arc::new(CardStore {
            calls,
            node,
            rand: super::card_store::boot_rand(),
            counter: AtomicU32::new(0),
            data_dir,
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

    /// Every alarm this node has raised over the history, in the order raised (each once).
    #[must_use]
    pub fn alarms(&self) -> Vec<String> {
        self.lock().alarmed.iter().cloned().collect()
    }

    /// The key of the oldest entry pending confirmation on this node, if any.
    #[must_use]
    pub fn pending(&self) -> Option<EntryKey> {
        self.lock().pending.first().map(|(k, _)| *k)
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
        let fleet = Self::resolve(&state.entries, &state.voids);
        let mut node = fleet.clone();
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

    /// **THE HISTORY**, resolved: every entry by key, an opening that lost its race and every
    /// voided entry KNOWN (its card still answers its id) but never in force.
    #[must_use]
    pub fn resolve(entries: &BTreeMap<EntryKey, StoredEntry>, voids: &[VoidRecord]) -> History {
        let winner = Self::opening(entries).map(|e| e.key);
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
                    effective_from: entry.effective_from,
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
        let history = Self::resolve(&state.entries, &state.voids);
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

    /// Why STRICT MODE (PR-B2's `advanced.strict_spend_recording`) refuses a new admission now, or
    /// `None`: a rate-card entry this node prices with is not yet confirmed by the store. The
    /// default mode serves through it.
    #[must_use]
    pub fn pending_refusal(&self) -> Option<String> {
        self.pending().map(|key| {
            format!(
                "the rate card entry {key} this node prices with is pending confirmation from the \
                 store"
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
            if entry.effective_from > now.saturating_add(SKEW_MS)
                && !voided.contains(&entry.key.hex())
            {
                messages.push(format!(
                    "rate card entry {} written by node {} starts {} ms ahead of this node's \
                     clock; it prices only instants from its own start, and any later change on \
                     any node keys above it and takes precedence",
                    entry.key,
                    entry.writer,
                    entry.effective_from - now,
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
    fn merge(&self, scanned: Scanned) -> bool {
        let mut state = self.lock();
        let mut changed = false;
        for entry in scanned.entries {
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
        changed
    }

    /// Rescan the store, and publish what is new.
    ///
    /// # Errors
    ///
    /// The store failed or refused the scan.
    pub fn rescan(&self, deadline: Option<Instant>) -> Result<bool, String> {
        let scanned = scan(self.calls.as_ref(), deadline)?;
        Ok(self.merge(scanned))
    }

    fn spool_dir(&self) -> Option<&std::path::Path> {
        self.data_dir.as_deref()
    }

    fn load_spool(&self) -> Spool {
        match self.spool_dir().map(Spool::load) {
            Some(Ok(spool)) => spool,
            Some(Err(why)) => {
                tracing::error!("the rate card spool does not read: {why}");
                Spool::default()
            }
            None => Spool::default(),
        }
    }

    fn save_spool(&self, spool: &Spool) -> Result<(), String> {
        match self.spool_dir() {
            Some(dir) => spool.save(dir),
            None => Ok(()),
        }
    }

    /// The next key this node writes: `t_ms = max(now, head + 1)`.
    fn next_key(&self, state: &State) -> EntryKey {
        let head = Self::resolve(&state.entries, &state.voids).head_t_ms();
        let t = head.map_or(now_ms(), |h| now_ms().max(h.saturating_add(1)));
        EntryKey::new(t, self.rand, self.counter.fetch_add(1, Ordering::Relaxed))
    }

    /// **THE BOOT.** Re-put the entries the spool holds, read the history, copy the journal's
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
        // THE SPOOL FIRST: an entry written and not confirmed before the restart is re-put.
        let spool = self.load_spool();
        let mut unconfirmed = Vec::new();
        for write in &spool.pending {
            let records = write.records()?;
            let key = EntryKey::parse_hex(&write.key)
                .ok_or_else(|| format!("the rate card spool names `{}`", write.key))?;
            // The spooled entry is this node's own: held, and (a change) the entry it prices with,
            // so the boot below adopts it rather than writing it again.
            for entry in Scanned::of(records.clone()).entries {
                let mut state = self.lock();
                if matches!(entry.author, EntryAuthor::Change) {
                    state.own = Some(entry.key);
                }
                state.entries.insert(entry.key, entry);
            }
            if put_all(self.calls.as_ref(), &records, deadline(), false) != PutOutcome::Ready {
                tracing::error!(
                    "the rate card entry {key} is not confirmed by the store yet; it is re-put in \
                     the background"
                );
                unconfirmed.push((key, records));
            }
        }
        if unconfirmed.len() != spool.pending.len() {
            let keep: BTreeSet<String> = unconfirmed.iter().map(|(k, _)| k.hex()).collect();
            let mut spool = spool.clone();
            spool.pending.retain(|w| keep.contains(&w.key));
            self.save_spool(&spool)?;
        }
        let reput = !unconfirmed.is_empty();
        self.lock().pending = unconfirmed;
        if reput {
            self.spawn_reput();
        }
        // THE READ: the whole schema. A store error fails the boot, unless the node is only
        // re-putting an entry, which it does in the background.
        match self.rescan(deadline()) {
            Ok(_) => {}
            Err(why) if reput => tracing::error!("{why}; the boot continues and keeps re-putting"),
            Err(why) => return Err(why),
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
        if self.lock().entries.is_empty() {
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
            match put_all(self.calls.as_ref(), &entry.records()?, deadline(), true) {
                PutOutcome::Ready => {}
                PutOutcome::Refused(why) | PutOutcome::Doubtful(why) => {
                    return Err(format!(
                        "the rate-card history is empty and the store would not take its opening \
                         entry: {why}"
                    ))
                }
            }
            self.lock().entries.insert(entry.key, entry);
            // Another node may have opened it at the same time: the lowest key wins.
            let _ = self.rescan(deadline());
        }
        {
            let mut state = self.lock();
            self.publish(&state);
            self.check_alarms(&mut state);
        }
        self.loaded.store(true, Ordering::Release);
        self.apply(card, origin);
        self.spawn_rescan();
        Ok(())
    }

    /// **A CONFIGURATION RESOLVED `card`** (boot, reload, apply, settings, plugin reload or
    /// rollback, overlay and named-map writes; `origin` names which, and who). Equal to this
    /// node's own card: nothing. Equal to the card in force: this node adopts that entry.
    /// Otherwise a WHOLE-card entry is appended, effective now, recording `origin` and the fields
    /// that changed. Nothing is refused: a write the store does not confirm is pending and re-put.
    /// Answers the entry this node now prices with.
    pub fn apply(self: &Arc<Self>, card: &CardFields, origin: &str) -> Option<EntryKey> {
        if !self.is_loaded() {
            return None;
        }
        let now = now_ms();
        let entry = {
            let mut state = self.lock();
            let own = state.own.and_then(|k| state.entries.get(&k).cloned());
            if let Some(own) = own.as_ref().filter(|e| e.card == *card) {
                return Some(own.key);
            }
            if let Some(in_force) = Self::in_force_at(&state, now).filter(|e| e.card == *card) {
                state.own = Some(in_force.key);
                return Some(in_force.key);
            }
            self.skew_alarm(&mut state, now);
            let previous = own.or_else(|| Self::in_force_at(&state, now));
            let key = self.next_key(&state);
            StoredEntry {
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
            }
        };
        tracing::debug!(
            key = %entry.key,
            origin,
            fields = ?entry.set_fields,
            "the rate card changed: a history entry is appended, effective now"
        );
        let key = entry.key;
        self.write(entry, true);
        Some(key)
    }

    /// A head more than the skew bound ahead of this node's clock is alarmed, naming it and its
    /// writer. It never delays a change (see [`Self::apply`]).
    fn skew_alarm(&self, state: &mut State, _now: u64) {
        self.check_alarms(state);
    }

    /// Write `entry` write-before-apply: spooled first, put with the in-lock bound. READY, it is
    /// confirmed; anything else leaves it PENDING, in force on this node and re-put in the
    /// background until READY. Never refused.
    fn write(self: &Arc<Self>, entry: StoredEntry, own: bool) {
        let key = entry.key;
        let records = match entry.records() {
            Ok(records) => records,
            Err(why) => {
                tracing::error!("rate card entry {key} cannot be written: {why}");
                Vec::new()
            }
        };
        let mut spool = self.load_spool();
        spool.pending.push(SpooledWrite::of(&key, &records));
        if let Err(why) = self.save_spool(&spool) {
            tracing::error!(
                "rate card entry {key} could not be spooled before it was written: {why}; it is \
                 held in memory and re-put until the store confirms it"
            );
        }
        // IN FORCE ON THIS NODE AT ONCE, already spooled: the generation that resolved it is live,
        // so its counts carry this entry's id from now, before the store has answered.
        {
            let mut state = self.lock();
            state.entries.insert(key, entry);
            if own {
                state.own = Some(key);
            }
            self.publish(&state);
        }
        let outcome = put_all(
            self.calls.as_ref(),
            &records,
            Some(Instant::now() + IN_LOCK_BOUND),
            true,
        );
        if outcome == PutOutcome::Ready {
            spool.pending.retain(|w| w.key != key.hex());
            if let Err(why) = self.save_spool(&spool) {
                tracing::error!(
                    "rate card entry {key} IS in force fleet-wide, and the local spool could not \
                     be cleared: {why}"
                );
            }
            let mut state = self.lock();
            self.check_alarms(&mut state);
            return;
        }
        let why = match &outcome {
            PutOutcome::Refused(why) | PutOutcome::Doubtful(why) => why.clone(),
            PutOutcome::Ready => String::new(),
        };
        tracing::error!(
            "rate card entry {key} is in force on this node and pending confirmation from the \
             store ({why}); it is re-put until the store confirms it"
        );
        self.lock().pending.push((key, records));
        self.spawn_reput();
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
        if !self.is_loaded() {
            return Err("the rate-card history is not loaded".to_string());
        }
        let entry = {
            let mut state = self.lock();
            self.skew_alarm(&mut state, now_ms());
            let base = Self::in_force_at(&state, from).map(|e| e.key);
            StoredEntry {
                key: self.next_key(&state),
                effective_from: from,
                effective_until: Some(until),
                appended_at: now_ms(),
                author: EntryAuthor::Amend {
                    reason: hex::encode(reason_hash),
                },
                actor: actor.to_string(),
                base,
                writer: self.node,
                set_fields: Vec::new(),
                card,
                correction: None,
            }
        };
        let key = entry.key;
        self.write(entry, false);
        Ok(key)
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
        let entry = self
            .lock()
            .entries
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("no rate card entry {key} is known to this node"))?;
        if entry.effective_from <= now_ms() {
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

    /// Re-put every pending entry, oldest first, until each is READY. An entry the store keeps
    /// REFUSING is alarmed, naming the store's reason, and still re-put: the node never drops it.
    fn spawn_reput(self: &Arc<Self>) {
        {
            let mut state = self.lock();
            if state.reputting {
                return;
            }
            state.reputting = true;
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        let _ = std::thread::Builder::new()
            .name("card-reput".into())
            .spawn(move || {
                let mut pause = Duration::from_millis(100);
                let mut refusals: BTreeMap<EntryKey, u32> = BTreeMap::new();
                loop {
                    std::thread::sleep(pause);
                    pause = (pause * 2).min(Duration::from_secs(5));
                    let Some(this) = weak.upgrade() else { return };
                    let pending = this.lock().pending.clone();
                    if pending.is_empty() {
                        this.lock().reputting = false;
                        return;
                    }
                    for (key, records) in pending {
                        match put_all(
                            this.calls.as_ref(),
                            &records,
                            Some(Instant::now() + Duration::from_secs(10)),
                            true,
                        ) {
                            PutOutcome::Ready => {
                                let mut spool = this.load_spool();
                                spool.pending.retain(|w| w.key != key.hex());
                                if let Err(why) = this.save_spool(&spool) {
                                    tracing::error!(
                                        "rate card entry {key} is confirmed; the spool: {why}"
                                    );
                                }
                                this.lock().pending.retain(|(k, _)| *k != key);
                                refusals.remove(&key);
                                tracing::warn!("rate card entry {key} is confirmed by the store");
                            }
                            PutOutcome::Refused(why) => {
                                let n = refusals.entry(key).or_insert(0);
                                *n += 1;
                                if *n == 3 {
                                    let mut state = this.lock();
                                    this.alarm(
                                        &mut state,
                                        format!(
                                            "the store keeps REFUSING rate card entry {key}: \
                                             {why}; it is in force on this node and still re-put"
                                        ),
                                    );
                                }
                            }
                            PutOutcome::Doubtful(_) => {}
                        }
                    }
                }
            });
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
