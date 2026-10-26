// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FLEET-SHARED RATE-CARD HISTORY, as this node holds it (MONEY-DESIGN section 3a; owner ruling
//! 2026-10-25: money is ledger counts x rate card, the store keeps only counts and the card with its
//! history, and after first boot the card changes ONLY through `PUT /config/settings`).
//!
//! [`CardStore`] reads the history from the store (`busbar.card.v1`, [`super::card_store`]),
//! resolves it (the highest-keyed LIVE entry covering an instant prices it), and writes new entries
//! write-before-apply:
//!
//! - **The opening entry** is written at boot only when the history is empty: the node's merged
//!   seed card (file plus overlay) from instant zero, recording the merged seed's digest and the
//!   file-only seed's. Racing nodes each write one; the LOWEST key wins and the others are never in
//!   force.
//! - **A PUT** writes the head's card with the request's fields replaced, under a key above the
//!   head. Its bytes go to the local spool first (with a data directory), then every part and the
//!   commit are put and acked. READY within [`super::card_store::IN_LOCK_BOUND`] answers applied;
//!   anything doubtful answers "applied, pending confirmation", closes this node's admissions and
//!   re-puts the same bytes until READY. A first-attempt REFUSED refuses the apply.
//! - **There is no WITHDRAW.** An entry that landed stays. `card abandon` stops a pending re-put and
//!   writes a VOID for it; `card void` voids an entry not yet in force.
//! - **Clock skew** is checked by the writer only: a head more than [`super::card_store::SKEW_MS`]
//!   ahead of this node's clock refuses a card change and alarms, naming the entry and its writer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use busbar_contract::store_calls::StoreCalls;
use busbar_kernel::config::card::{CardFields, CardSet, EditRefused};
use busbar_kernel::rate_apply::CardPut;
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

/// THE SEED a boot raises: the merged card the boot's configuration resolved, and the file's own.
#[derive(Debug, Clone, Default)]
pub struct Seed {
    /// The file plus the overlay, as boot merges them.
    pub merged: Option<CardFields>,
    /// The file alone.
    pub file: Option<CardFields>,
}

/// What a disk card is, against the history (MONEY-DESIGN section 3a "Disk loads").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskVerdict {
    /// Unedited, or a PUT card copied into the file.
    Accepted,
    /// The file was edited BACK to the seed after a PUT changed the card: the load proceeds on the
    /// card in force, and the audit record `card.file_differs` names it.
    FileDiffers(Vec<String>),
    /// An edit.
    Edited(EditRefused),
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
    loaded: AtomicBool,
    rescanning: AtomicBool,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<EntryKey, StoredEntry>,
    voids: Vec<VoidRecord>,
    pending: Option<(EntryKey, super::card_store::Records)>,
    reputting: bool,
    alarmed: BTreeSet<String>,
    seed: Seed,
    last_file: Option<CardFields>,
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

    /// The history as this node resolves it, for pricing.
    #[must_use]
    pub fn history(&self) -> Option<Arc<History>> {
        self.published.load_full()
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

    /// The key of the entry pending confirmation on this node, if any.
    #[must_use]
    pub fn pending(&self) -> Option<EntryKey> {
        self.lock().pending.as_ref().map(|(k, _)| *k)
    }

    /// Rebuild the resolved history from what this node holds, and publish it.
    fn publish(&self, state: &State) {
        self.published
            .store(Some(Arc::new(Self::resolve(&state.entries, &state.voids))));
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
                EntryAuthor::Put | EntryAuthor::Migrated { .. } => {
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

    /// The card `GET /config/settings` renders, and which of its fields to show: a field is shown
    /// when a PUT set it on some entry and the card in force differs there from the merged seed.
    #[must_use]
    pub fn rendered(&self) -> Option<(CardFields, Vec<String>)> {
        let in_force = self.in_force()?;
        let state = self.lock();
        let seed = Self::opening(&state.entries)?.card.clone();
        let marked: BTreeSet<&String> = state
            .entries
            .values()
            .filter(|e| matches!(e.author, EntryAuthor::Put))
            .flat_map(|e| e.set_fields.iter())
            .collect();
        let fields: Vec<String> = in_force
            .differing_fields(&seed)
            .into_iter()
            .filter(|f| marked.contains(f))
            .collect();
        (!fields.is_empty()).then_some((in_force, fields))
    }

    /// Why this node refuses a new admission now, or `None`.
    #[must_use]
    pub fn admission_refusal(&self) -> Option<String> {
        self.pending().map(|key| {
            format!(
                "the rate card entry {key} is pending confirmation from the store; this node \
                 refuses admissions until the store confirms it or an operator runs `card abandon`"
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

    /// The readers' alarms over what this node holds: far-future entries, concurrent edits (two
    /// PUTs extending one head; the higher key is in force and the other's fields are lost), and
    /// entries extending a voided one.
    fn check_alarms(&self, state: &mut State) {
        let now = now_ms();
        let voided: BTreeSet<String> = state.voids.iter().map(|v| v.voided.clone()).collect();
        let mut messages = Vec::new();
        for entry in state.entries.values() {
            if entry.key.t_ms() > now.saturating_add(SKEW_MS) && !voided.contains(&entry.key.hex())
            {
                messages.push(format!(
                    "rate card entry {} written by node {} is dated {} ms ahead of this node's \
                     clock; it prices only instants from its own start. An operator may run `card \
                     void {}` while its start is still in the future",
                    entry.key,
                    entry.writer,
                    entry.key.t_ms() - now,
                    entry.key
                ));
            }
            if let Some(base) = entry.base {
                if voided.contains(&base.hex()) {
                    messages.push(format!(
                        "rate card entry {} (node {}) extends the voided entry {base}: it still \
                         carries that entry's fields; re-apply the intended fields through PUT \
                         /config/settings",
                        entry.key, entry.writer
                    ));
                }
            }
        }
        let puts: Vec<&StoredEntry> = state
            .entries
            .values()
            .filter(|e| matches!(e.author, EntryAuthor::Put) && !voided.contains(&e.key.hex()))
            .collect();
        for (i, lower) in puts.iter().enumerate() {
            for higher in &puts[i + 1..] {
                if lower.base.is_some() && lower.base == higher.base {
                    let lost: Vec<String> = lower
                        .card
                        .differing_fields(&higher.card)
                        .into_iter()
                        .filter(|f| lower.set_fields.contains(f))
                        .collect();
                    messages.push(format!(
                        "concurrent rate card edits: entries {} (node {}) and {} (node {}) both \
                         extend {}; the higher key {} is in force and the fields [{}] set by {} \
                         are LOST. Nothing posted is repriced; re-apply them through PUT \
                         /config/settings",
                        lower.key,
                        lower.writer,
                        higher.key,
                        higher.writer,
                        lower.base.map(|b| b.hex()).unwrap_or_default(),
                        higher.key,
                        lost.join(", "),
                        lower.key
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

    /// **THE BOOT.** Re-put a pending entry the spool holds, read the history, copy the journal's
    /// card records into it (`migrated`, every chain's), and open it with the seed when it is
    /// still empty. A non-empty history judges the boot's file card: an edit is not applied, and
    /// is audited, logged and alarmed, never a failed boot.
    ///
    /// # Errors
    ///
    /// The store would not read the history back, or would not take the opening entry or a
    /// migrated one.
    pub fn boot(self: &Arc<Self>, seed: Seed, migrated: Vec<StoredEntry>) -> Result<(), String> {
        let deadline = || Some(Instant::now() + BOOT_DEADLINE);
        {
            self.lock().seed = seed.clone();
        }
        // THE SPOOL FIRST, before admissions open: a pending entry is re-put to READY, and an
        // abandoned one's VOID is offered again (it warns at every boot until READY).
        let spool = self.load_spool();
        if let Some(pending) = spool.pending.as_ref() {
            let records = pending.records()?;
            let key = EntryKey::parse_hex(&pending.key)
                .ok_or_else(|| format!("the rate card spool names `{}`", pending.key))?;
            match put_all(self.calls.as_ref(), &records, deadline(), false) {
                PutOutcome::Ready => {
                    let mut spool = spool.clone();
                    spool.pending = None;
                    self.save_spool(&spool)?;
                }
                PutOutcome::Refused(why) | PutOutcome::Doubtful(why) => {
                    tracing::error!(
                        "the pending rate card entry {key} is not confirmed by the store yet \
                         ({why}); this node refuses admissions and keeps re-putting it"
                    );
                    self.lock().pending = Some((key, records));
                    self.spawn_reput();
                }
            }
        }
        for abandoned in &spool.abandoned {
            tracing::warn!(
                "rate card entry {} was abandoned on this node and its VOID is not confirmed by \
                 the store yet; it is re-put in the background",
                abandoned.key
            );
        }
        if !spool.abandoned.is_empty() {
            self.spawn_void_reput();
        }
        // THE READ: the whole schema. A store error fails the boot, unless the node is only
        // re-putting a pending entry, which serves with admissions closed.
        match self.rescan(deadline()) {
            Ok(_) => {}
            Err(why) if self.pending().is_some() => {
                tracing::error!("{why}; the boot continues with admissions closed");
            }
            Err(why) => return Err(why),
        }
        // THE MIGRATION, before the opening rule: every chain's card records, under time keys, an
        // idempotent union (a key the store holds is not written again).
        let held: BTreeSet<EntryKey> = self.lock().entries.keys().copied().collect();
        for entry in migrated.into_iter().filter(|e| !held.contains(&e.key)) {
            let records = entry.records()?;
            match put_all(self.calls.as_ref(), &records, deadline(), true) {
                PutOutcome::Ready => {}
                PutOutcome::Refused(why) | PutOutcome::Doubtful(why) => {
                    return Err(format!(
                        "the store would not take the rate card entry {} migrated from node \
                         journals: {why}",
                        entry.key
                    ))
                }
            }
            let mut state = self.lock();
            state.entries.insert(entry.key, entry);
        }
        // THE OPENING RULE: an empty history is opened with the seed, from instant zero, now.
        let empty = Self::opening(&self.lock().entries).is_none() && self.lock().entries.is_empty();
        if empty {
            let merged = seed.merged.clone().unwrap_or_default();
            let file = seed.file.clone().unwrap_or_else(|| merged.clone());
            let entry = {
                let state = self.lock();
                StoredEntry {
                    key: self.next_key(&state),
                    effective_from: 0,
                    effective_until: None,
                    appended_at: now_ms(),
                    author: EntryAuthor::Opening {
                        seed: digest_hex(&merged),
                        file_seed: digest_hex(&file),
                    },
                    actor: "boot".to_string(),
                    base: None,
                    writer: self.node,
                    set_fields: Vec::new(),
                    card: merged,
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
        // A FILE CARD EDITED AFTER FIRST BOOT is not applied: the boot serves the history, and
        // says so at every boot until the file matches or the change is made through PUT.
        if !empty {
            if let Some(file) = seed.file.as_ref() {
                match self.judge_disk(file) {
                    DiskVerdict::Edited(refused) => {
                        refused.audit();
                        let msg = format!(
                            "{} (the boot serves the rate card in force from the history)",
                            EditRefused {
                                path: "boot".to_string(),
                                fields: refused.fields.clone(),
                            }
                        );
                        let mut state = self.lock();
                        self.alarm(&mut state, msg);
                    }
                    DiskVerdict::Accepted | DiskVerdict::FileDiffers(_) => {}
                }
            }
        }
        self.spawn_rescan();
        Ok(())
    }

    /// **JUDGE A DISK CARD** (MONEY-DESIGN section 3a "Disk loads"): the file card against the file-only
    /// seed and the card in force. Not loaded yet: accepted (the boot judges it once loaded).
    pub fn judge_disk(&self, file: &CardFields) -> DiskVerdict {
        let Some(in_force) = self.in_force() else {
            return DiskVerdict::Accepted;
        };
        let mut state = self.lock();
        let file_seed = match Self::opening(&state.entries).map(|e| &e.author) {
            Some(EntryAuthor::Opening { file_seed, .. }) => Some(file_seed.clone()),
            _ => Self::opening(&state.entries).map(|e| digest_hex(&e.card)),
        };
        let digest = digest_hex(file);
        let previous = state.last_file.replace(file.clone());
        if file_seed.as_deref() == Some(digest.as_str()) {
            // Unedited since the seed. Edited BACK to it after a PUT changed the card, it is said.
            let back = in_force != *file && previous.as_ref().is_some_and(|p| p != file);
            return if back {
                DiskVerdict::FileDiffers(file.differing_fields(&in_force))
            } else {
                DiskVerdict::Accepted
            };
        }
        if *file == in_force {
            return DiskVerdict::Accepted;
        }
        state.last_file = previous;
        DiskVerdict::Edited(EditRefused {
            path: "config.yaml".to_string(),
            fields: file.differing_fields(&in_force),
        })
    }

    /// **JUDGE A REQUEST BODY'S CARD** (`POST /config/apply`): equal to the merged seed or to the
    /// card in force, it passes.
    ///
    /// # Errors
    ///
    /// Any other card: the edit.
    pub fn judge_body(&self, path: &str, card: &CardFields) -> Result<(), EditRefused> {
        let Some(in_force) = self.in_force() else {
            return Ok(());
        };
        let seed = Self::opening(&self.lock().entries).map(|e| e.card.clone());
        if *card == in_force || seed.as_ref() == Some(card) {
            return Ok(());
        }
        Err(EditRefused {
            path: path.to_string(),
            fields: card.differing_fields(&in_force),
        })
    }

    /// Refuse a card change while an entry is pending, or while the head is beyond the skew bound.
    fn writable(&self, state: &mut State) -> Result<(), String> {
        if let Some((key, _)) = state.pending.as_ref() {
            return Err(format!(
                "the rate card entry {key} is pending confirmation from the store; no further \
                 card change is accepted on this node until it is confirmed or an operator runs \
                 `card abandon`"
            ));
        }
        let now = now_ms();
        let head = Self::resolve(&state.entries, &state.voids)
            .live_head()
            .map(|e| e.key());
        if let Some(head) = head.filter(|h| h.t_ms() > now.saturating_add(SKEW_MS)) {
            let writer = state.entries.get(&head).map_or(0, |e| e.writer);
            let msg = format!(
                "the rate card change is refused: entry {head}, written by node {writer}, is \
                 dated {} ms ahead of this node's clock (more than the {} s skew bound); an \
                 operator runs `card void {head}` and applies again",
                head.t_ms() - now,
                SKEW_MS / 1000
            );
            self.alarm(state, msg.clone());
            return Err(msg);
        }
        Ok(())
    }

    /// Write `entry` write-before-apply: spooled first, put with the in-lock bound, then in force on
    /// this node. A doubtful write is pending and re-put in the background.
    fn write(self: &Arc<Self>, entry: StoredEntry) -> Result<CardPut, String> {
        let records = entry.records()?;
        let key = entry.key;
        let mut spool = self.load_spool();
        spool.pending = Some(SpooledWrite::of(&key, &records));
        self.save_spool(&spool).map_err(|why| {
            format!("the rate card entry could not be spooled before it was written: {why}")
        })?;
        let outcome = put_all(
            self.calls.as_ref(),
            &records,
            Some(Instant::now() + IN_LOCK_BOUND),
            true,
        );
        match outcome {
            PutOutcome::Ready => {
                spool.pending = None;
                let saved = self.save_spool(&spool);
                let mut state = self.lock();
                state.entries.insert(key, entry);
                self.publish(&state);
                self.check_alarms(&mut state);
                if let Err(why) = saved {
                    tracing::error!(
                        "rate card entry {key} IS in force fleet-wide, and the local spool could \
                         not be cleared: {why}"
                    );
                }
                Ok(CardPut::Ready { key: key.hex() })
            }
            PutOutcome::Refused(why) => {
                spool.pending = None;
                let _ = self.save_spool(&spool);
                Err(format!(
                    "the store refused the rate card entry, so the change was not applied: {why}"
                ))
            }
            PutOutcome::Doubtful(why) => {
                tracing::error!(
                    "rate card entry {key} is applied on this node and pending confirmation from \
                     the store ({why}); admissions are refused until it is confirmed"
                );
                {
                    let mut state = self.lock();
                    state.entries.insert(key, entry);
                    state.pending = Some((key, records));
                    self.publish(&state);
                }
                self.spawn_reput();
                Ok(CardPut::Pending { key: key.hex() })
            }
        }
    }

    /// **THE ONE CARD PATH** (`PUT /config/settings`): rescan, build the head's card with `set`'s
    /// fields replaced, `check` it, write it.
    ///
    /// # Errors
    ///
    /// A pending entry, a far-future head, a failed rescan, the check's refusal, or a
    /// first-attempt REFUSED.
    pub fn put(
        self: &Arc<Self>,
        set: &CardSet,
        actor: &str,
        check: &mut dyn FnMut(&CardFields) -> Result<(), String>,
    ) -> Result<CardPut, String> {
        self.writable(&mut self.lock())?;
        self.rescan(Some(Instant::now() + IN_LOCK_BOUND))
            .map_err(|why| format!("the rate card change is refused: {why}"))?;
        let (base, entry_key) = {
            let mut state = self.lock();
            self.writable(&mut state)?;
            let base = Self::in_force_at(&state, now_ms())
                .ok_or_else(|| "the rate-card history holds no card in force".to_string())?;
            let key = self.next_key(&state);
            (base, key)
        };
        let card = base.card.with_set(set);
        if card == base.card {
            return Ok(CardPut::Unchanged);
        }
        check(&card)?;
        self.write(StoredEntry {
            key: entry_key,
            effective_from: entry_key.t_ms(),
            effective_until: None,
            appended_at: now_ms(),
            author: EntryAuthor::Put,
            actor: actor.to_string(),
            base: Some(base.key),
            writer: self.node,
            set_fields: set.field_names(),
            card,
            correction: None,
        })
    }

    /// A BOUNDED AMEND: `card` priced over `[from, until)`, written like a PUT.
    ///
    /// # Errors
    ///
    /// As [`Self::put`].
    pub fn amend(
        self: &Arc<Self>,
        from: u64,
        until: u64,
        card: CardFields,
        reason_hash: [u8; 32],
        actor: &str,
    ) -> Result<CardPut, String> {
        let entry = {
            let mut state = self.lock();
            self.writable(&mut state)?;
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
        self.write(entry)
    }

    /// The card of the entry covering `t`, as fields, with its key.
    #[must_use]
    pub fn card_at(&self, t: u64) -> Option<(EntryKey, CardFields)> {
        let state = self.lock();
        Self::in_force_at(&state, t).map(|e| (e.key, e.card))
    }

    /// **`card void <key>`**: void an entry whose start is still in the future by this node's
    /// clock. The VOID is written and acked before it is answered.
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
            PutOutcome::Refused(why) | PutOutcome::Doubtful(why) => Err(format!(
                "the store did not take the VOID for {key}: {why}; run `card void` again"
            )),
        }
    }

    /// **`card abandon`**: stop re-putting the pending entry, void it, and reopen admissions at
    /// the history's card. The VOID is synced to the local spool first and re-put in the
    /// background until READY.
    ///
    /// # Errors
    ///
    /// Nothing is pending, or the spool could not be written.
    pub fn abandon(self: &Arc<Self>, actor: &str) -> Result<EntryKey, String> {
        let key = self
            .pending()
            .ok_or_else(|| "no rate card entry is pending on this node".to_string())?;
        let void = VoidRecord {
            voided: key.hex(),
            voider: self.node,
            at_ms: now_ms(),
            actor: actor.to_string(),
            why: "abandon".to_string(),
        };
        let record = void.record()?;
        let mut spool = self.load_spool();
        spool.pending = None;
        spool.abandoned.push(SpooledWrite::of(&key, &[record]));
        self.save_spool(&spool)?;
        {
            let mut state = self.lock();
            state.pending = None;
            state.voids.push(void);
            self.publish(&state);
        }
        self.spawn_void_reput();
        Ok(key)
    }

    /// Re-put the pending entry until READY, then reopen admissions.
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
                loop {
                    std::thread::sleep(pause);
                    pause = (pause * 2).min(Duration::from_secs(5));
                    let Some(this) = weak.upgrade() else { return };
                    let Some((key, records)) = this.lock().pending.clone() else {
                        this.lock().reputting = false;
                        return;
                    };
                    let outcome = put_all(
                        this.calls.as_ref(),
                        &records,
                        Some(Instant::now() + Duration::from_secs(10)),
                        false,
                    );
                    if outcome == PutOutcome::Ready {
                        let mut spool = this.load_spool();
                        if spool.pending.as_ref().map(|p| p.key.as_str()) == Some(&key.hex()) {
                            spool.pending = None;
                        }
                        if let Err(why) = this.save_spool(&spool) {
                            tracing::error!("rate card entry {key} is confirmed; the spool: {why}");
                        }
                        let mut state = this.lock();
                        if state.pending.as_ref().map(|(k, _)| *k) == Some(key) {
                            state.pending = None;
                        }
                        state.reputting = false;
                        tracing::warn!(
                            "rate card entry {key} is confirmed by the store; admissions reopen"
                        );
                        return;
                    }
                }
            });
    }

    /// Re-put every abandoned entry's VOID until READY, dropping each from the spool when it is.
    fn spawn_void_reput(self: &Arc<Self>) {
        let weak: Weak<Self> = Arc::downgrade(self);
        let _ = std::thread::Builder::new()
            .name("card-void-reput".into())
            .spawn(move || {
                let mut pause = Duration::from_millis(100);
                loop {
                    let Some(this) = weak.upgrade() else { return };
                    let mut spool = this.load_spool();
                    if spool.abandoned.is_empty() {
                        return;
                    }
                    spool.abandoned.retain(|write| {
                        let Ok(records) = write.records() else {
                            return false;
                        };
                        put_all(
                            this.calls.as_ref(),
                            &records,
                            Some(Instant::now() + Duration::from_secs(10)),
                            false,
                        ) != PutOutcome::Ready
                    });
                    if let Err(why) = this.save_spool(&spool) {
                        tracing::error!("the rate card spool: {why}");
                    }
                    if spool.abandoned.is_empty() {
                        return;
                    }
                    drop(this);
                    std::thread::sleep(pause);
                    pause = (pause * 2).min(Duration::from_secs(5));
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

/// **THE MIGRATION** (MONEY-DESIGN section 3a, before the opening rule): every chain's `Policy` records —
/// configured cards and amendments — as `busbar.card.v1` entries under TIME keys
/// (`appended_at_ms ++ journal node ++ node_seq`). Duplicates by (card, `effective_from`) collapse
/// to the lowest key, and only the oldest opening entry is kept. A correction is rebuilt over the
/// entry its chain sealed it over; one whose base its chain does not hold is left out, named.
#[must_use]
pub fn migrated(chains: &[Chain], writer: u64) -> Vec<StoredEntry> {
    let mut out: Vec<StoredEntry> = Vec::new();
    for (node, records) in chains {
        // The chain's own history as it rebuilt it, to find each correction's base card.
        let mut history = History::new();
        let mut cards: Vec<CardFields> = Vec::new();
        let mut chain_opened = false;
        for record in records
            .iter()
            .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        {
            let key = |at: u64| EntryKey::new(at, node.to_be_bytes(), record.node_seq as u32);
            if let Some(applied) = crate::root::kernel::CardApplied::from_body(&record.body) {
                let opening = !chain_opened && applied.effective_from == 0;
                chain_opened |= opening;
                let card = applied.form.to_fields();
                history.append(CardEntryDraft {
                    effective_from: applied.effective_from,
                    effective_until: None,
                    card: rate_card_of(&card),
                    appended_at: applied.appended_at,
                    author: Author::Config { policy_epoch: 0 },
                });
                cards.push(card.clone());
                out.push(StoredEntry {
                    key: key(applied.appended_at),
                    effective_from: applied.effective_from,
                    effective_until: None,
                    appended_at: applied.appended_at,
                    author: EntryAuthor::Migrated {
                        node: *node,
                        node_seq: record.node_seq,
                        opening,
                        reason: None,
                    },
                    actor: "migration".to_string(),
                    base: None,
                    writer,
                    set_fields: Vec::new(),
                    card,
                    correction: None,
                });
                continue;
            }
            #[cfg(feature = "root-admin")]
            if let Some(amendment) = crate::root::units_admin::amendment_from_body(&record.body) {
                let cells: Vec<(String, String, u64)> = amendment
                    .rates
                    .iter()
                    .filter_map(|(l, c, n)| n.map(|n| (l.clone(), c.clone(), n)))
                    .collect();
                let card = match amendment.sealed_over {
                    // A `v3` correction: its cells over the card its chain sealed it over.
                    Some(base) => {
                        let Some(base_card) = usize::try_from(base.seq.get())
                            .ok()
                            .and_then(|i| cards.get(i))
                        else {
                            tracing::error!(
                                node,
                                node_seq = record.node_seq,
                                "a journalled rate correction names a base entry its chain does \
                                 not hold; it is not migrated"
                            );
                            continue;
                        };
                        crate::root::kernel::cells_onto(
                            base_card,
                            &cells,
                            Some(amendment.sealed_fee),
                        )
                    }
                    // A `v1`/`v2` correction: the cells and fee were the whole card it sealed.
                    None => crate::root::kernel::cells_onto(
                        &CardFields {
                            rate_card: Some(BTreeMap::new()),
                            ..CardFields::default()
                        },
                        &cells,
                        Some(amendment.sealed_fee),
                    ),
                };
                history.append(CardEntryDraft {
                    effective_from: amendment.effective_from,
                    effective_until: amendment.effective_until,
                    card: rate_card_of(&card),
                    appended_at: amendment.amended_at_ms,
                    author: Author::Amend {
                        reason_hash: amendment.reason_hash,
                    },
                });
                cards.push(card.clone());
                out.push(StoredEntry {
                    key: key(amendment.amended_at_ms),
                    effective_from: amendment.effective_from,
                    effective_until: amendment.effective_until,
                    appended_at: amendment.amended_at_ms,
                    author: EntryAuthor::Migrated {
                        node: *node,
                        node_seq: record.node_seq,
                        opening: false,
                        reason: Some(hex::encode(amendment.reason_hash)),
                    },
                    actor: "migration".to_string(),
                    base: None,
                    writer,
                    set_fields: Vec::new(),
                    card,
                    correction: None,
                });
            }
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
