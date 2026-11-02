// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub use super::auth_bindings;

use std::sync::{Arc, LazyLock, Mutex};

use busbar_contract::caps::{Admittance, Grant, Hold, PrincipalId};
use busbar_kernel::inflight::ArrivalDoor;

#[must_use]
pub fn new_kernel() -> busbar_kernel::teller::Kernel {
    busbar_kernel::teller::Kernel::new()
}

#[must_use]
pub fn new_registration() -> busbar_kernel::Registration {
    busbar_kernel::Registration::new()
}

/// A HISTORY PINNED BY ONE READER: the `Arc` it took at admission, and the snapshot it took with it.
///
/// The two travel together because neither is the pin on its own. The `Arc` alone would let a reader
/// see entries appended after it was admitted — an apply landing mid-body would reprice a request
/// halfway through, which is the exact hazard the pin exists to prevent. The seq alone would name a
/// snapshot of a history the reader no longer holds. Held as a pair, `view()` answers the same
/// entries for this reader's whole life however many applies land behind it.
///
/// `HistoryView` is a borrow, so it cannot be the thing that is stored; it is spelled out of this
/// pair on demand, which costs nothing — a slice and a number.
#[derive(Clone, Debug)]
pub struct PinnedHistory {
    history: Arc<busbar_kernel_ledger::cost::History>,
    at: busbar_kernel_ledger::cost::HistorySeq,
}

impl PinnedHistory {
    #[must_use]
    pub fn view(&self) -> busbar_kernel_ledger::cost::HistoryView<'_> {
        self.history.snapshot(self.at)
    }

    #[must_use]
    pub fn view_at(
        &self,
        at: busbar_kernel_ledger::cost::HistorySeq,
    ) -> busbar_kernel_ledger::cost::HistoryView<'_> {
        self.history.snapshot(at.min(self.at))
    }

    #[must_use]
    pub fn seq(&self) -> busbar_kernel_ledger::cost::HistorySeq {
        self.at
    }

    #[cfg(test)]
    #[must_use]
    pub fn for_test(
        history: Arc<busbar_kernel_ledger::cost::History>,
        at: busbar_kernel_ledger::cost::HistorySeq,
    ) -> Self {
        PinnedHistory { history, at }
    }

    #[cfg(test)]
    #[must_use]
    pub fn for_test_at(other: &PinnedHistory, at: busbar_kernel_ledger::cost::HistorySeq) -> Self {
        PinnedHistory {
            history: Arc::clone(&other.history),
            at,
        }
    }
}

/// THE PROCESS'S ONE RATE-CARD HISTORY, and it lives in the root because a rate is a statement about
/// a deployment rather than about a plane. A plane reports what a unit consumed; what those
/// quantities are worth is read here, off the same configured figures the engine's own spend
/// projection derives from.
///
/// APPEND-ONLY, not swap-in-place. The engine rebuilds its projection's rates on every config apply
/// and reload; the root answers by APPENDING a dated entry that prices what happens after it. The
/// entry before it is not touched, not closed and not deleted — which is the whole design: a booked
/// line is never rewritten, so a posting that already happened goes on resolving to the card it was
/// earned under however many times an operator edits a price. Replacing the card, as this holder did
/// before, silently re-priced every past posting on the next read.
///
/// PINNED BY THE READER, not read twice. A unit takes its [`PinnedHistory`] at ADMISSION and prices
/// its whole life against that one snapshot, including the accrual that lands after its body has
/// drained. That is what makes the pricing a promise rather than a race: a request that opened
/// before an apply is billed on the history it was admitted under, and an apply landing mid-body
/// cannot reprice a request halfway through. The next admission takes the new head.
#[derive(Default)]
pub struct RootHistory {
    /// `None` until the boot resolution raises the rate-apply seam. Absent, a report is not priced
    /// and nothing is posted — the honest answer for a build that has read no configuration yet,
    /// rather than a fallback card whose figures no operator wrote.
    history: arc_swap::ArcSwapOption<busbar_kernel_ledger::cost::History>,
    /// **THE ROOT'S OWN COUNT OF CONFIG RESOLUTIONS**, and that count is what an entry records as
    /// its policy epoch.
    ///
    /// The rate-apply seam carries the figures and nothing else — no epoch, by design
    /// (`crates/busbar-substrate/src/rate_apply.rs:14`) — so there is no engine number to copy here
    /// and inventing one that looked like the engine's would be worse than counting honestly. The
    /// boot resolution is epoch 0 and each apply after it is the next, which is a true statement
    /// about which generation of the deployment's configuration produced the entry. The day the seam
    /// carries the engine's own epoch, this counter is what it replaces.
    resolutions: std::sync::atomic::AtomicU64,
    /// **WHERE AN APPLIED CARD IS MADE DURABLE** (#79, OWNER RULING Q14 "date everything"). A
    /// history that lives only in memory is rebuilt at the next boot as the boot card from instant
    /// zero, and every posting a restart replays is then priced at a card that was not in force when
    /// it arrived. So every config-applied card is journalled on the node's one book with its
    /// `effective_from`, and a boot rebuilds the history from the chain before it rebuilds the book.
    /// Off — the default, and every holder but the one a production boot arms — journals nothing.
    journal: Mutex<CardJournal>,
    /// One append at a time — a config apply or a signed correction — so an entry's number on the
    /// history and its record's position on the chain are the same order.
    applying: Mutex<()>,
    /// The form of the config card in force, as the journal holds it.
    in_force: Mutex<Option<CardForm>>,
    /// **THE FLEET-SHARED HISTORY IN THE STORE** (MONEY-DESIGN section 3a): set by the production boot
    /// before its book opens ([`Self::keep_in_store`]). Once it is loaded nothing is journalled,
    /// and every change of the configured card appends an entry to it.
    store: std::sync::OnceLock<Arc<crate::root::card_history::CardStore>>,
    /// The card the boot's configuration resolved: the history's opening entry, or the boot's own
    /// change, once the history is loaded.
    boot_card: Mutex<Option<busbar_kernel::config::card::CardFields>>,
}

/// Where a holder's applied cards go (see [`RootHistory::arm_journal`]).
#[derive(Default)]
enum CardJournal {
    /// Nothing is journalled: a build with no root ledger, a test's holder, or a node with no data
    /// directory — the previous release's no-persistence shape, whose history is the boot card.
    #[default]
    Off,
    /// Armed at boot, before the book exists: applies are held until the boot's book rebuilds the
    /// history from its chain ([`RootHistory::restore`]).
    Armed(Vec<CardApplied>),
    /// The history was rebuilt from the chain and the boot's cards journalled; the book's shared
    /// handle is not bound yet ([`RootHistory::bind_journal`]), so an apply has no journal to go on
    /// and is refused ([`CardRefused::Unbound`]).
    Restored,
    /// Every apply goes on this book's journal as it lands.
    Bound {
        book: Arc<Mutex<crate::root::durability::Durability>>,
        token: Grant<busbar_contract::caps::DurableWrite>,
    },
}

/// Why the boot's rebuild of the dated history refused the boot.
#[derive(Debug)]
pub enum CardBootError {
    /// The journal could not make one of the boot's cards durable.
    Lost(busbar_contract::caps::DurabilityLost),
    /// The store would not read the history back or take the opening entry.
    Store(String),
}

impl From<busbar_contract::caps::DurabilityLost> for CardBootError {
    fn from(lost: busbar_contract::caps::DurabilityLost) -> Self {
        CardBootError::Lost(lost)
    }
}

impl std::fmt::Display for CardBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardBootError::Lost(lost) => write!(
                f,
                "the journal could not make the boot's rate card durable at step {}",
                lost.step().as_str()
            ),
            CardBootError::Store(why) => f.write_str(why),
        }
    }
}

/// WHY A CONFIG CARD APPLY WAS REFUSED: the card was not made durable, so the card in force is the
/// one that was (MONEY-AUDIT D-6).
#[derive(Debug)]
pub enum CardRefused {
    /// The journal could not make the applied card durable, and the card is IN DOUBT: the journal
    /// chained its record before the log was asked to take it, and the log retained the refused
    /// batch and offers it again, in order, on the next append (`busbar-kernel-wal`
    /// `Journal::append`, `Wal::append_batch`). So the record may yet land, and the holder put the
    /// card in force back on the journal behind it at the same instant ([`RootHistory::withdraw`]).
    Lost(busbar_contract::caps::DurabilityLost),
    /// The log neither holds nor owes the card, so the record can never land: nothing is published
    /// and nothing is put back — the node fails closed. Every arm of `Wal::append_batch` retains
    /// the batch it was handed, a failed roll onto a fresh segment included (kernel-wal finding 4),
    /// so a log that keeps that rule never answers this; it is the answer should one not.
    Dropped(busbar_contract::caps::DurabilityLost),
    /// The boot's book has rebuilt the history but its handle is not bound yet: there is no journal
    /// the card could go on.
    Unbound,
    /// The history is Store-owned. Legacy raw-rate notifications cannot append another card;
    /// generation transactions use the confirmed preparation seam.
    InStore,
}

impl std::fmt::Debug for RootHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootHistory").finish_non_exhaustive()
    }
}

impl RootHistory {
    #[must_use]
    pub fn pin(&self) -> Option<PinnedHistory> {
        let history = match self.card_store() {
            Some(store) => store.node_history()?,
            None => self.history()?,
        };
        let at = history.head()?;
        Some(PinnedHistory { history, at })
    }

    #[must_use]
    pub fn history(&self) -> Option<Arc<busbar_kernel_ledger::cost::History>> {
        match self.store.get() {
            Some(store) if store.is_loaded() => store.history(),
            Some(_) => None,
            None => self.history.load_full(),
        }
    }

    pub fn keep_in_store(
        &self,
        calls: Arc<dyn busbar_contract::store_calls::StoreCalls>,
        node: u64,
    ) {
        let _ = self
            .store
            .set(crate::root::card_history::CardStore::new(calls, node));
    }

    #[must_use]
    pub fn card_store(&self) -> Option<&Arc<crate::root::card_history::CardStore>> {
        self.store.get().filter(|s| s.is_loaded())
    }

    #[must_use]
    pub fn keeps_store(&self) -> bool {
        self.store.get().is_some()
    }

    #[must_use]
    pub fn pending_refusal(&self) -> Option<String> {
        self.card_store().and_then(|s| s.pending_refusal())
    }

    pub fn card_applied(&self, card: &busbar_kernel::config::card::CardFields, origin: &str) {
        match self.card_store() {
            Some(store) => {
                store.apply(card, origin);
            }
            None => {
                let mut boot = self.boot_card.lock().unwrap_or_else(|p| p.into_inner());
                if boot.is_none() {
                    *boot = Some(card.clone());
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn boot_in_store(
        &self,
        own: Option<&[busbar_kernel_wal::JournalRecord]>,
    ) -> Result<(), String> {
        let store = self.store.get().ok_or("no store kept")?;
        self.boot_store(store, own)
    }

    fn boot_store(
        &self,
        store: &Arc<crate::root::card_history::CardStore>,
        own: Option<&[busbar_kernel_wal::JournalRecord]>,
    ) -> Result<(), String> {
        let mut chains: Vec<crate::root::card_history::Chain> = Vec::new();
        if let Some(own) = own {
            chains.push((store.node(), own.to_vec()));
        }
        match crate::root::durability::stored_chains(store.calls().as_ref(), store.node()) {
            Ok(others) => chains.extend(others),
            Err(why) => tracing::warn!(
                "other nodes' journals could not be read for the rate-card migration: {why}"
            ),
        }
        let migrated = crate::root::card_history::migrated(&chains, store.node());

        let Some(card) = self
            .boot_card
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        else {
            tracing::error!(
                "the boot raised no rate card before its book opened; the rate-card history in the \
                 store is not opened with an empty one"
            );
            return Ok(());
        };
        store.boot(&card, &format!("boot of node {}", store.node()), migrated)
    }

    pub fn apply(
        &self,
        card: busbar_kernel_ledger::cost::RateCard,
        now_ms: u64,
    ) -> busbar_kernel_ledger::cost::HistorySeq {
        let _one_at_a_time = self.applying.lock().unwrap_or_else(|p| p.into_inner());
        let policy_epoch = self
            .resolutions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.append_config(card, now_ms, policy_epoch)
    }

    fn effective_from_for(&self, now_ms: u64) -> u64 {
        match self.history.load().as_deref() {
            Some(history) if !history.is_empty() => now_ms,
            _ => 0,
        }
    }

    fn append_config(
        &self,
        card: busbar_kernel_ledger::cost::RateCard,
        now_ms: u64,
        policy_epoch: u64,
    ) -> busbar_kernel_ledger::cost::HistorySeq {
        let mut appended = busbar_kernel_ledger::cost::HistorySeq::OPENING;
        self.history.rcu(|current| {
            let mut next = match current {
                Some(history) => busbar_kernel_ledger::cost::History::clone(history),
                None => busbar_kernel_ledger::cost::History::new(),
            };
            let effective_from = if next.is_empty() { 0 } else { now_ms };
            let seq = next.append(busbar_kernel_ledger::cost::CardEntryDraft {
                effective_from,
                effective_until: None,
                card: card.clone(),
                appended_at: now_ms,
                author: busbar_kernel_ledger::cost::Author::Config { policy_epoch },
            });

            appended = seq;
            Some(Arc::new(next))
        });
        appended
    }

    pub fn apply_rates(
        &self,
        rates: &busbar_kernel::rate_apply::RawRates<'_>,
        now_ms: u64,
    ) -> Result<busbar_kernel_ledger::cost::HistorySeq, CardRefused> {
        let _one_at_a_time = self.applying.lock().unwrap_or_else(|p| p.into_inner());
        register_classes(rates);

        if self.store.get().is_some() {
            return Err(CardRefused::InStore);
        }
        let card = card_from_raw(rates);
        let form = CardForm::of(rates, &card);

        let policy_epoch = self.resolutions.load(std::sync::atomic::Ordering::Relaxed);
        self.journal_or_withdraw(
            CardApplied {
                effective_from: self.effective_from_for(now_ms),
                appended_at: now_ms,
                policy_epoch,
                form: form.clone(),
            },
            now_ms,
        )?;
        *self.in_force.lock().unwrap_or_else(|p| p.into_inner()) = Some(form);
        Ok(self.append_config(card, now_ms, policy_epoch))
    }

    fn spend_epoch(&self, policy_epoch: u64) {
        self.resolutions.fetch_max(
            policy_epoch.saturating_add(1),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn journal_or_withdraw(&self, applied: CardApplied, _now_ms: u64) -> Result<(), CardRefused> {
        match self.journal_applied(applied.clone()) {
            Ok(()) => {
                self.spend_epoch(applied.policy_epoch);
                Ok(())
            }
            Err(CardRefused::Unbound) => Err(CardRefused::Unbound),
            Err(CardRefused::Dropped(lost)) => {
                self.spend_epoch(applied.policy_epoch);
                Err(CardRefused::Dropped(lost))
            }
            Err(CardRefused::Lost(lost)) => {
                self.spend_epoch(applied.policy_epoch);
                Err(CardRefused::Lost(lost))
            }
            Err(CardRefused::InStore) => Err(CardRefused::InStore),
        }
    }

    pub fn arm_journal(&self) {
        let mut journal = self.journal.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(*journal, CardJournal::Off) {
            *journal = CardJournal::Armed(Vec::new());
        }
    }

    pub(crate) fn disarm_journal(&self) {
        *self.journal.lock().unwrap_or_else(|p| p.into_inner()) = CardJournal::Off;
    }

    fn journal_applied(&self, applied: CardApplied) -> Result<(), CardRefused> {
        let mut journal = self.journal.lock().unwrap_or_else(|p| p.into_inner());
        match &mut *journal {
            CardJournal::Off => Ok(()),
            CardJournal::Armed(held) => {
                held.push(applied);
                Ok(())
            }
            CardJournal::Restored => Err(CardRefused::Unbound),
            CardJournal::Bound { book, token } => {
                let mut durability = book.lock().unwrap_or_else(|p| p.into_inner());
                journal_card(&mut durability, &applied, token)
                    .map(|_| ())
                    .map_err(|lost| refusal_of(&durability, lost))
            }
        }
    }

    pub(crate) fn restore(
        journalled: Vec<JournalledCard>,
        held: Vec<CardApplied>,
    ) -> RestoredHistory {
        use busbar_kernel_ledger::cost::{CardEntryDraft, History};
        let mut refused: Vec<CorrectionRefused> = Vec::new();
        let mut opening: Option<CardEntryDraft> = None;
        let mut rest: Vec<JournalledCard> = Vec::new();
        let mut newest: Option<CardForm> = None;
        let mut next_epoch = 0u64;
        for card in journalled {
            match card {
                JournalledCard::Applied(applied) => {
                    next_epoch = next_epoch.max(applied.policy_epoch.saturating_add(1));
                    newest = Some(applied.form.clone());
                    if applied.effective_from == 0 && opening.is_none() {
                        opening = Some(applied.draft());
                    } else {
                        rest.push(JournalledCard::Applied(applied));
                    }
                }
                other => rest.push(other),
            }
        }
        let mut write = Vec::new();
        for mut applied in held {
            if opening.is_none() {
                applied.effective_from = 0;
                opening = Some(applied.draft());
            } else if newest.as_ref() == Some(&applied.form) {
                continue;
            } else {
                applied.effective_from = applied.appended_at;
                applied.policy_epoch = next_epoch;
                next_epoch = next_epoch.saturating_add(1);
                rest.push(JournalledCard::Applied(applied.clone()));
            }
            newest = Some(applied.form.clone());
            write.push(applied);
        }
        let mut history = History::new();
        if let Some(opening) = opening {
            history.append(opening);
        }
        for card in rest {
            let draft = match card {
                JournalledCard::Applied(applied) => applied.draft(),
                JournalledCard::Amended(draft) => draft,

                JournalledCard::Corrected(correction, sealed_over) => {
                    match correction.rebuild_over(history.current(), sealed_over) {
                        Ok(draft) => draft,
                        Err(cause) => {
                            let finding = CorrectionRefused {
                                effective_from: correction.effective_from,
                                effective_until: correction.effective_until,
                                appended_at: correction.appended_at,
                                sealed_over,
                                cause,
                            };
                            tracing::error!("{finding}");
                            refused.push(finding);
                            continue;
                        }
                    }
                }
            };
            history.append(draft);
        }
        RestoredHistory {
            history,
            write,
            next_epoch,
            newest,
            refused,
        }
    }

    pub(crate) fn rebuild_from_chain(
        &'static self,
        durability: &mut crate::root::durability::Durability,
        records: Option<&[busbar_kernel_wal::JournalRecord]>,
    ) -> Result<Vec<CorrectionRefused>, CardBootError> {
        if let Some(store) = self.store.get() {
            *self.journal.lock().unwrap_or_else(|p| p.into_inner()) = CardJournal::Off;
            self.boot_store(store, records)
                .map_err(CardBootError::Store)?;
            durability.cards_from = Some(self);
            return Ok(Vec::new());
        }
        let Some(records) = records else {
            self.disarm_journal();
            return Ok(Vec::new());
        };
        let mut journal = self.journal.lock().unwrap_or_else(|p| p.into_inner());
        let CardJournal::Armed(held) = &mut *journal else {
            return Ok(Vec::new());
        };
        let RestoredHistory {
            history,
            write,
            next_epoch,
            newest,
            refused,
        } = Self::restore(journalled_cards(records), std::mem::take(held));
        let token = new_kernel().durability_token();
        for applied in &write {
            journal_card(durability, applied, &token)?;
        }
        if !history.is_empty() {
            self.history.store(Some(Arc::new(history)));
        }
        self.resolutions
            .fetch_max(next_epoch, std::sync::atomic::Ordering::Relaxed);
        *self.in_force.lock().unwrap_or_else(|p| p.into_inner()) = newest;
        *journal = CardJournal::Restored;
        durability.cards_from = Some(self);
        Ok(refused)
    }

    pub fn bind_journal(&self, book: &Arc<Mutex<crate::root::durability::Durability>>) {
        if !matches!(
            *self.journal.lock().unwrap_or_else(|p| p.into_inner()),
            CardJournal::Restored
        ) {
            return;
        }
        let ours = book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cards_from
            .is_some_and(|holder| std::ptr::eq(holder, self));
        if !ours {
            return;
        }
        let mut journal = self.journal.lock().unwrap_or_else(|p| p.into_inner());
        if !matches!(*journal, CardJournal::Restored) {
            return;
        }
        *journal = CardJournal::Bound {
            book: Arc::clone(book),
            token: new_kernel().durability_token(),
        };
    }

    pub fn amend<E>(
        &self,
        correction: &Correction,
        seal: impl FnOnce(&busbar_kernel_ledger::cost::RateCard, CorrectionBase) -> Result<(), E>,
    ) -> Result<busbar_kernel_ledger::cost::HistorySeq, AmendRefused<E>> {
        self.amend_by(correction, "admin", seal)
    }

    pub fn amend_by<E>(
        &self,
        correction: &Correction,
        actor: &str,
        seal: impl FnOnce(&busbar_kernel_ledger::cost::RateCard, CorrectionBase) -> Result<(), E>,
    ) -> Result<busbar_kernel_ledger::cost::HistorySeq, AmendRefused<E>> {
        let store = self.card_store();

        let _one_at_a_time = store
            .is_none()
            .then(|| self.applying.lock().unwrap_or_else(|p| p.into_inner()));
        let current = self.history().ok_or(AmendRefused::NoHistory)?;

        if let Some(cut) = current.current().correction_cut(
            correction.effective_from,
            correction.effective_until,
            correction.appended_at.saturating_add(1_000),
            busbar_kernel::governance::SECS_PER_DAY.saturating_mul(1_000),
        ) {
            return Err(AmendRefused::CutsRow(cut));
        }
        let (base, draft) = correction
            .draft_over(current.current())
            .ok_or(AmendRefused::NoSoleCard)?;
        let store_base = if let Some(store) = store {
            let key = current
                .current()
                .entry_at(correction.effective_from)
                .ok_or(AmendRefused::NoSoleCard)?
                .key();
            Some(store.entry(&key).ok_or(AmendRefused::NoSoleCard)?)
        } else {
            None
        };
        seal(&draft.card, base).map_err(AmendRefused::Seal)?;

        if let Some(store) = store {
            let until = correction
                .effective_until
                .ok_or_else(|| AmendRefused::Store("an amend must name its end".to_string()))?;
            let original = store_base.ok_or(AmendRefused::NoSoleCard)?;
            let base_card = original.card;
            let cells: Vec<(String, String, u64)> = correction
                .cells
                .iter()
                .map(|(cell, nanos)| (cell.lane.clone(), cell.class.clone(), *nanos))
                .collect();
            let card = cells_onto(&base_card, &cells, correction.fee);
            let reason_hash = match &correction.author {
                busbar_kernel_ledger::cost::Author::Amend { reason_hash } => *reason_hash,
                _ => [0; 32],
            };
            let key = store
                .amend_from(
                    (correction.effective_from, until),
                    Some(original.key),
                    card,
                    reason_hash,
                    actor,
                )
                .map_err(AmendRefused::Store)?;
            let history = store.history().ok_or(AmendRefused::NoHistory)?;
            return history
                .entry(&key)
                .map(busbar_kernel_ledger::cost::CardEntry::seq)
                .ok_or(AmendRefused::NoHistory);
        }

        let mut next = busbar_kernel_ledger::cost::History::clone(&current);
        let seq = next.append(draft);
        self.history.store(Some(Arc::new(next)));
        Ok(seq)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.history().as_ref().map_or(0, |h| h.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub static ROOT_CARD: LazyLock<RootHistory> = LazyLock::new(RootHistory::default);

pub(crate) fn card_from_config<'r>(
    rates: impl IntoIterator<Item = (&'r str, busbar_contract::billing::RawTierRates)>,
    flat_minor: i64,
    present: bool,
) -> busbar_kernel_ledger::cost::RateCard {
    let lanes = present.then(|| {
        rates.into_iter().map(|(lane, raw)| {
            (
                lane,
                busbar_kernel_ledger::cost::TierRates {
                    input: raw.input,
                    output: raw.output,
                    cache_read: raw.cache_read,
                    cache_write: raw.cache_write,
                },
            )
        })
    });

    busbar_kernel_ledger::cost::RateCard::from_config(lanes, flat_minor)
}

/// The root, answering the engine's rate-apply seam.
///
/// The whole of the wiring: the engine resolved the deployment's rates — at boot or on a live apply —
/// and the root builds a card from the SAME two configured figures and APPENDS it to the history,
/// dated at the instant the apply landed. One configuration, two readings, and the apply moves both
/// or neither.
///
/// The instant is read HERE, once, from the same wall clock a unit's arrival is read from, so the
/// entry's `effective_from` and a posting's `arrived_ms` are two readings of one scale and a
/// comparison between them means what it says.
#[derive(Debug, Clone, Copy)]
pub struct CardRepricer;

impl busbar_kernel::rate_apply::RateApply for CardRepricer {
    fn prepare_recovery(
        &self,
        card: &busbar_kernel::config::card::CardFields,
        rates: &busbar_kernel::rate_apply::RawRates<'_>,
        origin: &str,
    ) -> Result<Box<dyn busbar_kernel::rate_apply::PreparedRates>, String> {
        busbar_kernel::rate_apply::RateApply::prepare_recovery(&*ROOT_CARD, card, rates, origin)
    }

    fn prepare(
        &self,
        card: &busbar_kernel::config::card::CardFields,
        rates: &busbar_kernel::rate_apply::RawRates<'_>,
        origin: &str,
    ) -> Result<Box<dyn busbar_kernel::rate_apply::PreparedRates>, String> {
        busbar_kernel::rate_apply::RateApply::prepare(&*ROOT_CARD, card, rates, origin)
    }

    fn rates_applied(&self, rates: &busbar_kernel::rate_apply::RawRates<'_>) {
        match ROOT_CARD.apply_rates(rates, busbar_kernel::store::now_ms()) {
            Ok(_) | Err(CardRefused::InStore) => {}
            Err(refused) => tracing::error!(
                ?refused,
                "the journal did not take an applied rate card: the apply is refused and the card \
                 in force is unchanged"
            ),
        }
    }

    fn card_applied(&self, card: &busbar_kernel::config::card::CardFields, origin: &str) {
        ROOT_CARD.card_applied(card, origin);
    }
}

impl busbar_kernel::rate_apply::RateApply for RootHistory {
    fn prepare_recovery(
        &self,
        card: &busbar_kernel::config::card::CardFields,
        _rates: &busbar_kernel::rate_apply::RawRates<'_>,
        origin: &str,
    ) -> Result<Box<dyn busbar_kernel::rate_apply::PreparedRates>, String> {
        let store = self
            .store
            .get()
            .ok_or("rate recovery requires the configured Store")?;
        store
            .prepare_recovery(card, origin)
            .map(|prepared| Box::new(prepared) as Box<dyn busbar_kernel::rate_apply::PreparedRates>)
    }

    fn prepare(
        &self,
        card: &busbar_kernel::config::card::CardFields,
        _rates: &busbar_kernel::rate_apply::RawRates<'_>,
        origin: &str,
    ) -> Result<Box<dyn busbar_kernel::rate_apply::PreparedRates>, String> {
        let store = self
            .store
            .get()
            .ok_or("rate activation requires the configured Store; no rate-card Store is bound")?;
        store
            .prepare(card, origin)
            .map(|prepared| Box::new(prepared) as Box<dyn busbar_kernel::rate_apply::PreparedRates>)
    }

    fn rates_applied(&self, rates: &busbar_kernel::rate_apply::RawRates<'_>) {
        if let Err(refused) = self.apply_rates(rates, busbar_kernel::store::now_ms()) {
            tracing::error!(
                ?refused,
                "a legacy rate notification could not activate its rates"
            );
        }
    }

    fn card_applied(&self, card: &busbar_kernel::config::card::CardFields, origin: &str) {
        RootHistory::card_applied(self, card, origin);
    }
}

impl busbar_kernel::rate_apply::PreparedRates for crate::root::card_history::PreparedCard {
    fn confirm_activation(
        self: Box<Self>,
    ) -> Result<Box<dyn busbar_kernel::rate_apply::RateCommit>, String> {
        (*self)
            .confirm_activation()
            .map(|confirmed| Box::new(confirmed) as Box<dyn busbar_kernel::rate_apply::RateCommit>)
    }
}

impl busbar_kernel::rate_apply::RateCommit for crate::root::card_history::ConfirmedCard {
    fn commit(self: Box<Self>) {
        crate::root::card_history::ConfirmedCard::commit(*self);
    }
}

pub(crate) fn card_from_raw(
    rates: &busbar_kernel::rate_apply::RawRates<'_>,
) -> busbar_kernel_ledger::cost::RateCard {
    card_from_config(
        rates.lanes.iter().map(|(lane, r)| (lane.as_str(), *r)),
        rates.flat_minor,
        rates.present,
    )
    .with_unit_rates(rates.units.iter().map(|(lane, class, nanos)| {
        (
            busbar_kernel_ledger::cost::LaneClass::new(lane.as_str(), class.as_str()),
            *nanos,
        )
    }))
    .with_plane_fees(rates.plane_fees.iter().map(|(p, f)| (p.as_str(), *f)))
}

pub(crate) fn register_classes(rates: &busbar_kernel::rate_apply::RawRates<'_>) {
    let mut registration = new_registration();
    for class in busbar_contract::records::RESERVED_UNITS {
        let _ = registration.key(class);
    }

    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        for class in decl.billable_classes {
            let _ = registration.key(class.class);
        }
        for unit in decl.fee_units {
            let _ = registration.key(unit);
        }
    }
    for (_lane, class, _nanos) in rates.units {
        let _ = registration.key(class);
    }
}

pub const CARD_APPLIED_TAG: &str = "busbar/rate-card-applied/v1";

const RESERVED_CLASSES: [&str; 4] = [
    busbar_kernel_ledger::cost::CLASS_INPUT,
    busbar_kernel_ledger::cost::CLASS_OUTPUT,
    busbar_kernel_ledger::cost::CLASS_CACHE_READ,
    busbar_kernel_ledger::cost::CLASS_CACHE_WRITE,
];

/// **ONE APPLIED CARD, IN INTEGERS** — what the card priced, read off the card the apply built, so a
/// restart rebuilds the same card without a configured decimal ever crossing the journal (#44: the
/// float-to-integer conversion happens once, at the intake, and never again).
///
/// Every PLANE's card is in it (#47): its lanes are the plane-qualified keys, its presence is its
/// `"<plane>\u{1f}"` key, and its fees are its own. Two forms are equal exactly when they build the
/// same card — which is what lets a boot tell a restart that changed a price from one that did not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardForm {
    /// Whether a rate card was configured at all (absent: every class reads 0, the flat figure posts).
    present: bool,
    /// The flat per-request figure, clamped as the card holds it.
    flat: u64,
    /// Every configured lane key, in the deployment's order.
    lanes: Vec<String>,
    /// `(lane, reserved class, nano-units per unit)` for each configured lane's four reserved
    /// classes, as the card holds them; `None` is a cell the card could not represent (UNPRICED).
    cells: Vec<(String, String, Option<u64>)>,
    /// `(lane, open class, nano-units per unit)`, as configured (item 123).
    units: Vec<(String, String, u64)>,
    /// `(plane, per request, per session)`, clamped as the card holds them.
    planes: Vec<(String, u64, u64)>,
}

impl CardForm {
    #[must_use]
    pub fn of(
        rates: &busbar_kernel::rate_apply::RawRates<'_>,
        card: &busbar_kernel_ledger::cost::RateCard,
    ) -> Self {
        let lanes: Vec<String> = rates.lanes.iter().map(|(lane, _)| lane.clone()).collect();
        let cells = if rates.present {
            lanes
                .iter()
                .filter(|key| {
                    !busbar_kernel_ledger::cost::split_plane_lane(key)
                        .1
                        .is_empty()
                })
                .flat_map(|key| {
                    RESERVED_CLASSES.iter().map(move |class| {
                        let nanos = card
                            .lane_rates(key)
                            .filter(|rates| rates.class_priced(class))
                            .map(|rates| rates.nanos_per_unit(class));
                        (key.clone(), (*class).to_string(), nanos)
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let clamp = |figure: i64| u64::try_from(figure.max(0)).unwrap_or(0);
        CardForm {
            present: rates.present,
            flat: clamp(card.fee()),
            lanes,
            cells,
            units: rates.units.to_vec(),
            planes: rates
                .plane_fees
                .iter()
                .map(|(plane, fees)| {
                    (
                        plane.clone(),
                        clamp(fees.per_request),
                        clamp(fees.per_session),
                    )
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn card(&self) -> busbar_kernel_ledger::cost::RateCard {
        use busbar_kernel_ledger::cost::{LaneClass, PlaneFees, RateCard, TierRates};
        let unpriced: std::collections::BTreeSet<&str> = self
            .cells
            .iter()
            .filter(|(_, _, nanos)| nanos.is_none())
            .map(|(lane, _, _)| lane.as_str())
            .collect();
        let kept = |lane: &str| !unpriced.contains(lane);
        let figure = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        let base = if self.present {
            RateCard::from_config(
                Some(
                    self.lanes
                        .iter()
                        .filter(|lane| kept(lane))
                        .map(|lane| (lane.as_str(), TierRates::default())),
                ),
                figure(self.flat),
            )
        } else {
            RateCard::absent(figure(self.flat))
        };
        base.with_unit_rates(
            self.cells
                .iter()
                .filter_map(|(lane, class, nanos)| nanos.map(|n| (lane, class, n)))
                .chain(self.units.iter().map(|(lane, class, n)| (lane, class, *n)))
                .filter(|(lane, _, _)| kept(lane))
                .map(|(lane, class, n)| (LaneClass::new(lane.as_str(), class.as_str()), n)),
        )
        .with_plane_fees(self.planes.iter().map(|(plane, request, session)| {
            (
                plane.as_str(),
                PlaneFees {
                    per_request: figure(*request),
                    per_session: figure(*session),
                },
            )
        }))
    }
}

impl CardForm {
    #[must_use]
    pub fn to_fields(&self) -> busbar_kernel::config::card::CardFields {
        let unpriced: std::collections::BTreeSet<&str> = self
            .cells
            .iter()
            .filter(|(_, _, nanos)| nanos.is_none())
            .map(|(lane, _, _)| lane.as_str())
            .collect();
        let mut composed: std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> =
            std::collections::BTreeMap::new();
        if self.present {
            for lane in self.lanes.iter().filter(|l| !unpriced.contains(l.as_str())) {
                composed.entry(lane.clone()).or_default();
            }
        }
        let mut fields = busbar_kernel::config::card::CardFields::from_composed(
            self.present.then_some(&composed),
            i64::try_from(self.flat).unwrap_or(i64::MAX),
            self.planes
                .iter()
                .map(|(plane, request, session)| {
                    (
                        plane.clone(),
                        busbar_kernel_ledger::cost::PlaneFees {
                            per_request: i64::try_from(*request).unwrap_or(i64::MAX),
                            per_session: i64::try_from(*session).unwrap_or(i64::MAX),
                        },
                    )
                })
                .collect(),
        );
        let cells: Vec<(String, String, u64)> = self
            .cells
            .iter()
            .filter(|(lane, _, _)| !unpriced.contains(lane.as_str()))
            .filter_map(|(lane, class, nanos)| nanos.map(|n| (lane.clone(), class.clone(), n)))
            .chain(self.units.iter().cloned())
            .collect();
        fields = cells_onto(&fields, &cells, None);
        fields
    }
}

fn micro_of(nanos: u64) -> f64 {
    format!("{}.{:03}", nanos / 1000, nanos % 1000)
        .parse()
        .unwrap_or(0.0)
}

#[must_use]
pub(crate) fn cells_onto(
    base: &busbar_kernel::config::card::CardFields,
    cells: &[(String, String, u64)],
    fee: Option<i64>,
) -> busbar_kernel::config::card::CardFields {
    let mut composed = base.composed().unwrap_or_default();
    for (lane, class, nanos) in cells {
        let entry = composed.entry(lane.clone()).or_default();
        match class.as_str() {
            busbar_kernel_ledger::cost::CLASS_INPUT => entry.input_utok = micro_of(*nanos),
            busbar_kernel_ledger::cost::CLASS_OUTPUT => entry.output_utok = micro_of(*nanos),
            busbar_kernel_ledger::cost::CLASS_CACHE_READ => {
                entry.cache_read_utok = micro_of(*nanos)
            }
            busbar_kernel_ledger::cost::CLASS_CACHE_WRITE => {
                entry.cache_write_utok = micro_of(*nanos);
            }
            other => {
                let text = format!("{}.{:03}", nanos / 1000, nanos % 1000);
                if let Ok(rate) = busbar_kernel_ledger::cost::UnitRate::parse_micros(&text) {
                    entry.units.insert(other.to_string(), rate);
                }
            }
        }
    }
    let present =
        base.rate_card.is_some() || !base.plane_rate_cards.is_empty() || !cells.is_empty();
    busbar_kernel::config::card::CardFields::from_composed(
        present.then_some(&composed),
        fee.unwrap_or(base.per_request_fee),
        base.plane_fees.clone(),
    )
}

/// **ONE CONFIG APPLY, JOURNALLED**: the card and the instant it took effect from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardApplied {
    /// The first instant the entry prices, in wall-clock milliseconds: zero for the opening entry,
    /// the apply's own instant for every later one.
    pub effective_from: u64,
    /// When the apply landed, in wall-clock milliseconds.
    pub appended_at: u64,
    /// The configuration generation that produced it.
    pub policy_epoch: u64,
    /// The card.
    pub form: CardForm,
}

impl CardApplied {
    pub(crate) fn draft(&self) -> busbar_kernel_ledger::cost::CardEntryDraft {
        busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from: self.effective_from,
            effective_until: None,
            card: self.form.card(),
            appended_at: self.appended_at,
            author: busbar_kernel_ledger::cost::Author::Config {
                policy_epoch: self.policy_epoch,
            },
        }
    }

    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let form = &self.form;
        let mut body = busbar_kernel_wal::BodyWriter::new();
        body.text(CARD_APPLIED_TAG)
            .num(self.effective_from)
            .num(self.appended_at)
            .num(self.policy_epoch)
            .num(u64::from(form.present))
            .num(form.flat)
            .num(form.lanes.len() as u64);
        for lane in &form.lanes {
            body.text(lane);
        }
        body.num(form.cells.len() as u64);
        for (lane, class, nanos) in &form.cells {
            body.text(lane)
                .text(class)
                .num(u64::from(nanos.is_some()))
                .num(nanos.unwrap_or(0));
        }
        body.num(form.units.len() as u64);
        for (lane, class, nanos) in &form.units {
            body.text(lane).text(class).num(*nanos);
        }
        body.num(form.planes.len() as u64);
        for (plane, request, session) in &form.planes {
            body.text(plane).num(*request).num(*session);
        }
        body.finish()
    }

    #[must_use]
    pub fn from_body(bytes: &[u8]) -> Option<CardApplied> {
        let mut body = busbar_kernel_wal::BodyReader::new(bytes);
        if body.text()? != CARD_APPLIED_TAG {
            return None;
        }
        let effective_from = body.num()?;
        let appended_at = body.num()?;
        let policy_epoch = body.num()?;
        let present = match body.num()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let flat = body.num()?;
        let mut lanes = Vec::new();
        for _ in 0..body.num()? {
            lanes.push(body.text()?.to_string());
        }
        let mut cells = Vec::new();
        for _ in 0..body.num()? {
            let (lane, class) = (body.text()?.to_string(), body.text()?.to_string());
            let priced = body.num()?;
            let nanos = body.num()?;
            cells.push((lane, class, (priced == 1).then_some(nanos)));
        }
        let mut units = Vec::new();
        for _ in 0..body.num()? {
            units.push((
                body.text()?.to_string(),
                body.text()?.to_string(),
                body.num()?,
            ));
        }
        let mut planes = Vec::new();
        for _ in 0..body.num()? {
            planes.push((body.text()?.to_string(), body.num()?, body.num()?));
        }
        body.is_done().then_some(CardApplied {
            effective_from,
            appended_at,
            policy_epoch,
            form: CardForm {
                present,
                flat,
                lanes,
                cells,
                units,
                planes,
            },
        })
    }
}

fn journal_card(
    durability: &mut crate::root::durability::Durability,
    applied: &CardApplied,
    token: &Grant<busbar_contract::caps::DurableWrite>,
) -> Result<busbar_kernel_wal::JournalAck, busbar_contract::caps::DurabilityLost> {
    let entry =
        busbar_kernel_wal::Entry::new(busbar_kernel_wal::RecordClass::Policy, applied.body())
            .at(applied.appended_at / 1_000, 0);
    durability
        .journal
        .append(token, busbar_contract::caps::StepName::Route, &[entry])
}

fn refusal_of(
    durability: &crate::root::durability::Durability,
    lost: busbar_contract::caps::DurabilityLost,
) -> CardRefused {
    let journal = &durability.journal;
    let card = (journal.node(), journal.next_seq().saturating_sub(1));
    let log = journal.log();
    if log.holds(card.0, card.1) || log.owed().iter().any(|r| r.identity() == card) {
        CardRefused::Lost(lost)
    } else {
        CardRefused::Dropped(lost)
    }
}

pub(crate) enum JournalledCard {
    Applied(CardApplied),

    Amended(busbar_kernel_ledger::cost::CardEntryDraft),

    Corrected(Correction, CorrectionBase),
}

/// **A SIGNED CORRECTION, AS CELLS OVER THE CARD IN FORCE** (#79: a correction reprices exactly
/// its window and exactly the cells it names). The live verb and a restart's rebuild both turn it
/// into its history entry through [`Correction::draft_over`] alone, against the same history prefix
/// (the live append runs under the apply lock, so the chain's order is the history's), so the card
/// a restart rebuilds is the card the live node priced.
#[derive(Debug, Clone)]
pub struct Correction {
    /// Start of the corrected window, milliseconds, inclusive.
    pub effective_from: u64,
    /// End of the corrected window, milliseconds, exclusive; `None` is open-ended.
    pub effective_until: Option<u64>,
    /// When the correction was admitted, milliseconds.
    pub appended_at: u64,
    /// The signer and the digest of the reason.
    pub author: busbar_kernel_ledger::cost::Author,
    /// Every cell it names, at its corrected integer rate (a plane-qualified lane is that plane's).
    pub cells: Vec<(busbar_kernel_ledger::cost::LaneClass, u64)>,
    /// The flat fee it names, minor units; `None` keeps the fee in force.
    pub fee: Option<i64>,
}

impl Correction {
    #[must_use]
    pub fn draft_over(
        &self,
        view: busbar_kernel_ledger::cost::HistoryView<'_>,
    ) -> Option<(CorrectionBase, busbar_kernel_ledger::cost::CardEntryDraft)> {
        let base = view.sole_entry_over(self.effective_from, self.effective_until)?;
        let card = base
            .card()
            .corrected(self.cells.iter().cloned(), self.fee)?;
        Some((
            CorrectionBase {
                seq: base.seq(),
                card_digest: base.card().digest(),
            },
            busbar_kernel_ledger::cost::CardEntryDraft {
                effective_from: self.effective_from,
                effective_until: self.effective_until,
                card,
                appended_at: self.appended_at,
                author: self.author.clone(),
            },
        ))
    }

    pub fn rebuild_over(
        &self,
        view: busbar_kernel_ledger::cost::HistoryView<'_>,
        sealed_over: CorrectionBase,
    ) -> Result<busbar_kernel_ledger::cost::CardEntryDraft, BaseMismatch> {
        let held = u64::try_from(view.entries().len()).unwrap_or(u64::MAX);
        if held <= sealed_over.seq.get() {
            return Err(BaseMismatch::MissingBase);
        }
        let base = view
            .sole_entry_over(self.effective_from, self.effective_until)
            .ok_or(BaseMismatch::OtherBase(None))?;
        if base.seq() != sealed_over.seq {
            return Err(BaseMismatch::OtherBase(Some(base.seq())));
        }
        if base.card().digest() != sealed_over.card_digest {
            return Err(BaseMismatch::BaseDigest);
        }
        let (_, draft) = self.draft_over(view).ok_or(BaseMismatch::NoCardForCells)?;
        Ok(draft)
    }
}

/// **THE ENTRY A SIGNED CORRECTION WAS SEALED OVER** (#79): the entry's number on the history and
/// the digest of its card ([`busbar_kernel_ledger::cost::RateCard::digest`]), as the live append
/// resolved them. Every `v3` record carries it, written at amend time, and a restart rebuilds the
/// correction only over the entry at that number holding that card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrectionBase {
    /// The base entry's number.
    pub seq: busbar_kernel_ledger::cost::HistorySeq,
    /// The digest of the base entry's card.
    pub card_digest: [u8; 32],
}

/// **A JOURNALLED SIGNED CORRECTION THE REBUILD REFUSED** (#79): the history a restart rebuilt
/// does not hold, at the correction's place on the chain, the entry the correction was sealed
/// over. Rebuilding it over whatever card prices its window now would reprice the window at a card
/// no operator signed, so it is not rebuilt. The refusal is a named restart finding
/// ([`crate::root::durability::JournalDisagreement::CorrectionRefused`]), as a set-aside amendment
/// record or a quarantined segment is, and never only a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrectionRefused {
    /// Start of the refused correction's window, milliseconds.
    pub effective_from: u64,
    /// End of its window, milliseconds; `None` is open-ended.
    pub effective_until: Option<u64>,
    /// When it was admitted, milliseconds.
    pub appended_at: u64,
    /// The entry its record says it was sealed over.
    pub sealed_over: CorrectionBase,
    /// What the rebuilt history holds instead.
    pub cause: BaseMismatch,
}

/// How the rebuilt history fails a correction's [`CorrectionBase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseMismatch {
    /// The rebuilt history holds no entry at the base's number when the correction is reached: an
    /// entry the live node priced under never reached the chain ahead of the correction.
    MissingBase,
    /// The window resolves to another entry, or to no single one (`None`).
    OtherBase(Option<busbar_kernel_ledger::cost::HistorySeq>),
    /// The base entry is there, and holds a card other than the one the correction was sealed over.
    BaseDigest,
    /// The base matches, and a named cell still has no present card to land on.
    NoCardForCells,
}

impl std::fmt::Display for CorrectionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let window = match self.effective_until {
            Some(until) => format!("[{}, {until})", self.effective_from),
            None => format!("[{}, open)", self.effective_from),
        };
        let base = self.sealed_over.seq;
        write!(
            f,
            "the signed rate correction over {window}, admitted at {}, is REFUSED and not rebuilt: ",
            self.appended_at
        )?;
        match self.cause {
            BaseMismatch::MissingBase => write!(
                f,
                "the rebuilt history holds no entry {base}, the entry it was sealed over"
            ),
            BaseMismatch::OtherBase(Some(seq)) => write!(
                f,
                "its window resolves to entry {seq}, not entry {base}, the entry it was sealed over"
            ),
            BaseMismatch::OtherBase(None) => write!(
                f,
                "no single entry prices its window, and it was sealed over entry {base}"
            ),
            BaseMismatch::BaseDigest => write!(
                f,
                "entry {base} holds a card other than the one it was sealed over"
            ),
            BaseMismatch::NoCardForCells => write!(
                f,
                "a cell it names has no present card to land on over entry {base}"
            ),
        }
    }
}

/// Why [`RootHistory::amend`] appended nothing.
#[derive(Debug)]
pub enum AmendRefused<E> {
    /// No history yet: no opening entry a correction could out-rank.
    NoHistory,
    /// No single card prices the whole window, or a named cell has no present card to land on.
    NoSoleCard,
    /// The boundary that would cut inside a metering row (#32,
    /// [`busbar_kernel_ledger::cost::HistoryView::correction_cut`]).
    CutsRow(u64),
    /// The seal (the durable record written ahead of the append) refused.
    Seal(E),
    /// The store-kept history refused the entry (a pending entry, a far-future head, an open-ended
    /// amend, or the store's first-attempt refusal).
    Store(String),
}

pub(crate) struct RestoredHistory {
    pub(crate) history: busbar_kernel_ledger::cost::History,
    write: Vec<CardApplied>,
    next_epoch: u64,
    newest: Option<CardForm>,
    refused: Vec<CorrectionRefused>,
}

pub(crate) fn journalled_cards(
    records: &[busbar_kernel_wal::JournalRecord],
) -> Vec<JournalledCard> {
    records
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .filter_map(|r| {
            CardApplied::from_body(&r.body)
                .map(JournalledCard::Applied)
                .or_else(|| journalled_amendment(&r.body))
        })
        .collect()
}

pub(crate) fn journalled_cards_at(
    records: &[busbar_kernel_wal::JournalRecord],
) -> Vec<(u64, Vec<u8>, JournalledCard)> {
    records
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .filter_map(|r| {
            CardApplied::from_body(&r.body)
                .map(JournalledCard::Applied)
                .or_else(|| journalled_amendment(&r.body))
                .map(|card| (r.node_seq, r.body.clone(), card))
        })
        .collect()
}

#[cfg(feature = "root-admin")]
fn journalled_amendment(body: &[u8]) -> Option<JournalledCard> {
    let amendment = crate::root::units_admin::amendment_from_body(body)?;
    let author = busbar_kernel_ledger::cost::Author::Amend {
        reason_hash: amendment.reason_hash,
    };

    let cells = amendment.rates.iter().filter_map(|(lane, class, nanos)| {
        nanos.map(|nanos| {
            (
                busbar_kernel_ledger::cost::LaneClass::new(lane.as_str(), class.as_str()),
                nanos,
            )
        })
    });
    if let Some(sealed_over) = amendment.sealed_over {
        return Some(JournalledCard::Corrected(
            Correction {
                effective_from: amendment.effective_from,
                effective_until: amendment.effective_until,
                appended_at: amendment.amended_at_ms,
                author,
                cells: cells.collect(),
                fee: Some(amendment.sealed_fee),
            },
            sealed_over,
        ));
    }
    Some(JournalledCard::Amended(
        busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from: amendment.effective_from,
            effective_until: amendment.effective_until,
            card: busbar_kernel_ledger::cost::RateCard::from_nano_rates(
                cells,
                amendment.sealed_fee,
            ),
            appended_at: amendment.amended_at_ms,
            author,
        },
    ))
}

#[cfg(not(feature = "root-admin"))]
fn journalled_amendment(_body: &[u8]) -> Option<JournalledCard> {
    None
}

impl busbar_kernel::rate_apply::RateEpoch for CardRepricer {
    fn era_at(&self, at_ms: u64) -> busbar_kernel_ledger::cost::RawRateEra {
        busbar_kernel::rate_apply::RateEpoch::era_at(&*ROOT_CARD, at_ms)
    }

    fn effective_from_at(&self, at_ms: u64) -> u64 {
        busbar_kernel::rate_apply::RateEpoch::effective_from_at(&*ROOT_CARD, at_ms)
    }

    fn history(&self) -> Option<Arc<busbar_kernel_ledger::cost::History>> {
        ROOT_CARD.history()
    }
}

impl busbar_kernel::rate_apply::RateEpoch for RootHistory {
    fn era_at(&self, at_ms: u64) -> busbar_kernel_ledger::cost::RawRateEra {
        let history = self
            .card_store()
            .and_then(|store| store.node_history())
            .or_else(|| self.history());
        let Some(history) = history else {
            return busbar_kernel_ledger::cost::RawRateEra::legacy(0);
        };
        history.current().entry_at(at_ms).map_or_else(
            || busbar_kernel_ledger::cost::RawRateEra::legacy(0),
            |entry| {
                busbar_kernel_ledger::cost::RawRateEra::entry(
                    entry.effective_from(),
                    entry.key().id(),
                )
            },
        )
    }

    fn effective_from_at(&self, at_ms: u64) -> u64 {
        busbar_kernel::rate_apply::RateEpoch::era_at(self, at_ms).effective_from
    }

    fn history(&self) -> Option<Arc<busbar_kernel_ledger::cost::History>> {
        RootHistory::history(self)
    }
}

pub fn install_card_repricer() {
    ROOT_CARD.arm_journal();
}

/// The admission unit, standing at the in-flight table's arrival door.
///
/// The kernel's in-flight table takes a `&dyn ArrivalDoor` and, until this existed, the only
/// implementor in the tree was a test double — which made "a hold cannot exist without the unit's
/// own token" true everywhere except in the one place that mattered. The binding is a delegation
/// and nothing else: the kernel's door exports the constructor, and a root that computed
/// anything here would be a root deciding what a unit is for.
#[derive(Debug, Default, Clone, Copy)]
pub struct AdmissionDoor;

impl ArrivalDoor for AdmissionDoor {
    fn arrival_hold(&self, principal: PrincipalId, token: &Grant<Admittance>) -> Hold {
        busbar_kernel::door::arrival_hold(principal, token)
    }
}

pub type VerbStoreHandle = Option<Arc<dyn busbar_kernel_seams::verb_store::Store + Send + Sync>>;

pub struct ProductionUnits {
    pub auth_bindings: auth_bindings::AuthBindings,

    pub arrival_door: AdmissionDoor,

    pub durability: Arc<Mutex<crate::root::durability::Durability>>,

    #[cfg(feature = "root-admin")]
    pub admin: crate::root::units_admin::AdminBinding,

    pub store: VerbStoreHandle,

    pub admin_token: busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
}

impl ProductionUnits {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        kernel: &busbar_kernel::teller::Kernel,
        durability: crate::root::durability::Durability,
        #[cfg(feature = "root-admin")] admin: crate::root::units_admin::AdminBinding,
        store: VerbStoreHandle,
    ) -> Self {
        ProductionUnits::new_sharing(
            kernel,
            Arc::new(Mutex::new(durability)),
            #[cfg(feature = "root-admin")]
            admin,
            store,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new_sharing(
        kernel: &busbar_kernel::teller::Kernel,
        durability: Arc<Mutex<crate::root::durability::Durability>>,
        #[cfg(feature = "root-admin")] admin: crate::root::units_admin::AdminBinding,
        store: VerbStoreHandle,
    ) -> Self {
        ProductionUnits {
            auth_bindings: auth_bindings::AuthBindings::without_directory(),
            arrival_door: AdmissionDoor,
            durability,
            #[cfg(feature = "root-admin")]
            admin,
            store,

            admin_token: kernel.admin_token(),
        }
    }

    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only(
        dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>,
        door: crate::root::units_admin::AdminDoorFn,
    ) -> Self {
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");

        ProductionUnits::admin_only_sharing(dispatch, door, Arc::new(Mutex::new(durability)), None)
    }

    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_over_book(
        dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>,
        door: crate::root::units_admin::AdminDoorFn,
        book: &crate::root::durability::NodeBook,
    ) -> Self {
        ProductionUnits::admin_only_sharing(
            dispatch,
            door,
            Arc::clone(&book.durability),
            book.verb_store.clone(),
        )
    }

    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only_sharing(
        dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>,
        door: crate::root::units_admin::AdminDoorFn,
        durability: Arc<Mutex<crate::root::durability::Durability>>,
        store: VerbStoreHandle,
    ) -> Self {
        let kernel = new_kernel();
        let mut units = ProductionUnits::new_sharing(
            &kernel,
            Arc::clone(&durability),
            crate::root::units_admin::AdminBinding::new(dispatch, door),
            store,
        );

        ROOT_CARD.bind_journal(&durability);
        units.admin.amendments = Some(Arc::new(crate::root::units_admin::AmendmentJournal::new(
            Arc::clone(&durability),
            kernel.durability_token(),
        )));
        units.admin.audit = Some(Arc::new(crate::root::units_admin::NodeAudit::new(
            durability,
        )));
        units
    }

    #[must_use]
    pub fn with_auth_bindings(mut self, bindings: auth_bindings::AuthBindings) -> Self {
        self.auth_bindings = bindings;
        self
    }
}

#[cfg(test)]
#[path = "tests/kernel.rs"]
mod tests;
