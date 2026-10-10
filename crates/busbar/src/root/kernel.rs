// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The authority, the interner and the one implementor of the kernel's `Units` trait.
//!
//! Three things the design draws have, until now, existed in the tree only as test doubles: an
//! implementor of `busbar_kernel::teller::Units`, an implementor of
//! `busbar_kernel::inflight::ArrivalDoor`, and a live `busbar_contract::Registration`. This file is
//! where the production ones live, and it is the only place in the workspace entitled to name all
//! fourteen units at once.
//!
//! ## Fourteen units, twelve methods
//!
//! The mapping is not one-to-one and never was. Two of the twelve methods reach more than one unit,
//! three reach none, and five units are never reached through `Units` at all:
//!
//! | `Units` method | unit(s) reached |
//! |---|---|
//! | `arrival` | none — the kernel's own gate over the configured budgets |
//! | `decode` | the claimed plane, not a unit |
//! | `authenticate` | the registered plane's step, through `UnitsRegistry` |
//! | `verify` | the trust unit, reading the breaker unit's view |
//! | `approve` | the scope unit |
//! | `admit` | the admission unit, priced by the cost unit |
//! | `route` | the egress unit, over the breaker and egress-auth units |
//! | `meter` | the usage unit |
//! | `audit` | the audit unit, then the ledger unit |
//! | `audit_refused` | the audit unit — the door a unit that never passed Admit leaves through |
//! | `encode` | the claimed plane, not a unit |
//! | `evidence` | the usage and cost units, read once by the exit path |
//!
//! Reached elsewhere, and bound by the root rather than by a step: the WAL unit sits under the
//! ledger on the durability path; the verbs unit is a destination at Route, holding the admin
//! token; connection security (TLS) is core's, built once per listener outside the loop entirely; the
//! egress-auth unit is called from inside Route by the egress unit; and the breaker unit is
//! consulted at Verify and recorded at Route without ever being a step of its own.
//!
//! ## One plane at a time
//!
//! The bodies arrive one plane at a time — admin first, then the other three, then the reference
//! plane last — and the first of them has landed. Every method therefore begins with the same
//! question: is this unit one the admin bindings opened? If it is, the step runs against the units
//! that plane composes over. If it is not, the step REFUSES, naming the step it refused at.
//!
//! The refusal is deliberate and is not a placeholder. A unit that reached this type on a plane
//! this root does not yet drive was routed to the wrong loop, and there are only two honest answers
//! to that: end it saying so, or panic. Serving it half-composed — arriving it, admitting it, and
//! then finding at Route that nothing knows what it is — would charge a request slot for a unit that
//! could never have been answered. A refusal at the first step costs nothing and says exactly what
//! happened, which is what makes the coexistence window safe to be in.

// The authenticate step's three seams live beside the other root modules; reached here by the
// name every call site uses.
pub use super::auth_bindings;

use std::sync::{Arc, LazyLock, Mutex};

use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival, Audit, Authenticate, Consumption, Decode, Encode, Grant,
    Hold, Meter, Outcome, Pass, PrincipalId, Refusal, Route, SeatVerdict, VerifiedDestination,
    Verify,
};
use busbar_kernel::inflight::ArrivalDoor;
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::teller::{Evidence, UnitCtx, Units};
use busbar_kernel_egress::trust::Trust;

/// Take the kernel's seal. Boot only, once per process.
///
/// The seal is the node's whole authority: every token a unit is ever lent is minted from it, for
/// the length of one call, and there is no second way to obtain one. Calling this twice would give
/// a process two authorities, which is why the composition root calls it exactly once and hands the
/// kernel around by reference from there.
#[must_use]
pub fn new_kernel() -> busbar_kernel::teller::Kernel {
    busbar_kernel::teller::Kernel::new()
}

/// Open the vocabulary interner.
///
/// Config-derived open-vocabulary keys — a lane, a pool, a model, a provider host, a dialect name,
/// a loaded plugin's key — are leaked into `&'static str` exactly once, here, at registration. The
/// resulting allocation is fixed and countable; a leak per connection or per dial is a defect
/// rather than a variant of the rule. [`busbar_contract::Registration`] enforces the "exactly
/// once, and never after boot" half itself: it is idempotent, and it refuses a new key once the
/// image's vocabulary is frozen.
#[must_use]
pub fn new_registration() -> busbar_contract::Registration {
    busbar_contract::Registration::new()
}

// ---------------------------------------------------------------------------------------------
// The dated card history the root prices against
// ---------------------------------------------------------------------------------------------

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
    /// The snapshot this reader was admitted under.
    ///
    /// Everything with `seq <= at`, which is exactly the history as it stood at the door. An entry
    /// appended since is not in it and cannot be: the slice stops short of it.
    #[must_use]
    pub fn view(&self) -> busbar_kernel_ledger::cost::HistoryView<'_> {
        self.history.snapshot(self.at)
    }

    /// The snapshot's own number — the figure a posting records so a reader can reproduce it.
    #[must_use]
    pub fn seq(&self) -> busbar_kernel_ledger::cost::HistorySeq {
        self.at
    }

    /// A pin over a history a test built by hand, so a proof can name the instants its entries take
    /// effect at instead of racing the wall clock the holder reads.
    ///
    /// `cfg(test)` and nothing else compiles it: the shipped binary reaches a pin through
    /// [`RootHistory::pin`], which is the only construction that can produce one over the process's
    /// own history. A production caller able to assemble a snapshot out of parts is a caller able to
    /// price a request against a history the node never resolved.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(
        history: Arc<busbar_kernel_ledger::cost::History>,
        at: busbar_kernel_ledger::cost::HistorySeq,
    ) -> Self {
        PinnedHistory { history, at }
    }

    /// The same history, pinned at an EARLIER snapshot — the one construction that proves the seq is
    /// load-bearing, because both pins hold the identical `Arc`.
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
    /// THE CARD A CONFIG CHANGE STAGED: on the journal, not yet published, because the change it
    /// was staged for has not committed. Published by the commit ([`Self::apply_rates`]) or
    /// withdrawn ([`Self::withdraw_staged`]).
    staged: Mutex<Option<CardApplied>>,
    /// The form of the config card in force, as the journal holds it: what a withdrawal puts back
    /// behind a staged card whose change did not commit, or behind a card the journal left in doubt
    /// ([`Self::withdraw`]).
    in_force: Mutex<Option<CardForm>>,
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
    /// The log did not even retain the card: its segment was poisoned and a fresh one could not be
    /// opened, so the batch was refused before it was held (`Wal::append_batch`). The record can
    /// never land, so nothing is published and nothing is put back — the node fails closed, and
    /// every later append on that log is refused at the same check until a segment opens.
    Dropped(busbar_contract::caps::DurabilityLost),
    /// The boot's book has rebuilt the history but its handle is not bound yet: there is no journal
    /// the card could go on.
    Unbound,
}

impl std::fmt::Debug for RootHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootHistory").finish_non_exhaustive()
    }
}

impl RootHistory {
    /// The history as it stands, pinned at its head for the caller's whole life.
    ///
    /// The returned pair is the reader's to keep: an append after this call is seen by the NEXT
    /// caller and leaves this one reading the snapshot it was admitted under.
    #[must_use]
    pub fn pin(&self) -> Option<PinnedHistory> {
        let history = self.history.load_full()?;
        let at = history.head()?;
        Some(PinnedHistory { history, at })
    }

    /// The history AS A WHOLE, for a reader that snapshots it itself.
    ///
    /// [`Self::pin`] answers the request path, which wants the head fixed for one unit's whole
    /// life. A ledger READ wants the entries and its own choice of snapshot — an invoice cut at
    /// seq 3 is re-derived by asking for seq 3 again — so it takes the `Arc` and names the
    /// snapshot, rather than being handed one somebody else chose. Both are the same read-copy:
    /// an append after this call is seen by the next caller and leaves this one on the history it
    /// asked under.
    ///
    /// `None` until the boot resolution raises the rate-apply seam, which is a node with no entry
    /// a posting could resolve to — never a node whose postings are free.
    #[must_use]
    pub fn history(&self) -> Option<Arc<busbar_kernel_ledger::cost::History>> {
        self.history.load_full()
    }

    /// **THE ONLY MUTATOR: APPEND.** Put `card` on the history effective from `now_ms`, and return
    /// the entry's number.
    ///
    /// The FIRST entry is effective from instant ZERO rather than from `now_ms`, and that is not a
    /// convenience. A first entry starting at boot would leave every instant before boot in a hole,
    /// and a hole is a refusal — so a posting whose arrival the node dated a millisecond early, or a
    /// legacy row carrying nothing finer than a UTC day, would price at nothing. Effective from zero
    /// with no end, one entry covers every instant, and a deployment that never edits a price is a
    /// single-entry history: arithmetically the previous release, to the byte.
    ///
    /// EVERY LATER ENTRY is effective from `now_ms` and closes nothing. The previous entry stays
    /// open-ended and stays exactly as it was written; the resolution rule takes the highest
    /// covering seq, so this entry out-ranks it from `now_ms` forward and the entry before it goes
    /// on answering for every instant before that, forever. Closing the old entry would be a write
    /// to a record that is already booked.
    ///
    /// Read-copy-update rather than load-then-store: two applies landing together would otherwise
    /// each clone the same history and the second's store would drop the first's entry on the floor,
    /// which is a price change that silently did not happen.
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

    /// The `effective_from` a config card applied at `now_ms` takes: instant zero for the first
    /// entry, `now_ms` for every later one (see [`Self::apply`]).
    fn effective_from_for(&self, now_ms: u64) -> u64 {
        match self.history.load().as_deref() {
            Some(history) if !history.is_empty() => now_ms,
            _ => 0,
        }
    }

    /// [`Self::apply`] under a policy epoch the caller already took, answering the entry's number.
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
            // The closure may run more than once; the run whose swap lands is the last one.
            appended = seq;
            Some(Arc::new(next))
        });
        appended
    }

    /// **THE APPLY THE RATE-APPLY SEAM MAKES**: build the card from the configured figures, put the
    /// entry on the node's journal, and only then append it to the history (as [`Self::apply`]) —
    /// so a restart rebuilds the history the node priced under rather than dating the boot card
    /// from instant zero (#79).
    ///
    /// JOURNAL FIRST, PUBLISH SECOND (MONEY-AUDIT D-6). A card published before its record is
    /// durable prices postings in an era a restart cannot reproduce: the rebuilt history lacks the
    /// entry and every row earned under it reprices at the card before. So an apply the journal
    /// will not take is REFUSED: the card in force stays the one that was. A refusal is IN DOUBT,
    /// not absent — the journal chained the record and the log retained it — so the card in force
    /// is journalled back behind it at the same instant and both land on the live history, which
    /// then prices every instant as the rebuilt chain does (REV-293 #1); the refused record's
    /// policy epoch is spent, so no later entry shares it.
    ///
    /// # Errors
    ///
    /// The journal could not make the applied card durable, or the boot's book has rebuilt the
    /// history but its handle is not bound yet, so there is no journal the card could go on.
    pub fn apply_rates(
        &self,
        rates: &busbar_kernel::rate_apply::RawRates<'_>,
        now_ms: u64,
    ) -> Result<busbar_kernel_ledger::cost::HistorySeq, CardRefused> {
        let _one_at_a_time = self.applying.lock().unwrap_or_else(|p| p.into_inner());
        register_classes(rates);
        let card = card_from_raw(rates);
        let form = CardForm::of(rates, &card);
        // THE COMMIT OF A STAGED CARD: already on the journal, so it is published as journalled —
        // its own `effective_from`, its own epoch — and nothing is written twice. A staged card
        // that is not this one belongs to a change that did not commit, and is withdrawn first.
        let staged = self.staged.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(staged) = staged {
            if staged.form == form {
                *self.in_force.lock().unwrap_or_else(|p| p.into_inner()) = Some(form);
                return Ok(self.append_config(card, staged.appended_at, staged.policy_epoch));
            }
            self.withdraw(staged, now_ms);
        }
        // One apply at a time (the lock above), so the epoch and the `effective_from` read here are
        // the ones the append below lands with.
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

    /// Spend `policy_epoch`: a record was sealed under it, so no later entry may take it — whether
    /// or not that record lands.
    fn spend_epoch(&self, policy_epoch: u64) {
        self.resolutions.fetch_max(
            policy_epoch.saturating_add(1),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Journal `applied` BEFORE it is published (the caller publishes on `Ok`). A refusal the
    /// journal left IN DOUBT ([`CardRefused::Lost`]) is withdrawn as it is refused: the card in
    /// force goes on the journal behind it at the same instant, and both entries land on the live
    /// history in one step, so the live node prices every instant as the history a restart rebuilds
    /// from the chain — whichever way the log's retry lands (REV-293 #1). A card the log dropped
    /// outright ([`CardRefused::Dropped`]) can never land, and nothing is published for it. The
    /// caller holds `applying`.
    fn journal_or_withdraw(&self, applied: CardApplied, now_ms: u64) -> Result<(), CardRefused> {
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
                self.withdraw(applied, now_ms);
                Err(CardRefused::Lost(lost))
            }
        }
    }

    /// Put the card in force back on the journal at `in_doubt`'s own `effective_from`, behind it, so
    /// the in-doubt entry — a card the journal left in doubt, or a staged card whose config change
    /// did not commit (REV-309 #2: both entries land in memory whatever the put-back's answer) —
    /// never prices an instant — on the chain a restart rebuilds from (where the
    /// equal `effective_from` resolves to the later entry), and in memory, where both entries land
    /// in one step whatever the journal answers for the second: an in-doubt answer is retained
    /// behind the first and lands with it. Only a put-back the log dropped outright leaves the
    /// in-doubt card alone on the live history, which is then the one the chain will hold. The
    /// caller holds `applying`.
    fn withdraw(&self, in_doubt: CardApplied, now_ms: u64) {
        let prior = self
            .in_force
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut drafts = vec![in_doubt.draft()];
        match prior {
            None => tracing::error!(
                effective_from = in_doubt.effective_from,
                "a rate card the journal left in doubt has no card in force to put back behind it"
            ),
            Some(prior) => {
                let policy_epoch = self.resolutions.load(std::sync::atomic::Ordering::Relaxed);
                let back = CardApplied {
                    effective_from: in_doubt.effective_from,
                    appended_at: now_ms,
                    policy_epoch,
                    form: prior,
                };
                match self.journal_applied(back.clone()) {
                    Ok(()) | Err(CardRefused::Lost(_)) => {
                        self.spend_epoch(policy_epoch);
                        drafts.push(back.draft());
                    }
                    Err(refused) => {
                        self.spend_epoch(policy_epoch);
                        tracing::error!(
                            ?refused,
                            effective_from = in_doubt.effective_from,
                            "the log dropped the card in force put back behind a rate card left in \
                             doubt: the in-doubt card prices from this instant, as the chain holds it"
                        );
                    }
                }
            }
        }
        self.history.rcu(|current| {
            let mut next = match current {
                Some(history) => busbar_kernel_ledger::cost::History::clone(history),
                None => busbar_kernel_ledger::cost::History::new(),
            };
            for draft in &drafts {
                next.append(draft.clone());
            }
            Some(Arc::new(next))
        });
    }

    /// **STAGE THE CARD A CONFIG CHANGE IS ABOUT TO COMMIT** (MONEY-AUDIT D-6, ARCHITECT ruling
    /// 2026-10-02): put it on the journal BEFORE the change is saved, and publish nothing. The
    /// commit publishes it ([`Self::apply_rates`]); a change that does not commit withdraws it
    /// ([`Self::withdraw_staged`]). Only a bound journal stages: a holder journalling nothing (Off)
    /// or holding the boot's card for its book (Armed) has nothing to make durable yet.
    ///
    /// # Errors
    ///
    /// The journal refused the card, or the book's handle is not bound yet: the config change is
    /// refused whole, so the old configuration and the old card both stay — a refusal the journal
    /// left in doubt with the card in force journalled back behind the staged one.
    pub fn stage_rates(
        &self,
        rates: &busbar_kernel::rate_apply::RawRates<'_>,
        now_ms: u64,
    ) -> Result<(), CardRefused> {
        let _one_at_a_time = self.applying.lock().unwrap_or_else(|p| p.into_inner());
        match *self.journal.lock().unwrap_or_else(|p| p.into_inner()) {
            CardJournal::Off | CardJournal::Armed(_) => return Ok(()),
            CardJournal::Restored => return Err(CardRefused::Unbound),
            CardJournal::Bound { .. } => {}
        }
        let stale = self.staged.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(stale) = stale {
            self.withdraw(stale, now_ms);
        }
        register_classes(rates);
        let card = card_from_raw(rates);
        let policy_epoch = self.resolutions.load(std::sync::atomic::Ordering::Relaxed);
        let applied = CardApplied {
            effective_from: self.effective_from_for(now_ms),
            appended_at: now_ms,
            policy_epoch,
            form: CardForm::of(rates, &card),
        };
        // A refusal the journal left in doubt is withdrawn as it is refused (REV-309 #1): the
        // staged record is chained and retained, so it lands with the next append, and without the
        // card in force behind it a restart would price from the staging at a card neither the
        // configuration nor the live history ever held. A card the log dropped outright never
        // lands and is put back by nothing: fail closed.
        self.journal_or_withdraw(applied.clone(), now_ms)?;
        *self.staged.lock().unwrap_or_else(|p| p.into_inner()) = Some(applied);
        Ok(())
    }

    /// **THE STAGED CARD'S CONFIG CHANGE DID NOT COMMIT**: withdraw it. A no-op with nothing staged.
    pub fn withdraw_staged(&self, now_ms: u64) {
        let _one_at_a_time = self.applying.lock().unwrap_or_else(|p| p.into_inner());
        let staged = self.staged.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(staged) = staged {
            self.withdraw(staged, now_ms);
        }
    }

    /// ARM THE JOURNAL: from here on every apply is recorded — held until the boot's book has
    /// rebuilt the history ([`Self::restore`]) and its handle is bound ([`Self::bind_journal`]),
    /// then written as it lands. The production boot arms the process holder before its first
    /// resolution; nothing else does, so a test's holder and a build with no root ledger journal
    /// nothing.
    pub fn arm_journal(&self) {
        let mut journal = self.journal.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(*journal, CardJournal::Off) {
            *journal = CardJournal::Armed(Vec::new());
        }
    }

    /// THE NO-PERSISTENCE SHAPE: a boot with no data directory keeps no chain to rebuild from, so
    /// the history is the boot card from instant zero exactly as it always was, and nothing is held.
    pub(crate) fn disarm_journal(&self) {
        *self.journal.lock().unwrap_or_else(|p| p.into_inner()) = CardJournal::Off;
    }

    /// Record one apply wherever this holder's journal stands, BEFORE it is published.
    ///
    /// Off journals nothing (no chain to rebuild from). Armed holds the boot's opening card for
    /// the boot's book, which journals it as it rebuilds the history — or refuses the boot. Bound
    /// writes it. Restored refuses: the history was rebuilt from the chain but the book's handle
    /// is not bound yet, so there is no journal the card could go on.
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

    /// **THE BOOT'S REBUILD OF THE DATED HISTORY FROM THE CHAIN**, run by the book before it prices
    /// a single replayed posting, from the chain's cards and the applies `held` since the holder
    /// was armed. Answers the history, the records the book must write before it is published, and
    /// the next policy epoch.
    ///
    /// - A chain with NO config card on it (a fresh node, or a journal written before cards were
    ///   journalled): the history stays what the boot resolved — its card from instant zero, the
    ///   previous release's reading — and that opening entry is written, dated from zero.
    /// - Otherwise the history IS the chain's: every journalled entry, in the order it was written,
    ///   each with the `effective_from` it was applied at — the opening entry first. The boot's own
    ///   resolution is appended, dated at the instant it landed, ONLY where it differs from the
    ///   newest journalled config card: a restart that changed no price appends nothing and moves
    ///   nothing; a restart that did prices what happens after the boot and nothing before it.
    fn restore(journalled: Vec<JournalledCard>, held: Vec<CardApplied>) -> RestoredHistory {
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
                // Nothing configured was ever journalled: the boot card opens the history from
                // instant zero, as it always has.
                applied.effective_from = 0;
                opening = Some(applied.draft());
            } else if newest.as_ref() == Some(&applied.form) {
                // The configuration did not change a price: no new generation of the card.
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
                // The correction over the history as it stood when it was sealed — the same prefix
                // the live append resolved it against, checked against the entry it names. A
                // prefix that does not hold that entry refuses it, by name (#79).
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

    /// **THE BOOT'S REBUILD, RUN BY THE BOOK** before it prices a replayed posting: `records` is the
    /// chain it read, or `None` for a node with no data directory (the previous release's
    /// no-persistence shape: the history stays the boot card from instant zero and nothing is
    /// held) or a chain that could not be read (rebuilt from nothing, journalled nothing).
    ///
    /// A chain written before applied cards were journalled holds none: its history starts at the
    /// boot card from instant zero, exactly as it did, and that opening entry is journalled now.
    ///
    /// JOURNAL FIRST, PUBLISH SECOND (MONEY-AUDIT D-6): the boot's cards go on the chain before
    /// the rebuilt history is published. A holder that was not armed rebuilds nothing.
    ///
    /// Answers every journalled correction the rebuild refused ([`CorrectionRefused`]), which the
    /// book reports among its restart findings.
    ///
    /// # Errors
    ///
    /// The journal could not make one of the boot's cards durable: the boot refuses rather than
    /// price under an era a restart could not reproduce.
    pub(crate) fn rebuild_from_chain(
        &'static self,
        durability: &mut crate::root::durability::Durability,
        records: Option<&[busbar_kernel_wal::JournalRecord]>,
    ) -> Result<Vec<CorrectionRefused>, busbar_contract::caps::DurabilityLost> {
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

    /// **BIND THE BOOK THE HISTORY WAS REBUILT FROM**: journal every apply after it before it
    /// lands. A no-op for any other book and for a holder whose history was not rebuilt from a
    /// chain — which is every holder but the production boot's. Nothing is held to write here: an
    /// apply between the rebuild and this bind was refused ([`CardRefused::Unbound`]).
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

    /// **THE SIGNED, BACK-DATED CORRECTION** — the effect half of the `amend_rate_history` verb.
    /// Append an [`busbar_kernel_ledger::cost::Author::Amend`] entry over the window the operator
    /// named, and return its number.
    ///
    /// THE ENTRY IS THE CARD IN FORCE WITH THE NAMED CELLS CORRECTED ([`Correction::draft_over`]),
    /// never a card of the named cells alone: a correction of one rate keeps every other lane, class,
    /// plane card and the fee it did not name exactly as they were priced (#79 "a correction reprices
    /// exactly its window"). A window no single card prices, or a cell with no present card to land
    /// on, is [`AmendRefused::NoSoleCard`] and appends nothing; a boundary that would cut inside a
    /// stored metering row — or make the units after the window price at it — is
    /// [`AmendRefused::CutsRow`] (#32) and appends nothing.
    ///
    /// Unlike [`RootHistory::apply`] this never invents a from-zero opening entry: an amendment
    /// corrects a history that already has one, so an empty holder is a REFUSAL
    /// ([`AmendRefused::NoHistory`]) rather than a first write. It closes nothing and rewrites
    /// nothing: the entry it corrects stays exactly as booked, every snapshot taken before this one
    /// still returns the old answer, and the resolution rule's highest-covering-seq wins means this
    /// entry out-ranks the corrected one for `[effective_from, effective_until)` from this seq
    /// forward.
    ///
    /// `seal` is handed the corrected card and the entry it is sealed over ([`CorrectionBase`])
    /// BEFORE the append, and makes the correction durable with both; its refusal appends nothing
    /// ([`AmendRefused::Seal`]). Seal and append run under the apply lock, so a restart's rebuild
    /// reaches each correction over the prefix the live append resolved it against. Where it does
    /// not (an applied card whose journal write was lost), the record's base does not match and the
    /// rebuild refuses the correction ([`CorrectionRefused`]) rather than rebuild it over another
    /// card.
    ///
    /// It does NOT bump the config-resolution epoch: an amendment is an operator's correction, not a
    /// new generation of the deployment's configuration.
    pub fn amend<E>(
        &self,
        correction: &Correction,
        seal: impl FnOnce(&busbar_kernel_ledger::cost::RateCard, CorrectionBase) -> Result<(), E>,
    ) -> Result<busbar_kernel_ledger::cost::HistorySeq, AmendRefused<E>> {
        let _one_at_a_time = self.applying.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.history.load_full().ok_or(AmendRefused::NoHistory)?;
        // OWNER ruling #32 (2026-09-29): A CORRECTION THAT WOULD CUT INSIDE A STORED ROW IS
        // REFUSED. `appended_at` is the first instant of the second the correction arrived in, so a
        // unit stored later in that second is counted as stored.
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
        seal(&draft.card, base).map_err(AmendRefused::Seal)?;
        // Every other append runs under the same lock, so the history the draft was resolved
        // against is the history it lands on.
        let mut next = busbar_kernel_ledger::cost::History::clone(&current);
        let seq = next.append(draft);
        self.history.store(Some(Arc::new(next)));
        Ok(seq)
    }

    /// How many entries stand on the history. A read for the tests and for the operator surface that
    /// reports the head; it is never on a pricing path.
    #[must_use]
    pub fn len(&self) -> usize {
        self.history.load().as_ref().map_or(0, |h| h.len())
    }

    /// Whether no configuration has been resolved yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The process's history holder, reached by the root's units and by nothing below them.
///
/// A `static` for the same reason the LLM node is one: the seam a unit is driven through is a bare
/// `fn` and a bare `fn` cannot capture, so the holder has to be reachable by name. It exists before
/// the boot that reads the configuration finishes, holding no history, which is exactly the state a
/// report arriving that early should be priced in — it isn't.
pub static ROOT_CARD: LazyLock<RootHistory> = LazyLock::new(RootHistory::default);

/// The configured rates, in the cost unit's own card.
///
/// A RELAY, AND DELIBERATELY NOTHING MORE. Reading the deployment's configuration is the root's;
/// turning those figures into a card is the cost unit's, on
/// [`busbar_kernel_ledger::cost::RateCard::from_config`] — so the class fan-out, the absent/present branch and
/// the fee's clamp all happen where the card lives, and there is no arithmetic here to disagree with
/// it. No plane sees a rate at all.
///
/// THE ROOT'S, NOT A PLANE'S. The card this builds is the one every plane's exit prices against —
/// the holder above is the process's, reached by mcp, a2a, voice and admin exactly as it is by llm —
/// so the relay belongs beside the holder and the repricer rather than in one plane's unit file. It
/// lived in the node's file (now `plane_node`) while llm was the only leg switched over, and a
/// plane's unit file is compiled out with its plane: any build without that plane's feature lost the
/// root's ability to price a card at all. The deletability of a plane is the whole point of the feature, so the thing
/// that must survive every deletion lives on the ungated side of the seam.
///
/// A deployment with no `rate_card:` builds an ABSENT card rather than no card at all, and the
/// difference matters: absent prices every class at nothing and still charges the flat fee, which is
/// exactly what the previous release bills for that deployment.
///
/// The card carries no version of its own any more. Which card a posting was priced against is the
/// number of the history entry that holds it, and that number belongs to the history: a card naming
/// itself would be a second identity that can disagree with the first. This relay builds the card;
/// appending it to the history is [`RootHistory::apply`]'s.
///
/// THERE IS NO DENOMINATION TO CARRY. #66 (`BUSBAR-1.6.0.md:528`, owner-locked) rules money
/// UNITLESS: the configured figures are abstract cost units (`crates/busbar-core/src/config/mod.rs`:
/// "ABSTRACT cost units (no currency, no FX)"), the card holds them as integers at the one scale,
/// and what a dashboard DISPLAYS them as is the dashboard's (`docs/configuration.md:634`). This
/// relay used to take a `currency` argument, sourced from a `node_currency()` that always answered
/// `USD`; both are gone, and the scale is now a constant nothing can name.
pub(crate) fn card_from_config<'r>(
    rates: impl IntoIterator<Item = (&'r str, busbar_contract::billing::RawTierRates)>,
    flat_minor: i64,
    present: bool,
) -> busbar_kernel_ledger::cost::RateCard {
    // The substrate's neutral raw-rate view, lifted into the cost unit's own — four numbers copied
    // across a crate boundary, in the same canonical order, with nothing computed on the way.
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
    // The flat figure crosses as a NEUTRAL minor-unit value; the cost unit's constructor is the one
    // that reads it AS the per-request fee (clamps it, bills it), so no plane and no root file spells
    // a fee — the read lives where the card lives.
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
    fn rates_staged(&self, rates: &busbar_kernel::rate_apply::RawRates<'_>) -> Result<(), String> {
        ROOT_CARD
            .stage_rates(rates, busbar_kernel::store::now_ms())
            .map_err(|refused| format!("the journal did not take the rate card ({refused:?})"))
    }

    fn rates_withdrawn(&self) {
        ROOT_CARD.withdraw_staged(busbar_kernel::store::now_ms());
    }

    fn rates_applied(&self, rates: &busbar_kernel::rate_apply::RawRates<'_>) {
        if let Err(refused) = ROOT_CARD.apply_rates(rates, busbar_kernel::store::now_ms()) {
            tracing::error!(
                ?refused,
                "the journal did not take an applied rate card: the apply is refused and the card \
                 in force is unchanged"
            );
        }
    }
}

/// The card one rate apply builds, and so the card every DATED history entry holds: the reserved
/// four and the flat figure through [`card_from_config`], then every open-class rate the lanes'
/// `units:` name (item 123) — the same two steps, in the same order, the live card is built by
/// (`CostModel::resolve_parts`). Without the second step an older era holding open-class usage
/// (a rerank's `search_units`) resolved to a card with no such cell and REFUSED where the live
/// card priced it.
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
    // Each plane's own fees (#47), dated with the card they were configured beside.
    .with_plane_fees(rates.plane_fees.iter().map(|(p, f)| (p.as_str(), *f)))
}

// ---------------------------------------------------------------------------------------------
// An applied card, as the journal keeps it
// ---------------------------------------------------------------------------------------------

/// REGISTER EVERY CLASS A UNIT MAY REPORT, at the moment a configuration is applied — boot or a later
/// apply, both of which are registration time (config is finite). The reserved four, every installed
/// plane's declared billable classes, and every open class a lane's `units:` names go into the
/// process vocabulary, so a unit's one line can resolve the classes
/// it reports by lookup ([`busbar_contract::Registration::resolve`]) and never intern one per unit.
pub(crate) fn register_classes(rates: &busbar_kernel::rate_apply::RawRates<'_>) {
    let mut registration = new_registration();
    for class in busbar_contract::records::RESERVED_UNITS {
        let _ = registration.key(class);
    }
    // Every installed plane's DECLARED billable classes and fee units (`PlaneDeclaration`): the
    // classes a plane may report are the ones it declares, linked or dropped in.
    for decl in busbar_kernel::plane::registry::plane_decls() {
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

/// The tag a journalled config-applied card's body opens with. A `Policy`-class record, beside the
/// signed amendment's (`units_admin::AMENDMENT_RECORD_TAG`): both are entries of the dated history.
pub const CARD_APPLIED_TAG: &str = "busbar/rate-card-applied/v1";

/// The four reserved classes every configured lane carries a rate for.
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
    /// The integer form of `card`, which the apply built from `rates` ([`card_from_raw`]).
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

    /// The card this form holds — built through the same constructors, in the same order, the
    /// apply built it through: the lanes' presence, then every cell's integer rate, then each
    /// plane's fees.
    ///
    /// A cell the applied card could not represent was UNPRICED on it. The rebuild cannot spell an
    /// unpriced reserved cell without a decimal, so it leaves that whole LANE off the card, which
    /// REFUSES every class on it (#42) rather than pricing any at a zero nobody configured. Config
    /// validation refuses such a rate before a card is ever built, so no admitted card has one.
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
    /// The history entry this record is.
    fn draft(&self) -> busbar_kernel_ledger::cost::CardEntryDraft {
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

    /// The record's body.
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

    /// Read one back; `None` for a body that is not one (another `Policy` record) or is malformed.
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

/// Put one config-applied card on `durability`'s journal (#79): a `Policy` record carrying the card
/// and the instant it took effect from, which a boot reads back to rebuild the dated history before
/// it prices a replayed posting. A price LIST, not a unit's money: the chain's postings still carry
/// counts and an arrival instant only.
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

/// What a `DurabilityLost` from [`journal_card`] leaves the card as. The journal sealed the card
/// last, so it is the number just below the journal's next; the log either holds it or owes it
/// (retained, offered again on the next append: IN DOUBT) — or neither, which is the one path that
/// refuses a batch before retaining it: a poisoned segment no fresh one could replace (DROPPED).
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

/// One entry of the dated history as the chain holds it.
pub(crate) enum JournalledCard {
    /// A config apply ([`CardApplied`]).
    Applied(CardApplied),
    /// A signed back-dated correction written before corrections overlaid the card in force
    /// (`busbar/rate-amendment/v1`, `v2`): its window, the whole card it sealed, its signer — rebuilt
    /// as exactly the card that record sealed.
    Amended(busbar_kernel_ledger::cost::CardEntryDraft),
    /// A signed back-dated correction, as `amend_rate_history` journalled it ahead of its append
    /// (item 30): the cells it named over the card in force for its window ([`Correction`]).
    /// Without it a restart dropped the correction and its window repriced at the card it had
    /// corrected. With it the entry it was sealed over ([`CorrectionBase`]), which the rebuild
    /// must find again before it rebuilds the correction.
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
    /// The history entry this correction appends over `view`, and the entry it is sealed over: the
    /// ONE card in force for the whole window
    /// ([`busbar_kernel_ledger::cost::HistoryView::sole_entry_over`]) with the named cells set
    /// ([`busbar_kernel_ledger::cost::RateCard::corrected`]). `None` when no single card prices
    /// the window, or a named cell has no present card to land on — a refusal, never a guess.
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

    /// **A JOURNALLED CORRECTION, REBUILT AT A RESTART** (#79): the entry [`Self::draft_over`]
    /// appends over `view`, ONLY where `view` holds the entry the correction was sealed over —
    /// the entry numbered `sealed_over.seq`, the one card pricing the whole window, holding the card
    /// whose digest the record carries. Anything else is the [`BaseMismatch`] that names it, and
    /// nothing is rebuilt over a card no operator signed.
    ///
    /// # Errors
    ///
    /// The first way `view` fails `sealed_over`, in the order [`BaseMismatch`] lists them.
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
}

/// What [`RootHistory::restore`] rebuilt from the chain: the history, the boot's records the book
/// must journal before it is published, the next policy epoch, the newest config card, and every
/// journalled correction the rebuild refused ([`CorrectionRefused`]).
struct RestoredHistory {
    history: busbar_kernel_ledger::cost::History,
    write: Vec<CardApplied>,
    next_epoch: u64,
    newest: Option<CardForm>,
    refused: Vec<CorrectionRefused>,
}

/// Every entry of the dated history on `records`, in the order the chain holds them.
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

/// A journalled signed correction: a `v3` record is the [`Correction`] its effect appended — its
/// named cells and the fee it sealed, over the card in force for its window, rebuilt against the
/// same history prefix; a `v1`/`v2` record is the whole card it sealed. Either way appended at its
/// admission instant and authored by its signer.
#[cfg(feature = "root-admin")]
fn journalled_amendment(body: &[u8]) -> Option<JournalledCard> {
    let amendment = crate::root::units_admin::amendment_from_body(body)?;
    let author = busbar_kernel_ledger::cost::Author::Amend {
        operator_fingerprint: amendment.operator_fingerprint,
        reason_hash: amendment.reason_hash,
    };
    // An UNPRICED cell (`None`) is left off, so a hit on it refuses (#42) exactly as it did on the
    // card the correction sealed — never priced at a zero.
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

/// A build without the admin plane has no correction verb, so its chain holds no correction.
#[cfg(not(feature = "root-admin"))]
fn journalled_amendment(_body: &[u8]) -> Option<JournalledCard> {
    None
}

/// **THE ROOT, DATING A PRICE** — the read-side twin of the apply above.
///
/// The metering accrual asks WHEN the card it is serving under started, so that a cell aggregated
/// over a UTC day carries an instant finer than the day and a card published at noon splits the
/// day rather than repricing all of it (DECISION #79). The answer is the `effective_from` of the
/// entry the head resolves to at that instant — a DATE, never a rate, which is what lets an
/// accrual on the serving path ask it at all.
///
/// The HEAD, not a pinned snapshot: an accrual is dated when it happens, by the history as it
/// stands then. A back-dated correction appended afterwards does not change when the cell was
/// earned; it changes what that instant is worth, and the read resolves that.
impl busbar_kernel::rate_apply::RateEpoch for CardRepricer {
    fn effective_from_at(&self, at_ms: u64) -> u64 {
        let Some(history) = ROOT_CARD.history() else {
            // No configuration resolved yet: zero, the opening entry's own `effective_from`, so the
            // cell dates to a card that covers it rather than to none at all.
            return 0;
        };
        history
            .current()
            .entry_at(at_ms)
            .map_or(0, busbar_kernel_ledger::cost::CardEntry::effective_from)
    }

    /// THE SAME HISTORY, handed to the budget ledger (OWNER RULING Q14): its reads and its gate
    /// price each era of a budget cell at the card this history resolves for it, so `/keys` and
    /// `/groups` usage, the `/metrics` spend gauges and the gate agree with `GET /admin/usage`.
    fn history(&self) -> Option<Arc<busbar_kernel_ledger::cost::History>> {
        ROOT_CARD.history()
    }
}

/// **THE ROOT, ANSWERING THE USAGE READ'S DATED-HISTORY SEAM** (DECISION #79).
///
/// `GET /api/v1/admin/usage` prices each metering row against the card in force at that row's own
/// instant rather than against the newest card ever authored, and the history it resolves through
/// is THIS process's — the same one every posting is priced by. The direction is this way round
/// because it has to be: the admin crate cannot name the binary, so it declares the seam and the
/// root installs itself as the answer.
///
/// It hands over the history and NOTHING ELSE. Which entry answers for an instant is the cost
/// unit's [`busbar_kernel_ledger::cost::HistoryView::card_at`], and what a metering row's instant
/// IS belongs to the read; a root that resolved here would be a second opinion about money in a
/// file nobody reads for one.
#[derive(Debug, Clone, Copy)]
pub struct RootUsageHistory;

impl busbar_core_admin::v1::service::UsageRateHistory for RootUsageHistory {
    fn history(&self) -> Option<Arc<busbar_kernel_ledger::cost::History>> {
        ROOT_CARD.history()
    }
}

/// Install the root as the process's rate holder. Boot only, once.
///
/// THREE HALVES OF ONE FACT — the deployment's rates live here, and all three readings of that
/// fact go up together or none does. The APPLY half hears the engine resolve a configuration and
/// appends a dated entry. The DATE half answers the metering accrual asking when the entry it is
/// serving under started, which is what gives a UTC-day cell an instant finer than the day. The
/// READ half hands the history to the ledger read that prices against it. Any two without the
/// third is a node that dates its prices and then reports them off the newest card anyway —
/// exactly the defect this seam exists to rule out.
pub fn install_card_repricer() {
    // Armed BEFORE the boot resolution, so the opening entry is held for the book to journal: the
    // boot's book rebuilds the dated history from its chain (#79) before it prices a posting.
    ROOT_CARD.arm_journal();
    busbar_kernel::rate_apply::install_rate_apply(&CardRepricer);
    busbar_kernel::rate_apply::install_rate_epoch(&CardRepricer);
    busbar_core_admin::v1::service::install_usage_rate_history(&RootUsageHistory);
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

/// The node's store behind the published ABI, as the verbs unit reaches it: the loader's ABI-2 adapter
/// over the CONFIGURED store (bound at boot, [`crate::root::durability::NodeBook::verb_store`]), or
/// `None` on a node with no store, where each disaster-recovery verb answers as a store failure.
pub type VerbStoreHandle = Option<Arc<dyn busbar_contract::verb_store::Store + Send + Sync>>;

/// The long-lived objects the root owns, behind the one trait the loop reaches a unit through.
///
/// Only the units with state across requests are fields. The other eight are facades — free
/// functions or unit structs the step calls with the facts it was handed — and holding an empty
/// value for each of them would be furniture rather than structure.
pub struct ProductionUnits {
    /// Every `(pool, destination)` breaker cell and every destination's lifetime budget, behind the
    /// port the egress unit reaches it through.
    ///
    /// There is exactly one of these and it is reached only here. Two breaker units would be two
    /// sets of cells: a trip recorded through one would be invisible to the other, and a lane the
    /// walk had benched would still read as ready at Verify.
    pub breaker: crate::root::adapters::BreakerAdapter,
    /// The seams the authenticate step is handed beside the request: the signed-key verifier and the
    /// revocation view — and NO credential cache. The node's one flushable cache is the kernel's; a
    /// second one here would be a second answer to "has this credential been seen" that an
    /// operator's flush could not reach (item 249).
    pub auth_bindings: auth_bindings::AuthBindings,
    /// The trust unit. Stateless: it is handed the pool view and the kind facts per call.
    pub trust: Trust,
    /// The arrival door, bound to the admission unit and to nothing else.
    pub arrival_door: AdmissionDoor,
    /// The journal, the ledger and the audit record chain.
    ///
    /// Behind one lock because all four are append-only and a unit's settlement touches more than
    /// one of them: the record is sealed, the ledger moves and the journal takes the batch, and a
    /// reader that saw two of the three would be reading a half-settled unit.
    /// Behind an `Arc` as well as the lock, because the five ledger views read the same four things
    /// this node writes. They hold a handle to THIS value rather than a copy of it taken at boot: a
    /// view over a copy would serve the figures the node had when it started listening, which is a
    /// worse answer than no figures at all because it looks like a current one. What the views take
    /// at request time is a snapshot under this lock, which is the same lock a settlement holds — so
    /// no read can see a unit half-settled, and no reader can write, because what crosses the seam
    /// is a value and never the ledger.
    pub durability: Arc<Mutex<crate::root::durability::Durability>>,
    /// What the scope unit reads at Approve. Silence is a refusal.
    pub scope_policy: crate::root::policy::ScopePolicy,
    /// The admin plane's bindings: the seam an operation's body is reached through, and the table
    /// of admin units the loop is currently walking.
    ///
    /// One plane's bindings rather than five, because one plane has been switched. The other four
    /// arrive as their own fields as their own steps land, and until then their step methods say so
    /// rather than answering for a plane that is still served elsewhere.
    #[cfg(feature = "root-admin")]
    pub admin: crate::root::units_admin::AdminBinding,
    /// The store, behind the published ABI. The verbs unit's disaster-recovery subset and its
    /// sealed idempotency cache both reach it, and both reach the same one. `None` on a node with no
    /// configured store ([`VerbStoreHandle`]).
    pub store: VerbStoreHandle,
    /// The credential the kernel lends the verbs unit for the length of an execution.
    ///
    /// Minted once, at boot, from the node's one authority — the second token in the tree minted
    /// outside the loop, for the same reason as the first: a kernel verb is a Route destination
    /// rather than a step, so no step's token stands in for it.
    pub admin_token: busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    /// The planes registered onto this loop, in registration order.
    ///
    /// Every step consults this table before it does anything: the FIRST plane whose `claims`
    /// answers for the unit `ctx` names is the one that runs, and a unit no plane claims falls
    /// through to the step's own default. The loop body therefore names no concrete plane — a plane
    /// is a value registered here at composition, not a branch soldered into the dispatch — which is
    /// what lets a plane be added or deleted without touching a single one of the twelve methods
    /// below. With no plane registered the table is empty, `resolve` always answers `None`, and
    /// every step is its own default: byte-identical to a node that drives no plane at all.
    registry: UnitsRegistry,
}

impl ProductionUnits {
    /// Assemble the units the loop reaches, over what the root already built.
    ///
    /// Everything expensive — opening a journal, hydrating the ledger cells, reading the rate
    /// cards — has happened by the time this is called. This is the
    /// assembly, not the work. Every argument is a value configuration decided, which is the shape
    /// that makes it impossible to construct these units and forget one.
    // The argument list IS the point, and shortening it would cost the property the doc comment
    // above claims. Every parameter is one decision configuration made; bundling them into a struct
    // would give that struct a `Default`, and a `Default` is exactly how a deployment ends up with a
    // value it never read its configuration for. A long list that cannot be built wrong beats a
    // short one that can. There is no metering policy among them (items 239/246): nothing the loop
    // reaches prices through one — what prices is the rate card, through the one function Tally
    // governs.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        kernel: &busbar_kernel::teller::Kernel,
        durability: crate::root::durability::Durability,
        breaker_policy: crate::root::adapters::BreakerPolicy,
        scope_policy: crate::root::policy::ScopePolicy,
        #[cfg(feature = "root-admin")] admin: crate::root::units_admin::AdminBinding,
        store: VerbStoreHandle,
    ) -> Self {
        ProductionUnits::new_sharing(
            kernel,
            Arc::new(Mutex::new(durability)),
            breaker_policy,
            scope_policy,
            #[cfg(feature = "root-admin")]
            admin,
            store,
        )
    }

    /// The same assembly over a book somebody else owns.
    ///
    /// [`ProductionUnits::new`] takes the durability by value, which says the node it builds is the
    /// only thing that settles onto it — true of a node with one plane on the loop and false the
    /// moment a second plane's exit arm needs the same book. This takes the handle instead, so the
    /// caller keeps one and every arm that settles is settling onto the book these units read.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new_sharing(
        kernel: &busbar_kernel::teller::Kernel,
        durability: Arc<Mutex<crate::root::durability::Durability>>,
        breaker_policy: crate::root::adapters::BreakerPolicy,
        scope_policy: crate::root::policy::ScopePolicy,
        #[cfg(feature = "root-admin")] admin: crate::root::units_admin::AdminBinding,
        store: VerbStoreHandle,
    ) -> Self {
        #[cfg_attr(not(feature = "root-admin"), allow(unused_mut))]
        let mut units = ProductionUnits {
            breaker: crate::root::adapters::BreakerAdapter::with_policy(breaker_policy),
            // The unbound posture, which is the one a node has until it is handed a directory:
            // the cache is real, and the two authorities are absent rather than permissive. A
            // deployment whose keys are busbar's own binds them through
            // `ProductionUnits::with_auth_bindings` at boot, where the governance state exists.
            auth_bindings: auth_bindings::AuthBindings::without_directory(),
            trust: Trust,
            arrival_door: AdmissionDoor,
            durability,
            scope_policy,
            #[cfg(feature = "root-admin")]
            admin,
            store,
            // Minted once, at boot, from the node's one authority. The verbs unit is lent it for the
            // length of an execution and holds nothing after; there is no second way to obtain one.
            admin_token: kernel.admin_token(),
            // Empty at birth. A plane is registered onto the loop below, through the one public
            // additive seam — never soldered into the dispatch — so that a build with no plane
            // feature holds an empty table and every step is its own default.
            registry: UnitsRegistry::default(),
        };
        // The admin plane registers through the SAME seam every plane uses. Its key is the plane's
        // own, so the registry names planes by exactly the words the plane names itself with.
        #[cfg(feature = "root-admin")]
        units.register_units(
            crate::root::units_admin::UNITS_KEY,
            Box::new(crate::root::units_admin::AdminPlane),
        );
        units
    }

    /// The units an administrative listener needs, and only those.
    ///
    /// One plane has been switched onto the loop, and this is the composition for it: the journal is
    /// memory-buffered because the administrative surface writes no money and probes no directory,
    /// and the store is the unconfigured one because no admin operation this root drives reaches
    /// the disaster-recovery subset. Both of those is a decision this constructor
    /// MAKES rather than defaults into, and each is the reason the corresponding argument of
    /// [`ProductionUnits::new`] is not asked for here.
    ///
    /// When the other four planes switch, they come in through `new` with the configuration they
    /// actually need. This constructor exists because an admin-only node genuinely needs less, not
    /// because the rest is unfinished.
    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only(
        dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>,
        door: crate::root::units_admin::AdminDoorFn,
    ) -> Self {
        // One value, two halves. The ledger is handed the write half and keeps it for the life of
        // the node; the read half stays here so the ledger views have somewhere to read the
        // previous release's rows from. They are the same rows because they are the same value —
        // a second recorder would be a second answer to what the dual write wrote.
        let rows = busbar_kernel_ledger::legacy::SummedRows::new();
        ProductionUnits::admin_only_over(dispatch, door, Box::new(rows.clone()), Arc::new(rows))
    }

    /// The same composition, over legacy rows the caller supplies both halves of.
    ///
    /// Split out because the two halves are one obligation: whatever the ledger dual-writes onto is
    /// what the reconciliation view has to read back, and a constructor that took only the write
    /// half would leave the view reading a different set of rows from the one the node writes. A
    /// caller passing two halves of different values is making that mistake explicitly rather than
    /// inheriting it.
    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only_over(
        dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>,
        door: crate::root::units_admin::AdminDoorFn,
        write: Box<dyn busbar_kernel_ledger::legacy::LegacyRows>,
        read: Arc<dyn crate::root::units_admin::LegacyRowsRead>,
    ) -> Self {
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
            write,
        )
        .expect("a memory-buffered journal cannot fail to open");
        // An admin-only node over a book of its own has no configured store behind it.
        ProductionUnits::admin_only_sharing(
            dispatch,
            door,
            Arc::new(Mutex::new(durability)),
            read,
            None,
        )
    }

    /// THE BOOTED NODE'S ADMIN UNITS: [`ProductionUnits::admin_only_sharing`] over the one book
    /// boot opened, its legacy rows, and the store boot bound beside them (row 113, ruling (B)).
    ///
    /// The book carries the store for the same reason it carries the rows: they are halves of what
    /// boot composed, and a caller that took the book but not its store would serve the three
    /// disaster-recovery verbs over nothing — refused as a store failure on a node whose store is
    /// right there. `None` is a node with no configured store.
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
            Arc::clone(&book.rows) as Arc<dyn crate::root::units_admin::LegacyRowsRead>,
            book.verb_store.clone(),
        )
    }

    /// The same composition again, over a book the caller already opened.
    ///
    /// The one constructor a boot that serves more than the administrative listener can use. The
    /// other two open a book of their own, which is right for a node whose only settlements are the
    /// admin plane's; it is wrong the moment a second plane's exit arm settles, because that arm
    /// would be moving figures on a book these views cannot see. An operator reading the totals
    /// would get an empty table off a node that had been posting all day — and an empty table
    /// reconciles, so the emptiness would not even read as a fault.
    ///
    /// So the book arrives as an argument. The caller holds the same handle it passes here, and what
    /// every plane settles onto is what these views read.
    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only_sharing(
        dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>,
        door: crate::root::units_admin::AdminDoorFn,
        durability: Arc<Mutex<crate::root::durability::Durability>>,
        read: Arc<dyn crate::root::units_admin::LegacyRowsRead>,
        store: VerbStoreHandle,
    ) -> Self {
        let kernel = new_kernel();
        let mut units = ProductionUnits::new_sharing(
            &kernel,
            Arc::clone(&durability),
            crate::root::adapters::BreakerPolicy::new(),
            crate::root::policy::ScopePolicy::new(),
            crate::root::units_admin::AdminBinding::new(dispatch, door),
            store,
        );
        // The views are bound after the units are assembled rather than through the constructor,
        // because what they read is the durability the constructor took ownership of — the handle
        // does not exist until it has. Binding it here is what makes the served figures this node's
        // rather than an empty table that looks like a balanced one.
        units.admin.ledger = Arc::new(crate::root::units_admin::NodeLedger::new(
            Arc::clone(&durability),
            read,
        ));
        // The three audit-chain reads are bound off the SAME handle, for the same reason and at the
        // same moment. A chain read and a ledger view answer different halves of what this node
        // holds — evidence and money — and binding one is not binding the other, but both read the
        // durability this constructor took ownership of and neither exists before it has.
        //
        // Until this line the three verbs resolved and refused: a node served its own chain to
        // nobody, which makes a signed chain a claim rather than evidence.
        // A sealed rate-card amendment is recorded on this SAME book's journal, with its figures,
        // before it touches the history (item 30). Without this binding `amend_rate_history`
        // refuses: the only trail it used to leave was the legacy admin ring, a volatile thousand
        // entries behind a seam that does nothing.
        //
        // And every config-applied card goes on the same journal (#79): the process holder binds
        // the book its boot rebuilt the dated history from, and journals nothing for any other.
        ROOT_CARD.bind_journal(&durability);
        units.admin.amendments = Some(Arc::new(crate::root::units_admin::AmendmentJournal::new(
            Arc::clone(&durability),
            kernel.durability_token(),
        )));
        // Item 271: an idempotency claim the admin plane's replay cache takes goes on this SAME
        // journal — on a node with a data directory only. A memory-buffered node keeps the
        // previous release's shape: nothing extra is shipped to its store.
        let on_disk = durability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .on_disk();
        if on_disk {
            units.admin.claims = Some(Arc::new(crate::root::units_admin::RootClaimJournal::new(
                Arc::clone(&durability),
                kernel.durability_token(),
            )));
        }
        units.admin.audit = Some(Arc::new(crate::root::units_admin::NodeAudit::new(
            durability,
        )));
        units
    }

    /// Bind the authenticate step's three seams to a node's virtual-key directory.
    ///
    /// Separate from [`ProductionUnits::new`] because the directory is not a value configuration
    /// decided — it is a live handle on the governance state, which exists only after the store is
    /// open and the keys are hydrated, and threading it through the constructor would make every
    /// caller that has no directory pass an absence.
    #[must_use]
    pub fn with_auth_bindings(mut self, bindings: auth_bindings::AuthBindings) -> Self {
        self.auth_bindings = bindings;
        self
    }

    /// Register a plane onto this loop, keyed by its own name, and return `self` to chain.
    ///
    /// ADDITIVE and public: a plane is a value handed to the root here, never a branch edited into
    /// the dispatch. Registration order is claim precedence — the first plane whose `claims` answers
    /// for a unit is the one that runs it — so a caller registers the most specific plane first. A
    /// plane composes over the root's state by reference and owns none of it, which is what keeps the
    /// money book, the auth chain and the durability the root's however many planes register.
    pub fn register_units(
        &mut self,
        key: &'static str,
        plane: Box<dyn RegisteredUnits>,
    ) -> &mut Self {
        self.registry.planes.push((key, plane));
        self
    }
}

/// A plane, driven through the kernel's teller loop over the root's state.
///
/// It mirrors [`Units`] method-for-method, each with a leading `root: &ProductionUnits` — a plane
/// COMPOSES over the root by reference and owns none of it. That is the whole discipline: a plane
/// reaches the auth chain, the store, the durability and the admin bindings through the `root` it is
/// handed for the length of one call, and holds nothing across requests that the root does not. A
/// plane that owned auth or the book would be a second answer to what this node's money and identity
/// are, and there is exactly one of each.
pub trait RegisteredUnits: Send + Sync {
    /// Whether this plane claims the unit `ctx` names. The registry runs the first plane that does.
    fn claims(&self, root: &ProductionUnits, ctx: &UnitCtx) -> bool;

    /// The plane's Arrival step. See [`Units::arrival`].
    fn arrival(
        &self,
        root: &ProductionUnits,
        token: &Pass<Arrival>,
        ctx: &UnitCtx,
    ) -> SeatVerdict<Arrival>;

    /// The plane's Decode step. See [`Units::decode`].
    fn decode(
        &self,
        root: &ProductionUnits,
        token: &Pass<Decode>,
        ctx: &UnitCtx,
    ) -> SeatVerdict<Decode>;

    /// The plane's Authenticate step. See [`Units::authenticate`].
    fn authenticate(
        &self,
        root: &ProductionUnits,
        token: &Pass<Authenticate>,
        ctx: &UnitCtx,
    ) -> SeatVerdict<Authenticate>;

    /// The plane's Verify step. See [`Units::verify`].
    fn verify(
        &self,
        root: &ProductionUnits,
        token: &Pass<Verify>,
        trust: &busbar_contract::caps::Grant<busbar_contract::caps::Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify>;

    /// The plane's Approve step. See [`Units::approve`].
    fn approve(
        &self,
        root: &ProductionUnits,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve>;

    /// The plane's Admit step. See [`Units::admit`].
    // One argument over the lint's ceiling, and it is the `root` every method on this trait leads
    // with — a plane composes over the root by reference rather than owning it, which is the whole
    // design. Mirroring [`Units::admit`] arg-for-arg is the property this trait exists to hold.
    #[allow(clippy::too_many_arguments)]
    fn admit(
        &self,
        root: &ProductionUnits,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit>;

    /// The plane's Route step. See [`Units::route`].
    fn route(
        &self,
        root: &ProductionUnits,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        destinations: &[busbar_contract::caps::VerifiedDestination],
    ) -> SeatVerdict<Route>;

    /// The plane's Meter step. See [`Units::meter`].
    fn meter(
        &self,
        root: &ProductionUnits,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[busbar_contract::caps::VerifiedDestination],
    ) -> SeatVerdict<Meter>;

    /// The plane's Audit step. See [`Units::audit`].
    fn audit(
        &self,
        root: &ProductionUnits,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> SeatVerdict<Audit>;

    /// The plane's refused-Audit step. See [`Units::audit_refused`].
    fn audit_refused(
        &self,
        root: &ProductionUnits,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit>;

    /// The plane's Encode step. See [`Units::encode`].
    fn encode(
        &self,
        root: &ProductionUnits,
        token: &Pass<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> SeatVerdict<Encode>;

    /// The plane's Evidence read. See [`Units::evidence`].
    fn evidence(&self, root: &ProductionUnits, ctx: &UnitCtx) -> Evidence;
}

/// The planes registered onto one loop, in registration order.
///
/// A plain ordered list, because claim precedence IS registration order: [`resolve`] answers the
/// first plane whose `claims` is true, so a caller puts the most specific plane first. Empty by
/// default, which is the state a node has before any plane is registered and the state a build with
/// no plane feature keeps for its whole life — and an empty table resolves to nothing, so every step
/// is its own default.
///
/// [`resolve`]: UnitsRegistry::resolve
#[derive(Default)]
pub struct UnitsRegistry {
    planes: Vec<(&'static str, Box<dyn RegisteredUnits>)>,
}

impl UnitsRegistry {
    /// The first plane that claims this unit, or nothing.
    ///
    /// First-wins over the registration order, so the caller's ordering is the precedence. A unit no
    /// registered plane claims answers `None`, and the step that asked falls through to its own
    /// default — which is the byte-identity property the whole seam turns on.
    fn resolve(&self, root: &ProductionUnits, ctx: &UnitCtx) -> Option<&dyn RegisteredUnits> {
        self.planes
            .iter()
            .find(|(_key, plane)| plane.claims(root, ctx))
            .map(|(_key, plane)| plane.as_ref())
    }
}

/// Every step below asks the registry the same question first — is there a plane that claims this
/// unit? — and names no plane in doing so. The FIRST plane whose `claims` answers runs the step; a
/// unit no registered plane claims falls through to the step's own default, which is a refusal naming
/// the step (never a panic and never a silent pass: a unit that reached here claimed by nothing was
/// routed wrongly, and the honest answer is to say so and end it rather than serve it half-composed).
/// Which planes exist is a composition decision made at [`ProductionUnits::register_units`], not a
/// branch in this loop.
impl ProductionUnits {
    /// Whether this unit is one the admin bindings are walking.
    ///
    /// Membership of the table, not a guess from the context: the surface that opened the unit is
    /// what put it there, so a unit that is in the table is one this root composed and a unit that
    /// is not is one it did not.
    ///
    /// It is now the admin plane's `claims` that the dispatch consults, and this method is kept only
    /// for the test that asserts a fixture is a unit the admin plane never claimed — the same
    /// question, asked directly.
    #[cfg(all(test, feature = "root-admin"))]
    fn is_admin(&self, ctx: &UnitCtx) -> bool {
        self.admin.units.holds(ctx.key)
    }
}

// Every step hands its facts to the registry's resolve branch before it defaults, so no argument
// goes unused in any build — a node with an empty registry still names every fact in the branch it
// never takes at runtime. The old `allow(unused_variables)` the no-plane build once needed is gone
// with the per-method refusals that made the arguments dead.
impl Units for ProductionUnits {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.arrival(self, token, ctx);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::NoDestination),
        )
    }

    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> SeatVerdict<Decode> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.decode(self, token, ctx);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::DecodeFailed),
        )
    }

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.authenticate(self, token, ctx);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::Unauthenticated),
        )
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &busbar_contract::caps::Grant<busbar_contract::caps::Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.verify(self, token, trust, ctx, principal);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::NoDestination),
        )
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.approve(self, token, ctx, principal, destinations);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::ScopeDenied),
        )
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.admit(self, token, admit, ctx, principal, destinations, leases);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::NoDestination),
        )
    }

    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        destinations: &[busbar_contract::caps::VerifiedDestination],
    ) -> SeatVerdict<Route> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.route(self, token, ctx, destinations);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::NoDestination),
        )
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[busbar_contract::caps::VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.meter(self, token, usage, ctx, provisional, destinations);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::Unpriced),
        )
    }

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> SeatVerdict<Audit> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.audit(self, token, ctx, outcome);
        }
        SeatVerdict::proceed(token, unclaimed_facts(outcome))
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.audit_refused(self, token, ctx, refusal);
        }
        SeatVerdict::proceed(
            token,
            // The step is the decision's stamp. A refusal that reaches the refused-audit door
            // without one never came from a decision; the door itself is the latest step it could
            // have been raised at, which is a truer answer than a fixed sentinel.
            unclaimed_facts(&Outcome::Refused(
                refusal
                    .step()
                    .unwrap_or(busbar_contract::caps::StepName::Admit),
                refusal.reason(),
            )),
        )
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.encode(self, token, ctx, outcome);
        }
        SeatVerdict::refuse(
            token,
            Refusal::new(busbar_contract::caps::ReasonCode::DecodeFailed),
        )
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        if let Some(plane) = self.registry.resolve(self, ctx) {
            return plane.evidence(self, ctx);
        }
        // Nothing located, nothing accrued, no upstream candidate: a unit no plane claimed reached
        // no destination, and the settlement table's answer for that is zero on every row.
        Evidence::default()
    }
}

/// The operation class a unit no plane claimed is sealed under.
///
/// Its own word, and not a borrowed one. What happened is that the unit reached the root's audit
/// door without any plane on this node having composed it, which is neither a read nor a write of
/// anything an operator administers.
const OP_UNCLAIMED: &str = "unclaimed";

/// What the record says about a unit this root did not compose.
///
/// The admin plane's "the verb did not resolve" facts used to answer here, and they name an
/// administrative READ — so every unit of every other plane that reached this door was sealed as
/// one. A voice turn or a chat completion refused at the root is not an operator reading a
/// configuration page, and a record that says it was is wrong about the one thing an audit record
/// exists to state. Nothing here is derived from the admin plane, because nothing about this unit
/// is administrative.
fn unclaimed_facts(outcome: &Outcome) -> busbar_contract::AuditFacts {
    busbar_contract::AuditFacts {
        op_class: busbar_contract::OpClassId::new(OP_UNCLAIMED),
        finish: if outcome.is_completed() {
            busbar_contract::FinishClass::Complete
        } else {
            busbar_contract::FinishClass::Error
        },
    }
}

#[cfg(test)]
#[path = "tests/kernel.rs"]
mod tests;
