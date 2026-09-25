// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The journal, the ledger and the audit unit's two streams — and the one `if` that decides whether
//! this node writes to a disk.
//!
//! ## One journal, and this is where every unit is bound to it
//!
//! The journal unit owns the chain: fixed records, one numbering, one head. What it deliberately
//! does NOT own is any knowledge of what a posting, a checkpoint or a sealed audit record contains —
//! a log that could parse them would be a log that has to change whenever they do. So the binding
//! lives here, in the composition root, which is the one place where the journal, the ledger and the
//! audit unit are all in scope at once.
//!
//! Four kinds of record are bound below, and they are the four that used to keep their own private
//! notion of where they lived:
//!
//! - the **audit unit's sealed records**, which had a chain of their own with no position in any
//!   wider order;
//! - the **ledger's postings**, which moved figures in memory and were reconstructed afterwards;
//! - the **ledger's checkpoints**, which were sealed and signed and then held by whoever asked for
//!   one;
//! - the **migration marker**, which lived in the store adapter's node-local shim and therefore did
//!   not survive a restart even on a node that had a data directory to keep it in.
//!
//! All four are now journal records with a class, in one chain, verifiable against each other. That
//! is what "one journal" buys: a settlement and the audit record for it have an ORDER, and an
//! auditor can say which came first without asking two units that never agreed on a clock.
//!
//! ## The branch, and why it is the only place the data directory is read
//!
//! A deployment that configures no data directory needs none: without one the journal is
//! memory-buffered and shipped to the configured store, and durability is the store's durability.
//! That is not a degraded mode — it is the previous release's shape, and the great majority of
//! deployments run it.
//!
//! The journal unit states the rule as a type, and says so in its own words: *constructing an
//! on-disk log IS the decision to write to a disk; nothing probes for a directory or guesses at
//! one*. So there is exactly one branch, it is here, and it is the only place on this path that
//! reads the configured directory. Nothing downstream may probe, resolve a keyset path
//! speculatively, or open anything "just in case" — a file appearing next to a configuration that
//! asked for none is the failure this shape exists to make impossible, and the tests below assert
//! it by listing the directory rather than by trusting the code.
//!
//! ## The shipper is part of the answer, not an optimisation, and it has a name
//!
//! Without a data directory, the journal is *shipped to the configured store synchronously*, which
//! is why the unset branch takes the store's shipper rather than the null one. That shipper is the
//! store adapter's, and the verb behind it is the contract's `append_batch(stream, records)` —
//! segment-level batched, idempotent on the `(node, node_seq)` pair the journal's records carry,
//! which is what makes a re-offered batch after a store hiccup append what is new and pass over what
//! is already there. Reading one record of the chain back by key is the other three the contract
//! adds for a kernel-held durable record, `record_put`, `record_get` and `record_scan`.
//!
//! On every store this binary can load, all four are answered by the adapter's NODE-LOCAL SHIM: the
//! binary's store window tops out below the payload schema at which those operations gain a wire, so
//! there is no published store that speaks them and the shim is the answer rather than a fallback.
//! It acknowledges and never fails, which is why a memory-buffered journal on such a deployment
//! never sees a durability loss it did not deserve. A node with no store configured and no directory
//! keeps nothing, which is again the previous release's behaviour and not a silent data loss: there
//! was nowhere it was ever going.
//!
//! **One constraint this places on the caller, and it is load-bearing.** In the memory-buffered
//! mode the shipper's answer is part of the commit: a failed ship comes back as a durability loss
//! with the batch retained. On a node with no configured peers — which is every previous-release
//! deployment — a store hiccup must still be write-behind. The retained batch is re-appended, and
//! that is write-behind by another name; what must not happen is the caller turning that answer
//! into a refusal at the door. The previous release served through a store hiccup, and a refusal
//! there would be a deployment that started refusing requests it used to serve. The retention is
//! bounded and the bound's behaviour is the journal unit's named decision, not this module's.
//!
//! ## Dual writing is the default, not an option
//!
//! The ledger is constructed dual-writing onto the previous release's rows. Two things require it
//! and neither is optional: the reconciliation identity — ledger sums equal legacy spend, fee count
//! equals billable requests — and rollback, which is the previous release's binary reading the
//! rows this one wrote. It is constructed before anything listens, because the first accepted
//! connection can settle.
//!
//! ## One administrative audit ring, and it is not here
//!
//! The root holds the audit unit's RECORD chain — the new fixed record, fed by the audit step and
//! journalled beside the postings. It holds no administrative mutation ring. The previous release's
//! administrative chain is the kernel's one durable ring, written by the core-admin handlers as each
//! mutation applies and served by `GET /api/v1/admin/audit`. The root used to keep a second,
//! RAM-only copy of it behind a seam that persisted nothing and that no endpoint read (item 237);
//! a second ring is a second answer to "what changed", so there is one.
//!
//! Journalling a sealed record does not touch the administrative ring: the journal carries only
//! its own record classes, and there is a test below that says so.

use std::path::{Path, PathBuf};

use crate::root::kernel::PinnedHistory;

use busbar_contract::caps::{DurabilityLost, DurableWrite, Grant, PostingFlags, StepName};
use busbar_kernel_audit::{AuditChain, AuditRecord};
use busbar_kernel_ledger::checkpoint::Checkpoint;
use busbar_kernel_ledger::cost::{HistoryView, MoneyError};
use busbar_kernel_ledger::legacy::{LegacyRows, RecordingRows};
use busbar_kernel_ledger::migration::{MigrationError, MigrationMarker, MigrationRecords};
use busbar_kernel_ledger::settle::{Figures, Ledger, Settlement};
use busbar_kernel_ledger::totals::{
    BucketId, BucketScope, CapDimension, Totals, TotalsKey, WindowStart,
};
use busbar_kernel_wal::{
    BodyReader, BodyWriter, Entry, Journal, JournalAck, JournalRecord, Mode, OpenError,
    RecordClass, Shipper,
};

/// The book rebuild: replaying the journal's chain back into a ledger, and the restart
/// reconciliation over the result. Split out for `structure-lint`; a private child module, so its
/// items reach here the same way any other item defined directly in this file would, and the two
/// that are part of this module's own public surface are re-exported below so no caller's path
/// changes.
mod replay;
use replay::{apply_opened, replay_into, same_movement, Replayed};
pub use replay::{JournalDisagreement, Recoverable};

/// The node amendment journal bound to the chain: each sealed amendment journalled, and the node
/// journal rebuilt from the chain at boot. A private child module, as `replay` is.
mod amend;
// Re-exported for its one production caller, `main`'s boot-book open, which a build runs only when a
// root leg opens the book; the unit tests reach it through `amend` directly.
pub use amend::bind_amendments;

/// What the root reads out of configuration to decide the durability shape.
///
/// One field, because there is one decision. Its absence is the previous release's shape and its
/// presence is a deliberate statement that this node keeps its own journal.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DurabilityConfig {
    /// The configured data directory, if the operator named one.
    pub data_dir: Option<PathBuf>,
}

/// The durability stack the root owns: the journal, the ledger and the audit record chain.
pub struct Durability {
    /// The one journal. On disk only where a data directory was configured; otherwise
    /// memory-buffered and shipped through the store adapter's plane-record verbs.
    pub journal: Journal,
    /// The ledger, dual-writing onto the previous release's rows.
    pub ledger: Ledger,
    /// The new fixed record's chain.
    pub record: AuditChain,
    /// The seals this node made, oldest first.
    ///
    /// Retained here rather than re-read off the journal, because the journal does not keep enough
    /// to rebuild one: [`checkpoint_body`] carries the seal's digest and its shape — how many
    /// balances, which watermarks — and deliberately not the balances themselves, so a chain that
    /// verifies stays a fixed size per seal. A reader wanting the sealed figures has to be handed
    /// the checkpoint, so the node keeps the checkpoints it sealed.
    ///
    /// Appended by [`Durability::journal_checkpoint`] and by nothing else, and only after the
    /// journal has taken the record: a seal this node kept but never got onto the chain would be a
    /// figure with no position, which is the one thing the journal exists to prevent.
    pub checkpoints: Vec<Checkpoint>,
    /// WHICH BOOT OF THIS JOURNAL this process is: one more than the highest any record on the
    /// chain was written under, and 1 on a chain that holds none.
    ///
    /// A unit's key and its monotonic reading both restart at every boot, so on their own they do
    /// not name one unit across a restart. Every hold and posting record carries the incarnation
    /// that wrote it, and a hold opened under one incarnation is closed only by a posting written
    /// under the same one — which is what lets a boot tell a hold its predecessor left open from a
    /// hold this process has not got to yet.
    pub incarnation: u64,
    /// What the RESTART RECONCILIATION found when this book was built (item 128): every balance on
    /// which the book in memory and the book the journal rebuilds disagree, and any journal record
    /// that could not be read. Empty is the only good answer. See [`Durability::reconcile_with_journal`].
    pub restart_findings: Vec<JournalDisagreement>,
    /// How many holds a predecessor left open that this boot RECOVERED and posted (item 127).
    pub recovered_holds: usize,
    /// The idempotency claims a predecessor took with no hold ever made durable behind them, VOIDED
    /// at this boot so a client's retry is not answered with a unit that never ran. Oldest first.
    pub voided_claims: Vec<String>,
    /// THE COUNTS ROWS WHOSE PRICING REFUSED (#42, #43, #71): a unit's raw counts, on the chain,
    /// that the card in force could not price. The fact is kept — the counts are what the unit did
    /// — and the money is not: no figure moved the book for them. Every read of the balance and
    /// window one of these sits on REFUSES rather than answering the priced remainder, which would
    /// be a silent zero for the class the card was silent about. Rebuilt from the chain at boot.
    refused: Vec<Posting>,
    /// Settled figures the book moved whose journal record the log has not confirmed yet.
    ///
    /// Each was moved out of `settled` into `unreconciled` when its append came back as a
    /// durability loss (ARCHITECTURE.md 4.2: nothing is reported as settled that the store has not
    /// confirmed), and each moves back when a later append succeeds — the log re-offers a retained
    /// batch ahead of the next one, so a later success is the confirmation.
    unconfirmed: Vec<(TotalsKey, WindowStart, i128)>,
    /// WHAT BOOT RECOVERY SET ASIDE from a corrupt journal segment: each entry names the segment
    /// file, the byte offset, the byte count and the quarantine file the damaged remainder went to.
    /// Empty is the only good answer. The records in them are NOT on the book, so this node's
    /// figures read lower than what it served. Logged at `ERROR` and counted on
    /// `busbar_journal_quarantined_total` when the book is built; put on the chain as a
    /// `ChainBreak` record by [`Durability::journal_quarantines`].
    pub quarantined: Vec<busbar_kernel_wal::Quarantine>,
    /// WHERE A REPLAY READS THE DATED RATE-CARD HISTORY IT PRICES THE CHAIN'S COUNTS AGAINST (#71,
    /// #79). The chain carries no money: a posting is a unit's raw counts and the arrival instant
    /// they price at, so rebuilding the book is `Σ count × rate(card_at(arrived_ms))` through the
    /// one spend function. Asked at the moment of the rebuild, never cached, so a card appended
    /// after boot is in the view a later reconciliation prices against.
    history: HistorySource,
    /// THE HOLDER WHOSE DATED HISTORY THIS BOOK REBUILT FROM ITS CHAIN at boot (#79), and so the
    /// one whose later applies it journals ([`crate::root::kernel::RootHistory::bind_journal`]).
    /// `None` on every book a production boot with a data directory did not build.
    pub(crate) cards_from: Option<&'static crate::root::kernel::RootHistory>,
    /// THE POSITION OF THE NEWEST AMENDMENT this book rebuilt the node amendment journal from
    /// ([`Durability::restore_amendments`]), and so the book whose later amendments are journalled
    /// ([`bind_amendments`]). `None` on every book that rebuilt nothing.
    amendments_through: Option<u64>,
}

/// Where the book reads the dated rate-card history a replay prices against: a snapshot pinned
/// at the moment of the read.
pub type HistorySource = Box<dyn Fn() -> Option<PinnedHistory> + Send + Sync>;

/// The process's own history: the one every unit's exit priced against.
fn root_history() -> HistorySource {
    Box::new(|| crate::root::kernel::ROOT_CARD.pin())
}

impl std::fmt::Debug for Durability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Durability")
            .field("mode", &self.journal.mode())
            .field("head", &self.journal.head_hex())
            .finish_non_exhaustive()
    }
}

impl Durability {
    /// Whether this node writes its journal to a disk.
    #[must_use]
    pub fn on_disk(&self) -> bool {
        matches!(self.journal.mode(), Mode::OnDisk)
    }

    /// Put a durable `ChainBreak` record on the journal for every segment remainder boot recovery
    /// quarantined, naming the segment file, the byte offset, the byte count and the quarantine
    /// file. `wall` is seconds since the Unix epoch. `Ok(None)` when nothing was set aside.
    ///
    /// # Errors
    ///
    /// The journal could not make the records durable.
    pub fn journal_quarantines(
        &mut self,
        token: &Grant<DurableWrite>,
        at: StepName,
        wall: u64,
    ) -> Result<Option<JournalAck>, DurabilityLost> {
        self.journal.record_quarantines(token, at, wall)
    }

    /// Put a sealed audit record on the journal.
    ///
    /// The audit unit sealed it; this puts it in the one order. The record's own chain is unchanged
    /// and the previous release's chain is not touched at all — the body here is the sealed record's
    /// two digests and the facts an auditor reads it for, and the class is `Transaction` because a
    /// sealed record is what a unit's money movement looks like when it is finished.
    ///
    /// # Errors
    ///
    /// The journal could not make the record durable. Without a data directory that means the store
    /// refused the batch; with one it means a write or a sync failed.
    pub fn journal_audit(
        &mut self,
        record: &AuditRecord,
        token: &Grant<DurableWrite>,
        at: StepName,
    ) -> Result<JournalAck, DurabilityLost> {
        let entry = Entry::new(RecordClass::Transaction, audit_body(record))
            .at(record.wall, record.mono)
            .under(record.controls.lease_epoch, record.controls.policy_epoch);
        self.journal.append(token, at, &[entry])
    }

    /// Put a settlement on the journal.
    ///
    /// # Errors
    ///
    /// As [`Durability::journal_audit`].
    pub fn journal_posting(
        &mut self,
        posting: &Posting,
        token: &Grant<DurableWrite>,
        at: StepName,
    ) -> Result<JournalAck, DurabilityLost> {
        let entry =
            Entry::new(RecordClass::Transaction, posting.body()).at(posting.wall, posting.mono);
        self.journal.append(token, at, &[entry])
    }

    /// Put a sealed checkpoint on the journal.
    ///
    /// The checkpoint already carries its own body digest and its signature; what the journal adds
    /// is a POSITION — which postings it comes after, on the same chain those postings are on. A
    /// checkpoint whose position had to be inferred from a clock would be a checkpoint two nodes
    /// could disagree about.
    ///
    /// # Errors
    ///
    /// As [`Durability::journal_audit`].
    pub fn journal_checkpoint(
        &mut self,
        checkpoint: &Checkpoint,
        token: &Grant<DurableWrite>,
        at: StepName,
    ) -> Result<JournalAck, DurabilityLost> {
        let entry =
            Entry::new(RecordClass::Checkpoint, checkpoint_body(checkpoint)).at(checkpoint.wall, 0);
        let ack = self.journal.append(token, at, &[entry])?;
        self.checkpoints.push(checkpoint.clone());
        Ok(ack)
    }

    /// The newest migration marker on the chain, if this deployment has migrated.
    ///
    /// The same replay [`JournalMigrationRecords::read_marker`] does, reachable without a durability
    /// token — because reading the chain is not a write and a reader that had to hold the credential
    /// for writing one would be a read seam holding a write capability. The migration step keeps its
    /// own path because it needs the token anyway for the marker it may then seal.
    ///
    /// A journal that will not read back answers `None` here rather than an error. That is the right
    /// answer for a READ of the marker — a view says what it can see — and it is deliberately not
    /// the answer the migration step gets, which distinguishes "unreadable" from "absent" because
    /// treating one as the other there is how a deployment re-opens balances it already opened.
    #[must_use]
    pub fn migration_marker(&self) -> Option<MigrationMarker> {
        let replayed = self.journal.replay().ok()?.ok()?;
        replayed
            .iter()
            .filter(|r| r.class == RecordClass::Migration)
            .max_by_key(|r| r.node_seq)
            .and_then(|r| migration_marker_from(&r.body))
    }

    /// OPEN A HOLD ON THE BOOK AND ON THE JOURNAL, before the unit it reserves for runs (item 127).
    ///
    /// The half of the protocol that was never written: every production journal write used to
    /// happen at or after SETTLE time, so a node killed mid-unit left a hold that existed only in
    /// memory — nothing on the chain said it had been opened, so nothing at the next boot could
    /// settle it. This record is what a boot reads back: a hold opened here and closed by no
    /// posting of the same incarnation is a hold a predecessor left open, and
    /// [`build_for_node`] recovers and posts it.
    ///
    /// The book moves as the identity describes a reservation (item 26): the amount is DRAWN from
    /// the store into the slice, and spent out of the slice into the hold — `drawn` and
    /// `open_holds` rise together and the slice nets to nothing. The settlement that closes it moves
    /// the other half, through [`Ledger::post`].
    ///
    /// `at.stamp.mono` is the unit's own arrival reading, and the posting that closes the hold must
    /// carry the same one on the same balance and window: with the incarnation, that names the unit
    /// on the chain.
    ///
    /// THE RECORD HOLDS NO MONEY (#71, #77(3)). What the reservation was sized for is a set of raw
    /// counts — `reservation` — and `arrived_ms` is the instant they price at (#79). The figure the
    /// book moves by is DERIVED from the two through the one spend function, here and again on
    /// every replay, so a restart rebuilds the same reservation from the same fact. A reservation
    /// the card cannot price moves no balance, on this side and on the replay alike.
    ///
    /// # Errors
    ///
    /// As [`Durability::journal_audit`]. The book has moved either way, and a failed append is
    /// retained and re-offered by the log — it is never a refusal at the door.
    pub fn open_hold(
        &mut self,
        at: &Settling<'_>,
        principal: &busbar_contract::caps::PrincipalId,
        reservation: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<JournalAck, DurabilityLost> {
        let opened = HoldOpened {
            key: at.key.clone(),
            window: at.window,
            principal: principal.as_str().to_string(),
            held: Held::Counts {
                counts: reservation.clone(),
                arrived_ms,
            },
            incarnation: self.incarnation,
            wall: at.stamp.wall,
            mono: at.stamp.mono,
        };
        let pinned = (self.history)();
        let reserved = opened.reserved(pinned.as_ref().map(PinnedHistory::view).as_ref());
        apply_opened(&mut self.ledger, &opened.key, opened.window, reserved);
        let entry =
            Entry::new(RecordClass::Transaction, opened.body()).at(opened.wall, opened.mono);
        let appended = self.journal.append(at.durability, at.step, &[entry]);
        self.confirm(appended.as_ref().ok());
        appended
    }

    /// THE RESTART RECONCILIATION (item 128): the book in memory against the book the journal
    /// rebuilds, balance by balance.
    ///
    /// The check that used to be here compared an EMPTY book with empty checkpoints: every restart
    /// began from `Ledger::dual_writing` over nothing, so the money view reset to zero and the
    /// identity passed because both sides were zero — an instrument that could not say no. This one
    /// compares two things that can disagree: the figures this node holds, and the figures its own
    /// chain says it should hold. A balance the book lost, or moved without a record, is named with
    /// both readings.
    ///
    /// `settled` is compared together with `unreconciled`, because a posting whose append the log
    /// has not confirmed is moved between those two and has not left the book.
    #[must_use]
    pub fn reconcile_with_journal(&self) -> Vec<JournalDisagreement> {
        let records = match self.journal.replay() {
            Ok(Ok(records)) => records,
            Ok(Err(broken)) => {
                return vec![JournalDisagreement::Unreadable(format!(
                    "the journal does not verify: {broken:?}"
                ))]
            }
            Err(e) => {
                return vec![JournalDisagreement::Unreadable(format!(
                    "the journal could not be read: {e}"
                ))]
            }
        };
        let mut rebuilt = Ledger::new();
        let pinned = (self.history)();
        let view = pinned.as_ref().map(PinnedHistory::view);
        let replay = replay_into(&mut rebuilt, &records, view.as_ref(), false);
        let mut findings: Vec<JournalDisagreement> = replay
            .unreadable
            .into_iter()
            .map(JournalDisagreement::Unreadable)
            .collect();
        // Compared by WHICH unit's row, not by the refusal's wording: the reason a replay gives is
        // the one spend function's, derived at the read, and the live row carries the reason the
        // settling arm was handed.
        let unit = |row: &Posting| (row.incarnation, row.key.clone(), row.window, row.mono);
        if replay.refused.iter().map(unit).collect::<Vec<_>>()
            != self.refused.iter().map(unit).collect::<Vec<_>>()
        {
            findings.push(JournalDisagreement::RefusedRows {
                journal: replay.refused.len(),
                book: self.refused.len(),
            });
        }
        let journal = rebuilt.book().snapshot();
        let book = self.ledger.book().snapshot();
        let mut keys: Vec<&(TotalsKey, WindowStart)> = journal.keys().chain(book.keys()).collect();
        keys.sort();
        keys.dedup();
        for at in keys {
            let from_journal = journal.get(at).copied().unwrap_or_default();
            let in_book = book.get(at).copied().unwrap_or_default();
            if !same_movement(&from_journal, &in_book) {
                findings.push(JournalDisagreement::Balance {
                    key: at.0.clone(),
                    window: at.1,
                    journal: Box::new(from_journal),
                    book: Box::new(in_book),
                });
            }
        }
        findings
    }

    /// THE CHAIN, READ BACK AND PRICED: every posting on it, in chain order, with the figures a
    /// replay derives for it from its counts at its epoch (#71, #79) — the money as a view over
    /// the records, never a figure any record holds. A chain that will not read back reads as
    /// nothing; [`Durability::reconcile_with_journal`] is the read that says why.
    #[must_use]
    pub fn read_back(&self) -> Vec<Posting> {
        let Ok(Ok(records)) = self.journal.replay() else {
            return Vec::new();
        };
        let pinned = (self.history)();
        let view = pinned.as_ref().map(PinnedHistory::view);
        replay_into(&mut Ledger::new(), &records, view.as_ref(), true).read
    }

    /// Note what a journal append said about the settled figures the log had not confirmed.
    ///
    /// A success means every batch the log was retaining went out ahead of this one, so each
    /// unconfirmed figure moves back into `settled`. A success that DROPPED records to make room
    /// (an overflow, named on the chain by a break) cannot say which went, so nothing moves back.
    fn confirm(&mut self, ack: Option<&JournalAck>) {
        if ack.is_some_and(|ack| ack.overflow.is_none()) {
            for (key, window, amount) in std::mem::take(&mut self.unconfirmed) {
                self.ledger
                    .record_unreconciled(&key, window, amount.saturating_neg());
            }
        }
    }

    /// Recover every hold a predecessor left open: materialise it from its record and settle it
    /// through the recovery table, then post that settlement onto the book and the chain as if the
    /// unit had ended — under the incarnation and arrival reading that OPENED it, so the posting
    /// closes that hold and no later boot recovers it twice.
    ///
    /// The table reads what the chain says the unit did. A unit whose dispatch record was durable
    /// had something leave the node, so its posting is the last accrual checkpoint it made — its
    /// counts, priced at their epoch, and none if it never checkpointed — marked RECOVERED. A unit
    /// with no dispatch record sent nothing: zero, marked VOIDED. Neither guesses upward.
    fn recover(&mut self, open: Vec<Recoverable>) {
        if open.is_empty() {
            return;
        }
        let kernel = busbar_kernel::teller::Kernel::new();
        let token = kernel.durability_token();
        let canary = busbar_contract::caps::Canary::new();
        let current = busbar_contract::slice::Epoch(self.incarnation);
        let pinned = (self.history)();
        let view = pinned.as_ref().map(PinnedHistory::view);
        // The checkpoint's figure, derived from its counts like every figure on this book. One the
        // card refuses is kept as a refused row and posts nothing.
        let checkpointed: Vec<Result<u64, String>> = open
            .iter()
            .map(|held| match &held.checkpoint {
                None => Ok(0),
                Some((counts, arrived_ms)) => price_counts(view.as_ref(), counts, *arrived_ms)
                    .and_then(|nanos| u64::try_from(nanos).map_err(|_| MoneyError::Overflow))
                    .map_err(|refused| format!("{refused:?}")),
            })
            .collect();
        let records: Vec<busbar_kernel::recovery::HoldRecord> = open
            .iter()
            .zip(&checkpointed)
            .map(|(held, checkpointed)| busbar_kernel::recovery::HoldRecord {
                unit: busbar_contract::UnitKey::new(held.hold.mono),
                principal: busbar_contract::caps::PrincipalId::new(held.hold.principal.as_str()),
                // The reservation as the replay derived it from the hold's counts — the same
                // figure the rebuilt book already holds open for it.
                reserved: held.hold.reserved(view.as_ref()),
                checkpointed: checkpointed.as_ref().copied().unwrap_or(0),
                dispatched: held.dispatched,
                lease_epoch: busbar_contract::slice::Epoch(held.hold.incarnation),
            })
            .collect();
        let posted = busbar_kernel::recovery::recover_all(&kernel, &records, current, &canary);
        for ((held, checkpointed), posted) in open.iter().zip(checkpointed).zip(posted) {
            let hold = &held.hold;
            let at = Settling {
                key: &hold.key,
                window: hold.window,
                durability: &token,
                step: StepName::Meter,
                stamp: PostingStamp {
                    rate_card_version: busbar_kernel_ledger::cost::HistorySeq::OPENING.get(),
                    wall: hold.wall,
                    mono: hold.mono,
                },
            };
            // What the posting is evidence FOR: the checkpoint's counts, where the table posted
            // them. A unit the table voided posts nothing and carries nothing.
            let evidence = held
                .checkpoint
                .as_ref()
                .filter(|_| held.dispatched)
                .map(|(counts, arrived_ms)| (counts.clone(), *arrived_ms));
            let fee_count = evidence.as_ref().map_or(0, |(counts, _)| counts.fee_count);
            let settlement = self
                .ledger
                .post_counted(at.key, at.window, posted, fee_count);
            let recovered = self.journal_settlement_counted(
                &at,
                settlement,
                hold.incarnation,
                evidence.as_ref().map(|(counts, _)| counts),
                evidence.as_ref().map_or(0, |(_, arrived_ms)| *arrived_ms),
            );
            // A checkpoint the card refuses to price is kept, as every refused row is, and every
            // read over its balance refuses — the same row a replay of this chain rebuilds.
            if let (Err(why), Some((counts, arrived_ms))) = (checkpointed, evidence) {
                if let Ok(Settled { mut posting, .. }) = recovered {
                    posting.refusal = Some(why);
                    posting.counts = Some(counts);
                    posting.arrived_ms = arrived_ms;
                    self.refused.push(posting);
                }
            }
            self.recovered_holds = self.recovered_holds.saturating_add(1);
        }
    }

    /// VOID every idempotency claim a predecessor took with no hold made durable behind it.
    ///
    /// A claim whose unit no hold record names died between the claim and the hold — the one kill
    /// point at which [`busbar_kernel::recovery::voids_claim`] says the claim must go: kept, it is
    /// a key that would answer the client's retry with a unit that never ran. The void is a record
    /// of its own on the chain, so no later boot voids it again and a reader can see it happened.
    fn void_claims(&mut self, unheld: Vec<ClaimTaken>) {
        let point = busbar_kernel::recovery::KillPoint::BetweenClaimAndHold;
        if unheld.is_empty() || !busbar_kernel::recovery::voids_claim(point) {
            return;
        }
        let token = busbar_kernel::teller::Kernel::new().durability_token();
        for taken in unheld {
            let record = ClaimRecord {
                taken,
                voided: true,
            };
            let entry = Entry::new(RecordClass::Transaction, record.body())
                .at(record.taken.wall, record.taken.mono);
            // A durability loss is retained and re-offered like any other append; the claim is
            // void in this process either way, and a boot that finds no void record voids it again.
            let _ = self.journal.append(&token, StepName::Admit, &[entry]);
            self.voided_claims.push(record.taken.claim);
        }
    }

    /// RECORD THAT A UNIT DISPATCHED — something left the node for it.
    ///
    /// Written before the dispatch, on the unit's balance and window and under its arrival
    /// reading, so it names the hold [`Durability::open_hold`] opened. A node killed after this
    /// record is durable recovers the unit's hold as consumed up to its last accrual checkpoint and
    /// marked RECOVERED; one killed before it recovers the hold as nothing, marked VOIDED.
    ///
    /// # Errors
    ///
    /// As [`Durability::journal_audit`]. A failed append is retained and re-offered by the log — it
    /// is never a refusal of the dispatch.
    pub fn journal_dispatch(&mut self, at: &Settling<'_>) -> Result<JournalAck, DurabilityLost> {
        self.journal_mark(at, Mark::Dispatched)
    }

    /// RECORD A UNIT'S ACCRUAL SO FAR, as counts and the instant they price at (#71, #79) — never a
    /// figure. The last one a unit makes is what a recovery posts for it if the node dies before
    /// the unit settles.
    ///
    /// # Errors
    ///
    /// As [`Durability::journal_dispatch`].
    pub fn checkpoint_accrual(
        &mut self,
        at: &Settling<'_>,
        counts: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<JournalAck, DurabilityLost> {
        self.journal_mark(
            at,
            Mark::Accrued {
                counts: counts.clone(),
                arrived_ms,
            },
        )
    }

    /// RECORD AN IDEMPOTENCY CLAIM a unit took, on its balance and window and under its arrival
    /// reading, before its hold is made durable. A boot that finds the claim with no hold behind it
    /// voids it ([`Durability::voided_claims`]).
    ///
    /// # Errors
    ///
    /// As [`Durability::journal_dispatch`].
    pub fn journal_claim(
        &mut self,
        at: &Settling<'_>,
        claim: &str,
    ) -> Result<JournalAck, DurabilityLost> {
        let record = ClaimRecord {
            taken: ClaimTaken {
                claim: claim.to_string(),
                key: at.key.clone(),
                window: at.window,
                incarnation: self.incarnation,
                wall: at.stamp.wall,
                mono: at.stamp.mono,
            },
            voided: false,
        };
        let entry =
            Entry::new(RecordClass::Transaction, record.body()).at(at.stamp.wall, at.stamp.mono);
        let appended = self.journal.append(at.durability, at.step, &[entry]);
        self.confirm(appended.as_ref().ok());
        appended
    }

    fn journal_mark(
        &mut self,
        at: &Settling<'_>,
        mark: Mark,
    ) -> Result<JournalAck, DurabilityLost> {
        let record = UnitMark {
            key: at.key.clone(),
            window: at.window,
            incarnation: self.incarnation,
            wall: at.stamp.wall,
            mono: at.stamp.mono,
            mark,
        };
        let entry =
            Entry::new(RecordClass::Transaction, record.body()).at(record.wall, record.mono);
        let appended = self.journal.append(at.durability, at.step, &[entry]);
        self.confirm(appended.as_ref().ok());
        appended
    }

    /// Settle a hold and put what it produced on the journal, in that order.
    ///
    /// The binding the journal was built for, and the reason [`Durability::journal_posting`] is a
    /// method here rather than a call the ledger makes: the ledger unit owns the arithmetic and
    /// knows nothing about a chain, and the journal unit owns the chain and knows nothing about a
    /// posting. Joining them is the composition root's job, and doing it in ONE function is what
    /// makes "every posting is a journal record" a fact about the code rather than a convention
    /// every call site has to remember.
    ///
    /// A unit that ran past everything reservable leaves two records, not one. The settlement says
    /// what was reserved and what was posted; the overdraft record says what part of it nothing
    /// backed, as its own entry in the same order, so the carry into the next window can be read
    /// off the chain rather than inferred from a difference between two settlements.
    ///
    /// # Errors
    ///
    /// As [`Durability::journal_audit`]. The books have already moved when this fails — value was
    /// delivered and the settlement is the truth about it — so the failure is a durability loss to
    /// be retained and re-appended, never a settlement that is rolled back.
    pub fn settle(
        &mut self,
        at: &Settling<'_>,
        hold: busbar_contract::caps::Hold,
        priced_nanos: u128,
        usage: &busbar_contract::caps::Usage,
        ledger: &busbar_contract::caps::Grant<busbar_contract::caps::WriteMoney>,
    ) -> Result<Settled, DurabilityLost> {
        let settlement =
            self.ledger
                .settle_recording(at.key, at.window, hold, priced_nanos, usage, ledger);
        self.journal_settlement(at, settlement)
    }

    /// Settle a posting the loop's exit path already built, and journal it.
    ///
    /// The exit path owns the hold and consumes it there, so what comes back out of a finished unit
    /// is a posting and never a hold. This is the same act as [`Durability::settle`] from that side:
    /// the books move through the ledger's one book-moving function, and the same two records reach
    /// the same chain.
    ///
    /// # Errors
    ///
    /// As [`Durability::settle`].
    pub fn settle_posted(
        &mut self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
    ) -> Result<Settled, DurabilityLost> {
        let settlement = self.ledger.post(at.key, at.window, posted);
        self.journal_settlement(at, settlement)
    }

    /// [`Durability::settle_posted`] for a unit whose RAW COUNTS are known (#71): the posting record
    /// carries them, per class string — the reserved four and every open class — and `arrived_ms`,
    /// the instant they price at (#79). The record carries NO figure: the book moves by the posting
    /// here, and a replay re-derives the same figure from the counts through the one spend function.
    ///
    /// # Errors
    ///
    /// As [`Durability::settle`].
    pub fn settle_counted(
        &mut self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<Settled, DurabilityLost> {
        let settlement = self
            .ledger
            .post_counted(at.key, at.window, posted, counts.fee_count);
        self.journal_settlement_counted(at, settlement, self.incarnation, Some(counts), arrived_ms)
    }

    /// PUT A UNIT'S COUNTS ON THE CHAIN WITH NO FIGURE BEHIND THEM (#43: the write is unconditional).
    ///
    /// For a unit whose counts priced to nothing, or whose pricing REFUSED (#42: a present card
    /// silent about the lane or a hit class, a hole in the history, a figure past the record). The
    /// book does not move — there is no amount, and a zero or a partial would be a figure nobody
    /// priced — but the counts are a fact about what the unit did, and a fact is recorded whether
    /// or not the card can price it. A refused row is kept, and every read of its balance and
    /// window refuses ([`Durability::settled_read`]).
    ///
    /// # Errors
    ///
    /// As [`Durability::journal_audit`]. The row is kept in memory either way and a failed append
    /// is retained and re-offered by the log.
    pub fn post_counts(
        &mut self,
        at: &Settling<'_>,
        principal: &busbar_contract::caps::PrincipalId,
        counts: &UnitCounts,
        arrived_ms: u64,
        refusal: Option<String>,
    ) -> Result<Posting, DurabilityLost> {
        let posting = Posting {
            principal: principal.as_str().to_string(),
            kind: PostingKind::Counted,
            incarnation: self.incarnation,
            key: at.key.clone(),
            window: at.window,
            reserved: 0,
            settled: 0,
            overdraft: 0,
            rate_card_version: at.stamp.rate_card_version,
            wall: at.stamp.wall,
            mono: at.stamp.mono,
            arrived_ms,
            flags: PostingFlags::NONE,
            counts: Some(counts.clone()),
            refusal,
            era: RecordEra::Counts,
        };
        if posting.refusal.is_some() {
            self.refused.push(posting.clone());
        }
        let entry =
            Entry::new(RecordClass::Transaction, posting.body()).at(posting.wall, posting.mono);
        let appended = self.journal.append(at.durability, at.step, &[entry]);
        self.confirm(appended.as_ref().ok());
        appended.map(|_| posting)
    }

    /// The counts rows whose pricing refused, oldest first.
    #[must_use]
    pub fn refused_rows(&self) -> &[Posting] {
        &self.refused
    }

    /// **THE BOOK'S SETTLED FIGURE FOR ONE BALANCE AND WINDOW — or the refusal (#42).**
    ///
    /// `settled` read together with `unreconciled` (a posting the log has not confirmed has not left
    /// the book). A balance and window on which a unit's counts REFUSED to price has no figure: the
    /// priced remainder would answer the refused class at nothing, which is the silent zero #42
    /// forbids on a present card. So the read refuses, naming the row.
    ///
    /// # Errors
    ///
    /// [`RefusedCounts`]: a counts row on this balance and window whose pricing refused.
    pub fn settled_read(
        &self,
        key: &TotalsKey,
        window: WindowStart,
    ) -> Result<i128, Box<RefusedCounts>> {
        if let Some(row) = self
            .refused
            .iter()
            .find(|row| row.key == *key && row.window == window)
        {
            return Err(Box::new(RefusedCounts {
                key: row.key.clone(),
                window: row.window,
                lane: row
                    .counts
                    .as_ref()
                    .map(|c| c.lane.clone())
                    .unwrap_or_default(),
                refusal: row.refusal.clone().unwrap_or_default(),
            }));
        }
        let figures = self.ledger.book().get(key, window);
        Ok(figures.settled.saturating_add(figures.unreconciled))
    }

    fn journal_settlement(
        &mut self,
        at: &Settling<'_>,
        settlement: Settlement,
    ) -> Result<Settled, DurabilityLost> {
        self.journal_settlement_as(at, settlement, self.incarnation)
    }

    /// [`Durability::journal_settlement`], naming the incarnation the posting belongs to — this
    /// process's own for every live settlement, and the opening incarnation's for a hold recovered
    /// at boot.
    fn journal_settlement_as(
        &mut self,
        at: &Settling<'_>,
        settlement: Settlement,
        incarnation: u64,
    ) -> Result<Settled, DurabilityLost> {
        self.journal_settlement_counted(at, settlement, incarnation, None, 0)
    }

    /// [`Durability::journal_settlement_as`], with the unit's raw counts on the settlement's record
    /// where the caller knows them. The carry beside it repeats no counts, as it repeats no reserved
    /// or settled figure: one fact, one record.
    fn journal_settlement_counted(
        &mut self,
        at: &Settling<'_>,
        settlement: Settlement,
        incarnation: u64,
        counts: Option<&UnitCounts>,
        arrived_ms: u64,
    ) -> Result<Settled, DurabilityLost> {
        let stamp = at.stamp;
        let principal = settlement.posted.principal().as_str().to_string();
        let posting = Posting {
            principal: principal.clone(),
            kind: PostingKind::Settlement,
            incarnation,
            key: at.key.clone(),
            window: at.window,
            reserved: i128::from(settlement.posted.reserved()),
            settled: i128::from(settlement.posted.settled()),
            overdraft: i128::from(settlement.posted.overdraft()),
            rate_card_version: stamp.rate_card_version,
            wall: stamp.wall,
            mono: stamp.mono,
            arrived_ms: counts.map_or(0, |_| arrived_ms),
            flags: settlement.posted.flags(),
            counts: counts.cloned(),
            refusal: None,
            era: RecordEra::Counts,
        };
        // The overdraft's own record. It carries no counts and no figure: the settlement above
        // already carries the fact, and the carry is DERIVED from it, so repeating anything here
        // would double what a replay adds up. What this record holds that nothing else does is the
        // carry's POSITION, on the chain, in order, beside the posting it came out of.
        let overdraft = settlement.overdraft.as_ref().map(|note| Posting {
            principal: principal.clone(),
            kind: PostingKind::Carry,
            incarnation,
            key: note.key.clone(),
            window: note.window,
            reserved: 0,
            settled: 0,
            overdraft: note.amount,
            rate_card_version: stamp.rate_card_version,
            wall: stamp.wall,
            mono: stamp.mono,
            arrived_ms: 0,
            flags: PostingFlags::NONE,
            counts: None,
            refusal: None,
            era: RecordEra::Counts,
        });
        // ONE BATCH, both records. A batch is the unit of durability — one store round trip
        // memory-buffered, one fsync on disk — and the settlement and its carry are two entries of
        // one act rather than two acts. Appending them separately paid twice for it on every
        // overdrafting settlement, and left a window in which the chain held a settlement whose
        // carry was not on it yet.
        let entries: Vec<Entry> = std::iter::once(&posting)
            .chain(overdraft.as_ref())
            .map(|record| {
                Entry::new(RecordClass::Transaction, record.body()).at(record.wall, record.mono)
            })
            .collect();
        match self.journal.append(at.durability, at.step, &entries) {
            Ok(ack) => {
                self.confirm(Some(&ack));
                Ok(Settled {
                    settlement,
                    posting,
                    overdraft,
                })
            }
            Err(lost) => {
                // The books moved and the chain does not have it yet (item 26). What was settled is
                // MOVED to `unreconciled` — not reported as settled until the log confirms it — and
                // moves back on the next append that succeeds. The figure is still accounted for,
                // so the identity does not move.
                let settled = posting.settled;
                if settled != 0 {
                    self.ledger.record_unreconciled(at.key, at.window, settled);
                    self.unconfirmed.push((at.key.clone(), at.window, settled));
                }
                Err(lost)
            }
        }
    }

    /// The ledger's own records, on the journal.
    ///
    /// This is what the migration step binds its marker to. It replaces the store adapter's
    /// node-local shim, which could only ever hold the marker for the life of a process — so a node
    /// with a data directory re-read the previous release's rows on every single boot, and the one
    /// record that says "this deployment has already opened its balances" was the one record with
    /// nowhere durable to live.
    pub fn migration_records<'a>(
        &'a mut self,
        token: &'a Grant<DurableWrite>,
        at: StepName,
    ) -> JournalMigrationRecords<'a> {
        JournalMigrationRecords {
            journal: &mut self.journal,
            token,
            at,
        }
    }
}

/// The facts a posting record needs that neither the books nor the hold hold.
///
/// A stamp rather than three arguments, so a caller cannot get the clock and the card version in the
/// wrong order without the compiler noticing, and so adding a fourth is one change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PostingStamp {
    /// Which card version priced the unit.
    pub rate_card_version: u64,
    /// The wall clock, in whole seconds. The unit's pinned arrival epoch, never a fresh read.
    pub wall: u64,
    /// The node's monotonic clock.
    pub mono: u64,
}

/// Where a settlement lands: which balance, which window, on whose authority, and stamped how.
///
/// One borrowed value rather than six arguments, and it is not only tidiness. The window and the
/// stamp's wall clock are the same pinned arrival epoch read two ways; passing them separately is
/// how a straddling unit ends up booked in one window and recorded in another.
#[derive(Debug, Clone, Copy)]
pub struct Settling<'a> {
    /// Which balance moves.
    pub key: &'a TotalsKey,
    /// Which window it moves in.
    pub window: WindowStart,
    /// The token the journal append is made under.
    pub durability: &'a Grant<DurableWrite>,
    /// Which step the append is attributed to.
    pub step: StepName,
    /// What the record carries beyond the figures.
    pub stamp: PostingStamp,
}

/// What one settlement moved and what it left on the chain.
#[derive(Debug)]
pub struct Settled {
    /// What the ledger did: the posting, the residual released, the overdraft noted.
    pub settlement: Settlement,
    /// The settlement's own journal record.
    pub posting: Posting,
    /// The overdraft's journal record, where the unit ran past everything reservable.
    pub overdraft: Option<Posting>,
}

/// THE MONEY-BOOK SETTLING SEAM (DECISIONS #25 / #26 S2).
///
/// The single interface an exit arm calls to settle its cost onto the durability book. Its DTO is
/// the neutral [`Settling`] descriptor already in this module: it carries the balance the hold
/// reserved against (`key` + `window`), the authority the append is made under (`durability`), and
/// the [`PostingStamp`] the record is dated and ordered by — the reserve/settle/stamp the exit arm
/// performs, expressed with no plane in the name. What settles through it is "an exit arm"; what it
/// settles onto is "the book".
///
/// The seam is `&self`, not `&mut`: the lock over the one book is taken and released BEHIND the
/// seam, per settlement. So any number of exit arms hold the same seam and settle through it
/// concurrently — the seam is the whole of their contention, not a single book each arm has to
/// reach past the others to lock. That is what dissolves the "one-book serialization point": exit
/// arms compose behind the seam rather than sharing one `&mut Durability`.
///
/// Today the only impl is [`SharedBook`], a verbatim pass-through onto the one shared [`Durability`]
/// — byte-for-byte the settlement every exit arm makes now. The consolidated one-book is a later
/// impl swapped in behind this same trait by a one-line composition flip; nothing above the seam
/// changes when it is.
pub trait MoneyBook: Send + Sync {
    /// Settle a posting the exit path already built, and journal it.
    ///
    /// The exit path owns the hold and consumes it there, so what reaches the seam is a
    /// [`busbar_contract::caps::Posted`] and never a hold. This is the settlement act every plane's exit arm
    /// makes; see [`Durability::settle_posted`] for the book side of it.
    ///
    /// # Errors
    ///
    /// The journal could not make the record durable. The books have already moved — value was
    /// delivered and the settlement is the truth about it — so this is a durability loss to be
    /// retained and re-appended, never a settlement that is rolled back.
    fn settle_posted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
    ) -> Result<Settled, DurabilityLost>;

    /// [`MoneyBook::settle_posted`] with the unit's raw counts on the record (#71). See
    /// [`Durability::settle_counted`].
    ///
    /// # Errors
    ///
    /// As [`MoneyBook::settle_posted`].
    fn settle_counted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<Settled, DurabilityLost>;

    /// The unit's raw counts with no figure behind them — priced to nothing, or REFUSED (#42/#43).
    /// See [`Durability::post_counts`].
    ///
    /// # Errors
    ///
    /// As [`MoneyBook::settle_posted`].
    fn post_counts(
        &self,
        at: &Settling<'_>,
        principal: &busbar_contract::caps::PrincipalId,
        counts: &UnitCounts,
        arrived_ms: u64,
        refusal: Option<String>,
    ) -> Result<Posting, DurabilityLost>;
}

/// The byte-identical pass-through: settle onto the ONE shared durability book (DECISION #25).
///
/// Holds a handle on the same `Arc<Mutex<Durability>>` every view reads and every arm settles onto,
/// takes that lock exactly the way every other holder takes it, and delegates verbatim to
/// [`Durability::settle_posted`]. It adds nothing and changes nothing: the `Settling` it is handed
/// and the `Posted` it settles reach the ledger's one book-moving function unaltered, so the postings
/// on the chain are the same bytes in the same order they are today. It exists so exit arms name a
/// seam instead of a book, not so the book behaves differently.
pub struct SharedBook {
    durability: std::sync::Arc<std::sync::Mutex<Durability>>,
}

impl SharedBook {
    /// A pass-through over a book the caller already opened and shares.
    #[must_use]
    pub fn over(durability: std::sync::Arc<std::sync::Mutex<Durability>>) -> Self {
        SharedBook { durability }
    }
}

impl std::fmt::Debug for SharedBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedBook").finish_non_exhaustive()
    }
}

impl MoneyBook for SharedBook {
    fn settle_posted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
    ) -> Result<Settled, DurabilityLost> {
        // The same lock, taken the way every other holder of it takes it — read through a poisoning
        // an unrelated unit caused rather than refusing to settle a delivered unit. Held for exactly
        // the settlement and released, which is what lets a second arm settle behind this one.
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability.settle_posted(at, posted)
    }

    fn settle_counted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<Settled, DurabilityLost> {
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability.settle_counted(at, posted, counts, arrived_ms)
    }

    fn post_counts(
        &self,
        at: &Settling<'_>,
        principal: &busbar_contract::caps::PrincipalId,
        counts: &UnitCounts,
        arrived_ms: u64,
        refusal: Option<String>,
    ) -> Result<Posting, DurabilityLost> {
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability.post_counts(at, principal, counts, arrived_ms, refusal)
    }
}

/// A settlement as the journal carries it.
///
/// A value rather than a reference to the ledger's books, because a posting is a thing that happened
/// at a moment and the books are what they are now. The two are different facts and a record built
/// out of the second could not be replayed.
///
/// **THE RECORD IS COUNTS AND AN INSTANT, NEVER MONEY (#71, #77(3)).** What reaches the chain
/// ([`Posting::body`]) is whose unit it was, which balance and window, the unit's raw counts per
/// class and the arrival instant they price at (#79). The three figures below are this node's
/// READING of the posting — what the book moved by, live, or what a replay derived from the counts
/// through the one spend function — and none of them is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posting {
    /// Whose unit it was.
    pub principal: String,
    /// Whether this is the settlement itself or the overdraft carry beside it.
    pub kind: PostingKind,
    /// Which boot of this node's journal the unit belonged to.
    pub incarnation: u64,
    /// Which balance moved.
    pub key: TotalsKey,
    /// Which window it moved in.
    pub window: WindowStart,
    /// What had been reserved — a reading, never written.
    pub reserved: i128,
    /// What was settled — a reading, never written.
    pub settled: i128,
    /// What was spent with no reservation behind it — a reading, never written.
    pub overdraft: i128,
    /// Which card version the unit arrived under: reporting provenance, never a pricing input (#79).
    pub rate_card_version: u64,
    /// The wall clock, in whole seconds.
    pub wall: u64,
    /// The node's monotonic clock.
    pub mono: u64,
    /// THE CARD EPOCH: the unit's arrival instant in milliseconds, which is what the dated history
    /// resolves the card its counts price against (#79). 0 on a record with no counts — there is
    /// nothing on it to price.
    pub arrived_ms: u64,
    /// How far the posting is believed: recovered, voided, estimated, late.
    pub flags: PostingFlags,
    /// THE UNIT'S RAW COUNTS, per class string (#71) — `None` on a record whose writer did not know
    /// them (the carry, and every plane that settles through [`Durability::settle_posted`]), which
    /// prices at nothing.
    pub counts: Option<UnitCounts>,
    /// Why the counts could not be priced; `None` on a row that priced.
    pub refusal: Option<String>,
    /// Which era of the record this was read from. See [`RecordEra`].
    pub era: RecordEra,
}

/// Which shape of posting record a [`Posting`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordEra {
    /// A record carrying counts and the card epoch, and no money: its figures are derived.
    Counts,
    /// A record written while the chain still carried settled FIGURES. Read as written — the
    /// figure is the fact that record holds, and there are no counts to derive another from.
    Figures,
}

/// A unit's raw counts, as its posting record carries them (#71): the lane that served it, the
/// billable-request count the flat fee is charged on, and the count per class string — the reserved
/// four and every OPEN class alike. No price: pricing is the read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitCounts {
    /// The serving lane, the key a card entry is written against.
    pub lane: String,
    /// How many billable requests the unit is.
    pub fee_count: u64,
    /// The count per class string, as the plane reported it.
    pub classes: std::collections::BTreeMap<String, u64>,
}

impl UnitCounts {
    /// The counts as one row of a ledger slice at `arrived_ms` — what a read prices through the one
    /// function (`busbar_kernel_ledger::cost::price_in_view`).
    #[must_use]
    pub fn entry(&self, arrived_ms: u64) -> busbar_kernel_ledger::cost::LedgerEntry {
        self.classes
            .iter()
            .fold(
                busbar_kernel_ledger::cost::LedgerEntry::new(self.lane.as_str(), arrived_ms),
                |entry, (class, count)| entry.with_whole(class.as_str(), *count),
            )
            .with_fee_count(self.fee_count)
    }

    /// Whether the counts say nothing at all: no class and no fee.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fee_count == 0 && self.classes.is_empty()
    }
}

/// **THE BOOK'S MONEY, AS A VIEW** (#71): what `counts` cost at the card in force at `arrived_ms`
/// (#79), in nano-units, through the one spend function.
///
/// Counts that say nothing cost nothing, with or without a history. Anything else needs the dated
/// history, and a node that has none has no entry to price at — a refusal, never a zero (#42).
///
/// # Errors
///
/// Every refusal of the one function: no entry covers the instant, a present card silent about
/// the lane or a hit class, a figure past the range.
pub fn price_counts(
    history: Option<&HistoryView<'_>>,
    counts: &UnitCounts,
    arrived_ms: u64,
) -> Result<u128, MoneyError> {
    if counts.is_empty() {
        return Ok(0);
    }
    let history = history.ok_or(MoneyError::NoCardInForce { at: arrived_ms })?;
    let exact = busbar_kernel_ledger::cost::price_exact(&[counts.entry(arrived_ms)], history)?;
    busbar_kernel_ledger::cost::nanos_of_exact(exact)
}

/// A read that met a counts row the card refused to price (#42). Never a figure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedCounts {
    /// The balance the row sits on.
    pub key: TotalsKey,
    /// Its window.
    pub window: WindowStart,
    /// The lane that served the unit.
    pub lane: String,
    /// Why the pricing refused.
    pub refusal: String,
}

impl std::fmt::Display for RefusedCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} in the window opening at {}: a unit's counts on lane {:?} could not be priced ({}); \
             the balance has no figure",
            self.key, self.window, self.lane, self.refusal
        )
    }
}

impl std::error::Error for RefusedCounts {}

/// The posting flags, as the record carries them: one bit per flag, in a fixed order.
const FLAG_BITS: [PostingFlags; 8] = [
    PostingFlags::ESTIMATED,
    PostingFlags::METER_DISPUTED,
    PostingFlags::OVERDRAFT,
    PostingFlags::LATE_ACCRUAL,
    PostingFlags::RECOVERED,
    PostingFlags::VOIDED,
    PostingFlags::UNPOSTED,
    PostingFlags::DOWNGRADED,
];

fn flags_to_bits(flags: PostingFlags) -> u64 {
    FLAG_BITS
        .iter()
        .enumerate()
        .filter(|(_, flag)| flags.contains(**flag))
        .fold(0, |bits, (at, _)| bits | (1 << at))
}

fn flags_from_bits(bits: u64) -> Option<PostingFlags> {
    // A bit this build does not name is not a body this build wrote.
    if bits >> FLAG_BITS.len() != 0 {
        return None;
    }
    Some(
        FLAG_BITS
            .iter()
            .enumerate()
            .filter(|(at, _)| bits & (1 << at) != 0)
            .fold(PostingFlags::NONE, |flags, (_, flag)| flags.with(*flag)),
    )
}

/// A counts block: present or not, then the lane, the fee count and each class.
fn write_counts(body: &mut BodyWriter, counts: Option<&UnitCounts>) {
    let Some(counts) = counts else {
        body.num(0);
        return;
    };
    body.num(1);
    body.text(&counts.lane);
    body.num(counts.fee_count);
    body.num(counts.classes.len() as u64);
    for (class, count) in &counts.classes {
        body.text(class);
        body.num(*count);
    }
}

/// A counts block, read back. `None` for a block this build did not write.
fn read_counts_block(body: &mut BodyReader<'_>) -> Option<Option<UnitCounts>> {
    match body.num()? {
        0 => return Some(None),
        1 => {}
        _ => return None,
    }
    let lane = body.text()?.to_string();
    let fee_count = body.num()?;
    let n = body.num()?;
    let mut classes = std::collections::BTreeMap::new();
    for _ in 0..n {
        let class = body.text()?.to_string();
        let count = body.num()?;
        // One class twice is not a body this build wrote: the writer iterates a map.
        if classes.insert(class, count).is_some() {
            return None;
        }
    }
    Some(Some(UnitCounts {
        lane,
        fee_count,
        classes,
    }))
}

impl Posting {
    /// The journal body: whose unit, which balance and window, the unit's raw counts and the instant
    /// they price at — and no figure (#71, #77(3)).
    ///
    /// The record opens with its own tag, so it can never be read as a record of the era that
    /// carried figures (which opened with a balance display) and a replay knows which of the two it
    /// holds without guessing. The balance is written as FIELDS, which a rebuild parses back
    /// unambiguously.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut body = BodyWriter::new();
        body.text(POSTING_COUNTS);
        body.num(self.kind.code());
        body.num(self.incarnation);
        body.text(&self.principal);
        write_key(&mut body, &self.key);
        body.num(self.window);
        body.num(self.rate_card_version);
        body.num(self.arrived_ms);
        body.num(flags_to_bits(self.flags));
        write_counts(&mut body, self.counts.as_ref());
        body.finish()
    }

    /// Read a posting back off the chain. `None` for a record that is not one — an audit record, a
    /// hold, or a posting written before the chain could place it on a balance.
    ///
    /// A record of the counts era comes back with its three figures at ZERO and its counts: the
    /// figures are a derivation a replay makes against the dated history ([`price_counts`]), not a
    /// fact the record holds. A record of the figures era comes back as written.
    #[must_use]
    pub fn from_record(record: &JournalRecord) -> Option<Posting> {
        if record.class != RecordClass::Transaction {
            return None;
        }
        let mut body = BodyReader::new(&record.body);
        let first = body.text()?;
        if first == POSTING_COUNTS {
            return Posting::read_counts_era(&mut body, record);
        }
        Posting::read_figures_era(first, &mut body, record)
    }

    fn read_counts_era(body: &mut BodyReader<'_>, record: &JournalRecord) -> Option<Posting> {
        let kind = PostingKind::from_code(body.num()?)?;
        let incarnation = body.num()?;
        let principal = body.text()?.to_string();
        let key = read_key(body)?;
        let window = body.num()?;
        let rate_card_version = body.num()?;
        let arrived_ms = body.num()?;
        let flags = flags_from_bits(body.num()?)?;
        let counts = read_counts_block(body)?;
        if !body.is_done() {
            return None;
        }
        // A counts row carries its counts by definition; one without them is not a body this build
        // wrote.
        if kind == PostingKind::Counted && counts.is_none() {
            return None;
        }
        Some(Posting {
            principal,
            kind,
            incarnation,
            key,
            window,
            reserved: 0,
            settled: 0,
            overdraft: 0,
            rate_card_version,
            wall: record.wall,
            mono: record.mono,
            arrived_ms,
            flags,
            counts,
            refusal: None,
            era: RecordEra::Counts,
        })
    }

    /// A record of the era that carried settled figures: the balance display, the window, three
    /// figures and a version, then the tail that places it, and possibly the counts tail. Migrated
    /// on read: the figures are what that record says, and nothing is rewritten.
    fn read_figures_era(
        shown: &str,
        body: &mut BodyReader<'_>,
        record: &JournalRecord,
    ) -> Option<Posting> {
        let window = body.num()?;
        let reserved = body.figure()?;
        let settled = body.figure()?;
        let overdraft = body.figure()?;
        let rate_card_version = body.num()?;
        if body.text()? != POSTING_TAIL {
            return None;
        }
        let kind = PostingKind::from_code(body.num()?)?;
        let incarnation = body.num()?;
        let principal = body.text()?.to_string();
        let key = read_key(body)?;
        let (counts, refusal) = if body.is_done() {
            // A record written before the counts tail: no counts, and nothing refused.
            (None, None)
        } else {
            read_counts_tail(body)?
        };
        // The two spellings of the balance must name the same one, or this is not a body this
        // build can read and reading it would be guessing.
        if !body.is_done() || key.to_string() != shown {
            return None;
        }
        if kind == PostingKind::Counted && counts.is_none() {
            return None;
        }
        Some(Posting {
            principal,
            kind,
            incarnation,
            key,
            window,
            reserved,
            settled,
            overdraft,
            rate_card_version,
            wall: record.wall,
            mono: record.mono,
            arrived_ms: 0,
            flags: PostingFlags::NONE,
            counts,
            refusal,
            era: RecordEra::Figures,
        })
    }
}

/// The counts tail of the figures era, read back. `None` for a tail this build did not write.
fn read_counts_tail(body: &mut BodyReader<'_>) -> Option<(Option<UnitCounts>, Option<String>)> {
    if body.text()? != POSTING_COUNTS_TAIL {
        return None;
    }
    let lane = body.text()?.to_string();
    let fee_count = body.num()?;
    let n = body.num()?;
    let mut classes = std::collections::BTreeMap::new();
    for _ in 0..n {
        let class = body.text()?.to_string();
        let count = body.num()?;
        if classes.insert(class, count).is_some() {
            return None;
        }
    }
    let refused = body.num()?;
    let why = body.text()?.to_string();
    let refusal = match refused {
        0 if why.is_empty() => None,
        1 => Some(why),
        _ => return None,
    };
    Some((
        Some(UnitCounts {
            lane,
            fee_count,
            classes,
        }),
        refusal,
    ))
}

/// Which of a settlement's two records a [`Posting`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostingKind {
    /// The settlement: what the unit consumed, closing whatever hold it opened. The one a rebuild
    /// moves the book by.
    Settlement,
    /// The overdraft carry beside it, marking where the part nothing reserved was carried out.
    /// Replaying it as well would count that part twice.
    Carry,
    /// A unit's raw counts with no hold behind them and NO figure the book moved by when they
    /// were written (#43: the write is unconditional): the counts priced to nothing, or the card
    /// REFUSED to price them (#42).
    Counted,
}

impl PostingKind {
    fn code(self) -> u64 {
        match self {
            PostingKind::Settlement => 1,
            PostingKind::Carry => 2,
            PostingKind::Counted => 3,
        }
    }

    fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(PostingKind::Settlement),
            2 => Some(PostingKind::Carry),
            3 => Some(PostingKind::Counted),
            _ => None,
        }
    }
}

/// The tag a posting of the counts era opens with. No record of the figures era can begin with
/// it: that record's first field is a balance's display, which always carries a `/`.
const POSTING_COUNTS: &str = "posting.v3";

/// The tag between a figures-era posting's original fields and the tail a rebuild reads.
const POSTING_TAIL: &str = "posting.v2";

/// The tag between the figures-era tail and the unit's raw counts.
const POSTING_COUNTS_TAIL: &str = "posting.counts.v1";

/// The tag a figures-era hold's journal record opens with. No posting can begin with it.
const HOLD_OPENED: &str = "hold.open";

/// The tag a counts-era hold's journal record opens with.
const HOLD_OPENED_COUNTS: &str = "hold.open.v2";

/// What a hold reserved, as its record carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// The counts the reservation was sized for and the instant they price at (#71, #79).
    Counts {
        /// The raw counts.
        counts: UnitCounts,
        /// The unit's arrival, in milliseconds: the card epoch.
        arrived_ms: u64,
    },
    /// A record of the era that carried the reserved FIGURE. Read as written.
    Figure(u64),
}

/// A hold as the journal carries it (item 127): opened, and not yet closed by a posting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldOpened {
    /// Which balance it reserves against.
    pub key: TotalsKey,
    /// Which window.
    pub window: WindowStart,
    /// Whose unit it is.
    pub principal: String,
    /// What was reserved: counts and their epoch, never money.
    pub held: Held,
    /// Which boot of this node's journal opened it.
    pub incarnation: u64,
    /// The unit's arrival, whole seconds.
    pub wall: u64,
    /// The unit's arrival on the node's monotonic clock — with the balance, the window and the
    /// incarnation, the name of the unit on the chain.
    pub mono: u64,
}

impl HoldOpened {
    /// Its journal body.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut body = BodyWriter::new();
        match &self.held {
            Held::Counts { counts, arrived_ms } => {
                body.text(HOLD_OPENED_COUNTS);
                body.num(self.incarnation);
                body.text(&self.principal);
                write_key(&mut body, &self.key);
                body.num(self.window);
                body.num(*arrived_ms);
                write_counts(&mut body, Some(counts));
            }
            Held::Figure(reserved) => {
                body.text(HOLD_OPENED);
                body.num(self.incarnation);
                body.text(&self.principal);
                write_key(&mut body, &self.key);
                body.num(self.window);
                body.num(*reserved);
            }
        }
        body.finish()
    }

    /// Read one back. `None` for a record that is not a hold.
    #[must_use]
    pub fn from_record(record: &JournalRecord) -> Option<HoldOpened> {
        if record.class != RecordClass::Transaction {
            return None;
        }
        let mut body = BodyReader::new(&record.body);
        let tag = body.text()?;
        if tag != HOLD_OPENED && tag != HOLD_OPENED_COUNTS {
            return None;
        }
        let incarnation = body.num()?;
        let principal = body.text()?.to_string();
        let key = read_key(&mut body)?;
        let window = body.num()?;
        let held = if tag == HOLD_OPENED_COUNTS {
            let arrived_ms = body.num()?;
            Held::Counts {
                counts: read_counts_block(&mut body)??,
                arrived_ms,
            }
        } else {
            Held::Figure(body.num()?)
        };
        body.is_done().then_some(HoldOpened {
            key,
            window,
            principal,
            held,
            incarnation,
            wall: record.wall,
            mono: record.mono,
        })
    }

    /// What the hold reserves, as the book reads it: the counts priced at their epoch through the
    /// one spend function, or the figure a record of the earlier era holds. A reservation the card
    /// cannot price reserves nothing on this book — the same answer live and on every replay.
    #[must_use]
    pub fn reserved(&self, history: Option<&HistoryView<'_>>) -> u64 {
        match &self.held {
            Held::Figure(reserved) => *reserved,
            Held::Counts { counts, arrived_ms } => price_counts(history, counts, *arrived_ms)
                .ok()
                .and_then(|nanos| u64::try_from(nanos).ok())
                .unwrap_or(0),
        }
    }

    /// The name of the unit on the chain: which boot, which balance and window, and which arrival.
    ///
    /// The balance rather than the principal, because the balance is what both ends are keyed by:
    /// the hold is opened on it and the settlement moves it, whichever principal the steps between
    /// settled on.
    fn unit(&self) -> (u64, TotalsKey, WindowStart, u64) {
        (self.incarnation, self.key.clone(), self.window, self.mono)
    }
}

/// The tag a dispatch mark's record opens with.
const UNIT_DISPATCHED: &str = "unit.dispatched";

/// The tag an accrual checkpoint's record opens with.
const UNIT_ACCRUED: &str = "unit.accrued";

/// The tag an idempotency claim's record opens with.
const CLAIM_TAKEN: &str = "claim.taken";

/// The tag the record voiding an idempotency claim opens with.
const CLAIM_VOIDED: &str = "claim.voided";

/// What a mark on a unit's open hold says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mark {
    /// Something left the node for the unit.
    Dispatched,
    /// The unit's accrual so far: counts and the instant they price at, never a figure.
    Accrued {
        /// The counts.
        counts: UnitCounts,
        /// The card epoch.
        arrived_ms: u64,
    },
}

/// A mark on a unit, as the journal carries it: named by the same four things that name its hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitMark {
    /// The balance.
    pub key: TotalsKey,
    /// The window.
    pub window: WindowStart,
    /// Which boot of this node's journal wrote it.
    pub incarnation: u64,
    /// The unit's arrival, whole seconds.
    pub wall: u64,
    /// The unit's arrival on the node's monotonic clock.
    pub mono: u64,
    /// What it says.
    pub mark: Mark,
}

impl UnitMark {
    /// Its journal body.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut body = BodyWriter::new();
        match &self.mark {
            Mark::Dispatched => {
                body.text(UNIT_DISPATCHED);
            }
            Mark::Accrued { .. } => {
                body.text(UNIT_ACCRUED);
            }
        }
        body.num(self.incarnation);
        write_key(&mut body, &self.key);
        body.num(self.window);
        if let Mark::Accrued { counts, arrived_ms } = &self.mark {
            body.num(*arrived_ms);
            write_counts(&mut body, Some(counts));
        }
        body.finish()
    }

    /// Read one back. `None` for a record that is not a mark.
    #[must_use]
    pub fn from_record(record: &JournalRecord) -> Option<UnitMark> {
        if record.class != RecordClass::Transaction {
            return None;
        }
        let mut body = BodyReader::new(&record.body);
        let tag = body.text()?;
        if tag != UNIT_DISPATCHED && tag != UNIT_ACCRUED {
            return None;
        }
        let incarnation = body.num()?;
        let key = read_key(&mut body)?;
        let window = body.num()?;
        let mark = if tag == UNIT_ACCRUED {
            let arrived_ms = body.num()?;
            Mark::Accrued {
                counts: read_counts_block(&mut body)??,
                arrived_ms,
            }
        } else {
            Mark::Dispatched
        };
        body.is_done().then_some(UnitMark {
            key,
            window,
            incarnation,
            wall: record.wall,
            mono: record.mono,
            mark,
        })
    }

    fn unit(&self) -> (u64, TotalsKey, WindowStart, u64) {
        (self.incarnation, self.key.clone(), self.window, self.mono)
    }
}

/// An idempotency claim a unit took, named by the same four things that name its hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimTaken {
    /// The claim — the idempotency key.
    pub claim: String,
    /// The balance.
    pub key: TotalsKey,
    /// The window.
    pub window: WindowStart,
    /// Which boot of this node's journal took it.
    pub incarnation: u64,
    /// The unit's arrival, whole seconds.
    pub wall: u64,
    /// The unit's arrival on the node's monotonic clock.
    pub mono: u64,
}

impl ClaimTaken {
    fn unit(&self) -> (u64, TotalsKey, WindowStart, u64) {
        (self.incarnation, self.key.clone(), self.window, self.mono)
    }
}

/// A claim's record: taken, or voided at recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimRecord {
    taken: ClaimTaken,
    voided: bool,
}

impl ClaimRecord {
    fn body(&self) -> Vec<u8> {
        let mut body = BodyWriter::new();
        body.text(if self.voided {
            CLAIM_VOIDED
        } else {
            CLAIM_TAKEN
        });
        body.num(self.taken.incarnation);
        write_key(&mut body, &self.taken.key);
        body.num(self.taken.window);
        body.text(&self.taken.claim);
        body.finish()
    }

    fn from_record(record: &JournalRecord) -> Option<ClaimRecord> {
        if record.class != RecordClass::Transaction {
            return None;
        }
        let mut body = BodyReader::new(&record.body);
        let tag = body.text()?;
        if tag != CLAIM_TAKEN && tag != CLAIM_VOIDED {
            return None;
        }
        let incarnation = body.num()?;
        let key = read_key(&mut body)?;
        let window = body.num()?;
        let claim = body.text()?.to_string();
        body.is_done().then_some(ClaimRecord {
            taken: ClaimTaken {
                claim,
                key,
                window,
                incarnation,
                wall: record.wall,
                mono: record.mono,
            },
            voided: tag == CLAIM_VOIDED,
        })
    }
}

/// A balance as fields: bucket, then dimension and scope as a tag and a name each.
fn write_key(body: &mut BodyWriter, key: &TotalsKey) {
    body.text(key.bucket.as_str());
    let (dimension, class) = match &key.dimension {
        CapDimension::NanoUnits => (0, ""),
        CapDimension::Requests => (1, ""),
        CapDimension::Concurrent => (2, ""),
        CapDimension::Class(class) => (3, class.as_str()),
    };
    body.num(dimension);
    body.text(class);
    let (scope, pool) = match &key.scope {
        BucketScope::All => (0, ""),
        BucketScope::Pool(pool) => (1, pool.as_str()),
    };
    body.num(scope);
    body.text(pool);
}

fn read_key(body: &mut BodyReader<'_>) -> Option<TotalsKey> {
    let bucket = BucketId::new(body.text()?);
    let dimension = match (body.num()?, body.text()?) {
        (0, _) => CapDimension::NanoUnits,
        (1, _) => CapDimension::Requests,
        (2, _) => CapDimension::Concurrent,
        (3, class) => CapDimension::Class(class.to_string()),
        _ => return None,
    };
    let scope = match (body.num()?, body.text()?) {
        (0, _) => BucketScope::All,
        (1, pool) => BucketScope::Pool(pool.to_string()),
        _ => return None,
    };
    Some(TotalsKey::new(bucket, dimension, scope))
}

/// The journal body of a sealed audit record.
///
/// The two digests first, because they are what ties this journal record back to the audit chain the
/// record is also on; then the facts an auditor asks for. Content is not here for the same reason it
/// is not in the audit record: the journal is a financial record exempt from erasure, so anything put
/// in it can never be taken out.
#[must_use]
pub fn audit_body(record: &AuditRecord) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.text(&record.prev_hash);
    body.text(&record.hash);
    body.num(record.what.unit_key.get());
    body.text(record.what.op_class.as_str());
    body.text(record.what.destination.as_deref().unwrap_or(""));
    body.text(record.origin_kind);
    body.text(&format!("{:?}", record.outcome.unit_end));
    body.text(&format!("{:?}", record.outcome.finish));
    body.num(u64::from(record.usage.tier_bp));
    body.num(u64::from(record.usage.fee_count));
    body.text(&record.usage.currency);
    body.num(record.usage.rate_card_version);
    body.text(&record.usage.bucket_chain_ref);
    body.text(record.correlation_hash.as_deref().unwrap_or(""));
    body.finish()
}

/// The journal body of a sealed checkpoint.
#[must_use]
pub fn checkpoint_body(checkpoint: &Checkpoint) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.num(checkpoint.checkpoint_seq);
    body.num(checkpoint.node);
    body.num(checkpoint.wall);
    body.bytes(&checkpoint.body_hash);
    body.num(checkpoint.totals.len() as u64);
    body.num(checkpoint.backup_watermark);
    body.num(checkpoint.store_seq_high_water);
    body.num(u64::from(checkpoint.signature.is_some()));
    body.finish()
}

/// How many bytes a migration marker takes on the journal. Fixed, because every field of it is.
const MIGRATION_MARKER_BYTES: usize = 8 * 6 + 8 + 32;

/// The migration marker's journal body.
#[must_use]
pub fn migration_body(marker: &MigrationMarker) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.num(marker.checkpoint_seq);
    body.num(marker.node);
    body.num(marker.sealed_at);
    body.bytes(&marker.body_hash);
    body.num(marker.balances);
    body.num(marker.cells_read);
    body.num(marker.rate_card_version);
    body.finish()
}

/// Read a migration marker back off the journal.
///
/// `None` for a body that is not one — a build that met a record it could not read must say it did
/// not find a marker rather than inventing a partial one, because "unreadable" and "absent" are
/// different facts and treating one as the other is how a migration runs twice.
#[must_use]
pub fn migration_marker_from(body: &[u8]) -> Option<MigrationMarker> {
    if body.len() != MIGRATION_MARKER_BYTES {
        return None;
    }
    let num = |at: usize| u64::from_le_bytes(body[at..at + 8].try_into().unwrap_or([0; 8]));
    // The length prefix the body writer put in front of the digest. A body whose prefix says
    // anything else is not a marker this build wrote, and reading past it would be guessing.
    if num(24) != 32 {
        return None;
    }
    Some(MigrationMarker {
        checkpoint_seq: num(0),
        node: num(8),
        sealed_at: num(16),
        body_hash: body[32..64].try_into().ok()?,
        balances: num(64),
        cells_read: num(72),
        rate_card_version: num(80),
    })
}

/// The ledger's own records, kept on the journal.
///
/// Borrows the journal rather than cloning a handle to it, so a marker cannot be written through a
/// second path while the migration step holds this one.
pub struct JournalMigrationRecords<'a> {
    journal: &'a mut Journal,
    token: &'a Grant<DurableWrite>,
    at: StepName,
}

impl std::fmt::Debug for JournalMigrationRecords<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalMigrationRecords")
            .field("head", &self.journal.head_hex())
            .finish_non_exhaustive()
    }
}

impl MigrationRecords for JournalMigrationRecords<'_> {
    /// The newest `Migration` record on the chain, if there is one.
    ///
    /// A journal that will not read back is an ERROR and not an absence, which is the whole reason
    /// this trait's read returns a result: answering "no marker" to a chain nobody could read is how
    /// a deployment silently re-opens balances it already opened.
    fn read_marker(&self) -> Result<Option<MigrationMarker>, MigrationError> {
        let replayed = self
            .journal
            .replay()
            .map_err(|e| MigrationError::RecordsUnavailable(e.to_string()))?
            .map_err(|e| MigrationError::RecordsUnavailable(e.to_string()))?;
        Ok(replayed
            .iter()
            .filter(|r| r.class == RecordClass::Migration)
            .max_by_key(|r| r.node_seq)
            .and_then(|r| migration_marker_from(&r.body)))
    }

    fn write_marker(&mut self, marker: &MigrationMarker) -> Result<(), MigrationError> {
        let entry =
            Entry::new(RecordClass::Migration, migration_body(marker)).at(marker.sealed_at, 0);
        self.journal
            .append(self.token, self.at, &[entry])
            .map(|_| ())
            .map_err(|lost| {
                MigrationError::RecordsUnavailable(format!(
                    "the journal lost a durable write at {}",
                    lost.step().as_str()
                ))
            })
    }
}

/// Build the journal, the ledger and the audit record chain, as node zero.
///
/// # Errors
///
/// As [`build_for_node`].
pub fn build(
    cfg: &DurabilityConfig,
    shipper: Box<dyn Shipper>,
    legacy_rows: Box<dyn LegacyRows>,
) -> Result<Durability, OpenError> {
    build_for_node(cfg, 0, shipper, legacy_rows)
}

/// THE NODE'S ONE BOOK, and the read half of the dual write that goes with it.
///
/// Two halves of one value, handed out together for the same reason the ledger's own constructor
/// takes them together: whatever a settlement dual-writes onto is what the reconciliation view has
/// to read back. A caller that built the two separately would have a node whose ledger posts onto
/// one set of rows while its views read another, and the identity over that pair reports every row
/// as out.
pub struct NodeBook {
    /// The journal, the ledger and the audit record chain, behind the one lock every settlement and
    /// every view takes.
    pub durability: std::sync::Arc<std::sync::Mutex<Durability>>,
    /// The previous release's rows, as the dual write fills them. The write half is inside the
    /// ledger; this is the same value, kept so a view has somewhere to read them from.
    pub rows: std::sync::Arc<RecordingRows>,
}

/// Open the one book a process settles onto.
///
/// ONE of these per process, built at boot and shared by every plane's exit arm and by the
/// administrative views. A second would be a second set of books: money posted through one would be
/// invisible to the other, and the views — which are what an operator reads to decide whether the
/// dual write is keeping up — would answer over a book nothing settles into. That is not a
/// hypothetical shape; it is what a node has when each mount builds its own.
///
/// THE NO-STORE FALLBACK, and it is that rather than the boot path. Memory-buffered, keeping
/// nothing: a node with no configured store has nowhere to ship a batch to, so it takes the null
/// shipper and reads no data directory, which is the previous release's behaviour for that
/// deployment and not a silent data loss — there was nowhere the records were ever going.
///
/// **A DEPLOYMENT WITH A STORE DOES NOT COME THROUGH HERE.** It is composed by the binary's
/// `compose_boot_book`, which takes the CONFIGURED data directory and the configured store's
/// shipper and seals the opening before it hands the book back. This constructor hard-codes both
/// answers, which is correct only because the one caller that reaches it has already established
/// that there is no store to make either decision against.
#[must_use]
pub fn node_book() -> NodeBook {
    node_book_over(root_history())
}

/// [`node_book`], naming where its money view reads the dated rate-card history.
#[must_use]
pub fn node_book_over(history: HistorySource) -> NodeBook {
    let rows = std::sync::Arc::new(RecordingRows::new());
    let durability = build_priced(
        &DurabilityConfig { data_dir: None },
        0,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(RecordingRows::clone(&rows)),
        history,
    )
    .expect("a memory-buffered journal cannot fail to open");
    NodeBook {
        durability: std::sync::Arc::new(std::sync::Mutex::new(durability)),
        rows,
    }
}

/// Build the journal, the ledger and the audit record chain.
///
/// The whole decision is the first `match`. Everything after it is the same on both branches, which
/// is the point: a node without a data directory is not running a reduced stack, it is running the
/// same stack over a journal that keeps its records in memory and ships them to the store.
///
/// `node` is the identity the journal's records carry. It is the writer's own name for a record and
/// half of the pair the log deduplicates on, so two nodes numbering from one counter would collide —
/// which is why it is an argument rather than a default.
///
/// # Errors
///
/// A configured data directory could not be opened, or the journal already there could not be read.
/// There is no error arm on the other branch: a memory-buffered journal cannot fail to open.
pub fn build_for_node(
    cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper>,
    legacy_rows: Box<dyn LegacyRows>,
) -> Result<Durability, OpenError> {
    build_with_cards(
        cfg,
        node,
        shipper,
        legacy_rows,
        root_history(),
        Some(&crate::root::kernel::ROOT_CARD),
    )
}

/// [`build_for_node`], naming where the book reads the dated rate-card history its replay prices
/// the chain's counts against. The process's own is the root's holder; a caller that holds a
/// history of its own — a test, a tool re-deriving a node's book — hands it here.
///
/// # Errors
///
/// As [`build_for_node`].
pub fn build_priced(
    cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper>,
    legacy_rows: Box<dyn LegacyRows>,
    history: HistorySource,
) -> Result<Durability, OpenError> {
    build_with_cards(cfg, node, shipper, legacy_rows, history, None)
}

/// [`build_priced`], naming the holder whose DATED HISTORY the book rebuilds from its chain before
/// it prices a replayed posting (#79). The production boot names the process holder; a holder that
/// was not armed ([`crate::root::kernel::RootHistory::arm_journal`]) is left as it is.
///
/// # Errors
///
/// As [`build_for_node`].
pub fn build_with_cards(
    cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper>,
    legacy_rows: Box<dyn LegacyRows>,
    history: HistorySource,
    cards: Option<&'static crate::root::kernel::RootHistory>,
) -> Result<Durability, OpenError> {
    // The journal is handed the root's wall clock: the log unit reads none of its own.
    let clock = busbar_substrate_values::store::now_ms;
    let journal = match cfg.data_dir.as_deref() {
        // The previous release's shape: nothing is opened, nothing is probed, and durability is
        // whatever the store the batches are shipped to provides.
        None => Journal::memory_buffered_to(node, shipper, clock),
        // The operator asked for a journal on this node's own disk. This call is that decision.
        Some(dir) => Journal::in_directory(node, dir, shipper, clock)?,
    };

    let mut durability = Durability {
        journal,
        // Not `Ledger::new()`. The reconciliation identity and rollback both require the dual
        // write, and both are release requirements rather than deployment choices.
        ledger: Ledger::dual_writing(legacy_rows),
        record: AuditChain::new(),
        checkpoints: Vec::new(),
        // Set from the chain below, before anything can write under it.
        incarnation: 0,
        restart_findings: Vec::new(),
        recovered_holds: 0,
        voided_claims: Vec::new(),
        refused: Vec::new(),
        unconfirmed: Vec::new(),
        quarantined: Vec::new(),
        history,
        cards_from: None,
        amendments_through: None,
    };

    // A CORRUPT JOURNAL DOES NOT STOP THE BOOT, AND IT IS NEVER SILENT. The log has already kept
    // every record before the damage and copied the damaged remainder, byte for byte, into a
    // quarantine file it synced before cutting the segment. What it cannot do is raise the alarm:
    // that is here — a loud line naming the file, the offset, the byte count and the quarantine,
    // and a counter an operator alerts on. The durable record is `journal_quarantines`, which the
    // boot calls once it holds a durability token. A torn tail after a crash never appears here.
    durability.quarantined = durability.journal.log().quarantined().to_vec();
    for q in &durability.quarantined {
        tracing::error!(
            segment = ?q.segment_file,
            offset = q.offset,
            damage_at = q.damage_at,
            bytes = q.bytes,
            quarantine = ?q.kept,
            "{q}"
        );
        metrics::counter!(busbar_kernel::metrics::JOURNAL_QUARANTINED_TOTAL).increment(1);
    }

    // THE BOOK IS REBUILT FROM THE CHAIN, not opened empty (item 128). An empty book here was the
    // money view resetting to zero on every restart — and the reconciliation passing, because both
    // sides were zero. Every hold opened and every settlement posted is replayed through the
    // ledger's own arithmetic, the dual write included, so the book and the rows it feeds are what
    // they were when the node stopped. A memory-buffered journal replays nothing: it starts empty.
    //
    // AND THE DATED RATE-CARD HISTORY IS REBUILT FROM THE CHAIN FIRST (#79, OWNER RULING Q14), so a
    // replayed posting prices at the card in force when it arrived — never at the boot card.
    let chain = durability.journal.replay();
    if let Some(cards) = cards {
        let records = match (&cfg.data_dir, &chain) {
            (Some(_), Ok(Ok(records))) => Some(records.as_slice()),
            _ => None,
        };
        cards.rebuild_from_chain(&mut durability, records);
    }
    let pinned = (durability.history)();
    let view = pinned.as_ref().map(PinnedHistory::view);
    let (replayed, unreadable) = match chain {
        Ok(Ok(records)) => (
            replay_into(&mut durability.ledger, &records, view.as_ref(), false),
            None,
        ),
        Ok(Err(broken)) => (
            Replayed::nothing(),
            Some(format!("the journal does not verify: {broken:?}")),
        ),
        Err(e) => (
            Replayed::nothing(),
            Some(format!("the journal could not be read: {e}")),
        ),
    };
    durability.incarnation = replayed.incarnation.saturating_add(1);
    durability.refused = replayed.refused;

    // THE HOLDS A PREDECESSOR LEFT OPEN ARE RECOVERED HERE, before anything can settle onto this
    // book (item 127): `recovery::recover_all` had no production caller, so a hold whose node died
    // mid-unit was never posted by anybody. Each is posted per the recovery table and closed on the
    // chain under the incarnation that opened it.
    durability.recover(replayed.open);

    // AND EVERY IDEMPOTENCY CLAIM A PREDECESSOR TOOK WITH NO HOLD BEHIND IT IS VOIDED, so a client's
    // retry is answered by running the unit rather than by a unit that never ran.
    durability.void_claims(replayed.unheld_claims);

    // AND THE RESTART RECONCILIATION RUNS OVER THE REAL BOOK: what is in memory now, against what
    // the chain rebuilds. It is a comparison of two things that can disagree, reported rather than
    // refused — a node boots over what it can read, and the finding says what it could not.
    let mut findings: Vec<JournalDisagreement> = unreadable
        .into_iter()
        .map(JournalDisagreement::Unreadable)
        .collect();
    findings.extend(
        replayed
            .unreadable
            .into_iter()
            .map(JournalDisagreement::Unreadable),
    );
    findings.extend(durability.reconcile_with_journal());
    findings.dedup();
    for finding in &findings {
        tracing::error!(finding = %finding, "the restart reconciliation found the book and the journal disagree");
    }
    durability.restart_findings = findings;
    Ok(durability)
}

/// Every path this node may write to, given its configuration.
///
/// Empty when no data directory was configured, which is the machine-checkable form of *no
/// directory, no files*. A caller that wants to assert the absence has something to assert against
/// rather than a sentence to trust.
#[must_use]
pub fn writable_paths(cfg: &DurabilityConfig) -> Vec<&Path> {
    cfg.data_dir.as_deref().into_iter().collect()
}

#[cfg(test)]
#[path = "../tests/durability.rs"]
mod tests;
