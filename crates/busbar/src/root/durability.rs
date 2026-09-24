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

use busbar_contract::caps::{DurabilityLost, DurableWrite, Grant, StepName};
use busbar_kernel_audit::{AuditChain, AuditRecord};
use busbar_kernel_ledger::checkpoint::Checkpoint;
use busbar_kernel_ledger::legacy::{LegacyRows, RecordingRows};
use busbar_kernel_ledger::migration::{MigrationError, MigrationMarker, MigrationRecords};
use busbar_kernel_ledger::settle::{Ledger, Settlement};
use busbar_kernel_ledger::totals::{
    BucketId, BucketScope, CapDimension, Totals, TotalsKey, WindowStart,
};
use busbar_kernel_wal::{
    BodyReader, BodyWriter, Entry, Journal, JournalAck, JournalRecord, Mode, OpenError,
    RecordClass, Shipper,
};

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
    /// # Errors
    ///
    /// As [`Durability::journal_audit`]. The book has moved either way, and a failed append is
    /// retained and re-offered by the log — it is never a refusal at the door.
    pub fn open_hold(
        &mut self,
        at: &Settling<'_>,
        principal: &busbar_contract::caps::PrincipalId,
        reserved: u64,
    ) -> Result<JournalAck, DurabilityLost> {
        let opened = HoldOpened {
            key: at.key.clone(),
            window: at.window,
            principal: principal.as_str().to_string(),
            reserved,
            incarnation: self.incarnation,
            wall: at.stamp.wall,
            mono: at.stamp.mono,
        };
        apply_opened(&mut self.ledger, &opened);
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
        let replay = replay_into(&mut rebuilt, &records);
        let mut findings: Vec<JournalDisagreement> = replay
            .unreadable
            .into_iter()
            .map(JournalDisagreement::Unreadable)
            .collect();
        if replay.refused != self.refused {
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
    fn recover(&mut self, open: Vec<HoldOpened>) {
        if open.is_empty() {
            return;
        }
        let kernel = busbar_kernel::teller::Kernel::new();
        let token = kernel.durability_token();
        let canary = busbar_contract::caps::Canary::new();
        let current = busbar_contract::slice::Epoch(self.incarnation);
        let records: Vec<busbar_kernel::recovery::HoldRecord> = open
            .iter()
            .map(|hold| busbar_kernel::recovery::HoldRecord {
                unit: busbar_contract::UnitKey::new(hold.mono),
                principal: busbar_contract::caps::PrincipalId::new(hold.principal.as_str()),
                reserved: hold.reserved,
                // No accrual checkpoint and no dispatch record is journalled, so the table's
                // recovery row posts zero, marked void: a crash is not evidence of consumption.
                checkpointed: 0,
                dispatched: false,
                lease_epoch: busbar_contract::slice::Epoch(hold.incarnation),
            })
            .collect();
        let posted = busbar_kernel::recovery::recover_all(&kernel, &records, current, &canary);
        for (hold, posted) in open.iter().zip(posted) {
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
            let settlement = self.ledger.post(at.key, at.window, posted);
            // A durability loss here is retained and re-offered like any other; the book has
            // moved and the hold is settled in memory either way.
            let _ = self.journal_settlement_as(&at, settlement, hold.incarnation);
            self.recovered_holds = self.recovered_holds.saturating_add(1);
        }
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
    /// carries them, per class string — the reserved four and every open class — beside the figure
    /// they were priced to, so the chain holds the fact and not only its price.
    ///
    /// # Errors
    ///
    /// As [`Durability::settle`].
    pub fn settle_counted(
        &mut self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
    ) -> Result<Settled, DurabilityLost> {
        let settlement = self.ledger.post(at.key, at.window, posted);
        self.journal_settlement_counted(at, settlement, self.incarnation, Some(counts))
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
            counts: Some(counts.clone()),
            refusal,
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
        self.journal_settlement_counted(at, settlement, incarnation, None)
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
            counts: counts.cloned(),
            refusal: None,
        };
        // The overdraft's own record. Reserved and settled are zero on it deliberately: the
        // settlement above already carries both, and repeating them here would double every figure
        // a replay adds up. What this record holds that nothing else does is the carry, on the
        // chain, in order, beside the posting it came out of.
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
            counts: None,
            refusal: None,
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
    ) -> Result<Settled, DurabilityLost> {
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability.settle_counted(at, posted, counts)
    }

    fn post_counts(
        &self,
        at: &Settling<'_>,
        principal: &busbar_contract::caps::PrincipalId,
        counts: &UnitCounts,
        refusal: Option<String>,
    ) -> Result<Posting, DurabilityLost> {
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability.post_counts(at, principal, counts, refusal)
    }
}

/// A settlement as the journal carries it.
///
/// A value rather than a reference to the ledger's books, because a posting is a thing that happened
/// at a moment and the books are what they are now. The two are different facts and a record built
/// out of the second could not be replayed.
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
    /// What had been reserved.
    pub reserved: i128,
    /// What was settled.
    pub settled: i128,
    /// What was spent with no reservation behind it.
    pub overdraft: i128,
    /// Which card version priced it.
    pub rate_card_version: u64,
    /// The wall clock, in whole seconds.
    pub wall: u64,
    /// The node's monotonic clock.
    pub mono: u64,
    /// THE UNIT'S RAW COUNTS, per class string (#71) — `None` on a record written before they were
    /// carried, and on a record whose writer did not know them (the carry, and every plane that
    /// settles through [`Durability::settle_posted`]).
    pub counts: Option<UnitCounts>,
    /// Why the counts on a [`PostingKind::Counted`] row could not be priced; `None` on every other
    /// record, and on a counts row that priced to nothing.
    pub refusal: Option<String>,
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

impl Posting {
    /// The journal body: the balance it moved, the window, and the three figures — and then what a
    /// restart needs to rebuild the book from it.
    ///
    /// The first six fields are the record every reader already knew, unchanged and in the same
    /// place. What follows them is the tail a boot reads (items 127/128): which of the two records
    /// of one settlement this is (only the settlement moves the book — the carry repeats its
    /// overdraft), which incarnation wrote it and whose unit it was (which, with the record's
    /// monotonic reading, names the hold it closes), and the balance as FIELDS rather than as the
    /// display string above, which a rebuild could not parse back unambiguously.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut body = BodyWriter::new();
        body.text(&self.key.to_string());
        body.num(self.window);
        body.figure(self.reserved);
        body.figure(self.settled);
        body.figure(self.overdraft);
        body.num(self.rate_card_version);
        body.text(POSTING_TAIL);
        body.num(self.kind.code());
        body.num(self.incarnation);
        body.text(&self.principal);
        write_key(&mut body, &self.key);
        // THE COUNTS TAIL (#71), appended after the v2 tail exactly as that one was appended after
        // the original six fields: a record without it is a record written before it existed and
        // reads back with no counts, so a journal written by an earlier build rebuilds the same
        // book. Written only where the counts are known, so every other record is byte-identical.
        if let Some(counts) = &self.counts {
            body.text(POSTING_COUNTS_TAIL);
            body.text(&counts.lane);
            body.num(counts.fee_count);
            body.num(counts.classes.len() as u64);
            for (class, count) in &counts.classes {
                body.text(class);
                body.num(*count);
            }
            body.num(u64::from(self.refusal.is_some()));
            body.text(self.refusal.as_deref().unwrap_or(""));
        }
        body.finish()
    }

    /// Read a posting back off the chain. `None` for a record that is not one — an audit record, a
    /// hold, or a posting written before the tail existed, which a rebuild cannot place.
    #[must_use]
    pub fn from_record(record: &JournalRecord) -> Option<Posting> {
        if record.class != RecordClass::Transaction {
            return None;
        }
        let mut body = BodyReader::new(&record.body);
        let shown = body.text()?;
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
        let key = read_key(&mut body)?;
        let (counts, refusal) = if body.is_done() {
            // A record written before the counts tail: no counts, and nothing refused.
            (None, None)
        } else {
            read_counts(&mut body)?
        };
        // The two spellings of the balance must name the same one, or this is not a body this
        // build wrote and reading it would be guessing.
        if !body.is_done() || key.to_string() != shown {
            return None;
        }
        // A counts row carries its counts by definition; one without them is not a body this
        // build wrote.
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
            counts,
            refusal,
        })
    }
}

/// The counts tail, read back. `None` for a tail this build did not write.
fn read_counts(body: &mut BodyReader<'_>) -> Option<(Option<UnitCounts>, Option<String>)> {
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
        // One class twice is not a body this build wrote: the writer iterates a map.
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
    /// The settlement: what was reserved and what was posted. The one a rebuild moves the book by.
    Settlement,
    /// The overdraft carry beside it, repeating the part nothing reserved. Replaying it as well
    /// would count that part twice.
    Carry,
    /// A unit's raw counts with NO figure behind them (#43: the write is unconditional): the counts
    /// priced to nothing, or the card REFUSED to price them (#42). It moves no balance.
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

/// The tag between a posting's original fields and the tail a rebuild reads.
const POSTING_TAIL: &str = "posting.v2";

/// The tag between the v2 tail and the unit's raw counts (#71).
const POSTING_COUNTS_TAIL: &str = "posting.counts.v1";

/// The tag a hold's journal record opens with. No posting can begin with it: a posting's first
/// field is a balance's display, which always carries a `/`.
const HOLD_OPENED: &str = "hold.open";

/// A hold as the journal carries it (item 127): opened, and not yet closed by a posting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldOpened {
    /// Which balance it reserves against.
    pub key: TotalsKey,
    /// Which window.
    pub window: WindowStart,
    /// Whose unit it is.
    pub principal: String,
    /// What was reserved.
    pub reserved: u64,
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
        body.text(HOLD_OPENED);
        body.num(self.incarnation);
        body.text(&self.principal);
        write_key(&mut body, &self.key);
        body.num(self.window);
        body.num(self.reserved);
        body.finish()
    }

    /// Read one back. `None` for a record that is not a hold.
    #[must_use]
    pub fn from_record(record: &JournalRecord) -> Option<HoldOpened> {
        if record.class != RecordClass::Transaction {
            return None;
        }
        let mut body = BodyReader::new(&record.body);
        if body.text()? != HOLD_OPENED {
            return None;
        }
        let incarnation = body.num()?;
        let principal = body.text()?.to_string();
        let key = read_key(&mut body)?;
        let window = body.num()?;
        let reserved = body.num()?;
        body.is_done().then_some(HoldOpened {
            key,
            window,
            principal,
            reserved,
            incarnation,
            wall: record.wall,
            mono: record.mono,
        })
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

/// A reservation's movement on the book: drawn into the slice and spent out of it into the hold.
fn apply_opened(ledger: &mut Ledger, hold: &HoldOpened) {
    let amount = i128::from(hold.reserved);
    ledger.record_draw(&hold.key, hold.window, amount);
    ledger.record_slice_spent(&hold.key, hold.window, amount);
    ledger.record_hold_opened(&hold.key, hold.window, hold.reserved);
}

/// What replaying a chain into a book left over.
struct Replayed {
    /// Holds opened and closed by no posting of the same unit, in chain order.
    open: Vec<HoldOpened>,
    /// The highest incarnation any record carried; 0 on a chain with none.
    incarnation: u64,
    /// Records that look like this build's money records and could not be read.
    unreadable: Vec<String>,
    /// Counts rows whose pricing refused, in chain order.
    refused: Vec<Posting>,
}

impl Replayed {
    /// What a chain that could not be read at all leaves: nothing to rebuild from.
    fn nothing() -> Self {
        Replayed {
            open: Vec::new(),
            incarnation: 0,
            unreadable: Vec::new(),
            refused: Vec::new(),
        }
    }
}

/// REBUILD A BOOK FROM THE CHAIN, in chain order: every hold opened, every settlement posted.
///
/// Reads every `Transaction` record, not only the migration marker (the two replays this module
/// had filtered `Migration` alone, so a restart read nothing a unit had done). Audit records share
/// the class and are passed over; a posting written before the tail existed cannot be placed on a
/// balance, and is named rather than silently skipped.
fn replay_into(ledger: &mut Ledger, records: &[JournalRecord]) -> Replayed {
    let mut open: Vec<HoldOpened> = Vec::new();
    let mut incarnation = 0;
    let mut unreadable = Vec::new();
    let mut refused = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.class == RecordClass::Transaction)
    {
        if let Some(hold) = HoldOpened::from_record(record) {
            incarnation = incarnation.max(hold.incarnation);
            apply_opened(ledger, &hold);
            open.push(hold);
        } else if let Some(posting) = Posting::from_record(record) {
            incarnation = incarnation.max(posting.incarnation);
            if posting.kind == PostingKind::Counted {
                // No balance moves for a counts row; a refused one is kept, so the reads over its
                // balance refuse after a restart exactly as they did before it.
                if posting.refusal.is_some() {
                    refused.push(posting);
                }
                continue;
            }
            if posting.kind == PostingKind::Settlement {
                let (Ok(reserved), Ok(settled), Ok(overdraft)) = (
                    u64::try_from(posting.reserved),
                    u64::try_from(posting.settled),
                    u64::try_from(posting.overdraft),
                ) else {
                    unreadable.push(format!(
                        "node {} record {}: a posting with a negative figure",
                        record.node, record.node_seq
                    ));
                    continue;
                };
                ledger.replay_post(
                    &posting.key,
                    posting.window,
                    &posting.principal,
                    reserved,
                    settled,
                    overdraft,
                );
                let unit = (
                    posting.incarnation,
                    posting.key.clone(),
                    posting.window,
                    posting.mono,
                );
                if let Some(at) = open.iter().position(|hold| hold.unit() == unit) {
                    open.remove(at);
                }
            }
        } else if looks_like_a_posting(record) {
            unreadable.push(format!(
                "node {} record {}: a posting this build cannot place on a balance",
                record.node, record.node_seq
            ));
        }
    }
    Replayed {
        open,
        incarnation,
        unreadable,
        refused,
    }
}

/// A posting without the tail: a balance display, a window and three figures and a version, and
/// nothing else. An audit record never has this shape — it opens with two digests.
fn looks_like_a_posting(record: &JournalRecord) -> bool {
    let mut body = BodyReader::new(&record.body);
    body.text().is_some_and(|shown| shown.contains('/'))
        && body.num().is_some()
        && body.figure().is_some()
        && body.figure().is_some()
        && body.figure().is_some()
        && body.num().is_some()
}

/// Whether two readings of one balance moved it the same way. `settled` is read together with
/// `unreconciled`: a posting the log has not confirmed moves between those two, not out of the book.
fn same_movement(journal: &Totals, book: &Totals) -> bool {
    journal.drawn == book.drawn
        && journal.open_holds == book.open_holds
        && journal.open_slice_remainders == book.open_slice_remainders
        && journal.overdraft_carried_out == book.overdraft_carried_out
        && journal.settled.saturating_add(journal.unreconciled)
            == book.settled.saturating_add(book.unreconciled)
}

/// Something the restart reconciliation found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalDisagreement {
    /// The chain, or a money record on it, could not be read.
    Unreadable(String),
    /// A balance the book and the chain disagree about.
    Balance {
        /// Which balance.
        key: TotalsKey,
        /// Which window.
        window: WindowStart,
        /// What the chain rebuilds it to. Boxed, as the book's reading beside it is: a finding is
        /// rare and a full set of figures is wide.
        journal: Box<Totals>,
        /// What the book holds.
        book: Box<Totals>,
    },
    /// The refused counts rows the node holds are not the ones its chain holds.
    RefusedRows {
        /// How many the chain rebuilds.
        journal: usize,
        /// How many the node holds.
        book: usize,
    },
}

impl std::fmt::Display for JournalDisagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalDisagreement::Unreadable(why) => f.write_str(why),
            JournalDisagreement::RefusedRows { journal, book } => write!(
                f,
                "the journal rebuilds {journal} refused counts row(s), the node holds {book}"
            ),
            JournalDisagreement::Balance {
                key,
                window,
                journal,
                book,
            } => write!(
                f,
                "{key} in the window opening at {window}: the journal rebuilds settled {} / held {} \
                 / drawn {}, the book holds settled {} / held {} / drawn {}",
                journal.settled.saturating_add(journal.unreconciled),
                journal.open_holds,
                journal.drawn,
                book.settled.saturating_add(book.unreconciled),
                book.open_holds,
                book.drawn
            ),
        }
    }
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
    let rows = std::sync::Arc::new(RecordingRows::new());
    let durability = build(
        &DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(RecordingRows::clone(&rows)),
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
    let journal = match cfg.data_dir.as_deref() {
        // The previous release's shape: nothing is opened, nothing is probed, and durability is
        // whatever the store the batches are shipped to provides.
        None => Journal::memory_buffered_to(node, shipper),
        // The operator asked for a journal on this node's own disk. This call is that decision.
        Some(dir) => Journal::in_directory(node, dir, shipper)?,
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
        refused: Vec::new(),
        unconfirmed: Vec::new(),
    };

    // THE BOOK IS REBUILT FROM THE CHAIN, not opened empty (item 128). An empty book here was the
    // money view resetting to zero on every restart — and the reconciliation passing, because both
    // sides were zero. Every hold opened and every settlement posted is replayed through the
    // ledger's own arithmetic, the dual write included, so the book and the rows it feeds are what
    // they were when the node stopped. A memory-buffered journal replays nothing: it starts empty.
    let (replayed, unreadable) = match durability.journal.replay() {
        Ok(Ok(records)) => (replay_into(&mut durability.ledger, &records), None),
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
#[path = "tests/durability.rs"]
mod tests;
