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
//! ## Two audit streams that do not merge, and a journal that touches neither
//!
//! The audit unit keeps a legacy chain and a record chain, and they stay apart deliberately. The
//! legacy chain is the previous release's administrative mutation chain — moved, not rewritten,
//! because a change to its digest would report every deployment's history as tampered. The record
//! chain is the new fixed record. The root holds both; the legacy chain is fed by the verbs unit's
//! administrative path and the record chain by the audit step.
//!
//! Journalling a sealed record does not touch the legacy chain, and there is a test below that says
//! so by building two logs and comparing them byte for byte. An administrative read is the previous
//! release's read of the previous release's entries; the journal is additional, and additional has
//! to mean invisible from that side.

use std::path::{Path, PathBuf};

use busbar_caps::{DurabilityLost, DurabilityToken, StepName};
use busbar_unit_audit::{AuditChain, AuditLog, AuditRecord, Clock, NoSeam};
use busbar_unit_ledger::checkpoint::Checkpoint;
use busbar_unit_ledger::hydrate::{HydratedPosting, Hydration, HydrationError, SpendSource};
use busbar_unit_ledger::legacy::{LegacyRows, RecordingRows};
use busbar_unit_ledger::migration::{MigrationError, MigrationMarker, MigrationRecords};
use busbar_unit_ledger::settle::{Ledger, Settlement};
use busbar_unit_ledger::totals::{TotalsKey, WindowStart};
use busbar_unit_wal::{
    BodyWriter, Entry, Journal, JournalAck, Mode, OpenError, RecordClass, Shipper,
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

/// The durability stack the root owns: the journal, the ledger and the two audit chains.
pub struct Durability {
    /// The one journal. On disk only where a data directory was configured; otherwise
    /// memory-buffered and shipped through the store adapter's plane-record verbs.
    pub journal: Journal,
    /// The ledger, dual-writing onto the previous release's rows.
    pub ledger: Ledger,
    /// The new fixed record's chain.
    pub record: AuditChain,
    /// The previous release's administrative mutation chain, moved rather than rewritten.
    pub legacy: AuditLog,
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
        token: &DurabilityToken,
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
        token: &DurabilityToken,
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
        token: &DurabilityToken,
        at: StepName,
    ) -> Result<JournalAck, DurabilityLost> {
        put_checkpoint_on(
            &mut self.journal,
            &mut self.checkpoints,
            checkpoint,
            token,
            at,
        )
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
        hold: busbar_caps::Hold,
        priced_nanos: u128,
        usage: &busbar_caps::Usage,
        ledger: &busbar_caps::LedgerToken,
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
        posted: busbar_caps::Posted,
    ) -> Result<Settled, DurabilityLost> {
        let settlement = self.ledger.post(at.key, at.window, posted);
        self.journal_settlement(at, settlement)
    }

    fn journal_settlement(
        &mut self,
        at: &Settling<'_>,
        settlement: Settlement,
    ) -> Result<Settled, DurabilityLost> {
        let stamp = at.stamp;
        let posting = Posting {
            key: at.key.clone(),
            window: at.window,
            reserved: i128::from(settlement.posted.reserved()),
            settled: i128::from(settlement.posted.settled()),
            overdraft: i128::from(settlement.posted.overdraft()),
            rate_card_version: stamp.rate_card_version,
            wall: stamp.wall,
            mono: stamp.mono,
        };
        // The overdraft's own record. Reserved and settled are zero on it deliberately: the
        // settlement above already carries both, and repeating them here would double every figure
        // a replay adds up. What this record holds that nothing else does is the carry, on the
        // chain, in order, beside the posting it came out of.
        let overdraft = settlement.overdraft.as_ref().map(|note| Posting {
            key: note.key.clone(),
            window: note.window,
            reserved: 0,
            settled: 0,
            overdraft: note.amount,
            rate_card_version: stamp.rate_card_version,
            wall: stamp.wall,
            mono: stamp.mono,
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
        self.journal.append(at.durability, at.step, &entries)?;
        Ok(Settled {
            settlement,
            posting,
            overdraft,
        })
    }

    /// **The settled postings this node's chain holds, decoded back into the ledger's vocabulary.**
    ///
    /// The read half of [`Posting::body`], and it lives beside it for the reason
    /// [`migration_marker_from`] does: the encoding is the composition root's, the log unit frames
    /// bytes it cannot parse, and the ledger unit knows nothing about a chain. One writer and one
    /// reader, in one file, is what keeps the two from drifting.
    ///
    /// # Errors
    ///
    /// The chain could not be read, or a record on it could not be understood as a posting. Both
    /// are errors and neither is an empty answer: a boot that answers "nothing settled" to a chain
    /// it could not read is a boot that hands every maxed-out key its whole cap again.
    pub fn replay_postings(&self) -> Result<JournalSpend, HydrationError> {
        let replayed = self
            .journal
            .replay()
            .map_err(|e| HydrationError::RecordUnavailable(e.to_string()))?
            .map_err(|e| HydrationError::RecordUnavailable(e.to_string()))?;
        let mut postings = Vec::new();
        for record in &replayed {
            if record.class != RecordClass::Transaction {
                continue;
            }
            // The audit records share this class, so the discriminator is the body itself: a
            // posting's first field is a balance key, and an audit record's is a hex digest. A body
            // that is not a posting is passed over rather than reported, because it is not one and
            // never claimed to be; a body that IS one and will not decode is the error arm.
            match posting_from(&record.body) {
                Some(posting) => postings.push(posting),
                None => continue,
            }
        }
        Ok(JournalSpend { postings })
    }

    /// **Restore the ledger's settled spend from this node's own chain.**
    ///
    /// Boot only. What comes back is what each balance carried into this process, which is what the
    /// door is bound to — see `busbar_unit_admission::CarriedSpend`.
    ///
    /// # Errors
    ///
    /// As [`Durability::replay_postings`].
    pub fn hydrate_ledger(&mut self) -> Result<Hydration, HydrationError> {
        let source = self.replay_postings()?;
        self.ledger.hydrate(&source)
    }

    /// **The node's ledger tick: seal, journal, anchor, retire — in that one order.**
    ///
    /// The binding the checkpoint was built for, and the reason it had no production caller until
    /// now. Three units are in scope here and nowhere else: the ledger owns the figures and the
    /// retention boundary, the journal owns the position, and the anchor sink is the deployment's.
    /// Joining them in ONE function is what makes "every seal is on the chain and nothing is retired
    /// against a seal that is not" a fact about the code rather than a convention.
    ///
    /// The journal append sits between the seal and the anchor deliberately. A seal that reached the
    /// anchor sink but not the chain would be a figure with no position — the one thing the journal
    /// exists to prevent — and the ledger's own tick already refuses to retire anything the anchor
    /// did not take, so a failed anchor here costs the node nothing but growth it can see.
    ///
    /// # Errors
    ///
    /// The checkpoint could not be signed, or the journal lost the record. Nothing has been retired
    /// in either case: the ledger retires only inside its own tick, which this has not reached.
    pub fn tick_ledger(
        &mut self,
        at: &busbar_unit_ledger::tick::TickAt<'_>,
        anchor: &mut dyn busbar_unit_ledger::checkpoint::CheckpointAnchor,
        token: &DurabilityToken,
        step: StepName,
    ) -> Result<busbar_unit_ledger::tick::Tock, TickLost> {
        // The seal, WITHOUT the anchor and without the retirement, so the chain takes it before
        // anything acts on it. `JournalledAnchor` below is what puts the journal in the middle.
        let mut journalled = JournalledAnchor {
            journal: &mut self.journal,
            checkpoints: &mut self.checkpoints,
            token,
            step,
            anchor,
            lost: None,
        };
        let tock = self
            .ledger
            .tick(at, &mut journalled)
            .map_err(TickLost::Sign)?;
        match journalled.lost {
            Some(lost) => Err(TickLost::Journal(lost)),
            None => Ok(tock),
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
        token: &'a DurabilityToken,
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
    pub durability: &'a DurabilityToken,
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

/// A settlement as the journal carries it.
///
/// A value rather than a reference to the ledger's books, because a posting is a thing that happened
/// at a moment and the books are what they are now. The two are different facts and a record built
/// out of the second could not be replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posting {
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
}

impl Posting {
    /// The journal body: the balance it moved, the window, and the three figures.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut body = BodyWriter::new();
        body.text(&self.key.to_string());
        body.num(self.window);
        body.figure(self.reserved);
        body.figure(self.settled);
        body.figure(self.overdraft);
        body.num(self.rate_card_version);
        body.finish()
    }
}

/// **The settled postings a chain replay found, as the ledger's boot seam takes them.**
///
/// A value rather than a borrow of the journal, because the ledger folds them into the same
/// `Durability` the journal lives in and a boot that held the chain open while it wrote to the book
/// would be a boot that could not compile. Collected once, at boot, and dropped.
#[derive(Debug, Clone, Default)]
pub struct JournalSpend {
    postings: Vec<HydratedPosting>,
}

impl JournalSpend {
    /// Nothing settled: the answer for a chain with no postings on it.
    #[must_use]
    pub fn nothing() -> Self {
        JournalSpend::default()
    }

    /// How many postings were found.
    #[must_use]
    pub fn len(&self) -> usize {
        self.postings.len()
    }

    /// Whether the chain held none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.postings.is_empty()
    }
}

impl SpendSource for JournalSpend {
    fn postings(&self) -> Result<Vec<HydratedPosting>, HydrationError> {
        Ok(self.postings.clone())
    }
}

/// Put a sealed checkpoint on a journal and keep it, in that order.
///
/// One implementation, two callers: [`Durability::journal_checkpoint`] and the anchor the tick wraps
/// the deployment's sink in. A second copy of these four lines is a second answer to "is a seal this
/// node kept always on the chain", and the answer has to be yes on both paths.
fn put_checkpoint_on(
    journal: &mut Journal,
    kept: &mut Vec<Checkpoint>,
    checkpoint: &Checkpoint,
    token: &DurabilityToken,
    at: StepName,
) -> Result<JournalAck, DurabilityLost> {
    let entry =
        Entry::new(RecordClass::Checkpoint, checkpoint_body(checkpoint)).at(checkpoint.wall, 0);
    let ack = journal.append(token, at, &[entry])?;
    kept.push(checkpoint.clone());
    Ok(ack)
}

/// Why a ledger tick did not finish.
#[derive(Debug)]
pub enum TickLost {
    /// The checkpoint could not be signed.
    Sign(busbar_unit_ledger::checkpoint::SignError),
    /// The journal could not make the seal durable.
    Journal(DurabilityLost),
}

impl std::fmt::Display for TickLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TickLost::Sign(why) => write!(f, "the checkpoint could not be signed: {why}"),
            TickLost::Journal(lost) => write!(
                f,
                "the journal lost the checkpoint at {}",
                lost.step().as_str()
            ),
        }
    }
}

impl std::error::Error for TickLost {}

/// **The journal, wedged between the seal and the anchor.**
///
/// The ledger's tick takes an anchor and calls it with the sealed checkpoint. That call is the one
/// moment at which the seal exists and nothing has acted on it yet, which is exactly where the
/// chain has to take it — so this stands in front of the deployment's real sink, puts the record on
/// the journal, and only then hands the checkpoint on.
///
/// A journal that will not take it means the sink is not called at all and the anchor answer is a
/// failure, which is the right shape: the ledger then retires nothing, and the node grows rather
/// than discarding figures against a seal that has no position.
struct JournalledAnchor<'a> {
    journal: &'a mut Journal,
    checkpoints: &'a mut Vec<Checkpoint>,
    token: &'a DurabilityToken,
    step: StepName,
    anchor: &'a mut dyn busbar_unit_ledger::checkpoint::CheckpointAnchor,
    lost: Option<DurabilityLost>,
}

impl busbar_unit_ledger::checkpoint::CheckpointAnchor for JournalledAnchor<'_> {
    fn anchor(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), busbar_unit_ledger::checkpoint::AnchorError> {
        match put_checkpoint_on(
            self.journal,
            self.checkpoints,
            checkpoint,
            self.token,
            self.step,
        ) {
            Ok(_) => {}
            Err(lost) => {
                let at = lost.step().as_str().to_string();
                self.lost = Some(lost);
                return Err(busbar_unit_ledger::checkpoint::AnchorError::Unavailable(
                    format!("the journal would not take the seal at {at}"),
                ));
            }
        }
        self.anchor.anchor(checkpoint)
    }

    fn head(
        &self,
    ) -> Result<
        Option<busbar_unit_ledger::checkpoint::AnchoredHead>,
        busbar_unit_ledger::checkpoint::AnchorError,
    > {
        self.anchor.head()
    }

    fn is_self_attesting(&self) -> bool {
        self.anchor.is_self_attesting()
    }
}

/// **The door's carried-spend seam, answered out of what the ledger restored at boot.**
///
/// The one place the two vocabularies meet in production. The door names a bucket and a window; the
/// ledger names a balance — a bucket in one dimension at one scope — and the mapping between them is
/// the composition root's, because it is the root that decided what a principal's bucket is called
/// in each of them.
///
/// A window of zero is the all-time bucket, the one that never rolls. Its settlements land in
/// whichever dated window they happened in, so the answer for it is every window's carry; any other
/// window is answered by itself alone.
///
/// Frozen at boot, deliberately: see [`busbar_unit_admission::CarriedSpend`] for why a live view of
/// the book would count every settlement twice.
#[derive(Debug, Clone, Default)]
pub struct HydratedSpend {
    carried: busbar_unit_ledger::hydrate::Carried,
}

impl HydratedSpend {
    /// What one hydration restored, as the door reads it.
    #[must_use]
    pub fn of(hydration: &Hydration) -> Self {
        HydratedSpend {
            carried: hydration.carried.clone(),
        }
    }

    /// Nothing carried — the posture of a node whose chain held no postings, and the one that makes
    /// the door's comparison the one it made before this seam existed.
    #[must_use]
    pub fn nothing() -> Self {
        HydratedSpend::default()
    }
}

impl busbar_unit_admission::CarriedSpend for HydratedSpend {
    fn carried_cents(&self, bucket_id: &str, window: u64) -> i64 {
        self.carried
            .bucket_cents(bucket_id, (window != 0).then_some(window))
    }
}

/// How many bytes a posting record carries beyond its balance key's name: the key's own length
/// prefix, the window, the three figures, and the card version. Fixed, because every one of them is.
const POSTING_BYTES_BESIDE_KEY: usize = 8 + 8 + 16 + 16 + 16 + 8;

/// Read a settled posting back off the journal, or `None` for a body that is not one.
///
/// `None` rather than a partial value, for the reason [`migration_marker_from`] gives: a body this
/// build cannot read is not a posting it may guess at. The `Transaction` class carries sealed audit
/// records too, and the discriminator is structural — an audit record's first field is a hex digest
/// and a posting's is a balance key, which a digest can never parse as.
#[must_use]
pub fn posting_from(body: &[u8]) -> Option<HydratedPosting> {
    if body.len() < 8 {
        return None;
    }
    let key_len = usize::try_from(u64::from_le_bytes(body[0..8].try_into().ok()?)).ok()?;
    if body.len() != key_len + POSTING_BYTES_BESIDE_KEY {
        return None;
    }
    let key = totals_key_from(std::str::from_utf8(body.get(8..8 + key_len)?).ok()?)?;
    let at = 8 + key_len;
    let num = |off: usize| -> Option<u64> {
        Some(u64::from_le_bytes(body.get(off..off + 8)?.try_into().ok()?))
    };
    let figure = |off: usize| -> Option<i128> {
        Some(i128::from_le_bytes(
            body.get(off..off + 16)?.try_into().ok()?,
        ))
    };
    Some(HydratedPosting {
        key,
        window: num(at)?,
        // `reserved` at `at + 8` is deliberately not read: what a hold reserved is closed by the
        // restart, and restoring it would hold budget against a request that will never arrive.
        settled: figure(at + 8 + 16)?,
        overdraft: figure(at + 8 + 32)?,
    })
}

/// Read a balance key back out of the name [`TotalsKey`]'s own `Display` writes.
///
/// Parsed from the RIGHT, because the two trailing fields are drawn from closed vocabularies and
/// the leading one — the bucket — is a name an operator chose and may contain anything at all. A
/// name that does not end in a recognised scope and dimension is not a balance key, which is
/// exactly the test that tells a posting body from a sealed audit record's.
fn totals_key_from(text: &str) -> Option<TotalsKey> {
    use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension};

    let (head, scope) = match text.strip_suffix("/all") {
        Some(head) => (head, BucketScope::All),
        None => {
            let (head, pool) = text.rsplit_once("/pool:")?;
            (head, BucketScope::Pool(std::sync::Arc::from(pool)))
        }
    };
    let (bucket, dimension) = if let Some(b) = head.strip_suffix("/nano-units") {
        (b, CapDimension::NanoUnits)
    } else if let Some(b) = head.strip_suffix("/requests") {
        (b, CapDimension::Requests)
    } else if let Some(b) = head.strip_suffix("/concurrent") {
        (b, CapDimension::Concurrent)
    } else {
        let (b, class) = head.rsplit_once("/class ")?;
        (b, CapDimension::Class(std::sync::Arc::from(class)))
    };
    if bucket.is_empty() {
        return None;
    }
    Some(TotalsKey::new(BucketId::new(bucket), dimension, scope))
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
    body.figure(record.amount.pre_tier);
    body.figure(record.amount.priced);
    body.num(u64::from(record.amount.tier_bp));
    body.num(u64::from(record.amount.fee_count));
    body.text(&record.amount.currency);
    body.num(record.amount.rate_card_version);
    body.text(&record.amount.bucket_chain_ref);
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
    token: &'a DurabilityToken,
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

/// Build the journal, the ledger and the two audit chains, as node zero.
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
    /// The journal, the ledger and the two audit chains, behind the one lock every settlement and
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
/// Memory-buffered, with no data directory read and no shipper of its own, which is the previous
/// release's shape: nothing is probed, nothing is opened, and no file appears beside a configuration
/// that asked for none.
#[must_use]
pub fn node_book() -> NodeBook {
    let rows = std::sync::Arc::new(RecordingRows::new());
    let durability = build(
        &DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(RecordingRows::clone(&rows)),
    )
    .expect("a memory-buffered journal cannot fail to open");
    NodeBook {
        durability: std::sync::Arc::new(std::sync::Mutex::new(durability)),
        rows,
    }
}

/// How often the node ticks its ledger, in seconds.
///
/// Hourly, and the number is a trade rather than a taste. A tick digests every row in the book and
/// reaches the anchor sink, so it is not free; and the thing it buys — a sealed, anchored, journalled
/// position the retention boundary can act on — is measured in windows, and the shortest window a
/// deployment configures is a day. Hourly is twenty-four seals a day against a bound that moves once
/// a day, which leaves room for a stalled anchor to recover without the book growing a day's worth
/// of rows in the meantime.
pub const LEDGER_TICK_INTERVAL_SECS: u64 = 3_600;

/// **How far the node's own retention may reach, in the absence of a configured backup.**
///
/// The start of the day the tick is running in, so windows that have CLOSED may be retired and the
/// live one may not. A node without a data directory gets zero, which retires nothing at all: its
/// journal is memory-buffered and shipped, and discarding a balance because a batch was accepted
/// somewhere is not a claim this node is in a position to make.
///
/// It is deliberately conservative and deliberately not configurable here. The checkpoint's
/// `backup_watermark` field is where a deployment with a real backup states how far IT has got, and
/// when that seam exists this function is what it replaces. Until then the honest default is "as far
/// as this node's own durable chain, and not one window further".
#[must_use]
pub fn node_backup_watermark(on_disk: bool, wall: u64) -> u64 {
    if on_disk {
        busbar_unit_admission::budget_window(busbar_unit_admission::window::WINDOW_DAY, wall)
    } else {
        0
    }
}

/// The root's wall clock, in whole seconds since the Unix epoch, as every other reading on this
/// path spells it: a clock that reads before the epoch gives zero rather than panicking.
///
/// It lives HERE, in the composition root, because reading the wall clock is the root's job. The
/// audit unit takes a [`Clock`] and has no implementation of its own — a unit that could read the
/// clock could produce a different record from the same inputs, and then replaying the inputs would
/// no longer reproduce the record.
struct RootWallClock;

impl Clock for RootWallClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// Build the journal, the ledger and the two audit chains.
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

    Ok(Durability {
        journal,
        // Not `Ledger::new()`. The reconciliation identity and rollback both require the dual
        // write, and both are release requirements rather than deployment choices.
        ledger: Ledger::dual_writing(legacy_rows),
        record: AuditChain::new(),
        // The ring takes the ROOT's clock. The audit unit has none of its own to fall back on, which
        // is the point: reading the wall clock is the composition root's job, and a unit that could
        // do it for itself would stop being replayable from its inputs.
        legacy: AuditLog::with(Box::new(RootWallClock), Box::new(NoSeam)),
        checkpoints: Vec::new(),
    })
}

/// **The node's ledger tick, running for the life of the process.**
///
/// THE DRIVER, and the reason there is one. Sealing digests every row in the book and anchoring
/// reaches a sink outside the node; doing either on the path that admits a request would put an
/// unbounded fold and a network call inside the decision that says yes or no. So it is a background
/// task on the root's own clock, spawned once at boot beside the write-behind flusher, and the
/// request path never reaches it.
///
/// It runs one FINAL tick when the shutdown signal fires, for the same reason the flusher does: a
/// graceful stop should leave the book sealed at where it actually got to, so the next boot's
/// hydration and the next node's audit both start from a position rather than from the last hour's.
///
/// The anchor is [`busbar_unit_ledger::SelfAttestingAnchor`] and the label goes with it: a node that
/// files its own seals where it can rewrite them has proved nothing to anybody, and
/// [`busbar_unit_ledger::AnchorState::self_attesting`] carries that onward to whatever reports the
/// node's health. Binding a real sink is a deployment's decision and this is where it will arrive.
pub fn spawn_ledger_tick(
    durability: std::sync::Arc<std::sync::Mutex<Durability>>,
    token: DurabilityToken,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut anchor = busbar_unit_ledger::SelfAttestingAnchor::new();
        let mut checkpoint_seq: u64 = 0;
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(LEDGER_TICK_INTERVAL_SECS));
        // The first tick of a tokio interval fires immediately; the node has just booted and its
        // book is whatever the hydration restored, which is a position worth sealing.
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.recv() => {
                    checkpoint_seq += 1;
                    tick_once(&durability, &token, &mut anchor, checkpoint_seq);
                    return;
                }
            }
            checkpoint_seq += 1;
            tick_once(&durability, &token, &mut anchor, checkpoint_seq);
        }
    })
}

/// One tick, with the lock held for exactly as long as it takes.
///
/// Split out so the loop above reads as the schedule and this reads as the act, and so the guard's
/// scope is a function body rather than something a future holds across an await.
fn tick_once(
    durability: &std::sync::Mutex<Durability>,
    token: &DurabilityToken,
    anchor: &mut dyn busbar_unit_ledger::checkpoint::CheckpointAnchor,
    checkpoint_seq: u64,
) {
    let wall = RootWallClock.now();
    let mut book = durability.lock().unwrap_or_else(|p| p.into_inner());
    let on_disk = book.on_disk();
    let node = book.journal.node();
    let at = busbar_unit_ledger::tick::TickAt {
        checkpoint_seq,
        node,
        wall,
        // This node's own chain head, cross-linked into the seal. One node, one head: a fleet's
        // other heads arrive through whatever collects them, and inventing a peer's is worse than
        // sealing without it.
        heads: vec![busbar_unit_ledger::checkpoint::ChainHead {
            node,
            node_seq: book.journal.next_seq().saturating_sub(1),
            hash: book.journal.head(),
        }],
        backup_watermark: node_backup_watermark(on_disk, wall),
        // The chain's own high-water, which for a node whose journal IS its durable record is the
        // figure this field names: the last sequence anything durable knows about.
        store_seq_high_water: book.journal.next_seq().saturating_sub(1),
        history_seq: None,
        // No signer bound. A checkpoint with no signature is honest about what it is — the figures
        // digested and positioned, with nobody's name on them — and is exactly what
        // `Checkpoint::seal`'s `None` arm exists for. Binding the deployment's key is the same
        // decision as binding a real anchor sink and arrives with it.
        secret: None,
    };
    if let Err(why) = book.tick_ledger(&at, anchor, token, StepName::Meter) {
        // A tick that could not finish is reported and the loop keeps its schedule. It has retired
        // nothing — the ledger retires only inside its own tick, which this did not reach — so the
        // cost of a failed tick is a book that did not shrink, which the next one will.
        eprintln!("busbar: the ledger tick did not finish: {why}");
    }
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
