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
use busbar_unit_audit::{AuditChain, AuditLog, AuditRecord};
use busbar_unit_ledger::checkpoint::Checkpoint;
use busbar_unit_ledger::legacy::LegacyRows;
use busbar_unit_ledger::migration::{MigrationError, MigrationMarker, MigrationRecords};
use busbar_unit_ledger::settle::Ledger;
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
        let entry =
            Entry::new(RecordClass::Checkpoint, checkpoint_body(checkpoint)).at(checkpoint.wall, 0);
        self.journal.append(token, at, &[entry])
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
        legacy: AuditLog::new(),
    })
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
mod tests {
    use super::*;
    use busbar_caps::KernelSeal;
    use busbar_unit_audit::{Clock, NoSeam};
    use busbar_unit_ledger::legacy::RecordingRows;
    use busbar_unit_wal::{decode_run, verify_journal, NullShipper};

    /// A scratch directory that removes itself, following the journal unit's own test fixture: the
    /// point of these tests is what is and is not created, so each needs a directory nobody else is
    /// writing to.
    struct ScratchDir {
        path: PathBuf,
    }

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "busbar-root-durability-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("scratch directory");
            ScratchDir { path }
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.path)
                .expect("scratch directory is readable")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn rows() -> Box<dyn LegacyRows> {
        Box::new(RecordingRows::new())
    }

    fn token() -> DurabilityToken {
        DurabilityToken::mint(&KernelSeal::acquire_for_kernel())
    }

    fn marker(seq: u64, sealed_at: u64) -> MigrationMarker {
        MigrationMarker {
            checkpoint_seq: seq,
            node: 4,
            sealed_at,
            body_hash: [7u8; 32],
            balances: 3,
            cells_read: 11,
            rate_card_version: 5,
        }
    }

    /// The unset branch, and the assertion that matters: the working directory the node was started
    /// in is untouched. Not "no journal was opened" — no FILE appeared, checked by listing.
    #[test]
    fn no_data_dir_creates_no_file() {
        let scratch = ScratchDir::new("unset");
        assert!(scratch.entries().is_empty(), "the fixture starts empty");

        let cfg = DurabilityConfig { data_dir: None };
        let durability =
            build(&cfg, Box::new(NullShipper::new()), rows()).expect("memory-buffered cannot fail");

        assert!(!durability.on_disk());
        assert_eq!(durability.journal.mode(), Mode::MemoryBuffered);
        assert_eq!(
            scratch.entries(),
            Vec::<String>::new(),
            "a node with no configured data directory wrote a file"
        );
        assert!(
            writable_paths(&cfg).is_empty(),
            "no data directory means no writable path at all"
        );
    }

    /// And writing every kind of record to it still creates nothing. The branch above says the
    /// journal was built without a disk; this says it stays that way once the units start using it,
    /// which is the claim an operator actually cares about.
    #[test]
    fn no_data_dir_creates_no_file_even_once_every_unit_has_written() {
        let scratch = ScratchDir::new("unset-in-use");
        let mut durability = build(
            &DurabilityConfig { data_dir: None },
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("memory-buffered cannot fail");
        let token = token();

        durability
            .journal_posting(&posting(), &token, StepName::Meter)
            .expect("the null shipper takes it");
        durability
            .migration_records(&token, StepName::Meter)
            .write_marker(&marker(0, 1_700_000_000))
            .expect("the marker goes on the chain");

        assert_eq!(
            scratch.entries(),
            Vec::<String>::new(),
            "writing to the journal created a file on a node with no data directory"
        );
        assert!(!durability.on_disk());
    }

    fn posting() -> Posting {
        use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension};
        Posting {
            key: TotalsKey::new(
                BucketId::new("vk_a"),
                CapDimension::NanoUnits,
                BucketScope::All,
            ),
            window: 86_400,
            reserved: 5_000,
            settled: 4_200,
            overdraft: 0,
            rate_card_version: 3,
            wall: 1_700_000_000,
            mono: 42,
        }
    }

    /// A sealed audit record for a unit that ran.
    fn audit_inputs(unit: u64) -> busbar_unit_audit::AuditInputs {
        use busbar_caps::{KernelSeal, Origin, OriginKind, Outcome, UnitKey};
        use busbar_unit_audit::{
            Amount, AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, What,
        };
        AuditInputs {
            subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
            what: What {
                unit_key: UnitKey::new(unit),
                op_class: OpClassId::new("chat.completion"),
                destination: Some("upstream-a".into()),
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: 1_700_000_000 + unit,
            mono: unit * 1_000,
            origin: Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client),
            outcome: OutcomeFacts {
                unit_end: Outcome::Completed,
                step: None,
                finish: FinishClass::Complete,
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            amount: Amount {
                lines: Vec::new(),
                pre_tier: 600,
                priced: 540,
                tier_bp: 9_000,
                fee_count: 1,
                currency: "USD".into(),
                rate_card_version: 3,
                bucket_chain_ref: "chain:free>paid".into(),
            },
            controls: Controls {
                lease_epoch: 4,
                policy_epoch: 7,
                ..Controls::default()
            },
            correlation_label: Some("customer-order-99".into()),
        }
    }

    /// A sealed audit record goes on the journal, carrying the two digests that tie it back to the
    /// audit unit's own chain — and the epochs it ran under land in the journal header, which is
    /// where a reader asking "under which policy" looks.
    #[test]
    fn a_sealed_audit_record_goes_on_the_journal() {
        use busbar_caps::{Audit as AuditStep, KernelSeal, UnitToken};
        use busbar_unit_audit::Audit as _;

        let mut durability = build_for_node(
            &DurabilityConfig { data_dir: None },
            4,
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("memory-buffered cannot fail");
        let token = token();
        let audit_token: UnitToken<AuditStep> = UnitToken::mint(&KernelSeal::acquire_for_kernel());

        let sealed = durability.record.seal(audit_inputs(11), &audit_token);
        let ack = durability
            .journal_audit(&sealed, &token, StepName::Meter)
            .expect("the record goes on the chain");

        let record = &ack.sealed[0];
        assert_eq!(record.class, RecordClass::Transaction);
        assert_eq!(record.wall, sealed.wall);
        assert_eq!(record.mono, sealed.mono);
        assert_eq!(record.lease_epoch, 4);
        assert_eq!(record.policy_epoch, 7);
        assert_eq!(
            record.body,
            audit_body(&sealed),
            "the body is the sealed record's, digests first"
        );
        // The tie back to the audit unit's chain: the journal body opens with that chain's two
        // hashes, so a reader holding one can find the other.
        assert!(String::from_utf8_lossy(&record.body).contains(&sealed.hash));
        assert_eq!(durability.record.sealed(), 1);
        assert_eq!(
            durability.legacy.len(),
            0,
            "journalling a sealed record must not touch the previous release's chain"
        );
    }

    /// The set branch: the operator asked for a journal on this node's disk, so one appears. The
    /// mirror of the test above, and the reason that one means something — an assertion that no
    /// file appears is only worth having if a file appears when it should.
    #[test]
    fn a_configured_data_dir_opens_a_journal_on_disk() {
        let scratch = ScratchDir::new("set");
        let cfg = DurabilityConfig {
            data_dir: Some(scratch.path.clone()),
        };
        let durability =
            build(&cfg, Box::new(NullShipper::new()), rows()).expect("the directory is writable");

        assert!(durability.on_disk());
        assert_eq!(durability.journal.mode(), Mode::OnDisk);
        assert!(
            !scratch.entries().is_empty(),
            "a configured data directory should hold the journal's first segment"
        );
        assert_eq!(writable_paths(&cfg), vec![scratch.path.as_path()]);
    }

    /// The two branches build the same stack. A node without a data directory is not running a
    /// reduced ledger or a reduced audit chain; only the journal's backing differs.
    #[test]
    fn both_branches_build_the_same_ledger_and_audit_streams() {
        let scratch = ScratchDir::new("same");
        let buffered = build(
            &DurabilityConfig { data_dir: None },
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("memory-buffered cannot fail");
        let on_disk = build(
            &DurabilityConfig {
                data_dir: Some(scratch.path.clone()),
            },
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("the directory is writable");

        // The audit chains start at the same place on both, because neither is a function of where
        // the journal lives.
        assert_eq!(buffered.record.next_seq(), on_disk.record.next_seq());
        assert_eq!(buffered.legacy.len(), on_disk.legacy.len());
        assert!(buffered.ledger.is_dual_writing());
        assert!(on_disk.ledger.is_dual_writing());
        // And the journal starts at genesis on both.
        assert_eq!(buffered.journal.head(), on_disk.journal.head());
        assert_eq!(buffered.journal.next_seq(), 1);
    }

    /// A data directory that cannot be opened is an error the caller sees, not a silent fall back
    /// to memory. An operator who asked for a journal on disk and did not get one has to be told:
    /// the quiet downgrade is how a deployment discovers at recovery time that it kept nothing.
    #[test]
    fn an_unopenable_data_dir_is_an_error_and_not_a_silent_downgrade() {
        let scratch = ScratchDir::new("unopenable");
        // A regular file where the directory should be: the open fails, and it fails as an error.
        let blocked = scratch.path.join("not-a-directory");
        std::fs::write(&blocked, b"").expect("write the blocking file");

        let cfg = DurabilityConfig {
            data_dir: Some(blocked),
        };
        assert!(build(&cfg, Box::new(NullShipper::new()), rows()).is_err());
    }

    /// Every unit's records are on ONE chain, in the order they happened, and the chain verifies.
    /// This is the whole row: an audit record, a posting, a checkpoint and a migration marker, with
    /// one numbering across all four.
    #[test]
    fn one_journal_carries_every_unit_in_one_order() {
        let mut durability = build_for_node(
            &DurabilityConfig { data_dir: None },
            4,
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("memory-buffered cannot fail");
        let token = token();

        durability
            .migration_records(&token, StepName::Meter)
            .write_marker(&marker(0, 1_700_000_000))
            .expect("the marker goes on the chain");
        durability
            .journal_posting(&posting(), &token, StepName::Meter)
            .expect("the posting goes on the chain");
        let checkpoint = Checkpoint::seal(
            1,
            4,
            1_700_000_100,
            Vec::new(),
            Default::default(),
            0,
            0,
            None,
        )
        .expect("an unsigned checkpoint seals");
        durability
            .journal_checkpoint(&checkpoint, &token, StepName::Meter)
            .expect("the checkpoint goes on the chain");

        let replayed = durability
            .journal
            .replay()
            .expect("the journal reads back")
            .expect("and verifies");
        let classes: Vec<RecordClass> = replayed.iter().map(|r| r.class).collect();
        assert_eq!(
            classes,
            vec![
                RecordClass::Migration,
                RecordClass::Transaction,
                RecordClass::Checkpoint
            ]
        );
        let seqs: Vec<u64> = replayed.iter().map(|r| r.node_seq).collect();
        assert_eq!(seqs, vec![1, 2, 3], "one numbering across every unit");
        assert!(replayed.iter().all(|r| r.node == 4));
        verify_journal(&replayed).expect("the whole chain verifies");
    }

    /// The migration marker lives on the journal, and reading it back is what makes a second boot
    /// free. Where it used to live — the store adapter's node-local shim — it could not be read back
    /// by anything else and did not survive a restart even on a node with a disk.
    #[test]
    fn the_migration_marker_is_a_journal_record_and_reads_back() {
        let mut durability = build_for_node(
            &DurabilityConfig { data_dir: None },
            4,
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("memory-buffered cannot fail");
        let token = token();

        assert_eq!(
            durability
                .migration_records(&token, StepName::Meter)
                .read_marker()
                .expect("readable"),
            None,
            "a deployment that has not migrated has no marker"
        );

        let sealed = marker(0, 1_700_000_000);
        durability
            .migration_records(&token, StepName::Meter)
            .write_marker(&sealed)
            .expect("the marker goes on the chain");

        assert_eq!(
            durability
                .migration_records(&token, StepName::Meter)
                .read_marker()
                .expect("readable"),
            Some(sealed),
            "the marker read back off the chain is the marker that was sealed"
        );
    }

    /// And it survives a restart when there is a disk to keep it on — which is the improvement the
    /// binding buys, and the one the node-local shim could never make.
    #[test]
    fn with_a_data_dir_the_marker_survives_a_restart() {
        let scratch = ScratchDir::new("marker-restart");
        let cfg = DurabilityConfig {
            data_dir: Some(scratch.path.clone()),
        };
        let token = token();
        let sealed = marker(0, 1_700_000_000);

        {
            let mut durability = build_for_node(&cfg, 4, Box::new(NullShipper::new()), rows())
                .expect("the directory is writable");
            durability
                .migration_records(&token, StepName::Meter)
                .write_marker(&sealed)
                .expect("the marker goes on the chain");
        }

        let mut restarted = build_for_node(&cfg, 4, Box::new(NullShipper::new()), rows())
            .expect("the journal reopens onto what it wrote");
        assert_eq!(
            restarted
                .migration_records(&token, StepName::Meter)
                .read_marker()
                .expect("readable"),
            Some(sealed),
            "a second boot found the marker its first boot sealed"
        );
    }

    /// The previous release's administrative chain is UNTOUCHED by any of this.
    ///
    /// Said by building two logs and driving one of them through a node that is also journalling:
    /// every entry, including the digest that a deployment's whole history verifies against, is
    /// identical. A journal that had quietly become an input to that digest would report every
    /// deployed chain as tampered at the next boot, and that is the one change this release may not
    /// make.
    #[test]
    fn journalling_does_not_touch_the_legacy_admin_chain() {
        let mut durability = build_for_node(
            &DurabilityConfig { data_dir: None },
            4,
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("memory-buffered cannot fail");
        let token = token();
        // The digest covers the timestamp, so the two logs are put on one fixed clock: the claim is
        // about what journalling does to the chain, and a wall clock ticking between two writes
        // would make the comparison say nothing.
        durability.legacy = AuditLog::with(Box::new(PinnedClock), Box::new(NoSeam));
        let alone = AuditLog::with(Box::new(PinnedClock), Box::new(NoSeam));

        let mutations = [
            ("key.create", "vk_a"),
            ("key.rotate", "vk_a"),
            ("key.delete", "vk_b"),
        ];

        for (action, resource) in mutations {
            // The node is journalling between administrative writes, exactly as it would be.
            durability
                .journal_posting(&posting(), &token, StepName::Meter)
                .expect("the posting goes on the chain");
            durability.legacy.record_by(
                action,
                resource,
                busbar_unit_audit::OUTCOME_APPLIED,
                "admin",
            );
            alone.record_by(
                action,
                resource,
                busbar_unit_audit::OUTCOME_APPLIED,
                "admin",
            );
        }

        // The WIRE, field for field, digest included: what an administrative read returns is what a
        // node with no journal at all would have returned.
        let on_the_wire = |log: &AuditLog| {
            serde_json::to_string(&log.export()).expect("the previous release's record encodes")
        };
        assert_eq!(durability.legacy.len(), 3);
        assert_eq!(
            on_the_wire(&durability.legacy),
            on_the_wire(&alone),
            "the administrative chain differs from one written on a node with no journal at all"
        );
        assert!(durability.legacy.verify());
        // And the journal has only its own records on it — the administrative entries did not leak
        // onto it either, which is the other half of "the two do not merge".
        let replayed = durability
            .journal
            .replay()
            .expect("readable")
            .expect("verifies");
        assert_eq!(replayed.len(), 3);
        assert!(replayed.iter().all(|r| r.class == RecordClass::Transaction));
    }

    /// A clock that does not move, so two chains written independently are comparable.
    #[derive(Debug)]
    struct PinnedClock;

    impl Clock for PinnedClock {
        fn now(&self) -> u64 {
            1_700_000_000
        }
    }

    /// The shipped batches ARE the chain, so a node with no data directory that shipped everything
    /// has lost nothing it shipped.
    #[test]
    fn what_the_store_took_is_the_chain() {
        let shipper = busbar_unit_wal::BufferShipper::new();
        let mut durability = build_for_node(
            &DurabilityConfig { data_dir: None },
            4,
            Box::new(shipper.clone()),
            rows(),
        )
        .expect("memory-buffered cannot fail");
        let token = token();

        durability
            .migration_records(&token, StepName::Meter)
            .write_marker(&marker(0, 1_700_000_000))
            .expect("the marker ships");
        for _ in 0..3 {
            durability
                .journal_posting(&posting(), &token, StepName::Meter)
                .expect("the posting ships");
        }

        let shipped = decode_run(&shipper.records()).expect("the store took journal records");
        verify_journal(&shipped).expect("what the store holds is a chain that verifies");
        assert_eq!(shipped.len(), 4);
        assert_eq!(
            shipped.last().expect("a record").hash,
            durability.journal.head(),
            "the store's head is the node's head"
        );
    }
}
