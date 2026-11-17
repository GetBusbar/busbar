// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;

use busbar_contract::caps::{DurabilityLost, DurableWrite, Grant, StepName};
use busbar_kernel_audit::{
    from_journal_body, journal_body, AuditChain, AuditInputs, AuditKeySet, AuditRecord,
    AuditVerifyingKey, KeyError,
};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, RecordClass};

use busbar_kernel::persistence::journal::runtime::StagedRun;
use busbar_kernel::persistence::journal::runtime::{BufferBudget, RuntimeJournal};
use std::sync::Arc;

#[cfg(test)]
#[path = "../tests/store_scan_prefetch.rs"]
mod native_scan_tests;

#[cfg(test)]
#[path = "../tests/audit_group_atomic.rs"]
mod native_audit_group_atomic;
#[cfg(test)]
#[path = "../tests/audit_group_lane.rs"]
mod native_audit_group_lane;

mod unit_checkpoint;
mod unit_checkpoint_audit;
mod usage_recovery;
pub(crate) use unit_checkpoint::unit_checkpoint_sink;
#[cfg(test)]
pub(crate) use unit_checkpoint_audit::{RunningAudit, SelectedAuditIdentity};
pub(crate) use usage_recovery::usage_recovery_sink;

mod store_identity;
pub(crate) use store_identity::{host_identity, take_node};
#[cfg(test)]
pub(crate) use store_identity::{stored_keyset, BootIdentity};

pub(crate) use store_identity::walk_stored_chains;

mod amend;

pub(crate) use amend::bind_amendments;

pub(crate) use amend::verify_held;

mod audit;

pub(crate) use audit::{AuditWindowAt, LineIdentity};

mod audit_page;

pub(crate) mod audit_services;
pub(crate) mod notary;
pub(crate) mod predecessor;
pub(crate) mod response_intent;
pub(crate) mod restart_seal;
pub(crate) mod signer;
pub(crate) use notary::HeadFeed;

mod ring;
pub(crate) use ring::AuditRing;

mod recovery;
pub(crate) use recovery::{node_verb_store, report_operator_breaks};

mod plugin_floor;
pub(crate) use plugin_floor::{
    check_prepared_candidate as check_prepared_plugin_floor_candidate, hold as hold_plugin_floor,
    prepare_candidate as prepare_plugin_floor_candidate,
};

pub(crate) const AUDIT_RING: usize = 1_024;

/// PULSED WHEN A RUN OF AUDIT RECORDS IS CONFIRMED: the one `Notify` a `/records?wait=` read
/// sleeps on (ADMIN-API-1.6 §3.3, V7). A pulse wakes only the reads waiting at that moment, so a
/// read arms its wait before it looks for records.
pub(crate) fn records_pulse() -> &'static tokio::sync::Notify {
    static PULSE: std::sync::LazyLock<tokio::sync::Notify> =
        std::sync::LazyLock::new(tokio::sync::Notify::new);
    &PULSE
}

/// The accepted journal configuration. Persistence is always owned by the configured Store.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DurabilityConfig {
    /// The legacy data directory, accepted for compatibility and never opened by these builders.
    pub data_dir: Option<PathBuf>,
}

pub struct Durability {
    pub journal: Arc<RuntimeJournal>,

    pub record: AuditChain,

    audit_ring: AuditRing,

    pub audit_findings: Vec<String>,

    pub audit_signed_from: Option<u64>,

    pub incarnation: u64,

    pub restart_findings: Vec<String>,
    boot_records: Vec<JournalRecord>,

    pub voided_claims: Vec<String>,

    amendments_through: Option<u64>,

    history_budget: BufferBudget,

    resumed: bool,

    /// Where a sealed terminal unit's audit line is noted for its checkpoint removal
    /// (SHUTDOWN-HANG F1a). Weak: governance owns the checkpoint sink, which holds this book.
    pub audit_hints: Option<std::sync::Weak<busbar_kernel::governance::GovState>>,

    /// THE NOTARY'S HEAD FEED (SEALING-FIX §3.2): every staged line is published here under this
    /// book's lock, so the notary reads the head without taking it.
    pub(crate) head: Arc<HeadFeed>,

    /// The WAL `node_seq` of the newest audit line read back at reopen (0 for none).
    resumed_head_node_seq: u64,
}

impl Durability {
    /// The retained audit ring: the newest <= `AUDIT_RING` sealed records, oldest first.
    #[must_use]
    pub(crate) fn audit_records(&self) -> &[AuditRecord] {
        self.audit_ring.as_slice()
    }

    /// Test-only: in-place mutation of the visible ring window (tamper proofs).
    #[cfg(test)]
    pub(crate) fn audit_records_mut_for_tamper_test(&mut self) -> &mut [AuditRecord] {
        self.audit_ring.window_mut_for_tamper_test()
    }

    /// Test-only: remove ring records in place (tamper-by-removal proofs).
    #[cfg(test)]
    pub(crate) fn retain_audit_for_tamper_test(&mut self, f: impl FnMut(&AuditRecord) -> bool) {
        self.audit_ring.retain_for_tamper_test(f);
    }
}

pub type ChainRead = std::io::Result<Result<Vec<JournalRecord>, busbar_kernel_wal::JournalBreak>>;

pub(crate) struct ChainAt {
    journal: Arc<RuntimeJournal>,
    budget: BufferBudget,
    through: u64,
}
impl ChainAt {
    pub async fn read(self) -> ChainRead {
        let mut records = self
            .journal
            .read_records(self.budget)
            .await
            .map_err(|error| {
                std::io::Error::other(format!("native journal read failed: {error:?}"))
            })?;
        records.retain(|record| record.node_seq < self.through);
        Ok(busbar_kernel_wal::verify_journal(&records).map(|()| records))
    }
    fn store(&self) -> Option<&str> {
        None
    }
}

fn unreadable_in(store: Option<&str>, e: &std::io::Error) -> String {
    match store {
        Some(store) => format!("the journal could not be read back from the store `{store}`: {e}"),
        None => format!("the journal could not be read back: {e}"),
    }
}

impl std::fmt::Debug for Durability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Durability")
            .field("node", &self.journal.node())
            .field("pending", &self.journal.pending_records())
            .finish_non_exhaustive()
    }
}

impl Durability {
    #[cfg(test)]
    #[must_use]
    pub fn on_disk(&self) -> bool {
        false
    }
    #[must_use]
    pub(crate) fn keeps_chain(&self) -> bool {
        self.resumed
    }
    pub async fn chain(&self) -> ChainRead {
        self.chain_at().read().await
    }
    #[must_use]
    pub(crate) fn chain_at(&self) -> ChainAt {
        ChainAt {
            journal: self.journal.clone(),
            budget: self.history_budget,
            through: self.journal.next_seq(),
        }
    }
    pub(crate) fn unreadable(&self, e: &std::io::Error) -> String {
        unreadable_in(None, e)
    }
    #[must_use]
    pub(crate) fn runtime_journal(&self) -> Arc<RuntimeJournal> {
        self.journal.clone()
    }
    #[must_use]
    pub(crate) fn stored_walk_inputs(
        &self,
    ) -> (Arc<RuntimeJournal>, u64, AuditKeySet, BufferBudget) {
        (
            self.journal.clone(),
            self.journal.node(),
            keyset_of(&self.record),
            self.history_budget,
        )
    }
    #[cfg(test)]
    #[must_use]
    pub(crate) fn durable_in_store(&self) -> bool {
        true
    }
    #[cfg(test)]
    pub(crate) fn stage_entries(&self, entries: &[Entry]) -> Result<Arc<StagedRun>, String> {
        self.journal
            .stage_run(entries)
            .map_err(|error| format!("native journal stage failed: {error:?}"))
    }
    #[cfg(test)]
    pub(crate) async fn journal_claim(
        book: &Arc<std::sync::Mutex<Self>>,
        claim: ClaimBalance,
        stamp: ClaimStamp,
        token: &Grant<DurableWrite>,
        at: StepName,
    ) -> Result<Arc<StagedRun>, DurabilityLost> {
        let (journal, run) = {
            let book = book.lock().unwrap_or_else(|poison| poison.into_inner());
            let record = ClaimRecord {
                taken: ClaimTaken {
                    claim: claim.claim,
                    key: claim.key,
                    window: claim.window,
                    incarnation: book.incarnation,
                    wall: stamp.wall,
                    mono: stamp.mono,
                },
                voided: false,
            };
            let entry =
                Entry::new(RecordClass::Transaction, record.body()).at(stamp.wall, stamp.mono);
            let run = book
                .journal
                .stage_run(&[entry])
                .map_err(|_| DurabilityLost::observed(token, at))?;
            (book.journal.clone(), run)
        };
        journal
            .confirm(&run)
            .await
            .map_err(|_| DurabilityLost::observed(token, at))?;
        Ok(run)
    }
    async fn void_claims(&mut self, unheld: Vec<ClaimTaken>) -> Result<(), std::io::Error> {
        for taken in unheld {
            let record = ClaimRecord {
                taken,
                voided: true,
            };
            let entry = Entry::new(RecordClass::Transaction, record.body())
                .at(record.taken.wall, record.taken.mono);
            let run = self
                .journal
                .stage_run(&[entry])
                .map_err(native_open_error)?;
            loop {
                use busbar_contract::persistence::Failure;
                use busbar_kernel::persistence::journal::RuntimeError;
                match self.journal.confirm(&run).await {
                    Ok(()) => break,
                    Err(RuntimeError::Pending)
                    | Err(RuntimeError::Backend(Failure::Unavailable | Failure::Overloaded)) => {
                        // The native owner retains this exact candidate. Keep
                        // the local run and Durability alive; never stage a
                        // replacement void after an uncertain confirmation.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Err(error) => return Err(native_open_error(error)),
                }
            }
            self.voided_claims.push(record.taken.claim);
        }
        Ok(())
    }
}

#[must_use]
pub(crate) fn keyset_of(chain: &AuditChain) -> AuditKeySet {
    let mut keys = AuditKeySet::new();
    if let Some(key) = chain
        .public_key_hex()
        .and_then(|hex| AuditVerifyingKey::from_hex(&hex).ok())
    {
        keys.insert(key);
    }
    keys
}

const CLAIM_TAKEN: &str = "claim.taken";

const CLAIM_VOIDED: &str = "claim.voided";

/// The balance a claim is journalled on: its bucket, its dimension and its scope as a tag and a
/// name each, and the window. Plain fields: the record's bytes, as every build since the claim
/// record was introduced has written them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimKey {
    /// The bucket.
    pub bucket: String,
    /// The dimension's tag and its class name (empty but for a class dimension).
    pub dimension: (u64, String),
    /// The scope's tag and its pool name (empty but for a pool scope).
    pub scope: (u64, String),
}

#[cfg(test)]
/// What a claim is taken as: the claim itself, the balance and the window it is journalled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimBalance {
    /// The claim — the idempotency key.
    pub claim: String,
    /// The balance.
    pub key: ClaimKey,
    /// The window.
    pub window: u64,
}

#[cfg(test)]
/// When a claim was taken: whole seconds, and the node's monotonic reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaimStamp {
    /// Whole seconds.
    pub wall: u64,
    /// The node's monotonic clock.
    pub mono: u64,
}

/// An idempotency claim a unit took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimTaken {
    /// The claim — the idempotency key.
    pub claim: String,
    /// The balance.
    pub key: ClaimKey,
    /// The window.
    pub window: u64,
    /// Which boot of this node's journal took it.
    pub incarnation: u64,
    /// The unit's arrival, whole seconds.
    pub wall: u64,
    /// The unit's arrival on the node's monotonic clock.
    pub mono: u64,
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
        let key = &self.taken.key;
        body.text(&key.bucket);
        body.num(key.dimension.0);
        body.text(&key.dimension.1);
        body.num(key.scope.0);
        body.text(&key.scope.1);
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
        let bucket = body.text()?.to_string();
        let dimension = (body.num()?, body.text()?.to_string());
        let scope = (body.num()?, body.text()?.to_string());
        let window = body.num()?;
        let claim = body.text()?.to_string();
        body.is_done().then_some(ClaimRecord {
            taken: ClaimTaken {
                claim,
                key: ClaimKey {
                    bucket,
                    dimension,
                    scope,
                },
                window,
                incarnation,
                wall: record.wall,
                mono: record.mono,
            },
            voided: tag == CLAIM_VOIDED,
        })
    }
}

fn open_claims(records: &[JournalRecord]) -> (Vec<ClaimTaken>, u64) {
    let mut open: Vec<ClaimTaken> = Vec::new();
    let mut incarnation = 0;
    for claim in records.iter().filter_map(ClaimRecord::from_record) {
        incarnation = incarnation.max(claim.taken.incarnation);
        if claim.voided {
            open.retain(|taken| *taken != claim.taken);
        } else {
            open.push(claim.taken);
        }
    }
    (open, incarnation)
}

pub(crate) fn audit_body(
    record: &AuditRecord,
) -> Result<Vec<u8>, busbar_kernel_audit::FieldTooLong> {
    journal_body(record)
}

fn audit_entry(record: &AuditRecord) -> Result<Entry, busbar_kernel_audit::FieldTooLong> {
    Ok(Entry::new(RecordClass::Transaction, audit_body(record)?)
        .at(record.wall, record.mono)
        .under(record.controls.lease_epoch, record.controls.policy_epoch))
}

pub(crate) fn decode_audit(record: &JournalRecord) -> Result<Option<AuditRecord>, String> {
    if record.class != RecordClass::Transaction {
        return Ok(None);
    }
    from_journal_body(&record.body, &busbar_kernel::Registration::meter_class)
}

pub struct NodeBook {
    /// Verified persisted deployment public keys, retained with journal/export history.
    pub audit_verification_keys: Arc<AuditKeySet>,
    pub(crate) response_intents: Option<Arc<response_intent::ResponseIntentService>>,
    pub durability: Arc<std::sync::Mutex<Durability>>,
    pub runtime_journal: Arc<RuntimeJournal>,
    pub node_lease: Option<Arc<busbar_kernel::persistence::boot_identity::NodeLease>>,
    pub verb_store: crate::root::kernel::VerbStoreHandle,
    /// The signer threads and the notary (SEALING-FIX §3.3); `None` on a keyless book.
    pub audit: Option<Arc<audit_services::AuditServices>>,
}
impl NodeBook {
    #[cfg(test)]
    pub(crate) fn runtime_journal(&self) -> Arc<RuntimeJournal> {
        self.runtime_journal.clone()
    }
}

fn native_open_error(error: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("native journal: {error:?}"))
}

#[cfg(test)]
/// The root opens one native owner and shares this exact Arc with every
/// journal-writing service. There is no legacy shipper or second live sealer.
pub(crate) async fn node_book(
    journal: Arc<RuntimeJournal>,
    history_budget: BufferBudget,
) -> Result<NodeBook, std::io::Error> {
    let durability = build_on_store(
        &DurabilityConfig::default(),
        journal.node(),
        journal.clone(),
        None,
        history_budget,
    )
    .await?;
    Ok(NodeBook {
        audit_verification_keys: Arc::new(AuditKeySet::new()),
        response_intents: None,
        durability: Arc::new(std::sync::Mutex::new(durability)),
        runtime_journal: journal,
        node_lease: None,
        verb_store: None,
        audit: None,
    })
}

pub(crate) async fn build_on_store(
    _cfg: &DurabilityConfig,
    node: u64,
    journal: Arc<RuntimeJournal>,
    cards: Option<&'static crate::root::kernel::RootHistory>,
    history_budget: BufferBudget,
) -> Result<Durability, std::io::Error> {
    if journal.node() != node {
        return Err(native_open_error("journal node identity differs"));
    }
    let records = journal
        .read_records(history_budget)
        .await
        .map_err(native_open_error)?;
    let mut durability = Durability {
        journal,
        record: AuditChain::new().sealing_as(node),
        audit_ring: AuditRing::new(),
        audit_findings: Vec::new(),
        audit_signed_from: None,
        incarnation: 0,
        restart_findings: Vec::new(),
        boot_records: Vec::new(),
        voided_claims: Vec::new(),
        amendments_through: None,
        history_budget,
        resumed: true,
        audit_hints: None,
        head: Arc::new(HeadFeed::default()),
        resumed_head_node_seq: 0,
    };
    let mut findings = Vec::new();
    if let Some(cards) = cards {
        cards
            .rebuild_from_chain(&mut durability, Some(&records))
            .await
            .map_err(|error| native_open_error(error.to_string()))?;
    }
    durability.resume_audit(&records);
    durability.publish_resumed_head();
    findings.extend(
        durability
            .audit_findings
            .iter()
            .map(|why| format!("audit chain: {why}")),
    );
    let (open, claimed) = open_claims(&records);
    let audited = durability
        .audit_records()
        .iter()
        .map(|record| record.what.incarnation)
        .max()
        .unwrap_or(0);
    durability.incarnation = claimed
        .max(audited)
        .checked_add(1)
        .ok_or_else(|| native_open_error("journal incarnation exhausted"))?;
    durability.void_claims(open).await?;
    findings.dedup();
    durability.restart_findings = findings;
    durability.boot_records = records;
    Ok(durability)
}

#[cfg(test)]
pub(crate) use audit::tests::Scratch;

#[cfg(test)]
#[path = "../tests/durability.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "../tests/ring_front_eviction.rs"]
mod ring_front_eviction;

#[cfg(test)]
#[path = "../tests/durability_boot_reads.rs"]
mod boot_reads;

#[cfg(test)]
#[path = "../tests/durability_reads_unlocked.rs"]
mod reads_unlocked;

#[cfg(test)]
#[path = "../tests/durability_notary.rs"]
mod notary_tests;

#[cfg(test)]
#[path = "../tests/durability_signer.rs"]
mod signer_tests;

#[cfg(test)]
#[path = "../tests/response_intent.rs"]
pub(crate) mod response_intent_tests;
