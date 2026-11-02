// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;

use busbar_contract::caps::{DurabilityLost, DurableWrite, Grant, StepName};
use busbar_kernel_audit::{
    from_journal_body, journal_body, AuditChain, AuditInputs, AuditKeySet, AuditRecord,
    AuditVerifyingKey, KeyError,
};
use busbar_kernel_wal::{
    BodyReader, BodyWriter, Entry, Journal, JournalAck, JournalRecord, Mode, OpenError,
    RecordClass, Shipper,
};

mod store_chain;
pub use store_chain::{read_chain, JournalLane, RECORD_SLOTS};

#[cfg(feature = "root-admin")]
pub use store_chain::ACK_DEADLINE;

#[cfg(feature = "root-admin")]
pub(crate) use store_chain::{off_runtime, wait_for};

#[cfg(test)]
pub use store_chain::{part_key, JOURNAL_SCHEMA};

mod conditional;

mod usage_recovery;
pub(crate) use usage_recovery::usage_recovery_sink;

mod store_identity;
pub use store_identity::{host_identity, keep_keyset, stored_keyset, take_node};

#[cfg(test)]
pub use store_identity::node_id;

#[cfg(any(test, feature = "root-admin"))]
pub use store_identity::walk_stored_chains;

pub use store_identity::stored_chains;

mod amend;

pub use amend::bind_amendments;

#[cfg(feature = "root-admin")]
pub(crate) use amend::verify_held;

mod audit;
mod audit_heads;

#[cfg(feature = "root-admin")]
pub use audit::AuditWindowAt;

mod recovery;
pub use recovery::{node_verb_store, report_operator_breaks};

mod plugin_floor;
pub use plugin_floor::{
    check as check_plugin_floor, check_candidate as check_plugin_floor_candidate,
    hold as hold_plugin_floor, release_keys_floor,
};

pub const AUDIT_RING: usize = 1_024;

/// The accepted journal configuration. Persistence is always owned by the configured Store.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DurabilityConfig {
    /// The legacy data directory, accepted for compatibility and never opened by these builders.
    pub data_dir: Option<PathBuf>,
}

pub struct Durability {
    pub journal: Journal,

    pub record: AuditChain,

    pub audit_records: Vec<AuditRecord>,

    pub audit_findings: Vec<String>,

    pub audit_signed_from: Option<u64>,

    pub incarnation: u64,

    pub restart_findings: Vec<String>,

    pub voided_claims: Vec<String>,

    pub quarantined: Vec<busbar_kernel_wal::Quarantine>,

    pub(crate) cards_from: Option<&'static crate::root::kernel::RootHistory>,

    amendments_through: Option<u64>,

    lane: Option<JournalLane>,

    resumed: bool,
}

fn chain_of(
    journal: &Journal,
    store_kept: Option<&JournalLane>,
) -> std::io::Result<Result<Vec<JournalRecord>, busbar_kernel_wal::JournalBreak>> {
    match store_kept {
        Some(lane) => store_chain::whole_chain(journal, lane),
        None => journal.replay(),
    }
}

pub type ChainRead = std::io::Result<Result<Vec<JournalRecord>, busbar_kernel_wal::JournalBreak>>;

pub struct ChainAt(ChainSource);

enum ChainSource {
    Read(ChainRead),

    Stored(store_chain::HeldChain),
}

impl ChainAt {
    pub fn read(self) -> ChainRead {
        match self.0 {
            ChainSource::Read(read) => read,
            ChainSource::Stored(held) => held.read(),
        }
    }

    fn store(&self) -> Option<&str> {
        match &self.0 {
            ChainSource::Read(_) => None,
            ChainSource::Stored(held) => Some(held.store()),
        }
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
            .field("mode", &self.journal.mode())
            .field("head", &self.journal.head_hex())
            .finish_non_exhaustive()
    }
}

impl Durability {
    #[must_use]
    pub fn on_disk(&self) -> bool {
        matches!(self.journal.mode(), Mode::OnDisk)
    }

    #[must_use]
    pub fn keeps_chain(&self) -> bool {
        self.resumed
    }

    pub fn chain(&self) -> ChainRead {
        self.chain_at().read()
    }

    #[must_use]
    pub fn chain_at(&self) -> ChainAt {
        ChainAt(match self.store_kept() {
            Some(lane) => match store_chain::HeldChain::of(&self.journal, lane) {
                Ok(held) => ChainSource::Stored(held),
                Err(e) => ChainSource::Read(Err(e)),
            },
            None => ChainSource::Read(self.journal.replay()),
        })
    }

    fn store_kept(&self) -> Option<&JournalLane> {
        self.lane.as_ref().filter(|_| self.resumed)
    }

    pub(crate) fn unreadable(&self, e: &std::io::Error) -> String {
        unreadable_in(self.store_kept().map(JournalLane::store), e)
    }

    #[must_use]
    pub fn lane(&self) -> Option<&JournalLane> {
        self.lane.as_ref()
    }

    #[must_use]
    pub fn stored_walk_inputs(
        &self,
    ) -> Option<(JournalLane, u64, busbar_kernel_audit::AuditKeySet)> {
        let lane = self.lane.as_ref()?;
        Some((lane.clone(), self.journal.node(), keyset_of(&self.record)))
    }

    #[must_use]
    pub fn durable_in_store(&self) -> bool {
        self.store_kept().is_some()
    }

    #[must_use]
    pub fn refuses_money(&self) -> Option<String> {
        self.lane.as_ref().and_then(JournalLane::refuses_money)
    }

    pub fn offer_held_back(&mut self) -> usize {
        if !self.durable_in_store() || self.journal.buffered() == 0 {
            return 0;
        }
        let token = busbar_kernel::teller::Kernel::new().durability_token();

        let _ = self.journal.append(&token, StepName::Meter, &[]);
        self.journal.buffered()
    }

    pub fn journal_quarantines(
        &mut self,
        token: &Grant<DurableWrite>,
        at: StepName,
        wall: u64,
    ) -> Result<Option<JournalAck>, DurabilityLost> {
        self.journal.record_quarantines(token, at, wall)
    }

    pub fn journal_claim(
        &mut self,
        claim: ClaimBalance,
        stamp: ClaimStamp,
        token: &Grant<DurableWrite>,
        at: StepName,
    ) -> Result<JournalAck, DurabilityLost> {
        let record = ClaimRecord {
            taken: ClaimTaken {
                claim: claim.claim,
                key: claim.key,
                window: claim.window,
                incarnation: self.incarnation,
                wall: stamp.wall,
                mono: stamp.mono,
            },
            voided: false,
        };
        let entry = Entry::new(RecordClass::Transaction, record.body()).at(stamp.wall, stamp.mono);
        self.journal.append(token, at, &[entry])
    }

    fn void_claims(&mut self, unheld: Vec<ClaimTaken>) {
        if unheld.is_empty() {
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

            let _ = self.journal.append(&token, StepName::Admit, &[entry]);
            self.voided_claims.push(record.taken.claim);
        }
    }
}

#[must_use]
pub fn keyset_of(chain: &AuditChain) -> AuditKeySet {
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
pub struct ClaimKey {
    /// The bucket.
    pub bucket: String,
    /// The dimension's tag and its class name (empty but for a class dimension).
    pub dimension: (u64, String),
    /// The scope's tag and its pool name (empty but for a pool scope).
    pub scope: (u64, String),
}

/// What a claim is taken as: the claim itself, the balance and the window it is journalled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimBalance {
    /// The claim — the idempotency key.
    pub claim: String,
    /// The balance.
    pub key: ClaimKey,
    /// The window.
    pub window: u64,
}

/// When a claim was taken: whole seconds, and the node's monotonic reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimStamp {
    /// Whole seconds.
    pub wall: u64,
    /// The node's monotonic clock.
    pub mono: u64,
}

/// An idempotency claim a unit took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimTaken {
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

pub fn audit_body(record: &AuditRecord) -> Result<Vec<u8>, busbar_kernel_audit::FieldTooLong> {
    journal_body(record)
}

fn audit_entry(record: &AuditRecord) -> Result<Entry, busbar_kernel_audit::FieldTooLong> {
    Ok(Entry::new(RecordClass::Transaction, audit_body(record)?)
        .at(record.wall, record.mono)
        .under(record.controls.lease_epoch, record.controls.policy_epoch))
}

pub fn decode_audit(record: &JournalRecord) -> Result<Option<AuditRecord>, String> {
    if record.class != RecordClass::Transaction {
        return Ok(None);
    }
    from_journal_body(&record.body, &busbar_kernel::Registration::meter_class)
}

pub struct NodeBook {
    pub durability: std::sync::Arc<std::sync::Mutex<Durability>>,

    pub verb_store: crate::root::kernel::VerbStoreHandle,
}

#[must_use]
pub fn node_book() -> NodeBook {
    let durability = build(
        &DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    NodeBook {
        durability: std::sync::Arc::new(std::sync::Mutex::new(durability)),
        verb_store: None,
    }
}

pub fn build(
    cfg: &DurabilityConfig,
    shipper: Box<dyn Shipper<busbar_kernel_wal::Record>>,
) -> Result<Durability, OpenError> {
    build_for_node(cfg, 0, shipper)
}

pub fn build_for_node(
    cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper<busbar_kernel_wal::Record>>,
) -> Result<Durability, OpenError> {
    build_with_cards(cfg, node, shipper, Some(&crate::root::kernel::ROOT_CARD))
}

pub fn build_with_cards(
    cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper<busbar_kernel_wal::Record>>,
    cards: Option<&'static crate::root::kernel::RootHistory>,
) -> Result<Durability, OpenError> {
    build_inner(cfg, node, shipper, None, cards)
}

pub fn build_on_store(
    cfg: &DurabilityConfig,
    node: u64,
    lane: JournalLane,
    cards: Option<&'static crate::root::kernel::RootHistory>,
) -> Result<Durability, OpenError> {
    let resume = read_chain(lane.calls().as_ref(), node).map_err(|why| {
        OpenError::Io(std::io::Error::other(format!(
            "the journal could not be read back from the store `{}`: {why}",
            lane.store()
        )))
    })?;

    let decoded = busbar_kernel_wal::decode_run(&resume)
        .and_then(|records| busbar_kernel_wal::verify_journal(&records).map(|()| records))
        .map_err(|broken| {
            OpenError::Io(std::io::Error::other(format!(
                "the journal does not verify: {broken}"
            )))
        })?;
    let heads = lane
        .initialize_heads(node, &decoded)
        .map_err(|why| OpenError::Io(std::io::Error::other(why)))?;
    let shipper = lane.shipper();
    build_inner(cfg, node, shipper, Some((lane, resume, heads)), cards)
}

fn build_inner(
    _cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper<busbar_kernel_wal::Record>>,
    over_store: Option<(
        JournalLane,
        Vec<busbar_kernel_wal::Record>,
        busbar_kernel_audit::HeadHistory,
    )>,
    cards: Option<&'static crate::root::kernel::RootHistory>,
) -> Result<Durability, OpenError> {
    let clock = busbar_kernel::store::now_ms;
    let (lane, resume, retained_heads) = over_store
        .map_or((None, None, None), |(lane, records, heads)| {
            (Some(lane), Some(records), Some(heads))
        });
    let resumed = resume.is_some();
    let journal = match &resume {
        Some(records) => {
            Journal::memory_resumed(node, records, shipper, clock)?.retaining_at_bound()
        }
        None => Journal::memory_buffered_to(node, shipper, clock),
    };

    let mut durability = Durability {
        journal,

        record: AuditChain::new().sealing_as(if resumed {
            node
        } else {
            busbar_kernel::door::node()
        }),
        audit_records: Vec::new(),
        audit_findings: Vec::new(),
        audit_signed_from: None,

        incarnation: 0,
        restart_findings: Vec::new(),
        voided_claims: Vec::new(),
        quarantined: Vec::new(),
        cards_from: None,
        amendments_through: None,
        lane,
        resumed,
    };

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
        metrics::counter!(busbar_kernel::snapshot::JOURNAL_QUARANTINED_TOTAL).increment(1);
    }

    let chain = match resume.filter(|_| resumed) {
        Some(records) => Ok(busbar_kernel_wal::decode_run(&records)
            .and_then(|decoded| busbar_kernel_wal::verify_journal(&decoded).map(|()| decoded))),
        None => durability.journal.replay(),
    };

    let records = match chain {
        Ok(Ok(records)) => records,
        Ok(Err(broken)) => {
            return Err(OpenError::Io(std::io::Error::other(format!(
                "the journal does not verify: {broken}"
            ))))
        }
        Err(e) => {
            return Err(OpenError::Io(std::io::Error::other(
                durability.unreadable(&e),
            )))
        }
    };
    let mut findings: Vec<String> = durability
        .quarantined
        .iter()
        .map(|q| format!("journal quarantine: {q}"))
        .collect();
    if let Some(cards) = cards {
        let records = durability.keeps_chain().then_some(records.as_slice());

        let refused = cards
            .rebuild_from_chain(&mut durability, records)
            .map_err(|refused| OpenError::Io(std::io::Error::other(refused.to_string())))?;

        findings.extend(refused.into_iter().map(|refused| refused.to_string()));
    }
    durability.resume_audit(&records);
    if let Some(heads) = retained_heads {
        durability.record = durability
            .record
            .retaining_heads(heads)
            .map_err(|why| OpenError::Io(std::io::Error::other(why)))?;
    }
    findings.extend(
        durability
            .audit_findings
            .iter()
            .map(|why| format!("audit chain: {why}")),
    );

    let (open, claimed) = open_claims(&records);
    let audited = durability
        .audit_records
        .iter()
        .map(|r| r.what.incarnation)
        .max()
        .unwrap_or(0);
    durability.incarnation = claimed.max(audited).saturating_add(1);

    durability.void_claims(open);
    findings.dedup();
    for finding in &findings {
        tracing::error!(finding = %finding, "the boot could not read back part of the journal");
    }
    durability.restart_findings = findings;
    Ok(durability)
}

#[cfg(test)]
pub(crate) use audit::tests::Scratch;

#[cfg(test)]
#[path = "../tests/durability.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/durability_boot_reads.rs"]
mod boot_reads;

#[cfg(all(test, feature = "root-admin"))]
#[path = "../tests/durability_reads_unlocked.rs"]
mod reads_unlocked;
