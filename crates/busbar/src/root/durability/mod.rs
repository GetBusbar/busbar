// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The node's journal and the audit unit's record chain — and the one `if` that decides whether
//! this node writes to a disk.
//!
//! ## What the journal carries, and what it does not
//!
//! The journal unit owns the chain: fixed records, one numbering, one head. The records bound to it
//! here are the **audit unit's sealed records**, the **node amendment journal** (content accesses),
//! the **dated rate-card history** (`Policy` records, until the card history moves to the store),
//! the operator's chain breaks and the admin idempotency claims.
//!
//! It carries NO MONEY. Money is the ledger's counts — the usage and metering rows in the
//! configured store — priced by the rate card, in core, at read time (MONEY-DESIGN §3). There is no
//! second ledger here: no holds, no postings, no unit marks, no checkpoints and no book rebuilt at
//! boot, so a unit's settlement never takes this journal's lock (owner ruling 2026-10-25: no
//! process-wide lock around `fsync`). A chain a pre-release build wrote may still hold such
//! records; they verify as chain links and are read as nothing else.
//!
//! ## The branch, and why it is the only place the data directory is read
//!
//! A deployment that configures no data directory needs none: without one the journal is
//! memory-buffered and its records are kept by the configured store. The journal unit states the
//! rule as a type: *constructing an on-disk log IS the decision to write to a disk*. So there is
//! exactly one branch, it is here, and it is the only place on this path that reads the configured
//! directory. Nothing downstream may probe, resolve a keyset path speculatively, or open anything
//! "just in case".
//!
//! ## Where the records go, and how a restart gets them back
//!
//! The production boot builds the journal over the configured store ([`build_on_store`]). Each
//! record is written through the store's v3 `record_put` slot under the journal schema, keyed
//! `(node, node_seq)` big-endian so `record_scan` returns chain order ([`store_chain`]). The write
//! is WRITE-BEHIND on the host's one bounded lane ([`JournalLane`]). With no data directory the boot
//! RESUMES the chain from the store: the audit records, the dated rate-card history and the
//! amendment journal are rebuilt from it ([`Durability::keeps_chain`]).
//!
//! **What a full lane means.** While the lane has room a store that refuses costs nothing a client
//! sees. When it is full the journal's next batch is retained by the log, which re-offers it on the
//! next append, and the node FAILS CLOSED for the records still on the journal
//! ([`Durability::refuses_money`]) until the store takes what waits. No record is dropped.
//!
//! A configured store that does not offer the record slots at all cannot keep a journal, and the
//! boot refuses it, naming the store and the slots (`root::boot::book`).

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


/// The journal kept in the configured store: its schema and keys, the boot's read-back and the
/// host's write-behind lane. A private child module; its public items are re-exported here.
mod store_chain;
pub use store_chain::{read_chain, JournalLane, RECORD_SLOTS};
pub(crate) use store_chain::off_runtime;
// Its one caller is the admin append's wait on the store (`units_admin`), compiled with `root-admin`.
#[cfg(feature = "root-admin")]
pub use store_chain::ACK_DEADLINE;
// What the tests read the store's rows back by.
#[cfg(test)]
pub use store_chain::{part_key, JOURNAL_SCHEMA};

/// Who a node is and the key it signs with, kept in the configured store: the node registry, the
/// deployment keyset, and the walk `/admin/verify` makes of every stored chain.
mod store_identity;
pub use store_identity::{host_identity, keep_keyset, persisted_node, stored_keyset, take_node};
// The host registry's own id, read by the boot through `take_node`; the tests reach it directly.
#[cfg(test)]
pub use store_identity::node_id;
// Its callers are the admin verify (`units_admin`, `root-admin`) and the tests.
#[cfg(any(test, feature = "root-admin"))]
pub use store_identity::walk_stored_chains;

/// The node amendment journal bound to the chain: each sealed amendment journalled, and the node
/// journal rebuilt from the chain at boot. A private child module, as `replay` is.
mod amend;
// Re-exported for its one production caller, `main`'s boot-book open, which a build runs only when a
// root leg opens the book; the unit tests reach it through `amend` directly.
pub use amend::bind_amendments;
// Its one caller is the admin verify (`units_admin`), compiled with `root-admin`.
#[cfg(feature = "root-admin")]
pub(crate) use amend::verify_held;

/// The fixed audit chain's seams on the book: sealing a unit's one record, the cache rebuilt at boot,
/// a window read back off the journal, and the walk `GET /admin/verify` reports. A private child
/// module, as `replay` is; its methods are `Durability`'s own.
mod audit;
// Its one caller is the admin unit's audit range read (`units_admin`), compiled with `root-admin`.
#[cfg(feature = "root-admin")]
pub use audit::AuditWindowAt;

/// The three disaster-recovery verbs over the node's journal and the configured store (status row
/// 187): the operator's chain break on the chain, the epoch floor in the store, the restore refused.
/// A private child module, as `replay` is; its public items are re-exported here.
mod recovery;
pub use recovery::{boot_recovery, node_verb_store};

/// The first-party anti-downgrade floor the store keeps per host.
mod plugin_floor;
pub use plugin_floor::hold as hold_plugin_floor;

/// How many sealed audit records a node keeps in memory: a CACHE of the newest, never the record.
/// The journal holds every one (`audit.v4`), and a window older than this is read back off it.
pub const AUDIT_RING: usize = 1_024;

/// What the root reads out of configuration to decide the durability shape.
///
/// One field, because there is one decision. Its absence is the previous release's shape and its
/// presence is a deliberate statement that this node keeps its own journal.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DurabilityConfig {
    /// The configured data directory, if the operator named one.
    pub data_dir: Option<PathBuf>,
}

/// The durability stack the root owns: the journal and the audit record chain.
pub struct Durability {
    /// The one journal. On disk only where a data directory was configured; otherwise
    /// memory-buffered, its records kept by the configured store through [`Durability::lane`].
    pub journal: Journal,
    /// The new fixed record's chain.
    pub record: AuditChain,
    /// THE NEWEST SEALED AUDIT RECORDS, oldest first, at most [`AUDIT_RING`]: a cache over the
    /// journal, which keeps every record this chain ever sealed. Rebuilt from the journal at boot.
    pub audit_records: Vec<AuditRecord>,
    /// What the boot could not read back of the audit chain: a journalled record that does not
    /// decode, or names a class nobody declares here. Each is a restart finding.
    pub audit_findings: Vec<String>,
    /// THE FIRST AUDIT POSITION SEALED WHILE A KEY WAS BOUND: from here on every record must carry
    /// a signature, and an unsigned one is a `/verify` finding. `None` while no record was sealed
    /// under a key.
    pub audit_signed_from: Option<u64>,
    /// WHICH BOOT OF THIS JOURNAL this process is: one more than the highest any record on the
    /// chain was written under, and 1 on a chain that holds none. Every audit record and claim
    /// carries the incarnation that wrote it.
    pub incarnation: u64,
    /// What the boot found it could not read back or verify: a quarantined segment, an audit record
    /// that does not decode, an amendment that does not link, a refused rate correction. Empty is
    /// the only good answer.
    pub restart_findings: Vec<String>,
    /// The idempotency claims a predecessor took, VOIDED at this boot so a client's retry is not
    /// answered with a unit that never ran. Oldest first.
    pub voided_claims: Vec<String>,
    /// WHAT BOOT RECOVERY SET ASIDE from a corrupt journal segment: each entry names the segment
    /// file, the byte offset, the byte count and the quarantine file the damaged remainder went to.
    /// Logged at `ERROR` and counted on `busbar_journal_quarantined_total` when the journal is
    /// built; put on the chain as a `ChainBreak` record by [`Durability::journal_quarantines`].
    pub quarantined: Vec<busbar_kernel_wal::Quarantine>,
    /// THE HOLDER WHOSE DATED HISTORY THIS JOURNAL REBUILT FROM ITS CHAIN at boot (#79), and so the
    /// one whose later applies it journals ([`crate::root::kernel::RootHistory::bind_journal`]).
    pub(crate) cards_from: Option<&'static crate::root::kernel::RootHistory>,
    /// THE POSITION OF THE NEWEST AMENDMENT this journal rebuilt the node amendment journal from
    /// ([`Durability::restore_amendments`]), and so the journal whose later amendments are
    /// journalled ([`bind_amendments`]). `None` on every journal that rebuilt nothing.
    amendments_through: Option<u64>,
    /// THE HOST'S LANE TO THE CONFIGURED STORE the journal ships through, on a journal built over
    /// one ([`build_on_store`]). `None` on a journal built over a bare shipper.
    lane: Option<JournalLane>,
    /// The memory-buffered journal was RESUMED from the chain the configured store kept, so the
    /// chain has a durable source as a disk would be one.
    resumed: bool,
}

/// [`Durability::chain`] over a borrowed journal and the lane its chain is kept through, if any.
fn chain_of(
    journal: &Journal,
    store_kept: Option<&JournalLane>,
) -> std::io::Result<Result<Vec<JournalRecord>, busbar_kernel_wal::JournalBreak>> {
    match store_kept {
        Some(lane) => store_chain::whole_chain(journal, lane),
        None => journal.replay(),
    }
}

/// What a read of the whole chain answers: the records oldest first, or why it could not be read.
pub type ChainRead = std::io::Result<Result<Vec<JournalRecord>, busbar_kernel_wal::JournalBreak>>;

/// THE CHAIN AS OF ONE HOLD OF THE BOOK'S LOCK, to be read after letting go of it
/// ([`Durability::chain_at`]). On a journal resumed from the store, reading the whole chain scans
/// the store through its plugin, a wait per block of the chain; the book's lock is the one every
/// unit's open, settle and seal takes on the request path, so a read off the request path takes
/// this under the lock and reads it without (THE DESIGN §11.2: no blocking on the hot path).
pub struct ChainAt(ChainSource);

/// Where a [`ChainAt`] reads from.
enum ChainSource {
    /// Already read, under the lock: a disk, or a journal with no store behind it, reads no plugin.
    Read(ChainRead),
    /// What the node holds of a chain the store keeps; the store is read by [`ChainAt::read`].
    Stored(store_chain::HeldChain),
}

impl ChainAt {
    /// The chain as of the hold it was taken under: [`Durability::chain`]'s answer for that moment.
    ///
    /// # Errors
    ///
    /// The chain could not be read back.
    pub fn read(self) -> ChainRead {
        match self.0 {
            ChainSource::Read(read) => read,
            ChainSource::Stored(held) => held.read(),
        }
    }

    /// The configured store the chain is read from, on a journal resumed from one.
    fn store(&self) -> Option<&str> {
        match &self.0 {
            ChainSource::Read(_) => None,
            ChainSource::Stored(held) => Some(held.store()),
        }
    }
}

/// WHY A CHAIN READ FAILED, as [`Durability::unreadable`] says it, for a chain kept in `store`.
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
    /// Whether this node writes its journal to a disk.
    #[must_use]
    pub fn on_disk(&self) -> bool {
        matches!(self.journal.mode(), Mode::OnDisk)
    }

    /// WHETHER THE CHAIN HAS A DURABLE SOURCE: on a disk, or resumed from the configured store. The
    /// chain-rebuilt state — the dated history, the amendment journal, an audit window older than
    /// the cache — is rebuilt from it then, and only then.
    #[must_use]
    pub fn keeps_chain(&self) -> bool {
        self.on_disk() || self.resumed
    }

    /// THE WHOLE CHAIN, read back oldest first and verified: every chain read after boot goes
    /// through here. On a disk, and on a journal with no store behind it, that is the log's own
    /// replay. On a journal RESUMED from the configured store it is the store's chain joined to
    /// what the node has not handed it yet ([`store_chain::whole_chain`]): the memory log keeps
    /// only its newest segment resident, so its own replay is a suffix once the chain outgrows one.
    ///
    /// # Errors
    ///
    /// The chain could not be read back.
    pub fn chain(&self) -> ChainRead {
        self.chain_at().read()
    }

    /// [`Durability::chain`] in two halves: what the node holds of the chain, taken here under the
    /// book's lock, and the store read by [`ChainAt::read`] once the lock is let go. A read off the
    /// request path takes this rather than the whole chain, so no unit waits on the store plugin
    /// for it (THE DESIGN §11.2).
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

    /// The lane the chain is kept through, on a journal resumed from the store.
    fn store_kept(&self) -> Option<&JournalLane> {
        self.lane.as_ref().filter(|_| self.resumed)
    }

    /// WHY A CHAIN READ FAILED, in the words the boot refuses with: the same refusal
    /// [`build_on_store`] gives a store that would not read the chain back the first time. A boot
    /// step that reads the chain again never takes a failed read for an empty chain.
    pub(crate) fn unreadable(&self, e: &std::io::Error) -> String {
        unreadable_in(self.store_kept().map(JournalLane::store), e)
    }

    /// The host's lane to the configured store, on a book built over one.
    #[must_use]
    pub fn lane(&self) -> Option<&JournalLane> {
        self.lane.as_ref()
    }

    /// What `/admin/verify` needs to walk every chain the store keeps, taken under the book's lock
    /// so the walk itself runs without it: the lane to the store, this node's id and the keys this
    /// node signs with. `None` on a book with no store behind it.
    #[must_use]
    pub fn stored_walk_inputs(
        &self,
    ) -> Option<(JournalLane, u64, busbar_kernel_audit::AuditKeySet)> {
        let lane = self.lane.as_ref()?;
        Some((
            lane.clone(),
            self.journal.node(),
            keyset_of(&self.record),
        ))
    }

    /// Whether the store is where this journal's durability is: no disk, and a lane to the store.
    /// A durable verb then answers only once the store acknowledged its record.
    #[must_use]
    pub fn durable_in_store(&self) -> bool {
        !self.on_disk() && self.lane.is_some()
    }

    /// WHY A NEW MONEY-BEARING UNIT IS REFUSED (ARCHITECT 2026-10-07 H3 ruling): the store is where
    /// this journal is kept and the lane to it is full, so admitting more work would grow what the
    /// node holds for the store without bound. `None` otherwise — always on a disk, where the store
    /// is catch-up work.
    #[must_use]
    pub fn refuses_money(&self) -> Option<String> {
        if self.on_disk() {
            return None;
        }
        self.lane.as_ref().and_then(JournalLane::refuses_money)
    }

    /// RE-OFFER WHAT THE JOURNAL HOLDS BACK FROM THE STORE, and answer how many records it still
    /// holds back. A batch the full lane turned away waits in the journal, outside the lane, until
    /// an append re-offers it; an append of nothing does that and seals nothing. Never calls the
    /// store: the lane takes the batch or turns it away. 0 at once on a book whose durability is not
    /// its store, and on one that holds nothing back.
    pub fn offer_held_back(&mut self) -> usize {
        if !self.durable_in_store() || self.journal.buffered() == 0 {
            return 0;
        }
        let token = busbar_kernel::teller::Kernel::new().durability_token();
        // Turned away again, the batch stays retained; the count below says so.
        let _ = self.journal.append(&token, StepName::Meter, &[]);
        self.journal.buffered()
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

    /// RECORD AN IDEMPOTENCY CLAIM, before the unit behind it runs. A boot voids every claim a
    /// predecessor took ([`Durability::voided_claims`]): no unit's state outlives its process here.
    ///
    /// # Errors
    ///
    /// The journal could not make the record durable; it is retained and re-offered by the log.
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

    /// VOID every idempotency claim a predecessor took and nobody voided. The void is a record of
    /// its own on the chain, so no later boot voids it again and a reader can see it happened.
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
            // A durability loss is retained and re-offered like any other append; the claim is
            // void in this process either way, and a boot that finds no void record voids it again.
            let _ = self.journal.append(&token, StepName::Admit, &[entry]);
            self.voided_claims.push(record.taken.claim);
        }
    }
}

/// The public half of the key this chain signs with, as a set — empty when the chain was given
/// none, because a set must never carry a key the node does not sign with.
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

/// The record tag of a claim taken.
const CLAIM_TAKEN: &str = "claim.taken";
/// The record tag of a claim voided at boot.
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

/// The claims a chain holds that nobody voided, in chain order, and the highest incarnation any
/// claim names.
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

/// The journal body of a sealed audit record: the whole record, `audit.v4`
/// ([`journal_body`]), so the journal can answer for it after the cache has let
/// it go. Content is not in it for the same reason it is not in the record: the journal is a
/// financial record exempt from erasure, so anything put in it can never be taken out.
#[must_use]
pub fn audit_body(record: &AuditRecord) -> Vec<u8> {
    journal_body(record)
}

/// The journal entry a sealed audit record goes on the chain as: its whole body, stamped with its
/// own two clocks and the epochs it ran under.
fn audit_entry(record: &AuditRecord) -> Entry {
    Entry::new(RecordClass::Transaction, audit_body(record))
        .at(record.wall, record.mono)
        .under(record.controls.lease_epoch, record.controls.policy_epoch)
}

/// Read one journal record back as the sealed audit record it keeps, if it keeps one. A usage
/// line's class resolves against the registered vocabulary; one that does not is an error.
///
/// # Errors
///
/// The record is an `audit.v4` body that does not decode, or names a class nobody declares here.
pub fn decode_audit(record: &JournalRecord) -> Result<Option<AuditRecord>, String> {
    if record.class != RecordClass::Transaction {
        return Ok(None);
    }
    from_journal_body(&record.body, &busbar_kernel::Registration::meter_class)
}


/// THE NODE'S ONE JOURNAL, and the disaster-recovery verbs' store that goes with it.
pub struct NodeBook {
    /// The journal and the audit record chain, behind the one lock the audit seal and the views
    /// take. A unit's settlement never takes it.
    pub durability: std::sync::Arc<std::sync::Mutex<Durability>>,
    /// The disaster-recovery verbs' store, as the admin verbs unit reaches it ([`node_verb_store`]):
    /// this journal for the chain break and the store it is shipped to for the epoch floor (row
    /// 187). `None` on a node with no configured store (row 113, ruling (B)).
    pub verb_store: crate::root::kernel::VerbStoreHandle,
}

/// A journal with no store behind it: memory-buffered over the null shipper, reading no data
/// directory, keeping its chain for the life of the process and no longer. The boot never builds
/// one — a 1.6.0 configuration names its store (Q-STORE = (B)) — so this is for a caller with no
/// store to ship to by construction: a tool, a test.
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

/// Build the journal and the audit record chain, as node zero.
///
/// # Errors
///
/// As [`build_for_node`].
pub fn build(
    cfg: &DurabilityConfig,
    shipper: Box<dyn Shipper<busbar_kernel_wal::Record>>,
) -> Result<Durability, OpenError> {
    build_for_node(cfg, 0, shipper)
}

/// Build the journal and the audit record chain.
///
/// The whole decision is the first `match`. Everything after it is the same on both branches: a
/// node without a data directory is not running a reduced stack, it is running the same stack over
/// a journal that keeps its records in memory and ships them to the store.
///
/// `node` is the identity the journal's records carry: half of the pair the log deduplicates on.
///
/// # Errors
///
/// A configured data directory could not be opened, or the journal already there could not be read
/// or does not verify.
pub fn build_for_node(
    cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper<busbar_kernel_wal::Record>>,
) -> Result<Durability, OpenError> {
    build_with_cards(cfg, node, shipper, Some(&crate::root::kernel::ROOT_CARD))
}

/// [`build_for_node`], naming the holder whose DATED HISTORY the journal rebuilds from its chain
/// (#79). The production boot names the process holder; a holder that was not armed
/// ([`crate::root::kernel::RootHistory::arm_journal`]) is left as it is.
///
/// # Errors
///
/// As [`build_for_node`].
pub fn build_with_cards(
    cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper<busbar_kernel_wal::Record>>,
    cards: Option<&'static crate::root::kernel::RootHistory>,
) -> Result<Durability, OpenError> {
    build_inner(cfg, node, shipper, None, cards)
}

/// THE JOURNAL OVER THE CONFIGURED STORE — the production boot's: the journal ships through `lane`
/// to the store's record slots, and with no data directory it RESUMES from the chain the store kept
/// ([`read_chain`]), keeping every record at its bound. With a data directory the disk is the
/// record and the store is catch-up work, read nothing back from.
///
/// # Errors
///
/// As [`build_for_node`], and: the store would not read its journal back, or the chain it holds
/// could not be seeded.
pub fn build_on_store(
    cfg: &DurabilityConfig,
    node: u64,
    lane: JournalLane,
    cards: Option<&'static crate::root::kernel::RootHistory>,
) -> Result<Durability, OpenError> {
    let resume = match cfg.data_dir {
        Some(_) => None,
        None => Some(read_chain(lane.calls().as_ref(), node).map_err(|why| {
            OpenError::Io(std::io::Error::other(format!(
                "the journal could not be read back from the store `{}`: {why}",
                lane.store()
            )))
        })?),
    };
    let shipper = lane.shipper();
    build_inner(
        cfg,
        node,
        shipper,
        Some((lane, resume.unwrap_or_default())),
        cards,
    )
}

/// The one construction every builder above shares. `over_store` is `Some` on a journal over the
/// configured store: the lane to it, and with no data directory the records the journal is seeded
/// with (the chain the store kept, possibly none).
fn build_inner(
    cfg: &DurabilityConfig,
    node: u64,
    shipper: Box<dyn Shipper<busbar_kernel_wal::Record>>,
    over_store: Option<(JournalLane, Vec<busbar_kernel_wal::Record>)>,
    cards: Option<&'static crate::root::kernel::RootHistory>,
) -> Result<Durability, OpenError> {
    // The journal is handed the root's wall clock: the log unit reads none of its own.
    let clock = busbar_kernel::store::now_ms;
    let (lane, resume) =
        over_store.map_or((None, None), |(lane, records)| (Some(lane), Some(records)));
    let resumed = cfg.data_dir.is_none() && resume.is_some();
    let journal = match (cfg.data_dir.as_deref(), &resume) {
        // No disk, and the store is where the chain is kept: resume it.
        (None, Some(records)) => {
            Journal::memory_resumed(node, records, shipper, clock)?.retaining_at_bound()
        }
        // No disk and no store behind the shipper: the chain lives as long as the process.
        (None, None) => Journal::memory_buffered_to(node, shipper, clock),
        // The operator asked for a journal on this node's own disk. This call is that decision.
        (Some(dir), Some(_)) => Journal::in_directory_adopting(node, dir, shipper, clock)?,
        (Some(dir), None) => Journal::in_directory(node, dir, shipper, clock)?,
    };

    let mut durability = Durability {
        journal,
        // Every record this chain seals names this node. On a chain the store keeps, that is the
        // id the store assigned this host; otherwise it is the node half of every op id the kernel
        // mints in this process.
        record: AuditChain::new().sealing_as(if resumed {
            node
        } else {
            busbar_kernel::door::node()
        }),
        audit_records: Vec::new(),
        audit_findings: Vec::new(),
        audit_signed_from: None,
        // Set from the chain below, before anything can write under it.
        incarnation: 0,
        restart_findings: Vec::new(),
        voided_claims: Vec::new(),
        quarantined: Vec::new(),
        cards_from: None,
        amendments_through: None,
        lane,
        resumed,
    };

    // A CORRUPT JOURNAL DOES NOT STOP THE BOOT, AND IT IS NEVER SILENT. The log kept every record
    // before the damage and copied the damaged remainder into a quarantine file; the alarm is here.
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

    // A RESUMED chain is read from what the store returned rather than off the seeded buffer: the
    // buffer keeps its newest memory segment resident, the store keeps all of it.
    let chain = match resume.filter(|_| resumed) {
        Some(records) => Ok(busbar_kernel_wal::decode_run(&records)
            .and_then(|decoded| busbar_kernel_wal::verify_journal(&decoded).map(|()| decoded))),
        None => durability.journal.replay(),
    };
    // A CHAIN THE BOOT CANNOT VERIFY REFUSES THE BOOT, naming the break, as a store that would not
    // read it back does ([`build_on_store`]). Taken for an empty chain, the boot would go on sealing
    // onto it from position one again.
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
        // A boot card the journal will not take refuses the boot (MONEY-AUDIT D-6).
        let refused = cards
            .rebuild_from_chain(&mut durability, records)
            .map_err(|lost| {
                OpenError::Io(std::io::Error::other(format!(
                    "the journal could not make the boot's rate card durable at step {}",
                    lost.step().as_str()
                )))
            })?;
        // A signed rate correction the dated history's rebuild refused: its base is not on the
        // rebuilt history, so it is reported rather than rebuilt over a card nobody signed (#79).
        findings.extend(
            refused
                .into_iter()
                .map(|refused| refused.to_string()),
        );
    }
    durability.resume_audit(&records);
    findings.extend(
        durability
            .audit_findings
            .iter()
            .map(|why| format!("audit chain: {why}")),
    );
    // THE INCARNATION: one past the highest any record names. A sealed audit record and a claim
    // each name the boot that wrote them.
    let (open, claimed) = open_claims(&records);
    let audited = durability
        .audit_records
        .iter()
        .map(|r| r.what.incarnation)
        .max()
        .unwrap_or(0);
    durability.incarnation = claimed.max(audited).saturating_add(1);
    // EVERY IDEMPOTENCY CLAIM A PREDECESSOR TOOK IS VOIDED, so a client's retry is answered by
    // running the unit rather than by a unit that never ran here.
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
