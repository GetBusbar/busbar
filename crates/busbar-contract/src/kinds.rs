//! The shapes the plugin kinds share outside `abi/`: a plane's fact and credential-locator
//! answers, the auth kind's challenge round, the store kind's journal trait and its record shapes,
//! an export sink's acknowledgement, and the envelope-field bound.
//!
//! Fallibility: every fallible store method returns [`StoreError`]; see the trait doc for what a
//! failure means, rather than repeating it per method.

use crate::bounded::{BoundedVec, Facts, MAX_KEYS, MAX_RECORD_BYTES};
use crate::ids::{PrincipalId, RecordSchemaId, SchemeAlt, SessionId};
use crate::plugin::Plugin;
use core::fmt;

// ── shared fact shapes ───────────────────────────────────────────────────────────────────────

/// What a plane answers a read-only introspection verb with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlaneFacts<'u> {
    /// The facts, under this plane's own declared keys.
    pub facts: Facts<'u>,
}

/// What a plane says a response contained.
///
/// Content facts are evidence for the record and the export path. A minted secret's placeholder
/// never appears here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContentFacts<'u> {
    /// The facts, under this plane's own declared keys.
    pub facts: Facts<'u>,
}

// ── auth ─────────────────────────────────────────────────────────────────────────────────────

/// Where a plane says this unit's credential is, and how it narrows the claim's scheme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct CredentialLocator {
    /// The alternative the plane narrows to, within the claim's declared set.
    pub narrowing: Option<SchemeAlt>,
    /// Whether the credential is the session's cached one rather than one on this unit's bytes.
    pub from_session: bool,
}

/// The opaque state one round of a challenge-response exchange hands to the next.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChallengeState(pub Vec<u8>);

/// A challenge an auth scheme wants delivered to the client.
///
/// The proof of round n arrives carrying the state of round n minus one, which is what lets the
/// scheme stay stateless across rounds. Rounds and bytes are both bounded by configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The bytes to deliver.
    pub bytes: Vec<u8>,
    /// The state the next round's proof will carry back.
    pub state: ChallengeState,
    /// How many rounds remain before the exchange is refused.
    pub rounds_left: u8,
}

// ── store ────────────────────────────────────────────────────────────────────────────────────

/// One fixed-size record's bytes.
///
/// The size ceiling is the design's, and it is a ceiling on the *record*, not on the batch: a
/// journal of fixed-size records is a journal whose replay cost is arithmetic rather than a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordBytes {
    bytes: Vec<u8>,
}

impl RecordBytes {
    /// Take bytes as a record.
    ///
    /// # Errors
    /// Returns the length back when the bytes exceed the record ceiling.
    pub fn new(bytes: Vec<u8>) -> Result<Self, usize> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(bytes.len());
        }
        Ok(Self { bytes })
    }

    /// The bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Where one stream of the journal has reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Head {
    /// The stream's sequence number.
    pub seq: u64,
    /// The epoch that sequence belongs to.
    pub epoch: u64,
}

/// A per-node slice of a bucket window, drawn from the store and fenced by epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SliceGrant {
    /// How much of the window this node may spend.
    pub amount: u64,
    /// The epoch that fences it.
    pub epoch: u64,
}

/// Something went wrong under the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The backend could not be reached.
    Unavailable,
    /// The call did not return within its deadline.
    Timeout,
    /// The write lost a fencing race and this node's epoch is stale.
    Fenced,
    /// A gap was detected between what was written and what read back.
    Gap,
    /// The backend rejected the value.
    Rejected(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StoreError {}

/// The durable store behind the journal.
///
/// Every method here runs on a bounded blocking pool under a per-kind deadline, and a call that
/// overruns ends its unit rather than blocking the loop. The interface generation a store declares
/// decides how it loads: a store built against an older generation loads through an in-tree
/// adapter rather than being refused, so a configuration written for the previous release boots
/// unchanged.
///
/// # Errors
/// Every method returns [`StoreError`] on failure (unavailable, timeout, a fencing race, a gap
/// between what was written and what read back, or an outright rejection); see the enum for what
/// each variant means. A method's own doc only adds words when its failure mode is distinctive.
pub trait Store: Plugin + Send + Sync + 'static {
    /// Append a batch of journal records.
    fn append_batch(&self, stream: &str, records: &[RecordBytes]) -> Result<Head, StoreError>;

    /// Read a batch of journal records back.
    fn replay_batch(
        &self,
        stream: &str,
        from: u64,
        limit: u32,
    ) -> Result<Vec<RecordBytes>, StoreError>;

    /// Draw this node's slice of a bucket window. Fails if this node's epoch is fenced out.
    fn reserve(&self, bucket: &str, amount: u64, epoch: u64) -> Result<SliceGrant, StoreError>;

    /// Hand an undrawn slice back.
    fn release(&self, bucket: &str, grant: SliceGrant) -> Result<(), StoreError>;

    /// Where each stream has reached.
    fn heads(&self) -> Result<Vec<(String, Head)>, StoreError>;

    /// Say this node is alive at this epoch. Fails if this node has been fenced out.
    fn heartbeat(&self, node: &str, epoch: u64) -> Result<(), StoreError>;

    /// Elect which node writes the next checkpoint.
    fn elect_checkpoint(&self, node: &str, epoch: u64) -> Result<bool, StoreError>;

    /// Claim an idempotency key for this unit.
    fn claim_key(&self, namespace: &str, key: &[u8], unit: u64) -> Result<bool, StoreError>;

    /// Drop the claims a failed unit made.
    fn void_claims(&self, namespace: &str, unit: u64) -> Result<(), StoreError>;

    /// Seal a replayable answer under its key.
    fn replay_put(&self, namespace: &str, key: &[u8], value: &[u8]) -> Result<(), StoreError>;

    /// Read a sealed replayable answer back.
    fn replay_get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;

    /// Register a live session in the fleet directory.
    fn session_put(
        &self,
        session: SessionId,
        node: &str,
        principal: &PrincipalId,
    ) -> Result<(), StoreError>;

    /// Drop a session from the directory, at close or at lease expiry.
    fn session_remove(&self, session: SessionId) -> Result<(), StoreError>;

    /// Which sessions a principal holds across the fleet.
    fn sessions_for(&self, principal: &PrincipalId)
        -> Result<Vec<(SessionId, String)>, StoreError>;

    /// Write one of a plane's kernel-held durable records.
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError>;

    /// Read one of a plane's kernel-held durable records.
    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError>;

    /// Walk a plane's records under a prefix.
    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError>;

    /// Read the previous release's own cells, for a migrating deployment.
    fn legacy_cells_read(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;

    /// Write the previous release's own cells, for a migrating deployment.
    fn legacy_cells_write(&self, key: &str, value: &[u8]) -> Result<(), StoreError>;

    /// Where the previous release's audit stream had reached.
    fn legacy_audit_head(&self) -> Result<Option<Head>, StoreError>;

    /// How far a backup has captured.
    fn backup_watermark(&self) -> Result<Option<Head>, StoreError>;

    /// Drop everything older than a sequence, under the retention the operator set.
    fn purge_before(&self, stream: &str, seq: u64) -> Result<u64, StoreError>;
}

// ── secret ───────────────────────────────────────────────────────────────────────────────────

/// A reference to a secret: `{ module, settings }`, where `settings` is the resolving plugin's own
/// reference grammar. There is ONE `SecretRef` (DECISIONS #83 merge, fold F1): the config reference
/// type defined in [`crate::secret_ref`], re-exported here under the kind ABI's spelling.
pub use crate::secret_ref::SecretRef;

// ── export ───────────────────────────────────────────────────────────────────────────────────

/// A sink's acknowledgement.
///
/// A sink written against this contract acknowledges at-least-once. The previous release's own
/// sink subsystem stays fire-and-forget with its admission gate, and it refuses a configuration
/// that asks it for durability rather than pretending to provide it.
///
/// Derives `Deserialize` as well as `Serialize`, and pins `snake_case` wire tokens (`durable` /
/// `received` / `retry`) — OWNER-RULED 2026-09-21: no consumer outside this crate names `Ack` yet
/// (verified by a repo-wide grep), so this is the cheapest moment this ever moves. See
/// `tests/ack_wire.rs` for the pinned wire form and round-trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ack {
    /// Received and durable at the sink.
    Durable,
    /// Received, not durable.
    Received,
    /// Not received; the kernel retries.
    Retry,
}

// ── the shapes the loop passes around that no one kind owns ───────────────────────────────────

/// A bounded list of envelope fields: the one spelling of the bound, for every shape that carries
/// one.
pub type EnvelopeFields<'u> = BoundedVec<crate::wire::EnvelopeField<'u>, MAX_KEYS>;
