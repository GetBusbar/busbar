//! The other plugin kinds: auth, egress auth, store, secret, hook and export — one closed shape
//! per trait, transcribed from the plugin-kinds table of the design. See
//! `docs/design/contract-notes.md` for why four of the six reach outside the process on a bounded
//! blocking pool while the other two (hook, egress-auth scheme) are pure.
//!
//! Fallibility: every fallible method below returns its trait's own error enum; see the trait doc
//! for what a failure means, rather than repeating it per method.

use crate::bounded::{ArenaBytes, BoundedVec, Facts, IrPatch, MAX_KEYS, MAX_RECORD_BYTES};
use crate::dest::{
    AuthDecoration, CandidateSet, EgressBody, Permutation, VerifiedDestination, VetoCode,
};
use crate::grammar::ArrivalLocation;
use crate::ids::{LaneId, PrincipalId, RecordSchemaId, SchemeAlt, SessionId, StreamId};
use crate::plugin::Plugin;
use crate::unit::{Clock, ConfigView, Ctx, Step, Unit};
use crate::wire::{ArrivalRecord, Frame};
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

/// What an auth scheme establishes about a principal.
///
/// The session-bindable flag is what lets an authenticate-once protocol run over a transport that
/// does not itself bind: a completed first unit that sets it binds the session, and every later
/// unit on that session reads the cached principal instead of re-authenticating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialFacts {
    /// Who.
    pub principal: PrincipalId,
    /// Which issuer vouched for them.
    pub issuer: Option<String>,
    /// When the evidence stops being good, in seconds since the epoch.
    pub expiry: Option<u64>,
    /// Whether this evidence may be cached for the session.
    pub session_bindable: bool,
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

/// What an auth scheme answers with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Established: here is who.
    Facts(CredentialFacts),
    /// Not yet: deliver this and hand me the answer.
    Challenge(Challenge),
    /// I have no opinion on this credential; ask the next scheme in the chain.
    Pass,
}

/// Key material an auth scheme refreshes on the node's clock.
///
/// Its `Debug` prints how much material there is and when it was fetched — the two facts a stalled
/// refresh is diagnosed from — and never the material.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct KeyMaterial {
    /// The material, in whatever encoding the scheme uses.
    pub bytes: Vec<u8>,
    /// When it was fetched, in seconds since the epoch.
    pub fetched_at: u64,
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("len", &self.bytes.len())
            .field("fetched_at", &self.fetched_at)
            .finish()
    }
}

/// A credential as the kernel hands it to a scheme.
///
/// The kernel has already copied the span out of the read cursor and masked what remains, so the
/// bytes here are the credential and the wire no longer holds it.
/// Its `Debug` says where the credential arrived and how long it was, never what it was — the same
/// shape [`SecretValue`] uses, for the same reason. Every scheme across the ABI is handed one of
/// these, so the code that might format it is code this tree cannot read.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    /// Where it was found.
    pub location: ArrivalLocation,
    /// The bytes.
    pub bytes: Vec<u8>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("location", &self.location)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Turns an arriving credential into facts about a principal.
///
/// A scheme sees the credential and nothing else — no plane, no unit, no destination. Its own
/// secret, whether a stored verifier or a static key, reaches it through the secret plugin and
/// never through a plane.
pub trait AuthScheme: Plugin + Send + Sync + 'static {
    /// The arrival forms this scheme's credential can be found in.
    fn locations(&self) -> &'static [ArrivalLocation];

    /// Whether this scheme reaches outside the process, and so runs on the blocking pool under a
    /// deadline with an access entry per call.
    fn does_io(&self) -> bool;

    /// Judge a credential.
    ///
    /// Abstaining continues the chain; that is how a multi-scheme configuration composes without
    /// any scheme knowing the others exist.
    fn verify(
        &self,
        credential: &Credential,
        arrival: &ArrivalRecord,
        clock: Clock,
        prior: Option<&ChallengeState>,
    ) -> AuthOutcome;

    /// Refresh key material. Driven by the node's clock, never by a request.
    fn refresh(&self, clock: Clock) -> KeyMaterial;
}

// ── egress auth ──────────────────────────────────────────────────────────────────────────────

/// What signs on an egress-auth scheme's behalf.
///
/// The scheme asks for a signature; it never holds the key. Only the auth, egress-auth and
/// transport-key units can expose a secret, and this handle is the egress-auth unit's own.
pub trait Signer: Send + Sync {
    /// Sign these bytes with the named key. Errors when the key cannot be resolved or the
    /// signature cannot be made.
    fn sign(&self, key: &str, bytes: &[u8]) -> Result<Vec<u8>, SignFailed>;
}

/// A signature could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignFailed {
    /// The named key does not resolve.
    UnknownKey,
    /// The key resolved but the signature could not be made.
    Unavailable,
}

impl fmt::Display for SignFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SignFailed {}

/// Decorates an outbound request with an upstream's own scheme.
///
/// Pure: it computes a decoration and returns it. The egress-auth unit is what applies it, checks
/// the envelope still equals the verified destination, and re-runs the lane cross-check on the
/// decorated bytes.
pub trait EgressAuthScheme: Plugin + Send + Sync + 'static {
    /// Decorate a request.
    fn decorate<'u>(
        &self,
        cfg: &dyn ConfigView,
        body: &EgressBody<'u>,
        signer: &dyn Signer,
    ) -> AuthDecoration<'u>;

    /// Continue a multi-round exchange with the upstream's challenge.
    fn continue_handshake<'u>(
        &self,
        state: &ChallengeState,
        frame: &Frame,
        signer: &dyn Signer,
    ) -> AuthDecoration<'u>;
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

/// A reference to a secret, in the plugin's own reference grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef(pub String);

/// A resolved secret's bytes.
///
/// Only the auth, egress-auth and transport-key units can expose one. The canary check in the
/// gate greps for a resolved secret appearing anywhere else.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Wrap resolved bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Read the bytes.
    ///
    /// Named for what it is. The three units that may call it are named in the design; every other
    /// call site is a finding.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(redacted)")
    }
}

/// Something went wrong under the secret plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretError {
    /// The reference does not resolve.
    Unknown,
    /// The backing store could not be reached.
    Unavailable,
    /// The sealed bytes did not authenticate.
    NotAuthentic,
    /// The reference is not in this plugin's grammar.
    Malformed,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SecretError {}

/// Resolves, signs, seals and unseals key material.
///
/// Sealing is deterministic and misuse-resistant: the same plaintext under the same key and
/// context seals to the same bytes, which is what lets a replay cache be sealed at all.
///
/// # Errors
/// Every method returns [`SecretError`] on failure (unknown reference, unavailable backing
/// store, sealed bytes that fail to authenticate, or a reference outside this plugin's grammar).
pub trait Secret: Plugin + Send + Sync + 'static {
    /// The reference grammar this plugin accepts.
    fn ref_grammar(&self) -> &'static str;

    /// Resolve a reference.
    fn resolve(&self, r: &SecretRef) -> Result<SecretValue, SecretError>;

    /// Watch a reference for change. Returning nothing means the value does not change under this
    /// plugin. Every reference migrated from the previous release is inert here: it was resolved
    /// once at the site the old release resolved it, and re-resolving would be a behaviour change.
    fn watch(&self, r: &SecretRef) -> Result<Option<u64>, SecretError>;

    /// Sign bytes with a named key.
    fn sign(&self, key: &str, bytes: &[u8]) -> Result<Vec<u8>, SecretError>;

    /// Seal bytes under a key and a context.
    fn seal(&self, key: &str, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretError>;

    /// Unseal bytes under a key and a context. Fails if the bytes do not authenticate.
    fn unseal(&self, key: &str, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SecretError>;
}

// ── hook ─────────────────────────────────────────────────────────────────────────────────────

/// Where in the loop a hook observes.
///
/// Four seats, and each maps onto one of the previous release's four stages. The two that sit
/// after the admission step see the candidate set as it stands after the draw, which is why a
/// restriction to nothing there still consumes the request slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Seat {
    /// Before the step named.
    Before(Step),
    /// After the step named.
    After(Step),
}

/// What a hook is: an observer, or a gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum HookKindDecl {
    /// Facts only. It cannot change anything.
    Tap,
    /// It may veto, restrict, reorder or rewrite.
    Gate,
}

/// What happens to a unit when a hook itself fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum OnFailure {
    /// Refuse the unit. The default for a hook written against this contract.
    Closed,
    /// Carry on as if the hook had abstained. What a migrated hook keeps, so its deployment's
    /// behaviour does not change under it.
    Nothing,
}

/// What a hook can see.
///
/// Declared-key: a hook sees the keys it declared and nothing else, so adding a hook cannot widen
/// what leaves the process.
#[derive(Debug)]
pub struct HookView<'u, 'a> {
    /// Which seat this call is at.
    pub seat: Seat,
    /// The unit.
    pub unit: &'a Unit<'u>,
    /// The candidates as they stand at this seat.
    pub candidates: &'a [VerifiedDestination],
    /// The lane each candidate is priced on.
    pub lanes: &'a [Option<LaneId>],
    /// The facts the hook declared keys for.
    pub facts: Facts<'u>,
}

/// What a hook answers with.
///
/// Every field is optional and every one of them means "no opinion" when absent. At one seat the
/// hooks run against the same candidate set and their answers compose: restrictions intersect, the
/// first veto wins by chain position, the last non-absent order wins and is re-validated against
/// the restricted set, and a rewrite is applied by the kernel to the spooled body, never to bytes
/// already on the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookFacts<'u> {
    /// An order over the candidate set.
    pub permutation: Option<Permutation>,
    /// A narrowing of the candidate set.
    pub restrict: Option<CandidateSet>,
    /// A refusal.
    pub veto: Option<VetoCode>,
    /// Edits to the spooled body.
    pub rewrite: Option<IrPatch<'u>>,
    /// Facts to record, under this hook's own declared keys.
    pub tap: Facts<'u>,
}

/// Observes or gates a unit at one of the four seats.
///
/// Pure, and bounded by its own declarations: which seats it sits at, whether it may change the
/// selected destination, whether it may rewrite, and how much price movement its rewrite may
/// cause. A rewrite that would move the price further than declared is refused rather than
/// applied.
pub trait Hook: Plugin + Send + Sync + 'static {
    /// Whether this hook only observes, or may also gate.
    fn hook_kind(&self) -> HookKindDecl;

    /// The seats this hook sits at.
    fn seats(&self) -> &'static [Seat];

    /// The fact keys this hook produces.
    fn hook_facts(&self) -> &'static [&'static str];

    /// What happens to a unit when this hook itself fails.
    fn on_failure(&self) -> OnFailure;

    /// How much priced movement this hook's rewrites may cause, in nano-units.
    fn max_priced_delta(&self) -> u64;

    /// Whether this hook may change the selected destination.
    fn may_change_destination(&self) -> bool;

    /// Whether this hook may rewrite the body at all.
    ///
    /// Declaring this is what makes the body's end the deepest pointer, so the whole body is
    /// spooled before the unit opens and the gate always sees all of it.
    fn may_rewrite(&self) -> bool;

    /// Observe one unit at one seat.
    fn observe<'u, 'a>(&self, seat: Seat, view: &HookView<'u, 'a>) -> HookFacts<'u>;
}

// ── export ───────────────────────────────────────────────────────────────────────────────────

/// What an export sink is handed.
#[derive(Clone, Debug, PartialEq)]
pub enum ExportItem<'u> {
    /// One journal entry, as bytes.
    JournalEntry(RecordBytes),
    /// What a plane said a response contained.
    ///
    /// Boxed because a fact map is pre-sized to its key ceiling: carrying one inline would make
    /// every other variant of this enum as large as the largest.
    Content(Box<ContentFacts<'u>>),
    /// A retention segment: a contiguous run of the journal, sealed.
    Segment {
        /// Which stream.
        stream: &'u str,
        /// The first sequence in the run.
        from: u64,
        /// The last sequence in the run.
        to: u64,
        /// The sealed bytes.
        bytes: ArenaBytes<'u>,
    },
}

/// A sink's acknowledgement.
///
/// A sink written against this contract acknowledges at-least-once. The previous release's own
/// sink subsystem stays fire-and-forget with its admission gate, and it refuses a configuration
/// that asks it for durability rather than pretending to provide it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Ack {
    /// Received and durable at the sink.
    Durable,
    /// Received, not durable.
    Received,
    /// Not received; the kernel retries.
    Retry,
}

/// Ships journal entries, content facts and segments off the node.
pub trait Export: Plugin + Send + Sync + 'static {
    /// Take one item.
    fn receive<'u>(&self, item: ExportItem<'u>) -> Ack;
}

/// An export sink that can also anchor the journal's head somewhere outside the node.
///
/// Anchoring is what makes the chain checkable by someone who does not trust the node: the head is
/// written where the node cannot rewrite it, and read back to compare.
///
/// # Errors
/// Both methods return [`StoreError`] when the anchor cannot be written or read.
pub trait Anchor: Export {
    /// Write a head out.
    fn write_head(&self, head: Head) -> Result<(), StoreError>;

    /// Read one of the last heads back.
    fn read_head(&self, n: u32) -> Result<Option<Head>, StoreError>;
}

// ── the shapes the loop passes around that no one kind owns ───────────────────────────────────

/// One stream's worth of what a plane relayed, for the metering step's kernel-derived floor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct KernelCounts {
    /// Bytes the kernel relayed inbound.
    pub bytes_in: u64,
    /// Bytes the kernel relayed outbound.
    pub bytes_out: u64,
    /// Frames the kernel relayed inbound.
    pub frames_in: u32,
    /// Frames the kernel relayed outbound.
    pub frames_out: u32,
    /// Monotonic nanoseconds the unit was open.
    pub elapsed_nanos: u128,
}

/// The facts a hook or a plane may attach to one stream of a session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamFacts<'u> {
    /// Which stream.
    pub stream: Option<StreamId>,
    /// The facts.
    pub facts: Facts<'u>,
}

/// A bounded list of envelope fields, for the kinds that build one.
pub type EnvelopeFields<'u> = BoundedVec<crate::wire::EnvelopeField<'u>, MAX_KEYS>;

/// Everything the kernel hands a plugin call that is not the call's own arguments.
///
/// Re-exported here so a plugin crate can name the context without reaching for the module it
/// lives in.
pub type CallCtx<'u> = Ctx<'u>;
