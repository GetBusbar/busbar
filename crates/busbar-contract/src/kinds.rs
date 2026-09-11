//! The other plugin kinds: auth, egress auth, store, secret, hook and export — one closed shape
//! per trait, transcribed from the plugin-kinds table of the design. See
//! `docs/design/contract-notes.md` for why four of the six reach outside the process on a bounded
//! blocking pool while the other two (hook, egress-auth scheme) are pure.
//!
//! Fallibility: every fallible method below returns its trait's own error enum; see the trait doc
//! for what a failure means, rather than repeating it per method.

use crate::bounded::{BoundedVec, Facts, IrPatch, MAX_KEYS, MAX_RECORD_BYTES};
use crate::dest::{
    AuthDecoration, CandidateSet, EgressBody, Permutation, VerifiedDestination, VetoCode,
};
use crate::grammar::ArrivalLocation;
use crate::ids::{LaneId, PrincipalId, RecordSchemaId, SchemeAlt, SessionId};
use crate::plugin::Plugin;
use crate::unit::{Clock, ConfigView, Step, Unit};
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
///
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

// ── virtual keys ─────────────────────────────────────────────────────────────────────────────

/// One scope a virtual key may target: a kind word and a value under it.
///
/// Kind-agnostic on purpose — the list is exhaustive across every kind, and nothing here
/// privileges one kind over a kind that does not exist yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyScope {
    /// The kind of thing the value names.
    pub kind: String,
    /// The name under that kind.
    pub value: String,
}

/// The facts the authenticate and eligibility steps read out of a verified virtual key.
///
/// The key's POSTURE — what it may target and whether it is live — and nothing that could be
/// presented again. Its group, pools and labels are the directory's business: a value carried
/// through here would be a value a step could act on, and each step decides one thing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFacts {
    /// The key's stable subject id — the principal's id, the ledger bucket, the audit attribution.
    pub id: String,
    /// The key's operator-facing label.
    pub name: String,
    /// The scopes the key may target. `None` is every scope of every kind (the grant was omitted
    /// at mint); `Some(list)` is exactly those, across all kinds; `Some([])` is no scope at all —
    /// an empty list is the empty set, never "all".
    pub scopes: Option<Vec<KeyScope>>,
    /// Whether the key is switched on.
    pub enabled: bool,
    /// The key's own hard expiry, in seconds; `None` is never. Distinct from a signed token's
    /// `exp` claim, which the verifier has already enforced.
    pub expires_at: Option<u64>,
    /// The tombstone, in seconds: `Some` is a key that was hard-deleted and whose id will never be
    /// reissued, kept so attribution by id keeps resolving. `None` is live.
    pub deleted_at: Option<u64>,
}

/// The virtual-key directory the authenticate step reaches inside the loop.
///
/// Every method answers about a PRESENTED credential and none hands anything back that could be
/// presented again, which is what makes the face safe to hold behind a shared handle: nothing on
/// it leaks a secret and nothing on it mutates the directory. It is declared here, beside the
/// other kind faces, because the unit that asks and the root that answers may not name each
/// other: the unit names this trait, the root binds the node's own directory behind it, and a
/// deployment whose keys come from somewhere else binds its own.
///
/// Every answer is read PER CALL and never captured: a key rotated, a subject revoked or an
/// operator credential re-set is judged by the next request, not by the next process.
pub trait VirtualKeyDirectory: Send + Sync {
    /// Verify a signed virtual key and resolve the facts behind it. `None` for anything that is
    /// not a currently-valid key: unknown, unsigned, expired, rotated, revoked or disabled.
    ///
    /// `expected_aud` is the plane boundary, threaded rather than checked by a caller so that a
    /// route added to an audience-bound plane later cannot forget a check that happens inside the
    /// verifier. `None` means the residual plane, where a token that CARRIES an audience is
    /// inadmissible.
    ///
    /// The order an implementor must follow is the ladder the design pins — signature, then the
    /// token's own expiry, then the denylist, then the rotation generation — each step
    /// short-circuiting the ones after it, so the FIRST reason a token failed is the one reported
    /// rather than a later one that happened to also be true.
    fn verify(&self, credential: &str, now: u64, expected_aud: Option<&str>) -> Option<KeyFacts>;

    /// Whether the subject a credential names is on the revocation denylist.
    ///
    /// The gate for a NEW unit and for nothing else — a unit already in flight is never asked,
    /// because revoking mid-unit would tear down work already paid for and observed while the next
    /// unit is refused a fraction of a second later anyway. It is not the place a signed token's
    /// revocation is enforced: [`VirtualKeyDirectory::verify`] consults the same denylist as its
    /// third step. What this covers is the credential shapes whose subject IS the credential's own
    /// id, where there is no signature to read a subject out of; an implementor that cannot resolve
    /// a credential to a subject answers `false` and loses nothing.
    fn is_revoked(&self, credential: &str) -> bool;

    /// The digest of the operator's own credential, when one is configured; `None` means the
    /// operator door is shut. Read per call, so that a rotation is judged by the next request.
    fn operator_token_hash(&self) -> Option<String>;
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
    ///
    /// The context is what the unit's lifetime is bound to, and it is here for the same reason
    /// `decorate` takes a body: without an argument carrying it, the only decoration a second
    /// round could return was one that borrowed nothing, so a scheme that wanted to answer a
    /// challenge with bytes it had built could not be written at all. The arena the context
    /// carries is where those bytes come from.
    fn continue_handshake<'u>(
        &self,
        state: &ChallengeState,
        frame: &Frame,
        ctx: &crate::unit::Ctx<'u>,
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

/// ONE RECORD HANDED TO A SINK, for a stream that sink declared.
///
/// It is ALREADY SERIALIZED and ALREADY BOUNDED: the projection that says what may appear in it
/// was resolved from the operator's configuration long before it got here, so an ungranted field
/// is absent by the time any sink can see one. A sink FRAMES this record — as a line, as a body —
/// and never builds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportItem<'u> {
    /// The stream this record belongs to, as the frozen export token the operator configures it
    /// under (`metrics`, `logs`, `traces`, `costs`, `decisions`, `events`, `identity`, `prompts`,
    /// `completions`).
    ///
    /// A TOKEN and not an enum: the frozen word-space is the plugin ABI's, which this crate may not
    /// name, and a second enum here would be a second vocabulary drifting beside the frozen one.
    pub stream: &'u str,
    /// The record.
    pub bytes: &'u [u8],
}

/// ONE FRAMED DELIVERY: the whole of what a sink decides about putting a record on a wire.
///
/// DATA, not a request. A request type belongs to the wire it goes out on, and a sink names no
/// wire — so it states the three facts and its host does the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Where this delivery is addressed.
    pub target: String,
    /// The headers it rides under, in the order the sink decided them.
    pub headers: Vec<(String, String)>,
    /// The framed body.
    pub body: Vec<u8>,
}

/// The bar a host enforces before a request may reach a sink, stated in the SINK's words.
///
/// A sink of kind `export` names no auth chain and no router, so it says what it NEEDS and its
/// host says that in whatever language this process's front door speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteBar {
    /// Unauthenticated.
    Open,
    /// A valid client token.
    Key,
}

/// ONE ROUTE A SINK DECLARES IT WILL SERVE.
///
/// Data, not a mount: the sink states it and its host decides whether this process can honour it,
/// confines it to the namespace this KIND allows, refuses a collision, enforces the bar, and only
/// then calls [`Export::serve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteStatement {
    /// The absolute path.
    pub path: &'static str,
    /// The uppercase request-method token.
    pub method: &'static str,
    /// The bar the host enforces before the request arrives.
    pub bar: RouteBar,
}

/// One request matched to a declared route, as the sink is handed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeRequest<'a> {
    /// The path the request arrived on.
    pub path: &'a str,
    /// The uppercase request-method token.
    pub method: &'a str,
    /// The headers the host chose to relay, bounded by the host.
    pub headers: &'a [(String, String)],
    /// The request body.
    pub body: &'a [u8],
}

/// What a sink SAYS on a declared route, stated as what it is — a status, headers and a body —
/// and turned into this process's own response type by its host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    /// The response status.
    pub status: u16,
    /// The response headers, in the order the sink decided them.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

/// WHAT A HOST LENDS A SINK for the length of ONE call, and not one instant longer.
///
/// Every method is a thing that belongs to the PROCESS and not to the sink: the wire this
/// deployment's egress posture opens, the reading this process can take of itself. A sink reaches
/// them through this face or not at all, which is what lets a crate of kind `export` name no
/// runtime, no socket, no recorder and no registry. Every method is an ANSWER; none is a
/// capability a sink could use to change the process it was composed into.
pub trait ExportHost {
    /// Put one framed delivery on the wire this process owns, inside the slot the host admitted
    /// this item under. `false` ⇒ the host took it nowhere.
    fn send(&self, delivery: Delivery) -> bool;

    /// This process's current exposition of one stream, as of THIS call — with whatever it derives
    /// at observation time already refreshed, so what comes back is true now and not as of some
    /// earlier call.
    ///
    /// `None` ⇒ this host exposes nothing for that stream. Deliberately NOT the same value as
    /// `Some(String::new())`: "nothing installed" and "installed and empty" are different facts
    /// about a process and a sink is entitled to answer them differently.
    fn read(&self, stream: &str) -> Option<String>;
}

/// A SINK'S ACKNOWLEDGEMENT, and it means what it says at the moment [`Export::receive`] returns.
///
/// None of the three is a wish. A sink that cannot tell the difference between enqueued and
/// delivered says [`Ack::Received`] and never [`Ack::Durable`]; an acknowledgement that carries no
/// information is worse than none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Ack {
    /// The record is where a crash on this node cannot lose it.
    ///
    /// Nothing in this tree returns it: the sinks that ship telemetry are unfsynced by design,
    /// because telemetry must not affect serving. It stays in the vocabulary because it is the one
    /// word a sink that DOES fsync has, and the at-least-once statement this contract makes is
    /// made of it.
    Durable,
    /// The sink has the record and claims no durability for it — an unfsynced append that
    /// succeeded, a framed delivery a host's wire accepted.
    Received,
    /// The sink did NOT take it. A failed open or write; a delivery the host refused; any item at
    /// all handed to a PULL sink, which is scraped and is never handed one.
    ///
    /// It states a fact about the sink. What a host does about it is the host's — this tree's
    /// request-log fan-out counts a drop, because a retry queue in front of a telemetry sink is a
    /// memory leak with a deadline.
    Retry,
}

/// EVERY EXPORT SINK, and the whole of what one is.
///
/// A sink declares WHAT IT CARRIES, takes one already-serialized record for one of them, declares
/// WHAT IT SERVES, and answers a request matched to one of those routes. Push sinks live
/// in the first pair, pull sinks in the second, and every sink states all four: there are no
/// defaults here, so a sink that does not push and a sink that does not serve each say so in their
/// own file rather than inheriting a silence from this one.
pub trait Export: Plugin + Send + Sync + 'static {
    /// What THIS instance carries, as frozen export tokens. A host only ever hands it an item
    /// whose token is named here.
    fn streams(&self) -> &'static [&'static str];

    /// Take one record for a declared stream.
    fn receive(&self, item: ExportItem<'_>, host: &dyn ExportHost) -> Ack;

    /// The routes THIS instance serves — its own compiled-in declarations. A push-only sink
    /// declares none.
    fn routes(&self) -> &'static [RouteStatement];

    /// Answer one request matched to a declared route. Never called for a route this sink did not
    /// declare, and never before the host has enforced that route's stated bar.
    fn serve(&self, req: &ServeRequest<'_>, host: &dyn ExportHost) -> Served;
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

/// A bounded list of envelope fields: the one spelling of the bound, for every shape that carries
/// one.
pub type EnvelopeFields<'u> = BoundedVec<crate::wire::EnvelopeField<'u>, MAX_KEYS>;
