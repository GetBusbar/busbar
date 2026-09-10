//! The other plugin kinds: auth, egress auth, store, secret, hook and export — one closed shape
//! per trait, transcribed from the plugin-kinds table of the design. See
//! `docs/design/contract-notes.md` for why four of the six reach outside the process on a bounded
//! blocking pool while the other two (hook, egress-auth scheme) are pure.
//!
//! Fallibility: every fallible method below returns the one structured [`PluginError`] of
//! `crate::error`; the class taxonomy there says what a failure means, so no trait repeats it.

use crate::bounded::{ArenaBytes, BoundedVec, Facts, IrPatch, MAX_KEYS, MAX_RECORD_BYTES};
use crate::dest::{
    AuthDecoration, CandidateSet, EgressBody, Permutation, VerifiedDestination, VetoCode,
};
use crate::error::PluginError;
use crate::grammar::ArrivalLocation;
use crate::ids::{LaneId, PrincipalId, RecordSchemaId, SchemeAlt, SessionId};
use crate::plugin::Plugin;
use crate::store::{
    CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, UsageDelta, UsageLedger,
    VirtualKey,
};
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

/// The durable store behind the journal.
///
/// Every method here runs on a bounded blocking pool under a per-kind deadline, and a call that
/// overruns ends its unit rather than blocking the loop. The interface generation a store declares
/// decides how it loads: a store built against an older generation loads through an in-tree
/// adapter rather than being refused, so a configuration written for the previous release boots
/// unchanged.
///
/// # Errors
/// Every method returns [`PluginError`] on failure. A fencing race is `Conflict`; a gap between
/// what was written and what read back is `Integrity`; the rest are what their class says.
pub trait Store: Plugin + Send + Sync + 'static {
    /// Append a batch of journal records.
    fn append_batch(&self, stream: &str, records: &[RecordBytes]) -> Result<Head, PluginError>;

    /// Read a batch of journal records back.
    fn replay_batch(
        &self,
        stream: &str,
        from: u64,
        limit: u32,
    ) -> Result<Vec<RecordBytes>, PluginError>;

    /// Draw this node's slice of a bucket window. Fails if this node's epoch is fenced out.
    fn reserve(&self, bucket: &str, amount: u64, epoch: u64) -> Result<SliceGrant, PluginError>;

    /// Hand an undrawn slice back.
    fn release(&self, bucket: &str, grant: SliceGrant) -> Result<(), PluginError>;

    /// Where each stream has reached.
    fn heads(&self) -> Result<Vec<(String, Head)>, PluginError>;

    /// Say this node is alive at this epoch. Fails if this node has been fenced out.
    fn heartbeat(&self, node: &str, epoch: u64) -> Result<(), PluginError>;

    /// Elect which node writes the next checkpoint.
    fn elect_checkpoint(&self, node: &str, epoch: u64) -> Result<bool, PluginError>;

    /// Claim an idempotency key for this unit.
    fn claim_key(&self, namespace: &str, key: &[u8], unit: u64) -> Result<bool, PluginError>;

    /// Drop the claims a failed unit made.
    fn void_claims(&self, namespace: &str, unit: u64) -> Result<(), PluginError>;

    /// Seal a replayable answer under its key.
    fn replay_put(&self, namespace: &str, key: &[u8], value: &[u8]) -> Result<(), PluginError>;

    /// Read a sealed replayable answer back.
    fn replay_get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>, PluginError>;

    /// Register a live session in the fleet directory.
    fn session_put(
        &self,
        session: SessionId,
        node: &str,
        principal: &PrincipalId,
    ) -> Result<(), PluginError>;

    /// Drop a session from the directory, at close or at lease expiry.
    fn session_remove(&self, session: SessionId) -> Result<(), PluginError>;

    /// Which sessions a principal holds across the fleet.
    fn sessions_for(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<(SessionId, String)>, PluginError>;

    /// Write one of a plane's kernel-held durable records.
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), PluginError>;

    /// Read one of a plane's kernel-held durable records.
    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, PluginError>;

    /// Walk a plane's records under a prefix.
    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, PluginError>;

    /// Read the previous release's own cells, for a migrating deployment.
    fn legacy_cells_read(&self, key: &str) -> Result<Option<Vec<u8>>, PluginError>;

    /// Write the previous release's own cells, for a migrating deployment.
    fn legacy_cells_write(&self, key: &str, value: &[u8]) -> Result<(), PluginError>;

    /// Where the previous release's audit stream had reached.
    fn legacy_audit_head(&self) -> Result<Option<Head>, PluginError>;

    /// How far a backup has captured.
    fn backup_watermark(&self) -> Result<Option<Head>, PluginError>;

    /// Drop everything older than a sequence, under the retention the operator set.
    fn purge_before(&self, stream: &str, seq: u64) -> Result<u64, PluginError>;

    // ── THE ENFORCEMENT HALF OF THE STORE FACE ────────────────────────────────────────────────
    //
    // The twenty-two verbs above are the journal, the fleet directory and the record half. The
    // twenty-three below are the enforcement half: the virtual-key directory, the token ledger and
    // the metering book, row-looked-up credentials, the revocation denylist, and the two record
    // verbs the record half was missing. They are declared HERE, with their real semantics, rather
    // than folded onto `record_put`: `usage_add` accumulates atomically where `record_put` sets
    // absolutely, and `key_put`'s tombstone guard is a test-and-write only a backend can make
    // atomic. Forcing either through the record verbs would change what the money and the
    // revocation paths mean, which is the one thing this face may not do.
    //
    // Every verb is bodiless, like every other verb on every kind trait here. The accept-and-keep-
    // nothing and fail-closed DEFAULTS the 1.5.5 replay trait carried are compatibility behaviour,
    // not face behaviour, so they live in the loader's adapter and are answered there on a legacy
    // artifact's behalf.

    /// UPSERT a virtual key by its id — the mint path and every in-place update (rename,
    /// enable/disable, regroup, rotate).
    ///
    /// ONE precondition, and it is the FACE's rather than the caller's: a `key_put` whose
    /// `deleted_at` is `None` MUST NOT overwrite a stored row whose `deleted_at` is `Some(_)`.
    /// Answer `Conflict` instead. The tombstone is permanent and the id is never reissued, so
    /// silently clearing one resurrects a key an operator revoked. A caller cannot close this: its
    /// check is a read-then-write, and a `key_revoke` committing in between slips straight through.
    /// Only the backend can make the test and the write one operation. Writing a row that CARRIES a
    /// tombstone is unaffected — hydration and fixtures legitimately do it.
    ///
    /// Otherwise an ABSOLUTE set, not a compare-and-set: no expected revision is taken, so two
    /// concurrent writers are last-writer-wins on the whole row. Said here so the tombstone guard is
    /// not mistaken for general optimistic concurrency, which this is not.
    fn key_put(&self, key: &VirtualKey) -> Result<(), PluginError>;

    /// Read one virtual key by id; `None` for an id this store has never held.
    fn key_get(&self, id: &str) -> Result<Option<VirtualKey>, PluginError>;

    /// EVERY virtual key, live or tombstoned — deliberately UNFILTERED. A caller that wants a
    /// live-only view filters at the point it renders one; [`Store::keys_since`] needs tombstones to
    /// be visible here for the eviction its own doc describes. A backend must not filter.
    fn key_list(&self) -> Result<Vec<VirtualKey>, PluginError>;

    /// TOMBSTONE a virtual key: the row is NOT removed. Atomically destroy every credential row for
    /// the key (secret material must not outlive it), set it disabled with the deletion stamped, and
    /// leave the naming and grouping fields untouched so anything that attributes by id — metering
    /// rows, audit records — keeps resolving forever.
    ///
    /// Idempotent on an already-tombstoned id. An id that names NO ROW is a loud `NotFound`, and
    /// that is a DIFFERENT case: "already revoked" means the operator's intent is satisfied and the
    /// evidence is on disk, while "no such id" means it is not and the likeliest cause is a stale id
    /// or a typo. Collapsing them tells an operator a key was revoked when nothing was touched.
    ///
    /// Erasing the key's personal data is a separate, explicit operation — see
    /// [`Store::key_scrub`] — so "this key is gone" and "this key's personal data is gone" stay
    /// independently auditable.
    fn key_revoke(&self, id: &str) -> Result<(), PluginError>;

    /// PII erasure ONLY: null the naming fields on an ALREADY-tombstoned key. Every other field, and
    /// every attribution that reads the row by id, is untouched — this satisfies "erase the personal
    /// data" without touching financial evidence, which is what a right-to-erasure request actually
    /// needs. `NotFound` for an unknown id; `Rejected` for a key that is still live, because
    /// scrubbing an active principal would be silent, un-auditable data loss.
    fn key_scrub(&self, id: &str) -> Result<(), PluginError>;

    /// Every virtual key with a revision above `since` — the INCREMENTAL hydration delta, taken
    /// instead of a full reload on each staleness tick. `since = 0` returns every key.
    ///
    /// UNLIKE [`Store::key_list`] this must NOT filter tombstones, and the reason is a security one:
    /// a hydrator learns that a key was revoked only by seeing its deletion stamp appear here, and
    /// that is what tells it to evict the key's cached credentials. See
    /// [`Store::credentials_since`] for why that eviction cannot wait on a credential-row delta.
    fn keys_since(&self, since: u64) -> Result<Vec<VirtualKey>, PluginError>;

    /// The TOKEN LEDGER for one bucket and window. The bucket is a key's own budget bucket or a
    /// budget-group bucket — the same shape either way. An untouched pair reads as the EMPTY ledger,
    /// never `NotFound`. NO money field crosses this seam: spend is derived at read time from the
    /// ledger against the rate card, so a store never holds a price.
    fn usage_get(&self, bucket: &str, window_start: u64) -> Result<UsageLedger, PluginError>;

    /// ABSOLUTE set of a bucket's window ledger — replaces the whole requests-plus-per-model-token
    /// record. SINGLE-WRITER ONLY: with several nodes sharing one store an absolute overwrite loses
    /// the other nodes' accruals, which is why the fleet flush path uses [`Store::usage_add`].
    fn usage_put(
        &self,
        bucket: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Result<(), PluginError>;

    /// ATOMIC ADDITIVE accumulate of a bucket's window ledger: add the signed requests delta and
    /// each per-model, per-tier token delta — possibly negative, a refund — to the durable record,
    /// with counters floored at zero.
    ///
    /// This is the FLEET-HONEST flush primitive, and it is the reason the enforcement half is
    /// declared rather than folded onto the record verbs. `record_put` is an absolute set; N nodes
    /// each flushing their delta-since-last-flush through an absolute set is last-writer-wins, and
    /// the fleet total is simply wrong. A backend implements this with whatever its storage makes
    /// atomic. No money field crosses here either — only counts.
    fn usage_add(
        &self,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Result<(), PluginError>;

    /// Accumulate one completed response's RAW consumption into its metering row, keyed by key,
    /// bucket, model and provider, counting one more request. Metering is OBSERVABILITY:
    /// best-effort, and never consulted for enforcement.
    fn metering_add(&self, delta: &MeteringDelta) -> Result<(), PluginError>;

    /// Every metering row accumulated in a metering bucket, for the by-model and by-key
    /// aggregations the usage read renders.
    fn metering_list(&self, bucket: u64) -> Result<Vec<MeteringRow>, PluginError>;

    /// RETENTION sweep of the token ledger: drop every window that starts before this, and say how
    /// many went. A background sweeper on the operator's interval is the only caller — never the
    /// request path.
    fn usage_purge_before(&self, before: u64) -> Result<u64, PluginError>;

    /// RETENTION purge of the durable metering book. Unlike [`Store::usage_purge_before`] this must
    /// NEVER be wired to an automatic sweeper: metering rows are billing evidence, and evidence is
    /// purged only when an operator explicitly asks, exactly as a key is tombstoned rather than
    /// removed and for the same reason. An explicit, audited operator action is the only thing that
    /// may reach it.
    fn metering_purge_before(&self, bucket: &str) -> Result<u64, PluginError>;

    /// Persist a row-looked-up credential. UPSERTs on the key, kind and slot the credential names.
    /// Minting into an occupied LIVE slot — one not yet revoked — MUST fail rather than destroy a
    /// working credential in the middle of an overlap window: an explicit slot pointed at a live
    /// credential is almost certainly an operator mistake, not an intended rotation.
    fn credential_put(&self, secret: &CredentialSecret) -> Result<(), PluginError>;

    /// ATOMIC key-and-credential mint: persist the key row AND its paired credential row together,
    /// or neither. A caller cannot compose this out of [`Store::key_put`] and
    /// [`Store::credential_put`] — a failure between them leaves a key that can never be used or a
    /// credential owned by nothing — which is why it is its own verb.
    fn key_put_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Result<(), PluginError>;

    /// Every credential row for a key, METADATA ONLY — never the secret. The listing surface an
    /// operator reads. [`Store::credential_lookup`] is the one verb that returns material.
    fn credential_list(&self, key_id: &str) -> Result<Vec<CredentialMeta>, PluginError>;

    /// Resolve a credential kind and public id to its full secret material — the verify-path and
    /// hydration lookup. An unknown pair is `None` and NEVER an error: an unrecognized public id is
    /// a normal, expected outcome of an admit path, not a store failure, and reporting it as one
    /// would turn every probe into an incident.
    fn credential_lookup(
        &self,
        kind: &str,
        public_id: &str,
    ) -> Result<Option<CredentialSecret>, PluginError>;

    /// Revoke ONE credential by id, independently of the key that owns it. The reason is operator
    /// metadata for the audit trail and is never a secret.
    ///
    /// Idempotent on an already-revoked id; an id that names NO ROW is an error. A backend must
    /// therefore read the row count its write actually affected, or check for the row first: a
    /// statement that matched nothing looks identical to one that matched, and this is precisely the
    /// case where those two must not be confused — an operator who is told a leaked credential was
    /// killed must not find it still live.
    fn credential_revoke(&self, id: &str, reason: &str) -> Result<(), PluginError>;

    /// Every credential row above a revision, SECRET INCLUDED — the incremental hydration delta for
    /// the in-process verify cache, which must never make a synchronous store call and so needs the
    /// material in hand rather than metadata. `since = 0` returns every row.
    ///
    /// A CONTRACT THE CONSUMER OWES, not just this verb: a revision delta CANNOT observe a deletion
    /// — a row that is gone simply stops appearing. [`Store::key_revoke`] destroys every credential
    /// row for its key, so a consumer that reacts ONLY to credential deltas would keep serving a
    /// revoked key's credential from cache forever, which is an authentication bypass. Whenever
    /// [`Store::keys_since`] shows a key newly tombstoned, the consumer MUST evict that key's
    /// credentials itself rather than wait for a delta that will never come.
    fn credentials_since(&self, since: u64) -> Result<Vec<CredentialSecret>, PluginError>;

    /// Add a subject to the REVOCATION DENYLIST. A minted signed credential is stateless, so
    /// revoking one means recording its subject here; the verify path refuses any credential whose
    /// subject is present. Idempotent. The reason is operator metadata for the audit trail, never a
    /// secret.
    fn denylist_add(&self, subject: &str, reason: &str) -> Result<(), PluginError>;

    /// Every denied subject, for the boot hydrate of the in-memory denylist.
    fn denylist_list(&self) -> Result<Vec<String>, PluginError>;

    /// DELETE the record a schema and key identify; absent is a no-op. The record half declares
    /// `record_put`, `record_get` and `record_scan` and no way to remove one, so a plane that keeps
    /// durable rows could create and read them but never retire one outside the retention sweep.
    fn record_delete(&self, schema: RecordSchemaId, key: &[u8]) -> Result<(), PluginError>;

    /// IS THIS CAPABILITY STILL LIVE? A MULTI-USE, time-and-state-bounded check, and deliberately
    /// NOT [`Store::claim_key`]'s single-use claim.
    ///
    /// Answer `true` while the record the schema and key identify is present, still active, and
    /// `now` has not passed `expires_at`. It SPENDS NOTHING: asking twice answers the same both
    /// times, because what this expresses is "the work this names is still in flight", not "nobody
    /// has used this yet". A callback a counterparty makes several times for one piece of work is
    /// the case it exists for — a claim would refuse every honest call after the first, and a check
    /// that answered `true` forever would let a captured capability replay after the work finished.
    ///
    /// The answer for a store that keeps no such record is `false`, and that is the whole point. For
    /// a READ, "this store remembers nothing" and "there is nothing to remember" are the same
    /// answer. For a CAPABILITY CHECK they are opposites: a store that cannot say whether a
    /// capability is live must never be read as saying that it is.
    fn record_live(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        expires_at: u64,
        now: u64,
    ) -> Result<bool, PluginError>;
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

/// Resolves, signs, seals and unseals key material.
///
/// Sealing is deterministic and misuse-resistant: the same plaintext under the same key and
/// context seals to the same bytes, which is what lets a replay cache be sealed at all.
///
/// # Errors
/// Every method returns [`PluginError`] on failure. A reference outside this plugin's grammar
/// is `Malformed`; a reference that does not resolve is `NotFound`; a caller the policy refuses is
/// `Denied` — a configuration matter, never folded onto `NotFound`; sealed bytes that do not
/// authenticate are `Integrity`.
pub trait Secret: Plugin + Send + Sync + 'static {
    /// The reference grammar this plugin accepts.
    fn ref_grammar(&self) -> &'static str;

    /// Resolve a reference.
    fn resolve(&self, r: &SecretRef) -> Result<SecretValue, PluginError>;

    /// Watch a reference for change. Returning nothing means the value does not change under this
    /// plugin. Every reference migrated from the previous release is inert here: it was resolved
    /// once at the site the old release resolved it, and re-resolving would be a behaviour change.
    fn watch(&self, r: &SecretRef) -> Result<Option<u64>, PluginError>;

    /// Sign bytes with a named key.
    fn sign(&self, key: &str, bytes: &[u8]) -> Result<Vec<u8>, PluginError>;

    /// Seal bytes under a key and a context.
    fn seal(&self, key: &str, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PluginError>;

    /// Unseal bytes under a key and a context. Fails if the bytes do not authenticate.
    fn unseal(&self, key: &str, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, PluginError>;
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
/// Both methods return [`PluginError`] when the anchor cannot be written or read.
pub trait Anchor: Export {
    /// Write a head out.
    fn write_head(&self, head: Head) -> Result<(), PluginError>;

    /// Read one of the last heads back.
    fn read_head(&self, n: u32) -> Result<Option<Head>, PluginError>;
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
