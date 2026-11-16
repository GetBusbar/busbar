// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit record: the same shape for every caller, with no exceptions.

use busbar_contract::caps::{Abort, Origin, Outcome, ReasonCode, StepName, UnitKey};

#[cfg(any(test, feature = "test-support"))]
mod test_support;

/// Whose activity this is.
///
/// A resolved principal appears as its principal IDENTIFIER — the key id the governance store
/// resolved the credential to, which an operator holding that store can resolve back to the key.
/// It is not a pseudonym, and the journal is exempt from erasure, so a reader must treat a
/// principal's id on a sealed record as kept for the life of the chain. An arrival that never
/// resolved to anybody is recorded as an arrival, because "nobody authenticated" is itself a fact
/// worth keeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// A resolved principal, by its principal identifier (the governance key id).
    PrincipalId(String),
    /// Something that arrived and was never attributed to a principal.
    Arrival,
    /// The node acting for itself.
    Node(u64),
    /// A rolled-up figure rather than one actor.
    Aggregate,
}

/// An identifier a caller supplies for the kind of operation performed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpClassId(String);

impl OpClassId {
    /// Name one.
    pub fn new(id: impl Into<String>) -> Self {
        OpClassId(id.into())
    }

    /// Its name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a unit finished, as the caller sees it. The second and last thing a caller contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishClass {
    /// Everything asked for was delivered.
    Complete,
    /// One turn of a longer exchange finished.
    TurnComplete,
    /// Some of it was delivered.
    Partial,
    /// It failed.
    Error,
}

/// WHAT was done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct What {
    /// Which unit.
    pub unit_key: UnitKey,
    /// WHICH BOOT of the node the unit ran in. A unit key restarts at every boot, so the key alone
    /// names two different units across two boots; the pair is unique. Digested from recipe `v4`.
    pub incarnation: u64,
    /// What kind of operation, as the caller names it.
    pub op_class: OpClassId,
    /// Where it went, once the trust unit had judged the destination. Absent when the unit never
    /// left the node.
    pub destination: Option<String>,
    /// The unit that caused this one, if any.
    pub parent: Option<UnitKey>,
    /// The digest of the hook chain as it stood before the unit ran.
    pub pre_hook_head: Option<String>,
    /// And after.
    pub post_hook_head: Option<String>,
}

/// HOW it went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeFacts {
    /// How the unit ended.
    pub unit_end: Outcome,
    /// Which step it ended at, when it ended somewhere in particular.
    pub step: Option<StepName>,
    /// How it finished, as the caller classifies it.
    pub finish: FinishClass,
    /// Whether a hook failed during the unit.
    pub hook_failed: bool,
    /// How far the emission ran under or over what was planned. Negative is under.
    pub emission_delta: i64,
    /// Whether the unit ran under a policy that had already been superseded.
    pub stale_policy: bool,
}

/// One quantity, with where the number came from.
pub use busbar_contract::caps::{QuantitySource, UsageLine};

/// WHAT WAS USED: the counts, and the provenance a read-time price is computed from.
///
/// No priced figure. The tier, the fee count and the rate card version are the INPUTS the one
/// function (`Tally::row`) takes alongside the counts; what they come to is computed when it is
/// read, never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    /// The quantities, with their sources.
    pub lines: Vec<UsageLine>,
    /// The tier in force, in basis points — an input to the read-time price, not a price.
    pub tier_bp: u32,
    /// How many request fees were charged.
    pub fee_count: u32,
    /// The actual fleet entry key on new records, absent when no key was attached.
    /// Legacy recipes encode no actual key; their original ordinal stays in the recipe metadata.
    pub rate_card_version: Option<[u8; 20]>,
    /// Which chain of buckets it was drawn against.
    pub bucket_chain_ref: String,
}

/// What one hook's answer did to the unit: its decision head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookHead {
    /// It let the unit through as it was.
    Pass,
    /// It stopped the unit.
    Veto,
    /// It changed the unit: rewrote its request, or ordered or narrowed where it may go.
    Modify,
}

impl HookHead {
    /// The frozen text the digest and the journal carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HookHead::Pass => "pass",
            HookHead::Veto => "veto",
            HookHead::Modify => "modify",
        }
    }

    /// The head [`HookHead::as_str`] spells `tag`, if any.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        [HookHead::Pass, HookHead::Veto, HookHead::Modify]
            .into_iter()
            .find(|h| h.as_str() == tag)
    }
}

/// One hook that ran (THE DESIGN §1: "controls (... hooks applied)").
///
/// Which hook, by the key the deployment configured it under (never the instance that serves it),
/// its decision head, and whether it failed — and nothing priced: what a hook changed is in the
/// counts it changed, and those are the usage lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookApplied {
    /// Which hook: its configured key.
    pub hook: String,
    /// What its answer did to the unit.
    pub head: HookHead,
    /// It could not answer (an error, a deadline): its head is then what its `on_error` made of
    /// it. A failure is recorded, never dropped.
    pub failed: bool,
}

/// THE CONTROLS that were in force.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Controls {
    /// The hold this unit ran under.
    pub hold_ref: Option<String>,
    /// The settlement that closed it.
    pub settle_ref: Option<String>,
    /// The slice the hold drew from.
    pub slice_ref: Option<String>,
    /// The lease in force.
    pub lease_ref: Option<String>,
    /// Which lease generation.
    pub lease_epoch: u64,
    /// Which policy generation.
    pub policy_epoch: u64,
    /// Every hook that ran.
    pub hooks_applied: Vec<HookApplied>,
    /// Whether this unit was answered from a replay rather than performed.
    pub replayed: bool,
    /// The units this one caused.
    pub children: Vec<UnitKey>,
}

/// How one attempt of a unit at a target ended (recipe `v7` frames it; ADMIN-API-1.6 §9 fills it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The target answered.
    Ok,
    /// The target failed and the unit moved to the next one.
    Failover,
    /// The target failed and the unit ended there.
    Failed,
    /// The attempt was cancelled.
    Cancelled,
}

impl AttemptOutcome {
    /// Every outcome, in tag order.
    pub const ALL: [AttemptOutcome; 4] = [
        AttemptOutcome::Ok,
        AttemptOutcome::Failover,
        AttemptOutcome::Failed,
        AttemptOutcome::Cancelled,
    ];

    /// The frozen text the digest, the journal and the read carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptOutcome::Ok => "ok",
            AttemptOutcome::Failover => "failover",
            AttemptOutcome::Failed => "failed",
            AttemptOutcome::Cancelled => "cancelled",
        }
    }

    /// The outcome [`AttemptOutcome::as_str`] spells `tag`, if any.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        AttemptOutcome::ALL.into_iter().find(|o| o.as_str() == tag)
    }
}

/// One attempt slot of a `v7` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// How it ended.
    pub outcome: AttemptOutcome,
    /// The lane it was made at.
    pub target: String,
    /// The reason it did not answer, empty when it did.
    pub reason: String,
    /// Its duration in microseconds, 0 when not measured.
    pub us: u64,
}

/// How many attempts a `v7` record holds inline; `attempts_total` counts beyond them.
pub const ATTEMPT_SLOTS: usize = 4;

/// WHAT RECIPE `v7` ADDS (ADMIN-API-1.6 §3.2): the facts `/records` serves history-stably.
///
/// Every field is a copy or one short text, so a seal stays one allocation over `v6` (the
/// attribution). A record sealed before `v7` decodes with the default, and a read tells the two
/// apart by [`AuditRecord::recipe`], never by these values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitFacts {
    /// The arrival, in milliseconds since the epoch (the reading `wall` is the seconds of).
    pub wall_ms: u64,
    /// `group`, `pool` and `provider` of the unit's metering, joined by U+001F, each empty when
    /// absent. Built once per unit from the entry metering keys on.
    pub attribution: String,
    /// The process boot nonce: 16 random bytes per process, all zero when the RNG fill failed.
    pub boot_nonce: [u8; 16],
    /// The HTTP status the unit answered with, 0 for none (§9).
    pub status: u16,
    /// Microseconds to the first body write, 0 when not measured (§9).
    pub ttft_us: u64,
    /// Microseconds until the last frame was handed over, 0 when not measured (§9).
    pub total_us: u64,
    /// The first [`ATTEMPT_SLOTS`] attempts, filled from the front (§9).
    pub attempts: [Option<Attempt>; ATTEMPT_SLOTS],
    /// How many attempts were made in all, including those beyond the slots.
    pub attempts_total: u32,
    /// What `records.user` and `records.labels` keep (§3.5): empty unless the operator switched
    /// them on, and then sealed as the optional records tail after `attempts_total`.
    pub records: RecordFacts,
}

/// How many request labels a record keeps at most (`records.labels`, ADMIN-API-1.6 §3.5).
pub const LABEL_SLOTS: usize = 8;

/// WHAT `records.user` AND `records.labels` KEEP OF A UNIT (ADMIN-API-1.6 §3.5).
///
/// Empty (the default, and everything a record sealed before §3.5 holds) frames nothing: the
/// recipe and the journal add the records tail only when [`RecordFacts::is_empty`] is false, so
/// every `v7` record sealed without it keeps its bytes and its digest. Empty costs no allocation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordFacts {
    /// The end user as `records.user` keeps it: a pseudonym or the cut plain value.
    pub user: Option<String>,
    /// The allow-listed request headers, `(lower-case name, value)`, in the allow-list's order.
    pub labels: Vec<(std::sync::Arc<str>, String)>,
}

impl RecordFacts {
    /// Whether nothing is kept, so the record frames no records tail.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.user.is_none() && self.labels.is_empty()
    }
}

/// The separator inside [`UnitFacts::attribution`].
pub const ATTRIBUTION_SEP: char = '\u{1f}';

impl UnitFacts {
    /// The facts of a unit that arrived at `wall_ms`, with nothing else known.
    #[must_use]
    pub fn at(wall_ms: u64) -> Self {
        UnitFacts {
            wall_ms,
            ..UnitFacts::default()
        }
    }

    /// The sealed `(group, pool, provider)`, each `None` when empty.
    #[must_use]
    pub fn attributed(&self) -> [Option<&str>; 3] {
        let mut parts = self.attribution.splitn(3, ATTRIBUTION_SEP);
        let mut next = || parts.next().filter(|s| !s.is_empty());
        [next(), next(), next()]
    }

    /// The attempts filled from the front.
    pub fn attempts_used(&self) -> impl Iterator<Item = &Attempt> {
        self.attempts.iter().map_while(Option::as_ref)
    }
}

/// Join `group`, `pool` and `provider` into the one sealed attribution text.
#[must_use]
pub fn attribution(group: &str, pool: &str, provider: &str) -> String {
    let mut out = String::with_capacity(group.len() + pool.len() + provider.len() + 2);
    out.push_str(group);
    out.push(ATTRIBUTION_SEP);
    out.push_str(pool);
    out.push(ATTRIBUTION_SEP);
    out.push_str(provider);
    out
}

/// THE NODE-QUALIFIED UNIT ID (ADMIN-API-1.6 §3.4, C5): `node_<16 hex>.<32 hex>.<unit key>`.
///
/// A `UnitKey` restarts at 1 on every boot of every node, so the key alone is no join id. This
/// one string is `UnitRecord.unit`, the `{unit}` of `content_ref` and the data plane's
/// `X-Request-Id`: one formatter, so the three cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitId {
    node: u64,
    boot_nonce: [u8; 16],
    unit_key: u64,
}

impl UnitId {
    /// The id of `unit_key` sealed by `node` in the process whose boot nonce is `boot_nonce`;
    /// `None` when the nonce is all zero (the RNG fill failed, so no id is unique).
    #[must_use]
    pub fn of(node: u64, boot_nonce: [u8; 16], unit_key: u64) -> Option<Self> {
        (boot_nonce != [0; 16]).then_some(UnitId {
            node,
            boot_nonce,
            unit_key,
        })
    }
}

impl std::fmt::Display for UnitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "node_{:016x}.{}.{}",
            self.node,
            HexBytes(&self.boot_nonce),
            self.unit_key
        )
    }
}

/// One audit record: the same shape for every caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// WHO.
    pub subject: Subject,
    /// WHAT.
    pub what: What,
    /// WHEN, in unix seconds on the wall clock.
    pub wall: u64,
    /// WHEN, on the node's monotonic clock, so a wall clock that jumped cannot reorder a unit's own
    /// events.
    pub mono: u64,
    /// WHICH NODE SEALED IT (THE DESIGN §1: "when (wall + monotonic, node)"): the node half of every
    /// `op_id` the sealing process mints, a non-zero draw of the OS CSPRNG. Nodes share one store,
    /// and a monotonic reading compares only against readings of the same node, so the record names
    /// the node its `mono` belongs to. Digested from recipe `v4`, so neither the digest, the
    /// signature over it nor the range read can be re-attributed to another node.
    pub node: u64,
    /// Where the unit came from.
    pub origin_kind: &'static str,
    /// HOW IT WENT.
    pub outcome: OutcomeFacts,
    /// WHAT WAS USED.
    pub usage: Usage,
    /// THE CONTROLS.
    pub controls: Controls,
    /// The digest of the correlation label, never the label itself.
    pub correlation_hash: Option<String>,
    /// What recipe `v7` adds; the default on a record sealed before it.
    pub unit: UnitFacts,
    /// WHEN THIS LINE WAS LINKED INTO THE CHAIN, in milliseconds since the epoch, read under the
    /// caller's lock just before [`AuditChain::link`] (SEALING-FIX §3.1). The date every sealing rule
    /// uses; never the arrival `wall`. Digested by the link recipe only; 0 on every older recipe.
    pub linked_ms: u64,
    /// WHERE this record sits in the chain, counting from one.
    ///
    /// The link alone says a record's neighbour is the one it names; it cannot say that the record
    /// at the END was the last one sealed, because a run whose tail was cut still links perfectly.
    /// The position is what makes a truncation visible: it is digested, so it cannot be renumbered,
    /// and it is contiguous, so a hole has nowhere to hide.
    pub seq: u64,
    /// The preceding record's digest.
    pub prev_hash: String,
    /// WHICH RECIPE this record was sealed under, and so the rules its digest is recomputed by
    /// Every record this build seals is [`crate::recipe::Recipe::V7`]; a record sealed
    /// under `v2` keeps verifying by `v2`'s rules.
    pub recipe: crate::recipe::Recipe,
    /// This record's own digest.
    pub hash: String,
    /// THE SIGNATURE OVER [`AuditRecord::hash`], minted at seal time by the process that sealed
    /// this record. 128 lowercase hex characters, over [`crate::sign::signing_preimage`].
    ///
    /// `None` on a node that seals unsigned — a node with no signing key configured — and on every
    /// record sealed before this node had one. That is honest rather than convenient: a signature
    /// a receiver applied later proves the receiver got those bytes, not that this node made them,
    /// so there is no back-fill that would mean anything.
    ///
    /// NOT DIGESTED, and it could not be: it is computed FROM the digest. That is also what keeps
    /// every chain already on disk verifying — [`AuditChain::digest_of`] is byte-for-byte the
    /// function it was before signing existed.
    pub signature: Option<String>,
    /// WHICH KEY minted [`AuditRecord::signature`] — the identifier, never the key.
    ///
    /// An identifier and not a key, so that a record names what signed it without the record
    /// becoming the place a verifier learns what to trust. The key itself comes from the published
    /// key set, which is a different read, deliberately.
    pub key_id: Option<std::sync::Arc<str>>,
}

/// Everything a caller supplies. The position and the two hashes are not here, for the same reason
/// they are not on the retired admin record: the chain owns them.
#[derive(Debug, Clone)]
pub struct AuditInputs {
    /// WHO.
    pub subject: Subject,
    /// WHAT.
    pub what: What,
    /// WHEN, on the wall clock.
    pub wall: u64,
    /// WHEN, on the monotonic one.
    pub mono: u64,
    /// Where it came from.
    pub origin: Origin,
    /// HOW IT WENT.
    pub outcome: OutcomeFacts,
    /// WHAT WAS USED.
    pub usage: Usage,
    /// THE CONTROLS.
    pub controls: Controls,
    /// The correlation label, which is HASHED on the way in and never stored.
    pub correlation_label: Option<String>,
    /// What recipe `v7` adds.
    pub unit: UnitFacts,
}

impl AuditRecord {
    /// The node-qualified unit id ([`UnitId`]): `None` before `v7`, which sealed no boot nonce,
    /// and when the sealing process had none.
    #[must_use]
    pub fn unit_id(&self) -> Option<UnitId> {
        if !self.recipe.carries_unit_facts() {
            return None;
        }
        UnitId::of(self.node, self.unit.boot_nonce, self.what.unit_key.get())
    }
}

mod sealed {
    pub trait Sealed {}
}

/// The audit unit: it seals records, and it is the only thing that can.
///
/// The token is the point. A caller can say what it saw and a hook can say what it did, but turning
/// either into a record that goes on the chain takes the audit step's own token, which the loop
/// hands out for the length of one call. So a record on the chain is a record the audit unit made.
///
/// SEALED on a private supertrait, the same shape the breaker unit's kernel-facing trait has. The
/// token proves the loop is at the audit step; the seal is what says the thing answering that step
/// is the audit unit. Without it a plugin crate could implement this trait, be handed the token the
/// loop lends, and put a record on the chain that the audit unit never made — and a record nobody
/// can attribute to the audit unit is not evidence. [`AuditChain`] is the only implementor there
/// can be. Nothing outside this crate can name the supertrait, so nothing outside it can implement
/// this one:
///
/// ```compile_fail
/// struct Impostor;
/// impl crate::Audit for Impostor {
///     fn seal(
///         &mut self,
///         _inputs: crate::AuditInputs,
///         _token: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
///     ) -> crate::AuditRecord {
///         unimplemented!()
///     }
/// }
/// ```
pub trait Audit: sealed::Sealed {
    /// Seal one record onto the chain.
    fn seal(
        &mut self,
        inputs: AuditInputs,
        token: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
    ) -> AuditRecord;
}

/// The chain of fixed audit records.
///
/// A separate chain from the retired admin chain, deliberately. They record different things at
/// different rates, and pouring one into the other would make a busy hour of request-rate records
/// evict the operator-rate ones — silently, because a pruned ring looks exactly like one that was
/// never written to.
/// DERIVED, and the derive is load-bearing rather than incidental: it reaches
/// [`crate::sign::AuditSigningKey`], whose own `Debug` prints the key identifier and refuses to
/// print the secret. So `{:?}` on a whole chain — which is what an error path or a panic message
/// actually does — cannot produce key material. The test `debug_never_shows_the_secret` formats
/// this type, not just the key, for exactly that reason.
#[derive(Debug)]
pub struct AuditChain {
    pub(crate) tail_hash: String,
    pub(crate) next_seq: u64,
    pub(crate) sealed: u64,
    /// The key this chain signs with, when the node was given one.
    signer: Option<crate::sign::AuditSigningKey>,
    /// The node every record this chain seals names ([`AuditRecord::node`]). See
    /// [`AuditChain::sealing_as`].
    node: u64,
    /// The anchors. See [`crate::heads`].
    heads: crate::heads::HeadHistory,
}

/// HAND-WRITTEN for the reason the retired admin chain writes its own: a DERIVED default gives
impl Default for AuditChain {
    fn default() -> Self {
        AuditChain::new()
    }
}

impl AuditChain {
    /// A chain with nothing in it.
    pub fn new() -> Self {
        AuditChain {
            tail_hash: String::new(),
            next_seq: 1,
            sealed: 0,
            signer: None,
            node: 0,
            heads: crate::heads::HeadHistory::new(),
        }
    }

    /// CONTINUE FROM THE RECORDS A PREDECESSOR SEALED, oldest first from the genesis, as the
    pub fn resume(sealed: &[AuditRecord]) -> Self {
        let mut chain = AuditChain::new();
        for record in sealed {
            chain.heads.observe(record);
        }
        if let Some(last) = sealed.last() {
            chain.tail_hash.clone_from(&last.hash);
            chain.next_seq = last.seq.saturating_add(1);
        }
        chain
    }

    /// SIGN FROM HERE ON, with this key.
    #[must_use]
    pub fn signing_with(mut self, key: crate::sign::AuditSigningKey) -> Self {
        self.signer = Some(key);
        self
    }

    /// A secret derived from the key this chain signs with, under `label`
    #[must_use]
    pub fn derived_secret(&self, label: &[u8]) -> Option<[u8; 32]> {
        self.signer.as_ref().map(|k| k.derived_secret(label))
    }

    /// A key derived from the deployment keyset seed this chain signs with, by HKDF-SHA256 under
    /// `salt` and `info` ([`crate::sign::AuditSigningKey::derived_key`]); `None` unsigned.
    #[must_use]
    pub fn derived_key(&self, salt: &[u8], info: &[u8]) -> Option<[u8; 32]> {
        self.signer.as_ref().map(|k| k.derived_key(salt, info))
    }

    /// SEAL AS THIS NODE from here on: every record names `node` ([`AuditRecord::node`]).
    #[must_use]
    pub fn sealing_as(mut self, node: u64) -> Self {
        self.node = node;
        self
    }

    /// The node this chain seals as.
    #[must_use]
    pub fn node(&self) -> u64 {
        self.node
    }

    /// The public half of the key this chain signs with, for the key-set read.
    pub fn public_key_hex(&self) -> Option<String> {
        self.signer.as_ref().map(|k| k.public_key_hex())
    }

    /// Sign one ledger checkpoint's body with THIS chain's key — the one keyset.
    pub fn sign_checkpoint_body(&self, body: &[u8]) -> Option<Vec<u8>> {
        self.signer.as_ref().map(|k| k.sign_checkpoint_body(body))
    }

    /// The anchors this node has published. See [`crate::heads`].
    pub fn heads(&self) -> &crate::heads::HeadHistory {
        &self.heads
    }

    /// Check one record's signature against one key.
    pub fn verify_signature(
        record: &AuditRecord,
        key: &crate::sign::AuditVerifyingKey,
    ) -> Result<(), crate::sign::KeyError> {
        let signature = record
            .signature
            .as_deref()
            .ok_or(crate::sign::KeyError::Unsigned)?;
        if AuditChain::digest_of(record) != record.hash {
            return Err(crate::sign::KeyError::DigestMismatch);
        }
        key.verify_digest(&record.hash, signature)
    }

    /// The position the next record will take.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// How many records this chain has sealed since it was built.
    pub fn sealed(&self) -> u64 {
        self.sealed
    }

    /// The digest of the most recent record.
    pub fn head(&self) -> &str {
        &self.tail_hash
    }

    /// Recompute one record's digest from its own fields — the verification primitive.
    pub fn digest_of(record: &AuditRecord) -> String {
        crate::recipe::digest_record(record)
    }

    /// VERIFY A WHOLE CHAIN: `records` is oldest-first and starts at the chain's genesis, so the
    pub fn verify_chain(records: &[AuditRecord]) -> Result<(), AuditBreak> {
        Self::walk(records, Anchor::Genesis)
    }

    /// VERIFY A WINDOW of a chain: the same walk, but the first record's position and link are
    pub fn verify_window(records: &[AuditRecord]) -> Result<(), AuditBreak> {
        Self::walk(records, Anchor::Window)
    }

    fn walk(records: &[AuditRecord], anchor: Anchor) -> Result<(), AuditBreak> {
        let Some(first) = records.first() else {
            return Ok(());
        };
        let (mut expected_prev, mut expected_seq): (&str, u64) = match anchor {
            Anchor::Genesis => ("", 1u64),
            Anchor::Window => (&first.prev_hash, first.seq),
        };
        for (i, record) in records.iter().enumerate() {
            if let Some(kind) =
                link_break(&record.prev_hash, record.seq, expected_prev, expected_seq)
            {
                return Err(AuditBreak {
                    at_index: i + 1,
                    kind,
                });
            }
            if AuditChain::digest_of(record) != record.hash {
                return Err(AuditBreak {
                    at_index: i + 1,
                    kind: AuditBreakKind::DigestMismatch,
                });
            }
            expected_prev = &record.hash;
            expected_seq = expected_seq.saturating_add(1);
        }
        Ok(())
    }
}

/// THE LINK AND THE POSITION, judged in that order and reported apart.
pub(crate) fn link_break(
    prev_hash: &str,
    seq: u64,
    expected_prev: &str,
    expected_seq: u64,
) -> Option<AuditBreakKind> {
    if prev_hash != expected_prev {
        Some(AuditBreakKind::LinkMismatch)
    } else if seq != expected_seq {
        Some(AuditBreakKind::SequenceMismatch {
            expected: expected_seq,
            found: seq,
        })
    } else {
        None
    }
}

/// Where a walk over a run of records starts from.
#[derive(Clone, Copy)]
enum Anchor {
    /// The chain's beginning: position one and an empty previous hash are required.
    Genesis,
    /// A window into a longer chain: the first record's position and link are taken as given, and
    Window,
}

impl sealed::Sealed for AuditChain {}

impl AuditChain {
    /// Prepare the unchanged signed preimage, retain its original journal
    /// custody, then advance the audit chain. A refused stage leaves no hole.
    pub fn seal_for_journal<T, E>(
        &mut self,
        inputs: AuditInputs,
        _token: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        stage: impl FnOnce(&AuditRecord) -> Result<T, E>,
    ) -> Result<(AuditRecord, T), E> {
        // One recipe for every new seal: v7 frames every quantity as exact decimal text, whole
        // or fractional, so there is no choice left to make (ADMIN-API-1.6 §3.2).
        let recipe = crate::recipe::Recipe::V7;
        let mut record = AuditRecord {
            subject: inputs.subject,
            what: inputs.what,
            wall: inputs.wall,
            mono: inputs.mono,
            node: self.node,
            origin_kind: inputs.origin.kind().as_str(),
            outcome: inputs.outcome,
            usage: inputs.usage,
            controls: inputs.controls,

            correlation_hash: inputs
                .correlation_label
                .as_deref()
                .map(|label| crate::digest::sha256_hex(label.as_bytes())),
            unit: inputs.unit,
            linked_ms: 0,
            seq: self.next_seq,
            prev_hash: std::mem::take(&mut self.tail_hash),
            recipe,
            hash: String::new(),
            signature: None,
            key_id: None,
        };
        record.hash = AuditChain::digest_of(&record);

        if let Some(signer) = &self.signer {
            record.key_id = Some(signer.key_id_shared());
            record.signature = Some(signer.sign_digest(&record.hash));
        }
        let custody = match stage(&record) {
            Ok(custody) => custody,
            Err(refused) => {
                // The chain did not advance: the refused record's prev_hash is the tail it took.
                self.tail_hash = std::mem::take(&mut record.prev_hash);
                return Err(refused);
            }
        };
        self.tail_hash.clone_from(&record.hash);
        self.next_seq = self.next_seq.saturating_add(1);
        self.sealed += 1;
        self.heads.observe(&record);
        Ok((record, custody))
    }
}
impl Audit for AuditChain {
    fn seal(
        &mut self,
        inputs: AuditInputs,
        token: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
    ) -> AuditRecord {
        match self.seal_for_journal(inputs, token, |_| Ok::<_, std::convert::Infallible>(())) {
            Ok((record, ())) => record,
            Err(never) => match never {},
        }
    }
}

/// Where a run of audit records stops verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditBreak {
    /// The one-based index into the run.
    pub at_index: usize,
    /// What is wrong.
    pub kind: AuditBreakKind,
}

/// What is wrong with a run of audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditBreakKind {
    /// A record's own fields do not hash to its stored digest: it was edited.
    DigestMismatch,
    /// A record does not point at its predecessor: something was inserted, removed or reordered.
    LinkMismatch,
    /// A record points at its predecessor but carries the wrong position: it was renumbered.
    SequenceMismatch {
        /// The position the walk expected.
        expected: u64,
        /// The position the record carries.
        found: u64,
    },
}

impl std::fmt::Display for AuditBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            AuditBreakKind::DigestMismatch => write!(
                f,
                "the audit record at index {} does not hash to its own fields — it was EDITED",
                self.at_index
            ),
            AuditBreakKind::LinkMismatch => write!(
                f,
                "the audit record at index {} does not point at its predecessor — a record was \
                 INSERTED, REMOVED or REORDERED here",
                self.at_index
            ),
            AuditBreakKind::SequenceMismatch { expected, found } => write!(
                f,
                "the audit record at index {} points at its predecessor but is numbered {found} \
                 where {expected} follows — it was RENUMBERED",
                self.at_index
            ),
        }
    }
}

impl std::error::Error for AuditBreak {}

/// The frozen text for one step name.
pub(crate) fn step_tag(step: StepName) -> &'static str {
    match step {
        StepName::Arrival => "Arrival",
        StepName::Decode => "Decode",
        StepName::Authenticate => "Authenticate",
        StepName::Verify => "Verify",
        StepName::Approve => "Approve",
        StepName::Admit => "Admit",
        StepName::Route => "Route",
        StepName::Meter => "Meter",
        StepName::Audit => "Audit",
        StepName::Encode => "Encode",
    }
}

/// The frozen text for one reason code: its wire name in upper camel case, written straight into
/// whatever formats it.
#[derive(Clone, Copy)]
pub(crate) struct ReasonTag(pub(crate) ReasonCode);

impl std::fmt::Display for ReasonTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        let mut start_of_word = true;
        for ch in self.0.as_str().chars() {
            if ch == '_' {
                start_of_word = true;
            } else if start_of_word {
                for upper in ch.to_uppercase() {
                    f.write_char(upper)?;
                }
                start_of_word = false;
            } else {
                f.write_char(ch)?;
            }
        }
        Ok(())
    }
}

/// The frozen text for an abort.
#[derive(Clone, Copy)]
pub(crate) struct AbortTag(pub(crate) Abort);

impl std::fmt::Display for AbortTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Abort::Kernel { reason } => write!(f, "Kernel {{ reason: {} }}", ReasonTag(reason)),
            Abort::Superseded { by } => write!(f, "Superseded {{ by: UnitKey({}) }}", by.get()),
        }
    }
}

/// The frozen text for how a unit ended.
#[derive(Clone, Copy)]
pub(crate) struct OutcomeTag(pub(crate) Outcome);

impl std::fmt::Display for OutcomeTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Outcome::Completed => f.write_str("Completed"),
            Outcome::Refused(step, reason) => {
                write!(f, "Refused({}, {})", step_tag(step), ReasonTag(reason))
            }
            Outcome::Failed(step, reason) => {
                write!(f, "Failed({}, {})", step_tag(step), ReasonTag(reason))
            }
            Outcome::Aborted(abort) => write!(f, "Aborted({})", AbortTag(abort)),
            Outcome::TimedOut(step) => write!(f, "TimedOut({})", step_tag(step)),
        }
    }
}

/// The frozen text for how a caller classified the finish.
pub(crate) fn finish_tag(finish: FinishClass) -> &'static str {
    match finish {
        FinishClass::Complete => "Complete",
        FinishClass::TurnComplete => "TurnComplete",
        FinishClass::Partial => "Partial",
        FinishClass::Error => "Error",
    }
}

/// The frozen text for which side of the unit a locator's value belongs to.
pub(crate) fn direction_tag(direction: busbar_contract::ClassDirection) -> &'static str {
    match direction {
        busbar_contract::ClassDirection::Input => "Input",
        busbar_contract::ClassDirection::Response => "Response",
        busbar_contract::ClassDirection::CacheRead => "CacheRead",
        busbar_contract::ClassDirection::CacheWrite => "CacheWrite",
        busbar_contract::ClassDirection::Kernel => "Kernel",
    }
}

/// The frozen text for where a usage line's quantity came from.
#[derive(Clone, Copy)]
pub(crate) struct QuantitySourceTag<'a>(pub(crate) &'a QuantitySource);

impl std::fmt::Display for QuantitySourceTag<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            QuantitySource::Locator { direction, ptr } => write!(
                f,
                "Locator {{ direction: {}, ptr: LocatorPtr({:?}) }}",
                direction_tag(*direction),
                ptr.as_str()
            ),
            QuantitySource::KernelBytes { divisor } => {
                write!(f, "KernelBytes {{ divisor: {divisor} }}")
            }
            QuantitySource::KernelFrames { factor } => {
                write!(f, "KernelFrames {{ factor: {factor} }}")
            }
            QuantitySource::TransportUnits => f.write_str("TransportUnits"),
            QuantitySource::KernelElapsedMono => f.write_str("KernelElapsedMono"),
            QuantitySource::Count => f.write_str("Count"),
            QuantitySource::PlaneCount { content_fact_key } => {
                write!(f, "PlaneCount {{ content_fact_key: {content_fact_key:?} }}")
            }
        }
    }
}

/// The frozen text for whose figure or content an entry concerns.
pub(crate) fn subject_tag(subject: &Subject) -> &'static str {
    match subject {
        Subject::PrincipalId(_) => "principal",
        Subject::Arrival => "arrival",
        Subject::Node(_) => "node",
        Subject::Aggregate => "aggregate",
    }
}

/// The value half of a subject: the principal, the node number, or nothing.
#[derive(Clone, Copy)]
pub(crate) struct SubjectValue<'a>(pub(crate) &'a Subject);

impl std::fmt::Display for SubjectValue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Subject::PrincipalId(p) => f.write_str(p),
            Subject::Arrival | Subject::Aggregate => Ok(()),
            Subject::Node(id) => write!(f, "{id}"),
        }
    }
}

/// Bytes as lowercase hexadecimal, written straight into whatever formats them.
#[derive(Clone, Copy)]
pub(crate) struct HexBytes<'a>(pub(crate) &'a [u8]);

impl std::fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Whether `value` formats as exactly `tag`, compared as it is written: nothing is built.
pub(crate) fn displays_as(value: impl std::fmt::Display, tag: &str) -> bool {
    /// Eats `rest` as the formatted text arrives; fails on the first byte that differs.
    struct Matcher<'a> {
        rest: &'a str,
    }
    impl std::fmt::Write for Matcher<'_> {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            match self.rest.strip_prefix(s) {
                Some(rest) => {
                    self.rest = rest;
                    Ok(())
                }
                None => Err(std::fmt::Error),
            }
        }
    }
    let mut matcher = Matcher { rest: tag };
    std::fmt::write(&mut matcher, format_args!("{value}")).is_ok() && matcher.rest.is_empty()
}

/// The tags as strings, for the tests that pin their frozen text.
#[cfg(test)]
pub(crate) fn reason_tag(reason: ReasonCode) -> String {
    ReasonTag(reason).to_string()
}

#[cfg(test)]
pub(crate) fn abort_tag(abort: Abort) -> String {
    AbortTag(abort).to_string()
}

#[cfg(test)]
pub(crate) fn outcome_tag(outcome: Outcome) -> String {
    OutcomeTag(outcome).to_string()
}

#[cfg(test)]
pub(crate) fn quantity_source_tag(source: &QuantitySource) -> String {
    QuantitySourceTag(source).to_string()
}

#[cfg(test)]
pub(crate) fn subject_value(subject: &Subject) -> String {
    SubjectValue(subject).to_string()
}
