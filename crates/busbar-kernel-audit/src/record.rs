// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit record: the same shape for every caller, with no exceptions.

use busbar_contract::caps::{Abort, Origin, Outcome, ReasonCode, StepName, UnitKey};

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
    /// Every record this build seals is [`crate::recipe::Recipe::V5`]; a record sealed
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
    pub key_id: Option<String>,
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
    tail_hash: String,
    next_seq: u64,
    sealed: u64,
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
            chain.tail_hash = last.hash.clone();
            chain.next_seq = last.seq.saturating_add(1);
        }
        chain
    }

    /// Restore the independently retained anchors after reading the journal's remaining records.
    pub fn retaining_heads(
        mut self,
        heads: crate::heads::HeadHistory,
    ) -> Result<Self, &'static str> {
        if let Some(observed) = self.heads.tip() {
            let retained = heads
                .tip()
                .ok_or("retained audit history has no journal tip")?;
            if observed.seq > retained.seq || observed.seq == retained.seq && observed != retained {
                return Err("retained audit head disagrees with the journal");
            }
        }
        if let Some(tip) = heads.tip() {
            self.tail_hash = tip.hash.clone();
            self.next_seq = tip
                .seq
                .checked_add(1)
                .ok_or("audit head sequence is exhausted")?;
        }
        self.heads = heads;
        Ok(self)
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

    /// Which key this chain signs with, by identifier. `None` on a node that seals unsigned.
    pub fn signing_key_id(&self) -> Option<&str> {
        self.signer.as_ref().map(|k| k.key_id())
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
        crate::recipe::digest_over(&crate::recipe::digest_fields(record))
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
        let (mut expected_prev, mut expected_seq) = match anchor {
            Anchor::Genesis => (String::new(), 1u64),
            Anchor::Window => (first.prev_hash.clone(), first.seq),
        };
        for (i, record) in records.iter().enumerate() {
            if let Some(kind) =
                link_break(&record.prev_hash, record.seq, &expected_prev, expected_seq)
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
            expected_prev = record.hash.clone();
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
enum Anchor {
    /// The chain's beginning: position one and an empty previous hash are required.
    Genesis,
    /// A window into a longer chain: the first record's position and link are taken as given, and
    Window,
}

impl sealed::Sealed for AuditChain {}

impl Audit for AuditChain {
    fn seal(
        &mut self,
        inputs: AuditInputs,
        _token: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
    ) -> AuditRecord {
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
            seq: self.next_seq,
            prev_hash: self.tail_hash.clone(),
            recipe: crate::recipe::Recipe::V5,
            hash: String::new(),
            signature: None,
            key_id: None,
        };
        record.hash = AuditChain::digest_of(&record);

        if let Some(signer) = &self.signer {
            record.key_id = Some(signer.key_id().to_string());
            record.signature = Some(signer.sign_digest(&record.hash));
        }
        self.tail_hash = record.hash.clone();
        self.next_seq = self.next_seq.saturating_add(1);
        self.sealed += 1;

        self.heads.observe(&record);
        record
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

/// The frozen text for one reason code: its wire name in upper camel case, which is exactly what the
pub(crate) fn reason_tag(reason: ReasonCode) -> String {
    let mut out = String::with_capacity(reason.as_str().len());
    let mut start_of_word = true;
    for ch in reason.as_str().chars() {
        if ch == '_' {
            start_of_word = true;
        } else if start_of_word {
            out.extend(ch.to_uppercase());
            start_of_word = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// The frozen text for how a unit was cut short.
pub(crate) fn abort_tag(abort: Abort) -> String {
    match abort {
        Abort::Kernel { reason } => format!("Kernel {{ reason: {} }}", reason_tag(reason)),
        Abort::Superseded { by } => format!("Superseded {{ by: UnitKey({}) }}", by.get()),
    }
}

/// The frozen text for how a unit ended.
pub(crate) fn outcome_tag(outcome: Outcome) -> String {
    match outcome {
        Outcome::Completed => "Completed".to_string(),
        Outcome::Refused(step, reason) => {
            format!("Refused({}, {})", step_tag(step), reason_tag(reason))
        }
        Outcome::Failed(step, reason) => {
            format!("Failed({}, {})", step_tag(step), reason_tag(reason))
        }
        Outcome::Aborted(abort) => format!("Aborted({})", abort_tag(abort)),
        Outcome::TimedOut(step) => format!("TimedOut({})", step_tag(step)),
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

/// The frozen text for where one reported quantity came from.
pub(crate) fn quantity_source_tag(source: &QuantitySource) -> String {
    match source {
        QuantitySource::Locator { direction, ptr } => format!(
            "Locator {{ direction: {}, ptr: LocatorPtr({:?}) }}",
            direction_tag(*direction),
            ptr.as_str()
        ),
        QuantitySource::KernelBytes { divisor } => format!("KernelBytes {{ divisor: {divisor} }}"),
        QuantitySource::KernelFrames { factor } => format!("KernelFrames {{ factor: {factor} }}"),
        QuantitySource::TransportUnits => "TransportUnits".to_string(),
        QuantitySource::KernelElapsedMono => "KernelElapsedMono".to_string(),
        QuantitySource::Count => "Count".to_string(),
        QuantitySource::PlaneCount { content_fact_key } => {
            format!("PlaneCount {{ content_fact_key: {content_fact_key:?} }}")
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

/// The subject's own identifier, as one text field.
pub(crate) fn subject_value(subject: &Subject) -> String {
    match subject {
        Subject::PrincipalId(p) => p.clone(),
        Subject::Arrival | Subject::Aggregate => String::new(),
        Subject::Node(id) => id.to_string(),
    }
}
