// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit record: the same shape for every caller, with no exceptions.
//!
//! ## Why "fixed" is the point
//!
//! An audit whose shape varies by the door it came in through is an audit an auditor cannot read.
//! Somebody asking "what happened at 14:32" gets a different set of fields depending on which door
//! the request came in through, and comparing two of them means reading two schemas. So the record
//! is one shape, and a caller contributes exactly TWO IDENTIFIERS to it: what kind of operation this
//! was, and how it finished. Everything else is the same for everybody.
//!
//! ## Six groups, because they answer six different questions
//!
//! WHO, WHAT, WHEN, OUTCOME, USAGE, CONTROLS, and the link to the record before. They are grouped
//! rather than flattened because the groups are what a reader actually asks for: an incident asks
//! who and what, a billing dispute asks usage, and a compliance review asks controls.
//!
//! ## A price is never in here either
//!
//! The record carries COUNTS and the provenance a read-time price needs — the tier, the fee count,
//! the rate card version — and never a priced figure (#43, #71, #77(3)). Money is a view on the
//! ledger and the rate card, computed when it is read through the one function
//! (`busbar_kernel_ledger::cost::Tally`); a figure sealed here would be a second copy of that
//! answer, frozen at seal time, that no correction to the card could ever reach.
//!
//! ## Content is never in here
//!
//! Not the request, not the response, not a fragment of either. The correlation LABEL is hashed, and
//! the record carries the hash. This is not squeamishness: the journal is a financial record that is
//! exempt from erasure, so anything put in it can never be taken out, and a prompt in a record that
//! cannot be deleted is a promise nobody can keep. Content facts flow to export plugins, which are a
//! different seam with a different lifetime — and every one of those accesses is itself an entry,
//! which is what [`crate::amend`] is for.

use busbar_contract::caps::{Abort, Origin, Outcome, ReasonCode, StepName, UnitKey};

/// Whose activity this is.
///
/// A resolved principal appears as a pseudonym, never as an identifier a reader could resolve on
/// their own. An arrival that never resolved to anybody is recorded as an arrival, because "nobody
/// authenticated" is itself a fact worth keeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// A resolved principal, as a pseudonym.
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
///
/// The source travels with the quantity because a figure the destination confirmed and a figure the
/// node estimated are not the same evidence, and a billing dispute turns on exactly that
/// difference. Both the line and its provenance are the capability crate's own: this record is the
/// sealed copy of what the usage unit folded, and a record that spelled the provenance differently
/// from the fold that produced it could not be checked against it. The audit crate carried a
/// four-arm reading of the design's seven-arm set; those four are the first four of the seven,
/// unchanged in meaning.
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
    /// Which currency the nano-units are of.
    pub currency: String,
    /// Which rate card version was in force — the card a read-time price is taken at.
    pub rate_card_version: u64,
    /// Which chain of buckets it was drawn against.
    pub bucket_chain_ref: String,
}

/// One hook that ran.
///
/// Which hook, and nothing priced: what a hook changed is in the counts it changed, and those are
/// the usage lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookApplied {
    /// Which hook.
    pub hook: String,
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
/// they are not on the previous release's record: the chain owns them.
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
/// A separate chain from the previous release's, deliberately. They record different things at
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
    /// The anchors, kept forever. See [`crate::heads`].
    heads: crate::heads::HeadHistory,
}

/// HAND-WRITTEN for the reason the previous release's chain writes its own: a DERIVED default gives
/// a next position of zero, which is not a position a chain has, and the position is now DIGESTED
/// into every record — so a silently zero-based chain would seal records that a verifier walking
/// from the genesis rejects. It delegates to the one real constructor so the two cannot drift.
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
            heads: crate::heads::HeadHistory::new(),
        }
    }

    /// Continue from a persisted tail.
    pub fn resume(tail_hash: String, next_seq: u64) -> Self {
        AuditChain {
            tail_hash,
            next_seq,
            sealed: 0,
            signer: None,
            heads: crate::heads::HeadHistory::new(),
        }
    }

    /// SIGN FROM HERE ON, with this key.
    ///
    /// A builder rather than a constructor argument, so that a node that was given no key keeps the
    /// shape it had and a node that was given one says so in one place. Records sealed BEFORE this
    /// was called stay unsigned, which is the truth about them.
    ///
    /// Signing is in-process and at seal time, because that is the only moment at which a signature
    /// means "this node produced this record". See [`crate::sign`].
    #[must_use]
    pub fn signing_with(mut self, key: crate::sign::AuditSigningKey) -> Self {
        self.signer = Some(key);
        self
    }

    /// Sample heads at a chosen rate instead of hourly. See [`crate::heads::HeadHistory::every`].
    #[must_use]
    pub fn sampling_heads_every(mut self, seconds: u64) -> Self {
        self.heads = crate::heads::HeadHistory::every(seconds);
        self
    }

    /// Which key this chain signs with, by identifier. `None` on a node that seals unsigned.
    ///
    /// The identifier, never the key: there is no accessor on this type that yields key material,
    /// and adding one would defeat [`crate::sign::AuditSigningKey`]'s whole shape.
    pub fn signing_key_id(&self) -> Option<&str> {
        self.signer.as_ref().map(|k| k.key_id())
    }

    /// The public half of the key this chain signs with, for the key-set read.
    pub fn public_key_hex(&self) -> Option<String> {
        self.signer.as_ref().map(|k| k.public_key_hex())
    }

    /// Sign one ledger checkpoint's body with THIS chain's key — the one keyset (Q71(3), #82).
    ///
    /// `None` on a node that seals unsigned: its checkpoints are sealed unsigned too, which is the
    /// truth about them, and no second key is ever looked for.
    pub fn sign_checkpoint_body(&self, body: &[u8]) -> Option<Vec<u8>> {
        self.signer.as_ref().map(|k| k.sign_checkpoint_body(body))
    }

    /// The anchors this node has published, kept forever. See [`crate::heads`].
    pub fn heads(&self) -> &crate::heads::HeadHistory {
        &self.heads
    }

    /// THE RETENTION PASS over sealed records, and the reason it takes `&self`.
    ///
    /// The predicate is the one every store in this tree already applies — a record whose own
    /// instant is before the cutoff goes — spelled once, here, by the unit that owns the records
    /// rather than separately by each thing that holds some.
    ///
    /// `&self`, NOT `&mut self`, AND THAT IS THE GUARANTEE. The head history lives on this type;
    /// a pass that cannot borrow the chain mutably cannot prune it, whatever a later edit to this
    /// function's body tries to do. Phrased as a comment it would be a request; phrased as the
    /// receiver it is a compile error. A puller that was offline across this cutoff has lost the
    /// records, which was the deal, and still has the anchor, which was never on the table.
    ///
    /// Returns how many records went.
    pub fn prune_records_before(&self, records: &mut Vec<AuditRecord>, before: u64) -> usize {
        let was = records.len();
        records.retain(|r| r.wall >= before);
        was - records.len()
    }

    /// Check one record's signature against one key.
    ///
    /// Two judgements, not one: that the record hashes to its own fields (which is what the chain
    /// walk checks) and that the signature over that hash verifies. A signature checked against a
    /// hash nobody recomputed is a signature over a number, not over a record — an editor who
    /// rewrote a field and left the old hash and the old signature in place would pass.
    ///
    /// # Errors
    ///
    /// The record carries no signature, the record does not hash to its own fields, or the
    /// signature does not verify.
    pub fn verify_signature(
        record: &AuditRecord,
        key: &crate::sign::AuditVerifyingKey,
    ) -> Result<(), crate::sign::KeyError> {
        let signature = record
            .signature
            .as_deref()
            .ok_or(crate::sign::KeyError::Unsigned)?;
        if AuditChain::digest_of(record) != record.hash {
            return Err(crate::sign::KeyError::BadSignature);
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
    ///
    /// ONE RECIPE, and this walks it. The field order, the framing and the exact spelling of every
    /// value live in [`crate::recipe::digest_fields`], which is also what the range read publishes
    /// and what `docs/audit-chain-digest-v2.md` describes. Before, the order lived here and the
    /// document described it from the outside — two copies of one contract, and the one thing a
    /// published digest recipe cannot survive is two spellings of itself: a drift between them
    /// would make every third-party verification fail while looking, to the third party, exactly
    /// like a tampered chain.
    ///
    /// LENGTH-PREFIXED, not separator-joined, and that survives the move. Every field here can hold
    /// arbitrary text — a bucket chain reference, an operation class a caller named — and a
    /// separator-joined digest is only safe while no field can contain the separator. Length
    /// prefixes make the boundary unforgeable whatever the fields hold.
    ///
    /// The frozen hex in `the_sealed_digest_of_a_fully_populated_record_is_the_frozen_hex` is what
    /// says the move did not cost a byte.
    pub fn digest_of(record: &AuditRecord) -> String {
        crate::recipe::digest_over(&crate::recipe::digest_fields(record))
    }

    /// VERIFY A WHOLE CHAIN: `records` is oldest-first and starts at the chain's genesis, so the
    /// first position must be one and the first previous hash must be empty.
    ///
    /// That is what catches a HEAD truncation. A run whose oldest records were dropped links
    /// perfectly to itself — every remaining record still names the one before it — and the only
    /// thing that says records are missing is that the run does not begin where the chain does.
    ///
    /// An EMPTY run verifies, deliberately and for the same reason the previous release's chain
    /// says so: "this chain has no records" and "every record was deleted" are indistinguishable
    /// from the records alone, and claiming otherwise would claim a guarantee this cannot provide.
    pub fn verify_chain(records: &[AuditRecord]) -> Result<(), AuditBreak> {
        Self::walk(records, Anchor::Genesis)
    }

    /// VERIFY A WINDOW of a chain: the same walk, but the first record's position and link are
    /// taken as given rather than required to be the genesis.
    ///
    /// This is for a run read out of a bounded store, where the oldest retained record's
    /// predecessor was legitimately pruned. Everything after that first record is checked exactly
    /// as [`Self::verify_chain`] checks it — contiguous positions, matching links, matching
    /// digests — so a cut anywhere INSIDE the window is still caught. It is a separate entry point
    /// rather than a lenient default: a caller holding a whole chain that called this would be
    /// silently excusing a missing head.
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

    /// Whether a run of records ENDING AT THIS CHAIN'S HEAD is whole: the walk from the genesis,
    /// plus the check the walk cannot make on its own — that the last record in the run is the last
    /// record the chain sealed. A tail truncation is invisible to any verifier reading only the
    /// records, because the survivors link and number correctly among themselves; it takes the
    /// chain's own head to notice.
    pub fn verify_to_head(&self, records: &[AuditRecord]) -> Result<(), AuditBreak> {
        Self::verify_chain(records)?;
        let (tail_hash, tail_seq) = records
            .last()
            .map(|r| (r.hash.as_str(), r.seq))
            .unwrap_or(("", 0));
        if tail_hash != self.tail_hash || tail_seq.saturating_add(1) != self.next_seq {
            return Err(AuditBreak {
                at_index: records.len(),
                kind: AuditBreakKind::LinkMismatch,
            });
        }
        Ok(())
    }
}

/// THE LINK AND THE POSITION, judged in that order and reported apart (item 405).
///
/// The LINK first: a record missing, inserted or reordered breaks it, and at either end of a cut
/// the position breaks too — so checking the link first names the real defect ("something is
/// missing here") for every splice. The POSITION second, and as its own kind: a record that names
/// its predecessor correctly but carries the wrong number was RENUMBERED, and saying it "does not
/// point at its predecessor" would be false — it does. The operator's response to a renumbering is
/// not the response to a splice, so the two do not share a kind. The amendment chain's walk judges
/// its links through this same function.
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
    /// only its own digest is checked.
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
            origin_kind: inputs.origin.kind().as_str(),
            outcome: inputs.outcome,
            usage: inputs.usage,
            controls: inputs.controls,
            // The label is hashed here and dropped. There is no path from this function that keeps
            // it, which is what "content never enters the chain" has to mean to be worth saying.
            correlation_hash: inputs
                .correlation_label
                .as_deref()
                .map(|label| crate::legacy::sha256_hex(label.as_bytes())),
            seq: self.next_seq,
            prev_hash: self.tail_hash.clone(),
            hash: String::new(),
            signature: None,
            key_id: None,
        };
        record.hash = AuditChain::digest_of(&record);
        // THE SIGNATURE, HERE AND NOWHERE ELSE.
        //
        // Position: immediately after the digest and before the head advances, so the thing signed
        // is the digest this chain is about to adopt as its head. One signature per SEALED RECORD —
        // which is one per finished unit, at the audit step, after the response has been produced —
        // and not one per frame, per token or per byte. The serving path does not reach this
        // function; nothing on it signs anything.
        //
        // No key configured is not an error and not a panic: it is an unsigned record, and a record
        // that says it is unsigned is honest. See `crate::sign` for why nothing back-fills it.
        if let Some(signer) = &self.signer {
            record.key_id = Some(signer.key_id().to_string());
            record.signature = Some(signer.sign_digest(&record.hash));
        }
        self.tail_hash = record.hash.clone();
        self.next_seq = self.next_seq.saturating_add(1);
        self.sealed += 1;
        // The anchor is taken from the finished record, so a head always carries the signature the
        // record carries rather than a second one minted over the same digest.
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

// ── THE TAGS THE DIGEST FREEZES ──────────────────────────────────────────────────────────────────
//
// Three of the digested fields are enumerations, and their text used to be whatever the derived
// `Debug` printed. That made every persisted chain hostage to a derive: renaming a variant, adding a
// field to one, or a future compiler changing how it renders a struct variant would all move the
// sealed hash, and a moved hash makes every stored record report itself as TAMPERED at the next
// boot. None of those are changes anybody would expect to have that effect.
//
// So the text is written out here instead. The spellings are the ones the chain already froze —
// they are deliberately the derive's spellings, because reproducing what is on disk is the whole
// point — but they are now a decision in this file rather than a side effect somewhere else. A test
// checks each one against today's `Debug` so that a rename is reported as a difference to look at
// rather than applied silently to the hash.

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
/// chain froze.
///
/// Derived from the wire name rather than written out as fifty match arms, because the reason list
/// is open — it carries `#[non_exhaustive]`, so no match here could ever cover it — and because the
/// relation "the frozen tag is the wire name in upper camel case" is a single rule a test can check
/// against every declared reason at once. A reason added tomorrow gets the right tag by the same
/// rule instead of falling into a catch-all arm that would digest two different reasons identically.
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
    // A client that went away and a node that is draining both arrive as a kernel abort with a
    // named reason, so the tag carries the reason rather than a variant of its own.
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
///
/// The locator's pointer keeps the quoting the chain froze — a quoted, escaped string — which is the
/// library's own rendering of a text value and not a derive's rendering of a type.
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
///
/// Two fields — a tag and a value — rather than one, so that a principal whose pseudonym happened to
/// read as "node" could not be confused with a node. The node's number is IN the value, because
/// leaving it out would let two nodes' records digest identically.
pub(crate) fn subject_value(subject: &Subject) -> String {
    match subject {
        Subject::PrincipalId(p) => p.clone(),
        Subject::Arrival | Subject::Aggregate => String::new(),
        Subject::Node(id) => id.to_string(),
    }
}
