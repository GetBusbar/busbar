// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit record: the same shape for every plane, with no exceptions.
//!
//! ## Why "fixed" is the point
//!
//! An audit whose shape varies by protocol is an audit an auditor cannot read. Somebody asking "what
//! happened at 14:32" gets a different set of fields depending on which door the request came in
//! through, and comparing two of them means reading two schemas. So the record is one shape, and a
//! plane contributes exactly TWO IDENTIFIERS to it: what kind of operation this was, and how it
//! finished. Everything else is the same for everybody.
//!
//! ## Six groups, because they answer six different questions
//!
//! WHO, WHAT, WHEN, OUTCOME, AMOUNT, CONTROLS, and the link to the record before. They are grouped
//! rather than flattened because the groups are what a reader actually asks for: an incident asks
//! who and what, a billing dispute asks amount, and a compliance review asks controls.
//!
//! ## Content is never in here
//!
//! Not the request, not the response, not a fragment of either. The correlation LABEL is hashed, and
//! the record carries the hash. This is not squeamishness: the journal is a financial record that is
//! exempt from erasure, so anything put in it can never be taken out, and a prompt in a record that
//! cannot be deleted is a promise nobody can keep. Content facts flow to export plugins, which are a
//! different seam with a different lifetime — and every one of those accesses is itself an entry,
//! which is what [`crate::amend`] is for.

use busbar_caps::{Abort, Origin, Outcome, ReasonCode, StepName, UnitKey};

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

/// An identifier a plane supplies for the kind of operation performed.
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

/// How a unit finished, as the plane sees it. The second and last thing a plane contributes.
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
    /// What kind of operation, as the plane names it.
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
    /// How it finished, as the plane classifies it.
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
pub use busbar_caps::{QuantitySource, UsageLine};

/// WHAT IT COST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amount {
    /// The quantities, with their sources.
    pub lines: Vec<UsageLine>,
    /// What it came to before the tier was applied, in nano-units.
    pub pre_tier: i128,
    /// And after — the figure the money moved by.
    pub priced: i128,
    /// The tier applied, in basis points.
    pub tier_bp: u32,
    /// How many request fees were charged.
    pub fee_count: u32,
    /// Which currency the nano-units are of.
    pub currency: String,
    /// Which rate card version priced it.
    pub rate_card_version: u64,
    /// Which chain of buckets it was drawn against.
    pub bucket_chain_ref: String,
}

/// One hook that ran, and what it cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookApplied {
    /// Which hook.
    pub hook: String,
    /// How much it changed the priced amount by, in nano-units.
    pub priced_delta: i128,
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
    /// Every hook that ran, and what it cost.
    pub hooks_applied: Vec<HookApplied>,
    /// Whether this unit was answered from a replay rather than performed.
    pub replayed: bool,
    /// The units this one caused.
    pub children: Vec<UnitKey>,
}

/// One audit record: the same shape for every plane.
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
    /// WHAT IT COST.
    pub amount: Amount,
    /// THE CONTROLS.
    pub controls: Controls,
    /// The digest of the correlation label, never the label itself.
    pub correlation_hash: Option<String>,
    /// The preceding record's digest.
    pub prev_hash: String,
    /// This record's own digest.
    pub hash: String,
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
    /// WHAT IT COST.
    pub amount: Amount,
    /// THE CONTROLS.
    pub controls: Controls,
    /// The correlation label, which is HASHED on the way in and never stored.
    pub correlation_label: Option<String>,
}

/// The audit unit: it seals records, and it is the only thing that can.
///
/// The token is the point. A plane can say what it saw and a hook can say what it did, but turning
/// either into a record that goes on the chain takes the audit step's own token, which the loop
/// hands out for the length of one call. So a record on the chain is a record the audit unit made.
pub trait Audit {
    /// Seal one record onto the chain.
    fn seal(
        &mut self,
        inputs: AuditInputs,
        token: &busbar_caps::UnitToken<busbar_caps::Audit>,
    ) -> AuditRecord;
}

/// The chain of fixed audit records.
///
/// A separate chain from the previous release's, deliberately. They record different things at
/// different rates, and pouring one into the other would make a busy hour of request-rate records
/// evict the operator-rate ones — silently, because a pruned ring looks exactly like one that was
/// never written to.
#[derive(Debug, Default)]
pub struct AuditChain {
    tail_hash: String,
    next_seq: u64,
    sealed: u64,
}

impl AuditChain {
    /// A chain with nothing in it.
    pub fn new() -> Self {
        AuditChain {
            tail_hash: String::new(),
            next_seq: 1,
            sealed: 0,
        }
    }

    /// Continue from a persisted tail.
    pub fn resume(tail_hash: String, next_seq: u64) -> Self {
        AuditChain {
            tail_hash,
            next_seq,
            sealed: 0,
        }
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
        let mut d = crate::legacy::Digest::new(crate::legacy::Framing::LengthPrefixed);
        // Length-prefixed, because this record is NEW. Every field here can hold arbitrary text —
        // a bucket chain reference, an operation class a plane named — and a separator-joined digest
        // is only safe while no field can contain the separator. Length prefixes make the boundary
        // unforgeable whatever the fields hold.
        d.text(&record.prev_hash);
        d.text(subject_tag(&record.subject));
        d.text(&subject_value(&record.subject));
        d.num(record.what.unit_key.get());
        d.text(record.what.op_class.as_str());
        d.text(record.what.destination.as_deref().unwrap_or(""));
        d.num(record.what.parent.map(|p| p.get()).unwrap_or(0));
        d.text(record.what.pre_hook_head.as_deref().unwrap_or(""));
        d.text(record.what.post_hook_head.as_deref().unwrap_or(""));
        d.num(record.wall);
        d.num(record.mono);
        d.text(record.origin_kind);
        d.text(&outcome_tag(record.outcome.unit_end));
        d.text(
            &record
                .outcome
                .step
                .map(|s| s.as_str().to_string())
                .unwrap_or_default(),
        );
        d.text(finish_tag(record.outcome.finish));
        d.num(u64::from(record.outcome.hook_failed));
        d.text(&record.outcome.emission_delta.to_string());
        d.num(u64::from(record.outcome.stale_policy));
        d.num(record.amount.lines.len() as u64);
        for line in &record.amount.lines {
            d.text(line.class.as_str());
            d.num(line.quantity);
            d.text(&quantity_source_tag(&line.source));
            d.num(u64::from(line.estimated));
        }
        d.text(&record.amount.pre_tier.to_string());
        d.text(&record.amount.priced.to_string());
        d.num(u64::from(record.amount.tier_bp));
        d.num(u64::from(record.amount.fee_count));
        d.text(&record.amount.currency);
        d.num(record.amount.rate_card_version);
        d.text(&record.amount.bucket_chain_ref);
        d.text(record.controls.hold_ref.as_deref().unwrap_or(""));
        d.text(record.controls.settle_ref.as_deref().unwrap_or(""));
        d.text(record.controls.slice_ref.as_deref().unwrap_or(""));
        d.text(record.controls.lease_ref.as_deref().unwrap_or(""));
        d.num(record.controls.lease_epoch);
        d.num(record.controls.policy_epoch);
        d.num(record.controls.hooks_applied.len() as u64);
        for hook in &record.controls.hooks_applied {
            d.text(&hook.hook);
            d.text(&hook.priced_delta.to_string());
        }
        d.num(u64::from(record.controls.replayed));
        d.num(record.controls.children.len() as u64);
        for child in &record.controls.children {
            d.num(child.get());
        }
        d.text(record.correlation_hash.as_deref().unwrap_or(""));
        d.finish()
    }

    /// Whether a run of records links and digests correctly, oldest first.
    pub fn verify(records: &[AuditRecord]) -> Result<(), AuditBreak> {
        let mut expected_prev = records
            .first()
            .map(|r| r.prev_hash.clone())
            .unwrap_or_default();
        for (i, record) in records.iter().enumerate() {
            if record.prev_hash != expected_prev {
                return Err(AuditBreak {
                    at_index: i + 1,
                    kind: AuditBreakKind::LinkMismatch,
                });
            }
            if AuditChain::digest_of(record) != record.hash {
                return Err(AuditBreak {
                    at_index: i + 1,
                    kind: AuditBreakKind::DigestMismatch,
                });
            }
            expected_prev = record.hash.clone();
        }
        Ok(())
    }
}

impl Audit for AuditChain {
    fn seal(
        &mut self,
        inputs: AuditInputs,
        _token: &busbar_caps::UnitToken<busbar_caps::Audit>,
    ) -> AuditRecord {
        let mut record = AuditRecord {
            subject: inputs.subject,
            what: inputs.what,
            wall: inputs.wall,
            mono: inputs.mono,
            origin_kind: inputs.origin.kind().as_str(),
            outcome: inputs.outcome,
            amount: inputs.amount,
            controls: inputs.controls,
            // The label is hashed here and dropped. There is no path from this function that keeps
            // it, which is what "content never enters the chain" has to mean to be worth saying.
            correlation_hash: inputs
                .correlation_label
                .as_deref()
                .map(|label| crate::legacy::sha256_hex(label.as_bytes())),
            prev_hash: self.tail_hash.clone(),
            hash: String::new(),
        };
        record.hash = AuditChain::digest_of(&record);
        self.tail_hash = record.hash.clone();
        self.next_seq = self.next_seq.saturating_add(1);
        self.sealed += 1;
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
    match abort {
        Abort::Client => "Client".to_string(),
        Abort::Kernel { reason } => format!("Kernel {{ reason: {} }}", reason_tag(reason)),
        Abort::Drain => "Drain".to_string(),
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

/// The frozen text for how a plane classified the finish.
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

fn subject_tag(subject: &Subject) -> &'static str {
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
fn subject_value(subject: &Subject) -> String {
    match subject {
        Subject::PrincipalId(p) => p.clone(),
        Subject::Arrival | Subject::Aggregate => String::new(),
        Subject::Node(id) => id.to_string(),
    }
}
