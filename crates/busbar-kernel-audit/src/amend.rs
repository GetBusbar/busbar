// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two amendment classes: an access, and an adjustment.
//!
//! ## Access — every time somebody outside the node reads content
//!
//! Content never enters the chain, but it does leave the node: a hook sees it, an export plugin
//! receives it. Each of those is a disclosure, and a disclosure that leaves no record is a
//! disclosure nobody can answer questions about later. So every hook or export content access is an
//! entry of its own, naming who read what and why, and — deliberately — not what they read.
//!
//! The record is small on purpose. It is written at request rate, so anything expensive in it would
//! be a reason to turn it off, and an audit that gets turned off under load is an audit that is not
//! there when it matters.
//!
//! ## Adjust — every time a figure that was already recorded changes
//!
//! A journal is append-only, so a figure is never corrected in place; a correction is a NEW entry
//! that names the old one and says what it is now. That is what makes an adjustment visible: there
//! is no state in which the original amount has quietly become something else. The amendment carries
//! what it was, what it is, who authorised it, and — because a correction that nobody can question is
//! a correction nobody should trust — the reason.
//!
//! **What an adjustment carries is COUNTS, never money** (owner ruling Q9, #71, #43): money is a
//! read-time view on the ledger × the rate card, so the figure a correction changes is the unit's
//! raw count per billable class, and the amendment names the CARD EPOCH — the instant whose card
//! those counts price at (#79). The corrected money is then what the one function
//! (the ledger's `cost::Tally`) derives from the corrected counts at that card; a money
//! figure sealed here would be a second copy of that answer that no later card correction could
//! reach. A correction that would take any count below zero is REFUSED ([`CorrectionRefused`]):
//! a negative measurement is not a thing a meter reports.
//!
//! **An adjustment names the POOL its unit was dispatched through** (owner ruling Q64/Q67), so a
//! pool-scoped budget bucket takes the correction as well as the group-wide ones. The field is
//! OPTIONAL on the record and only in that one sense: an adjustment sealed before it existed cannot
//! be rewritten (it is hash-chained), so it reads as UNSCOPED — group-wide buckets only, exactly as
//! it always did — and its digest is the one it was sealed with. A new correction always names one.
//!
//! ## Why these are amendments rather than fields on the audit record
//!
//! Both happen at a different time from the unit they concern, and often more than once. Folding
//! them into the unit's own record would mean either rewriting that record — which the whole design
//! exists to prevent — or waiting to write it until nothing further could happen, which is never.

use crate::record::{subject_tag, subject_value, OpClassId, Subject};
use busbar_contract::{
    authz::Scope,
    caps::{Audit, Pass},
    count::Count,
};
use std::collections::{BTreeMap, VecDeque};

/// A unit's counts, keyed by the billable class string the plane declared (#71).
pub type ClassCounts = BTreeMap<String, Count>;

/// Which class of amendment this is.
///
/// The two names are the two the journal knows. Keeping them as a closed pair rather than an open
/// string is what stops a third meaning being invented at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmendClass {
    /// Somebody outside the node read content.
    Access,
    /// A figure that was already recorded changed.
    Adjust,
}

impl AmendClass {
    /// The word this class is written as.
    pub fn as_str(self) -> &'static str {
        match self {
            AmendClass::Access => "access",
            AmendClass::Adjust => "adjust",
        }
    }
}

impl AmendClass {
    /// The class written as `word`, or `None` for a word the journal does not know.
    pub fn parse(word: &str) -> Option<AmendClass> {
        [AmendClass::Access, AmendClass::Adjust]
            .into_iter()
            .find(|c| c.as_str() == word)
    }
}

impl std::fmt::Display for AmendClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of thing reached for the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    /// A hook, running inside the unit.
    Hook,
    /// An export plugin, receiving facts on its way off the node.
    Export,
}

impl Reader {
    /// The word this reader is written as.
    pub fn as_str(self) -> &'static str {
        match self {
            Reader::Hook => "hook",
            Reader::Export => "export",
        }
    }

    /// The reader written as `word`, or `None` for a word the journal does not know.
    pub fn parse(word: &str) -> Option<Reader> {
        [Reader::Hook, Reader::Export]
            .into_iter()
            .find(|r| r.as_str() == word)
    }
}

/// A subject as the two frozen fields an amendment digests it by: its tag, then its identifier.
/// The pair a durable record of the amendment carries, so reading it back reproduces the digest.
pub fn subject_fields(subject: &Subject) -> (&'static str, String) {
    (subject_tag(subject), subject_value(subject))
}

/// The subject [`subject_fields`] wrote, or `None` for a pair it never writes.
pub fn subject_from_fields(tag: &str, value: &str) -> Option<Subject> {
    let subject = match tag {
        "principal" => Subject::PrincipalId(value.to_string()),
        "arrival" => Subject::Arrival,
        "node" => Subject::Node(value.parse().ok()?),
        "aggregate" => Subject::Aggregate,
        _ => return None,
    };
    (subject_fields(&subject).1 == value).then_some(subject)
}

/// One content access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// What kind of thing read it.
    pub reader: Reader,
    /// Which one, by name.
    pub name: String,
    /// Whose content it was.
    pub subject: Subject,
    /// What kind of operation the content belonged to.
    pub op_class: OpClassId,
    /// Which fields were reached for. Field NAMES, never their values.
    pub fields: Vec<String>,
    /// When, in unix seconds.
    pub wall: u64,
}

/// One correction to counts that were already recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjust {
    /// Which entry is being corrected, by its digest.
    pub amends_hash: String,
    /// Whose counts they are.
    pub subject: Subject,
    /// The lane the counts were recorded on — the key a card entry is written against.
    pub lane: String,
    /// THE CARD EPOCH: the instant, in milliseconds, whose card the counts price at (#79). A
    /// correction changes a count, never the card it prices against, so this is carried unchanged.
    pub card_epoch_ms: u64,
    /// The counts as recorded, per billable class.
    pub was: ClassCounts,
    /// The counts as corrected, per billable class. Never below zero.
    pub now: ClassCounts,
    /// Who authorised the correction.
    pub authorised_by: String,
    /// Why. A correction nobody can question is a correction nobody should trust, so this is not
    /// optional.
    pub reason: String,
    /// When, in unix seconds.
    pub wall: u64,
    /// The pool the corrected unit was dispatched through (owner ruling Q64/Q67): a pool-scoped
    /// budget bucket for this pool takes the correction too. `None` only on an adjustment sealed
    /// before the field existed — UNSCOPED, the group-wide buckets alone — and then it is not
    /// digested, so that adjustment's sealed hash still verifies.
    pub pool: Option<String>,
}

impl Adjust {
    /// How far one class's count moved, in micro-units (scale 6). A class absent on one side is
    /// zero on that side.
    ///
    /// SATURATING, not refusing: a correction that moves a count DOWN is the commonest one there
    /// is — a duplicate charge on a retried request is exactly `was` greater than `now` — so "was
    /// exceeds now" is a normal amendment. What is not normal is a pair far enough apart to overrun
    /// the signed range, and a wrapped delta would read as a correction in the OPPOSITE direction;
    /// saturating pins it at the extreme instead. This is a convenience over two fields the chain
    /// digests separately, never the source of either.
    pub fn delta(&self, class: &str) -> i128 {
        let side = |c: &ClassCounts| c.get(class).map_or(0, |n| n.micros());
        side(&self.now).saturating_sub(side(&self.was))
    }

    /// Whether this correction reaches a group budget bucket of scope `scope` (owner ruling
    /// Q64/Q67). An UNSCOPED bucket (`None`) takes every correction of a unit it counted; a
    /// pool-scoped one takes only a correction naming its own pool — by exact equality, the same
    /// predicate the budget book's accrual walk uses (`ChainBucket::applies_to_pool`), so a
    /// correction reaches exactly the buckets the unit was charged on. A correction sealed before
    /// the pool was recorded names none and so reaches the unscoped buckets only.
    pub fn reaches(&self, scope: Option<&busbar_contract::records::ScopeRef>) -> bool {
        scope.is_none_or(|s| s.kind == "pool" && Some(s.value.as_str()) == self.pool.as_deref())
    }
}

/// Why a correction was refused before it reached the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrectionRefused {
    /// The correction would take this class's count below zero.
    NegativeCount {
        /// The class.
        class: String,
    },
    /// No reason was given.
    NoReason,
}

impl std::fmt::Display for CorrectionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorrectionRefused::NegativeCount { class } => write!(
                f,
                "a correction may not take the {class:?} count below zero"
            ),
            CorrectionRefused::NoReason => f.write_str("a correction must say why"),
        }
    }
}

impl std::error::Error for CorrectionRefused {}

/// What the amendment is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmendBody {
    /// A content access.
    Access(Access),
    /// A correction.
    Adjust(Adjust),
}

impl AmendBody {
    /// Which class this body belongs to.
    pub fn class(&self) -> AmendClass {
        match self {
            AmendBody::Access(_) => AmendClass::Access,
            AmendBody::Adjust(_) => AmendClass::Adjust,
        }
    }
}

/// One amendment, on its own chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amendment {
    /// Its position.
    pub seq: u64,
    /// What it is about.
    pub body: AmendBody,
    /// The preceding amendment's digest.
    pub prev_hash: String,
    /// Its own digest.
    pub hash: String,
}

impl Amendment {
    /// Which class this amendment belongs to.
    pub fn class(&self) -> AmendClass {
        self.body.class()
    }
}

/// The chain of amendments.
///
/// One chain for both classes, because an access and a correction are both "something happened after
/// the fact" and interleaving them preserves the order in which they did. Splitting them would make
/// the question "what happened to this posting, in order" need two reads and a merge.
#[derive(Debug)]
pub struct AmendChain {
    tail_hash: String,
    next_seq: u64,
}

/// HAND-WRITTEN, and it must stay that way — the same reason the previous release's chain writes its
/// own: a DERIVED default gives a next position of zero, which is not a position a chain has, and
/// the position is DIGESTED here, so a silently zero-based chain would seal amendments that a
/// verifier walking from one rejects. It delegates to the one real constructor so the two cannot
/// drift apart.
impl Default for AmendChain {
    fn default() -> Self {
        AmendChain::new()
    }
}

impl AmendChain {
    /// A chain with nothing in it.
    pub fn new() -> Self {
        AmendChain {
            tail_hash: String::new(),
            next_seq: 1,
        }
    }

    /// Continue from a persisted tail.
    pub fn resume(tail_hash: String, next_seq: u64) -> Self {
        AmendChain {
            tail_hash,
            next_seq,
        }
    }

    /// The position the next amendment will take.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The digest of the most recent amendment.
    pub fn head(&self) -> &str {
        &self.tail_hash
    }

    /// Append one amendment, linking and sealing it.
    ///
    /// The token is the audit unit's, for the same reason sealing an audit record needs one: an
    /// amendment is evidence, and evidence anybody could add is evidence nobody can rely on.
    pub fn append(&mut self, body: AmendBody, _token: &Pass<Audit>) -> Amendment {
        let mut amendment = Amendment {
            seq: self.next_seq,
            body,
            prev_hash: self.tail_hash.clone(),
            hash: String::new(),
        };
        amendment.hash = AmendChain::digest_of(&amendment);
        self.tail_hash = amendment.hash.clone();
        self.next_seq = self.next_seq.saturating_add(1);
        amendment
    }

    /// Recompute one amendment's digest from its own fields.
    ///
    /// Length-prefixed, like the fixed audit record and unlike the previous release's chain: nothing
    /// here is already on anybody's disk, so the framing is chosen for the property rather than
    /// inherited for compatibility.
    ///
    /// The subject enters as the same two frozen fields the audit record digests — a tag naming the
    /// kind of subject, then its identifier — rather than as whatever the derived `Debug` prints.
    /// A derive is not a wire format: renaming a subject variant, or a future compiler rendering an
    /// enumeration differently, would move every sealed amendment hash, and an amendment is a
    /// correction to money, so a moved hash makes the correction read as tampered. Two fields rather
    /// than one for the reason the record gives: a principal whose pseudonym happened to read as
    /// "node" must not digest as a node.
    pub fn digest_of(amendment: &Amendment) -> String {
        let mut d = crate::legacy::Digest::new(crate::legacy::Framing::LengthPrefixed);
        d.text(&amendment.prev_hash);
        d.num(amendment.seq);
        d.text(amendment.class().as_str());
        match &amendment.body {
            AmendBody::Access(a) => {
                d.text(a.reader.as_str());
                d.text(&a.name);
                d.text(subject_tag(&a.subject));
                d.text(&subject_value(&a.subject));
                d.text(a.op_class.as_str());
                d.num(a.fields.len() as u64);
                for field in &a.fields {
                    d.text(field);
                }
                d.num(a.wall);
            }
            AmendBody::Adjust(a) => {
                d.text(&a.amends_hash);
                d.text(subject_tag(&a.subject));
                d.text(&subject_value(&a.subject));
                d.text(&a.lane);
                d.num(a.card_epoch_ms);
                for side in [&a.was, &a.now] {
                    d.num(side.len() as u64);
                    for (class, count) in side {
                        d.text(class);
                        d.text(&count.to_decimal_string());
                    }
                }
                d.text(&a.authorised_by);
                d.text(&a.reason);
                d.num(a.wall);
                // Q64: LAST and only when present, so an unscoped adjustment digests exactly as it
                // was sealed; length-prefixed, so a pooled one can never digest as an unscoped one.
                if let Some(pool) = &a.pool {
                    d.text(pool);
                }
            }
        }
        d.finish()
    }

    /// VERIFY A WHOLE CHAIN of amendments: `amendments` is oldest-first and starts at the chain's
    /// genesis, so the first position must be one and the first previous hash must be empty.
    ///
    /// That is what catches a HEAD truncation. A run whose oldest amendments were dropped links
    /// perfectly to itself — every remaining amendment still names the one before it — and the only
    /// thing that says amendments are missing is that the run does not begin where the chain does.
    /// Seeding the expectation from the run's own first element instead would let a correction
    /// history with its head cut off verify clean, and the amendments most worth removing are the
    /// early ones a later correction was written to cover.
    ///
    /// There is deliberately NO lenient window form here, unlike the fixed record's chain. That one
    /// has [`crate::record::AuditChain::verify_window`] because records are read out of a bounded
    /// store whose oldest rows are legitimately pruned. Amendments are not pruned — an access and a
    /// correction are the whole reason the journal is kept — so a run that does not start at the
    /// genesis is missing entries, not windowed, and there is no caller for whom excusing that would
    /// be right.
    ///
    /// An EMPTY run verifies, deliberately and for the reason the record's chain gives: "this chain
    /// has no amendments" and "every amendment was deleted" are indistinguishable from the
    /// amendments alone, and claiming otherwise would claim a guarantee this cannot provide. Use
    /// [`Self::verify_to_head`] where the chain itself is on hand to say which it is.
    pub fn verify(amendments: &[Amendment]) -> Result<(), crate::record::AuditBreak> {
        // The genesis anchor: position one, and no predecessor.
        let mut expected_prev = String::new();
        let mut expected_seq = 1u64;
        for (i, amendment) in amendments.iter().enumerate() {
            // The link, then the position, reported apart: the record chain's own judgement.
            if let Some(kind) = crate::record::link_break(
                &amendment.prev_hash,
                amendment.seq,
                &expected_prev,
                expected_seq,
            ) {
                return Err(crate::record::AuditBreak {
                    at_index: i + 1,
                    kind,
                });
            }
            if AmendChain::digest_of(amendment) != amendment.hash {
                return Err(crate::record::AuditBreak {
                    at_index: i + 1,
                    kind: crate::record::AuditBreakKind::DigestMismatch,
                });
            }
            expected_prev = amendment.hash.clone();
            expected_seq = expected_seq.saturating_add(1);
        }
        Ok(())
    }

    /// Whether a run of amendments ENDING AT THIS CHAIN'S HEAD is whole: the walk from the genesis,
    /// plus the check the walk cannot make on its own — that the last amendment in the run is the
    /// last one the chain sealed. A tail truncation is invisible to any verifier reading only the
    /// amendments, because the survivors link and number correctly among themselves; it takes the
    /// chain's own head to notice. The newest correction is also the likeliest one somebody would
    /// want gone.
    pub fn verify_to_head(
        &self,
        amendments: &[Amendment],
    ) -> Result<(), crate::record::AuditBreak> {
        Self::verify(amendments)?;
        let (tail_hash, tail_seq) = amendments
            .last()
            .map(|a| (a.hash.as_str(), a.seq))
            .unwrap_or(("", 0));
        if tail_hash != self.tail_hash || tail_seq.saturating_add(1) != self.next_seq {
            return Err(crate::record::AuditBreak {
                at_index: amendments.len(),
                kind: crate::record::AuditBreakKind::LinkMismatch,
            });
        }
        Ok(())
    }
}

/// A convenience for the commonest access: one named hook or export read one unit's content.
pub fn content_access(
    reader: Reader,
    name: impl Into<String>,
    subject: Subject,
    op_class: OpClassId,
    fields: Vec<String>,
    wall: u64,
) -> AmendBody {
    AmendBody::Access(Access {
        reader,
        name: name.into(),
        subject,
        op_class,
        fields,
        wall,
    })
}

/// Named so that the type checker, rather than a reviewer, notices an amendment written against no
/// prior entry: an adjustment must name what it amends.
///
/// # Errors
///
/// [`CorrectionRefused::NegativeCount`] for a corrected count below zero, and
/// [`CorrectionRefused::NoReason`] for a blank reason.
#[allow(clippy::too_many_arguments)]
pub fn correction(
    amends: &str,
    subject: Subject,
    lane: impl Into<String>,
    card_epoch_ms: u64,
    was: ClassCounts,
    now: ClassCounts,
    authorised_by: impl Into<String>,
    reason: impl Into<String>,
    wall: u64,
) -> Result<AmendBody, CorrectionRefused> {
    if let Some((class, _)) = now.iter().find(|(_, n)| n.is_negative()) {
        return Err(CorrectionRefused::NegativeCount {
            class: class.clone(),
        });
    }
    let reason = reason.into();
    if reason.trim().is_empty() {
        return Err(CorrectionRefused::NoReason);
    }
    Ok(AmendBody::Adjust(Adjust {
        amends_hash: amends.to_string(),
        subject,
        lane: lane.into(),
        card_epoch_ms,
        was,
        now,
        authorised_by: authorised_by.into(),
        reason,
        wall,
        pool: None,
    }))
}

/// How many amendments a journal keeps in memory. Bounds RAM, not history: accesses are written at
/// request rate, so an unbounded in-memory run is a leak. Corrections are never released — they are
/// operator-rate, and [`AmendJournal::counts_now`] reads them.
pub const AMENDMENTS_RETAINED: usize = 1000;

/// A chain together with the amendments it sealed: the one node-wide journal a hook read, an export
/// read and a correction are all appended to, in the order they happened.
#[derive(Debug, Default)]
pub struct AmendJournal {
    chain: AmendChain,
    recent: VecDeque<Amendment>,
    released: u64,
    corrections: Vec<Amendment>,
}

impl AmendJournal {
    /// An empty journal.
    pub fn new() -> Self {
        AmendJournal::default()
    }

    /// Seal one amendment onto the chain and keep it.
    pub fn append(&mut self, body: AmendBody, token: &Pass<Audit>) -> Amendment {
        let amendment = self.chain.append(body, token);
        if amendment.class() == AmendClass::Adjust {
            self.corrections.push(amendment.clone());
        }
        if self.recent.len() == AMENDMENTS_RETAINED {
            self.recent.pop_front();
            self.released = self.released.saturating_add(1);
        }
        self.recent.push_back(amendment.clone());
        amendment
    }

    /// The amendments still held, oldest first.
    pub fn recent(&self) -> impl Iterator<Item = &Amendment> {
        self.recent.iter()
    }

    /// Every correction ever appended, oldest first.
    pub fn corrections(&self) -> &[Amendment] {
        &self.corrections
    }

    /// How many older amendments have left the in-memory window.
    pub fn released(&self) -> u64 {
        self.released
    }

    /// The chain's head.
    pub fn head(&self) -> &str {
        self.chain.head()
    }

    /// The counts an entry stands at NOW: its most recent correction's `now`, or `recorded` when
    /// nothing has corrected it. The recorded counts are never rewritten — this is the read.
    pub fn counts_now(&self, amends_hash: &str, recorded: &ClassCounts) -> ClassCounts {
        self.corrections
            .iter()
            .rev()
            .find_map(|a| match &a.body {
                AmendBody::Adjust(adj) if adj.amends_hash == amends_hash => Some(adj.now.clone()),
                _ => None,
            })
            .unwrap_or_else(|| recorded.clone())
    }

    /// REBUILD A JOURNAL FROM A WHOLE RUN read back off durable storage, oldest first from the
    /// genesis: the chain resumes at the run's head, every correction is kept, and the newest
    /// [`AMENDMENTS_RETAINED`] are held. The run is verified first, so a journal is never rebuilt
    /// over a broken chain.
    ///
    /// # Errors
    ///
    /// The run does not verify from the genesis ([`AmendChain::verify`]).
    pub fn restore(run: Vec<Amendment>) -> Result<AmendJournal, crate::record::AuditBreak> {
        AmendChain::verify(&run)?;
        let chain = run.last().map_or_else(AmendChain::new, |a| {
            AmendChain::resume(a.hash.clone(), a.seq.saturating_add(1))
        });
        let corrections = (run.iter())
            .filter(|a| a.class() == AmendClass::Adjust)
            .cloned()
            .collect();
        let released = run.len().saturating_sub(AMENDMENTS_RETAINED);
        Ok(AmendJournal {
            chain,
            recent: run.into_iter().skip(released).collect(),
            released: released as u64,
            corrections,
        })
    }

    /// Verify what is held: from the genesis while nothing has been released, and always to the
    /// chain's own head. Once the window has moved, the run is checked from its first held link.
    pub fn verify(&self) -> Result<(), crate::record::AuditBreak> {
        let run: Vec<Amendment> = self.recent.iter().cloned().collect();
        if self.released == 0 {
            return self.chain.verify_to_head(&run);
        }
        for (i, pair) in run.windows(2).enumerate() {
            if let Some(kind) = crate::record::link_break(
                &pair[1].prev_hash,
                pair[1].seq,
                &pair[0].hash,
                pair[0].seq.saturating_add(1),
            ) {
                return Err(crate::record::AuditBreak {
                    at_index: i + 2,
                    kind,
                });
            }
        }
        for (i, a) in run.iter().enumerate() {
            if AmendChain::digest_of(a) != a.hash {
                return Err(crate::record::AuditBreak {
                    at_index: i + 1,
                    kind: crate::record::AuditBreakKind::DigestMismatch,
                });
            }
        }
        let last = run.last().map(|a| (a.hash.as_str(), a.seq));
        if last.is_some_and(|(h, s)| {
            h != self.chain.head() || s.saturating_add(1) != self.chain.next_seq()
        }) {
            return Err(crate::record::AuditBreak {
                at_index: run.len(),
                kind: crate::record::AuditBreakKind::LinkMismatch,
            });
        }
        Ok(())
    }
}

// ── THE NODE'S ONE JOURNAL ───────────────────────────────────────────────────────────────────────
//
// A hook and an export sink are resolved per config generation, but what they read is the node's
// to account for, so the node keeps ONE journal for the life of the process. Every writer below
// takes the audit step's token: the kernel mints it, and only the kernel can.

static NODE: std::sync::OnceLock<std::sync::Mutex<AmendJournal>> = std::sync::OnceLock::new();

fn node() -> std::sync::MutexGuard<'static, AmendJournal> {
    NODE.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// WHERE THE NODE JOURNAL'S AMENDMENTS ARE MADE DURABLE: handed every amendment the node journal
/// seals, in chain order, as it is sealed. The composition root binds one over its own journal;
/// with none bound the node journal is memory-only, the previous release's shape.
///
/// Called with the node journal's lock held — that is what keeps what reaches the sink in chain
/// order with no gap — so an implementation must never seal an amendment itself, and no caller
/// may seal one while holding whatever lock the sink takes.
pub trait AmendSink: Send + Sync {
    /// `amendment` was just sealed onto the node journal.
    fn sealed(&self, amendment: &Amendment);
}

static SINK: std::sync::RwLock<Option<std::sync::Arc<dyn AmendSink>>> =
    std::sync::RwLock::new(None);

/// Seal `body` onto `journal` and hand it to the bound sink, under the journal's lock.
fn seal(journal: &mut AmendJournal, body: AmendBody, token: &Pass<Audit>) -> Amendment {
    let amendment = journal.append(body, token);
    if let Some(sink) = SINK.read().unwrap_or_else(|p| p.into_inner()).as_ref() {
        sink.sealed(&amendment);
    }
    amendment
}

/// REBUILD THE NODE JOURNAL from a whole run read back off durable storage (see
/// [`AmendJournal::restore`]), replacing what it holds, and answer the position of the run's
/// newest amendment (0 for an empty run) — what [`bind_node_sink`] is told was already durable.
///
/// # Errors
///
/// The run does not verify from the genesis; the node journal is left as it was.
pub fn restore_node(run: Vec<Amendment>) -> Result<u64, crate::record::AuditBreak> {
    let through = run.last().map_or(0, |a| a.seq);
    let restored = AmendJournal::restore(run)?;
    *node() = restored;
    Ok(through)
}

/// BIND the node journal's sink (`None` unbinds). Every amendment it still holds above position
/// `journalled_through` is handed over first, in chain order, so an amendment sealed between the
/// rebuild and the binding reaches the sink too and what is durable has no gap.
pub fn bind_node_sink(sink: Option<std::sync::Arc<dyn AmendSink>>, journalled_through: u64) {
    let journal = node();
    if let Some(sink) = &sink {
        for amendment in journal.recent().filter(|a| a.seq > journalled_through) {
            sink.sealed(amendment);
        }
    }
    *SINK.write().unwrap_or_else(|p| p.into_inner()) = sink;
}

fn subject_of(principal: Option<&str>) -> Subject {
    principal.map_or(Subject::Arrival, |p| Subject::PrincipalId(p.to_string()))
}

/// Record on the node journal that `reader` `name` was handed `fields` of a unit's content at
/// `wall` (unix seconds, the caller's clock — this unit reads none). `op_class` is the caller's
/// label for the operation — data, never branched on.
pub fn record_read(
    token: &Pass<Audit>,
    reader: Reader,
    name: &str,
    principal: Option<&str>,
    op_class: &str,
    fields: Vec<String>,
    wall: u64,
) -> Amendment {
    let body = content_access(
        reader,
        name,
        subject_of(principal),
        OpClassId::new(op_class),
        fields,
        wall,
    );
    seal(&mut node(), body, token)
}

/// One correction to a recorded unit's counts, as the admin verb states it.
#[derive(Debug, Clone)]
pub struct CountCorrection<'a> {
    /// The digest of the entry whose counts are corrected.
    pub amends: &'a str,
    /// Whose counts they are.
    pub principal: Option<&'a str>,
    /// The lane the counts were recorded on.
    pub lane: &'a str,
    /// The card epoch the counts price at (#79), carried unchanged.
    pub card_epoch_ms: u64,
    /// The counts per class as the correction says they should be.
    pub now: ClassCounts,
    /// Who authorised it.
    pub authorised_by: &'a str,
    /// Why.
    pub reason: &'a str,
    /// The pool the unit was dispatched through (Q64/Q67). The admin verb always names one; `None`
    /// seals an unscoped correction, the shape every adjustment sealed before the field had.
    pub pool: Option<&'a str>,
}

/// Why a correction did not land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrectionError {
    /// Only the full (root) admin scope may correct a recorded count.
    NotRoot,
    /// The correction itself was refused (a count below zero, no reason).
    Refused(CorrectionRefused),
}

/// THE CORRECTION VERB'S JOURNAL HALF: amend a recorded unit's counts on the node journal.
/// Root-only, audited (the adjustment is sealed with who and why), and refusing a count below
/// zero. `recorded` is what the entry carries; what it was BEFORE this correction is read through
/// any earlier correction, so a second correction names the first one's result as its `was`.
///
/// # Errors
///
/// [`CorrectionError::NotRoot`] below the full scope; [`CorrectionError::Refused`] for a refused
/// correction. Nothing is sealed on either.
pub fn correct_counts(
    token: &Pass<Audit>,
    scope: Scope,
    recorded: &ClassCounts,
    c: CountCorrection<'_>,
    wall: u64,
) -> Result<Amendment, CorrectionError> {
    if scope != Scope::Full {
        return Err(CorrectionError::NotRoot);
    }
    let mut journal = node();
    let mut body = correction(
        c.amends,
        subject_of(c.principal),
        c.lane,
        c.card_epoch_ms,
        journal.counts_now(c.amends, recorded),
        c.now,
        c.authorised_by,
        c.reason,
        wall,
    )
    .map_err(CorrectionError::Refused)?;
    if let AmendBody::Adjust(adj) = &mut body {
        adj.pool = c.pool.map(str::to_string);
    }
    Ok(seal(&mut journal, body, token))
}

/// The counts an entry stands at now on the node journal: its latest correction, or `recorded`.
pub fn counts_now(amends: &str, recorded: &ClassCounts) -> ClassCounts {
    node().counts_now(amends, recorded)
}

/// The amendments the node journal holds, oldest first.
pub fn node_recent() -> Vec<Amendment> {
    node().recent().cloned().collect()
}

/// Every correction the node journal has sealed, oldest first.
pub fn node_corrections() -> Vec<Amendment> {
    node().corrections().to_vec()
}

/// The digest of an audit record, so an amendment can name the entry it amends without the caller
/// reaching into the chain's internals.
pub fn amends(record: &crate::record::AuditRecord) -> String {
    record.hash.clone()
}
