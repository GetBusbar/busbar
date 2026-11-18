// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two amendment classes: an access, and an adjustment.

use crate::record::{subject_tag, OpClassId, Subject, SubjectValue};
use busbar_contract::{
    caps::{Audit, DurableWrite, Grant, Pass},
    count::Count,
};
use std::collections::{BTreeMap, VecDeque};

/// A unit's counts, keyed by the billable class string the plane declared.
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
pub fn subject_fields(subject: &Subject) -> (&'static str, SubjectText<'_>) {
    let value = match subject {
        Subject::PrincipalId(p) => SubjectText::Text(p),
        Subject::Arrival | Subject::Aggregate => SubjectText::Text(""),
        Subject::Node(id) => SubjectText::node(*id),
    };
    (subject_tag(subject), value)
}

/// A subject's identifier as text, lent or spelled on the stack: it reads as a `&str`.
#[derive(Debug, Clone, Copy)]
pub enum SubjectText<'a> {
    /// The principal's own text, or nothing.
    Text(&'a str),
    /// A node number's decimal digits, right-aligned in the buffer, and how many there are.
    Digits([u8; 20], u8),
}

impl SubjectText<'_> {
    /// A node number in decimal.
    fn node(id: u64) -> Self {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        let mut rest = id;
        loop {
            at -= 1;
            digits[at] = b'0' + (rest % 10) as u8;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        SubjectText::Digits(digits, (digits.len() - at) as u8)
    }
}

impl std::ops::Deref for SubjectText<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        match self {
            SubjectText::Text(text) => text,
            SubjectText::Digits(digits, len) => {
                std::str::from_utf8(&digits[digits.len() - usize::from(*len)..]).unwrap_or("")
            }
        }
    }
}

// Read back from the journal at restore, never per request: it lives off the request path.
pub use crate::off_path::amend::subject_from_fields;

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

/// One correction to counts that were already recorded, as pre-release 1.6.0 sealed it. Never
/// written now and never priced: kept so a chain that holds one still verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjust {
    /// Which entry is being corrected, by its digest.
    pub amends_hash: String,
    /// Whose counts they are.
    pub subject: Subject,
    /// The lane the counts were recorded on — the key a card entry is written against.
    pub lane: String,
    /// THE CARD EPOCH: the instant, in milliseconds, whose card the counts price at. A
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
    /// The pool the corrected unit was dispatched through: a pool-scoped budget bucket for this
    /// pool takes the correction too. `None` only on an adjustment sealed before the field existed
    /// — UNSCOPED, the group-wide buckets alone — and then it is not digested, so that adjustment's
    /// sealed hash still verifies.
    pub pool: Option<String>,
}

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

/// HAND-WRITTEN, and it must stay that way — the same reason the retired admin chain writes its
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
    pub fn append(&mut self, body: AmendBody, _token: &Pass<Audit>) -> Amendment {
        let mut amendment = Amendment {
            seq: self.next_seq,
            body,
            prev_hash: std::mem::take(&mut self.tail_hash),
            hash: String::new(),
        };
        amendment.hash = AmendChain::digest_of(&amendment);
        self.tail_hash.clone_from(&amendment.hash);
        self.next_seq = self.next_seq.saturating_add(1);
        amendment
    }

    /// Recompute one amendment's digest from its own fields.
    pub fn digest_of(amendment: &Amendment) -> String {
        let mut d = crate::digest::Digest::new(crate::digest::Framing::LengthPrefixed);
        d.text(&amendment.prev_hash);
        d.num(amendment.seq);
        d.text(amendment.class().as_str());
        match &amendment.body {
            AmendBody::Access(a) => {
                d.text(a.reader.as_str());
                d.text(&a.name);
                d.text(subject_tag(&a.subject));
                d.text_fmt(format_args!("{}", SubjectValue(&a.subject)));
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
                d.text_fmt(format_args!("{}", SubjectValue(&a.subject)));
                d.text(&a.lane);
                d.num(a.card_epoch_ms);
                for side in [&a.was, &a.now] {
                    d.num(side.len() as u64);
                    for (class, count) in side {
                        d.text(class);
                        d.text_fmt(format_args!("{count}"));
                    }
                }
                d.text(&a.authorised_by);
                d.text(&a.reason);
                d.num(a.wall);

                if let Some(pool) = &a.pool {
                    d.text(pool);
                }
            }
        }
        d.finish()
    }

    /// VERIFY A WHOLE CHAIN of amendments: `amendments` is oldest-first and starts at the chain's
    pub fn verify(amendments: &[Amendment]) -> Result<(), crate::record::AuditBreak> {
        Self::verify_run(amendments.iter())
    }

    /// [`AmendChain::verify`] over any run, borrowed where it lies.
    fn verify_run<'a>(
        amendments: impl Iterator<Item = &'a Amendment>,
    ) -> Result<(), crate::record::AuditBreak> {
        let mut expected_prev: &str = "";
        let mut expected_seq = 1u64;
        for (i, amendment) in amendments.enumerate() {
            if let Some(kind) = crate::record::link_break(
                &amendment.prev_hash,
                amendment.seq,
                expected_prev,
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
            expected_prev = &amendment.hash;
            expected_seq = expected_seq.saturating_add(1);
        }
        Ok(())
    }

    /// Verify `amendments`, then require that they end exactly where this chain's head is.
    pub fn verify_to_head(
        &self,
        amendments: &[Amendment],
    ) -> Result<(), crate::record::AuditBreak> {
        self.verify_run_to_head(amendments.iter(), amendments.len())
    }

    /// [`AmendChain::verify_to_head`] over any run of `len` amendments, borrowed where it lies.
    fn verify_run_to_head<'a>(
        &self,
        amendments: impl Iterator<Item = &'a Amendment> + Clone,
        len: usize,
    ) -> Result<(), crate::record::AuditBreak> {
        Self::verify_run(amendments.clone())?;
        let (tail_hash, tail_seq) = amendments
            .last()
            .map(|a| (a.hash.as_str(), a.seq))
            .unwrap_or(("", 0));
        if tail_hash != self.tail_hash || tail_seq.saturating_add(1) != self.next_seq {
            return Err(crate::record::AuditBreak {
                at_index: len,
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

/// How many amendments a journal keeps in memory. Bounds RAM, not history: accesses are written at
pub const AMENDMENTS_RETAINED: usize = 1000;

/// A chain together with the amendments it sealed: the one node-wide journal a hook read and an
/// export read are appended to, in the order they happened.
#[derive(Debug, Default)]
pub struct AmendJournal {
    chain: AmendChain,
    recent: VecDeque<Amendment>,
    released: u64,
}

impl AmendJournal {
    /// An empty journal.
    pub fn new() -> Self {
        AmendJournal::default()
    }

    /// Seal one amendment onto the chain and keep it.
    pub fn append(&mut self, body: AmendBody, token: &Pass<Audit>) -> Amendment {
        let amendment = self.chain.append(body, token);
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

    /// How many older amendments have left the in-memory window.
    pub fn released(&self) -> u64 {
        self.released
    }

    /// The chain's head.
    pub fn head(&self) -> &str {
        self.chain.head()
    }

    /// A journal from its parts, as a restore rebuilt them (see `AmendJournal::restore`, which runs
    /// off the request path).
    pub(crate) fn from_parts(
        chain: AmendChain,
        recent: VecDeque<Amendment>,
        released: u64,
    ) -> Self {
        AmendJournal {
            chain,
            recent,
            released,
        }
    }

    /// Verify what is held: from the genesis while nothing has been released, and always to the
    pub fn verify(&self) -> Result<(), crate::record::AuditBreak> {
        self.verify_window()
    }

    /// The held window: linked, numbered, hashing to its own fields, and ending at the head.
    fn verify_window(&self) -> Result<(), crate::record::AuditBreak> {
        let run = &self.recent;
        if self.released == 0 {
            return self.chain.verify_run_to_head(run.iter(), run.len());
        }
        for (i, (earlier, later)) in run.iter().zip(run.iter().skip(1)).enumerate() {
            if let Some(kind) = crate::record::link_break(
                &later.prev_hash,
                later.seq,
                &earlier.hash,
                earlier.seq.saturating_add(1),
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
        let last = run.back().map(|a| (a.hash.as_str(), a.seq));
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

/// An amendment lacks native durable confirmation. Its exact original remains
/// owned by the sink; callers must not publish a durable success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmendPersistError;
/// Owned asynchronous confirmation of an already staged original amendment.
pub type AmendCommit =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AmendPersistError>> + Send>>;
/// Reserves original amendments in order and confirms their native durability.
pub trait AmendSink: Send + Sync {
    /// Stage the exact original synchronously, preserving amendment order, then
    /// return an owned confirmation future. Only Ok means native Applied.
    fn sealed(&self, amendment: &Amendment) -> Result<AmendCommit, AmendPersistError>;

    /// Stage several consecutive originals as one unit, in order, and return one confirmation
    /// for all of them. A sink that can commit them together (one durable run) overrides this; the
    /// default stages each one and confirms them in order.
    fn sealed_many(&self, amendments: &[Amendment]) -> Result<AmendCommit, AmendPersistError> {
        let mut confirmations = Vec::with_capacity(amendments.len());
        for amendment in amendments {
            confirmations.push(self.sealed(amendment)?);
        }
        Ok(Box::pin(async move {
            for confirmation in confirmations {
                confirmation.await?;
            }
            Ok(())
        }))
    }
}

/// One content access to record: `reader` `name` was handed `fields` of a unit's content for
/// `principal` (`None`: the arrival) under `op_class` at `wall` (unix seconds).
#[derive(Debug, Clone)]
pub struct ReadFact<'a> {
    /// What kind of thing reached for the content.
    pub reader: Reader,
    /// The hook or export module's name.
    pub name: &'a str,
    /// The principal the content belongs to; `None` is the arrival.
    pub principal: Option<&'a str>,
    /// The operation class the content was handed over under.
    pub op_class: &'a str,
    /// The content fields handed over.
    pub fields: Vec<String>,
    /// When, in unix seconds.
    pub wall: u64,
}

/// What the journal's one lock guards: the journal, and the sink its amendments go to.
#[derive(Default)]
struct Held {
    journal: AmendJournal,
    sink: Option<std::sync::Arc<dyn AmendSink>>,
}

/// THE NODE'S AMENDMENT JOURNAL: every hook or export content access, in the order they happened,
/// and the sink that makes them durable. One per node, owned by the state that lives as long as the
/// node does and reached through it; every method takes `&self`, so it is shared by `Arc` and never
/// copied.
#[derive(Default)]
pub struct NodeAmendments {
    held: std::sync::Mutex<Held>,
}

impl std::fmt::Debug for NodeAmendments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held = self.held();
        f.debug_struct("NodeAmendments")
            .field("head", &held.journal.head())
            .field("held", &held.journal.recent.len())
            .field("durable", &held.sink.is_some())
            .finish()
    }
}

impl NodeAmendments {
    /// An empty journal, bound to no sink.
    #[must_use]
    pub fn new() -> Self {
        NodeAmendments::default()
    }

    /// Poison-recovering: a panic under this lock (a sink that panicked) leaves an amendment that
    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// VERIFY THE JOURNAL AS IT IS HELD NOW — the on-demand check `GET /admin/verify` runs. The boot
    pub fn verify(&self) -> Result<(), crate::record::AuditBreak> {
        self.held().journal.verify()
    }

    /// TEST ONLY: edit the newest held amendment's recorded hash in place, as an in-memory tamper
    /// would. Never compiled into a shipped build.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn tamper_for_test(&self) {
        if let Some(last) = self.held().journal.recent.back_mut() {
            let zeros = last.hash.len().max(1);
            last.hash.clear();
            last.hash.extend(std::iter::repeat_n('0', zeros));
        }
    }

    /// REBUILD THE JOURNAL from a whole run read back off durable storage (see
    pub fn restore(
        &self,
        run: Vec<Amendment>,
        _token: &Grant<DurableWrite>,
    ) -> Result<u64, crate::record::AuditBreak> {
        let through = run.last().map_or(0, |a| a.seq);
        let restored = AmendJournal::restore(run)?;
        self.held().journal = restored;
        Ok(through)
    }

    /// BIND the journal's sink (`None` unbinds). Every amendment it still holds above position
    pub async fn bind(
        &self,
        sink: Option<std::sync::Arc<dyn AmendSink>>,
        journalled_through: u64,
        _token: &Grant<DurableWrite>,
    ) -> Result<(), AmendPersistError> {
        let pending = {
            let mut held = self.held();
            let pending = match &sink {
                Some(sink) => crate::off_path::amend::stage_unjournalled(
                    &held.journal,
                    sink.as_ref(),
                    journalled_through,
                )?,
                None => Vec::new(),
            };
            held.sink = sink;
            pending
        };
        for confirmation in pending {
            confirmation.await?;
        }
        Ok(())
    }

    /// Record several content accesses at once: each fact is its own amendment (own seq and hash,
    /// chained in order), but all of them are staged as one unit and confirmed by one await, so
    /// the accesses of one request stage cost one durable commit instead of one each. Nothing is
    /// committed to the chain unless the sink retained every original.
    pub async fn record_reads(
        &self,
        _token: &Pass<Audit>,
        facts: &[ReadFact<'_>],
    ) -> Result<Vec<Amendment>, AmendPersistError> {
        if facts.is_empty() {
            return Ok(Vec::new());
        }
        let (amendments, confirmation) = {
            let mut held = self.held();
            let mut seq = held.journal.chain.next_seq;
            let mut tail = held.journal.chain.tail_hash.clone();
            let mut amendments = Vec::with_capacity(facts.len());
            for fact in facts {
                let next = seq.checked_add(1).ok_or(AmendPersistError)?;
                let mut amendment = Amendment {
                    seq,
                    body: content_access(
                        fact.reader,
                        fact.name,
                        subject_of(fact.principal),
                        OpClassId::new(fact.op_class),
                        fact.fields.clone(),
                        fact.wall,
                    ),
                    prev_hash: std::mem::take(&mut tail),
                    hash: String::new(),
                };
                amendment.hash = AmendChain::digest_of(&amendment);
                tail.clone_from(&amendment.hash);
                seq = next;
                amendments.push(amendment);
            }
            let sink = held.sink.as_ref().ok_or(AmendPersistError)?;
            let confirmation = sink.sealed_many(&amendments)?;
            // Commit only after exact original custody is retained; refused
            // memory admission must not create an amendment-chain hole.
            held.journal.chain.tail_hash = tail;
            held.journal.chain.next_seq = seq;
            for amendment in &amendments {
                if held.journal.recent.len() == AMENDMENTS_RETAINED {
                    held.journal.recent.pop_front();
                    held.journal.released = held.journal.released.saturating_add(1);
                }
                held.journal.recent.push_back(amendment.clone());
            }
            (amendments, confirmation)
        };
        confirmation.await?;
        Ok(amendments)
    }

    /// The amendments the journal holds, oldest first.
    #[must_use]
    pub fn recent(&self) -> Vec<Amendment> {
        crate::off_path::amend::copy_run(&self.held().journal)
    }
}

/// The subject of a content access. The amendment keeps the principal's name for as long as the
/// journal holds it, and the reader's fact lends the name as plain text, so the one copy is made
/// here, in place.
fn subject_of(principal: Option<&str>) -> Subject {
    principal.map_or(Subject::Arrival, |p| {
        Subject::PrincipalId(busbar_contract::kept::Text::from(
            std::sync::Arc::<str>::from(p),
        ))
    })
}
