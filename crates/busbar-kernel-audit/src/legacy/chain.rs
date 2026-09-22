// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPEND-ONLY HASH CHAIN — moved here unchanged from the previous release.
//!
//! ## Why this file is a move and not a rewrite
//!
//! Every byte this mechanism produces is already on somebody's disk. A digest that changed would not
//! break a feature; it would make every deployed chain fail to verify at its next boot, which is to
//! say it would report the whole of a deployment's history as TAMPERED. So the framing, the field
//! order, the sequence allocation, the linkage and the walk are here exactly as they were, and the
//! only differences are that the visibility is public (this is a crate rather than a module now) and
//! that the digest is taken from this crate's own one-line helper instead of a neighbour's.
//!
//! ## One mechanism is not one stream
//!
//! Several chains run on this: the admin mutation log, and whatever else a deployment keeps. They
//! stay separate. A record's SCOPE is what keeps them apart, and the verifier refuses a record whose
//! scope is not the chain's, so one caller's evidence can never be made to depend on another's rows.
//!
//! ## What a record type still owns
//!
//! Which fields the digest covers, in which order, and how they are framed. Those differ legitimately
//! between streams and they are wire facts of what is already written down, so they travel with the
//! record. Everything else is here, once.
//!
//! ## The claim, stated honestly
//!
//! Tamper-EVIDENCE, not tamper-prevention. A chain detects an altered, reordered, inserted or removed
//! record after the fact. It does not stop one, and a host compromised at the moment of writing can
//! rewrite a whole chain consistently and this will verify. Prevention means shipping the records
//! off-box to something the compromised host cannot rewrite.

use std::marker::PhantomData;

/// The lowercase hexadecimal digest the chain is built on.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// HOW A RECORD'S FIELDS ARE FRAMED INTO THE DIGEST INPUT.
///
/// A wire fact of chains that already exist on disk, not a preference. Changing the framing of an
/// existing stream would make every persisted chain in every deployment fail to verify at the next
/// boot. That is the one migration this module may never do silently, so the framing travels with
/// the record type instead of being unified away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Every field is prefixed with its big-endian eight-byte length, and integers are their
    /// eight-byte big-endian form. THE FRAMING A NEW RECORD TYPE MUST CHOOSE: length prefixes make
    /// the split between fields unforgeable regardless of what any field contains, so a caller who
    /// can choose one field's bytes cannot forge the same byte stream under a different split. A
    /// separator-joined digest is only safe while no field can contain the separator, which is a
    /// property of today's fields rather than of the code.
    LengthPrefixed,
    /// Fields joined by a vertical bar, integers in decimal. The framing of the admin audit chain,
    /// kept byte for byte because its records are already on disk.
    PipeSeparated,
}

/// THE ONE CANONICALISER. A record feeds its chained fields in through [`Digest::text`] and
/// [`Digest::num`]; the framing and the hash function are not its business.
pub struct Digest {
    framing: Framing,
    buf: Vec<u8>,
    /// Pipe-separated only: whether a separator is owed before the next field.
    started: bool,
}

impl Digest {
    /// A canonicaliser in the given framing.
    pub fn new(framing: Framing) -> Self {
        Digest {
            framing,
            buf: Vec::new(),
            started: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        match self.framing {
            Framing::LengthPrefixed => {
                self.buf
                    .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
                self.buf.extend_from_slice(bytes);
            }
            Framing::PipeSeparated => {
                if self.started {
                    self.buf.push(b'|');
                }
                self.buf.extend_from_slice(bytes);
            }
        }
        self.started = true;
    }

    /// Feed one string field.
    pub fn text(&mut self, s: &str) -> &mut Self {
        self.push(s.as_bytes());
        self
    }

    /// Feed one integer field.
    pub fn num(&mut self, v: u64) -> &mut Self {
        match self.framing {
            Framing::LengthPrefixed => self.push(&v.to_be_bytes()),
            Framing::PipeSeparated => self.push(v.to_string().as_bytes()),
        }
        self
    }

    /// The digest of everything fed in so far.
    pub fn finish(self) -> String {
        sha256_hex(&self.buf)
    }

    /// The framed bytes, before hashing. Only a test that is checking the framing itself wants
    /// these.
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
}

/// The operator-facing words for one stream: what to call the chain, and what to call the thing a
/// chain is scoped to. Carried by a break so the message names WHICH log to go and look at without
/// the error type having to be generic over the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainLabels {
    /// Written as it should read mid-sentence, for example "the admin audit chain".
    pub chain: &'static str,
    /// The noun for what one chain is scoped TO: "principal", "task", "log".
    pub scope: &'static str,
}

/// ONE KIND OF CHAINED RECORD. Implementing this is the ENTIRE cost of a new stream of evidence: the
/// chaining, the sequence allocation, the linkage, the digest and the verifier are inherited.
///
/// The sequence, the previous hash and the hash are NEVER caller-supplied — [`ChainedRecord::Input`]
/// is the payload a call site may choose, and [`ChainedRecord::link`] receives the chain's own
/// allocations separately, so no call site can supply a sequence number or a link of its own
/// choosing.
pub trait ChainedRecord: Sized {
    /// The fields a caller supplies. It must NOT contain the sequence, the previous hash or the
    /// hash.
    type Input;

    /// The operator-facing words for this stream, used when a break is reported.
    const LABELS: &'static ChainLabels;
    /// See [`Framing`] — a wire fact of the records already on disk, not a preference.
    const FRAMING: Framing;

    /// The chain this record belongs to. A chain holds exactly one scope; the verifier refuses any
    /// record whose scope is not the chain's.
    fn scope_of(&self) -> &str;
    /// This record's position in its chain.
    fn seq(&self) -> u64;
    /// The preceding record's hash.
    fn prev_hash(&self) -> &str;
    /// This record's own hash.
    fn hash(&self) -> &str;

    /// Build the record from the chain's allocations plus the caller's payload. The hash is left
    /// empty; [`seal`] fills it and is the only thing that may.
    fn link(scope: &str, seq: u64, prev_hash: String, input: Self::Input) -> Self;

    /// Store the computed digest. [`seal`] is the only caller; a record type that set its own hash
    /// anywhere else would be a second place a digest is computed.
    fn set_hash(&mut self, hash: String);

    /// FEED THE CHAINED FIELDS, IN ORDER — the one thing a record type says about the digest.
    ///
    /// The previous hash is fed here rather than by the mechanism, because streams do not agree on
    /// where it sits relative to the scope, and their field ORDER is as much a wire fact as the
    /// framing is.
    ///
    /// A field left out is a field a tamper can change without detection, so anything that carries
    /// meaning about WHAT HAPPENED belongs in. A pure join key is deliberately left out: it is
    /// legitimately absent on paths with no inbound request, and a field that is sometimes absent
    /// must not be able to make an otherwise-intact chain unverifiable.
    fn digest_fields(&self, d: &mut Digest);
}

/// Recompute a record's digest from its own fields — the verification primitive, and the only place
/// a digest is ever computed.
pub fn digest<R: ChainedRecord>(record: &R) -> String {
    let mut d = Digest::new(R::FRAMING);
    record.digest_fields(&mut d);
    d.finish()
}

/// Build a record at a given chain position and SEAL it with its digest. The one construction path:
/// the sequence and the previous hash arrive as arguments from whatever owns the position, never
/// from the caller's payload.
pub fn seal<R: ChainedRecord>(scope: &str, seq: u64, prev_hash: String, input: R::Input) -> R {
    let mut record = R::link(scope, seq, prev_hash, input);
    record.set_hash(digest(&record));
    record
}

/// ONE CHAIN'S POSITION, in memory: the tail link and the next sequence number. Small on purpose —
/// the records themselves live in a store, and holding every record of every scope in memory is the
/// thing a durable log exists to avoid.
pub struct Chain<R> {
    /// The hash of the most recent record, or empty when the chain is empty.
    tail_hash: String,
    /// The sequence the NEXT appended record gets.
    next_seq: u64,
    /// A function pointer rather than the record itself: the position owns no record, so the marker
    /// must not drag variance or auto-trait obligations in from the record type.
    _record: PhantomData<fn() -> R>,
}

/// HAND-WRITTEN, and it must stay that way: a DERIVED default gives a next sequence of zero, which
/// is not a valid position — the first record of a chain is one — and the derive would hand a
/// silently zero-based chain to every caller that reached it. The test named after this comment
/// pins the two constructors against each other.
impl<R> Default for Chain<R> {
    fn default() -> Self {
        Chain {
            tail_hash: String::new(),
            next_seq: 1,
            _record: PhantomData,
        }
    }
}

// Hand-written rather than derived for the same reason the default is: a derive would demand
// `Clone`, `Debug` or `PartialEq` of the RECORD type, which the position does not hold.
impl<R> Clone for Chain<R> {
    fn clone(&self) -> Self {
        Chain {
            tail_hash: self.tail_hash.clone(),
            next_seq: self.next_seq,
            _record: PhantomData,
        }
    }
}

impl<R> std::fmt::Debug for Chain<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chain")
            .field("tail_hash", &self.tail_hash)
            .field("next_seq", &self.next_seq)
            .finish()
    }
}

impl<R> PartialEq for Chain<R> {
    fn eq(&self, other: &Self) -> bool {
        self.tail_hash == other.tail_hash && self.next_seq == other.next_seq
    }
}

impl<R> Eq for Chain<R> {}

impl<R: ChainedRecord> Chain<R> {
    /// A chain with nothing in it. The first record gets sequence one and an empty previous hash.
    pub fn new() -> Self {
        Chain {
            tail_hash: String::new(),
            next_seq: 1,
            _record: PhantomData,
        }
    }

    /// Continue a chain from what is already PERSISTED, so a restart continues the same chain rather
    /// than opening a second one under the same scope.
    ///
    /// The records are VERIFIED before they are trusted to position the chain. Resuming from an
    /// unverified tail would append a valid-looking link onto a forged one and launder the forgery:
    /// every subsequent verification would pass and the break would sit permanently behind the point
    /// anybody looks. On a broken chain this returns the break and the CALLER decides — see
    /// [`Chain::from_persisted_unverified`], because refusing to record anything further would mean
    /// a detected tamper silently stops all further evidence.
    pub fn from_persisted(records: &[R]) -> Result<Self, ChainBreak> {
        verify_chain(records)?;
        Ok(Self::from_persisted_unverified(records))
    }

    /// Position a chain on the tail of `records` WITHOUT verifying them. Only for the
    /// tamper-detected path, where the break has already been reported and the alternative is to
    /// stop recording evidence entirely.
    pub fn from_persisted_unverified(records: &[R]) -> Self {
        match records.last() {
            None => Chain::new(),
            Some(last) => Chain {
                tail_hash: last.hash().to_string(),
                next_seq: last.seq().saturating_add(1),
                _record: PhantomData,
            },
        }
    }

    /// The sequence the next appended record will carry.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Append one record, linking it to the tail and advancing the chain.
    pub fn append(&mut self, scope: &str, input: R::Input) -> R {
        let record: R = seal(scope, self.next_seq, self.tail_hash.clone(), input);
        self.tail_hash = record.hash().to_string();
        self.next_seq = self.next_seq.saturating_add(1);
        record
    }
}

/// WHY a chain failed to verify. Four distinguishable causes, because the operator's response to
/// each is different — a verifier that returns a boolean tells an operator that something is wrong
/// and nothing else, which in practice means it is run once and then ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreakKind {
    /// This record's stored hash is not the digest of its own fields: a field was edited in place.
    DigestMismatch {
        /// What the record claims.
        stored: String,
        /// What its fields actually hash to.
        recomputed: String,
    },
    /// This record's previous hash is not the previous record's hash: something was inserted,
    /// removed, or reordered around here.
    LinkMismatch {
        /// The predecessor's hash.
        expected: String,
        /// What the record points at.
        found: String,
    },
    /// The sequence is not contiguous: a gap, or a duplicate. A link check alone misses this when a
    /// whole contiguous run is removed from the TAIL.
    SequenceBreak {
        /// The position the walk was at.
        expected: u64,
        /// The position the record claims.
        found: u64,
    },
    /// A record from a different scope is present in this chain. A chain is scoped to ONE log;
    /// mixing them would make one caller's evidence depend on another caller's rows.
    ForeignScope {
        /// The chain's scope.
        expected: String,
        /// The record's.
        found: String,
    },
}

/// A verification failure: WHERE it is and WHAT it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The one-based index INTO THE SLICE at which the break was found. Distinct from the sequence,
    /// which is itself untrustworthy on a sequence break — reporting only the sequence would report
    /// the tampered value as if it were a position.
    pub at_index: usize,
    /// The record's claimed sequence number.
    pub seq: u64,
    /// The scope the chain is scoped to.
    pub scope: String,
    /// The stream's own words, carried so the message names WHICH log an operator has to go and
    /// look at without this type being generic over the record.
    pub labels: &'static ChainLabels,
    /// What is wrong.
    pub kind: ChainBreakKind,
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} for {} `{}` BROKEN at index {} (seq {}): ",
            self.labels.chain, self.labels.scope, self.scope, self.at_index, self.seq
        )?;
        match &self.kind {
            ChainBreakKind::DigestMismatch { stored, recomputed } => write!(
                f,
                "the record's own fields do not hash to its stored digest (stored {stored}, \
                 recomputed {recomputed}) — this record was EDITED"
            ),
            ChainBreakKind::LinkMismatch { expected, found } => write!(
                f,
                "prev_hash does not match the preceding record's hash (expected {expected}, found \
                 {found}) — a record was INSERTED, REMOVED or REORDERED here"
            ),
            ChainBreakKind::SequenceBreak { expected, found } => write!(
                f,
                "sequence is not contiguous (expected {expected}, found {found}) — records were \
                 REMOVED or DUPLICATED"
            ),
            ChainBreakKind::ForeignScope { expected, found } => write!(
                f,
                "a record belonging to {} `{found}` appears in {} `{expected}`'s chain",
                self.labels.scope, self.labels.scope
            ),
        }
    }
}

impl std::error::Error for ChainBreak {}

/// VERIFY A WHOLE CHAIN — `records` is the store's oldest-first list for ONE scope, starting at the
/// chain's genesis, so the sequence must start at one and the first previous hash must be empty.
///
/// An EMPTY list verifies. That is not a loophole waved through: "this scope has no records" is
/// indistinguishable from "every record was deleted" using the records alone, and pretending
/// otherwise would make the verifier claim a guarantee it cannot provide. What DOES narrow it is
/// held elsewhere, by whoever holds the OTHER half.
pub fn verify_chain<R: ChainedRecord>(records: &[R]) -> Result<(), ChainBreak> {
    walk(records, Anchor::Genesis)
}

/// VERIFY A WINDOW of a chain: the same walk, but the first record's position is taken as given
/// rather than required to be the genesis.
///
/// This exists for a BOUNDED RING: the oldest retained record's predecessor has legitimately been
/// pruned, so its link cannot be checked and its sequence is whatever the chain had reached.
/// Everything after it is checked exactly as [`verify_chain`] does. It is deliberately a SEPARATE
/// entry point rather than a lenient default: a caller that holds a whole chain and calls this would
/// be silently excusing a missing head.
pub fn verify_window<R: ChainedRecord>(records: &[R]) -> Result<(), ChainBreak> {
    walk(records, Anchor::Window)
}

/// Where the walk starts from.
enum Anchor {
    /// The chain's beginning: sequence one and an empty previous hash are required.
    Genesis,
    /// A window into a longer chain: the first record's position is taken as given, and only its own
    /// digest is checked.
    Window,
}

fn walk<R: ChainedRecord>(records: &[R], anchor: Anchor) -> Result<(), ChainBreak> {
    let Some(first) = records.first() else {
        return Ok(());
    };
    let scope = first.scope_of().to_string();
    let (mut expected_prev, mut expected_seq) = match anchor {
        Anchor::Genesis => (String::new(), 1u64),
        Anchor::Window => (first.prev_hash().to_string(), first.seq()),
    };

    for (i, rec) in records.iter().enumerate() {
        let at_index = i + 1;
        let brk = |kind| ChainBreak {
            at_index,
            seq: rec.seq(),
            scope: scope.clone(),
            labels: R::LABELS,
            kind,
        };
        if rec.scope_of() != scope {
            return Err(brk(ChainBreakKind::ForeignScope {
                expected: scope.clone(),
                found: rec.scope_of().to_string(),
            }));
        }
        if rec.seq() != expected_seq {
            return Err(brk(ChainBreakKind::SequenceBreak {
                expected: expected_seq,
                found: rec.seq(),
            }));
        }
        // The LINK is checked before the DIGEST. Both are wrong when a record is spliced out, and
        // the link is the one that names the real defect ("something is missing here") while the
        // digest would report the innocent successor as edited.
        if rec.prev_hash() != expected_prev {
            return Err(brk(ChainBreakKind::LinkMismatch {
                expected: expected_prev.clone(),
                found: rec.prev_hash().to_string(),
            }));
        }
        let recomputed = digest(rec);
        if recomputed != rec.hash() {
            return Err(brk(ChainBreakKind::DigestMismatch {
                stored: rec.hash().to_string(),
                recomputed,
            }));
        }
        expected_prev = rec.hash().to_string();
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(())
}
