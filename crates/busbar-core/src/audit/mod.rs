// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPEND-ONLY HASH CHAIN — one mechanism, in core, for every stream of evidence busbar keeps.
//!
//! ## Why this is core and not a plane's
//!
//! Owner's ruling, 2026-08-13: *"auditing is core. nothing auditing wise should be mcp a2a or llm
//! specific. thats how audits break."* It is exact, and the reason is the product claim rather than
//! tidiness. busbar sells TAMPER-EVIDENCE: a chain detects an altered, reordered, inserted or
//! deleted record after the fact. THREE chain implementations mean three answers to "what happened",
//! and an auditor reads whichever one was wired last. A per-plane audit does not merely duplicate
//! code — it falsifies the property the code exists to provide.
//!
//! So there is ONE append ([`Chain::append`]/[`seal`]), ONE digest ([`digest`]) and ONE verifier
//! ([`verify_chain`]/[`verify_window`]), and they live here. A plane supplies the RECORD; it never
//! supplies the mechanism. [`crate::trust`] is the precedent this copies rather than a new idea: it
//! owns the trust lifecycle while a plane supplies only the artifact, and `a2a/pin.rs` says so in
//! its own header — *"A2A supplies an artifact; it does not supply a second state machine."*
//!
//! ## ONE MECHANISM IS NOT ONE STREAM, and conflating them would be a different defect
//!
//! Three chains run on this one mechanism and they stay SEPARATE:
//!
//! | stream | scope of a chain | rate |
//! |---|---|---|
//! | [`crate::admin::audit`] — admin MUTATIONS | one chain, process-wide | operator-rate |
//! | [`crate::calllog`] — MCP tool CALLS | one chain per PRINCIPAL | request-rate |
//! | [`crate::provenance`] — A2A task EVENTS | one chain per TASK | task-rate |
//!
//! `mcp/calllog.rs`'s own header records why the per-call event was moved OFF the admin ring: an
//! admin mutation is operator-rate and a tool call is REQUEST-rate, so sharing one bounded ring
//! means a busy afternoon evicts every admin record, silently. Unifying the MECHANISM must not
//! re-merge the STREAMS, and it does not: [`ChainedRecord::scope_of`] is what keeps them apart, and
//! the verifier REFUSES a record whose scope is not the chain's ([`ChainBreakKind::ForeignScope`]),
//! so one caller's evidence can never be made to depend on another caller's rows. store-mysql had a
//! real cross-principal read defect of exactly that shape (a case-insensitive collation let one key
//! id read another's chain), and the scope check is the engine-side half of not repeating it.
//!
//! ## WHAT A PLANE STILL OWNS: which fields the digest covers
//!
//! The three digests cover different fields, and that difference is legitimate — an admin mutation
//! has an `action` and a `resource`, a tool call has a `tool` and a pin generation, a task event has
//! a state. So [`ChainedRecord::digest_fields`] is the ONE thing a record type supplies about the
//! digest: which fields, in which order. Everything else — the sequence allocation, the `prev_hash`
//! linkage, the canonicalisation, the hash function and the verification walk — is here, once.
//!
//! ADDING A FOURTH STREAM COSTS A RECORD TYPE AND NOTHING ELSE. That is the acceptance test for this
//! seam, and `tests/chain_tests.rs` writes a throwaway fourth record type and chains and verifies it
//! with no new mechanism, so the claim is checked rather than asserted.
//!
//! ## The claim, stated honestly
//!
//! TAMPER-EVIDENCE, not tamper-prevention. A chain detects an altered, reordered, inserted or
//! removed record AFTER the fact; it does not stop one, and a host compromised at the moment of
//! writing can rewrite a whole chain consistently and this will verify. Prevention means shipping
//! the records off-box to something the compromised host cannot rewrite. Anything stronger said
//! about it is oversold.

pub(crate) mod journal;
pub mod vocab {
    pub use busbar_substrate::audit::vocab::*;
}

use std::marker::PhantomData;

/// HOW A RECORD'S FIELDS ARE FRAMED INTO THE DIGEST INPUT.
///
/// This is a WIRE FACT of chains that already exist on disk, not a preference. Every framing here is
/// the one the corresponding records were written with, and the store contract documents the formula
/// (see `busbar_api::AuditRecord`/`TaskEventRow`). Changing the framing of an existing stream would
/// make every persisted chain in every deployment fail to verify at the next boot — which is to say
/// it would report the whole history as TAMPERED. That is the one migration this module may never do
/// silently, so the framing travels with the record type instead of being unified away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// Every field is prefixed with its big-endian `u64` length, and integers are their 8-byte
    /// big-endian form. THE FRAMING A NEW RECORD TYPE MUST CHOOSE: length prefixes make the split
    /// between fields unforgeable regardless of what any field contains, so a caller who can choose
    /// one field's bytes cannot forge the same byte stream under a different split. A
    /// separator-joined digest is only safe while no field can contain the separator, which is a
    /// property of today's fields rather than of the code.
    LengthPrefixed,
    /// Fields joined by `|`, integers in decimal. The legacy framing of the admin audit chain and
    /// the A2A task provenance chain, kept byte-for-byte because their records are already on disk.
    PipeSeparated,
}

/// THE ONE CANONICALISER. A record feeds its chained fields in through [`Digest::text`] and
/// [`Digest::num`]; the framing and the hash function are not its business.
pub(crate) struct Digest {
    framing: Framing,
    buf: Vec<u8>,
    /// PipeSeparated only: whether a separator is owed before the next field.
    started: bool,
}

impl Digest {
    fn new(framing: Framing) -> Self {
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
    pub(crate) fn text(&mut self, s: &str) -> &mut Self {
        self.push(s.as_bytes());
        self
    }

    /// Feed one integer field.
    pub(crate) fn num(&mut self, v: u64) -> &mut Self {
        match self.framing {
            Framing::LengthPrefixed => self.push(&v.to_be_bytes()),
            Framing::PipeSeparated => self.push(v.to_string().as_bytes()),
        }
        self
    }

    /// Feed ALREADY-FRAMED raw bytes verbatim — the join primitive for the host-side journal cleave.
    /// The plane hands a pre-framed content SUFFIX and the host byte-concatenates it after the framed
    /// prelude, so `sha256_hex(frame_prelude(..) ⧺ suffix)` byte-equals the legacy single-[`Digest`]
    /// output (the chain-cleave contract). Frame-independent: it appends no
    /// length prefix and no separator of its own — the suffix already carries the leading `|` a
    /// PipeSeparated stream owes (Option A). It still flips `started`. ADDITIVE: no existing digest
    /// calls it, so not a single persisted byte changes.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self.started = true;
        self
    }

    fn finish(self) -> String {
        busbar_api::sha256_hex(&self.buf)
    }
}

/// Frame a chain record's PRELUDE — `prev_hash`, then `scope` IFF `digests_scope` (some streams omit
/// it), then `seq` — in `framing`, returning the raw framed bytes. The host owns the prelude; a plane
/// supplies only its own content suffix, and the digest input is `frame_prelude(..) ⧺ suffix`. The
/// PipeSeparated genesis landmine is preserved BY CONSTRUCTION: `prev_hash` is pushed FIRST and always
/// (even when empty), which flips `started`, so an empty genesis `prev_hash` still yields the leading
/// `|` before `seq`/`scope` that every deployed store was written with. ADDITIVE — not yet on any
/// persisted path; the Phase-3 `audit::Journal` will own the whole append through it.
pub(crate) fn frame_prelude(
    framing: Framing,
    prev_hash: &str,
    scope: Option<&str>,
    seq: u64,
) -> Vec<u8> {
    let mut d = Digest::new(framing);
    d.text(prev_hash);
    if let Some(s) = scope {
        d.text(s);
    }
    d.num(seq);
    d.buf
}

/// The operator-facing words for one stream: what to call the chain, and what to call the thing a
/// chain is scoped to. Carried by a [`ChainBreak`] so the message names WHICH log to go and look at
/// without the error type having to be generic over the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainLabels {
    /// Written as it should read mid-sentence, e.g. "the MCP per-call chain".
    pub(crate) chain: &'static str,
    /// The noun for what one chain is scoped TO: "principal", "task", "log".
    pub(crate) scope: &'static str,
}

/// ONE KIND OF CHAINED RECORD. Implementing this is the ENTIRE cost of a new stream of evidence:
/// the chaining, the sequence allocation, the linkage, the digest and the verifier are inherited.
///
/// `seq`, `prev_hash` and `hash` are NEVER caller-supplied — [`ChainedRecord::Input`] is the payload
/// a call site may choose, and [`ChainedRecord::link`] receives the chain's own allocations
/// separately, so no call site can supply a sequence number or a link of its own choosing.
pub(crate) trait ChainedRecord: Sized {
    /// The fields a caller supplies. It must NOT contain `seq`, `prev_hash` or `hash`.
    type Input;

    /// The operator-facing words for this stream, used when a break is reported.
    ///
    /// ONE reference rather than two `&'static str` consts, and the reason is mechanical: [`ChainBreak`]
    /// is returned by value from every verifier, and two fat pointers pushed it over the size at
    /// which a large `Err` variant becomes its own defect (`clippy::result_large_err`). A pointer to
    /// a promoted static costs eight bytes and says the same thing.
    const LABELS: &'static ChainLabels;
    /// See [`Framing`] — a wire fact of the records already on disk, not a preference.
    const FRAMING: Framing;

    /// The chain this record belongs to. A chain holds exactly one scope; the verifier refuses any
    /// record whose scope is not the chain's.
    fn scope_of(&self) -> &str;
    fn seq(&self) -> u64;
    fn prev_hash(&self) -> &str;
    fn hash(&self) -> &str;

    /// Build the record from the chain's allocations plus the caller's payload. `hash` is left
    /// empty; [`seal`] fills it and is the only thing that may.
    fn link(scope: &str, seq: u64, prev_hash: String, input: Self::Input) -> Self;

    /// Store the computed digest. [`seal`] is the only caller; a record type that set its own hash
    /// anywhere else would be a second place a digest is computed.
    fn set_hash(&mut self, hash: String);

    /// FEED THE CHAINED FIELDS, IN ORDER — the one thing a plane says about the digest.
    ///
    /// `prev_hash` is fed here too rather than by the mechanism, because the three existing streams
    /// do not agree on where it sits relative to the scope, and their field ORDER is as much a wire
    /// fact as the framing is.
    ///
    /// A field left out is a field a tamper can change without detection, so anything that carries
    /// meaning about WHAT HAPPENED belongs in. A pure JOIN KEY (`request_id`) is deliberately left
    /// out: it is supplied by the request spine and is legitimately absent on paths with no inbound
    /// request, and a field that is sometimes absent must not be able to make an otherwise-intact
    /// chain unverifiable.
    fn digest_fields(&self, d: &mut Digest);
}

/// Recompute a record's digest from its own fields — the verification primitive, and the only place
/// a digest is ever computed.
pub(crate) fn digest<R: ChainedRecord>(record: &R) -> String {
    let mut d = Digest::new(R::FRAMING);
    record.digest_fields(&mut d);
    d.finish()
}

/// Build a record at a given chain position and SEAL it with its digest. The one construction path:
/// `seq` and `prev_hash` arrive as arguments from whatever owns the position ([`Chain`], or the
/// admin ring which allocates under its own lock), never from the caller's payload.
pub(crate) fn seal<R: ChainedRecord>(
    scope: &str,
    seq: u64,
    prev_hash: String,
    input: R::Input,
) -> R {
    let mut record = R::link(scope, seq, prev_hash, input);
    record.set_hash(digest(&record));
    record
}

/// ONE CHAIN'S POSITION, in memory: the tail link and the next sequence number. Small on purpose —
/// the records themselves live in the store, and holding every record of every scope in RAM is the
/// thing a durable log exists to avoid.
pub(crate) struct Chain<R> {
    /// The `hash` of the most recent record, or empty when the chain is empty.
    tail_hash: String,
    /// The sequence the NEXT appended record gets.
    next_seq: u64,
    /// `fn() -> R` rather than `R`: the position owns no record, so the marker must not drag
    /// variance or auto-trait obligations in from the record type.
    _record: PhantomData<fn() -> R>,
}

/// HAND-WRITTEN, and it must stay that way: a DERIVED `Default` gives `next_seq: 0`, which is not a
/// valid sequence — the first record of a chain is `seq` 1 — and the derive would hand a silently
/// zero-based chain to every `entry().or_default()` that reaches it. That is not hypothetical: it is
/// exactly what a clippy suggestion to replace `or_insert_with(Chain::new)` with `or_default()`
/// produced on the MCP call log, and it went undetected by that module's own focused run because the
/// two constructors were only distinguishable through the SUITE. Now there is one `Default` for
/// every stream instead of one per plane, so the hazard is closed in one place. Pinned by
/// `the_default_chain_is_the_new_chain_because_a_derived_default_starts_at_zero`.
impl<R> Default for Chain<R> {
    fn default() -> Self {
        // The same body as `Chain::new`, written out rather than delegating, only because `new`
        // carries a `R: ChainedRecord` bound this impl deliberately does not. `next_seq: 1` is the
        // invariant either way, and the test named above pins the two against each other.
        Chain {
            tail_hash: String::new(),
            next_seq: 1,
            _record: PhantomData,
        }
    }
}

// Hand-written rather than derived for the same reason `Default` is: a derive would demand
// `R: Clone`/`R: Debug`/`R: PartialEq` of the RECORD type, which the position does not hold.
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
    /// A chain with nothing in it. The first record gets `seq` 1 and an empty `prev_hash`.
    pub(crate) fn new() -> Self {
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
    pub(crate) fn from_persisted(records: &[R]) -> Result<Self, ChainBreak> {
        verify_chain(records)?;
        Ok(Self::from_persisted_unverified(records))
    }

    /// Position a chain on the tail of `records` WITHOUT verifying them. Only for the
    /// tamper-detected path, where the break has already been reported and the alternative is to
    /// stop recording evidence entirely.
    pub(crate) fn from_persisted_unverified(records: &[R]) -> Self {
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
    pub(crate) fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Append one record, linking it to the tail and advancing the chain.
    pub(crate) fn append(&mut self, scope: &str, input: R::Input) -> R {
        let record: R = seal(scope, self.next_seq, self.tail_hash.clone(), input);
        self.tail_hash = record.hash().to_string();
        self.next_seq = self.next_seq.saturating_add(1);
        record
    }
}

/// WHY a chain failed to verify. Four distinguishable causes, because the operator's response to
/// each is different — a verifier that returns `bool` tells an operator that something is wrong and
/// nothing else, which in practice means it is run once and then ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainBreakKind {
    /// This record's stored `hash` is not the digest of its own fields: a field was edited in place.
    DigestMismatch { stored: String, recomputed: String },
    /// This record's `prev_hash` is not the previous record's `hash`: something was inserted,
    /// removed, or reordered around here.
    LinkMismatch { expected: String, found: String },
    /// The sequence is not contiguous: a gap (records removed) or a duplicate/regression. A link
    /// check alone misses this when a whole contiguous run is removed from the TAIL.
    SequenceBreak { expected: u64, found: u64 },
    /// A record from a different scope is present in this chain. A chain is scoped to ONE principal,
    /// task or log; mixing them would make one caller's evidence depend on another caller's rows.
    ForeignScope { expected: String, found: String },
}

/// A verification failure: WHERE it is and WHAT it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The 1-based index INTO THE SLICE at which the break was found. Distinct from `seq`, which is
    /// itself untrustworthy on a `SequenceBreak` — reporting only `seq` would report the tampered
    /// value as if it were a position.
    pub(crate) at_index: usize,
    /// The record's claimed sequence number.
    pub(crate) seq: u64,
    /// The scope the chain is scoped to (the principal id, the task id, …).
    pub scope: String,
    /// The stream's own words, carried so the message names WHICH log an operator has to go and
    /// look at without this type being generic over the record.
    pub(crate) labels: &'static ChainLabels,
    pub(crate) kind: ChainBreakKind,
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

/// VERIFY A WHOLE CHAIN — `records` is the store's oldest-first list for ONE scope, starting at the
/// chain's genesis, so `seq` must start at 1 and the first `prev_hash` must be empty.
///
/// An EMPTY list verifies. That is not a loophole waved through: "this scope has no records" is
/// indistinguishable from "every record was deleted" using the records alone, and pretending
/// otherwise would make the verifier claim a guarantee it cannot provide. What DOES narrow it is
/// held elsewhere, by whoever holds the OTHER half — a store that enumerates a principal it then
/// returns no rows for, or a task row whose chain does not reach its terminal state.
pub(crate) fn verify_chain<R: ChainedRecord>(records: &[R]) -> Result<(), ChainBreak> {
    walk(records, Anchor::Genesis)
}

/// VERIFY A WINDOW of a chain: the same walk, but the first record's position is taken as given
/// rather than required to be the genesis.
///
/// This exists for a BOUNDED RING (the admin audit log keeps the most recent
/// `MAX_AUDIT_ENTRIES` and the durable store keeps the rest): the oldest retained record's
/// predecessor has legitimately been pruned, so its link cannot be checked and its `seq` is
/// whatever the chain had reached. Everything after it is checked exactly as [`verify_chain`] does.
/// It is deliberately a SEPARATE entry point rather than a lenient default: a caller that holds a
/// whole chain and calls this would be silently excusing a missing head.
pub(crate) fn verify_window<R: ChainedRecord>(records: &[R]) -> Result<(), ChainBreak> {
    walk(records, Anchor::Window)
}

/// Where the walk starts from.
enum Anchor {
    /// The chain's beginning: `seq` 1 and an empty `prev_hash` are required.
    Genesis,
    /// A window into a longer chain: the first record's `seq`/`prev_hash` are taken as given, and
    /// only its own digest is checked.
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

#[cfg(test)]
#[path = "tests/chain_tests.rs"]
mod chain_tests;

#[cfg(test)]
#[path = "tests/boot_verify_golden.rs"]
mod boot_verify_golden;
