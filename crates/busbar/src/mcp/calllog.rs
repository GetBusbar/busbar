// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE PER-CALL LOG: one hash-chained record per MCP tool call, written through to the
//! configured governance store, read back at boot, and verifiable.
//!
//! ## Why this is not the admin audit log
//!
//! The per-call event used to ride [`crate::admin::audit::AUDIT`]. That log is admin-MUTATION-only
//! and its engine-side working set is a bounded ring of
//! [`crate::admin::audit::MAX_AUDIT_ENTRIES`] entries. An admin mutation is operator-rate; a tool
//! call is REQUEST-rate. Sharing the ring means one busy afternoon of tool calls evicts every admin
//! row from it, so "who changed this registration" stops being answerable at exactly the moment an
//! incident makes somebody ask — and the loss is silent, because a ring that pruned looks identical
//! to a ring that was never written to. Two populations that churn at different rates do not share
//! one bounded buffer.
//!
//! ## The shape is the A2A task store's, deliberately
//!
//! [`crate::a2a`]'s durable substrate settled this same problem — "make a stateful thing survive a
//! restart without breaking every already-signed store plugin" — and this is that shape:
//!
//! - the [`busbar_api::Store`] methods are DEFAULTED, so a plugin built before they existed keeps
//!   compiling and simply provides no durability;
//! - the defaults ACCEPT AND KEEP NOTHING, which makes a write's return value worthless as evidence:
//!   the engine learns whether a deployment is durable by READING BACK, never from an `Ok(())`;
//! - the chain is scoped to a bounded unit rather than being global (there, the task; here, the
//!   principal — see [`busbar_api::McpCallRecord`] for why those two and not the server);
//! - a chain break found at boot is REPORTED while the row is STILL RESTORED. Refusing to restore a
//!   record whose chain does not verify would turn a DETECTION control into a DELETION primitive:
//!   anyone who can write to the store could erase a caller's whole call history by corrupting one
//!   byte of one record. The break is named, loudly, and the chain continues from the broken tail
//!   rather than being silently re-based onto it.
//!
//! ## What the claim actually is
//!
//! TAMPER-EVIDENCE, not tamper-prevention. A chain detects an altered, reordered, inserted or
//! removed record after the fact; it does not stop one, and a host compromised at the moment of
//! writing can rewrite a whole chain consistently and this will verify. Prevention means shipping
//! the records off-box to something the compromised host cannot rewrite. Anything stronger said
//! about it is oversold.
//!
//! ## The RAM default really is lossy, and that is a product contract
//!
//! `store: memory` implements none of these methods, so the trait defaults apply, nothing persists,
//! and [`McpCallLog::restore_from_store`] reports zero. That zero is the truth being reported, not a
//! bug, and the engine must never paper over it — `tests/calllog_tests.rs` keeps a permanent paired
//! NEGATIVE test asserting exactly that, because a durability test that has never seen a
//! non-durable store has proven nothing.

// NO PRODUCTION CALL SITE ON THIS BRANCH, and that is a coordination fact rather than an oversight.
// The one place a per-call record is emitted today is the inbound method dispatcher, which a
// sibling agent holds open on a parallel branch for the upstream leg; rewriting its audit call here
// would guarantee a conflict on the file whose merge matters most. The substrate, its chain, its
// verifier and its restore are what needed settling and pinning first, and they are exercised
// end-to-end by their own tests. Same posture the trust lifecycle and the audience-bound mint took.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_api::{McpCallRecord, Store, StoreResult};

/// Outcome tokens. Small, stable, greppable — tooling branches on these strings.
pub(crate) const OUTCOME_DISPATCHED: &str = "dispatched";
pub(crate) const OUTCOME_REFUSED: &str = "refused";

/// The fields a caller supplies for one call record. `seq`, `prev_hash` and `hash` are NOT here:
/// they are the chain's own business and are computed by [`CallChain::append`], so no call site can
/// supply a sequence number or a link of its own choosing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallInput {
    pub(crate) ts: u64,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) outcome: &'static str,
    pub(crate) reason: String,
    pub(crate) tool_digest: String,
    pub(crate) pin_generation: u64,
    pub(crate) request_id: String,
}

/// The digest over a record's CHAINED fields.
///
/// `request_id` is deliberately EXCLUDED. It is a join key handed in by the request spine, it is
/// absent on any path with no inbound request, and a field that is sometimes absent must not be able
/// to make an otherwise-intact chain unverifiable.
///
/// Every field IS length-prefixed rather than separator-joined. `tool` carries a caller-supplied
/// name and `reason`/`server` are engine-controlled tokens, but relying on that split is the classic
/// digest-collision-by-framing bug: a caller who can choose one field's bytes can otherwise forge
/// the same byte stream under a different split. Length prefixes make the split unforgeable
/// regardless of what any field contains, so this stays correct if a future field becomes
/// caller-influenced.
fn compute_hash(record: &McpCallRecord) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut field = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    field(record.prev_hash.as_bytes());
    field(record.principal.as_bytes());
    field(&record.seq.to_be_bytes());
    field(&record.ts.to_be_bytes());
    field(record.server.as_bytes());
    field(record.tool.as_bytes());
    field(record.outcome.as_bytes());
    field(record.reason.as_bytes());
    field(record.tool_digest.as_bytes());
    field(&record.pin_generation.to_be_bytes());
    busbar_api::sha256_hex(&buf)
}

/// ONE PRINCIPAL'S CHAIN, in memory: the tail link and the next sequence number. Small on purpose —
/// the records themselves live in the store, and holding every call of every caller in RAM is the
/// thing this durable path exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallChain {
    /// The `hash` of the most recent record, or empty when the chain is empty.
    tail_hash: String,
    /// The sequence the NEXT appended record gets.
    next_seq: u64,
}

/// HAND-WRITTEN, and it must stay that way: a DERIVED `Default` gives `next_seq: 0`, which is not a
/// valid sequence — the first record of a chain is `seq` 1 — and the derive would hand a silently
/// zero-based chain to every `entry().or_default()` in the file. That is not hypothetical: it is
/// exactly what a clippy suggestion to replace `or_insert_with(CallChain::new)` with `or_default()`
/// produced, and it went undetected by the module's own focused run because the two constructors
/// were only distinguishable through the SUITE. Pinned by
/// `the_default_chain_is_the_new_chain_because_a_derived_default_starts_at_zero`.
impl Default for CallChain {
    fn default() -> Self {
        CallChain::new()
    }
}

impl CallChain {
    /// A chain with nothing in it. The first record gets `seq` 1 and an empty `prev_hash`.
    pub(crate) fn new() -> Self {
        CallChain {
            tail_hash: String::new(),
            next_seq: 1,
        }
    }

    /// Continue a chain from what is already PERSISTED, so a restart continues the same chain rather
    /// than opening a second one under the same principal.
    ///
    /// The records are VERIFIED before they are trusted to position the chain. Resuming from an
    /// unverified tail would append a valid-looking link onto a forged one and launder the forgery:
    /// every subsequent verification would pass and the break would sit permanently behind the point
    /// anybody looks. On a broken chain this returns the break and the CALLER decides — the engine's
    /// answer is [`CallChain::from_persisted_unverified`], because refusing to record anything
    /// further would mean a detected tamper silently stops all further evidence.
    pub(crate) fn from_persisted(records: &[McpCallRecord]) -> Result<Self, ChainBreak> {
        verify_chain(records)?;
        Ok(Self::from_persisted_unverified(records))
    }

    /// Position a chain on the tail of `records` WITHOUT verifying them. Only for the
    /// tamper-detected path, where the break has already been reported and the alternative is to
    /// stop recording evidence entirely.
    pub(crate) fn from_persisted_unverified(records: &[McpCallRecord]) -> Self {
        match records.last() {
            None => CallChain::new(),
            Some(last) => CallChain {
                tail_hash: last.hash.clone(),
                next_seq: last.seq.saturating_add(1),
            },
        }
    }

    /// The sequence the next appended record will carry.
    pub(crate) fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Append one record, linking it to the tail and advancing the chain.
    pub(crate) fn append(&mut self, principal: &str, input: CallInput) -> McpCallRecord {
        let mut record = McpCallRecord {
            principal: principal.to_string(),
            seq: self.next_seq,
            ts: input.ts,
            server: input.server,
            tool: input.tool,
            outcome: input.outcome.to_string(),
            reason: input.reason,
            tool_digest: input.tool_digest,
            pin_generation: input.pin_generation,
            request_id: input.request_id,
            prev_hash: self.tail_hash.clone(),
            hash: String::new(),
        };
        record.hash = compute_hash(&record);
        self.tail_hash = record.hash.clone();
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
    /// The sequence is not `1, 2, 3, …`: a gap (records removed) or a duplicate/regression. A link
    /// check alone misses this when a whole contiguous run is removed from the TAIL.
    SequenceBreak { expected: u64, found: u64 },
    /// A different principal's record is present in this chain. A chain is scoped to ONE principal;
    /// mixing them would make one caller's evidence depend on another caller's rows.
    ForeignPrincipal { expected: String, found: String },
}

/// A verification failure: WHERE it is and WHAT it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainBreak {
    /// The 1-based index INTO THE SLICE at which the break was found. Distinct from `seq`, which is
    /// itself untrustworthy on a `SequenceBreak` — reporting only `seq` would report the tampered
    /// value as if it were a position.
    pub(crate) at_index: usize,
    /// The record's claimed sequence number.
    pub(crate) seq: u64,
    /// The principal the chain is scoped to.
    pub(crate) principal: String,
    pub(crate) kind: ChainBreakKind,
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MCP call chain for principal `{}` BROKEN at index {} (seq {}): ",
            self.principal, self.at_index, self.seq
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
            ChainBreakKind::ForeignPrincipal { expected, found } => write!(
                f,
                "a record belonging to principal `{found}` appears in principal `{expected}`'s chain"
            ),
        }
    }
}

/// VERIFY one principal's chain. `records` must be the store's oldest-first list for a single
/// principal.
///
/// An EMPTY list verifies. That is not a loophole waved through: "this principal made no calls" is
/// indistinguishable from "every record was deleted" using the records alone, and pretending
/// otherwise would make the verifier claim a guarantee it cannot provide. What DOES narrow it is
/// held elsewhere — [`Store::list_mcp_call_principals`] names a principal the store has rows for, so
/// an enumerated principal with an empty chain is detectable by the caller that holds both, which is
/// what [`McpCallLog::restore_from_store`] does.
pub(crate) fn verify_chain(records: &[McpCallRecord]) -> Result<(), ChainBreak> {
    let Some(first) = records.first() else {
        return Ok(());
    };
    let principal = first.principal.clone();
    let mut expected_prev = String::new();
    let mut expected_seq = 1u64;

    for (i, rec) in records.iter().enumerate() {
        let at_index = i + 1;
        let brk = |kind| ChainBreak {
            at_index,
            seq: rec.seq,
            principal: principal.clone(),
            kind,
        };
        if rec.principal != principal {
            return Err(brk(ChainBreakKind::ForeignPrincipal {
                expected: principal.clone(),
                found: rec.principal.clone(),
            }));
        }
        if rec.seq != expected_seq {
            return Err(brk(ChainBreakKind::SequenceBreak {
                expected: expected_seq,
                found: rec.seq,
            }));
        }
        // The LINK is checked before the DIGEST. Both are wrong when a record is spliced out, and
        // the link is the one that names the real defect ("something is missing here") while the
        // digest would report the innocent successor as edited.
        if rec.prev_hash != expected_prev {
            return Err(brk(ChainBreakKind::LinkMismatch {
                expected: expected_prev.clone(),
                found: rec.prev_hash.clone(),
            }));
        }
        let recomputed = compute_hash(rec);
        if recomputed != rec.hash {
            return Err(brk(ChainBreakKind::DigestMismatch {
                stored: rec.hash.clone(),
                recomputed,
            }));
        }
        expected_prev = rec.hash.clone();
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(())
}

/// What a boot rehydrate actually found. Every number is reported rather than summed into one
/// "restored" count: they mean different things to an operator, and a single number hides the two
/// that are bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Restored {
    /// Principals whose chain position was resumed.
    pub(crate) principals: usize,
    /// Records read back across every principal. THE DURABILITY SIGNAL: zero here on a deployment
    /// that has been serving calls means the configured backend is keeping none of them.
    pub(crate) records: usize,
    /// Principals the store ENUMERATED but returned no records for. Counted rather than ignored: an
    /// enumerated-but-empty chain is the one shape the verifier cannot judge on its own (see
    /// [`verify_chain`]), and it is what a wholesale deletion of one caller's evidence looks like.
    pub(crate) empty_chains: usize,
    /// Chains that FAILED to verify. Tamper evidence. The records are still restored and the chain
    /// still resumes — refusing would let anyone who can write to the store erase a caller's history
    /// by corrupting one byte — but the break is reported and the chain continues from the broken
    /// tail rather than being silently re-based onto it.
    pub(crate) chain_breaks: Vec<ChainBreak>,
}

/// Why a call record could not be written durably.
#[derive(Debug)]
pub(crate) enum CallLogError {
    /// The durable write failed. SURFACED rather than swallowed: an evidence record that is not
    /// durable is one a restart will lose, and the caller has to be able to decide whether that is
    /// acceptable for the call it is recording.
    Store(busbar_api::StoreError),
}

impl std::fmt::Display for CallLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallLogError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// THE PER-CALL LOG. No `Debug`: `dyn Store` is not `Debug` (a backend must not be obliged to render
/// itself, and one that did would be a place a credential could surface in a log).
#[derive(Default)]
pub(crate) struct McpCallLog {
    /// Chain POSITIONS only, keyed by principal — a tail hash and a next sequence, never the
    /// records. The store owns the records.
    chains: Mutex<HashMap<String, CallChain>>,
    sink: Mutex<Option<Arc<dyn Store>>>,
}

/// THE PROCESS-WIDE CALL LOG. Process state, not config-derived state, so it lives as a global
/// rather than on the swappable `App` snapshot — exactly like [`crate::admin::audit::AUDIT`], and
/// for the same reason: a config apply must not reset the chain positions, because doing so would
/// open a SECOND chain at seq 1 under a principal that already has one, and two chains that each
/// verify and together describe nothing is strictly worse than no chain at all.
pub(crate) static CALLS: std::sync::LazyLock<McpCallLog> =
    std::sync::LazyLock::new(McpCallLog::new);

impl McpCallLog {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Poison-recovering lock. The data behind it stays consistent after a panic (the critical
    /// sections only mutate a map of chain positions), and cascading a poison would make every
    /// subsequent tool call panic too — a data plane that wedges permanently because one request
    /// panicked.
    fn chains(&self) -> MutexGuard<'_, HashMap<String, CallChain>> {
        self.chains.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sink(&self) -> Option<Arc<dyn Store>> {
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
    }

    /// Attach the configured governance store as the DURABLE SINK. Called once at boot. With no sink
    /// attached — or with a backend that implements none of these methods, which is the same thing
    /// from here — the log keeps chain positions in RAM and nothing survives a restart. That is the
    /// documented `store: memory` behaviour.
    pub(crate) fn set_sink(&self, store: Arc<dyn Store>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// BOOT REHYDRATE. Enumerate the principals the store holds records for, resume each chain from
    /// its persisted tail, and REPORT what was found.
    ///
    /// This is the ONLY place durability is learned. A write's `Ok(())` proves nothing (the trait
    /// default accepts and keeps nothing), so the engine finds out what its backend actually kept by
    /// reading it back.
    pub(crate) fn restore_from_store(&self, store: &dyn Store) -> StoreResult<Restored> {
        let principals = store.list_mcp_call_principals()?;
        let mut out = Restored::default();
        let mut chains = self.chains();
        for principal in &principals {
            let records = store.list_mcp_calls(principal)?;
            if records.is_empty() {
                // The store named this principal and then produced nothing for it. Reported, never
                // silently skipped: it is exactly what one caller's evidence being deleted wholesale
                // looks like, and the verifier alone cannot tell it from "never called".
                tracing::error!(
                    principal = %principal,
                    "the durable MCP call log enumerates this principal but returned NO records \
                     for it; the chain is being reopened at seq 1 and the discrepancy is reported \
                     rather than skipped silently"
                );
                out.empty_chains += 1;
                chains.insert(principal.clone(), CallChain::new());
                out.principals += 1;
                continue;
            }
            let chain = match CallChain::from_persisted(&records) {
                Ok(c) => c,
                Err(brk) => {
                    // REPORTED, and the records stay restored. See the module header: refusing here
                    // would convert a detection control into a deletion primitive.
                    tracing::error!(
                        principal = %principal,
                        break_detail = %brk,
                        "MCP per-call CHAIN VERIFICATION FAILED on restore — the persisted records \
                         do not verify against their own hash chain. They are still restored and \
                         the chain resumes from the broken tail; refusing to restore them would let \
                         anyone able to write to the store DELETE a caller's history by corrupting \
                         one record."
                    );
                    out.chain_breaks.push(brk);
                    CallChain::from_persisted_unverified(&records)
                }
            };
            out.records += records.len();
            chains.insert(principal.clone(), chain);
            out.principals += 1;
        }
        Ok(out)
    }

    /// RECORD one tool call: chain it, write it through, and advance the chain only once the durable
    /// write has succeeded.
    ///
    /// The order matters. Advancing the in-memory chain first and writing afterwards leaves the
    /// process believing a record exists that a restart will then un-happen, and — worse for a hash
    /// chain — burns a sequence number that nothing occupies, so the next successful write lands on
    /// a `seq` the verifier will report as a gap forever. On a failed write the position is left
    /// exactly where it was, so the next call reuses the sequence and the chain stays contiguous.
    pub(crate) fn record(
        &self,
        principal: &str,
        input: CallInput,
    ) -> Result<McpCallRecord, CallLogError> {
        let mut chains = self.chains();
        let chain = chains.entry(principal.to_string()).or_default();
        let mut candidate = chain.clone();
        let record = candidate.append(principal, input);
        if let Some(store) = self.sink() {
            store
                .append_mcp_call(&record)
                .map_err(CallLogError::Store)?;
        }
        *chain = candidate;
        Ok(record)
    }

    /// The sequence the next record for `principal` will carry. 1 for a principal with no chain.
    pub(crate) fn next_seq(&self, principal: &str) -> u64 {
        self.chains()
            .get(principal)
            .map(CallChain::next_seq)
            .unwrap_or(1)
    }

    /// How many principals this process is holding a chain position for.
    pub(crate) fn len(&self) -> usize {
        self.chains().len()
    }

    /// READ ONE PRINCIPAL'S CALLS BACK from the store. The durability question, asked the only way
    /// it can honestly be asked.
    pub(crate) fn read_back(
        &self,
        store: &dyn Store,
        principal: &str,
    ) -> StoreResult<Vec<McpCallRecord>> {
        store.list_mcp_calls(principal)
    }

    /// VERIFY one principal's persisted chain, end to end, against the store.
    ///
    /// This is the operator-facing half, and its existence is the difference between evidence and
    /// decoration: a chain nothing ever recomputes proves nothing, because nobody ever finds out
    /// that it does not verify. `Ok(Ok(n))` is `n` records verified; `Ok(Err(brk))` names where and
    /// which; `Err` is the store failing to answer, which is not a verdict about the chain.
    pub(crate) fn verify_principal_chain(
        &self,
        store: &dyn Store,
        principal: &str,
    ) -> StoreResult<Result<usize, ChainBreak>> {
        let records = store.list_mcp_calls(principal)?;
        match verify_chain(&records) {
            Ok(()) => Ok(Ok(records.len())),
            Err(brk) => Ok(Err(brk)),
        }
    }

    /// RETENTION: ask the store to drop call records older than `before`. Returns how many durable
    /// rows went. The policy lives at the call site, not here — retention is a setting, not a
    /// subsystem — so this owns the mechanism and nothing about the window.
    ///
    /// Chain positions are NOT reset. A purge removes the oldest records; reopening the chain at
    /// seq 1 afterwards would make every subsequent record collide with a sequence the store may
    /// still hold, which is the one thing the append contract calls a forked log.
    pub(crate) fn compact(&self, before: u64) -> StoreResult<u64> {
        match self.sink() {
            Some(store) => store.purge_mcp_calls_before(before),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
#[path = "tests/calllog_tests.rs"]
mod calllog_tests;
