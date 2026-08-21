// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE PER-CALL LOG: one hash-chained record per MCP tool call, written through to the
//! configured governance store, read back at boot, and verifiable.
//!
//! ## The CHAIN is not this file's, and that is the point
//!
//! This module used to carry its own `compute_hash`, `CallChain`, `ChainBreak`, `ChainBreakKind` and
//! `verify_chain` — a second copy of what `a2a/provenance.rs` had and a third of what
//! `admin/audit.rs` had. Owner's ruling, 2026-08-13: *"auditing is core. nothing auditing wise
//! should be mcp a2a or llm specific. thats how audits break."* Three chains give three answers to
//! "what happened", and an auditor reads whichever was wired last.
//!
//! So the mechanism is [`crate::audit`]'s: one append, one digest, one verifier. What stays here is
//! the RECORD (which fields a call carries and which of them the digest covers — see
//! `impl ChainedRecord for McpCallRecord`) and the SINK (attaching the store, rehydrating at boot,
//! writing through). MCP supplies a record; it does not supply a second chain.
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
//! and [`PlaneCallLog::restore_from_store`] reports zero. That zero is the truth being reported, not a
//! bug, and the engine must never paper over it — `tests/calllog_tests.rs` keeps a permanent paired
//! NEGATIVE test asserting exactly that, because a durability test that has never seen a
//! non-durable store has proven nothing.

// ── WIRED. WHAT IS WRITTEN, AND WHAT IS STILL NOT ───────────────────────────────────────────────
//
// This module carried `#![cfg_attr(not(test), allow(dead_code))]` and a header saying it had NO
// PRODUCTION CALL SITE: the substrate, the chain, the verifier and the restore were all real, all
// tested, and nothing wrote a record. It is wired now, and the exact extent of the wiring is stated
// here rather than left to be discovered:
//
//   WRITTEN — every inbound `tools/call` that reaches `mcp::method::tools_call`, at every terminal:
//   the dispatched result, every refusal (admission, dispatch-time re-validation, header mismatch,
//   the tasks gate, the caller-ask gate, the budget, the egress gate, the upstream's own refusal,
//   and the terminal ask assertion), and the creation of an asynchronous task.
//
//   NOT WRITTEN — three things, each for a stated reason:
//     * `prompts/get` and `resources/read`. `McpCallRecord.tool` is the tool routing key and the
//       chain is documented as one record per TOOL CALL; widening it to every capability is a
//       schema decision, not a wiring decision, and inventing a `tool` value for a prompt would put
//       a name in that field that no `mcp_tool:` grant can ever name.
//     * The ROUND STRUCTURE of a multi-round exchange. One `tools/call` request produces one
//       record. A caller-ask round that returns `InputRequiredResult` records the round as refused
//       with `caller_ask_pending`, and the retry that follows is its own inbound request and its
//       own record; the upstream input-required rounds inside a single dispatch are NOT individually
//       recorded. The log answers "who called what, and did it go out", not "how many round trips it
//       took".
//     * The task's OWN upstream leg. A `tools/call` answered with a task records `task_created` at
//       the moment the task is created and admitted; the runner's later dispatch, retries and
//       terminal status are the A2A-shaped task provenance chain's business (`mcp::tasks`), not a
//       second per-call record under a request that has already been answered.
//
// The sink is attached at boot in `main.rs`, beside the durable audit and the A2A task table, and
// with no durable store configured the log keeps chain positions in RAM and persists nothing — the
// documented `store: memory` behaviour, and the reason `restore_from_store` reports what it found
// rather than assuming.
//
// ── AND THE OPERATOR-FACING READ SURFACE IS STILL NOT MOUNTED ───────────────────────────────────
//
// `PlaneCallLog::verify_principal_chain`, `read_back`, `compact`, `next_seq` and `len` have NO
// production caller. Each carries its own `#[allow(dead_code)]` and its own note, individually
// rather than under one module-wide blanket, so that the next thing to lose its caller BREAKS THE
// BUILD instead of joining a silent amnesty — which is precisely how the writer itself went missing.
//
// The one that matters commercially is `verify_principal_chain`. By this module's own argument a
// chain nothing ever recomputes proves nothing, because nobody ever finds out that it does not
// verify. Today the ONLY recomputation in a running deployment is the boot rehydrate
// (`restore_from_store`, which does verify every chain it restores and reports every break at
// ERROR). There is no on-demand admin verb, so between two boots a tamper is undetected. That is a
// REAL GAP, it is named here, and it must not be described as continuous verification anywhere.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::plane::store::{call_record, decode, PlaneStore, KIND_CALL};
use busbar_api::{McpCallRecord, PlaneSelector, StoreResult};

use crate::audit::{verify_chain, ChainBreak, ChainLabels, ChainedRecord, Digest, Framing};

/// The outcome and reason tokens THIS stream uses, re-exported from the ONE audit vocabulary in
/// [`crate::audit::vocab`]. They are core's, not MCP's: the ruling promoted the richer set of words
/// this plane got right (`not_granted` / `egress_denied` / `upstream_failed`, distinguishable where
/// the admin log has a single "refused") to the shared vocabulary rather than flattening to the
/// weakest of the three. The re-export exists so the call sites keep one import path; the
/// definitions, and the reasoning about each word, live in core.
// MCP-only re-export: these tokens name the MCP call stream's outcomes; the A2A relay uses its own
// subset, so with `plane-mcp` off (and A2A on) this path re-exports them with no local user.
#[cfg_attr(not(feature = "plane-mcp"), allow(unused_imports))]
pub(crate) use crate::audit::vocab::{
    OUTCOME_DISPATCHED, OUTCOME_REFUSED, REASON_CALLER_ASK_PENDING, REASON_MALFORMED,
    REASON_TASK_CREATED, REASON_UPSTREAM_FAILED,
};

/// This stream's chain: one per PRINCIPAL. A type alias over the core mechanism — there is no second
/// implementation behind it.
pub(crate) type CallChain = crate::audit::Chain<McpCallRecord>;

/// The reason token for a call an operator's HOOK GATE refused (`tools.hooks:` /
/// `tools.<server>.hooks:`).
///
/// `refused`, and a token of its OWN rather than folding into `not_granted`: those two send an
/// operator to different places. `not_granted` means the caller's key does not reach this tool and
/// the remedy is a scope; this means the tool was reachable and a policy the operator attached said
/// no, and the remedy is that policy. A single word for both would make an operator debug the
/// grant matrix for a decision the grant matrix did not take.
pub(crate) const REASON_HOOK_REJECTED: &str = "hook_rejected";

/// The fields a caller supplies for one call record. `seq`, `prev_hash` and `hash` are NOT here:
/// they are the chain's own business and are supplied by [`crate::audit::Chain::append`], so no call
/// site can supply a sequence number or a link of its own choosing.
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

impl ChainedRecord for McpCallRecord {
    type Input = CallInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the MCP per-call chain",
        scope: "principal",
    };
    /// LENGTH-PREFIXED, and this is the framing a NEW record type must copy. `tool` carries a
    /// caller-supplied name and `reason`/`server` are engine-controlled tokens, but relying on that
    /// split is the classic digest-collision-by-framing bug: a caller who can choose one field's
    /// bytes can otherwise forge the same byte stream under a different split. Length prefixes make
    /// the split unforgeable regardless of what any field contains, so this stays correct if a
    /// future field becomes caller-influenced.
    const FRAMING: Framing = Framing::LengthPrefixed;

    fn scope_of(&self) -> &str {
        &self.principal
    }

    fn seq(&self) -> u64 {
        self.seq
    }

    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }

    fn hash(&self) -> &str {
        &self.hash
    }

    fn link(scope: &str, seq: u64, prev_hash: String, input: CallInput) -> Self {
        McpCallRecord {
            principal: scope.to_string(),
            seq,
            ts: input.ts,
            server: input.server,
            tool: input.tool,
            outcome: input.outcome.to_string(),
            reason: input.reason,
            tool_digest: input.tool_digest,
            pin_generation: input.pin_generation,
            request_id: input.request_id,
            prev_hash,
            hash: String::new(),
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    /// The chained fields, in the order the records already on disk were written with.
    ///
    /// `request_id` is deliberately EXCLUDED. It is a join key handed in by the request spine, it is
    /// absent on any path with no inbound request, and a field that is sometimes absent must not be
    /// able to make an otherwise-intact chain unverifiable.
    fn digest_fields(&self, d: &mut Digest) {
        d.text(&self.prev_hash)
            .text(&self.principal)
            .num(self.seq)
            .num(self.ts)
            .text(&self.server)
            .text(&self.tool)
            .text(&self.outcome)
            .text(&self.reason)
            .text(&self.tool_digest)
            .num(self.pin_generation);
    }
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
pub(crate) struct PlaneCallLog {
    /// Chain POSITIONS only, keyed by principal — a tail hash and a next sequence, never the
    /// records. The store owns the records.
    chains: Mutex<HashMap<String, CallChain>>,
    sink: Mutex<Option<Arc<dyn PlaneStore>>>,
}

/// THE PROCESS-WIDE CALL LOG. Process state, not config-derived state, so it lives as a global
/// rather than on the swappable `App` snapshot — exactly like [`crate::admin::audit::AUDIT`], and
/// for the same reason: a config apply must not reset the chain positions, because doing so would
/// open a SECOND chain at seq 1 under a principal that already has one, and two chains that each
/// verify and together describe nothing is strictly worse than no chain at all.
pub(crate) static CALLS: std::sync::LazyLock<PlaneCallLog> =
    std::sync::LazyLock::new(PlaneCallLog::new);

impl PlaneCallLog {
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

    fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
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
    pub(crate) fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// BOOT REHYDRATE. Enumerate the principals the store holds records for, resume each chain from
    /// its persisted tail, and REPORT what was found.
    ///
    /// This is the ONLY place durability is learned. A write's `Ok(())` proves nothing (the trait
    /// default accepts and keeps nothing), so the engine finds out what its backend actually kept by
    /// reading it back.
    pub(crate) fn restore_from_store(&self, store: &dyn PlaneStore) -> StoreResult<Restored> {
        let principals = store.list_plane_record_parents(KIND_CALL)?;
        let mut out = Restored::default();
        let mut chains = self.chains();
        for principal in &principals {
            let records: Vec<McpCallRecord> = store
                .list_plane_records(KIND_CALL, &PlaneSelector::Parent(principal.clone()))?
                .iter()
                .map(|body| decode(body))
                .collect::<StoreResult<_>>()?;
            if records.is_empty() {
                // The store named this principal and then produced nothing for it. Reported, never
                // silently skipped: it is exactly what one caller's evidence being deleted wholesale
                // looks like, and the verifier alone cannot tell it from "never called".
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_CALLLOG_EMPTY_CHAIN,
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
                    crate::diagnostics::diag_error!(
                        crate::diagnostics::PLANE_CALLLOG_CHAIN_VERIFY_FAILED,
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
            let plane = call_record(&record).map_err(CallLogError::Store)?;
            store
                .append_plane_record(&plane)
                .map_err(CallLogError::Store)?;
        }
        *chain = candidate;
        Ok(record)
    }

    /// The sequence the next record for `principal` will carry. 1 for a principal with no chain.
    ///
    /// NO PRODUCTION CALLER. A diagnostic on the chain position, kept because the position is the one
    /// piece of state the store does not own and the tests assert the append ordering through it.
    #[allow(dead_code)]
    pub(crate) fn next_seq(&self, principal: &str) -> u64 {
        self.chains()
            .get(principal)
            .map(CallChain::next_seq)
            .unwrap_or(1)
    }

    /// How many principals this process is holding a chain position for.
    ///
    /// NO PRODUCTION CALLER — a diagnostic, not a metric: it counts principals seen SINCE BOOT, which
    /// is not the number of principals the store holds rows for, and publishing it as if it were
    /// would be a number that quietly means something else.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.chains().len()
    }

    /// READ ONE PRINCIPAL'S CALLS BACK from the store. The durability question, asked the only way
    /// it can honestly be asked.
    ///
    /// NO PRODUCTION CALLER: nothing in a running deployment reads a principal's calls back, because
    /// there is no admin verb that would. See the module header — the read surface is not mounted.
    #[allow(dead_code)]
    pub(crate) fn read_back(
        &self,
        store: &dyn PlaneStore,
        principal: &str,
    ) -> StoreResult<Vec<McpCallRecord>> {
        store
            .list_plane_records(KIND_CALL, &PlaneSelector::Parent(principal.to_string()))?
            .iter()
            .map(|body| decode(body))
            .collect()
    }

    /// VERIFY one principal's persisted chain, end to end, against the store.
    ///
    /// This is the operator-facing half, and its existence is the difference between evidence and
    /// decoration: a chain nothing ever recomputes proves nothing, because nobody ever finds out
    /// that it does not verify. `Ok(Ok(n))` is `n` records verified; `Ok(Err(brk))` names where and
    /// which; `Err` is the store failing to answer, which is not a verdict about the chain.
    ///
    /// NO PRODUCTION CALLER, and this is the gap the module header names: between two boots nothing
    /// recomputes a chain, so a tamper is detected at the next restart and not before.
    #[allow(dead_code)]
    pub(crate) fn verify_principal_chain(
        &self,
        store: &dyn PlaneStore,
        principal: &str,
    ) -> StoreResult<Result<usize, ChainBreak>> {
        let records: Vec<McpCallRecord> = store
            .list_plane_records(KIND_CALL, &PlaneSelector::Parent(principal.to_string()))?
            .iter()
            .map(|body| decode(body))
            .collect::<StoreResult<_>>()?;
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
    ///
    /// NO PRODUCTION CALLER: no retention window is configurable for the call log in this release,
    /// so nothing purges it. The mechanism is here and the POLICY is absent, which means a durable
    /// deployment's call log grows without bound until an operator prunes it themselves.
    #[allow(dead_code)]
    pub(crate) fn compact(&self, before: u64) -> StoreResult<u64> {
        match self.sink() {
            Some(store) => store.purge_plane_records_before(KIND_CALL, before),
            None => Ok(0),
        }
    }
}

/// THE ONE PRODUCTION EMITTER. Every per-call record a running busbar writes goes through here.
///
/// ## Why the failure is swallowed, loudly, instead of failing the call
///
/// [`PlaneCallLog::record`] surfaces a durable-write failure precisely so the CALLER can decide, and
/// this is that decision, made once and in one place. A store hiccup must not turn into a refused
/// tool call: the log is EVIDENCE, not ADMISSION, and a gateway whose data plane stops when its
/// audit backend blinks has converted an observability dependency into an availability dependency.
/// The same call the durable audit log makes, for the same reason.
///
/// It is swallowed at `error!` with the record's own identifying fields, never at `warn!` and never
/// silently: a deployment that is losing evidence has to be able to find out, and the ONE thing that
/// would make this defensible-looking and wrong is a failure nobody can see. The chain position is
/// left untouched on failure (see `record`), so the next call reuses the sequence and the chain
/// stays contiguous rather than acquiring a permanent gap at the point of the outage.
///
/// ## The `request_id` really is a join key
///
/// It is emitted on the success line too, at `debug!`, because a join key that appears in exactly
/// one place joins nothing. That line is what lets an operator holding a request id find the durable
/// record, and holding a durable record find the request.
pub(crate) fn emit(principal: &str, input: CallInput) {
    let (server, tool, outcome, request_id) = (
        input.server.clone(),
        input.tool.clone(),
        input.outcome,
        input.request_id.clone(),
    );
    // Transition latch: a durable-store write failure here recurs per served call during an outage,
    // so surface the ERROR only on the TRANSITION into the failing state and hold subsequent
    // failures at debug. A successful write clears the latch so a future outage re-errors. (Same
    // shape as the metrics scrape's `KEY_GAUGE_LIMIT_WARNED` latch.)
    static WRITE_FAILED_LATCHED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    match CALLS.record(principal, input) {
        Ok(record) => {
            WRITE_FAILED_LATCHED.store(false, std::sync::atomic::Ordering::Relaxed);
            tracing::debug!(
                principal = %principal,
                request_id = %request_id,
                seq = record.seq,
                server = %server,
                tool = %tool,
                outcome = %outcome,
                "mcp per-call record appended"
            );
        }
        Err(e) => {
            if !WRITE_FAILED_LATCHED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_CALLLOG_WRITE_FAILED,
                    principal = %principal,
                    request_id = %request_id,
                    server = %server,
                    tool = %tool,
                    outcome = %outcome,
                    error = %e,
                    "the durable MCP per-call record could NOT be written: this call is being served and \
                     its evidence is being LOST. The chain position is unchanged, so the chain stays \
                     contiguous — what is missing is this record, not the ones after it."
                );
            } else {
                crate::diagnostics::diag_debug!(
                    crate::diagnostics::PLANE_CALLLOG_WRITE_FAILED,
                    principal = %principal,
                    request_id = %request_id,
                    server = %server,
                    tool = %tool,
                    outcome = %outcome,
                    error = %e,
                    "the durable MCP per-call record could NOT be written: this call is being served and \
                     its evidence is being LOST. The chain position is unchanged, so the chain stays \
                     contiguous — what is missing is this record, not the ones after it."
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/calllog_tests.rs"]
mod calllog_tests;
