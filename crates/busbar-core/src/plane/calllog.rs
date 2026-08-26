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
//! the RECORD (which fields a call carries and which of them the digest covers — the `call_suffix`
//! pre-framing built plane-side) and the SINK (attaching the store, rehydrating at boot, writing
//! through the neutral journal seam). MCP supplies a record shape; it does not supply a second chain.
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

use std::sync::Arc;

use crate::plane::store::{decode, PlaneStore, KIND_CALL};
use busbar_api::{McpCallRecord, PlaneSelector, StoreError, StoreResult};

use crate::audit::journal::NeutralBody;
use crate::audit::{verify_chain, ChainBreak, Framing};
use crate::plane_host::journal::PlaneJournalRecord;
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{
    Framing as AbiFraming, JournalStreamDesc, ReframeOut, StatusClass, POD_VERSION,
};
use core::mem::MaybeUninit;

/// The host-assigned `kind_id` the MCP `call` durable stream is registered under and addressed by on
/// every scoped op. Distinct from the A2A `task_event` stream's id (1); process-global.
pub(crate) const KIND_ID_CALL: u32 = 2;

/// The MCP `call` stream's FFI reframe slot: delegates the raw-buffer work to the audited
/// [`crate::plane_host::journal::reframe_bridge`] (so this file stays `deny(unsafe)`) over the native
/// [`reframe_call`] decode, which handles BOTH the neutral body and a legacy `serde(McpCallRecord)` row.
extern "C-unwind" fn reframe_call_ffi(
    _host: HostCtx,
    _kind_id: u32,
    body_ptr: *const u8,
    body_len: usize,
    out: *mut MaybeUninit<ReframeOut>,
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
) -> StatusClass {
    crate::plane_host::journal::reframe_bridge(
        body_ptr,
        body_len,
        out,
        prev_buf,
        prev_cap,
        hash_buf,
        hash_cap,
        suffix_buf,
        suffix_cap,
        reframe_call,
    )
}

/// REGISTER the MCP `call` durable stream with the host (once, at boot, before the rehydrate):
/// `LengthPrefixed` framing with the principal in the digest, under [`KIND_ID_CALL`], bounded at
/// [`MAX_TRACKED_PRINCIPALS`] positions. Uses the WITHIN-CORE capped register (the ABI descriptor
/// carries no LRU cap, and this crate must not touch the hot ABI); the host attaches the durable sink
/// from `app.governance` at register time.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub fn register_call_stream(app: &Arc<crate::state::App>) {
    register_call_stream_as(KIND_ID_CALL, app);
}

/// BOOT-TIME rehydrate of the durable `call` chain, driven over a fresh dispatch scope so the
/// caller-driven seed reaches the host over a live `HostCtx`. The `with_dispatch_scope` mint stays
/// CORE-side here (the returned [`Restored`] and the [`PlaneStore`] the read walks are both core types
/// a plane cannot name), so a plane's boot hook calls THIS instead of naming
/// `crate::plane_host::with_dispatch_scope`. Byte-identical to the in-place restore it replaced.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub fn restore_from_store_over(
    app: &Arc<crate::state::App>,
    store: &dyn PlaneStore,
) -> StoreResult<Restored> {
    crate::plane_host::with_dispatch_scope(app, |host, _| CALLS.restore_from_store(host, store))
}

/// Register the `call` stream under an ARBITRARY `kind_id` — production pins [`KIND_ID_CALL`], a TEST
/// drives over a FRESH id so parallel tests never share one process-global chain.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub(crate) fn register_call_stream_as(kind_id: u32, app: &Arc<crate::state::App>) {
    let kind = KIND_CALL.as_bytes();
    let desc = JournalStreamDesc {
        size: core::mem::size_of::<JournalStreamDesc>() as u32,
        version: POD_VERSION,
        framing: AbiFraming::LengthPrefixed,
        digests_scope: 1,
        kind_id,
        _reserved: 0,
        kind_ptr: kind.as_ptr(),
        kind_len: kind.len(),
    };
    crate::plane_host::with_dispatch_scope(app, |host, _vt| {
        crate::plane_host::journal::journal_register_capped(
            host,
            &desc as *const JournalStreamDesc,
            reframe_call_ffi,
            MAX_TRACKED_PRINCIPALS,
        );
    });
}

/// Pack a set of stored bodies into the [`journal_seed`](crate::plane_host::journal) wire shape:
/// `u32` count LE, then per body a `u32` length LE + its bytes — the inverse of the host's unpack.
fn pack_bodies(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(bodies.len() as u32).to_le_bytes());
    for b in bodies {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// The outcome and reason tokens THIS stream uses, re-exported from the ONE audit vocabulary in
/// [`crate::audit::vocab`]. They are core's, not MCP's: the ruling promoted the richer set of words
/// this plane got right (`not_granted` / `egress_denied` / `upstream_failed`, distinguishable where
/// the admin log has a single "refused") to the shared vocabulary rather than flattening to the
/// weakest of the three. The re-export exists so the call sites keep one import path; the
/// definitions, and the reasoning about each word, live in core.
// MCP-only re-export: these tokens name the MCP call stream's outcomes; the A2A relay uses its own
// subset, so with `plane-mcp` off (and A2A on) this path re-exports them with no local user.
#[cfg_attr(not(feature = "plane-mcp"), allow(unused_imports))]
pub use crate::audit::vocab::{
    OUTCOME_DISPATCHED, OUTCOME_REFUSED, REASON_CALLER_ASK_PENDING, REASON_MALFORMED,
    REASON_TASK_CREATED, REASON_UPSTREAM_FAILED,
};

/// The reason token for a call an operator's HOOK GATE refused (`tools.hooks:` /
/// `tools.<server>.hooks:`).
///
/// `refused`, and a token of its OWN rather than folding into `not_granted`: those two send an
/// operator to different places. `not_granted` means the caller's key does not reach this tool and
/// the remedy is a scope; this means the tool was reachable and a policy the operator attached said
/// no, and the remedy is that policy. A single word for both would make an operator debug the
/// grant matrix for a decision the grant matrix did not take.
pub const REASON_HOOK_REJECTED: &str = "hook_rejected";

// D3 Phase-C: the neutral per-call record INPUT is now a substrate POD so a plane builds it without
// naming `busbar_core::plane::calllog`; re-exported here so `CALLS.record`/[`emit`] and every in-core
// call site is unchanged. `seq`/`prev_hash`/`hash` are still NOT on it — they are the chain's own
// business, supplied by [`crate::audit::Chain::append`].
pub use busbar_substrate::plane::calllog::CallInput;

// ── THE DURABLE JOURNAL SEAM — the MCP call chain's framing, held PLANE-SIDE ─────────────────────
//
// The per-principal chain is the NEUTRAL store-backed journal (`Journal<PlaneJournalRecord>`) — the
// SAME seq-authority, position cache, LRU, write-ordering and store-resume the shipped streams use,
// over a record shape that names no MCP type. Core's durable path carries NONE of the MCP call
// stream's framing facts; they ride each record/input across the seam via the pre-framed content
// suffix built here. This file keeps that framing (it moves out with the mcp/ relocation), exactly as
// `plane::taskstore` keeps the A2A event framing.

/// The MCP per-call stream's framing (see [`McpCallRecord::FRAMING`]): every field self-delimits, so
/// the prelude and the plane's suffix byte-concatenate with no separator.
const CALL_FRAMING: Framing = Framing::LengthPrefixed;
/// The principal (the chain SCOPE) participates in the digest — [`McpCallRecord::digest_fields`] feeds
/// it right after `prev_hash`, exactly the prelude `frame_prelude(prev_hash, Some(scope), seq)` emits
/// when `digests_scope` is set.
const CALL_DIGESTS_SCOPE: bool = true;

/// The MCP call's pre-framed content SUFFIX: the chained fields AFTER the prelude
/// (`prev_hash`/`principal`/`seq`), framed LengthPrefixed EXACTLY as [`crate::audit::Digest`] frames
/// them, so `frame_prelude(prev_hash, principal, seq) ⧺ suffix` reproduces the legacy
/// [`McpCallRecord`] digest byte stream byte-for-byte. Every field is `len:u64-be ⧺ bytes`; a `num`
/// is its eight big-endian bytes carried as one such length-prefixed field (matching `Digest::push`
/// under LengthPrefixed). The field ORDER is the tail of [`McpCallRecord::digest_fields`]: ts, server,
/// tool, outcome, reason, tool_digest, pin_generation. `request_id` is EXCLUDED, matching the digest
/// (a join key absent on paths with no inbound request must not be able to break an intact chain).
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
fn call_suffix(
    ts: u64,
    server: &str,
    tool: &str,
    outcome: &str,
    reason: &str,
    tool_digest: &str,
    pin_generation: u64,
) -> Vec<u8> {
    fn lp_text(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u64).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    fn lp_num(out: &mut Vec<u8>, v: u64) {
        let b = v.to_be_bytes();
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(&b);
    }
    let mut out = Vec::new();
    lp_num(&mut out, ts);
    lp_text(&mut out, server);
    lp_text(&mut out, tool);
    lp_text(&mut out, outcome);
    lp_text(&mut out, reason);
    lp_text(&mut out, tool_digest);
    lp_num(&mut out, pin_generation);
    out
}

/// Parse a LengthPrefixed call SUFFIX back into its typed fields — the exact inverse of
/// [`call_suffix`], for reconstructing a typed [`McpCallRecord`] from a stored neutral body. Fails
/// closed on a truncated/oversized field rather than reading past the buffer.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
fn parse_call_suffix(
    content: &[u8],
) -> StoreResult<(u64, String, String, String, String, String, u64)> {
    fn take<'a>(content: &'a [u8], off: &mut usize) -> StoreResult<&'a [u8]> {
        if *off + 8 > content.len() {
            return Err(StoreError(
                "truncated call suffix length prefix".to_string(),
            ));
        }
        let len = u64::from_be_bytes(content[*off..*off + 8].try_into().unwrap()) as usize;
        *off += 8;
        if *off + len > content.len() {
            return Err(StoreError("truncated call suffix field".to_string()));
        }
        let s = &content[*off..*off + len];
        *off += len;
        Ok(s)
    }
    fn take_num(content: &[u8], off: &mut usize) -> StoreResult<u64> {
        let b = take(content, off)?;
        let arr: [u8; 8] = b
            .try_into()
            .map_err(|_| StoreError("call suffix num field is not 8 bytes".to_string()))?;
        Ok(u64::from_be_bytes(arr))
    }
    fn take_text(content: &[u8], off: &mut usize) -> StoreResult<String> {
        Ok(String::from_utf8_lossy(take(content, off)?).into_owned())
    }
    let mut off = 0usize;
    let ts = take_num(content, &mut off)?;
    let server = take_text(content, &mut off)?;
    let tool = take_text(content, &mut off)?;
    let outcome = take_text(content, &mut off)?;
    let reason = take_text(content, &mut off)?;
    let tool_digest = take_text(content, &mut off)?;
    let pin_generation = take_num(content, &mut off)?;
    Ok((
        ts,
        server,
        tool,
        outcome,
        reason,
        tool_digest,
        pin_generation,
    ))
}

/// THE DECODE BRIDGE (plane-side reframe): turn one stored `call` body back into a chain record.
///
/// Handles BOTH the NEW neutral `{seq, prev_hash, hash, content}` body the seam persists AND an OLD
/// `serde(McpCallRecord)` body a store held before the cleave — so a deployed store spanning the
/// upgrade both VERIFIES and READS BACK. The neutral body is tried first (the shape every post-cleave
/// append writes); a legacy row lacks the required `content` field and falls through to the typed
/// decode, whose fields rebuild the identical suffix. `scope` is the principal (the store parent),
/// supplied by the caller and never read from the body.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
fn reframe_call(scope: &str, body: &[u8]) -> StoreResult<PlaneJournalRecord> {
    if let Ok(nb) = decode::<NeutralBody>(body) {
        return Ok(PlaneJournalRecord::from_parts(
            scope.to_string(),
            nb.seq,
            nb.prev_hash,
            nb.hash,
            nb.content,
            CALL_FRAMING,
            CALL_DIGESTS_SCOPE,
        ));
    }
    let row: McpCallRecord = decode(body)?;
    let content = call_suffix(
        row.ts,
        &row.server,
        &row.tool,
        &row.outcome,
        &row.reason,
        &row.tool_digest,
        row.pin_generation,
    );
    Ok(PlaneJournalRecord::from_parts(
        scope.to_string(),
        row.seq,
        row.prev_hash,
        row.hash,
        content,
        CALL_FRAMING,
        CALL_DIGESTS_SCOPE,
    ))
}

/// READ-BACK DECODE BRIDGE to a TYPED record: reconstruct an [`McpCallRecord`] from the NEW neutral
/// body OR an OLD `serde(McpCallRecord)` body. Digest-faithful — the rebuilt fields feed
/// [`McpCallRecord::digest_fields`] the SAME bytes the stored `hash` was sealed over, so a chain read
/// back through it `verify_chain`-passes byte-identically. From a NEUTRAL body `request_id` comes back
/// EMPTY: it is a join key, never in the digest and so never in the neutral content; a legacy body
/// still carries it. `principal` is the chain scope, supplied by the caller (the store parent), never
/// read from a neutral body.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub(crate) fn mcp_call_record_from_body(
    principal: &str,
    body: &[u8],
) -> StoreResult<McpCallRecord> {
    if let Ok(nb) = decode::<NeutralBody>(body) {
        let (ts, server, tool, outcome, reason, tool_digest, pin_generation) =
            parse_call_suffix(&nb.content)?;
        return Ok(McpCallRecord {
            principal: principal.to_string(),
            seq: nb.seq,
            ts,
            server,
            tool,
            outcome,
            reason,
            tool_digest,
            pin_generation,
            request_id: String::new(),
            prev_hash: nb.prev_hash,
            hash: nb.hash,
        });
    }
    decode::<McpCallRecord>(body)
}

/// TEST ONLY: verify a chain presented as TYPED [`McpCallRecord`]s by reframing each into the neutral
/// journal record the seam persists and running the ONE verifier. The typed `ChainedRecord` impl is
/// gone (the row moves to `busbar-mcp`), so a test that holds typed rows — read back through a store
/// test-ext — verifies them through the SAME reframe/digest production reads a persisted chain with.
/// The scope, and the digest's inclusion of it, come from each row's own `principal`, exactly as the
/// deleted `McpCallRecord::scope_of`/`digest_fields` did.
#[cfg(test)]
pub(crate) fn verify_call_rows(rows: &[McpCallRecord]) -> Result<(), ChainBreak> {
    let records: Vec<PlaneJournalRecord> = rows
        .iter()
        .map(|r| {
            let content = call_suffix(
                r.ts,
                &r.server,
                &r.tool,
                &r.outcome,
                &r.reason,
                &r.tool_digest,
                r.pin_generation,
            );
            PlaneJournalRecord::from_parts(
                r.principal.clone(),
                r.seq,
                r.prev_hash.clone(),
                r.hash.clone(),
                content,
                CALL_FRAMING,
                CALL_DIGESTS_SCOPE,
            )
        })
        .collect();
    verify_chain(&records)
}

/// What a boot rehydrate actually found. Every number is reported rather than summed into one
/// "restored" count: they mean different things to an operator, and a single number hides the two
/// that are bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restored {
    /// Principals whose chain position was resumed.
    pub principals: usize,
    /// Records read back across every principal. THE DURABILITY SIGNAL: zero here on a deployment
    /// that has been serving calls means the configured backend is keeping none of them.
    pub records: usize,
    /// Principals the store ENUMERATED but returned no records for. Counted rather than ignored: an
    /// enumerated-but-empty chain is the one shape the verifier cannot judge on its own (see
    /// [`verify_chain`]), and it is what a wholesale deletion of one caller's evidence looks like.
    pub empty_chains: usize,
    /// Chains that FAILED to verify. Tamper evidence. The records are still restored and the chain
    /// still resumes — refusing would let anyone who can write to the store erase a caller's history
    /// by corrupting one byte — but the break is reported and the chain continues from the broken
    /// tail rather than being silently re-based onto it.
    pub chain_breaks: Vec<ChainBreak>,
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

/// The upper bound on how many principals' chain POSITIONS this process caches in RAM at once.
///
/// The map is a CACHE of the store's per-principal tail, not the system of record — the durable
/// store owns the records — so it can be bounded without losing anything: a principal evicted here is
/// resumed from the store on its next call (see [`PlaneCallLog::resume_missing`]), so the chain stays
/// contiguous with the persisted tail exactly as a boot rehydrate would make it. Without a bound the
/// map grew one entry per DISTINCT principal ever seen and was never evicted — an MCP tool call is
/// request-rate and a principal is a caller identity, so a deployment serving many short-lived
/// principals leaked memory unboundedly. The eviction is least-recently-USED (a still-active
/// principal is kept resident and never pays a readback), and the cap is generous enough that any
/// realistic working set of concurrently-active callers fits without a single eviction.
const MAX_TRACKED_PRINCIPALS: usize = 16_384;

/// THE PER-CALL LOG. A thin MCP-facing wrapper over the generic core [`Journal`]: the principal-keyed
/// position cache, the LRU bound, the store-resume of an evicted tail, the write-through sink and the
/// write-ordering invariant all live in [`crate::audit::journal`] now — this file keeps only the
/// MCP RECORD (`McpCallRecord`), the MCP operator vocabulary (the diagnostics its restore emits), and
/// the read surface. No `Debug`: the journal holds a `dyn PlaneStore`, which is deliberately not
/// `Debug` (a backend must not be obliged to render itself, where a credential could surface in a log).
pub struct PlaneCallLog {
    /// The host-side durable stream this log's per-principal chain is addressed by. Production is
    /// always [`KIND_ID_CALL`] (one process, one MCP call stream); a TEST constructs a log over a
    /// FRESH id (see [`PlaneCallLog::with_kind_id`]) so parallel tests never share one process-global
    /// chain. The chain's seq-authority, position cache, LRU bound ([`MAX_TRACKED_PRINCIPALS`]) and
    /// store-resume all live host-side in the registered DurableStream now; this wrapper keeps only the
    /// MCP RECORD (`McpCallRecord`), the operator vocabulary, and the read surface.
    kind_id: u32,
}

impl Default for PlaneCallLog {
    fn default() -> Self {
        Self::new()
    }
}

/// THE PROCESS-WIDE CALL LOG. Process state, not config-derived state, so it lives as a global
/// rather than on the swappable `App` snapshot — exactly like [`crate::admin::audit::AUDIT`], and
/// for the same reason: a config apply must not reset the chain positions, because doing so would
/// open a SECOND chain at seq 1 under a principal that already has one, and two chains that each
/// verify and together describe nothing is strictly worse than no chain at all.
pub static CALLS: std::sync::LazyLock<PlaneCallLog> = std::sync::LazyLock::new(PlaneCallLog::new);

impl PlaneCallLog {
    pub(crate) fn new() -> Self {
        Self {
            kind_id: KIND_ID_CALL,
        }
    }

    /// TEST ONLY: a log whose per-principal chain is addressed by a specific host-side stream id, so
    /// parallel tests never share one process-global chain. Production uses the default
    /// [`KIND_ID_CALL`] via [`PlaneCallLog::new`].
    #[cfg(test)]
    pub(crate) fn with_kind_id(kind_id: u32) -> Self {
        Self { kind_id }
    }

    /// BOOT REHYDRATE. Enumerate the principals the store holds records for, resume each chain from
    /// its persisted tail HOST-SIDE, and REPORT what was found.
    ///
    /// This wrapper owns the MCP OPERATOR VOCABULARY — it emits the MCP diagnostics for the two
    /// findings that are bad news. It drives the enumeration itself (rather than the whole-store
    /// `journal_restore`) so it can recompute the RICH [`ChainBreak`] locally on a break — the neutral
    /// seam header carries only counts. An empty chain and a chain break are each REPORTED rather than
    /// skipped or refused (refusing would convert a detection control into a deletion primitive).
    ///
    /// This is the ONLY place durability is learned. A write's `Ok(())` proves nothing (the trait
    /// default accepts and keeps nothing), so the engine finds out what its backend actually kept by
    /// reading it back.
    pub fn restore_from_store(
        &self,
        host: HostCtx,
        store: &dyn PlaneStore,
    ) -> StoreResult<Restored> {
        let principals = store.list_plane_record_parents(KIND_CALL)?;
        let mut out = Restored::default();
        for principal in &principals {
            let bodies =
                store.list_plane_records(KIND_CALL, &PlaneSelector::Parent(principal.clone()))?;
            out.principals += 1;
            out.records += bodies.len();
            if bodies.is_empty() {
                // The store named this principal and then produced nothing for it. Reported, never
                // silently skipped: it is exactly what one caller's evidence being deleted wholesale
                // looks like, and the verifier alone cannot tell it from "never called".
                out.empty_chains += 1;
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_CALLLOG_EMPTY_CHAIN,
                    principal = %principal,
                    "the durable MCP call log enumerates this principal but returned NO records \
                     for it; the chain is being reopened at seq 1 and the discrepancy is reported \
                     rather than skipped silently"
                );
            }
            if let Some(brk) = self.seed_chain(host, principal, &bodies)? {
                // REPORTED, and the records stay restored. See the module header: refusing here would
                // convert a detection control into a deletion primitive.
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_CALLLOG_CHAIN_VERIFY_FAILED,
                    principal = %brk.scope,
                    break_detail = %brk,
                    "MCP per-call CHAIN VERIFICATION FAILED on restore — the persisted records \
                     do not verify against their own hash chain. They are still restored and \
                     the chain resumes from the broken tail; refusing to restore them would let \
                     anyone able to write to the store DELETE a caller's history by corrupting \
                     one record."
                );
                out.chain_breaks.push(brk);
            }
        }
        Ok(out)
    }

    /// SEED one principal's host-side chain position from its raw stored bodies through the durable
    /// seam. On a break the RICH [`ChainBreak`] is recomputed locally (read-only, touching no position)
    /// so the operator diagnostic still names WHICH break and WHERE; a clean verify returns `None`.
    fn seed_chain(
        &self,
        host: HostCtx,
        principal: &str,
        bodies: &[Vec<u8>],
    ) -> StoreResult<Option<ChainBreak>> {
        let packed = pack_bodies(bodies);
        let hdr = crate::plane_host::journal::seed_scoped_via_seam(
            host,
            self.kind_id,
            principal,
            &packed,
        )
        .map_err(|()| {
            StoreError("MCP per-call chain seed failed at the durable seam".to_string())
        })?;
        if hdr.broke == 0 {
            return Ok(None);
        }
        let records: Vec<PlaneJournalRecord> = bodies
            .iter()
            .map(|b| reframe_call(principal, b))
            .collect::<StoreResult<_>>()?;
        Ok(verify_chain(&records).err())
    }

    /// RECORD one tool call: mint the seq/prev_hash/hash through the ONE core chain (host-side, under
    /// [`KIND_ID_CALL`]), persist the neutral body under the journal's write-ordering invariant, and
    /// return the TYPED record. A cache MISS is resolved host-side by the journal's resume: a first-seen
    /// principal opens at seq 1, an LRU-evicted one is resumed from the store's persisted tail (via the
    /// registered reframe), so eviction never forks a durable chain.
    pub(crate) fn record(
        &self,
        host: HostCtx,
        principal: &str,
        input: CallInput,
    ) -> Result<McpCallRecord, CallLogError> {
        let content = call_suffix(
            input.ts,
            &input.server,
            &input.tool,
            input.outcome,
            &input.reason,
            &input.tool_digest,
            input.pin_generation,
        );
        // The full append returns the chain's minted `(seq, prev_hash, hash)` — the `Seq`-only ABI
        // append does not surface the link, which the typed `McpCallRecord` carries.
        let (seq, prev_hash, hash) = crate::plane_host::journal::journal_append_scoped_full(
            host,
            self.kind_id,
            principal,
            &content,
        )
        .map_err(CallLogError::Store)?;
        // Return the TYPED record for the caller: the chain's minted seq/prev_hash/hash plus the
        // caller's own fields (including `request_id`, which the neutral body deliberately drops).
        Ok(McpCallRecord {
            principal: principal.to_string(),
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
            hash,
        })
    }

    /// RECORD one call WITHOUT a host — the deferred MCP client-leg path (`mcp::client::issue`), which
    /// is `async` (a `HostCtx` is `!Send`) and reaches no `App` to open one. Same chain, same store,
    /// same typed record as [`PlaneCallLog::record`]; only the host-recovery step (which the append
    /// never uses) is skipped. This is the hostless in-core emit the cleave keeps for that one site.
    pub(crate) fn record_hostless(
        &self,
        principal: &str,
        input: CallInput,
    ) -> Result<McpCallRecord, CallLogError> {
        let content = call_suffix(
            input.ts,
            &input.server,
            &input.tool,
            input.outcome,
            &input.reason,
            &input.tool_digest,
            input.pin_generation,
        );
        let (seq, prev_hash, hash) =
            crate::plane_host::journal::journal_append_scoped_full_hostless(
                self.kind_id,
                principal,
                &content,
            )
            .map_err(CallLogError::Store)?;
        Ok(McpCallRecord {
            principal: principal.to_string(),
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
            hash,
        })
    }

    /// The sequence the next record for `principal` will carry. 1 for a principal with no chain.
    ///
    /// NO PRODUCTION CALLER. A diagnostic on the host-side chain position, kept because the position is
    /// the one piece of state the store does not own and the tests assert the append ordering through it.
    #[allow(dead_code)]
    pub(crate) fn next_seq(&self, principal: &str) -> u64 {
        crate::plane_host::journal::journal_next_seq_scoped(self.kind_id, principal)
    }

    /// How many principals this process is holding a chain position for.
    ///
    /// NO PRODUCTION CALLER — a diagnostic, not a metric: it counts principals seen SINCE BOOT, which
    /// is not the number of principals the store holds rows for, and publishing it as if it were
    /// would be a number that quietly means something else.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        crate::plane_host::journal::journal_len_scoped(self.kind_id)
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
            .map(|body| mcp_call_record_from_body(principal, body))
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
        // Reads the store directly and reframes locally — the operator-facing verify wants the rich
        // break and the record count, neither of which the neutral seam header carries. Touches no
        // chain position, so it needs no host.
        let records: Vec<PlaneJournalRecord> = store
            .list_plane_records(KIND_CALL, &PlaneSelector::Parent(principal.to_string()))?
            .iter()
            .map(|b| reframe_call(principal, b))
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
    pub(crate) fn compact(&self, host: HostCtx, before: u64) -> StoreResult<u64> {
        crate::plane_host::journal::compact_via_seam(host, self.kind_id, before).map_err(|()| {
            StoreError("MCP per-call log compaction failed at the durable seam".to_string())
        })
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
pub fn emit(host: HostCtx, principal: &str, input: CallInput) {
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
    match CALLS.record(host, principal, input) {
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

/// THE DEFERRED-SITE EMITTER: the hostless twin of [`emit`] for `mcp::client::issue` — the MCP
/// client-leg verb path that has no `HostCtx` to open (see [`PlaneCallLog::record_hostless`]). It
/// swallows a durable-write failure the same way [`emit`] does (evidence, not admission), so the
/// deferred path's behaviour matches the production emitter but for the host it never had.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub fn emit_hostless(principal: &str, input: CallInput) {
    let (server, tool, outcome, request_id) = (
        input.server.clone(),
        input.tool.clone(),
        input.outcome,
        input.request_id.clone(),
    );
    if let Err(e) = CALLS.record_hostless(principal, input) {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::PLANE_CALLLOG_WRITE_FAILED,
            principal = %principal,
            request_id = %request_id,
            server = %server,
            tool = %tool,
            outcome = %outcome,
            error = %e,
            "the durable MCP per-call record could NOT be written on the client-leg path; its \
             evidence is being LOST. The chain position is unchanged, so the chain stays contiguous."
        );
    }
}

// ── TEST HARNESS — the per-principal chain is host-side now, so a test drives it over a host ──────

/// TEST ONLY: a fresh, process-unique `call` stream id, well above the production ids (1/2) and the
/// `plane_host::journal` test range (base 10_000) and the A2A `task_event` test range (base 100_000).
#[cfg(test)]
pub(crate) fn fresh_test_kind_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(200_000);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// TEST ONLY: a `PlaneCallLog` + an app whose governance store is `store`, with the `call` stream
/// registered against it under a FRESH host-side id so parallel tests are isolated. Every chain write
/// is driven inside [`CallTestHarness::host`].
#[cfg(test)]
pub(crate) struct CallTestHarness {
    pub(crate) log: PlaneCallLog,
    pub(crate) app: Arc<crate::state::App>,
}

#[cfg(test)]
impl CallTestHarness {
    /// Fresh isolated harness over `store` (the chain sink, via registration against an app whose
    /// governance wraps it). A "restart" is just a second `over` the SAME store — the chain persists
    /// in the store, so the fresh log reads it back through its own rehydrate.
    pub(crate) fn over(store: Arc<dyn busbar_api::Store>) -> Self {
        let kind_id = fresh_test_kind_id();
        let gov =
            Arc::new(crate::governance::GovState::new(store, None).expect("gov store constructs"));
        let app = crate::test_support::TestApp::new().governance(gov).build();
        register_call_stream_as(kind_id, &app);
        Self {
            log: PlaneCallLog::with_kind_id(kind_id),
            app,
        }
    }

    /// Drive one synchronous chain op with a live `HostCtx` over this harness's app.
    pub(crate) fn host<R>(&self, f: impl FnOnce(HostCtx) -> R) -> R {
        crate::plane_host::with_dispatch_scope(&self.app, |h, _| f(h))
    }

    // ── forwarders: the host-taking chain ops driven over this harness's app, the position-reading
    //    diagnostics forwarded straight through (they touch no chain position, so they need no host) ──
    pub(crate) fn record(
        &self,
        principal: &str,
        input: CallInput,
    ) -> Result<McpCallRecord, CallLogError> {
        self.host(|host| self.log.record(host, principal, input))
    }
    pub(crate) fn restore_from_store(&self, store: &dyn PlaneStore) -> StoreResult<Restored> {
        self.host(|host| self.log.restore_from_store(host, store))
    }
    pub(crate) fn compact(&self, before: u64) -> StoreResult<u64> {
        self.host(|host| self.log.compact(host, before))
    }
    pub(crate) fn next_seq(&self, principal: &str) -> u64 {
        self.log.next_seq(principal)
    }
    pub(crate) fn len(&self) -> usize {
        self.log.len()
    }
    pub(crate) fn read_back(
        &self,
        store: &dyn PlaneStore,
        principal: &str,
    ) -> StoreResult<Vec<McpCallRecord>> {
        self.log.read_back(store, principal)
    }
    pub(crate) fn verify_principal_chain(
        &self,
        store: &dyn PlaneStore,
        principal: &str,
    ) -> StoreResult<Result<usize, ChainBreak>> {
        self.log.verify_principal_chain(store, principal)
    }
}

/// TEST ONLY: the PRODUCTION `call` stream ([`KIND_ID_CALL`]), registered ONCE against a shared
/// no-sink app so the working-set / global-`CALLS` tests mint sequences without racing to re-register
/// (a re-register resets every position). A chain-asserting test aims this stream at its own store
/// with [`aim_global_call_sink`] while it holds the process-wide call-log test lock.
#[cfg(test)]
fn global_call_host_app() -> &'static Arc<crate::state::App> {
    static APP: std::sync::OnceLock<Arc<crate::state::App>> = std::sync::OnceLock::new();
    APP.get_or_init(|| {
        let app = crate::test_support::TestApp::new().build();
        register_call_stream(&app);
        app
    })
}

/// TEST ONLY: ensure the process-wide `call` stream is registered ONCE (no-sink) — for a front-door
/// integration harness whose app is not booted through `mcp_hydrate`. Idempotent (never re-registers).
#[cfg(test)]
pub(crate) fn ensure_global_call_stream_registered() {
    let _ = global_call_host_app();
}

/// TEST ONLY: run `f` with a host over the shared global-`CALLS` app (registration ensured).
#[cfg(test)]
pub(crate) fn with_global_call_host<R>(f: impl FnOnce(HostCtx) -> R) -> R {
    crate::plane_host::with_dispatch_scope(global_call_host_app(), |h, _| f(h))
}

/// TEST ONLY: aim (or detach, with `None`) the process-wide `call` stream's durable sink — for a
/// chain-asserting global-`CALLS` test.
#[cfg(test)]
pub(crate) fn aim_global_call_sink(store: Option<Arc<dyn PlaneStore>>) {
    let _ = global_call_host_app();
    crate::plane_host::journal::set_stream_sink_for_test(KIND_ID_CALL, store);
}

#[cfg(test)]
#[path = "tests/calllog_tests.rs"]
mod calllog_tests;
