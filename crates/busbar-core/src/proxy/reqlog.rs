// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODEL PLANE'S PER-REQUEST CHAIN: one hash-chained record per inbound model request, scoped to
//! the presenting key, on the ONE chain mechanism in [`crate::audit`].
//!
//! ## Why this file exists at all, stated as the defect it closes
//!
//! `grep crate::audit` over `proxy/` and `handlers/` returned ZERO production hits. Model traffic
//! landed in billing (`governance`), in telemetry (`/metrics`) and in the request-log export, and in
//! NO tamper-evident chain — while the MCP plane chained every `tools/call` (`plane::calllog`) and the
//! A2A plane chained every task event (`a2a::provenance`). The owner's ruling is that auditing is
//! core functionality and *"LLM == MCP == A2A — just different protocols, not a different pathway
//! through the engine at all"*, so the flagship plane being the unaudited one is the doctrine
//! inverted. Billing is not auditing: a usage counter answers "how much", it is a mutable aggregate,
//! and an edited row leaves the total looking exactly like a total.
//!
//! ## The mechanism is NOT this file's, and that is the whole design
//!
//! Owner's ruling, 2026-08-13: *"auditing is core. nothing auditing wise should be mcp a2a or llm
//! specific. thats how audits break."* Three chain implementations mean three answers to "what
//! happened". So there is no `compute_hash`, no `verify`, no `Chain` here: this file supplies a
//! RECORD — which fields a model request carries and which of them the digest covers — and inherits
//! the append, the digest, the linkage and the verifier from [`crate::audit`]. The module header
//! there states the acceptance test for its own seam ("adding a fourth stream costs a record type
//! and nothing else"); this is that fourth stream, and it cost a record type and nothing else.
//!
//! ## ONE MECHANISM IS NOT ONE STREAM
//!
//! This stream stays SEPARATE from the admin ring, the MCP call log and the A2A task chain, for the
//! reason `mcp/calllog.rs` records: an admin mutation is operator-rate and a model request is
//! REQUEST-rate, so sharing one bounded ring means a busy afternoon evicts every admin record,
//! silently. [`crate::audit`]'s verifier refuses a record whose scope is not the chain's, so one
//! caller's evidence can never be made to depend on another caller's rows.
//!
//! ## Scoped to the PRINCIPAL, like the call log and unlike the task chain
//!
//! A model request has no durable object of its own to be scoped to — there is no task — so the
//! bounded unit is the presenting key, exactly as `plane::calllog` is. That is also the unit an
//! auditor asks about ("what did this key do"), and it means one caller's chain is verifiable
//! without possessing any other caller's records.
//!
//! An UNGOVERNED request (no `governance:` section, or no key resolved) is recorded under
//! [`PRINCIPAL_UNGOVERNED`] rather than dropped. A chain that silently omits every anonymous request
//! is a chain with a hole an attacker can choose, and the sentinel is a fixed string rather than
//! anything caller-supplied so it cannot be spoofed into another principal's chain.
//!
//! ## ── WHAT IS WIRED, AND WHAT IS HONESTLY NOT ────────────────────────────────────────────────
//!
//! WRITTEN — every inbound model request, at the ONE terminal every one of them passes through
//! (`ingress::finish_inner`, which is also where the plane's metrics and its refund decision are
//! made). Dispatches and refusals alike: a governance refusal is evidence, and it is the half a log
//! that only records successes cannot provide.
//!
//! NOT WRITTEN — durability. `busbar_api::Store` carries no model-request method, and adding one is
//! a plugin-ABI change fanned out to four external store repositories; it is deliberately not made
//! here. So this chain is a bounded IN-MEMORY window and A RESTART LOSES IT. That is the same floor
//! `a2a::pushdeliver`'s pin map and `plane::calllog` under `store: memory` are documented with, it is
//! stated here rather than discovered, and NOTHING may describe this stream as durable until a
//! store method exists. What IS true of it today: within one process lifetime the window is
//! append-only, hash-linked and verifiable, so an in-process edit of a retained record is detected.
//!
//! NOT MOUNTED — the operator-facing read surface. [`LlmRequestLog::verify_principal_chain`] and
//! [`LlmRequestLog::records_for`] have no admin verb, exactly as `plane::calllog`'s equivalents do
//! not; each carries its own `#[allow(dead_code)]` and its own note rather than a module-wide
//! blanket, so the next thing to lose its caller BREAKS THE BUILD instead of joining a silent
//! amnesty. It is a REAL GAP and it is named here.
//!
//! ## The claim, stated honestly
//!
//! TAMPER-EVIDENCE, not tamper-prevention, and only over the retained window. Stated in full in
//! [`crate::audit`], where the mechanism lives.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use crate::audit::{verify_window, ChainBreak, ChainLabels, ChainedRecord, Digest, Framing};

/// The outcome and reason tokens this stream uses, from the ONE audit vocabulary. Re-exported so the
/// call site keeps one import path; the definitions, and the argument for each word, live in core.
pub(crate) use crate::audit::vocab::{
    OUTCOME_DISPATCHED, OUTCOME_REFUSED, REASON_LIMIT_EXCEEDED, REASON_NOT_GRANTED,
    REASON_UPSTREAM_FAILED,
};

/// This stream's chain: one per principal. A type alias over the core mechanism — there is no second
/// implementation behind it.
pub(crate) type RequestChain = crate::audit::Chain<LlmRequestRecord>;

/// The scope an UNGOVERNED request is chained under. A fixed engine-chosen string, never anything a
/// caller can influence, so no request can be steered into a governed principal's chain.
pub(crate) const PRINCIPAL_UNGOVERNED: &str = "ungoverned";

/// How many records the process keeps, across every principal.
///
/// ONE ring rather than one per principal, and the argument `mcp/calllog.rs` makes against a shared
/// ring does NOT apply: that one was about mixing an operator-rate population with a request-rate
/// one, where the fast population silently evicts the slow one's entire history. Every record here
/// is the same population at the same rate, so oldest-first eviction across the whole ring means
/// every principal is trimmed proportionally to how much it used, rather than one class of evidence
/// being wiped by another. It also gives the retention a fixed ceiling in bytes instead of one that
/// scales with however many keys a deployment has minted.
///
/// Eviction is oldest-first GLOBALLY, so what is retained for any one principal is a contiguous
/// SUFFIX of that principal's chain — which is exactly the shape [`verify_window`] verifies, and the
/// reason [`LlmRequestLog::verify_principal_chain`] uses the window verifier rather than
/// [`crate::audit::verify_chain`]: the head has legitimately been pruned, and a caller holding a
/// whole chain that used the lenient entry point would be silently excusing a missing head.
const MAX_RETAINED_REQUESTS: usize = 2048;

/// The fields a caller supplies for one request record. `seq`, `prev_hash` and `hash` are NOT here:
/// they are the chain's own business and are supplied by [`crate::audit::Chain::append`], so no call
/// site can supply a sequence number or a link of its own choosing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestInput {
    pub(crate) ts: u64,
    /// The dialect the request ARRIVED on (`anthropic`, `openai`, `gemini`, …). The plane speaks
    /// six, so which one a caller used is a fact about the request rather than about the build.
    pub(crate) ingress_protocol: String,
    /// The BOUNDED pool label (`ingress::pool_label`), never the raw caller-supplied model string —
    /// the same unbounded-cardinality reasoning the metric label is bounded for.
    pub(crate) pool: String,
    pub(crate) outcome: &'static str,
    pub(crate) reason: &'static str,
    /// The HTTP status the caller was answered with. Chained, because at a refusal terminal it is
    /// the most specific true thing the engine knows.
    pub(crate) status: u16,
}

/// ONE MODEL REQUEST, as evidence. Lives in core rather than in `busbar_api` precisely because it is
/// NOT persisted (see the header): a type in the plugin ABI that no store method takes would be an
/// invitation to believe a durable path exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LlmRequestRecord {
    pub(crate) principal: String,
    pub(crate) seq: u64,
    pub(crate) ts: u64,
    pub(crate) ingress_protocol: String,
    pub(crate) pool: String,
    pub(crate) outcome: String,
    pub(crate) reason: String,
    pub(crate) status: u16,
    pub(crate) prev_hash: String,
    pub(crate) hash: String,
}

impl ChainedRecord for LlmRequestRecord {
    type Input = RequestInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the model per-request chain",
        scope: "principal",
    };

    /// LENGTH-PREFIXED, which is what [`crate::audit::Framing`] requires of a NEW record type and is
    /// not merely inherited style here: `ingress_protocol` and `pool` are engine-bounded today, but
    /// relying on that is the classic digest-collision-by-framing bug — a caller who can choose one
    /// field's bytes could otherwise forge the same byte stream under a different split. Length
    /// prefixes make the split unforgeable whatever any field contains. Nothing of this stream is on
    /// disk, so there is no legacy framing to preserve and no reason to copy the pipe-separated one.
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

    fn link(scope: &str, seq: u64, prev_hash: String, input: RequestInput) -> Self {
        LlmRequestRecord {
            principal: scope.to_string(),
            seq,
            ts: input.ts,
            ingress_protocol: input.ingress_protocol,
            pool: input.pool,
            outcome: input.outcome.to_string(),
            reason: input.reason.to_string(),
            status: input.status,
            prev_hash,
            hash: String::new(),
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    /// Every field that carries meaning about WHAT HAPPENED is inside, including the status: a
    /// tamper that rewrote a 403 into a 200 would otherwise be undetectable.
    fn digest_fields(&self, d: &mut Digest) {
        d.text(&self.prev_hash)
            .text(&self.principal)
            .num(self.seq)
            .num(self.ts)
            .text(&self.ingress_protocol)
            .text(&self.pool)
            .text(&self.outcome)
            .text(&self.reason)
            .num(u64::from(self.status));
    }
}

/// WHICH TERMINAL A REQUEST REACHED, as the engine knows it rather than as a status code implies.
///
/// A status alone cannot answer it: the same 400 is a malformed body on one path and a vendor's
/// quota shape on another (`ingress::admit_check` maps an exhausted budget to the writer's
/// `quota_exceeded_status`, which is 400 for Bedrock), and a 200 that never left the process would
/// be indistinguishable from one that did. So the terminal is passed down explicitly by the three
/// `finish` forms, each of which already knows which of the two it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Terminal {
    /// The request passed every governance guard and was dispatched — [`OUTCOME_DISPATCHED`],
    /// whatever the upstream then did with it.
    Admitted,
    /// The request was turned away before any upstream was contacted — [`OUTCOME_REFUSED`].
    Rejected,
}

/// The chained `outcome`/`reason` pair for a terminal, in the shared vocabulary.
///
/// ## The reason is left EMPTY rather than guessed, and that is deliberate
///
/// The vocabulary's own header argues that plural, distinguishable refusal words beat one flat
/// "refused" because each sends an operator somewhere different. That argument cuts both ways: a
/// word inferred from a status that cannot carry it sends an operator somewhere WRONG, which is
/// worse than sending them nowhere. Two statuses on this plane are unambiguous — 403 is the pool
/// ACL or a frozen group ([`REASON_NOT_GRANTED`]), 429 is a rate or concurrency bucket
/// ([`REASON_LIMIT_EXCEEDED`]) — and they are the governance decisions an audit is actually asked
/// about. The rest chain the STATUS, which is the most specific true thing this terminal knows,
/// with an empty reason.
///
/// THE NAMED GAP: the pre-routing refusals (malformed body, unresolved model, unsupported action)
/// and the vendor-shaped quota statuses know their own reason at the site and do not yet hand it
/// down. Threading it is a change to every `finish_rejected` call site; until it is made, this
/// function does not pretend to know.
pub(crate) fn outcome_of(terminal: Terminal, status: u16) -> (&'static str, &'static str) {
    match terminal {
        // `upstream_failed` rides `dispatched`, never `refused`: the call WENT OUT and the far end
        // broke. Recording it as a refusal would say the opposite of what happened and send an
        // operator to chase an authorization problem that does not exist (`audit::vocab`).
        Terminal::Admitted if (200..300).contains(&status) => (OUTCOME_DISPATCHED, ""),
        Terminal::Admitted => (OUTCOME_DISPATCHED, REASON_UPSTREAM_FAILED),
        Terminal::Rejected => match status {
            403 => (OUTCOME_REFUSED, REASON_NOT_GRANTED),
            429 => (OUTCOME_REFUSED, REASON_LIMIT_EXCEEDED),
            _ => (OUTCOME_REFUSED, ""),
        },
    }
}

/// THE PER-REQUEST LOG: chain positions per principal, plus the bounded window of records the
/// process retains.
#[derive(Default)]
pub(crate) struct LlmRequestLog {
    /// Chain POSITIONS, keyed by principal — a tail hash and a next sequence. Unbounded in the same
    /// way `plane::calllog`'s is, and bounded in practice by the same thing: the principals are minted
    /// key ids plus one fixed sentinel, not caller-chosen strings.
    chains: Mutex<HashMap<String, RequestChain>>,
    /// The retained records, oldest first, across every principal. See [`MAX_RETAINED_REQUESTS`].
    ring: Mutex<VecDeque<LlmRequestRecord>>,
}

/// THE PROCESS-WIDE MODEL REQUEST LOG. Process state, not config-derived state, so it lives as a
/// global rather than on the swappable `App` snapshot — exactly like [`crate::admin::audit::AUDIT`]
/// and [`crate::plane::calllog::CALLS`], and for the same reason: a config apply must not reset the
/// chain positions, because doing so would open a SECOND chain at seq 1 under a principal that
/// already has one, and two chains that each verify and together describe nothing is strictly worse
/// than no chain at all.
pub(crate) static REQUESTS: std::sync::LazyLock<LlmRequestLog> =
    std::sync::LazyLock::new(LlmRequestLog::new);

impl LlmRequestLog {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Poison-recovering locks, for the reason `plane::calllog` gives: the critical sections only
    /// mutate chain positions and a record ring, so the data stays consistent after a panic, and
    /// cascading a poison would wedge the whole data plane because one request panicked.
    fn chains(&self) -> MutexGuard<'_, HashMap<String, RequestChain>> {
        self.chains.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ring(&self) -> MutexGuard<'_, VecDeque<LlmRequestRecord>> {
        self.ring.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// APPEND ONE REQUEST to its principal's chain and retain it in the bounded window.
    ///
    /// Infallible and never on the caller's critical path in any way it can observe: this is the
    /// last thing that happens to a request that has already been answered, and an evidence write
    /// that could refuse a request would be a new way to take the plane down.
    pub(crate) fn record(&self, principal: &str, input: RequestInput) -> LlmRequestRecord {
        let record = {
            let mut chains = self.chains();
            // `or_default()` IS SAFE HERE, and it is worth saying why because it is the same line
            // that once opened a zero-based chain on the MCP call log. A DERIVED `Default` would
            // give `next_seq: 0`, which is not a valid sequence; `crate::audit::Chain` therefore
            // hand-writes its `Default` to be its `new`, and pins the two against each other
            // (`the_default_chain_is_the_new_chain_because_a_derived_default_starts_at_zero`). The
            // hazard is closed once, in core, for every stream — which is the whole argument for
            // one mechanism. `plane::calllog` reads identically.
            let chain = chains.entry(principal.to_string()).or_default();
            chain.append(principal, input)
        };
        let mut ring = self.ring();
        ring.push_back(record.clone());
        while ring.len() > MAX_RETAINED_REQUESTS {
            ring.pop_front();
        }
        record
    }

    /// The retained records for ONE principal, oldest first — a contiguous suffix of that
    /// principal's chain (see [`MAX_RETAINED_REQUESTS`] for why it is contiguous).
    ///
    /// NO PRODUCTION CALLER, and its own allow rather than a module-wide one: when an admin read
    /// verb is mounted this is what it reads, and until then the absence is named rather than
    /// amnestied. The tests drive the PRODUCTION path and then read through here, which is the only
    /// thing that can distinguish "the plane chains its requests" from "the chain works".
    #[allow(dead_code)]
    pub(crate) fn records_for(&self, principal: &str) -> Vec<LlmRequestRecord> {
        self.ring()
            .iter()
            .filter(|r| r.principal == principal)
            .cloned()
            .collect()
    }

    /// RECOMPUTE one principal's retained window and report the first break.
    ///
    /// NO PRODUCTION CALLER — the same real gap `plane::calllog::verify_principal_chain` names, and it
    /// matters for the same reason: a chain nothing ever recomputes proves nothing, because nobody
    /// ever finds out that it does not verify. Nothing anywhere may describe this stream as
    /// continuously verified.
    #[allow(dead_code)]
    pub(crate) fn verify_principal_chain(&self, principal: &str) -> Result<(), ChainBreak> {
        verify_window(&self.records_for(principal))
    }
}

#[cfg(test)]
#[path = "tests/reqlog_tests.rs"]
mod reqlog_tests;
