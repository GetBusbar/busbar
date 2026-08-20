// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The diagnostics catalog: every operator-facing `warn!`/`error!` carries a stable
//! `BUSBAR-NNNN` code an operator can paste into the docs and land on an entry that says what
//! it means, whether it needs action, and what to do.
//!
//! This module is the SINGLE SOURCE OF TRUTH (the "internal_errors" registry). Each diagnostic
//! is a [`Diagnostic`] const; [`REGISTRY`] collects them all. The `docs/diagnostics.md` page and
//! `docs/diagnostics.json` are GENERATED from `REGISTRY` (see [`render_markdown`]/[`render_json`])
//! and a test asserts the committed files match a fresh render, so the docs can never drift.
//!
//! ## Codes
//!
//! `BUSBAR-NNNN`. The thousands digit is the [`Class`]; the last three are the member. Codes are
//! append-only and immutable: retiring a diagnostic sets `retired: true` and keeps the number, so
//! an operator's old logs stay resolvable. Never recycle a number.
//!
//! ## Emitting
//!
//! Use [`diag_warn!`], [`diag_error!`], [`diag_debug!`] instead of the bare `tracing` macros. They
//! attach the `diag = "BUSBAR-NNNN"` field so the code shows in every line and is greppable:
//!
//! ```ignore
//! use crate::diagnostics::{diag_warn, DURABLE_WRITETHROUGH_BELOW_FLOOR};
//! diag_warn!(DURABLE_WRITETHROUGH_BELOW_FLOOR, seq, durable_floor, "seq predates the durable floor");
//! ```
//!
//! ## Severity → level
//!
//! [`Severity::BenignRecurring`] is the log-spam bucket: expected, self-healing, may fire per
//! request/tick — it lives at `debug!` or a `warn!`-once latch, NEVER an unlatched `warn!`.
//! [`Severity::Actionable`] is a `warn!`/`error!` at human cadence (latched if it can recur).
//! [`Severity::Fatal`] is a boot refusal / exit.

use std::fmt;

#[cfg(test)]
mod tests;

/// The class of a diagnostic — the thousands digit of its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// 1000 — durable audit floor, single-writer detach, store-outage backfill.
    Durability,
    /// 2000 — audit chain verification, tamper evidence, snapshot restore.
    Audit,
    /// 3000 — config.yaml parse/validate/schema, providers file, overrides.
    Config,
    /// 4000 — tokens, oauth_as/cimd, egress_auth, trust, sigv4 credentials.
    Auth,
    /// 5000 — upstream, egress gate, SSRF guard, breaker, availability, handlers.
    Proxy,
    /// 6000 — loader, ABI floor, signature/trust, plugin_routes, hooks.
    Plugins,
    /// 7000 — a2a, mcp, export, ir, proto, plane store.
    Plane,
    /// 8000 — holds, quotas, metering, appbuild, governance state.
    Governance,
    /// 9000 — startup, tls, telemetry, eventstream, preflight, jemalloc.
    Boot,
}

impl Class {
    /// The thousands multiplier: `Durability` → 1, `Boot` → 9. The code's `code / 1000`.
    pub const fn ordinal(self) -> u16 {
        match self {
            Class::Durability => 1,
            Class::Audit => 2,
            Class::Config => 3,
            Class::Auth => 4,
            Class::Proxy => 5,
            Class::Plugins => 6,
            Class::Plane => 7,
            Class::Governance => 8,
            Class::Boot => 9,
        }
    }

    /// Human title for the class, used as the section heading in the generated docs page.
    pub const fn title(self) -> &'static str {
        match self {
            Class::Durability => "Durability & write-through",
            Class::Audit => "Audit chain",
            Class::Config => "Config",
            Class::Auth => "Auth & identity",
            Class::Proxy => "Proxy & routing",
            Class::Plugins => "Plugins",
            Class::Plane => "Plane protocols",
            Class::Governance => "Governance & cost",
            Class::Boot => "Boot & lifecycle",
        }
    }

    /// Every class, in code order — the iteration order for the generated docs.
    pub const ALL: [Class; 9] = [
        Class::Durability,
        Class::Audit,
        Class::Config,
        Class::Auth,
        Class::Proxy,
        Class::Plugins,
        Class::Plane,
        Class::Governance,
        Class::Boot,
    ];
}

/// How severe a diagnostic is — this decides the log level the emitting site uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Expected, self-healing, may fire per request/tick. `debug!` or a `warn!`-once latch.
    BenignRecurring,
    /// An operator can and should act (misconfig, outage, refusal). `warn!` or `error!`.
    Actionable,
    /// Boot refuses / the process exits. `error!` then exit.
    Fatal,
}

impl Severity {
    /// Stable lowercase token for the machine (`diagnostics.json`) form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::BenignRecurring => "benign_recurring",
            Severity::Actionable => "actionable",
            Severity::Fatal => "fatal",
        }
    }
}

/// One catalog entry. Constructed as a `const` per code; all are gathered into [`REGISTRY`].
#[derive(Debug, Clone, Copy)]
pub struct Diagnostic {
    /// The numeric code, e.g. `1001`. Rendered as `BUSBAR-1001`.
    pub code: u16,
    /// The class this code belongs to; `class.ordinal()` must equal `code / 1000`.
    pub class: Class,
    /// Stable kebab-case anchor: the docs URL fragment and a rename-proof identity. Never changes.
    pub slug: &'static str,
    /// Short human title.
    pub title: &'static str,
    /// Intended severity → the log level the emitting site uses.
    pub severity: Severity,
    /// One to three sentences: what the condition means.
    pub summary: &'static str,
    /// What an operator should do, or `"None — self-heals."` for benign-recurring.
    pub action: &'static str,
    /// The version the code was introduced in.
    pub since: &'static str,
    /// A retired code: kept for historical log resolution, no longer emitted.
    pub retired: bool,
}

impl Diagnostic {
    /// The `BUSBAR-NNNN` banner, zero-allocation (a [`fmt::Display`] wrapper over the code).
    pub const fn banner(&self) -> Banner {
        Banner(self.code)
    }
}

/// `Display`s as `BUSBAR-0001`. Used as the `diag` field on every emitted line.
#[derive(Debug, Clone, Copy)]
pub struct Banner(pub u16);

impl fmt::Display for Banner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BUSBAR-{:04}", self.0)
    }
}

/// Look a code up (e.g. for a future `GET /diagnostics` or a CLI `busbar explain 1001`).
pub fn by_code(code: u16) -> Option<&'static Diagnostic> {
    REGISTRY.iter().copied().find(|d| d.code == code)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE CATALOG. Add a const here (codes ascending within a class), then add it to REGISTRY below,
// then regenerate the docs: `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-core diagnostics`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The archetype: an audit entry whose seq is at/below the recovered durable floor.
pub const DURABLE_WRITETHROUGH_BELOW_FLOOR: Diagnostic = Diagnostic {
    code: 1001,
    class: Class::Durability,
    slug: "durable-writethrough-below-floor",
    title: "Durable audit write-through skipped (seq at or below the recovered floor)",
    severity: Severity::BenignRecurring,
    summary: "An audit entry's sequence number is at or below the recovered durable floor, so it \
              is already persisted under that seq and the write-through is correctly skipped — the \
              entry is retained in the in-memory ring. A single occurrence at boot is expected \
              after a durable-store restore.",
    action:
        "None — self-healing. If it warns repeatedly for DIFFERENT sequence numbers, suspect a \
             second node writing the same durable store (see BUSBAR-1002).",
    since: "1.6.0",
    retired: false,
};

/// A tail ahead of what this node persisted — a second writer on the same durable audit store.
pub const DURABLE_SECOND_WRITER_DETACH: Diagnostic = Diagnostic {
    code: 1002,
    class: Class::Durability,
    slug: "durable-second-writer-detach",
    title: "Durable audit log has another writer — this node detached its durable sink",
    severity: Severity::Actionable,
    summary: "The durable audit store's tail is ahead of what this node last persisted, which can \
              only mean a second busbar is writing the same store. The durable audit log supports \
              exactly ONE writer; two nodes overwrite each other's entries and break the hash \
              chain, which the next boot reports as tampering. This node has detached its durable \
              sink and now audits only to its ephemeral in-memory ring.",
    action: "Ensure exactly one busbar instance is pointed at this durable audit store. Give the \
             other instance its own store, then restart this node to re-attach a durable sink.",
    since: "1.6.0",
    retired: false,
};

/// The in-memory audit ring is not yet reconciled with the durable tail, so writes are held.
pub const DURABLE_AUDIT_RING_UNRECONCILED: Diagnostic = Diagnostic {
    code: 1003,
    class: Class::Durability,
    slug: "durable-audit-ring-unreconciled",
    title: "Durable audit write-through held — ring not yet reconciled with the durable tail",
    severity: Severity::Actionable,
    summary:
        "This process's in-memory audit ring is not yet reconciled with the durable tail (the \
              boot restore did not read or verify it, and a retry read is still failing), so the \
              write-through is held rather than risk overwriting durable history. The entry is \
              retained in the RAM ring and will backfill once the store answers with a verifiable \
              tail.",
    action:
        "Check the durable audit store is reachable and returns a verifiable tail. This clears \
             itself once a tail read succeeds (logged as recovery at info level).",
    since: "1.6.0",
    retired: false,
};

/// Appending an audit entry to the durable store failed — a store outage; entry retained in RAM.
pub const DURABLE_AUDIT_WRITETHROUGH_FAILED: Diagnostic = Diagnostic {
    code: 1004,
    class: Class::Durability,
    slug: "durable-audit-writethrough-failed",
    title: "Durable audit write-through failed (entry retained in the in-memory ring)",
    severity: Severity::Actionable,
    summary: "Appending an audit entry to the durable store failed — typically a durable-store \
              outage. The entry is retained in the in-memory ring and the state snapshot and will \
              backfill on the next successful write-through, so nothing is lost from the ring.",
    action: "Investigate the durable audit store outage. No entries are lost from the in-memory \
             ring; they persist once the store recovers and the next mutation backfills them.",
    since: "1.6.0",
    retired: false,
};

/// A durable-chain seq was pruned from the ring before it could persist — an unrepairable gap.
pub const DURABLE_AUDIT_BACKFILL_GAP: Diagnostic = Diagnostic {
    code: 1005,
    class: Class::Durability,
    slug: "durable-audit-backfill-gap",
    title: "Durable audit chain has an unrepairable gap (a seq was pruned before it persisted)",
    severity: Severity::Actionable,
    summary: "A durable-chain sequence number is no longer in the in-memory ring (it was pruned \
              during a store outage longer than the ring bound), so it can never be backfilled \
              in-process. The durable chain therefore has an unrepairable gap at that seq and \
              catch-up stops below the hole. This is real durable-audit data loss for that seq.",
    action: "Recent entries remain in the in-memory ring, but the DURABLE log has a permanent gap \
             at the named seq. Resolve the store outage that caused it; restore the durable store \
             from a backup if the durable chain's completeness is required for compliance.",
    since: "1.6.0",
    retired: false,
};

// ── 5000 — Proxy & routing ──────────────────────────────────────────────────────────────────────

/// Same-protocol non-stream billing copy hit the reassembly cap; the tail (with usage) is kept.
pub const USAGE_TAP_REASSEMBLY_CAP_EXCEEDED: Diagnostic = Diagnostic {
    code: 5001,
    class: Class::Proxy,
    slug: "usage-tap-reassembly-cap-exceeded",
    title: "Same-protocol non-stream body exceeded the usage-tap reassembly cap (tail retained)",
    severity: Severity::BenignRecurring,
    summary: "A same-protocol non-streaming JSON response body grew past the usage-tap reassembly \
              cap, so busbar dropped the oldest bytes and retained only the TAIL (where every \
              dialect's `usage` object sits) to still bill the request. The client receives the \
              body verbatim regardless; only the internal billing copy is truncated.",
    action: "None — self-heals; the trailing usage object still bills correctly for a recognized \
             dialect. If BILLING_TRUNCATED_TOTAL climbs steadily, some upstream is returning \
             unusually large bodies whose usage may undercount for an unrecognized dialect.",
    since: "1.6.0",
    retired: false,
};

/// Upstream transport error mid-stream, after the first byte already reached the client.
pub const UPSTREAM_MIDSTREAM_TRANSPORT_ERROR: Diagnostic = Diagnostic {
    code: 5002,
    class: Class::Proxy,
    slug: "upstream-midstream-transport-error",
    title: "Mid-stream upstream transport error (generic interruption returned to the client)",
    severity: Severity::BenignRecurring,
    summary: "An upstream transport error occurred AFTER the first byte of a streaming response \
              was already sent to the client. busbar returns a generic, vendor-neutral \
              interruption frame in the client's ingress protocol rather than leaking the raw \
              transport error, and records a compensating breaker transient.",
    action: "None — self-heals per request; the circuit breaker already tracks the upstream \
             fault. A sustained rate indicates a flaky upstream lane worth investigating via \
             breaker telemetry.",
    since: "1.6.0",
    retired: false,
};

/// Upstream transport error before the first byte of a streaming response arrived.
pub const UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR: Diagnostic = Diagnostic {
    code: 5003,
    class: Class::Proxy,
    slug: "upstream-prefirstbyte-transport-error",
    title: "Pre-first-byte upstream transport error (body stream terminated generically)",
    severity: Severity::BenignRecurring,
    summary: "An upstream transport error occurred BEFORE the first byte of a streaming response \
              arrived. busbar terminates the body stream with a generic message, refunds the \
              request budget unit, and records a compensating breaker transient so the failed \
              attempt counts against the lane.",
    action: "None — self-heals; failover and the breaker handle it. Persistent occurrence on one \
             lane points to an unhealthy upstream endpoint.",
    since: "1.6.0",
    retired: false,
};

/// A (pool, lane) circuit breaker transitioned Closed→Open. Warn-once per logical trip.
pub const LANE_BREAKER_TRIPPED: Diagnostic = Diagnostic {
    code: 5004,
    class: Class::Proxy,
    slug: "lane-breaker-tripped",
    title: "Lane circuit breaker tripped (Closed→Open)",
    severity: Severity::BenignRecurring,
    summary: "A circuit breaker for a (pool, lane) transitioned Closed→Open after accumulated \
              failures crossed its threshold, so busbar stops sending traffic to that lane until \
              the breaker's cooldown lets it probe for recovery. Emitted once per logical trip.",
    action: "Traffic fails over to healthy lanes automatically. If a lane trips repeatedly, \
             investigate that upstream's health, credentials, or rate limits.",
    since: "1.6.0",
    retired: false,
};

/// A routing-policy hook errored; the pool's `on_error` fallback was applied. Warn-once (latched).
pub const ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK: Diagnostic = Diagnostic {
    code: 5005,
    class: Class::Proxy,
    slug: "routing-policy-failed-on-error-fallback",
    title: "Routing policy failed; on_error fallback applied",
    severity: Severity::Actionable,
    summary: "A routing-policy hook returned an ERROR while deciding a request, so busbar applied \
              the pool's configured `on_error` fallback. A hook binary that is down, crashing, or \
              returning garbage degrades every request in the pool to the fallback. Warned once \
              per fault window; continued failures log at debug.",
    action: "Fix the routing-policy hook — check that its process is running, reachable, and \
             returning a valid decision. The pool serves via `on_error` until it recovers.",
    since: "1.6.0",
    retired: false,
};

/// A routing-policy hook exceeded its deadline; the `on_error` fallback was applied. Warn-once.
pub const ROUTING_POLICY_DEADLINE_EXCEEDED: Diagnostic = Diagnostic {
    code: 5006,
    class: Class::Proxy,
    slug: "routing-policy-deadline-exceeded",
    title: "Routing policy deadline exceeded; on_error fallback applied",
    severity: Severity::Actionable,
    summary: "A routing-policy hook did not answer within the seam's hard wall-clock deadline, so \
              busbar applied the pool's `on_error` fallback. A slow hook adds latency to every \
              request in the pool. Warned once per fault window; continued timeouts log at debug.",
    action: "Investigate why the routing-policy hook is slow (overload, blocking I/O, an \
             undersized deadline). Tune the hook or raise its configured timeout if the latency \
             is legitimate.",
    since: "1.6.0",
    retired: false,
};

/// An `on_error` fallback hook answered for a failed gate — a recovery signal.
pub const ON_ERROR_FALLBACK_ANSWERED: Diagnostic = Diagnostic {
    code: 5007,
    class: Class::Proxy,
    slug: "on-error-fallback-answered",
    title: "on_error fallback hook answered for the failed gate",
    severity: Severity::BenignRecurring,
    summary: "After a routing gate failed, one of its configured `on_error` fallback hooks \
              answered and decided the request. This is a RECOVERY signal: the fallback chain did \
              its job.",
    action: "None — informational. The paired gate-failure diagnostic (BUSBAR-5005/5006) names \
             the primary hook to fix.",
    since: "1.6.0",
    retired: false,
};

/// An `on_error` fallback hook itself failed; the chain continued. Warn-once (latched).
pub const ON_ERROR_FALLBACK_HOOK_FAILED: Diagnostic = Diagnostic {
    code: 5008,
    class: Class::Proxy,
    slug: "on-error-fallback-hook-failed",
    title: "on_error fallback hook failed; continuing down the chain",
    severity: Severity::Actionable,
    summary: "An `on_error` fallback hook itself returned an error, so busbar continued down the \
              fallback chain to the next link (or the reserved terminal). The fallback chain meant \
              to cover a broken primary is itself partly broken. Warned once per fault window.",
    action: "Fix the failing fallback hook. The request is still served by a later chain link or \
             the terminal policy, but the chain has less depth than configured.",
    since: "1.6.0",
    retired: false,
};

/// An `on_error` fallback hook exceeded its deadline; the chain continued. Warn-once (latched).
pub const ON_ERROR_FALLBACK_DEADLINE_EXCEEDED: Diagnostic = Diagnostic {
    code: 5009,
    class: Class::Proxy,
    slug: "on-error-fallback-deadline-exceeded",
    title: "on_error fallback hook deadline exceeded; continuing down the chain",
    severity: Severity::Actionable,
    summary: "An `on_error` fallback hook exceeded its deadline, so busbar continued down the \
              fallback chain. Warned once per fault window; continued timeouts log at debug.",
    action: "Investigate why the fallback hook is slow, or raise its timeout if the latency is \
             expected. The chain still resolves via a later link or the terminal policy.",
    since: "1.6.0",
    retired: false,
};

/// A cross-protocol non-stream upstream body failed mid-transfer; success not recorded.
pub const CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED: Diagnostic = Diagnostic {
    code: 5010,
    class: Class::Proxy,
    slug: "crossproto-nonstream-midtransfer-failed",
    title: "Cross-protocol non-stream upstream body failed mid-transfer",
    severity: Severity::BenignRecurring,
    summary: "On a cross-protocol non-streaming route, the upstream body failed mid-transfer, so \
              busbar did not record success or usage, refunded the request budget, records a \
              compensating breaker transient, and returns an ingress-native error.",
    action: "None — self-heals; the breaker compensates. A sustained rate indicates a flaky \
             upstream lane.",
    since: "1.6.0",
    retired: false,
};

/// A cross-protocol success body exceeded busbar's translation cap; cannot translate.
pub const CROSSPROTO_TRANSLATION_CAP_EXCEEDED: Diagnostic = Diagnostic {
    code: 5011,
    class: Class::Proxy,
    slug: "crossproto-translation-cap-exceeded",
    title: "Cross-protocol non-stream success body exceeded the translation cap",
    severity: Severity::BenignRecurring,
    summary:
        "A cross-protocol non-streaming success body exceeded busbar's translation cap, so it \
              cannot be translated into the client's protocol and the client receives a 500 with \
              no completion. This is busbar's OWN cap, not an upstream fault, so tokens are not \
              charged and the breaker success stands.",
    action: "None — self-heals per request. If it recurs for legitimate large responses, raise \
             the translated-body cap (`limits`) so those responses translate.",
    since: "1.6.0",
    retired: false,
};

/// A binary/opaque cross-protocol upstream body failed the egress codec's read_response.
pub const CROSSPROTO_BINARY_CODEC_FAILED: Diagnostic = Diagnostic {
    code: 5012,
    class: Class::Proxy,
    slug: "crossproto-binary-codec-failed",
    title: "Cross-protocol binary response failed the egress codec (read_response)",
    severity: Severity::BenignRecurring,
    summary: "A binary/opaque cross-protocol upstream response could not be decoded by the egress \
              codec's `read_response`, so busbar returns an ingress-native 500 rather than leaking \
              the upstream's native body. Often a broken or renamed upstream response field.",
    action: "None — self-heals per request. If it recurs for one upstream, the provider may have \
             changed its response shape; check for a busbar update covering that dialect.",
    since: "1.6.0",
    retired: false,
};

/// A JSON 2xx cross-protocol upstream body was rejected by the egress codec.
pub const CROSSPROTO_JSON_CODEC_FAILED: Diagnostic = Diagnostic {
    code: 5013,
    class: Class::Proxy,
    slug: "crossproto-json-codec-failed",
    title: "Cross-protocol JSON response failed the egress codec (read_response_value)",
    severity: Severity::BenignRecurring,
    summary: "A JSON 2xx cross-protocol upstream response was rejected by the egress codec's \
              `read_response_value` (e.g. a missing expected field), so busbar returns an \
              ingress-native 500 instead of leaking the upstream body. Same root-cause family as \
              BUSBAR-5012.",
    action: "None — self-heals per request. Recurrence for one upstream suggests a changed or \
             renamed response field; check for a busbar update.",
    since: "1.6.0",
    retired: false,
};

/// Degraded-path cross-protocol response not translatable; ingress-native error returned.
pub const CROSSPROTO_RESPONSE_NOT_TRANSLATABLE_DEGRADED: Diagnostic = Diagnostic {
    code: 5014,
    class: Class::Proxy,
    slug: "crossproto-response-not-translatable-degraded",
    title: "Degraded cross-protocol response not translatable (ingress-native error returned)",
    severity: Severity::BenignRecurring,
    summary: "On the degraded path, a cross-protocol upstream response could not be translated \
              into the client's protocol, so busbar returns an ingress-native error rather than \
              leaking the upstream's native wire format to a different-protocol client. This is a \
              deliberate refusal to relay a foreign-format body, not a busbar fault.",
    action: "None — self-heals per request; returning the native error is the correct, safe \
             behavior.",
    since: "1.6.0",
    retired: false,
};

/// Cross-protocol response not translatable (would leak the upstream's native body).
pub const CROSSPROTO_RESPONSE_NOT_TRANSLATABLE: Diagnostic = Diagnostic {
    code: 5015,
    class: Class::Proxy,
    slug: "crossproto-response-not-translatable",
    title: "Cross-protocol response not translatable (ingress-native error returned)",
    severity: Severity::BenignRecurring,
    summary: "A cross-protocol upstream response could not be translated into the client's \
              protocol, so busbar returns an ingress-native error instead of leaking the \
              upstream's native body to a different-protocol client. This is normal, safe \
              operation — an open-relay refusal — not a fault.",
    action: "None — self-heals per request; refusing to relay an untranslatable foreign body is \
             the intended behavior.",
    since: "1.6.0",
    retired: false,
};

/// A rewrite-gate hook rejected the request. Normal policy enforcement.
pub const REWRITE_GATE_REJECTED: Diagnostic = Diagnostic {
    code: 5016,
    class: Class::Proxy,
    slug: "rewrite-gate-rejected",
    title: "Rewrite gate rejected the request",
    severity: Severity::BenignRecurring,
    summary: "A rewrite-gate hook rejected the request, so busbar returns the hook's clamped \
              status and sanitized message in the client's native envelope. This is normal policy \
              enforcement, not an error.",
    action: "None — self-heals per request. The ROUTE_POLICY counters carry the volume; a client \
             seeing rejections should adjust its request to satisfy the policy.",
    since: "1.6.0",
    retired: false,
};

/// Materializing the validated request body for the rewrite pass failed; fail-closed reject.
pub const REWRITE_BODY_MATERIALIZE_FAILED: Diagnostic = Diagnostic {
    code: 5017,
    class: Class::Proxy,
    slug: "rewrite-body-materialize-failed",
    title: "Materializing the validated request body for the rewrite pass failed",
    severity: Severity::Actionable,
    summary: "busbar could not materialize the validated request body into a DOM for the rewrite \
              pass, so it fails CLOSED and rejects the request rather than forwarding it \
              un-rewritten. Unreachable in practice (the bytes already validated), but \
              operator-visible if it ever fires.",
    action: "Investigate — this indicates a serious internal inconsistency (validated bytes that \
             no longer parse). Capture the request context and file a bug; the request was safely \
             rejected, not mis-forwarded.",
    since: "1.6.0",
    retired: false,
};

/// Re-serializing a committed rewrite failed; reject rather than forward the un-rewritten body.
pub const REWRITE_RESERIALIZE_FAILED: Diagnostic = Diagnostic {
    code: 5018,
    class: Class::Proxy,
    slug: "rewrite-reserialize-failed",
    title: "Re-serializing a committed rewrite failed (request rejected to protect the invariant)",
    severity: Severity::Actionable,
    summary: "A committed request rewrite could not be re-serialized into the retained bytes, so \
              busbar rejects the request rather than risk a failover hop forwarding the ORIGINAL \
              un-rewritten body. Protects the rewrite invariant (fail-closed) across failover. Not \
              realistically reachable.",
    action: "Investigate the rewrite hook and request that triggered it; a rewrite that produces \
             an unserializable body is a bug. The request was safely rejected, never forwarded \
             un-rewritten.",
    since: "1.6.0",
    retired: false,
};

/// A decision-gate hook rejected the request. Normal policy enforcement.
pub const DECISION_GATE_REJECTED: Diagnostic = Diagnostic {
    code: 5019,
    class: Class::Proxy,
    slug: "decision-gate-rejected",
    title: "Decision gate rejected the request",
    severity: Severity::BenignRecurring,
    summary: "A decision-gate hook rejected the request; busbar returns the gate's clamped status \
              and sanitized message in the client's native envelope. Normal policy enforcement.",
    action: "None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.",
    since: "1.6.0",
    retired: false,
};

/// A decision gate's restrict left no eligible lane; on_empty weighted escape.
pub const DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE: Diagnostic = Diagnostic {
    code: 5020,
    class: Class::Proxy,
    slug: "decision-gate-restrict-weighted-escape",
    title: "Decision gate restrict left no eligible lane; on_empty: weighted escape",
    severity: Severity::BenignRecurring,
    summary: "A decision gate's restrict left no eligible lane, and its `on_empty` policy is \
              `weighted`, so busbar skips that restriction and falls back to weighted selection \
              across the full pool. Normal advisory-restrict behavior.",
    action: "None — self-heals per request. If the restriction should be enforced strictly, set \
             its `on_empty` to reject.",
    since: "1.6.0",
    retired: false,
};

/// A decision gate's restrict left no eligible lane; on_empty reject (fail-closed).
pub const DECISION_GATE_RESTRICT_REJECT: Diagnostic = Diagnostic {
    code: 5021,
    class: Class::Proxy,
    slug: "decision-gate-restrict-reject",
    title: "Decision gate restrict left no eligible lane (on_empty: reject)",
    severity: Severity::BenignRecurring,
    summary:
        "A decision gate's restrict left no eligible lane and its `on_empty` policy is reject \
              (fail-closed), so busbar rejects the request rather than route to an ineligible \
              lane. This is the correct compliance behavior.",
    action: "None — self-heals per request; the counters carry the volume. If rejections are \
             unexpected, review the pool membership tags against the restrict's required tags.",
    since: "1.6.0",
    retired: false,
};

/// A routing-policy hook rejected the request. Normal policy enforcement.
pub const ROUTING_POLICY_REJECTED: Diagnostic = Diagnostic {
    code: 5022,
    class: Class::Proxy,
    slug: "routing-policy-rejected",
    title: "Routing policy rejected the request",
    severity: Severity::BenignRecurring,
    summary: "A routing-policy hook rejected the request; busbar returns the policy's clamped \
              status and sanitized message in the client's native envelope. Normal policy \
              enforcement.",
    action: "None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.",
    since: "1.6.0",
    retired: false,
};

/// A routing policy's restrict left no eligible lane; on_empty weighted escape.
pub const ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE: Diagnostic = Diagnostic {
    code: 5023,
    class: Class::Proxy,
    slug: "routing-policy-restrict-weighted-escape",
    title: "Routing policy restrict left no eligible lane; on_empty: weighted escape",
    severity: Severity::BenignRecurring,
    summary: "A routing policy's restrict left no eligible lane and its `on_empty` is `weighted`, \
              so busbar escapes to full-pool weighted selection. Normal advisory-restrict \
              behavior.",
    action: "None — self-heals per request. Set `on_empty` to reject if the restriction must be \
             enforced strictly.",
    since: "1.6.0",
    retired: false,
};

/// A routing policy's restrict left no eligible lane; on_empty reject (fail-closed).
pub const ROUTING_POLICY_RESTRICT_REJECT: Diagnostic = Diagnostic {
    code: 5024,
    class: Class::Proxy,
    slug: "routing-policy-restrict-reject",
    title: "Routing policy restrict left no eligible lane (on_empty: reject)",
    severity: Severity::BenignRecurring,
    summary: "A routing policy's restrict left no eligible lane and its `on_empty` is reject \
              (fail-closed), so busbar rejects the request rather than route to an ineligible \
              upstream. Correct compliance behavior.",
    action: "None — self-heals per request. If unexpected, review pool membership tags against \
             the restrict's required tags.",
    since: "1.6.0",
    retired: false,
};

/// No response headers within the per-attempt cap; failing over to the next lane.
pub const ATTEMPT_TIMEOUT_FAILOVER: Diagnostic = Diagnostic {
    code: 5025,
    class: Class::Proxy,
    slug: "attempt-timeout-failover",
    title: "No response headers within the attempt cap; failing over",
    severity: Severity::BenignRecurring,
    summary: "An upstream attempt returned no response headers within its per-attempt \
              time-to-headers cap, so busbar fails over to the next candidate lane. Expected under \
              a slow lane; failover is normal operation.",
    action: "None — self-heals via failover; telemetry counters carry the volume. If one lane \
             times out constantly, investigate its latency or raise its `attempt_timeout_ms`.",
    since: "1.6.0",
    retired: false,
};

/// A lane's breaker is hard-down on its fresh logical trip. Warn-once (latched).
pub const LANE_HARD_DOWN: Diagnostic = Diagnostic {
    code: 5026,
    class: Class::Proxy,
    slug: "lane-hard-down",
    title: "Lane hard-down (breaker trip)",
    severity: Severity::BenignRecurring,
    summary: "A lane's circuit breaker is hard-down (tripped) and this is the FRESH logical trip, \
              so busbar fails over and stops routing to the lane until its cooldown allows a \
              recovery probe. Recurring still-down probes log at debug. Emitted once per logical \
              trip.",
    action: "Traffic fails over automatically. Investigate the named upstream's health if a lane \
             stays hard-down.",
    since: "1.6.0",
    retired: false,
};

/// Usage tap: unknown ingress protocol for a same-protocol 2xx body. Warn-once (latched).
pub const USAGE_TAP_UNKNOWN_PROTOCOL: Diagnostic = Diagnostic {
    code: 5027,
    class: Class::Proxy,
    slug: "usage-tap-unknown-protocol",
    title: "Usage tap: unknown ingress protocol for a same-protocol 2xx body",
    severity: Severity::BenignRecurring,
    summary: "The usage tap could not recognize the ingress protocol of a same-protocol 2xx body, \
              so it bills 0 tokens for the request. Warned once per (protocol, reason); \
              BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.",
    action: "None if the protocol is genuinely unmetered. If a metered dialect is billing 0 \
             tokens, the protocol name is unexpected — check the route configuration and for a \
             busbar update covering it.",
    since: "1.6.0",
    retired: false,
};

/// Usage tap: a same-protocol 2xx body did not parse as JSON. Warn-once (latched).
pub const USAGE_TAP_BAD_JSON: Diagnostic = Diagnostic {
    code: 5028,
    class: Class::Proxy,
    slug: "usage-tap-bad-json",
    title: "Usage tap: failed to parse a same-protocol 2xx body as JSON",
    severity: Severity::BenignRecurring,
    summary:
        "The usage tap could not parse a same-protocol 2xx body as JSON, so it bills 0 tokens \
              for the request. Warned once per (protocol, reason); the raw body is never logged \
              (it may carry secrets). BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.",
    action: "None — self-heals per request. Sustained occurrence for one upstream means it is \
             returning non-JSON 2xx bodies busbar cannot meter; investigate that upstream.",
    since: "1.6.0",
    retired: false,
};

/// Usage tap: read_response could not decode a same-protocol 2xx body. Warn-once (latched).
pub const USAGE_TAP_DECODE_FAILED: Diagnostic = Diagnostic {
    code: 5029,
    class: Class::Proxy,
    slug: "usage-tap-decode-failed",
    title: "Usage tap: read_response failed to decode a same-protocol 2xx body",
    severity: Severity::BenignRecurring,
    summary: "The usage tap's `read_response` could not decode a same-protocol 2xx body into the \
              IR, so it bills 0 tokens for the request. Warned once per (protocol, reason); \
              BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.",
    action: "None — self-heals per request. If a metered dialect bills 0 tokens repeatedly, the \
             upstream's response shape may have changed; check for a busbar update covering it.",
    since: "1.6.0",
    retired: false,
};

/// No response headers within the per-attempt cap on the degraded path.
pub const ATTEMPT_TIMEOUT_DEGRADED: Diagnostic = Diagnostic {
    code: 5030,
    class: Class::Proxy,
    slug: "attempt-timeout-degraded",
    title: "No response headers within the attempt cap (degraded path)",
    severity: Severity::BenignRecurring,
    summary: "On the degraded routing path, an upstream attempt returned no response headers \
              within its per-attempt cap, so busbar records a breaker transient and tries the next \
              degraded candidate. Degraded-path sibling of BUSBAR-5025.",
    action: "None — self-heals via the degraded candidate walk; telemetry counters carry the \
             volume.",
    since: "1.6.0",
    retired: false,
};

/// A compliance restrict left no eligible lane in the fallback pool; fail closed.
pub const FALLBACK_RESTRICT_NO_ELIGIBLE_LANE: Diagnostic = Diagnostic {
    code: 5031,
    class: Class::Proxy,
    slug: "fallback-restrict-no-eligible-lane",
    title: "Compliance restrict left no eligible lane in the fallback pool (fail closed)",
    severity: Severity::BenignRecurring,
    summary: "A compliance restrict re-applied against a fallback pool left no eligible lane, so \
              busbar fails closed (503) rather than spill to an ineligible upstream. Fail-closed \
              is the correct behavior for a compliance restriction.",
    action: "None — self-heals per request. If the fallback pool should serve this traffic, \
             ensure its members carry the tags the restrict requires.",
    since: "1.6.0",
    retired: false,
};

/// The Prometheus recorder failed to install at boot; /metrics will be empty.
pub const PROMETHEUS_RECORDER_INSTALL_FAILED: Diagnostic = Diagnostic {
    code: 5032,
    class: Class::Proxy,
    slug: "prometheus-recorder-install-failed",
    title: "Prometheus recorder install failed; /metrics will be empty",
    severity: Severity::Actionable,
    summary: "The Prometheus metrics recorder failed to install at boot, so the /metrics endpoint \
              will be empty for the life of the process. busbar continues serving proxy traffic, \
              but is blind to metrics.",
    action: "Investigate the boot error (often a duplicate recorder install or a conflicting \
             exporter). Restart busbar after resolving it; /metrics stays empty until then.",
    since: "1.6.0",
    retired: false,
};

/// The metrics maintenance (drain) thread failed to spawn at boot.
pub const METRICS_MAINTENANCE_THREAD_SPAWN_FAILED: Diagnostic = Diagnostic {
    code: 5033,
    class: Class::Proxy,
    slug: "metrics-maintenance-thread-spawn-failed",
    title: "Could not spawn the metrics maintenance thread (observations drain on scrape only)",
    severity: Severity::Actionable,
    summary: "busbar could not spawn the metrics maintenance (drain) thread at boot, so buffered \
              metric observations now drain only when /metrics is scraped instead of on a timer. \
              Metrics are still correct but may lag between scrapes.",
    action: "Investigate the thread-spawn failure (typically OS thread/resource exhaustion). \
             Metrics remain available on scrape; restart after resolving the resource limit for \
             timely draining.",
    since: "1.6.0",
    retired: false,
};

/// A /metrics scrape could not list virtual keys; per-key gauges skipped this scrape.
pub const METRICS_SCRAPE_LIST_KEYS_FAILED: Diagnostic = Diagnostic {
    code: 5034,
    class: Class::Proxy,
    slug: "metrics-scrape-list-keys-failed",
    title: "Metrics scrape: failed to list virtual keys (per-key gauges skipped)",
    severity: Severity::BenignRecurring,
    summary:
        "A /metrics scrape could not list virtual keys from the governance store (a transient \
              store hiccup), so it skips the per-key spend/token gauges for this scrape. Other \
              gauges still refresh.",
    action: "None — self-heals on the next scrape once the store responds. Sustained failures \
             indicate a governance-store problem worth investigating.",
    since: "1.6.0",
    retired: false,
};

/// Virtual-key count exceeds the per-key gauge limit; gauges truncated. Warn-once (latched).
pub const METRICS_KEY_GAUGE_LIMIT_EXCEEDED: Diagnostic = Diagnostic {
    code: 5035,
    class: Class::Proxy,
    slug: "metrics-key-gauge-limit-exceeded",
    title: "Metrics scrape: virtual-key count exceeds the per-key gauge limit (truncating)",
    severity: Severity::Actionable,
    summary:
        "The number of virtual keys exceeds the per-key gauge limit (`metrics.key_gauge_limit`), \
              so busbar emits gauges for only the first `limit` keys to bound Prometheus \
              cardinality and scrape-path DB load. Some keys have no per-key series. Warned once \
              until the count drops back under the limit.",
    action: "Raise `metrics.key_gauge_limit` if you need per-key series for all keys and can \
             afford the cardinality, or reduce the number of active virtual keys. Aggregate group \
             gauges are unaffected.",
    since: "1.6.0",
    retired: false,
};

/// A /metrics scrape could not read one key's usage; that key's gauges skipped this scrape.
pub const METRICS_SCRAPE_KEY_USAGE_READ_FAILED: Diagnostic = Diagnostic {
    code: 5036,
    class: Class::Proxy,
    slug: "metrics-scrape-key-usage-read-failed",
    title: "Metrics scrape: usage read failed; skipping key",
    severity: Severity::BenignRecurring,
    summary: "During a /metrics scrape, reading one virtual key's usage from the store failed, so \
              busbar skips that key's gauges for this scrape and continues with the rest. Per-key, \
              per-scrape.",
    action: "None — self-heals on the next scrape. A high volume across keys points to a \
             governance-store problem.",
    since: "1.6.0",
    retired: false,
};

/// A /metrics scrape could not read a group ledger bucket; that bucket skipped this scrape.
pub const METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED: Diagnostic = Diagnostic {
    code: 5037,
    class: Class::Proxy,
    slug: "metrics-scrape-group-ledger-read-failed",
    title: "Metrics scrape: group ledger read failed; skipping bucket",
    severity: Severity::BenignRecurring,
    summary: "During a /metrics scrape, reading a group budget bucket's ledger from the store \
              failed, so busbar skips that bucket's gauges for this scrape and continues. \
              Per-bucket, per-scrape.",
    action: "None — self-heals on the next scrape. Sustained failures indicate a governance-store \
             problem.",
    since: "1.6.0",
    retired: false,
};

/// EVERY diagnostic, in ascending code order. The tests assert uniqueness and class alignment.
pub static REGISTRY: &[&Diagnostic] = &[
    &DURABLE_WRITETHROUGH_BELOW_FLOOR,
    &DURABLE_SECOND_WRITER_DETACH,
    &DURABLE_AUDIT_RING_UNRECONCILED,
    &DURABLE_AUDIT_WRITETHROUGH_FAILED,
    &DURABLE_AUDIT_BACKFILL_GAP,
    &USAGE_TAP_REASSEMBLY_CAP_EXCEEDED,
    &UPSTREAM_MIDSTREAM_TRANSPORT_ERROR,
    &UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR,
    &LANE_BREAKER_TRIPPED,
    &ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
    &ROUTING_POLICY_DEADLINE_EXCEEDED,
    &ON_ERROR_FALLBACK_ANSWERED,
    &ON_ERROR_FALLBACK_HOOK_FAILED,
    &ON_ERROR_FALLBACK_DEADLINE_EXCEEDED,
    &CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED,
    &CROSSPROTO_TRANSLATION_CAP_EXCEEDED,
    &CROSSPROTO_BINARY_CODEC_FAILED,
    &CROSSPROTO_JSON_CODEC_FAILED,
    &CROSSPROTO_RESPONSE_NOT_TRANSLATABLE_DEGRADED,
    &CROSSPROTO_RESPONSE_NOT_TRANSLATABLE,
    &REWRITE_GATE_REJECTED,
    &REWRITE_BODY_MATERIALIZE_FAILED,
    &REWRITE_RESERIALIZE_FAILED,
    &DECISION_GATE_REJECTED,
    &DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
    &DECISION_GATE_RESTRICT_REJECT,
    &ROUTING_POLICY_REJECTED,
    &ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
    &ROUTING_POLICY_RESTRICT_REJECT,
    &ATTEMPT_TIMEOUT_FAILOVER,
    &LANE_HARD_DOWN,
    &USAGE_TAP_UNKNOWN_PROTOCOL,
    &USAGE_TAP_BAD_JSON,
    &USAGE_TAP_DECODE_FAILED,
    &ATTEMPT_TIMEOUT_DEGRADED,
    &FALLBACK_RESTRICT_NO_ELIGIBLE_LANE,
    &PROMETHEUS_RECORDER_INSTALL_FAILED,
    &METRICS_MAINTENANCE_THREAD_SPAWN_FAILED,
    &METRICS_SCRAPE_LIST_KEYS_FAILED,
    &METRICS_KEY_GAUGE_LIMIT_EXCEEDED,
    &METRICS_SCRAPE_KEY_USAGE_READ_FAILED,
    &METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED,
];

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Emit macros. `pub(crate)` — internal to busbar-core. Sites `use crate::diagnostics::diag_warn;`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `warn!` carrying the `diag = "BUSBAR-NNNN"` field. First arg is the [`Diagnostic`] const.
macro_rules! diag_warn {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::warn!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `error!` carrying the `diag = "BUSBAR-NNNN"` field.
macro_rules! diag_error {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::error!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `debug!` carrying the `diag = "BUSBAR-NNNN"` field (the benign-recurring / latched-quiet arm).
macro_rules! diag_debug {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::debug!(diag = %$diag.banner(), $($rest)*)
    };
}
pub(crate) use {diag_debug, diag_error, diag_warn};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Doc generation — `docs/diagnostics.md` (human) and `docs/diagnostics.json` (machine).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Path of the committed markdown page, relative to the repo root (this crate is `crates/busbar-core`).
pub const COMMITTED_DIAGNOSTICS_MD: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.md");
/// Path of the committed machine-readable catalog.
pub const COMMITTED_DIAGNOSTICS_JSON: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.json");

/// Render the operator-facing markdown page from [`REGISTRY`]: one section per class, a table
/// anchored by slug so `…/diagnostics#<slug>` deep-links.
pub fn render_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Busbar diagnostics catalog\n\n");
    out.push_str(
        "Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its \
         `diag` field. Find the code below for what it means, whether it needs action, and what \
         to do. This page is generated from the code — do not edit by hand.\n\n",
    );
    out.push_str("Codes are grouped by class (the thousands digit).\n\n");
    for class in Class::ALL {
        let mut rows: Vec<&Diagnostic> = REGISTRY
            .iter()
            .copied()
            .filter(|d| d.class == class)
            .collect();
        if rows.is_empty() {
            continue;
        }
        rows.sort_by_key(|d| d.code);
        out.push_str(&format!(
            "## {}xxx — {}\n\n",
            class.ordinal(),
            class.title()
        ));
        for d in rows {
            let retired = if d.retired { " *(retired)*" } else { "" };
            out.push_str(&format!(
                "<a id=\"{slug}\"></a>\n### {banner} — {title}{retired}\n\n\
                 - **Severity:** {sev}\n- **Since:** {since}\n- **Slug:** `{slug}`\n\n\
                 {summary}\n\n**What to do:** {action}\n\n",
                slug = d.slug,
                banner = d.banner(),
                title = d.title,
                retired = retired,
                sev = d.severity.as_str(),
                since = d.since,
                summary = d.summary,
                action = d.action,
            ));
        }
    }
    out
}

/// Render the machine-readable catalog (stable field order, pretty, trailing newline).
pub fn render_json() -> String {
    // Hand-rolled to avoid a serde derive dependency on a doc artifact and to pin field order.
    let mut items = Vec::new();
    let mut sorted = REGISTRY.to_vec();
    sorted.sort_by_key(|d| d.code);
    for d in sorted {
        items.push(format!(
            "  {{\n    \"code\": \"{banner}\",\n    \"number\": {num},\n    \"class\": \"{class}\",\n    \
             \"slug\": \"{slug}\",\n    \"title\": {title},\n    \"severity\": \"{sev}\",\n    \
             \"summary\": {summary},\n    \"action\": {action},\n    \"since\": \"{since}\",\n    \
             \"retired\": {retired}\n  }}",
            banner = d.banner(),
            num = d.code,
            class = class_key(d.class),
            slug = d.slug,
            title = json_str(d.title),
            sev = d.severity.as_str(),
            summary = json_str(d.summary),
            action = json_str(d.action),
            since = d.since,
            retired = d.retired,
        ));
    }
    format!("[\n{}\n]\n", items.join(",\n"))
}

/// Stable lowercase key for a class in the JSON form.
fn class_key(c: Class) -> &'static str {
    match c {
        Class::Durability => "durability",
        Class::Audit => "audit",
        Class::Config => "config",
        Class::Auth => "auth",
        Class::Proxy => "proxy",
        Class::Plugins => "plugins",
        Class::Plane => "plane",
        Class::Governance => "governance",
        Class::Boot => "boot",
    }
}

/// Minimal JSON string escaping for the doc artifact (quote, backslash, control chars).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
