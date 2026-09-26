// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S OWN CODED DIAGNOSTICS (#83a O4): the fifteen codes only this plane's code emits —
//! the nine cross-protocol IR normalizations, the two usage-tap faults a same-protocol tap reads
//! before it decodes, the three event-stream framing guards, and the dropped provider-metadata
//! report. The plane owns its constants exactly as every other plane does, and hands them to the
//! host's catalog through [`DIAGNOSTICS`](crate::diagnostics::DIAGNOSTICS) (`install_diagnostics` at the composition root).
//!
//! NUMBERING AND TEXT ARE FROZEN. Each constant keeps the `BUSBAR-NNNN`, slug, title, summary and
//! action the host catalog publishes in `docs/diagnostics.md` / `docs/diagnostics.json`, so an
//! operator's logs and the published page read identically whichever crate defines the constant;
//! the drift test beside this module fails if a constant here and the catalog entry of the same code
//! disagree in any field.
//!
//! The shared decode-failure code, `USAGE_TAP_DECODE_FAILED`, is not here: a cell's default tap and
//! this plane both print it, so it is one contract shape (`busbar_contract::diagnostic`).

use busbar_contract::diagnostic::{Class, Diagnostic, Severity};

pub const IR_CLAMP_N_TO_1: Diagnostic = Diagnostic {
    code: 7078,
    class: Class::Plane,
    slug: "ir-clamp-n-to-1",
    title: "Cross-protocol transcode clamped n>1 to 1",
    severity: Severity::BenignRecurring,
    summary: "On a cross-protocol hop the neutral response IR carries a single candidate, so a \
              request asking for n>1 completions is clamped to n=1 before the egress writer emits it \
              — otherwise extra choices would be generated, billed, and then dropped. Fires per \
              request on the affected seam, so it is logged at debug.",
    action: "None — self-heals. To use n>1, route the request to a same-protocol lane where the \
             body is forwarded verbatim.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_CACHED_CONTENT: Diagnostic = Diagnostic {
    code: 7084,
    class: Class::Plane,
    slug: "ir-drop-cached-content",
    title: "Cross-protocol transcode dropped a provider cachedContent reference",
    severity: Severity::BenignRecurring,
    summary:
        "A provider `cachedContent` reference was dropped on the cross-protocol seam because the \
              referenced context cache lives server-side at the origin provider and cannot be projected into \
              `contents`: the backend answers on the visible history only and the caller is billed \
              full uncached input. Fires per request, logged at debug.",
    action: "None — self-heals. Route cachedContent requests to a same-protocol lane to use the cache.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_CACHE_CONTROL_OVER_CAP: Diagnostic = Diagnostic {
    code: 7081,
    class: Class::Plane,
    slug: "ir-drop-cache-control-over-cap",
    title: "Cross-protocol transcode dropped cache_control breakpoints past the dialect cap",
    severity: Severity::BenignRecurring,
    summary:
        "The request carried more cache_control breakpoints than the egress dialect allows (the \
              target vendor 400s past its documented cap), so the breakpoints past the cap were \
              dropped before the writer emitted them. Reachable only cross-protocol; fires per \
              request, logged at debug.",
    action:
        "None — self-heals. Reduce the number of cache breakpoints, or route to a same-protocol \
             lane if the full set is load-bearing.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_HOSTED_TOOLS: Diagnostic = Diagnostic {
    code: 7082,
    class: Class::Plane,
    slug: "ir-drop-hosted-tools",
    title: "Cross-protocol transcode dropped hosted (built-in) tools",
    severity: Severity::BenignRecurring,
    summary: "One or more provider-hosted (built-in) tools were dropped on the cross-protocol seam \
              because they have no function-tool equivalent on a backend that does not host them; forwarding \
              them would emit a malformed empty-name function tool the upstream rejects. Fires per \
              request, logged at debug.",
    action: "None — self-heals. Route hosted-tool requests to a lane whose backend hosts them.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_MESSAGE_NAME: Diagnostic = Diagnostic {
    code: 7083,
    class: Class::Plane,
    slug: "ir-drop-message-name",
    title: "Cross-protocol transcode dropped per-message participant names (messages[].name)",
    severity: Severity::BenignRecurring,
    summary: "Per-message participant names (`messages[].name`) were dropped on the \
              cross-protocol seam because no target protocol models a per-message speaker name, so a \
              multi-speaker transcript reaches the backend with its speaker labels removed. Fires \
              per request, logged at debug.",
    action: "None — self-heals. Put the speaker in the message text, or route to a same-protocol lane that models them.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_PROMPT_CACHE: Diagnostic = Diagnostic {
    code: 7080,
    class: Class::Plane,
    slug: "ir-drop-prompt-cache",
    title: "Cross-protocol transcode dropped prompt-cache breakpoints",
    severity: Severity::BenignRecurring,
    summary: "Prompt-cache breakpoints were cleared on the cross-protocol seam because the target \
              lane's dialect gates its cache marker per model and the lane does not declare the \
              capability; the request proceeds uncached. Fires per request on the affected seam, \
              logged at debug.",
    action:
        "None — self-heals. Set `prompt_caching: true` on the model if the backend accepts cache \
             markers.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_REASONING: Diagnostic = Diagnostic {
    code: 7079,
    class: Class::Plane,
    slug: "ir-drop-reasoning",
    title: "Cross-protocol transcode dropped a reasoning/thinking ask",
    severity: Severity::BenignRecurring,
    summary: "A request's reasoning/thinking parameter was dropped on the cross-protocol seam because \
              the target lane does not declare the reasoning capability; the request proceeds at the \
              backend's default thinking level. Fires per request on the affected seam, logged at \
              debug.",
    action: "None — self-heals. Set `reasoning: true` on the model or pool member if the backend \
             accepts thinking params.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_UNMODELED_KEYS: Diagnostic = Diagnostic {
    code: 7085,
    class: Class::Plane,
    slug: "ir-drop-unmodeled-keys",
    title: "Cross-protocol transcode dropped unmodeled request keys",
    severity: Severity::BenignRecurring,
    summary: "The source dialect's unmodeled top-level request keys were dropped on the \
              cross-protocol seam because no target writer can re-emit a foreign dialect's key, so \
              every key named in the log is not forwarded to the backend. Fires per request; only \
              key names are logged (never their values), at debug.",
    action:
        "None — self-heals. Route to a same-protocol lane (which forwards the caller's original \
             bytes verbatim) if a named field is load-bearing.",
    since: "1.6.0",
    retired: false,
};

pub const IR_TRUNCATE_STOP_SEQUENCES: Diagnostic = Diagnostic {
    code: 7086,
    class: Class::Plane,
    slug: "ir-truncate-stop-sequences",
    title: "Stop sequences truncated to the protocol's documented cap",
    severity: Severity::BenignRecurring,
    summary: "The request carried more stop sequences than the target protocol's documented cap \
              allows, so the excess were dropped before forwarding. Fires per request on the \
              affected seam, logged at debug.",
    action: "None — self-heals. Reduce the number of stop sequences, or route to a same-protocol \
             lane if the full set is required.",
    since: "1.6.0",
    retired: false,
};

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

pub const EVENTSTREAM_EVENTTYPE_HEADER_OVERSIZE: Diagnostic = Diagnostic {
    code: 9004,
    class: Class::Boot,
    slug: "eventstream-eventtype-header-oversize",
    title: "Event-stream :event-type header exceeds the string cap (frame dropped)",
    severity: Severity::BenignRecurring,
    summary: "An event-stream `:event-type` header exceeded the AWS type-7 string cap, so busbar \
              dropped the frame rather than emit a malformed one. This is unreachable for any real \
              upstream event name (the only caller-supplied value on the frame); it guards the data \
              path and fires per-frame, so it is emitted at debug.",
    action: "None — self-heals per frame; a real upstream event name never trips it. Sustained \
             occurrence would mean a caller is supplying an over-long event-type, worth checking the \
             ingress path.",
    since: "1.6.0",
    retired: false,
};

pub const EVENTSTREAM_EXCEPTIONTYPE_HEADER_OVERSIZE: Diagnostic = Diagnostic {
    code: 9005,
    class: Class::Boot,
    slug: "eventstream-exceptiontype-header-oversize",
    title: "Event-stream :exception-type header exceeds the string cap (frame dropped)",
    severity: Severity::BenignRecurring,
    summary: "An event-stream `:exception-type` header exceeded the AWS type-7 string cap, so busbar \
              dropped the exception frame — a swallowed mid-stream error signal — rather than emit a \
              malformed one. It fires per-frame on the streaming data path and is near-unreachable \
              for a real exception type, so it is emitted at debug.",
    action: "None — self-heals per frame. If it recurs, an upstream mid-stream error carried an \
             over-long exception-type name; check the egress dialect mapping for that upstream.",
    since: "1.6.0",
    retired: false,
};

pub const EVENTSTREAM_FRAME_OVERSIZE: Diagnostic = Diagnostic {
    code: 9006,
    class: Class::Boot,
    slug: "eventstream-frame-oversize",
    title: "Event-stream frame exceeds MAX_FRAME_BYTES (frame dropped)",
    severity: Severity::BenignRecurring,
    summary: "An event-stream frame's total size exceeded MAX_FRAME_BYTES, so busbar dropped it \
              rather than byte-truncate the payload (a truncated JSON body is worse for a native SDK \
              than no frame). Unreachable for any real upstream event-stream delta; it only guards \
              a pathological multi-MiB single event and fires per-frame, so it is emitted at debug.",
    action: "None — self-heals per frame; dropping is graceful (nothing is emitted for that event). \
             Sustained occurrence would indicate an upstream emitting abnormally large single \
             events, worth investigating that lane.",
    since: "1.6.0",
    retired: false,
};

pub const PROTO_DROP_PROVIDER_METADATA: Diagnostic = Diagnostic {
    code: 7088,
    class: Class::Plane,
    slug: "proto-drop-provider-metadata",
    title: "Cross-protocol transcode dropped response-side provider metadata",
    severity: Severity::BenignRecurring,
    summary:
        "Response-side provider metadata (a vendor guardrail `trace`, a vendor `safetyRatings`) \
              was dropped on the cross-protocol seam because it is a vendor-scoped artifact the \
              caller's protocol has no shape to receive. Fires per response on the affected seam, \
              logged at debug.",
    action: "None — self-heals. If this metadata is compliance evidence, route the request to a \
             same-protocol lane where the upstream body reaches the client verbatim.",
    since: "1.6.0",
    retired: false,
};

/// Every code this plane defines, in catalog order, for the composition root's
/// `install_diagnostics`.
pub static DIAGNOSTICS: &[&Diagnostic] = &[
    &USAGE_TAP_UNKNOWN_PROTOCOL,
    &USAGE_TAP_BAD_JSON,
    &EVENTSTREAM_EVENTTYPE_HEADER_OVERSIZE,
    &EVENTSTREAM_EXCEPTIONTYPE_HEADER_OVERSIZE,
    &EVENTSTREAM_FRAME_OVERSIZE,
    &IR_CLAMP_N_TO_1,
    &IR_DROP_REASONING,
    &IR_DROP_PROMPT_CACHE,
    &IR_DROP_CACHE_CONTROL_OVER_CAP,
    &IR_DROP_HOSTED_TOOLS,
    &IR_DROP_MESSAGE_NAME,
    &IR_DROP_CACHED_CONTENT,
    &IR_DROP_UNMODELED_KEYS,
    &IR_TRUNCATE_STOP_SEQUENCES,
    &PROTO_DROP_PROVIDER_METADATA,
];

#[cfg(test)]
#[path = "tests/diagnostics_drift_tests.rs"]
mod drift_tests;
