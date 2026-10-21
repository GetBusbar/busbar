// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S OWN CODED DIAGNOSTICS (#83a O4): the thirty-one codes only this plane's code
//! emits — the nine cross-protocol IR normalizations, the two usage-tap faults a same-protocol tap
//! reads before it decodes, the three event-stream framing guards, the dropped provider-metadata
//! report, and the sixteen lane-engine codes (the usage-tap reassembly cap, the two upstream
//! transport interruptions, the lane breaker trip, the six cross-protocol response faults, the
//! three rewrite-pass refusals, the two per-attempt timeouts and the restrict fallback with no
//! eligible lane). The plane owns its constants exactly as every other plane does, and hands them
//! to the host's catalog through [`DIAGNOSTICS`](crate::codec::diagnostics::DIAGNOSTICS)
//! (folded into the catalogue the composition root lends); the host's own registry holds none of them.
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
    severity: Severity::Actionable,
    summary: "On a cross-protocol hop the neutral response IR carries a single candidate, so a request \
              asking for n>1 completions is clamped to n=1 before the egress writer emits it — \
              otherwise extra choices would be generated, billed, and then dropped. Warned on every \
              translated request it affects (one drop path, `codec::drops`), and recorded in the audit \
              log as `egress.control_unrepresentable` naming the wire path.",
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
    severity: Severity::Actionable,
    summary: "A provider `cachedContent` reference was dropped on the cross-protocol seam because the \
              referenced context cache lives server-side at the origin provider and cannot be \
              projected into `contents`: the backend answers on the visible history only and the \
              caller is billed full uncached input. Warned on every translated request it affects (one \
              drop path, `codec::drops`), and recorded in the audit log as \
              `egress.control_unrepresentable` naming the wire path.",
    action: "None — self-heals. Route cachedContent requests to a same-protocol lane to use the cache.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_CACHE_CONTROL_OVER_CAP: Diagnostic = Diagnostic {
    code: 7081,
    class: Class::Plane,
    slug: "ir-drop-cache-control-over-cap",
    title: "Cross-protocol transcode dropped cache_control breakpoints past the dialect cap",
    severity: Severity::Actionable,
    summary: "The request carried more cache_control breakpoints than the egress dialect allows (the \
              target vendor 400s past its documented cap), so the breakpoints past the cap were \
              dropped before the writer emitted them. Reachable only cross-protocol. Warned on every \
              translated request it affects (one drop path, `codec::drops`), and recorded in the audit \
              log as `egress.control_unrepresentable` naming the wire path.",
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
    severity: Severity::Actionable,
    summary: "One or more provider-hosted (built-in) tools were dropped on the cross-protocol seam \
              because they have no function-tool equivalent on a backend that does not host them; \
              forwarding them would emit a malformed empty-name function tool the upstream rejects. \
              Warned on every translated request it affects (one drop path, `codec::drops`), and \
              recorded in the audit log as `egress.control_unrepresentable` naming the wire path.",
    action: "None — self-heals. Route hosted-tool requests to a lane whose backend hosts them.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_MESSAGE_NAME: Diagnostic = Diagnostic {
    code: 7083,
    class: Class::Plane,
    slug: "ir-drop-message-name",
    title: "Cross-protocol transcode dropped per-message participant names (messages[].name)",
    severity: Severity::Actionable,
    summary: "Per-message participant names (`messages[].name`) were dropped on the cross-protocol \
              seam because no target protocol models a per-message speaker name, so a multi-speaker \
              transcript reaches the backend with its speaker labels removed. Warned on every \
              translated request it affects (one drop path, `codec::drops`), and recorded in the audit \
              log as `egress.control_unrepresentable` naming the wire path.",
    action: "None — self-heals. Put the speaker in the message text, or route to a same-protocol lane that models them.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_PROMPT_CACHE: Diagnostic = Diagnostic {
    code: 7080,
    class: Class::Plane,
    slug: "ir-drop-prompt-cache",
    title: "Cross-protocol transcode dropped prompt-cache breakpoints",
    severity: Severity::Actionable,
    summary: "Prompt-cache breakpoints were cleared on the cross-protocol seam because the target \
              lane's dialect gates its cache marker per model and the lane does not declare the \
              capability; the request proceeds uncached. Warned on every translated request it affects \
              (one drop path, `codec::drops`), and recorded in the audit log as \
              `egress.control_unrepresentable` naming the wire path.",
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
    severity: Severity::Actionable,
    summary: "A request's reasoning/thinking parameter was dropped on the cross-protocol seam because \
              the target lane does not declare the reasoning capability; the request proceeds at the \
              backend's default thinking level. Warned on every translated request it affects (one \
              drop path, `codec::drops`), and recorded in the audit log as \
              `egress.control_unrepresentable` naming the wire path.",
    action: "None — self-heals. Set `reasoning: true` on the model or pool member if the backend \
             accepts thinking params.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_UNMODELED_KEYS: Diagnostic = Diagnostic {
    code: 7085,
    class: Class::Plane,
    slug: "ir-drop-unmodeled-keys",
    title: "Cross-protocol transcode dropped an unmapped member",
    severity: Severity::Actionable,
    summary: "A member of the source dialect that the target dialect has no form for was dropped on \
              the cross-protocol seam: a request member its map file does not model, or a request or \
              answer content block of a kind the other dialect cannot carry. Nothing is put in its \
              place. Only the wire path is logged (never the value). Warned on every translated \
              request or response it affects (one drop path, `codec::drops`); a request-side drop is \
              also recorded in the audit log as `egress.control_unrepresentable` naming the wire path.",
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
    severity: Severity::Actionable,
    summary: "The request carried more stop sequences than the target protocol's documented cap \
              allows, so the excess were dropped before forwarding. Warned on every translated request \
              it affects (one drop path, `codec::drops`), and recorded in the audit log as \
              `egress.control_unrepresentable` naming the wire path.",
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
    severity: Severity::Actionable,
    summary:
        "Response-side provider metadata (a vendor guardrail `trace`, a vendor `safetyRatings`) \
              was dropped on the cross-protocol seam because it is a vendor-scoped artifact the \
              caller's protocol has no shape to receive. Warned on every translated response it \
              affects (one drop path, `codec::drops`), naming the wire path.",
    action: "None — self-heals. If this metadata is compliance evidence, route the request to a \
             same-protocol lane where the upstream body reaches the client verbatim.",
    since: "1.6.0",
    retired: false,
};

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
    action: "None — self-heals per request. If it recurs for legitimately large replies, raise \
             the translated-body cap (`limits`) so those replies translate.",
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
/// Every code this plane defines, in catalog order, for the composition root's
/// diagnostics fold (`register_diagnostics`).
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
    &USAGE_TAP_REASSEMBLY_CAP_EXCEEDED,
    &UPSTREAM_MIDSTREAM_TRANSPORT_ERROR,
    &UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR,
    &LANE_BREAKER_TRIPPED,
    &CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED,
    &CROSSPROTO_TRANSLATION_CAP_EXCEEDED,
    &CROSSPROTO_BINARY_CODEC_FAILED,
    &CROSSPROTO_JSON_CODEC_FAILED,
    &CROSSPROTO_RESPONSE_NOT_TRANSLATABLE_DEGRADED,
    &CROSSPROTO_RESPONSE_NOT_TRANSLATABLE,
    &REWRITE_GATE_REJECTED,
    &REWRITE_BODY_MATERIALIZE_FAILED,
    &REWRITE_RESERIALIZE_FAILED,
    &ATTEMPT_TIMEOUT_FAILOVER,
    &ATTEMPT_TIMEOUT_DEGRADED,
    &FALLBACK_RESTRICT_NO_ELIGIBLE_LANE,
];

#[cfg(test)]
#[path = "tests/diagnostics_drift_tests.rs"]
mod drift_tests;
