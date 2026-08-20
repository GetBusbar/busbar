# Busbar diagnostics catalog

Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its `diag` field. Find the code below for what it means, whether it needs action, and what to do. This page is generated from the code — do not edit by hand.

Codes are grouped by class (the thousands digit).

## 1xxx — Durability & write-through

<a id="durable-writethrough-below-floor"></a>
### BUSBAR-1001 — Durable audit write-through skipped (seq at or below the recovered floor)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `durable-writethrough-below-floor`

An audit entry's sequence number is at or below the recovered durable floor, so it is already persisted under that seq and the write-through is correctly skipped — the entry is retained in the in-memory ring. A single occurrence at boot is expected after a durable-store restore.

**What to do:** None — self-healing. If it warns repeatedly for DIFFERENT sequence numbers, suspect a second node writing the same durable store (see BUSBAR-1002).

<a id="durable-second-writer-detach"></a>
### BUSBAR-1002 — Durable audit log has another writer — this node detached its durable sink

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-second-writer-detach`

The durable audit store's tail is ahead of what this node last persisted, which can only mean a second busbar is writing the same store. The durable audit log supports exactly ONE writer; two nodes overwrite each other's entries and break the hash chain, which the next boot reports as tampering. This node has detached its durable sink and now audits only to its ephemeral in-memory ring.

**What to do:** Ensure exactly one busbar instance is pointed at this durable audit store. Give the other instance its own store, then restart this node to re-attach a durable sink.

<a id="durable-audit-ring-unreconciled"></a>
### BUSBAR-1003 — Durable audit write-through held — ring not yet reconciled with the durable tail

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-ring-unreconciled`

This process's in-memory audit ring is not yet reconciled with the durable tail (the boot restore did not read or verify it, and a retry read is still failing), so the write-through is held rather than risk overwriting durable history. The entry is retained in the RAM ring and will backfill once the store answers with a verifiable tail.

**What to do:** Check the durable audit store is reachable and returns a verifiable tail. This clears itself once a tail read succeeds (logged as recovery at info level).

<a id="durable-audit-writethrough-failed"></a>
### BUSBAR-1004 — Durable audit write-through failed (entry retained in the in-memory ring)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-writethrough-failed`

Appending an audit entry to the durable store failed — typically a durable-store outage. The entry is retained in the in-memory ring and the state snapshot and will backfill on the next successful write-through, so nothing is lost from the ring.

**What to do:** Investigate the durable audit store outage. No entries are lost from the in-memory ring; they persist once the store recovers and the next mutation backfills them.

<a id="durable-audit-backfill-gap"></a>
### BUSBAR-1005 — Durable audit chain has an unrepairable gap (a seq was pruned before it persisted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-backfill-gap`

A durable-chain sequence number is no longer in the in-memory ring (it was pruned during a store outage longer than the ring bound), so it can never be backfilled in-process. The durable chain therefore has an unrepairable gap at that seq and catch-up stops below the hole. This is real durable-audit data loss for that seq.

**What to do:** Recent entries remain in the in-memory ring, but the DURABLE log has a permanent gap at the named seq. Resolve the store outage that caused it; restore the durable store from a backup if the durable chain's completeness is required for compliance.

## 5xxx — Proxy & routing

<a id="usage-tap-reassembly-cap-exceeded"></a>
### BUSBAR-5001 — Same-protocol non-stream body exceeded the usage-tap reassembly cap (tail retained)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `usage-tap-reassembly-cap-exceeded`

A same-protocol non-streaming JSON response body grew past the usage-tap reassembly cap, so busbar dropped the oldest bytes and retained only the TAIL (where every dialect's `usage` object sits) to still bill the request. The client receives the body verbatim regardless; only the internal billing copy is truncated.

**What to do:** None — self-heals; the trailing usage object still bills correctly for a recognized dialect. If BILLING_TRUNCATED_TOTAL climbs steadily, some upstream is returning unusually large bodies whose usage may undercount for an unrecognized dialect.

<a id="upstream-midstream-transport-error"></a>
### BUSBAR-5002 — Mid-stream upstream transport error (generic interruption returned to the client)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `upstream-midstream-transport-error`

An upstream transport error occurred AFTER the first byte of a streaming response was already sent to the client. busbar returns a generic, vendor-neutral interruption frame in the client's ingress protocol rather than leaking the raw transport error, and records a compensating breaker transient.

**What to do:** None — self-heals per request; the circuit breaker already tracks the upstream fault. A sustained rate indicates a flaky upstream lane worth investigating via breaker telemetry.

<a id="upstream-prefirstbyte-transport-error"></a>
### BUSBAR-5003 — Pre-first-byte upstream transport error (body stream terminated generically)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `upstream-prefirstbyte-transport-error`

An upstream transport error occurred BEFORE the first byte of a streaming response arrived. busbar terminates the body stream with a generic message, refunds the request budget unit, and records a compensating breaker transient so the failed attempt counts against the lane.

**What to do:** None — self-heals; failover and the breaker handle it. Persistent occurrence on one lane points to an unhealthy upstream endpoint.

<a id="lane-breaker-tripped"></a>
### BUSBAR-5004 — Lane circuit breaker tripped (Closed→Open)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `lane-breaker-tripped`

A circuit breaker for a (pool, lane) transitioned Closed→Open after accumulated failures crossed its threshold, so busbar stops sending traffic to that lane until the breaker's cooldown lets it probe for recovery. Emitted once per logical trip.

**What to do:** Traffic fails over to healthy lanes automatically. If a lane trips repeatedly, investigate that upstream's health, credentials, or rate limits.

<a id="routing-policy-failed-on-error-fallback"></a>
### BUSBAR-5005 — Routing policy failed; on_error fallback applied

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `routing-policy-failed-on-error-fallback`

A routing-policy hook returned an ERROR while deciding a request, so busbar applied the pool's configured `on_error` fallback. A hook binary that is down, crashing, or returning garbage degrades every request in the pool to the fallback. Warned once per fault window; continued failures log at debug.

**What to do:** Fix the routing-policy hook — check that its process is running, reachable, and returning a valid decision. The pool serves via `on_error` until it recovers.

<a id="routing-policy-deadline-exceeded"></a>
### BUSBAR-5006 — Routing policy deadline exceeded; on_error fallback applied

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `routing-policy-deadline-exceeded`

A routing-policy hook did not answer within the seam's hard wall-clock deadline, so busbar applied the pool's `on_error` fallback. A slow hook adds latency to every request in the pool. Warned once per fault window; continued timeouts log at debug.

**What to do:** Investigate why the routing-policy hook is slow (overload, blocking I/O, an undersized deadline). Tune the hook or raise its configured timeout if the latency is legitimate.

<a id="on-error-fallback-answered"></a>
### BUSBAR-5007 — on_error fallback hook answered for the failed gate

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `on-error-fallback-answered`

After a routing gate failed, one of its configured `on_error` fallback hooks answered and decided the request. This is a RECOVERY signal: the fallback chain did its job.

**What to do:** None — informational. The paired gate-failure diagnostic (BUSBAR-5005/5006) names the primary hook to fix.

<a id="on-error-fallback-hook-failed"></a>
### BUSBAR-5008 — on_error fallback hook failed; continuing down the chain

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `on-error-fallback-hook-failed`

An `on_error` fallback hook itself returned an error, so busbar continued down the fallback chain to the next link (or the reserved terminal). The fallback chain meant to cover a broken primary is itself partly broken. Warned once per fault window.

**What to do:** Fix the failing fallback hook. The request is still served by a later chain link or the terminal policy, but the chain has less depth than configured.

<a id="on-error-fallback-deadline-exceeded"></a>
### BUSBAR-5009 — on_error fallback hook deadline exceeded; continuing down the chain

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `on-error-fallback-deadline-exceeded`

An `on_error` fallback hook exceeded its deadline, so busbar continued down the fallback chain. Warned once per fault window; continued timeouts log at debug.

**What to do:** Investigate why the fallback hook is slow, or raise its timeout if the latency is expected. The chain still resolves via a later link or the terminal policy.

<a id="crossproto-nonstream-midtransfer-failed"></a>
### BUSBAR-5010 — Cross-protocol non-stream upstream body failed mid-transfer

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-nonstream-midtransfer-failed`

On a cross-protocol non-streaming route, the upstream body failed mid-transfer, so busbar did not record success or usage, refunded the request budget, records a compensating breaker transient, and returns an ingress-native error.

**What to do:** None — self-heals; the breaker compensates. A sustained rate indicates a flaky upstream lane.

<a id="crossproto-translation-cap-exceeded"></a>
### BUSBAR-5011 — Cross-protocol non-stream success body exceeded the translation cap

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-translation-cap-exceeded`

A cross-protocol non-streaming success body exceeded busbar's translation cap, so it cannot be translated into the client's protocol and the client receives a 500 with no completion. This is busbar's OWN cap, not an upstream fault, so tokens are not charged and the breaker success stands.

**What to do:** None — self-heals per request. If it recurs for legitimate large responses, raise the translated-body cap (`limits`) so those responses translate.

<a id="crossproto-binary-codec-failed"></a>
### BUSBAR-5012 — Cross-protocol binary response failed the egress codec (read_response)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-binary-codec-failed`

A binary/opaque cross-protocol upstream response could not be decoded by the egress codec's `read_response`, so busbar returns an ingress-native 500 rather than leaking the upstream's native body. Often a broken or renamed upstream response field.

**What to do:** None — self-heals per request. If it recurs for one upstream, the provider may have changed its response shape; check for a busbar update covering that dialect.

<a id="crossproto-json-codec-failed"></a>
### BUSBAR-5013 — Cross-protocol JSON response failed the egress codec (read_response_value)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-json-codec-failed`

A JSON 2xx cross-protocol upstream response was rejected by the egress codec's `read_response_value` (e.g. a missing expected field), so busbar returns an ingress-native 500 instead of leaking the upstream body. Same root-cause family as BUSBAR-5012.

**What to do:** None — self-heals per request. Recurrence for one upstream suggests a changed or renamed response field; check for a busbar update.

<a id="crossproto-response-not-translatable-degraded"></a>
### BUSBAR-5014 — Degraded cross-protocol response not translatable (ingress-native error returned)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-response-not-translatable-degraded`

On the degraded path, a cross-protocol upstream response could not be translated into the client's protocol, so busbar returns an ingress-native error rather than leaking the upstream's native wire format to a different-protocol client. This is a deliberate refusal to relay a foreign-format body, not a busbar fault.

**What to do:** None — self-heals per request; returning the native error is the correct, safe behavior.

<a id="crossproto-response-not-translatable"></a>
### BUSBAR-5015 — Cross-protocol response not translatable (ingress-native error returned)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-response-not-translatable`

A cross-protocol upstream response could not be translated into the client's protocol, so busbar returns an ingress-native error instead of leaking the upstream's native body to a different-protocol client. This is normal, safe operation — an open-relay refusal — not a fault.

**What to do:** None — self-heals per request; refusing to relay an untranslatable foreign body is the intended behavior.

<a id="rewrite-gate-rejected"></a>
### BUSBAR-5016 — Rewrite gate rejected the request

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `rewrite-gate-rejected`

A rewrite-gate hook rejected the request, so busbar returns the hook's clamped status and sanitized message in the client's native envelope. This is normal policy enforcement, not an error.

**What to do:** None — self-heals per request. The ROUTE_POLICY counters carry the volume; a client seeing rejections should adjust its request to satisfy the policy.

<a id="rewrite-body-materialize-failed"></a>
### BUSBAR-5017 — Materializing the validated request body for the rewrite pass failed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `rewrite-body-materialize-failed`

busbar could not materialize the validated request body into a DOM for the rewrite pass, so it fails CLOSED and rejects the request rather than forwarding it un-rewritten. Unreachable in practice (the bytes already validated), but operator-visible if it ever fires.

**What to do:** Investigate — this indicates a serious internal inconsistency (validated bytes that no longer parse). Capture the request context and file a bug; the request was safely rejected, not mis-forwarded.

<a id="rewrite-reserialize-failed"></a>
### BUSBAR-5018 — Re-serializing a committed rewrite failed (request rejected to protect the invariant)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `rewrite-reserialize-failed`

A committed request rewrite could not be re-serialized into the retained bytes, so busbar rejects the request rather than risk a failover hop forwarding the ORIGINAL un-rewritten body. Protects the rewrite invariant (fail-closed) across failover. Not realistically reachable.

**What to do:** Investigate the rewrite hook and request that triggered it; a rewrite that produces an unserializable body is a bug. The request was safely rejected, never forwarded un-rewritten.

<a id="decision-gate-rejected"></a>
### BUSBAR-5019 — Decision gate rejected the request

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `decision-gate-rejected`

A decision-gate hook rejected the request; busbar returns the gate's clamped status and sanitized message in the client's native envelope. Normal policy enforcement.

**What to do:** None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.

<a id="decision-gate-restrict-weighted-escape"></a>
### BUSBAR-5020 — Decision gate restrict left no eligible lane; on_empty: weighted escape

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `decision-gate-restrict-weighted-escape`

A decision gate's restrict left no eligible lane, and its `on_empty` policy is `weighted`, so busbar skips that restriction and falls back to weighted selection across the full pool. Normal advisory-restrict behavior.

**What to do:** None — self-heals per request. If the restriction should be enforced strictly, set its `on_empty` to reject.

<a id="decision-gate-restrict-reject"></a>
### BUSBAR-5021 — Decision gate restrict left no eligible lane (on_empty: reject)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `decision-gate-restrict-reject`

A decision gate's restrict left no eligible lane and its `on_empty` policy is reject (fail-closed), so busbar rejects the request rather than route to an ineligible lane. This is the correct compliance behavior.

**What to do:** None — self-heals per request; the counters carry the volume. If rejections are unexpected, review the pool membership tags against the restrict's required tags.

<a id="routing-policy-rejected"></a>
### BUSBAR-5022 — Routing policy rejected the request

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `routing-policy-rejected`

A routing-policy hook rejected the request; busbar returns the policy's clamped status and sanitized message in the client's native envelope. Normal policy enforcement.

**What to do:** None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.

<a id="routing-policy-restrict-weighted-escape"></a>
### BUSBAR-5023 — Routing policy restrict left no eligible lane; on_empty: weighted escape

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `routing-policy-restrict-weighted-escape`

A routing policy's restrict left no eligible lane and its `on_empty` is `weighted`, so busbar escapes to full-pool weighted selection. Normal advisory-restrict behavior.

**What to do:** None — self-heals per request. Set `on_empty` to reject if the restriction must be enforced strictly.

<a id="routing-policy-restrict-reject"></a>
### BUSBAR-5024 — Routing policy restrict left no eligible lane (on_empty: reject)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `routing-policy-restrict-reject`

A routing policy's restrict left no eligible lane and its `on_empty` is reject (fail-closed), so busbar rejects the request rather than route to an ineligible upstream. Correct compliance behavior.

**What to do:** None — self-heals per request. If unexpected, review pool membership tags against the restrict's required tags.

<a id="attempt-timeout-failover"></a>
### BUSBAR-5025 — No response headers within the attempt cap; failing over

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `attempt-timeout-failover`

An upstream attempt returned no response headers within its per-attempt time-to-headers cap, so busbar fails over to the next candidate lane. Expected under a slow lane; failover is normal operation.

**What to do:** None — self-heals via failover; telemetry counters carry the volume. If one lane times out constantly, investigate its latency or raise its `attempt_timeout_ms`.

<a id="lane-hard-down"></a>
### BUSBAR-5026 — Lane hard-down (breaker trip)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `lane-hard-down`

A lane's circuit breaker is hard-down (tripped) and this is the FRESH logical trip, so busbar fails over and stops routing to the lane until its cooldown allows a recovery probe. Recurring still-down probes log at debug. Emitted once per logical trip.

**What to do:** Traffic fails over automatically. Investigate the named upstream's health if a lane stays hard-down.

<a id="usage-tap-unknown-protocol"></a>
### BUSBAR-5027 — Usage tap: unknown ingress protocol for a same-protocol 2xx body

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `usage-tap-unknown-protocol`

The usage tap could not recognize the ingress protocol of a same-protocol 2xx body, so it bills 0 tokens for the request. Warned once per (protocol, reason); BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.

**What to do:** None if the protocol is genuinely unmetered. If a metered dialect is billing 0 tokens, the protocol name is unexpected — check the route configuration and for a busbar update covering it.

<a id="usage-tap-bad-json"></a>
### BUSBAR-5028 — Usage tap: failed to parse a same-protocol 2xx body as JSON

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `usage-tap-bad-json`

The usage tap could not parse a same-protocol 2xx body as JSON, so it bills 0 tokens for the request. Warned once per (protocol, reason); the raw body is never logged (it may carry secrets). BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.

**What to do:** None — self-heals per request. Sustained occurrence for one upstream means it is returning non-JSON 2xx bodies busbar cannot meter; investigate that upstream.

<a id="usage-tap-decode-failed"></a>
### BUSBAR-5029 — Usage tap: read_response failed to decode a same-protocol 2xx body

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `usage-tap-decode-failed`

The usage tap's `read_response` could not decode a same-protocol 2xx body into the IR, so it bills 0 tokens for the request. Warned once per (protocol, reason); BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.

**What to do:** None — self-heals per request. If a metered dialect bills 0 tokens repeatedly, the upstream's response shape may have changed; check for a busbar update covering it.

<a id="attempt-timeout-degraded"></a>
### BUSBAR-5030 — No response headers within the attempt cap (degraded path)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `attempt-timeout-degraded`

On the degraded routing path, an upstream attempt returned no response headers within its per-attempt cap, so busbar records a breaker transient and tries the next degraded candidate. Degraded-path sibling of BUSBAR-5025.

**What to do:** None — self-heals via the degraded candidate walk; telemetry counters carry the volume.

<a id="fallback-restrict-no-eligible-lane"></a>
### BUSBAR-5031 — Compliance restrict left no eligible lane in the fallback pool (fail closed)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `fallback-restrict-no-eligible-lane`

A compliance restrict re-applied against a fallback pool left no eligible lane, so busbar fails closed (503) rather than spill to an ineligible upstream. Fail-closed is the correct behavior for a compliance restriction.

**What to do:** None — self-heals per request. If the fallback pool should serve this traffic, ensure its members carry the tags the restrict requires.

<a id="prometheus-recorder-install-failed"></a>
### BUSBAR-5032 — Prometheus recorder install failed; /metrics will be empty

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `prometheus-recorder-install-failed`

The Prometheus metrics recorder failed to install at boot, so the /metrics endpoint will be empty for the life of the process. busbar continues serving proxy traffic, but is blind to metrics.

**What to do:** Investigate the boot error (often a duplicate recorder install or a conflicting exporter). Restart busbar after resolving it; /metrics stays empty until then.

<a id="metrics-maintenance-thread-spawn-failed"></a>
### BUSBAR-5033 — Could not spawn the metrics maintenance thread (observations drain on scrape only)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `metrics-maintenance-thread-spawn-failed`

busbar could not spawn the metrics maintenance (drain) thread at boot, so buffered metric observations now drain only when /metrics is scraped instead of on a timer. Metrics are still correct but may lag between scrapes.

**What to do:** Investigate the thread-spawn failure (typically OS thread/resource exhaustion). Metrics remain available on scrape; restart after resolving the resource limit for timely draining.

<a id="metrics-scrape-list-keys-failed"></a>
### BUSBAR-5034 — Metrics scrape: failed to list virtual keys (per-key gauges skipped)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `metrics-scrape-list-keys-failed`

A /metrics scrape could not list virtual keys from the governance store (a transient store hiccup), so it skips the per-key spend/token gauges for this scrape. Other gauges still refresh.

**What to do:** None — self-heals on the next scrape once the store responds. Sustained failures indicate a governance-store problem worth investigating.

<a id="metrics-key-gauge-limit-exceeded"></a>
### BUSBAR-5035 — Metrics scrape: virtual-key count exceeds the per-key gauge limit (truncating)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `metrics-key-gauge-limit-exceeded`

The number of virtual keys exceeds the per-key gauge limit (`metrics.key_gauge_limit`), so busbar emits gauges for only the first `limit` keys to bound Prometheus cardinality and scrape-path DB load. Some keys have no per-key series. Warned once until the count drops back under the limit.

**What to do:** Raise `metrics.key_gauge_limit` if you need per-key series for all keys and can afford the cardinality, or reduce the number of active virtual keys. Aggregate group gauges are unaffected.

<a id="metrics-scrape-key-usage-read-failed"></a>
### BUSBAR-5036 — Metrics scrape: usage read failed; skipping key

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `metrics-scrape-key-usage-read-failed`

During a /metrics scrape, reading one virtual key's usage from the store failed, so busbar skips that key's gauges for this scrape and continues with the rest. Per-key, per-scrape.

**What to do:** None — self-heals on the next scrape. A high volume across keys points to a governance-store problem.

<a id="metrics-scrape-group-ledger-read-failed"></a>
### BUSBAR-5037 — Metrics scrape: group ledger read failed; skipping bucket

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `metrics-scrape-group-ledger-read-failed`

During a /metrics scrape, reading a group budget bucket's ledger from the store failed, so busbar skips that bucket's gauges for this scrape and continues. Per-bucket, per-scrape.

**What to do:** None — self-heals on the next scrape. Sustained failures indicate a governance-store problem.

