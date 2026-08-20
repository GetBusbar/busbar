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

## 4xxx — Auth & identity

<a id="token-exchange-mint-failed"></a>
### BUSBAR-4001 — Token-exchange could not mint a self-serve key

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `token-exchange-mint-failed`

An authenticated, authorized token-exchange request could not be completed because minting the self-serve key failed inside busbar (a keystore write or HMAC/signing fault), so the caller receives a 500. The identity was valid; the failure is on busbar's side, not the client's.

**What to do:** Investigate the keystore / signing subsystem — check disk, permissions, and the key-derivation secret. The condition is rare; capture the logged detail and file a bug if it recurs.

<a id="login-offload-saturated"></a>
### BUSBAR-4002 — Login plugin offload saturated (permit not acquired; login rejected fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `login-offload-saturated`

A login-plugin call could not obtain a blocking-offload permit within the wait window because the offload budget is fully in flight — a login plugin is wedged and not returning. busbar rejects the login fail-closed rather than complete a login it never ran. Warned once on entry to the saturated state; recurrence logs at debug.

**What to do:** Investigate the login plugin (LDAP/AD bind, an OIDC token/userinfo round-trip) — it is blocking past its timeout. Restore or restart it; the saturation clears once calls return within budget.

<a id="login-plugin-panicked"></a>
### BUSBAR-4003 — Login plugin call panicked (login rejected fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `login-plugin-panicked`

A login plugin's blocking call panicked (the offloaded task returned a join error), so busbar rejects the login fail-closed rather than complete a login it never verified. A panicking plugin is a plugin bug.

**What to do:** Fix the login plugin — a panic on the login path is a bug in that plugin. Capture the logged method/op context and the plugin's own logs; logins via that method fail until it is corrected.

<a id="auth-chain-open-relay"></a>
### BUSBAR-4004 — auth.chain is empty (open relay)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `auth-chain-open-relay`

The auth chain was built with no verifiers and no keys-in-chain, so every data-plane request is admitted unauthenticated — an OPEN RELAY. This is acceptable only for local development. Emitted once when the chain is built.

**What to do:** Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing busbar to any untrusted network. An open relay in production forwards anyone's traffic on your upstream credentials.

<a id="auth-offload-saturated"></a>
### BUSBAR-4005 — Auth chain offload saturated (permit not acquired; request denied fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `auth-offload-saturated`

The auth chain could not obtain a blocking-offload permit within the wait window because the offload budget is fully in flight — an auth plugin is wedged and not returning. The chain never ran, so the credential is unverified and busbar denies fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.

**What to do:** Investigate the auth plugin — it is blocking past its timeout and starving the offload budget. Restore or restart it; the saturation clears once chain calls return within budget.

<a id="auth-chain-panicked"></a>
### BUSBAR-4006 — Auth chain panicked (request denied fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `auth-chain-panicked`

The auth chain's blocking task panicked, so busbar denies the request fail-closed rather than admit an unverified credential. A panicking chain is a plugin bug. Warned once on entry to the panicking state; recurrence logs at debug.

**What to do:** Fix the auth plugin — a panic in the chain is a bug in one of its modules. Capture the logged error and the plugin's own logs; requests are denied until it is corrected.

<a id="admin-module-unresolved"></a>
### BUSBAR-4007 — admin_auth names a module with no resolved plugin

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-module-unresolved`

The admin auth chain named a module that has no resolved plugin, and busbar skipped it fail-closed. This is supposed to be impossible after a successful boot — `AdminAuthChain::build` fails closed on any unresolvable name — so reaching it means the admin-module table drifted from the configured chain.

**What to do:** Investigate the admin auth configuration and plugin load state; a named admin module is missing at runtime. Restart busbar so boot re-resolves the chain, and file a bug with the logged module name if it persists.

<a id="admin-offload-saturated"></a>
### BUSBAR-4008 — Admin auth offload saturated (permit not acquired; request denied fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-offload-saturated`

The admin auth chain could not obtain a blocking-offload permit within the wait window because the admin offload budget is fully in flight — an admin auth plugin is wedged and not returning. The chain never ran, so busbar denies fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.

**What to do:** Investigate the admin auth plugin — it is blocking past its timeout. Restore or restart it; admin access is denied until admin-chain calls return within budget.

<a id="admin-chain-stalled"></a>
### BUSBAR-4009 — Admin auth chain did not complete in time (request denied fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-chain-stalled`

The admin auth chain's offloaded task did not complete within its deadline, or it panicked, so busbar denies the admin request fail-closed rather than admit an unverified operator. Warned once on entry to the stalled state; recurrence logs at debug.

**What to do:** Investigate the admin auth plugin — it is slow or crashing on the admin path. Restore or restart it; admin access is denied until the chain completes within its deadline.

<a id="admin-forbidden-suppressed"></a>
### BUSBAR-4010 — Admin request forbidden (audit record suppressed this window)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `admin-forbidden-suppressed`

An admin request was forbidden (insufficient scope for the path), and a durable audit record for it was suppressed because one was already written for this principal in the current rate window. This is a per-request signal of a CLIENT-side authorization failure, not an operator problem, so it is emitted at debug to avoid log spam under a client that keeps retrying a forbidden call.

**What to do:** None — self-heals; the client is being correctly refused. Persistent volume from one principal indicates a misconfigured client or a probe; the durable audit chain already carries the first occurrence per window.

<a id="keys-in-chain-passthrough-conflict"></a>
### BUSBAR-4011 — auth.chain names `keys` alongside upstream_credentials: passthrough

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `keys-in-chain-passthrough-conflict`

The auth chain names the `keys` verifier while `upstream_credentials` is set to `passthrough`. keys-in-chain requires a valid virtual key on every request and supersedes passthrough's accept-and-forward-the-caller-credential intent, so passthrough never takes effect. Warned once at first request.

**What to do:** Resolve the config conflict: use `upstream_credentials: own` (or omit it) alongside `keys`, or drop `keys` from the chain if you genuinely want to forward caller credentials. The two settings are mutually exclusive.

<a id="self-subject-unsafe"></a>
### BUSBAR-4012 — Token-exchange refused an unsafe self-serve subject

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `self-subject-unsafe`

A token-exchange request presented a principal id that is unsafe as a self-serve subject — empty, containing a '/' route separator or a control character, or carrying a reserved `vk_`/`user:`/`group:` prefix — so busbar refused it with a 403. This is a CLIENT-supplied bad value, not an operator problem, so it is emitted at debug to avoid spam from a misbehaving client.

**What to do:** None — self-heals; the client must present a valid subject id. If a legitimate identity is being rejected, its id needs to be reshaped to avoid the reserved prefixes and separators.

<a id="egress-apikey-invalid-bytes"></a>
### BUSBAR-4013 — Egress API key contains invalid header bytes (auth header omitted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `egress-apikey-invalid-bytes`

A configured egress credential (a static `api-key`/`x-goog-api-key`) contains bytes that are invalid in an HTTP header value (typically an ASCII control character), so busbar omits the auth header entirely and the upstream will reject with 401. The credential is misconfigured.

**What to do:** Fix the configured egress credential — remove stray whitespace/control characters (often a trailing newline from how the secret was pasted or injected). Requests to that upstream 401 until the key is a valid header value.

<a id="egress-oauth-token-invalid-bytes"></a>
### BUSBAR-4014 — Minted OAuth token contains invalid header bytes (auth header omitted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `egress-oauth-token-invalid-bytes`

An OAuth token minted for egress contains bytes invalid in an HTTP header value, so busbar omits the `Bearer` auth header and the upstream will reject with 401. Fires on mint (per refresh), not per request, and is near-unreachable for a well-formed token endpoint.

**What to do:** Investigate the OAuth token endpoint — it returned an access token with control or non-ASCII bytes. Requests to that upstream 401 until it mints a header-safe token.

<a id="egress-oauth-empty-token"></a>
### BUSBAR-4015 — OAuth token endpoint returned a 200 with an empty access_token

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `egress-oauth-empty-token`

The upstream OAuth token endpoint answered 200 but with an EMPTY access_token. busbar treats it as a (retryable) mint failure rather than storing it, because an empty token collides with the pre-first-mint sentinel and would wedge the lane permanently. It retries on the refresh cadence.

**What to do:** Investigate the OAuth token endpoint / client-credentials configuration — a 200 with no token usually means a misconfigured client, scope, or audience. Egress to that upstream 401s until a non-empty token is minted.

<a id="egress-oauth-mint-failed"></a>
### BUSBAR-4016 — OAuth token mint (refresh) failed; retrying

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `egress-oauth-mint-failed`

The background OAuth token refresh failed to mint a new token. busbar keeps serving the current token and retries soon; if retries keep failing past expiry, egress requests carry a stale/empty token and the upstream 401s. Fires on the refresh cadence, not per request.

**What to do:** Investigate the OAuth token endpoint — a transient outage self-heals on the next retry; sustained failures mean a credential/endpoint/network problem that will 401 egress once the current token expires.

<a id="trust-sweep-not-attempted"></a>
### BUSBAR-4017 — Scheduled trust sweep could not be attempted (registration not contacted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-sweep-not-attempted`

A scheduled trust sweep could not even be ATTEMPTED for a registration (a local precondition failed before any contact), so the upstream was not contacted and its trust state is unchanged. The registration is not re-verified this tick.

**What to do:** Investigate the logged reason for the named subject — typically a local resource or config problem preventing the sweep from starting. Trust state is preserved, not demoted; resolve the cause so the registration is re-verified on schedule.

<a id="trust-sweep-contact-failed"></a>
### BUSBAR-4018 — Scheduled trust sweep could not authenticate the upstream (failed contact recorded)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-sweep-contact-failed`

A scheduled trust sweep reached the upstream but could not authenticate it, so busbar records a failed contact against the registration. Repeated failed contacts feed the anomaly breaker toward suspension (see BUSBAR-4021).

**What to do:** Investigate the named upstream's reachability and credentials for the logged subject. A transient failure is recorded and self-heals on a later clean sweep; persistent failures will suspend the registration.

<a id="trust-upstream-drifted"></a>
### BUSBAR-4019 — Upstream drifted from the approved pin (registration demoted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-upstream-drifted`

A scheduled trust sweep found the upstream DRIFTED from its approved pin — something changed underneath a standing approval — so busbar demoted the registration and it stops serving until an operator re-approves. This is the headline trust diagnostic: the operator's first notice that a pinned upstream changed.

**What to do:** Review the logged drift (pin change, added/removed/changed attributes) for the named subject. If the change is expected, re-approve the registration to restore service; if not, treat it as a potential compromise of that upstream.

<a id="trust-recovery-held"></a>
### BUSBAR-4020 — Clean trust observation held (recovery backoff not yet elapsed)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `trust-recovery-held`

A scheduled trust sweep made a clean observation, but the recovery backoff since the last drift has not yet elapsed, so the observation is not yet believed and the registration stays demoted for now. This is the expected self-healing backoff, so it is emitted at debug.

**What to do:** None — self-heals. The registration recovers automatically once enough consecutive clean observations accumulate past the recovery backoff.

<a id="trust-registration-suspended"></a>
### BUSBAR-4021 — Anomaly breaker suspended a trust registration

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-registration-suspended`

The trust anomaly breaker suspended a registration — accumulated failed contacts or drift crossed its threshold — so the registration stops serving until the condition clears or an operator intervenes. A transition event, emitted once per suspension.

**What to do:** Investigate the named subject's upstream (see the preceding contact-failure or drift diagnostics for the cause). Resolve the underlying fault; the registration recovers or requires re-approval depending on why it was suspended.

<a id="trust-sweep-panicked"></a>
### BUSBAR-4022 — Scheduled trust sweep panicked (job continues)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-sweep-panicked`

A scheduled trust sweep pass panicked. busbar catches the panic and CONTINUES the sweep job — exiting would turn one bad upstream into a deployment that silently never sweeps again — but that tick's registrations were not all swept. A panicking sweep is a code bug.

**What to do:** Capture the logged plane context and file a bug — a sweep pass should never panic. The job keeps running, but investigate promptly since the panicking tick left some registrations un-swept.

<a id="oauth-as-sweep-failed"></a>
### BUSBAR-4023 — oauth_as expired-record sweep failed (retrying next tick)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `oauth-as-sweep-failed`

The oauth_as authorization-server sweep of expired records failed for a tick — typically a transient store hiccup — so busbar retries on the next tick. Expired records simply linger until a sweep succeeds. Warned once on entry to the failing state; recurrence logs at debug so a persistent store problem cannot spam.

**What to do:** None if it clears on the next tick. Sustained failures indicate an oauth_as store problem worth investigating; expired records accumulate until a sweep succeeds.

<a id="sigv4-hmac-init-failed"></a>
### BUSBAR-4024 — SigV4 HMAC-SHA256 init failed (documented unreachable)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `sigv4-hmac-init-failed`

Initializing HMAC-SHA256 for AWS SigV4 signing failed. This is documented as unreachable — HMAC-SHA256 accepts a key of any length — so reaching it indicates a serious crypto-library inconsistency. busbar returns an empty signature, which the upstream rejects.

**What to do:** Capture the logged error and file a bug; this should not be possible. SigV4-signed egress (e.g. Bedrock) fails to authenticate until it is resolved.

<a id="oauth-as-ephemeral-signing-key"></a>
### BUSBAR-4025 — oauth_as generated an ephemeral ES256 signing key (tokens die on restart)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `oauth-as-ephemeral-signing-key`

The oauth_as authorization server has no `signing_key` configured, so busbar generated an EPHEMERAL ES256 key at boot. Every token this deployment issues is signed with that in-memory key and stops verifying the moment the process restarts, because a new key is generated on the next boot. Acceptable only for a trial or local development.

**What to do:** Set `oauth_as.signing_key` to a durable key reference before relying on issued tokens across restarts. Until then, every restart invalidates all outstanding oauth_as tokens.

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

## 6xxx — Plugins

<a id="plugins-fetch-reload-miss"></a>
### BUSBAR-6001 — plugins.fetch missed on reload (keeping the current artifact)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plugins-fetch-reload-miss`

During a reload, fetching a pinned plugin artifact missed (the source did not return a usable download for the pinned spec), so busbar kept the artifact already on disk and continued the reload. The running plugin is unchanged; the intended refresh did not land.

**What to do:** Check the plugin source (registry/URL) and the pinned spec for the named artifact — a transient fetch miss self-heals on the next reload, a persistent one means the pin no longer resolves. busbar keeps serving the current artifact until a fetch succeeds.

## 8xxx — Governance & cost

<a id="revocation-resync-outstanding"></a>
### BUSBAR-8001 — Revocation denylist re-sync still outstanding from an earlier window

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `revocation-resync-outstanding`

A revocation-denylist re-sync launched in an earlier window has not returned — the governance store has not answered for at least a full sync window — so busbar keeps serving the last-known revocations and does not start a second overlapping read. A peer's revoke may not be visible on this node until the store recovers. The CAS bound rate-limits this warning to once per window.

**What to do:** Investigate the governance store's health and latency. Revocations already known stay enforced (fail-closed); the risk is a NEW revoke made elsewhere not yet reaching this node. Re-sync resumes automatically once the store answers.

<a id="revocation-resync-failed"></a>
### BUSBAR-8002 — Revocation denylist re-sync failed (keeping the previously-known revocations)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `revocation-resync-failed`

A revocation-denylist re-sync read from the governance store returned an error, so busbar keeps the previously-known revocations in place (fail-closed: a store blip never widens access) and leaves the set marked stale so the next window retries. A peer's revoke may not be visible on this node until a later sync succeeds.

**What to do:** Investigate the governance store — a transient error self-heals on the next window's retry; sustained failures mean the store is unreachable and cross-node revocations are not propagating.

<a id="governance-key-reserved-namespace-collision"></a>
### BUSBAR-8003 — Refused to synthesize a governance key (principal id collides with a reserved namespace)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `governance-key-reserved-namespace-collision`

A principal id (attacker-influenceable at the IdP) starts with a reserved ledger-bucket prefix (`group:` or `vk_`), which would alias a group's or a real virtual key's ledger and rate bucket. busbar fails closed and synthesizes NO key for that principal rather than mint a colliding bucket. This is a per-request, caller-side signal, not an operator problem, so it is emitted at debug.

**What to do:** None — self-heals; the principal is correctly refused data-plane access. If a legitimate identity is being rejected, its IdP subject must be reshaped to avoid the reserved `group:` and `vk_` prefixes.

<a id="limit-window-unrecognized"></a>
### BUSBAR-8004 — Unrecognized limit window (enforcing as all-time 'total')

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `limit-window-unrecognized`

A limit's window word was not recognized — it can only arise from a corrupt or foreign store row, since config parse rejects unknown windows. busbar fails SAFE and enforces the limit as the all-time ('total') window, the tightest enforcement, never wider, and surfaces the value so the corruption is visible instead of silent.

**What to do:** Inspect the governance store row for the named window value — it was written by something other than a validated config load. Enforcement is safe (all-time) in the meantime; correct the row so the intended window applies.

<a id="refresh-self-inconsistent-binding"></a>
### BUSBAR-8005 — Self-serve refresh left an inconsistent binding (tombstone AND rollback both failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `refresh-self-inconsistent-binding`

During a self-serve key refresh, tombstoning the prior binding failed and the compensating rollback of the newly-minted binding ALSO failed, so the subject may now have TWO live bindings in the store for one identity. busbar exhausted its best-effort recovery and surfaces the inconsistent state for inspection. Rare.

**What to do:** Inspect the governance store for the named subject — it may hold two live bindings (old_id and new_id). Tombstone whichever is not intended so the subject has exactly one valid credential.

<a id="refresh-self-cache-refresh-failed"></a>
### BUSBAR-8006 — Self-serve refresh: cache reconcile failed after tombstoning the prior binding

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `refresh-self-cache-refresh-failed`

During a self-serve key refresh, the store tombstone of the prior binding committed but the follow-up cache reconcile (a store round-trip) failed. busbar evicted the prior binding directly from the cache so its old token stops verifying immediately; the store is consistent, but the rest of the cache may be stale until the next successful refresh.

**What to do:** Investigate the governance store's reachability — the durable state is correct and the old credential no longer verifies. The cache self-heals on the next successful reconcile; sustained failures mean the store is unhealthy.

<a id="accrual-group-missing"></a>
### BUSBAR-8007 — Group missing at accrual (tokens ledgered to the key bucket only)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `accrual-group-missing`

A group referenced by a key was gone by the time usage was accrued (the group was deleted between admission and accrual), so busbar degrades to ledgering the tokens on the key's own bucket only rather than lose them. The request was already admitted and served; nothing is lost. This is a per-request, self-degrading path, so it is emitted at debug.

**What to do:** None — self-heals; tokens are preserved on the key bucket. Frequent occurrence for one key means a group is being deleted out from under active keys; reconcile the key's group assignment.

<a id="metering-flush-partial-failure"></a>
### BUSBAR-8008 — Metering flush: some keys failed to persist this tick (retained for retry)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `metering-flush-partial-failure`

A metering flush tick could not persist one or more keys' usage deltas to the store. busbar retains the failed deltas and retries them on the next tick, so no usage is lost. This is already collapsed to ONE aggregate warning per tick (per-key detail is at debug), so it fires at a human cadence, not per key.

**What to do:** Investigate the governance store if the failure count stays non-zero across ticks — a transient store hiccup self-heals on the next flush. Usage is retained and re-tried, so billing is not lost, only delayed.

<a id="delete-key-cache-reconcile-failed"></a>
### BUSBAR-8009 — delete_key: tombstone committed and key evicted, but cache reconcile failed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `delete-key-cache-reconcile-failed`

An admin key deletion committed the tombstone in the store and evicted the deleted key from the in-memory caches (it no longer authenticates), but the follow-up full cache reconcile failed. The deletion is durable and the key is dead; only OTHER cache entries may be stale until the next successful refresh. Rare admin path.

**What to do:** Investigate the governance store's reachability — the deletion itself is complete and safe. The cache self-heals on the next successful refresh; sustained failures indicate an unhealthy store.

<a id="rotate-key-cache-reconcile-failed"></a>
### BUSBAR-8010 — rotate_key: new generation committed, but cache reconcile failed (new secret not returned)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `rotate-key-cache-reconcile-failed`

An admin key rotation committed the new generation in the store — so the PREVIOUS credential is permanently dead — and evicted the key from the caches, but the follow-up cache reconcile failed, so the freshly-minted secret could not be returned to the admin. The rotation IS durable; the new secret is simply lost from this response. Rare admin path.

**What to do:** Re-rotate the key to obtain a fresh secret — the previous credential is already dead and will not come back. Investigate the governance store's reachability, which is why the reconcile failed.

<a id="budget-flush-partial-failure"></a>
### BUSBAR-8011 — Budget flush: some buckets failed to persist this tick (re-marked dirty for retry)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `budget-flush-partial-failure`

A budget flush tick could not persist one or more group-budget buckets to the store. busbar re-marks those buckets dirty and retries them on the next tick, so no spend is lost. This is already collapsed to ONE aggregate warning per tick (per-bucket detail is at debug), so it fires at a human cadence, not per bucket.

**What to do:** Investigate the governance store if the failure count stays non-zero across ticks — a transient store hiccup self-heals on the next flush. Spend is retained and re-tried, so budgets are not lost, only delayed.

<a id="safe-mode-overlay-quarantined"></a>
### BUSBAR-8012 — SAFE MODE: config overlay not merged (running on base config.yaml alone)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `safe-mode-overlay-quarantined`

busbar was booted with `--safe-mode`, so the persisted config overlay (API-registered hooks) was NOT merged and busbar is running on the operator-owned base config.yaml alone. This is the intentional escape hatch for an applied hook that harms traffic and re-applies itself every boot. The overlay file is untouched, not deleted.

**What to do:** This is an operator-requested state. Repair or remove the offending overlay entry, then boot WITHOUT `--safe-mode` to re-apply the overlay. Until then, API-registered hooks are not in effect.

<a id="provider-api-key-unresolved"></a>
### BUSBAR-8013 — Provider api_key did not resolve (degraded to an empty key)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `provider-api-key-unresolved`

A provider's `api_key` secret reference did not resolve at boot, so busbar degraded that provider to an empty key. This is legitimate for keyless local upstreams (ollama/vLLM), but for a real provider it means egress will be unauthenticated and the upstream will reject with 401.

**What to do:** If the provider needs a key, fix its `api_key` secret reference (the secret is missing or the resolver could not read it) and restart. If the upstream is genuinely keyless, no action is needed.

<a id="open-relay-no-auth"></a>
### BUSBAR-8014 — auth.chain is empty — OPEN RELAY (every request admitted unauthenticated)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `open-relay-no-auth`

The auth chain is empty (either explicitly, or because the `auth:` block is absent and serde-defaults to none), so every data-plane request is admitted unauthenticated — an OPEN RELAY forwarding anyone's traffic on your upstream credentials. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr so the state cannot be masked by log configuration. Acceptable only for local development.

**What to do:** Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing busbar to any untrusted network. This is the same open-relay condition as BUSBAR-4004, surfaced at boot.

<a id="store-secret-ref-unresolved"></a>
### BUSBAR-8015 — Store settings hold a secret reference that does not resolve here

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `store-secret-ref-unresolved`

A governance-store `settings` value holds a secret reference that does not resolve on this boot. busbar warns rather than fails, because the store is restart-to-apply and staging a ref whose secret the orchestrator mounts on the next deploy is a legitimate workflow. But if the secret is still absent at the next restart, THAT restart will fail in resolve_settings before serving.

**What to do:** Ensure the named store secret reference resolves before the next restart. If you are staging it for an upcoming deploy, no action now; otherwise fix the reference so the next restart does not die resolving it.

<a id="governance-store-ephemeral"></a>
### BUSBAR-8016 — Governance store is in-memory (ephemeral) — state resets on restart

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `governance-store-ephemeral`

busbar selected the in-memory (ephemeral) governance store, so virtual keys, groups' usage, and ledgers live only in RAM and are LOST on restart. This is the default when no durable store plugin is configured — fine for a trial or local development, but not for anything that must retain keys or spend across restarts.

**What to do:** Configure a durable governance store plugin for persistence if keys, usage, or budgets must survive a restart. No action is needed for ephemeral/dev use.

<a id="durable-keys-inert"></a>
### BUSBAR-8017 — Durable keys are inert (keys exist but `keys` is not in the running auth chain)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-keys-inert`

A durable governance store holds virtual keys, but the running auth chain does not include the `keys` verifier, so those keys enforce nothing — every request bypasses key-based governance. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr, the same pattern as the open-relay banner, so the inert state cannot be masked by log configuration.

**What to do:** Add `keys` to `auth.chain` so the durable keys actually gate traffic, or remove the keys if key-based governance is not intended. Until then, minted keys are dead weight.

