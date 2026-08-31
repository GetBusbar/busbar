# Busbar diagnostics catalog

Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its `diag` field. Find the code below for what it means, whether it needs action, and what to do. This page is generated from the code — do not edit by hand.

Codes are grouped by class (the thousands digit).

## 2xxx — Audit chain

<a id="a2a-task-chain-verify-failed"></a>
### BUSBAR-2030 — A2A per-task provenance chain failed verification on restore (tamper evidence)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-task-chain-verify-failed`

A persisted A2A task row was read back at boot but its per-task provenance chain does NOT verify against its own hashes, so the task is NOT resumed. This is distinct from a row that merely could not be read (BUSBAR-7024): the bytes were read and the chain does not add up, which is tamper evidence — the durable task state was altered out from under busbar, or its store is corrupt. Emitted once per affected task at boot.

**What to do:** Treat the durable A2A task store as compromised until explained: capture it for forensic review before it is overwritten, and restore it from a trusted backup once the cause is understood. The named task is not resumed; other in-flight tasks continue.

## 7xxx — Plane protocols

<a id="a2a-extended-card-agent-omitted"></a>
### BUSBAR-7001 — Agent omitted from the extended agent card (card names the backend authority in text)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-extended-card-agent-omitted`

While building the extended agent card, one member agent was omitted because its own card names the backend authority in free text that busbar cannot safely rewrite. Publishing it unchanged would leak the backend endpoint, so the agent is dropped from the extended card rather than exposed. A transcode limitation, not an outage.

**What to do:** None — self-heals. If the omitted agent should be reachable, adjust its published card so it does not name the backend authority in unstructured text busbar cannot rewrite.

<a id="a2a-push-config-unrecorded"></a>
### BUSBAR-7002 — A2A push-notification config could not be recorded (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-push-config-unrecorded`

A caller registered a push-notification callback but the pinned config could not be written to the durable task store, so the request is refused rather than accepting a callback busbar cannot persist. Typically a durable-store outage. Warned once on the transition into the failing state; subsequent failures hold at debug to avoid spam.

**What to do:** Investigate the durable governance/task store outage. Push-config registration resumes once the store accepts writes again.

<a id="a2a-pool-not-interchangeable"></a>
### BUSBAR-7003 — A2A submission not accepted (the pool's members are not interchangeable)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-pool-not-interchangeable`

A submission targeted an agent pool whose members are not interchangeable under the seam's rules, so it was not accepted. A routine per-request routing refusal, benign and expected under the configured pool policy; surfaced at debug so a busy caller cannot spam the log.

**What to do:** None — self-heals. If submissions should route, configure the pool's members to be interchangeable (matching capabilities) so the seam can dispatch across them.

<a id="a2a-pin-refusal-unrecorded"></a>
### BUSBAR-7004 — Pin-refused A2A task could not be recorded as rejected (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-pin-refusal-unrecorded`

A submission was refused because the pool's members are not interchangeable, but the resulting `rejected` transition could not be written to the durable task store. The caller is still told; the durable row is what could not be updated. Typically a store outage. Warned once on the transition; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. The caller received the refusal; only the durable record of it failed and resumes once the store accepts writes.

<a id="a2a-extended-card-build-failed"></a>
### BUSBAR-7005 — Extended agent card could not be built

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-extended-card-build-failed`

busbar could not build the extended agent card for a request. The card that composes the registered agents into the surface busbar publishes failed to assemble, so the caller is served without the extended view. Usually a registration/config problem in one of the member cards.

**What to do:** Check the registered agent cards named nearby for a malformed or unreachable entry; the extended card composes them, and one bad member fails the build.

<a id="a2a-no-csprng-callback"></a>
### BUSBAR-7006 — No CSPRNG available — busbar registers no push callback of its own with any backend

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-no-csprng-callback`

At startup no cryptographically-secure RNG was available, so busbar cannot mint the unguessable token that secures its own push callback and therefore registers NO callback of its own with any backend. A genuine platform/wiring problem, not a per-request condition — busbar's own push path is disabled for the process lifetime.

**What to do:** Investigate why the platform CSPRNG is unavailable (a broken entropy source or a sandboxed getrandom). busbar's own push registration stays disabled until restarted on a host with a working CSPRNG.

<a id="a2a-pushback-not-delivered"></a>
### BUSBAR-7007 — A2A pushed state was not delivered onward

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-pushback-not-delivered`

A state pushed to busbar by a backend could not be delivered onward to the caller's registered callback (the callback is down or refused it). The task's state is still recorded and the caller's poll will find it; the push is a best-effort wake, not the source of truth. Per-request and benign, so surfaced at debug.

**What to do:** None — self-heals. A persistently unreachable callback is the caller's endpoint to fix; the recorded state remains pollable regardless.

<a id="a2a-own-card-build-failed"></a>
### BUSBAR-7008 — busbar's own agent card could not be built

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-own-card-build-failed`

busbar could not build its OWN agent card — the card that describes the A2A surface busbar publishes for callers. Without it, callers cannot discover busbar's agent surface. Usually a boot/config problem in the agent-plane definition.

**What to do:** Check the A2A plane configuration (agents, bindings, endpoint) for a malformed entry; busbar's own card is composed from it and could not assemble.

<a id="a2a-refuse-serve-card"></a>
### BUSBAR-7009 — Refusing to serve an agent card

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-refuse-serve-card`

busbar refused to serve an agent card for the named agent because the card could not be produced safely for this request (it failed to build or rewrite). The caller is refused rather than handed a card that leaks a backend or is malformed.

**What to do:** Check the named agent's registered card for a malformed or non-rewritable entry; the refusal names the agent so the offending registration can be corrected.

<a id="a2a-interrupted-task-unresumed"></a>
### BUSBAR-7010 — Interrupted A2A task could not be resumed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-interrupted-task-unresumed`

A task that had been interrupted could not be resumed, so the hop cannot continue from where it left off. The caller is answered with the failure; the task's stored state is unchanged. Usually the backend or the stored resumption context is no longer usable.

**What to do:** Inspect the named task and its backend: an interrupted task that cannot resume typically means the backend lost the session or the stored resume point is stale. The caller may re-submit.

<a id="a2a-inbound-task-unopened"></a>
### BUSBAR-7011 — Inbound A2A task could not be opened (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-inbound-task-unopened`

An inbound submission could not open a task — the durable row that records the task as submitted (and to whom it was dispatched) could not be created, so busbar refuses the request rather than run work it cannot account for. Typically a durable-store outage. Warned once on the transition; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. Inbound submissions resume once the store accepts writes again.

<a id="a2a-inbound-task-unrecorded"></a>
### BUSBAR-7012 — Inbound A2A task could not be recorded (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-inbound-task-unrecorded`

An inbound task was opened but its submission could not be written to the durable task store, so the caller is answered `503` rather than left with work that has no durable record. Typically a durable-store outage. Warned once on the transition into the failing state; subsequent failures hold at debug to avoid spam.

**What to do:** Investigate the durable task-store outage. Inbound submissions are recorded again once the store accepts writes.

<a id="a2a-outbound-cred-unleased"></a>
### BUSBAR-7013 — Outbound A2A credential could not be leased

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-outbound-cred-unleased`

busbar could not lease the outbound credential needed to make a hop to the target agent, so the hop is refused. The egress-auth path that mints or fetches the credential for this agent failed. Usually an egress-auth wiring or credential-source problem.

**What to do:** Check the egress-auth configuration and credential source for the named agent (scopes, the credential plugin/store). Outbound hops resume once a credential can be leased.

<a id="a2a-agent-binding-unspeakable"></a>
### BUSBAR-7014 — Registered agent card declares no binding busbar can speak

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-agent-binding-unspeakable`

The registered agent's card declares only bindings this build cannot speak, so the hop is refused HERE by name rather than relayed as an envelope the backend never offered to read. A backend that publishes only an unspeakable binding is unreachable to busbar. A registration/config problem, not a transient fault.

**What to do:** Register the agent with a binding busbar can speak, or upgrade busbar to a build that speaks the agent's binding; the log names the agent and the binding it declared.

<a id="a2a-relay-thread-incomplete"></a>
### BUSBAR-7015 — A2A relay thread did not complete (join failure)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-relay-thread-incomplete`

A relay worker thread did not complete cleanly — its join returned an error, which means the thread panicked or was cancelled mid-relay. The task's outcome for that hop is therefore unknown. An internal fault, not a backend refusal.

**What to do:** Capture the surrounding logs for the panic/backtrace and file it: a relay thread that does not join is a busbar-internal bug. The named task may need to be re-submitted.

<a id="a2a-push-notify-undelivered"></a>
### BUSBAR-7016 — A2A push notification was not delivered

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-push-notify-undelivered`

A push notification for a task's state change could not be delivered to the caller's registered callback (the callback is down or refused it). Never fatal to the task and never retried into a hammer: the outcome is recorded and the caller's poll will find it. Per-request and benign, so surfaced at debug.

**What to do:** None — self-heals. A persistently unreachable callback is the caller's endpoint to fix; the task's recorded state remains pollable regardless.

<a id="a2a-stream-empty"></a>
### BUSBAR-7017 — Backend stream carried no event

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-stream-empty`

A backend's streaming response ended without carrying any event, so the relay had nothing to forward for that task. Benign and per-request — an empty stream is a valid (if unusual) backend behaviour. Surfaced at debug so a chatty backend cannot spam.

**What to do:** None — self-heals. If backends routinely return empty streams, investigate the backend; busbar simply records that the stream carried nothing.

<a id="a2a-relayed-stream-refused"></a>
### BUSBAR-7018 — Relayed A2A stream ended in a refusal

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-relayed-stream-refused`

A relayed streaming task ended in a refusal from the backend rather than a normal completion. The refusal is recorded against the task and the caller's poll will find it. Per-request and expected under normal backend policy, so surfaced at debug.

**What to do:** None — self-heals. A stream that ends in a refusal reflects the backend's own decision; the recorded refusal is what the caller reads.

<a id="a2a-stream-relay-incomplete"></a>
### BUSBAR-7019 — A2A streaming relay thread did not complete (join failure)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-stream-relay-incomplete`

A streaming-relay worker thread did not complete cleanly — its join returned an error, which means it panicked or was cancelled mid-stream. The streamed task's outcome is therefore unknown. An internal fault, not a backend refusal.

**What to do:** Capture the surrounding logs for the panic/backtrace and file it: a streaming-relay thread that does not join is a busbar-internal bug. The named task may need re-submitting.

<a id="a2a-relayed-outcome-unrecorded"></a>
### BUSBAR-7020 — Relayed A2A task outcome could not be recorded (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-relayed-outcome-unrecorded`

A relayed hop SUCCEEDED and the caller is owed its answer, but the resulting state transition could not be written to the durable task store. Reported, never fatal: a store that refused the transition is an operator problem, not a reason to discard completed, billed work. Warned once on the transition; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. The caller still receives the completed hop; only the durable outcome record failed and resumes once the store accepts writes.

<a id="a2a-relayed-submission-failed"></a>
### BUSBAR-7021 — Relayed A2A task submission failed

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-relayed-submission-failed`

A relayed task submission was refused by the backend. The refusal is recorded against the task and returned to the caller; busbar did not accept work it could not place. Per-request and expected under normal backend policy or load, so surfaced at debug.

**What to do:** None — self-heals. A submission the backend refuses reflects the backend's own decision or capacity; the caller reads the recorded refusal and may re-submit.

<a id="a2a-breaker-refusal-unrecorded"></a>
### BUSBAR-7022 — Breaker-refused A2A task could not be recorded as rejected (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-breaker-refusal-unrecorded`

A submission was refused before the socket by the cross-plane breaker, but the resulting `rejected` transition could not be written to the durable task store. The caller still gets the `503` + `Retry-After`; the durable row is what could not be updated. Typically a store outage. Warned once on the transition; then held at debug.

**What to do:** Investigate the durable task-store outage. The caller received the breaker refusal; only the durable record of it failed and resumes once the store accepts writes.

<a id="a2a-failure-unrecorded"></a>
### BUSBAR-7023 — Failed A2A task could not be recorded as failed (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-failure-unrecorded`

A task reached the terminal `failed` state but that transition could not be written to the durable task store, so a durable row may still claim the work is in flight. The caller is answered and any registered callback is fired; the durable record is what failed. Typically a store outage. Warned once on the transition; then held at debug.

**What to do:** Investigate the durable task-store outage. The caller was told of the failure; the durable `failed` record resumes once the store accepts writes.

<a id="a2a-task-rows-unreadable"></a>
### BUSBAR-7024 — Persisted A2A task rows could not be read back (not resumable)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-task-rows-unreadable`

At boot, some persisted A2A task rows could not be read back and are therefore NOT resumable — they were most likely written by a different engine version. Reported separately from the restored count and at warn, because folding an unreadable in-flight task into the restored total is how a task that silently ceased to exist across a deploy stays invisible.

**What to do:** Expected once after an engine-version change; the named rows cannot be resumed by this binary. If it recurs without a version change, inspect the durable task store for corruption. Callers of the affected tasks may re-submit.

<a id="a2a-task-state-unread"></a>
### BUSBAR-7025 — Durable A2A task state could not be read at boot (in-flight tasks start empty)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-task-state-unread`

At boot, the durable A2A task state could not be read at all, so busbar starts with NO in-flight tasks restored rather than block boot on the store. Any task that was in flight before restart is invisible to this process until the store answers. Typically a durable-store outage.

**What to do:** Investigate the durable governance/task store outage and restart once it is reachable so in-flight tasks are restored. Until then, busbar serves with an empty in-flight set.

<a id="a2a-card-fetch-panicked"></a>
### BUSBAR-7026 — Agent-card fetch panicked during an operator-driven verb

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-card-fetch-panicked`

While running an operator-driven verb, the agent-card fetch panicked rather than returning an error or a card. The operator's action could not complete. An internal fault on the fetch path, not a backend refusal.

**What to do:** Capture the surrounding logs for the panic/backtrace and file it: a card fetch that panics is a busbar-internal bug. Retry the operator verb once resolved.

<a id="a2a-reverify-cadence-unparsed"></a>
### BUSBAR-7027 — A2A re-verification cadence did not parse (registration keeps the release default)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-reverify-cadence-unparsed`

An agent registration's re-verification cadence did not parse, so the registration keeps the release-default cadence rather than the operator's intended value. Config validation should have refused this before boot; reaching this point means a bad cadence slipped through to registration.

**What to do:** Fix the named agent's re-verification cadence to a parseable value and reload. Until then, that agent re-verifies on the release-default cadence, not the configured one.

<a id="a2a-card-cert-no-spki"></a>
### BUSBAR-7028 — Card endpoint certificate yielded no SPKI pin

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-card-cert-no-spki`

When fetching an agent card over TLS, the endpoint's certificate yielded no SPKI pin, so busbar cannot pin the endpoint's key for that fetch. A trust/pin configuration problem: without an SPKI pin the card's transport cannot be pinned to a known key.

**What to do:** Check the card endpoint's TLS certificate and busbar's pinning configuration for that agent; a certificate that yields no SPKI cannot be pinned.

<a id="a2a-push-outcome-unchained"></a>
### BUSBAR-7029 — A2A push-notification delivery outcome could not be chained

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-push-outcome-unchained`

The outcome of a push-notification delivery could not be appended to its provenance chain. The delivery itself already happened (or was already refused); only the record-keeping append failed. Per-request and benign to the delivery path, so surfaced at debug.

**What to do:** None — self-heals for delivery. If it recurs, investigate the durable provenance store, since delivery outcomes are then going unchained.

<a id="a2a-dispatch-unrecorded"></a>
### BUSBAR-7100 — A2A dispatch (task.delegated) event could not be recorded (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-dispatch-unrecorded`

An inbound task was durably submitted, but the chained `task.delegated` event — who delegated, to which registered agent — could not be written before the hop. The hop proceeds (the submit already succeeded and failing the request mid-flight would discard work the caller is owed), so the task's provenance chain is missing its dispatch record for this hop. Typically a durable-store outage. Warned once on the transition into the failing state; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. Later hops chain their dispatch records again once the store accepts writes; the gap in affected chains is permanent and this diagnostic is its record.

<a id="a2a-push-callback-unpersisted"></a>
### BUSBAR-7101 — A2A inline push callback could not be persisted (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-push-callback-unpersisted`

A push-notification callback supplied INLINE on a task submission was validated and accepted, but writing it onto the durable task row failed. The in-process delivery caches are still populated, so notifications deliver for this process lifetime — but after a restart the rehydrated row carries no callback and delivery for this task silently stops. Typically a durable-store outage. Warned once on the transition into the failing state; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. Callbacks registered while it persists survive only until the next restart; callers can re-register via `tasks/pushNotificationConfig/set` once the store accepts writes.

<a id="a2a-push-config-undeleted"></a>
### BUSBAR-7102 — A2A push-notification config delete could not clear the durable row (write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-push-config-undeleted`

A caller deleted a push-notification config but the durable task row's callback could not be cleared. The delete is REFUSED (the config stays registered everywhere and the caller receives an internal error so it can retry) rather than answered OK — acknowledging a delete while the durable callback survives would mean a callback the caller deleted still receiving the task's completion after a restart, the one outcome a delete exists to prevent. Typically a durable-store outage. Warned once on the transition into the failing state; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. The caller's retry succeeds once the store accepts writes again.

<a id="a2a-push-rearm-failed"></a>
### BUSBAR-7103 — A2A push registration re-arm at the backend agent failed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-push-rearm-failed`

A read of busbar's own push registration at the backend agent discovered it gone (the backend refused it, dropped it, or restarted without it) and the re-arm request the reconciliation issued FAILED — so the caller's callback stays armed at busbar and dead at the agent until a later reconciliation succeeds. Per-hop condition against a live backend; the next read of the registration retries.

**What to do:** Investigate why the backend agent refuses busbar's push-config create (auth, capability, outage). Deliveries the agent originates resume once a re-arm succeeds.

