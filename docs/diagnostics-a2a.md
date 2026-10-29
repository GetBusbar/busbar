# Busbar diagnostics catalog

Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its `diag` field. Find the code below for what it means, whether it needs action, and what to do. This page is generated from the code — do not edit by hand.

Codes are grouped by class (the thousands digit).

## 2xxx — Audit chain

<a id="a2a-task-chain-verify-failed"></a>
### BUSBAR-2030 — A2A per-task provenance chain failed verification on restore (tamper evidence)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-task-chain-verify-failed`

When the plane restored its task records after its instance opened, an in-flight task's per-task provenance chain did NOT verify: the host reported a break on that task's chain. This is distinct from a row that merely could not be read (BUSBAR-7024): the bytes were read and the chain does not add up, which is tamper evidence — the durable task state was altered out from under busbar, or its store is corrupt. The task is still held and served: a break is reported, never a deletion, because deleting on a break would let anyone able to write the store erase a caller's task. Emitted once per affected in-flight task on each restore.

**What to do:** Treat the durable A2A task store as compromised until explained: capture it for forensic review before it is overwritten, and restore it from a trusted backup once the cause is understood. The named task stays held; other tasks are unaffected.

## 7xxx — Plane protocols

<a id="a2a-pool-not-interchangeable"></a>
### BUSBAR-7003 — A2A submission not accepted (the pool's members are not interchangeable)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-pool-not-interchangeable`

A submission targeted an agent pool whose members are not interchangeable under the seam's rules, so it was not accepted. A routine per-request routing refusal, benign and expected under the configured pool policy; surfaced at debug so a busy caller cannot spam the log.

**What to do:** None — self-heals. If submissions should route, configure the pool's members to be interchangeable (matching capabilities) so the seam can dispatch across them.

<a id="a2a-outbound-cred-unleased"></a>
### BUSBAR-7013 — Outbound A2A credential could not be leased

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-outbound-cred-unleased`

busbar could not lease the outbound credential needed to make a hop to the target agent, so the hop is refused. The egress-auth path that mints or fetches the credential for this agent failed. Usually an egress-auth wiring or credential-source problem.

**What to do:** Check the egress-auth configuration and credential source for the named agent (scopes, the credential plugin/store). Outbound hops resume once a credential can be leased.

<a id="a2a-relayed-stream-refused"></a>
### BUSBAR-7018 — Relayed A2A stream ended in a refusal

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-relayed-stream-refused`

A relayed streaming task ended in a refusal from the backend rather than a normal completion. The refusal is recorded against the task and the caller's poll will find it. Per-request and expected under normal backend policy, so surfaced at debug.

**What to do:** None — self-heals. A stream that ends in a refusal reflects the backend's own decision; the recorded refusal is what the caller reads.

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

When the plane restored its task records after its instance opened, some persisted A2A task rows could not be read back and are therefore NOT resumable — most likely written by a different busbar version. Reported separately from the restored count and at warn, because folding an unreadable in-flight task into the restored total is how a task that silently ceased to exist across a deploy stays invisible.

**What to do:** Expected once after a version change; the counted rows cannot be resumed by this binary. If it recurs without a version change, inspect the durable task store for corruption. Callers of the affected tasks may re-submit.

<a id="a2a-task-state-unread"></a>
### BUSBAR-7025 — Durable A2A task state could not be read on restore (nothing counted or chain-checked)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-task-state-unread`

When the plane restored its task records after its instance opened, the durable A2A task records could not be listed at all, so nothing was counted and no in-flight task's provenance chain was checked. Serving does not wait on the restore: each task is still read from its own record when a request names it, and a request the store cannot answer is refused. Typically a durable-store outage.

**What to do:** Investigate the durable task store outage. Once it answers, requests read their tasks again; restart to have the restore count the tasks and check their chains.

<a id="plane-sse-frame-not-utf8"></a>
### BUSBAR-7104 — A relayed SSE frame was not valid UTF-8 and was dropped

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-sse-frame-not-utf8`

The shared SSE frame reader (the JSON-RPC plane relays) assembled a complete event whose bytes are not valid UTF-8. The event-stream format is UTF-8 BY DEFINITION, so this is a malformed backend; the frame is DROPPED rather than lossily transcoded, which would hand the client a corrupted payload. The stream itself continues, so a client sees a missing event, not a failure. The `bytes` field carries the size of the frame that was dropped.

**What to do:** Investigate the named backend agent: its event stream is emitting non-UTF-8 bytes, which no conforming event-stream consumer can read. Until it is fixed the affected events are lost; busbar relays every well-formed event around them.

