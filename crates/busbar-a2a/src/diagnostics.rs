// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A2A plane diagnostics — the `A2A_*` catalog entries this crate OWNS.
//!
//! These consts were plane-specific vocabulary living in the neutral
//! `busbar_substrate::diagnostics` catalog; the plane extraction relocated them here so the neutral
//! crate names no `A2A_*` diagnostic. Each keeps its stable `BUSBAR-NNNN` number and slug — the
//! move preserves identity, it does not renumber: codes are REGISTERED, never collapsed.
//!
//! [`DIAGNOSTICS`] is the slice the composition root hands to
//! [`install_diagnostics`](busbar_substrate::diagnostics::install_diagnostics) so these codes join
//! the runtime catalog (`REGISTRY ∪ installed`) and resolve through `by_code`. The `busbar` binary
//! names one stable path: `busbar-a2a::DIAGNOSTICS`.

use busbar_substrate::diagnostics::{Class, Diagnostic, Severity};

/// A restored A2A task's per-task provenance chain failed verification at boot — tamper evidence.
/// Lives in `a2a/mod.rs`, but the subject is the provenance chain's integrity, so it is a 2000 code.
pub const A2A_TASK_CHAIN_VERIFY_FAILED: Diagnostic = Diagnostic {
    code: 2030,
    class: Class::Audit,
    slug: "a2a-task-chain-verify-failed",
    title: "A2A per-task provenance chain failed verification on restore (tamper evidence)",
    severity: Severity::Actionable,
    summary:
        "A persisted A2A task row was read back at boot but its per-task provenance chain does NOT \
              verify against its own hashes, so the task is NOT resumed. This is distinct from a row \
              that merely could not be read (BUSBAR-7024): the bytes were read and the chain does not \
              add up, which is tamper evidence — the durable task state was altered out from under \
              busbar, or its store is corrupt. Emitted once per affected task at boot.",
    action:
        "Treat the durable A2A task store as compromised until explained: capture it for forensic \
             review before it is overwritten, and restore it from a trusted backup once the cause is \
             understood. The named task is not resumed; other in-flight tasks continue.",
    since: "1.6.0",
    retired: false,
};

/// An agent is dropped from the extended card because its card names the backend authority in text.
pub const A2A_EXTENDED_CARD_AGENT_OMITTED: Diagnostic = Diagnostic {
    code: 7001,
    class: Class::Plane,
    slug: "a2a-extended-card-agent-omitted",
    title: "Agent omitted from the extended agent card (card names the backend authority in text)",
    severity: Severity::BenignRecurring,
    summary: "While building the extended agent card, one member agent was omitted because its own \
              card names the backend authority in free text that busbar cannot safely rewrite. \
              Publishing it unchanged would leak the backend endpoint, so the agent is dropped from \
              the extended card rather than exposed. A transcode limitation, not an outage.",
    action: "None — self-heals. If the omitted agent should be reachable, adjust its published card \
             so it does not name the backend authority in unstructured text busbar cannot rewrite.",
    since: "1.6.0",
    retired: false,
};

/// A local push-notification config could not be written to the durable task store — a store outage.
pub const A2A_PUSH_CONFIG_UNRECORDED: Diagnostic = Diagnostic {
    code: 7002,
    class: Class::Plane,
    slug: "a2a-push-config-unrecorded",
    title: "A2A push-notification config could not be recorded (durable store write failed)",
    severity: Severity::Actionable,
    summary: "A caller registered a push-notification callback but the pinned config could not be \
              written to the durable task store, so the request is refused rather than accepting a \
              callback busbar cannot persist. Typically a durable-store outage. Warned once on the \
              transition into the failing state; subsequent failures hold at debug to avoid spam.",
    action:
        "Investigate the durable governance/task store outage. Push-config registration resumes \
             once the store accepts writes again.",
    since: "1.6.0",
    retired: false,
};

/// A pool's members are not interchangeable, so a fresh submission is not accepted — routine refusal.
pub const A2A_POOL_NOT_INTERCHANGEABLE: Diagnostic = Diagnostic {
    code: 7003,
    class: Class::Plane,
    slug: "a2a-pool-not-interchangeable",
    title: "A2A submission not accepted (the pool's members are not interchangeable)",
    severity: Severity::BenignRecurring,
    summary: "A submission targeted an agent pool whose members are not interchangeable under the \
              seam's rules, so it was not accepted. A routine per-request routing refusal, benign and \
              expected under the configured pool policy; surfaced at debug so a busy caller cannot \
              spam the log.",
    action: "None — self-heals. If submissions should route, configure the pool's members to be \
             interchangeable (matching capabilities) so the seam can dispatch across them.",
    since: "1.6.0",
    retired: false,
};

/// A pin-refused task could not be recorded as rejected — a store outage on the durable task store.
pub const A2A_PIN_REFUSAL_UNRECORDED: Diagnostic = Diagnostic {
    code: 7004,
    class: Class::Plane,
    slug: "a2a-pin-refusal-unrecorded",
    title: "Pin-refused A2A task could not be recorded as rejected (durable store write failed)",
    severity: Severity::Actionable,
    summary:
        "A submission was refused because the pool's members are not interchangeable, but the \
              resulting `rejected` transition could not be written to the durable task store. The \
              caller is still told; the durable row is what could not be updated. Typically a \
              store outage. Warned once on the transition; subsequent failures hold at debug.",
    action: "Investigate the durable task-store outage. The caller received the refusal; only the \
             durable record of it failed and resumes once the store accepts writes.",
    since: "1.6.0",
    retired: false,
};

/// The extended agent card could not be built for a request — a card-composition failure.
pub const A2A_EXTENDED_CARD_BUILD_FAILED: Diagnostic = Diagnostic {
    code: 7005,
    class: Class::Plane,
    slug: "a2a-extended-card-build-failed",
    title: "Extended agent card could not be built",
    severity: Severity::Actionable,
    summary:
        "busbar could not build the extended agent card for a request. The card that composes \
              the registered agents into the surface busbar publishes failed to assemble, so the \
              caller is served without the extended view. Usually a registration/config problem in \
              one of the member cards.",
    action:
        "Check the registered agent cards named nearby for a malformed or unreachable entry; the \
             extended card composes them, and one bad member fails the build.",
    since: "1.6.0",
    retired: false,
};

/// No CSPRNG at startup, so busbar registers no push callback of its own with any backend.
pub const A2A_NO_CSPRNG_CALLBACK: Diagnostic = Diagnostic {
    code: 7006,
    class: Class::Plane,
    slug: "a2a-no-csprng-callback",
    title: "No CSPRNG available — busbar registers no push callback of its own with any backend",
    severity: Severity::Actionable,
    summary: "At startup no cryptographically-secure RNG was available, so busbar cannot mint the \
              unguessable token that secures its own push callback and therefore registers NO \
              callback of its own with any backend. A genuine platform/wiring problem, not a \
              per-request condition — busbar's own push path is disabled for the process lifetime.",
    action: "Investigate why the platform CSPRNG is unavailable (a broken entropy source or a \
             sandboxed getrandom). busbar's own push registration stays disabled until restarted on \
             a host with a working CSPRNG.",
    since: "1.6.0",
    retired: false,
};

/// A pushed state was not delivered onward to the caller's callback — a per-request delivery miss.
pub const A2A_PUSHBACK_NOT_DELIVERED: Diagnostic = Diagnostic {
    code: 7007,
    class: Class::Plane,
    slug: "a2a-pushback-not-delivered",
    title: "A2A pushed state was not delivered onward",
    severity: Severity::BenignRecurring,
    summary: "A state pushed to busbar by a backend could not be delivered onward to the caller's \
              registered callback (the callback is down or refused it). The task's state is still \
              recorded and the caller's poll will find it; the push is a best-effort wake, not the \
              source of truth. Per-request and benign, so surfaced at debug.",
    action:
        "None — self-heals. A persistently unreachable callback is the caller's endpoint to fix; \
             the recorded state remains pollable regardless.",
    since: "1.6.0",
    retired: false,
};

/// busbar's own agent card could not be built at boot/config — a card-composition failure.
pub const A2A_OWN_CARD_BUILD_FAILED: Diagnostic = Diagnostic {
    code: 7008,
    class: Class::Plane,
    slug: "a2a-own-card-build-failed",
    title: "busbar's own agent card could not be built",
    severity: Severity::Actionable,
    summary: "busbar could not build its OWN agent card — the card that describes the A2A surface \
              busbar publishes for callers. Without it, callers cannot discover busbar's agent \
              surface. Usually a boot/config problem in the agent-plane definition.",
    action:
        "Check the A2A plane configuration (agents, bindings, endpoint) for a malformed entry; \
             busbar's own card is composed from it and could not assemble.",
    since: "1.6.0",
    retired: false,
};

/// busbar is refusing to serve an agent card for a specific agent — a per-request card refusal.
pub const A2A_REFUSE_SERVE_CARD: Diagnostic = Diagnostic {
    code: 7009,
    class: Class::Plane,
    slug: "a2a-refuse-serve-card",
    title: "Refusing to serve an agent card",
    severity: Severity::Actionable,
    summary:
        "busbar refused to serve an agent card for the named agent because the card could not \
              be produced safely for this request (it failed to build or rewrite). The caller is \
              refused rather than handed a card that leaks a backend or is malformed.",
    action: "Check the named agent's registered card for a malformed or non-rewritable entry; the \
             refusal names the agent so the offending registration can be corrected.",
    since: "1.6.0",
    retired: false,
};

/// An interrupted task could not be resumed on the relay path — the hop cannot continue.
pub const A2A_INTERRUPTED_TASK_UNRESUMED: Diagnostic = Diagnostic {
    code: 7010,
    class: Class::Plane,
    slug: "a2a-interrupted-task-unresumed",
    title: "Interrupted A2A task could not be resumed",
    severity: Severity::Actionable,
    summary: "A task that had been interrupted could not be resumed, so the hop cannot continue from \
              where it left off. The caller is answered with the failure; the task's stored state is \
              unchanged. Usually the backend or the stored resumption context is no longer usable.",
    action: "Inspect the named task and its backend: an interrupted task that cannot resume typically \
             means the backend lost the session or the stored resume point is stale. The caller may \
             re-submit.",
    since: "1.6.0",
    retired: false,
};

/// An inbound task could not be opened (the task object failed to construct) — usually a store outage.
pub const A2A_INBOUND_TASK_UNOPENED: Diagnostic = Diagnostic {
    code: 7011,
    class: Class::Plane,
    slug: "a2a-inbound-task-unopened",
    title: "Inbound A2A task could not be opened (durable store write failed)",
    severity: Severity::Actionable,
    summary: "An inbound submission could not open a task — the durable row that records the task as \
              submitted (and to whom it was dispatched) could not be created, so busbar refuses the \
              request rather than run work it cannot account for. Typically a durable-store outage. \
              Warned once on the transition; subsequent failures hold at debug.",
    action: "Investigate the durable task-store outage. Inbound submissions resume once the store \
             accepts writes again.",
    since: "1.6.0",
    retired: false,
};

/// An inbound task could not be recorded (the submit write failed) — usually a store outage.
pub const A2A_INBOUND_TASK_UNRECORDED: Diagnostic = Diagnostic {
    code: 7012,
    class: Class::Plane,
    slug: "a2a-inbound-task-unrecorded",
    title: "Inbound A2A task could not be recorded (durable store write failed)",
    severity: Severity::Actionable,
    summary: "An inbound task was opened but its submission could not be written to the durable task \
              store, so the caller is answered `503` rather than left with work that has no durable \
              record. Typically a durable-store outage. Warned once on the transition into the \
              failing state; subsequent failures hold at debug to avoid spam.",
    action: "Investigate the durable task-store outage. Inbound submissions are recorded again once \
             the store accepts writes.",
    since: "1.6.0",
    retired: false,
};

/// An outbound credential could not be leased for a hop — an egress-auth wiring problem.
pub const A2A_OUTBOUND_CRED_UNLEASED: Diagnostic = Diagnostic {
    code: 7013,
    class: Class::Plane,
    slug: "a2a-outbound-cred-unleased",
    title: "Outbound A2A credential could not be leased",
    severity: Severity::Actionable,
    summary: "busbar could not lease the outbound credential needed to make a hop to the target \
              agent, so the hop is refused. The egress-auth path that mints or fetches the credential \
              for this agent failed. Usually an egress-auth wiring or credential-source problem.",
    action: "Check the egress-auth configuration and credential source for the named agent (scopes, \
             the credential plugin/store). Outbound hops resume once a credential can be leased.",
    since: "1.6.0",
    retired: false,
};

/// A registered agent's card declares no binding busbar can speak — a registration/config problem.
pub const A2A_AGENT_BINDING_UNSPEAKABLE: Diagnostic = Diagnostic {
    code: 7014,
    class: Class::Plane,
    slug: "a2a-agent-binding-unspeakable",
    title: "Registered agent card declares no binding busbar can speak",
    severity: Severity::Actionable,
    summary: "The registered agent's card declares only bindings this build cannot speak, so the hop \
              is refused HERE by name rather than relayed as an envelope the backend never offered to \
              read. A backend that publishes only an unspeakable binding is unreachable to busbar. A \
              registration/config problem, not a transient fault.",
    action: "Register the agent with a binding busbar can speak, or upgrade busbar to a build that \
             speaks the agent's binding; the log names the agent and the binding it declared.",
    since: "1.6.0",
    retired: false,
};

/// A relay thread did not complete (a join failure) — an internal panic on the relay path.
pub const A2A_RELAY_THREAD_INCOMPLETE: Diagnostic = Diagnostic {
    code: 7015,
    class: Class::Plane,
    slug: "a2a-relay-thread-incomplete",
    title: "A2A relay thread did not complete (join failure)",
    severity: Severity::Actionable,
    summary: "A relay worker thread did not complete cleanly — its join returned an error, which \
              means the thread panicked or was cancelled mid-relay. The task's outcome for that hop \
              is therefore unknown. An internal fault, not a backend refusal.",
    action: "Capture the surrounding logs for the panic/backtrace and file it: a relay thread that \
             does not join is a busbar-internal bug. The named task may need to be re-submitted.",
    since: "1.6.0",
    retired: false,
};

/// A push notification was not delivered onward — a per-request best-effort delivery miss.
pub const A2A_PUSH_NOTIFY_UNDELIVERED: Diagnostic = Diagnostic {
    code: 7016,
    class: Class::Plane,
    slug: "a2a-push-notify-undelivered",
    title: "A2A push notification was not delivered",
    severity: Severity::BenignRecurring,
    summary: "A push notification for a task's state change could not be delivered to the caller's \
              registered callback (the callback is down or refused it). Never fatal to the task and \
              never retried into a hammer: the outcome is recorded and the caller's poll will find \
              it. Per-request and benign, so surfaced at debug.",
    action: "None — self-heals. A persistently unreachable callback is the caller's endpoint to fix; \
             the task's recorded state remains pollable regardless.",
    since: "1.6.0",
    retired: false,
};

/// A backend's stream carried no event — a per-request empty-stream observation.
pub const A2A_STREAM_EMPTY: Diagnostic = Diagnostic {
    code: 7017,
    class: Class::Plane,
    slug: "a2a-stream-empty",
    title: "Backend stream carried no event",
    severity: Severity::BenignRecurring,
    summary: "A backend's streaming response ended without carrying any event, so the relay had \
              nothing to forward for that task. Benign and per-request — an empty stream is a valid \
              (if unusual) backend behaviour. Surfaced at debug so a chatty backend cannot spam.",
    action: "None — self-heals. If backends routinely return empty streams, investigate the backend; \
             busbar simply records that the stream carried nothing.",
    since: "1.6.0",
    retired: false,
};

/// A relayed stream ended in a refusal — a per-request backend refusal on the streaming path.
pub const A2A_RELAYED_STREAM_REFUSED: Diagnostic = Diagnostic {
    code: 7018,
    class: Class::Plane,
    slug: "a2a-relayed-stream-refused",
    title: "Relayed A2A stream ended in a refusal",
    severity: Severity::BenignRecurring,
    summary: "A relayed streaming task ended in a refusal from the backend rather than a normal \
              completion. The refusal is recorded against the task and the caller's poll will find \
              it. Per-request and expected under normal backend policy, so surfaced at debug.",
    action:
        "None — self-heals. A stream that ends in a refusal reflects the backend's own decision; \
             the recorded refusal is what the caller reads.",
    since: "1.6.0",
    retired: false,
};

/// A streaming relay thread did not complete (a join failure) — an internal panic on the stream path.
pub const A2A_STREAM_RELAY_INCOMPLETE: Diagnostic = Diagnostic {
    code: 7019,
    class: Class::Plane,
    slug: "a2a-stream-relay-incomplete",
    title: "A2A streaming relay thread did not complete (join failure)",
    severity: Severity::Actionable,
    summary: "A streaming-relay worker thread did not complete cleanly — its join returned an error, \
              which means it panicked or was cancelled mid-stream. The streamed task's outcome is \
              therefore unknown. An internal fault, not a backend refusal.",
    action: "Capture the surrounding logs for the panic/backtrace and file it: a streaming-relay \
             thread that does not join is a busbar-internal bug. The named task may need re-submitting.",
    since: "1.6.0",
    retired: false,
};

/// A relayed task's outcome could not be recorded — usually a store outage; the hop still succeeded.
pub const A2A_RELAYED_OUTCOME_UNRECORDED: Diagnostic = Diagnostic {
    code: 7020,
    class: Class::Plane,
    slug: "a2a-relayed-outcome-unrecorded",
    title: "Relayed A2A task outcome could not be recorded (durable store write failed)",
    severity: Severity::Actionable,
    summary: "A relayed hop SUCCEEDED and the caller is owed its answer, but the resulting state \
              transition could not be written to the durable task store. Reported, never fatal: a \
              store that refused the transition is an operator problem, not a reason to discard \
              completed, billed work. Warned once on the transition; subsequent failures hold at debug.",
    action: "Investigate the durable task-store outage. The caller still receives the completed hop; \
             only the durable outcome record failed and resumes once the store accepts writes.",
    since: "1.6.0",
    retired: false,
};

/// A relayed task submission failed at the backend — a per-request backend refusal.
pub const A2A_RELAYED_SUBMISSION_FAILED: Diagnostic = Diagnostic {
    code: 7021,
    class: Class::Plane,
    slug: "a2a-relayed-submission-failed",
    title: "Relayed A2A task submission failed",
    severity: Severity::BenignRecurring,
    summary:
        "A relayed task submission was refused by the backend. The refusal is recorded against \
              the task and returned to the caller; busbar did not accept work it could not place. \
              Per-request and expected under normal backend policy or load, so surfaced at debug.",
    action:
        "None — self-heals. A submission the backend refuses reflects the backend's own decision \
             or capacity; the caller reads the recorded refusal and may re-submit.",
    since: "1.6.0",
    retired: false,
};

/// A breaker-refused task could not be recorded as rejected — usually a store outage.
pub const A2A_BREAKER_REFUSAL_UNRECORDED: Diagnostic = Diagnostic {
    code: 7022,
    class: Class::Plane,
    slug: "a2a-breaker-refusal-unrecorded",
    title:
        "Breaker-refused A2A task could not be recorded as rejected (durable store write failed)",
    severity: Severity::Actionable,
    summary:
        "A submission was refused before the socket by the cross-plane breaker, but the \
              resulting `rejected` transition could not be written to the durable task store. The \
              caller still gets the `503` + `Retry-After`; the durable row is what could not be \
              updated. Typically a store outage. Warned once on the transition; then held at debug.",
    action:
        "Investigate the durable task-store outage. The caller received the breaker refusal; only \
             the durable record of it failed and resumes once the store accepts writes.",
    since: "1.6.0",
    retired: false,
};

/// A failed task could not be recorded as failed — usually a store outage; the caller is still answered.
pub const A2A_FAILURE_UNRECORDED: Diagnostic = Diagnostic {
    code: 7023,
    class: Class::Plane,
    slug: "a2a-failure-unrecorded",
    title: "Failed A2A task could not be recorded as failed (durable store write failed)",
    severity: Severity::Actionable,
    summary:
        "A task reached the terminal `failed` state but that transition could not be written to \
              the durable task store, so a durable row may still claim the work is in flight. The \
              caller is answered and any registered callback is fired; the durable record is what \
              failed. Typically a store outage. Warned once on the transition; then held at debug.",
    action: "Investigate the durable task-store outage. The caller was told of the failure; the \
             durable `failed` record resumes once the store accepts writes.",
    since: "1.6.0",
    retired: false,
};

/// Persisted A2A task rows could not be read back at boot and are NOT resumable — version mismatch.
pub const A2A_TASK_ROWS_UNREADABLE: Diagnostic = Diagnostic {
    code: 7024,
    class: Class::Plane,
    slug: "a2a-task-rows-unreadable",
    title: "Persisted A2A task rows could not be read back (not resumable)",
    severity: Severity::Actionable,
    summary: "At boot, some persisted A2A task rows could not be read back and are therefore NOT \
              resumable — they were most likely written by a different engine version. Reported \
              separately from the restored count and at warn, because folding an unreadable in-flight \
              task into the restored total is how a task that silently ceased to exist across a \
              deploy stays invisible.",
    action: "Expected once after an engine-version change; the named rows cannot be resumed by this \
             binary. If it recurs without a version change, inspect the durable task store for \
             corruption. Callers of the affected tasks may re-submit.",
    since: "1.6.0",
    retired: false,
};

/// Durable A2A task state could not be read at boot; in-flight tasks start empty — a store outage.
pub const A2A_TASK_STATE_UNREAD: Diagnostic = Diagnostic {
    code: 7025,
    class: Class::Plane,
    slug: "a2a-task-state-unread",
    title: "Durable A2A task state could not be read at boot (in-flight tasks start empty)",
    severity: Severity::Actionable,
    summary: "At boot, the durable A2A task state could not be read at all, so busbar starts with NO \
              in-flight tasks restored rather than block boot on the store. Any task that was in \
              flight before restart is invisible to this process until the store answers. Typically \
              a durable-store outage.",
    action: "Investigate the durable governance/task store outage and restart once it is reachable so \
             in-flight tasks are restored. Until then, busbar serves with an empty in-flight set.",
    since: "1.6.0",
    retired: false,
};

/// A card fetch panicked during an operator-driven verb — an internal fault on an operator action.
pub const A2A_CARD_FETCH_PANICKED: Diagnostic = Diagnostic {
    code: 7026,
    class: Class::Plane,
    slug: "a2a-card-fetch-panicked",
    title: "Agent-card fetch panicked during an operator-driven verb",
    severity: Severity::Actionable,
    summary: "While running an operator-driven verb, the agent-card fetch panicked rather than \
              returning an error or a card. The operator's action could not complete. An internal \
              fault on the fetch path, not a backend refusal.",
    action: "Capture the surrounding logs for the panic/backtrace and file it: a card fetch that \
             panics is a busbar-internal bug. Retry the operator verb once resolved.",
    since: "1.6.0",
    retired: false,
};

/// A re-verification cadence did not parse; the registration keeps the release default — config bug.
pub const A2A_REVERIFY_CADENCE_UNPARSED: Diagnostic = Diagnostic {
    code: 7027,
    class: Class::Plane,
    slug: "a2a-reverify-cadence-unparsed",
    title: "A2A re-verification cadence did not parse (registration keeps the release default)",
    severity: Severity::Actionable,
    summary: "An agent registration's re-verification cadence did not parse, so the registration \
              keeps the release-default cadence rather than the operator's intended value. Config \
              validation should have refused this before boot; reaching this point means a bad \
              cadence slipped through to registration.",
    action: "Fix the named agent's re-verification cadence to a parseable value and reload. Until \
             then, that agent re-verifies on the release-default cadence, not the configured one.",
    since: "1.6.0",
    retired: false,
};

/// A card endpoint's certificate yielded no SPKI pin — a trust/pin configuration problem.
pub const A2A_CARD_CERT_NO_SPKI: Diagnostic = Diagnostic {
    code: 7028,
    class: Class::Plane,
    slug: "a2a-card-cert-no-spki",
    title: "Card endpoint certificate yielded no SPKI pin",
    severity: Severity::Actionable,
    summary:
        "When fetching an agent card over TLS, the endpoint's certificate yielded no SPKI pin, \
              so busbar cannot pin the endpoint's key for that fetch. A trust/pin configuration \
              problem: without an SPKI pin the card's transport cannot be pinned to a known key.",
    action:
        "Check the card endpoint's TLS certificate and busbar's pinning configuration for that \
             agent; a certificate that yields no SPKI cannot be pinned.",
    since: "1.6.0",
    retired: false,
};

/// A push-notification delivery outcome could not be chained — a per-request provenance write miss.
pub const A2A_PUSH_OUTCOME_UNCHAINED: Diagnostic = Diagnostic {
    code: 7029,
    class: Class::Plane,
    slug: "a2a-push-outcome-unchained",
    title: "A2A push-notification delivery outcome could not be chained",
    severity: Severity::BenignRecurring,
    summary: "The outcome of a push-notification delivery could not be appended to its provenance \
              chain. The delivery itself already happened (or was already refused); only the \
              record-keeping append failed. Per-request and benign to the delivery path, so surfaced \
              at debug.",
    action: "None — self-heals for delivery. If it recurs, investigate the durable provenance store, \
             since delivery outcomes are then going unchained.",
    since: "1.6.0",
    retired: false,
};

/// The `task.delegated` chain event could not be written after a successful Submit — store outage.
pub const A2A_DISPATCH_UNRECORDED: Diagnostic = Diagnostic {
    code: 7100,
    class: Class::Plane,
    slug: "a2a-dispatch-unrecorded",
    title: "A2A dispatch (task.delegated) event could not be recorded (durable store write failed)",
    severity: Severity::Actionable,
    summary: "An inbound task was durably submitted, but the chained `task.delegated` event — who \
              delegated, to which registered agent — could not be written before the hop. The hop \
              proceeds (the submit already succeeded and failing the request mid-flight would \
              discard work the caller is owed), so the task's provenance chain is missing its \
              dispatch record for this hop. Typically a durable-store outage. Warned once on the \
              transition into the failing state; subsequent failures hold at debug.",
    action: "Investigate the durable task-store outage. Later hops chain their dispatch records \
             again once the store accepts writes; the gap in affected chains is permanent and this \
             diagnostic is its record.",
    since: "1.6.0",
    retired: false,
};

/// A submission-inline push callback could not be persisted to the durable task row.
pub const A2A_PUSH_CALLBACK_UNPERSISTED: Diagnostic = Diagnostic {
    code: 7101,
    class: Class::Plane,
    slug: "a2a-push-callback-unpersisted",
    title: "A2A inline push callback could not be persisted (durable store write failed)",
    severity: Severity::Actionable,
    summary: "A push-notification callback supplied INLINE on a task submission was validated and \
              accepted, but writing it onto the durable task row failed. The in-process delivery \
              caches are still populated, so notifications deliver for this process lifetime — but \
              after a restart the rehydrated row carries no callback and delivery for this task \
              silently stops. Typically a durable-store outage. Warned once on the transition into \
              the failing state; subsequent failures hold at debug.",
    action: "Investigate the durable task-store outage. Callbacks registered while it persists \
             survive only until the next restart; callers can re-register via \
             `tasks/pushNotificationConfig/set` once the store accepts writes.",
    since: "1.6.0",
    retired: false,
};

/// A push-config delete could not clear the durable row — the delete is refused, caller retries.
pub const A2A_PUSH_CONFIG_UNDELETED: Diagnostic = Diagnostic {
    code: 7102,
    class: Class::Plane,
    slug: "a2a-push-config-undeleted",
    title: "A2A push-notification config delete could not clear the durable row (write failed)",
    severity: Severity::Actionable,
    summary: "A caller deleted a push-notification config but the durable task row's callback \
              could not be cleared. The delete is REFUSED (the config stays registered everywhere \
              and the caller receives an internal error so it can retry) rather than answered OK — \
              acknowledging a delete while the durable callback survives would mean a callback the \
              caller deleted still receiving the task's completion after a restart, the one outcome \
              a delete exists to prevent. Typically a durable-store outage. Warned once on the \
              transition into the failing state; subsequent failures hold at debug.",
    action: "Investigate the durable task-store outage. The caller's retry succeeds once the store \
             accepts writes again.",
    since: "1.6.0",
    retired: false,
};

/// The reconciliation found busbar's own push registration gone at the agent and the re-arm failed.
pub const A2A_PUSH_REARM_FAILED: Diagnostic = Diagnostic {
    code: 7103,
    class: Class::Plane,
    slug: "a2a-push-rearm-failed",
    title: "A2A push registration re-arm at the backend agent failed",
    severity: Severity::Actionable,
    summary: "A read of busbar's own push registration at the backend agent discovered it gone \
              (the backend refused it, dropped it, or restarted without it) and the re-arm request \
              the reconciliation issued FAILED — so the caller's callback stays armed at busbar \
              and dead at the agent until a later reconciliation succeeds. Per-hop condition \
              against a live backend; the next read of the registration retries.",
    action: "Investigate why the backend agent refuses busbar's push-config create (auth, \
             capability, outage). Deliveries the agent originates resume once a re-arm succeeds.",
    since: "1.6.0",
    retired: false,
};

/// A2A'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the composition
/// root installs via `install_diagnostics`. Ascending by code, mirroring the neutral `REGISTRY`.
pub static DIAGNOSTICS: &[&Diagnostic] = &[
    &A2A_TASK_CHAIN_VERIFY_FAILED,
    &A2A_EXTENDED_CARD_AGENT_OMITTED,
    &A2A_PUSH_CONFIG_UNRECORDED,
    &A2A_POOL_NOT_INTERCHANGEABLE,
    &A2A_PIN_REFUSAL_UNRECORDED,
    &A2A_EXTENDED_CARD_BUILD_FAILED,
    &A2A_NO_CSPRNG_CALLBACK,
    &A2A_PUSHBACK_NOT_DELIVERED,
    &A2A_OWN_CARD_BUILD_FAILED,
    &A2A_REFUSE_SERVE_CARD,
    &A2A_INTERRUPTED_TASK_UNRESUMED,
    &A2A_INBOUND_TASK_UNOPENED,
    &A2A_INBOUND_TASK_UNRECORDED,
    &A2A_OUTBOUND_CRED_UNLEASED,
    &A2A_AGENT_BINDING_UNSPEAKABLE,
    &A2A_RELAY_THREAD_INCOMPLETE,
    &A2A_PUSH_NOTIFY_UNDELIVERED,
    &A2A_STREAM_EMPTY,
    &A2A_RELAYED_STREAM_REFUSED,
    &A2A_STREAM_RELAY_INCOMPLETE,
    &A2A_RELAYED_OUTCOME_UNRECORDED,
    &A2A_RELAYED_SUBMISSION_FAILED,
    &A2A_BREAKER_REFUSAL_UNRECORDED,
    &A2A_FAILURE_UNRECORDED,
    &A2A_TASK_ROWS_UNREADABLE,
    &A2A_TASK_STATE_UNREAD,
    &A2A_CARD_FETCH_PANICKED,
    &A2A_REVERIFY_CADENCE_UNPARSED,
    &A2A_CARD_CERT_NO_SPKI,
    &A2A_PUSH_OUTCOME_UNCHAINED,
    &A2A_DISPATCH_UNRECORDED,
    &A2A_PUSH_CALLBACK_UNPERSISTED,
    &A2A_PUSH_CONFIG_UNDELETED,
    &A2A_PUSH_REARM_FAILED,
];

#[cfg(test)]
#[path = "a2a/tests/diagnostics_tests.rs"]
mod diagnostics_tests;
