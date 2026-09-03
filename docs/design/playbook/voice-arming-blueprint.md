<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# Voice-arming blueprint — the two-column atomic edit to the doctrine ledgers

*Code-grounded, exhaustive spec for "arming" the `busbar-voice` plane in the two doctrine
gates — `crates/busbar/tests/capability_equality.rs` (+ `qa/capability-equality.json`) and
`crates/busbar/tests/plane_isomorphism.rs` (+ `qa/plane-hook-isomorphism.allow`). This file
changes NO production code, tests, or ledgers; it is the checklist that drives the arming
commit.*

## Decision context (fixed inputs)

- Voice **ships default-ON + deletable**: `plane-voice` is added to `busbar`'s `default`
  feature set (`crates/busbar/Cargo.toml:75`), exactly as `plane-mcp` / `plane-a2a` are.
  `plane-voice = ["dep:busbar-voice", "busbar-voice?/runtime", "busbar-core/plane-voice"]`
  (`Cargo.toml:101`) already turns the runtime on, so under `default` the installed
  `PLANE_DECL` has `routes` / `hydrate` / `start` / `default_section` / `build_runtime` all
  `Some` (the `#[cfg(feature = "runtime")]` arms in `crates/busbar-voice/src/lib.rs`). Strong-form
  deletability stays proven by `scripts/plane-delete-test.sh voice`.
- **Twilio g711 IS in scope** — the telephony media-stream leg is a real ingress/egress, so the
  net-guard "revisit on a request-authored callback" caveat is called out per-cell below.
- Voice arms as **TWO directional columns**: `voice-client` (the dialed WSS to the realtime
  provider + telephony media egress — one session pinned to one provider socket) and
  `voice-server` (the inbound session-open front door — browser sideband WS + Twilio media
  webhook). This mirrors the mcp/a2a client/server split.

This RETIRES the pending-voice posture: `VOICE_PENDING_COLUMN`
(`capability_equality.rs:78`) and its totality-check exemption
(`capability_equality.rs:386-388`) are deleted, because voice now answers to two REAL ledger
columns rather than a placeholder identity.

---

## 0. One gate rule that overrides the resolution doc's cited test paths

`capability_equality.rs:207` demands every `proven` cell's `test` path
**`file.contains("/tests/") || file.ends_with("_tests.rs")`**. The voice runtime's existing
assertions live in `crates/busbar-voice/src/runtime/tests.rs` and `.../runtime/scope.rs` —
**neither** matches (`runtime/tests.rs` is not under a `/tests/` dir and ends `/tests.rs`, not
`_tests.rs`). So the resolution doc's instruction to point voice cells "at `runtime/tests.rs`"
would make the gate RED with "not a test location".

**Consequence for arming:** the two PROVEN capabilities (`audit-chain`,
`governance-budget`) need their proving assertions in a **gate-valid** file. Use the plane's
own established pattern — a `#[path = "tests/<name>_tests.rs"] mod <name>_tests;` file under
`crates/busbar-voice/src/tests/` (as `config.rs:184`, `mount.rs:410`, `diagnostics.rs:44`
already do). Those paths contain `/tests/` **and** end `_tests.rs`, so they clear the gate; gate
them `#[cfg(all(test, feature = "runtime"))]` so they compile with the durable engine / lease.
The assertions to relocate/wrap already exist and pass:
`runtime/tests.rs::session_scope_reattach_and_foreign_owner_refusal` (durable session chain via
`SealedEvent`/`tail_hash` genesis, `scope.rs:143`) for audit-chain, and
`runtime/tests.rs::settle_past_cap_hard_closes_the_carrier` +
`host_lease_reserves_settles_and_hard_closes_at_the_real_cap` for governance-budget.

---

## 1. The 26 cells (13 capabilities × {voice-client, voice-server})

Tally: **4 PROVEN** (audit-chain, governance-budget — both legs), **13 NOT-APPLICABLE**,
**9 MISSING** (blocking; the honest queue this arming grows, exactly as the resolution doc
warned). The missing set is printed by `scripts/capability-equality-summary.py`; it is legal and
green as long as the pin matches reality.

### voice-client (the dial leg: outbound WSS to OpenAI Realtime / Gemini Live / Twilio media)

| # | capability | verdict | grounding |
|---|---|---|---|
| 1 | breaker-trip | **MISSING** | the core breaker ABI exists (`plane_host::EngineHost::breaker_admit/settle/record`, `plane_host/mod.rs:363-395`) but is not wired into the dial/session-open path. See §2.1. |
| 2 | breaker-fastfail | **MISSING** | no admission-before-dial against a tripped provider cell. See §2.2. |
| 3 | failover-reroute | **N/A** | a duplex session is pinned to one provider socket for its whole lifetime, so there is no pre-first-byte candidate set to walk on the dial leg; a dropped session re-dials as a NEW session, never a mid-session reroute, so `failover::walk` has nothing to select over here. |
| 4 | hooks-tap | **MISSING** | no observe/transform path over the session-open params — the same tap gap as MCP/A2A pre-arming. See §2.3 (one wiring closes cells 4 both legs). |
| 5 | hooks-gate | **MISSING** | no `hooks::gate::decide` at session-open admission. See §2.4 (one wiring closes both legs). |
| 6 | audit-chain | **PROVEN** | `crates/busbar-voice/src/tests/audit_chain_tests.rs::an_opened_voice_session_seals_a_genesis_event_and_survives_reattach_on_the_durable_chain` (new file, §0). |
| 7 | governance-budget | **PROVEN** | `crates/busbar-voice/src/tests/governance_budget_tests.rs::a_session_lease_settled_past_its_cap_hard_closes_and_refuses_further_spend` (new file, §0). |
| 8 | disposition | **N/A** | disposition classifies a discrete upstream ANSWER (proto Stage 1 → `breaker::classify`); a duplex frame stream has no per-hop answer to normalize — a fatal provider frame closes the session rather than resolving into a Disposition, so Stage 2 has nothing to classify on the dial leg. |
| 9 | metrics | **MISSING** | `diagnostics.rs` declares `VOICE_SESSION_LEASE_EXHAUSTED` but no plane-labelled upstream-leg series reaches a real `/metrics` scrape yet. See §2.5. |
| 10 | trust-pinning | **N/A** | voice providers (OpenAI Realtime, Gemini Live) are operator-declared config endpoints, not peer-published artifacts; there is no upstream-authored schema digest or card to pin — exactly the argument the `llm` dial cell is not-applicable under. |
| 11 | net-guard | **N/A** | the provider WSS is an operator-configured endpoint and no request-authored URL reaches the dial, so there is no SSRF surface on the outbound leg (the `net_guard` resolve→pin→guard at `topology::dial_provider` is defense-in-depth, not a request-URL guard); revisit if a T3 request-authored callback URL is ever dialed, like a2a-server push delivery. |
| 12 | egress-auth | **MISSING** | the provider credential / WebRTC ephemeral token is not injected through the one egress mechanism — `DECLS.egress_auth_headers = None` (`lib.rs:271`). See §2.6. |
| 13 | catalogue | **N/A** (defensible; see §2.7) | the voice plane's config is the SINGULAR `streams:` section, not a named-definition map like `tools:`/`agents:`, so there are no per-item registrations for `catalogue::entitled` to walk and trust-gate; `named_def_list` / `registry_contains` are `None` by construction, so no caller-visible catalogue exists on this plane. |

### voice-server (the front door: inbound session-open — browser sideband WS + Twilio webhook)

| # | capability | verdict | grounding |
|---|---|---|---|
| 1 | breaker-trip | **N/A** | the voice front door is an inbound role; opening a session records no upstream target availability, so there is no core breaker cell to trip here — the outbound provider dial a session triggers is the voice-client cell's subject, the same shape mcp-server/a2a-server breaker-trip are N/A under. |
| 2 | breaker-fastfail | **N/A** | the inbound session-open has no dispatch against an upstream to make fast; admission-before-dial against a tripped provider cell belongs to the voice-client dial leg, not the front door that merely accepts the session. |
| 3 | failover-reroute | **N/A** | the front door is an inbound role with no candidate set to walk; failover selection over interchangeable provider members is the outbound voice-client leg's decision, exactly as a2a-server reroute is not-applicable on the receiving side. |
| 4 | hooks-tap | **MISSING** | no observe/transform over the inbound session-open params yet. Closed by the same one wiring as voice-client cell 4 (§2.3), one battery both directions. |
| 5 | hooks-gate | **MISSING** | no `hooks::gate::decide` at inbound admission yet. Closed by the same one wiring as voice-client cell 5 (§2.4). |
| 6 | audit-chain | **PROVEN** | `crates/busbar-voice/src/tests/audit_chain_tests.rs::an_inbound_session_open_lands_a_sealed_genesis_event_the_front_door_wrote` (new file, §0). |
| 7 | governance-budget | **PROVEN** | `crates/busbar-voice/src/tests/governance_budget_tests.rs::the_session_lease_bills_the_presenting_key_and_refuses_past_the_cap_with_a_hard_close` (new file, §0). |
| 8 | disposition | **N/A** | disposition classifies an upstream's ANSWER; the inbound session-open has no upstream answer to normalize, so Stage-1/Stage-2 classification has no subject here — the same argument mcp-server and a2a-server disposition are not-applicable under. |
| 9 | metrics | **MISSING** | no plane-labelled front-door series on a real `/metrics` scrape yet. Closed alongside voice-client cell 9 (§2.5). |
| 10 | trust-pinning | **N/A** | the browser-sideband and telephony callers that reach the front door publish no artifact (no schema digest, agent card, or SPKI) for the trust lifecycle to pin; there is no peer-authored object whose drift could be detected, unlike the a2a-server card-fingerprint cell. |
| 11 | net-guard | **N/A** | the inbound session listener derives no outbound destination of its own; the one outbound a session triggers is the provider dial, guarded (defense-in-depth) on the voice-client leg, so the front door has no request-authored egress to SSRF-guard — the mcp-server net-guard argument. |
| 12 | egress-auth | **N/A** | the front door's only outbound is the provider dial, whose credential injection is the voice-client egress-auth cell; the inbound caller's own bearer is authenticated by the Auth plugin, which is not egress credential planning — the same split mcp-server egress-auth is not-applicable under. |
| 13 | catalogue | **N/A** (defensible; see §2.7) | the voice plane declares the SINGULAR `streams:` section, not a named-definition map, so the front door exposes no per-item registry for `catalogue::entitled` to walk; `named_def_list` / `registry_contains` are `None`, so there is no caller-visible catalogue surface to trust-gate. |

---

## 2. Concrete wiring for the feature-work capabilities (the MISSING cells)

Prerequisite for §2.1–§2.4 (breaker + hooks): **thread the production `Arc<dyn EngineHost>` into
the voice runtime.** Today `runtime::build_runtime_hosted` (`runtime/mod.rs:179`) takes only
`Arc<dyn MeteringHost>` (the D2 money hop). The `EngineHost` supertrait
(`plane_host/mod.rs:1157`) already carries every seam these cells need
(`gate_decide:974`, `transform_over:1012`, `breaker_admit:363`, `breaker_settle:374`,
`breaker_record_success:384`, `breaker_record_signal:389`), and the composition root holds the
live `Arc<dyn EngineHost>` (it already upcasts it to the `MeteringHost` slice at the call site).
So the wiring precondition is: **widen `build_runtime_hosted` to accept `Arc<dyn EngineHost>`**
(keep the `MeteringHost` upcast for the money hop) and stash it on `VoiceRuntime` so the session
pump (`runtime/session.rs`) and the dial path (`topology/mod.rs`) can reach the host seams. This
is a body/entry change, NOT a `PlaneDecl::build_runtime` fn-pointer ABI change (that pointer stays
`build_runtime` and remains host-less by design — the hosted entry is a sibling).

### 2.1 breaker-trip × voice-client
- **Seam:** `EngineHost::breaker_record_signal` / `breaker_record_success` (`plane_host/mod.rs:389,384`).
- **Site:** the provider dial in `crates/busbar-voice/src/topology/mod.rs` (`dial_provider`): on a
  dial/connect failure or a fatal provider close, record the failure signal into the one core cell,
  keyed by the session's `(pool, lane)`.
- **Prereq:** `EngineHost` threaded via `build_runtime_hosted` (above).
- **Test to write:** `crates/busbar-voice/src/tests/breaker_tests.rs::a_hard_down_provider_records_into_the_core_cell_and_opens_it`
  — a stub provider that refuses the dial; assert the core cell opens (read back through the host).
  Delete the `breaker_record_signal` call to prove it red.

### 2.2 breaker-fastfail × voice-client
- **Seam:** `EngineHost::breaker_admit` (`plane_host/mod.rs:363`) — the admission probe.
- **Site:** BEFORE `dial_provider` opens the socket, call `breaker_admit(pool, lane)`; on refusal,
  fail the session-open in milliseconds with the breaker's `Retry-After`
  (`breaker_retry_after_secs:395`) instead of waiting out the dial timeout.
- **Prereq:** as §2.1.
- **Test:** `crates/busbar-voice/src/tests/breaker_tests.rs::a_tripped_provider_cell_refuses_a_fresh_session_open_before_the_dial`.

### 2.3 hooks-tap × {voice-client, voice-server} (one wiring closes both)
- **Seam:** `EngineHost::transform_over` (`plane_host/mod.rs:1012`) — the plane names no core hook
  symbol (the Seam-B inversion), exactly as the MCP/A2A tap wirings do.
- **Site:** the governed session-open in `crates/busbar-voice/src/mount.rs`
  (`run_gauntlet_session`), AFTER the gate (§2.4) and BEFORE the provider credential is leased /
  the dial opens: run the resolved rewrite-hook chain over the session-open params (the `streams:`
  request projection — model, voice, session posture). The open sits before the dial, so one
  wiring covers both directions (`voice-client` + `voice-server`), the "one battery both
  directions" fact the mcp/a2a tap cells rely on.
- **Prereq:** `EngineHost` threaded (§2 preamble).
- **Test:** `crates/busbar-voice/src/tests/hook_tap_tests.rs::a_rewrite_hook_edits_the_session_open_params_before_the_provider_dial`
  — register a rewrite hook, drive a session-open through `run_gauntlet_session`, assert the dial
  saw the rewritten params; BYTE-IDENTICAL passthrough when no rewrite hook is attached. Flips
  BOTH cells 4 to PROVEN pointing at this one test.

### 2.4 hooks-gate × {voice-client, voice-server} (one wiring closes both)
- **Seam:** `EngineHost::gate_decide` (`plane_host/mod.rs:974`) — the same generic two-armed
  `GateVerdict::{Proceed, Reject}` MCP fires at `method.rs` and A2A at `receive.rs`.
- **Site:** `run_gauntlet_session` (`mount.rs`) at inbound admission, over the session-open's
  `IrFacts` projection (ingress protocol = voice, method = session-open). A `Reject` short-circuits
  the open before any dial. The open precedes the dial, so one gate covers both columns.
- **Prereq:** `EngineHost` threaded (§2 preamble).
- **Test:** `crates/busbar-voice/src/tests/hook_gate_tests.rs::streams_hooks_reject_all_refuses_a_session_open`.

### 2.5 metrics × {voice-client, voice-server}
- **Registry:** the process-global `metrics` recorder scraped by the core `/metrics` endpoint.
- **Site:** the session pump (`runtime/session.rs`) and dial leg (`topology/mod.rs`): emit
  plane-labelled families (a session-open/attempt counter with `plane="voice"` for the front door,
  an upstream-attempt/failure counter for the dial leg), mirroring the mcp/a2a client-leg families
  (`busbar_upstream_attempts_total` / `..._failures_total`).
- **Prereq:** voice booted into the composition root (default-ON satisfies this) so a real scrape
  sees the series; no `EngineHost` thread needed for emission.
- **Test:** extend the real-scrape integration
  `crates/busbar-core/tests/plane_integration.rs` (add a `voice` assertion to the existing
  multi-plane scrape) OR a plane-local `crates/busbar-voice/src/tests/metrics_tests.rs::a_voice_session_appears_on_a_real_metrics_scrape_under_its_plane_label`.
  Flips BOTH cells 9.

### 2.6 egress-auth × voice-client
- **Seam:** `ProtocolDecl::egress_auth_headers` (`proto.rs:701`) — the ONE egress credential
  mechanism (`egress_auth/mod.rs:219`), never a caller token passed through.
- **Site:** `crates/busbar-voice/src/lib.rs:271` — set `DECLS.egress_auth_headers` from `None` to
  `Some(<EgressAuthHeaders builder>)` that plans the provider bearer / WebRTC ephemeral token (and
  the Twilio media-stream credential) onto the dial's headers. Follows the pattern the LLM plane's
  Bedrock SigV4 signer uses to hand in a scheme (`egress_auth/mod.rs:15`).
- **Test:** `crates/busbar-voice/src/tests/egress_tests.rs::the_provider_dial_carries_the_planned_credential_and_never_a_caller_token`.

### 2.7 catalogue × {voice-client, voice-server} — argued N/A, wiring recorded either way
- **N/A argument (adopted):** `streams:` is a **SINGULAR** config section (the top-level noun that
  declares the plane, `lib.rs:186`), NOT a named-definition map like `tools:` / `agents:`. There are
  no named stream registrations, so `catalogue::entitled` has no per-item set to walk and gate; the
  decl states this structurally — `named_def_list: None`, `named_def_get: None`,
  `registry_contains: None` (`lib.rs:214-216`). "What this caller may SEE" therefore has no subject
  on this plane. (Both voice columns carry this same N/A, ≥60-char reason in §1.)
- **What would make it PROVEN instead** (recorded so a future config-grammar slice can flip it): give
  `streams:` a named-definition sub-map (named stream defs), wire `named_def_list` /
  `registry_contains` on `PLANE_DECL`, and add
  `crates/busbar-voice/src/tests/catalogue_tests.rs::a_key_sees_only_the_stream_defs_it_is_entitled_to`.
  Until a named registry exists, N/A is the honest verdict.

---

## 3. Atomic-arming edits

### (a) `qa/capability-equality.json`

**Add two `planes[]` entries** (into the `"planes"` object, after `"a2a-server"`):

```json
    "voice-client": "busbar's outbound duplex leg: the dialed WSS to the realtime voice provider (OpenAI Realtime / Gemini Live) and the telephony media egress (Twilio g711); one session is pinned to one provider socket for its whole lifetime",
    "voice-server": "busbar's voice front door: inbound session-open ingress -- the browser sideband WebSocket and the telephony (Twilio) media-stream webhook -- that opens a governed duplex session"
```

**Append all 26 cells** to the `"cells"` array:

```json
    { "capability": "breaker-trip", "plane": "voice-client", "state": "missing" },
    { "capability": "breaker-trip", "plane": "voice-server", "state": "not-applicable",
      "reason": "the voice front door is an inbound role; opening a session records no upstream target availability, so there is no core breaker cell to trip here -- the outbound provider dial a session triggers is the voice-client cell's subject, the same shape mcp-server/a2a-server breaker-trip are N/A under." },
    { "capability": "breaker-fastfail", "plane": "voice-client", "state": "missing" },
    { "capability": "breaker-fastfail", "plane": "voice-server", "state": "not-applicable",
      "reason": "the inbound session-open has no dispatch against an upstream to make fast; admission-before-dial against a tripped provider cell belongs to the voice-client dial leg, not the front door that merely accepts the session." },
    { "capability": "failover-reroute", "plane": "voice-client", "state": "not-applicable",
      "reason": "a duplex voice session is pinned to one provider socket for its whole lifetime, so there is no pre-first-byte candidate set to walk on the dial leg; a dropped session re-dials as a NEW session, never a mid-session reroute, so failover::walk has nothing to select over here." },
    { "capability": "failover-reroute", "plane": "voice-server", "state": "not-applicable",
      "reason": "the front door is an inbound role with no candidate set to walk; failover selection over interchangeable provider members is the outbound voice-client leg's decision, exactly as a2a-server reroute is not-applicable on the receiving side." },
    { "capability": "hooks-tap", "plane": "voice-client", "state": "missing" },
    { "capability": "hooks-tap", "plane": "voice-server", "state": "missing" },
    { "capability": "hooks-gate", "plane": "voice-client", "state": "missing" },
    { "capability": "hooks-gate", "plane": "voice-server", "state": "missing" },
    { "capability": "audit-chain", "plane": "voice-client", "state": "proven",
      "test": "crates/busbar-voice/src/tests/audit_chain_tests.rs::an_opened_voice_session_seals_a_genesis_event_and_survives_reattach_on_the_durable_chain",
      "note": "the DurableHandleEngine seals a genesis SealedEvent/tail_hash at SessionHandle::open (scope.rs) and the per-turn cursor bumps chain onto it; the relocated assertion (from runtime/tests.rs::session_scope_reattach_and_foreign_owner_refusal) drives open->bump->reattach and reads the durable row back. Runtime-gated; placed under src/tests/ so the equality gate's /tests/ location rule is met." },
    { "capability": "audit-chain", "plane": "voice-server", "state": "proven",
      "test": "crates/busbar-voice/src/tests/audit_chain_tests.rs::an_inbound_session_open_lands_a_sealed_genesis_event_the_front_door_wrote",
      "note": "the inbound session-open through run_gauntlet_session seals the genesis event the front door wrote; asserts the chain read-back is non-empty (an empty read is a failure, not a pass)." },
    { "capability": "governance-budget", "plane": "voice-client", "state": "proven",
      "test": "crates/busbar-voice/src/tests/governance_budget_tests.rs::a_session_lease_settled_past_its_cap_hard_closes_and_refuses_further_spend",
      "note": "the D2 HostLease settle-past-cap hard-close over plane_host::MeteringHost (metering.rs); relocated from runtime/tests.rs::settle_past_cap_hard_closes_the_carrier + host_lease_reserves_settles_and_hard_closes_at_the_real_cap into a /tests/ location for the gate." },
    { "capability": "governance-budget", "plane": "voice-server", "state": "proven",
      "test": "crates/busbar-voice/src/tests/governance_budget_tests.rs::the_session_lease_bills_the_presenting_key_and_refuses_past_the_cap_with_a_hard_close",
      "note": "the session lease attributes spend to the presenting key and refuses past the cap with a hard close, host-side through HostMeteringPort." },
    { "capability": "disposition", "plane": "voice-client", "state": "not-applicable",
      "reason": "disposition classifies a discrete upstream ANSWER (proto Stage 1 -> breaker::classify); a duplex frame stream has no per-hop answer to normalize -- a fatal provider frame closes the session rather than resolving into a Disposition, so Stage 2 has nothing to classify on the dial leg." },
    { "capability": "disposition", "plane": "voice-server", "state": "not-applicable",
      "reason": "disposition classifies an upstream's ANSWER; the inbound session-open has no upstream answer to normalize, so Stage-1/Stage-2 classification has no subject here -- the same argument mcp-server and a2a-server disposition are not-applicable under." },
    { "capability": "metrics", "plane": "voice-client", "state": "missing" },
    { "capability": "metrics", "plane": "voice-server", "state": "missing" },
    { "capability": "trust-pinning", "plane": "voice-client", "state": "not-applicable",
      "reason": "voice providers (OpenAI Realtime, Gemini Live) are operator-declared config endpoints, not peer-published artifacts; there is no upstream-authored schema digest or card to pin -- exactly the argument the llm dial cell is not-applicable under." },
    { "capability": "trust-pinning", "plane": "voice-server", "state": "not-applicable",
      "reason": "the browser-sideband and telephony callers that reach the front door publish no artifact (no schema digest, agent card, or SPKI) for the trust lifecycle to pin; there is no peer-authored object whose drift could be detected, unlike the a2a-server card-fingerprint cell." },
    { "capability": "net-guard", "plane": "voice-client", "state": "not-applicable",
      "reason": "the provider WSS is an operator-configured endpoint and no request-authored URL reaches the dial, so there is no SSRF surface on the outbound leg (the net_guard resolve->pin->guard at topology::dial_provider is defense-in-depth, not a request-URL guard); revisit if a T3 request-authored callback URL is ever dialed, like a2a-server push delivery." },
    { "capability": "net-guard", "plane": "voice-server", "state": "not-applicable",
      "reason": "the inbound session listener derives no outbound destination of its own; the one outbound a session triggers is the provider dial, guarded (defense-in-depth) on the voice-client leg, so the front door has no request-authored egress to SSRF-guard." },
    { "capability": "egress-auth", "plane": "voice-client", "state": "missing" },
    { "capability": "egress-auth", "plane": "voice-server", "state": "not-applicable",
      "reason": "the front door's only outbound is the provider dial, whose credential injection is the voice-client egress-auth cell; the inbound caller's own bearer is authenticated by the Auth plugin, which is not egress credential planning -- the same split mcp-server egress-auth is not-applicable under." },
    { "capability": "catalogue", "plane": "voice-client", "state": "not-applicable",
      "reason": "the voice plane's config is the SINGULAR streams: section, not a named-definition map like tools:/agents:, so there are no per-item registrations for catalogue::entitled to walk and trust-gate; named_def_list and registry_contains are None by construction, so no caller-visible catalogue exists on this plane." },
    { "capability": "catalogue", "plane": "voice-server", "state": "not-applicable",
      "reason": "the voice plane declares the SINGULAR streams: section, not a named-definition map, so the front door exposes no per-item registry for catalogue::entitled to walk; named_def_list/registry_contains are None, so there is no caller-visible catalogue surface to trust-gate." }
```

Post-edit invariants: 13 caps × 7 planes = **91 cells** (65 existing + 26). Proven count rises
by 4 (still ≥ `MIN_PROVEN` 20). N/A reasons all ≥ 60 chars. Missing queue grows by 9.

### (b) `crates/busbar/tests/capability_equality.rs`

1. **Widen `PLANES`** (`:48`) to 7:
   ```rust
   const PLANES: [&str; 7] = [
       "llm", "mcp-client", "mcp-server", "a2a-client", "a2a-server",
       "voice-client", "voice-server",
   ];
   ```
2. **Update the verbatim assertion** in `the_gates_own_constants_are_the_doctrines` (`:312-329`)
   — the `assert_eq!(PLANES, [ ... ])` literal must match the new 7-wide array (append
   `"voice-client", "voice-server"`). Leave the "owner's ruling" prose; add a clause that the two
   voice directions join the two bidirectional protocols.
3. **Flip the `PLANE_CRATE_LEDGER_COLUMNS` voice row** (`:73`) from
   `("voice", &[VOICE_PENDING_COLUMN])` to `("voice", &["voice-client", "voice-server"])`.
4. **Retire `VOICE_PENDING_COLUMN`**: delete the const (`:76-78`) and the totality-check exemption
   block in `every_workspace_plane_crate_maps_to_at_least_one_ledger_column`
   (`:386-388` — the `if col == VOICE_PENDING_COLUMN { continue; }`). With voice now mapping to two
   real ledger columns, the loop validates both against `ledger_columns` (which now contains them),
   so the exemption is dead. Update the doc comments that reference the pending column
   (`:66-68`, `:76-78`, `:357-360`) to state voice is now a full two-column plane.

`MIN_CAPABILITIES` (12) and `MIN_PROVEN` (20) are unchanged and still satisfied.

### (c) `crates/busbar/tests/plane_isomorphism.rs`

The isomorphism gate reflects `PlaneDecl` **registry hooks** (`HOOK_FIELDS`, `:46-66`), NOT the 13
equality capabilities — so the 7 feature-work capabilities above create **no** isomorphism rows.
Voice's registry-hook Some/None (under `plane-voice` ⇒ runtime-on, from `lib.rs`): **Some** on
`routes`, `hydrate`, `start`, `default_section`, `build_runtime`; **None** on `admin_routes`,
`openapi`, `config_validate`, `registry_contains`, `reresolve_gates`, `retain_verify_gates`,
`on_swap`, `parse_endpoint`, `lower_endpoint`, `card_signing_domain`, `card_kid_prefix`.

Voice's five `Some` hooks create **no new asymmetries** and DO NOT stale any existing row (every
existing declared `None` — `llm`/`mcp`/`a2a` — remains `None`; voice being `Some` never removes a
sibling's `None`).

Voice's eleven `None` hooks are each **asymmetric** (a sibling is `Some`) → each needs a
ledger-anchored **allow row** (real wiring is NOT owed — these are config-grammar/registration/card
surfaces the singular-`streams:` plane genuinely lacks, the same class llm's `None`s are allowed
under):

| voice hook (None) | sibling(s) Some | verdict | anchor capability (cell exists for both voice columns) |
|---|---|---|---|
| `admin_routes` | mcp, a2a | allow row | catalogue |
| `openapi` | mcp, a2a | allow row | catalogue |
| `config_validate` | mcp, a2a | allow row | catalogue |
| `registry_contains` | mcp, a2a | allow row | catalogue |
| `reresolve_gates` | mcp, a2a | allow row | trust-pinning |
| `retain_verify_gates` | mcp, a2a | allow row | trust-pinning |
| `on_swap` | mcp | allow row | trust-pinning |
| `parse_endpoint` | mcp | allow row | egress-auth |
| `lower_endpoint` | mcp | allow row | egress-auth |
| `card_signing_domain` | a2a | allow row | trust-pinning |
| `card_kid_prefix` | a2a | allow row | trust-pinning |

Edits:

1. **`installed_decls`** (`:100-109`) — add, gated on the busbar-crate feature:
   ```rust
   #[cfg(feature = "plane-voice")]
   v.push(("voice", &busbar_voice::PLANE_DECL));
   ```
   (Add `busbar-voice` as a dev/optional dep of the `busbar` test target if not already linked via
   the `plane-voice` feature.)
2. **`PLANE_LEDGER_COLUMNS`** (`:79-83`) — add `("voice", &["voice-client", "voice-server"])`. The
   allow-row plane key `"voice"` resolves through this to BOTH ledger columns, so each anchor
   capability's cell must exist for `voice-client` AND `voice-server` — they do (all 26 cells land
   in edit (a)).
3. **Axis assertion** `the_reflected_hook_set_and_constants_are_the_doctrine` (`:358-364`) — widen
   the `assert_eq!(keys, vec!["llm", "mcp", "a2a"])` to `vec!["llm", "mcp", "a2a", "voice"]`.
4. `MIN_ASYMMETRIES` (10) and `MIN_HOOK_FIELDS` (15) unchanged — the allowlist grows from 16 to 27
   rows, still above the floor.

### (d) `qa/plane-hook-isomorphism.allow`

Append these **11 new rows** to `"asymmetries"` (do NOT add `"voice"` to the existing llm/mcp/a2a
rows — a separate row per hook keeps a voice-specific reason and avoids the "declared twice"
error; `(field, plane)` pairs stay unique):

```json
    { "field": "admin_routes",       "planes_none": ["voice"], "capability": "catalogue",     "reason": "the voice plane's streams: is a singular section, not a named-definition map, so it has no per-registration admin surface to mount" },
    { "field": "openapi",            "planes_none": ["voice"], "capability": "catalogue",     "reason": "the voice plane contributes no plane-owned OpenAPI path document; its duplex session ingress is not described as an OpenAPI fragment" },
    { "field": "config_validate",    "planes_none": ["voice"], "capability": "catalogue",     "reason": "the voice streams: grammar is validated through parse_section/default_section, not a separate plane-owned config_validate hook" },
    { "field": "registry_contains",  "planes_none": ["voice"], "capability": "catalogue",     "reason": "the voice plane keeps no named-registration registry to answer containment on; streams: is a singular section with no named stream defs" },
    { "field": "reresolve_gates",    "planes_none": ["voice"], "capability": "trust-pinning", "reason": "the voice plane pins no per-peer artifact (providers are operator-declared endpoints), so there are no container gates to re-resolve on a swap" },
    { "field": "retain_verify_gates","planes_none": ["voice"], "capability": "trust-pinning", "reason": "the voice plane retains no verify gates because it holds no pinned peer artifacts across generations" },
    { "field": "on_swap",            "planes_none": ["voice"], "capability": "trust-pinning", "reason": "endpoint hot-swap on generation change is an MCP-endpoint concern; the voice plane swaps no per-endpoint object, dialing an operator-configured provider socket" },
    { "field": "parse_endpoint",     "planes_none": ["voice"], "capability": "egress-auth",   "reason": "the parse-endpoint hook lowers the MCP client-endpoint config grammar; the voice plane has no such per-endpoint config section" },
    { "field": "lower_endpoint",     "planes_none": ["voice"], "capability": "egress-auth",   "reason": "the lower-endpoint hook is the MCP client-endpoint lowering; the voice plane lowers no endpoint config, dialing an operator-configured provider" },
    { "field": "card_signing_domain","planes_none": ["voice"], "capability": "trust-pinning", "reason": "agent-card signing identity is an A2A-only capability; the voice plane issues no signed card for a peer to verify" },
    { "field": "card_kid_prefix",    "planes_none": ["voice"], "capability": "trust-pinning", "reason": "the card key-id prefix is part of A2A-only agent-card signing; the voice plane mints no card key" }
```

Each `reason` is ≥ 40 chars (clears `plane_isomorphism.rs:209`); each `capability` is a declared
ledger capability (clears `:222`) whose cell exists for both `voice-client` and `voice-server`
(clears `:244`).

---

## 4. Commit-composition guardrails

- **This is one atomic ledger commit.** It must also CREATE the two gate-valid proving files
  `crates/busbar-voice/src/tests/audit_chain_tests.rs` and `.../governance_budget_tests.rs` (§0)
  with the four named fns, wired via `#[path = "tests/..._tests.rs"] mod ...;` and gated
  `#[cfg(all(test, feature = "runtime"))]` — otherwise the four PROVEN cells fail the file/fn
  existence check (`capability_equality.rs:213-230`). Their assertions are relocations of already-
  passing runtime tests, so no new behaviour is proven, only re-homed to a gate-valid path.
- **The 9 MISSING cells stay MISSING in this commit** — arming honestly grows the queue (resolution
  doc §"voice column"). Each is zeroed later by the §2 wiring + its named test, flipped to PROVEN in
  the SAME commit as that test (the ledger discipline). None of the §2 wiring is required for the
  arming commit to be green; missing is a legal, printed state.
- **Do not** point any voice PROVEN cell at `runtime/tests.rs` / `scope.rs` — those paths fail the
  gate's `/tests/` location rule (§0).
- After edit, re-run `cargo test -p busbar --test capability_equality --test plane_isomorphism`
  (default features, so `plane-voice` is on) plus `scripts/plane-delete-test.sh voice`.
