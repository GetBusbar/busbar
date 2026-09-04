<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# Voice-DoD finish checklist — the exact remaining steps to the last 1/11

Execution-ready recipe consolidating this session's mapping. Dev is green at 10/11; the sole RED is
`NO-DEFERRAL --strict-done`, which arms only when voice reaches full DoD. Everything below is BUILD
(the design is already adversarially audited in the sibling playbook docs cited per step). Each numbered
block is one self-contained, gate-green, money-byte-identical increment; land and push before the next.

Money-path safety note: the byte-identity oracles are all LLM-plane (`egress_differential`,
`on_exhausted`, `crossproto_delivery_billing`, `pool_upstream_creds`). Voice has its OWN D2 lease path,
so none of the work below touches the billing corpus — byte-identity holds by construction. Verify it
anyway at each push (it is cheap).

Per-increment gate battery (all must pass before push):
`cargo build --workspace` · `cargo build --no-default-features` · `cargo clippy --workspace --all-targets -- -D warnings` (0/0)
· `cargo fmt --check` · `./scripts/plane-purity-lint.sh --check` (TOTAL 0 / BACKWARDS 0) · config-schema additive-only
· `./scripts/plane-delete-test.sh --all` (four planes) · `cargo test --workspace` · `cargo test -p busbar-voice --features runtime`
· `bash testing/voice-conformance/voice-conformance.sh` (0 failures) · `./scripts/structure-lint.sh` · `python3 scripts/public-hygiene-lint.py`.

---

## A. The mint/SDP live legs (REQUIRED — `prod-composition.md` §1–2, `t2-webrtc.md` §2/§4/§5)

The bar is **mock-tested to LLM-egress parity**, NOT credential-gated: CI never dials a real provider for
any plane. Mirror the LLM egress pattern — the owned hyper `EngineClient`
(`crates/busbar-substrate/src/egress/engine/client.rs:49`, `.request()` at `:105`), built via
`busbar_substrate::proxy::build_egress_client(&EngineSpec::pooled_webpki(..))`; tests point a lane at the
loopback `busbar_core::test_support::MockServer` (`:225`, `.base_url()` → 127.0.0.1) and the REAL client dials it.

- **A1. Concrete HTTPS `TokenMinter`** (`crates/busbar-voice/src/topology/webrtc.rs`, trait at `:51`). Real
  `POST /v1/realtime/client_secrets` with the real key over `EngineClient`. Add: TTL clamp (default 600s,
  clamp `[10,7200]`) on the request `expires_after.seconds`; assert the returned value has the `ek_` prefix
  before returning; stamp `OpenAI-Safety-Identifier` = the caller-identity session binding. Only the trait +
  a `FakeMinter` (`topology/tests.rs:184`) exist today. Test (loopback): clamp applied, `ek_` prefix asserted,
  Safety-Identifier header sent, real key NEVER in the browser-facing response.
- **A2. SDP broker one-shot + `rtc_<call_id>` correlation** (net-new handler). Accept `application/sdp`,
  `POST /v1/realtime/calls` with `Authorization: Bearer ek_…`, return the SDP answer, **preserve the
  `Location: /v1/realtime/calls/rtc_<call_id>` header verbatim**, and thread `rtc_<call_id>` into BOTH the
  durable `VoiceSessionRow` (`runtime/scope.rs`) AND the sideband dial URL. This is `t2-webrtc.md` §5 risk 3
  (highest risk): a mismatch silently governs call A while media flows on call B. Make `rtc_<call_id>` the
  single correlation key; assert it end-to-end (broker → scope row → sideband URL) in a conformance test
  BEFORE wiring the route.
- **A3. Replace the mount.rs 501** (`crates/busbar-voice/src/mount.rs`, `open_governed` `Ok(())` arm at
  `:320`). The WebRTC mint + SDP + sideband paths serve for real via A1/A2, keeping `run_gauntlet_session`
  FIRST (verify-before-charge) intact. Telephony/Twilio may stay a documented non-marker deferral.
- Deferrable, do NOT build (out of T2 scope per `prod-composition.md` §3/§4): live Twilio, a real
  `ToolExecutor` beyond echo, a nonzero `Pricing` book (the hard-stop mechanism is proven without it).

## B. The 7 isomorphism capability cells (`capability-equality-resolution.md`)

Prerequisite for B2–B4/B6: thread the production `EngineHost` into the voice runtime — wire
`build_runtime_hosted` (`crates/busbar-voice/src/runtime/mod.rs`) so the session-open/dial path can reach the
host seams (today it binds `LocalMeteringPort`/`EchoToolExecutor`; `build_runtime` stays the dev/test path).

- **B1. egress-auth** — inject the provider credential / webrtc `ek_` through the one egress mechanism
  (`DECLS.egress_auth_headers`, currently `None` in `lib.rs`). Foundational for A. Test: the dial/mint carries
  the resolved header via `CredentialProvider::headers_for`.
- **B2. hooks-gate** — call `hooks::gate::decide` via `EngineHost::gate_decide` at session-open admission.
  Slot into `SessionGauntlet::verify_destination` (`topology/mod.rs:125`, today only a destination-denial
  check) — the gauntlet needs a host handle threaded in (B-prereq). Mirror `mcp/method.rs:1557`. Test: a
  rewrite/reject hook refuses a session-open before charge.
- **B3. hooks-tap** — run the rewrite chain over voice frames via the neutral `transform_over` host seam
  (already built for MCP/A2A). Site: `runtime/session.rs` frame handling. Test: a rewrite hook edits a frame.
- **B4. breaker-trip / breaker-fastfail** — wire the core breaker ABI (seam-audit-D) into the dial/
  session-open path: classify a fatal dial, and admission-before-dial against a tripped provider cell. Two
  cells, one wiring. Tests: a tripped cell fast-fails the open; a fatal dial trips it.
- **B5. metrics** — put voice on the real `/metrics` scrape (it declares `VOICE_SESSION_LEASE_EXHAUSTED` in
  `diagnostics.rs` but is not scraped until booted). Lands with the default-on arming (D). Test: the counter
  appears on a scrape.
- **B6. catalogue** — either a `streams:` named-def registry (`named_def_list`/`registry_contains`, currently
  `None`) OR argue N/A if voice's singular `streams:` section genuinely has no named registrations (it is a
  SINGULAR section, not a map — N/A is defensible; state the ≥60-char reason).

Each cell lands with its proving test in `crates/busbar-voice/**/tests/` (or `_tests.rs`). The four already
argued N/A in the resolution doc (failover-reroute, disposition, trust-pinning, net-guard) carry over.

## C. De-skeleton (`de-skeleton-plan.md` — most are now stale-reword; code is done)

Remove/reword the 21 `SKELETON` + `dev-only until DoD` markers across `lib.rs`, `ir/mod.rs`, `ir/usage.rs`,
`runtime/mod.rs`, `runtime/session.rs`, plus the stale `diagnostics.rs:14` ("not yet booted") and the stale
evidence in `gate-no-deferral.md:32-40`. This must land WITH the arming (D) so the no-deferral floor-count
stays consistent (removing an allowlisted marker fails the gate until the allowlist is updated in lock-step).

## D. Atomic arming (LAST — one commit; `gate-no-deferral.md` §3.4, and the two ledgers)

All of D lands together (the doctrine gates cross-check each other):

- **D1. Boot into default** — add `plane-voice` to `default` in `crates/busbar/Cargo.toml:75` (voice becomes
  default-on AND deletable, exactly like `plane-mcp`/`plane-a2a`). `handler: Some(_)` + `verbs` non-empty in
  the default build (`lib.rs`). `busbar_voice::PLANE_DECL` already `push`ed in `main.rs` behind the feature.
  **← this is the owner-confirm point: it ships voice serving in the default binary.**
- **D2. capability-equality ledger** (`qa/capability-equality.json` + `crates/busbar/tests/capability_equality.rs`):
  add `voice-client`/`voice-server` to `planes`, add all 26 directional cells (proven/N-A per B, no `missing`
  — the oracle EQUALITY group requires 0 missing), widen the `PLANES` const + its verbatim assertion, flip the
  `PLANE_CRATE_LEDGER_COLUMNS` voice row, retire `VOICE_PENDING_COLUMN` + its exemption. Proving tests land in
  the SAME commit.
- **D3. plane-isomorphism** (`crates/busbar/tests/plane_isomorphism.rs` + `qa/plane-hook-isomorphism.allow`):
  add voice to `installed_decls` + `PLANE_LEDGER_COLUMNS` + the axis assertion; any voice hook that is
  None-while-a-sibling-is-Some gets a ledger-anchored allow row or real wiring.
- **D4. no-deferral** — with C done and the state assertion (handler Some, in default) satisfied, update the
  allowlist floor and run `./scripts/no-deferral-gate.sh --strict-done` → GREEN.

## Final verification → 11/11

`./scripts/verify-1.6.0-done.sh` → 11/11 groups GREEN. Push dev. Confirm the CI umbrella + Voice/MCP/A2A
conformance all `success`. Prune worktrees.

## Blocker on record

As of this writing the build is blocked by the **weekly Opus rate limit (resets Sep 8, 10am PT)** — the two
build agents (mint/SDP legs; arming blueprint) were killed by a 429 before producing anything. The steps
above are turnkey the moment capacity is available (post-reset, on a non-Opus model, or by the owner).
