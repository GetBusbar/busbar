<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# Neutrality audit — findings ledger + mechanical prevention

Every finding from the multi-model both-directions audit matrix (store, ingress/egress, observability,
host-ABI, config/registry, gate-coverage, per-plugin llm/mcp/a2a, cross-plane graph, new-crate-diff,
plus an independent second-model re-audit). Each row: the finding, the FIX, and the MECHANICAL
PREVENTION (a gate or test that fails the build if it recurs) — because "audited once" is not "cannot
recur." Owner directive: fix all, prevent all, then re-audit from every angle / every model.

Verdicts that were CLEAN (no fix needed) are listed at the bottom for the record.

## Directional invariant (the thing being enforced)
`plane → core → store` is generic in both directions:
- REVERSE (plane names core): `plane-purity-lint --check` BACKWARDS = 0, **blocking in CI**. Solid.
- FORWARD (core names/serves a plane): must be equally blocking, at TOKEN and STRUCTURAL granularity.

---

## Findings requiring a fix + prevention

### F1 — host-ABI method NAMES carry plane vocabulary (token-level)
`plane_host/mod.rs`: `tool_pool_members(server)` (MCP), `card_sign` (A2A), `agent_defs` (A2A) — neutral
signatures, plane-named identifiers.
- **FIX:** route MCP through the existing neutral `plane_pool_members`; rename `card_sign`→`host_sign`,
  `agent_defs`→`plane_defs`; update MCP/A2A callers. (In flight.)
- **PREVENT:** extend `plane-abi-neutrality.sh`'s declaration-line scan from `busbar-plugin/hot/` to
  ALSO cover `busbar-substrate/src/plane_host/` + `busbar-core/src/hooks/`, with the role-noun banlist
  (`tool agent server card sampling task round prompt` + dialects), and WIRE IT INTO CI as blocking.
  Then a plane-named method on the host ABI reddens CI. (In flight.)

### F2 — voice-transport/media nouns are ungated in core (token-level, forward)
`rtc/sdp/webrtc/twilio/dtmf/rtp/sideband/realtime/audio/mulaw/g711/barge` are banned by NO gate; a
`SdpOffer` in a neutral crate would pass everything today.
- **FIX:** none needed today (zero hits — voice keeps them in busbar-voice).
- **PREVENT:** new `scripts/plane-transport-neutrality.sh --check` (+ `--selftest` + a Rust witness
  test) failing if any neutral crate names a transport/media noun; blocking in CI. Green today, red the
  instant one leaks. (In flight.)

### F3 — host-ABI SEMANTIC single-plane capabilities on the universal sum-trait (the subtle one)
Second-model finding. `JournalHost::call_log_emit`/`call_log_emit_hostless` + payload
`plane::calllog::CallInput` (fields `server`/`tool`/`tool_digest`/`pin_generation` — MCP vocabulary),
and `IdentityHost::quarantine_settle`/`approval_redeem`/`ask_state_sealer` — all MCP-only callers, yet
they ride supertraits of the universal `EngineHost` that A2A/voice/LLM inherit unnarrowed. Generically
NAMED, so token gates (F1) are structurally blind; the coupling is semantic (what the method is FOR).
Inert today (no cross-plane call), but a real ABI leak: a new plane's compile surface names MCP's
vocabulary.
- **FIX (structural):** move single-plane host capabilities OFF the universal `EngineHost` sum into
  plane-narrowed slice traits that are NOT supertraits of `EngineHost`. MCP obtains them by narrowing
  (an `as_mcp_host()`/downcast or a dedicated `Arc<dyn McpTrustHost>`), exactly as voice already
  narrows to `Arc<dyn MeteringHost>` for its D2 lease. After the move, the universal trait carries only
  capabilities ≥2 planes use, so no plane inherits another plane's vocabulary — the semantic coupling
  becomes structurally impossible.
- **PREVENT (mechanical, converts semantic→structural):** a Rust test in `crates/busbar/tests/`
  (the one crate that links every plane) that, for EACH method on the universal `EngineHost` slice set,
  asserts it is called by ≥2 plane crates OR is on an explicit `UNIVERSAL_HOST_METHODS` allowlist with
  a written reason. A NEW single-plane method added to the universal trait fails the test until it is
  either moved to a narrowed slice or justified. This makes "is a host capability plane-specific?"
  a mechanical question (caller-count across plane crates), not a human judgement.

### F4 — voice D2 lease billing has no byte-pinned regression oracle
Second-model finding. The four money oracles are all LLM-plane (and `egress_differential` is actually
TLS/SPKI parity, not billing). Voice's `cost_reserve`/`cost_settle`/`cost_close` D2 path (the ONLY
caller is `busbar-voice/src/runtime/metering.rs`) has no oracle-style backstop.
- **FIX + PREVENT (one artifact):** add a voice D2 billing oracle test — reserve→settle→exhaust with
  byte/scalar-pinned expected lease state + hard-close, mirroring the LLM oracles' rigor — so a future
  voice change that drifts the lease math reddens CI. This is both the fix and the prevention.

### F5 — forward neutral→plane enforcement is only word-boundary (systemic, meta-audit)
The only BLOCKING forward gate (`plane-purity --check`) matches plane keys at word boundaries where `_`
is not a boundary, so ~44 underscore-joined leaks (`mcp_slot`, `a2a_stateful`, `DEFAULT_PROTOCOL=
"anthropic"`, `McpEndpointSection`) sit in neutral crates uncaught; three neutrality gates
(`plane-abi-neutrality`, `plane-noun-gate`, `plane-config-noun-gate`) aren't in CI at all.
- **FIX:** the ~44 leaks are the in-core-twin extraction (see F6) — cleared as that lands.
- **PREVENT:** once the neutral-scope leaks are cleared, ARM `plane-grep-gate` over the neutral roots
  as blocking (split so the neutral scope arms independently of the cross-plane scope), add the
  transport nouns (F2), and wire the orphan gates into CI. Then substring forward-neutrality is blocking,
  not report-only.

### F6 — in-core plane-twin residual (pre-existing, tracked; the extraction this branch is named for)
`busbar-core/src/{calllog.rs, plane/quarantine.rs, plane/approvals.rs}` hold MCP durable trust/audit
ENGINE state (owner-ruled core-resident: auditing/key-derivation is engine-wide); the `KIND_*` doc
attributions + the ~44 F5 substring leaks are its surface. NOT reached by the plane as a forward
coupling (planes use neutral seams), but it is why F3/F5 exist.
- **FIX:** complete the extraction (relocate the MCP engine state + its host ABI, per F3) — a separate,
  larger workstream on `integration/plane-extraction`, out of 1.6.0-voice scope but the durable end
  state.
- **PREVENT:** F3's universal-trait test + F5's armed forward gate together prevent NEW twins and lock
  in each increment of the extraction.

---

## Prevention summary (the mechanical backstops, once all land)
1. `plane-purity-lint --check` — reverse (plane→core) + word-boundary forward. **Already blocking.**
2. `plane-abi-neutrality.sh` — role-noun forward over `hot/` + `plane_host/` + `hooks/`. **→ blocking (F1).**
3. `plane-transport-neutrality.sh` — voice/media noun forward over neutral crates. **→ blocking (F2).**
4. `EngineHost` universal-trait purity test — every universal host method used by ≥2 planes or
   allowlisted. **→ blocking (F3).**  ← the semantic-coupling backstop.
5. Voice D2 billing oracle — voice money-path byte-pinned. **→ blocking (F4).**
6. `plane-grep-gate` armed on neutral scope + transport nouns + orphan gates in CI. **→ blocking (F5),
   after F6 clears the neutral-scope leaks.**
7. `plane-delete-test --all` — structural reverse-independence. **Already blocking.**

With 1–7 blocking in CI, "core stays generic in both directions, token AND structural" is mechanically
enforced — the re-audit day verifies the gates, not the tree by hand.

---

## CLEAN verdicts (for the record — audited, no fix needed)
- Store seam (PlaneStore/DurableHandleEngine/PlaneRecord): opaque `kind`, opaque body, neutral keys.
- Ingress/egress: no dialect scheme in core; forwarded-header set is caller-supplied; T4 mode absent.
- Observability: metric families neutral, `plane` is a label value; voice diagnostics/audit-kind plane-owned.
- Config/registry: Stage A `NamedMapSection` eviction HELD; core names no plane noun as a parse target.
- busbar-llm / busbar-mcp / busbar-a2a: clean both directions; delete-test PASS; codecs/vocab in-plane;
  taskstore on the neutral engine.
- Cross-plane graph: production off-diagonal zero; only acyclic dev-dep test back-edges.
- New-crate-only diff: true for logic + a fixed ~8-file assembly delta; one irreducible `main.rs` push.

---

## Voice-serving audit (4-model adversarial, money / credential / governance / neutrality+failure-modes)
The voice serving substrate (mint/SDP/breaker/egress/hooks/metrics one-shot passes) was reviewed by four
independent adversarial agents, one per angle, each grounding claims against a green build/107-test run.
Money path CLEAN (verify-before-charge, no double-charge, by-value guard closes on every exit, fail-closed,
breaker-fold-can't-charge — all confirmed). Neutrality CLEAN both directions (diff confined to busbar-voice
+ Cargo.lock; `dial_provider` parameterized; `rtc_call_id` correlation forgery-resistant/owner-gated/durable;
`dial_signal` fails safe; no panics on attacker input). Governance ordering sound and bypass-resistant.

### F7 — SDP broker forwarded the caller's inbound GOVERNANCE bearer to the provider (credential, HIGH)
`serve_sdp` read the inbound `Authorization` and forwarded it verbatim to `POST /v1/realtime/calls`. The SDP
route is `RouteAuth::Key`, so that inbound header is the caller's busbar GOVERNANCE bearer — forwarding it
exfiltrates busbar's own authority to the provider (replayable against busbar). Latent behind `provider=None`
(501 today) but committed, green-tested behavior that fires the instant provider config is threaded. The decl
doc had imagined "browser `ek_` on the SDP hop", but an `ek_` can't ride the `RouteAuth::Key` slot and no
server-side `ek_` is persisted between the separate mint/SDP requests — a credential-slot collision.
- **FIX:** the SDP broker authenticates upstream with busbar's OWN provider key (busbar brokers the call
  server-side), via the shared `voice_provider_bearer` builder; the inbound headers are NEVER read for
  egress. An `ek_`-relay model (forward the browser secret) needs a resolved `ek_` source on a
  non-`Authorization` inbound slot or a minted+persisted secret — a flagged PROTOCOL follow-on, not guessed.
- **PREVENT:** `sdp_tests` now records the `Authorization` the loopback provider is dialed with and asserts
  it equals `Bearer <provider key>` AND `!=` a distinct inbound-governance sentinel — a regression guard that
  reddens the instant any inbound token is forwarded upstream.

### F8 — the declared egress-credential builder was not on the live serving path (credential, MEDIUM)
`voice_egress_auth_headers` (the lane-constant `egress_auth_headers` decl the `egress_tests` battery proves)
was referenced only by the decl + its test — `serve_sdp` forwarded the inbound header and `serve_mint`'s
minter built its own bearer, so the tested builder gave false assurance masking F7.
- **FIX:** extracted `voice_provider_bearer` as the ONE provider-bearer construction; both the decl and the
  live `serve_sdp` egress authenticate through it, so the tested builder IS the live credential path.
- **PREVENT:** `egress_tests` (the builder) + F7's `sdp_tests` guard (the live path) now pin the same code.

### F9 — one-shot / uncomposed-501 durable-session lifecycle (money+governance, LOW — deferred to WS-accept)
The one-shot Mint/SDP passes and the not-yet-served sideband/telephony 501 legs run `begin_session`
(gauntlet + lease + durable genesis) then return without an explicit `handle.close`. The lease closes
deterministically (by-value guard) — NO money leak — but the durable row persists. For SDP this persistence
is INTENDED (the `rtc_call_id` correlation the sideband later reads; `sdp_tests` reads the row back), so a
per-request close would be WRONG. The genuine residue is orphan-REAPING of rows from looped/uncomposed opens,
whose correct resolution (session TTL/close across the mint→sdp→sideband lifecycle) is coupled to the pending
WS-accept seam — the accept path opens/keeps the session at accept time and owns teardown.
- **FIX:** resolve in the WS-accept seam (imminent), where the session lifecycle is designed end-to-end.
- **PREVENT:** the WS-accept work adds a lifecycle test (an uncomposed/aborted open leaves no live row after
  its TTL/teardown) alongside the existing `sdp_tests` correlation-persistence test.

### F10 — breaker single-flight relaxed on recovery (neutrality/robustness, LOW — deferred to WS-accept)
`dial_provider` admits a HalfOpen recovery probe then drops the admission scope BEFORE the dial resolves,
folding the outcome in-place via `breaker_record_*`. Safe (the in-place record is authoritative; no
double-count, no mistrip) but it collapses the single-flight window, so concurrent dials can herd a
recovering upstream. The leg is wired-but-not-yet-live (only tests reach `dial_provider` today).
- **FIX:** when the telephony provider leg goes live (WS-accept seam), hold the `DispatchScope` across the
  dial and `breaker_settle` after, restoring canonical HalfOpen single-flight.
- **PREVENT:** a breaker recovery test asserting a single probe in flight during recovery, added with the leg.
