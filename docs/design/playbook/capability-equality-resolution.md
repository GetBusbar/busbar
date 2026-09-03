<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# Isomorphism-to-zero: resolving the 5 `missing` cells + the pending voice column

*What it takes to drive `qa/capability-equality.json` to a zero-`missing` ledger. Per-cell
verdict — **IMPLEMENT** (real feature work, with what), **RECLASSIFY-N/A** (a ledger edit, with
the argument), or **PROVEN-ELSEWHERE** — decided against the actual code, not the ledger prose.*

> Owner's ruling, the reason this is a gate: *"breakers, hooks, auditing — list all the core
> functionality. outside should ONLY BE Auth, Store, Protocols, i.e. Plugins. Any plugin gets all
> functionality. LLM == MCP == A2A — just different protocols not different pathway through engine
> at all."* The discriminator for IMPLEMENT-vs-N/A below is that ruling: an asymmetry the ruling
> forbids is a gap to close, not a difference to argue away.

## Bottom line

| # | cell | verdict | cost |
|---|---|---|---|
| 1 | `hooks-tap × mcp-client` | **IMPLEMENT** | shares one wiring w/ #2 |
| 2 | `hooks-tap × mcp-server` | **IMPLEMENT** | 1 transform wiring at `mcp/method.rs` + 1 test → closes #1 & #2 |
| 3 | `hooks-tap × a2a-client` | **IMPLEMENT** | shares one wiring w/ #4 |
| 4 | `hooks-tap × a2a-server` | **IMPLEMENT** | 1 transform wiring at `a2a/receive.rs` + 1 test → closes #3 & #4 |
| 5 | `hooks-gate × a2a-client` | **RECLASSIFY-N/A** | pure ledger edit |
| — | **voice column** | **LEDGER EDIT + REAL WORK** | 2 proven + 4 N/A pins land immediately; **7 cells land `missing`** (grows the queue) |

**Isomorphism-to-zero is NOT a ledger edit.** Exactly one of the six items (the a2a-client
hooks-gate cell) is a pure reclassification. The four hooks-tap cells are real feature work — two
transform-chain wirings, ~each mirroring the LLM `apply_global_rewrites` seam — because the gate
already reaches these planes' payloads and the ruling forbids declaring the tap half inapplicable.
The voice column, made honest, ADDS seven `missing` cells; zeroing them needs breaker/hooks/metrics
wiring **and** booting voice out of dev-only.

---

## The tap/gate split, established from the code

The hooks system has two halves, and only one of them is plane-agnostic today:

- **The GATE half is generic and already shared.** `busbar_core::hooks::gate::decide`
  (`crates/busbar-core/src/hooks/gate.rs:217`) takes an `IrFacts` projection and returns a
  two-armed `GateVerdict::{Proceed, Reject}` — no plane branch, `ingress_protocol` is data only.
  MCP fires it at `crates/busbar-mcp/src/mcp/method.rs:1522` and A2A at
  `crates/busbar-a2a/src/a2a/receive.rs:1060`, both through the `EngineHost::gate_decide` host seam
  (`crates/busbar-substrate/src/plane_host/mod.rs:863`). This is why every `hooks-gate` cell except
  a2a-client is already `proven`.
- **The TAP/TRANSFORM half is LLM-plane-only.** The rewrite chain `apply_global_rewrites`
  (`crates/busbar-llm/src/engine/hooks.rs:373`), the observe stage-taps `fire_stage_taps`
  (`hooks.rs:996`), and usage projection `record_token_usage`
  (`crates/busbar-llm/src/engine/usage.rs:133`) are all defined in and called only from
  `busbar-llm/src/engine/pipeline.rs`. An exhaustive grep of `crates/busbar-mcp/src` and
  `crates/busbar-a2a/src` for `apply_global_rewrites` / `.transform(` / `tap_hooks` /
  `fire_stage_taps` returns **zero** call sites. The gate on these planes has no `rewrite` arm
  (`GateVerdict` is two-armed), so the transform capability is genuinely absent, not folded in.

The rewrite *machinery* is body/dialect-generic (it mutates a `serde_json::Value` dispatched by
`busbar_substrate::proto::decl_for(..).dialect()`), so nothing structural stops it running over an
MCP tool-call `arguments` object or an A2A submission's `params`. The one truly LLM-specific piece
is **usage projection** (`TokenUsage`, rate cards, budget windows) — but that is a *sub-part* of the
capability, not the whole; the observe/transform half is what these cells owe and lack.

---

## The 5 missing cells

### 1 & 2 — `hooks-tap × {mcp-client, mcp-server}` → IMPLEMENT

**Not N/A.** The gate already builds the hook projection from the tool-call arguments at
`method.rs:1522` and screens what would go upstream; there is no structural reason an
observe/transform pass cannot run over the same payload, and the ruling ("any plugin gets all
functionality") forbids calling the tap half inapplicable while the LLM plane has it. The ledger's
own note ("the tap half of the hook surface is LLM-only today") already frames it as a gap.

**What to implement.** At the existing gate site in `mcp/method.rs` (which already has the
`gate_attached` presence check, the serialized `args_json`, the `request_id`, and the
`spawn_blocking` hop), add a **transform pass**: run the resolved rewrite-hook chain over the
tool-call `arguments` before the outbound credential is leased, reusing the projection already
assembled there. Simplest delivery is a new `EngineHost::transform_over` host seam beside
`gate_decide`, so the plane body still names no core hook symbol (the Seam-B inversion). One wiring
at `method.rs` covers **both** MCP directions — the same "one battery covers both directions" fact
the `hooks-gate` MCP cells already rely on (`method.rs` sits before the client leg, no ungated
entry).

**Test to add** (closes both cells, one commit):
`crates/busbar-mcp/src/mcp/tests/hook_tap_tests.rs::a_rewrite_hook_edits_the_tool_call_arguments_before_they_go_upstream`
— register a rewrite hook, POST a `tools/call` through `build_router`, assert the upstream saw the
rewritten arguments; delete the transform call to prove it red.

### 3 & 4 — `hooks-tap × {a2a-client, a2a-server}` → IMPLEMENT

Identical argument. The A2A gate fires at `receive.rs:1060` over the submission `params`; the relay
(a2a-client) inherits that inbound gate (`relay` runs downstream of `admitted`), and originated hops
run downstream too, so one transform wiring at the `receive.rs` admission covers **both** A2A
directions — the same coverage shape the gate battery uses.

**What to implement.** At `a2a/receive.rs::admitted` (after the gate block, before the meter/egress
gate/task row), run the rewrite chain over the submission `params` via the same
`transform_over` host seam.

**Test to add** (closes both cells):
`crates/busbar-a2a/src/a2a/tests/hook_tap_tests.rs::a_rewrite_hook_edits_the_submission_params_before_the_hop`.

> **Scoping note (honest limit to record in the cells):** *usage projection* (token accrual) stays
> LLM-only by nature — MCP/A2A have no per-plane token stream (MCP sampling rides the LLM engine and
> is that plane's evidence). The tap cells are closed by the **observe/transform (rewrite)** half;
> the usage-projection sub-part is not owed here and its absence is not a gap.

### 5 — `hooks-gate × a2a-client` → RECLASSIFY-N/A

**This is the one pure ledger edit.** Busbar-originated A2A traffic is not an independent ungated
entry point. The only "originate" production entries — `mirror_push_config`
(`crates/busbar-a2a/src/a2a/originate.rs:189`) and `refresh_listed_tasks` (`originate.rs:317`) —
have their sole call sites *inside* `receive.rs::admitted` (at `receive.rs:1302` and `:1211`), in
the local-verb block that runs **after** the proven inbound gate at `receive.rs:1060`. Every
originated hop is therefore a mechanical consequence of an inbound request that already cleared the
operator's `agents.hooks:` gate (`originate.rs:20-21,34` says exactly this). Push delivery
(`pushdeliver.rs:356`) targets the **caller's own registered webhook**, not a submission to an
agent, so the `agents.hooks:` projection (agent method + params) has no semantic target there. This
is the same rationale the mcp-client cell is `proven` under ("no ungated production entry to the
client leg").

**Concrete edit** — replace the a2a-client `hooks-gate` cell in `qa/capability-equality.json`:

```json
{
  "capability": "hooks-gate",
  "plane": "a2a-client",
  "state": "not-applicable",
  "reason": "busbar-originated A2A traffic is not a second gate point: originate (mirror_push_config, refresh_listed_tasks) is called only from receive.rs::admitted, downstream of the proven inbound hooks gate, and push delivery targets the caller's own webhook, which the agent-submission gate has no semantic target for. Same rationale the mcp-client cell is proven under."
}
```

(Reason is ≥60 chars, so it clears `capability_equality.rs:239`.) No test changes.

---

## The voice column — declaring it honestly is a ledger edit; zeroing it is feature work

Voice is a real, tested duplex-session engine behind the off-by-default `runtime` cargo feature
(`crates/busbar-voice/src/runtime/{session,metering,scope}.rs`, ~7k lines, 68 tests across five
files, a 1,129-line conformance harness). But the shipped `PLANE_DECL`
(`crates/busbar-voice/src/lib.rs:84`) is a skeleton (every runtime hook `None`) and voice is not
booted into the composition root until M5 (`docs/design/playbook/m5-voice-boot.md`). Today the
totality gate pins voice to `VOICE_PENDING_COLUMN` (`capability_equality.rs:78`) so it is honestly
named as pending; the directional column does not yet exist in the ledger.

To make voice a **full, non-pending column** you add `"voice"` to `planes` and fill all 13 rows (the
cross-product totality gate makes a partial column RED). Enumeration below, aligned to the plane
whose shape voice most resembles — the **llm** plane (outbound to an operator-declared provider, no
peer-published artifact, no request-authored URL):

| capability | voice verdict | evidence / argument |
|---|---|---|
| `audit-chain` | **PROVEN** | `scope.rs` hash-chains `SealedEvent`/`tail_hash` on `DurableHandleEngine`; runtime-gated test in `crates/busbar-voice/src/runtime/tests.rs` (name it in the cell). |
| `governance-budget` | **PROVEN** | `metering.rs` D2 `HostLease` settle-past-cap hard-close over `plane_host::MeteringHost`; runtime/tests.rs. |
| `failover-reroute` | **N/A** | a duplex session is pinned to one provider socket for its lifetime; there is no candidate set to walk mid-session, and a lost session re-dials as a NEW session, not a reroute. |
| `disposition` | **N/A** | disposition classifies a discrete upstream ANSWER (Stage 1 → `breaker::classify`); a duplex frame stream has no per-hop answer — a fatal frame closes the session, it is not a Disposition. |
| `trust-pinning` | **N/A** | voice providers (OpenAI Realtime / Gemini Live) are operator-declared config endpoints, not peer-published artifacts — the same argument the `llm` cell is N/A under. |
| `net-guard` | **N/A** | the provider WSS is an operator-configured endpoint; no request-authored URL reaches the dial, so no SSRF surface — same argument as `llm`. (The `net_guard` resolve→pin→guard at `topology/mod.rs::dial_provider` is defense-in-depth, not a request-URL guard.) **Revisit** when the T3 inbound webhook receiver lands — a request-authored callback IS owed net-guard, like a2a-server push delivery. |
| `breaker-trip` | **MISSING** | the core breaker ABI exists (seam-audit-D) but is not wired into the voice dial/session-open path. Feature work. |
| `breaker-fastfail` | **MISSING** | same — no admission-before-dial against a tripped provider cell. |
| `hooks-tap` | **MISSING** | no observe/transform path over voice frames — the same tap gap as MCP/A2A above. |
| `hooks-gate` | **MISSING** | no `hooks::gate::decide` at session-open admission. |
| `metrics` | **MISSING** | `diagnostics.rs` declares `VOICE_SESSION_LEASE_EXHAUSTED` but voice is not on a real `/metrics` scrape yet (unbooted). |
| `egress-auth` | **MISSING** | the provider credential / webrtc ephemeral token is not injected through the one egress mechanism (`DECLS.egress_auth_headers = None`). |
| `catalogue` | **MISSING** | no `streams:` named-def registry yet (`named_def_list`/`registry_contains = None`); a streams catalogue is a future config-grammar slice. |

**Voice column tally: 2 proven, 4 N/A, 7 missing.** Declaring the column is a ledger edit that
lands the 2 proven cells (pointing at existing runtime-gated tests) and the 4 argued N/A pins
immediately — but it also adds **7 new `missing` cells to the queue**. So adding voice honestly
*moves the ledger away from zero*, not toward it. Those seven zero only with real feature work
(breaker wiring, hooks tap+gate, metrics/egress-auth/catalogue on the dial path) **and** voice being
booted out of dev-only at M5. Until then, keeping voice pinned to `VOICE_PENDING_COLUMN` is the
honest state; do not add the column just to claim a wider matrix.

---

## Total real-implementation work for isomorphism-to-zero

1. **MCP transform/tap wiring** — a `transform_over` host seam + a rewrite pass at
   `mcp/method.rs:1522`, one `hook_tap_tests.rs` test. Closes 2 cells.
2. **A2A transform/tap wiring** — the same seam applied at `a2a/receive.rs`'s admission, one
   `hook_tap_tests.rs` test. Closes 2 cells.
3. **a2a-client hooks-gate** — one JSON reclassification to N/A (above). No code.
4. **Voice** — declaring the column is a ledger edit (2 proven + 4 N/A), but seven cells need
   breaker/hooks/metrics/egress-auth/catalogue wiring plus M5 boot before they flip to proven; this
   is the largest bucket and is gated on the voice-boot milestone.

The four hooks-tap cells (items 1–2) are the only new capability work strictly required to zero the
*existing* five-cell queue; the a2a-client cell is a ledger edit. Voice is a separate, larger track
that should not be folded into the current column until its cells can be filled without growing the
queue.
