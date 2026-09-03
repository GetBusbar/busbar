# busbar 1.6.0 — MASTER PLAN (audited playbook → build)

Orchestrator synthesis of the parallel design+audit swarm. Working branch:
`integration/config-seam-stage1-rebased` (on `origin/dev` 7004d8a7). Dev-only pushes. Byte-identical
money path or STOP.

## THE HEADLINE FINDING (changes the scope)
The tree is **~80% ahead of the stale seam-audit docs** (pinned at `e393b9e6`). Already built +
green behind the `runtime` feature (verified by multiple agents): neutral duplex pump
(`byte_duplex`, neutral `CallRef`), `Transport::WebSocket` ingress-upgrade + guarded WSS egress
dialer, D2 cost slots (`cost_reserve`/`cost_settle`, minor-19), `MeteringHost`, the full four-layer
voice IR, **both** dialect codecs (OpenAI Realtime + Gemini Live, 68/68 tests, zero `todo!()` in
bodies), the runtime session core, **both** topologies (WebRTC sideband + telephony g711). The five
conformance legs are REAL and pass (0 vacuous). Handle-engine audit-C (a)(b)(c) already landed.

So 1.6.0 is **finish + govern + wire + test + close the config seam**, not "build a voice stack."

## REMAINING WORK (the real register) — owner = build step
| # | Item | Kind | Risk | Blocks |
|---|------|------|------|--------|
| 1 | **M5 boot** — Cargo `plane-voice` feature (off-default), main.rs register_planes/diagnostics, PLANE_DECL `parse_section`/`default_section`/`owned_config_sections=["streams"]`, `StreamsCfg` (reuse `ir::config::SessionConfig`+`IrVad`; +limits 3600s/32768/4096), boot-validate conformance leg | mechanical | low | seam grammar |
| 2 | **Stage A** — Option A: remove `NamedMapSection::Tools/Agents`→`Plane(&str)`, `ALL`→`sections()` folded from registry (`named_def_list.is_some()`), `DeployCfg::plane_section(&str)` accessor (3 arms: tools/agents/streams). Byte-identical openapi/taxonomy/config-schema. | delicate | HIGH (byte-id) | — |
| 3 | **`run_gauntlet_session`** — verify-destination-before-charge at session open (append to one-Response `run_gauntlet`; witness test guards the sibling). `begin_session` reserves lease + streams with NO admission today. | money-path | HIGH | safe voice serve |
| 4 | **SessionScope `Drop`/arena + lease refund** + **A1/D1 substrate-owned `ArrivalCtx` newtype** (dual-compile downcast panic). First field set = one-way ABI door. | one-way door | HIGH | voice serve |
| 5 | **`IrDuplexUsage → CostBreakdown` fold** — reuse EXISTING UsageComponent/rate path; NO new variant/label/constant. The mid-session hard-stop link. | money-path | HIGH | hard-stop |
| 6 | **Gemini 1→2 flip** — `VOICE_WIRE_FORMATS` + `DECLS.codec` one-liner; superset turns on by arithmetic; cross-parity leg. | one-liner | low | superset |
| 7 | **Handle-engine (d)** — dual-compile `Box<dyn Any>` readback witness (voice is 1st core-slot rider). | witness | med | assurance |
| 8 | **Gates** — `no-deferral-gate.sh` (+ committed allowlist for hot/*), `verify-1.6.0-done.sh` oracle, isomorphism via capability-equality. | additive | med | proof |
| 9 | **De-skeleton doc headers** — voice `lib.rs`/`Cargo.toml`/`voice-conformance.sh` say SKELETON/"dev-only until DoD" but code is complete+green; correct them (also required for no-deferral green). | doc | low | no-deferral |
| 10 | **Prod-composition (required subset)** — real pricing/tools into `build_runtime` from `streams:`, HTTP ingress routes voice's `PLANE_DECL.routes` mounts, ephemeral `ek_` mint. (LiveKit media adapter / live Twilio = classify deferrable.) | wiring | med | serve |

## RECONCILED DECISIONS
- **Stage A = Option A** (not B). Option B blocked by serde `flatten ⊗ deny_unknown_fields` + config-schema snapshot break. (Adversarial audits Sonnet+Opus in flight; may add constraints.)
- **No `admin_named_map` bool** — derive from `named_def_list.is_some()`.
- **Build order (integration-order agent, AUTHORITATIVE):** gates(G0, additive) → **Stage A alone (tree-wide re-type, serial)** → fan out: worktree-1 T1-transport ∥ worktree-2 (audit-C(d)→SessionScope-Drop→cost-lease, they share `hot/*`+`scope.rs`) → **M5** → **T2** (gemini flip + conformance serialize on `voice-conform.rs`; money-path trio gauntlet/usage-fold live here). `busbar-voice/src/lib.rs` is the convergence file → voice last. T1 does NOT collide with Stage A (disjoint files).
- **CORRECTION: `streams:` is a SINGULAR typed section (like `store:`/`limits:`), NOT a named-map.** So Stage A's `NamedMapSection` work is tools/agents-only (2-arm accessor); M5's `streams` DeployCfg field + `parse_section` is independent of NamedMapSection.
- **Stage A design revision required (Sonnet adversary):** ~30 bare `::Tools.key()`/`::Agents.key()` sites with no DeployCfg in scope must be repointed to `decl.config_section` (reading the noun from the registry — further de-nouns core); named_map.rs has 8 match sites not 3; +4 ALL-iteration sites. Finalize after Opus adversary.
- **Done-oracle EXCLUDES `plane-noun-gate`/`plane-grep-gate` == 0** (locked: those measure billing vocab that STAYS in core; orthogonal to purity). Purity proof = `plane-purity-lint --check` TOTAL 0/BACKWARDS 0 (green today) + delete-test all four planes.
- **hot/* deferral**: allowlisted as out-of-1.6.0 foundation scaffolding (additive/unused, never called). Flagged to owner as the one honest "known future work" outside 1.6.0 product surface.
- **"voice booted" = feature-gated (off-default) + boot-validated + functionally complete** (gauntlet-session/lease-drop/usage-fold closed), NOT shipped-on. `plane-voice` must NOT enter `default` (would change config-schema snapshot).

## OPEN CONFLICTS (adversarial process resolving)
1. hot/* allowlistable vs must-remove (ace32b vs ae0cef90) → RESOLVED allowlist (foundation scaffolding).
2. SessionScope shape reported as `{engine,owner,id}` vs `{}` empty across agents → session-drop agent resolving against THIS branch.
3. Does 1.6.0 require voice production-on or feature-complete-gated? → taking feature-complete-gated (honors "dev-only until DoD" + locked purity), all skeleton markers cleared.

## DONE = `scripts/verify-1.6.0-done.sh` green
Build battery (full-gate) · plane-purity 0/0 + delete-test ×4 · byte-identity money path (openapi,
config corpus, 6 llm oracles) · config additive-only · full test incl. `-p busbar-voice --features
runtime` · conformance selftests + verdict-coverage + voice legs `=ready` · **no-deferral gate**
(allowlist exact) · **isomorphism** (capability-equality 0 missing + voice column proven). Every
sub-gate runs its own `--selftest` first; report-only meters NOT part of done per locked invariant.
