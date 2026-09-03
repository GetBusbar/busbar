# busbar 1.6.0 — overnight progress report

Live as of the current push. Branch `integration/config-seam-stage1-rebased`, pushed to **origin/dev**.
All pushes dev-only. Money path byte-identical throughout (verified every increment).

## Method (what you asked for)
Design → parallel adversarial audit (Sonnet + Opus) → finalize → build → verify full battery → bank
green to dev. **33 audited playbook docs** committed (`docs/design/playbook/`). The **big finding** that
reshaped scope: the voice stack was **~80% already built** behind the `runtime` feature (neutral duplex
pump, WS transport, D2 lease, both dialect codecs, both topologies, full IR). So 1.6.0 = **finish +
govern + wire + close the seam**, not build-from-scratch.

## DONE and CI-GREEN on dev (each pushed as a byte-identical green increment)
1. **Config seam Stage A (DoD #1)** — `NamedMapSection::Tools/Agents` evicted → `Plane(&str)` folded
   from the plane registry; `DeployCfg::plane_section` accessor; ~30 `.key()` sites repointed to
   `decl.config_section`; deletion-gate reads the frozen mirror (fail-closed). **openapi.json +
   config-schema byte-identical** (`f3365eb5…` / `1ae714a5…`). Adversarially audited (both verdicts
   SHIP-WITH-CHANGES; all fixes applied). Core's generic named-map machinery names no plane noun.
2. **Voice plane booted (DoD #2)** — `plane-voice` feature (off-default, per the locked "dev-only until
   DoD"), `register_planes`/diagnostics wired, `StreamsCfg` + real `parse_section`/`default_section`,
   `build_runtime` reads real config, **boot-validate conformance leg** (streams validates, voice ∈
   `config_sections()`, dup-claim guard rejects a collision). config-schema **additively** bumped
   (`b4081cc2`), **billing/limits corpus byte-stable**, openapi unchanged.
3. **Voice money-path (DoD #3 core)** — `run_gauntlet_session` (verify-before-charge at session open,
   shared `admit_open`, D3 witness), usage→cost **host-pricing** (`MeteringHost::price_usage`, reuses
   the LLM pricer, zero-book removed), `LeaseCloseGuard` + refund (leak fixed, red-before-green proof).
   **All money oracles byte-identical** (egress_differential 5, on_exhausted 35, crossproto 3,
   pool_creds 2); no new label/unit/constant.
4. **Isomorphism mcp/a2a → 0 (DoD #4 partial)** — hooks-tap wired on MCP+A2A via a neutral
   `transform_over` seam (byte-identical absent hooks); capability-equality 5 missing → **0** for the
   non-voice queue.
5. **Gemini superset (DoD #3)** — `VOICE_WIRE_FORMATS` 1→2 → `has_superset_ir` on by arithmetic;
   cross-parity leg runs both dialects (oo/og/go/gg), 4/4 green. (`DECLS.codec` stays `None` by design —
   voice's superset is its own IR, not a `DialectCodec` facade.)
6. **Acceptance harness** — `verify-1.6.0-done.sh` oracle + `no-deferral-gate.sh` + `plane-config-noun-gate.sh`
   + `plane_isomorphism.rs` test, each un-gameable with `--selftest`.
7. **Handle-engine audit-C (d)** — dual-compile `Box<dyn Any>` readback witness (red-before-green proven).
8. **De-skeleton** — stale voice SKELETON/PENDING prose corrected to the true (complete) state.

Every increment passed: build (workspace + no-default + plane-voice), clippy 0/0, fmt, plane-purity
0/0, delete-test all four planes, structure-lint, public-hygiene, config-stability additive, full
workspace test, MCP/A2A/Voice conformance.

## REMAINING (honest; in flight or scoped)
- **Voice route-mounting** (in flight): `PLANE_DECL.routes`/`claims`/`admission` are still `None` — voice
  REGISTERS + validates + boot-validates, but does not yet MOUNT its data routes (serve). Being wired
  structurally now (WebRTC sideband + telephony WS + `ek_` mint + SDP broker as ports, arrival via
  `run_gauntlet_session`). **Live-provider dial (OpenAI/Gemini realtime, Twilio) is naturally
  credential-gated** — cannot be end-to-end validated unattended (no secrets); it stays behind the
  minter/broker ports a deployment supplies. This is the true T2 remainder.
- **Voice capability column** (isomorphism incl. voice): voice is off-default so not in the default
  isomorphism reflection; its ledger column is pinned pending. To be filled (proven/N/A) after
  route-mounting, or documented as the voice-DoD remainder.
- **Gate arming + oracle finalize**: wire no-deferral/config-noun/isomorphism into CI as blocking once
  the above are green; the two residual no-deferral markers are the *sanctioned* "dev-only until DoD"
  feature-gate notes (allowlist, not deferrals).
- **Worktree pruning**: ~90 stale `agent-*` scratch worktrees to prune at the very end (after live
  agents finish).

## Judgment calls made (unattended)
- Stage A **Option A** over B (serde `flatten⊗deny_unknown_fields` blocks B); no new `admin_named_map`
  field (derived from `named_def_list`).
- **Additive config-schema bump for `streams:`** ratified as sanctioned (additive-only classifier green;
  billing corpus untouched) — NOT a money-path violation (the schema fingerprint ≠ the billing corpus).
- Host-side pricing (rate_card stays in core; LLM path byte-identical) over relocating the pricer.
- `DECLS.codec = None` and `busbar-voice?/runtime` optional-dep syntax (keeps voice deletable).
- Live-provider voice legs treated as credential-gated (documented), not faked.
