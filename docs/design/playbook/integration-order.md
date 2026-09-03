<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# 1.6.0 BUILD / INTEGRATION ORDER — landing all workstreams onto one branch

Status: **AUTHORITATIVE INTEGRATION PLAN.** Companion to the per-workstream playbooks in this
directory and to `docs/design/plane4-duplex-session-1.6.0-plan.md` (the build program). This doc
answers exactly one question: **in what order, on which worktrees, with which re-verify at each
merge, do all 1.6.0 workstreams land on `integration/config-seam-stage1-rebased` (base
`origin/dev@7004d8a7`) such that every intermediate commit is green** — build + clippy + purity
(`--check`=0) + neutrality + delete-test + no-plugins + byte-identity oracles + airlock-version-
monotone + D1/D2/D3 witnesses — and no merge breaks byte-identity or purity.

**Release model.** Dev-only pushes; bank each green increment; never a broken tree. The three
existing Stage-A increments (S1 registry+dup-guard `38050555`, S2a raw-rate-view `3005149c`, Stage-C
`voice:`→`streams:` keystone `ae85025d`) are already banked on this branch and are byte-identity-
preserving per commit — the ordering below extends that discipline to the rest.

---

## 1. Why "seam → then fan out" (the governing constraint, proven from file overlap)

Stage A is not a local edit — it is a **tree-wide re-type of the plane-config registry**. Core's
`NamedMapSection` stops naming `Tools`/`Agents`/`streams` as parse targets; those sections now
travel in from each plane's `PLANE_DECL::parse_section` (`stage-a-design.md`). The rewrite therefore
touches the **registration site of every plane**. Verified against
`integration/config-seam-stage1-rebased` diffed at its merge-base with `7004d8a7`:

```
crates/busbar-core/src/config/mod.rs          crates/busbar-core/src/plane/registry.rs
crates/busbar-substrate/src/plane/registry.rs crates/busbar-substrate/src/billing.rs
crates/busbar-core/src/cost.rs                crates/busbar-llm/src/lib.rs        # llm PLANE_DECL
crates/busbar-mcp/src/mcp/mod.rs   # mcp PLANE_DECL   crates/busbar-a2a/src/a2a/mod.rs   # a2a PLANE_DECL
crates/busbar-voice/src/lib.rs     # voice PLANE_DECL
```

Because Stage A edits `busbar-{llm,mcp,a2a,voice}`'s registration files, **no plane-side workstream
can run in parallel with it** — any branch that also edits a plane's `lib.rs`/`mod.rs` registration
would conflict with Stage A's re-type of that same call. Hence: **Stage A lands first, serially,
alone.** This is the "seam." Only once it is banked do the substrate-capability tracks "fan out."

The complementary fact — proven below — is that **T1 (substrate transport/pump/session) does NOT
collide with Stage A at the file level**: T1 lives in `transport.rs`, `media.rs`, `plane_host/*`,
`plugin/hot/*`; Stage A lives in `config/*`, `plane/registry.rs`, `admin/v1/*`. They are disjoint.
The kickoff's "T1 seams collide with the substrate the seam rewrites" is true only at the
**convergence file `busbar-voice/src/lib.rs`** (voice's `PLANE_DECL` declares its `streams:` config
section *via Stage A's registry* AND consumes T1's `SessionScope`/cost-lease/pump seams), which is
why **voice lands last**, after both Stage A and T1.

---

## 2. Collision matrix (evidence-backed)

Pairwise file overlaps computed from each workstream branch diffed at its merge-base with
`7004d8a7`, plus the target files named in each playbook / seam-audit doc. `●` = same file(s)
edited (must serialize or rebase); `○` = adjacent module, low-risk (re-verify at merge); blank =
disjoint (parallel-safe).

| ↓ vs → | StageA (config seam) | T1-transport | T1-SessScope | T1-cost-lease | audit-C handle | M5 voice-boot | T2 voice | Gates |
|---|---|---|---|---|---|---|---|---|
| **StageA (config seam)** | — | | | ○ `cost.rs` | ○ `plane/mod.rs` | ● `voice/lib.rs` | ● `voice/lib.rs` | ○ `busbar-llm` |
| **T1-transport** (`transport.rs`,`media.rs`,`ingress/arrival.rs`,pump,MCP/A2A-WS) | | — | | | | | ○ consumes | |
| **T1-SessScope** (`plane_host/scope.rs`) | | | — | | ● `scope.rs` | | ○ consumes | |
| **T1-cost-lease** (`hot/host.rs`,`hot/pod.rs`,`plane_host/mod.rs`,`cost_host.rs`) | ○ `cost.rs` | | | — | ● `hot/host.rs`+`pod.rs` | ○ `voice/lib.rs` | ○ consumes | |
| **audit-C handle** (`plane/handle_engine.rs`,`taskstore.rs` lift,`hot/{host,pod,workitem}.rs`,`scope.rs`) | ○ `plane/mod.rs` | | ● `scope.rs` | ● `hot/host.rs`+`pod.rs` | — | | ○ consumes | |
| **M5 voice-boot** (`busbar/src/main.rs`,`voice/lib.rs`,Cargo features) | ● `voice/lib.rs` | | | ○ `voice/lib.rs` | | — | ● `voice/lib.rs` | ○ delete-test |
| **T2 voice** (`busbar-voice/**`: WebRTC/Twilio/Gemini/IR/runtime) | ● `voice/lib.rs` | ○ | ○ | ○ | ○ | ● `voice/lib.rs` | — | ○ conformance |
| **Gates** (no-deferral / isomorphism / done-oracle; `scripts/*.sh`,`qa/segments.toml`) | ○ | | | | | ○ | ○ | — |

**The three hard-serialization edges (`●`), each a merge that would break the tree:**

1. **`plugin/hot/host.rs` + `hot/pod.rs`** — edited by **BOTH** T1-cost-lease (D2 `cost_reserve`/
   `cost_settle` trailing slots, airlock **minor 18→19**) **and** audit-C (workitem/host/pod for the
   handle engine + `WorkItem` D1 witness). Two parallel branches both appending trailing slots and
   both bumping the airlock minor would produce a **non-monotone / reshaped ABI** → airlock-version
   gate + D2 witness RED. **Serialize:** land audit-C's `hot/*` changes first, then T1-cost-lease
   appends the D2 slots and owns the single 18→19 bump.
2. **`plane_host/scope.rs`** — edited by T1-SessScope (`SessionScope` field wire-out) **and** audit-C
   (`DurableScope` taxonomy for the handle engine). A blind merge yields a scope struct neither
   designed. **Serialize** the two within one worktree.
3. **`busbar-voice/src/lib.rs`** — the convergence file, edited by Stage A (`streams:` keystone),
   M5 (typed `parse_section`), T2 (runtime), and cost-lease (metering). It **cannot type-check**
   until Stage A's registry shape AND the T1 seams it names both exist → voice is strictly last.

**Soft edges (`○`) to re-verify, not serialize:** `cost.rs` (Stage A's byte-identity-critical
`RateEntryCfg`/raw-rate-view vs any T1 CostHold audit — re-run the billing byte oracles at merge);
`plane/mod.rs` (Stage A registry module decl vs audit-C handle-engine module decl — mod-tree merge,
re-run plane registry tests).

---

## 3. Dependency DAG

```
                      ┌──────────────────────────────────────────────┐
   G0  GATES ARMED    │  purity 169→0 & flip --check ; neutrality ban │
   (T0 prereq)        │  list +{voice,audio,realtime,rtc,sdp,webrtc,  │
                      │  barge}; delete-test +voice; no-deferral +     │
                      │  isomorphism + done-oracle gates armed         │
                      └───────────────────────┬──────────────────────┘
                                              │ (purity==0 BEFORE any plane work;
                                              │  touches busbar-llm + scripts + qa)
                                              ▼
                      ┌──────────────────────────────────────────────┐
   STAGE A (SEAM)     │  evict Tools/Agents/streams from core         │
   serial, alone      │  NamedMapSection; plane-owned-config registry; │
                      │  re-type every plane PLANE_DECL::parse_section │
                      │  (S1,S2a,StageC already banked → finish)       │
                      └───────────────┬───────────────┬──────────────┘
                                      │ fan out       │
                 ┌────────────────────┘               └───────────────────┐
                 ▼ (worktree-1, disjoint)                                  ▼ (worktree-2, serial sub-chain)
        ┌─────────────────────┐                          ┌───────────────────────────────────────────┐
        │ T1-transport        │                          │ audit-C handle-engine (lift taskstore →    │
        │  transport.rs +WS,  │                          │  substrate; hot/{host,pod,workitem}; scope) │
        │  pump port CallRef, │                          │            ▼  (same worktree, hot/* + scope)│
        │  media path,        │                          │ T1-SessionScope (plane_host/scope.rs)       │
        │  MCP/A2A WS binding  │                          │            ▼                                 │
        └──────────┬──────────┘                          │ T1-cost-lease (D2 slots hot/*; airlock 18→19;│
                   │                                      │  plane_host/mod.rs; cost_host.rs)           │
                   │                                      └───────────────────────┬─────────────────────┘
                   └───────────────┬──────────────────────────────────────────────┘
                                   ▼ (both worktrees merged back; re-verify)
                      ┌──────────────────────────────────────────────┐
   VOICE (LAST)       │  M5 voice-boot: main.rs register_planes +      │
   serial, gated      │  voice PLANE_DECL parse_section(streams:) +    │
                      │  Cargo `runtime` feature (default-off) +       │
                      │  conformance boot-validate                     │
                      │            ▼                                    │
                      │  T2 voice: IR → WebRTC → Twilio → Gemini →      │
                      │  runtime session (all behind `runtime`)        │
                      └──────────────────────────────────────────────┘

   Edges:  G0 → StageA → {T1-transport ∥ (audit-C → SessScope → cost-lease)} → M5 → T2
   audit-C precedes voice for a 2nd reason: it LIFTS taskstore out of busbar-a2a; until the lift lands
   and a2a consumes it, any voice reach into busbar_a2a:: fails plane-purity (voice's durable session
   record must park on the SUBSTRATE engine, never busbar_a2a::).
```

---

## 4. Recommended LINEAR landing sequence (each step ends green; bank before next)

1. **G0 — Gates armed / purity to 0.** Drive `plane-purity-lint BACKWARDS` 169→0 (busbar-llm
   import-repoint + engine off `&App`), flip gate `--baseline`→`--check` blocking; add the seven
   voice nouns to `plane-abi-neutrality.sh` `banned=`+`mandated=`; add `voice` to
   `plane-delete-test.sh` `PLANES`; arm no-deferral, isomorphism, done-oracle. *Touches
   `busbar-llm/**` + `scripts/*.sh` + `qa/segments.toml` — do BEFORE Stage A (Stage A also re-types
   `busbar-llm/src/lib.rs`; drain purity there first to avoid a double edit).* Re-verify: purity
   `--check`=0, `--selftest`, 5 byte oracles unchanged.
2. **Stage A (SEAM) — finish the config-registry rewrite.** S1/S2a/StageC are banked; complete the
   remaining `NamedMapSection` eviction + `admin/v1/*` + `config/{named_map,overlay,mod}.rs` +
   `plane/registry.rs` so tools/agents/streams travel from the plane registry. Serial, alone.
   Re-verify: build+clippy+purity+neutrality+delete+no-plugins + **config-corpus byte-identity**
   (`openapi.json`, error taxonomy, config corpus unchanged) + isomorphism gate.
   **← BANK. This is the fan-out point.**
3. **T1-transport** (worktree-1, parallel-safe): `Transport::WebSocket` + full dispatch, pump port
   (`CallRef` correlation), media path, MCP/A2A WS bindings. Disjoint from all Stage-A and
   `hot/*`/`scope.rs` files. Re-verify on the worktree, then **merge to integration**; re-verify the
   full gate set + D1 `WorkItem` witness.
4. **audit-C handle-engine** (worktree-2): lift `TaskRegistry`→`busbar-substrate/plane/handle_engine.rs`,
   a2a consumes it, `hot/{host,pod,workitem}.rs`, `scope.rs` DurableScope. **Land its `hot/*` edits
   before cost-lease.** Re-verify: handle-engine suite green *for A2A*, `git grep busbar_a2a::
   crates/busbar-llm crates/busbar-voice`=0, purity+neutrality.
5. **T1-SessionScope** (worktree-2, after audit-C — shares `scope.rs`): wire out `SessionScope`
   fields; prove Drop reclaim leak-free. Re-verify: scope tests + purity (no `CallRef` in the
   neutral struct).
6. **T1-cost-lease** (worktree-2, after audit-C — shares `hot/host.rs`+`pod.rs`): append D2
   `cost_reserve`/`cost_settle` trailing slots, **single airlock 18→19 bump**, `plane_host/mod.rs`
   `run_gauntlet_session`, `cost_host.rs`; audit `CostHold` for high-rate settle before freeze.
   Re-verify: airlock-version-monotone gate, D2 POD round-trip, byte oracles (esp. billing) unchanged.
   **← merge worktree-2 to integration; re-verify full gate set + D1/D2/D3.**
7. **M5 voice-boot** (serial, after both worktrees): `busbar/src/main.rs` `register_planes()` pushes
   `&busbar_voice::PLANE_DECL` behind the `runtime` feature; voice `PLANE_DECL::parse_section` owns
   `streams:`; Cargo features (default-off so a red voice crate never reddens the neutral release);
   conformance boot-validate. Re-verify: delete-test (voice now a real assertion —
   `git rm -r crates/busbar-voice` still compiles core/substrate/api), isomorphism (4 planes).
8. **T2 voice** (serial, behind `runtime`): four-layer IR → Topology-A WS bridge → Topology-B
   WebRTC → Twilio → Gemini 2nd dialect → runtime session/metering. Gemini + conformance-wire
   contend on `voice-conform.rs` → serialize within this step. Re-verify: voice conformance suite +
   **media verbatim-relay byte-oracle** + all gates.

---

## 5. Merge-back points, re-verify, and RISK points

**Merge-back.** Every worktree merges to `integration/config-seam-stage1-rebased`. Order after the
seam: worktree-1 (transport) and worktree-2 (handle/scope/cost chain) are file-disjoint, so either
merges first; voice merges only after both. **Re-verify at EVERY merge** (not just per-commit): the
full gate set — build, clippy, `plane-purity-lint --check`=0, neutrality, delete-test, no-plugins,
the 5 byte-identity oracles (`egress_differential_tests`, `crossproto_delivery_billing_tests`,
`on_exhausted_tests`, `pool_upstream_creds_tests`, health), airlock-version-monotone, and the
D1/D2/D3 witnesses.

**Risk points where a merge could break byte-identity or purity:**

- **R1 — airlock double-edit (`hot/host.rs`+`pod.rs`).** audit-C and cost-lease both edit these and
  both are airlock-sensitive. Parallel bumps → non-monotone/reshaped ABI → airlock gate + D2
  witness RED. *Mitigation: strict serialize in worktree-2; audit-C first, cost-lease owns the sole
  18→19 bump.* (Highest risk.)
- **R2 — `plane_host/scope.rs` double-edit.** SessScope + audit-C both shape the scope struct.
  *Mitigation: serialize; audit-C's DurableScope before SessScope's field wire-out.*
- **R3 — `cost.rs` byte-identity.** Stage A's `RateEntryCfg`/raw-rate-view is byte-oracle-critical
  (billing/egress-differential). Any T1 CostHold-audit edit to the rate/breakdown path can drift the
  oracles silently. *Mitigation: re-run billing + egress-differential oracles at any `cost.rs`
  touch.*
- **R4 — `voice/lib.rs` convergence / type-break.** If any voice edit (M5/T2/cost-lease) lands
  before Stage A's `streams:` keystone, the voice section won't type. *Mitigation: voice strictly
  after Stage A + T1 + audit-C (enforced by step order).*
- **R5 — purity via the a2a→substrate lift.** Until audit-C lifts `taskstore` and a2a consumes it,
  any voice/LLM reach into `busbar_a2a::` fails purity on the spot. *Mitigation: audit-C before
  voice; `git grep busbar_a2a:: crates/busbar-{llm,voice}`=0 asserted at each merge.*
- **R6 — `plane/mod.rs` mod-tree merge.** Stage A (registry) + audit-C (handle-engine) both add
  module decls. Low risk; re-run plane registry tests at merge.
