# busbar 1.6.0 — GAP CENSUS (master checklist)

Status: **AUDIT (read-only).** Adversarial sweep of the tree at worktree `config-seam-work`
(`integration/plane-extraction`) against the DoD: *voice plane booted, four-noun config seam
closed, all CI green, nothing outstanding/deferred.* Every row is verified against code at audit
time. Two design-time facts corrected against the seam audits (which were taken at base
`e393b9e6`): several audit items have **already landed** in this tree and are marked RESOLVED.

Gate status verified live:
- `scripts/plane-purity-lint.sh --check` → **PASS**, BACKWARDS **0**, all categories 0. No residual.
- `scripts/plane-abi-neutrality.sh` → **PASS**, 0 banned nouns in `hot/`. (Memory's "fails on
  busbar-plugin/src/hot/*" is **STALE** — it passes now. Recorded as G19.)
- `cargo check -p busbar-voice --features runtime` → **exit 0** (substrate+voice compile clean).

Legend — Sev: CRIT/HIGH/MED/LOW. Scope: IN = gates 1.6.0 DoD, OUT = out of 1.6.0.
Workstreams referenced (designed elsewhere, coverage only noted here): **StageA** (remove
`NamedMapSection::Tools/Agents`), **M5** (voice-boot), **T1** (transport-WS / pump / SessionScope /
cost-lease / media), **T2** (WebRTC / Twilio g711 / Gemini Live / runtime pump / voice IR),
**no-deferral-gate**, **done-oracle**. **ORPHAN** = no listed workstream owns it.

---

## A. THE PRIMARY BUILD GAPS (in-scope, workstream-owned)

**G1 — StageA not started: `NamedMapSection::Tools`/`Agents` still present + ~50 call sites.**
`crates/busbar-core/src/config/named_map.rs:28` (enum has 4 variants: IdentityProviders, Export,
**Tools**, **Agents**); `ALL` at `:54`. Consumed across `busbar-core` (appbuild.rs:1272/1304/1438/
1541/1570/1575; config/mod.rs:4690/4962; admin/v1/service.rs:1095/1135; admin/v1/json/named_map.rs:
667; plane/config.rs:276-321; config_validate/mod.rs:1030; test_support/mod.rs:1519+), `busbar-mcp`
(tools_config_tests.rs:401/633), `busbar-a2a` (config_tests.rs:507-538), `busbar-substrate`
(plane/registry.rs:338). Scope: **IN** — the four-noun config seam is not closed while the two
plane-shaped nouns still live on the shared map enum. Workstream: **StageA**. Sev **HIGH** (large
blast radius across 5 crates + admin OpenAPI + config migration).

**G2 — M5 voice-boot fully un-wired: the binary neither depends on nor boots `busbar-voice`.**
`crates/busbar/Cargo.toml` has no `busbar-voice` dep; `main.rs:658 register_planes()` installs
llm/mcp/a2a only (`:668/670/675`), never `busbar_voice::PLANE_DECL`; `main.rs:690
register_diagnostics()` omits `busbar_voice::DIAGNOSTICS`; `VOICE_BUILD_RUNTIME = None` in the
default build (`busbar-voice/src/lib.rs`). Voice runtime is real (compiles under `runtime`) but
nothing links or registers it. Scope: **IN** (DoD = "voice plane booted"). Workstream: **M5**.
Sev **HIGH**.

**G3 — SessionScope RAII / money-path half still stubbed (arena, Drop, lease, pipes).**
Durable-binding half LANDED (`crates/busbar-substrate/src/plane_host/scope.rs:382-484`, 3 fields
engine/owner/id; voice consumes it at `busbar-voice/src/runtime/scope.rs:82-199`). Still missing:
the owning `DispatchScope` arena, `Drop`-reclaim of the pooled upstream socket, and the
`Drop`-bearing lease holder — audit A(2)/B(4). Without them an abnormal session close/panic leaks
the pooled socket and the cost reservation (finalize never runs). Scope: **IN**, one-way door (first
field set is inherited by every future duplex plane). Workstream: **T1 SessionScope** (playbook
`docs/design/playbook/t1-session-scope.md`). Sev **HIGH**.

**G4 — Duplex pump port: MCP correlation table keyed on MCP `id_key`, must lift to a plane-neutral
`CallRef`.** Working single-reader + correlation table already exists on the MCP **server** leg
(`crates/busbar-mcp/src/mcp/stdio_serve.rs:280/292/393/401/424`); the client leg lacks it
(`mcp/client/stdio.rs:822-827`). Lifting to substrate must not drag MCP's JSON-RPC `id_key`
vocabulary into the neutral pump (audit A(4)/E(1)). Also ratify (audit E ranked-1): the voice pump
is a **new** bidirectional path on `pipe_read`/`pipe_write` + `InboundKind::Stream`/
`EmitKind::Unsolicited` + `SessionScope`, NOT a reuse of `StreamTranslate`/`FirstByteBody`
(response-only, `proto.rs:444`, `engine/response_body.rs:234`). Scope: **IN**. Workstream: **T1
pump port / T2 runtime pump**. Sev **MED**.

**G5 — Media Layer-3: `IrAudioFrame{dir,seq}` net-new; no per-frame carrier / streaming codec.**
`MediaBlob` (`crates/busbar-substrate/src/media.rs:103`) is whole-payload one-shot; the verbatim
response tap (`proto_stream.rs:91-97`) is response-direction only; `TranscriptionReq.stream`/
`SpeechReq.stream` (`audio.rs:66/161`) are vestigial delivery-mode bits with no incremental codec
(audit E ranked-2/3). Must build a new incremental frame IR beside `MediaBlob`, not on top of it.
Scope: **IN**. Workstream: **T1 media path** (playbook `t1-media-path.md`) / **T2 voice IR**.
Sev **MED**.

**G6 — D2 cost-lease: mechanism ARMED in nanodollar denomination; residual owner-decisions only.**
`busbar-substrate/src/plane_host/mod.rs:395-416 MeteringHost::cost_reserve(estimate_nanos:u128)/
cost_settle(exact_nanos:u128)` + `SettleOutcome` (`:370`) + `CostHold::is_exhausted()`/`remaining()`
(`busbar-core/src/plane/cost.rs:380/369`). This RESOLVES audit-B CRIT items 1 (plane pre-prices to
nanos, host never prices), 2 (exhaustion accessors now exist), 3 (scalar readback via
`SettleOutcome`). **Residuals:** (a) `MagnitudePod.caller_cap`/`Magnitude.caller_cap: Option<u64>`
still loses `Some(0)` refuse-all if that Pod is on any frozen hot-ABI slot (audit B(4)/B(5) —
`cost.rs:281`); (b) who fires the **session-open** reserve — the opening charge lives in consumed
`drive` which the session sibling can't call (audit B(6)). Scope: **IN**. Workstream: **T1
cost-lease / T2 metering** (voice metering port already present: `busbar-voice/src/runtime/
metering.rs`). Sev **MED** (down from CRIT — mostly resolved).

**G7 — Transport::WebSocket ARMED, but there is still no ingress-listener dispatch keyed on
`Transport`.** Ingress/egress duplex WS is implemented under `busbar-substrate/runtime`
(`egress/duplex_ws.rs`, `ingress/duplex_ws.rs`, `Transport::WebSocket => UpstreamWireKind::Duplex`
at `transport.rs:252`). But ingress still keys on protocol-name string (`arrival.rs`), not on
`Transport` — the acceptor side is not a `Transport`-axis dispatch for ANY variant (audit A(3)
scope-honesty). Resolve whether 1.6.0 needs the generic axis or the point WS wiring suffices.
Scope: **IN** (point wiring), axis generalization arguably OUT. Workstream: **T1 transport-WS**.
Sev **LOW/MED**.

**G8 — D3 gauntlet single-`Response` foreclosure: needs a `run_gauntlet_session` sibling + a witness
test to keep the door open.** `run_gauntlet`/`GauntletPlane::drive` are append-safe only as a free
fn + trait (`plane_host/mod.rs:167/177`); a 1.6.0 "simplification" that inlines it or makes the
one-`Response` return the sole session entry forecloses the duplex sibling (audit B Seam 2 /
D ranked-2). Scope: **IN**. Workstream: **T1 SessionScope / T2 runtime session pump**. Sev **MED**.

---

## B. RESERVED SUBSTRATE SEAMS — status (task item 2)

**G9 — WorkItem `InboundKind::Stream` / `EmitKind::Unsolicited`: tags WIRED; host EMIT slot is a
future append-only add.** `crates/busbar-plugin/src/hot/workitem.rs:25-47` (`Stream`=?, `Unsolicited`
=3, doc "WIRED for duplex-session"). Carriers are present and reshape-proof (audit C Seam 3 / D
"not surfaced — adequate"). The out-of-process host emit slot for `Unsolicited` is NOT needed for
1.6.0 voice (voice uses the substrate trait path, not the hot ABI). Scope: **OUT** (reserved).
Workstream: none needed. Sev **LOW**.

**G10 — Hot-ABI `PlaneHostVtable::STUB`: ~48 `unimplemented!()` host-call stubs (incl. `cost_reserve`
/`cost_settle`).** `crates/busbar-plugin/src/hot/host.rs:652-711` — an explicit compile-surface
fixture ("Downstream agents replace each stub… a real host replaces each with an impl", `:652`,
`:707`). This is the **out-of-process protocols-as-plugins** keystone (design
`docs/design/1.6.0-protocols-as-plugins.md`, present in the main worktree), NOT on the 1.6.0 voice
path — voice consumes the neutral `busbar_substrate::plane_host` traits, which ARE implemented.
Scope: **OUT** of 1.6.0 (declared-now/wired-later). Workstream: protocols-as-plugins (post-1.6.0).
Sev **LOW**. *(Adversarial note: nothing in the 1.6.0 gates forces these to be real; confirm no
done-oracle rule trips on `unimplemented!` in `hot/`.)*

**Reserved-seam summary:** `SessionScope` (G3 — binding done, RAII half open), `cost_reserve/settle`
(G6 — substrate trait armed; hot-ABI slot stubbed/out-of-scope), `Transport::WebSocket` (G7 —
armed), `InboundKind::Stream`/`EmitKind::Unsolicited` (G9 — tags wired). **None of the substrate
reserved seams is a blocking stub for 1.6.0 except the SessionScope RAII half (G3).**

---

## C. AUDIT A–E FIX ITEMS — cross-check (task item 3). RESOLVED items proven against this tree.

**G11 — WS-arrival `ArrivalPayload` dual-compile TypeId trap: RESOLVED.** Audit A(1)/D(1) HIGH
flagged the payload as `busbar-core`-owned/private. In THIS tree it is **substrate-owned**:
`busbar-substrate/src/ingress/arrival.rs` defines `ArrivalPayload`, and core re-exports it
(`busbar-core/src/ingress/arrival_host.rs:24 pub use busbar_substrate::…::ArrivalPayload`). Residual
(minor): `ArrivalCtx(Box<dyn Any>)` is still an unconstrained generic downcast (`arrival.rs:35/46`)
guarded by doc + `.expect()` (`arrival_host.rs:28`) — a second minter of a wrong type still trips at
runtime. Scope: **IN** (harden or test the single-minter invariant). Workstream: **T1 transport-WS**.
Sev **LOW** (core hazard resolved).

**G12 — `SubmitRecord.event` is now `Option<SealedEvent>`: audit C(3) RESOLVED.**
`busbar-substrate/src/plane/handle_engine.rs:175` — a durable handle without a per-event chain
(Responses-stateful, voice-session) is expressible with no dummy genesis. No action. Sev n/a.

**G13 — `scoped_mutate(owner,id,plan)` exists: audit C(2) RESOLVED.** `SessionScope::mutate` →
`engine.scoped_mutate` (`scope.rs:461-469`); the write path is now anti-enumeration-hardened like the
read path. No action. Sev n/a.

Remaining A–E items map to G3 (A2/B1-4), G4 (A4/E1), G5 (E2/E3), G6 (A5/B1-6), G7 (A3/A6), G8
(B-seam2/D2). **Every A–E surface-now item is either RESOLVED (G11/G12/G13) or owned by a T1/T2
workstream row above** — none is un-covered EXCEPT the two hygiene items D3/D4 (see G16/G17) and the
handle-engine-C throughput/witness items (G14/G15).

---

## D. HANDLE-ENGINE AUDIT-C 2ND-CONSUMER FIXES (task item 4) — mostly ORPHAN

**G14 — [ORPHAN] Process-wide `handles` Mutex held across durable-store I/O in mutate/sweep/
rehydrate.** `busbar-substrate/src/plane/handle_engine.rs:317` (single `self.handles.lock()`), audit
C ranked-1: a concurrent second consumer (voice sessions, Responses-stateful) hits a process-wide
bottleneck where A2A's serial cadence hid it. Shard to per-handle lock or document the deliberate
submit-vs-mutate asymmetry. Not owned by any listed workstream. Scope: **IN** (one-way door once a
concurrent consumer depends on current semantics — voice IS that consumer). Sev **MED** (dangerous:
correctness-adjacent under concurrency, and hardest to change later).

**G15 — [ORPHAN] Dual-compiled `Box<dyn Any>` readback witness not landed.** Audit C ranked-4: the
handle-engine opacity claim (a foreign plane's row survives store round-trip under two `busbar-core`
compile units) is asserted, not demonstrated — only constructor is `taskstore.rs:504`; no core slot
rides the engine today. Prove it before voice (the second consumer) inherits it. Scope: **IN**
(correctness assurance for the seam voice builds on). Sev **MED**.

**G16 — [ORPHAN, docs] Signpost the three overlapping durable primitives + reconcile extraction
notes.** Audit C ranked-5/6: `DurableHandleEngine` vs `journal_*` host family
(`hot/host.rs:489-503`) vs stubbed `workhandle_open`/`resume` (`hot/host.rs:791-802`) are
unsignposted; `docs/design/1.6.0-handle-engine-extraction-notes.md` still documents the pre-landing
API (`HandleUpdate`/`apply`/`advance_cursor`/`get_scoped`) rather than the shipped `Mutation`/single
`mutate`/`scoped_get`/`MutateError::Rejected`. Scope: **IN** (docs hygiene, gates "nothing
outstanding"). Sev **LOW**.

---

## E. PLANE-PURITY / ABI-NEUTRALITY RESIDUALS (task items 5, 7)

**G17 — plane-purity BACKWARDS residual: NONE.** `plane-purity-lint.sh --check` reports
BACKWARDS 0 and TOTAL 0, verdict PASS. No gap.

**G18 — [ORPHAN, hygiene] `EngineHost` god-trait (~32 flat methods) + `LlmBuildInput` LLM-naming.**
Audit D ranked-3/4: split `EngineHost` into supertraits before voice + Bucket-C accrete more;
rename `LlmBuildInput` (`build_input.rs:279`) → `PlaneBuildInput` if it is the general duplex build
carrier. Neither is correctness. Scope: **OUT** of 1.6.0 (hygiene; cheapest now but non-gating),
UNLESS voice references `LlmBuildInput` by name — then the rename becomes IN. Sev **LOW**.

**G19 — plane-abi-neutrality: PASS (memory stale).** `plane-abi-neutrality.sh` → 0 banned nouns in
`hot/`. The memory note "fails on busbar-plugin/src/hot/*" no longer reproduces on this tree. No gap;
recorded so the build phase does not chase a phantom. Sev n/a.

---

## F. DEFERRAL-MARKER SWEEP (task item 1) — classification

Grep of `TODO|FIXME|SKELETON|PENDING|DEFER|unimplemented!|todo!|stub` across `crates/**.rs`:

- **hot-ABI stubs** (`hot/host.rs` ~48 `unimplemented!()`) → G10, OUT-of-scope keystone.
- **`busbar-voice` "SKELETON"** doc string (`lib.rs:4`, and `DIAGNOSTICS` "Not yet booted… joins at
  M5") → **G20** below, tied to M5 (doc/boot drift), IN.
- **Algorithmic "deferred terminal frame"** comments in `busbar-llm` (`proto_stream.rs`,
  `proto_codec.rs`, `bedrock/mod.rs`, `engine/response_body.rs`) and `busbar-substrate/proto.rs:445`
  → these describe the SSE terminal-usage FOLD state machine (deferred `message_delta`/`metadata`
  emission), NOT incomplete work. **Not gaps.**
- **`plugin-sign` `TODO(release-keys)`** (`crates/plugin-sign/src/lib.rs:80`) — the real release
  keypair is generated by the release orchestrator, by design. **OUT** (release infra), benign.
- **`main.rs` migration `TODO/WARNING`** (`:208/1699/1744`) — the config-migration CLI *emits*
  TODO comments into user output; not a code gap.
- **`ir/facts.rs:292`, `net_guard.rs:722`, `audit/vocab.rs:67`, `diagnostics` `*_PENDING_*`** —
  vocabulary constants / rejected-design commentary / real diagnostics. **Not gaps.**

**No ORPHAN deferral marker on the voice/config path.** All markers are covered-by-workstream,
out-of-scope-keystone, or benign-algorithmic.

**G20 — [ORPHAN-ish, doc] `busbar-voice` still self-documents as "SKELETON" while its runtime is
implemented and compiles.** `lib.rs:4` ("SKELETON"), `:29` ("Not yet booted by the binary — voice
joins register_diagnostics at M5"). Cosmetic but violates "nothing outstanding" once M5 lands.
Fold into **M5**. Sev **LOW**.

---

## G. NO-DEFERRAL GATE + DONE-ORACLE (workstreams) — not yet present

**G21 — no-deferral gate script does not exist.** No `scripts/*deferr*`; no CI job asserting
zero unresolved deferral markers on the release change set. Scope: **IN** (DoD explicitly forbids
deferrals). Workstream: **no-deferral-gate** (being designed). Sev **MED** (this census is its
input corpus).

**G22 — done-oracle does not exist.** No `scripts/*done*`/`*oracle*` gate mechanizing "voice booted
+ four-noun seam closed + green". Scope: **IN**. Workstream: **done-oracle**. Sev **MED**.

---

## H. TEST HEALTH (task item 8)

**G23 — [ORPHAN] `admin::tests::…named_map_error_surface…` noted flaky.** Present at
`crates/busbar-core/src/admin/tests/tests.rs:14525`
(`named_map_error_surface_answers_its_declared_taxonomy`). Not independently re-run in this audit
(workspace test compile cost). Note: StageA (G1) rewrites the `NamedMapSection` taxonomy this test
asserts, so it will change regardless — sequence the flake fix WITH StageA rather than before.
Scope: **IN** ("all CI green"). Sev **MED** (flake blocks a green gate). Ownership unclear → ORPHAN,
recommend folding into StageA.

*(Not exhaustively re-run: full `cargo test` workspace. `cargo check -p busbar-voice --features
runtime` is green; plane gates green. A full green-CI pass is itself a done-oracle obligation, G22.)*

---

## I. KICKOFF DEFERRED OWNER-REVIEW ITEMS (task item 6) — scope classification

All six are pre-existing LLM-plane / security-posture questions unrelated to the voice plane or the
four-noun config seam. Default classification: **OUT of 1.6.0** (owner-review backlog, non-gating),
subject to owner override.

- **G24 — Image `detail` cross-pair drop** (LLM image translation fidelity): **OUT** — LLM-plane
  translation nicety; no voice/config dependency.
- **G25 — Gemini multi-input embeddings truncation**: **OUT** — LLM embeddings edge; no DoD link.
- **G26 — Governance budget concurrent-overshoot**: **OUT of voice DoD**, but ADJACENT to G14 (the
  same class of process-wide-concurrency budget race the handle-engine Mutex exhibits). Flag for the
  owner: if voice sessions are the first true concurrent budget consumers, this graduates to IN.
  Sev **MED** if graduated.
- **G27 — First-party plugin anti-downgrade floor**: **OUT** — plugin-trust posture, ties to the
  post-1.6.0 protocols-as-plugins work (G10), not this release.
- **G28 — SigV4 secret-at-rest**: **OUT** — Bedrock egress-auth secret hygiene; security posture
  backlog, no voice/config dependency.
- **G29 — engine `deny` vs `forbid(unsafe_code)`**: **OUT** — lint-strictness policy; note that the
  hot-ABI (`extern "C-unwind"`, G10) is where `unsafe` actually lives, so resolve WITH that keystone,
  not in 1.6.0.

---

## SUMMARY

- **In-scope build gaps (workstream-owned):** G1 (StageA), G2 (M5), G3/G4/G5/G6/G7/G8 (T1/T2),
  G21/G22 (gate/oracle). All have a home.
- **RESOLVED-since-audit (do not rebuild):** G11 (arrival payload substrate-owned), G12
  (`SubmitRecord.event: Option`), G13 (`scoped_mutate`), plus D2 CRIT items 1-3 folded into G6.
- **ORPHAN gaps (no listed workstream owns them): 8** — G14, G15, G16, G18, G20, G23; plus
  conditionally G26 (if it graduates) and G29-adjacency. Core count of genuine unassigned
  in-scope work: **G14, G15, G16, G20, G23** (5 clearly IN + unowned) with G18 hygiene borderline.
- **Reserved seams needing NO 1.6.0 impl:** G9, G10 (out-of-scope keystone).
