# Voice (Plane 4) conformance battery — making it REAL and green

Status of this doc: written from a fresh run of the battery in this worktree
(`bash testing/voice-conformance/voice-conformance.sh --selftest` and `--verdict`,
`cargo test -p busbar-voice --features runtime`), not from the header comments alone. The
header of `testing/voice-conformance/voice-conformance.sh` still describes an "HONEST
SCAFFOLD state" ("the voice runtime does not exist yet"). That is **stale** — the runtime,
codecs, and all four legs are implemented and pass for real. See §1 and §3 for the one
real gap this staleness could cause (a reviewer trusting the comment over the code) and
the fix.

## 1. Current state of each leg

Ground truth, from actually running the harness (`voice-conform`, built via
`cargo build -p busbar-voice --features runtime --bin voice-conform`, 7s clean build) and
reading `crates/busbar-voice/src/bin/voice-conform.rs` (1129 lines) plus the runtime it
drives (`crates/busbar-voice/src/runtime/*.rs`, `crates/busbar-voice/src/ir/codec/*`).

| Leg | `LEG_STATUS` | Wired to real harness? | Notes |
|---|---|---|---|
| gate-selftest | n/a (meta) | **Yes** | `--selftest` plants 8 fixtures (accept/refuse) against the real `emit_verdict`/`_process_leg` code path, not a parallel reimplementation. All 8 pass in this worktree. `verdict-covers-every-leg.py --selftest` and the real coverage lint both pass. |
| spec-per-dialect (openai, gemini) | `ready` | **Yes** | Drives every fixture in `testing/voice-conformance/fixtures/{dialect}/` through `OpenAiRealtimeCodec` / `GeminiLiveCodec` (wire→IR→wire), asserting round-trip stability. 20 openai fixtures + 16 gemini fixtures all produce `RESULT ... PASS`. Documented drops (e.g. `serverContent.inputTranscription.json`, `toolCallCancellation.json`) print as accounted-for PASS rows with a stated reason, never silently absent. |
| replay | `ready` | **Yes** | Threads one `DecodeState` per dialect through its captured `transcript.jsonl` golden and asserts the ordered concept skeleton (config→connect→audio→tool→result→audio→barge-in→close) with no load-bearing drop. openai: 18/18 IR events re-encode; gemini: 14/14. |
| cross-parity (oo, og, go, gg) | `ready` | **Yes** | Drives all 4 ordered pairs through `docs/design/voice-cross-dialect-map.json`; every shared-concept fixture round-trips, every asymmetric (dialect-only) concept is exercised as a documented drop+warn in its origin→other direction. All slices PASS. |
| governance-probe (V1–V4, D2) | `ready` (governance kind — never moves the conformance verdict) | **Yes** | All 5 checkpoints probe the *real* T2 runtime under `--features runtime`: `LocalLease` settle-past-cap hard-close, barge-in cancel+truncate at heard-ms, budget-capped lease exhaustion, usage pricing/settlement, and OpenAI-only fields (`semantic_vad`, `g711`) down-scoped toward Gemini. Separation from the conformance verdict is itself covered by `--selftest` ("a governance leg that FAILs does not fail conformance" → accept). |
| verdict | n/a (aggregator) | **Yes** | `needs:` is `gate-selftest, spec-per-dialect, replay, cross-parity, governance-probe` — exact match to the job set, confirmed by `verdict-covers-every-leg.py` (no missing/ghost/unread legs). Every leg is asserted `== success`; `skipped`/`cancelled` are red, not exempted, matching the MCP/A2A pattern for the *control*-equivalent legs. |

Local full-run output (this worktree): **4 legs declared, 4 ready & passing, 0 pending, 0
conformance failures, 0 accounting problems.** `cargo test -p busbar-voice --features
runtime` (the workspace's separately-run voice suite per `ci.yml`): **68 passed, 0
failed.**

**Bottom line for the count the caller asked for: 0 legs are currently vacuous.** All 5
conformance-workflow jobs (gate-selftest, spec-per-dialect, replay, cross-parity,
governance-probe) execute real assertions against real code; none is a scaffold that
would render vacuous-green. This differs from the `voice-conformance.sh` file header,
which undersells the current state (see §3.1).

One structural difference from MCP/A2A is intentional and not a gap: voice has **no
third-party CONTROL leg** (no "judge a known-good peer first"), because there is no
independent third-party OpenAI-Realtime/Gemini-Live conformance suite to run as a
control, unlike MCP's official SDK or A2A's reference implementation. The battery
substitutes captured, dialect-owner-authored transcripts (`fixtures/{openai,gemini}/`) as
its ground truth instead. This is a real, load-bearing gap relative to the sibling
batteries' two-leg rule — see §3.4.

## 2. Fixtures inventory

| Path | Present? | Content |
|---|---|---|
| `testing/voice-conformance/fixtures/openai/` | **Yes** | 20 files: full session lifecycle (session.created, session.update ×3 variants, input_audio_buffer.* ×5, conversation.item.* ×3, response.* ×6, error.json) + `transcript.jsonl` golden. |
| `testing/voice-conformance/fixtures/gemini/` | **Yes** | 16 files: setup/setupComplete, clientContent, realtimeInput ×3 variants, serverContent.* ×5, toolCall/toolResponse/toolCallCancellation, goAway, usageMetadata + `transcript.jsonl` golden. |
| `docs/design/voice-cross-dialect-mapping.md` | **Yes** (98 lines) | Human-readable rationale for the shared/asymmetric concept split. |
| `docs/design/voice-cross-dialect-map.json` | **Yes** (127 lines) | Machine-readable map `cross-parity.sh`/`voice-conform cross` consumes directly. |

All fixture and mapping inputs the workflow's header calls out as "authored by another
agent; referenced, not created, here" are present and are the ones actually driving
the legs (confirmed by `VC_FIXTURES`/`VC_MAP` path resolution in
`testing/voice-conformance/lib/conform-bin.sh` and by the fixture filenames appearing in
the real `--verdict` output).

## 3. Work remaining to make every leg assert something real

Since every leg already asserts something real today, this section is about closing the
residual honesty/robustness gaps rather than building legs from nothing.

### 3.1 Fix the stale scaffold-era file header (do first — cheap, prevents a real trust failure)

`testing/voice-conformance/voice-conformance.sh` lines 6–24 still say "the voice runtime
does not exist yet... the honest report is PENDING." That is no longer true: `LEG_STATUS`
is `ready` in all 4 `legs/*.sh` files and every leg genuinely executes. A stale comment
claiming *less* capability than the code has is not itself vacuous-green (the runner's
own `--selftest`/`--verdict` output is accurate), but it is a real risk: a reviewer or a
future editor who trusts the comment over the code could "improve" a leg back into a
scaffold, or dismiss a real red as expected-pending noise. **Action:** rewrite the header
to match `mcp-conformance.yml`'s framing ("now WIRED... verdict reflects REAL leg
results," which the *workflow* file already correctly says) and delete the
PENDING-is-legitimate-green section, since no leg is PENDING today. Low risk, no code
change, but load-bearing for anyone auditing this later without re-running it.

### 3.2 Elevate honest PENDING sub-items out of "documented drop" where the underlying gap is closeable

A few fixtures resolve as PASS-but-documented-drop rather than a full round-trip:
- `realtimeInput.audioStreamEnd.json` — "codec drops (map aspires to commit-mapping; not
  yet wired)" — this is the one place the map's own comment (`gg` cross-parity output:
  "codec drops (map aspires to commit-mapping; not yet wired)") admits the *codec*, not
  just the fixture, is short of the map's stated ambition.
- `serverContent.inputTranscription.json` / `outputTranscription.json` — "no shared IR
  home" (structural, likely permanent — fine as documented drops).
- `toolCallCancellation.json`, `goAway.json` — dialect-only concepts with no OpenAI twin
  (structural, fine as documented drops).

**Action:** only `gemini_audio_stream_end` needs follow-up work — either wire the
commit-mapping the map's comment aspires to (making it a real PASS instead of a
documented drop), or edit the map/mapping doc to state plainly that this is a permanent,
not aspirational, asymmetry. Leaving the aspirational language in place while treating it
as accounted-for is the one place today's "documented drop, never faked green" discipline
is doing slightly more work than the underlying map document supports.

### 3.3 Governance leg: tighten what "real" means for V1/V2/V4

D2 and V3 clearly exercise the real `LocalLease`/carrier hard-close path (confirmed via
`runtime::tests::settle_past_cap_hard_closes_the_carrier` and the `gov_d2()`/`gov_v3()`
call sites in `voice-conform.rs`). V1 (barge-in) and V2 (turn-budget) are also driven
through the real session pump per the `--verdict` output detail strings ("response.cancel
+ truncate at the heard ms", "capped lease bounds spend"). **Action:** none required for
correctness; recommend adding one negative-control style assertion per governance
checkpoint (a deliberately-broken lease/pump that MUST fail V1–V4), mirroring
`mcp-conformance.yml`'s `battery-negative-control` job, so the governance probe's own
sensitivity is provable rather than assumed. This is the one structural asymmetry with
MCP/A2A's anti-vacuity discipline that the voice battery does not yet copy.

### 3.4 No third-party CONTROL leg — decide and document the posture explicitly

MCP and A2A's core discipline is "CONTROL runs ALWAYS... a battery that cannot judge a
known-good third-party peer cannot be trusted to judge ours." Voice has no such
leg — there is no independent, third-party-authored OpenAI-Realtime/Gemini-Live
conformance suite to run as control, so the fixtures play a different, weaker role (a
recorded but self-authored transcript, not an external judge). **Action (design
decision, not urgent):** either (a) explicitly document in the workflow header why voice
is exempt from the two-leg rule (no third-party suite exists for these two vendor wire
protocols), which is honest and matches reality, or (b) treat the captured fixtures as
needing external provenance (e.g., captured against the *actual* OpenAI/Gemini APIs, not
hand-built) and state that provenance in the fixtures' own header/README, so "captured
transcript" cannot silently mean "hand-authored JSON that merely matches our own codec's
expectations." Recommend (a) now, with (b) tracked as a real risk (see risk list below).

## 4. The boot-validate leg M5 adds

No "M5" or "boot-validate" leg exists anywhere in this repo today (checked
`.github/workflows/`, `testing/voice-conformance/`, `docs/design/plane4-*.md`,
`docs/design/plane4-duplex-session-1.6.0-plan.md`'s T0–T4 task list). This is therefore a
**forward design**, not a status report on existing work, modeled directly on the pattern
`mcp-conformance.yml`'s `official-subject`/`battery-subject` jobs use for "arm from a
build of this commit, not from an external deployment or variable":

**`boot-validate` (M5) — boot the real T2 session runtime end-to-end and prove the plane
actually starts, not just that its codecs round-trip in-process.**

- **What it adds that the other 4 legs don't cover:** every existing leg drives
  `voice-conform` as a library-call harness against fixtures — no leg boots an actual
  `SessionCore`/carrier over a real transport (WS ingress, egress dial through
  `net_guard`) the way a caller would hit it. `boot-validate` closes that gap: build
  `busbar-voice` with `--features runtime`, stand up the session pump on loopback (same
  posture as `official-subject`'s "boot busbar on loopback, mint a real audience-bound
  credential" — no secret, no external deployment), open both topologies (server-to-server
  WS bridge and the WebRTC sideband mint/relay path) against a fake but wire-real peer, and
  assert: session opens, `PlaneDecl`/`ProtocolDecl` registration is visible, first
  audio/text frame round-trips over the *actual socket*, and a policy-violating dial
  (wrong target, no guard) is refused exactly as `topology::tests::dial_provider_fails_closed_on_a_guarded_target`
  proves in-process today — but over the wire, not just as a unit test.
- **Arm state, not pending/ready:** since the runtime now exists and builds cleanly (this
  worktree confirms `cargo build -p busbar-voice --features runtime --bin voice-conform`
  succeeds in ~7s), `boot-validate` should adopt the MCP/A2A **ARMED OR RED** rule from day
  one rather than voice's now-obsolete PENDING/READY split: publish `armed` as a job
  output (`[ -x target/debug/voice-conform ]` plus a live loopback-boot check, not just a
  binary-exists check), and have `verdict`'s aggregator treat `armed=false` as red exactly
  as `mcp-conformance.yml`'s `armed()` shell function does.
- **Selftest obligation:** before it's trusted, `boot-validate --selftest` must plant (a) a
  boot that never opens a socket (must be refused), (b) a boot that opens a socket but
  never reaches session-established (must be refused), (c) a policy-violating dial that is
  wrongly allowed (must be refused), and (d) a clean, real boot (must be accepted) — the
  same shape as `voice-conformance.sh selftest`'s existing 8 fixtures, extended by these 4.
- **Placement in the workflow:** a new job in `voice-conformance.yml`, `needs:
  gate-selftest`, added to `verdict`'s `needs:` list (which `verdict-covers-every-leg.py`
  will then require by construction — it fails today if a job exists and isn't in
  `needs:`), and read by name in the verdict step's `strict`/`armed` calls.

## 5. Dependency on T2 (spec-per-dialect needs the real codecs)

**This dependency is already satisfied**, not outstanding. `docs/design/plane4-duplex-
session-1.6.0-plan.md` §T2.5 calls out Gemini Live as the task that "earns the superset
IR → the backend-swap moat," and `crates/busbar-voice/src/ir/codec/gemini/mod.rs` (609
lines) plus `crates/busbar-voice/src/ir/codec/mod.rs` (582 lines, the OpenAI codec) are
both implemented and are exactly what `spec-per-dialect` and `cross-parity` drive today —
confirmed by the 20/20 openai and 16/16 gemini fixtures round-tripping through
`OpenAiRealtimeCodec`/`GeminiLiveCodec` in the live `--verdict` run in §1. The
`busbar-voice/Cargo.toml` header comment ("STATUS: SKELETON ONLY... no pump, no
reader/writer bodies") is stale in the same way the shell script header is (§3.1) — the
pump body exists in `runtime/session.rs` (whose own doc-comment says "the pump body the
skeleton in `lib.rs` left `todo!()`", i.e., it was filled in after `lib.rs` was written,
and `lib.rs`/`Cargo.toml` were never updated to say so). **Action:** update
`crates/busbar-voice/Cargo.toml`'s top header and the `lib.rs` skeleton comment to match
current reality, for the same reason as §3.1 — stale "skeleton" language sitting next to
a genuinely working plugin is a standing invitation for someone to either distrust a real
green or, worse, "simplify" working code back toward the skeleton it's described as.

---

## Summary

Read the real harness output (not just file headers) for `testing/voice-conformance/` and
`crates/busbar-voice/`: all 5 conformance-workflow legs (gate-selftest, spec-per-dialect
×2 dialects, replay, cross-parity, governance-probe) execute genuine assertions against
the real `OpenAiRealtimeCodec`/`GeminiLiveCodec` and T2 session runtime — 0 are vacuous
scaffolds today, contrary to what `voice-conformance.sh`'s and `busbar-voice/Cargo.toml`'s
own headers claim. The verdict-coverage lint and `--selftest` both pass. Remaining work is
mostly documentation truth-telling plus two real design gaps: no third-party CONTROL leg
(no such suite exists for these two vendor protocols) and no negative-control for the
governance probe. `boot-validate` (M5) is a genuinely new, not-yet-built leg that should
adopt the ARMED-OR-RED discipline immediately rather than the now-obsolete PENDING/READY
split voice started with.

File: `docs/design/playbook/conformance-voice.md`

Top 3 risks:
1. Stale "scaffold"/"skeleton" headers in `voice-conformance.sh` and `busbar-voice/Cargo.toml` invite a future editor to regress working code back toward the description, or to dismiss a real red as expected.
2. No third-party CONTROL leg — fixtures are self-authored/self-captured, not judged against an independent reference the way MCP/A2A are, so a codec bug shared between the implementation and the fixture author's assumptions would not be caught.
3. `gemini_audio_stream_end` is carried as a "documented drop" while the map's own comment says the mapping "aspires to" wire it — an aspirational gap dressed as an accounted-for one.

Count of legs currently vacuous: **0 of 5** (gate-selftest, spec-per-dialect, replay, cross-parity, governance-probe all execute real assertions; governance-probe is correctly excluded from the conformance verdict itself, per design, not vacuity).
