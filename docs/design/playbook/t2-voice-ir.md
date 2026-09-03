# Playbook T2 — Completing busbar-voice's four-layer duplex/session IR

Status: playbook (build-facing), derived from `docs/design/plane4-duplex-session.md` (authoritative
design, "AUTHORITATIVE DESIGN (not build)") and `docs/design/plane4-seam-audit-E-ir.md` (adversarial
audit). Scope: `crates/busbar-voice/src/ir/` as it exists on `integration/plane-extraction` today.

**Correction to the "TYPE STUBS" premise.** `crates/busbar-voice/src/ir/mod.rs:24-25` still says
*"SKELETON: every type below is a STUB… bodies are `todo!()` or minimal"* — that comment is now
**stale**. `git grep -n 'todo!\|unimplemented!' crates/busbar-voice/src/ir/` returns exactly one hit,
inside that same doc-comment string, not in any function body. The reader/writer pair for BOTH
dialects is implemented with real hand-mapped logic and a substantial test suite:
`crates/busbar-voice/src/ir/codec/mod.rs` (582 lines, `OpenAiRealtimeCodec` reader+writer, both
directions) + `crates/busbar-voice/src/ir/codec/tests.rs` (526 lines, 26 `#[test]` fns) +
`crates/busbar-voice/src/ir/codec/gemini/mod.rs` (609 lines, `GeminiLiveCodec`) +
`crates/busbar-voice/src/ir/codec/gemini/tests.rs` (619 lines, 33 `#[test]` fns). What remains is
narrower than the mod.rs doc-comment implies: the runtime (pump/session-store/gauntlet wiring) is
genuinely not built (and is explicitly out of `busbar-voice/src/ir/`'s scope — it is substrate/P1-P2
work per `plane4-duplex-session.md` §4.3, §5), one usage→`CostBreakdown` fold is marked future work,
and the mod.rs doc-comment itself needs updating so nobody re-derives a stale "build everything"
task list from it.

---

## 1. The four IR layers — concrete types, stub vs built

| Layer | Module | Concrete types | Status |
|---|---|---|---|
| 1 — tool-call | `crates/busbar-voice/src/ir/tool.rs` | `CallRef(u64)` (`tool.rs:23`), `IrDuplexTool{CallOpen,CallArgs,CallClose,CallResult}` (`tool.rs:35-71`) | **Types built.** No `todo!()`. Reader/writer bodies live in `codec/mod.rs:449-479` (write_up), `:490-518` (write_down), `:334-365` (read_down tool cases), `:255-269` (read_up `CallResult`) — all real, all tested (`codec/tests.rs:302-413`). |
| 2 — control/config | `crates/busbar-voice/src/ir/control.rs`, `crates/busbar-voice/src/ir/config.rs` | `Eagerness`, `IrVad{ServerVad,SemanticVad}` (`control.rs:19-73`), `IrDuplexControl{SessionConfigure,ResponseCreate,ResponseCancel,InputAudioCommit,InputAudioClear,ItemCreate,ItemDelete,ItemTruncate}` (`control.rs:77-121`), `SessionConfig` (`config.rs:92-139`, GA `session` object, faithfully typed incl. `MaxOutputTokens` int-or-`"inf"` custom (de)serialize at `config.rs:24-56`) | **Types + serde built.** Reader/writer real (`codec/mod.rs:229-292` read_up, `:416-448` write_up). Barge-in `audio_played_ms` is derived, not copied (see §2 below). |
| 3 — media/audio-frame | `crates/busbar-voice/src/ir/media.rs` | `UpDown{Up,Down}`, `AudioFormat{Pcm16,G711Ulaw}` w/ `bytes_per_ms`/`bytes_to_ms`/`ms_to_bytes` (`media.rs:20-84`), `truncate_point_ms` (`media.rs:93-95`), `IrAudioFrame{dir,seq,media:Bytes}` (`media.rs:99-107`) | **Types + arithmetic built,** identity-transform reader/writer real (`codec/mod.rs:241-248` decode, `:411-414`/`:535-538` encode). `codec::DecodeState` (`codec/mod.rs:76-161`) carries the per-session `up_seq`/`down_seq`/`played_bytes`/`output_fmt` this layer needs. |
| 4 — usage/rate-limit | `crates/busbar-voice/src/ir/usage.rs` | `IrDuplexUsage{audio_in,audio_out,text_in,text_out,cached}` (`usage.rs:16-28`) | **Type built + extraction wired** (`codec/mod.rs:389-404` `extract_usage`, `:560-574` `usage_to_wire`, tested `codec/tests.rs:414-441,511-525`). **Genuinely open:** `usage.rs:15` says *"the `CostBreakdown` fold is future work"* — no code today converts `IrDuplexUsage` into a `busbar-core::plane::cost::CostBreakdown`. That's the money-path gap (§3).

Plus the event unions that project the four layers onto the two directions of travel —
`crates/busbar-voice/src/ir/event.rs`: `IrClientEvent{AudioFrame,Control,Tool}` (`event.rs:19-26`,
the genuinely net-new client→server vocabulary — no analog anywhere else in the tree, confirmed by
audit §1.2/§Seam1) and `IrServerEvent{SessionCreated,Tool,SpeechStarted,SpeechStopped,AudioFrame,
AudioDone,Usage,RateLimits,Error}` (`event.rs:31-74`, sibling of `busbar-llm`'s `IrStreamEvent`, not
an extension of it). Both are fully matched by the codec's `read_up`/`read_down`/`write_up`/
`write_down` (`codec/mod.rs:198-214` trait defs, `:222-385` OpenAI impl, `gemini/mod.rs` Gemini
impl).

**To build (not in `ir/` today, out of this doc's write scope but load-bearing context):**
- The substrate bidirectional pump (`plane4-duplex-session.md` §4.3) — a port of MCP's `Session<W>`
  (`crates/busbar-mcp/src/mcp/stdio_serve.rs:383-410`) that actually drives `DuplexReader`/
  `DuplexWriter` over live `pipe_read`/`pipe_write` bytes. `codec/mod.rs` has the trait + both dialect
  impls; nothing in the tree calls them from a live socket yet — verified: `git grep -rn
  "DuplexReader\|DuplexWriter" crates/ --include=*.rs` outside `busbar-voice/src/ir/` is empty.
- `SessionScope` wire-out (`crates/busbar-substrate/src/plane_host/scope.rs:366`, still the empty
  `#[non_exhaustive]` stub) to hold the `CallRef` table, the two `PipeId`s, the `CostHold` lease.
- The D2 ABI slots (`cost_reserve`/`cost_settle`, frozen signatures at
  `docs/design/plane4-duplex-session.md` §6, not yet added to `PlaneHostVtable`).

---

## 2. The read→IR→write roundtrip fidelity contract

**The user's requirement, restated precisely against this plane's asymmetric layers (design §2.1,
§10 first bullet):** same-dialect must be **100% lossless**; cross-dialect is **best-effort, honestly
bounded** — never silently lossy, every loss point named. This is not a hedge; it is the same
discipline the LLM plane's `roundtrip_fidelity_tests.rs` already encodes for chat (an EXACT allow-list
of accepted divergences, not a fuzzy budget), extended to the reality that Plane 4 has TWO distinct
fidelity classes where the LLM plane effectively has one (LLM's `same_proto` path bypasses the IR
entirely via byte-verbatim short-circuit; voice's Layer 3 media *is* the IR and must stay verbatim
through it, not around it).

### 2.1 Two fidelity classes, precisely

1. **Same-dialect (OpenAI Realtime → IR → OpenAi Realtime).** Must be **byte-exact on the wire fields
   that round-trip through the IR untouched**, and **value-exact** (not necessarily byte-exact, since
   JSON re-serialization is fine) everywhere else. Concretely:
   - Layer 3 (media): the *decoded* bytes are the identity — `decode_audio` (`codec/mod.rs:183-185`)
     → `IrAudioFrame.media: Bytes` → `encode_audio` (`codec/mod.rs:188-190`) must satisfy
     `encode_audio(decode_audio(b64)) == b64` for any valid base64 payload. This is a pure roundtrip
     property test, not yet in `codec/tests.rs` as a `proptest`/quickcheck — today it's covered only by
     example-based tests (`uplink_audio_append_decodes_base64_and_frames_up`,
     `downlink_audio_delta_frames_down_tracks_playback_and_bumps_seq`, `codec/tests.rs:184-239`).
   - Layer 1 (tool): `call_id` is carried on every IR variant precisely so the writer is **stateless**
     (`codec/mod.rs:21` doc, `:406-408`) — a same-dialect round trip must reproduce the exact `call_id`
     string, never a re-minted one. Tested: `function_call_output_authoring_roundtrips`
     (`codec/tests.rs:384-413`), `tool_call_loop_correlates_by_call_id` (`:302-382`).
   - Layer 2 (control): `SessionConfig`'s `#[serde(skip_serializing_if = ...)]` discipline
     (`config.rs:100-138`) is exactly what makes a *partial* `session.update` patch JSON-stable —
     absent fields decode to `None` and stay absent on re-encode, so a same-dialect round trip never
     synthesizes a field the client didn't send. The one deliberate exception is `turn_detection`,
     serialized even when `None` because GA distinguishes `null` (VAD disabled) from omitted
     (`config.rs:90-91` doc, `:127`) — that is a **documented, tested** non-divergence, not a loss
     (`session_update_null_turn_detection_disables_vad`, `codec/tests.rs:138-150`).
   - Layer 4 (usage): `extract_usage`/`usage_to_wire` (`codec/mod.rs:389-404`, `:560-574`) is a lossy
     shape today by construction — it drops `total_tokens` provenance nuance and rebuilds it as a sum
     — but since usage is **extraction-only, never client-facing** (design §2.5, "not client-facing"
     in the mod.rs table row `mod.rs:16`), byte-exactness on the re-emitted `usage` object is not a
     contract the plane makes; only the extracted token-class values must be exact
     (`usage_extraction_survives_reencode`, `codec/tests.rs:511-525`).

2. **Cross-dialect (OpenAI Realtime ⇄ Gemini Live via the shared IR).** The Gemini codec's own header
   states the honest bound (`gemini/mod.rs:26-28`): setup translation is a genuine cross-dialect map,
   "**a FIXPOINT at the IR level (wire→IR→wire→IR is stable) but not byte-for-byte**." That is the
   correct, and only honest, cross-dialect contract for a control-layer shape with no shared byte
   grammar: `read(write(read(wire))) == read(wire)` — decode is idempotent past the first hop, not that
   `write(read(wire)) == wire`. Tested directly: `setup_is_ir_fixpoint_across_reencode`
   (`gemini/tests.rs:112-127`), and the uplink audio analog `realtime_input_ga_audio_is_ir_fixpoint`
   (`gemini/tests.rs:291-316`, "decode GA audio → write → decode yields the same IR" — audio itself
   *is* byte-stable cross-dialect since both dialects carry raw PCM, only the envelope differs).
   Tool-call cross-dialect fidelity is a **shape** claim, not a byte claim: Gemini's atomic
   `toolCall.functionCalls[]` expands into the same streamed `CallOpen→CallArgs→CallClose` triple
   OpenAI streams natively (`gemini/mod.rs:21-25` doc, tested `tool_call_expands_atomic_call_and_
   correlates`, `gemini/tests.rs:434-469`) — correlation is exact, framing cadence is not, and that
   asymmetry is named in the module doc rather than hidden.

### 2.2 The `roundtrip_fidelity_tests` pattern to mirror

The LLM plane's pattern (`crates/busbar-llm/src/tests/proto/roundtrip_fidelity_tests.rs:1-120`) is
the template to port, not re-invent:

- A **`Divergence(String)`** leaf-diff type (`roundtrip_fidelity_tests.rs:44-45`) rendered as one
  stable string per differing JSON leaf (`"LOST …"` / `"ADDED …"` / `"CHANGED …"`), so a failure diff
  is greppable and value differences (float formatting, key order) don't spuriously fail the test —
  only *structural* divergence does (`diff()`, `:55-94`).
  - `LOST` = present in the original, absent after the round trip (the loss class).
  - `ADDED` = the writer synthesized a leaf the original didn't carry (a proxy tell, or a
    dialect-required default).
  - `CHANGED` = a leaf's *value* changed (the corruption class).
- Each test declares an **EXACT allow-list** and asserts **set equality**, not a budget
  (`roundtrip_fidelity_tests.rs:21-34`, the "why an allow-list not a budget" doc): a *new* divergence
  fails (catches regressions), and a divergence *disappearing* also fails (forces the allow-list entry
  to be deleted when a fix lands, keeping it a live reviewed inventory instead of a stale comment).
- `assert_request_roundtrip(proto, body, allowed)` / `assert_response_roundtrip(...)`
  (`roundtrip_fidelity_tests.rs:98-117`) run `reader.read_* → writer.write_*` through the real
  registered codec and diff the output against the input.

**The port for `busbar-voice`, concretely — a new file
`crates/busbar-voice/src/ir/codec/roundtrip_fidelity_tests.rs`:**

```rust
// same-dialect: OpenAI wire → IR → OpenAI wire, per wire event type, on RICH fixtures
fn assert_up_roundtrip(codec: &OpenAiRealtimeCodec, wire_json: Value, allowed: &[&str]) {
    let mut st = DecodeState::default();
    let ir = codec.read_up(wire(&wire_json.to_string()), &mut st);
    // same-dialect: exactly one IR event in, one wire event out, for the control/tool cases;
    // media is per-frame 1:1 by construction (codec/mod.rs read_up INPUT_AUDIO_APPEND arm).
    let out = ir.into_iter().map(|e| as_value(&codec.write_up(e))).collect::<Vec<_>>();
    assert_divergences("openai-realtime", "UP", &wire_json, &out[0], allowed);
}
// mirror for assert_down_roundtrip (read_down/write_down) and a cross-dialect variant that
// round-trips OpenAI wire -> IR -> Gemini wire -> IR and asserts IR-fixpoint (§2.1 class 2)
// rather than wire-equality, per the gemini/mod.rs:26-28 honesty bound.
```

Fixtures to seed it from (all already exist as example-based assertions in `codec/tests.rs` /
`gemini/tests.rs` — the port's job is to generalize them into the allow-list diff harness, not
invent new coverage):
- `ga_session_server_vad()` (`codec/tests.rs:52-75`) — the richest `SessionConfig` fixture, exercises
  every field including `tools`/`tool_choice` opaque passthrough and `max_output_tokens: "inf"`.
- `gemini_setup()` (`gemini/tests.rs:54-73`) — the cross-dialect control fixture that must assert
  IR-fixpoint, not wire-equality (§2.1).
- The tool-loop fixture in `tool_call_loop_correlates_by_call_id` (`codec/tests.rs:302-382`) and its
  Gemini atomic-expansion analog (`gemini/tests.rs:434-469`).

**Known, currently-undocumented allow-list candidates** (divergences the port will need to declare,
not fix, on day one — surfacing them now so the first commit isn't a surprise red build):
- Layer 4 `usage_to_wire` re-derives `total_tokens` as a sum rather than carrying whatever the
  original `total_tokens` value was verbatim (`codec/mod.rs:563`) — an `ADDED`/`CHANGED` on
  `response.usage.total_tokens` is expected and acceptable per §2.1 class 1's usage carve-out, but it
  must be an explicit allow-list line, not silent.
- `IrDuplexControl::ResponseCreate{response: Option<Value>}` carries the per-response override object
  opaquely (`control.rs:85-90`) — any field OpenAI adds to that object round-trips fine (opaque
  passthrough), but if a *future* codec edit ever starts destructuring it, this is the regression
  surface the allow-list would catch first.

---

## 3. Usage IR → `usage_units` → the money path

**Today's wiring stops one hop short of the ledger.** `extract_usage` (`codec/mod.rs:389-404`) pulls
`IrDuplexUsage{audio_in, audio_out, text_in, text_out, cached}` off `response.done.usage`'s
`input_token_details`/`output_token_details` — this is real, tested code, doing exactly the same move
the LLM reader makes with `recover_truncated_usage` (`crates/busbar-llm/src/proto_codec.rs:100`) +
`IrUsage` on `MessageDelta` (`crates/busbar-llm/src/ir/types.rs:246`), per the audit's SEAM 1 note
(§Seam1(b), "the ONE part that genuinely reuses shipped LLM code" — conceptually, not by code sharing,
since `IrDuplexUsage` is its own type). What's missing, named explicitly in `usage.rs:15`
("SKELETON: … the `CostBreakdown` fold is future work"):

**The build task:** a `fn fold_cost_breakdown(usage: &IrDuplexUsage, rates: &VoiceRateTable) ->
CostBreakdown` in `busbar-voice`, mirroring `busbar-core::plane::cost::CostBreakdown::new`
(`crates/busbar-core/src/plane/cost.rs:191-250`) — which enforces, as its **one structural
invariant**, that top-level components sum to `total`
(`crates/busbar-core/src/plane/cost.rs:126-128,227-229`, `TopLevelSumMismatch`). Concretely:

- `audio_in`/`audio_out` become **top-level** `CostComponent`s labeled e.g. `"audio_input"`/
  `"audio_output"` (`CostComponent::top`, `cost.rs:91`) — audio dominates cost per the design's
  callout (`plane4-duplex-session.md` §2.5: "audio vs text are separate token classes, audio
  dominates"), so these must never be folded into a text bucket.
- `text_in`/`text_out` become their own top-level components, same pattern.
- `cached` becomes a **nested** component under whichever parent it discounts (`CostComponent::nested`,
  `cost.rs:99-100`, "does NOT contribute to the total") — cached tokens are billed at a different rate
  but must not double-count toward `total`.
- The fold feeds `CostHold::settle_partial(&CostBreakdown)` (`cost.rs:327`, cited at design §3.3) on
  every `response.done.usage` frame — the *exact* charge, per the design's invariant "the running sum
  is the real charge, never the estimate" (`plane4-duplex-session.md` §3.3) — and
  `journal_append_scoped("session-<id>", …)` (`crates/busbar-plugin/src/hot/host.rs:491`) for the
  audit chain. **Both of these are runtime/pump concerns, not `ir/` concerns** — the fold function
  itself (pure `IrDuplexUsage -> CostBreakdown`) is the piece that belongs in `busbar-voice/src/ir/
  usage.rs`, and it is the one piece of this design still genuinely unbuilt inside `ir/`'s boundary.
- Rate table sourcing (`VoiceRateTable` above) is a **new open question**, not resolved by either
  design doc: OpenAI Realtime prices audio tokens differently from Whisper/TTS legacy pricing, and the
  design docs don't cite an existing rate-table type this should extend vs. duplicate. Flag before
  building (§5).

`CostBreakdown`'s opaque-suffix crossing at the D2 ABI boundary (design §6-D2, `host.rs:533-536`
frozen shape) means the host never parses these labels (`cost.rs:73-82`, "core names no plane label")
— so the fold's label strings are entirely `busbar-voice`'s to choose and change without an ABI bump,
as long as `total` stays the sum invariant.

---

## 4. Why the IR stays the plane's OWN (`codec: None`) until Gemini earns the superset

This is not a hedge, it's the same discipline A2A already ships (design §1.4, audit SEAM 2). The
concrete evidence in the tree today, not just the doctrine:

- **`mod.rs:18-22`** states the rule directly: *"The IR is the plane's OWN … `codec: None` while
  OpenAI Realtime is the only dialect (the A2A rule, §1.4: a superset IR is earned at the SECOND wire
  format and not before)."*
- **The precedent it copies is cited with file:line**, not asserted: MCP declares
  `codec: None, handler: Some(&McpRequestHandler)` (`crates/busbar-mcp/src/codec/mod.rs:93-94`, design
  §1.3); A2A's plane header states *"A2A has ONE wire format today, so it earns no superset
  intermediate representation. The rule is that a plane earns one at its SECOND wire format and not
  before"* (`crates/busbar-a2a/src/a2a/mod.rs:15-16`, design §1.4).
- **The Gemini codec that WOULD be the superset-earning second dialect already exists in the tree**
  (`crates/busbar-voice/src/ir/codec/gemini/mod.rs`, 609 lines, real reader/writer, 619 lines of
  tests) — but it targets the **same shared IR** the OpenAI codec targets
  (`gemini/mod.rs:4-11`: *"mapped to/from the SAME shared voice IR that `super::OpenAiRealtimeCodec`
  targets… Earning a cross-dialect superset IR is exactly what a SECOND dialect does"*). This is the
  literal mechanism: the IR types in `tool.rs`/`control.rs`/`media.rs`/`usage.rs`/`event.rs` **did not
  change shape** to accommodate Gemini — `IrDuplexTool`, `IrDuplexControl`, `IrAudioFrame`,
  `IrDuplexUsage` are the exact same structs both codecs read into and write out of. The superset is
  earned in the **codec layer** (two `DuplexReader`/`DuplexWriter` impls converging on one IR), not by
  reshaping the IR itself — which is the whole point of "the plane's own IR:" it was designed honestly
  for one dialect and happened to be general enough that dialect #2 slotted in without a breaking
  change. That's the practical test of "codec: None was the right call at one dialect," retroactively
  confirmed.
- **What "codec: None → Some" actually toggles** is the `ProtocolDecl` registration
  (`crates/busbar-substrate/src/proto.rs:648-669`, design §1.1) — a `busbar-voice`-crate-level
  registry decision about whether cross-dialect routing is exposed, not an IR-shape decision. The IR
  work in `ir/` is complete for both dialects today; flipping the registry flag is a separable, later,
  cheap decision (and per design §8 is explicitly P4/1.8.0, "the second dialect that *earns the
  superset IR* and turns the four-layer IR into the cross-dialect backend-swap moat" — i.e. the moat
  is a product/scope decision, not a code-readiness one).
- **The honest limit stays honest even after Gemini lands:** the Gemini codec's own doc names its
  DROP+WARN set explicitly (`gemini/mod.rs:32-35`: input/output transcription side-channels,
  `toolCallCancellation`, `goAway`/session-resumption, non-audio model-turn parts have "NO shared-IR
  home") — earning the superset does not silently claim full parity; the gaps are enumerated in the
  same file that earns the superset, which is the correct place for that honesty to live.

---

## 5. Residual risks

1. **Stale "SKELETON/`todo!()`" doc-comment will mislead the next reader into re-scoping already-done
   work.** `mod.rs:24-25` is materially wrong today — no `todo!()` bodies exist, both dialects are
   implemented and tested. Left uncorrected, an implementer (human or agent) briefed from that
   docstring alone will over-scope "build the reader/writer" as new work, duplicate ~1,700 lines of
   already-correct, already-tested code, or worse, introduce a divergent second implementation.
   **Fix is cheap:** update `mod.rs:24-25` to describe the true remaining surface (pump/session-store/
   D2 wiring outside `ir/`, the `CostBreakdown` fold inside it) — a doc-only change, no test risk.

2. **No `roundtrip_fidelity_tests.rs`-pattern harness exists yet for either dialect.** Coverage today
   is entirely example-based (59 `#[test]` fns across both `codec/tests.rs` and `gemini/tests.rs`),
   which is real and good coverage but — per the LLM plane's own lesson (`roundtrip_fidelity_tests.rs:
   14-19`, "a field that is never read and never emitted has nothing to check it… a field no test
   would miss is a field a future edit can silently drop") — structurally cannot catch a newly-added
   `SessionConfig` field, a new Realtime event type, or a new Gemini `toolCall` shape that both the
   reader and the writer forget to handle simultaneously (the exact failure mode the LLM plane's
   history shows: fields "looked well covered while attachments, usage sub-buckets and citation
   offsets were being dropped in silence"). §2.2's port closes this gap; until it lands, this is the
   single highest-leverage risk against the 100%-lossless same-dialect requirement.

3. **The usage→money path has one real, acknowledged gap: no `CostBreakdown` fold.**
   `usage.rs:15` names it as future work, and no rate-table type is cited anywhere in either design
   doc or the current tree for voice-specific audio/text pricing — meaning this isn't just an
   unwritten function, it's an open design question (what rates, what label taxonomy, whether it
   reuses an LLM-plane rate-table type or needs its own) that should be resolved *before* the fold is
   written, not discovered mid-implementation. Until it's built, Layer 4's "extraction only" promise
   (design §2.5) is fulfilled up to `IrDuplexUsage`, but the chain to `cost_settle`/
   `journal_append_scoped` (design §3.3) — the actual mid-session budget hard-stop that's the
   headline product claim (design §0, "the one 1.6.0 one-way door") — has no code on the `busbar-voice`
   side to call it with. This is a P2 (1.7.0) blocker per the design's own phased plan (§8), not a
   1.6.0 concern, but it should be tracked as such explicitly rather than left implicit in a one-line
   doc comment.
