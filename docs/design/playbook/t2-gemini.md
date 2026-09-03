# T2 — The Gemini Live adapter: the SECOND dialect that earns the superset IR

Status: **DESIGN PLAYBOOK (grounds the already-landed skeleton).** Read-only against the tree.
Owner: Matthew. Scope: the design of **Gemini Live (`BidiGenerateContent`)** as busbar-voice's
**second** dialect — the wire format that, by the A2A rule (`plane4-duplex-session.md:126-144`),
flips `VOICE_WIRE_FORMATS` from length 1→2 and thereby *earns* the plane its cross-dialect
**superset IR**. This mirrors exactly how A2A earns a superset at its second wire format
(`crates/busbar-a2a/src/a2a/mod.rs:15-16`) and how the LLM plane earns one across its six chat
dialects (`crates/busbar-llm/src/ir/mod.rs:4-6`).

The skeleton this playbook grounds already landed: the `GeminiLiveCodec`
(`crates/busbar-voice/src/ir/codec/gemini/mod.rs:70-609`), the shared IR the two dialects both
target (`crates/busbar-voice/src/ir/`), the cross-dialect map
(`docs/design/voice-cross-dialect-map.json`, `docs/design/voice-cross-dialect-mapping.md`), and the
4-ordered-pair cross-parity conformance leg
(`testing/voice-conformance/legs/cross-parity.sh:38`). This doc states *why* the pieces sit where
they do, and what remains a stub vs net-new.

---

## 1. How Gemini flips `VOICE_WIRE_FORMATS` 1→2 and turns ON the superset IR

### 1.1 The mechanism — length, not a boolean

`Plane::has_superset_ir` is **not** a field a plane sets; it is **derived from the length** of the
plane's wire-format list. The derivation chain, cited:

- `PlaneDecl.wire_format_names: fn() -> &'static [&'static str]`
  (`crates/busbar-substrate/src/plane/registry.rs:232`), whose own doc pins the rule:
  *"`Plane::wire_formats` and `Plane::has_superset_ir` stay DERIVED from this list's length, so the
  superset-IR rule remains a rule rather than a fact about today's planes"*
  (`registry.rs:230-231`).
- `plane::wire_formats(key) -> usize` (`crates/busbar-core/src/plane/mod.rs:226`) returns the list
  length; `has_superset_ir(key)` = `superset_of(wire_formats(key))`
  (`mod.rs:232-233`); and `superset_of(n) = n >= 2` (`mod.rs:256-257`).
- The invariant is gate-pinned: `a_plane_earns_a_superset_ir_at_two_wire_formats_and_not_before`
  (`crates/busbar-core/src/plane/tests/plane_tests.rs:92-99`) asserts, for *every* plane,
  `has_superset_ir(p) == (wire_formats(p) >= 2)`.

Today the voice plane declares exactly **one** dialect:

```
const VOICE_WIRE_FORMATS: &[&str] = &[OPENAI_REALTIME];   // crates/busbar-voice/src/lib.rs:77
```

whose length-1 is *what denies the plane a superset IR* (`lib.rs:74-77`,
`PLANE_DECL.wire_format_names = || VOICE_WIRE_FORMATS`, `lib.rs:103`). Adding Gemini is a **one-line
list edit** —

```
const VOICE_WIRE_FORMATS: &[&str] = &[OPENAI_REALTIME, GEMINI_LIVE];   // len 1 → 2
```

— and `has_superset_ir("voice")` flips `false → true` automatically, with no edit to core. That is
the whole seam: the second dialect *earns* the superset by arithmetic, exactly the A2A discipline
(`plane4-duplex-session.md:140-144`). Note the `DECLS` `ProtocolDecl.codec` field
(`crates/busbar-voice/src/lib.rs:151`, `codec: None`) is the *other* half of the same fact — the
`codec: None → Some` flip at the second dialect (`proto.rs`'s two mutually-informing fields,
`plane4-duplex-session.md:64-80`); the voice plane models the superset as its own shared IR types
rather than a `DialectCodec` facade, so the load-bearing signal is the list length.

### 1.2 What the superset IR must model (and already does)

While OpenAI Realtime was the sole dialect, the "IR" could have been a busbar-owned *mirror* of the
Realtime event schema (the A2A one-canonical-type posture, `a2a/mod.rs:7-16`). The second dialect
forces the IR to become a genuine **superset**: a neutral vocabulary that is *no dialect's wire*,
that both `read`/`write` map to and from losslessly-where-possible. The shared IR must model:

1. **A dialect-neutral session config** that is the *union* of both setup surfaces, not OpenAI's
   `session` object. This is why `SessionConfig` carries a `model` field
   (`crates/busbar-voice/src/ir/config.rs:100-101`) that OpenAI never puts on `session.update`
   (server-side only) but Gemini carries as `setup.model` — *"Modeled here as the genuinely-shared
   field the SECOND dialect (Gemini) earns into the superset IR"* (`config.rs:96-99`). One dialect
   would not have needed it; two do.
2. **A neutral VAD surface** (`IrVad`, `crates/busbar-voice/src/ir/control.rs:47-73`) whose
   `ServerVad` knobs are the intersection both dialects can populate — Gemini's
   `automaticActivityDetection.{prefixPaddingMs,silenceDurationMs}` map in
   (`gemini/mod.rs:120-138`), OpenAI's `threshold`/`create_response`/`interrupt_response` take
   shared defaults when the source is Gemini.
3. **A correlation abstraction decoupled from any wire id** — `CallRef`
   (`crates/busbar-voice/src/ir/tool.rs:12-23`), *"NOT the wire `call_id` … a `CallRef →
   (client_call_id, upstream_call_id)` table … lets a client that speaks OpenAI `call_id` be
   bridged to a Gemini Live tool-call that correlates by NAME"*. A single dialect would just carry
   `call_id`; the bridge is why the neutral handle exists.
4. **A streamed-vs-atomic tool normalization.** OpenAI *streams* a call (announce → arg-deltas →
   done); Gemini delivers it *atomically* (`toolCall.functionCalls[]`). The superset picks the
   streamed triple `CallOpen → CallArgs → CallClose` (`tool.rs:35-71`) as canonical, and the Gemini
   reader **expands** each atomic call into that triple (`gemini/mod.rs:446-475`) so the correlation
   moat is identical across dialects.
5. **A neutral token-class carrier** (`IrDuplexUsage`, `crates/busbar-voice/src/ir/usage.rs:16-28`)
   that both `response.done.usage` (details-object, `codec/mod.rs:389-404`) and Gemini's
   `usageMetadata.*TokensDetails[]` (details-array, `gemini/mod.rs:276-289`) extract into.
6. **A client→server event vocabulary** (`IrClientEvent`,
   `crates/busbar-voice/src/ir/event.rs:19-26`) — the genuine net-new work the LLM `IrStreamEvent`
   structurally lacks (`plane4-duplex-session.md:96-103`). This is dialect-independent and already
   present; the second dialect does not add to it, it *validates* it.

The honest claim: the shared IR is **asymmetric by layer** (`plane4-duplex-session.md:857-863`).
Gemini genuinely *reshapes* Layer 1 (tool: atomic↔streamed) and Layer 2 (control: `setup` object is
structurally unlike `session`, so its translation is a byte-lossy IR-level fixpoint — stable at
`wire→IR→wire→IR`, not byte-for-byte, `gemini/mod.rs:26-28`). Layer 3 (media) stays an identity
byte-relay whose only cross-dialect work is the `mimeType` rate tag (§3). Layer 4 (usage) is
extraction-only both ways.

---

## 2. The OpenAI ↔ Gemini cross-dialect equivalence map (the 4 ordered pairs)

### 2.1 The 4 ordered pairs the cross-parity leg checks

The conformance leg drives **four ordered `read(A) → shared IR → write(B) → IR` slices**
(`testing/voice-conformance/legs/cross-parity.sh:38`, `LEG_SLICES=(oo og go gg)`):

| Pair | A → B | What it proves |
|---|---|---|
| **oo** | OpenAI → OpenAI | same-dialect identity is stable (a non-identity same-dialect map is already broken, `cross-parity.sh:18-19`) |
| **og** | OpenAI → Gemini | an OpenAI-captured session re-derives faithfully under Gemini (`cross-parity.sh:14`) |
| **go** | Gemini → OpenAI | a Gemini-captured session re-derives faithfully under OpenAI (`cross-parity.sh:15`) |
| **gg** | Gemini → Gemini | same-dialect identity for the *second* dialect (`cross-parity.sh:16`) |

Both diagonals (`oo`, `gg`) are ordered slices in their own right, not skipped — running only the
cross pairs would never catch a within-dialect non-identity (`cross-parity.sh:18-20`). The load-
bearing fields are compared on a **correlation-collapsed** view (`CallRef` is a per-session mint, so
its integer value is normalized before diffing, `cross-parity.sh:23-25`).

### 2.2 The concept equivalence map (per layer)

The full table is `docs/design/voice-cross-dialect-mapping.md:45-60` (machine-readable:
`voice-cross-dialect-map.json:25-110`). The load-bearing rows the four pairs exercise:

| Concept | OpenAI wire | Gemini wire | Shared IR | Codec sites |
|---|---|---|---|---|
| Session config | `session.update{session}` | `setup{}` | `IrDuplexControl::SessionConfigure{SessionConfig}` | `codec/mod.rs:229-240`; `gemini/mod.rs:141-254` |
| Handshake ack | `session.created` | `setupComplete{}` | `IrServerEvent::SessionCreated{session}` (opaque) | `codec/mod.rs:301-311`; `gemini/mod.rs:400-404` |
| Input audio | `input_audio_buffer.append{audio}` | `realtimeInput.audio{mimeType,data}` (GA) / `mediaChunks[]` (legacy) | `IrClientEvent::AudioFrame{Up}` | `codec/mod.rs:241-248`; `gemini/mod.rs:337-367` |
| Output audio | `response.output_audio.delta{delta}` | `serverContent.modelTurn.parts[].inlineData` | `IrServerEvent::AudioFrame{Down}` | `codec/mod.rs:320-328`; `gemini/mod.rs:406-429` |
| Turn done | `response.output_audio.done` + `response.done` | `serverContent.{turnComplete,generationComplete}` | `IrServerEvent::AudioDone` | `codec/mod.rs:329-333`; `gemini/mod.rs:438-442` |
| Tool call (streamed↔atomic) | `response.function_call_arguments.delta/.done` (`call_id`) | `toolCall.functionCalls[]` (`id`, whole) | `IrDuplexTool::CallOpen/CallArgs/CallClose` | `codec/mod.rs:334-365`; `gemini/mod.rs:446-475` |
| Tool result | `conversation.item.create{function_call_output}` (`call_id`, string) | `toolResponse.functionResponses[]` (`id`, object) | `IrDuplexTool::CallResult` | `codec/mod.rs:255-269`; `gemini/mod.rs:369-390` |
| Barge-in | `speech_started` + `conversation.item.truncate{audio_end_ms}` | `serverContent.interrupted:true` | `IrServerEvent::SpeechStarted` / `IrDuplexControl::ItemTruncate{audio_played_ms}` | `codec/mod.rs:312-319`; `gemini/mod.rs:430-437` |
| Usage | `response.done.usage.*_token_details` | `usageMetadata.*TokensDetails[]` | `IrDuplexUsage` | `codec/mod.rs:389-404`; `gemini/mod.rs:276-289` |

**The load-bearing join is the tool correlation id** (`voice-cross-dialect-mapping.md:62-66`):
OpenAI `call_id` ↔ Gemini `functionCalls[].id` / `functionResponses[].id` must round-trip
identically. Both codecs mint the *same* `CallRef` for a given id via
`DecodeState::ref_for_call_id` (`codec/mod.rs:119-127`), so `og`/`go` carry a tool call across the
bridge without losing the join.

### 2.3 The asymmetry honesty contract (what drops, per pair)

The cross-parity **verdict** checks the asymmetry table (`voice-cross-dialect-mapping.md:68-89`,
`voice-cross-dialect-map.json:111-126`) — every concept that lives in exactly one dialect must
either be reconstructed or **dropped-with-diagnostic**, never silently invented (the LLM plane's
provider-field discipline). The pairs that bite:

- **`og` (OpenAI→Gemini) drops:** `semantic_vad` eagerness → nearest sensitivity; sample-accurate
  `audio_end_ms` truncate precision (Gemini `interrupted` carries no offset); explicit
  `speech_started/stopped` ms boundaries; `input_audio_buffer.clear`; per-response
  `response.create.response{}` overrides; g711 telephony (no Gemini mode); GA input
  `noise_reduction`; the structured in-band `error` event; client `event_id`. Codec realization:
  the Gemini writer frames the discrete OpenAI controls (`ResponseCreate`/`ResponseCancel`/
  `InputAudioCommit`/`InputAudioClear`/`ItemDelete`/`ItemTruncate`) as an empty `realtimeInput{}`
  marker rather than panicking (`gemini/mod.rs:510-517`) — the drop is structural, not a crash.
- **`go` (Gemini→OpenAI) drops/synthesizes:** `setupComplete` gate synthesized (OpenAI has none);
  `toolCallCancellation` dropped+warn (told to host out-of-band, `gemini/mod.rs:481-484`);
  `generationComplete` collapsed into `response.done`; `goAway`/session-resumption dropped+warn;
  `audioStreamEnd` maps to `input_audio_buffer.commit` under manual VAD.

Barge-in is the subtlest and the one genuine semantic mismatch (`plane4-duplex-session.md:152-175`):
OpenAI is **client-authoritative** (`audio_end_ms` the plane computes from its own playback
tracking, `DecodeState::played_ms`/`flush_playback`, `codec/mod.rs:140-160`); Gemini is
**server-authoritative** (`interrupted:true`, no offset). `og` drops the ms figure; `go`
reconstructs it plane-side — a diagnostic-flagged reconstruction, not a faithful carry.

---

## 3. The Gemini Live codec / adapter concrete shape

The adapter is `GeminiLiveCodec` — a zero-size unit struct
(`crates/busbar-voice/src/ir/codec/gemini/mod.rs:70-74`), identical in stance to
`OpenAiRealtimeCodec` (`codec/mod.rs:219-220`): **stateless and shareable**, because all
per-session state lives in the shared `DecodeState` (`codec/mod.rs:76-161`). It implements the same
two traits both dialects share (`codec/mod.rs:198-214`):

```
impl DuplexReader for GeminiLiveCodec {  // wire → IR
    fn read_up(&self,   evt, st) -> Vec<IrClientEvent>   // gemini/mod.rs:313
    fn read_down(&self, evt, st) -> Vec<IrServerEvent>   // gemini/mod.rs:395
}
impl DuplexWriter for GeminiLiveCodec {  // IR → wire
    fn write_up(&self,   ev) -> WireEvent   // gemini/mod.rs:496
    fn write_down(&self, ev) -> WireEvent   // gemini/mod.rs:551
}
```

Concrete shape decisions, each grounded:

- **Dispatch on the tagged-union top-level key**, not a `type` field. Gemini names its message kind
  by the single top-level object key (`setup`/`clientContent`/`realtimeInput`/`toolResponse` up;
  `setupComplete`/`serverContent`/`toolCall`/`toolCallCancellation`/`usageMetadata` down,
  `gemini/mod.rs:50-62`); the reader `v.get(wire::KEY)` dispatches (`gemini/mod.rs:318-392`). This
  is the structural counterpart to OpenAI's `str_at(&v,"type")` dispatch (`codec/mod.rs:227-228`).
- **Degrade, don't error.** An unrecognized/malformed frame yields an **empty vec**
  (`gemini/mod.rs:314-316,484`) — the streaming-decode discipline the OpenAI codec also follows
  (`codec/mod.rs:16-17`). "Warn" is realized as the silent drop (the crate links no logging surface,
  `gemini/mod.rs:34-35`).
- **Atomic→streamed tool expansion** (`gemini/mod.rs:446-475`): one Gemini `toolCall` frame →
  `CallOpen` + `CallArgs`(whole args as one delta) + `CallClose`. The stateless writer re-frames
  *one Gemini `toolCall` per IR tool event* (`tool_call_frame`, `gemini/mod.rs:491-493`);
  coalescing the triple back into a single atomic frame is the **runtime pump's** job, not the
  codec's (`gemini/mod.rs:24-25`).
- **Uplink audio accepts BOTH spellings** — the GA `realtimeInput.audio{}` single blob (preferred)
  and the legacy `realtimeInput.mediaChunks[]` array (`gemini/mod.rs:337-367`). This is the
  honest-PENDING that commit `8ef39da6` closed: `read_up` previously decoded only the legacy array,
  so the GA single blob (which the captured fixtures already use) decoded to zero IR. Preferring the
  GA blob when present prevents a GA peer double-decoding.
- **The mimeType rate seam** (Layer 3's only cross-dialect work): Gemini tags the PCM rate in the
  blob `mimeType` (`audio/pcm;rate=16000` uplink, `audio/pcm;rate=24000` downlink,
  `gemini/mod.rs:67-68`) where OpenAI carries no per-frame format. `audio_format_from_mime`
  (`gemini/mod.rs:82-97`) probes it; the writer injects the constant mime on the way out
  (`write_up` `UPLINK_MIME`, `gemini/mod.rs:500`; `write_down` `DOWNLINK_MIME`,
  `gemini/mod.rs:589`). The identity byte-relay is unchanged — base64 in/out via the shared
  `decode_audio`/`encode_audio` helpers (`codec/mod.rs:182-190`); only the rate tag is bridged.
- **`interrupted → SpeechStarted`, `turnComplete → AudioDone`** (`gemini/mod.rs:430-442`) with
  synthetic empty `item_id`/`audio_start_ms=0` — the offsets Gemini does not carry are left at their
  neutral defaults, and the reconstruction lives in the runtime, not the codec.

The codec is **transport-agnostic**: both dialects ride the same `wss://` byte-duplex `PipeId` the
substrate pump owns (`plane4-duplex-session.md:479-512`); the codec sees only `WireEvent(Bytes)`
(`codec/mod.rs:68-69`). Adding Gemini therefore touches **no** transport/pump code — the second
dialect is purely a second codec + the one-line wire-format list bump.

---

## 4. Stub vs net-new in `ir/`

The four-layer IR **types** are already present and dialect-neutral — they were built as the
superset from the start (the skeleton, `crates/busbar-voice/src/ir/mod.rs:24-25`). So the second
dialect adds almost nothing to `ir/` *type* surface; it fills the codec.

**Already present (stub or complete), REUSED unchanged by Gemini:**

- `event::{IrClientEvent,IrServerEvent}` (`event.rs:19-74`) — the two unions; net-new IR work but
  *dialect-independent*, so Gemini reuses them verbatim.
- `tool::{CallRef,IrDuplexTool}` (`tool.rs`), `control::{IrDuplexControl,IrVad,Eagerness}`
  (`control.rs`), `media::{IrAudioFrame,AudioFormat,UpDown,truncate_point_ms}` (`media.rs`),
  `usage::IrDuplexUsage` (`usage.rs`), `config::{SessionConfig,MaxOutputTokens}` (`config.rs`).
- `codec::{DuplexReader,DuplexWriter,WireEvent,DecodeState}` (`codec/mod.rs:68-214`) — the traits
  and per-session state; `DecodeState` is dialect-neutral and shared (the `CallRef` table, seq
  counters, playback bookkeeping serve both codecs).

**Net-new for the Gemini dialect (the whole of `codec/gemini/`):**

- `GeminiLiveCodec` + its `DuplexReader`/`DuplexWriter` impls (`codec/gemini/mod.rs`, ~610 lines,
  already landed) and its tests (`codec/gemini/tests.rs`).
- Gemini-private mapping helpers with **no OpenAI counterpart**: `session_config_from_setup` /
  `setup_from_session_config` (`gemini/mod.rs:141-254`), `vad_from_realtime_input_config`
  (`gemini/mod.rs:120-138`), `system_instruction_text` (`gemini/mod.rs:102-114`),
  `audio_format_from_mime` (`gemini/mod.rs:82-97`), `usage_from_metadata` / `usage_to_metadata`
  (`gemini/mod.rs:276-308`), `modality_tokens` (`gemini/mod.rs:259-272`), `tool_call_frame`
  (`gemini/mod.rs:491-493`), and the `wire` key constants + mime constants (`gemini/mod.rs:50-68`).
- Re-exports wiring it into the plane: `pub use codec::gemini::GeminiLiveCodec`
  (`crates/busbar-voice/src/ir/mod.rs:35`).

**The one-line non-`ir/` edit that actually flips the plane** (still pending — the codec landed
ahead of it): add `GEMINI_LIVE` to `VOICE_WIRE_FORMATS` (`crates/busbar-voice/src/lib.rs:77`) and
declare its `ProtocolDecl` name, flipping `has_superset_ir` true and — at the runtime P4 step —
`DECLS.codec` from `None` toward the superset facade.

**Net-new outside `ir/` (conformance, already scaffolded):** the `gemini/` fixture tree and the
`og/go/gg` slices of `testing/voice-conformance/legs/cross-parity.sh` — a **drop-in** on the
scaffold (`testing/voice-conformance/README.md:11-13`), not a rebuild.

---

## 5. Residual risks

1. **Setup translation is byte-lossy by design (an IR-level fixpoint, not verbatim).** Gemini's
   `setup` is structurally unlike OpenAI's `session` object (`gemini/mod.rs:26-28`), so
   `og`/`go` cannot be byte-diffed — the cross-parity leg must compare at the **IR** level, and a
   `wire→IR→wire→IR` stability regression (e.g. a `SessionConfig` field that decodes but doesn't
   re-encode) would slip a same-shape byte diff. The `oo`/`gg` diagonals guard within-dialect
   identity; the cross pairs must stay IR-compared, never byte-compared.
2. **Barge-in precision is irreducibly lossy toward Gemini and reconstructed toward OpenAI.**
   `og` drops `audio_end_ms` (Gemini has no field); `go` synthesizes `SpeechStarted` with
   `audio_start_ms=0` and an empty `item_id` (`gemini/mod.rs:432-437`) and relies on the *runtime's*
   playback tracking (`DecodeState::flush_playback`, `codec/mod.rs:156-160`) to compute a truncate
   point the wire never carried. The codec cannot fix this — it is the client-authoritative vs
   server-authoritative split. Risk: a runtime that forgets to drive `record_played`/`flush_playback`
   silently produces `audio_played_ms=0` truncations with no error.
3. **GA-vs-beta wire drift is not backward-compatible, and the codec straddles both spellings by
   hand.** GA renamed events (`response.output_audio.delta` vs legacy `response.audio.delta`,
   handled at `codec/mod.rs:50-53,320`) and nested the OpenAI session object; Gemini's GA
   `realtimeInput.audio{}` vs legacy `mediaChunks[]` (`gemini/mod.rs:354-362`) is the same hazard —
   `8ef39da6` already caught one honest gap where the GA uplink spelling decoded to zero IR. Each
   new GA field (image input added in GA; `noise_reduction`; conversation-item message/tool-result
   shapes on `conversation.item.create`) is a fresh place a captured fixture can silently decode to
   empty. Mitigation is fixture coverage of *both* spellings per concept (the map already pins
   `session.update.ga_nested.json`), but the surface grows with every GA revision and there is no
   compile-time guard that a new wire key is handled — an unrecognized key is an intentional empty
   vec, indistinguishable from a missed one.

---

## Summary

- **Adding Gemini Live is a one-line `VOICE_WIRE_FORMATS` bump (len 1→2)** that flips
  `has_superset_ir` true by *derivation* (`plane/mod.rs:232-257`), earning the plane its superset IR
  exactly as A2A earns one at its 2nd wire format.
- **The superset IR is dialect-neutral and already built** (`crates/busbar-voice/src/ir/`); the
  second dialect *validates* it — `model`, `CallRef`, the streamed-tool triple, and `IrDuplexUsage`
  exist *because* two dialects must meet in one shape.
- **The 4 ordered cross-parity pairs are `oo/og/go/gg`** (`cross-parity.sh:38`), compared at the IR
  level on a correlation-collapsed view; the asymmetry table is the drop-don't-invent honesty
  contract.
- **The Gemini codec (`codec/gemini/mod.rs`) is net-new; the IR types are reused stubs.** It is a
  stateless unit struct dispatching on the tagged-union key, expanding atomic tool calls into the
  shared streamed triple, and bridging the `mimeType` rate tag over an otherwise-identity media
  relay. It touches no transport/pump code.

**File:** `docs/design/playbook/t2-gemini.md`

**Top 3 risks:**
1. Setup translation is byte-lossy (IR-level fixpoint) — cross pairs must be IR-compared, never
   byte-compared, or a re-encode regression slips through.
2. Barge-in precision is irreducibly lossy toward Gemini / plane-reconstructed toward OpenAI;
   a runtime that skips playback tracking silently emits `audio_played_ms=0` truncations.
3. GA-vs-beta wire drift is not backward-compatible and is straddled by hand — an unhandled new GA
   key decodes to an empty vec indistinguishable from a bug (the class `8ef39da6` already caught).
