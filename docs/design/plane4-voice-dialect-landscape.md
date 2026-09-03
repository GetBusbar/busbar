# Plane 4 — Voice Dialect Landscape & Cross-Dialect Feasibility (authoritative research)

Status: **RESEARCH (not build).** Read-only analysis + web verification. Owner: Matthew.
Scope: ground `busbar-voice`'s cross-dialect translation moat by answering two decisive
questions — (1) is **OpenAI Realtime ⇄ Gemini Live** bidirectional voice translation viable
through the layered plane-IR, the way the 6 chat dialects cross-translate? and (2) what is the
real realtime-voice **protocol landscape**, and therefore what **dialect roster** must the plane
read/write to cover the market?

Companion to `docs/design/plane4-duplex-session.md` (the plane's IR, pump, gauntlet contract)
and `docs/design/1.6.0-duplex-plane-and-realtime.md` (the whether/when-to-build analysis). This
doc does not restate the architecture; it grounds the *market and protocol* case those docs
assume, with current-state citations.

**Verification note.** OpenAI moved its docs to `developers.openai.com`; Realtime went **GA on
2025-08-28** (the `gpt-realtime` release), which **drops the `OpenAI-Beta: realtime=v1` header**,
nests config under `session.audio.input/output.*`, uses object audio formats
(`{"type":"audio/pcm","rate":24000}`), `output_modalities`, and renames events to
`response.output_audio.delta` / `response.output_audio_transcript.delta`. All current-state
claims below were re-verified against GA docs this pass (2026-09-01); every non-trivial claim
carries a URL. Where a doc page did not expose a field I wanted, I say so explicitly under
"Could not verify."

---

## TL;DR — the two verdicts

1. **OpenAI Realtime ⇄ Gemini Live is VIABLE through the layered IR — but it is a *speech-native
   duplex bridge*, not a lossless codec swap.** Session/control, turn lifecycle, and tool calling
   **CLEAN-TRANSLATE** (same shape, different wire nouns — exactly the 6-chat-dialect move).
   Input audio is **TRANSCODE-REQUIRED** (OpenAI's canonical input is PCM16@**24 kHz**; Gemini
   requires PCM16@**16 kHz** in), so the media layer must resample on the client→upstream leg.
   Output audio is verbatim (both emit 24 kHz). The **irreducible loss** is a thin band of
   dialect-private semantics: OpenAI's byte-exact server-side `audio_end_ms` truncation vs
   Gemini's server-computed `interrupted` (barge-in is **LOSSY-DROP-WITH-DIAGNOSTIC** on the
   playback-position detail), semantic-VAD "eagerness" vs Gemini's start/end sensitivity enums,
   and per-turn usage token-class granularity. **Ceiling:** the IR bridges two speech-native
   duplex models; it does **not** turn either into a Whisper→LLM→TTS cascade (§Part 1 verdict).

2. **"OpenAI Realtime is the de-facto voice wire" is PARTIALLY TRUE.** It is the wire *most cloud
   emulators copy* — **xAI Grok** (`wss://api.x.ai/v1/realtime`, OpenAI-client-compatible) and
   **Azure OpenAI** (the same GA protocol) are free anchors — but the two strongest non-OpenAI
   natives, **Gemini Live** and **AWS Nova Sonic**, run *their own* protocols, and the
   orchestrators that actually own the market's media pump (**Pipecat, LiveKit Agents**) abstract
   *over* all of them with their own client transports rather than re-exposing the OpenAI wire.
   So OpenAI Realtime is the **de-facto server-to-server wire**, not the universal one.
   **Roster priority:** anchor on OpenAI Realtime (banks xAI + Azure + OpenAI-compat clouds for
   free) → **Gemini Live** is the #1 real translation-value dialect (own protocol, own vendor,
   earns the superset IR) → **AWS Nova Sonic** is #2 (own protocol, event-driven HTTP/2). Ultravox
   / Kyutai Moshi / Qwen-Omni are self-host **read** targets that matter for on-prem, not the
   first write targets.

---

# PART 1 — OpenAI Realtime ⇄ Gemini Live cross-translation feasibility

The core question: can `busbar-voice`'s layered plane-IR (tool-layer normalize / control-layer
translate / media-layer verbatim-or-transcode tap / usage-layer extract — see
`plane4-duplex-session.md` §2) bridge these two *the way the 6 chat dialects cross-translate*, or
is it structurally impossible?

Both are **speech-native duplex** models over a persistent socket that exchange
JSON-serialized events (OpenAI over WebSocket/WebRTC/SIP; Gemini over a single WebSocket to
`wss://generativelanguage.googleapis.com/ws/…BidiGenerateContent`). That shared shape — *stream of
typed events, config-then-turns, tools mid-call, barge-in* — is what makes the bridge tractable.
The differences are in the nouns, the audio rates, and a thin band of dialect-private semantics.

## 1.1 Layer-by-layer mapping

Classification legend: **CLEAN-TRANSLATE** (IR reshapes wire nouns, no fidelity loss) ·
**TRANSCODE-REQUIRED** (media bytes must be re-encoded/resampled) ·
**LOSSY-DROP-WITH-DIAGNOSTIC** (no faithful counterpart; drop loudly per the `IR_DROP_*`
doctrine) · **IMPOSSIBLE** (no bridge exists at any layer).

### A. Session / config

| OpenAI Realtime (GA) | Gemini Live | Class |
|---|---|---|
| `session.update` with `session.type:"realtime"` | `BidiGenerateContentSetup` (one-shot, first message) | **CLEAN-TRANSLATE** — both are "configure the session," IR `SessionConfigure` maps both |
| `session.audio.output` + `output_modalities:["audio"]`/`["text"]` | `generationConfig.responseModalities` + `speechConfig` | **CLEAN-TRANSLATE** |
| `session.audio.input.format {type:"audio/pcm",rate:24000}` | `realtimeInput` blobs `audio/pcm;rate=16000` | **TRANSCODE-REQUIRED** (see §C) |
| `instructions` (mutable via `session.update` mid-session) | `systemInstruction` (**set-once at setup**, text-only) | **CLEAN-TRANSLATE on open; LOSSY-DROP mid-session** — Gemini has no mid-session instruction swap |
| `turn_detection {type:"server_vad", threshold, silence_duration_ms, prefix_padding_ms}` | `realtimeInputConfig.automaticActivityDetection {startOfSpeechSensitivity, endOfSpeechSensitivity, silenceDurationMs, prefixPaddingMs}` | **CLEAN-TRANSLATE** (silence/prefix map 1:1; sensitivity ↔ threshold is an approximation) |
| `turn_detection {type:"semantic_vad", eagerness}` | closest is `activityHandling` / hybrid VAD (no direct "eagerness" scalar) | **LOSSY-DROP-WITH-DIAGNOSTIC** — semantic-VAD eagerness has no faithful Gemini counterpart |
| `tools` (function schemas) | `tools[]` (function declarations) | **CLEAN-TRANSLATE** — same as the chat-dialect tool schema normalize |

Asymmetries: Gemini's `sessionResumption` (server-issued `SessionResumptionUpdate` handles),
`contextWindowCompression` (sliding window), and `inputAudioTranscription`/`outputAudioTranscription`
config have **no OpenAI counterpart** (OpenAI treats input transcription as a separate async
side-channel, not a setup toggle). These are Gemini-private → carried when Gemini is the backend,
dropped-with-diagnostic when translated *to* an OpenAI client. OpenAI's mutable `session.update`
mid-call is strictly richer than Gemini's set-once setup: **instruction/tool/VAD re-config
mid-session is one-directional** (OpenAI→Gemini loses it after open).

### B. Turn / event lifecycle

| OpenAI Realtime | Gemini Live | Class |
|---|---|---|
| `response.create` (client requests a turn) | `clientContent {turns, turnComplete:true}` triggers generation | **CLEAN-TRANSLATE** |
| `response.output_audio.delta` (server audio chunks) | `serverContent.modelTurn.parts[].inlineData` (audio) | **CLEAN-TRANSLATE** (framing) + **TRANSCODE** (bytes, §C) |
| `response.output_audio_transcript.delta` | `serverContent.outputTranscription` | **CLEAN-TRANSLATE** |
| `response.done` (terminal, carries `usage`) | `serverContent.generationComplete` then `turnComplete` | **CLEAN-TRANSLATE** — Gemini splits "generation done" from "turn done"; IR folds both into one terminal |
| `response.cancel` | (no explicit cancel; `activityStart`/barge-in supersedes) | **LOSSY-DROP-WITH-DIAGNOSTIC** — no clean Gemini "cancel this response" verb |
| `input_audio_buffer.speech_started/stopped` (server VAD signals) | implicit via `interrupted` + activity detection | **CLEAN-TRANSLATE** (approx) |

The lifecycle is the cleanest layer: both are "client asks → server streams parts → server
signals done," and the plane's `IrServerEvent`/`IrClientEvent` union (`plane4-duplex-session.md`
§2.6) names both. The only genuine gap is `response.cancel` (OpenAI has an explicit response-abort
verb; Gemini folds cancellation into activity/interruption).

### C. Input / output audio — the transcode boundary

- **OpenAI:** canonical **PCM16 @ 24 kHz**, mono, little-endian, for **both** input and output
  (`{"type":"audio/pcm","rate":24000}`). Telephony variants `audio/pcmu` (μ-law) and `audio/pcma`
  (A-law) at 8 kHz are available for the g711 lanes.
- **Gemini:** input **PCM16 @ 16 kHz** (`audio/pcm;rate=16000`, ~100 ms chunks), output **PCM16 @
  24 kHz**, mono little-endian.

Therefore the media layer's transform is **not symmetric**:

| Leg | OpenAI rate | Gemini rate | Media layer |
|---|---|---|---|
| client(OpenAI)→upstream(Gemini) **input** | 24 kHz | wants 16 kHz | **TRANSCODE-REQUIRED** (downsample 24→16 kHz) |
| upstream(Gemini)→client(OpenAI) **output** | wants 24 kHz | emits 24 kHz | **VERBATIM** (identity relay — the meter/audit tap) |
| g711 telephony lane (either) | pcmu/pcma 8 kHz | 16 kHz in | **TRANSCODE-REQUIRED** (μ-law↔PCM + resample) |

This is exactly the media-layer design in `plane4-duplex-session.md` §2.4: "verbatim by default,
the seam where the *optional* transcode lives (g711 ↔ pcm24k), armed only when a lane declares
it." Cross-dialect OpenAI⇄Gemini **arms** the resample on the input leg. It is CPU, not a
fidelity ceiling — resampling PCM is lossless-enough for speech; the doctrine's "don't burn CPU to
lose fidelity" (§2.4) applies to *same-dialect* relay, which stays verbatim.

### D. Tool calling

| OpenAI Realtime | Gemini Live | Class |
|---|---|---|
| `response.function_call_arguments.delta` / `.done` (streamed args) | `toolCall.functionCalls[]` (delivered whole, each with `id`) | **CLEAN-TRANSLATE** — OpenAI streams arg deltas, Gemini delivers the whole call; the IR `CallArgs`/`CallClose` normalizes streamed-vs-whole |
| `conversation.item.create {type:function_call_output, call_id, output}` then `response.create` | `toolResponse.functionResponses[]` (matched by `id`) | **CLEAN-TRANSLATE** |
| **correlation key = `call_id`** (opaque string) | **correlation key = `id`** (per functionCall) | **CLEAN-TRANSLATE via `CallRef` remap** |

This is the layer where the plane earns its keep, and it maps cleanly because both dialects have a
correlation-key + name + args + result loop. The `CallRef → (client_call_id, upstream_id)` remap
table in `SessionScope` (`plane4-duplex-session.md` §2.2) is exactly what bridges OpenAI's
`call_id` string to Gemini's per-call `id`. The one nuance: OpenAI **streams** argument deltas
(`function_call_arguments.delta`), Gemini delivers the **whole** `functionCall` in one `toolCall` —
so translating OpenAI→Gemini buffers the deltas to a whole call (trivial), and Gemini→OpenAI
synthesizes a single `.done` with no intermediate `.delta` (a faithful, non-lossy simplification).
Tools execute **server-side under governance** in both directions — the browser is never trusted
to author a `CallResult` (§2.2). **CLEAN-TRANSLATE.**

### E. Barge-in / interruption

| OpenAI Realtime | Gemini Live | Class |
|---|---|---|
| `input_audio_buffer.speech_started` → client/plane issues `conversation.item.truncate {item_id, content_index, audio_end_ms}` | server emits `serverContent.interrupted:true` and stops on its own | **LOSSY-DROP-WITH-DIAGNOSTIC** (on the *playback-position* detail) |

This is the **subtlest** layer and the one genuine semantic mismatch. OpenAI's model puts the
client (or busbar, on WebSocket) in charge of telling the server **exactly how much audio the user
actually heard** (`audio_end_ms`) so the server can truncate the conversation item to match reality
— and on WebSocket busbar must *track playback position itself* because the server emits audio
faster than realtime (`plane4-duplex-session.md` §2.3). Gemini's model is **server-authoritative**:
on detected activity it emits `interrupted:true` and truncates its own turn; the client does not
send a played-milliseconds figure back.

Consequence for the bridge:
- **Gemini→OpenAI-client:** busbar receives `interrupted`, must *synthesize* the OpenAI
  `speech_started` + compute an `audio_end_ms` from its own playback tracking to hand the client a
  faithful truncation. Doable, but the millisecond figure is *plane-computed*, not carried — a
  lossy reconstruction, flagged with a diagnostic.
- **OpenAI-client→Gemini:** busbar receives the client's `conversation.item.truncate {audio_end_ms}`
  but Gemini has **no field to convey "the user heard exactly N ms"** — Gemini already truncated
  server-side. The `audio_end_ms` is **dropped-with-diagnostic**; the barge-in *effect* is
  preserved (both stop), only the exact cut-point reconciliation is lost.

The barge-in *behavior* bridges; the byte-exact truncation *bookkeeping* is the irreducible loss.

### F. Usage / limits

| OpenAI Realtime | Gemini Live | Class |
|---|---|---|
| `response.done.usage` — separate **audio vs text token classes** (input/output, cached), audio dominates | `usageMetadata` — `promptTokenCount`, `responseTokenCount`, `cachedContentTokenCount`, `toolUsePromptTokenCount`, `thoughtsTokenCount`, plus `*TokensDetails` **modality breakdowns** | **CLEAN-TRANSLATE (extract-only)** |
| `rate_limits.updated` (server pushes remaining quota) | (no equivalent push; quota via API error / headers) | **LOSSY-DROP-WITH-DIAGNOSTIC** — no Gemini in-band rate-limit push |

Usage is **extraction-only, never client-facing** (`plane4-duplex-session.md` §2.5): both dialects
expose per-turn token counts with a modality (audio/text) split, so both fold into the neutral
`IrDuplexUsage { audio_in, audio_out, text_in, text_out, cached }` carrier → `CostBreakdown`. The
one gap is OpenAI's proactive `rate_limits.updated` push, which Gemini has no counterpart for
(Gemini signals throttling out-of-band). That is a metering *convenience* loss, not a correctness
loss — the ledger still settles from the per-turn usage.

## 1.2 Layer classification summary

| Layer | Class | Irreducible loss |
|---|---|---|
| A. Session/config | **CLEAN-TRANSLATE** | mid-session instruction/VAD swap (OpenAI→Gemini one-way); semantic-VAD eagerness; Gemini resumption/compression are backend-private |
| B. Turn lifecycle | **CLEAN-TRANSLATE** | `response.cancel` has no clean Gemini verb |
| C. Input audio | **TRANSCODE-REQUIRED** | 24 kHz → 16 kHz resample on input leg (CPU, not fidelity) |
| C. Output audio | **VERBATIM** | none (both 24 kHz) |
| D. Tool calling | **CLEAN-TRANSLATE** | none material (streamed-vs-whole args normalize) |
| E. Barge-in | **LOSSY-DROP-WITH-DIAGNOSTIC** | byte-exact `audio_end_ms` reconciliation across the server-authoritative/client-authoritative split |
| F. Usage/limits | **CLEAN-TRANSLATE (extract)** | `rate_limits.updated` push (no Gemini equivalent) |

No layer is **IMPOSSIBLE.** The bridge is real.

## 1.3 PART 1 VERDICT

**OpenAI Realtime ⇄ Gemini Live bidirectional voice translation is VIABLE through the layered IR —
in the same sense the 6 chat dialects cross-translate, with one added cost (an input-audio
resample) and one thin band of irreducible loss (barge-in playback-position bookkeeping + a few
dialect-private config knobs).** Session, lifecycle, tool-calling, and usage all CLEAN-TRANSLATE
because both are speech-native duplex models with the same event-stream shape; the media layer is
verbatim on output and a bounded 24→16 kHz transcode on input; the only genuine semantic
mismatch is barge-in truncation, where OpenAI is client-authoritative (`audio_end_ms`) and Gemini
is server-authoritative (`interrupted`), forcing a plane-computed, diagnostic-flagged
reconstruction rather than a faithful carry.

**The ceiling, stated plainly:** this bridges **two speech-native duplex models**; it does **not**
turn either into a STT→LLM→TTS cascade. Routing an OpenAI Realtime client to a local
Whisper+Llama+Piper stack is *orchestration* (Pipecat/LiveKit), not a dialect reshape
(`plane4-duplex-session.md` §2.7). Within the ceiling, OpenAI⇄Gemini is exactly the moat the
plane's second dialect is meant to earn — the same OpenAI-Realtime client, backend swapped to
Gemini Live, with no client rewrite.

---

# PART 2 — The realtime-voice protocol landscape & the de-facto-wire question

The killer question for every player: **does it speak OpenAI Realtime, or its own protocol?** That
single fact decides whether busbar-voice gets it "for free" by anchoring on the OpenAI dialect, or
whether it is a real, separate translation target.

## 2.1 Cloud speech-native duplex

| Player | Protocol | Compat verdict | Evidence |
|---|---|---|---|
| **OpenAI Realtime (`gpt-realtime`)** | WebSocket / WebRTC / SIP, JSON events, PCM16@24k | **the anchor** | GA 2025-08-28; `developers.openai.com/api/docs/guides/realtime` |
| **Azure OpenAI Realtime** | the **same** GA protocol (WS/WebRTC/SIP) | **[OpenAI-Realtime-compatible]** — same events, different host/auth | Microsoft Learn "GPT Realtime API" (WebRTC/SIP/WS) |
| **xAI Grok voice** (`grok-voice-*`) | `wss://api.x.ai/v1/realtime` — OpenAI client libs work by base-URL swap | **[OpenAI-Realtime-compatible]** (documented minor diffs) | docs.x.ai speech-to-speech; LiteLLM xAI-realtime provider |
| **Google Gemini Live** | `BidiGenerateContent` WebSocket, own event schema, 16k-in/24k-out | **[own protocol]** — the #1 real translation target | `ai.google.dev/api/live` |
| **AWS Nova Sonic** | `InvokeModelWithBidirectionalStream` over **HTTP/2**, SigV4 auth, `sessionStart`/`promptStart` event sequence | **[own protocol]** — not WebSocket, not OpenAI-shaped | AWS Bedrock `InvokeModelWithBidirectionalStream`; Nova speech-bidirection docs |
| **Inworld voice agents** | own realtime API (also integrable via orchestrators) | **[own protocol]** | inworld.ai voice-agents |

Reading: the **OpenAI-compatible cloud cluster** (OpenAI + Azure + xAI) is a single dialect the
plane banks by implementing OpenAI Realtime once. The **own-protocol cloud cluster** (Gemini Live,
Nova Sonic, Inworld) is where separate adapters — and the plane's translation value — live.

## 2.2 Self-hostable / open

| Player | Protocol | Compat verdict | Evidence |
|---|---|---|---|
| **Ultravox (fixie-ai)** | own real-time API (multimodal LLM, frozen-Llama/gemma3/qwen3 cores); also a Pipecat S2S service | **[own protocol]**, self-hostable | github.com/fixie-ai/ultravox; ultravox.ai Pipecat integration |
| **Kyutai Moshi / Unmute** | own full-duplex protocol (Moshi ~160 ms latency, open weights); Unmute = pipeline adding voice to any text LLM | **[own protocol]**, self-hostable, offline-capable | kyutai.org/unmute |
| **Qwen2.5-Omni / Qwen3-Omni** | served via **vLLM-Omni** / **SGLang-Omni** — **OpenAI-*compatible* `/v1/audio/*` + `/v1/chat/completions`** with streaming, **not** a full duplex Realtime WS | **[partial — OpenAI-compat HTTP surface, not the Realtime duplex wire]** | docs.vllm.ai/projects/vllm-omni; sgl-project sglang-omni |
| **vLLM / SGLang realtime** | OpenAI-compatible **chat/audio** endpoints; realtime *streaming* but not the `/v1/realtime` duplex session API | **[partial]** — cascade-shaped, not speech-native duplex wire | same |

Reading: the open/self-host tier is **mostly its own protocols** for true duplex (Ultravox,
Moshi), while the vLLM/SGLang "OpenAI-compatible" surface is the **chat/audio** REST family, not
the Realtime duplex socket — i.e. it's a *cascade* endpoint, which by the Part 1 ceiling is
orchestration territory, not a duplex dialect the plane bridges. These matter as **on-prem read
targets** (govern/meter a self-hosted voice stack), not as first write targets.

## 2.3 Orchestrators (define the client wire, own the media pump)

| Orchestrator | What it exposes to the client | OpenAI-Realtime surface? | Owns media/WebRTC/SIP? |
|---|---|---|---|
| **Pipecat** (Daily) | its own client transport (WebRTC-first, Daily/others); supports OpenAI Realtime, Azure, xAI/Grok, **Gemini Live, Nova Sonic, Ultravox** as *backend* S2S services | **consumes** OpenAI Realtime as a backend; does **not** re-expose the OpenAI wire to the client | **yes** — WebRTC-first streaming, turn detection, SIP via Twilio/etc. |
| **LiveKit Agents** | LiveKit **WebRTC room** model (agent joins as a participant); many OpenAI-compatible model plugins | **consumes** OpenAI Realtime; client speaks LiveKit's room protocol, not the OpenAI wire | **yes** — LiveKit WebRTC SFU + open-source SIP bridge (Apache-2.0) |

This is the load-bearing landscape fact for build-vs-adopt: **the orchestrators own the mic /
resample / jitter-buffer / WebRTC-SFU / SIP media leg**, and they treat OpenAI Realtime (and
Gemini Live, and Nova Sonic) as *interchangeable backends behind their own client transport.* They
do **not** propagate the OpenAI Realtime wire to the end client. That confirms
`plane4-duplex-session.md` §8's "own the gauntlet, adopt the media pump": busbar sits **in front
of** or **beside** these as the governed key/route/audit boundary; it does not compete with their
media plumbing.

## 2.4 The de-facto-wire thesis — assessment

**"OpenAI Realtime is becoming the de-facto voice wire (the chat-completions of voice) that most
stacks emulate": PARTIALLY TRUE.**

Evidence **for** (server-to-server wire):
- **xAI Grok** deliberately implements OpenAI's Realtime wire (`wss://api.x.ai/v1/realtime`,
  OpenAI client libraries work by base-URL swap).
- **Azure OpenAI** ships the identical GA protocol.
- Every orchestrator (**Pipecat, LiveKit**) and proxies (**LiteLLM**) implement OpenAI Realtime as
  a first-class backend — it's the reference integration.

Evidence **against** (universal wire):
- The two strongest non-OpenAI natives run **their own protocols**: **Gemini Live**
  (`BidiGenerateContent`) and **AWS Nova Sonic** (HTTP/2 `InvokeModelWithBidirectionalStream`,
  SigV4). Neither emulates OpenAI; both are backed by hyperscalers with no incentive to.
- The **orchestrators own the client wire**, not OpenAI. A LiveKit client speaks the LiveKit room
  protocol; a Pipecat client speaks Pipecat's transport. OpenAI Realtime is a backend they abstract
  *away*, so at the *client* edge OpenAI is **not** the de-facto wire.
- Self-host duplex (Ultravox, Moshi) is its own protocol; the vLLM/SGLang "OpenAI-compatible"
  surface is chat/audio REST, **not** the Realtime duplex socket.

**Net:** OpenAI Realtime is the **de-facto server-to-server voice wire** among *cloud
model vendors that choose to emulate a competitor* (xAI) and the reference every proxy/orchestrator
integrates — but it is **not** the universal client wire, and the highest-value non-OpenAI models
(Gemini, Nova Sonic) are its own-protocol rivals. That asymmetry is precisely *why the translation
moat exists*: if everyone emulated OpenAI there'd be nothing to translate.

## 2.5 PART 2 VERDICT — recommended dialect roster priority

Anchor + earned-superset strategy, in priority order:

1. **OpenAI Realtime (GA) — the anchor. READ + WRITE first.** Implementing this one dialect banks
   **xAI Grok** and **Azure OpenAI** for free (OpenAI-Realtime-compatible) and makes busbar the
   governed boundary in front of every Pipecat/LiveKit/LiteLLM stack that already speaks it. This
   is the whole first cut (Topology A, `plane4-duplex-session.md` §8), `codec: None`, one wire.

2. **Gemini Live — the #1 translation-value dialect. The one that EARNS the superset IR.** Own
   protocol, own vendor, speech-native duplex — the exact second wire format that (per the A2A
   rule, §1.4) flips `codec: None`→`Some` and turns the four-layer IR into a real cross-dialect
   backend-swap. Part 1 proves the bridge is viable. This is the moat's proof point.

3. **AWS Nova Sonic — #2 non-compat dialect.** Own protocol, and *architecturally distinct*
   (HTTP/2 bidirectional stream + SigV4, not WebSocket), so it also **stress-tests the
   Transport→listener/dialer seam** (`plane4-duplex-session.md` §4.1) beyond WebSocket. High value
   for AWS-resident buyers; second real translation target after Gemini.

4. **Self-host READ targets (govern/meter, not first write):** **Ultravox**, **Kyutai
   Moshi/Unmute**, **Qwen-Omni via vLLM/SGLang**. These matter for the on-prem story (busbar as the
   governed boundary in front of a self-hosted voice model) but are own-protocol and lower-leverage
   as *write* targets than Gemini/Nova. Note the vLLM/SGLang "OpenAI-compatible" surface is
   chat/audio REST (cascade), **outside** the duplex ceiling — govern them as `Invoke`s, don't
   bridge them as a duplex dialect.

5. **Do NOT chase the orchestrator client wire (Pipecat/LiveKit transports).** They own the media
   pump; busbar adopts them for media (§8) rather than emulating their client protocol. Not a
   dialect.

**One-line roster:** *OpenAI Realtime (anchor; +xAI +Azure free) → Gemini Live (earn the superset)
→ Nova Sonic (own-protocol #2, non-WS transport) → self-host read tier.*

---

## Could not verify from current docs (flagged)

- **Exact OpenAI `response.done.usage` field names at GA** (e.g. `input_token_details.audio_tokens`
  vs `text_tokens`, `cached_tokens`). The GA guide pages confirm audio-vs-text token *classes*
  exist and audio dominates, but I could not pull the exact JSON field schema from the fetched GA
  pages this pass. The design docs' claim (audio/text separate classes) is confirmed directionally;
  the precise field keys should be re-checked against the GA event reference before coding the
  `IrDuplexUsage` extractor.
- **Gemini Live `interrupted` → whether any field conveys played-duration.** Docs confirm
  `serverContent.interrupted:true` and server-side truncation, but I found no field carrying an
  "audio played ms" figure — consistent with the §E "server-authoritative, no client audio_end_ms"
  reading, but stated as *absence not found* rather than *documented as absent*.
- **xAI Grok Realtime exact divergences from OpenAI.** Sources confirm base-URL-swap compatibility
  and note "documented differences" plus one report of static-audio/tool-call oddities when pointed
  bluntly at the OpenAI provider — so treat xAI as *near*-compatible (a thin shim may be needed),
  not byte-identical.
- **AWS Nova Sonic event schema depth.** Confirmed own-protocol (HTTP/2, SigV4,
  `sessionStart`/`promptStart` sequence, JSON events), but I did not enumerate its full event
  taxonomy — sufficient for the roster verdict (own protocol, non-WS transport), not yet for an
  adapter spec.

---

## Sources

OpenAI Realtime (GA):
- https://developers.openai.com/api/docs/guides/realtime
- https://developers.openai.com/api/docs/guides/realtime-conversations
- https://developers.openai.com/api/docs/guides/realtime-vad.md
- https://developers.openai.com/api/docs/guides/realtime-websocket
- https://openai.com/index/introducing-gpt-realtime/

Gemini Live:
- https://ai.google.dev/api/live
- https://ai.google.dev/gemini-api/docs/live-api/capabilities
- https://ai.google.dev/gemini-api/docs/live-api/get-started-sdk
- https://firebase.google.com/docs/ai-logic/live-api/configuration

Azure OpenAI Realtime:
- https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/realtime-audio
- https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/realtime-audio-webrtc
- https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/realtime-audio-sip

xAI Grok voice:
- https://docs.x.ai/developers/model-capabilities/audio/voice-agent
- https://docs.litellm.ai/docs/providers/xai_realtime

AWS Nova Sonic:
- https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModelWithBidirectionalStream.html
- https://docs.aws.amazon.com/nova/latest/userguide/speech-bidirection.html
- https://aws.amazon.com/blogs/aws/introducing-amazon-nova-sonic-human-like-voice-conversations-for-generative-ai-applications/

Self-host / open:
- https://github.com/fixie-ai/ultravox
- https://www.ultravox.ai/blog/introducing-the-ultravox-integration-for-pipecat
- https://kyutai.org/unmute/
- https://github.com/QwenLM/Qwen3-Omni
- https://docs.vllm.ai/projects/vllm-omni/en/latest/serving/speech_api/
- https://sgl-project.github.io/sglang-omni/

Orchestrators:
- https://docs.livekit.io/agents/models/
- https://github.com/livekit/agents
- https://github.com/pipecat-ai/pipecat
- https://docs.pipecat.ai/api-reference/server/services/s2s/ultravox
- https://deepwiki.com/pipecat-ai/pipecat/4.5-speech-to-speech-services
</content>
</invoke>
