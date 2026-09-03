# Plane 4 — Seam Audit E: Plane-IR & Codec

Status: **READ-ONLY ADVERSARIAL AUDIT.** No code changed. Owner: Matthew.
Citation base: pinned commit `e393b9e6` (busbar 1.6.0 integration base; extracted plane crates present).
Companion to the LAYERED plane-IR design (`docs/design/plane4-duplex-session.md`) and the
OpenAI↔Gemini-Live feasibility research (`docs/design/plane4-voice-dialect-landscape.md`), both of
which live on later commits and were read via `git show` for this audit.

Scope: the four IR/codec seams the voice plane's layered IR must build on or diverge from — the LLM
plane's response-shaped IR+codec, the per-plane-IR pattern (MCP/A2A), the core StreamTranslator seam,
and the one-shot media IR. Every claim is re-verified `file:line` against the pinned tree.

---

## THE KEY VERDICT (stated first)

**Does the response-shaped IR/stream seam actually host a duplex plane, or is a new path needed?**

**A NEW, PARALLEL BIDIRECTIONAL PATH IS REQUIRED. The response-shaped seams cannot host a duplex
plane — not by extension, not by configuration.** Two independent structural facts prove it:

1. **The core streaming seam is one-way by type.** `StreamTranslator::feed(&mut self, chunk: &[u8])
   -> Vec<u8>` (`crates/busbar-substrate/src/proto.rs:444`) is defined as *"Feed a chunk of EGRESS
   bytes; return the translated INGRESS bytes"* — a single egress→ingress (server→client) pump. Its
   whole vtable — `finish` (`:446`), `usage` (`:450`), `terminal_error` (`:452`), `aborted` (`:454`)
   — is response-terminal. There is **no request-direction feed**. The concrete response carrier
   `FirstByteBody<S,P>` (`crates/busbar-llm/src/engine/response_body.rs:45`) is an `impl Stream`
   (`:234`, `poll_next` `:241`) wrapping the **upstream response body** — a response Stream, full stop.

2. **The LLM IR has no client→server event vocabulary.** `IrStreamEvent`
   (`crates/busbar-llm/src/ir/types.rs:200-250`) is exactly `{ MessageStart, BlockStart, BlockDelta,
   BlockStop, MessageDelta, MessageStop, Error }` — **every variant is server→client**. The request
   side is a *whole* `IrRequest` via `read_request(&Value)` (`crates/busbar-llm/src/proto_codec.rs:91`),
   never a stream of client events.

**BUT the new path is additive, not a re-architecture, because it rides shipping NEUTRAL primitives
below the response-only seams:** `pipe_read`/`pipe_write` are already-wired *bidirectional* raw-byte
duplex slots (`crates/busbar-plugin/src/hot/host.rs:474/476`, *"The host moves RAW BYTES only —
line/message framing stays PLANE-side"* `:156`); the duplex carriers `InboundKind::Stream`
(`crates/busbar-plugin/src/hot/workitem.rs:31`) + `EmitKind::Unsolicited` (`:45-47`, *"WIRED for
duplex-session"*) exist; and `SessionScope {}` (`crates/busbar-substrate/src/plane_host/scope.rs:366`)
is the dormant `#[non_exhaustive]` stub whose doc says *"the riders that add a duplex/session plane
wire this out"* (`:361`). The design's §4.3 says exactly this. **The audit's job is to confirm the plan
does not lean on the response-only seams by accident — and it does not — while surfacing the one
residual trap: an implementer who reaches for `StreamTranslate`/`FirstByteBody` as the pump will hit a
one-way wall.**

---

## SEAM 1 — The LLM plane's IR + codec (response-shaped only)

### (a) TODAY
- **`IrStreamEvent` is response-shaped only.** `crates/busbar-llm/src/ir/types.rs:200-250` — the seven
  variants are all server→client (block/message lifecycle + terminal `Error`). Confirmed: no
  client→server variant exists.
- **The request side is whole-JSON, not a stream.** `ProtocolReader::read_request(&Value) -> IrRequest`
  (`crates/busbar-llm/src/proto_codec.rs:91`). The streaming reader
  `read_response_events(event_type, data, &mut StreamDecodeState) -> Vec<IrStreamEvent>`
  (`proto_codec.rs:135`) is *response*-fan-out only (*"one wire event/chunk → 0..n IR stream events"*).
  `ProtocolWriter` mirrors it: `write_request` (`:198`) is whole-request; `write_response_event`
  (`:270`) / `write_response_events` (`:285`) are response-stream. There is **no `read_request_events`
  and no `write_request_event`** — verified absent.
- **`TranscriptionReq.stream: bool` (`crates/busbar-llm/src/ir/audio.rs:66`) and `SpeechReq.stream:
  bool` (`:161`) are vestigial.** Each only backs `wants_stream()` (`:81-83`, `:191-192`); **no codec
  consumes them for incremental framing** — there is no streaming reader/writer over `MediaBlob`. They
  select a response delivery mode, they do not constitute an audio-frame codec.

### (b) WITH CHANGES
The voice plane's `IrClientEvent` union (design §2.6: `AudioFrame(up)`, `SessionConfigure`,
`ResponseCreate/Cancel`, `ItemTruncate`, `CallResult`) is the thing that fills this gap, and it is
**genuinely net-new** — the design says so (§2.6, *"This type has no analog anywhere in the tree
today"*) and the code confirms it: the only client-direction IR is a whole `IrRequest`. `IrServerEvent`
is the *sibling* (not extension) of `IrStreamEvent` — same server→client shape, plane-owned type. The
usage layer (design §2.5) is the ONE part that genuinely reuses shipped LLM code:
`recover_truncated_usage` (`proto_codec.rs:100`) + `IrUsage` on `MessageDelta` (`ir/types.rs:246`) is
the exact extract-onto-neutral-token-carrier move `IrDuplexUsage` copies.

### (c) SURFACE-NOW
- The plan's premise is **accurate** against the codec reality: it does not treat the LLM IR as
  bidirectional; it correctly names the client→server vocabulary as net-new. No mismatch here — but see
  the vestigial `stream:bool` note ranked in the master list, so nobody assumes STT/TTS streaming is a
  partial foundation.

---

## SEAM 2 — The per-plane-IR PATTERN (MCP / A2A own their IR, even pass-through)

### (a) TODAY
- **MCP declares `codec: None, handler: Some(&McpRequestHandler)`**
  (`crates/busbar-mcp/src/codec/mod.rs:93-94`), header: *"MCP declares a HANDLER and NO CODEC: its IR
  is its own, there is no cross-dialect translation into or out of it"* (`:82-84`). Its notification
  carriage is one reader + one writer, both directions same bytes: *"BOTH DIRECTIONS READ THE SAME
  BYTES … one reader and one writer here rather than a pair per direction"* (`:169-174`). A received
  notification is a **hint** that *"may never itself install, approve or promote anything"* (`:176-182`)
  — the exact trust posture Layer-2 (control-locking, browser-untrusted) inherits.
- **A2A owns ONE canonical mirror type** (`crates/busbar-a2a/src/a2a/mod.rs:9`, *"A plane owns ONE
  canonical internal type: protocol in, canonical type, protocol out … busbar-owned structs MIRRORING
  the A2A specification"*), and states the superset rule: *"A2A has ONE wire format today, so it earns
  no superset intermediate representation. The rule is that a plane earns one at its SECOND wire format
  and not before"* (`:15-16`). Pass-through is still typed carriage: *"a streamed one comes back as SSE,
  event by event, under the same identity"* (`:41`).

### (b) WITH CHANGES
`busbar-voice`'s layered IR follows this template exactly: `codec: None` while OpenAI Realtime is the
only dialect (like MCP), a busbar-owned canonical mirror of the duplex event schema (like A2A), earning
the cross-dialect superset only at the **second** dialect (Gemini Live `BidiGenerateContent`) — which
the feasibility doc grounds as CLEAN-TRANSLATE on session/lifecycle/tools, TRANSCODE on 24k→16k input
audio, LOSSY-DROP on byte-exact barge-in. This is the same discipline A2A already ships, not a hedge.

### (c) SURFACE-NOW
- **none.** The pattern is real, cited, and directly reusable as a template. The voice plane diverges
  from LLM (which has a `codec: Some` superset over six wire formats) and converges with MCP/A2A
  (`codec: None`, own IR). No mismatch.

---

## SEAM 3 — The StreamTranslator core seam + FirstByteBody (response-only)

### (a) TODAY
- **`StreamTranslator` is byte-in/byte-out, response-direction only.**
  `crates/busbar-substrate/src/proto.rs:441-457`: `feed(&mut self, chunk: &[u8]) -> Vec<u8>` is
  *"Feed a chunk of EGRESS bytes; return the translated INGRESS bytes"* (`:442-444`). The core keeps
  only a byte-in/byte-out trait + a fn-ptr factory (`crates/busbar-core/src/proto/stream_translator.rs:5-6`,
  `new_stream_translator(ingress, egress, is_sse)` `:44/53`). Core names zero concrete stream IR — good
  neutrality, but the seam is **structurally unidirectional**: egress (upstream response) → ingress
  (client response).
- **`FirstByteBody` is a RESPONSE Stream.** `crates/busbar-llm/src/engine/response_body.rs:45` —
  `impl<S,P> Stream for FirstByteBody<S,P>` (`:234`), `poll_next` (`:241`) pulls from the wrapped
  upstream response stream `S`. It is the token-usage-tapping response body, nothing more.
- **The verbatim same-dialect tap is also response-only.** `same_proto` mode (`crates/busbar-llm/src/
  proto_stream.rs:91-97`) re-emits original frame bytes verbatim while the IR runs *"purely as a
  side-channel … drives `last_usage`"* — but this is `feed()` on the same one-way egress→ingress pump.
- **The bidirectional byte primitives DO ship, one level down.** `pipe_read`/`pipe_write`
  (`crates/busbar-plugin/src/hot/host.rs:474/476`), raw-bytes contract *"framing stays PLANE-side"*
  (`:156`, `:471`); duplex carriers `InboundKind::Stream` (`workitem.rs:31`) + `EmitKind::Unsolicited`
  (`workitem.rs:45-47`); `SessionScope {}` dormant stub (`scope.rs:366`, doc `:361`).

### (b) WITH CHANGES
**The voice plane needs a NEW bidirectional pump — NOT this response-only translator.** The duplex pump
(design §4.3, a port of MCP's `Session<W>` generalized to any byte-duplex `PipeId`) owns a reader task
per direction over `pipe_read`/`pipe_write`, correlates via the `CallRef` table in `SessionScope`, and
re-mints the host per frame via `LiveHostFactory`. It sits **beside** `StreamTranslator`/`FirstByteBody`
on the shared neutral byte substrate, not on top of them. `StreamTranslator` remains the LLM plane's
response translator, untouched; the voice pump is a parallel path. Server→client frames ride
`EmitKind::Unsolicited`; the read side rides `InboundKind::Stream`.

### (c) SURFACE-NOW — see master list items 1 & 2. This seam is the crux of the verdict.

---

## SEAM 4 — Media / audio IR (one-shot blob → incremental frame)

### (a) TODAY
- **`MediaBlob` is a one-shot, whole-payload blob.** `crates/busbar-substrate/src/media.rs:103`:
  `{ payload: MediaPayload, mime_type: String, pcm: Option<PcmParams> }`, where `MediaPayload` is
  `Bytes | B64` (`:86-89`) — exactly ONE representation of ONE complete payload. `TranscriptionReq.audio:
  Option<MediaBlob>` (`crates/busbar-llm/src/ir/audio.rs:57`) and `SpeechResp.audio: Option<MediaBlob>`
  (`:242`) are whole-blob-in / whole-blob-out. There is **no sequence number, no direction tag, no
  frame boundary** — verified.
- **The transcode building block exists at blob granularity only.** `PcmParams { sample_rate, channels,
  bit_depth }` (`media.rs:94-98`) already carries the 24 kHz/16 kHz rate the feasibility doc's
  cross-dialect resample (§C, 24k→16k on the input leg) needs — but only on a whole blob, with no
  streaming reader/writer that would apply it per frame.

### (b) WITH CHANGES
The plan's `IrAudioFrame { dir: UpDown, seq: u64, media: Bytes }` (design §2.4) is **net-new and shares
nothing with `MediaBlob` except an opaque byte payload.** The gap from one-shot to incremental is real:
`MediaBlob` = one complete payload; `IrAudioFrame` = a directional, sequenced stream of partial frames
under a live session. The design's claim that Layer-3 "reuses" the verbatim same-dialect tap
(`proto_stream.rs:91-97`) is a **conceptual** analogy (identity transform + metering side-channel), NOT
code reuse — that tap is response-direction-only and JSON-SSE-frame granularity, and cannot carry a
client→server (up-leg) raw audio frame. The optional cross-dialect transcode (24k↔16k, g711↔pcm24k) is
new plane-side code over `PcmParams`-shaped params, armed per lane.

### (c) SURFACE-NOW — see master list items 2 & 3.

---

## SURFACE-NOW — RANKED

1. **[HIGHEST] The duplex pump is a PARALLEL path, not a generalization of `StreamTranslator`/
   `FirstByteBody` — and the response-only seams offer no request-direction hook to extend.**
   `StreamTranslator::feed` is egress→ingress by type (`proto.rs:444`); `FirstByteBody` is an upstream-
   response `Stream` (`engine/response_body.rs:234`). The plan is *correct* (§4.3 builds a new
   substrate pump on `pipe_read`/`pipe_write`), but the codec reality makes the trap concrete: any
   implementer who reaches for the shipped streaming translator as the voice pump hits a one-way wall.
   **Ratify in the plan, loudly: the voice pump does NOT reuse `StreamTranslate`; it is a new
   bidirectional path on the neutral byte/carrier primitives (`pipe_read`/`pipe_write` +
   `InboundKind::Stream`/`EmitKind::Unsolicited` + `SessionScope`).** This is the key verdict.

2. **[HIGH] Media one-shot→incremental is a real gap, and the "identity IR = shipped verbatim tap"
   analogy is conceptual, not code reuse.** `MediaBlob` (`media.rs:103`) is a whole payload with no
   seq/dir; `IrAudioFrame{dir,seq}` (design §2.4) is net-new. The verbatim tap the plan cites
   (`proto_stream.rs:91-97`) is response-direction-only and frame-JSON granularity — it cannot carry an
   up-leg audio frame. `PcmParams.sample_rate` (`media.rs:95`) gives the transcode *parameter* at blob
   level, but there is no per-frame carrier or streaming codec. Surface so nobody scopes Layer-3 as
   "reuse the existing media path" — it is a new incremental-frame IR beside the one-shot `MediaBlob`.

3. **[MEDIUM] `TranscriptionReq.stream`/`SpeechReq.stream` are vestigial — STT/TTS streaming is NOT a
   partial foundation for the voice plane.** `audio.rs:66`/`:161` only feed `wants_stream()`; no codec
   frames incremental audio off them. The plan correctly builds `IrAudioFrame` fresh, but a reader
   skimming the plan might assume audio streaming is half-built. It is not — the flags are a delivery-
   mode bit with no incremental codec behind them.

4. **[LOW / NOT A MISMATCH — recorded for completeness] The usage layer genuinely DOES reuse shipped
   code, and the plan is accurate there.** `recover_truncated_usage` (`proto_codec.rs:100`) + `IrUsage`
   on `MessageDelta` (`ir/types.rs:246`) → neutral token carrier is exactly `IrDuplexUsage`'s move
   (design §2.5). No divergence; the one layer where "builds on" is literal.

**Nothing in the plan wrongly assumes bidirectionality.** The design repeatedly and correctly states
that `IrStreamEvent` is response-only and that `IrClientEvent` is net-new (§2.6). The audit confirms
that premise against the code rather than contradicting it — the residual risk is implementation-time
seam confusion (item 1), not a design error.
