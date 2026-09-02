# Plane 4 — The Duplex / Session Plane (authoritative design)

Status: **AUTHORITATIVE DESIGN (not build).** Read-only against the tree.
Owner: Matthew. Scope: the design of busbar's **fourth plane kind** — the **duplex / session
plane** — and its first instance, a **live-voice** plane whose first dialect is **OpenAI
Realtime** (bidirectional voice: the WebSocket `/v1/realtime` session API +
`client_secret` → browser WebRTC, with tools mid-call).

**Relationship to the existing doc.** This document is the serious engineering design that sits
on top of `docs/design/1.6.0-duplex-plane-and-realtime.md`. That doc's **Part II** is the
authoritative analysis of *whether* and *when* to build (three orthogonal axes A/B/C; the
D1/D2/D3 ABI locks; the 1.7.0-on-a-1.6.0-ABI recommendation). This doc does **not** duplicate
it — it **cross-references** it and goes past it into the thing Part II deliberately left open:
**the plane's own IR, its reader/writer pair, the pump, the session store, and the enterprise
build calls**, each grounded file:line against the real tree.

**Citation base.** Every `crates/…:NNN` citation is against the branch where the extracted
plane crates live — `integration/plane-extraction` (the same branch Part II audits). The 1.6.0
release line (`HEAD`, monolithic `crates/busbar/`) is the same code pre-extraction; where it
matters I say so. All claims were re-verified this pass; where I could only verify a negative
(nothing exists) I say "verified absent," and where a claim is a recommendation rather than a
fact I label it **[RECOMMENDATION]**.

**The load-bearing conceptual rule this design obeys (owner, explicit):** *the plane's IR is
NOT the LLM IR.* Every plane defines its **own** IR — its own reader/writer, its own
pass-through carriage — even where much of what it carries is opaque. MCP and A2A each do this
already (§1). Plane 4 therefore gets its **own** duplex/session IR (§2), modeled on that
pattern, and does **not** reuse or extend `busbar-llm`'s chat IR.

---

## 0. TL;DR for the impatient

- **What it is.** A new plane *kind* — long-lived, bidirectional, per-frame-governed — added
  as a **new crate** (`busbar-voice`, §7) that owns 100% of its protocol vocabulary and rides
  the **one gauntlet + one hot ABI unchanged**. Core/substrate/api never learn the word
  "audio."
- **The centerpiece is the IR (§2).** A four-layer duplex/session IR: **tool-call** (full
  normalization — where the plane earns its keep), **control/config** (translatable,
  cross-dialect only), **media/audio-frame** (verbatim byte-relay by default — an *identity*
  IR, the meter/audit tap), **usage/rate-limit** (extraction-only). It adds the one thing the
  LLM IR structurally lacks: a **client→server event vocabulary** (today's `IrStreamEvent` is
  response-shaped only — proven at `crates/busbar-llm/src/ir/types.rs:200`).
- **The gauntlet contract (§3).** Session-open = **one** `run_gauntlet` pass; per-frame
  governance = the **hot vtable** against a populated `SessionScope`. "One open pass + N
  metered/audited frames," never a bypass.
- **The one 1.6.0 one-way door (§6).** Freeze the `cost_reserve`/`cost_settle` lease
  signatures now (D2). Post-hoc metering cannot hard-stop a live audio stream; the reserve/settle
  lease is the only primitive that can, and it is a *reserved, not present* extension point today
  (`crates/busbar-plugin/src/hot/host.rs:533`). This is the single ABI decision that, if
  deferred, turns Plane 4 into a re-architecture.
- **Scope call (§8): 1.7.0 crate, not 1.6.0 — but freeze D2 in 1.6.0.** First cut = the **thin
  same-dialect server-to-server WS bridge** for the owner's Jarvis stack (fits the gauntlet
  cleanly, needs no media pump, no browser, no cross-dialect). Browser WebRTC, media
  build/adopt, and the cross-dialect moat are additive on the frozen seam.

---

## 1. How MCP and A2A each define their OWN plane IR (the pattern to copy)

This is the mandatory study. Plane 4's IR is designed by this same pattern, so it is cited
first and in full.

### 1.1 The seam: a protocol declares *either* a codec *or* a handler

The registry descriptor `ProtocolDecl` (`crates/busbar-substrate/src/proto.rs:648`) carries the
two mutually-informing fields that define what "this plane's IR" *is*:

- `codec: Option<&'static dyn DialectCodec>` (`proto.rs:664`) — the **cross-dialect** facade.
  Its own doc: *"or `None` for a protocol that serves operations without a cross-dialect codec
  (**MCP, whose IR is its own**)."*
- `handler: Option<&'static dyn RequestHandler>` (`proto.rs:669`) — the cell that serves one
  exchange.

**This is the whole thesis of per-plane IR in one field.** A `codec: Some(_)` plane
(the six LLM chat dialects) normalizes through a **superset IR** shared across dialects. A
`codec: None, handler: Some(_)` plane (MCP) declares that **its IR is its own** — it does not
translate into or out of a shared representation; it reads its wire into its own canonical type,
serves, and writes its wire back.

### 1.2 The LLM plane's IR — the shared superset (the thing Plane 4 must NOT reuse)

`crates/busbar-llm/src/ir/mod.rs:4-6`: *"The superset intermediate representation (IR) — request
and response/stream sides — that **every protocol's Reader/Writer maps to and from**, so any
ingress protocol can reach any backend losslessly."*

Its reader/writer pair is the model for *shape*, not for *reuse*:

- `ProtocolReader` (`crates/busbar-llm/src/proto_codec.rs:63`): `read_request(&Value) ->
  IrRequest` (`:91`), `read_response(&Value) -> IrResponse` (`:143`), and the streaming reader
  **`read_response_events(event_type, data, &mut StreamDecodeState) -> Vec<IrStreamEvent>`**
  (`:135`) — *"one wire event/chunk → 0..n IR stream events, threading per-request decode state."*
- `ProtocolWriter` (`proto_codec.rs:149`): `upstream_path*` + body/model rewrite + the re-framing
  side.

**The asymmetry that forces Plane 4 to define its own vocabulary:** `IrStreamEvent`
(`crates/busbar-llm/src/ir/types.rs:200-250`) has exactly these variants — `MessageStart`,
`BlockStart`, `BlockDelta{IrDelta}`, `BlockStop`, `MessageDelta`, `MessageStop`, `Error`. **Every
one is server→client.** There is no client→server event variant, because the LLM request is one
whole `IrRequest`, not a stream of events. A duplex plane has client→server *events*
(`input_audio_buffer.append`, `response.create`, `conversation.item.truncate`) that this
vocabulary cannot name. That is the single most important structural reason Plane 4's IR is new
and not an extension of this one.

### 1.3 MCP's IR — its own, and "both directions read the same bytes"

MCP declares `codec: None, handler: Some(&McpRequestHandler)`
(`crates/busbar-mcp/src/codec/mod.rs:91-98`), and its own header states the rule plainly
(`codec/mod.rs:82-86`): *"MCP declares a HANDLER and NO CODEC: **its IR is its own**, there is no
cross-dialect translation into or out of it."*

Its reader/writer pair for the server-originated half is the closest existing analog to what
Plane 4 needs, and its design note is load-bearing (`codec/mod.rs:169-174`): *"**BOTH DIRECTIONS
READ THE SAME BYTES.** When busbar is the server it EMITS these to its caller; when busbar is the
client it RECEIVES them from an upstream. That is one wire message and two directions of travel,
so it is **one reader and one writer** here rather than a pair per direction."*

- Reader: `McpNotification::read(method, params) -> Option<Self>` (`codec/mod.rs:209`).
- Writer: `McpNotification::write(&self) -> Bytes` (`codec/mod.rs:229`).

And crucially, a *received* notification is a **hint the plane may not act on**
(`codec/mod.rs:176-182`): it "may prompt a re-read … it may never itself install, approve or
promote anything." That is the trust posture Plane 4's control layer inherits (§2.3, §5.2 — the
browser is never trusted).

### 1.4 A2A's IR — one canonical mirrored type; the superset is *earned*, not assumed

A2A's plane header states the discipline (`crates/busbar-a2a/src/a2a/mod.rs:7-16`): *"A plane owns
**ONE canonical internal type**: protocol in, canonical type, protocol out … busbar-owned structs
MIRRORING the A2A specification, never a third party's generated wire types."* And the rule that
governs when a superset IR appears at all (`a2a/mod.rs:15-16`): *"A2A has ONE wire format today, so
it earns no superset intermediate representation. **The rule is that a plane earns one at its
SECOND wire format and not before.**"*

The reader→canonical→writer carriage lives in the plane's own sibling modules (`canonical`,
`receive`, `serve` — declared `a2a/mod.rs:542-591`), and the pass-through cases are explicit: an
admin approval reply is carried *verbatim* (`AdminReply::Prebuilt`, `a2a/mod.rs:490-493`), and a
streamed answer "comes back as SSE, event by event, under the same identity" (`a2a/mod.rs:34-43`).

**The rule Plane 4 inherits from A2A.** OpenAI Realtime alone is *one* wire format → the plane
earns **no** cross-dialect superset IR yet; its canonical type is a busbar-owned mirror of the
Realtime event schema, and the media path is verbatim carriage. The superset IR is earned at the
**second** dialect (Gemini Live BidiGenerateContent) — which is exactly where the cross-dialect
moat (§7.4, §8) lives. This is not a hedge; it is the same discipline A2A already ships.

### 1.5 Summary of the pattern

| Plane | `codec` | IR posture | Reader / Writer |
|---|---|---|---|
| LLM (6 dialects) | `Some` | shared **superset** IR (earned by 6 wire formats) | `ProtocolReader`/`ProtocolWriter`, `proto_codec.rs:63/149` |
| MCP | `None` | **its own** IR; one reader/writer, both directions same bytes | `McpNotification::read/write`, `codec/mod.rs:209/229` |
| A2A | `None` today | **one canonical mirror**; superset earned at 2nd wire format | `canonical`/`receive`/`serve`, `a2a/mod.rs:542-591` |
| **Voice (Plane 4)** | `None` at 1 dialect → `Some` at 2 | **its own** layered duplex IR (§2); superset earned at Gemini Live | **new** — §2.5 |

---

## 2. The Plane-4 IR — the centerpiece

Plane 4's IR is its **own**, modeled on §1: a busbar-owned canonical mirror of the duplex event
schema, `codec: None` while OpenAI Realtime is the only dialect, earning a superset at the second.
It is **layered**, and the layers differ in *how much the IR reshapes the wire* — from full
normalization to identity. This is the owner's mental model made rigorous.

The four layers, and the honest claim for each:

```
 client ⇄ busbar ⇄ upstream (OpenAI Realtime / Gemini Live)
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Layer 1  TOOL-CALL          FULL NORMALIZATION      (the moat; §2.2)    │
 │ Layer 2  CONTROL / CONFIG   TRANSLATABLE, x-dialect only (§2.3)         │
 │ Layer 3  MEDIA / AUDIO      VERBATIM byte-relay = IDENTITY IR (§2.4)    │
 │ Layer 4  USAGE / RATE-LIMIT EXTRACTION only, not client-facing (§2.5)   │
 └───────────────────────────────────────────────────────────────────────┘
```

### 2.1 "Pass-through is still an IR" — the point that must not be lost

The owner's rule: *pass-through ≠ no IR.* MCP and A2A prove it — MCP's notification carriage is a
reader/writer even though it changes nothing semantically (`codec/mod.rs:169-174`); A2A carries an
approval reply *verbatim* through a typed `AdminReply::Prebuilt` (`a2a/mod.rs:490-493`). The
busbar precedent that nails it is same-dialect chat streaming, which **re-emits upstream bytes
verbatim while running the IR purely as a usage side-channel**. The code says it exactly
(`crates/busbar-llm/src/proto_stream.rs:90-97`, the `same_proto` field): *"`feed` re-emits the
ORIGINAL frame bytes verbatim (byte-exact passthrough) INSTEAD of re-serializing the IR … The IR
pipeline still runs per frame, but purely as a side-channel: it drives `last_usage` (the billing
value). The serialized IR output it produces is DISCARDED."* An identity transform is still a *tap* — the one place
meter/audit reads the stream. Layer 3 (media) is exactly this: an IR whose transform is the
identity function, and whose *reason to exist* is the tap, not the reshape.

### 2.2 Layer 1 — Tool-call (FULL normalization — where the plane earns its keep)

This is the layer where the IR genuinely reshapes the wire, and it is the whole reason a governed
plane beats a dumb WS pipe: **tools execute server-side, under governance, and the browser is
never trusted to author them.**

The Realtime tool loop the IR normalizes: the model streams
`response.function_call_arguments.delta` → `…done` (+ the full item in `response.done`); busbar
executes the tool server-side and returns `conversation.item.create{ type:
function_call_output, call_id, output }` then `response.create`. **`call_id` is the join key**,
and a tool-call turn often produces **no audio** until the result is fed back.

The neutral tool-call IR (busbar-owned; names no OpenAI noun in core, lives in `busbar-voice`):

```
IrDuplexTool =                       // Plane-4-owned; modeled on IrDelta::InputJsonDelta
  | CallOpen   { call_ref: CallRef, name: String }          // fn call announced
  | CallArgs   { call_ref: CallRef, json_delta: Bytes }     // streamed argument delta
  | CallClose  { call_ref: CallRef }                        // args complete
  | CallResult { call_ref: CallRef, output: Bytes }         // busbar's server-side result
```

- **`CallRef` is the correlation abstraction**, not the wire `call_id`. This is the exact move
  the LLM plane already makes: `IrDelta::InputJsonDelta` (`crates/busbar-llm/src/ir/types.rs:1056`)
  normalizes streamed tool-argument deltas and the plane does **cross-dialect id remap** on top
  (existing doc §1.1, "normalized `InputJsonDelta`, cross-dialect id remap"). Plane 4 reuses the
  *shape* of that idea with its own type — a `CallRef → (client_call_id, upstream_call_id)`
  remap table held in `SessionScope` (§3), so a client that speaks OpenAI `call_id` can be
  bridged to a Gemini Live tool-call that correlates by *name*, not id.
- **The governance bite lands here.** Before `CallResult` is authored, the plane runs the
  operator's request-admission gates over the tool + args via the host `gate_decide` seam
  (`crates/busbar-substrate/src/plane_host/mod.rs:250`) — exactly as MCP `tools/call` does today.
  The browser (WebRTC topology, §5.2) never sees the real key and cannot forge a `CallResult`; the
  sideband control WSS authors it server-side.

**Reader/writer:** `read_tool_event(wire_event) -> Option<IrDuplexTool>` and
`write_tool_event(IrDuplexTool) -> Bytes`, one pair, both directions (the MCP discipline,
`codec/mod.rs:169-174`) — client→server (`CallResult` write to upstream) and server→client
(`CallOpen/Args/Close` read from upstream).

### 2.3 Layer 2 — Control / config (translatable; bites only cross-dialect)

The session-control events — `session.update`, `response.create`, `response.cancel`,
`conversation.item.truncate`, VAD config (`server_vad` threshold/`silence_duration_ms`,
`semantic_vad` eagerness) — are IR-translatable but the translation only *matters* cross-dialect
(OpenAI Realtime ⇄ Gemini Live `BidiGenerateContent`). Same-dialect, they are verbatim carriage
(Layer-3 discipline). The neutral control IR:

```
IrDuplexControl =
  | SessionConfigure { instructions, tools, vad: IrVad, modalities, audio_fmt }
  | ResponseCreate   { modalities, ... }
  | ResponseCancel
  | ItemTruncate     { item_ref, audio_played_ms }   // barge-in bookkeeping — see below
```

Two design points that are load-bearing:

- **Instruction/tool locking is a control-layer invariant, not a feature.** In the WebRTC
  topology the browser must not be able to override the system instructions or the tool set with
  its own `session.update`. The plane holds the authoritative `SessionConfigure` server-side and
  the sideband WSS re-applies it; a client-originated `SessionConfigure` is a *hint* (the MCP
  received-notification posture, `codec/mod.rs:176-182`), reconciled against the locked config,
  never trusted blind.
- **Barge-in bookkeeping is the subtle part and it lives here.** On
  `input_audio_buffer.speech_started` the plane cancels the in-flight response and issues
  `ItemTruncate{ audio_played_ms }` where `audio_played_ms` is the audio the user *actually
  heard*. On WebSocket, **busbar must track playback position itself** (the server emits audio
  faster than realtime); on WebRTC the server truncates automatically. `audio_played_ms` is
  therefore a piece of *plane-computed* IR state, not a field copied off the wire — the clearest
  proof that even the "control" layer is a real IR with its own derived state, not a relabeling.

### 2.4 Layer 3 — Media / audio-frame (VERBATIM by default — an identity IR)

Audio frames (`input_audio_buffer.append` up; `response.output_audio.delta` down) are
**byte-relayed verbatim by default**. Per §2.1 this is still an IR — the tap point for meter and
audit, and the seam where the *optional* transcode would live (g711 ↔ pcm24k for telephony; only
armed when a lane declares it). The neutral frame IR:

```
IrAudioFrame { dir: UpDown, seq: u64, media: Bytes /* opaque; identity transform by default */ }
```

- **Why verbatim and not translate:** the fidelity doctrine (existing doc §6) is binding here.
  Nobody cross-translates a live OpenAI voice session to Anthropic — Anthropic has no realtime
  surface — so the media stream is *effectively same-dialect passthrough*. Running a lossy
  cross-dialect IR over 24 kHz PCM frames would burn CPU to *lose* fidelity. The IR is for the
  tap, not the reshape.
- **The transport primitive that carries it is already the right shape.** The host moves **raw
  bytes**; the plane frames on top. That is the explicit contract of `pipe_read`/`pipe_write`
  (`crates/busbar-plugin/src/hot/host.rs:155-171`): *"The host moves RAW BYTES only — line/message
  framing stays PLANE-side, layered on top."* An audio frame is a framed message the plane lays
  over a `PipeId` byte channel — identical in shape to how MCP lays newline-delimited JSON-RPC over
  a stdio `PipeId`, just a different frame codec.

### 2.5 Layer 4 — Usage / rate-limit (EXTRACTION only)

`response.done.usage` (audio vs text are **separate token classes**, audio dominates) and
`rate_limits.updated` are **extracted**, never client-translated. This is the metering/audit tap
feeding `cost_settle` + `journal_append_scoped` (§3). The extraction is exactly the same move the
LLM reader makes with `recover_truncated_usage` (`proto_codec.rs:100`) and `IrUsage` on
`MessageDelta` (`ir/types.rs:246`) — read the usage object, map this dialect's fields onto a
neutral token-class carrier, hand it to the ledger. The neutral carrier:

```
IrDuplexUsage { audio_in, audio_out, text_in, text_out, cached }  // token classes → CostBreakdown
```

which the plane folds into a `CostBreakdown` (`crates/busbar-core/src/plane/cost.rs:177`) whose
top-level components sum to `total` — the one invariant core enforces (`cost.rs:186`, "the parts
add up"), with audio/text as labeled opaque components core never interprets (`cost.rs:73-82`).

### 2.6 The reader/writer pair — the bidirectional analog of `ProtocolReader`/`ProtocolWriter`

The single design delta vs the LLM `ProtocolReader` is that Plane 4 needs a **client→server event
vocabulary** (§1.2). So the plane defines two directions over one wire schema (the MCP
"one reader, one writer, both directions" discipline, `codec/mod.rs:169-174`):

```
trait DuplexReader {                      // wire → IR
  fn read_up(&self,   evt: WireEvent) -> Vec<IrClientEvent>;   // client→server events (NEW vocab)
  fn read_down(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrServerEvent>; // server→client
}
trait DuplexWriter {                      // IR → wire
  fn write_up(&self,   ev: IrClientEvent) -> Bytes;    // re-frame to upstream dialect
  fn write_down(&self, ev: IrServerEvent) -> Bytes;    // re-frame to client dialect
}
```

- `IrServerEvent` is the union of the four layers' server→client cases (`CallOpen/Args/Close`,
  `SpeechStarted/Stopped`, `AudioFrame(down)`, `Usage`, `RateLimits`, `Error`). It is the *sibling*
  of `IrStreamEvent` (`ir/types.rs:200`), not an extension of it — a separate, plane-owned type.
- `IrClientEvent` is the union of the client→server cases (`AudioFrame(up)`, `SessionConfigure`,
  `ResponseCreate/Cancel`, `ItemTruncate`, `CallResult`). **This type has no analog anywhere in the
  tree today** — verified: `IrStreamEvent` is response-shaped only (`ir/types.rs:200-250`), and the
  request path is whole-JSON `IrRequest` (`proto_codec.rs:91`). Building it is the genuine net-new
  IR work.
- `read_down` threads a `DecodeState` exactly as `read_response_events` threads `StreamDecodeState`
  (`proto_codec.rs:135`) — because barge-in playback-position tracking (§2.3) and `CallRef`
  correlation (§2.2) are per-session decode state, not per-frame.

### 2.7 The hard ceiling — stated honestly

**IR translation tops out at event + control + tool + optional audio transcode.** It **cannot**
turn a speech-native model (OpenAI Realtime, a single model doing speech-in/speech-out) into a
Whisper→LLM→TTS cascade. That is **model-replacement / orchestration** (Pipecat, LiveKit Agents),
not a dialect reshape. The dividing line, precisely:

- **Inside the ceiling (busbar's lane):** OpenAI Realtime ⇄ Gemini Live — two *speech-native*
  duplex dialects. Same shape, different wire; the four-layer IR bridges them. This is a real moat
  (§7.4).
- **Outside the ceiling (not busbar):** "route my OpenAI Realtime client to a local
  Whisper+Llama+Piper stack." That is composing three models into one duplex session — an
  orchestration graph, not a codec. busbar governs and meters the *pieces* (the Whisper call, the
  chat call, the TTS call are already three `Invoke` operations busbar proxies today), but it does
  not *become* the cascade. Positioned against the owner's stack: their LiteLLM already fronts
  Whisper (STT) + local chat models; busbar absorbs those as governed `Invoke`s, and Plane 4 adds
  the *speech-native* duplex path beside them — it does not merge them.

---

## 3. The gauntlet contract — one open pass + N metered/audited frames

This section is the concrete mapping of Part II §II.3 onto the real seams. Nothing here is
net-new gauntlet machinery; it is a *composition* of shipped seams plus the one frozen ABI add
(§6-D2).

### 3.1 Session-open is exactly one `run_gauntlet` pass

`run_gauntlet(req, plane)` (`crates/busbar-substrate/src/plane_host/mod.rs:177`) is a free fn that
runs `plane.verify_destination` (stage 2, sync) strictly before `plane.drive` (stages 4+5, async),
returning the plane's response. `GauntletPlane` (`plane_host/mod.rs:158`) is a trait a plane
implements in its own crate. Session-open maps onto this **unchanged**:

- `GauntletRequest` (`plane_host/mod.rs:125`) already carries the resolved identity (`gov`), the
  `destination` the pre-admission check judges (here: which upstream/model the session may talk to),
  the `correlation_id`, and `charged_at`. The WS-upgrade arrival (§4) populates it exactly as an
  HTTP arrival does.
- `verify_destination` (`plane_host/mod.rs:161`) judges the destination model/upstream **before**
  any charge — the invariant the sequence exists to enforce (`plane_host/mod.rs:170-176`, "nothing
  may reject after a charge").
- The **opening budget reservation** is minted at open through `govern_admit_reason`
  (`plane_host/mod.rs:264`), registering the RAII grant in the arena — and, for the lease, the
  frozen `cost_reserve` slot (§6-D2) reserves a coarse opening magnitude (`Magnitude`,
  `crates/busbar-core/src/plane/cost.rs:269`) over-estimated for the session's cap (~60 min).
- The **audit scope opens** with the first `journal_append_scoped(kind_id, "session-<id>", suffix)`
  (`crates/busbar-plugin/src/hot/host.rs:491`).

**This is not `drive`-returns-one-`Response`.** `run_gauntlet` returns
`axum::response::Response` today (`plane_host/mod.rs:180`) — a 20-minute metered session is not one
Response. Part II §II.4 correction #5 resolves this and it holds under scrutiny: `run_gauntlet` is a
*free fn* and `GauntletPlane` a *trait*; a **session-oriented sibling** — `run_gauntlet_session`
returning a `SessionScope` handle instead of a `Response` — is an **append-only add beside them**,
and session-*open* is still exactly today's one pass. **[RECOMMENDATION / D3-adjacent]** this
sibling is a `busbar-substrate` add on the 1.7.0 commit that arms it, not a 1.6.0 change; the 1.6.0
job is only to not make the one-`Response` return the *only* shape (keep the free fn + trait, do not
inline them).

### 3.2 Per-frame governance is the hot vtable against `SessionScope`

Once open, each frame reaches the **same host slots** the gauntlet uses, per frame, cheaply — never
re-running identity:

```
per client→server frame:  pipe_read(PipeId)  → DuplexReader.read_up → govern_admit_reason (cheap
                           per-frame check against the open lease) → DuplexWriter.write_up →
                           pipe_write(upstream PipeId)
per server→client frame:  pipe_read(upstream) → DuplexReader.read_down → WorkItem{ emit:
                           Unsolicited } to client
                           on Usage:  cost_settle(lease, exact CostBreakdown)   [B: metered lease]
                                      journal_append_scoped("session-<id>", …)  [B: audit chain]
                           if lease exhausted → hard close                       [B: mid-session stop]
session close:            SessionScope::Drop reclaims lease + pooled socket; journal seals record
```

- **`SessionScope` is the populated per-connection state** (`crates/busbar-substrate/src/plane_host/scope.rs:366`)
  — today an empty `#[non_exhaustive]` stub whose own doc says *"the riders that add a
  duplex/session plane wire this out"* (`scope.rs:358-366`). Plane 4 is that rider. It holds: the
  two `PipeId`s (client + pooled upstream), the `CostHold` lease, the journal scope string
  `"session-<id>"`, and the `CallRef` correlation table (§2.2). The pooled upstream socket is
  registered via `DispatchScope::register_pipe` (`scope.rs:302`) so its close is RAII-reclaimed.
- **`WorkItem{ inbound: Stream, emit: Unsolicited }` is the carrier** — both tags already reserved
  and WIRED: `InboundKind::Stream` (`crates/busbar-plugin/src/hot/workitem.rs:30`) and
  `EmitKind::Unsolicited` (`workitem.rs:45-47`, *"WIRED for duplex-session"*). A server→client audio
  frame is a host/peer-independent push not correlated to an inbound — exactly `Unsolicited`.
- **`LiveHostFactory` is the per-frame re-mint** (`plane_host/mod.rs:215`, *"Handed to transports
  that re-mint per frame"*). MCP's stdio loop already does this — `let host = (self.factory)();`
  per frame (`crates/busbar-mcp/src/mcp/stdio_serve.rs:522`, *"MINT THE NEUTRAL HOST over THIS
  frame's live snapshot"*). Plane 4 re-mints identically, so a mid-session config swap (budget
  change, key rotation) is seen on the next frame.

### 3.3 Reconciling with D2 — post-hoc metering cannot hard-stop a live stream

`meter_charge` (`plane_host/mod.rs:283`) debits **after the fact** and is fire-and-forget. For
audio you cannot refund bytes already streamed, so post-hoc charging cannot enforce a mid-session
budget cap. The **reserve-then-settle lease** is the only primitive that can, and it *ships today
as a type* — `CostHold::reserve` (`cost.rs:312`) / `settle_partial(&CostBreakdown)` (`cost.rs:327`)
/ `finalize() -> Settlement` (`cost.rs:334`). What is missing is the **hot-vtable slot to drive it
across the FFI seam** — which is D2 (§6). The lease semantics map cleanly:

- **open:** `CostHold::reserve(opening_estimate, flat_fee)` — a coarse over-estimate for the session
  cap; debited from the budget cell now.
- **per `response.done.usage`:** `settle_partial(exact)` — the true audio/text charge accrues; the
  running sum is the real charge, never the estimate (`cost.rs:324-329`).
- **exhaustion:** when settled ≥ reserved and the budget cell is dry, the plane hard-closes the
  session (the one thing post-hoc metering cannot do).
- **close:** `finalize()` returns `Settlement { ledgered_total, refund }` (`cost.rs:281-289`) — the
  unspent reserve returns to the cell. Over-settle (estimate was low) ledgers the true amount and
  refunds zero, never negative (`cost.rs:331-340`).

---

## 4. Transport + ingress + the pump

### 4.1 `Transport::WebSocket` — a variant *bought* when its first session lands

`Transport` (`crates/busbar-substrate/src/transport.rs:96-140`) is `{ Http, JsonRpc, HttpJson,
Grpc, Stdio }` — **no WebSocket variant** (verified). The module's doctrine is explicit and it
governs the add (`transport.rs:35-49`): variants are *"bought when a request drives them, not
guessed"* — A2A's three bindings and `Stdio` each *"arrived on the commit that armed it."* So
`Transport::WebSocket` is **not** a 1.6.0 pre-add; it lands on the 1.7.0 commit that arms the first
voice session. Transport is a substrate-owned axis by design, so this is a *core* add the plane
drives, not a plane type (Part II §II.5).

**The missing dispatch seam.** `Transport` has exactly one dispatch consumer today —
`upstream_wire()` (`transport.rs:218`), used only on the MCP client egress leg. **There is no code
mapping a `Transport` variant to an ingress listener or an egress dialer** (verified — the enum is
otherwise consumed only as a telemetry label, `transport.rs:185`). That generic
Transport→listener/dialer seam is the real net-new substrate primitive (§7 lists it as
plane-neutral).

### 4.2 The WS upgrade is a substrate ARRIVAL KIND — not an axum upgrade from a route

**The anti-pattern, called out loudly.** A `PlaneRouteFn` can return an
`axum::response::Response`, so one *could* return a `WebSocketUpgrade::on_upgrade(...)`. That hands
a raw socket to a plane closure that **bypasses `SessionScope`, the lease, and the audit chain** —
i.e. it bypasses the gauntlet. It is an anti-pattern, not a foothold. (Verified: there is **zero**
`WebSocketUpgrade`/`on_upgrade`/`tungstenite` anywhere in the tree — this is greenfield, so we get
to do it right the first time.)

**The right shape.** The WS upgrade enters through a **substrate arrival kind** that populates
`SessionScope`, exactly as the path-model dialects enter through the neutral `Arrival` seam today
(`crates/busbar-substrate/src/ingress/arrival.rs:139` — `Arrival { host, ctx, path, headers, body }`
carrying an `ArrivalHost` the dialect calls back through, `arrival.rs:59`). A duplex arrival is the
same *shape* of add as the stdio/gRPC arrivals the ingress dispatch comment already anticipates
(existing doc §II.2 item 3). The arrival runs `run_gauntlet` (open), then hands the accepted socket
to the pump under a `SessionScope`. Core names no "websocket" in the *decision* path — it sees an
arrival kind and a `PipeId`, nothing more.

### 4.3 The pump — port MCP's `Session<W>` into a substrate-owned bidirectional pump

MCP's duplex loop is the proven pattern to copy; it is bespoke and stdio-only today, and the port
generalizes it to any byte-duplex `PipeId`. The MCP mechanics (all
`crates/busbar-mcp/src/mcp/stdio_serve.rs`):

- **`Session<W>`** (`stdio_serve.rs:383-410`): `factory: LiveHostFactory` (`:388`, per-frame
  re-mint), frozen per-connection `gov`/`principal` (`:390`), the **single write lock**
  `out: tokio::sync::Mutex<W>` (`:393`, *"ONE writer, one lock: two concurrent responses
  interleaving inside a line would be a frame no reader could parse"*), the **inflight cancellation
  table** (`:399`), and the **pending correlation table** for busbar-originated requests
  (`:401`, `HashMap<id, oneshot::Sender>`).
- **`run_session`** (`stdio_serve.rs:280-357`): read loop → reply-correlation first
  (`route_reply`, `:310`/`:424-454`) → spawn each non-reply frame as a task (`:317`) → all writes
  funnel through `emit` under the one lock (`:415-421`). Server-originated **unsolicited** pushes
  call `emit` directly (`:1067-1071`), not `route_reply` — the `EmitKind::Unsolicited` shape in the
  flesh.

**What the port changes:** the reader is no longer `read_until(b'\n')` (stdio newline framing) but
the plane's `DuplexReader` over `pipe_read` bytes; the writer is `pipe_write` under the same single
`out` lock discipline. **What it must add that MCP's loop lacks:** MCP stdio is *not* wired to
`SessionScope`/`pipe_read`/`pipe_write`/`WorkItem` (verified — it uses the shared
`serve`/`rpc_dispatch` core seam but its own hand-rolled framing). The substrate pump wires those:
it owns the `PipeId`s, correlates via the `CallRef` table in `SessionScope`, and re-mints the host
per frame via `LiveHostFactory` (the one thing MCP's loop *does* already do, `:522`).

**The client leg is a warning, not a template.** MCP's client (`mcp/client/stdio.rs`) deliberately
has **no correlation table and no reader task** — it serializes whole exchanges behind a per-slot
`tokio::sync::Mutex<ChildSlot>` (`stdio.rs:829-831`) and documents why (`stdio.rs:820-827`:
demultiplexing on the JSON-RPC id would be *"a second correlation table … Serialising is the honest
shape until there is a reader task to own that table"*). Plane 4's upstream WS **cannot** serialize
— audio flows continuously in both directions — so the pump **must** own the reader task + the
`CallRef` table the MCP client punted on. That is the concrete net-new piece the pump adds over
both MCP legs.

**`pipe_read`/`pipe_write` are REAL host-wired today.** Do not misread the `unimplemented!()`
`PlaneHostVtable::STUB` (`crates/busbar-plugin/src/hot/host.rs:602-655`) as the live host — its own
doc says it is *"a compile-surface fixture, not a runnable host"* (`host.rs:604-605`) that exists
only to type-prove the signatures. The live host wires the real slots, and MCP stdio uses
`pipe_read`/`pipe_write` in production. The byte-duplex egress primitive ships; what is new is a
**WebSocket-framed `PipeId` dialer** (the egress side of §4.1's dispatch seam) and the ingress-upgrade
arrival (§4.2).

---

## 5. Session / handle store (axis C) and the two topologies

### 5.1 The session store — model on A2A's `taskstore`, ride `DurableScope`

Axis C (stateful handles / async) is a **separate** concern from the duplex transport and must not
wait behind WebSocket (Part II §II.1). The engine already exists: A2A's `taskstore`
(`crates/busbar-a2a/src/taskstore.rs`) is the blueprint, and for the LLM plane's stateful needs it
is nearly the *product*, not a blueprint to re-copy. Its mechanics, cited:

- **Lifecycle open→transition*→settle:** `submit` (`taskstore.rs:587-614`, durable write *before*
  the task is announced accepted); generic `transition<F>` (`:704-735`, the caller's closure decides
  the next state, durable-write-then-update-memory); terminal set matched as *string tokens*
  (`is_terminal_state`, `:317-319`) so the store *"names no `TaskState`."*
- **Retention/GC:** `MAX_RETAINED_TASKS = 4096` (`:328`), `sweep` (`:618-686`) — abandon stale
  active → `canceled`, TTL-evict terminal (`TERMINAL_TASK_TTL_SECS = 300`, `:324`), cap-evict oldest
  terminal first; an **active task is never dropped**.
- **Durable rehydration:** `restore_from_store` (`:498-583`) reads `list_plane_records`, decodes
  per-row (undecodable counted, never `?`-aborts), reloads each active task's event chain via
  `PlaneSelector::Parent(task_id)`, `verify_chain`s it, positions the chain, inserts into the working
  set — returns `Rehydrated { active, terminal, unreadable, chain_breaks }`.
- **Process-wide registry + scoped cross-request lookup:** `static TASKS` (`:404`, *"Process state,
  not config-derived … a config apply must not destroy in-flight tasks"*); `get_scoped(principal,
  id)` (`:859-867`) returns a single non-distinguishing `Denied::NotYours` for both missing and
  foreign (anti-enumeration).
- **Inbound-push cursor:** `set_push_callback` (`:839-855`) stores the callback URL on the row;
  `record_push_delivery` (`:773-798`) appends a delivery event; `advance_cursor` (`:801-835`) is the
  monotonic artifact cursor a resumed stream reads to know what was already delivered.

**The `DurableScope` fit.** A2A's taskstore rides the neutral `PlaneStore` seam (append/list/upsert/
purge_plane_records) rather than `DurableScope` directly, but the substrate scope taxonomy is built
for exactly this: `DurableScope` (`crates/busbar-substrate/src/plane_host/scope.rs:376-478`)
*"SURVIVES the process"* and its doc names the pattern — *"the async plane parks a handle at a `202`
and resumes it later by nested lookup."* Plane 4's **session record** (which upstream, which lease,
open/settle timestamps, the audit chain head) is a `DurableScope`-parked handle keyed
`"session-<id>"`, rehydrated on boot exactly as `restore_from_store` rehydrates tasks.

**The one genuinely net-new axis-C piece vs LiteLLM: the inbound webhook RECEIVER.** busbar has
outbound webhooks only (existing doc §1.6). Stateful Responses / batch / background all need busbar
to *receive* a completion push. This is orthogonal to voice and should ship independently on the
axis-C engine, not behind the duplex transport.

### 5.2 Two topologies (both keys-server-side)

**Topology A — server-to-server WS bridge (ships FIRST).** busbar terminates the client WS and holds
a persistent upstream WS with the real key. It sees every event: full metering, guardrails, audit,
server-side tools. This is the topology that fits the gauntlet cleanly (§3) and serves the owner's
own agent harness / server-side voice. **[RECOMMENDATION]** this is the whole 1.7.0 first cut (§8).

**Topology B — browser WebRTC (fast-follow).** Both halves are still keys-server-side:

- **Mint** the ephemeral `client_secret` — a JSON `POST /v1/realtime/client_secrets` that **is a
  normal gauntlet pass** (an `Invoke`-shaped one-shot, no duplex transport needed for the mint
  itself). *(Naming nuance for §7: the Realtime `client_secret` is a distinct concept from the
  OAuth `client_secret` that already appears in core auth, e.g. `crates/api/src/auth.rs:171`; the
  plane owns the Realtime meaning, core keeps the OAuth one — the neutrality test is about plane
  *nouns* like `input_audio_buffer`, not this shared English word.)*
- **Broker the SDP** — `POST /v1/realtime/calls`, `Content-Type: application/sdp` (a non-JSON body),
  preserving the `Location: /v1/realtime/calls/rtc_<call_id>` header. Audio then flows
  browser↔OpenAI peer-to-peer (busbar sees no media — the metering tap on Topology B is coarser, per
  `response.done.usage` on the sideband, not per audio frame).
- **Sideband control WSS keyed by `rtc_<call_id>`**, holding the real key: tool execution and
  instruction/`session.update` locking (§2.3) run server-side; the browser is never trusted to
  author tools or override instructions. This is a *second* long-lived socket the plane manages, and
  it is where Layer-1 (tool) and Layer-2 (control) governance lives when Layer-3 (media) is off-box.

---

## 6. The 1.6.0 ABI freezes (one-way doors)

Cross-reference Part II §II.5 for the full argument; this section states the freezes with exact
signatures.

### D1 — `WorkItem` duplex carrier tags. **Already locked; keep the witness.**
`InboundKind::Stream` (`crates/busbar-plugin/src/hot/workitem.rs:30`) + `EmitKind::Unsolicited`
(`:45-47`) are the duplex carrier, and the module's tests assert the tags exist and that `WorkItem`
can represent a duplex inbound+emit (`workitem.rs:18-19`). **Action: vigilance only** — do not let
any "simplification" collapse `WorkItem` to `(ptr,len)+sink` (the header warns this forces a
breaking reshape on the first exotic carrier, `:16-19`). Keep the witness test in the release gate.

### D2 — the metering-lease slots. **THE ONE REAL 1.6.0 DECISION. Freeze the shape now; add the slots when the plane lands.**
`cost_reserve`/`cost_settle` are **reserved but not present** in `PlaneHostVtable` — deliberately
(`crates/busbar-plugin/src/hot/host.rs:18-22` and the vtable position `:533-536`: *"add
`cost_reserve`/`cost_settle` as trailing `Option` slots below this line and bump the airlock MINOR —
an append-only add, never a reshape"*; echoed on the POD at `hot/pod.rs:636-638`). For Plane 4's hard
mid-session budget stop (§3.3) they are **mandatory**. Per the tree's own doctrine, do **not** ship
the slots in 1.6.0 — but **bless the shape** so the 1.7.0 add is mechanical. The frozen signatures,
mirroring the existing `CostHold` type and the surrounding slot conventions:

```rust
// APPENDED at the reserved EXTENSION POINT (hot/host.rs:533), trailing Option slots, airlock MINOR bump.

/// Open a reserve-then-settle lease for a high-rate carrier: reserve a coarse over-estimate
/// (host debits the budget cell now) and return an opaque host-side lease id. `Magnitude`
/// carries the plane's coarse unit+amount (audio-seconds / tokens) and the caller_cap.
pub type CostReserveFn = extern "C-unwind" fn(
    host: HostCtx,
    magnitude: *const Magnitude,   // crates/busbar-core/src/plane/cost.rs:269
    flat_fee_nanos: u128,
    out_lease: *mut CostLeaseId,   // NEW POD newtype (u64), 0 = NONE sentinel
) -> StatusClass;

/// Settle one EXACT increment against an open lease (a frame's / a turn's true cost), and read
/// back whether the lease is now exhausted so the plane can hard-close. The plane supplies the
/// itemized CostBreakdown as an opaque pre-framed suffix (the journal_append_scoped pattern);
/// the host accrues its `total` and answers exhaustion.
pub type CostSettleFn = extern "C-unwind" fn(
    host: HostCtx,
    lease: CostLeaseId,
    breakdown_ptr: *const u8,      // opaque CostBreakdown suffix (host never parses the labels)
    breakdown_len: usize,
    out_exhausted: *mut bool,      // true ⇒ budget dry ⇒ plane hard-closes the session
) -> StatusClass;

pub cost_reserve: Option<CostReserveFn>,   // trailing slot
pub cost_settle:  Option<CostSettleFn>,    // trailing slot
```

Design notes that make this append-only-safe: (a) both are `Option` trailing slots under the
sized/versioned `AbiPreamble` discipline every other appended cluster follows (e.g. the minor-9
journal family, `host.rs:483-503`); (b) the `CostBreakdown` crosses as an **opaque suffix** the host
never parses — core mints nothing from it but the accrued `total`, preserving the "core names no
plane label" rule (`cost.rs:73-82`); (c) `finalize`/refund stays plane-side on the shipped `CostHold`
(`cost.rs:334`) — the host slot only reserves and settles, so no refund policy is baked into the ABI.

**This is the only build-adjacent 1.6.0 action.** Ratify these signatures in this doc; do not ship
them.

### D3 — `SessionScope` and the gauntlet stay append-only-open. **Already locked; keep vigilance.**
`SessionScope {}` (`scope.rs:366`) stays an empty `#[non_exhaustive]` stub whose per-connection slot
is a later *append*, never a reshape; `run_gauntlet`/`GauntletPlane` stay a free fn + trait a session
entry sits beside (§3.1). **Action: vigilance only** — do not "tidy away" the dormant scope, and do
not make the one-`Response` return the only shape.

Everything else a duplex plane needs is **already shipping and needs no 1.6.0 decision:** the
byte-duplex `pipe_read`/`pipe_write` slots (`host.rs:474-476`), the per-session audit via
`journal_append_scoped` (`host.rs:491`), the per-frame re-mint via `LiveHostFactory`
(`plane_host/mod.rs:215`), the `DurableScope` park/resume engine (`scope.rs:376`), and the
`OpShape::Subscribe`/`Control` long-lived shapes (`crates/api/src/operation.rs:121-124`).

---

## 7. Grep-neutrality proof

### 7.1 The crate name: `busbar-voice` (justified)

**[RECOMMENDATION] Name the plane crate `busbar-voice`, not `busbar-realtime`.** The precedent is
`busbar-llm`: it is named for the **capability class** (LLM chat) and serves six *dialects*
(OpenAI, Anthropic, Gemini, Bedrock, Cohere, Responses) — it is **not** `busbar-openai`. The Plane-4
crate serves the **live-voice/duplex** capability class and will carry two dialects (OpenAI Realtime
first, Gemini Live second — the moat). Naming it `busbar-realtime` would file it under one vendor's
product noun, exactly the mistake `busbar-llm` avoided. `busbar-voice` also cleanly excludes axis-C
(batch/Files/stateful Responses) which is *not* voice and rides the A2A engine, not this crate (§5.1).

The **neutral duplex primitives are NOT in `busbar-voice`** — they live in `busbar-substrate` and are
reusable by any future duplex plane (a database-wire plane, a generic streaming plane):
`Transport::WebSocket` + the Transport→listener/dialer dispatch seam (§4.1), the WS-upgrade arrival
kind (§4.2), the substrate-owned bidirectional pump (§4.3), and the `SessionScope` wire-out (§3.2).
This is the same split as MCP: the *protocol* (`busbar-mcp`) vs the neutral `Transport::Stdio` +
`pipe_read`/`pipe_write` (`busbar-substrate`/`busbar-plugin`).

### 7.2 The nouns that live ONLY in `busbar-voice`

Verified absent from the entire tree today (so the crate introduces them from zero): `realtime`,
`input_audio_buffer`, `barge_in`, `response.output_audio`, and the OpenAI-Realtime event taxonomy.
These, plus the plane's IR types (`IrClientEvent`, `IrServerEvent`, `IrAudioFrame`, `IrDuplexTool`,
`IrDuplexControl`, `IrDuplexUsage`), the VAD config surface, the `rtc_<call_id>` sideband key, the
audio/text token-class split, and the Gemini Live `BidiGenerateContent` mapping — **all live only in
`busbar-voice`.**

### 7.3 Core/substrate/api name none of them — and the gates stay green

- **Neutrality:** core moves **opaque framed bytes** over `pipe_read`/`pipe_write` (`host.rs:155-171`,
  *"the host moves RAW BYTES only … framing stays PLANE-side"*), carries duplex work as
  `WorkItem{Stream,Unsolicited}` (`workitem.rs`), mints audit `seq`/`hash` over an **opaque suffix it
  never parses** (`journal_append_scoped`, `host.rs:491` + `JournalReframeFn`, `host.rs:194`), and
  meters an **opaque `CostBreakdown` suffix** (§6-D2). Core never names "audio."
- **Plane-purity / no-plugins-in-core:** `busbar-voice` declares its own `ProtocolDecl` with
  `codec: None` (one dialect) → `Some` (two dialects) exactly as MCP does (`proto.rs:664`), and core's
  registry unions whatever verbs/keys it declares without naming it (the MCP precedent,
  `codec/mod.rs:11-16`: *"nothing in `busbar-core` names this crate … `git grep busbar_mcp
  crates/busbar-core/src` is pinned at zero"*).
- **Plane-delete:** deleting `busbar-voice` is "4 files or so" and the app never knew it existed —
  the deletion test `operation.rs:30-33` states as the design's line-one requirement. Compiling the
  crate out removes the voice *protocol*; `Transport::WebSocket` and the pump are neutral substrate
  and stay (unused, like the pre-caller `Stdio` supervisor once did, `transport.rs:20-24`).
- **Grep-neutrality:** the test greps core/substrate/api for plane nouns. The one English-word
  collision to note (and it is *not* a violation): `client_secret` already appears in core in the
  **OAuth/OIDC** sense (`api/src/auth.rs:171`, `core/src/auth/mod.rs:2101`). The neutrality assertion
  is about **plane-specific nouns** (`input_audio_buffer`, `realtime`, `rtc_`), which are and stay
  zero in core — not about a shared English word whose meaning the plane owns locally.

---

## 8. Scope call — decisive

**Recommendation: Plane 4 is a 1.7.0 plane on the unchanged 1.6.0 ABI. In 1.6.0, freeze D2 and keep
the D1/D3 witnesses — nothing else.** This is Part II's recommendation and it survives the harder
look this doc took, for three reasons the design made concrete:

1. **The ABI is ~90% duplex-ready by deliberate design** (§3, §4, §6): the carriers, the per-frame
   re-mint, the scoped audit, the byte-duplex pipe, and the lease *type* all ship. The gap is one
   ABI shape (D2) plus a substrate transport/pump/arrival build — additive, not a re-architecture.
2. **Shipping voice inside 1.6.0 would drag the media build/adopt decision (§F) and a concrete
   vendor protocol into a release whose entire thesis is the neutral seam.** That contradicts the
   thesis it is meant to prove.
3. **D2 is the only true one-way door**, and it is *cheap* — ratify two signatures now, ship them
   with the plane later.

**But be decisive about the first cut.** The owner is weighing "a real Plane 4." The right answer is
**yes, build it — as a 1.7.0 crate whose first increment is the thin same-dialect server-to-server
bridge**, not the full moat. That first cut:

- **Topology A only** (server-to-server WS, §5.2) — fits the gauntlet cleanly, serves the Jarvis
  harness, needs **no** browser, **no** WebRTC, **no** SDP broker.
- **One dialect** (OpenAI Realtime) → `codec: None`, no cross-dialect superset IR yet (the A2A rule,
  §1.4). The four-layer IR is still real (tool normalize, control translate-stub, media verbatim,
  usage extract) — it just has one wire format on each side.
- **No media pump build** — Topology A relays audio *frames* over the WS as bytes (§2.4); the mic /
  24 kHz resample / jitter-buffer / WebRTC / SIP media pump is **not** in scope until Topology B.
- **Full gauntlet** — open pass + per-frame govern + `cost_reserve`/`settle` hard-stop + per-session
  audit chain. This is the whole differentiator and it is present from the first cut.

The **cross-dialect moat** (Gemini Live, earning the superset IR) and **browser WebRTC + media
adopt** (Pipecat/LiveKit, §F) are 1.7.x/1.8.0 follow-ons on the frozen seam. Media: **own the
gauntlet, adopt the media pump** — busbar owns keys/routing/govern/audit/server-side-tools; it adopts
Pipecat or LiveKit Agents for the mic/resample/jitter/WebRTC/SIP leg. Justification: the media pump
is a maintenance treadmill orthogonal to busbar's value (the governed control/keys/routing layer),
and both orchestrators already run *behind* OpenAI Realtime, so the adapter surface is small and the
"own the gauntlet" story is undiluted.

### Phased plan (each phase green; composition + plane-purity gates hold at every commit)

- **P0 (1.6.0):** ratify + freeze D2 signatures (this doc); keep D1/D3 witnesses in the release gate.
  Optionally land the orthogonal header-fidelity fix (existing doc Phase 0) whenever convenient.
- **P1 (1.7.0, substrate):** `Transport::WebSocket` + the Transport→listener/dialer dispatch seam; the
  WS-upgrade arrival kind; the substrate-owned bidirectional pump (port of MCP `Session<W>`); wire
  `SessionScope` out. Add the D2 slots. DoD: an echo duplex test plane accepts a WS client, holds a
  WS upstream, pumps both ways, reclaims `SessionScope` on close — no voice nouns yet.
- **P2 (1.7.0, `busbar-voice`):** the four-layer IR + `DuplexReader`/`DuplexWriter`; session-open
  through `run_gauntlet_session`; per-frame govern + `cost_settle` lease + `journal_append_scoped`
  chain; the mid-call tool loop + barge-in bookkeeping; OpenAI Realtime as the one dialect. DoD:
  Topology A holds a live voice session end-to-end — audio both ways, a mid-call tool answered
  server-side, barge-in truncates correctly, usage metered, budget hard-stops mid-session, session
  audited and restart-survivable.
- **P3 (1.7.x):** browser WebRTC — mint `client_secret`, broker SDP, sideband control WSS; adopt
  Pipecat/LiveKit for media.
- **P4 (1.8.0):** Gemini Live — the second dialect that *earns the superset IR* and turns the
  four-layer IR into the cross-dialect backend-swap moat.
- **(parallel, not gated by voice):** axis-C — the inbound webhook receiver + the session/handle
  store on the A2A engine, unlocking stateful Responses / batch / background. Needs no WebSocket.

---

## 9. What users get (the value narrative)

*Written for a buyer / VC, not for the compiler. Every claim here is honest about its ceiling.*

### 9.1 What a customer can DO that LiteLLM does not give them today

LiteLLM already bridges a Realtime WebSocket and mints ephemeral secrets — as an **opaque
WS↔WS passthrough** with logging bolted on the side. busbar's Plane 4 is the difference between
*a pipe that logs* and *a governed boundary that decides*. Concretely, the customer gains:

- **Governed voice sessions.** A live voice call opens through the **same one gauntlet** as every
  text call — identity, destination-verify, budget admission, audit-open — not a side-channel. One
  policy surface covers voice and text.
- **Server-side tool execution the browser cannot override.** When the model calls a tool mid-call,
  busbar executes it **server-side**, under the operator's request-admission gates, and the browser
  (WebRTC) never holds the key and cannot forge a result or rewrite the system instructions. "Tools
  mid-call, safely" is a *product guarantee*, not a hope.
- **Per-turn budget hard-stop mid-call.** A runaway voice session is **cut off when its budget is
  exhausted** — the reserve-then-settle lease (§3.3) can stop a live stream, which post-hoc metering
  (LiteLLM's model) structurally cannot. No more "the audio kept flowing while the alert fired."
- **A durable audit chain for a live voice call.** Every turn — audio, tool call, barge-in,
  truncation, usage — is a **hash-chained record under one session scope** that verifies through the
  one digest and **survives a restart**. "What did the voice agent do, and what did it cost, turn by
  turn" is answerable after the fact, cryptographically.
- **Keys never leave the server** — in both the server-to-server bridge and the browser WebRTC
  path (ephemeral mint + sideband control). The browser gets a short-lived secret and peer-to-peer
  media; it never gets your OpenAI key.

### 9.2 The specific payoff for the owner's Jarvis-like stack

Today: LiteLLM proxies OpenAI Whisper (voice) + local models (coding/report-gen) for a fleet of
specialist agents doing CI, monitoring, alerting, triage. Voice is a *pipe*; text is *proxied*; they
are two different governance stories.

After Plane 4, concretely:

- **The voice agents get the same admit / govern / execute / audit gauntlet as the text calls.** A
  triage agent that talks (Realtime) and a report-gen agent that writes (chat `Invoke`) are governed
  by **one** policy plane, metered into **one** ledger, audited into **one** chain.
- **One place to rotate keys, cap spend, and read back what a voice agent did.** Rotate the OpenAI
  key once; every voice session picks it up on the next frame (the `LiveHostFactory` per-frame
  re-mint, §3.2). Cap a noisy monitoring agent's voice budget the same way you cap its token budget.
  Read back a 3am incident call turn-by-turn from the same audit surface as the text calls.
- **The mid-call tools are the CI/monitoring actions themselves** — "restart the job," "acknowledge
  the alert," "pull the last 50 lines" — executed server-side under gates, not trusted to a browser
  or a prompt. The voice agent becomes a *governed operator*, not an ungoverned mouth.

### 9.3 The moat vs LiteLLM — cross-dialect backend-swap

LiteLLM's WS↔WS passthrough carries opaque bytes; it **cannot reshape the dialect**, so it cannot let
you keep your OpenAI-Realtime client and swap the backend. busbar's **layered plane-IR** can — and
this is the moat:

- **Tool layer — translate.** `function_call_arguments.delta/done` ⇄ Gemini Live's tool-call shape,
  with `CallRef` correlation and id/name remap (§2.2). Your client's tools work against either
  backend.
- **Control layer — translate.** `session.update` / VAD / `response.create` ⇄
  `BidiGenerateContent` config (§2.3). Your client's session config works against either backend.
- **Media layer — verbatim tap.** Audio frames relay byte-for-byte (§2.4), so the swap costs no
  fidelity and no transcode (except the optional telephony g711↔pcm24k, armed per lane).
- **Usage layer — extract.** Audio/text token classes normalize into one ledger regardless of
  backend (§2.5).

The payoff: **the same OpenAI-Realtime browser/agent client, pointed at Gemini Live or (later) a
local speech-native stack, with no client rewrite.** That is a capability LiteLLM's architecture
cannot reach, because it never builds the per-plane IR — it only forwards bytes.

### 9.4 The ceiling users should NOT expect (stated honestly)

The IR bridges **speech-native duplex dialects** (OpenAI Realtime ⇄ Gemini Live). It **cannot** turn
a speech-native Realtime model into a **Whisper→LLM→TTS cascade** — that is model-replacement /
orchestration (Pipecat, LiveKit), not a dialect reshape (§2.7). If the ask is "route my Realtime
client to my local Whisper + Llama + Piper," busbar governs and meters those three pieces as the
`Invoke` operations it already proxies — but it does not *become* the cascade, and no amount of IR
work would make it. Buyers should hear this plainly: busbar is the **governed boundary and the
cross-dialect bridge for duplex voice**, not a voice-pipeline orchestrator. The two compose (busbar
in front of Pipecat), but they are different products.

---

## 10. Adversarial self-review (challenging this design's own claims)

- **"Is the four-layer IR real, or is it three verbatim layers with a tool-call special case?"** It
  is real but *asymmetric by layer*, and the doc says so rather than overselling: Layer 1 genuinely
  reshapes (and is the whole value), Layer 2 reshapes only cross-dialect, Layers 3–4 are identity/
  extraction. That asymmetry is the *point* (owner's rule §2.1), and it matches the shipped precedent
  where same-dialect chat streaming runs the IR as a pure usage side-channel over verbatim bytes.
- **"Does session-open really fit `run_gauntlet` when it returns a `Response`?"** Open does (it *is*
  one pass). The long-lived session needs a sibling entry returning a `SessionScope` handle (§3.1).
  This is an append beside a free fn + trait, verified — not a reshape. The risk is a 1.6.0
  "simplification" that inlines `run_gauntlet` and forecloses it; D3 guards exactly that.
- **"Is D2 actually necessary, or is post-hoc metering good enough?"** Necessary. You cannot refund
  streamed audio; only a reserve/settle lease can hard-stop mid-session. The lease *type* ships
  (`CostHold`); only the FFI slot is missing. If D2 slips, the plane either bypasses the budget cap
  on live sessions (a governance hole) or reshapes the vtable later (a breaking ABI change). Freezing
  two signatures now avoids both.
- **"Is `busbar-voice` genuinely deletable / neutral, given `client_secret` is already in core?"**
  Yes — that collision is the OAuth `client_secret`, an unrelated English word core owns in the auth
  sense (§7.3). The plane's *nouns* (`input_audio_buffer`, `realtime`, `rtc_`) are verified zero in
  core and stay zero; the neutrality gate keys on those, not on shared words.
- **"Is adopting Pipecat/LiveKit a dependency risk?"** It is a *bounded* one: adopt them only for the
  media leg (Topology B, P3+), which is orthogonal to the gauntlet. Topology A (the first cut, the
  Jarvis payoff) needs neither. If an orchestrator is dropped, the governed boundary is untouched.
- **"What genuinely needs the owner?"** See §11.

---

## 11. Open questions that genuinely need the owner

1. **First cut = Topology A only, confirmed?** This doc recommends the thin same-dialect
   server-to-server bridge as the entire 1.7.0 first increment (no browser, no media pump, no
   cross-dialect). Does the Jarvis use case need in-*browser* voice on day one, or is server-side /
   harness-side voice the real near-term need? (If browser is day-one, P3 moves up and the media
   build/adopt decision becomes immediate.)
2. **D2 signature ratification.** The two signatures in §6-D2 are the one build-adjacent 1.6.0
   action. Ratify as written, or adjust the `Magnitude`-vs-raw-scalar and exhaustion-readback shapes
   before they freeze? (This is the one-way door — worth five minutes now.)
3. **Media ownership when Topology B lands (P3):** Pipecat vs LiveKit Agents vs native. The doc
   recommends adopt-for-media; the choice *between* the two orchestrators (SIP/telephony needs,
   licensing, ops footprint) is the owner's call and the biggest scope lever after the first cut.
4. **Axis-C sequencing.** The inbound webhook receiver + session/handle store (stateful Responses /
   batch / background) is orthogonal to voice and rides the A2A engine. Ship it *before*, *alongside*,
   or *after* the voice first cut? It is independently valuable and independently shippable.
```
