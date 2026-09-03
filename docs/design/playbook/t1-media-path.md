# Playbook T1 — The Media Parallel Path (busbar-voice Layer 3)

Status: **DESIGN PLAYBOOK (not build).** Read-only against the tree. Owner: Matthew.
Inputs: `docs/design/plane4-seam-audit-E-ir.md` (Seam 3, Seam 4, ranked items 1–2),
`docs/design/plane4-duplex-session.md` (§2.1, §2.4, §2.3 barge-in, §4.3 pump).

**The one sentence this playbook exists to enforce:** the voice media path is a **new,
parallel, bidirectional byte pump** built on `pipe_read`/`pipe_write` +
`InboundKind::Stream`/`EmitKind::Unsolicited` + `SessionScope`. It sits **beside**
`StreamTranslator`/`FirstByteBody`, never on top of them, and it does not extend
`MediaBlob` — it defines a new incremental frame type next to it. (Audit E, verdict, lines
17–46; ranked items 1–2, lines 181–197.)

---

## 1. The concrete types: `MediaBlob` (unchanged) vs `IrAudioFrame{dir,seq}` (net-new)

### 1.1 `MediaBlob` — stays exactly what it is, does not become the frame carrier

`crates/busbar-substrate/src/media.rs:103-108`:

```rust
pub struct MediaBlob {
    pub payload: MediaPayload,      // Bytes | B64            (media.rs:86-89)
    pub mime_type: String,
    pub pcm: Option<PcmParams>,     // { sample_rate, channels, bit_depth } (media.rs:94-98)
}
```

This is a **whole-payload, one-shot** blob — `TranscriptionReq.audio: Option<MediaBlob>`
(`crates/busbar-llm/src/ir/audio.rs:57`), `SpeechResp.audio: Option<MediaBlob>` (`:242`). It
has no sequence number, no direction tag, no frame boundary (Audit E Seam 4(a), lines
154-159). **Do not add `seq`/`dir` fields to `MediaBlob`** — that would silently turn a
one-shot STT/TTS carrier into a streaming one and break every existing whole-blob call site.
`MediaBlob` continues to serve exactly its current callers: whole-file transcription input,
whole-file speech output. `PcmParams` is reused as-is (§4 below) as the *parameter* shape for
telephony resampling, not the frame carrier.

### 1.2 `IrAudioFrame{dir,seq}` — net-new, lives in `busbar-voice`

Per design §2.4 (`plane4-duplex-session.md:270`) and Audit E (lines 166-173, "shares nothing
with `MediaBlob` except an opaque byte payload"):

```rust
// crates/busbar-voice/src/ir/media.rs (net-new file, net-new crate)

/// Direction of an audio frame relative to busbar, matching IrDuplexControl's use of
/// "up"/"down" elsewhere in the plane (design §2.6: AudioFrame(up) is a client→server
/// IrClientEvent variant; AudioFrame(down) is a server→client IrServerEvent variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioDir {
    /// client → busbar → upstream (mic capture / input_audio_buffer.append)
    Ingress,
    /// upstream → busbar → client (response.output_audio.delta)
    Egress,
}

/// A single directional, sequenced audio frame under a live duplex session.
/// Identity transform by default (§2.1/§2.4) — the tap point for meter/audit, not a reshape.
pub struct IrAudioFrame {
    pub dir: AudioDir,
    /// Per-(session, dir) monotonic sequence number — NOT a wire field copied verbatim;
    /// the plane assigns it as frames are read off pipe_read, mirroring how
    /// StreamDecodeState is plane-computed, not wire-derived (proto_codec.rs:135 model).
    pub seq: u64,
    /// Opaque payload — identity transform by default. Only touched by the optional
    /// telephony transcode (§4) or the cross-dialect resample (Gemini Live, 2nd dialect).
    pub media: Bytes,
}
```

**Why `IrAudioFrame` cannot live in or extend `MediaBlob`:** `MediaBlob` has no session
context, no ordering, no direction — it is a value, not a stream element. `IrAudioFrame` is
scoped to a live `SessionScope` (design §5.1, `DurableScope`-parked "session-<id>" handle) and
is meaningless outside a duplex pump. Two types, two lifetimes, two crates
(`busbar-substrate::media` vs `busbar-voice::ir::media`) — this mirrors the
`IrStreamEvent`/`IrServerEvent` "sibling, not extension" relationship the design states
explicitly for the control layer (design §2.6, line 321: *"It is the *sibling* of
`IrStreamEvent`… not an extension of it"*). `IrAudioFrame` is `MediaBlob`'s sibling under the
same rule, not its subtype.

`seq` ordering is **per (session_id, dir)** — ingress and egress are independent streams (full
duplex, not request/response), so there is no cross-direction ordering invariant to hold. This
matters for §3 (barge-in): a truncate only needs to reason about the egress sequence the
client actually played, never interleaved against ingress.

---

## 2. How bidirectional frames flow through the pump (not through the translator)

### 2.1 What NOT to reach for

`StreamTranslator::feed(&mut self, chunk: &[u8]) -> Vec<u8>`
(`crates/busbar-substrate/src/proto.rs:441-444`) is typed **egress bytes in → ingress bytes
out**, one direction, one call site per stream, response-terminal vtable (`finish`/`usage`/
`terminal_error`/`aborted`). `FirstByteBody<S,P>` (`crates/busbar-llm/src/engine/
response_body.rs:45,234`) `impl Stream`s over the **upstream response body** — it is a
response, not a duplex channel. The `same_proto` verbatim tap (`crates/busbar-llm/src/
proto_stream.rs:91-97`) is the closest existing "identity IR + side-channel metering" pattern
and is the right *conceptual* model for Layer 3's verbatim-by-default posture (design §2.1) —
but it is **still `feed()` on the one-way pump**: it cannot carry a client→server (ingress)
raw audio frame. Wiring voice media through any of these three types means bolting a second
direction onto a trait that is one-way **by its type signature**, not by an accident of
implementation — there is no version of `feed` that becomes bidirectional without breaking
every existing LLM-plane caller.

### 2.2 What to reach for instead

The pump is the substrate-owned port of MCP's `Session<W>` (design §4.3,
`crates/busbar-mcp/src/mcp/stdio_serve.rs:383-410` as the mechanics template):

- **Two independent byte legs**, not one `feed`: a read task per direction over
  `pipe_read`/`pipe_write` (`crates/busbar-plugin/src/hot/host.rs:161-171`, "the host moves RAW
  BYTES only — line/message framing stays PLANE-side"). Ingress and egress are two separate
  `PipeId`s (or one duplex `PipeId` read/written independently — either way, two logical
  streams, two frame-assembly loops).
- **The reader/writer split is `DuplexReader::read_up`/`read_down`** (design §2.6,
  lines 309-316) — `read_up` turns client-origin wire bytes into `IrClientEvent::AudioFrame(up)`
  wrapping an `IrAudioFrame{dir: Ingress, seq, media}`; `read_down` turns upstream wire bytes
  into `IrServerEvent::AudioFrame(down)` wrapping `IrAudioFrame{dir: Egress, seq, media}`. Two
  functions, not one `feed`, because the two directions have independent framing, independent
  sequence counters, and independent failure modes (a malformed ingress frame must not abort
  the egress stream and vice versa — unlike `StreamTranslator::aborted()`, which is a single
  stream-wide flag).
- **Carriage on the wire types that are already duplex-shaped:** `InboundKind::Stream`
  (`crates/busbar-plugin/src/hot/workitem.rs:31`, "a streamed inbound (chunked request body /
  duplex read side). WIRED") carries the ingress leg; `EmitKind::Unsolicited`
  (`workitem.rs:45-47`, "a host/peer-independent push not correlated to an inbound
  (duplex-session notification). WIRED for duplex-session") carries the egress leg — server
  push, not a reply to a specific inbound frame. This is the load-bearing distinction: LLM
  streaming uses `EmitKind::Stream` (a reply-shaped, request-correlated stream); voice egress
  audio is `EmitKind::Unsolicited` because it is not a reply to any one ingress frame — the
  model can start talking, get interrupted, and resume, decoupled from ingress cadence.
- **`out: tokio::sync::Mutex<W>` — one writer lock per direction, not one for the whole
  session.** MCP's `Session<W>` uses a single write lock because MCP has one logical output
  stream (`stdio_serve.rs:393`). Voice has two independent physical legs (ingress to upstream,
  egress to client) so the pump needs the **same discipline duplicated per direction**: one
  lock serializing egress frames+control+tool events onto the client socket, one lock
  serializing ingress audio+control onto the upstream socket. Getting this wrong (one shared
  lock for both directions) would deadlock the pump under full-duplex load — flag this
  explicitly for the implementer.
- **`CallRef` correlation table lives in `SessionScope`** (design §4.3, "it owns the `PipeId`s,
  correlates via the `CallRef` table in `SessionScope`"), not per-frame — tool-call correlation
  (Layer 1) is orthogonal to audio-frame sequencing (Layer 3) and must not share a table; audio
  frames are **not** correlated by `CallRef` at all, only by `(session_id, dir, seq)`.

### 2.3 Net effect

`StreamTranslator`/`FirstByteBody` remain untouched, LLM-plane-only, response-only. The voice
pump is 100% new code in `busbar-voice`, riding neutral primitives that already exist and are
already wired in production (MCP proves `pipe_read`/`pipe_write` are live, not stub —
`host.rs:602-605` warns not to mistake `PlaneHostVtable::STUB` for the real host). No core or
substrate type gains a second direction; no LLM type gains a voice-shaped variant.

---

## 3. Barge-in / truncate bookkeeping

Design §2.3 (`plane4-duplex-session.md:254-260`) is authoritative; this section makes the
`IrAudioFrame{dir,seq}` bookkeeping concrete against it.

### 3.1 The event sequence

1. Upstream emits `input_audio_buffer.speech_started` (user started talking over the model).
2. Plane **cancels the in-flight response** (stop emitting further egress frames /
   `ResponseCancel` upstream).
3. Plane issues `ItemTruncate{ item_ref, audio_played_ms }`
   (`IrDuplexControl::ItemTruncate`, `plane4-duplex-session.md:243`) — `audio_played_ms` is
   **the audio the user actually heard**, not the audio busbar sent.

### 3.2 `audio_played_ms` is plane-computed state, not a wire field

Design line 259: *"`audio_played_ms` is therefore a piece of plane-computed IR state, not a
field copied off the wire."* Concretely, against `IrAudioFrame{dir: Egress, seq}`:

- On **WebSocket** (Topology A, server-to-server bridge — the 1.7.0 first cut, design §5.2 /
  §8): busbar is the only party that knows what has actually reached the speaker, because the
  server can emit audio **faster than realtime** (buffered ahead). The pump must track, per
  session, a running `egress_audio_end_ms` derived from `IrAudioFrame{dir: Egress, seq}`
  arrival + the frame's PCM duration (`PcmParams.sample_rate` × frame byte length ÷
  bytes-per-sample, using the session's negotiated `audio_fmt` from `SessionConfigure`), summed
  in `seq` order up to the frame boundary the client has had time to actually play. This is
  **not** "sum of bytes emitted" — it is "sum of bytes emitted, clamped by wall-clock elapsed
  since response start," because emission outruns playback.
- On **WebRTC** (Topology B, fast-follow): "the server truncates automatically" (design line
  258) — OpenAI's Realtime server tracks playback position itself once audio flows
  peer-to-peer, so busbar does **not** need to compute `audio_played_ms` on that leg; the
  sideband control WSS (design §5.2) only forwards the truncate signal, it does not derive the
  timing.
- **`seq` is the ordering key `audio_played_ms` is computed against.** Frames are summed
  strictly in ascending `(session_id, Egress, seq)` order; a truncate event pins a `seq`
  boundary (the last frame counted toward `audio_played_ms`) so downstream `CallResult`/audit
  events can cite "truncated after egress seq N" without re-deriving timing from raw bytes.

### 3.3 Flush + guard post-truncate deltas

Two failure modes the pump must guard against, both a direct consequence of picking `seq` as
the ordering primitive:

1. **Flush stale egress frames already in flight.** Between "speech_started detected" and
   "`ResponseCancel` lands upstream," the pump may have already dequeued/buffered further
   `IrAudioFrame{dir: Egress, seq: N+1, N+2, …}` frames from the upstream read task. These must
   be **dropped, not written** to the client socket — otherwise the client keeps hearing audio
   after the user tried to interrupt. The write-lock discipline (§2.2) gives a single choke
   point: the truncate handler must acquire the egress writer lock and clear any queued-but-
   unwritten frames for that session before releasing it, so no frame with `seq >
   truncate_boundary_seq` reaches the wire.
2. **Guard post-truncate deltas from a stale `seq` counter.** After a truncate, the **next**
   response's egress frames must start a **fresh `seq` count** (or the pump must otherwise mark
   the sequence discontinuity), because `audio_played_ms` accounting for the truncated response
   is now closed — a late-arriving frame from the cancelled response with an old `seq` must
   never be summed into the new response's playback-position tracking. Concretely: the
   per-session `DecodeState` (design §2.6, "threads a `DecodeState` exactly as
   `read_response_events` threads `StreamDecodeState`") should carry a `response_generation:
   u64` alongside `seq`, bumped on every `ResponseCreate`/truncate, and the playback-position
   accumulator keys off `(response_generation, seq)` — not `seq` alone — so a stray
   in-flight frame from the just-truncated response cannot be mistaken for the new response's
   frame 0.

Both guards are new plane-side logic; nothing in `StreamTranslator`'s `aborted()`/`finish()`
vtable (proto.rs:452/446) models mid-stream truncation-and-resume, because the LLM plane never
needs to un-send audio the user already heard.

---

## 4. g711 8 kHz vs pcm16 24 kHz — the resampling boundary

### 4.1 Where the boundary sits

Design §2.4 (line 266): *"the seam where the *optional* transcode would live (g711 ↔ pcm24k
for telephony; only armed when a lane declares it)"*; §9.3 (line 836): *"except the optional
telephony g711↔pcm24k, armed per lane."* The default is **verbatim byte-relay** — no
resampling — because the fidelity doctrine (design §2.4, lines 273-277) says nobody
cross-translates a live voice session by default; the transcode is a **per-lane opt-in**, not a
pipeline stage every frame passes through.

### 4.2 The two lanes

| Lane | Format | Sample rate | When it applies |
|---|---|---|---|
| **Browser / WebRTC or server-to-server WS** | `pcm16` (`audio/L16;codec=pcm`) | 24 kHz (OpenAI Realtime's native rate) | Default. `IrAudioFrame.media` carries pcm16 bytes verbatim, `PcmParams{sample_rate:24000, channels:1, bit_depth:16}` describes the format at session-config time; no per-frame transcode. |
| **Telephony passthrough** | g711 (µ-law/A-law) | 8 kHz | Only when a lane explicitly declares telephony (SIP trunk / PSTN bridge) as its transport. |

`PcmParams` (`media.rs:94-98`) already carries exactly the shape needed to describe either
side of this boundary (`sample_rate`, `channels`, `bit_depth`) — Audit E confirms this (line
161-163: *"already carries the 24 kHz/16 kHz rate… but only on a whole blob, with no streaming
reader/writer that would apply it per frame"*). Reuse `PcmParams` as the **parameter type**
attached to a session's `SessionConfigure.audio_fmt` (design §2.3, line 240) for each leg (one
`PcmParams` for the client-facing leg, one for the upstream leg); do **not** invent a
voice-specific duplicate of the same three fields.

### 4.3 Where the transcode function lives (and where it does not)

- **Telephony g711↔pcm24k is new plane-side code**, armed per lane, sitting between the
  telephony `PipeId`'s read/write and the `IrAudioFrame` construction — i.e. it is a filter on
  the byte stream *before* `read_up`/`read_down` wraps it in `IrAudioFrame`, or symmetrically
  just *after* `write_up`/`write_down` unwraps it, so that `IrAudioFrame.media` is always in the
  session's *canonical* rate for that leg, and the transcode is invisible to the `seq`/`dir`
  bookkeeping in §3. This keeps barge-in math (which operates on frame *duration*, computed
  from `PcmParams`) correct regardless of which physical codec is on the wire, as long as the
  transcode step is symmetric about the `IrAudioFrame` boundary.
- **Cross-dialect resample (24 kHz OpenAI ↔ 16 kHz Gemini Live input)** is a *different* boundary
  — earned at the second dialect (design §1.4, §7.4), not part of this playbook's scope (single
  OpenAI-Realtime-dialect Topology A). Audit E Seam 2(b) (line 107) already scopes this as
  TRANSCODE-tier work for the feasibility doc, not Layer-3 default behavior.
- **Nothing in `busbar-substrate` or `busbar-core` learns g711 or pcm16 as a name** — per the
  grep-neutrality proof (design §7), the transcode function and its format enum live entirely
  inside `busbar-voice`, consuming the neutral `PcmParams` struct that already exists in
  `busbar-substrate::media` (a shared, opaque-to-core parameter shape, not a voice-specific
  wire noun).

---

## 5. Residual risks

1. **[HIGHEST] Implementer reaches for `StreamTranslator`/`FirstByteBody` as the pump.**
   Both are one-way *by type signature* (`proto.rs:444`, `response_body.rs:234`); there is no
   safe partial-adoption path — the fix is a from-scratch bidirectional pump (§2), and this
   temptation is the single highest-probability seam-confusion bug per Audit E's own ranking
   (lines 181-189). Mitigate by naming the pump's module/trait clearly (`DuplexReader`/
   `DuplexWriter`, not anything sharing a name with `StreamTranslate`) and CI-grepping for any
   `busbar-voice` import of `busbar-llm::proto_stream` or `busbar-substrate::proto::
   StreamTranslator`.

2. **[HIGH] `audio_played_ms` computed wrong on the WebSocket leg — off-by-frame or
   off-by-buffer-ahead errors silently under- or over-truncate.** This is genuinely new
   plane-computed state with no existing analog to copy (design line 259-260 says so
   explicitly) and no automated way to verify without a live/simulated upstream that emits
   audio faster than realtime. Both failure directions are bad: under-counting truncates too
   early (clips audio the user hadn't heard yet, feels broken); over-counting truncates too
   late (echoes audio over the user's interruption). The `response_generation`/`seq` composite
   key (§3.3) needs a dedicated unit-test harness simulating burst-ahead emission + a
   mid-stream truncate before this ships.

3. **[MEDIUM] Two-writer-lock discipline (one per direction) is a departure from MCP's
   proven one-lock `Session<W>`, and getting it wrong deadlocks the pump.** MCP's single lock
   is safe because MCP has one logical output stream; voice's two independent physical legs
   need two locks, and if an implementer defaults to copying MCP's `Session<W>` verbatim
   (one lock for both directions), a slow/blocked write on one leg (e.g. a stalled client
   socket) can stall the other leg's writes if the locking is naively shared. Flag this in code
   review of the first pump PR — it is the kind of bug that only shows up under real full-duplex
   load, not in a happy-path smoke test.
