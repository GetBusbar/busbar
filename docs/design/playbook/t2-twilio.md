# T2 playbook — Twilio Media Streams (g711) telephony topology for `busbar-voice`

Status: **DESIGN (not build).** Read-only against the tree; `crates/…:NNN` citations are against
`integration/plane-extraction`. Scope: the *concrete* Twilio wire adapter over the existing generic
telephony topology (`crates/busbar-voice/src/topology/telephony.rs`) — everything from the inbound
Twilio webhook through Media Streams WS frames to the already-governed `g711_ulaw` session core.
Gated on the crate's `runtime` feature exactly as the rest of T2 is
(`crates/busbar-voice/Cargo.toml:79-87`, "THE VOICE SESSION RUNTIME — the T2 live duplex engine …
OFF by default").

**Naming note (per `docs/design/plane4-duplex-session-1.6.0-plan.md:20-25`):** T1 is the substrate
*capability* — duplex transport, per-frame governance lease, session/handle engine — lifted into
`busbar-substrate`/`busbar-plugin` and shared by every plane. T2 is the first *consuming plugin*,
`busbar-voice`, that exercises those seams. This doc designs one concrete carrier
(Twilio Media Streams) riding T2's already-built generic telephony topology, which itself rides T1
unchanged. Nothing here proposes a T1 change.

---

## 0. TL;DR

- **Codec choice (memory, restated as the binding decision):** `g711_ulaw` end-to-end. Twilio Media
  Streams *is* 8 kHz µ-law already (`μ`-law, base64-framed) — matching the Realtime session's
  negotiated `input_audio_format`/`output_audio_format` to `g711_ulaw` means the Twilio frame's
  decoded payload is byte-identical to what the upstream Realtime session wants and emits. Zero
  resample, zero CPU, zero fidelity loss on the telephony leg.
- **The bridge is a thin WS proxy, already built generically.** `TelephonyProxy::run`
  (`crates/busbar-voice/src/topology/telephony.rs:129-191`) is transport-agnostic: it takes four
  `Stream`/`Sink<Vec<u8>>` halves and knows nothing about Twilio, SIP, or any other telephony
  carrier. **The net-new work is entirely the Twilio *envelope* adapter** — translating Twilio's
  JSON `{event, media:{payload}}` Media Streams protocol to/from the raw µ-law
  `Vec<u8>` frames `TelephonyProxy::run`'s `client_in`/`client_out` expect — plus the inbound
  webhook (TwiML) that starts the call and the `wss://` upgrade Twilio dials into.
- **Reuse is total on the governance/session side, net-new is confined to one envelope module.**
  Everything from `client_in`/`client_out` inward — the codec, `SessionCore`, the D2 lease, the
  durable `SessionScope`, the provider dial — is unchanged T2 machinery. See §4 for the exact seam
  map.

---

## 1. The Twilio Media Streams WS topology — concrete design

### 1.1 Inbound webhook (TwiML) — the call-setup leg

Twilio's voice flow starts as an **HTTP** webhook, not a WS: a call lands on a Twilio number,
Twilio `POST`s the configured voice webhook URL, and busbar's TwiML response tells Twilio to open a
Media Streams WS back to busbar. This is a **normal, one-shot HTTP gauntlet pass** — the same shape
as the browser topology's ephemeral-token mint (`docs/design/plane4-duplex-session.md:576-578`,
"Mint the ephemeral `client_secret` — a JSON `POST` … a normal gauntlet pass"), not a duplex
arrival. Concretely:

```
Twilio ──POST (call metadata: CallSid, From, To, …)──▶ busbar webhook route
                                                            │ run_gauntlet (identity, destination
                                                            │ verify — "may this number originate a
                                                            │ governed voice session")
                                                            ▼
Twilio ◀── TwiML <Response><Connect><Stream url="wss://…/twilio/{call_id}"/></Connect></Response> ──
```

- The TwiML response is a **static XML template** the plane renders with one variable (the WS URL,
  keyed by a `call_id` the plane mints at this pass) — it carries no audio and no provider secret.
  This is new code but it is *not* duplex: it is exactly the `Invoke`-shaped one-shot pass the design
  doc already establishes for token minting, so it needs no new gauntlet primitive.
- **Where the session's `owner`/`call_id` come from.** `begin_telephony` takes `owner` and
  `call_id` as plain `impl Into<String>` (`crates/busbar-voice/src/topology/telephony.rs:69-70`);
  the Twilio adapter's webhook handler is the one place that decides what those are (e.g. `owner` =
  the account/number config the operator scoped to that Twilio number; `call_id` = Twilio's
  `CallSid` or a plane-minted id embedded in the `Stream` URL). Nothing in `telephony.rs` cares which
  telephony carrier supplied them.
- **Locked config is decided here, not at the WS.** The webhook handler is where `g711_config()`
  (`crates/busbar-voice/src/topology/telephony.rs:34-41`) gets built and overlaid with the operator's
  instructions/tools (per the doc comment: *"Callers overlay their own instructions/tools onto the
  returned config before locking it"*) — the config is fixed **before** the WS even opens, so a
  malicious or buggy Twilio payload on the WS can never smuggle a different audio format or tool set
  in. This is the same "locked config, client update is a hint" invariant `SessionCore::on_client_frame`
  enforces per-frame (`crates/busbar-voice/src/runtime/session.rs:263-271`), just applied one layer
  earlier for the *format* choice specifically, since format is fixed at `begin_telephony` and not
  reconciled per-frame.

### 1.2 The WS media-frame leg — Twilio's envelope, decoded to raw bytes

Once Twilio dials `wss://…/twilio/{call_id}`, it speaks a **JSON-over-WS envelope** distinct from
both OpenAI Realtime's JSON events and from raw bytes:

```json
// Twilio → busbar, per ~20ms frame:
{"event":"media","sequenceNumber":"3","media":{"track":"inbound","chunk":"3","timestamp":"20","payload":"<base64 µ-law bytes>"},"streamSid":"MZ..."}

// busbar → Twilio, to play audio back:
{"event":"media","streamSid":"MZ...","media":{"payload":"<base64 µ-law bytes>"}}
```

plus lifecycle events with no `telephony.rs` analog: `connected` (once, first frame), `start`
(carries `streamSid`, `callSid`, negotiated `mediaFormat` — the plane should assert this echoes
`g711_ulaw`/8000Hz as a defense-in-depth check, not trust the webhook's own config silently), `mark`
(playback-position acks the plane can use to corroborate its own barge-in bookkeeping), `stop`
(terminal).

**This is the entire net-new surface** (§3): a small stateless codec —
`TwilioEnvelope::decode(ws_frame) -> Option<TwilioEvent>` /
`TwilioEnvelope::encode_media(streamSid, bytes) -> ws_frame` — that:

- On `media` events: base64-decodes `media.payload` to raw µ-law bytes and yields them as the
  `client_in: Stream<Item = Vec<u8>>` `TelephonyProxy::run` consumes
  (`crates/busbar-voice/src/topology/telephony.rs:129-141`, the `DIn` parameter).
- On outbound audio from the session core: base64-encodes the raw µ-law bytes (which are *already*
  the exact wire bytes the codec's `write_down` produced for an `AudioFrame` — see §2) into the
  Twilio `media` JSON envelope and writes it as the `client_out: Sink<Vec<u8>>` half (the `DOut`
  parameter).
- On `start`/`stop`/`mark`: these do **not** flow into `TelephonyProxy::run`'s stream — they are
  telephony-lifecycle, not voice-session content. The adapter task terminates the WS (and thus
  `client_in`) on `stop`; `mark` acks are consumed by the adapter for diagnostics/logging only (the
  session core's own `DecodeState::flush_playback` — `crates/busbar-voice/src/runtime/session.rs:152`
  — is the authoritative barge-in clock; Twilio's `mark` is a corroborating signal, never load-bearing).

### 1.3 The thin-proxy bridge — already built, Twilio-neutral

`TelephonyProxy::run` (`crates/busbar-voice/src/topology/telephony.rs:129-191`) is the bridge. It
is generic over four `Stream`/`Sink<Vec<u8>>` halves and already implements:

- **Provider leg** dialed through the net-guarded neutral WS transport
  (`crate::topology::dial_provider`, `crates/busbar-voice/src/topology/mod.rs:49-65`, which selects
  `Transport::WebSocket` and resolves-then-pins-then-guards the upstream `wss://`) — unchanged for
  Twilio; the provider is still OpenAI Realtime (or Gemini Live later), never Twilio.
- **Client leg** (`client_in`/`client_out`) — for Twilio, this is exactly the WS pair Twilio's
  Media Streams connection gives busbar, *after* the envelope adapter of §1.2 strips/adds the JSON
  wrapper. The adapter sits **between** the raw Twilio WS socket and `TelephonyProxy::run`'s
  `client_in`/`client_out` parameters — it is not a new topology, it is a new *pair of
  `Stream`/`Sink<Vec<u8>>` adapters* handed to the existing `run`.
- **The four-direction wiring, the funnels, the hard-close race** — all unchanged
  (`telephony.rs:143-190`): the provider-write funnel (`upstream_tx`/`upstream_rx`), the
  downlink funnel (`downlink_tx`/`downlink_rx` via `Carrier::with_downlink`,
  `crates/busbar-voice/src/runtime/carrier.rs:40-48`), the `carrier.closed()` race against both
  serves in the `tokio::select!` (`telephony.rs:179-182`), and the drain-then-await teardown
  (`telephony.rs:184-189`).

The concrete Twilio-specific composition, in full:

```
Twilio PSTN call
   │ (Twilio's own SIP/RTP→PCMU leg, opaque to busbar)
   ▼
Twilio Media Streams WS  ──(raw WS frames, Twilio JSON envelope)──▶  Twilio envelope adapter (NEW, §1.2)
                                                                          │ decode: JSON→raw µ-law Vec<u8>
                                                                          │ encode: raw µ-law Vec<u8>→JSON
                                                                          ▼
                                                             client_in / client_out
                                                                          │
                                                                 TelephonyProxy::run  (UNCHANGED,
                                                                 telephony.rs:129-191)
                                                                          │
                                                          provider_in / provider_out
                                                                          │
                                                    dial_provider (UNCHANGED, topology/mod.rs:49-65)
                                                                          │
                                                                          ▼
                                                          OpenAI Realtime `wss://…/v1/realtime`
                                                          (g711_ulaw negotiated both directions)
```

---

## 2. g711_ulaw passthrough vs the browser 24 kHz path — where they diverge, where they share the seam

### 2.1 Where they diverge

| | Telephony (T2 Twilio) | Browser (Topology A / WebRTC) |
|---|---|---|
| Negotiated format | `AudioFormat::G711Ulaw` both directions (`crates/busbar-voice/src/topology/telephony.rs:31-41`, `g711_config()`) | `pcm16` @ 24 kHz (the Realtime default, no format override — `crates/busbar-voice/src/ir/media.rs:34-35`) |
| Who relays media | busbar (`TelephonyProxy` — `client_in`/`client_out` carry real audio bytes) | **nobody** — the sideband `Carrier::sideband()` relays no downlink audio at all (`crates/busbar-voice/src/runtime/carrier.rs:52-61`, `send_downlink` returns `false` unconditionally when `downlink: None`); media is browser↔provider peer-to-peer via WebRTC |
| `bytes_per_ms` (barge-in truncate arithmetic) | 8 (`AudioFormat::G711Ulaw`, `crates/busbar-voice/src/ir/media.rs:66-70`) | 48 (`AudioFormat::Pcm16`) — but moot: WebRTC truncates automatically upstream, so this topology's `Carrier` never runs the byte-accounting path server-side |
| Envelope on the client leg | Twilio's own JSON (base64 `media.payload`) — **net-new** decode/encode (§1.2) | none — the client leg is the sideband control WSS only (OpenAI Realtime JSON events, same codec as the provider leg); no client-audio envelope exists because there is no client audio path through busbar |
| Resample | **none** — µ-law in, µ-law out, matching the upstream negotiation exactly | **none** — pcm16@24k in, pcm16@24k out; the *browser's* mic/speaker resampling is the browser's own business, off-box |
| Who dials the provider | `TelephonyProxy::run`'s `provider_in`/`provider_out` via `dial_provider` (same fn) | `Attached::session` served over the same `dial_provider` → `serve_messages` pump (`crates/busbar-voice/src/topology/webrtc.rs:84-87`) |

The one substantive divergence beyond the format itself: **Topology A relays zero audio bytes**
(it is mint + sideband control only), so its `Carrier` is fundamentally a control-only carrier;
Topology B's `TelephonyProxy` relays every audio byte both ways and its `Carrier` is a genuine media
relay (`Carrier::with_downlink`). The Twilio envelope work in §1.2 has **no counterpart** in
Topology A for exactly this reason — there is no client audio leg to wrap.

### 2.2 Where they share the seam

- **Same codec trait bound, same `SessionCore`.** Both topologies are generic over
  `C: DuplexReader + DuplexWriter` (`crates/busbar-voice/src/topology/telephony.rs:76`,
  `crates/busbar-voice/src/topology/webrtc.rs:110`) and both build a `SessionCore<C>` through the
  same `begin_session` (`crates/busbar-voice/src/topology/mod.rs:106-136`) — the tool-call
  correlation, barge-in truncate math, and metering-settle logic in
  `SessionCore::on_server_frame`/`on_client_frame`
  (`crates/busbar-voice/src/runtime/session.rs:120-280`) run byte-for-byte identically regardless of
  which topology is driving it. Twilio buys none of this; it inherits all of it.
- **Same provider dial, same net-guard.** `dial_provider` (`crates/busbar-voice/src/topology/mod.rs:49-65`)
  is the one door either topology uses to reach the upstream — Twilio does not get its own dialer.
- **Same pump primitive on the client leg's *shape*, different envelope on its *bytes*.**
  `serve_messages` (`crates/busbar-substrate/src/ingress/byte_duplex.rs:318`) is what both the
  provider leg and (for telephony) the client leg run through
  (`telephony.rs:173-174`, `up_serve`/`down_serve`); it is one-message-per-frame framing
  (`byte_duplex.rs:193-198`, `MessageSink`), agnostic to what's inside the `Vec<u8>`. The Twilio
  envelope adapter's job is entirely upstream of this call — it produces the `Vec<u8>` `client_in`
  stream `serve_messages` pumps, it does not change how the pump frames messages.
- **The identity-IR media tap (`plane4-duplex-session.md` §2.1/§2.4) is the same tap in both
  topologies where it runs at all** — `IrAudioFrame` (`crates/busbar-voice/src/ir/media.rs:99-107`)
  carries opaque bytes for the meter/audit side-channel; Twilio's µ-law bytes and the browser's
  (never-seen-by-busbar) pcm16 bytes are both instances of the same identity-transform doctrine, one
  of which (telephony) busbar actually touches and one of which (browser) it structurally cannot.

---

## 3. Stub vs net-new

**Already built (stub → shipped, reused verbatim):**

- `g711_config()` — the locked `AudioFormat::G711Ulaw`/`G711Ulaw` session config
  (`crates/busbar-voice/src/topology/telephony.rs:34-41`).
- `TelephonyProxy` / `begin_telephony` / `TelephonyProxy::run` — the whole generic thin-proxy bridge,
  funnels, hard-close race, teardown (`crates/busbar-voice/src/topology/telephony.rs:46-191`).
- `SessionCore`, `Carrier::with_downlink`, `VoiceSession`, `UplinkForwarder` — the governed
  session engine, tool-call moat, barge-in truncate, D2 metering settle
  (`crates/busbar-voice/src/runtime/session.rs`, `crates/busbar-voice/src/runtime/carrier.rs`).
- `dial_provider`, `begin_session`, `SessionBudget`, `StartError` — the provider dial and D2
  lease/durable-open sequencing common to both topologies (`crates/busbar-voice/src/topology/mod.rs`).
- `AudioFormat::G711Ulaw` + `bytes_per_ms`/`bytes_to_ms` — the barge-in arithmetic for the 8 kHz
  carrier (`crates/busbar-voice/src/ir/media.rs:36-38, 66-70`).
- `serve_messages` / `DuplexPlane` / `MessageSink` — the neutral T1 byte-duplex pump the client leg
  rides (`crates/busbar-substrate/src/ingress/byte_duplex.rs:81-92, 193-224, 318`).
- `dial_provider`'s net-guarded egress WS dialer (`crates/busbar-substrate/src/egress/duplex_ws.rs:142`,
  `Transport::WebSocket` → `UpstreamWireKind::Duplex`, `crates/busbar-substrate/src/transport.rs:154,167,252`).

**Net-new for T2-Twilio specifically (none of it exists in the tree today — verified: no `twilio`
hit anywhere in `crates/busbar-voice` or `docs/design`):**

1. **The Twilio envelope codec** (§1.2) — `decode`/`encode` between Twilio's JSON Media Streams
   protocol (`connected`/`start`/`media`/`mark`/`stop` events, base64 `media.payload`) and the raw
   `Vec<u8>` `client_in`/`client_out` halves `TelephonyProxy::run` already expects. This is a small,
   self-contained module — closer in shape to `crate::ir::codec`'s JSON-event hand-mapping than to
   anything transport-level.
2. **The inbound webhook (TwiML) HTTP route** (§1.1) — receives the Twilio call-setup `POST`, runs
   the one-shot admission gauntlet pass, mints `call_id`/`owner`, builds the locked `g711_config()`
   overlay, and renders the `<Connect><Stream url="…"/></Connect>` TwiML pointing back at the WS
   route. New route, new (thin) handler; no new gauntlet primitive.
3. **The WS accept route for `wss://…/twilio/{call_id}`** — the ingress side that upgrades Twilio's
   incoming WS, looks up the `call_id`'s prepared config (from step 2), and hands the socket's
   message stream/sink to the envelope adapter of item 1, then into `begin_telephony` +
   `TelephonyProxy::run`. This is wiring, not new engine logic — it is the same WS-arrival shape the
   design doc already specifies generically
   (`docs/design/plane4-duplex-session.md:461-477`, §4.2), applied to the one concrete carrier.
4. **Defense-in-depth format assertion on `start`** — checking Twilio's `start.mediaFormat` echoes
   the `g711_ulaw`/8000Hz the webhook locked, refusing (not silently reformatting) on mismatch. Small,
   new, and narrow.

**Not needed for Twilio (unlike the browser topology):** no ephemeral-token mint, no SDP broker, no
`TokenMinter` trait implementation — Twilio never touches the provider's credentials or SDP; busbar
holds the only connection to the provider, exactly as `TelephonyProxy` already assumes.

---

## 4. Reuse of T1 seams (transport-WS, pump, media, session, lease)

| T1 seam | Where it's defined | How Twilio T2 rides it |
|---|---|---|
| **Transport-WS** (the neutral egress dialer) | `Transport::WebSocket` → `UpstreamWireKind::Duplex` (`crates/busbar-substrate/src/transport.rs:154,167,252`); dialed via `busbar_substrate::egress::duplex_ws::dial` (`crates/busbar-substrate/src/egress/duplex_ws.rs:142`), wrapped by `dial_provider` (`crates/busbar-voice/src/topology/mod.rs:49-65`) | Unchanged — the Twilio topology's *provider* leg is dialed exactly as the browser topology's is. Twilio itself is never dialed by busbar (Twilio dials *in*); the Twilio-side WS is an **ingress** accept, not this egress primitive. |
| **Pump** | `serve_messages` (`crates/busbar-substrate/src/ingress/byte_duplex.rs:318`) over `DuplexPlane`/`MessageSink` (`byte_duplex.rs:81-92,193-224`) | Both the provider leg (`up_serve`) and the client leg (`down_serve`) run through it (`telephony.rs:173-174`); the client leg's `Vec<u8>` payload is post-envelope-decode raw µ-law, produced by the net-new adapter (§3.1) upstream of the pump call, so the pump itself needs no Twilio awareness. |
| **Media (identity IR / audio-frame layer)** | `IrAudioFrame`, `AudioFormat`, `truncate_point_ms` (`crates/busbar-voice/src/ir/media.rs:33-95`) | Unchanged — `AudioFormat::G711Ulaw`'s `bytes_per_ms = 8` (`media.rs:69`) is exactly the constant the barge-in truncate math needs for an 8 kHz carrier, already correct for Twilio's PCMU without any Twilio-specific branch. |
| **Session** (governed core + durable scope) | `SessionCore` (`crates/busbar-voice/src/runtime/session.rs:69-280`); `SessionHandle`/`VoiceSessionRow` durable binding (`crates/busbar-voice/src/runtime/scope.rs`) | Unchanged — `begin_telephony` calls the same `begin_session` (`topology/mod.rs:106-136`) every topology calls; the durable row is keyed `(owner, call_id)` regardless of which carrier supplied those strings (§1.1 decides *what* they are for Twilio, not *how* they're stored). |
| **Lease** (D2 metering) | `MeteringLease`/`Pricing` (`crates/busbar-voice/src/runtime/metering.rs`), reserved at `begin_session` (`topology/mod.rs:119-122`, fail-closed on refusal), settled per-frame in `on_server_frame` (`runtime/session.rs:137-149`) | Unchanged — the lease neither knows nor cares that the carrier is a phone call; `SessionBudget`'s `estimate_nanos`/`fee_nanos`/`cap_nanos` (`topology/mod.rs:71-79`) are set by the webhook handler (§1.1) exactly as `begin_telephony`'s caller sets them for any other carrier. |

**Bottom line:** the only seam Twilio T2 does *not* reuse unchanged is the client-leg **envelope** —
because Twilio, unlike the browser sideband (no client audio) and unlike a hypothetical raw-WS
telephony client (no envelope at all), wraps its audio in its own JSON protocol. Every other seam —
transport-WS, pump, media, session, lease — is exactly the seam the browser topology and the generic
telephony topology already prove.

---

## 5. Residual risks

1. **The envelope adapter is a new trust boundary that decodes attacker-reachable JSON before any
   session-level governance runs.** Twilio's Media Streams WS is reachable by anyone who can guess
   or intercept the `wss://…/twilio/{call_id}` URL (the `call_id` is the only secret in the path);
   the adapter's `decode` must validate `streamSid`/`callSid` against the value minted at the webhook
   step (§1.1) *before* handing bytes into `client_in`, or a replayed/forged WS connection could
   inject audio into an already-open session, or open a session against a `call_id` it does not own.
   `TelephonyProxy`/`SessionCore` do not themselves authenticate the caller — that responsibility
   sits entirely in the new adapter/route, which is exactly the part of this design with no shipped
   precedent to lean on.
2. **`start.mediaFormat` mismatch is a fail-open risk if the defense-in-depth check (§3, item 4) is
   skipped or implemented as a log-only warning.** If Twilio (via a misconfigured `<Stream>` TwiML
   attribute or a future Twilio default change) ever negotiates something other than `audio/x-mulaw`
   8000Hz, the raw bytes handed to `client_in` would silently be the wrong format, and
   `AudioFormat::G711Ulaw`'s `bytes_per_ms = 8` (`ir/media.rs:69`) would make the barge-in truncate
   arithmetic *wrong without erroring* — a subtle, hard-to-detect audio-desync bug rather than a
   crash. This must refuse the session outright, not warn.
3. **Backpressure/ordering between Twilio's `mark` acks and busbar's own playback-position
   bookkeeping is unspecified.** `DecodeState::flush_playback` (`crates/busbar-voice/src/runtime/session.rs:152`)
   is described as authoritative and Twilio's `mark` events are framed here (§1.2) as merely
   corroborating — but if Twilio's actual playout buffer runs meaningfully ahead of or behind
   busbar's byte-count model (e.g. Twilio buffers a few hundred ms client-side before playing), the
   barge-in truncate point computed server-side could diverge from what the caller actually heard.
   This needs empirical verification against a real Twilio `<Stream>` leg, not just protocol
   inspection — the design doc's own barge-in section already flags this class of risk for the
   generic WebSocket case (`docs/design/plane4-duplex-session.md:254-260`), and Twilio's carrier-side
   buffering is an additional, telephony-specific instance of it.

---

## Summary

Twilio Media Streams (g711) telephony rides the **already-built** T2 generic telephony topology
(`crates/busbar-voice/src/topology/telephony.rs`) unchanged from `client_in`/`client_out` inward:
same `SessionCore`, same D2 lease, same durable `SessionScope`, same net-guarded provider dial, same
`serve_messages` pump. `g711_ulaw` is locked end-to-end (`g711_config()`,
`crates/busbar-voice/src/topology/telephony.rs:34-41`) so Twilio's 8 kHz µ-law frames pass straight
through to the Realtime upstream with zero resample — the only place this diverges from the browser
24 kHz WebRTC topology is that Twilio relays real audio bytes through busbar at all (the browser
sideband relays none). The genuinely net-new work is narrow and confined to the client edge: (1) a
Twilio JSON-envelope codec (`media`/`start`/`stop`/`mark` ↔ raw µ-law `Vec<u8>`), (2) the inbound
TwiML webhook that starts the call as a one-shot gauntlet pass and locks the config before the WS
even opens, and (3) the WS-accept route that upgrades Twilio's connection and threads it through the
envelope adapter into the existing `begin_telephony`/`TelephonyProxy::run`.

Top risks: the envelope adapter is a new pre-governance trust boundary that must validate
`call_id`/`streamSid` before admitting bytes; a silent `mediaFormat` mismatch would corrupt the
barge-in truncate math without erroring; and Twilio-side playout buffering may desync the
server-computed truncate point from what the caller actually heard, which needs empirical
verification against a live Twilio leg.

File: `docs/design/playbook/t2-twilio.md`
