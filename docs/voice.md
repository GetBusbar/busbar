# Voice

Busbar fronts live, full-duplex voice and realtime sessions: the streaming plane, beside the model
plane, MCP and A2A. A caller opens a session against Busbar exactly as it reaches any other
audience-checked surface: a key at the door, then a governed open that runs the same admission gate,
the same fail-closed metering discipline and the same audit trail every other plane runs, before a
single audio frame moves. Busbar mints the ephemeral credential a browser needs, or sits between a
telephony carrier or a realtime client and the provider as a thin proxy. Either way Busbar never
becomes a second place tool definitions and instructions live: the locked session is the operator's.

The streaming plane is not code in this repository. It is a `kind: plane` plugin, built from
GetBusbar/busbar-plane-streaming, that the default build links and that can also be dropped in as a
signed plugin (see [Plugins](plugins.md)). The plane states what bytes mean and reports usage;
Busbar's core authenticates, admits, meters, prices, audits and runs every socket. This page is the
operator's reference: what `streams:` gets you, its grammar, the doors it mounts, how a session is
metered, and what the deployment must compose around it.

Cross-references: [Circuit breaker](/docs/circuit-breaker/) · [Configuration](/docs/configuration/) ·
[Observability](/docs/observability/) · [Hooks](/docs/hooks/) · [Operations](/docs/operations/).

---

## Media and control paths

<figure class="doc-diagram">
<img src="/docs/diagrams/realtime-media-control.svg" alt="Direct WebRTC audio flows between browser and provider; Busbar brokers and controls the session separately. Other transports use their configured bridge." loading="lazy" />
<figcaption><a href="/docs/diagrams/realtime-media-control.svg" download>Download SVG</a></figcaption>
</figure>

Do not assume all audio traverses Busbar in the same way on every door. The browser WebRTC door
terminates the browser's media at Busbar (which dials the provider on its own call) and exposes the
control channel as a separate sideband socket; the socket doors proxy frames both ways. Check each
door below for session mutation, usage and reconnect behaviour. Protocol or loopback tests are not
evidence of qualification against a real provider account.

## What the plane is

`streams:` is the streaming plane's one top-level section, beside `pools:` / `tools:` / `agents:`.
Unlike `tools:` and `agents:` it is not a named-definition registry: a deployment has exactly one
live-voice posture, the **locked session** every live session opens with, plus a few ceilings. The
section is read strictly: a key the plane does not model is refused at load, naming its path.

The plane speaks three caller dialects:

- **OpenAI Realtime**: a plain realtime socket, the browser's ephemeral secret, the SDP offer of a
  WebRTC call and its sideband socket.
- **Gemini Live**: a native full-duplex WebSocket proxy.
- **Twilio Media Streams**: telephony, bridged to OpenAI Realtime.

It dials the catalog model the session names. The OpenAI Realtime and Twilio doors need a provider
that speaks OpenAI Realtime; the Gemini door needs Gemini Live. When the model's provider protocol is
known, an incompatible door is refused before any dial.

### A deployment with no `public_url` fronts nothing

The plane publishes its doors against the deployment's top-level `public_url`. With none (or an
invalid one) the plane is not given a base to claim and mounts nothing. `streams:` content with no
`public_url` is a posture nothing can reach.

---

## Configuration

### The `streams:` section

| Key | Type | Default | What it is |
|---|---|---|---|
| `session` | object | the locked session defaults below | The session every live session opens with. It is the plane's flat session configuration with these keys only: `model`, `modalities`, `instructions`, `voice`, `input_audio_format`, `output_audio_format`, `turn_detection`, `tools`, `tool_choice`, `max_output_tokens`. The plane translates them into each provider's wire format. |
| `session_max_secs` | integer (seconds) | none (unlimited) | Hard wall-clock ceiling of one session. Absent means no limit. `0` is refused. |
| `context_window_tokens` | integer | `32768` | Context-window ceiling. |
| `max_output_tokens` | integer | `4096` | Per-response output ceiling. Must be **below** `context_window_tokens`; `0` is refused. |

**Locked session defaults.** When you write no `session:` (or omit `turn_detection` within it):
server-side voice-activity detection, threshold `0.5`, 300 ms prefix padding, **500 ms** silence,
`create_response: true`, `interrupt_response: true`. An explicit `turn_detection: null` disables VAD.
`modalities` is `[audio]` or `[text]` (a realtime session answers in one). Gemini Live has no
tool-choice policy field: omit `tool_choice` for a Gemini model (an explicit policy is refused rather
than silently ignored).

```yaml
public_url: https://gateway.example.com

streams:
  session:
    model: my-realtime-model        # a model in `models:` whose provider speaks the realtime dialect
    voice: marin
    instructions: You are a support agent for Acme. Be concise.
    turn_detection:
      threshold: 0.6
      prefix_padding_ms: 300
      silence_duration_ms: 400
      create_response: true
      interrupt_response: true
  session_max_secs: 1800
  context_window_tokens: 16384
  max_output_tokens: 2048
```

Caller updates cannot replace the locked instructions, tools, voice, modality, tool choice or
ceilings. Input transcription is refused by removing its configuration, because the plane does not
meter the separate transcription model. Unsupported or malformed uplink audio is dropped with a
bounded diagnostic. OpenAI response limits are clamped to the provider's supported range of 1 to 4096
tokens.

`streams:` carries no credential field. The realtime provider's key is the one your deployment already
declares for that provider: `streams.session.model` names a model, `models:` names that model's
provider, and the `providers:` entry carries the `base_url` and `api_key:` secret reference. Core
resolves it and presents it in the provider's own dialect (OpenAI Realtime: bearer; Gemini Live:
`x-goog-api-key`).

The browser's WebRTC media listener is core route configuration (`routes.<id>.media`, the `ip:port`
the browser's media arrives on), not part of `streams:`; with none configured the SDP door refuses
every offer. A settings bag from an earlier release that carried `streams.media.listen` is converted
once at load.

Like every plane section, `streams:` accepts the reserved core-owned keys (`hooks`, `rate_card`,
`fees`): see [Reserved names](configuration.md#reserved-names). Its billable classes are
`audio_tokens_in`, `audio_tokens_out`, `text_tokens_in`, `text_tokens_out`, `audio_seconds_in`,
`tool_calls`, `image_tokens_in`, `video_tokens_in` and a per-session count (`session`).

---

## Authentication and identity

Every door requires a key from the same key chain every other plane uses; a token minted for a
different resource is refused before any hook, lease or dial runs. The SDP door additionally accepts
the short-lived ticket the mint door issued. The telephony door's credential is the carrier's request
signature (below).

A key may be narrowed with `allowed_scopes`. The mint asks core whether the presenting key is
granted the session's model (a `pool:<model>` grant); a key that is not is refused (`403` on the mint) before any
lease or dial. As on every plane, a key with no `allowed_scopes` list at all is the wildcard.

### Twilio request signatures and replay

Twilio holds no Busbar key, so a request from Twilio (the Media Streams WebSocket upgrade, or a
signed webhook) is authenticated by its `X-Twilio-Signature` header instead. The plane names that
header on the telephony door, and core runs the auth instances configured for that route that read
it: an HMAC-SHA1, keyed by your Twilio auth token, over the URL Twilio requested plus the sorted form
parameters of a signed POST. A missing, wrong or re-targeted signature is refused before the request
reaches the plane. Which auth plugin verifies it, and how it is configured, is that plugin's own
documentation.

**A Twilio signature carries no replay protection.** It covers the URL and parameters only. It has no
timestamp and no one-time value, so the same signed request stays valid for as long as the auth token
does. Anyone who captures one (the upgrade URL with its header, or a webhook body with its header)
can send it again, and it verifies again. Busbar does not deduplicate Twilio requests: it does not
refuse a second request with the same `CallSid` or `MessageSid`. A replayed connection is a new
session of its own, and it is admitted and billed as one.

What an operator can do about it:

- **Keep requests from being captured.** Serve the Twilio routes over TLS only (`wss://` and
  `https://` in the TwiML and the console), and never log the signature header or full request URLs
  where others can read them.
- **Allow-list at the network edge.** Where Twilio publishes the egress ranges for the product you
  use, admit only those sources on the Twilio routes, in your firewall or load balancer.
- **Deduplicate on the call or message id.** If a replayed call or message would cost you money or
  cause harm, reject a repeated `CallSid` / `MessageSid` in front of Busbar or in the application
  Twilio calls. Busbar does not do this for you.
- **Rotate the auth token** if you think a signed request was exposed. Every signature made with the
  old token stops verifying.

---

## The doors

Six doors, all behind the same audience and key check. The four socket doors are WebSocket upgrades.

| Route | Method | What it does |
|---|---|---|
| `/v1/realtime/client_secrets` | POST | Mints the browser's short-lived `ek_` ticket (valid 600 seconds), so the long-lived provider key never reaches a browser. |
| `/v1/realtime/calls` | POST | Takes the browser's SDP offer (a key or the minted ticket) and answers it; Busbar terminates the media and places its own call to the provider. Calls are tracked per caller, and a full table refuses new calls (`429`) rather than evicting live ones. |
| `/v1/realtime/sideband/{call_id}` | GET (upgrade) | The browser session's control socket. It attaches only to a call the same caller's offer placed (otherwise `404`), inherits that call's lock and does not bill mirrored provider usage again. |
| `/v1/realtime` | GET (upgrade) | Plain server-to-server OpenAI Realtime over a socket. |
| `/v1/realtime/gemini/{call_id}` | GET (upgrade) | Gemini Live: a native full-duplex proxy, client socket on one side, the provider's on the other, Busbar metering and governing in the middle. Gemini has no mint or SDP concept, so it gains one route. |
| `/twilio/{call_id}` | GET (upgrade) | Twilio Media Streams telephony, bridged to OpenAI Realtime. The session is locked to 8 kHz G.711 µ-law both ways, so audio passes straight through with no resample. |

**Browser sideband.** Because the browser's media terminates at Busbar, the sideband carries control
and mirrored events; audio injected directly on the sideband still contributes ingress seconds. A
sideband exposes no new session parameters and cannot rewrite the existing call; ownership is checked
when attaching.

### Every door runs the governed open

Before any provider is dialed or any ticket minted, core runs the plane's stated intent through the
same sequence every plane uses: the operator's hook gate and tap (attached to the `streams` section
through `streams.hooks`), then admission and a metering lease, then the dial. A reject at any step
refuses the request with nothing leased and no live session left behind. A session retains the
configuration it was admitted under across refreshes.

---

## Governance and billing

**Voice has no meter and no budget of its own.** Every turn's usage is reported to core and landed on
the one ledger the other planes use, attributed to the presenting virtual key, so a voice session's
spend appears on the key's usage and the admin usage series exactly like a model call. Each class is
priced against the plane's `streams.rate_card`; a class with no rate is unpriced rather than free
(see [per-plane rate cards](configuration.md#per-plane-rate-cards-toolsrate_card-agentsrate_card-streamsrate_card-decisionsrate_card)).

The session's ceiling is the tightest remaining budget across the key's own bucket and every ancestor
group. A caller with nothing capped opens an uncapped session; a caller whose tightest bucket is
already spent is denied at the reserve; a caller with budget opens, and its session is hard-closed
when its usage reaches that remaining amount. `session_max_secs` additionally closes a session at a
wall-clock ceiling.

---

## Observability

The plane's front door counts on the shared per-plane request family
(`busbar_plane_requests_total` / `busbar_plane_request_duration_seconds`) with `plane="streaming"`.
The outbound provider dial counts on the shared `busbar_upstream_attempts_total` /
`busbar_upstream_failures_total` families and runs under the same circuit breaker as every other
plane's egress. See [Observability](/docs/observability/) for the shared metric families.

The plane contributes no diagnostic codes of its own: it raises only core-owned codes.

---

## Conformance

The streaming plane's tests, and the audio conformance cases of the model plane, live in their own
repositories and run in their own CI. A loopback conformance result is distinct from a real-provider
smoke result. If you are evaluating this plane for a production workload, qualify the dialect,
transport, provider, credential mode and usage accounting together against the release candidate:
the transport's ability to frame or authenticate a connection does not by itself establish provider
interoperability.
