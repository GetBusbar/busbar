# Voice

Busbar fronts live, full-duplex voice sessions — the fourth plane, beside the model plane, MCP and
A2A. A caller opens a session against Busbar exactly as it reaches any other audience-checked
surface: an audience-bound key at the door, then a governed open that runs the same admission gate,
the same fail-closed metering discipline and the same audit trail every other plane runs, before a
single audio frame moves. Busbar mints the ephemeral credential a browser needs to talk to the
realtime provider directly, or sits between a telephony carrier and that provider as a thin proxy —
either way Busbar never becomes a second place tool definitions and instructions live, and a session
that cannot afford to keep running is hard-closed, not left to run unmetered.

This page is the operator's reference for the plane as it exists in this build: what turning on
`streams:` gets you, the complete configuration grammar, how identity is established, the
topologies and the routes they mount, how a live session is metered, what it emits, and — because
this is a young plane — exactly where the wiring stops today and what a deployment has to compose
itself to go further.

Cross-references: [Circuit breaker](/docs/circuit-breaker/) (the one FSM, now including the
provider dial) · [Configuration](/docs/configuration/) · [Observability](/docs/observability/) ·
[Hooks](/docs/hooks/) · [Operations](/docs/operations/).

---

## What the plane is

The `streams:` section is the fourth top-level plane noun, beside `pools:` / `tools:` / `agents:`.
Writing a `streams:` block — or even leaving it absent — declares the voice plane's one posture:
unlike `tools:`/`agents:`, this is not a named-definition registry, because a deployment has exactly
one live-voice posture rather than a set of registrations
(`crates/busbar-voice/src/config.rs:1-27`). Its declaring section is `streams:`; the plane's own
registry key is `voice` (config_section ≠ registry key, exactly as MCP's key is `mcp` while its
declaring section is `tools:`).

Busbar's own two dialects are OpenAI Realtime and Gemini Live, sharing one cross-dialect IR the way
MCP and A2A share theirs — earned at the plane's *second* wire format, the same rule those planes
apply (`crates/busbar-voice/src/lib.rs:148-160`). **Both wire formats are mounted.** OpenAI Realtime
serves the `ek_` mint, the SDP broker, the browser-sideband WS accept and the telephony WS accept
(all under `/v1/realtime`); Gemini Live serves its own WS accept, a thin duplex proxy in the same
shape as telephony (client WS ↔ Busbar ↔ provider WS), under `/v1/realtime/gemini`
(`crates/busbar-voice/src/mount.rs`, `voice_claims` / `voice_ws_arrivals`). Gemini Live has no
ephemeral-mint or SDP-broker concept of its own — it is a native full-duplex socket on both legs — so
it gains one route, not a mint/SDP pair.

**Voice ships default-on.** `plane-voice` is in the `busbar` binary's default feature set, the same
posture as `plane-mcp` / `plane-a2a` — a shipped build installs the plane, claims its `streams:`
section, and mounts its routes without any build flag (`crates/busbar/Cargo.toml:78`,
`crates/busbar/src/main.rs:687-693`). It is also strong-form deletable: `git rm -r
crates/busbar-voice` leaves the rest of the workspace compiling
(`crates/busbar-voice/src/lib.rs:14-19`).

### A deployment with no `public_url` fronts nothing

Voice is receiving-only — there is no delegating side to keep alive the way A2A's `agents:` can run
with no `public_url`. `PLANE_DECL.build` reads the deployment's top-level `public_url`; with none, it
returns no dispatch slot at all, so the plane claims no path, binds no audience, and mounts no route
(`crates/busbar-voice/src/mount.rs:227-240`). `streams:` with content but no `public_url` is a
deployment that has written a posture nothing can reach.

### A `streams:` block naming a plane this build does not carry refuses to boot

Because `streams:` is not in `NamedMapSection`'s mirror, it is checked in its own right at
`config::resolve`: a present `streams:` block with no registered voice plane (a build compiled with
voice off) is refused by name, naming the section
(`crates/busbar-core/src/config/mod.rs:5040-5053`). With voice compiled in — the shipped default —
this never fires.

---

## Configuration

### The `streams:` section

`deny_unknown_fields`: a typo'd key fails boot (`crates/busbar-voice/src/config.rs:68`).

| Key | Type | Required | Default | What it is |
|---|---|---|---|---|
| `session` | object | no | the locked session defaults below | The session posture every session opens with: model, modalities, instructions, voice, input/output audio format, `turn_detection` (VAD), the tool set, tool-choice policy, and the per-response output-token ceiling. Its shape **is** the GA `session` wire object (`SessionConfig`) — there is no second, plane-private copy of the VAD/media grammar to drift from the wire one. |
| `session_max_secs` | u32 | no | `3600` (60 min) | Hard session wall-clock ceiling. |
| `context_window_tokens` | u32 | no | `32768` | Context-window ceiling. |
| `max_output_tokens` | u32 | no | `4096` | Per-response output-token ceiling. |

An absent `streams:` block decodes byte-identically to `StreamsCfg::default()`
(`crates/busbar-voice/src/config.rs:176-181`), so a deployment that writes nothing still gets this
posture the moment the plane is compiled in and `public_url` is set.

**The locked `session` defaults**, when the operator writes no `session:` (or omits
`turn_detection` within it): server-side voice-activity detection, threshold `0.5`, 300 ms prefix
padding, **500 ms** silence duration, `create_response: true`, `interrupt_response: true`
(`crates/busbar-voice/src/config.rs:46-63`). That 500 ms is a **plane posture**, chosen here and kept
distinct from the wire codec's own bare-decode default of 200 ms
(`crates/busbar-voice/src/ir/control.rs`, referenced in `config.rs:46-51`) — a raw `session.update`
round-trip through the codec is unaffected by the plane's own opinion about what an operator who
writes nothing should get.

```yaml
public_url: https://gateway.example.com

streams:
  session:
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

`streams:` carries no secret reference of any kind — there is no credential field in this grammar at
all (`crates/busbar-voice/src/config.rs:105-113`), and it does not need one. The realtime provider's
API key is the one your deployment already declares for that provider: `streams.session.model` names
a model, `models:` names that model's provider, and that `providers:` entry carries the `base_url`
and the `api_key:` secret reference — the same catalog and the same secret resolver every model lane's
credential comes from. At boot the composition root reads that entry and hands the plane the origin
plus the reference, and the plane resolves it through the deployment's resolver
(`crates/busbar/src/main.rs`, `crates/busbar-voice/src/mount.rs`). Pin no `streams.session.model` — or
name a model with no provider entry — and no provider is composed, which is the state described in
[What is structural and what is live](#what-is-structural-and-what-is-live) below.

### Boot refusals: the `streams:` section

| Refusal | Condition |
|---|---|
| an unknown key under `streams:` | `deny_unknown_fields` |
| `streams:` is configured but this build was compiled without the voice plane | `crates/busbar-core/src/config/mod.rs:5040-5053` |

There is no equivalent of MCP's empty-`auth.chain` boot refusal on this plane, and no `config_validate`
hook declared at all (`crates/busbar-voice/src/lib.rs:242`). Nothing here stops a deployment from
running `streams:` with an open `auth.chain` — configure your chain before turning the plane on.

---

## Authentication and identity

### The audience

The RFC 8707 resource indicator is **`<public_url>/v1/realtime`**, one reading of `public_url`
exactly as A2A derives `<public_url>/a2a` — so the audience a caller is told to ask for and the one
Busbar demands cannot drift apart (`crates/busbar-voice/src/mount.rs:93-96`, `:154-163`). The RFC
9728 metadata document is served at `/.well-known/oauth-protected-resource/v1/realtime`
(`crates/busbar-voice/src/mount.rs:116-119`).

**One audience, two claimed bases.** `MOUNT_PATH` (`/v1/realtime`) covers the four OpenAI Realtime
routes by segment-boundary match, and a second claim (`/v1/realtime/gemini`) covers the Gemini Live
route under its own dialect label — the A2A precedent of a plane returning more than one `(path,
wire)` pair. Both sit under the SAME bound audience (`<public_url>/v1/realtime`), so every route below
inherits the identical audience check at the mount rather than in a handler
(`crates/busbar-voice/src/mount.rs:voice_claims`).

Every route is `RouteAuth::Key` — the same key chain and audience check every other plane's doors
run. A token minted for a different resource is refused before any hook, lease or dial runs.

### Scope

The plane declares one scope kind, `session` (`crates/busbar-voice/src/lib.rs:219`), the
vocabulary an `allowed_scopes: [{ kind: session, value: … }]` entry validates against — and opening a
session checks it. Holding a key valid for this plane's **audience** is not the same as being
**granted** a session on it: the audience check answers "is this token for this door", the grant
answers "may this caller walk through it", the same double gate MCP runs over `mcp_server` +
`mcp_tool` and A2A runs over `agent`.

The value the grant names is the voice front door's pool, `voice-server`, so a key is narrowed to
voice with `allowed_scopes: [{ kind: session, value: voice-server }]`. As on every other plane, a key
with **no** `allowed_scopes` list at all is the store's wildcard and is granted every kind; a key that
carries an explicit list must have this entry in it, so a model-plane key (pool scopes only), a
session grant aimed at another pool, and an empty list are all refused. The refusal is `403` and it
lands **first** — before the operator's hook gate fires, before a metering lease is reserved, before a
durable session row exists and before any provider is dialed, on both the one-shot HTTP passes and the
WS accepts (`crates/busbar-voice/src/mount.rs`). An ungoverned deployment resolves no key and has no
grant to consult, so it is unaffected.

---

## The topologies

All three are assembled from one `VoiceRuntime` through `begin_session` (or, for a WS accept,
`open_admitted_session` / `open_admitted_telephony` behind an already-run gauntlet), which opens the
D2 metering lease and the durable session handle before a frame flows
(`crates/busbar-voice/src/topology/mod.rs:252-357`).

### Topology A — the browser WebRTC sideband

Busbar attaches to the session over a persistent WSS keyed by `call_id`, owning the locked
instructions and tool set. It mints the browser's ephemeral client secret so the browser can
establish its **media path directly with the provider** — media flows peer-to-peer; Busbar's own
socket carries only the sideband control channel, never audio
(`crates/busbar-voice/src/topology/webrtc.rs:1-10`). This is mint/guard + control, not a media
relay.

Two one-shot HTTP passes serve this topology:

| Route | Method | What it does |
|---|---|---|
| `POST /v1/realtime/client_secrets` | key | Mints the browser's short-lived `ek_` client secret through the configured provider, so the long-lived provider key never reaches a browser. |
| `POST /v1/realtime/calls` | key | Brokers the browser's SDP offer to the provider's own `POST …/calls` under Busbar's own provider credential, preserves the `Location` header verbatim, and stamps the provider's `rtc_<call_id>` onto the durable session row — the one key that ties Busbar's governance to the media call that actually flows. |

Plus one WS accept:

| Route | What it does |
|---|---|
| `GET /v1/realtime/sideband/{call_id}` (upgrade) | The persistent sideband control socket for a browser session. |

### Topology B — the telephony proxy

A thin WS proxy between a telephony carrier's media stream and the provider's realtime upstream,
proxying frames both ways while metering, governing the tool set and driving barge-in. It locks
`g711_ulaw` end-to-end so 8 kHz µ-law passes straight through with no resample; the barge-in
truncate point is computed from the codec's own playback marks
(`crates/busbar-voice/src/topology/telephony.rs:1-15`).

| Route | What it does |
|---|---|
| `GET /v1/realtime/telephony/{call_id}` (upgrade) | The carrier media leg, `g711_ulaw` proxied end-to-end. |

Twilio Media Streams is the one carrier envelope implemented: it decodes Twilio's JSON-over-WS
lifecycle and `media` events, renders the inbound-webhook TwiML pointing Twilio at the right WS URL,
refuses a negotiated format that is not `g711_ulaw` / 8000 Hz / mono (a silent mismatch would corrupt
the barge-in truncate arithmetic), and binds the connection's `streamSid` at admission so a forged or
replayed connection cannot inject audio into a session it does not own
(`crates/busbar-voice/src/topology/twilio.rs:1-18`).

### Topology C — the Gemini Live thin duplex

`GET /v1/realtime/gemini/{call_id}` (upgrade) is a native full-duplex proxy in the SAME shape as the
telephony leg — a client WS on one side, the Gemini Live provider's own WS on the other, Busbar in
the middle metering and governing — reusing `topology::telephony::TelephonyProxy` under the Gemini
codec rather than a mint/SDP pair (Gemini Live has no ephemeral-token or SDP-offer concept to broker).

### The one choke point every route runs through

Every route — the two one-shot HTTP passes and the three WS accepts — funnels through the same
sequence before a byte of the actual protocol runs (`crates/busbar-voice/src/mount.rs`, `ws_accept`):

1. **hooks-gate** (`streams` container) — an operator's request-admission gate over the locked
   session-open parameters. A reject refuses before any lease, mint or dial. Byte-identical /
   zero-cost when no gate is attached.
2. **hooks-tap** — a `prompt: rw`-style rewrite over the same parameters, after the gate and before
   any credential is leased. A committed rewrite replaces the locked session parameters the mint or
   dial then carries.
3. **the governed open** (`run_gauntlet_session`, verify-strictly-before-charge) — a denied
   destination (an upstream model on the plane's own denial set) refuses with `403` before any
   lease or durable row exists: zero bytes, zero charge.
4. **the serving leg** — past a clean open, the mint/broker/socket logic proper.

A budget or durable-open failure past the gauntlet commits no durable row and simply closes the
socket or answers the refusal — there is no orphaned live session row on any refused or aborted path
(`crates/busbar-voice/src/mount.rs:864-876`, `:966-976`).

---

## What is structural and what is live

This is the section to read before you point a real caller at this plane. The door is real and
governed on every route; what is left honestly incomplete is narrower than it was, and is stated here
precisely.

- **The provider credential is threaded per dialect, when your config names one.** At boot the
  composition root resolves the provider serving `streams.session.model` out of your ordinary
  `models:` / `providers:` catalog and composes it onto BOTH dialect endpoints — the OpenAI one
  (`Authorization: Bearer`) and the Gemini one (`x-goog-api-key`) — each its own set-once slot (see
  [Configuration](#the-streams-section) above). With a provider composed, `POST
  /v1/realtime/client_secrets` mints the browser's `ek_` secret and `POST /v1/realtime/calls` brokers
  the SDP offer, both under busbar's own server-side key; the telephony and Gemini Live WS accepts
  DIAL their composed provider (see the next bullet). With **no** provider composed — no
  `streams.session.model`, no matching `models:` entry, or a secret reference that does not resolve —
  the one-shot passes answer **`501 Not Implemented`** and the WS legs serve the client socket only
  (see below), after running the full hooks-gate → hooks-tap → governed-open sequence above. A
  reference that fails to resolve is fail-closed: it composes nothing and logs a warning rather than
  dialing with an empty credential. **Today `streams:` names ONE model**, so both dialect endpoints are
  composed from the SAME resolved (origin, reference) pair; fronting Gemini Live through a genuinely
  distinct provider entry needs a second `streams:` knob this cycle does not add.
- **The telephony and Gemini Live WS legs DIAL the composed provider.** Once one of these WS accepts
  clears the gauntlet, lease and durable open, it dials the composed provider through
  `topology::dial_provider` — the same net-guarded, breaker-admitted path every other plane's egress
  uses, keyed `stream:<dialect>` — and proxies BOTH sockets through
  `topology::telephony::TelephonyProxy::run` (barge-in, tool correlation and metering all still run
  over the relayed frames). With **no** provider composed, both legs fall back to serving the
  client-facing socket only: uplink frames are decoded and metered but the upstream sink is a channel
  with no receiver, so sends fail fast and every frame is discarded with zero buffering rather than an
  unbounded queue growing for the session's life (`crates/busbar-voice/src/mount.rs`, `ws_accept`).
- **The browser-WebRTC sideband dials nothing, by design.** Topology A's media path is peer-to-peer
  (the browser talks to the provider directly once minted); Busbar's own socket is control-only, so
  there is no provider leg for it to dial.
- **One stated limit in the WS dial itself:** the shared substrate WS dialer
  (`busbar_substrate::egress::duplex_ws::dial`) opens the socket with no custom-header hook, so
  OpenAI Realtime's native `Authorization: Bearer` scheme cannot ride the WS handshake yet — a real
  OpenAI provider dial needs that hook to land. Gemini's `?key=` query form does not have this
  problem. This is a substrate-level gap outside this plane's own files, not something the mount
  papers over; the voice conformance battery's `provider-dial` leg proves the wiring end to end
  against a loopback provider that does not check auth, precisely because that is the seam being
  proven, not vendor fidelity.

None of this is a defect in what is documented above: the routes, the audience, the hooks seam, the
gauntlet, the durable session model and the provider dial are all real and exercised by the crate's
own test suite (`crates/busbar-voice/src/tests/`, `crates/busbar-voice/src/runtime/tests.rs`) and by
`testing/voice-conformance/`'s `gemini-live-route` and `provider-dial` legs.

---

## Governance and billing

**Voice has no meter and no budget of its own.** Every turn's usage is landed on the *one* ledger
through the same core meter seam every plane uses — `host.meter_ledger` / `host.meter_series` —
attributed to the presenting virtual key, so a voice session's spend appears on `usage_for(key)` and
the admin usage series exactly like a model call or a tool call
(`crates/busbar-voice/src/runtime/metering.rs:30-40`, `:65-76`). This half is wired to the real,
live `EngineHost` at every mounted route — it is not a stand-in.

**The per-session admission budget is the caller's own.** Every mounted route rebinds the plane's
money hop onto the live host the moment a request hands it one (`build_runtime_hosted`,
`crates/busbar-voice/src/runtime/mod.rs`), so a served session reserves and settles on the host's own
reserve-then-settle cost lease — the same lease the rest of your deployment's spend flows through —
and each turn is priced against the deployment rate card by the host (`MeteringHost::price_usage`),
not by the plane. The in-process `LocalMeteringPort` remains only as the pre-host default the crate's
own tests drive; no served session keeps it.

The session's **ceiling** is read off the presenting key's real budget chain: the tightest remaining
bucket across the key's own bucket and every ancestor budget group, widened from the budget
projection's micro-units into the lease's nanodollars
(`crates/busbar-voice/src/runtime/metering.rs`). Three cases follow from that, and all three are
worth knowing:

- A caller with **nothing capped** anywhere in its chain opens an uncapped session — there is no
  ceiling to impose, exactly as an unbudgeted model call has none.
- A caller whose tightest bucket is **already spent** is denied at the reserve (`402`), so it never
  opens a session at all rather than opening one that could spend.
- A caller **with** budget opens, and its session is hard-closed the moment its settles reach that
  remaining amount — which is when the fail-closed D2 diagnostic (`BUSBAR-7050`, below) fires.

The reserve itself still debits a coarse fixed over-estimate (1000 nanodollars, no flat session fee);
that is an audit tap, not the ceiling.

### Diagnostic

| Code | Title | Severity | Meaning |
|---|---|---|---|
| `BUSBAR-7050` | Voice session hard-closed on metering-lease exhaustion | Benign, recurring | A live session's metering lease reached its real cap and was hard-closed rather than allowed to keep spending — the plane's fail-closed ceiling doing its job. Self-heals; if a caller needs a larger envelope, raise its configured session budget. |

(`crates/busbar-voice/src/diagnostics.rs`.) This is the plane's one contributed diagnostic in the
`Class::Plane` (7000) band, installed into the runtime catalog at boot alongside MCP's and A2A's.

### Hooks

Every governed session-open fires the operator's `streams`-container gate and tap, exactly as
described in [The one choke point](#the-one-choke-point-every-route-runs-through) above — the same
seam every other plane's hooks fire through (`host.gate_decide` / `host.transform_over`), attached by
container name `streams` since the plane has no per-registration noun to key a hook on
(`crates/busbar-voice/src/mount.rs:75-79`). A rejecting gate is byte-identical in cost to an
unattached one when no hook is configured.

### Durability

A session's durable row (`VoiceSessionRow`: id, owner, a monotonic turn counter, `terminal`, the
provider's `rtc_<call_id>` correlation key once the SDP broker stamps it) lives in the neutral
durable-handle engine, keyed `(owner, id)` — a second session bound to the same id under a different
owner is refused indistinguishably from "does not exist," the same anti-enumeration contract every
other durable-handle consumer inherits (`crates/busbar-voice/src/runtime/scope.rs:1-11`, `:33-59`).
Retention is generous and fixed, not operator-tunable: an hour of idle, an hour past terminal, a
working-set cap of 4096 rows (`crates/busbar-voice/src/runtime/scope.rs:25-31`).

With `store: memory` (the default), nothing survives a restart. With a durable store configured, boot
restores the working set through `voice_hydrate`: an active row is re-installed, a terminal one is
counted and left, and a row that cannot be decoded is counted and skipped rather than aborting the
restore — only a store-level list failure refuses boot
(`crates/busbar-voice/src/mount.rs:165-200`).

---

## Observability

The voice plane's front door counts on the same neutral, per-mounted-plane request family MCP and
A2A use, `busbar_plane_requests_total` / `busbar_plane_request_duration_seconds`, with
`plane="voice"` and `ingress_protocol` set to the LEG'S OWN dialect (`openai_realtime` for the
mint/SDP/sideband/telephony routes, `gemini_live` for the Gemini route) — never a plane-wide constant,
so the second dialect's traffic is never mislabelled under the first; the front-door `pool` label is
pinned to the constant `voice-server` for the same reason A2A pins its routing-target label — an
unbounded caller-chosen value would be a cardinality DoS one valid credential could drive
(`crates/busbar-voice/src/mount.rs`). See [Observability](/docs/observability/) for the shared metric
families every plane emits into.

The outbound provider dial, once a deployment composes one, counts on the shared
`busbar_upstream_attempts_total` / `busbar_upstream_failures_total` families under the breaker-cell
key `stream:<dialect>` — the same families and the same breaker every other plane's egress uses
(`crates/busbar-voice/src/topology/mod.rs`).

---

## Conformance

`testing/voice-conformance/` is armed: every leg is `ready` and drives the plane's real codecs and
runtime through the `voice-conform` harness, and the verdict reflects real leg results. The sibling
MCP and A2A batteries treat an unarmed subject leg as **RED** (the false green those batteries exist
to refuse), and the same rule holds here one plane over — a ready leg that executes nothing is red,
not green, which `voice-conformance.sh --selftest` proves by planting runs the accounting must refuse
and runs it must accept (`testing/voice-conformance/README.md`). The PENDING path stays live for a
future leg that is not armed yet, stated loudly and never dressed up as a pass.

The declared legs: `spec-per-dialect` (the OpenAI/Gemini spec battery, one slice per dialect),
`replay` (captured-transcript replay must re-derive identically), `cross-parity` (the four ordered
OpenAI⟷Gemini pairs must agree where the cross-dialect mapping says they must), the composition legs —
`provider-credential` (the credential the mint/SDP passes dial under is composed from the deployment's
own catalog and secret resolver, set-once, and an unresolvable reference composes nothing),
`metering-lease` (a session reserves on the host's lease, capped by the tightest bucket in the
caller's chain, denied at the door when spent), `session-scope` (the declared `session` grant is
enforced against the presenting key), `gemini-live-route` (the Gemini Live route is actually mounted —
claim, admission, WS arrival and the wire handshake itself, over the plane's public functions) and
`provider-dial` (a session actually dials the composed provider through a loopback socket via
`topology::dial_provider`, and its D2 metering lease settles the usage that arrived over it) — and
`governance` (barge-in preemption, turn-budget enforcement, the D2 hard-close checkpoint — product
policy, not protocol, and structurally unable to move the conformance verdict, the same rule A2A's
governance suite runs under).

```bash
bash testing/voice-conformance/voice-conformance.sh --selftest   # prove the accounting bites
bash testing/voice-conformance/voice-conformance.sh --verdict    # every leg, judged
bash testing/voice-conformance/voice-conformance.sh --list       # what is declared
```

If you are evaluating this plane for a production workload, read this section together with [What
is structural and what is live](#what-is-structural-and-what-is-live): the verdict now covers both
dialects' mounted routes and a live (loopback) provider dial end to end, and the one stated gap left
is vendor header-auth fidelity for a real OpenAI Realtime WS dial (see the last bullet there) — not
whether a session can dial a provider at all.
