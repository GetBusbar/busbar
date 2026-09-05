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
`streams:` gets you, the complete configuration grammar, how identity is established, the two
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
apply (`crates/busbar-voice/src/lib.rs:148-160`). **Today, only the OpenAI Realtime wire format is
mounted.** The Gemini Live codec exists in the IR layer (`crates/busbar-voice/src/ir/codec/gemini/`)
and is exercised by the cross-dialect test battery, but no ingress route speaks it yet — the plane's
protocol declaration names `openai_realtime` as its one live dialect
(`crates/busbar-voice/src/lib.rs:286-287`). If your deployment needs Gemini Live today, it is not
there.

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
all (`crates/busbar-voice/src/config.rs:105-113`). The realtime provider's own API key is not
configured through `streams:` in this build; see [What is structural and what is
live](#what-is-structural-and-what-is-live) below.

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

**One base claims all four routes.** `MOUNT_PATH` (`/v1/realtime`) covers `/v1/realtime/*` by
segment-boundary match, so every route below inherits the audience check at the mount rather than in
a handler (`crates/busbar-voice/src/mount.rs:253-264`).

Every route is `RouteAuth::Key` — the same key chain and audience check every other plane's doors
run. A token minted for a different resource is refused before any hook, lease or dial runs.

### Scope

The plane declares one scope kind, `session` (`crates/busbar-voice/src/lib.rs:219`), the
vocabulary an `allowed_scopes: [{ kind: session, value: … }]` entry validates against. **As
implemented today, opening a session does not check that grant.** The mount code resolves the
caller's audience-checked key (for attribution and the hook gate) but the governed-open path
described below contains no `session`-scope authorization check the way MCP double-gates
`mcp_server` + `mcp_tool` or A2A gates `agent` — any caller holding a key valid for the plane's
audience can open a session. If you need per-caller session authorization narrower than "holds a
key for this audience," it is not enforced here yet; gate it with a hook (below) instead.

---

## The two topologies

Both topologies are assembled from one `VoiceRuntime` through `begin_session` (or, for a WS accept,
`open_admitted_session` behind an already-run gauntlet), which opens the D2 metering lease and the
durable session handle before a frame flows (`crates/busbar-voice/src/topology/mod.rs:252-357`).

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

### The one choke point every route runs through

Every route — the two one-shot HTTP passes and the two WS accepts — funnels through the same
sequence before a byte of the actual protocol runs (`crates/busbar-voice/src/mount.rs:373-393`,
`:911-926`):

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
governed; several of the legs behind it are not wired to a live provider by the composition root in
this build.

- **The provider credential is not threaded.** `VoiceMount`'s `provider` field is `None` in every
  build today — nothing composes a realtime provider's base URL and API key onto the mount
  (`crates/busbar-voice/src/mount.rs:135-140`, `:227-240`). With no provider composed, both
  `POST /v1/realtime/client_secrets` and `POST /v1/realtime/calls` answer **`501 Not Implemented`**
  ("governed, but no provider credential composed") — after running the full hooks-gate → hooks-tap
  → governed-open sequence above, including the metering reserve and the durable session row. The
  admission and governance machinery is exercised for real; the provider round trip is not.
- **The WS legs serve the client socket only.** Once a browser-sideband or telephony WS accept
  clears the gauntlet, lease and durable open, it serves the client-facing socket over the neutral
  duplex pump. With no provider dial composed, a telephony session's uplink frames are decoded and
  metered but the upstream sink is a channel with no receiver: sends fail fast and every frame is
  discarded with zero buffering, rather than an unbounded queue growing for the session's life
  (`crates/busbar-voice/src/mount.rs:989-1003`). There is no live round trip to a realtime provider
  through the routes this build mounts, out of the box.
- **The circuit breaker and net-guarded dial exist as a library function** —
  `topology::dial_provider` dials a provider WSS through the same net-guarded, breaker-admitted path
  every other plane's egress uses, keyed `stream:<provider>` (`crates/busbar-voice/src/topology/mod.rs:41-171`)
  — but nothing in the shipped routes calls it yet, for the same reason: no provider is composed.
- **Metering is real for attribution, not yet real for admission.** See
  [Governance and billing](#governance-and-billing) below — this is the one gap most likely to
  surprise an operator who assumes a live session is capped against the caller's real grant.

None of this is a defect in what is documented above: the routes, the audience, the hooks seam, the
gauntlet and the durable session model are all real and exercised by the crate's own test suite
(`crates/busbar-voice/src/tests/`, `crates/busbar-voice/src/runtime/tests.rs`). What is missing is
the composition root's wiring of a concrete provider — a deployment (or a future release) supplies
`TokenMinter` / the guarded WS dial's concrete provider config to complete the path.

---

## Governance and billing

**Voice has no meter and no budget of its own.** Every turn's usage is landed on the *one* ledger
through the same core meter seam every plane uses — `host.meter_ledger` / `host.meter_series` —
attributed to the presenting virtual key, so a voice session's spend appears on `usage_for(key)` and
the admin usage series exactly like a model call or a tool call
(`crates/busbar-voice/src/runtime/metering.rs:30-40`, `:65-76`). This half is wired to the real,
live `EngineHost` at every mounted route — it is not a stand-in.

**The per-session admission budget is, in this build, a coarse, uncapped placeholder — not yet the
caller's real grant.** The two production entry points differ:

- `PLANE_DECL.build_runtime` — the hook actually wired at boot — binds `LocalMeteringPort`, an
  in-process reserve/settle lease whose contract matches the real one byte-for-byte but which is not
  backed by any caller's real spend ceiling (`crates/busbar-voice/src/runtime/mod.rs:142-165`).
- `build_runtime_hosted`, which binds the real host-backed lease (`HostMeteringPort`, pricing each
  turn against the deployment rate card via `MeteringHost::price_usage`), exists and is exercised by
  the crate's own D2 billing-oracle test, but **is not called anywhere in the shipped composition
  root** (`crates/busbar-voice/src/runtime/mod.rs:179-192`) — grep the tree and the only call sites
  are the crate's own tests and its own doc comments.
- The session-open budget every mounted route reserves against is a fixed structural placeholder —
  `estimate_nanos: 1_000, fee_nanos: 0, cap_nanos: None` (uncapped) — set at the route layer, not
  derived from the caller's grant (`crates/busbar-voice/src/mount.rs:418-423`, `:940-944`).

The practical read: a live session opened through this build's mounted routes is **not currently
capped against a caller's real budget**, even though every turn is still recorded, for real, against
that caller's usage. The fail-closed D2 hard-close diagnostic (`BUSBAR-7050`, below) fires only once
a real cap is wired in and a session settles past it — worth knowing before you treat its absence as
"nothing has spent anything."

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
`plane="voice"` and `ingress_protocol="openai_realtime"` (the plane's one live dialect today); the
front-door `pool` label is pinned to the constant `voice-server` for the same reason A2A pins its
routing-target label — an unbounded caller-chosen value would be a cardinality DoS one valid
credential could drive (`crates/busbar-voice/src/mount.rs:58-73`, `:483-499`). See
[Observability](/docs/observability/) for the shared metric families every plane emits into.

The outbound provider dial, once a deployment composes one, counts on the shared
`busbar_upstream_attempts_total` / `busbar_upstream_failures_total` families under the breaker-cell
key `stream:<provider>` — the same families and the same breaker every other plane's egress uses
(`crates/busbar-voice/src/topology/mod.rs:41-119`).

---

## Conformance

`testing/voice-conformance/` is a scaffold, honestly reported as such: the battery's shape — runner,
leg discovery, verdict emitter, CI workflow — is landed and enforced, but every leg reports
**PENDING**, not a pass, because there is nothing live to arm against yet. The sibling MCP and A2A
batteries treat an unarmed subject leg as **RED** (the false green those batteries exist to refuse);
voice instead states PENDING per leg and proves — via `voice-conformance.sh --selftest` — that the
day a leg is marked `ready`, it inherits the identical anti-vacuity discipline: a ready leg that
executes nothing is red, not green (`testing/voice-conformance/README.md`).

The declared legs, once filled: `spec-per-dialect` (the OpenAI/Gemini spec battery, one slice per
dialect), `replay` (captured-transcript replay must re-derive identically), `cross-parity` (the four
ordered OpenAI⟷Gemini pairs must agree where the cross-dialect mapping says they must), and
`governance` (barge-in preemption, turn-budget enforcement, the D2 hard-close checkpoint — product
policy, not protocol, and structurally unable to move the conformance verdict, the same rule A2A's
governance suite runs under).

```bash
bash testing/voice-conformance/voice-conformance.sh --selftest   # prove the accounting bites
bash testing/voice-conformance/voice-conformance.sh --verdict    # today: every leg PENDING
bash testing/voice-conformance/voice-conformance.sh --list       # what is declared
```

If you are evaluating this plane for a production workload, read this section together with [What
is structural and what is live](#what-is-structural-and-what-is-live): there is, today, no green
conformance run to point to, and the composition root has not yet wired a live provider for the
scaffold to judge.
