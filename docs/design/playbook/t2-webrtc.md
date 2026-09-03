# T2 — Browser-WebRTC Voice Topology (busbar-voice, behind `runtime`)

Status: **BUILD PLAYBOOK.** Read-only against the tree; grounds the browser WebRTC topology
("Topology B", `plane4-duplex-session.md` §5.2) onto the seams the `runtime`-feature crate already
ships. Companion to `plane4-duplex-session.md` (the plane's IR / pump / gauntlet contract) and
`plane4-voice-dialect-landscape.md` (the OpenAI Realtime GA wire). Every `crates/…:NNN` citation is
against `integration/plane-extraction`. Where a piece is absent it is called **NET-NEW**; where it
ships as a stub it is called **STUB (present)**.

The one framing rule for T2, stated up front: **in the browser-WebRTC topology busbar is a
mint/guard + sideband-control boundary, NOT a media relay.** Audio never transits busbar — mic
capture, 24 kHz framing, jitter-buffered playback, and server-side truncate-on-barge-in all happen
**off-box** (browser WebRTC peer, or an adopted Pipecat/LiveKit media leg). busbar holds the real
key, mints the ephemeral secret, brokers the SDP, and runs the tool + config-lock governance over a
sideband control WSS. This is the exact split the shipped `Carrier::sideband()`
(`crates/busbar-voice/src/runtime/carrier.rs:52-61`) already encodes: a carrier that **drops all
downlink media** (`carrier.rs:82-90`, `send_downlink` returns `false` when `downlink: None`).

---

## 1. The concrete WebRTC-sideband topology

Three server-side control-plane hops, then peer-to-peer media busbar never sees:

```
 browser                         busbar (holds REAL key)                 OpenAI Realtime
 ───────                         ───────────────────────                 ───────────────
  (1) POST mint  ───────────────▶  gauntlet pass (Invoke-shaped)
                                   mint ek_ via provider client-secrets  ──▶ POST /v1/realtime/client_secrets
                 ◀───────────────  ek_… (TTL-bounded, config-scoped)     ◀── ek_…
  (2) POST SDP offer ────────────▶ gauntlet pass; broker offer upstream  ──▶ POST /v1/realtime/calls
      (Content-Type: application/sdp, Authorization: Bearer ek_…)            Content-Type: application/sdp
                 ◀───────────────  SDP answer + Location: rtc_<call_id>  ◀── 201, Location: /v1/realtime/calls/rtc_…
  (3) ═══ WebRTC media (Opus/PCM) ══════ peer-to-peer ═══════════════════▶  (busbar sees NO frames)
                                   (2b) busbar dials sideband control WSS ──▶ wss keyed by rtc_<call_id>, REAL key
                                        tools + session.update locked here
```

- **(1) Ephemeral mint** — a JSON `POST` that is a *normal one-shot gauntlet pass* (an `Invoke`-shaped
  request, no duplex transport needed for the mint itself, `plane4-duplex-session.md` §5.2). busbar
  calls the provider `client_secrets` endpoint with the **real** key, receives an `ek_` secret, and
  returns only that to the browser. Modeled today by `TokenMinter::mint(&SessionConfig)`
  (`crates/busbar-voice/src/topology/webrtc.rs:52-56`), dependency-inverted so the composition root
  binds the real HTTPS call and tests bind a fake (`topology/tests.rs:185-198`).
- **(2) SDP offer/answer broker** — a *non-JSON* `POST /v1/realtime/calls`, `Content-Type:
  application/sdp`, body = the browser's SDP offer, `Authorization: Bearer ek_…`; busbar preserves the
  `Location: /v1/realtime/calls/rtc_<call_id>` header from the 201 and returns the SDP answer. This is
  a second gauntlet pass. **NET-NEW (see §2).**
- **(2b) Sideband control WSS** — busbar dials the provider's per-call control socket (keyed by
  `rtc_<call_id>`) holding the **real** key, and serves the four-layer IR over it: tool execution and
  `session.update`/instruction locking run server-side. This is `attach()` →
  `dial_provider(url, GuardPolicy)` → `serve_messages(…, VoiceSession)`
  (`topology/webrtc.rs:99-140`, `topology/mod.rs:49-65`, `runtime/session.rs:302-328`).
- **(3) Media** — browser↔OpenAI peer-to-peer WebRTC. busbar's metering tap is therefore **coarse**:
  per `response.done.usage` on the sideband, not per audio frame (`plane4-duplex-session.md` §5.2).
  Barge-in on WebRTC is **server-authoritative** — the provider truncates its own turn, so busbar does
  **not** run the WebSocket `audio_played_ms` playback-position math on this topology.

### The data path, concretely

| Hop | Transport | busbar role | Seam |
|---|---|---|---|
| mint | HTTPS one-shot | gauntlet pass + provider call with real key | `TokenMinter` (`webrtc.rs:52`) |
| SDP broker | HTTPS one-shot, `application/sdp` | gauntlet pass + verbatim SDP relay, preserve `Location` | **NET-NEW** |
| sideband control | egress WSS (`Transport::WebSocket`) | serve `VoiceSession` (tools+config lock+usage) | `dial_provider` (`mod.rs:49`) + `serve_messages` |
| media | WebRTC P2P | **none** — never transits busbar | `Carrier::sideband()` drops downlink (`carrier.rs:82`) |

---

## 2. What's STUB vs NET-NEW in `topology/` (and the seams it leans on)

**STUB (present) — the T2 skeleton the crate already ships:**

- `topology/webrtc.rs` — `attach()` (`:99-140`): locks `instructions`+`tools` into `SessionConfig`,
  mints the ephemeral token scoped to that locked config, `begin_session`s the governed session (lease
  + durable handle), returns `Attached { token, session, core, handle }` served over the sideband.
- `EphemeralToken { value, expires_at_unix }` (`webrtc.rs:24-30`) and the `TokenMinter` port
  (`:52-56`), `MintError`/`AttachError` (`:33-76`).
- `topology/mod.rs::dial_provider` (`:49-65`) — selects `Transport::WebSocket`, resolves it to
  `UpstreamWireKind::Duplex`, and lets the substrate `duplex_ws::dial` open the net-guarded socket; the
  plane holds no socket/resolver/WS-framing of its own. Fail-closed on an unpinned target
  (`topology/tests.rs:168-177`).
- `topology/mod.rs::begin_session` (`:106-136`) — the fail-closed open: `open_lease` (no lease ⇒ no
  session, `StartError::BudgetRefused`) then `bind_session`+`handle.open` (durable genesis).
- `Carrier::sideband()` (`runtime/carrier.rs:52-61`) — the media-less carrier proving busbar relays no
  audio on T2. Test: `webrtc_sideband_mints_token_locks_config_and_relays_no_media`
  (`topology/tests.rs:200-243`).

**NET-NEW — what T2 still needs, in priority order:**

1. **Ephemeral-secret hardening (see §4).** `EphemeralToken` (`webrtc.rs:24-30`) carries only
   `value`+`expires_at_unix`. It does **not** validate the `ek_` prefix, clamp the TTL (default **600s**,
   valid range **10–7200s**), or bind the session identity. Add: TTL clamp on mint, `ek_`-prefix
   assertion, and an **`OpenAI-Safety-Identifier`** binding stamped on the mint request (§4).
2. **A concrete `TokenMinter`** — the real HTTPS `POST /v1/realtime/client_secrets` via the substrate
   egress engine (`crates/busbar-substrate/src/egress/…`), holding the real key. Only the trait +
   fake exist today.
3. **The SDP offer/answer broker** — a new one-shot handler: accept `application/sdp` from the browser,
   `POST /v1/realtime/calls` upstream with `Bearer ek_…`, return the answer, **preserve `Location:
   …/rtc_<call_id>`**. Verified absent: no `sdp`/`offer`/`answer`/`rtc_` anywhere under
   `busbar-voice/src` except this playbook's siblings.
4. **HTTP ingress routes** for (1) and (3) as gauntlet passes — `attach()` is in-crate glue with no
   `PlaneRouteFn` wiring; the mint + SDP endpoints must arrive as neutral `Arrival`s
   (`plane4-duplex-session.md` §4.2), never a raw axum upgrade.
5. **`rtc_<call_id>` sideband keying** — `attach()` takes a plain `call_id: String`; T2 must key the
   sideband control WSS by the `rtc_<call_id>` the SDP broker returned, so the brokered media call and
   the control socket are the same session. A `session-binding → rtc_call_id` correlation in the
   `SessionScope` row (`runtime/scope.rs:38-49` `VoiceSessionRow`).

---

## 3. How T2 uses the T1 seams (by name)

- **T1 pump (`serve_messages` + `DuplexPlane`, `crates/busbar-substrate/src/ingress/byte_duplex.rs:318`).**
  The sideband control WSS is served through the neutral message-duplex pump: it owns framing, the
  single write lock, and the drain lifecycle; the plane is exactly two callbacks
  (`classify`/`handle`). `VoiceSession` (`runtime/session.rs:302-328`) is that `DuplexPlane` — it
  `classify`s every frame as `None` (Realtime events are fire-and-forget; correlation is at the IR
  layer, not transport), and `handle` drives `on_server_frame` onto `out` (upstream) + the carrier
  (downlink, a no-op on T2's sideband carrier). Egress uses `dial_provider` (`topology/mod.rs:49`).
- **Media path (`crates/busbar-voice/src/ir/media.rs`).** On T2 the media IR is **dormant**: audio is
  P2P so `IrAudioFrame` (`media.rs:99-107`) never crosses busbar, and the `truncate_point_ms` /
  `bytes_per_ms` barge-in arithmetic (`media.rs:62-95`) is **not** exercised — WebRTC truncation is
  server-authoritative. The memory-fact media pipeline (mic → 24 kHz downsample → base64 framing →
  jitter-buffered playback → truncate-on-barge-in with `audio_end_ms`+flush+guard) is the **browser /
  adopted-orchestrator** responsibility here, and is the WebSocket/telephony path's concern
  (`runtime/session.rs:151-171`), not T2's. T2 keeps only the *format* knowledge for the locked config.
- **`SessionScope` (`runtime/scope.rs` over `busbar_substrate::plane_host::SessionScope`).** `attach()`
  opens one durable `SessionHandle` keyed `(owner, call_id)` (`scope.rs:84-150`), owner-gated and
  anti-enumerating (a foreign owner gets the one indistinguishable `NotYours`, `scope.rs:4-11`). T2
  stamps the `rtc_<call_id>` binding into the `VoiceSessionRow` (§2 item 5) and bumps the turn cursor
  per settled `response.done`.
- **Cost-lease (D2) seam (`runtime/metering.rs`).** `begin_session` opens the reserve-then-settle lease
  before any hop (`mod.rs:120-122`); production binds `HostMeteringPort`/`HostLease`
  (`metering.rs:188-258`) over the neutral `MeteringHost` (`cost_reserve`/`cost_settle`/`cost_close`),
  tests bind `LocalLease` with the identical contract (`metering.rs:124-181`). On T2 the lease settles
  from the **coarse** sideband `response.done.usage` (`runtime/session.rs:137-149`); exhaustion trips
  `Carrier::hard_close()` (`carrier.rs:65-71`) which tears the sideband down — a runaway browser call
  is cut even though busbar never saw the media. A refused/`Some(0)` budget denies at the door
  (`metering.rs:170-173`), so the ephemeral secret is never even minted on a dry budget.

---

## 4. The exact ephemeral-secret flow (real key never crosses)

The invariant: **the browser only ever holds an `ek_` client secret; the real provider key stays
server-side and is used only on busbar↔provider hops.**

1. **Browser requests a session.** `POST` to busbar's mint route (a gauntlet pass). No key in the
   request; identity comes from the caller's resolved `gov` (`plane_host::GauntletRequest`).
2. **busbar locks the config.** `attach()` folds the plane's authoritative `instructions`+`tools` into
   `SessionConfig` (`webrtc.rs:99-117`, `config.rs:106-135`) — the browser cannot later override them
   (`runtime/session.rs:265-271`, a client `session.update` is reconciled against the locked copy,
   never trusted blind).
3. **busbar mints server-side.** `TokenMinter::mint(&locked_config)` calls the provider
   `client_secrets` endpoint **with the real key** (NET-NEW concrete impl over the egress engine).
   On the mint request busbar stamps:
   - **`OpenAI-Safety-Identifier`** = the session-binding derived from the caller identity (the
     memory-fact session binding) — so the minted secret is attributable and rate-limitable to *this*
     caller, not a shared blob. **NET-NEW** (add to the mint request headers; optionally a field on
     `SessionConfig`).
   - **TTL clamp**: request `expires_after.seconds` defaulting to **600s**, clamped to **[10, 7200]**.
     **NET-NEW** (`EphemeralToken` has no TTL policy today).
4. **busbar returns only `ek_…`.** The response to the browser carries the `ek_` value +
   `expires_at_unix` (`EphemeralToken`, `webrtc.rs:24-30`) and nothing else. Assert the `ek_` prefix
   before returning (NET-NEW guard). The real key never appears in any browser-facing payload.
5. **Browser uses `ek_` for the SDP handshake only.** The browser sends its SDP offer to busbar's
   broker with `Authorization: Bearer ek_…`; busbar forwards to `POST /v1/realtime/calls` and returns
   the answer + `Location: rtc_<call_id>`. The `ek_` is short-lived and single-session-scoped; media
   then flows P2P under it.
6. **busbar holds the real key on the sideband.** The control WSS (busbar↔provider, `rtc_<call_id>`)
   authenticates with the **real** key — this is where tools execute and config stays locked. The
   browser never holds this socket and cannot forge a `CallResult` (`runtime/session.rs:172-242`, the
   tool moat: correlate → execute server-side → feed result upstream).

Net: three server-side hops touch the real key (mint, SDP broker, sideband); the browser touches only
`ek_`; the lease is reserved before the mint and hard-stops the whole session on exhaustion.

---

## 5. Residual risks

1. **`ek_` scope vs busbar's governance boundary (highest).** Once the browser holds `ek_` and media
   is P2P, busbar's only live control lever is the sideband WSS + the coarse per-`response.done` lease
   settle. If a provider lets an `ek_` client mutate session config or author tool calls directly over
   the media/data channel (bypassing the sideband), the config-lock + tool-moat guarantees
   (`session.rs:265-271`, `:172-242`) leak. **Mitigation:** mint the `ek_` with the *minimal* scope the
   provider allows, stamp `OpenAI-Safety-Identifier`, keep TTL at the 600s default (never 7200 for
   browser lanes), and verify at build time that a client `session.update` over the data channel cannot
   override the locked instructions/tools. Must be re-verified against provider GA semantics before P3
   ships.
2. **Coarse metering can overspend within one turn.** T2 settles only at `response.done`
   (`session.rs:137-149`); a long single response streams P2P audio busbar never meters until the turn
   ends, so the hard-stop lands at turn boundaries, not mid-turn. A pathological long turn can exceed
   the cap before the settle fires. **Mitigation:** a conservative opening `estimate_nanos` + a
   per-turn `max_output_tokens` in the locked config (`config.rs:137-138`) to bound a single turn's
   worst case; document that T2's budget guarantee is turn-granular, not frame-granular (unlike the WS
   topology).
3. **SDP broker + `rtc_<call_id>` correlation is unbuilt and easy to get wrong.** The broker is a
   non-JSON `application/sdp` pass that must preserve the `Location` header and thread `rtc_<call_id>`
   into both the `SessionScope` row and the sideband dial (§2 items 3+5). A mismatch silently attaches
   the sideband to the wrong call (governance applied to call A, media on call B) with no error.
   **Mitigation:** make `rtc_<call_id>` the single correlation key, assert it end-to-end (mint →
   broker → scope row → sideband URL) in a conformance test before wiring the route.
