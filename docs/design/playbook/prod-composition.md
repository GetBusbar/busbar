# Production composition wiring for `busbar-voice` — the remaining stub→real seams

Status: **DESIGN (not build).** Read-only against the tree; every `crates/…:NNN` citation is against
`integration/plane-extraction`. This doc is the CONSOLIDATION layer: `docs/design/playbook/t2-webrtc.md`
(items 1–2), `docs/design/playbook/t2-twilio.md` (item 3), and `docs/design/playbook/t2-runtime-session.md`
+ `docs/design/playbook/m5-voice-boot.md` (item 5's mount hooks) already design most of this in depth —
this doc does not re-derive their content, it cites them, fills the one genuinely undesigned gap (item
4, the tool/pricing registries), and answers the one question none of them answers head-on: **which of
these five stub→real seams gate 1.6.0 "done" per the T2 DoD** (`plane4-duplex-session-1.6.0-plan.md:429-436`)
**and which are honestly post-1.6.0.**

Ground truth read for this doc: `crates/busbar-voice/src/runtime/mod.rs` (`build_runtime` line 94 vs
`build_runtime_hosted` line 114 — the dev/prod metering split, with tools+pricing still dev-default in
both), `topology/webrtc.rs` (`TokenMinter` trait line 53, `EphemeralToken` line 25), `topology/telephony.rs`
(the generic `g711` proxy), `runtime/tools.rs` (`ToolExecutor`/`EchoToolExecutor`), and `lib.rs:84-137`
(`PLANE_DECL`, every hook but `build_runtime` still `None`).

---

## 0. TL;DR

Five stub→real seams, one already fully designed elsewhere (webrtc mint/SDP, §1–2), one fully designed
elsewhere for the concrete carrier (Twilio envelope+webhook, §3), one undesigned until now (tool/pricing
registries, §4), and one that is really *two* different neutral seams wearing one name — `PlaneRouteSpec`
one-shot HTTP passes vs. a WS-upgrade **arrival kind** that must NOT be a `PlaneRouteSpec` (§5). The T2 DoD
(`plane4-duplex-session-1.6.0-plan.md:429-436`) names Topology A (WS bridge) end-to-end and Topology B
(browser WebRTC) end-to-end as REQUIRED; it names neither Twilio nor a real tool/pricing registry. Net:
**REQUIRED for 1.6.0** = the mint/SDP broker + WS-accept routing for Topologies A/B, `run_gauntlet_session`
+ `start`/`build`/`hydrate`/`parse_section` (item 5's engine, already scoped by `t2-runtime-session.md`).
**Deferrable** = live Twilio (item 3), a real tool registry beyond echo, and a real rate card beyond
zero-pricing (item 4) — none of these gate the DoD's audio-both-ways / tool-answered / barge-in / budget /
audit / Gemini-Live-no-rewrite claims, and Twilio explicitly is not in the T1.6.0-plan's T2 scope at all.

---

## 1. The ephemeral `ek_` client-secret mint

**What exists.** `EphemeralToken { value, expires_at_unix }` (`topology/webrtc.rs:25-30`) and the
`TokenMinter` trait (`:53-56`) — a dependency-inverted port with a fake bound in tests
(`topology/tests.rs:185-198`). `attach()` (`:99-140`) locks `instructions`+`tools` into `SessionConfig`
before minting, so the token is scoped to the SAME config busbar governs.

**Net-new.** (i) TTL clamp policy — default **600s**, valid range **10–7200s** — not present on
`EphemeralToken` today; (ii) `ek_`-prefix assertion on the returned value; (iii) an
**`OpenAI-Safety-Identifier`** header stamped on the mint request, binding the minted secret to the
caller's resolved identity (no field for this on `SessionConfig` today); (iv) a concrete HTTPS
`TokenMinter` impl calling `POST /v1/realtime/client_secrets` with the real key over the substrate
egress engine — only the trait + a test fake exist. Full design: `docs/design/playbook/t2-webrtc.md`
§2 item 1–2, §4 (the exact header/TTL/prefix contract), §5 risk 1.

**T1 seam it depends on.** The substrate egress HTTP client (the same one `dial_provider`'s sibling for
one-shot HTTPS passes would use — not yet named as a port in `topology/mod.rs`, which currently only
wraps the duplex WS egress `dial_provider:49-65`) + the gauntlet's resolved-caller identity
(`plane_host::GauntletRequest`) for the Safety-Identifier binding.

**Classification: REQUIRED for 1.6.0.** The T2 DoD's Topology B clause — *"a browser establishes WebRTC
voice with keys never leaving the server… locked instructions cannot be overridden by the client"*
(`plane4-duplex-session-1.6.0-plan.md:431-433`) — cannot be satisfied without a real mint; `TokenMinter`
staying a fake makes Topology B untestable end-to-end and the DoD's "keys never leave the server" claim
unverifiable in prod.

---

## 2. The SDP broker + `rtc_<call_id>` sideband correlation key

**What exists.** Nothing — verified absent (`t2-webrtc.md:129`, no `sdp`/`offer`/`answer`/`rtc_` hit
under `busbar-voice/src` outside the playbooks). `attach()` (`webrtc.rs:99-140`) takes `call_id` as a
plain caller-supplied string with no correlation to any brokered call.

**Net-new.** A one-shot handler: accept `application/sdp` from the browser, `POST /v1/realtime/calls`
upstream with `Authorization: Bearer ek_…`, return the SDP answer, **preserve the `Location:
/v1/realtime/calls/rtc_<call_id>` response header verbatim** — plus threading that `rtc_<call_id>` into
both the durable `VoiceSessionRow` (`runtime/scope.rs:38-49`, currently no such field) and the sideband
WSS dial URL, so the brokered media call and the control socket are provably the same session (not two
independently-correlatable strings). Full design: `t2-webrtc.md` §2 item 3+5, §5 risk 3 (the exact
failure mode — governance applied to call A, media on call B, with no error — if the correlation is
wrong).

**T1 seam it depends on.** The same one-shot HTTPS egress port as item 1 (a non-JSON,
`Content-Type: application/sdp` body — the gauntlet's `Invoke`-shaped one-shot pass, not the duplex
transport) + `SessionScope`/`VoiceSessionRow`'s durable row (`runtime/scope.rs`) for the correlation
field.

**Classification: REQUIRED for 1.6.0** for the SAME DoD clause as item 1 — Topology B is not a real
topology without the SDP handshake that actually opens the media call the sideband is supposed to
govern. The correlation-key wiring is the part most likely to be under-scoped if built in a rush; treat
it as inseparable from the broker itself, not a follow-up.

---

## 3. The Twilio JSON-envelope codec + inbound TwiML webhook

**What exists.** The entire generic telephony bridge — `g711_config()`, `TelephonyProxy`,
`begin_telephony`, `TelephonyProxy::run`'s four-`Stream`/`Sink` wiring, funnels, hard-close race,
teardown (`topology/telephony.rs:34-191`) — is carrier-agnostic and fully built. Nothing Twilio-specific
exists (verified: no `twilio` hit anywhere in `crates/busbar-voice` or `docs/design` outside the
playbook).

**Net-new.** (i) `TwilioEnvelope::decode`/`encode` — Twilio's JSON Media Streams protocol
(`connected`/`start`/`media`/`mark`/`stop`, base64 µ-law `media.payload`) ↔ the raw `Vec<u8>`
`client_in`/`client_out` `TelephonyProxy::run` already expects; (ii) the inbound TwiML webhook route —
a one-shot gauntlet pass that mints `call_id`/`owner`, builds+locks `g711_config()`, renders
`<Connect><Stream url="…"/></Connect>`; (iii) the WS-accept route for `wss://…/twilio/{call_id}` that
upgrades Twilio's connection and threads it through the envelope adapter into
`begin_telephony`/`TelephonyProxy::run`; (iv) a fail-closed `start.mediaFormat` assertion (refuse, not
warn, on a non-`g711_ulaw`/8000Hz echo). Full design: `t2-twilio.md` §1–3 (complete wire-level spec),
§5 (three residual risks: pre-governance `call_id`/`streamSid` forgery, silent format-mismatch
corrupting barge-in math, `mark`-vs-real-playout desync — none resolved without a live Twilio leg).

**T1 seam it depends on.** Nothing new beyond what item 5 already needs generically: the same
`PlaneRouteSpec` one-shot pass for the webhook + the same WS-accept arrival kind for the media socket
(§5 below) — Twilio adds no new T1 primitive, only a new envelope sitting between the WS-accept route
and `TelephonyProxy::run`'s already-generic `client_in`/`client_out` (`t2-twilio.md` §4 seam table).

**Classification: DEFERRABLE (post-1.6.0).** `plane4-duplex-session-1.6.0-plan.md`'s T2 section names
"both topologies" as browser-WebRTC + WS-bridge (`:387,396`) and never names Twilio or telephony as a
1.6.0 deliverable at all — the generic `TelephonyProxy` exists because it is the natural third leg of
the same governed core, not because 1.6.0's DoD requires a live phone call. The DoD's own text
(`:429-436`) is satisfiable by Topology A (WS bridge) + Topology B (browser) alone. Confirmed genuinely
out of scope by the plan doc's silence, not just by absence in the tree — this is the honest "not
everything here is 1.6.0" item the task asked to call out.

---

## 4. The real ToolExecutor registry + real Pricing book

**What exists.** `ToolExecutor` (`runtime/tools.rs:14-24`) is a clean, dependency-inverted, `async`,
`Send + Sync` port — production-shaped already. `EchoToolExecutor` (`:27-36`) is the only impl: it
echoes `(name, arguments)` back as JSON, proving correlation but executing nothing. `Pricing`
(`runtime/metering.rs:84-95`) is a five-field nanodollar rate struct (`audio_in`/`audio_out`/`text_in`/
`text_out`/`cached`), already the right SHAPE to price `IrDuplexUsage`'s per-token-class extraction —
but `build_runtime_with_metering` (`runtime/mod.rs:123-138`) constructs it all-zero (`:130-136`), and
binds `EchoToolExecutor` (`:129`), UNCONDITIONALLY in both the dev (`build_runtime`) and prod
(`build_runtime_hosted`) paths — the doc comment on `build_runtime` (`:87-93`) is explicit that this is
the honest interim, not an oversight: deriving either from config needs the plane's config-section
grammar (`parse_section`/`default_section`), which is `None` today (`lib.rs:124-135`) and is item 5's
concern, not this one's.

**Net-new — the least-designed of the five (no existing playbook covers it):**

1. **A real `ToolExecutor`.** Two shapes, not mutually exclusive: (a) a LOCAL registry — a
   `streams:`-config-declared map of tool name → handler (functions the operator wires directly, the
   `tools:` plane's own registry shape as precedent, though voice's `streams:` sub-grammar for it is
   undesigned), or (b) a FORWARDING executor that hands the correlated `(name, arguments)` to an
   already-governed cross-plane call — the obvious target being `busbar-mcp`'s own upstream tool-call
   path (`crates/busbar-mcp/src/mcp/upstream.rs`), which would make a voice-session tool call a
   governed MCP call under the hood. Neither is designed today; (b) is architecturally attractive
   (reuses an entire existing tool-execution moat instead of building a second one) but crosses a
   plane boundary voice does not otherwise cross (voice reaches only substrate/api per
   `plane4-duplex-session-1.6.0-plan.md:371-373`), so it needs its own neutrality review before being
   assumed safe.
2. **A real `Pricing` book, sourced from `rate_card:`-shaped config.** The existing LLM-plane
   precedent (`RateEntryCfg` — `input_utok`/`output_utok`/`cache_read_utok`/`cache_write_utok`,
   `crates/busbar-core/src/config/mod.rs:3684-3705`, and the ALL-OR-NOTHING validation discipline —
   absent `rate_card:` prices at zero, present requires every configured model to have an entry,
   `config.yaml:390-397`) is the shape to mirror for voice's five nanodollar fields, keyed by
   whatever the `streams:` grammar names as the priced unit (per-session? per-model-tier?
   undecided — this is new design, not a lift). Net-new: the `streams:`-side rate-card sub-grammar,
   its ALL-OR-NOTHING validation, and the fold from parsed config into a live `Pricing` value at
   `build_runtime`/`build_runtime_hosted` time.
3. **Threading both through `build_runtime`'s currently-ignored `_section` argument.** Both
   `build_runtime` (`:94-105`) and `build_runtime_hosted` (`:114-118`) ignore their `&dyn Any` config
   section today (the doc comment says so explicitly, `:87-93,111-112`) and call the same
   `build_runtime_with_metering` with hardcoded `EchoToolExecutor`+zero `Pricing`. Wiring a real
   registry/rate-card means this argument stops being ignored — a body change to an already-frozen
   signature, not an ABI change (the comment at `:92-93` calls this out as the deliberate reason the
   signature is real today even though the body ignores it).

**T1 seam it depends on.** The `streams:` config-section grammar (`parse_section`/`default_section`,
item 5 below) — both the tool registry and the rate card are read OUT of that section, so neither can
be built before item 5's grammar lands, only designed in parallel.

**Classification: split.** A real, non-zero `Pricing` book is arguably REQUIRED-adjacent — the DoD's
"budget hard-stops mid-session" clause (`plane4-duplex-session-1.6.0-plan.md:430`) is a real claim only
if the priced increments are non-zero; and an all-zero rate card is a live shipped diagnostic elsewhere
in the tree (`crates/busbar-substrate/src/diagnostics/mod.rs:3326-3340`, *"prices at ALL ZERO —
metered as free, uncapped"*) that voice's own dev default currently trips. But the DoD's LITERAL text
only requires the hard-stop MECHANISM to work (proven today by `LocalLease`/`HostLease` tests over
nonzero *estimate*/*cap* inputs, independent of per-token `Pricing`), so a real rate card is
**strongly recommended but not DoD-blocking**. A real `ToolExecutor` beyond echo is **DEFERRABLE**: the
DoD's "a mid-call tool answered server-side" clause (`:430`) is satisfiable by any executor that
answers server-side, including `EchoToolExecutor` — the DoD tests correlation and governance, not tool
usefulness, and no plan-doc text names a production tool registry as 1.6.0 scope.

---

## 5. The HTTP ingress routes `PLANE_DECL.routes` must mount

**What exists.** `PLANE_DECL.routes: None` (`lib.rs:113`) and every other surface/boot hook (`build`,
`hydrate`, `start`, `parse_section`, `default_section`, `admin_routes`) also `None`
(`lib.rs:106-135`) — only `build_runtime` is wired. The neutral seam itself is fully shipped and used
by other planes: `PlaneRouteSpec { path, method, auth, handler }` over a neutral `PlaneReqCtx`
(`crates/busbar-substrate/src/plane_routes.rs:47-79`), core-adapted without naming `Arc<AppHandle>`.

**This item is really two different seams, not one — the doc's own framing conflates them and that
conflation is the risk worth naming explicitly:**

1. **One-shot HTTP passes → `PlaneRouteSpec`.** The ephemeral mint (item 1), the SDP broker (item 2),
   and the Twilio TwiML webhook (item 3, if built) are ALL `Invoke`-shaped ordinary HTTP request/response
   passes — no duplex transport needed for the pass itself (`t2-webrtc.md:33-34`, `t2-twilio.md:39-40`
   both say this explicitly). These mount via `PLANE_DECL.routes` exactly as any other plane's HTTP
   surface does — genuinely net-new only in that `routes` is `None` today.
2. **WS-accept (browser sideband + telephony client leg) → NOT `PlaneRouteSpec`, an arrival kind.**
   `t2-runtime-session.md` §2.2 is explicit and load-bearing here: the `start` hook must register a
   **WS-upgrade arrival kind** (design §4.2) that populates `SessionScope`, "**NOT** an axum
   `on_upgrade` from a route, which would bypass the gauntlet" — because a raw route-level upgrade
   would hand off the socket before `run_gauntlet_session` reserves the lease/opens the durable handle,
   letting a session start ungoverned. `t2-runtime-session.md` §5 R3 flags the arrival payload itself
   as a `Box<dyn Any>` TypeId trap if it boxes a plane- or core-owned type instead of a
   substrate-owned newtype. This is `PLANE_DECL.start`'s job, not `PLANE_DECL.routes`'s.

**Net-new, concretely (superset of `t2-runtime-session.md` §4 + `t2-webrtc.md` §2 item 4):**
- `PLANE_DECL.routes` populated with the mint + SDP-broker `PlaneRouteSpec`s (+ Twilio's webhook, if
  built) — thin handlers over `PlaneReqCtx`.
- The WS-upgrade arrival kind (substrate-owned newtype payload) + `PLANE_DECL.start` registering it and,
  per accepted session, calling `run_gauntlet_session` (itself net-new, `t2-runtime-session.md:256-257`
  — `grep run_gauntlet_session` today hits only doc/comment text) then spawning `serve_messages` over
  the two `DuplexPlane` legs.
- `parse_section`/`default_section`/`build` for the `streams:` grammar (needed by item 4 too) —
  `m5-voice-boot.md` has a full worked design for this (`StreamsSection`, `PlaneCfg` impl, the
  boot-validate conformance leg).
- `hydrate` — boot-rehydrate durable session rows, A2A's `taskstore::restore_from_store` as precedent.

**T1 seam it depends on.** `PlaneRouteSpec`/`PlaneReqCtx` (shipped, `plane_routes.rs`) for the one-shot
passes; the (net-new) WS-upgrade arrival kind + `run_gauntlet_session` for the duplex accept; the
`streams:` config-grammar seam (`owned_config_sections`, `parse_section`) for `build`.

**Classification: REQUIRED for 1.6.0.** Without this, items 1–2 (the REQUIRED webrtc mint/broker) have
no HTTP door to be reached through, and Topology A/B cannot be driven end-to-end at all — `routes`/
`start` staying `None` is the reason the T2 DoD is currently unmet, not a separable nice-to-have. This
is the highest-leverage single piece of work among the five: it is the prerequisite for items 1, 2, and
half of item 4 (config-derived tools/pricing need `build`/`parse_section` from the same hook set).

---

## Summary — REQUIRED-for-1.6.0 vs deferrable

| # | Seam | REQUIRED for 1.6.0? | Why |
|---|---|---|---|
| 1 | `ek_` ephemeral mint (concrete `TokenMinter`, TTL clamp, Safety-Identifier) | **REQUIRED** | Topology B DoD clause literally names "keys never leaving the server" |
| 2 | SDP broker + `rtc_<call_id>` correlation | **REQUIRED** | No real Topology B without it; same DoD clause |
| 3 | Twilio envelope + TwiML webhook (live carrier) | **Deferrable** | Plan doc's T2 scope never names telephony/Twilio; DoD satisfiable by A+B alone |
| 4a | Real `Pricing` book from `rate_card`-shaped config | **Strongly recommended, not DoD-blocking** | Hard-stop *mechanism* is proven independent of nonzero per-token rates; all-zero rate card is a live diagnostic elsewhere in the tree |
| 4b | Real `ToolExecutor` beyond echo | **Deferrable** | DoD tests correlation/governance of a mid-call tool, not tool usefulness |
| 5 | `PLANE_DECL.routes`/`start`/`build`/`parse_section`/`hydrate` (one-shot routes + WS-accept arrival) | **REQUIRED** | Prerequisite door for items 1–2; without it neither topology is reachable end-to-end |

## Top 3 risks

1. **Conflating the two route seams in §5 (`PlaneRouteSpec` vs. the WS-accept arrival kind) and
   building the WS accept as a plain axum route-level `on_upgrade`.** That would let a session start
   before `run_gauntlet_session` reserves the lease/opens the durable handle — precisely the "governed
   session that starts ungoverned" failure `t2-runtime-session.md` R1 already flags as the CURRENT state
   of `begin_session` (it does not yet call `verify_destination` at all). This is the single easiest way
   to ship something that *looks* done (a WS handshake works) but silently violates the money/audit
   invariant.
2. **Building item 4's `ToolExecutor` as MCP-forwarding without a fresh neutrality pass.** Voice is
   scoped to reach only substrate/api, never another plane's crate
   (`plane4-duplex-session-1.6.0-plan.md:371-373`, the same rule that makes T3 "consume the substrate
   engine, never `busbar_a2a`," `:452-454`). A tool executor that calls into `busbar-mcp` directly would
   repeat exactly the mistake T1.8 exists to correct elsewhere in this same release.
3. **Twilio's format-mismatch and pre-governance forgery risks (`t2-twilio.md` §5 risks 1–2) landing
   anyway, on schedule pressure, without the fail-closed checks.** If item 3 does get pulled forward
   post-1.6.0, the two sharpest risks are non-optional: `start.mediaFormat` must REFUSE (not warn) on a
   non-`g711_ulaw` echo, or barge-in truncate math corrupts silently; and the envelope adapter must
   validate `call_id`/`streamSid` against the webhook-minted value BEFORE admitting bytes into
   `client_in`, or a guessed/replayed `wss://…/twilio/{call_id}` URL can inject audio into someone
   else's governed session.

**File:** `docs/design/playbook/prod-composition.md`
