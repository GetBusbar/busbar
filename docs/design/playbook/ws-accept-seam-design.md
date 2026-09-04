# WS-Accept Seam Design — a neutral, gauntlet-gated inbound-WebSocket arrival for busbar core/substrate

**Status:** design only. NO production code in this document.
**Scope:** the *inbound* WS-accept seam (Topology A client-WS bridge + telephony media WS). The
*egress* dial half already exists (`busbar_substrate::ingress::duplex_ws::dial` / the guarded dialer
under `runtime`) and is out of scope, as is browser-WebRTC (Topology B), which is one-shot HTTP
mint/SDP + an EGRESS provider dial and needs no inbound accept.
**Audience:** adversarial release audit. Every claim below cites `file:line` against the pinned tree.

---

## 0. The problem, verified against the tree

A plane's data-route handler is a neutral async fn over a `PlaneReqCtx`:

- `PlaneRouteFn = Arc<dyn Fn(PlaneReqCtx) -> PlaneRouteFuture + Send + Sync>`
  (`crates/busbar-substrate/src/plane_routes.rs:48`), stored in a
  `PlaneRouteSpec { path, method, auth, handler }` (`plane_routes.rs:53-65`).
- `PlaneReqCtx` (`plane_routes.rs:77-118`) carries `path`, `uri`, `method`, `headers`, `body`,
  `path_params`, resolved identity (`gov`/`principal`/`caller_principal`), the type-erased `engine`,
  the `host` seam, and the plane `slot`. **It carries no `WebSocketUpgrade` and no upgrade of any
  form.**
- The core router adapter `mount_plane_route` (`crates/busbar-core/src/router.rs:487-553`) builds
  `PlaneReqCtx` from HTTP extractors only — `State<Arc<AppHandle>>`, `RawPathParams`, `Uri`, the
  `Extension` identity, `HeaderMap`, and a **buffered** `Bytes` body (`router.rs:506-514`,
  assembled `router.rs:535-548`). A buffered-body extractor and a socket upgrade are mutually
  exclusive in axum (the body is consumed), so this adapter structurally cannot also extract an
  upgrade.

The gauntlet-safe acceptor already exists and is the thing that must be reached:
`serve_gauntlet(upgrade, req, gate, plane)` (`crates/busbar-substrate/src/ingress/duplex_ws.rs:146-158`),
built on `accept_gauntlet` (`duplex_ws.rs:121-137`), which runs
`run_gauntlet_session` (`crates/busbar-substrate/src/plane_host/mod.rs:281-286`) and only on `Ok`
calls `accept` → `upgrade.on_upgrade` (`duplex_ws.rs:82-91`, `duplex_ws.rs:135`). It **needs an
`axum::extract::ws::WebSocketUpgrade`** (`duplex_ws.rs:24,121,147`).

**No plane mounts a WS accept today.** Voice's `sideband_route`/`telephony_route`
(`crates/busbar-voice/src/mount.rs:398-407`) are `PlaneRouteSpec` handlers over `PlaneReqCtx`
(`mount.rs:221-258`) that funnel through `open_governed` → `begin_session`/`begin_telephony`
(`mount.rs:283-341`), which *do* run `run_gauntlet_session` (`crates/busbar-voice/src/topology/mod.rs:194`)
but then answer **`501 Not Implemented`** because there is no upgrade to accept — the live serving
leg "is composed by the deployment behind the plane's ports, not by this in-process structural
mount" (`mount.rs:321-326`). The gauntlet runs; the socket cannot.

The design docs prescribe the fix as a `PLANE_DECL.start`-registered **WS-upgrade arrival kind**,
explicitly **NOT** a route-level bare `on_upgrade` and **NOT** a `PlaneRouteSpec`:

- `docs/design/playbook/prod-composition.md:203-210` — "WS-accept … → NOT `PlaneRouteSpec`, an
  arrival kind … the `start` hook must register a WS-upgrade arrival kind … **NOT** an axum
  `on_upgrade` from a route, which would bypass the gauntlet … This is `PLANE_DECL.start`'s job, not
  `PLANE_DECL.routes`'s."
- `docs/design/playbook/t2-runtime-session.md:154-159,258-259` — same, plus "for each accepted
  session call `run_gauntlet_session`".
- `docs/design/plane4-seam-audit-D-abi.md:196-210,287-291` — the arrival **payload must be a
  substrate-owned newtype**, never a plane-boxed `Box<dyn Any>`, or the dual-compile witness fails at
  runtime with a `TypeId` mismatch.

---

## 1. Feature-gating decision (the crux) — with dep-graph evidence

### 1.1 What `axum/ws` actually pulls

`WebSocketUpgrade` is provided by axum's `ws` feature. In axum 0.8.9 that feature is **not free**:

```
# ~/.cargo/registry/.../axum-0.8.9/Cargo.toml  (lines 133-138)
ws = [
    "dep:tokio-tungstenite",   # line 136
    "dep:sha1",                # line 137
    "dep:base64",              # line 138
    ...
]
```

So enabling `axum/ws` on the `axum` node adds **tokio-tungstenite + sha1 + base64** to whatever
crate's dep graph turns it on. Cargo features are additive and unify per crate node across the build,
so turning `axum/ws` on *anywhere* in a build turns it on for the whole `axum` in that build.

Today `axum/ws` is enabled **only** under busbar-substrate's `runtime` feature
(`crates/busbar-substrate/Cargo.toml:192`: `runtime = ["dep:tokio-tungstenite", "dep:tokio-rustls",
"axum/ws"]`), which is OFF by default and forwarded only by `plane-voice`
(`busbar-substrate/Cargo.toml:208`: `plane-voice = ["runtime"]`) and, from core, by
`busbar-core/plane-voice = ["busbar-substrate/plane-voice"]` (`crates/busbar-core/Cargo.toml:172`).
The default/shipped/money-path build (`busbar-core/Cargo.toml:130`:
`default = ["auth-admin-tokens","hooks-ranking","plane-llm","plane-mcp","plane-a2a"]`) carries **no**
`runtime`, hence no `axum/ws`, hence no tokio-tungstenite. The substrate module that names
`WebSocketUpgrade` is itself gated: `#[cfg(feature = "runtime")] pub mod duplex_ws;`
(`crates/busbar-substrate/src/lib.rs:95-96`).

### 1.2 The three options, judged

**The hard constraint:** `PlaneReqCtx` (`plane_routes.rs:77`) and `mount_plane_route`
(`router.rs:487`) are **always compiled** — `pub mod plane_routes;` is ungated
(`busbar-substrate/src/lib.rs:143`) and `mount_plane_route` carries no `#[cfg]`. Anything they *name*
must resolve in the default build. Therefore any WS type they name forces `axum/ws` unconditionally.

- **(a) Enable `axum/ws` unconditionally in busbar-substrate AND busbar-core.**
  **REJECTED.** Dep-graph evidence (§1.1): this drags tokio-tungstenite + sha1 + base64 into the
  default build's `axum` node — into the LLM money path. It breaks the "a shipped build carries no WS
  edge" invariant the `runtime` feature exists to hold (`busbar-substrate/Cargo.toml:184-192`), it is
  a non-additive change to the default build's dependency closure (byte-identity of the compiled
  money path, and the deletion test that proves voice is strong-form deletable, both fail), and it
  makes voice's transport un-deletable because its edge is now welded into the always-on graph.

- **(b) Type-erase the upgrade as `Arc<dyn Any>` carried on the always-compiled `PlaneReqCtx`.**
  **REJECTED for the primary path** (kept only as the §8 fallback). It *would* let the always-compiled
  struct name no WS type — but it lands the socket-accept on `PlaneReqCtx`, i.e. on the
  `PLANE_DECL.routes` path the design docs explicitly forbid for WS
  (`prod-composition.md:203-210`). Worse, it recreates the **exact** dual-compile `TypeId` trap Audit
  D ranks as the sharpest hazard (`plane4-seam-audit-D-abi.md:196-210`): a `WebSocketUpgrade` boxed
  in core and downcast in a dual-compiled plane witness diverges on `TypeId` and fails at *runtime*,
  silently. And the buffered-body adapter still cannot produce an upgrade (§0), so `mount_plane_route`
  would need a WS-aware branch anyway — the erasure buys nothing the arrival kind doesn't buy more
  safely.

- **(c) A separate, feature-gated WS-arrival registration path.** **RECOMMENDED.** The WS type is
  named ONLY inside code compiled under the WS feature — a new `#[cfg(feature = "duplex-ws")]` module
  in busbar-core plus a `#[cfg(feature = "runtime")]` spec type in busbar-substrate (alongside the
  already-`runtime`-gated `duplex_ws`, `lib.rs:95-96`). The always-compiled `PlaneReqCtx` /
  `PlaneRouteSpec` / `mount_plane_route` are **untouched and name no WS type**. In the default build
  the module and `axum/ws` are both absent, so tokio-tungstenite stays out and the money-path dep
  closure is byte-identical. This is what the docs prescribe and what §2 details.

### 1.3 The neutral feature name

To keep the seam plane-neutral (constraint 2), gate the core WS-accept module on a **neutral** core
feature, `duplex-ws`, that forwards to substrate's neutral `runtime`:

```
# busbar-core/Cargo.toml (proposed, mirroring the existing forwards at :151-172)
duplex-ws  = ["busbar-substrate/runtime"]
plane-voice = ["busbar-substrate/plane-voice", "duplex-ws"]   # was: ["busbar-substrate/plane-voice"]
```

`plane-voice` gains `duplex-ws`, but `duplex-ws` names **no plane** — a future `plane-telephony` or
any other duplex plane turns on the same neutral capability. Neutrality holds: the WS-accept seam
names a transport capability, never voice.

---

## 2. The seam shape (types, registration site, and why)

The seam has three parts: a **substrate-owned arrival spec + payload newtype** (`runtime`-gated), a
**substrate-owned process registry** the `start` hook installs into (this part is *ungated* — it
stores boxed values and names no WS type), and a **feature-gated core mount** that drains the registry
and mounts real WS-accept routes. This mirrors the existing path-model arrival mechanism
(`crates/busbar-substrate/src/ingress/arrival.rs`: `install_path_ingress` `:173`, `path_ingress_for`
`:203`, `ArrivalHost` `:78`) so it reuses a proven, audited registration idiom.

### 2.1 Substrate side — the arrival spec and the newtype payload (`#[cfg(feature = "runtime")]`)

Add to the already-`runtime`-gated `duplex_ws` module (so it lives beside `serve_gauntlet`,
`duplex_ws.rs:146`, and names `WebSocketUpgrade` legally):

```
// #[cfg(feature = "runtime")], in busbar-substrate ingress::duplex_ws  (DESIGN — not code)

/// The substrate-owned newtype the upgrade rides on across the accept boundary — NEVER Box<dyn Any>.
/// Single-compiled in substrate, so its TypeId is identical in both dual-compiled core instances
/// (plane4-seam-audit-D-abi.md:196-210). Voice never boxes its own type here.
pub struct WsArrival {
    pub upgrade: axum::extract::ws::WebSocketUpgrade,
    /// The verbatim per-request facts the plane needs to build its GauntletRequest and its session:
    /// resolved identity, path captures, headers, uri. Sourced from the SAME extractors the non-WS
    /// adapter uses — but assembled by the WS-aware mount, not by mount_plane_route.
    pub gov: Option<busbar_api::PlaneRequestCtx>,
    pub principal: Option<busbar_api::AuthPrincipal>,
    pub caller_principal: Option<String>,
    pub path: String,
    pub uri: axum::http::Uri,
    pub headers: axum::http::HeaderMap,
    pub path_params: Vec<(String, String)>,
    pub host: std::sync::Arc<dyn crate::plane_host::EngineHost>,
    pub slot: std::sync::Arc<dyn std::any::Any + Send + Sync>,
}

/// One WS-accept ARRIVAL a plane declares: the exact path, the admission bar recorded verbatim in the
/// CoreRouteTable (identical shape to PlaneRouteSpec.auth, plane_routes.rs:59-62), and a NEUTRAL accept
/// fn that returns a finished axum Response. The accept fn MUST reach serve_gauntlet/accept_gauntlet
/// internally — it receives a WsArrival by value and hands the upgrade to serve_gauntlet; it never sees
/// a bare on_upgrade (that symbol lives only in accept, duplex_ws.rs:87, reached only through the
/// gauntlet sibling accept_gauntlet, duplex_ws.rs:135).
pub type WsAcceptFn = std::sync::Arc<dyn Fn(WsArrival) -> axum::response::Response + Send + Sync>;

pub struct WsArrivalSpec {
    pub path: String,
    pub auth: busbar_plugin::cold::http_endpoint::RouteAuth,
    pub accept: WsAcceptFn,
}
```

Note the accept fn returns `Response` **synchronously**: `serve_gauntlet` is sync (its gate is
`verify_destination`, sync — `plane_host/mod.rs:200-202,274-286`) and `upgrade.on_upgrade` returns the
101 response immediately while spawning the socket task (`duplex_ws.rs:87-91`). No async leg is needed
at the accept boundary, matching `run_gauntlet_session`'s sync signature (`plane_host/mod.rs:281`).

### 2.2 Substrate side — the registry (UNGATED; names no WS type)

The registry stores the arrivals a plane's `start` hook contributes and hands them to the core mount.
It can be ungated because it stores *opaque* values — but since `WsArrivalSpec` is `runtime`-gated,
the cleanest split is to make the registry itself `#[cfg(feature = "runtime")]` too (it has no reason
to exist without the transport). Model it on `arrival.rs`'s side-table (`install_path_ingress`
`:173-190`, `path_ingress_for` `:203`):

```
// #[cfg(feature = "runtime")], substrate  (DESIGN)
pub fn install_ws_arrivals(specs: Vec<WsArrivalSpec>);   // start hook calls this
pub fn take_ws_arrivals() -> Vec<WsArrivalSpec>;         // core mount drains it, once, at router build
```

### 2.3 Registration site — `PLANE_DECL.start`, NOT `routes`, NOT a `PlaneReqCtx` field

**Why `start` and not `routes`:** `PlaneDecl.routes` is
`fn(&dyn Any) -> Vec<PlaneRouteSpec>` (`crates/busbar-substrate/src/plane/registry.rs:281`) and its
handlers are driven by the always-compiled `mount_plane_route` over a buffered-body `PlaneReqCtx` —
the path that structurally cannot carry an upgrade (§0) and that the docs forbid for WS
(`prod-composition.md:210`). `PlaneDecl.start` is `Option<BootHook>` =
`fn(&dyn PlaneBootCtx) -> Result<(), String>` (`registry.rs:329,72`), runs once at boot **after
listeners are built** (`registry.rs:321-328`), and is the designated "arrival/accept mount"
(`t2-runtime-session.md:154-159`). The plane's `start` hook calls `install_ws_arrivals(...)` with its
`WsArrivalSpec`s (path + auth + a neutral accept fn closing over the plane's runtime slot).

**Why not a `PlaneReqCtx` field / a `PlaneRouteSpec` variant:** both are always-compiled types
(§1.2). Naming `WebSocketUpgrade` on either forces `axum/ws` unconditional (option a) or forces
`Arc<dyn Any>` erasure (option b, the `TypeId` trap). A separate `runtime`-gated spec type reached
via a registry keeps every always-compiled type WS-free — the whole point of option (c).

**Neutrality:** `WsArrivalSpec`/`WsAcceptFn`/`WsArrival` name only `axum`, `busbar_api`,
`busbar_plugin`, and this crate's own `EngineHost` — no plane token. Adding a plane is a new-crate-only
diff (a new `start` hook + accept fn), exactly as `routes`/`PlaneRouteSpec` already achieve for
non-WS.

---

## 3. The router-adapter change (busbar-core)

The always-compiled `mount_plane_route` (`router.rs:487-553`) is **not touched**. Instead, add a
sibling that runs only under the neutral WS feature:

```
// #[cfg(feature = "duplex-ws")]  in busbar-core::router  (DESIGN — not code)
fn mount_ws_arrivals(router: CoreRouter, handle: &Arc<state::AppHandle>) -> CoreRouter {
    let mut router = router;
    for spec in busbar_substrate::ingress::duplex_ws::take_ws_arrivals() {
        let WsArrivalSpec { path, auth, accept } = spec;
        // SAME CoreRouter::route call the non-WS adapter makes (router.rs:502), with the spec's own
        // (path, GET, auth) — so the CoreRouteTable row (path, method, RouteAuth) is byte-identical in
        // shape to a data route and the auth middleware enforces `auth` BEFORE the handler, exactly as
        // for PlaneRouteSpec (plane_routes.rs:59-62). Method is GET: a WS upgrade is an HTTP GET.
        router = router.route(path.clone(), RouteMethod::Get, auth, {
            let accept = accept.clone();
            let ctx_path = path.clone();
            move |upgrade: axum::extract::ws::WebSocketUpgrade,   // the WS-aware extractor
                  State(handle): State<Arc<state::AppHandle>>,
                  raw_params: RawPathParams,
                  uri: Uri,
                  gov: Option<Extension<busbar_api::PlaneRequestCtx>>,
                  principal: Option<Extension<busbar_api::AuthPrincipal>>,
                  headers: HeaderMap| {
                // Build WsArrival from the SAME sources mount_plane_route uses (router.rs:518-548),
                // minus the body (a WS GET carries none). Mint the host seam and read the slot exactly
                // as router.rs:533,547.
                let arrival = WsArrival { upgrade, gov, principal, caller_principal, path: ctx_path,
                                          uri, headers, path_params, host, slot };
                async move { accept(arrival) }   // accept() returns the finished Response
            }
        });
    }
    router
}
```

Key points for the audit:

- The **only** new axum extractor is `WebSocketUpgrade`, and it appears **only** inside a
  `#[cfg(feature = "duplex-ws")]` fn. The default build never compiles this and never names the type.
- The `CoreRouter::route(path, method, auth, …)` call is the **same** security-critical registration
  the non-WS adapter uses (`router.rs:502-514`), so the `CoreRouteTable` row and the auth middleware's
  pre-handler admission are identical in shape — the seam preserves the same posture invariant
  `plane_routes.rs:16-20` describes.
- Where is `mount_ws_arrivals` called? In the router builder, behind the same `#[cfg]`, after the
  plane data routes are mounted and after `start_planes` has run (so `install_ws_arrivals` has already
  populated the registry). The default build's builder has no such call — byte-identical assembly.
- The plane's **slot** must be resolvable at start time: the `start` hook closes the accept fn over
  the plane's runtime slot (`EngineHost::plane_slot`, the same slot `voice_routes` reads via
  `ctx.slot`, `mount.rs:360`), so the WS route reads plane state without a `PlaneReqCtx`.

---

## 4. How voice's sideband/telephony handlers use it via `serve_gauntlet`

Voice keeps its paths (`SIDEBAND_PATH = "/v1/realtime/sideband/{call_id}"`, `mount.rs:58`;
`TELEPHONY_PATH = "/v1/realtime/telephony/{call_id}"`, `mount.rs:62`) but moves their **WS legs** off
`PlaneRouteSpec` (`mount.rs:241-256`) and onto a `start` hook that installs `WsArrivalSpec`s. The
one-shot `ek_` mint and SDP-broker passes (`Ingress::Mint`/`Ingress::Sdp`, `mount.rs:266-268`) stay
exactly as they are — one-shot HTTP `PlaneRouteSpec`s (they are Topology B, no inbound WS, per
constraint 5).

Per accepted session, voice's accept fn:

1. Reads `arrival.gov` (the resolved caller, threaded by the auth layer that already ran because the
   route carries a real `RouteAuth`), `arrival.path_params` for `{call_id}` (as `serve` does today,
   `mount.rs:372-378`), and its slot for the `VoiceRuntime` (as `mount.rs:360`).
2. Builds the `GauntletRequest { gov, destination, correlation_id, charged_at, started }`
   (`plane_host/mod.rs:166-178`) exactly as `begin_session` does today
   (`crates/busbar-voice/src/topology/mod.rs:183-189`), with `destination` = the locked upstream model
   (`topology/mod.rs:178`).
3. Builds its `SessionGauntlet` gate (`topology/mod.rs:126-140`) — the `GauntletPlane` whose
   `verify_destination` refuses a denied model **before any charge** (`topology/mod.rs:127-138`).
4. Calls `serve_gauntlet(arrival.upgrade, req, Box::new(gate), duplex_plane)`
   (`duplex_ws.rs:146-158`). `serve_gauntlet` → `accept_gauntlet` (`duplex_ws.rs:155,121`) runs
   `run_gauntlet_session` (`duplex_ws.rs:131` → `plane_host/mod.rs:281-286` → `admit_open`
   `:237-247`) and: on `Err(refusal)` returns the plane's own finished refusal Response and **binds no
   socket, spawns no task, charges nothing** (`duplex_ws.rs:132-133`, header `:107-116`); on `Ok`
   accepts the upgrade (`duplex_ws.rs:135`) and drives the plane over the pump via `serve_messages`
   (`duplex_ws.rs:155-157`).

The `501` structural stub (`mount.rs:321-326`) disappears from the WS legs: the accept fn now returns
the real 101-switching upgrade on admit, or the gauntlet's refusal on refuse. `begin_session`'s
lease/durable-open reserve (the `SessionBudget` reserve, `mount.rs:290-318`) moves to happen **after**
`run_gauntlet_session` returns `Ok` and **before** the socket task pumps bytes — the plane's
"post-admit reserve/bind/open" the shared gate's contract mandates
(`plane_host/mod.rs:214-215,268-273`). Telephony uses the same accept fn with the `g711_ulaw` codec
config and `begin_telephony` carrier (`mount.rs:297-306`).

**Governance invariant (constraint 3), restated for the audit:** the gauntlet runs *before* the
socket upgrades because `serve_gauntlet` calls `run_gauntlet_session` and only on `Ok` reaches
`accept` → `upgrade.on_upgrade` (`duplex_ws.rs:131-136,87`). A bare `on_upgrade` is impossible on
this path: the accept fn receives only a `WsArrival` (§2.1) and the sole in-tree `on_upgrade`
(`duplex_ws.rs:87`) is private to `accept`, reached only through the gauntlet sibling `accept_gauntlet`
(`duplex_ws.rs:135`). The plane never holds a `WebSocketUpgrade` outside the accept fn and never sees
`accept` directly. The verify-strictly-before-charge order lives once in `admit_open`
(`plane_host/mod.rs:236-247`), shared by the one-shot and session siblings so a refactor cannot drift
them (`plane_host/mod.rs:266-273`).

---

## 5. Byte-identity + deletability argument

**Byte-identity of the money path (constraint 4):**

- The default build (`busbar-core/Cargo.toml:130`) enables neither `runtime`/`duplex-ws` nor
  `plane-voice`, so `axum/ws` is off → no tokio-tungstenite/sha1/base64 in the `axum` node (§1.1).
  The compiled dependency closure of the LLM money path is unchanged.
- `PlaneReqCtx` (`plane_routes.rs:77-118`), `PlaneRouteSpec` (`plane_routes.rs:53-65`), and
  `mount_plane_route` (`router.rs:487-553`) are **not edited** — all existing non-WS plane routes
  (every MCP/A2A route, and voice's `ek_` mint + SDP `PlaneRouteSpec`s, `mount.rs:229-240`) mount
  through the identical `CoreRouter::route` call and record byte-identical `CoreRouteTable` rows.
- The new `mount_ws_arrivals` (`router.rs`, `#[cfg(feature="duplex-ws")]`) and its builder call site
  are absent from the default build, so the router builder emits the same routes in the same order.
- The LLM catch-all/dispatch path (`router.rs:460-472`) is untouched.

**Deletability (constraint 2):** voice stays strong-form deletable because the WS-accept seam names
**no plane**. The seam is: a neutral `runtime`-gated spec/registry in substrate, a neutral
`duplex-ws`-gated mount in core, and a neutral `duplex-ws` feature that forwards to
`substrate/runtime`. Deleting the `busbar-voice` crate and its `plane-voice` forward removes the only
`WsArrivalSpec` producer; `install_ws_arrivals` is simply never called, `take_ws_arrivals` returns
empty, and `mount_ws_arrivals` mounts nothing. Nothing in substrate or core names voice. The
"adding a plane = new-crate-only diff" property holds in both directions.

---

## 6. The 2–3 sharpest risks, with mitigations

**R1 [HIGH] — the dual-compile `TypeId` trap on the arrival payload.** Audit D's rank-1 hazard
(`plane4-seam-audit-D-abi.md:196-210,287-291`): if the upgraded-socket handle / arrival payload rides
`ArrivalCtx(Box<dyn Any>)` (`arrival.rs:35`) or any plane-boxed `Box<dyn Any>`, a plane that boxes its
own type in one core compile and downcasts in the dual-compiled witness fails at **runtime**,
silently. *Mitigation (baked into §2.1):* `WsArrival` is a **substrate-owned, single-compiled
newtype** carrying `WebSocketUpgrade` by value — it is never `Box<dyn Any>`, so there is no downcast
and no `TypeId` to diverge. The only `Arc<dyn Any>` on it (`slot`) is the *already-proven-safe*
plane-slot crossing (`plane4-seam-audit-D-abi.md:153-161`), recovered via the same
`EngineHost::plane_slot` idiom voice already uses (`mount.rs:360`). A witness that constructs
`WsArrival` under dual compile and asserts the accept fn runs pins this.

**R2 [HIGH] — a route-level bare `on_upgrade` re-appears and bypasses the gauntlet.** The whole
governance invariant (constraint 3) rests on the accept fn never obtaining a raw upgrade to call
`on_upgrade` on directly, which would bind the socket before `verify_destination`. *Mitigation:*
`WsAcceptFn` receives `WsArrival` (which owns the upgrade) but the ONLY way to consume it into a live
socket is `serve_gauntlet`/`accept_gauntlet` (`duplex_ws.rs:146,121`); `accept` (`duplex_ws.rs:82`,
the sole `on_upgrade` caller `:87`) is reached only through `accept_gauntlet` (`:135`). Keep `accept`
crate-private to `duplex_ws` (it already is — no `pub` re-export outside the module) and add a
grep-gate / clippy-style lint denying `on_upgrade` outside `duplex_ws.rs`. A test asserts a refused
destination returns the refusal Response and spawns **zero** socket tasks (the `duplex_ws.rs:132-133`
path).

**R3 [MEDIUM] — feature drift welds the WS edge into the money path.** If a future edit adds
`axum/ws` under a default-on feature, or makes `mount_plane_route`/`PlaneReqCtx` name a WS type,
byte-identity and deletability silently break (option a's failure mode, §1.2). *Mitigation:* a
dependency-closure test asserting the default build's lockfile/`cargo tree` contains **no**
`tokio-tungstenite` (mirroring the existing "shipped build carries no WS edge" intent,
`busbar-substrate/Cargo.toml:184-192`); and a compile-fence test that `busbar-substrate` with
`--no-default-features` (no `runtime`) does not reference `duplex_ws`. Both fail loudly on drift.

---

## 7. Where each piece lands (summary map)

| Piece | Crate / file | Gate |
|---|---|---|
| `WsArrival` newtype, `WsAcceptFn`, `WsArrivalSpec` | `busbar-substrate/src/ingress/duplex_ws.rs` (beside `serve_gauntlet:146`) | `#[cfg(feature="runtime")]` |
| `install_ws_arrivals` / `take_ws_arrivals` registry | `busbar-substrate/src/ingress/duplex_ws.rs` (idiom of `arrival.rs:173,203`) | `#[cfg(feature="runtime")]` |
| `mount_ws_arrivals` + its builder call site | `busbar-core/src/router.rs` (sibling of `mount_plane_route:487`) | `#[cfg(feature="duplex-ws")]` |
| `duplex-ws` feature + `plane-voice` forward edit | `busbar-core/Cargo.toml` (near `:151-172`) | n/a |
| voice `start` hook installing `WsArrivalSpec`s + accept fn | `busbar-voice/src/mount.rs` (replaces WS legs `:241-256`) | `runtime` (voice's own) |
| Always-compiled `PlaneReqCtx`/`PlaneRouteSpec`/`mount_plane_route` | `plane_routes.rs`, `router.rs:487` | **UNCHANGED** |

---

## 8. Minimal fallback (if the full arrival-kind is too big for 1.6.0)

The smallest seam that unblocks voice's WS legs while preserving the governance invariant and
money-path byte-identity, deferring the neutral registry:

**A single feature-gated WS-route mount, still calling `serve_gauntlet`, no registry.** Add one
`#[cfg(feature="duplex-ws")]` fn in `busbar-core::router` that mounts a fixed pair of WS-accept routes
whose *paths and accept fns come from a `runtime`-gated `PlaneDecl` field* — e.g. a new
`Option<fn(&dyn Any) -> Vec<WsArrivalSpec>>` field on `PlaneDecl` (mirroring `routes:` at
`registry.rs:281`) read only inside the `#[cfg]` mount. This drops the `start`-hook/registry
indirection (§2.2–2.3) but keeps: (i) the substrate-owned `WsArrival` newtype (R1 mitigation intact),
(ii) `serve_gauntlet` as the only accept path (R2 intact), (iii) `axum/ws` gated off the default build
(byte-identity + deletability intact), and (iv) neutrality (the field is typed over neutral
`WsArrivalSpec`, names no plane). It is a strictly smaller diff — one new `#[cfg]` `PlaneDecl` field +
one `#[cfg]` mount fn + voice returning the specs — and it forecloses nothing: the `start`-hook
registry can replace the field later without touching the accept fn, the newtype, or `serve_gauntlet`.

**What the fallback gives up:** boot-time dynamism (arrivals fixed at router-build, like `routes:`
already are) and the exact `PLANE_DECL.start` registration the design docs name
(`prod-composition.md:210`) — acceptable for 1.6.0 because voice's WS paths are static and known at
build. **What it must NOT give up, and does not:** the `Box<dyn Any>` payload (would reopen R1) and
the bare `on_upgrade` (would reopen R2). If either of those is proposed to shrink the diff further,
reject it — they are the two invariants this whole seam exists to hold.

The type-erased `Arc<dyn Any>` upgrade on `PlaneReqCtx` (option b, §1.2) is **not** an acceptable
fallback: it lands WS on the forbidden `routes` path and reopens the R1 `TypeId` trap.
