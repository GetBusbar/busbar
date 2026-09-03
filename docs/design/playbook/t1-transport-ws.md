# T1 — `Transport::WebSocket` substrate seam (ingress-upgrade + egress-dialer), concretely

Status: **DESIGN / SEAM MAP. Read-only on code.** Base = this worktree's HEAD
`ae85025d` (`integration/config-seam-stage1-rebased`), which **already contains** commit
`2ac0bf26` ("arm `Transport::WebSocket` … acceptor + guarded dialer; route voice provider WSS
through it"). Every `file:line` below is at that HEAD.

> **Read this first — the seam is mostly BUILT, not greenfield.** The adversarial audit
> `docs/design/plane4-seam-audit-A-transport.md` was written at `e393b9e6`, *before* `2ac0bf26`
> landed, so it describes the acceptor/dialer as net-new and greenfield ("zero
> `WebSocketUpgrade`/`on_upgrade`/`tungstenite` in the tree"). On THIS branch that is **stale**:
> the neutral acceptor, the guarded dialer, the message pump, the `WebSocket` variant and the
> `Duplex` wire all exist and are armed under the `runtime` feature. What remains net-new is the
> *gauntlet-bound arrival kind*, the *config-grammar selection*, and the *D2 metering wiring* —
> §2 draws the line precisely.

---

## 1. The exact neutral types & signatures (crate/module named)

All three legs live in `busbar-substrate` and are armed under its `runtime` feature
(`crates/busbar-substrate/Cargo.toml:192` → `runtime = ["dep:tokio-tungstenite",
"dep:tokio-rustls", "axum/ws"]`). No voice/OpenAI vocabulary appears in any signature.

### 1.1 The axis selector — `busbar_substrate::transport`

`crates/busbar-substrate/src/transport.rs`

```rust
pub enum Transport { Http, JsonRpc, HttpJson, Grpc, Stdio, WebSocket }   // :97-155, WebSocket at :154

#[cfg(any(feature = "dispatch", feature = "runtime"))]
pub enum UpstreamWireKind { StreamableHttp, Stdio, Duplex }              // :167-179, Duplex at :172-178

impl Transport {
    pub fn name(self) -> &'static str;                                   // :209-221; WebSocket => "websocket" :219
    #[cfg(any(feature = "dispatch", feature = "runtime"))]
    pub fn upstream_wire(self) -> Option<UpstreamWireKind>;              // :244-255; WebSocket => Some(Duplex) :252
}
```

The axis answers "which channel" ONCE and hands back a **neutral discriminant**
(`UpstreamWireKind::Duplex`), never a plane wire type — the same discipline `upstream_wire`
already applied for the MCP legs (`transport.rs:223-239`). The gate widened from
`feature = "dispatch"` to `any(dispatch, runtime)` (`:165`, `:243`) so the duplex plane's dialer
resolves the axis with the MCP client leg compiled out.

### 1.2 Ingress WS upgrade — `busbar_substrate::ingress::duplex_ws`

`crates/busbar-substrate/src/ingress/duplex_ws.rs` (module gate `runtime`, `lib.rs:95-96`)

```rust
// axum upgrade extractor → neutral (frame-stream, frame-sink) over two mpsc channels.
pub fn channel(socket: axum::extract::ws::WebSocket)
    -> (UnboundedReceiver<Vec<u8>>, UnboundedSender<Vec<u8>>);           // :36-75

// The upgrade stays at the boundary: hand the plane the split socket once the handshake completes.
pub fn accept<F, Fut>(upgrade: WebSocketUpgrade, on_socket: F) -> axum::response::Response
where F: FnOnce(UnboundedReceiver<Vec<u8>>, UnboundedSender<Vec<u8>>) -> Fut + Send + 'static,
      Fut: Future<Output = ()> + Send + 'static;                        // :81-90

// One-call path: accept the upgrade and drive the pump for a plane that IS its socket.
pub fn serve<P: DuplexPlane>(upgrade: WebSocketUpgrade, plane: Arc<P>) -> Response;  // :97-104
```

Text and binary WS messages both surface as `Vec<u8>` frames; control frames (ping/pong/close)
are answered by the WS layer and never surface (`:44-59`). Outbound frame → one **binary** WS
message (`:66-68`). The `axum::extract::ws::{WebSocket, WebSocketUpgrade, Message}` import
(`:24`) is the only place the HTTP handshake is named — it never reaches the pump.

### 1.3 Egress dialer — `busbar_substrate::egress::duplex_ws` (guarded WSS client)

`crates/busbar-substrate/src/egress/duplex_ws.rs` (module gate `runtime`, `egress/mod.rs:31`)

```rust
pub enum DialError { Url(String), Guard(GuardRefusal), Connect(String), Tls(String), Handshake(String) } // :34-47

pub async fn dial(url: &str, policy: GuardPolicy)
    -> Result<( impl Stream<Item = Vec<u8>> + Unpin,
                impl Sink<Vec<u8>>  + Unpin + Send + 'static ), DialError>;  // :142-186
```

Internal, all neutral: `split_ws_url` — a **strict** `ws(s)://` recogniser, refuses userinfo
`@` (`:73-109`); `tls_config` — explicit `ring` provider + webpki roots, the same posture the
HTTP egress engine builds (never an ambient `builder()`) (`:115-130`); `split_messages` — maps
`WebSocketStream<S>` to the neutral `(Vec<u8>-sink, Vec<u8>-stream)` the pump consumes
(`:192-239`).

**The guard order is load-bearing** (`:152-186`): `net_guard::resolve_and_pin_async`
(`net_guard.rs:753`, one resolution, every answer judged, survivor pinned) **FIRST** → TCP to
`pinned.socket_addr()` (`net_guard.rs:516`) → TLS with SNI = URL host → WS handshake over the
already-guarded stream via `tokio_tungstenite::client_async` (`:174`, `:180`). The
`tokio-tungstenite` `connect` feature (which would re-resolve the name) is deliberately OFF
(`Cargo.toml:122-126`, module header `:13-22`), so this is the **only door** and no socket opens
to anything the guard did not pin.

### 1.4 The pump the two legs feed — `busbar_substrate::ingress::byte_duplex`

`crates/busbar-substrate/src/ingress/byte_duplex.rs` — the neutral, protocol-blind full-duplex
pump both legs hand their `(Stream<Vec<u8>>, Sink<Vec<u8>>)` pair to:

```rust
pub struct CallRef(pub u64);                                            // :56 (neutral correlation key, not MCP id_key)
pub trait DuplexPlane: Send + Sync + 'static {                         // :81-92
    fn classify(&self, frame: &[u8]) -> Option<CallRef>;               // :86 — plane owns "what a reply is"
    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle);// :91
}
pub struct DuplexHandle { .. }                                          // :99  emit :109 / mint :116 / issue :127
pub async fn serve_messages<St, Sk, P>(stream: St, sink: Sk, plane: Arc<P>);  // :318-334 (WS/message path)
pub async fn serve<R, W, P>(reader: R, writer: W, plane: Arc<P>);      // :276-306 (byte/newline path, MCP-stdio class)
```

Both legs call `serve_messages`: WS ingress via `duplex_ws::serve` (`ingress/duplex_ws.rs:101`);
WS egress by the plane feeding `dial`'s returned pair straight in. The correlation table keys on
substrate-owned `CallRef` (a bare `u64`, `:48-68`), **not** MCP's JSON-RPC `id_key` — the audit's
Seam-3 neutrality requirement is already satisfied here.

### 1.5 How a plane selects the transport (the two-enum pattern to copy)

A plane never branches on the axis; it maps its **operator config grammar** to the engine axis
through a per-plane `axis()` method — the shipped example is MCP:
`crates/busbar-mcp/src/mcp/config.rs:864` (config-grammar `enum Transport { StreamableHttp,
Stdio }`) → `axis()` (`:900-905`) → `busbar_substrate::transport::Transport`. The two enums are
deliberately distinct (`config.rs:896-905`): the config one is the frozen operator word, the
substrate one is the engine's reshapeable dispatch axis.

The duplex plane's live selection is `crates/busbar-voice/src/topology/mod.rs:49-65`
(`dial_provider`): it selects `Transport::WebSocket`, resolves `upstream_wire()` to
`UpstreamWireKind::Duplex` (a `let-else` refusal, not a panic, on mis-selection, `:61-63`), then
calls `duplex_ws::dial`. Proven armed end-to-end by
`crates/busbar-substrate/src/egress/tests/duplex_ws_tests.rs:82-113`
(`websocket_transport_is_armed_by_a_real_dialer`).

---

## 2. What already exists vs net-new (the honest line)

| Piece | Status at HEAD `ae85025d` | Cite |
|---|---|---|
| `Transport::WebSocket` variant + `name()` + `ALL` | **EXISTS** | `transport.rs:154,198,219` |
| `UpstreamWireKind::Duplex` + `upstream_wire` arm | **EXISTS** | `transport.rs:172-178,252` |
| Neutral WS ingress acceptor (`accept`/`serve`/`channel`) | **EXISTS** | `ingress/duplex_ws.rs:36-104` |
| Guarded WSS egress dialer (`dial`, guard-first) | **EXISTS** | `egress/duplex_ws.rs:142-186` |
| Neutral message pump (`serve_messages`, `CallRef`) | **EXISTS** | `byte_duplex.rs:318-334,56` |
| Plane selection (`Transport::WebSocket` → `Duplex` → dial) | **EXISTS** (voice) | `voice/topology/mod.rs:49-65` |
| `runtime` feature wiring (tungstenite/tokio-rustls/axum ws) | **EXISTS** | `Cargo.toml:192` |
| **Gauntlet-bound WS ARRIVAL KIND** (`run_gauntlet` at open + `SessionScope` populate) | **NET-NEW** | see below |
| **Config-grammar selection** for the WS leg (`streams:` grammar → url + `Transport::WebSocket`) | **NET-NEW** | `voice/lib.rs:96,124` |
| **D2 metering-lease wiring** on the byte path (`cost_reserve`/`cost_settle` slots, minor→19) | **NET-NEW** | audit §Seam-2(c) |

**The single most important net-new correction:** the acceptor at `ingress/duplex_ws.rs:81-90`
is a bare `WebSocketUpgrade::on_upgrade` (`:86`) — exactly the shape the design's §4.2 flags as
the *anti-pattern* if a route handler smuggles the socket out **bypassing the gauntlet, the lease,
and the audit chain**. The acceptor as shipped is neutral and correct, but it does **not itself**
run `run_gauntlet` or populate `SessionScope`. The net-new arrival kind must sit *in front* of
`serve`/`accept`: open-pass gauntlet → mint `SessionScope` → *then* hand the socket to the pump.
Nothing structural forces that ordering today; a plane that calls `duplex_ws::serve` directly from
a `PlaneRouteFn` gets a live ungoverned socket. This is R1 in §6.

---

## 3. How it stays plane-neutral (no voice/openai tokens in core/substrate)

- **Every substrate signature speaks `Vec<u8>`, `CallRef`, `Transport`, `GuardPolicy`** — no
  "voice", "audio", "openai", "realtime", "session", "gemini" noun appears in `transport.rs`,
  `ingress/duplex_ws.rs`, `egress/duplex_ws.rs`, or `byte_duplex.rs`. `name()` returns
  `"websocket"` (`transport.rs:219`) — a neutral transport noun, same tier as `"stdio"` (`:218`),
  and per audit §6 it is deliberately OFF the `structure-lint.sh` neutrality ban list.
- **The axis hands back a neutral discriminant, not a plane wire type** (`UpstreamWireKind::Duplex`,
  `transport.rs:172-178`); the plane maps it to its own machinery, exactly as MCP maps
  `StreamableHttp`/`Stdio` to `&dyn McpWire` on its own side (`:157-161`).
- **The pump owns framing/lock/correlation/lifecycle and nothing a plane means** — `classify` and
  `handle` are the plane's only two callbacks (`byte_duplex.rs:26-38,81-92`); the pump reads no
  frame content and attaches no wire meaning to `CallRef`.
- **`structure-lint.sh` forbids the agnostic core from branching on the transport axis**
  (`scripts/structure-lint.sh:1709-1715`); the one legitimate match stays in `upstream_wire`
  (`transport.rs:223-239`), and the plane's config→axis map stays in the plane
  (`mcp/config.rs:900-905`).
- **Voice keeps its own nouns in `busbar-voice`** (plan §7.2). `busbar-voice/src/lib.rs:84`
  declares the plane with `config_section: "streams"` (`:96`) — a neutral duplex noun — while the
  plane *key* is `"voice"`; core names no `streams`/`voice` parse target (skeleton `parse_section:
  None`, `:124`).

---

## 4. Collision surface with config-seam Stage A

This worktree IS the config-seam work (`integration/config-seam-stage1-rebased`; S1 plane-owned
config registry `38050555`, S2a neutral raw-rate-view `3005149c`, Stage-C voice `voice:`→`streams:`
noun `ae85025d`). Overlap is **real and concentrated at two points**:

1. **The `PlaneDecl` config triad is the exact seam T1's selection must ride.** T1's config
   selection (the `streams:` grammar that will name the upstream `wss://` url and select
   `Transport::WebSocket`) has no home until config-seam lands the opaque/`parse_section` path.
   Voice's decl carries `config_section: "streams"` but `parse_section: None` /
   `default_section: None` (`voice/lib.rs:96,124,135`) — the grammar is deferred to config-seam's
   third config-shape (`foundation-abi-config.md` Move D, `PlaneDecl.opaque_config`). **T1 must not
   author a competing `streams:` parse path; it consumes the one config-seam builds.** Coordinate
   ordering: config-seam Move D before T1's config selection.

2. **The D2 metering ABI slots are minted by the SAME generated-FFI surface config-seam Move A
   reshapes.** T1's money path (§5) rides `cost_reserve`/`cost_settle` as **trailing `Option`
   slots, airlock minor 18→19** (audit §Seam-2, `busbar-plugin/src/hot/host.rs:534-536`,
   `ABI_MINOR = 18` at `lib.rs:72`). Config-seam Move A (`foundation-abi-config.md §3`) turns that
   hand-authored vtable into a generated one with `#[host_abi(slot = "cost_settle", minor = 19)]`.
   **Both efforts bump the same minor and touch the same host surface** — a merge-order collision,
   not a logic one. Land the ABI generator (Move A) before appending the D2 slots so the slots are
   *generated*, not hand-shimmed into a surface that is about to be regenerated.

3. **Non-colliding, worth stating:** the acceptor/dialer/pump (§1.2–1.4) touch **no** config or
   ABI surface — they are pure substrate transport code behind `runtime`. Config-seam can move
   freely around them. The collision is entirely at the *selection* (config) and *metering* (ABI)
   edges, not the byte path.

---

## 5. Money-path / byte-identity touchpoints

**Money path (fail-closed is the marquee guarantee):**
- **No lease ⇒ no session.** `voice/topology/mod.rs:119-125` (`begin_session`): `open_lease(...)
  .ok_or(StartError::BudgetRefused)?` opens the D2 metering lease *before* the durable handle and
  *before any frame flows*; a refused/zero budget fails closed (`StartError::BudgetRefused`,
  `:83-87`). `SessionBudget { estimate_nanos, fee_nanos, cap_nanos }` (`:71-79`) is
  plane-priced nanodollars — **core prices nothing.**
- **The lease reserve/settle ABI** is the D2 append (audit §Seam-2): shipped
  `CostHold::reserve(estimate: CostAmount, fee: CostAmount)` (`busbar-core/src/plane/cost.rs:312`)
  takes an already-computed `CostAmount`, and `Magnitude.unit: &'static str` (`cost.rs:271`) is
  **not** FFI-POD — the `Magnitude → CostAmount` rate conversion has no owner yet. Decide owner
  before the minor-19 freeze (one-way door).
- **Post-hoc metering cannot hard-stop a live stream** (plan §3.3): the lease debits per frame but
  a duplex stream is already flowing, so budget-exhaustion is a *close*, not a *pre-refusal* — the
  fail-closed guarantee lives at session-open, not mid-stream.

**Byte identity (Layer-3 media is a VERBATIM identity IR, plan §2.4):**
- Frames cross the pump as `Vec<u8>` and it **parses none** (`byte_duplex.rs:8-38`). The message
  sink adds **no terminator** — "the frame IS one whole message" (`MessageSink::send`, `:200-206`)
  — so an audio frame in is byte-identical out.
- WS message-kind flattening is the one transform to audit for identity: both ingress
  (`ingress/duplex_ws.rs:44-59`) and egress (`egress/duplex_ws.rs:208-224`) map **text→bytes** and
  **binary→bytes** and re-emit outbound as **binary** (`ingress:66-68`, `egress:231`). A peer that
  sent *text* receives *binary* on the return leg — semantically identical payload, different WS
  opcode. For `g711_ulaw` telephony pass-through (binary both ways, plan §5.2 Topology B) this is
  a true identity; for a text-framed provider it is a re-frame to audit.
- The dialer verbatim round-trip is asserted by test (`duplex_ws_tests.rs:79`, *"the frame crossed
  both directions verbatim"*).

---

## 6. Top residual risks for an adversarial audit to attack

**R1 — [HIGH] The acceptor's bare `on_upgrade` can bypass the gauntlet.**
`ingress/duplex_ws.rs:86` calls `upgrade.on_upgrade(...)` and hands the socket to a plane closure
with **nothing structurally forcing `run_gauntlet` / `SessionScope` / lease first**. The net-new
arrival kind (§2) must gate the upgrade behind the open-pass, and there is no compile-time guard
that a plane didn't call `serve`/`accept` directly from a route handler — exactly the anti-pattern
plan §4.2 warns of. Attack: a `PlaneRouteFn` returning `duplex_ws::serve(...)` → live ungoverned
socket, no lease, no audit chain.

**R2 — [HIGH] `SessionScope` has no arena / no `Drop`, so nothing reclaims the pooled upstream
socket on close/panic/cancel.** `SessionScope {}` is an empty `#[non_exhaustive]` struct
(`busbar-substrate/src/plane_host/scope.rs:364-373`) — the RAII `register_pipe` reclaim lives on
`DispatchScope` (`:302-311`), not here. The egress `dial` spawns two detached tokio tasks
(`egress/duplex_ws.rs:207,229`) with no scope-owned reclaim handle. Attack: open N sessions, drop
each mid-stream → leaked upstream WS sockets + reader/writer tasks, unbounded. The first
`SessionScope` field set is a one-way door (plan T1.4) and must own an arena, not bare `PipeId`s.

**R3 — [HIGH] SSRF/guard invariants of the dialer are the whole security surface — attack the
recogniser and the "guard-first" ordering.** `split_ws_url` is a hand-written recogniser
(`egress/duplex_ws.rs:73-109`); the safety proof is that `resolve_and_pin_async` runs before any
socket opens and the `tokio-tungstenite` `connect` feature is OFF (no second resolution). Attack
surface: (a) a URL that parses to a different host than the one SNI/pin uses (IPv6-bracket / port /
userinfo edge cases, `:87-104`); (b) any code path that reaches `client_async` without the pin
(regression if the `connect` feature is ever re-enabled, `Cargo.toml:122`); (c) `ws://` plaintext
admitted when `policy.allow_plaintext`/`allow_private` is looser than intended
(`net_guard.rs:309-340`) — a plaintext provider leg leaks the credential to anyone on-path. The
guard is the reason a socket exists at all (`DialError::Guard` header, `:38-40`); byte-identity of
this ordering is the money-and-secrets invariant.

---

## Summary (≤8 lines)

- The T1 WS seam is **mostly BUILT** on this branch (`2ac0bf26`): neutral axis
  (`Transport::WebSocket`→`UpstreamWireKind::Duplex`), ingress acceptor
  (`ingress::duplex_ws`), guard-first WSS dialer (`egress::duplex_ws`), and the message pump
  (`byte_duplex::serve_messages`) all exist and are armed under the `runtime` feature.
- Neutral signatures are `Vec<u8>`/`CallRef`/`Transport`/`GuardPolicy` only — no voice/openai
  noun crosses into core/substrate; the plane selects via a config-`enum` → `axis()` map it owns.
- **Net-new** remaining: the gauntlet-bound arrival kind (open-pass + `SessionScope`), the
  config-grammar `streams:` selection, and the D2 metering-lease ABI slots (minor 18→19).
- **Config-seam collision** is at two edges only — `PlaneDecl` config triad (T1 must consume
  config-seam's `parse_section`/opaque path, not author its own) and the shared generated-FFI /
  minor-19 ABI surface (land Move A's generator before appending D2 slots).
- Money path fails closed at session-open (`begin_session` `open_lease().ok_or(BudgetRefused)`);
  byte path is a verbatim `Vec<u8>` identity except the text→binary WS re-frame on return.

File: `docs/design/playbook/t1-transport-ws.md`

**Top 3 risks:** (R1) acceptor's bare `on_upgrade` can hand a plane a live socket that bypasses
the gauntlet/lease/audit; (R2) `SessionScope` has no arena/`Drop`, so dropped sessions leak the
pooled upstream socket + its two detached tasks; (R3) the dialer's hand-written `split_ws_url` +
"guard-first, `connect`-feature-off" ordering is the entire SSRF surface — attack the recogniser's
host/pin agreement and any path to `client_async` without the pin.
</content>
</invoke>
