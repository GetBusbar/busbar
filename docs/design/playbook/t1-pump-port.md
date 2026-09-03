# T1 Playbook — the neutral duplex PUMP port

Status: **DESIGN. No code changed.** Read-only over CODE; the one writable artifact is this file.
Scope: design the substrate-owned bidirectional PUMP as a *generalization of the working MCP server
loop* (`crates/busbar-mcp/src/mcp/stdio_serve.rs`), keyed on a plane-neutral `CallRef`, with
MCP-specifics split to the plane side, MCP's stdio loop re-homed onto it byte-identically.

Sources: `docs/design/plane4-seam-audit-A-transport.md` (Seam 3, SURFACE-NOW #4; Seam 2),
`docs/design/plane4-duplex-session.md` §2.2 (`CallRef`), §4.3 (the pump). Every code claim is cited
`file:line`. Reading key: `[V]` verified from code this session, `[I]` inference/design.

---

## 0. The thesis, stated once

The audit's central correction (`plane4-seam-audit-A-transport.md:72-85`, SURFACE-NOW #4) governs
this whole document: **the pump is NOT an invention — the MCP SERVER leg already has the reader loop,
the correlation table, the write lock, and the cancellation table.** The pump is a *lift* of that
working loop into `busbar-substrate`, re-keyed off MCP's JSON-RPC `id_key` onto a neutral `CallRef`
the plane owns, with the MCP-only semantics (era verbs, notifications, MRTR, SSE unwrap, watchers)
peeled off onto the plane side. The MCP CLIENT leg (`mcp/client/stdio.rs:820-831`) is the one that
punted — it serializes because it *lacks* the reader task + correlation table the server leg has and
the pump generalizes `[V]`.

Concretely, the server loop already owns, in `stdio_serve.rs`:

| Piece | Site | Neutral? |
|---|---|---|
| single reader loop | `run_session` `:280-335`, `read_until(b'\n')` `:292` | framing is MCP; loop shape is neutral |
| single write lock | `out: tokio::sync::Mutex<W>` `:391-393`; `emit` `:415-421` | neutral |
| correlation table (server-originated asks) | `pending: Mutex<HashMap<String, oneshot::Sender>>` `:400-401` | **keyed on `id_key` — MCP** |
| cancellation table | `inflight: Mutex<HashMap<String, AbortHandle>>` `:398-399` | keyed on `id_key` — MCP |
| reply routing | `route_reply` `:310`,`:424-454`; `id_key` `:376-381` | neutral core (`jsonrpc::read_response` `:445`), MCP key |
| per-frame host re-mint | `let host = (self.factory)();` `:522` | neutral (`LiveHostFactory`) |
| client-originated request/await | `issue_request` `:457-481` | neutral shape, MCP id minting `:458` |

Everything below the correlation-key line is neutral machinery; everything keyed on `id_key`
(`:376-381`, MCP's type-tagged JSON-RPC id) or reaching MCP verbs is what must NOT ride into
substrate.

---

## 1. The neutral `CallRef` + pump port signatures (in `busbar-substrate`)

### 1.1 `CallRef` — the correlation abstraction (NOT MCP's `id_key`)

`CallRef` replaces the `String` produced by `id_key` (`stdio_serve.rs:376-381`) as the key of the
correlation and cancellation tables. It is an opaque, plane-minted, `Copy` u64 token — the substrate
never parses it, never derives it from wire bytes, and never assumes JSON-RPC. The plane owns the
`CallRef → (client_call_id, upstream_call_id)` remap that design §2.2 (`:212-218`) requires; the pump
sees only the token.

```rust
// crates/busbar-substrate/src/pump/mod.rs  (new module, plane-neutral)

/// A plane-neutral correlation handle for one in-flight duplex exchange. Generalizes MCP's
/// `id_key`-string key (`busbar-mcp/.../stdio_serve.rs:376-381`) to a token the substrate never
/// interprets: the plane mints it, maps it to whatever wire ids its dialect correlates by
/// (JSON-RPC id, OpenAI `call_id`, Gemini tool-name), and the pump uses it ONLY as a map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallRef(pub u64);

impl CallRef {
    /// A monotonic minter the pump offers the plane; the plane MAY instead supply its own.
    #[must_use]
    pub fn next(seq: &std::sync::atomic::AtomicU64) -> Self {
        Self(seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}
```

Why a token and not `id_key`: lifting `id_key` (`format!("s:{s}")` / `format!("n:{other}")`,
`:377-380`) would drag MCP's *"the string `\"1\"` and the number `1` never collide"* JSON-RPC concern
into substrate — exactly the neutrality red the audit flags (`seam-audit-A:83-85`). The plane keeps
`id_key` on ITS side of the seam (it is how the MCP plane derives a `CallRef` from a frame), and the
substrate map is `HashMap<CallRef, _>` `[I]`.

### 1.2 The framing seam — what the plane plugs into the pump

The MCP loop's one non-neutral primitive is framing: `read_until(b'\n')` (`:292`) on the read side and
`emit`'s `bytes.push(b'\n')` (`:417`) on the write side. Design §4.3 (`:497-498`) is explicit that
framing *"stays PLANE-side"* — matching the byte-duplex host contract *"host moves RAW BYTES only"*
(`busbar-plugin/src/hot/host.rs:156-159`). So the pump takes a plane-supplied codec:

```rust
/// The plane's framing + correlation policy. The pump owns the loop; the plane owns what a frame
/// IS and how a frame correlates. Mirrors the MCP codec pair (design §2.2 `:225-228`).
pub trait DuplexCodec: Send + Sync + 'static {
    /// Split the read buffer into the next complete frame, or `None` if more bytes are needed.
    /// (MCP impl: scan to `b'\n'`, strip it — `stdio_serve.rs:292,300-302`.)
    fn next_frame(&self, buf: &mut Vec<u8>) -> Option<Vec<u8>>;

    /// Serialize one outbound frame WITH its own framing (MCP impl: JSON + trailing `b'\n'`,
    /// `stdio_serve.rs:416-417`). The pump only funnels the bytes under the write lock.
    fn encode(&self, frame: &Frame) -> Vec<u8>;

    /// Classify an inbound frame for the loop: is it a REPLY to a `CallRef` we issued
    /// (→ route to the correlation table, the `route_reply` arm `:310`,`:424-454`), or fresh
    /// work (→ dispatch)? Returns the `CallRef` for the reply case and for cancellation keying.
    fn classify(&self, frame: &[u8]) -> FrameClass;
}

pub enum FrameClass {
    /// A reply the pump routes to `pending[call_ref]` (MCP: object with `result`/`error` + id,
    /// `stdio_serve.rs:431-439`). `outcome` is already neutral (`jsonrpc::read_response`-shaped).
    Reply { call_ref: CallRef },
    /// Fresh inbound work to dispatch; `call_ref` (if any) keys the cancellation table.
    Work { call_ref: Option<CallRef> },
    /// Not a frame (MCP: a blank line, `:303-304`). The pump skips it.
    Skip,
}
```

### 1.3 The pump port trait + struct

The pump generalizes `Session<W>` (`:383-410`) and `run_session` (`:280`). Two design choices from
the audit:

* **Read/write are two type parameters, not one `W`.** MCP's `Session<W>` writes to `W` and reads
  from a separate `R` threaded through `run_session` (`:239-249`,`:280-284`) `[V]` — already the
  right split; the pump keeps it, so the same struct serves stdio (`tokio::io::{stdin,stdout}`,
  `:232`) AND a `PipeId` byte channel (see §4 on the transport tax).
* **Dispatch is a plane closure, not a pump method.** MCP funnels every non-reply frame into
  `handle_frame` → `dispatch_frame` → the shared `serve`/`rpc_dispatch` seam (`:484-563`). The pump
  takes a `PumpHandler` the plane supplies; the pump never names MCP's `serve`.

```rust
/// The substrate-owned bidirectional pump: one reader task, one write lock, one correlation table,
/// one cancellation table — the generalization of `busbar-mcp/.../stdio_serve.rs` `Session<W>` +
/// `run_session`, re-keyed on `CallRef`. Protocol-neutral: it frames via `DuplexCodec` and
/// dispatches via `PumpHandler`; it names no MCP verb, no JSON-RPC, no voice noun.
pub struct Pump<W, C, H>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    C: DuplexCodec,
    H: PumpHandler,
{
    codec: C,
    handler: H,
    /// ONE writer, one lock — verbatim discipline from `stdio_serve.rs:391-393`.
    out: tokio::sync::Mutex<W>,
    /// Busbar-originated exchanges awaiting a reply — `pending` `:400-401`, re-keyed CallRef→sender.
    pending: std::sync::Mutex<HashMap<CallRef, tokio::sync::oneshot::Sender<Reply>>>,
    /// In-flight inbound dispatches, for cancellation — `inflight` `:398-399`, re-keyed on CallRef.
    inflight: std::sync::Mutex<HashMap<CallRef, tokio::task::AbortHandle>>,
    /// Background tasks aborted at close — `background` `:409`. (Watchers are plane-spawned, §2.)
    background: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
    seq: std::sync::atomic::AtomicU64,
}

/// The plane's per-frame behavior. The pump calls this for every `FrameClass::Work` frame; the
/// impl re-mints its host (MCP: `(self.factory)()` `:522`) and runs its own dispatch. Returning
/// bytes the pump writes under the lock keeps ALL emission single-locked.
pub trait PumpHandler: Send + Sync + 'static {
    /// Dispatch one inbound work frame; any produced frames are emitted via `PumpTx` under the
    /// pump's single write lock. `call_ref` is the cancellation key the pump registered.
    fn handle(&self, tx: PumpTx<'_>, frame: Vec<u8>, call_ref: Option<CallRef>)
        -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

impl<W, C, H> Pump<W, C, H> /* … */ {
    /// The reader loop — generalization of `run_session` `:280-357`.
    /// Loop: read bytes → `codec.next_frame` → `codec.classify`:
    ///   Reply → `route_reply` into `pending[call_ref]` (`:310`,`:440-453`);
    ///   Work  → spawn `handler.handle`, register `inflight[call_ref]` (`:317-334`);
    ///   Skip  → continue.
    /// Close: bounded drain of `inflight` (`:342-347`), abort `background` + `inflight`
    /// (`:349-354`), flush `out` (`:355-356`).
    pub async fn run<R: tokio::io::AsyncRead + Unpin>(self: Arc<Self>, reader: R) { /* … */ }

    /// Issue a busbar-originated exchange and await its reply — generalization of `issue_request`
    /// `:457-481`. The pump mints a `CallRef`, inserts into `pending`, encodes+emits under the
    /// lock, awaits the oneshot with the plane-supplied timeout, and always removes the entry.
    pub async fn issue(&self, frame: &Frame, timeout: Duration) -> Result<Reply, IssueError> { /* … */ }

    /// Emit one unsolicited frame — `EmitKind::Unsolicited` (`busbar-plugin/.../workitem.rs:47`),
    /// the `emit`-directly path (`stdio_serve.rs` server pushes, e.g. `:1067-1071`). Single-locked.
    pub async fn emit(&self, frame: &Frame) { /* out.lock().await; write_all; flush — `:415-421` */ }
}

/// A cheap emit handle handed to `PumpHandler::handle` so plane dispatch can write replies AND
/// unsolicited frames without owning the lock. Wraps `&Pump`; every write funnels through `out`.
pub struct PumpTx<'a> { /* &'a Pump-ish */ }
```

`Reply`/`Frame`/`IssueError` are neutral: `Reply` is the `Ok(Value)/Err(String)` outcome MCP's
`route_reply` already produces via `busbar_substrate::ingress::jsonrpc::read_response`
(`stdio_serve.rs:445-451`) — that reader is ALREADY in substrate and ALREADY neutral `[V]`, so the
reply outcome type crosses cleanly. `Frame` is opaque bytes the codec owns.

---

## 2. What stays PLANE-side, and how the seam splits

The audit's INFO note (`seam-audit-A:255-266`) is the spine here: *"'delete the bespoke loop' is not
a clean subtraction — it is a split of neutral-pump vs MCP-plane behavior."* The pump keeps ONLY the
loop/correlation/lock/cancel core. Everything below moves to the MCP plane's `PumpHandler`/codec impl
and its plane-spawned watchers — the pump never learns any of these words.

| MCP-specific behavior | Site in `stdio_serve.rs` | Where it goes |
|---|---|---|
| Newline framing | `read_until(b'\n')` `:292`; `push(b'\n')` `:417` | `DuplexCodec::{next_frame,encode}` (plane) |
| `id_key` correlation key | `id_key` `:376-381`; `envelope_id` `:368-372` | plane derives `CallRef` in `classify` |
| Reply vs request/notif classification | `route_reply` `:424-439` (checks `method`/`result`/`error`) | `DuplexCodec::classify` (plane) |
| The MCP era-verbs | `stdio_dispatch` `:582-638`: `initialize` `:583`, `ping` `:584`, `logging/setLevel` `:585-602`, `resources/subscribe|unsubscribe` `:603-636` | `PumpHandler::handle` → MCP dispatch (plane) |
| `logging/setLevel` session floor | `level` field `:397`; `body_with_session_level` `:494-513` | plane session-state, injected before dispatch (plane) |
| `resources/subscribe` watcher | `resource_subs` `:407`, `spawn_resource_watch` `:1024-1079`, `visible_resource_fingerprint` `:1083-1104` | plane watcher, registers its `AbortHandle` via `Pump::background` |
| `notifications/cancelled` handling | `observe_notification` `:701-712` (aborts `inflight`) | plane calls a pump `cancel(call_ref)` method |
| `notifications/progress` / `initialized` / `elicitation/response` | `:694`,`:716`,`:733-756` | plane `observe`, resolves `pending` via a pump handle |
| MRTR live-ask drive | `deliver` `:820-842`, `drive_asks` `:856-889` (uses `issue_request`) | plane, built on `Pump::issue` |
| SSE stream unwrap → lines / ping keepalive / early-close `notifications/cancelled` | `pump_stream` `:894-953` | plane, emits via `PumpTx`/`Pump::emit` |
| Task-result watcher | `watch_task_result` `:958-1012` | plane watcher on `Pump::background` |
| Synthesized routing headers | `synthesized_headers` `:1148-1194` | plane (it is HTTP-mirror furniture) |
| `initialize` capabilities body | `initialize_result` `:661-684` | plane |

The seam is therefore: **pump = { reader task, `codec`-driven framing dispatch, `out` write lock,
`pending<CallRef>` correlation, `inflight<CallRef>` cancellation, `background` abort set, `issue`,
`emit` }**; **plane = { the codec, the CallRef minting/remap, every verb, every notification, every
watcher, MRTR, SSE unwrap, headers }**. The one seam surface that must be *added* to keep the split
clean: a pump `cancel(call_ref)` and a way for the plane to resolve a `pending` entry from a
notification (elicitation/response `:744-755`, progress `:716-725`) — both are thin methods over the
existing two maps `[I]`.

Crucially, the neutral reply reader (`jsonrpc::read_response`, `:445`) is already substrate-side, so
the pump's `Reply` outcome needs no MCP code — the plane's codec `classify` decides *which* frames
are replies, the pump just routes them.

---

## 3. Adding the CLIENT leg (punted today)

The client leg (`mcp/client/stdio.rs`) is the punt the audit names (`seam-audit-A:234-239`,
`:79-82`): `StdioPool` (`stdio.rs:828-831`) runs **one child per registration, calls serialized by a
per-slot `Arc<tokio::sync::Mutex<ChildSlot>>`** because *"two request/response pairs interleaved on
[one byte stream] can only be told apart by demultiplexing on the JSON-RPC id — which is a second
correlation table … Serialising is the honest shape until there is a reader task to own that table"*
(`stdio.rs:820-827`) `[V]`.

**The pump IS that reader task + that owned correlation table.** So the client leg is added by
*inverting* the pump, not by writing new machinery:

1. The client leg is a `Pump` whose **reader** is the child's `stdout` and whose **writer** is the
   child's `stdin` — the mirror of the server leg's stdin/stdout. Same struct, same `pending<CallRef>`.
2. A client CALL becomes `Pump::issue(frame, timeout)` (`§1.3`, generalizing `issue_request`
   `:457-481`): mint a `CallRef`, insert into `pending`, write under the lock, await the oneshot. The
   reader task de-serializes concurrent replies by `classify` → `pending[call_ref]` — the exact
   demux the doc said was missing.
3. Child-originated REQUESTS (the child's `ping`/`roots/list`/`sampling` that `mcp/client/peer`
   answers today) arrive as `FrameClass::Work` and route to the client leg's `PumpHandler`.
4. The per-slot `Mutex<ChildSlot>` serialization (`stdio.rs:830`) is then **deleted** — concurrency is
   safe because the correlation table exists. This is the same "adopt-and-delete" MCP does for its
   server loop (§4), applied to the client leg.

The client leg is therefore **not** in the first pump-port increment (design §4.3 frames it as a
warning/motivation, `:505-512`); it is the *proof* the generalization was right, landing after the
server leg re-homes. Sizing: it is a re-home, not new machinery — the pump already owns everything
the client leg lacked `[I]`.

---

## 4. The concrete refactor of `stdio_serve` — byte-identical MCP conformance

The DoD is *"`busbar-mcp` no longer contains a bespoke duplex loop … total duplex-loop code goes
down"* (`plane4-duplex-session-1.6.0-plan.md:251-254`) WITHOUT changing a single MCP-observable byte.
The refactor:

1. **`Session<W>` loses its neutral fields** (`out` `:393`, `inflight` `:399`, `pending` `:401`,
   `background` `:409`, `ask_seq` `:402`) — they move into `Pump`. It KEEPS its MCP-plane fields
   (`factory` `:388`, `principal`/`gov` `:389-390`, `level` `:397`, `resource_subs` `:407`) and
   becomes the MCP `PumpHandler` impl. `Session` now *holds* an `Arc<Pump<…>>` for `issue`/`emit`.
2. **`run_session` `:280-357` is deleted**; `serve_io` (`:239-250`) constructs a `Pump` with an
   `McpCodec` (newline `next_frame`/`encode` + JSON-RPC `classify`, lifting `:292`,`:300-304`,
   `:416-417`,`:376-381`,`:424-439`) and calls `Pump::run(reader)`.
3. **`handle_frame`/`dispatch_frame`/`stdio_dispatch` `:484-654` become the `PumpHandler::handle`
   body** — unchanged in behavior: same per-frame `(self.factory)()` re-mint (`:522`), same
   `serve`/`rpc_dispatch` seam (`:532`,`:644`), same era-verbs (`:582-638`), same synthesized headers
   (`:640`,`:1148`). The MRTR `deliver`/`drive_asks` (`:765-889`) and `pump_stream` (`:894-953`) call
   `Pump::issue`/`PumpTx::emit` instead of the old `self.issue_request`/`self.emit`.
4. **`emit`/`issue_request`/`route_reply` `:415-481` collapse into `Pump::emit`/`issue`/route** —
   same single-lock write (`:418-420`), same `oneshot` correlation, same `busbar:{seq}` id minting
   (which stays PLANE-side: the plane's codec mints the wire id and maps it to the `CallRef`; the
   pump only holds the `CallRef` → so `ask_seq` `:402` moves to the MCP plane, and the pump's own
   `seq` mints `CallRef`s).
5. **Watchers stay MCP-plane** (`spawn_resource_watch` `:1024`, `watch_task_result` `:958`) but
   register their `AbortHandle`s into `Pump::background` (today `self.background`, `:1078`,`:1011`) so
   the pump's close path (`:349-351`) still aborts them.

**Byte-identical proof obligations** (the conformance guard):

* The write lock is the SAME `tokio::sync::Mutex` discipline (`:391-393`) — no interleaving change.
* The EOF path is preserved verbatim: bounded `EOF_DRAIN` drain (`:342-347`,`:365`), then abort
  `background` + `inflight`, then `out.flush()` (`:349-357`). The pump's close MUST reproduce the
  3-second drain, or one-shot-pipe invocations regress (`:336-341`).
* The cancellation race window (register-after-spawn, `:324-334`) is reproduced by the pump's
  spawn-then-`inflight.insert` order.
* Framing MUST byte-match: `McpCodec::encode` = `serde_json::to_vec` + `b'\n'` (`:416-417`),
  `next_frame` = `read_until(b'\n')` + strip (`:292`,`:300-302`) + blank-line skip (`:303-304`).
* The existing battery (`crates/busbar-mcp/src/mcp/tests/stdio_serve_tests.rs`, driving `serve_io`
  `:7`) and the process-level conformance (`crates/busbar/tests/mcp_stdio_serve.rs`, `:16`) are the
  RED-line: both must pass unchanged, and the MCP conformance battery
  (`testing/mcp-conformance/`) must stay green.

---

## 5. Collision with Stage A

Stage A (the transport-axis + arrival + session + ABI seams, `plane4-seam-audit-A-transport.md`) and
this pump port intersect at four points — the pump port CANNOT land before these are reconciled:

1. **[HARD DEP on Stage-A #2 — SessionScope has no arena/Drop.** `SessionScope {}` is empty
   (`scope.rs:364-366`), and `register_pipe`'s RAII reclaim lives on `DispatchScope`
   (`scope.rs:302-311`), which `SessionScope` does not own (`seam-audit-A:41-55`). The pump's
   `pending<CallRef>` table and the pooled UPSTREAM `PipeId` need a `Drop`-bearing home that reclaims
   on close/cancel/panic. Until T1.4 gives `SessionScope` an arena (mirroring
   `DurableScope { arena: DispatchScope }` `:404`), the pump has nowhere leak-free to hold the
   upstream socket. **The pump's `CallRef` table is a plane-owned field of `SessionScope`
   (design §4.3 `:501-502`), NOT a pump field** — so the pump struct's `pending` is the
   *server/self-origin* correlation, and the *client↔upstream* `CallRef` remap is `SessionScope`'s.

2. **[RESOLVED-BY-DESIGN — Stage-A #4 — correlation key neutrality.** This document's §1.1 is the
   direct answer to `seam-audit-A:83-85`: key on `CallRef`, keep `id_key` (`:376-381`) plane-side.

3. **[TENSION — Stage-A #3 — the acceptor/dialer axis is greenfield.** The pump is the LOOP; the
   thing that *constructs* a pump over a `PipeId` is the `Transport → {acceptor, dialer}` dispatch
   that A #3 says does not exist for any variant (`seam-audit-A:57-70`,`:144-150`). The pump port is
   orthogonal to that dispatch (it can be built and unit-tested over an in-memory duplex, exactly as
   `serve_io` is tested today, `:236-238`), but it cannot be WIRED to a real WS socket until T1.1's
   dialer/acceptor lands. Order: pump port (over `PipeId`/`AsyncRead`+`AsyncWrite`) → T1.1 dispatch →
   WS dialer feeds the pump.

4. **[TAX — Stage-A Seam 2 INFO — stdio uses tokio io directly, not the FFI pipe slots.** The audit
   notes MCP stdio's serve loop drives `tokio::io::{stdin,stdout}` directly (`serve_io` `:232`,
   `seam-audit-A:208-213`), NOT the `pipe_read`/`pipe_write` FFI slots (`host.rs:159-171`,`:474-476`).
   The pump must therefore be **generic over its byte channel** — an `AsyncRead`+`AsyncWrite` pair
   (stdio, in-memory tests) OR a `PipeId` driven through `pipe_read`/`pipe_write` (WS upstream). If
   the pump is forced to be `PipeId`-only, re-homing MCP stdio would push stdin/stdout through the FFI
   pipe tier — a framing/perf change that risks the byte-identical DoD. Keep the `R/W` generic
   parameters (§1.3) and add a `PipeId`-backed `AsyncRead`/`AsyncWrite` adapter for the WS side.

5. **[Stage-A #1 — the WS PipeId reaches the pump via `ArrivalCtx(Box<dyn Any>)`.** The upgraded
   socket handle rides the `Any` payload (`arrival.rs:36`, T1.2 `:218-221`); the dual-compile TypeId
   hazard (`seam-audit-A:23-39`) means the pump's `PipeId` input must be downcast from a
   **substrate-owned** payload type, or the pump receives a `None` at runtime. The pump itself takes a
   concrete `PipeId`/reader-writer — it must NOT take a `Box<dyn Any>`; the arrival unwraps before
   calling the pump.

---

## 6. Residual risks

* **R1 — SessionScope one-way door (HARD).** The pump port depends on T1.4 giving `SessionScope` an
  arena + `Drop` (`scope.rs:364-366` empty today; `seam-audit-A:41-55`). If the pump ships against
  the current empty `SessionScope`, the upstream `PipeId` and the `CallRef` remap table have no
  leak-free reclaim on disconnect/cancel/panic. **Land T1.4's field set BEFORE the pump wires a real
  upstream socket.** The pump can be built+tested over in-memory duplex without it, but must not be
  declared done until the reclaim is proven.

* **R2 — the split is not a clean subtraction; byte-identical conformance is fragile.** Twelve
  MCP-specific behaviors (§2) layer on the loop — era verbs (`:582-638`), MRTR (`:820-889`), SSE
  unwrap (`:894-953`), three watchers, session logging floor, `notifications/cancelled` semantics. If
  ANY leaks into the neutral pump (or any neutral behavior is dropped in the move — e.g. the
  `EOF_DRAIN` bound `:365`, the cancellation race window `:324-334`, the id-rewrite-to-caller
  `:845-849`), MCP conformance reds. Gate the refactor on the existing `stdio_serve_tests.rs` +
  `mcp_stdio_serve.rs` + `testing/mcp-conformance/` batteries staying green with zero diff.

* **R3 — the byte-channel generality tax.** The pump must serve BOTH a raw `AsyncRead`/`AsyncWrite`
  pair (stdio, tests — `serve_io` `:232`,`:239-249`) AND a `PipeId` over the FFI `pipe_read`/
  `pipe_write` slots (WS upstream — `host.rs:159-171`). A mis-shaped generic (e.g. `PipeId`-only)
  forces MCP stdio through the pipe tier and breaks byte-identical framing (`seam-audit-A:208-213`).
  Keep the `R`/`W` type parameters and supply a `PipeId`→`AsyncRead`/`AsyncWrite` adapter, rather than
  reshaping the pump around `PipeId`.
```
