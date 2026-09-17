# Loop-unification MAP — substrate `run_unit` vs kernel `run_unit`

Cell: `keystone-loop-unify` (busbar 1.6.0 KEYSTONE). This is the MAP, not a new
spec. It IMPLEMENTS the seam ruled in **DECISIONS #28** ("The loop's answer shape
is two-variant `PlaneAnswer`; … LOOP UNIFICATION"). Every claim below is verified
against real code at the file:line cited. Nothing here re-decides #28.

## 0. The two loops, located

| | KERNEL loop | SUBSTRATE loop |
|---|---|---|
| file | `crates/busbar-kernel/src/teller.rs` (1179 LOC) | `crates/busbar-substrate/src/teller/{mod,run,steps,tokens,unit}.rs` (~973 prod LOC) |
| entry | `run_unit` / `run_unit_async` (teller.rs:675,703) | `run_unit` / `open_unit` (teller/run.rs:98,228) |
| driven by | admin `admin_mount.rs:122`, llm `units_llm.rs:557`, transports `transports.rs:439` | `run_gauntlet[_session]` (plane_host/mod.rs:417,440) → `GauntletAdapter` (mod.rs:235) → substrate `run_unit` |
| riders | admin (byte-identical template), llm-native (money-parity proven, #29) | MCP `method.rs:1242`, A2A `receive.rs`, voice `topology`, duplex `duplex_ws.rs`, llm-native gauntlet |
| plane seam | `trait Units` (teller.rs:474) — one method per step, `&U` threaded | `trait TellerPlane` (teller/steps.rs:118) — one method per step, plane value threaded |

Crate dependency direction (verified, `Cargo.toml`): `busbar-kernel` depends only
on `busbar-caps`, `busbar-contract`, `busbar-grammar`. It does **not** depend on
`busbar-substrate`, and substrate does not depend on kernel — they are siblings.
`DispatchScope` lives in `busbar-substrate::plane_host::scope` (scope.rs:139).
**Consequence: the kernel loop cannot and must not name `DispatchScope`** — see §4.

## 1. Step order

- **Substrate: 9 steps** — arrival → decode → authenticate → verify → approve →
  admit (opens Hold) → route → meter → audit. (teller/mod.rs:66-112, run/run.rs
  `open`+`under_hold`.) route **and** meter are `async`.
- **Kernel: 10 steps** — the same nine **plus `encode`** (the bytes that leave),
  and a non-step `evidence()` the settlement table reads. (teller.rs `trait Units`
  476-574.) Only **route** is `async` (`RouteAwait`/`RouteLeg`, teller.rs:588-606);
  meter/audit/encode are sync.
- Kernel additionally folds a **challenge** short-circuit at authenticate
  (`Authenticated::Challenge` → `Admission::ZeroHold`, teller.rs:730) that has no
  substrate analogue (the gauntlet planes resolve identity upstream via `req.gov`).

## 2. Audit doors

Both loops have **two** audit doors, same shape:
- `audit_refused` — unit never passed Admit; nothing charged; no hold.
  (kernel teller.rs:558/793; substrate run.rs:69 `close_refused`, steps.rs:186.)
- `audit` — unit passed Admit; audited WITH the hold (admission stands), reached by
  completed / refused-under-hold / **abandoned** (caller went away).
  (kernel teller.rs:555, via `terminal` teller.rs:1004; substrate run.rs:81
  `close_admitted`, run.rs:104/176/191.)

Difference the keystone later collapses (NOT this cell — task forbids it):
- Kernel's two doors **converge on one exit** (`terminal`→`exit`, teller.rs:1004,
  1108): audit → encode → settle → seal `UnitEnd`, once. "One exit" is real here.
- Substrate's two doors each **return an axum `Response` directly** with no encode
  and no settle (run.rs:77,94). Settlement is the plane's own, inside `drive`.

`StepName::after_admit()` orders both (kernel via `busbar_caps`, substrate
unit.rs:51) so "refused before vs under the hold" is a comparison, not a table.

## 3. Token stamp, settle, encode

- **Token stamp.** Kernel mints every step token from the `KernelSeal`
  (`UnitToken::<S>::mint(seal)`, teller.rs:710+); the seal is the one authority and
  also mints the four out-of-loop tokens (transport-key, admin, durability, ledger,
  usage — teller.rs:111-193). Substrate mints seal-lessly
  (`UnitToken::<S>::mint()`, run.rs:37+); its sealing is the type-level `Step`
  seal (mod.rs:37) — no runtime `KernelSeal`.
- **Settle.** Kernel owns a full settlement table as pure functions —
  `settle_amount` (teller.rs:346), `fee_count` (414), `requests_drawn/settled`
  (450/459) — applied in `exit` (1108): take hold by CAS, release leases, spend
  the accrual meter, post `Usage`+`Posted::settle`, seal `UnitEnd`. Returns
  `Ended::{Settled{end,requests,fee} | AlreadySettled}` (teller.rs:653). Substrate
  has **no settlement** — the loop returns `Response`; the plane meters/charges
  inside `drive` (the GauntletAdapter's admit opens an EMPTY hold, meter is a
  status pass-through, audit just returns `closing.resp`: plane_host/mod.rs:313-357).
- **Encode.** Kernel has an explicit `encode` step producing the leaving bytes
  (teller.rs:566, called at 796 and 1016). Substrate has **no encode** — the
  plane's `drive`/`route` produces the finished axum `Response` and that IS the
  answer (materialized `Unary` or `Live`).

## 4. The answer shape — where `PlaneAnswer` actually goes (feeds Step 2)

Verified from the **admin template** (`admin_mount.rs:105-152`), which is the
byte-identical kernel-loop rider #28 says to mirror:

1. `run_unit` returns only **`Ended`** (the money/lifecycle outcome). It does
   **not** return a `Response`.
2. The **answer bytes are read back out of the plane's own table, keyed by
   `ctx.key`**: `self.units.admin.units.answer(key)` after the loop returns
   (admin_mount.rs:138). The plane's Route/encode step *stashed* the answer into
   its `AdminUnitTable`; the outer handler retrieves it by key.

This is exactly #28's `PlaneInFlight` binding table "keyed by `ctx.key` … answer at
Route, mirroring `AdminUnitTable`." So for the kernel loop, **`PlaneAnswer` is the
value the plane stores in its keyed table and the outer async handler serves** —
`Unary(status,headers,body)` for buffered verbs, `Live(Response)` for a streaming
body the handler serves directly (llm already does this via its `RouteLeg`,
`units_llm.rs:557`).

**Arena threading (the "lift DispatchScope onto kernel run_unit").** The kernel
loop is generic over `U: Units` and threads the plane value `&U` (plus `&UnitCtx`)
through **every** step (teller.rs:703-854). A plane therefore carries its own arena
**inside its `Units` value** — precisely as MCP/A2A/voice create `DispatchScope::new()`
inside `drive` today (mcp `method.rs:714,1408,1763`; a2a `receive.rs:1043,1728`;
voice `topology/mod.rs:143`). **No kernel-loop signature change is required to carry
the arena, and the kernel names no `DispatchScope`.** The minimal, plane-neutral
seam addition is thus:
- a neutral `PlaneAnswer { Unary(StatusCode, HeaderMap, Bytes) | Live(Response) }`
  answer type, owned by a **neutral** crate (substrate/api tier, NOT busbar-kernel,
  so kernel keeps naming zero planes and zero answer-shapes); and
- a plane-neutral `PlaneInFlight` keyed table (mirror of `AdminUnitTable`) the
  rider stashes its `PlaneAnswer` into at Route and the outer handler reads by
  `ctx.key`.

**Plane-neutrality witness (coordinator's required gate).** MCP is only the first
WITNESS on this seam; nothing in kernel `run_unit` / `Units` / `PlaneAnswer` may
know it is MCP. The existing `no_plane_names.rs` source gates
(`busbar-transport-http/tests/no_plane_names.rs:206`,
`busbar-transport-grpc/…:206`) already assert the loop names no concrete caller;
the new `PlaneAnswer`/`PlaneInFlight` types must be added to that grep's scope so it
goes **RED** if any plane noun (`mcp`, `a2a`, `voice`, `tools_call`, …) leaks into
the carrier. a2a/voice/llm then ride the IDENTICAL seam with **zero new seam code** —
only re-pointing their gauntlet rider.

## 5. Delta summary (what unification must reconcile)

| axis | kernel | substrate | unification (per #28) |
|---|---|---|---|
| steps | 10 (+encode) | 9 | keep kernel's 10; gauntlet planes make encode a pass-through of the `Response` they already shaped |
| async | route only | route + meter | keep kernel's one-await; MCP meter is sync once its per-round metering stays inside route/`drive` |
| audit doors | 2 → one exit | 2 → two direct returns | collapse substrate's two onto kernel's single exit (**follow-on, not this cell**) |
| settle | full table in `exit` | none (plane's own) | MCP keeps its own per-round metering inside route; kernel `exit` settles the plane-neutral outer hold (dual-write→flip, #29) |
| answer | `Ended` + plane keyed table | `Response` returned | `PlaneAnswer` in the plane keyed table, served by the outer handler |
| arena | rides plane `Units` value | created inside `drive` | unchanged — arena rides the plane value; kernel names no `DispatchScope` |

## 6. This cell's scope (per brief)

Seam + **MCP proof only**. Do NOT collapse the second audit door and do NOT delete
`crates/busbar-substrate/src/teller/` — that is the follow-on once MCP + A2A +
voice + llm all ride the kernel loop. MCP path must be byte-identical vs 1.5.5;
money proof runs `bin/oracle` direct on a fleet box (**#29**), not through the
circular `prove-remote.sh` wrapper.

Remaining re-point list after MCP (identical seam, rider-only change):
`busbar-a2a/src/a2a/receive.rs:892`, `busbar-voice` `topology/mod.rs:308`+`mount.rs`,
`busbar-substrate/src/ingress/duplex_ws.rs:175`, `busbar-llm/src/native_ingress.rs:592`.

## 7. Composition-root plane-neutrality (owner ruling — sequenced follow-on, this crate)

`main.rs::register_planes`/`register_protocols` today hardcodes
`busbar_{mcp,a2a,llm,voice}::PLANE_DECL`/`PROTO_DECL` (main.rs:597-688). Owner
ruling: the composition root must name ZERO planes — every plane SELF-REGISTERS via
the 1.5.5 SDK inventory `busbar_plugin_sdk::export_<kind>_plugin!` (pattern:
`auth-static-plugin/src/lib.rs:123` `export_auth_plugin!`), so compiled-in registers
the same way dropped-in does (#11 both-ways, #2 "a plugin is a plugin"). Sequenced as
the immediate follow-on commit to loop-unification (still this crate's `main.rs`);
the report flags which planes remain named in main.rs so the instance-noun-neutrality
gate's known-debt rows burn down. No other agent touches main.rs concurrently.
