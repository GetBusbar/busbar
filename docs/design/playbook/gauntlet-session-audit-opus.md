# Adversarial money-path audit — `run_gauntlet_session` (Opus)

**Target:** `docs/design/playbook/gauntlet-session.md`
**Method:** read-only, design-vs-real-code. Every anchor below was opened and checked.
**Pin:** branch `integration/plane-extraction` @ `b4c8e641`.

## Verdict: **SHIP-WITH-CHANGES**

The *shape* is sound and genuinely additive: a new free fn + a new trait beside
`run_gauntlet`/`GauntletPlane` touches no existing signature, and the verify→admit→reserve→durable→handoff
ORDER is fail-closed on refusal. But the design's headline claim — "*verified against real code*",
"*exactly the LLM open pass*", "*byte-identical*" — is **materially false at this pin**: the entire
voice call-side and the cited LLM/metering anchors do not exist, the admission set is NOT the LLM open
pass (it reorders and swaps mechanisms), and two rollback/ownership seams are unproven. None of these
sink the *idea*; all of them must be corrected before the doc can be treated as an implementable spec
rather than a sketch. Hence SHIP-WITH-CHANGES, not SHIP (over-claimed as verified) and not REJECT
(architecture is correct and additive).

---

## Attack-by-attack

### (1) Does the design change `run_gauntlet`'s one-Response behavior? — CLEAN (pure append achievable)
Real code: `run_gauntlet` is a self-contained free fn (`plane_host/mod.rs:177`, body ends `:185`) and
`GauntletPlane` a self-contained trait (`:158`). The three LLM/MCP/A2A impls
(`busbar-core/src/ingress/dispatch.rs:207`, `busbar-mcp/src/mcp/method.rs`, `busbar-a2a/src/a2a/receive.rs`)
depend only on the two existing methods. A **sibling free fn + sibling trait** that reuse
`GauntletRequest`/`VerifyOutcome`/`SessionScope` read-only add zero bytes to any of that. The design is
correctly disciplined NOT to add a method to `GauntletPlane` (that would touch every impl). Pure-append
is real. *(Nit: the doc's own line anchors are stale — it cites `run_gauntlet` at `:185` and
`GauntletPlane` at `:170`; actual `:177` / `:158`. See severity-LOW finding F8.)*

### (2) Is the session admission set EXACTLY the LLM open pass? — **NO (F1, the load-bearing miss)**
The doc claims the LLM open pass is `destination_guard → admission_door → select → forward_with_pool_parsed
(pool/breaker admit) → finish_admitted` and that the session mirrors it as
`verify → govern-admit + pool/breaker-admit → cost_reserve → durable`. Reading the **real** LLM `drive`
(`dispatch.rs:228–354`):
- `admission_door` (`:247`) is "**THE single budget-admission door**" — it does govern **and** the money
  charge *together, first*, before candidate selection.
- **Breaker admit is NOT a standalone pre-charge gate.** It lives *inside*
  `forward_with_pool_parsed` (`:312`) at egress, per-attempt, inseparable from actually sending bytes.
  There is no "breaker probe before charge" in the request plane.

So the session design **reorders** (breaker BEFORE reserve, vs LLM charges BEFORE it ever touches the
breaker) and **swaps the money mechanism** (see F2). "Exactly the LLM open pass / byte-identical" is
false. The reorder is arguably *safer* for a session, but two concrete hazards follow, below (F3, F4).

### (3) Ordering one-way-door in `begin_session` + both topologies — **UNVERIFIABLE (F5, critical to the doc's credibility)**
`crates/busbar-voice/` **does not exist.** `begin_session`, `SessionCore`, `VoiceRuntime`, `open_lease`,
`bind_session`, `topology/telephony.rs`, `topology/webrtc.rs`, `runtime/metering.rs` — **zero matches in
`crates/`.** The doc cites `topology/mod.rs:106`, `runtime/metering.rs:72`, `native_ingress.rs` as
"verified against real code"; all are fictional at this pin (the LLM open pass actually lives in
`ingress/dispatch.rs`, and `native_ingress.rs` does not exist). The one-way-door invariant therefore
cannot be checked against any code — it is an assertion about files that are not written. That does not
make it wrong, but it makes "STOP-condition, verified" an over-claim.

### (4) Refusal path — zero bytes / zero charge — DESIGN-CORRECT, one gap (F3)
On `VerifyOutcome::Refuse`, `run_gauntlet_session` returns `Err` before `open_session` — reserve is
unreached, so zero charge. Ordering govern/breaker admit BEFORE `cost_reserve` means an admit refusal is
also pre-reserve. Good. **Gap:** if `cost_reserve` *succeeds* and then **durable open fails**
(`bind_session`/`handle.open`), the doc says only "fail closed" and returns `Err` — it does not say the
reserve is released. Real `CostHold` (`busbar-core/src/plane/cost.rs:305`) only refunds at
`finalize()`; a `CostHold` dropped without `finalize` does **not** refund the budget cell (the caller
debits `reserved()` at reserve time). So a durable-open failure after a successful reserve = **charge on
a session that never opened** — the exact leak the doc exists to close. Needs an explicit reserve-rollback
on any post-reserve failure.

### (5) Double-count of the first frame — CLEAN (F not raised)
Real `CostHold` is structurally immune: `reserve` takes a *coarse over-estimate hold* (not a charge),
`settle_partial` accumulates the exact itemized total, `finalize` ledgers the settled sum and refunds
`reserved − settled` saturating. Doc invariant matches code: "*No double-count: the flat fee is folded
into reserved once and never re-added on settle*" (`cost.rs:301`). The first per-frame settle is just a
partial; it does not re-charge the reserve. **Contingent only** on voice's `MeteringLease` mirroring
`CostHold` semantics — and that type does not exist yet (F2), so it is asserted, not proven.

### (6) Is `SessionScope` the right handoff type? — **CONTESTED (F6)**
`SessionScope` is today an **empty `#[non_exhaustive]` stub** (`scope.rs:366`) with undefined `Drop`.
The doc hands the *live reserved lease* back inside `SessionScope`, then says `SessionCore` is "built
FROM scope's lease." The caller's own session-drop discipline puts the lease on `SessionCore.lease` (the
RAII home that releases on session end). That creates a **handoff window**: between `run_gauntlet_session`
returning `Ok(scope)` and `SessionCore` being assembled, the lease lives on a stub whose `Drop` does not
(yet) release it. If `begin_session` errors in that window, the reserve leaks (same class as F3). The
lease must be *moved* out of the scope into `SessionCore.lease` with a guaranteed drop-release on the
scope if the move never completes — unproven, and impossible to prove against an empty stub.

### (7) Does the D3 witness actually foreclose inlining? — **PARTIAL (F7)**
The `§3` witness pins the *substrate seam's shape* (two distinct terminal types, both entries exist) —
that genuinely blocks "delete the sibling / collapse the two Responses." **But it does not pin the
call-site invariant.** A refactor that keeps `run_gauntlet_session` compiling yet routes `begin_session`
*around* it (straight to `open_lease`, today's leak) leaves the witness green. The witness guards
existence, not USE. Also the `fn _shape(f: fn(...))` locks are weaker than claimed: a declared-but-unused
fn *parameter type* does not coerce `run_gauntlet` to it, so the signature is not actually pinned unless
you add `let _: fn(_, _) -> _ = run_gauntlet;`. Need (a) the coercion assignment and (b) a call-site
witness: `begin_session` with a refuse plane opens no lease and binds no socket.

---

## Findings

| # | Sev | File:line (real) | Failure scenario | Fix |
|---|-----|------------------|------------------|-----|
| F1 | **HIGH** | `ingress/dispatch.rs:247,312` vs doc §1b/§5 | Doc claims session admission == LLM open pass "byte-identical." Real LLM does govern+charge in one `admission_door` *before* selection, and breaker only at egress inside `forward_with_pool_parsed`. Design reorders (breaker-before-reserve) and is NOT parity. Any reviewer trusting "identical" ships a different admission set unaudited. | Rewrite §1b/§5 to state the session pass is a *deliberate reordering*, not a mirror; enumerate each check and justify the new order; drop "byte-identical"/"exactly the LLM open pass." |
| F2 | **HIGH** | doc §1b.3/§5 vs `plane/cost.rs:305` | Doc's money gate is `MeteringPort::reserve`/`MeteringLease` (`runtime/metering.rs`) — **nonexistent**. Real D2 is `CostHold` (2-arg `reserve(estimate, fee)`, not `reserve(estimate,fee,cap)`). LLM request path charges via `admission_door` chain buckets and never calls `CostHold`/`MeteringPort`. So §5's "reserves through the SAME D2 slot the request path uses" is false; single-accounting is NOT inherited from LLM and must be proven for voice. | Re-anchor on real `CostHold`; correct the `reserve` signature; drop the "same slot as request path" parity claim; specify voice's own single-accounting proof. |
| F3 | **HIGH** | doc §1b.3→.4 | Reserve succeeds, then `bind_session`/`handle.open` fails → `Err` returned but `CostHold` dropped without `finalize` → budget cell debited, never refunded → **charge on a session that never opened**. | Make `open_session` release/refund the reserve on ANY post-reserve failure (finalize-to-refund or explicit rollback) before returning `Err`. |
| F4 | **MED** | `plane_host/mod.rs:289` (`breaker_admit`) | Design adds a pre-open `breaker_admit` probe; if the per-frame egress also runs breaker admission, a half-open upstream's admission budget is decremented twice (open + first frame), tripping/holding the breaker wrong. | Specify that the open-probe reservation is the SAME breaker admission consumed by the first frame (hand the token through the scope), or that per-frame egress does not re-probe. |
| F5 | **MED (credibility-HIGH)** | doc §2/§0 cites `busbar-voice/**`, `native_ingress.rs`, `runtime/metering.rs` | Every voice-side anchor and the LLM `native_ingress.rs`/`MeteringPort` anchor is **absent from `crates/`**. Doc is marked "verified against real code" + "STOP-condition." One-way-door, choke-point, and topology-coverage claims are unverifiable. | Downgrade "verified" to "verified on the substrate seam; voice side is target-state (crate not yet present)"; fix all dead line anchors. |
| F6 | **MED** | `scope.rs:366` (`SessionScope {}` empty stub, no `Drop`) | Lease handed back inside a stub whose `Drop` is undefined; drop-audit puts the lease on `SessionCore.lease`. Error in the handoff window leaks the reserve (F3 class). | Define `SessionScope`'s lease ownership + `Drop`-release, and specify the move into `SessionCore.lease` with guaranteed release if the move aborts. |
| F7 | **MED** | doc §3 witness | Witness pins seam existence, not call-site use — a refactor can bypass `run_gauntlet_session` in `begin_session` and keep the witness green (leak reopens). `fn _shape` params don't actually lock `run_gauntlet`'s signature. | Add `let _: fn(..)->.. = run_gauntlet;` coercion locks AND a call-site witness: refuse-plane `begin_session` opens no lease / binds no socket. |
| F8 | LOW | doc §0 | Stale anchors: `run_gauntlet` cited `:185` (real `:177`), `GauntletPlane` `:170` (real `:158`). | Repin. |

## What holds
- Pure-additive sibling (free fn + separate trait, no `GauntletPlane` method add) — correct and safe (attack 1).
- Verify-strictly-before-reserve ⇒ zero charge on refuse — correct (attack 4, modulo F3 rollback).
- No structural first-frame double-count — `CostHold` is immune by construction (attack 5).
- Seam belongs in `busbar-substrate` on neutral `GauntletRequest`/`SessionScope` — plane-neutral, matches how the three request planes already ride `run_gauntlet`.
