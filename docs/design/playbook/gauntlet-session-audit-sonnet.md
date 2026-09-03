# Adversarial audit: `run_gauntlet_session` design vs. real code (sonnet)

**Target file named in the task, `docs/design/playbook/gauntlet-session.md`, DOES NOT EXIST.**
Verified: `find docs -iname '*gauntlet*'` and `git log --all -- '*gauntlet-session*'` both return
nothing under that name. The only design content for `run_gauntlet_session` in the tree lives in
`docs/design/plane4-duplex-session-1.6.0-plan.md` §T1.6 (line 287) and §B.5 (line 612-620). This
audit is against that content, since it is the only candidate the task's questions map onto.

## 1. `run_gauntlet` signature/shape — quoted, matches the design's citation

`crates/busbar-substrate/src/plane_host/mod.rs:185-193`:

```rust
pub async fn run_gauntlet(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> axum::response::Response {
    match plane.verify_destination(&req) {
        VerifyOutcome::Refuse(resp) => resp,
        VerifyOutcome::Proceed => plane.drive(req).await,
    }
}
```

Confirms: free fn, `GauntletPlane` is a trait (`:166`) with `verify_destination` (sync, `:169`)
and `drive(self: Box<Self>, ...)` (async, `:175`, returns `axum::response::Response`). The design's
citations (§3.1: "`run_gauntlet(req, plane)` … is a free fn … `GauntletPlane` … a trait") check out
verbatim.

## 2. `begin_session` today — line-by-line, no verify

`crates/busbar-voice/src/topology/mod.rs:106-136`:

```rust
pub fn begin_session<C>(...) -> Result<(Arc<SessionCore<C>>, SessionHandle), StartError> {
    let lease = rt.open_lease(budget.estimate_nanos, budget.fee_nanos, budget.cap_nanos)
        .ok_or(StartError::BudgetRefused)?;
    let handle = rt.bind_session(owner, call_id);
    handle.open(now).map_err(StartError::Durable)?;
    let core = Arc::new(SessionCore::new(codec, lease, Arc::clone(&rt.tools), rt.pricing, carrier, locked_config));
    Ok((core, handle))
}
```

Confirmed exactly: (1) `rt.open_lease` — budget reserve, fail-closed on refusal; (2)
`rt.bind_session` — binds a `SessionHandle` (thin wrapper over `busbar_substrate::plane_host::
SessionScope`, `runtime/scope.rs:84-102`); (3) `handle.open(now)` — durable genesis write. **No
call to `verify_destination`, no `GauntletPlane`, no `run_gauntlet`/`run_gauntlet_session`
anywhere in this function or its call sites** (checked `crates/busbar-voice/src/**`). The design's
own §3.1 gauntlet contract ("session-open is exactly one `run_gauntlet` pass") is aspirational —
today's `begin_session` is a private path that never runs the gauntlet at all, pre-admission or
otherwise. This is the actual gap the sibling is supposed to close, and it is bigger than "add a
function": `begin_session` must be *rewired* to call it, not merely coexist with it.

## 3. Is `run_gauntlet_session` absent — grep-confirmed

`grep -rn "run_gauntlet_session"` over the whole worktree (excluding target/): one hit, a comment
in `crates/busbar-voice/src/lib.rs:105` ("the pump / session-open through `run_gauntlet_session` is
the P2 build"). Zero implementations, zero signatures, zero call sites. Confirmed absent.

## 4. Can the sibling be added without touching `run_gauntlet`'s body — traced, and the answer is more fragile than the doc claims

The proposed signature (plan §B.5, line 616-619):

```rust
pub async fn run_gauntlet_session(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Result<SessionScope, axum::response::Response>;
```

Trivially true that `run_gauntlet`'s *body* need not change — it's a new free fn. But trace what
it can actually call: `GauntletPlane` has exactly two methods, `verify_destination` (reusable
as-is) and `drive(self: Box<Self>, req) -> axum::response::Response` (`mod.rs:171-175`). `drive` is
documented as "the plane's OWN engine: budget-admission, route/failover, egress, and the plane's
own metering" — a *request*-shaped, `Response`-shaped stage. There is no trait method that mints a
`SessionScope`. So `run_gauntlet_session` cannot be plane.verify_destination() + plane.drive() —
`drive`'s return type is flatly incompatible with `Result<SessionScope, Response>`. The sibling
therefore needs **either** a third `GauntletPlane` trait method (e.g. `open_session(self: Box<Self>,
req) -> Result<SessionScope, Response>`, an ABI-relevant trait change even if "append-only" in
spirit) **or** its own bespoke non-trait session-open logic that only reuses
`verify_destination`. The plan text glosses this as "reuses the same verify_destination-before-
charge sequence" and never states which of the two it is. That's a real hole: the one concrete
code snippet in the doc doesn't type-check against the trait it's supposedly a "sibling" of without
an unstated trait extension.

## 5. Does `SessionScope`'s current shape match what `begin_session` needs downstream — no, and the design doc is stale about it

`crates/busbar-substrate/src/plane_host/scope.rs:366-484`: `SessionScope` is **not** the "empty
`#[non_exhaustive]` stub" both design docs describe (plane4-duplex-session.md §3.2 line 405-410,
and the 1.6.0-plan's B.4 line 607: *"the struct is already `#[non_exhaustive]` … nothing
constructs it today"*). It is **already fully built out**: real fields (`engine: Arc
<DurableHandleEngine>`, `owner: String`, `id: String`) and real methods (`new`, `open`, `get`,
`mutate`, `close`) — all wired and consumed today. `crates/busbar-voice/src/runtime/scope.rs:84-
102` proves it's already in production use: `SessionHandle` is a thin newtype wrapping exactly this
`SessionScope` (`SessionHandle::bind` → `SessionScope::new(engine, owner, id)`). Both design docs'
premise — that `SessionScope` is dormant and "nothing constructs it today" — is **false against the
current tree**; the docs are describing an earlier commit's state. (`#[non_exhaustive]` does exist
in `scope.rs`, but on line 507, a *different* struct — not `SessionScope`.)

Consequence for the return-type question: `begin_session` returns `(Arc<SessionCore<C>>,
SessionHandle)`, where `SessionHandle` is `busbar-voice`'s own wrapper, not the bare substrate
`SessionScope`. If `run_gauntlet_session` returns `Result<SessionScope, Response>` as proposed, the
voice plane still has to re-wrap that `SessionScope` into its own `SessionHandle` — fine, cheap —
but `SessionScope::new`/`bind` require an already-resolved `Arc<DurableHandleEngine>`, `owner`, and
`id` that `run_gauntlet_session` has no stated way to obtain from a bare `GauntletRequest` (no
engine handle, no id-minting scheme in `GauntletRequest`, `mod.rs:133-145`). The plan's B.4 sketch
(line ~590-604) shows a *future*, expanded `SessionScope` carrying `upstream_pipe: PipeId`, `lease:
CostHold`, `journal_scope: String` — fields that do not exist on the struct today. So "does the
return type match what `begin_session` needs downstream" is doubly unresolved: (a) today's
`SessionScope` has none of the session-runtime state (`lease`/`PipeId`/journal scope) the design's
own per-frame governance section (§3.2) requires it to carry, and (b) `begin_session`'s existing
budget/durable-open logic (item 2 above) would need to be *deleted and replaced*, not composed,
since `run_gauntlet_session` as sketched would re-do the lease-open (`open_lease`) itself under a
different, ABI-neutral name (no `CostHold`/`Magnitude` type in scope at the substrate layer without
the still-unshipped D2 slots, plan §T1.5).

## Verdict: SHIP-WITH-CHANGES

The core seam (`run_gauntlet`/`GauntletPlane`) is solid and exactly as cited — that part of the
design is trustworthy. But the audited artifact itself doesn't exist at the path given, and the
substitute design (plan §B.5) has three concrete mechanical holes: (1) `begin_session` isn't a
"coexists beside the gauntlet" story, it's a "rewire an existing bypass" story — undersold; (2) the
one code snippet for `run_gauntlet_session` doesn't type-check against `GauntletPlane` as it stands
today — it needs an unstated trait addition or a bespoke non-trait path; (3) the "SessionScope is
still an empty non_exhaustive stub" premise both docs rely on is **false** against
`crates/busbar-substrate/src/plane_host/scope.rs` as of this commit — it's live, populated, and
already consumed by `busbar-voice`, and it still lacks the lease/pipe/journal fields §3.2's
per-frame governance actually needs. None of these are fatal to the overall direction, but "append-
only, touches nothing" is oversold; fix the trait-shape gap and refresh the SessionScope-is-a-stub
claim before treating this as ready to build from.
