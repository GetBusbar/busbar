# Money-path build refinements (from adversarial audits — apply BEFORE building)

## gauntlet-session (both audits: SHIP-WITH-CHANGES)
- `run_gauntlet` (`crates/busbar-substrate/src/plane_host/mod.rs:185`) is Response-shaped via `GauntletPlane::drive`. `run_gauntlet_session` CANNOT be built from it directly.
- FIX: factor the ADMISSION portion of the open pass (verify_destination → govern admit → breaker admit → cost_reserve) into a shared `fn admit_open(...) -> Result<Admitted, Response>` helper. `run_gauntlet` (one-Response) and `run_gauntlet_session` (duplex) both call it — pure factor-out, run_gauntlet behavior byte-identical.
- `run_gauntlet_session` returns the ADMISSION result + the reserved lease handle; it does NOT return a fattened SessionScope. `begin_session` (`crates/busbar-voice/src/topology/mod.rs:~106`) keeps using the existing `SessionScope {engine,owner,id}` (scope.rs:366-484, already built) and owns the lease in the voice layer (per session-drop ruling — no arena field added to SessionScope).
- begin_session ordering: call `run_gauntlet_session` at the TOP; only on Ok do open_lease/bind_session/handle.open + socket bind proceed. Refuse ⇒ zero bytes, zero charge.
- D3 witness: pin that `run_gauntlet` (one Response) and `run_gauntlet_session` (duplex) are distinct coexisting seams sharing `admit_open`, so a refactor can't inline/foreclose the sibling.

## usage→cost fold (both audits: SHIP-WITH-CHANGES)
- The pricer (`RateNanos`/`from_raw`/`reserved_nanos`/`price()`, cost.rs) is `pub(crate)` → UNREACHABLE from busbar-voice. Do NOT expose it to the plane.
- CORRECT DESIGN (keeps pricing host-side; voice stays plane-neutral, needs only MeteringHost): voice emits the `usage_units` map (BTreeMap<String,u64> — keys audio_in/audio_out/text_in/text_out/cached mapped onto the reserved billing keys input/output/cache_read via `busbar_substrate::billing::Usage`) through the `cost_settle` host slot; the HOST prices it via `CostModel::resolve_parts`'s `rate_card:`-derived `HashMap<String,RateNanos>` (cost.rs:419-457) into a nanodollar `CostBreakdown`. Verify the `cost_settle` ABI slot carries a usage map (not a pre-priced total); if it currently carries a bare u64 total, that's the seam to widen (additive, minor bump already at 19) — confirm against `hot/host.rs` cost_settle signature.
- Audio-vs-text rate separation = two rate-card MODEL lanes (existing per-(model,units) pricing), NOT a new unit/label/constant (STOP condition if a new one is introduced).
- The live defect to fix: `build_runtime_with_metering` (runtime/mod.rs) binds an all-zero Pricing book. Wire real rate_card rates (through the host, per above) so exhaustion actually fires.
- Guard: existing money oracles (egress_differential, on_exhausted, crossproto_delivery_billing) must stay byte-identical.

## Orchestration note
Playbook files exist in BOTH /Users/matthew/Developer/GetBusbar/busbar/docs/design/playbook/ (main checkout)
AND .../config-seam-work/docs/design/playbook/ (worktree). Consolidate onto the worktree at integration time; some earlier agents wrote to the main checkout path.
