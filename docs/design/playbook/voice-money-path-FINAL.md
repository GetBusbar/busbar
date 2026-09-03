# Voice money-path — FINALIZED build spec (one cohesive workstream)

Base: `integration/config-seam-stage1-rebased` (ae85025d — HAS busbar-voice). Money-path byte-identical
or STOP. Adversary inputs folded (gauntlet sonnet+opus, usage-cost sonnet+opus, session-drop).
NOTE: the gauntlet-OPUS adversary read the main checkout (no busbar-voice) — discount its "voice absent /
D2 fictional" claims; keep its F3 (refund-on-refuse) point.

Verified seam: `MeteringHost::cost_reserve(...estimate_nanos...) -> Option<CostLeaseId>` and
`cost_settle(&self, lease, exact_nanos: u128) -> Option<SettleOutcome>` (plane_host/mod.rs:395,407).
So `cost_settle` takes a PRE-PRICED nanodollar total — pricing is caller-side.

## Piece 1 — usage→cost pricing (host-prices; voice stays neutral)
PROBLEM: voice can't reach the `pub(crate)` pricer (RateNanos/from_raw/price); price() has fixed labels
(DuplicateLabel on 2 lanes). `build_runtime_with_metering` binds an all-zero Pricing book → exhaustion
never fires.
FIX (additive, keeps rate_card in core, voice neutral): add ONE method to `MeteringHost`:
```rust
/// Price a plane's usage_units for `model` into nanodollars via the deployment rate_card
/// (the SAME CostModel path LLM uses). Returns None if the model/rate is unknown (caller fails closed).
fn price_usage(&self, model: &str, usage: &busbar_substrate::billing::Usage) -> Option<u128>;
```
- Core's MeteringHost impl prices via `CostModel::resolve_parts` (cost.rs:419-457) → nanodollar total. SAME arithmetic LLM uses → LLM byte-identity untouched (LLM path unchanged; this is a new entry point over the same function).
- Voice: on `response.done.usage`, build `Usage{usage_units}` from `IrDuplexUsage` (audio_in/text_in→input, audio_out/text_out→output, cached→cache_read — audio vs text as separate rate-card MODEL lanes, NO new unit/label/constant), call `host.price_usage(model, &usage)` → nanos, then `cost_settle(lease, nanos)`.
- REMOVE the plane-private zero `Pricing` book (churns SessionCore::new/VoiceRuntime surface — update call sites/tests).
- STOP if this requires a NEW UsageComponent variant / nano constant / voice-only label, or if any existing money oracle (egress_differential, on_exhausted, crossproto_delivery_billing) moves a byte — report options instead.
- Hot-ABI parallel: if the out-of-process cost_settle slot needs price_usage too, that's an additive slot — report before adding (money-path ABI).

## Piece 2 — run_gauntlet_session (verify-before-charge at session open)
`run_gauntlet` (plane_host/mod.rs:~177-185, Response-shaped via GauntletPlane::drive). `begin_session`
(voice topology/mod.rs:~106) today: open_lease → bind_session → handle.open, ZERO admission.
FIX (pure additive; run_gauntlet body byte-identical):
- Factor the OPEN-PASS ADMISSION (verify_destination → govern admit → breaker admit → cost_reserve) into a shared helper `fn admit_open(...) -> Result<Admitted, Response>`. Match LLM's real ordering (gauntlet-opus F1: LLM does govern+charge in one admission_door before selection; breaker at egress) — replicate LLM's actual order, don't invent a new one.
- Add `run_gauntlet_session(...) -> Result<Admitted, Response>` (or `Result<(SessionAdmit, CostLeaseId), Response>`) calling `admit_open`; it does NOT return a fattened SessionScope. begin_session keeps the existing `SessionScope {engine,owner,id}` (scope.rs:366) and owns the lease in the voice layer.
- begin_session calls run_gauntlet_session at the TOP; only on Ok do lease/bind/open + socket bind proceed. On refuse: zero bytes, zero charge.
- F3 (refund-on-refuse): if cost_reserve succeeds but a later open step fails, the reserve MUST be finalized/refunded (no orphan debit). Use Piece-3's guard.
- D3 witness: pin that run_gauntlet (one Response) and run_gauntlet_session (duplex) coexist AND that begin_session actually CALLS run_gauntlet_session (call-site use, not just seam existence — gauntlet-opus F7).

## Piece 3 — LeaseCloseGuard + refund (leak fix; session-drop ruling)
- Do NOT add an arena/Drop field to SessionScope (freezes wrong shape). 
- Add a by-value `LeaseCloseGuard` owned by the topology `run()` loop (topology/{mod,telephony,webrtc}.rs) that finalizes the D2 lease on ANY exit incl. panic — closes the hard-close `select!` race where a parked detached per-frame handler pins `Arc<SessionCore>` so `HostLease::drop→cost_close` is refcount-gated (telephony.rs:~179-187 + byte_duplex abort-on-drop gap).
- Apply the discarded `Settlement.refund` in `close_lease` (cost_host.rs:~118) — guard double-refund.
- Red-before-green test: an abnormally-closed session releases its reserve (reserve returns to the budget cell).

## Gates the agent must pass (report results)
cargo build/clippy/test -p busbar-voice --features runtime; workspace build; the 6 money oracles
(busbar-llm) byte-identical; plane-purity-lint --check 0/0; NO new label/unit/constant (grep-verify).
Collision: this workstream touches plane_host/mod.rs (MeteringHost) + voice topology/runtime/session —
disjoint from Stage A (config/admin/registry) and from M5 (voice lib.rs PLANE_DECL). Merge separately.
