# D33 — retiring the legacy crates

> **The question.** "How much of this app is on the legacy? Let's get that removed."
>
> **The answer, up front.** On `origin/integration/oracle-phase0` the app still *boots* on the
> legacy graph. The composition root names **144** legacy paths (56 `busbar_core::`, 37
> `busbar_substrate::`, 23 `busbar_llm::`, 20 `busbar_voice::`, 4 `busbar_mcp::`, 4 `busbar_a2a::`);
> `busbar-substrate` still reaches back into `busbar-core` at **161** non-test lines across 28
> files, and `busbar-substrate-values` at **13**. But **57 of the root's 144, and a large share of
> substrate's 161, resolve through a path `busbar-core` merely `pub use`s from somewhere lower**
> (there are 153 `pub use busbar_substrate…` lines in core). Those are not migrations. They are
> spellings. Retargeting a spelling costs nothing, proves itself byte-for-byte, and shrinks the
> stated legacy reach by roughly a third before a single behavioural line moves.
>
> What is left after the spellings is the real work, and it is **not** a move. See §3: the ceiling
> forbids it.
>
> **Two corrections, found while executing (§5).** (1) `busbar-substrate` and
> `busbar-substrate-values` have **zero** `busbar_core::` reach — not 161 and 13, but **nought**, in
> production *and* in test code, and neither crate carries a Cargo edge to `busbar-core` at all, not
> even a dev-dependency. Every remaining mention is a doc comment recording where an item used to
> live. Those two crates are **already done**; the work item is retired, not scheduled. (2)
> `busbar_core::admin::restart` cannot move to the root yet: it is a shared process-global that
> core's own admin handler still writes (`begin_drain`, `can_restart`, `supervisor_detected`).
>
> **§7 is the third and largest correction (2026-09-08).** The whole tree was measured module by
> module against this plan, and the plan's premise — *residue with an existing replacement; delete
> and repoint* — holds for **8%** of the legacy body. Where a §2 row and a measurement disagree,
> **§7 wins and the row is amended**; every row §7 names is annotated in place.

## 1. The ceiling, and what it decides

`docs/design/ARCHITECTURE.md` §1.1 sets, and `cargo xtask gate construction` measures:

| ceiling | today | headroom |
|---|---|---|
| `busbar-kernel` (own + call-graph-reachable `busbar-unit-*`) ≤ **8 000** | 5 239 | 2 761 |
| `busbar-caps` + `busbar-contract` plugin-visible surface ≤ **3 500** | 3 466 | **34** |
| all `busbar-unit-*` ≤ **45 000** (verbs ≤ 15 000) | 13 672 (verbs 1 408) | 31 328 |
| the union kernel + caps/contract + unit-\* ≤ **56 000** | 22 377 | **33 623** |
| `busbar-grammar` ≤ 500 / `busbar-contract-transport` ≤ 1 000 | 386 / 443 | 114 / 557 |

The legacy production body is ~**107 k** lines (core 46 k, substrate 15 k, llm 14 k, mcp 12 k, a2a
12 k, voice 5 k, plugin-loader 3 k). The union has **33.6 k** of headroom. **Three quarters of the
legacy tree cannot be moved anywhere the gate will accept it.** The `caps`/`contract` pair has
thirty-four lines of headroom — for practical purposes it is closed, and no row below proposes
adding to it.

Two escape hatches exist and are the spine of the plan:

- **Planes and transports are not in the union.** `busbar-plane-*`, `busbar-transport-*` and the
  four `*-codec` crates carry no §1.1 ceiling. Dialect bodies belong there and the tree has already
  started: `busbar-llm-codec` is 37 k raw and `busbar-voice-codec` 5 k, so the LLM and voice dialect
  halves have *already* left `busbar-llm`/`busbar-voice`. What remains in those crates is engine.
- **The composition root (`crates/busbar`) is not in the union either.** Boot-shaped code — CLI
  diagnostics banners, TLS listener config, restart/drain publication, protocol installation — is
  the root's own and belongs *in the root*, not in a unit.

So the verdict vocabulary resolves, for this tree, mostly to **REPLACE** and **DELETE**, with
**MOVE** reserved for (a) the root's own boot leaves and (b) plane/codec-shaped bodies. Anything
whose only plausible home is the kernel or a unit must be **rewritten small** as part of the unit
that already owns that concern, never lifted.

## 2. Symbol ledger — the composition root

Enumerated with

```
grep -rho 'busbar_\(core\|llm\|substrate\|mcp\|a2a\|voice\)::[A-Za-z_:]*' \
  crates/busbar/src/root/ crates/busbar/src/main.rs | sort -u
```

`n` is the site count. **RE-EX** marks a path `busbar-core` only re-exports — retargeting it is a
spelling change with no behavioural surface at all.

### 2.1 `busbar_core::` — 56 symbols

| n | symbol | verdict | oracle families | ordering |
|---|---|---|---|---|
| 4 | `diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED` | **RE-EX → REPLACE** by `busbar_substrate_values::diagnostics::…` | `boot\|`, `cli\|` | none — cut 1 |
| 4 | `diagnostics::CLI_VALIDATE_CONFIG_INVALID` | RE-EX → REPLACE, ditto | `cli\|`, `documented-validate-checks\|` | cut 1 |
| 2 | `diagnostics::WORKER_THREADS_INVALID` | RE-EX → REPLACE | `boot\|` | cut 1 |
| 2 | `diagnostics::JEMALLOC_IDLE_PURGE_FALLBACK_UNAVAILABLE` | RE-EX → REPLACE | `boot\|` | cut 1 |
| 2 | `diagnostics::CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE` | RE-EX → REPLACE | `cli\|` | cut 1 |
| 1 ea | `diagnostics::{SIGNING_KEY_GENERATION_FAILED, METADATA_PROTECTION_DISABLED, CONFIG_OVERLAY_NOT_WRITABLE, CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED, CLI_LIST_PLUGINS_TRUST_INVALID, CLI_LIST_PLUGINS_CONFIG_UNREADABLE, BOOT_FATAL_ERROR}` | RE-EX → REPLACE | `cli\|`, `boot\|`, `plugin-list\|`, `documented-overlay-refused\|` | cut 1 |
| | *all 13 constants are defined in `busbar-substrate-values/src/diagnostics/mod.rs`; `busbar_core::diagnostics` is `pub use busbar_substrate::diagnostics::*`. The banner text, the code and `REGISTRY` order are untouched, so `docs/diagnostics.{md,json}` are unchanged.* | | | |
| 3 | `proxy::reqlog::REQUESTS` | **KEEP as a leaf, for now** — all three sites are `#[cfg(test)]` inside `root/units_llm.rs`, which the late-accrual agent owns. Retarget with that landing. | `llm\|`, `billing\|` | blocked on units_llm |
| 2 | `state::set_worker_shutdown` | RE-EX (`busbar_substrate::topology`) → REPLACE | `boot\|`, `admin.ops\|` | cut 2 |
| 1 ea | `state::{set_worker_id, set_worker_detached, set_data_workers, DETACHED_DRAIN_GRACE}` | RE-EX (`topology` / `detached`) → REPLACE | `boot\|`, `concurrency\|` | cut 2 |
| 1 | `state::DetachedTasks::new` | RE-EX (`busbar_substrate::detached`) → REPLACE | `admin.ops\|` | cut 2 |
| 1 | `state::App` | **DELETE with the crate.** The legacy application object. Its replacement is the root's own kernel wiring (`root/kernel.rs`); it disappears when the root stops booting the legacy pipeline, not before. | every family | last — after the engine twins |
| 2 | `config::TlsCfg` | RE-EX (`busbar_substrate::tls`) → REPLACE; the 1.5.5 `deny_unknown_fields` struct itself is untouched | `documented-tls\|`, `boot\|` | cut 2 |
| 2 | `config::secret::SecretResolver` | **MOVE → `busbar-core-config`** (§7.2 amends this row: the config layer has no replacement anywhere, so neither does its resolver; `config/secret.rs` is one of only two files in the layer with zero outbound edges, so it is movable the day the crate exists) | `config\|`, `boot\|` | with the config crate |
| 1 | `config::GroupCfg`, `config::groups::{LimitCfg, LimitMetric::Budget, LimitWindow::Total}` | RE-EX (`busbar_substrate::config::groups`) → REPLACE. **All four sites are in `root/units_llm.rs`** → blocked | `billing\|`, `config\|` | blocked on units_llm |
| 2 | `plane::registry::install_planes`, 1 `plane::registry::PlaneDecl` | **`PlaneDecl` is RE-EX and correct. `install_planes` is NOT.** The substrate's `plane::registry` carries `PlaneDecl`, `check_owned_config_claims`, `register_test_plane`, `test_registered_planes` — no process installer, no `plane_decls()`. **THE INSTALLER CANNOT MOVE TO THE ROOT EITHER**, which is the finding this row needs: `install_planes` writes the `INSTALLED` cell that `plane_decls()` reads, and `plane_decls()` has **13 production readers inside the legacy crate** (`boot.rs:58,107`, `router.rs:432`, `state.rs:976`, `appbuild.rs:1422,1634,1806,1896`, `config/named_map.rs:73`, `admin/v1/json/mod.rs:291`, `admin/v1/json/handlers.rs:3993,4724`, `admin/v1/service.rs:2483`). `crates/busbar` is bin-only (no `[lib]`) and the edge runs root → legacy crate, so those readers cannot name a root module and the storage cannot follow the installer. **The face this row needs is the process plane list living where BOTH the root and the legacy crate can read it** — i.e. the decl set as `busbar-contract` DATA. `install_planes` moves to the root in the same change that lands, and not before. | `boot\|`, `mcp\|`, `a2a\|` | blocked on the decl set becoming contract data |
| 2 | `plane::config::config_sections` | **THIS ROW WAS WRONG.** `busbar_substrate::plane::config::install_plane_sections(provider: fn() -> Vec<&'static str>)` is the **consumer** of `config_sections`, not its replacement — the root passes the legacy crate's function *into* it. The fold itself (`plane/config.rs:378`, over `config_sections_from` at `:388`) has no counterpart below, and it reads `plane_decls()`, so it is blocked on exactly the row above. Two production readers inside the legacy crate (`config/mod.rs:2328,2441`) rule out a move to the root for the same reason. | `config\|` | blocked with `install_planes` |
| 2 | `plane_host::engine_host`, 1 `plane_host::live_host_factory` | **DELETE with the crate** — the `EngineHost` seam is the coexistence adapter between the legacy engine and the plane crates; it dies with the engine twins. §7.8 amends the ORDER: the `EngineHost` trait cannot be deleted before the engine is, because six of the nine llm step files name it | `llm\|`, `mcp\|`, `a2a\|` | last, and after the R4 pre-cuts |
| 2 | `governance::GovState`, 1 `GovState::new_with_signer`, 1 `MemoryStore::new`, 1 `spawn_budget_flusher` | **REPLACE** by the caps/kernel governance path (`busbar-caps::hold`, `busbar-kernel::teller`) — but the *ledger* leg is being landed right now by the late-accrual agent; do not touch. **The VIRTUAL-KEY path, measured (`keep-core-delete-4`, over G1' `keep-face-governance`):** the face is `busbar_contract::{VirtualKeyDirectory, KeyFacts, KeyScope}`; its ONE implementor is the root's `auth_bindings::GovernanceDirectory`, which reads exactly `GovState::{verify_token, is_revoked, admin_token_hash}` — the same three the root's bindings read before the face landed, so the face orphaned nothing in core: the `ResolvedKey`/`KeyVerifier`/`RevocationView`-era readers were in `busbar-unit-auth` and are deleted there. Every `pub`/`pub(crate)` item under `governance/` was grepped for production readers; the only two with none (`pending_metering_totals`, `concurrent_in_flight`) are already `#[cfg(test)]`. The key directory itself (`GovState.keys`, `verify_token`, the denylist, `create_key`/`update_key`/`delete_key`/`rotate_key`) is live: the root's directory, core's own auth middleware (`auth/mod.rs`) and the admin key verbs read it. It moves when a unit owns the key store, behind the same face. `spawn_budget_flusher` stays until the budget cells leave core. | `billing\|`, `teller-meter-row\|` | blocked on the late-accrual landing; the key store, on a unit owning it |
| 2 | `boot::hydrate_all`, 1 `boot::start_planes`, 1 `boot::generate_signing_key_hex`, 1 `boot` | **MOVE** into the root's own boot (`crates/busbar/src/root/durability.rs` already owns hydration policy) as the legacy pipeline retires | `boot\|`, `store-persist\|`, `durable-governance-precondition\|` | after cut 4 |
| 1 | `proto::registry::install_protocols_with_path_ingress`, 1 `install_protocols`, 1 `proto::ProtocolDecl` | **THIS ROW WAS WRONG, AND THE INSTALLER IS NOW DONE.** There is no `busbar_substrate::proto::registry` module to re-export from — `busbar_substrate::proto` is a re-export of the values leaf's single-file `proto`, whose only `registry` spelling is a *function*. `install_protocols` and `ProtocolDecl` were genuine RE-EX and still are. `install_protocols_with_path_ingress` was never a re-export: it was the one symbol the legacy `proto/registry.rs` owned, and its stated reason for staying ("it names the core-only `Arrival`") had been stale since `ingress/path_ingress.rs` became a re-export of `busbar_substrate::ingress::arrival`. **MOVED to `crates/busbar/src/root/proto_install.rs`** — the composition root was its only caller, so it needs no replacement face and no transitional re-export. | `http\|`, `llm\|`, `route\|` | **done** |
| 1 | `profile::enabled`, 1 `profile::dump` | RE-EX (`busbar_substrate::profile`) → REPLACE | `ops\|` | cut 2 |
| 1 | `metrics::init` | RE-EX (`busbar_substrate::metrics`) → REPLACE | `ops\|` | cut 2 |
| 1 | `ingress::PathIngress` | RE-EX (`busbar_substrate::ingress::arrival::PathIngress`) → REPLACE — the root *already* names the substrate spelling one line away | `llm\|`, `route\|` | cut 2 |
| 1 | `proxy::configure_route_policy_headers` | RE-EX (`busbar_substrate::proxy`) → REPLACE | `http\|`, `route\|` | cut 2 |
| 1 | `admin::restart::{publish_shutdown, release_asked_drain, drain_released_at_exit}` | **MOVE, but blocked.** `busbar-core/src/admin/restart.rs` is 152 lines of process-lifecycle broadcast with no `App` in its signature, and its one true owner is the composition root (it *is* the process). But the module is a set of process **globals** that core's own legacy admin handler still writes — `crate::admin::restart::{supervisor_detected, can_restart, begin_drain}` at `busbar-core/src/admin/v1/json/handlers.rs:2494,2506,2517`. Moving the module to the root would split one static across two crates and silently break `POST /admin/restart` → drain-release. The move lands **with the admin plane**, when `busbar-plane-admin` owns the restart verb and core's handler is deleted. | `documented-admin-restart\|`, `admin.ops\|` | blocked on the admin plane owning the restart verb |
| 1 | `admin::planeverbs::CorePlaneAdminEnvelope` | REPLACE by `busbar_substrate::admin_verbs::install_plane_admin_envelope` (root names both today) | `admin.ops\|` | cut 3 |
| 1 | `egress::seam::CoreHostlessEgress` | REPLACE by `busbar_substrate::egress::seam::HostlessEgress` (root names both today) | `llm\|`, `mcp\|` | cut 3 |
| 1 | `cost::CostModel::resolve_parts` | **REPLACED, cell-proven** (`keep-face-costmodel-2`). `busbar_unit_cost::CostModel` (`model.rs`) binds the card, the `groups:` topology and the flat fee as one value — `resolve_parts`, `card`, `groups`, `pricing_enabled`, `model_unpriced` — and `GroupTable::resolve` is the ONE projection the door walks; the resolved topology's types moved down from the admission unit, whose walk stays as `ChainWalk`. The root's `group_specs` is a relay with no arithmetic (`GroupSpec`/`LimitSpec`/`ScopeSpec`, the card's `TierRates` shape), so the unit's dependency closure is still `busbar-caps` alone. The byte-identity cell (`root/tests/policy.rs`) holds core's resolver against the unit's on every field of every bucket, the clamped fee and both pricing-guard answers, and retires with `cost.rs`; the admission unit's tests resolve through the same face. **Wave A, measured (`keep-core-delete-4`).** The RATE HALF is done: core's private nano-rate table (`RateNanos`, `from_raw`/`from_cfg`, `reserved_rate`/`reserved_nanos`, the two nano constants — 119 lines) is deleted and `cost::CostModel` holds the unit's `RateCard`, built by `RateCard::from_config` over the config rows' neutral raw view; `pricing_enabled`/`model_unpriced`/`price_per_request_cents`/the lane lookup are the card's own answers and the derive loops price term for term as before. The dead second pricer (`cost::price`, `ExtraRates`, `STANDARD_TIER_BP`, the open-label namespace — 140 lines, `allow(dead_code)` outside tests) is deleted. **Wave B, measured (`keep-core-delete-5`): the GROUP HALF is done, and the two faces wave A named are landed.** (i) THE RELAY IS THE CONTRACT'S AND THE GRAMMAR'S, not the root's: `GroupSpec`/`LimitSpec`/`ScopeSpec`/`LimitMetric` are `busbar_contract::limits` (beside the RESOLVED form the contract already owns — `ids::BucketRef`, `ids::BucketScope`, `ids::BucketChain`), the one `GroupCfg -> GroupSpec` relay is `busbar_substrate::config::groups::group_specs` beside the grammar it reads, and the root's 39-line copy is deleted. Every party reaches it through an edge ARCHITECTURE.md already grants — `substrate -> contract`, `unit -> contract`, `legacy -> substrate`, `root -> substrate` — so no reader needs a copy, which is the whole point: with the vocabulary owned by the projecting crate only a composition root could name both sides. (ii) THE WALK IS THE DOOR'S: `busbar-core -> busbar-unit-admission` is declared (the drain permits it), `cost::CostModel` holds a `busbar_unit_cost::CostModel` and drives `GroupTable::resolve` over the one relay, and `ChainWalk` is walked ONCE PER GROUP AT BOOT. A request READS its chain by index-chase; `cost::BucketView` is a CURSOR (every field a borrow of, or a `Copy` off, a unit-owned value) so the admission path allocates nothing to resolve a chain — pinned by ADDRESS in `cost_tests::chain_read_is_a_borrow_not_a_build`, because a per-request rebuild returns equal values and would pass an `assert_eq!`. `project_groups`, `GroupBucket`, `GroupRuntime`, `Chain`, `ChainBucket`, `group_idx` and the whole byte-identity view (`resolved_view`, `resolved_fee`, `ResolvedGroupView`, `ResolvedBucketView`, `scope_pair`) are deleted; the root's cell now asserts the claim that is not tautological — that the engine and the root resolve the SAME `GroupRuntime` values off one configuration, by the unit's own equality. **Wave C, measured (`keep-core-delete-7`): the MONEY HALF IS GONE, and it needed no Store ABI change.** The T4-2 design's own headline: the blocker wave B recorded — that the unit derives over `&[UsageLine]` while the ledger row is a `BTreeMap<String, u64>`, so the map could not be priced without lifting it per call — was answered by an ADDITIVE face rather than by a wire change. `busbar_unit_cost::LaneRates::reserved_units_nanos` prices the MAP, beside the line fold and against the same card, and `derive_spend_{minor,micros}_units` derive over it; the accumulation and both projection tails are written ONCE for both report shapes. No wire, no ABI bump, no backend migration, no allocation, +70 measured surface lines in the unit, declared. The engine's fourteen pricing cells were copied into the unit and both sides ran green BEFORE the deletion, which is what makes it a re-point and not a loss of proof; the two divergences the design named are pinned as cells of their own (open-class pricing agrees on every card `from_config` can build, because `set_rate` has no production caller; the plain-vs-saturating add is identical below overflow and the unit's is a FIX above it). `reserved_nanos`, `derive_spend_cents`, `derive_spend_micros`, the private `lane` helper and `price_usage_nanos` are ALL deleted: the budget engine's four readers and the admin projection's one derive through the cost unit directly (through the one `pub(crate) use` seam line, so the unit is named once in the crate), and `price_usage_nanos` moved to a private free function beside its two `plane_host` callers rather than being copied into both. `cost.rs` is 471 lines (was 950, then 756, then 566) and derives no money at all; oracle billing/ledger/auth.lifecycle 21 cells, 0 diverging. **Wave D, measured (`keep-core-delete-8`): THE CHAIN CACHE IS GONE, and it did not go where this row said it would.** The residue sentence sent it to `busbar_unit_cost::GroupTable`. It cannot go there and the compiler settles it rather than a preference: the cache is made of what the WALK returns — `BucketChain`, `ChainBucket`, `ChainGroup` — and those four, with `ChainWalk` itself, are `busbar-unit-admission`'s, a crate that already depends on `busbar-unit-cost`, so the reverse library edge is `error: cyclic package dependency` by name. (The dev-only edge back from the cost unit, which carries the two-copies-of-one-rounding-rule agreement test, is permitted precisely because it is dev-only.) Two ways round were measured and both refused: moving `chain.rs` down into the cost unit reverses this row's OWN wave-B ruling that THE WALK IS THE DOOR'S, and `busbar_contract::ids::BucketChain` is a different value — `BucketRef` is `{id: &'static str, scope, capped}` over a `BoundedVec`, the shape a refusal PRINTS, with no caps, no window word and no group name. So the cache is `busbar_unit_admission::{ChainCache, Chain, BucketView}`, declared beside the `ChainWalk` it memoises, which is the same ruling one step further out: the topology is the cost unit's, the walk is the door's, and a memo of the walk is made of what the walk returns. `cost::BucketView`, `cost::Chain`, `CostModel::{group_chain, capped_bucket_ids}` and the `chains`/`empty_chain`/`capped_bucket_ids` fields are DELETED; one field, `chains: ChainCache`, replaces three. `chain_for` keeps its `&VirtualKey` entry (a unit crate cannot name `busbar-api`, and every reader holds it by that type) and `bucket_enforces_a_cap` keeps its name, both as relays, which is what the rule permits when the move makes an entry one line. The by-address no-allocation cell (`cost_tests::chain_read_is_a_borrow_not_a_build`) crosses UNCHANGED and now pins more than it did: it enters at the relay, so it holds the whole re-pointed path from the engine's entry to the cache's borrow. Measured: `cost.rs` 471 -> 292 lines (224 -> 116 surface), core -179 production against a 138-line declared raise (unit-total 14795 -> 14933, union 23685 -> 23825, kernel 5379 -> 5381 — the last because the admission unit's `lib.rs` is in the kernel's call-graph name-match set, so DECLARING a module there spends kernel budget: two lines of wiring, not two lines of kernel). 105 of the 138 are `cost.rs`'s own lines by identity, once `pub(crate) ` -> `pub ` and `key_id` -> `attribution_bucket_id`; the other 33 are the `ChainCache` struct, its `resolve`, `is_empty`, the widened signature and the module wiring — what a `pub` type in a `deny(missing_docs)` crate costs over a `pub(crate)` cursor inside its only reader. `busbar-core x unit` FALLS 43 -> 37 and wave B's own seam declaration is re-priced 24 -> 18 in the same commit, because six of the names it paid for left with the memo. Money oracle: 21 cells, 0 diverging. **What is still in `cost.rs`, and the reader that blocks each:** `is_bucket_of_group` (`governance/state.rs` group drop) and `bucket_enforces_a_cap` (`still_enforces_a_cap`), which are the ENGINE'S questions about the ledger's own ids rather than the unit's; and the `App`-shaped entries `resolve_parts`/`with_groups`/`groups`/`group_named`/`flat`/`card` that `appbuild.rs`, `state.rs`, `admin/v1/service.rs`, `plane_host/*` and the eight `test_support` sites hold by type. | `billing\|`, `ledger\|`, `teller-meter-row\|` | rate half + group half + MONEY half + CHAIN CACHE landed; the residue is the two ledger-id questions and the `App`-shaped entries, which go with `App` |
| 1 | `REQUEST_ACTIVITY_TICKS` | MOVE to the root (a drain-timing constant the root reads) | `admin.ops\|` | cut 3 |
| 1 | `test_support` | KEEP as a leaf until the legacy test corpus retires; not production | — | last |
| 2 | bare `busbar_core` | follows whatever the line above resolves to | — | — |

### 2.2 `busbar_substrate::` — 37 symbols

The substrate is **not** to be retired in this wave. It is the layer core is being drained *into*;
retiring it is a separate wave once the units own its behaviour. Every root row here is therefore
**KEEP as a leaf** except where noted, and the useful work is the *opposite* direction — moving core
down into it, which §2.1 does.

Three rows are exceptions, and they are the substrate's own remaining backwards reach, not the
root's:

| symbol group | verdict | oracle families | ordering |
|---|---|---|---|
| `ingress::arrival::{ArrivalCtx, ArrivalCtx::new, BodyIngress, PathIngress, install_*}` (13 sites) | KEEP — the neutral arrival seam; it is the *destination* of the core ingress drain | `llm\|`, `route\|`, `http\|` | — |
| `config::limits::LimitsResolved` (5) · `config::groups::{GroupCfg,LimitCfg,LimitMetric}` (6) | **KEEP as a leaf — 1.5.5 config parsing kept verbatim for byte-identity.** `deny_unknown_fields`, field order and serde attrs are frozen; 1.6.0 config = 1.5.5 config + plane sections. §7.2 amends the DESTINATION: these leaves are the part of the grammar that already crossed, and they move on to `busbar-core-config` with the rest of the layer rather than resting in the substrate, which is itself legacy. | `config\|`, `documented-docker-defaults\|` | with the config crate |
| `store::{now, now_ms, tool_key, BreakerState}` (9) | KEEP — neutral clock/store leaves | `teller\|` | — |
| `governance::{signing::TokenSigner::from_secret_bytes, signing::DEFAULT_KID, NewKeySpec, metering_bucket}` | KEEP — the busbar-signed-token crypto, already neutral | `key-rotate\|`, `key-expiry\|`, `key-revoke\|`, `billing\|` | — |
| `plane_host::EngineHost`, `proto::install_stream_translator_factory` | **DELETE with the engine twins** | `llm\|` | last |
| the rest (`proxy::*`, `diagnostics::*`, `egress::seam::*`, `handlers::request_handler`, `admin_verbs::*`, `plane::approvals::nonce`, `plane::config::install_plane_sections`, `ingress::duplex_ws::install_ws_arrivals`) | KEEP | — | — |

### 2.3 `busbar_llm::` — 23 symbols

| symbol group | verdict | oracle families | ordering |
|---|---|---|---|
| `proto_codec::PROTO_{OPENAI,ANTHROPIC,GEMINI,BEDROCK,COHERE,RESPONSES}` (22 sites) | **MOVE** into `busbar-llm-codec` (already 37 k of dialect body) and name them from `busbar-plane-llm` | `llm\|`, `http\|` | after the llm default flip |
| `native_ingress::{operation_ingress, ingress_path_model, synthesize_completion}`, `arrival::{PathArrivalFacts, PathModelFacts, gemini_rest, gemini_path_parse, bedrock_path_parse}`, `unit::walk`, `PATH_INGRESS`, `BODY_INGRESS` | **DELETE with the engine twins** — this is `pipeline.rs`/`walk.rs`/`native_ingress.rs`/`arrival.rs`, the two dispatch twins. Explicitly **out of scope for this session.** | `llm\|`, `billing\|`, `teller-route-failover\|` | after the llm leg's late accrual and the default flip |
| `proto_stream::new_stream_translator` | DELETE with the twins | `llm\|` | last |
| `{PLANE_DECL, DECLS}` | DELETE when `busbar-plane-llm` is sole | `llm\|` | after flip |
| `spawn_probers` | MOVE to the root (a boot-time task spawn) | `boot\|` | after flip |
| `testkit::install_test_seams` | KEEP (test surface) | — | — |

### 2.4 `busbar_voice::` — 20 symbols

All 20 sites live in `crates/busbar/src/root/units_voice.rs` and the **voice default flip is
queued**. Verdict for the whole set: `runtime::*`, `mount::*`, `topology::*`, `ir::codec::*` →
**DELETE with the crate** once the flip lands and `busbar-plane-voice` + `busbar-voice-codec` are
sole; `config::configured_session_model` → **MOVE** into `busbar-plane-voice`'s claim config;
`{PLANE_DECL, DIAGNOSTICS}` → DELETE with the crate. Ordering: **every row is blocked on the voice
default flip.** Oracle: there is no voice family in `cells.json` — the flip's own duplex-session
suite is the proof, plus `boot\|` for the decl.

### 2.5 `busbar_mcp::` / `busbar_a2a::` — 8 symbols

`mcp::{PROTO_DECL, PLANE_DECL, DIAGNOSTICS}` and `a2a::{PLANE_DECL, DIAGNOSTICS}` → **DELETE with
the crate**, after `busbar-plane-mcp` / `busbar-plane-a2a` are sole (they are 3.2 k and 2.9 k
against the legacy 22 k / 21 k, so the codec halves — `busbar-mcp-codec` 1.7 k,
`busbar-a2a-codec` 0.9 k — are still thin and the bodies have not crossed yet).
`mcp::mcp::stdio_serve::serve_stdio` → **REPLACE** by `busbar-transport-stdio`.
`a2a::taskstore::TASKS` (2) → **REPLACE** by the kernel's `PlaneRecord` store (§2.3 of
ARCHITECTURE). Oracle: `mcp\|`, `a2a\|`. Ordering: both after their planes are sole; the taskstore
row additionally after the kernel record store lands.

## 3. Crate-level sequence

The order is forced by three facts: the union ceiling (§1) means nothing large moves; the money path
must stay byte-identical; and three landings are in flight.

**Wave 0 — spellings (this session).** No behaviour, no bytes. Retarget every RE-EX path off
`busbar_core::` onto the crate that actually defines it. This is 17 root symbols plus the 13
diagnostics constants, and the same treatment applied to `busbar-substrate`'s 161 lines and
`busbar-substrate-values`' 13. **Nothing must land before it.** It is the only work in the plan with
no ordering constraint at all, and it is why it goes first: it makes the remaining reach *honest*,
so the next wave's counts mean something.

**Wave 1 — the root's own boot leaves (this session).** `admin::restart` (152 lines),
`REQUEST_ACTIVITY_TICKS`, then `config::secret::SecretResolver`. These are process-lifecycle and
boot-credential concerns the composition root already owns; they go **into `crates/busbar`**, which
carries no §1.1 ceiling, and the core module is deleted outright (no re-export — nothing else names
`admin::restart`). Must land after wave 0 only so the diffs do not overlap.

**Wave 2 — `busbar-substrate`'s remaining backwards reach — *retired, nothing to do*.** Measured
directly (§5): zero. The Phase-B extraction already finished this. The 161 and 13 in the brief are
what a raw `grep` over the two crates returns, and every one of those lines is a `//` or `///`
comment recording the item's former home. `busbar-substrate/Cargo.toml` names `busbar-core` in seven
comment lines and in no dependency, dev-dependency or feature. **The counter, not the code, was the
problem** — the purity lint strips comments and would have said so.

**Wave 3 — the plane crates, one at a time, each after its default flip.** Order: **voice first**
(5 k, flip queued, codec already carries the dialect), then **mcp** (12 k), then **a2a** (12 k),
then **llm** (14 k) last because its engine is the dispatch twins. For each: the dialect body moves
to `<plane>-codec`, the plane behaviour to `busbar-plane-<x>`, the decls delete,
`scripts/plane-delete-test.sh --all` proves the crate is actually removable. **Ceiling note:** none
of these consume union headroom, which is why this wave is tractable at all.

**Wave 4 — the engine twins.** `busbar-llm`'s `pipeline.rs` / `walk.rs` / `native_ingress.rs` /
`arrival.rs` and the `EngineHost` / `plane_host` coexistence adapters. **Explicitly out of scope for
this session.** Blocked on: the late-accrual pricing landing (`busbar-llm/src/unit/meter.rs`,
`root/units_llm.rs`, `busbar-caps/src/hold.rs`, `busbar-kernel/src/teller.rs`), then the llm default
flip.

**Wave 5 — `busbar-core` itself.** Only reachable once waves 2–4 have drained it. 46 k in, 33.6 k of
union headroom: the arithmetic says the residue is **deleted, not relocated**. `state::App`,
`boot::*`, `plane_host::*`, `governance::GovState` and `cost::CostModel` are each *replaced* by a
unit that already exists (`busbar-unit-cost` 579 lines against core's cost body is the shape of the
whole wave). **Not in this session.**

**Wave 6 — the codec fold: one crate per plane (owner decision, 2026-09-06).** Once wave 5 has
retired `busbar-core` and every plane crate's legacy caller is gone, each `*-codec` crate folds
into the plane crate it was split out of for the strangler: `busbar-plane-llm` absorbs
`busbar-llm-codec`, and likewise `busbar-plane-mcp`/`busbar-mcp-codec`,
`busbar-plane-a2a`/`busbar-a2a-codec`, `busbar-plane-voice`/`busbar-voice-codec`. The separate
codec crates existed only so the legacy engine and the new plane could share one codec during the
strangler; with the legacy caller deleted there is nothing left to share it with. Preconditions,
all required before a fold cut lands:
- the legacy caller of that plane's codec is gone (wave 3/4/5 has retired the engine twin that
  named it);
- `scripts/plane-purity-lint.sh --strict` and the source-denylist gate are green on the folded
  crate exactly as they were on the codec crate today — folding changes the crate boundary, not the
  rule;
- `scripts/plane-delete-test.sh --all` is green on the folded crate (the deletion test proves the
  plane, codec included, is still cleanly removable);
- the plugin summary (`docs/design/ARCHITECTURE.md` §1.1's crate list, `--validate`'s plugin
  listing) reads **five planes and no separate codec crates** — admin, llm, mcp, a2a, voice, each
  one crate.

Planes carry no §1.1 line ceiling (§1's first escape hatch), so the gate allows the fold outright;
nothing in this wave asks for a ceiling exception. This is the explicit last wave of D33: the plan
is not "done" until the fold has landed on all four non-admin planes and the tracker's D34 row (see
`docs/design/1.6.0-TRACKER.md`) is checked.

Two standing carve-outs, in every wave: the 1.5.5 config structs
(`busbar_substrate::config::{groups, limits}`, every `deny_unknown_fields` type) are **KEEP as a
leaf, verbatim, for byte-identity** — 1.6.0 config is 1.5.5 config plus plane sections and nothing
else; and the legacy `/usage` rows and `MeteringRow` literals stay where they are, the 1.6.0 ledger
being written *beside* them by design.

## 4. Proof obligations

Every cut: `cargo build --workspace`; `cargo test -p <touched>`;
`cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`;
`cargo xtask gate construction` with no new red row and the §1.1 ceilings above honoured;
`scripts/plane-purity-lint.sh --strict` not worse; `scripts/plane-delete-test.sh --all` when a plane
crate's dependencies changed.

Every third cut: `testing/shadow-oracle/record.sh --plane all --filter
'^(billing|llm|admin\.ops|boot|config)\|'` on the release binary, then `diff-cells.py --strict
--allow-harness-skew` against the 1.5.5 golden. **Zero diverging cells, or the cut is reverted** —
there is no "explained divergence" branch in this plan, because every cut in waves 0–2 is a
spelling or a relocation and a spelling that changes a cell is a bug.

The gate's baseline on `origin/integration/oracle-phase0` already carries red rows
(`request-path-fn-size` 1117/200, `terminal-doors-in-audit-step` 17/0, `one-pick-site` 4/2,
`hold-escapes` 2/0, `ports-only-tests:busbar-llm` 29/20, the `source-denylist` plane rows). Those
are pre-existing and are not this task's to fix; the obligation is **no new red row and no worse
number**. Note that `ports-only-tests:busbar-llm` (29 against a ceiling of 20) is itself a legacy
reach counter, so wave 0 should move it down, not up.

## 5. What was measured, and how

Every count in this document is reproducible from the tree. The commands, and the answers on
`origin/integration/oracle-phase0`:

```
# the root's legacy reach, by crate
grep -rho 'busbar_\(core\|llm\|substrate\|mcp\|a2a\|voice\)::[A-Za-z_:]*' \
  crates/busbar/src/root/ crates/busbar/src/main.rs | sort -u        # 144 distinct

# core-defined vs core-re-exported: 153 `pub use busbar_substrate…` lines in busbar-core
grep -rn 'pub use busbar_substrate' crates/busbar-core/src --include='*.rs' | wc -l

# the substrate's real reach — comments and test code excluded
grep -rn 'busbar_core::' crates/busbar-substrate/src --include='*.rs' \
  | grep -vE ':\s*(//|/\*|\*)' | wc -l                                # 0
grep -rn 'busbar_core::' crates/busbar-substrate-values/src --include='*.rs' \
  | grep -vE ':\s*(//|/\*|\*)' | wc -l                                # 0
grep -n 'busbar-core' crates/busbar-substrate/Cargo.toml               # 7 hits, all comments
```

The lesson worth keeping: **a raw `grep` for a crate path counts prose.** In a tree whose migration
discipline is "relocate the item and leave a comment saying where it came from", the comments
accumulate exactly where the migration has *succeeded*, so the naive reach counter is highest
precisely where the work is finished. Any future legacy-reach number in this project should be taken
with comments stripped (as `scripts/plane-purity-lint.sh` already does) or it will send the next
agent to clean a crate that is already clean.

## 6. Wave 0, executed — the proof

Two cuts landed (the 13 diagnostics constants; the worker/detached/profile/protocol-decl/TLS-config
spellings). Composition-root `busbar_core::` reach, code lines only, comments excluded:

| | before | after |
|---|---|---|
| distinct `busbar_core::` symbols | 56 | **34** |
| `busbar_core::` call sites across `main.rs` + `root/` | 70 | **38** |
| of those, in `main.rs` | 26 | **20** |

The residue is not spelling: `state::App`, `boot::*`, `plane_host::*`, `plane::registry::*`,
`governance::GovState`, `cost::CostModel`, `egress::seam::CoreHostlessEgress`,
`admin::planeverbs::CorePlaneAdminEnvelope`, `plane::config::config_sections`. Every one is either a
core-owned implementation of a substrate trait, or blocked on a landing named in §3.

Gates: `cargo xtask gate construction --report` **byte-identical to the baseline** (the tree's six
pre-existing red rows unchanged, no new one, every §1.1 ceiling unmoved).
`plane-purity-lint.sh --strict` **byte-identical to the baseline** (RED on KEY 379/378, BACKWARDS
33/29, test-reach llm 24/20 — all pre-existing, verified by running the lint against the base
`main.rs` and diffing). `cargo build --workspace`, `cargo fmt --check`,
`cargo clippy -p busbar --all-targets` clean.

Oracle, 378 cells over `^(billing|llm|admin\.ops|boot|config)\|`, `--strict
--allow-harness-skew`:

- against the 1.5.5 golden: 371 PASS, **7 FAIL**, all `admin.ops` — `GetAudit /items/0/seq 7→8`,
  `GetKeys /items/len 3→4`, `GetUsage /by_key/len 1→2`, `GetPools /members/0/ok 1→2`, `GetGroups`
  content-length.
- **the identical 7, with the identical values, on a release binary built from the unmodified base
  `main.rs`.** They are an artefact of recording a 385-cell *filtered* subset against a golden
  recorded over the full 885: the failing cells are exactly the ones whose value counts how many
  earlier cells ran (`seq`, `len`, `ok`). Nothing to do with either cut.
- **base recording vs cut recording, direct: 378 PASS, 0 FAIL, exit 0.** Byte-identical. The money
  path is untouched, as it must be.

The lesson for the next filtered oracle run: **a filter changes the answer for any cell that counts
prior cells.** Diff a filtered candidate against a filtered *base*, never against the full golden,
or seven cells will accuse an innocent commit.

## 7. Corrections from measurement — 2026-09-08

Every row below is a measurement of the tree, not a re-reading of the plan. Where a §2 or §3 row
disagrees with one of these, the row is wrong and this section is the amendment.

### 7.1 The premise holds for 8% of the body

The legacy production surface outside the loop — core, substrate, llm, mcp, a2a, voice — is
**95,492 lines** (89,277 excluding in-crate test surface), classified:

| class | lines | share |
|---|---|---|
| **EXISTS** — a named crate or module already holds it; the cut is a spelling or a repoint | 7,172 | 8.0 % |
| **PARTIAL** — something exists, most of the body does not | 42,594 | 47.7 % |
| **NONE** — no home anywhere in the workspace, under any kind | 21,426 | 24.0 % |
| **DIES-WITH** — coupled to an engine landing (the plane-host/ingress/state/appbuild wave, the llm twins) | 18,085 | 20.3 % |

`busbar-core` itself is **43,722** production surface lines against **58,722** lines of in-crate test
surface, and is a production dependency of exactly ONE crate — the composition root. Retiring it is
therefore not an inter-crate untangling problem; it is thirty-three production call sites in the root
and 43,722 lines with nowhere to go. **Twelve design gates** — owner or contract decisions, not agent
capacity — block roughly 76 k of the 89 k, and five of the twelve each block more than 5 k lines.
The measured cost of the whole plan is **≈155 agent-days over ≈88 cuts**, landing on one serial
runner at 15–40 minutes a landing: **≈110 landings ≈ 50 runner-hours**, which the runner sustains at
20–30 landings a day. This work is design-gated and landing-serialised, not agent-count-gated.

*Instrument note, worth carrying:* the surface counter only skips `src/tests/` and `src/tests.rs`, so
it counts NESTED test trees as surface. Every figure in this section is the counter's per-file output
with any path containing `/tests/`, or named `*_tests.rs` / `tests.rs`, subtracted — which is why
`busbar-core` reads 43,722 here and 102,444 from the bare script. No `busbar-unit-*` crate nests its
tests, so the union ceiling of §1 is unaffected; the ceilings of crates that do nest are over-read.

### 7.2 The config layer has no replacement — `busbar-core-config` is its home

`config/` is **5,034** surface lines (`mod.rs` 1,513, `migrate.rs` 1,827, `overlay.rs` 712,
`prepass.rs` 276, `named_map.rs` 224, `migrate_export.rs` 177, `secret.rs` 130, `patch.rs` 92,
`groups.rs` 83) and `config_validate/` a further **1,503**. There is no `busbar-*-config` crate in the
workspace; `busbar_api` holds only the secret-reference types. Only the LEAF sections crossed to
`busbar-substrate::config` (1,801 lines) — and the substrate is itself legacy, so the layer's final
home did not exist. Worse for a leaf-only cut: the layer reaches UP into ten core modules at **65
sites** (compiler-verified), and the byte-identity prepass itself names two of them.

**Owner ruling, 2026-09-08: a new crate, `busbar-core-config`** — kind `core`, name `config`, per the
naming rule; the substrate config leaves plus the core config layer, moved verbatim (structs and
prepass in one commit, the migrator with its corpus), the secret resolver with them. The assembled
crate measures **20,050** surface lines, so it owes its own ceiling row and a line in
`ARCHITECTURE.md` §1.1. The "delete, don't relocate" rule of §1 was written for residue that HAS a
replacement; this is not residue, it is the product's config grammar.

The unblock sequence is dependency-ordered, not parallel: the pool config, the export projection and
the issuer config leave the layer first; then the design gate — **plane declarations must become
contract-level data before a config crate can exist, because a config crate must not name a plane**;
then the mechanical remainder; then the plugin signature/loader block leaves `config/` for the loader.
Movable the day the crate exists, with zero outbound edges: `config/secret.rs` (130) and
`config/groups.rs` (83).

### 7.3 The hooks engine has no home — `busbar-core-hooks`

`hooks/` is **1,662** surface lines (`mod.rs` 879, `gate.rs` 236, `scrape.rs` 255, `wire.rs` 250,
`plugin.rs` 42). The substrate's `hooks` module is 254 lines and says of itself that it is *only the
plain-data layer* — the per-pool resolved-policy carriers and the outbound hook-request wire
projection. Policy resolution, the gates, the rewrites, the singleflight and the scrape are core's
and land nowhere. The destination this plan named — a hooks module in the root — **does not exist as
a file**, and creating it costs +8 `legacy-reach` against a headroom of 2 and breaches the root's own
reach rule.

**Owner ruling, 2026-09-08: a new crate, `busbar-core-hooks`.** The kind model already says why: the
kernel seats hook PLUGINS after Admit; the policy ENGINE that resolves what those seats mean is core.

### 7.4 The scoped chained-record journal → `busbar-unit-audit::journal`

`audit/` is 627 lines (`journal.rs` 352, `mod.rs` 275). The chain itself is already in
`busbar-unit-audit` (1,178), and the two primitives `mod.rs` needed were authorised into that crate's
legacy chain, so **`audit/mod.rs` is deletable in one commit** with its boot-verify golden ported as
its gate. `journal.rs` — the scoped chained-record journal — had no home: `busbar-unit-wal` is a byte
WAL with a journal record type but no generic scoped journal.

**Owner ruling, 2026-09-08: `busbar-unit-audit::journal`.** The same gate covers the plane-host
journal (851) and the per-tool-call chained log (483) — 1,686 lines behind one decision.

### 7.5 `trust/` is not a free delete

The execution table rates `trust/` a free DELETE against `busbar-unit-trust`. Measured, core's own
`trust/` is **16 surface lines** — the body already lives in `busbar-unit-trust` (1,399) and
`busbar-substrate::trust` (799, with 126 production call sites). What is NOT free is what rides with
it:

- **1,002 lines of tests with no home.** The re-verify half names the a2a pin walk; the validate half
  names the governance state object. Default: port them to `busbar-unit-trust` together with the pin
  walk, rather than write them off — a deleted test is a deleted proof.
- The validator's governance-resolve implementation moves beside the governance state it resolves
  against, for the orphan rule.

So the row is a repoint plus a test port, ordered behind the governance work — not a free delete.

### 7.6 The terminal `lib.rs` commit needs two things gone, not one

The last row of the execution table makes `#![forbid(unsafe_code)]` the milestone that proves the
crate is finished, and names the engine-host half's `unsafe` blocks as the only thing in the way.
**There is a second:** the test-only allocation-gate instrument carries its own `unsafe` allow, and
`forbid` refuses an `allow` anywhere in the crate, test-only or not. Both must go, in the same commit,
or the milestone cannot be reached.

### 7.7 The `limits` row is mis-scoped

The retirement map schedules `limits` (161 surface lines) to the admission unit as a tier-0,
no-blocker cut. That is true of the name only: the three functions in the module are a request-body
size cap and two health-probe defaults, and the admission unit holds none of the three. The admission
ENGINE the row means is in the governance state module, not in `limits`. **The destination is the
root or `busbar-transport-http`.** Correct the row before scheduling the cut.

### 7.8 The plane-host wave before the llm wave cannot run — the executable order

The tier ordering runs the plane-host cuts before the llm engine cuts. **That order cannot be
executed: the cut that deletes the engine-host trait deletes a trait six of the nine llm step files
name in production.** The executable order is:

**R4-0a … R4-0e (additive, deletes nothing) → the vtable rebuild → R4-1 … R4-7 → the engine-host
implementation, the trait, and the appbuild/state residue.**

R4-0 is the real work: relocate the fourteen engine symbols the step files name; wire the egress
unit; move the ledger write; replace the completion synthesiser. The deletions that follow are
7,019 production lines and close three standing red gate rows — the 1,117-line request-path function,
the terminal doors in the audit step, and the second pick site.

### 7.9 `build_app_from_config` has five callers inside core's own admin

Every plan document, this one included, batches the application-assembly module with the application
state and the router behind "everything above" — i.e. it dies when the root stops booting the legacy
pipeline. Measured, `build_app_from_config` has **five production callers inside core's own admin
handlers** (four in the JSON handler, one in the named-map handler) beside the root's one. The
consequence is an ordering edge nothing recorded: **the admin config-transaction cut and the admin
config-mutation cut are hard predecessors** of the appbuild cut, and a grep for the function name is
the gate that proves it.

### 7.10 The llm unit chain is a SHELL around the engine, not a twin of it

This plan and the retirement map both write that the llm unit directory is the DESTINATION for the
engine, the native ingress and the arrival tables. **That is false as code.** The unit's Route step
calls the engine's forward function directly — the 1,117-line function that is the single reason the
request-path function-size rule is red — and six of the nine step files name the substrate's
engine-host trait. The step files reach fourteen distinct engine symbols in production, the whole
forward loop among them. **Deleting the engine deletes the shipped request path, not a duplicate of
it**; and no test anywhere compares holds, refunds, accrual or price across the two legs.

Related, and stale in four places in the tree: **the llm root leg is DEFAULT ON.** The loop is the
shipped path for llm; the comments and the teller-steps data that still say "default off" are wrong,
and a reader planning this work off them plans the wrong cut. Measured shipped path per leg:
llm = loop, admin = split, mcp / a2a / voice = legacy.

### 7.11 `busbar-unit-egress` has never served a request

The rebuilt forward loop already exists and is dead: **1,810 production lines**, constructed in the
root's kernel wiring, with no production reader driving a request through it. This is why the
one-pick-site rule reads 4 against a ceiling of 2 — both loops are in the binary, the live pair in the
engine and the dead pair in the unit. Wiring it is not a re-target; it is the **first activation of
1,810 lines that have never been exercised in production, on the money path**, and it is blocked on a
golden for the mid-stream upstream-error path that does not exist (those cells are skips).

### 7.12 llm money is dual-booked

The unit chain owns the charge, the refund and the report; the engine still owns **every token
accrual that moves the live budget ledger and the metering series**. One request posts into two
books — the legacy governance ledger through the engine's usage module, and the root's ledger unit
through the late-accrual arm — and **nothing reconciles them**. The late-accrual arm, which is the
only thing putting llm money in the root's book, carries an open HIGH finding for **zero coverage**;
the unit's own accrual line is guarded by a flag that is true on every walked arm, so it never
executes; the unit's metering row is built and dropped; and the kernel settles zero on llm while a2a
and voice accrue — three planes, two settlement models. The thirteen billing cells read the LEGACY
book, so deleting the legacy accrual without moving the views first turns thirteen owed cells red.

### 7.13 Two homes that did not exist now have one

- **The OAuth authorization server** (1,341 lines: the metadata document, the routes, the consent UI,
  the signer, the policy) had no crate and no kind. Owner ruling, 2026-09-08: it is a **CONTROL**
  surface — `busbar-control-oauth2` — not a plane, not an auth plugin and not a core module. A
  verifier answers a question about a credential and stays the `auth` kind; an authorization server
  serves routes, and the request ends there.
- **Admin is the same kind.** `busbar-plane-admin` becomes `busbar-control-admin` at the rename. The
  split is metering and nothing else: a plane is the metered path and follows the strict workflow
  every plane follows; a control surface is not on it and follows the lesser one
  (verify → admit → audit → answer). `PLUGIN-TREE.md` §1 carries the kind row, its CAN/CANNOT list
  and the dependency row; `ARCHITECTURE.md` §1.4 carries the closed-shape/open-vocabulary row.
