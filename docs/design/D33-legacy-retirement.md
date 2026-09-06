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

## 1. The ceiling, and what it decides

`docs/design/ARCHITECTURE.md` §1.1 sets, and `scripts/construction-gate.sh` measures:

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
| 2 | `config::secret::SecretResolver` | **MOVE** into the root (`crates/busbar/src/root/` secret binding) or `busbar-substrate::config`; it is boot-time credential resolution the root already owns the policy for | `config\|`, `boot\|` | after cut 3 |
| 1 | `config::GroupCfg`, `config::groups::{LimitCfg, LimitMetric::Budget, LimitWindow::Total}` | RE-EX (`busbar_substrate::config::groups`) → REPLACE. **All four sites are in `root/units_llm.rs`** → blocked | `billing\|`, `config\|` | blocked on units_llm |
| 2 | `plane::registry::install_planes`, 1 `plane::registry::PlaneDecl` | RE-EX / thin → **REPLACE** by `busbar_substrate::plane::registry::…`; the *decl set itself* is deleted when the last legacy plane crate goes | `boot\|`, `mcp\|`, `a2a\|` | after the plane crates |
| 2 | `plane::config::config_sections` | RE-EX → REPLACE by `busbar_substrate::plane::config::install_plane_sections` (the root already names both) | `config\|` | cut 3 |
| 2 | `plane_host::engine_host`, 1 `plane_host::live_host_factory` | **DELETE with the crate** — the `EngineHost` seam is the coexistence adapter between the legacy engine and the plane crates; it dies with the engine twins | `llm\|`, `mcp\|`, `a2a\|` | last |
| 2 | `governance::GovState`, 1 `GovState::new_with_signer`, 1 `MemoryStore::new`, 1 `spawn_budget_flusher` | **REPLACE** by the caps/kernel governance path (`busbar-caps::hold`, `busbar-kernel::teller`) — but the *ledger* leg is being landed right now by the late-accrual agent; do not touch | `billing\|`, `teller-meter-row\|` | blocked on the late-accrual landing |
| 2 | `boot::hydrate_all`, 1 `boot::start_planes`, 1 `boot::generate_signing_key_hex`, 1 `boot` | **MOVE** into the root's own boot (`crates/busbar/src/root/durability.rs` already owns hydration policy) as the legacy pipeline retires | `boot\|`, `store-persist\|`, `durable-governance-precondition\|` | after cut 4 |
| 1 | `proto::registry::install_protocols_with_path_ingress`, 1 `install_protocols`, 1 `proto::ProtocolDecl` | RE-EX (`busbar_substrate::proto::registry`) → REPLACE | `http\|`, `llm\|`, `route\|` | cut 2 |
| 1 | `profile::enabled`, 1 `profile::dump` | RE-EX (`busbar_substrate::profile`) → REPLACE | `ops\|` | cut 2 |
| 1 | `metrics::init` | RE-EX (`busbar_substrate::metrics`) → REPLACE | `ops\|` | cut 2 |
| 1 | `ingress::PathIngress` | RE-EX (`busbar_substrate::ingress::arrival::PathIngress`) → REPLACE — the root *already* names the substrate spelling one line away | `llm\|`, `route\|` | cut 2 |
| 1 | `proxy::configure_route_policy_headers` | RE-EX (`busbar_substrate::proxy`) → REPLACE | `http\|`, `route\|` | cut 2 |
| 1 | `admin::restart::{publish_shutdown, release_asked_drain, drain_released_at_exit}` | **MOVE, but blocked.** `busbar-core/src/admin/restart.rs` is 152 lines of process-lifecycle broadcast with no `App` in its signature, and its one true owner is the composition root (it *is* the process). But the module is a set of process **globals** that core's own legacy admin handler still writes — `crate::admin::restart::{supervisor_detected, can_restart, begin_drain}` at `busbar-core/src/admin/v1/json/handlers.rs:2494,2506,2517`. Moving the module to the root would split one static across two crates and silently break `POST /admin/restart` → drain-release. The move lands **with the admin plane**, when `busbar-plane-admin` owns the restart verb and core's handler is deleted. | `documented-admin-restart\|`, `admin.ops\|` | blocked on the admin plane owning the restart verb |
| 1 | `admin::planeverbs::CorePlaneAdminEnvelope` | REPLACE by `busbar_substrate::admin_verbs::install_plane_admin_envelope` (root names both today) | `admin.ops\|` | cut 3 |
| 1 | `egress::seam::CoreHostlessEgress` | REPLACE by `busbar_substrate::egress::seam::HostlessEgress` (root names both today) | `llm\|`, `mcp\|` | cut 3 |
| 1 | `cost::CostModel::resolve_parts` | **REPLACE** by `busbar-unit-cost`. Money path — byte-identity required, so this rides the late-accrual landing, never ahead of it. | `billing\|`, `teller-meter-row\|` | blocked |
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
| `config::limits::LimitsResolved` (5) · `config::groups::{GroupCfg,LimitCfg,LimitMetric}` (6) | **KEEP as a leaf — 1.5.5 config parsing kept verbatim for byte-identity.** `deny_unknown_fields`, field order and serde attrs are frozen; 1.6.0 config = 1.5.5 config + plane sections. | `config\|`, `documented-docker-defaults\|` | never |
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

Two standing carve-outs, in every wave: the 1.5.5 config structs
(`busbar_substrate::config::{groups, limits}`, every `deny_unknown_fields` type) are **KEEP as a
leaf, verbatim, for byte-identity** — 1.6.0 config is 1.5.5 config plus plane sections and nothing
else; and the legacy `/usage` rows and `MeteringRow` literals stay where they are, the 1.6.0 ledger
being written *beside* them by design.

## 4. Proof obligations

Every cut: `cargo build --workspace`; `cargo test -p <touched>`;
`cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`;
`scripts/construction-gate.sh` with no new red row and the §1.1 ceilings above honoured;
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
