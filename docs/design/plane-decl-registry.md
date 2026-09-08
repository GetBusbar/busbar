# The plane declaration registry, and the config layer that must not name a plane

**Status:** design gate for busbar-core retirement (Track R, item 5). Written against
`integration/oracle-phase0` @ `b15bbdf7f`.

The brief for this document was: *design a contract-level `PlaneDecl`, have each plane crate
register it as data, have the root assemble the registry, and repoint the config layer's 21 sites
onto it so a config parser never names a plane.*

**The mechanism it asks for already exists, and it is not in the contract.** This document states
where it actually lives, what the 21 sites actually reach, which of the brief's premises the code
contradicts, and what the remaining cut is. The correction matters because the premise — "the
config layer has no neutral registry, so one must be built" — is what the 08:00 owner question was
resting on, and it is false.

---

## 1. The shape, as it exists

`PlaneDecl` is **already neutral**. It is declared in
`crates/busbar-substrate/src/plane/registry.rs`, not in `busbar-core`. Each plane crate constructs
its own as a `pub const PLANE_DECL: busbar_substrate::plane::registry::PlaneDecl` beside the code it
describes:

| plane | declaration site |
|---|---|
| llm | `crates/busbar-llm/src/lib.rs:213` |
| mcp | `crates/busbar-mcp/src/mcp/mod.rs:122` |
| a2a | `crates/busbar-a2a/src/a2a/mod.rs:72` |
| voice | `crates/busbar-voice/src/lib.rs:213` |

The record carries the config-layer fields the brief describes and more besides: `key`,
`config_section`, `subject_noun`, `scope_kinds`, `audit_kind`, `wire_format_names`, `fallback`,
`owned_config_sections`, and the seam hooks `default_section` / `parse_section` / `parse_endpoint` /
`build` / `claims` / `admission` / `routes` / `admin_routes` / `openapi` / `hydrate` / `start`. The
section schema/parse/validate hooks are already `fn` pointers on the record, exactly as asked.

The registry is **already root-assembled**. `busbar_core::plane::registry::install_planes` is the
composition root's one write; `BUILTIN_PLANE_DECLS` is empty in production with a stated reason
("Naming a plane crate's `PLANE_DECL` here would be a plane-crate symbol reference in neutral
source — a side channel around the ABI — so this stays empty"). Core's `#[cfg(test)]` built-ins live
in `plane/tests/registry_tests.rs`, the one file the neutral-purity lint excludes. Under
`test-support` a plane's own `testkit` registers through
`busbar_substrate::plane::registry::register_test_plane`, whose storage is on the substrate so a
plane names no core implementation to register itself.

**Core code already takes the decls as data.** `merged_boot_plane_decls(installed, builtins)` and
`build_dispatch(decls, slots)` are both split from their singletons and take `&[&PlaneDecl]` by
argument, precisely so their rules are drivable without booting an `App`.

And the neutral *read-back* seam the brief calls "a registry value core takes" is also already
there: `busbar_substrate::plane::config::{install_plane_sections, plane_sections}` — the root binds
a provider once at startup, and any crate reads the process section list back through it without
naming the registry.

## 2. What the 21 config-layer sites actually reach

Measured on the base, production lines only (comments and `src/**/tests/**` excluded), from
`busbar-core/src/config/**` and `busbar-core/src/config_validate/**`:

| target | sites |
|---|---|
| `crate::plane::registry::{plane_decls, plane_decl_for_config_section}` | 6 |
| `crate::plane::config::{PlaneCfg, split_section, validate_section_hooks, config_sections}` | 9 |
| `crate::plane::config::{AgentsSection, ToolsSection, StreamsSection, McpEndpointSection}` | 4 |
| `crate::plane::fallback_key` | 2 |

Every one of those resolves, today, to something that **names no plane**:

* `PlaneCfg`, `PlaneEndpointCfg`, `ContainerGateInputs`, `refuse_cross_plane_reference`, `Section`,
  `split_section` (the neutral half), `RESERVED_SECTION_KEYS`, `NAMED_MAP_SECTIONS`, `PlaneDecl`,
  `check_owned_config_claims`, `register_test_plane` — all **already in `busbar-substrate`**, and
  `busbar-core/src/plane/{config,registry}.rs` are re-export shims over them plus a little glue.
* the four `*Section` newtypes are type-erased `Box<dyn PlaneCfg>` carriers that resolve their
  plane's hooks *by config section string* through `plane_decl_for_config_section`. They name no
  plane type. `McpEndpointSection` is a frozen wire NAME recorded in
  `config-schema.snapshot.json`, and it is annotated as such.
* `config_sections()` derives the section list from `PlaneDecl::config_section` over the process
  decls plus `NAMED_MAP_SECTIONS`. The hardcoded
  `["pools","tools","agents","export","identity-providers"]` literal that used to sit in two
  plane-local files is already gone.
* `fallback_key()` reads `PlaneDecl::fallback` and explicitly never writes `"llm"`.

**This is machine-checked, and it was checked before this document was written.** The
`plane-purity` gate scans `crates/busbar-core/src` (among the neutral roots) and carries a `KEY` row
("no neutral crate names a concrete plane key") and a `SYMBOL` row ("no neutral crate binds a plane
crate under any spelling"). Both are green. The only plane-key literals anywhere under `config/` are
two in `prepass.rs` — `"mcp"` as a **frozen 1.5.5 top-level wire key** — each carrying a reasoned
`// plane-purity: frozen-wire` pragma.

### So the 21 sites are not a plane-naming problem

They are a **crate-location** problem. The config layer does not name a plane. It names
`busbar-core`, which is the crate being retired. That is the entire blocker, and it is a different
blocker with a different fix.

## 3. The gate rule

> A crate that parses config may name the plane registry's **shape** and read its **data**. It may
> never name a plane crate, and it may never spell a plane key except as a frozen 1.5.5 wire word
> carrying a reasoned pragma.
>
> A plane declares its section; core mounts it. The declaration travels with the plane crate; the
> registry is assembled at the composition root; every core reader takes `&[&PlaneDecl]` or reads
> the bound provider.

Machine-checked by `cargo xtask gate plane-purity`, rows `:symbol`, `:key`, `:type`, `:dialect`
over the neutral roots — plus the two rows this change adds, which close the two ways the rule could
have been *silently* stopped applying to the config layer:

| row | asserts | RED case |
|---|---|---|
| `plane-purity:symbol` (extended) | no neutral crate binds `busbar_plane_<p>::` — the **1.6.0** plane crates. `busbar_plane_llm` does not contain `busbar_llm`, so the pre-existing spelling let a neutral crate bind a 1.6.0 plane with the gate green. | `use busbar_plane_llm::PlaneDeclThing;` planted in `busbar-core/src/config/`; and `use busbar_plane_admin::Verb;` in `config_validate/`, which the KEY row cannot catch because `admin` is legitimate 1.5.5 config vocabulary (`auth.admin_auth:`, `/admin`, `admin-tokens`) and must never be in the key alternation. |
| `plane-purity:core-split-covered` | every `crates/busbar-core*` crate's `src` is a listed neutral root. | overlay `crates/busbar-core-config/src/lib.rs` → RED until the root is listed. |
| `plane-purity:plane-crate-census` | the SYMBOL row's `busbar_plane_<p>` literal is exactly the `crates/busbar-plane-*` directories on disk, both directions. | overlay a `crates/busbar-plane-telemetry/` → RED, names the unwatched plane. |

`core-split-covered` is the load-bearing one for this design. The neutral root set is a hand-written
list with `crates/busbar-core/src` in it. On the day the config layer becomes its own crate, its
sources move out from under that entry — the gate keeps scanning `crates/busbar-core/src`, finds the
config layer gone, and reports the passing answer to every ban over what remains. **The config layer
would stop being checked for naming a plane on exactly the day it became a separately-shippable
thing that must never name one.** That is not a violation of any ban; it is the absence of all of
them, which is why it needs a row rather than a hit.

## 4. Why the contract is the wrong home, stated with the number

`busbar-contract` is the 1.6.0 kernel↔plugin ABI. Its `plane.rs` declares `PlaneMeta` (claims, op
classes, meter classes, fact keys, record schemas, introspection verbs) and the `Plane` codec trait.
That is a *different object* from `PlaneDecl`: `PlaneMeta` says what bytes mean to the kernel;
`PlaneDecl` says how a plane's 1.5.5 YAML section is parsed, defaulted and lowered.

Putting the config declaration in the contract would also breach the ceiling. Measured on the base:

```
surface-ceiling:contract+caps      3477 / 3500
loc-ceilings:caps-contract         (same pair, 3500)
```

**23 lines of headroom.** `busbar-substrate/src/plane/registry.rs` is 719 lines and
`plane/config.rs` is 442. There is no version of this that fits, and there is no version that
*should* fit: the contract would have to name `serde_yaml::Value`, `serde_json::Value` and
`busbar_api::SecretRef` to carry the section hooks, and the plane crates that would register
against it (`busbar-plane-*`) are pure kinds whose `manifest-allowlist` row permits exactly
`busbar-contract` plus their own codec. **Nothing to propose leaving the contract — the addition
should not be made.**

## 5. Where the config layer's home actually is — and D33 already answered

`docs/design/D33-legacy-retirement.md` §2.2 has the verdict written down:

> `config::limits::LimitsResolved` (5) · `config::groups::{GroupCfg,LimitCfg,LimitMetric}` (6) —
> **KEEP as a leaf — 1.5.5 config parsing kept verbatim for byte-identity.** `deny_unknown_fields`,
> field order and serde attrs are frozen; 1.6.0 config = 1.5.5 config + plane sections. …
> **never**.

The config grammar's home in the written plan is **`busbar-substrate::config`**, where the leaf
shapes already sit (`auth.rs`, `groups.rs`, `hooks.rs`, `limits.rs`, `pools.rs`, `providers.rs`,
`sections.rs`) and where the `config-schema` gate already tracks the whole directory. §2.1's rows
say the same thing in the other direction: `config::TlsCfg` → `busbar_substrate::tls`,
`config::secret::SecretResolver` → "the root … **or** `busbar-substrate::config`",
`plane::config::config_sections` → `busbar_substrate::plane::config::install_plane_sections`.

**This contradicts the R5 agent's `busbar-core-config` proposal, and the owner should hear the
contradiction rather than the proposal.** The R5 note reasoned "substrate is itself legacy
(legacy-reach counts 46 `busbar_substrate` symbols), so config's final home does not exist yet."
That is true of the *root's reach into substrate* and false as an argument about config: D33 §2.2
explicitly rules the substrate **not** to be retired in this wave — "it is the layer core is being
drained *into*" — and rules the config leaves **KEEP … never**. A new `busbar-core-config` crate
would be a third home for a grammar that already has two, and would need its own ceiling row, its
own `config-schema` source entry, its own neutral-root entry and its own `legacy-reach` row.

## 6. The remaining cut, named

Not "build a registry". The registry is built. The cut is **finish draining `config/` and
`config_validate/` of their `busbar-core` edges**, in dependency order, until nothing but the
already-neutral shims remain — at which point the whole layer moves into `busbar-substrate::config`
in one commit with the prepass, and `busbar-core/src/plane/{config,registry}.rs` are deleted rather
than relocated.

Outbound edges from `config/` + `config_validate/`, production lines, measured:

| target module | base | now | disposition |
|---|---|---|---|
| `crate::plane` | 21 | 21 | already neutral in substance; §7 below |
| `crate::export` | 8 | 8 | another agent owns `export/` |
| `crate::failover` | 7 | **0** | **landed** — `CandidatePoolCfg` → `busbar_substrate::config::pools` |
| `crate::oauth_as` | 6 | 6 | another agent owns `oauth_as/` |
| `crate::admin` | 6 | **4** | 2 landed (`parse_duration_secs`); the 4 left are `Scope`, see below |
| `crate::auth` | 5 | 5 | another agent owns `auth/` (`ADMIN_PATH`) |
| `crate::diagnostics` | 5 | 5 | another agent owns `diagnostics/` |
| `crate::egress_auth` | 3 | **0** | **landed** |
| `crate::store` | 2 | **0** | **landed** — `MAX_POOL_MEMBERS` → `config::pools` |
| `crate::net_guard` | 2 | **0** | **landed** |
| `crate::durable` | 2 | **0** | **landed** — `busbar_api::durable` |
| `crate::breaker` | 1 | **0** | **landed** |
| `crate::proto` | 2 | **1** | `DEFAULT_MAX_TOKENS` landed; `proto::registry::registry()` is core-live |

Net: 65 non-plane edges measured in the R5 note, **21 removed here**, leaving 24 of which 24 are
either another agent's module (`auth` 5, `export` 8, `oauth_as` 6, `diagnostics` 5) or the two
below.

### The two that are not spellings, and why

**`admin::v1::contract::Scope` (4 sites) is a CYCLE, not a reach.** `Scope::parse_ceiling`'s refusal
message formats `crate::config::DEFAULT_MAX_ADMIN_SCOPE` — so config names `Scope` and `Scope` names
config. The reference cannot be inverted by moving one end; the type and its message move together,
and the message's constant has to move with them. `Scope` also carries `Grants`/`dominates`/`meet`
used across the whole admin surface, so this is the admin plane's move, not the config layer's.

**`proto::registry::registry()` (1 site)** is core-live (`busbar-core/src/proto/registry.rs`), not a
substrate shim. It retires on the protocol-registry axis.

### Unblock 7 (`busbar_plugin_sign`/`busbar_plugin_loader` in `config/mod.rs`) has a prerequisite

The brief asks that the ~190-line block (`fetch_spec_from`, `PluginsCfg::{fetch_specs, to_policy,
to_policy_with_floor}`) move into the plugin loader's policy home with the config struct staying as
pure data. It cannot go directly: those resolvers are methods on `PluginsCfg`, a busbar-core config
type, so `busbar-plugin-loader` would have to name `busbar-core` — the wrong direction, and
`plugin-loader`'s manifest names neither `busbar-core` nor `busbar-substrate` today, so it is also a
new workspace edge (a shared seam needing its own commit).

The order is therefore: **(a)** `PluginsCfg`/`PluginFetch`/`PluginTrustCfg`/`PluginPublisher` move
to `busbar_substrate::config::plugins` as pure data (they are config grammar, and
`busbar-substrate/src/config` is already in the `config-schema` tracked set, so the snapshot follows
the move); **(b)** `plugin-loader` gains a `busbar-substrate` edge in its own commit; **(c)** the
resolvers follow. Not attempted here — a half-move leaves the grammar in two crates, which is worse
than leaving it in one.

## 7. The `crate::plane` 21, specifically

They do not need a new registry. They need the shims under them to stop being in `busbar-core`.
Three of the four groups move with no design work at all, because their destination already exists:

1. **The four `*Section` newtypes + `RawPlaneSection`** (`plane/config.rs:97-363`) — pure carriers
   over `Box<dyn PlaneCfg>` and `serde_yaml::Value`, both already substrate types. They move to
   `busbar_substrate::plane::config` verbatim. The one constraint is stated in their own header and
   must be honoured: they live **outside** `config/` on purpose, because `config-schema`
   fingerprints that directory and a `RawPlaneSection` declared under `config/` would add a
   fingerprinted type and drift the snapshot.
2. **`config_sections` / `config_sections_from` / `validate_section_hooks` / the `split_section`
   wrapper / `fallback_key`** — thin folds over `plane_decls()`. They move with it.
3. **`plane_decls()` and its fold** — this is the one with a real hazard, and it is why this cut is
   not in this commit. The substrate already owns the *storage* for the test-support registration
   set (`test_registered_planes`), so the fold itself transplants cleanly; what does not is the
   `INSTALLED` / `PLANES` / `TEST_MEMO` **process-singleton triple** and its two asserts
   (`install_planes` twice; install-after-first-read). Those are ordering invariants over a
   `OnceLock` whose failure mode is silent and order-dependent across a 10-crate test run. It moves
   as its own commit with the registry tests, not welded to a section move.

There is one behavioural trap worth writing down, because it looks like a free win and is not.
`config/mod.rs:2328,2441` call `crate::plane::config::config_sections()` directly. The neutral
read-back for exactly this is `busbar_substrate::plane::config::plane_sections()`. But
`plane_sections()` returns the **empty list** when no provider has been bound, and the bind is the
composition root's (`install_plane_sections`) — so in core's own `cfg(test)` binary the swap would
silently turn every cross-plane hook refusal into a no-op, which is a config-validation behaviour
change that no snapshot would catch. Repointing those two sites requires the bind to be part of the
same change, or a fallback that is not "empty".

---

## Owner questions

1. **`busbar-core-config` vs `busbar-substrate::config`.** D33 §2.2 says the 1.5.5 config leaves
   KEEP in the substrate, *never* move, and §2.1 routes three more config items there. The R5 note
   proposes a new `busbar-core-config` crate on the premise that the substrate is legacy. Which
   stands? This document takes D33's ruling as written and lands against it — the `CandidatePoolCfg`
   move in §6 went to `busbar_substrate::config::pools`, not to a new crate. If the owner prefers
   the new crate, `plane-purity:core-split-covered` is already the row that makes the split visible,
   but every cost in §5 has to be paid.
2. **`busbar-unit-egress`'s duplicated failover constants.** The brief asked that
   `DEFAULT_FAILOVER_DEADLINE_SECS` / `DEFAULT_FAILOVER_CAP` in
   `busbar-unit-egress/src/pool.rs:17,21` point at the single definition in
   `busbar_substrate::failover`. **They cannot**: `busbar-unit-egress`'s workspace dependencies are
   `busbar-caps`, `busbar-contract`, `busbar-contract-transport`, `busbar-unit-breaker`. Naming the
   substrate from a unit crate is a kind-isolation breach and would be caught by
   `manifest-allowlist`. The two values (120, 3) are duplicated by *agreement*, not by linkage, and
   nothing makes them agree. Either the constants belong in `busbar-contract` (which the unit crate
   may name, at 23 lines of ceiling headroom), or the duplication is accepted and gets a census row
   that fails when the two drift.
3. **The plane-crate literal.** `PLANE_CRATE_ALTERNATION` now includes `admin`, which
   `PLANE_ALTERNATION` deliberately does not, because `admin` is frozen 1.5.5 config and auth
   vocabulary. Confirm that split is right: the plane *crate* is banned from neutral source, the
   plane *word* is not.
