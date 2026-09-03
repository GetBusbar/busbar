# Stage A design — evict `Tools`/`Agents` from core's `NamedMapSection`

Status: DRAFT for adversarial audit (Sonnet + Opus). Author: orchestrator, from design agent a52f24.

## Goal
Core's named-map machinery names NO plane noun as a parse target. `NamedMapSection` holds only
`IdentityProviders`, `Export`; tools/agents (and later `streams`) travel in from the plane registry.
Byte-identical `openapi.json`, error taxonomy, and config corpus. Adding a named-map plane trends
toward new-crate-only.

## Verified facts
- Enum: `crates/busbar-core/src/config/named_map.rs:28-48`; `const ALL` `:53-58` order
  `[IdentityProviders, Export, Tools, Agents]`.
- **Field-split snag (5 sites)** reach distinct concrete `DeployCfg` fields `deploy.tools.0` vs
  `deploy.agents.0` (both `Box<dyn PlaneCfg>`): `contains` `named_map.rs:155-156`,
  `entry_as_document` `:184-185`, `NamedDef::install` `:388-389`, resolve deletion-gate
  `config/mod.rs:4965-4968`, pool `member_kind` `config/mod.rs:4701-4705`.
- **Predicate is free**: a named-map plane == a `PlaneDecl` with `named_def_list.is_some()`
  (already how `singular`/`requires_module`/`referents`/`max_admin_scope` resolve the plane arms).
  **No new bool field.**
- **Serde**: `DeployCfg` is `#[serde(deny_unknown_fields)]` (`config/mod.rs:2922-2923`), relied on for
  loud typo rejection. Fields `tools: ToolsSection` `:2981`, `agents: AgentsSection` `:3061`, each a
  newtype over `Box<dyn PlaneCfg>` deserializing via `deserialize_plane_section(key,…)`
  (`plane/config.rs:279-305`), already type-erased + section-string-keyed.
- **Snapshot**: `config-schema.snapshot.json:384,484` records `tools`/`agents` as named fields;
  `scripts/config-schema.py` classifies field REMOVAL as BREAKING (exit 3).
- **Overlay** already string-keyed: `named_maps: BTreeMap<String,BTreeMap<String,Value>>`
  (`overlay.rs:745`), applied by looping `ALL` + `section.key()` (`:1058`). Option-agnostic.
- **`ALL` consumers (~10)**: `json/named_map.rs:83,801`, `json/handlers.rs:4540,4979`,
  `overlay.rs:622,1058`, `admin/rate.rs:121`, `named_map.rs:128`, `plane/config.rs:356`. Router mount
  order + OpenAPI path-item order derive from ALL order → byte-identity surface.

## Shared change (both options)
Replace `Tools`/`Agents` with one `Plane(&'static str)` variant. Turn `const ALL` into
`NamedMapSection::sections() -> Vec<NamedMapSection>` = the two core variants then one
`Plane(decl.config_section)` per `plane_decls()` entry with `named_def_list.is_some()`. Default
build layering `[llm,mcp,a2a]` filtered → `[Plane("tools"), Plane("agents")]` = same tail order as
today → `openapi.json`/router order byte-identical (pin with a test).

## OPTION A (RECOMMENDED) — one accessor seam on DeployCfg
Keep named `tools`/`agents` fields. Add:
```rust
fn plane_section(&self, section:&str) -> Option<&dyn PlaneCfg>;      // "tools"=>&*self.tools.0, "agents"=>&*self.agents.0, _=>None
fn plane_section_mut(&mut self, section:&str) -> Option<&mut dyn PlaneCfg>;
```
The 5 field-split sites drive through it.
- **5th-plane cost**: 1 new `DeployCfg` field + 1 accessor arm (down from ~6 core edits). Irreducible floor under `deny_unknown_fields`.
- **Byte-identity**: config corpus identical; snapshot unchanged (fields retained); openapi/taxonomy unchanged given `sections()` order.
- **Truth**: removes `Tools`/`Agents` from the enum + 4/5 dispatch sites + all generic machinery. Residual naming: the two `#[serde]` field decls (the wire contract) + one accessor body. Honest north-star claim: "the generic named-map machinery names no plane," not "DeployCfg names no plane."
- **Blast radius**: `named_map.rs` (enum + ALL→sections() + 3 matches→accessor), DeployCfg +2 methods, ~10 mechanical ALL→sections() renames, ~20 lines resolve/pool loops. No new PlaneDecl field. Substrate mirror untouched.

## OPTION B (REJECTED) — collapse to `plane_sections: BTreeMap<&'static str, Box<dyn PlaneCfg>>`
Blocked: serde `flatten` ⊗ `deny_unknown_fields` incompatible (flatten silently disables unknown-field rejection → destroys loud-typo guarantee); the only alternative is a hand-written `Deserialize for DeployCfg` which (a) is a large rewrite of the most security-sensitive struct and (b) blinds `config-schema.py` (scrapes `#[derive(Deserialize)]`). Removing `tools`/`agents` fields = snapshot BREAKING (exit 3) + config-corpus regression. B's only win: true new-crate-only storage.

## Residual risks of A (for the adversary to attack)
1. A does NOT fully deliver "core names no plane parse target" — 2 serde fields + 1 accessor still name the nouns (the `deny_unknown_fields` floor).
2. `sections()` order must equal `[identity-providers, export, tools, agents]` for openapi/router byte-identity — pin with an assertion test.
3. `ALL`→`sections()` is now runtime/allocating across ~10 sites incl. 2 openapi-schema/test-gated + parse_rel; a missed site is a compile error, not silent drift.
4. 5th-plane floor: 1 field + 1 arm, not new-crate-only.
5. Compiled-out plane parity: fields still default to `RawPlaneSection`, deletion-gate still fires — byte-identical.
6. Substrate mirror `NAMED_MAP_SECTIONS=[…,"tools","agents"]` (`busbar-substrate/plane/config.rs:268`) still names nouns — frozen hook-reference grammar tail, out of scope but an auditor will point at it.

## FINALIZED — Option A + adversary resolutions (Sonnet + Opus, both SHIP-WITH-CHANGES)
1. **F1 (HIGH) `path_root()` → `Cow<'static,str>`** (or return `String`): `Plane(section)` synthesizes `"/"+section` at runtime; the two core variants return their static literal. Ripples ~8 call sites — update each to accept `Cow`/`&str`.
2. **F3 (CRIT, fail-closed) deletion-gate keeps a STATIC noun source.** `config/mod.rs:4961` compiled-out rejection must NOT iterate `sections()` (which goes empty when the plane is compiled out → would silently ACCEPT a `tools:` block). It reads the frozen substrate mirror `busbar_substrate::plane::config::NAMED_MAP_SECTIONS` (the already-frozen `["identity-providers","export","tools","agents"]` hook-reference tail) so a config naming a compiled-out plane's section is still refused. This is the one place the full static noun set is legitimately named — in the neutral substrate, frozen, not in the generic core machinery.
3. **F2 (MED) compiled-out router/openapi divergence.** After A, `sections()` omits `tools` when `plane-mcp` is off → `/tools` not mounted, but static `openapi.json` documents it. Prod/default build always has mcp+a2a (default features) so no divergence there; the `--no-default-features` core build doesn't serve the same admin surface. RESOLUTION: accept + add a test asserting `sections()` == `[id-providers,export,tools,agents]` under the default/test feature set (the openapi-generating config), and document the core-only omission as correct (a compiled-out plane's admin routes SHOULD be absent).
4. **F5 + Sonnet: enumerate ALL sites.** named_map.rs has **8** match sites (not 3). Plus ~10 `deploy.tools.0`/`deploy.agents.0` refs in `resolve`/pools + ~30 bare `::Tools.key()`/`::Agents.key()` sites (appbuild, config/mod, config_validate, plane/config, test_support, cross-crate a2a/mcp tests). Repoint each `.key()` site to `decl.config_section` where a decl is in scope (further de-nouns core); where no decl/DeployCfg is in scope, use the frozen mirror constant. Tests iterating `ALL` / `ALL.contains(&::Agents)` migrate to `sections()`/membership.
5. **Predicate correction (F4):** the plane-arm resolution today uses `matches!` + config-section lookup, not `named_def_list`. For `sections()` the fold filter IS `named_def_list.is_some()` (correct — that marks a named-map plane); just don't claim the existing arms already use it.

**BYTE-IDENTITY GATES (build agent must prove):** openapi.json sha256 stays `f3365eb5e963184cc07bb8ffcd50d64f9a2f21a6a081cd4a96973a24e4bd631a`; config-schema.snapshot.json stays `1ae714a5540549f1c70241b19bffeef6a7079254b2abf65e3a630983534656e5`; `plane-purity-lint.sh --check` TOTAL 0/BACKWARDS 0; `plane-delete-test.sh --all` green; taxonomy test green; `cargo test -p busbar --features openapi-schema openapi_json_matches_committed_file` green.

## Coupling with M5 (streams)
Voice owns `streams:` via the seam. Under Option A, M5 adds a `streams: StreamsSection` field +
a `plane_section("streams")` arm — consistent, 3-arm accessor. This is why A scales cleanly.
