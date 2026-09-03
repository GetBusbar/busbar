# Stage A adversarial audit — Opus

Verdict: **SHIP-WITH-CHANGES**

Target: `docs/design/playbook/stage-a-design.md` (Option A: evict `Tools`/`Agents` from
`NamedMapSection`, add `DeployCfg::plane_section(&str)`, fold `ALL → sections()` from the plane
registry where `named_def_list.is_some()`).

Method: every claim checked against `config/named_map.rs`, `config/mod.rs` (DeployCfg + resolve),
`plane/config.rs`, `plane/registry.rs`, `config/overlay.rs`, `admin/rate.rs`,
`admin/v1/json/{named_map,handlers,mod}.rs`, `admin/v1/contract/taxonomy.rs`,
`config-schema.snapshot.json`, `busbar/src/main.rs`, `busbar-substrate/src/plane/config.rs`,
`plane/tests/registry_tests.rs`, `admin/v1/json/tests/tests.rs`.

## Bottom line

Option A is fundamentally sound. The deadliest attack (empty registry in openapi/test contexts) is
**defused for the default build**, and byte-identity of openapi/taxonomy/config-schema/config-corpus
holds there. But the design mis-states compiled-out parity, undercounts one signature change, and
under-specifies which sites may switch to `sections()`. Fix F1–F3 before implementing.

## Attack results

1. **Missed `ALL` consumer / const context** — NONE. Nine `NamedMapSection::ALL` consumers, all
   inside functions (`named_map.rs:128`, `overlay.rs:622,1058`, `rate.rs:121`,
   `json/named_map.rs:83,801`, `json/handlers.rs:4540,4979`, `plane/config.rs:356`). No `const`/`static`
   initializer uses `ALL`; grep for `const|static` above every `ALL` use is empty. A missed rename is
   a compile error, not silent drift. `substrate/plane/config.rs:268 NAMED_MAP_SECTIONS` is a
   *separate* frozen `[&str;4]` const (hook-ref grammar tail) — out of scope, unaffected by A.

2. **DEADLIEST — empty registry in openapi/schema/test → empty folded list.** DEFUSED for the
   default build. `openapi.json` is generated only by `openapi_json_matches_committed_file`
   (`json/tests/tests.rs:350`, `#[cfg(feature="openapi-schema")] #[test]`), i.e. under `cargo test`
   where **`cfg(test)` is true for busbar-core**, so `builtin_plane_decls()` returns
   `registry_tests::TEST_BUILTIN_PLANE_DECLS = [&busbar_llm, &busbar_mcp, &busbar_a2a]`
   (`registry_tests.rs:26-30`) with **no** `register_test_plane`/`install_planes` call required.
   `sections()` therefore folds `[identity-providers, export]` + (mcp→`tools`, a2a→`agents`) =
   `[identity-providers, export, tools, agents]`. Production serves the **static** committed
   `openapi.json` via `include_bytes!` (`handlers.rs:5120`), never a runtime `sections()`, so no
   production drift. Taxonomy (`taxonomy.rs`, gated `any(test, openapi-schema, test-support)`) is only
   *called* from `#[test]`s, so it too runs under `cfg(test)` with the built-ins. **BUT** see F2 for
   the plane-OFF build.

3. **Order in every build.** default / `cfg(test)` / openapi: `[identity-providers, export, tools,
   agents]` (canonical layering `llm→mcp→a2a`, llm skipped for `named_def_list=None`). Correct.
   `--no-default-features`: `[identity-providers, export]` only — see F2.

4. **Byte-identity.** `config-schema.snapshot.json` keeps `identity-providers`, `export`, `tools`
   (`:484`), `agents` (`:384`) — Option A retains the DeployCfg fields, and the `NamedMapSection` enum
   is not a config-fingerprinted type (absent from the snapshot). openapi/taxonomy/config-corpus
   unchanged for the default build. Drift only in a plane-subset build (F2).

5. **Compiled-out parity.** Config-field/resolve path: YES (fields are unconditional
   `ToolsSection`/`AgentsSection` over `Box<dyn PlaneCfg>` defaulting to `RawPlaneSection`;
   deletion-gate `config/mod.rs:4961` still fires). Router + openapi + rate surfaces: NO (F2). Design
   residual #5's "byte-identical" is overstated.

6. **"Core names no plane in the generic machinery."** TRUE for `named_map.rs` after
   `Tools|Agents → Plane(_)` collapse (`requires_module`, `referents`, `max_admin_scope`, `singular`
   all lose their noun literals). FALSE for the broader claim — `config/mod.rs` resolve still names
   `deploy.tools.0/agents.0`, `tool_defs`, `agent_defs`, `is_tool_member`, `is_agent_member` in ~10
   further sites A does not touch (F5). Also the `path_root` snag (F1).

7. **Better third option?** No. B's rejection (serde `flatten` ⊗ `deny_unknown_fields`,
   config-schema.py blinded) is correct. A "rename-only" `sections()` that stays the const list
   `[idp,export,tools,agents]` would sidestep F1/F2 but advances the stated goal by ~zero. A is the
   right shape.

8. **M5 streams as a 3rd arm.** Works under A: add unconditional `streams: StreamsSection` field +
   `plane_section("streams")` arm; `deny_unknown_fields` is satisfied because the carrier is compiled
   in regardless of the voice plane. Caveat = F4: the fold predicate `named_def_list.is_some()` only
   classifies streams as a named-map if voice's `PLANE_DECL` sets it AND streams is genuinely
   name-keyed (voice currently has `named_def_list: None`, `busbar-voice/src/lib.rs:117`).

## Findings

- **F1 [HIGH] — `path_root()` cannot stay `-> &'static str`.** `named_map.rs:72`. The shared change
  makes the variant `Plane(&'static str)` carrying `decl.config_section` (e.g. `"tools"`), but
  `path_root` must return the slashed form (`"/tools"`), which cannot be produced as a `&'static str`
  at runtime without leaking, and `PlaneDecl` carries no slashed path (design forbids a new PlaneDecl
  field). Callers: `named_map.rs:129` (`parse_rel` local `root`, `==`/`strip_prefix`), `rate.rs:123`
  (`starts_with`), `json/named_map.rs:87,91,114,805,818,858` (`format!`), tests. **Fix:** change
  `path_root()` to `Cow<'static,str>`/`String`, or delete it and prepend `"/"` to `key()` at call
  sites. Design's edit inventory ("3 matches→accessor, ~10 renames") omits this.

- **F2 [MEDIUM] — compiled-out router/openapi divergence.** `plane-mcp`/`plane-a2a` are individually
  toggleable and `--no-default-features` drops all planes (`busbar/Cargo.toml:71`,
  `main.rs:669-675`). With mcp compiled out, `register_planes` installs no mcp decl →
  `plane_decls()` omits it → `sections()` = `[identity-providers, export]` → the router
  (`json/named_map.rs:83`) does **not** mount `/tools`, so `GET /api/v1/admin/tools` 404s — whereas
  today `const ALL` mounts it unconditionally. The served `openapi.json` is the same static bytes in
  every build and still documents `/tools`, so a plane-off deployment's doc lies about its surface. No
  test catches it (the drift test runs under `cfg(test)` with all planes). **Fix:** either source the
  two core plane sections in `sections()` from the unconditional DeployCfg carrier fields (preserving
  const-`ALL` mount parity), or explicitly scope the byte-identity claim to the default build and add
  a plane-off surface test asserting the intended delta.

- **F3 [MEDIUM] — deletion-gate must NOT switch to `sections()`.** `config/mod.rs:4961-4979` loops a
  literal `[Tools, Agents]` and fires *only* when the owning plane is compiled out — its whole
  fail-closed purpose (refuse a `tools:` block a plane-less build cannot serve). If an implementer
  routes this loop through `sections()` (registry-folded), it is EMPTY exactly when the plane is
  compiled out, so a `tools:` block would be silently captured as `RawPlaneSection` instead of
  loud-refused — a fail-closed inversion. The design lists `4965-4968` as an accessor site but never
  states the loop *header* must stay a literal `[Plane("tools"), Plane("agents")]`. **Fix:** pin in
  the design that the compiled-out-sensitive sites (deletion-gate + pool `member_kind`
  `config/mod.rs:4701`) enumerate carrier sections literally, never `sections()`; add a test that a
  plane-off build still refuses a present `tools:`/`agents:`.

- **F4 [LOW] — false "Verified fact" about the predicate.** The design says
  `named_def_list.is_some()` "is already how `singular`/`requires_module`/`referents`/
  `max_admin_scope` resolve the plane arms." It is not — those use `matches!(self, Tools|Agents)` +
  `plane_decl_for_config_section(self.key())` (`named_map.rs:93,112,253,286`). The predicate is NEW to
  the fold. It is correct *today* (llm=None, mcp/a2a=Some, voice=None) but only coincidentally:
  `named_def_list` is the admin list-view seam, not a "owns a named-map section" flag. **Fix:** correct
  the claim; either add a dedicated `PlaneDecl` discriminator or assert
  `named_def_list.is_some() ⇔ named-map plane` as a tested invariant in `registry_tests`.

- **F5 [LOW] — "5 field-split sites" undercounts; scope honesty.** Beyond the 5 section-keyed sites,
  `config/mod.rs` resolve names `deploy.tools.0/agents.0` directly at `4811, 4840, 4844, 4924, 4953,
  5105, 5158` (container_gates, member predicates, validate_registry, `tool_defs`/`agent_defs`
  clone_box). A does not touch these (they are plane-specific, not section-keyed), so the *generic
  machinery* claim survives — but the "core names no plane" win is confined to `named_map.rs`. The
  design should say so rather than let a reader infer resolve is noun-free.
</content>
</invoke>
