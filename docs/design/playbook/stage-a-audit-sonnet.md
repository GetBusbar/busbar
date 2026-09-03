# Stage A audit (Sonnet) — adversarial verification of Option A

Scope: mechanical correctness of collapsing `NamedMapSection::{Tools,Agents}` into one
`Plane(&'static str)` variant, and the byte-identity gates. All line numbers verified against the
tree at HEAD (`crates/busbar-core`, `crates/busbar-mcp`, `crates/busbar-a2a`, `crates/busbar-substrate`).

## 1. `const ALL` → `sections()` — the "~10" list is correct but incomplete

Confirmed simple `for section in NamedMapSection::ALL` / `ALL.iter()` folds (all trivially become
`sections()` returning `Vec<NamedMapSection>`, no exhaustiveness risk):
`named_map.rs:128`, `overlay.rs:622,1058`, `admin/rate.rs:121`, `admin/v1/json/named_map.rs:83,801`,
`admin/v1/json/handlers.rs:4540,4979`, `plane/config.rs:356`. All good.

**Missed by the design's "~10" list** (same fold, but not enumerated, so an implementer greping only
the design doc will miss them):
- `crates/busbar-core/src/config/tests/named_map_tests.rs:15` — `for section in NamedMapSection::ALL`.
- `crates/busbar-core/src/plane/tests/config_tests.rs:37` — `.chain(NamedMapSection::ALL.iter()...)`.
- `crates/busbar-a2a/src/a2a/tests/config_tests.rs:524` — `NamedMapSection::ALL.contains(&NamedMapSection::Agents)`.
  This is qualitatively different: it needs `NamedMapSection::sections().contains(&NamedMapSection::Plane("agents"))`,
  a heap-allocating `Vec::contains` in a cross-crate (`busbar-a2a`) test the design never mentions
  touching at all — the design's blast-radius list only names `busbar-core` files.
- `crates/busbar-core/src/test_support/mod.rs:1705-1706` — a **literal array**
  `[NamedMapSection::Tools, NamedMapSection::Agents]` (not an `ALL` iteration at all), used to drive
  `plane_gates_map` construction. Under the fold this becomes
  `[NamedMapSection::Plane("tools"), NamedMapSection::Plane("agents")]` or (cleaner) an iteration over
  `NamedMapSection::sections()` filtered to `Plane(_)`. Not in the design's list.

Verdict: mechanically fine, but the design's "~10 ALL consumers" undercounts by at least 4, and two
of the misses are outside `busbar-core` (cross-crate blast radius the design's "Substrate mirror
untouched" framing implies doesn't exist).

## 2. The `.key()`-as-bare-constructor sites — the design has NO answer for these (the real gap)

The user's enumerated sites are all confirmed present at the stated lines, and there are **more of
them than the design's own inventory implies**:

| File:line | Current code | What it needs |
|---|---|---|
| `appbuild.rs:1272` | `.get(NamedMapSection::Tools.key())` | string key into `endpoint_resources` map |
| `appbuild.rs:1304` | `plane_decl_for_config_section(NamedMapSection::Tools.key())` | plane lookup key |
| `appbuild.rs:1438` | `.get(NamedMapSection::Tools.key())` | same as 1272 |
| `appbuild.rs:1441` | `plane_decl_for_config_section(NamedMapSection::Tools.key())` | plane lookup key |
| `appbuild.rs:1541` | `plane_decl_for_config_section(NamedMapSection::Agents.key())` | plane lookup key |
| `appbuild.rs:1570` | `plane_decl_for_config_section(NamedMapSection::Tools.key())` | plane lookup key |
| `appbuild.rs:1575` | `plane_decl_for_config_section(NamedMapSection::Agents.key())` | plane lookup key |
| `config/mod.rs:4690` | `NamedMapSection::Tools.key()` → `tools_section` local | opaque discriminant string |
| `config/mod.rs:4691` | `NamedMapSection::Agents.key()` → `agents_section` local | opaque discriminant string (**design's own list omits 4691**, only cites 4690) |
| `config/mod.rs:5041` | `NamedMapSection::Tools.key()` | error-message string |
| `config/mod.rs:5077` | `NamedMapSection::Tools.key()` | error-message string |
| `config_validate/mod.rs:1030` | `NamedMapSection::Tools.key()` | endpoint-section string |
| `plane/config.rs:276` | `default_plane_section(NamedMapSection::Tools.key())` | section key for `ToolsSection::default` |
| `plane/config.rs:284` | `deserialize_plane_section(NamedMapSection::Tools.key(), …)` | section key for `Deserialize` |
| `plane/config.rs:295` | `default_plane_section(NamedMapSection::Agents.key())` | section key for `AgentsSection::default` |
| `plane/config.rs:303` | `deserialize_plane_section(NamedMapSection::Agents.key(), …)` | section key for `Deserialize` |
| `plane/config.rs:321` | `deserialize_plane_endpoint(NamedMapSection::Tools.key(), …)` | section key for `mcp:` endpoint door |
| `test_support/mod.rs:1519` | `NamedMapSection::Tools.key()` | plane lookup key |
| `test_support/mod.rs:1739,1760` | `NamedMapSection::Agents.key()` | plane lookup key |
| `plane_integration.rs:170` | `NamedMapSection::Tools.key()` | plane lookup key (integration test) |
| `busbar-mcp/…/tools_config_tests.rs:401,633` | `NamedMapSection::Tools.validate_def(...)` | bare-constructed enum value, cross-crate |
| `busbar-a2a/…/config_tests.rs:507,515,528,530,534,538` | `NamedMapSection::Agents.{validate_def,key,path_root,requires_module,has_trust_ceiling}` | bare-constructed enum value, cross-crate |

That's **~26 sites**, not the ~13 the user's prompt sampled and not addressed anywhere in the design
doc's text. All of these construct `NamedMapSection::Tools` / `::Agents` as a **compile-time literal
with no `DeployCfg` in scope** — they are not field-split sites, so Option A's `plane_section()`
accessor (which takes `&self: &DeployCfg`) does not apply to them at all. The design's Option A
section describes only the DeployCfg accessor and is silent on this entire category.

The fold is mechanically *possible* — every one of these becomes either:
(a) the literal string `"tools"` / `"agents"` directly (dropping the enum indirection these call
sites only ever used to avoid hardcoding the string), or
(b) `NamedMapSection::Plane("tools").key()` (keeps the enum wrapper, trivially unwraps).

Both compile and are behavior-preserving. But the design **never states which**, never counts these
sites in its blast radius ("named_map.rs... DeployCfg +2 methods... ~10 mechanical ALL→sections()
renames... ~20 lines resolve/pool loops" — this list has no line item for ~26 bare `.key()`
call-through sites across 6 files and 2 external crates), and never flags that 2 of the crates
touched (`busbar-mcp`, `busbar-a2a`) are outside `busbar-core` — directly contradicting residual
risk #6's implicit framing that only the substrate mirror is out-of-crate.

## 3. `match` exhaustiveness inside `named_map.rs` — undercounted, not wrong

The design's blast radius claims "3 matches→accessor" for `named_map.rs`. Verified: there are
**8** match/matches! sites on `Tools`/`Agents` in that file, not 3:
- `contains()` :155-156, `entry_as_document()` :184-185, `NamedDef::install()` :388-389 — these 3
  are genuinely field-split and correctly route through the proposed `plane_section()` accessor.
- `singular()` :93, `requires_module()` :112, `parse_def()` :253, `referents()` :307/311,
  `max_admin_scope()` :329-330 — these 5 are **not** field-split (no `deploy.tools`/`deploy.agents`
  access; `Tools`/`Agents` are treated identically in every one) and just need `Tools | Agents` (or
  two separate arms) rewritten to `Plane(_)`. Mechanically trivial (single wildcard collapse per
  site) but the design's count is wrong by 5, and a reviewer relying on "3 matches" would be
  surprised mid-implementation.

Cross-file matches also confirmed and fold cleanly to `Plane(_)` (no field access, both currently
route through `plane_named_def_list`/`plane_named_def_get`/`plane_decl_for_config_section`, already
generic over `section.key()`): `admin/v1/service.rs:1095,1135`, `admin/v1/json/named_map.rs:667`.
None of these were named in the design doc's "Verified facts," but none is a correctness risk —
same mechanical rename as the two `has_trust_ceiling`/`requires_module` collapses above.

## 4. Field-split sites (design's list of 5) — confirmed accurate

`named_map.rs:155-156` (`contains`), `:184-185` (`entry_as_document`), `:388-389`
(`NamedDef::install`), `config/mod.rs:4965-4968` (resolve deletion-gate — verified: match arms
`Tools => deploy.tools.0.is_present()`, `Agents => deploy.agents.0.is_present()`), and
`config/mod.rs:4701-4705` (pool `member_kind`, verified: `deploy.tools.0.contains_def(name)` /
`deploy.agents.0.contains_def(name)`, **not currently routed through `NamedMapSection` at all** —
it's raw field access gated by the pre-computed `tools_section`/`agents_section` string locals from
line 4690-4691). All 5 correctly need `DeployCfg::plane_section()`/`plane_section_mut()`. Accurate.

## 5. `ALL` used as a slice const with `.contains(&Variant)` (item c in the ask)

Confirmed 3 test sites: `a2a/tests/config_tests.rs:524`, `named_map_tests.rs:15` (iteration, not
`.contains`, so no issue there), `plane/tests/config_tests.rs:37` (iteration). Only the a2a site
actually calls `.contains(&NamedMapSection::Agents)`, which needs `NamedMapSection::sections()` (a
`Vec`) — `Vec::contains` exists and works identically, just non-`const`/allocating, consistent with
residual risk #3's "runtime/allocating" callout. No correctness break, just the design's blast-radius
list should have named this site (it names risk #3 abstractly but never the concrete call site).

## 6. `config-schema.py` (item d)

Ran `python3 scripts/config-schema.py gen` against current HEAD and classified it against the
committed `crates/busbar-core/src/config/config-schema.snapshot.json`: **no schema delta** (sanity
check the gate itself is quiet on the unmodified tree). The scraper (`scripts/config-schema.py`)
extracts structural fingerprints purely from `#[derive(Deserialize)]` struct/enum declarations in a
tracked source-file list; `NamedMapSection` is a plain Rust enum with no `Deserialize` derive and is
not itself scraped. Since Option A keeps the `tools: ToolsSection` / `agents: AgentsSection` fields
on `DeployCfg` verbatim (only the internal `NamedMapSection` enum and its match arms change), the
field set the snapshot records is provably unchanged by this refactor. Confirms the design's
byte-identity claim for the schema gate specifically — this is the one gate I'm confident survives
untouched.

## Verdict: SHIP-WITH-CHANGES

The core mechanism (Option A's accessor for the 5 field-split sites, `sections()` for the ~13
true `ALL`-iteration sites, `Plane(_)` wildcard collapse for the 5 non-field-split matches) is sound
and byte-identity-preserving. Nothing found breaks compilation in a way that isn't a straightforward,
mechanical (if larger-than-advertised) rename. The design should be amended before implementation to:
1. Explicitly specify the replacement for bare `.key()`-as-constructor call sites (recommend: drop
   the enum indirection entirely at these ~26 non-field-split, non-`DeployCfg` sites and use the
   plane's own `config_section` string / a `"tools"`/`"agents"` literal — cleaner than
   `Plane("tools").key()` round-tripping through the enum for no reason).
2. Correct "3 matches→accessor" to "3 field-split + 5 wildcard-collapse" for `named_map.rs`.
3. Add `busbar-mcp` and `busbar-a2a` test files to the stated blast radius — this is NOT
   `busbar-core`-only, contrary to the doc's framing.
4. Add the 4 missed `ALL`/array-literal sites in §1 to the migration checklist.

**Site count missed by the design: ~30** (≈26 bare `.key()`-constructor sites across 6 files/2
external crates not discussed at all, + 4 `ALL`/array-literal sites not in the "~10" list).
