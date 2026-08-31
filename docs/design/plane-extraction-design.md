# Plane Extraction — Complete Design

Status: **DRAFT for owner review** · Author: engineering · Target: 1.7.x · Scope: `busbar-core`, `busbar-substrate`, `busbar-api`, `busbar-{llm,mcp,a2a}`, `busbar` (bin), store plugins

> This document is design-only. No production code changes until the owner signs off on the
> mechanisms and the implementation plan.

---

## 1. The requirement, and why we are here

### The requirement (day one)
A protocol plane (LLM, MCP, A2A) must be a **self-contained plugin that is merely compiled in for
convenience** — structurally identical to how `auth-admin-tokens` works today:

```toml
# crates/busbar/Cargo.toml — the reference plugin
auth-admin-tokens = ["dep:busbar-auth-admin-tokens"]   # separate crate, optional dep, default-ON
```

Turn the feature off (or `git rm -r` the crate) and the neutral crates still **compile and run** —
they just do not offer that capability. That is the binding acceptance criterion, and we name it:

> **THE DELETION TEST.** For each plane P: with `busbar-<P>` absent (feature off *and* the crate
> removed from the workspace), `busbar-core`, `busbar-substrate`, and `busbar-api` compile, and the
> binary boots and serves **no P protocol** — no dangling types, no hard-coded P vocabulary, no
> panic. Core "serving no protocols" is a valid, supported configuration.

Today the deletion test **fails for all three planes**. The requirement is not new; it eroded.

### Why we are here (the honest post-mortem)
Two root causes, and the second is the one that matters:

1. **LLM was the original product, not a "plane."** busbar began as an LLM gateway; the LLM codec
   *was* the core. MCP and A2A were added later as genuinely separable planes, so they received the
   plugin treatment (own crates, `plane-mcp`/`plane-a2a` features, a `PlaneDecl` registry, a generic
   `PlaneRecord` store API, a `PLANE_*` diagnostics namespace). LLM never got that treatment because
   historically it wasn't a plane — it was everything.

2. **There was no gate.** The extraction was done by hand, incrementally, and **nothing enforced
   completion or prevented regression.** So it stalled half-finished and new plane-specific code kept
   landing in the neutral crates unchallenged. This is the same failure mode the field-coverage and
   config-stability gates were built to kill: *a boundary with no instrument watching it drifts.*
   The single most important deliverable here is **the enforcement gate** (§6) — without it, any fix
   we land will erode again.

### What is already true (the mechanism exists — this is a *completion*, not a *start*)
Reading the code first-hand (not the summary audits, which overstated the coupling):

- **Generic durable-record contract already exists.** `busbar-api`'s `Store` trait exposes
  `upsert_plane_record` / `get_plane_record` / `append_plane_record` / `list_plane_records` /
  `list_plane_record_parents` / `purge_plane_records_before` / `delete_plane_record` over an opaque
  `PlaneRecord { kind, id, … bytes }` (`crates/api/src/store.rs:1383-1433`). There are **no**
  `append_mcp_call`-style methods on the trait. The audits were wrong on this point.
- **Plane registry exists and is type-erased.** `PlaneDecl` (`crates/busbar-substrate/src/plane/registry.rs:227`)
  carries `key`, `config_section`, `scope_kinds`, `subject_noun`, `audit_kind`,
  `wire_format_names: fn()->&[&str]`, and `claims`/`admission`/`build` as `fn(&dyn Any) -> …`. Planes
  install via `install_planes(&[&PlaneDecl])` from the composition root
  (`crates/busbar/src/main.rs:634` `register_planes`).
- **Protocol registry exists** — `ProtocolDecl` + `install_protocols_with_path_ingress`; the bin folds
  `busbar_llm::DECLS` / `PATH_INGRESS` and pushes `busbar_mcp::PROTO_DECL` (`main.rs:591`).
- **Diagnostics are mid-migration** — a `PLANE_*` neutral namespace exists (14 consts:
  `PLANE_TASK_CHAIN_VERIFY_FAILED`, `PLANE_CALLLOG_*`, `PLANE_AUDITLOG_*`) alongside the legacy
  plane-specific ones (**11 `MCP_*` + 34 `A2A_*`** still in `busbar-substrate/src/diagnostics/mod.rs`).
- **`plane_slots`** — a type-erased per-plane runtime-state map already exists on `App`
  (`plane_slot`/`PlaneSlots` trait, `MCP_RUNTIME_SLOT = "mcp:runtime"`).
- **No neutral crate normal-depends on a plane crate.** The `#[path=".../busbar-<plane>/…"]`
  dual-compiles are all `#[cfg(any(test, feature="test-support"))]`. The runtime crate graph is clean.

So the boundary is real and the plumbing exists. The job is to **push the residual plane-specific
*types, vocabulary, and diagnostics* out of the neutral crates through the seams that already exist**,
finish the LLM case (which barely started), and **install a gate** so it stays done.

---

## 2. Target architecture

A plane = a crate that OWNS everything protocol-specific about itself and REGISTERS it at the
composition root. The neutral crates carry only plane-agnostic ABI.

```
crates/busbar-<plane>/           the plugin: codec, runtime, its OWN record structs, its OWN
                                 diagnostics, its scope-kind + config-section declarations,
                                 a &PLANE_DECL (+ &PROTO_DECL for protocol planes)

crates/busbar/  (the bin only)   optional  dep:busbar-<plane>  behind  feature = plane-<plane>
                                 register_planes()/register_protocols() push each &DECL

busbar-core / -substrate / -api  NEUTRAL. Registries, the opaque PlaneRecord/PlaneDecl/ProtocolDecl
                                 ABIs, the generic plane_slots map, a PLANE_* diagnostics namespace.
                                 INVARIANT: no neutral-crate *source* (outside comments) names a
                                 concrete plane token — "mcp", "a2a", "openai", "anthropic",
                                 "gemini", "bedrock", "cohere", "responses", McpCallRecord, TaskRow, …
```

**The invariant (what the gate enforces):** *no neutral crate names a concrete plane.* Everything a
plane needs from core is reached through an opaque key supplied by the registry.

### 2.1 Governing principle: EVERYTHING CROSSES THE ABI, NOTHING AROUND IT

The plane ABI — the registries (`PlaneDecl` / `ProtocolDecl` / `install_planes` / `install_protocols`
/ `install_diagnostics` / `install_path_ingress`), the opaque `PlaneRecord`, the `plane_slots`
type-erased runtime map, and the plane vtable (`plane_host`) — is the **one and only** surface across
which core and a plane communicate. There are **no side channels.** Every one of the following is a
violation to be removed, not merely "gated":

1. **`#[path = "../../../busbar-<plane>/src/…"]` dual-compiles** (the test/`test-support` "witness
   build" in `core/proto/mod.rs`, `core/handlers/mod.rs`) — this reaches *around* the ABI to compile
   plane source into a neutral crate. It must go: a plane's tests live in the plane crate (linking
   `busbar-core` as a dev-dep), and any core test that needs a plane exercises it **through the
   registry/vtable**, exactly as production does — never by including plane source.
2. **Backwards dependencies** — `busbar-llm` naming `busbar_core::ingress::{gemini_arrival,
   bedrock_arrival}` or `busbar_core::proto::PROTO_*`. A plane may depend on the neutral ABI; it may
   **never** reach back into neutral *implementation*. Core→plane and plane→core-internals are both
   forbidden; only plane→ABI and ABI→plane(via registry) are allowed.
3. **Direct plane types in neutral crates** — `McpCallRecord`, `TaskRow`, etc. Cross the ABI as
   opaque `PlaneRecord` bytes.
4. **Named per-plane methods on neutral traits** — `PlaneHost::a2a_agent_defs`, `attach_mcp_durable_
   sinks`. Cross the ABI as generic capability lookups keyed by opaque `(plane_key, capability)`.
5. **Hard-coded plane vocabulary** — `"mcp"`, `Plane::Llm`, dialect names, `CANONICAL_PLANE_ORDER`.
   The registry is the source of truth; core reads opaque `&str` keys.

The test of done is not "core does not *say* mcp" — it is "the **only** thing that connects core to a
plane is the ABI; sever the ABI and nothing else references the plane." The gate in §6 checks exactly
this: no plane-crate path include, no plane-crate symbol reference, anywhere in a neutral crate.

---

## 3. Coupling inventory (the residual ledger)

Grouped by mechanism class. "Gated?" = whether it already drops with the plane feature off.
Counts/paths verified first-hand on the `dev` branch.

### 3A. Contract types in `busbar-api` (medium — the trait is generic, the *types* leaked)
- `McpCallRecord` (`store.rs:877`), `McpDemotionRow` (`:934`), `TaskRow` (`:783`), `TaskEventRow`
  (`:823`) — concrete plane record structs defined in the neutral contract crate. Used by:
  `busbar-mcp`(3)/`busbar-a2a`(10) (legit — they own the data), **`busbar-core`** (McpCallRecord ×8,
  TaskRow ×6 — residual leak), `plugin-loader`/`plugin-testkit`, and **`store-example-plugin`** (×2
  each — so they are effectively part of the store-plugin contract). **Not gated.**
- `ScopeRow` (`store.rs:39-94`) hard-codes `allowed_mcp_servers`/`allowed_mcp_tools` fields + the
  `"mcp_server"`/`"mcp_tool"` kind strings — MCP vocabulary in the neutral scope wire-partition,
  even though `PlaneDecl.scope_kinds` already declares each plane's kinds. **Not gated.**
- `OpShape` verbs (`operation.rs:65-66`) encode MCP method shapes; the file's own comment
  (`operation.rs:31`) admits it "fails the deletion test on line one."

### 3B. Diagnostics in `busbar-substrate` (medium — namespace exists, migration ~24% done)
- **11 `MCP_*` + 34 `A2A_*`** `Diagnostic` consts in `diagnostics/mod.rs`, all in the neutral `ALL`
  catalog, unconditional. The generic `PLANE_*` namespace (14 consts) shows the intended shape.
- `busbar/mcp/askstate/*` MAC crypto domains (`plane/approvals.rs:54,59`).
- `agent_key` A2A keyspace rule (`substrate/store.rs:133`).

### 3C. Host-trait methods in `busbar-substrate` / `busbar-core` (medium)
- `PlaneHost` declares `a2a_agent_pool_members` / `a2a_audience_bound` / `a2a_secret_resolver` /
  `a2a_agent_defs` (`substrate/plane_host/mod.rs:474-500`) + core impls (`core/plane_host/mod.rs:589-631`).
- ABI dispatch hard-codes `plane_key 0 => mcp`, `1 => a2a` (`core/plane_host/dispatch.rs:456-468`).
- `attach_mcp_durable_sinks` / `attach_a2a_durable_sinks` on a neutral boot trait
  (`substrate/plane/registry.rs`), `MCP_RUNTIME_SLOT`/`mcp_slot` names.
- `App` fields `a2a_agent_gates` / `agent_pools` / `agent_defs` (`core/state.rs:463,538,625`),
  `mcp_server_gates` (`:531`) — `allow(dead_code)`, not removed.

### 3D. Core-resident logic + vocabulary (medium)
- `calllog.rs` (MCP per-call hash-chain), `plane/quarantine.rs` (demotion store), `plane/config.rs`
  (`McpEndpointSection`, `AgentsSection`, `"mcp"`/`"a2a"` section keys), `config/migrate.rs`
  (`migrate_mcp_verify_ttl`).
- `CANONICAL_PLANE_ORDER = &["llm","mcp","a2a"]` (`plane/registry.rs:442`); scattered `"mcp"/"a2a"`
  routing strings; `metrics.rs` help text naming "MCP/A2A".

### 3E. LLM (severe — least extracted, and *entangled backwards*)
- **No `plane-llm` feature.** MCP/A2A have `plane-mcp`/`plane-a2a`; LLM has only the bin-level
  `proto-llm` gating the codec link. The LLM `PLANE_DECL` (`core/proto/mod.rs:867`) is compiled into
  core **unconditionally** and is the one builtin row in `BUILTIN_PLANE_DECLS`
  (`plane/registry.rs:344`), while MCP/A2A rows there are `#[cfg(test)]` and installed at runtime.
- **Backwards dependency (the worst structural item).** `gemini_arrival` / `bedrock_arrival` — the
  Gemini/Bedrock URL-model ingress handlers — live in **`busbar-core/src/ingress/mod.rs:899-1163`**,
  and `busbar-llm/src/lib.rs:121-128` reaches *back into core* to name them. The two crates are
  mutually entangled; the plugin cannot be removed because core holds two of its dialects' ingress.
- Hard-coded detection: `proto/detect.rs:24-91` sniffs `anthropic-version`/`x-goog-api-key`/
  `AWS4-HMAC-SHA256`/paths; `residual_dialect_for_path` (`proto/mod.rs:177`) is a second copy;
  `endpoints.rs:231` a third for `/v1/models`.
- Vocabulary/provider specifics: `PROTO_ANTHROPIC/OPENAI/GEMINI/BEDROCK/COHERE/RESPONSES` consts
  (`proto/mod.rs:819`, ~40 core sites); `openai_family.rs` (default model, tool limits, error banks,
  `MESSAGE_NAMES_SENTINEL`); `EGRESS_UA_*` (`proxy/egress.rs:253`); `LLM_HEAD_KEYS`; the roster
  string in `appbuild.rs:592`; `warn_untranslatable_response_metadata` hard-codes Gemini/Bedrock keys.

### 3F. Acceptable neutral seams (keep — do not touch)
`PlaneDecl`/`ProtocolDecl`/`PlaneRecord`/`plane_slots`/`install_planes`/`install_protocols`, the
`BUILTIN_DECLS` (production empty), the `PLANE_*` diagnostics namespace, the composition root. These
are the target pattern; the whole design is "route everything else through them."

---

## 4. The mechanisms (how each class is severed)

Design principle: **use the seams that already exist; add the minimum new ABI.**

### 4A. Contract types → plane crates, opaque at the boundary
- Move `McpCallRecord`/`McpDemotionRow` into `busbar-mcp`; `TaskRow`/`TaskEventRow` into `busbar-a2a`.
  Each plane serializes its struct into the existing opaque `PlaneRecord { kind, id, parent, bytes }`
  and deserializes on read. The neutral `Store` contract already speaks only `PlaneRecord` — **no
  trait change needed**, which is why this is medium not severe.
- `busbar-core`'s ~14 typed uses become `PlaneRecord`-level (it already routes durable writes through
  the generic API for the migrated paths; finish the rest — `calllog.rs`, `plane/quarantine.rs`).
- `ScopeRow`: replace the three typed `Option<Vec<String>>` fields with a generic per-kind map keyed
  by the registered `scope_kinds` (from `PlaneDecl`). Wire-compat preserved by rendering the same
  YAML keys the registry declares (the config grammar keys `allowed_mcp_servers` etc. stay — they are
  now *plane-declared*, not core-hard-coded).
- **Store-plugin contract impact** (§7): `store-example-plugin`, `plugin-loader`, `plugin-testkit`
  reference the concrete structs today. After the move they must operate on `PlaneRecord` bytes.
  This is the one genuinely breaking change and needs the migration in §7.

### 4B. Diagnostics → plane-contributed registry
- The plane already-partially-migrated `PLANE_*` consts prove the neutral shape. Two options
  (OPEN QUESTION, §8): (i) collapse the 45 `MCP_*`/`A2A_*` into generic `PLANE_*` where the meaning
  is plane-agnostic (chain-verify, write-failed, etc. — several already have `PLANE_*` twins), and
  (ii) for genuinely protocol-specific ones (`MCP_OUTPUT_SCHEMA_VIOLATION`, `A2A_EXTENDED_CARD_*`),
  move the const into the plane crate and register it via a new `install_diagnostics(&[&Diagnostic])`
  at the composition root — mirroring `install_planes`. `ALL` becomes `builtin_neutral ∪ registered`.
- Crypto domains (`busbar/mcp/askstate`) and `agent_key` move into the owning plane crate.

### 4C. Host trait → generic capability lookups
- Replace the four `a2a_*` `PlaneHost` methods with a generic capability read keyed by an opaque
  `(plane_key, capability_id)` resolved through `plane_slots` (which already carries the per-plane
  runtime `Arc<dyn Any>`). The plane downcasts its own slot; core names nothing A2A.
- Replace `plane_key 0/1 => mcp/a2a` dispatch with registry-assigned keys (the `PlaneDecl` order is
  already the source of truth; assign the ABI plane-key from registration index).
- `attach_*_durable_sinks` / slot-name consts move behind the registry (a plane declares its slot key).

### 4D. Vocabulary → registry-supplied
- `CANONICAL_PLANE_ORDER`, routing `"mcp"/"a2a"` strings, the `appbuild.rs:592` roster → derive from
  `installed_planes()` / `known_protocols()` (both already exist). Metrics help text becomes generic.

### 4E. LLM disentangle (the biggest single piece)
1. **Move `PLANE_DECL` into `busbar-llm`**; register it in `register_planes()` alongside MCP/A2A;
   delete the unconditional builtin row. Add a **`plane-llm` cargo feature** mirroring
   `plane-mcp`/`plane-a2a` (core default-on; forwards to a substrate marker).
2. **Move `gemini_arrival`/`bedrock_arrival` into `busbar-llm`** and register them via
   `install_path_ingress` — this **severs the backwards dependency** (`busbar-llm/src/lib.rs:121`
   stops naming `busbar_core::ingress::*`). Highest-value structural fix.
3. **Declared-detection registry.** Replace `proto/detect.rs`, `residual_dialect_for_path`, and the
   `endpoints.rs` duplicate with a predicate each `ProtocolDecl` supplies: `fn claims(&Headers,&Path)
   -> Option<ClaimStrength>`. Core folds the registered predicates in registration order; the
   residual arm becomes "no decl claimed it." (One implementation, three call sites collapse to it.)
4. **Push provider vocabulary onto the decls/plugin.** `PROTO_*` consts become `decl.name` (opaque
   `&str` at core sites); `EGRESS_UA_*` become `decl.egress_ua`; `openai_family.rs`,
   `LLM_HEAD_KEYS`, and `warn_untranslatable_response_metadata`'s per-dialect key lists move into
   `busbar-llm` (the last as a `decl.vendor_response_keys` field core iterates generically).

---

## 5. Phased implementation plan

Each phase is independently landable, green, and — critically — leaves the tree *no worse coupled*.
Order is by (risk ascending) × (unblocks-the-gate). Rough size = engineer-days, for calibration only.

| Phase | Content | Blast radius | Size |
|---|---|---|---|
| **P0 — cheap wins** | roster string from `known_protocols()`; `EGRESS_UA_*`/`PROTO_*`/`openai_family`/`LLM_HEAD_KEYS`/vendor-response-keys onto the LLM decl; metrics help text generic. No behavior change. | tiny | 1–2 |
| **P1 — LLM disentangle** | move `PLANE_DECL` + `gemini_arrival`/`bedrock_arrival` to `busbar-llm`; add `plane-llm` feature; declared-detection registry replacing detect.rs + 2 dups. **Kills the backwards dependency.** | core ingress/proto; bin register_planes | 4–6 |
| **P2 — diagnostics** | collapse plane-agnostic `MCP_*`/`A2A_*` into `PLANE_*`; move protocol-specific ones + crypto domains into the plane crates; add `install_diagnostics`. | substrate diagnostics; plane crates | 3–5 |
| **P3 — host trait + slots + vocabulary** | generic capability lookups replacing `a2a_*` methods; registry-assigned plane keys; `App` field de-naming; `CANONICAL_PLANE_ORDER`/routing strings from registry. | core/substrate plane_host, state | 4–6 |
| **P4 — the api contract** | move `McpCallRecord`/`TaskRow`/etc. into plane crates; generic `ScopeRow` per-kind map; de-type core's ~14 uses; **migrate store plugins**. The breaking one. | busbar-api, store plugins, plugin-loader/testkit | 5–8 |
| **P5 — THE GATE** | the deletion-test build matrix + the neutral-purity lint + selftest (§6). Lands *after* the tree is clean so it starts green, then it is permanent. | CI only | 2–3 |

P0–P3 are non-breaking and can run largely in parallel across agents (they touch disjoint files:
LLM=proto/ingress, diagnostics=substrate/diagnostics, host=plane_host, vocabulary=scattered but
mechanical). P4 is the serialization point (contract + plugins). P5 is last by construction.

---

## 6. THE ENFORCEMENT GATE (the deliverable that prevents recurrence)

Two CI checks, in the style of `config-stability-gate.sh` / `structure-lint.sh` (each with a
`--selftest` proving the scanner catches a planted violation before its verdict is trusted).

### 6.1 Deletion-test build matrix
For each plane P ∈ {llm, mcp, a2a}: build the neutral crates with P removed and assert success.
- **Weak form (feature off):** `cargo build -p busbar-core -p busbar-substrate -p busbar-api
  --no-default-features --features "<all planes except P>"` must compile.
- **Strong form (crate absent):** in a scratch checkout, remove `crates/busbar-<P>` from the
  workspace members and `dep:` lines, then build the neutral crates + `busbar` (bin) with P's feature
  off; assert compile + a boot smoke test that the binary starts and `/` reports the plane absent.
- **All-planes-off:** build core with every `plane-*` off; assert it compiles and boots "serving no
  protocols" (the owner's literal requirement). We already know core compiles with
  `--no-default-features` today (21.7 s) — the gate makes that a *permanent, asserted* property and
  extends it to the strong form.

### 6.2 Neutral-purity lint (`scripts/plane-purity-lint.sh`) — enforces "everything crosses the ABI"
Fails RED on any **side channel** in a **neutral-crate source** (`busbar-core`, `busbar-substrate`,
`busbar-api`; excluding comments, doc-strings, and — once the witness build is gone — `*/tests/*`):
1. **No plane-crate path include** — any `#[path = "…/busbar-{llm,mcp,a2a}/…"]` is an instant fail
   (this is the witness-build side channel; it must not exist in a neutral crate).
2. **No plane-crate symbol reference** — any `busbar_{llm,mcp,a2a}::` path in neutral source
   (there is no legitimate one; the composition-root bin is *not* neutral and is exempt).
3. **No concrete plane token** — the plane keys (`mcp`, `a2a`, `llm`), the six dialect names, or the
   plane record type names (`McpCallRecord`, `TaskRow`, …).
Allowed: the neutral ABI identifiers only (`PlaneRecord`, `PlaneDecl`, `ProtocolDecl`, `plane_slots`,
`install_*`, `PLANE_*` diagnostics). The lint ships with a curated allow-list of the *intentional*
neutral tokens and a `--selftest` that plants (a) a fake `#[path=...busbar-mcp...]`, (b) a
`busbar_a2a::Foo` reference, and (c) a `McpFoo` type in fixtures and proves the scanner catches all
three. This is the instrument whose absence let the boundary drift; it is the single most important
artifact in this document. The reverse edge is checked too: a plane crate may depend on the neutral
ABI but must not name `busbar_core::` *implementation* items (only the substrate ABI) — a companion
scan of the plane crates enforces "no backwards reach."

### 6.3 A `plane_purity` qa segment
Register both checks as a first-class `qa/segments.toml` segment (like `field-coverage`), so the
plane boundary becomes an independently-reported release-gating verdict — not a property nobody watches.

---

## 7. Blast radius, migration, compatibility

- **Store-plugin contract (phase P4) is the only breaking change.** `store-example-plugin`,
  `plugin-loader`, `plugin-testkit`, and any external store plugin reference `McpCallRecord`/`TaskRow`
  today. After P4 they operate on opaque `PlaneRecord` bytes. Migration: (a) provide a transitional
  `busbar-plugin` re-export/adapter for one minor version, (b) bump the plugin ABI/interface-version
  so a stale plugin is rejected with a clear message rather than mis-linking, (c) update the shipped
  example + testkit in the same PR. This is the one place we must sequence carefully and version.
- **Config compatibility is preserved.** The config grammar is frozen additive-only since 1.5.3 and
  guarded by `config-stability-gate.sh` + the 69-config migration corpus. Plane config sections
  (`mcp:`, `agents:`, `pools:`) keep their exact YAML keys — they become *plane-declared*
  (`PlaneDecl.config_section` already exists) rather than core-hard-coded, which is an internal
  refactor, not a grammar change. The migration corpus and stability gate must stay green through
  every phase (they are the compat proof).
- **Runtime/behavior:** none of P0–P3 changes behavior; P4 is a pure data-location refactor. The
  existing test suites (field-coverage, conformance, proxy) are the regression proof at each phase.
- **This is 1.7.x work.** 1.6.0 is complete and frozen-pending-promotion; nothing here touches it.

---

## 8. Risks, non-goals, open questions

**Open questions (for owner review — deliberately not decided here):**
1. **Diagnostics: collapse vs register.** Do we fold plane-agnostic diagnostics into `PLANE_*`
   (fewer, generic) or keep per-plane consts and register them from the plane crate
   (`install_diagnostics`)? The committed `diagnostics.md`/`.json` snapshot + its drift guard mean the
   *numbering/identity* of diagnostics is a stable contract — moving/renaming them is itself a
   reviewed change. Recommendation: register (preserves identities), collapse only exact duplicates.
2. **Store record schema: opaque bytes vs typed generic.** `PlaneRecord` carries bytes today.
   Do plane record structs serialize to an agreed encoding (CBOR/JSON) the store persists opaquely,
   or do we introduce a typed generic `Store<R>`? Opaque bytes keeps the store contract truly
   plane-agnostic (recommended); typed generics leak the schema back. Confirm.
3. **ABI plane-key stability.** Assigning the ABI `plane_key` from registration index means the key
   depends on which planes are compiled in. If any persisted data or wire format embeds the numeric
   plane-key, that must instead key on the stable string `PlaneDecl.key`. Audit persisted uses before
   P3.

**Non-goals:** dynamic (runtime `.so`) plugin loading of planes — "compiled in for convenience" is
explicitly the target; the `plane-abi-spike` crate explores true dynamic loading and is out of scope
here. We are making planes *removable/relocatable at build time*, matching `auth-admin-tokens`, not
hot-loadable.

**Risks:** P4's store-plugin break is the highest; mitigated by versioning + the adapter. The
declared-detection registry (phase P1) changes a hot path (ingress protocol resolution) — it must be
byte-for-byte behavior-preserving, proven by the existing detection tests. The diagnostics snapshot
drift guard will (correctly) fire on every move in P2 — expected, regenerated per its own command.

---

## 9. Definition of done

1. The deletion test passes for all three planes (weak + strong form) — asserted in CI (§6.1).
2. The neutral-purity lint is green and permanent, with a selftest (§6.2), as a qa segment (§6.3).
3. `busbar-{llm,mcp,a2a}` each carry their own record structs, diagnostics, detection, and vocabulary;
   the neutral crates name none of them.
4. `plane-llm` exists and gates LLM exactly as `plane-mcp`/`plane-a2a` gate their planes; the
   `busbar-core ↔ busbar-llm` backwards dependency is gone.
5. Config migration corpus + stability gate + all conformance/field-coverage suites stay green.
6. Store-plugin contract change is versioned and the shipped example/testkit migrated.
