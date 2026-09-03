<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# M5 — Booting the voice plane (Plane 4)

**Scope.** Link `busbar-voice` into the composition root exactly as `plane-mcp` / `plane-a2a`
are linked; give the voice `PLANE_DECL` ownership of the `streams:` config section with a real
typed `parse_section`; wire `build_runtime` off that typed config instead of dev defaults; add a
`boot-validate` conformance leg. **No new config surface beyond `streams:`** — the typed grammar
reuses the plane's existing `ir::config::SessionConfig` / `ir::control::IrVad` and adds only the
three session limits.

Everything the crate needs is already staged: `busbar_voice::DIAGNOSTICS` is re-exported
(`crates/busbar-voice/src/lib.rs:34`), `config_section: "streams"` is already declared
(`lib.rs:96`), and both `busbar-core/plane-voice` (`crates/busbar-core/Cargo.toml:172`) and
`busbar-substrate/plane-voice` markers exist and forward. M5 is the wiring that turns them on.

---

## 1. `crates/busbar/Cargo.toml` — crate dep + feature

**1a. Dependency edge** — after the `busbar-a2a` block (currently `:41`), mirroring it EXACTLY but
naming the runtime feature the plane's live path needs:

```toml
# THE VOICE PLANE-KIND CRATE (Plane 4), the analogue of busbar-a2a above. Optional behind
# `plane-voice`, and NOT in `default` — voice is dev-only until DoD, so the shipped binary is
# byte-unchanged. The `busbar-voice/runtime` edge is carried by the feature (below), not here.
busbar-voice = { path = "../busbar-voice", optional = true }
```

**1b. Feature** — after the `plane-a2a` feature (currently `:88`). It does **not** join `default`
(`:71`) — the ONE deviation from the mcp/a2a mirror, because voice is dev-only until DoD:

```toml
# THE VOICE PLANE, the busbar-voice crate, behind this switch. The analogue of `plane-a2a` — one
# switch for the crate edge + the core/substrate forwards — EXCEPT it is deliberately absent from
# `default`. `busbar-voice/runtime` is pulled here so a `plane-voice` build compiles the live
# session pump + its `build_runtime` body (the skeleton build leaves `build_runtime: None`).
plane-voice = ["dep:busbar-voice", "busbar-voice/runtime", "busbar-core/plane-voice"]
```

**1c. openapi-schema** — extend the forward at `:91` to add `"busbar-voice?/openapi-schema"`, if
`busbar-voice` exposes that feature (verify; add only if present).

---

## 2. `crates/busbar/src/main.rs` — three registration writes

**2a. `register_planes`** (`fn` at `:658`). After the `plane-a2a` push (`:674-675`), append the
byte-analogue:

```rust
    #[cfg(feature = "plane-voice")]
    installed.push(&busbar_voice::PLANE_DECL);
```

**2b. `register_diagnostics`** (`fn` at `:690`). After the `plane-a2a` extend (`:695-696`):

```rust
    #[cfg(feature = "plane-voice")]
    installed.extend_from_slice(busbar_voice::DIAGNOSTICS);
```

**2c. Hostless-egress gate** (`:723`). Voice consumes **only** `MeteringHost` (its D2 lease), NOT
the hostless-egress driver — it dials no governed outbound HTTP hop. So `plane-voice` is **NOT**
added to the `#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]` guard at `:723`. Leave it.
This is the concrete meaning of "voice needs only MeteringHost": of the god-host slices, voice
binds the metering supertrait alone, reached at session-open through the existing
`LiveHostFactory` (`busbar_substrate::plane_host::LiveHostFactory`, `:223`) upcast to
`Arc<dyn MeteringHost>` — no new composition-root write.

The A2A-only boot hooks (`install_plane_sections`, `install_plane_admin_envelope`, `:734-746`)
are untouched: voice mounts no admin verbs and no cross-plane hook grammar of its own.

---

## 3. `crates/busbar-voice/src/lib.rs` — PLANE_DECL hooks to fill

Three field edits inside `PLANE_DECL` (`:84-138`):

**3a. `owned_config_sections`** (`:137`) — from `&[]` to:

```rust
        // config-seam: voice OWNS the `streams:` grammar. `streams` is NOT in core's
        // CORE_OWNED_CONCRETE_SECTIONS (registry.rs:419 — providers/models/pools/rate_card/limits
        // only), so the dup-claim guard admits this claim; see §5.
        owned_config_sections: &["streams"],
```

**3b. `parse_section`** (`:124`) — from `None` to `Some(streams_parse_section)`, the new fn in §4.

**3c. `default_section`** (`:136`) — from `None` to `Some(streams_default_section)` (the empty
`StreamsCfg::default()`), so an ABSENT `streams:` decodes byte-identically to the plane's own
`Default`, exactly as A2A's `a2a_default_section` (`a2a/mod.rs:210`) does. Without this the
neutral `StreamsSection::default()` newtype falls back to a raw capture, not the typed default.

**3d. `build_runtime`** (`:132`, currently `VOICE_BUILD_RUNTIME`). No field change — the fn-pointer
already routes to `runtime::build_runtime` under the `runtime` feature. The BODY change is §6.

Fields that stay `None`: `parse_endpoint` / `lower_endpoint` (streams is a registry-shaped section,
not an endpoint door like `mcp:`); `routes` / `admin_routes` / `hydrate` / `start` / `config_validate`
(voice mounts nothing and admits no admin write in this stage). `build` stays `|_ctx| None` — voice's
runtime rides the `build_runtime` companion slot, not the dispatch `build` slot.

---

## 4. `StreamsCfg` typed config + `parse_section` (two crates)

### 4a. Plane-side: `crates/busbar-voice/src/config.rs` (NEW module; `pub mod config;` in `lib.rs`)

The typed section. **Reuse the IR** — do not restate the VAD/session grammar. The only NEW scalars
are the three limits, defaulted to the spec values:

```rust
use crate::ir::config::SessionConfig;   // session/media/VAD, already typed
use serde::{Deserialize, Serialize};

fn default_session_max_secs() -> u32 { 3600 }      // 60-minute session ceiling
fn default_context_window_tokens() -> u32 { 32_768 } // 32k context
fn default_max_output_tokens() -> u32 { 4096 }     // 4096 output

/// THE `streams:` SECTION — the voice plane's owned config. Its VAD/session/media shape IS the
/// GA `session` object (`SessionConfig`, which already carries `turn_detection: Option<IrVad>`
/// with the server_vad knobs threshold / prefix_padding_ms / silence_duration_ms /
/// create_response / interrupt_response). The three limits are the only plane-imposed ceilings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // a typo'd key is refused HERE exactly as the file refuses it
pub struct StreamsCfg {
    /// The locked session defaults every live session opens with (media formats, voice,
    /// instructions, turn_detection/VAD, tool set, per-response max_output_tokens).
    #[serde(default)]
    pub session: SessionConfig,
    /// Hard session wall-clock ceiling. Default 3600s (60 min).
    #[serde(default = "default_session_max_secs")]
    pub session_max_secs: u32,
    /// Context-window ceiling. Default 32768.
    #[serde(default = "default_context_window_tokens")]
    pub context_window_tokens: u32,
    /// Output-token ceiling per response. Default 4096.
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,
}
```

**Note on the silence default:** the IR's `IrVad::ServerVad` default is `silence_duration_ms = 200`
(`ir/control.rs:36`). The task's config default of **500** is a `streams:`-LEVEL default, not the
wire default. Model it by giving `StreamsCfg` a `#[serde(default)]` that fills an absent
`session.turn_detection` with a `ServerVad { silence_duration_ms: 500, .. }` in a
`fn default` — OR document that when the operator omits `turn_detection`, the plane synthesizes
`server_vad` with `silence_duration_ms: 500`. Keep this in the plane, so the IR's own 200 default
(used for raw wire decode round-trips) is unchanged.

`StreamsCfg` must implement `busbar_substrate::plane::config::PlaneCfg` (the trait at
`substrate/src/plane/config.rs:36`), mirroring `AgentsCfg`'s impl (`a2a/config.rs:321`). Because
`streams:` is NOT a named-definition registry, the registry methods are trivial:

- `secret_refs()` → `Vec::new()` (no secrets — the exhaustive-destructure discipline still applies
  to `StreamsCfg`'s fields so a future secret-bearing field must decide here);
- `contains_def` → `false`; `def_names` → `Vec::new()`; `entry_document` → `None`;
- `insert_def` → `Err("`streams:` has no named definitions".into())`;
- `container_gates` → empty `ContainerGateInputs`; `validate_registry` → `Ok(())`;
- `is_present` → `self != &StreamsCfg::default()` (true only when the operator wrote content);
- `as_any` / `clone_box` / `clone_arc_any` → the standard three.

The hooks (both UNCONDITIONAL — needed for config parse/validate even in the skeleton/no-`runtime`
build, so they live outside the `#[cfg(feature = "runtime")]` gate):

```rust
/// PLANE_DECL.parse_section — deserialize `streams:` through the plane's own typed shape, boxed as
/// the neutral PlaneCfg. Mirror of a2a_parse_section (a2a/mod.rs:200).
pub fn streams_parse_section(
    v: &serde_yaml::Value,
) -> Result<Box<dyn busbar_substrate::plane::config::PlaneCfg>, String> {
    serde_yaml::from_value::<StreamsCfg>(v.clone())
        .map(|c| Box::new(c) as Box<dyn busbar_substrate::plane::config::PlaneCfg>)
        .map_err(|e| e.to_string())
}

/// PLANE_DECL.default_section — the empty `streams:` (mirror of a2a_default_section).
pub fn streams_default_section() -> Box<dyn busbar_substrate::plane::config::PlaneCfg> {
    Box::<StreamsCfg>::default()
}
```

### 4b. Core-side: route a `streams:` field through the generic seam

Two edits, the exact `tools:`/`agents:` pattern:

**`crates/busbar-core/src/plane/config.rs`** — after `AgentsSection` (`:291-305`) add a
`StreamsSection(pub Box<dyn PlaneCfg>)` newtype whose `Default` and `Deserialize` call
`default_plane_section("streams")` / `deserialize_plane_section("streams", …)` (the generic hooks
at `:213` / `:227` already resolve the voice decl by config section and dispatch to
`streams_parse_section`; compiled out → raw capture, refused at resolve). Export it in the
`use crate::plane::config::{…}` at `config/mod.rs:32`.

**`crates/busbar-core/src/config/mod.rs`** — add one field to `DeployCfg` (struct at `:2924`),
beside `tools` (`:2982`):

```rust
    /// The top-level `streams:` section — THE VOICE PLANE's owned config (session/media/VAD +
    /// the three session limits). Type-erased behind the neutral `StreamsSection` seam, so
    /// `DeployCfg` names no `busbar_voice` type. Compiled out (voice off) ⇒ captured raw and
    /// refused at resolve if present, exactly as `tools:`/`agents:` are.
    #[serde(default)]
    pub(crate) streams: StreamsSection,
```

This is the ONLY config-surface addition. Because core's `plane-voice` feature already forwards to
substrate (`busbar-core/Cargo.toml:172`) and gates nothing in core source directly, no
`#[cfg]` guards are needed on the field itself — the generic registry lookup handles the
compiled-out case.

---

## 5. Dup-claim guard interaction (must refuse a collision)

`check_owned_config_claims` (`substrate/src/plane/registry.rs:556`) runs at boot over every decl's
`owned_config_sections` against `CORE_OWNED_CONCRETE_SECTIONS`
(`core/src/plane/registry.rs:419` = `providers/models/pools/rate_card/limits`).

- **Voice's claim is admitted:** `"streams"` ∉ `CORE_OWNED_CONCRETE_SECTIONS`, and no other decl
  claims it → `Ok(())`.
- **A collision IS refused, by construction:**
  - if a SECOND plane also lists `"streams"` → the guard's `claimed.insert` arm returns
    ``config section `streams` is claimed by two planes …`` and boot panics (`registry.rs:403`);
  - if anyone adds `"streams"` to `CORE_OWNED_CONCRETE_SECTIONS` while voice claims it → the
    ``core still owns it concretely`` arm fires. So `streams:` must never be a concrete
    `DeployCfg`-owned section — it is voice-owned from birth, which it is (the new field routes
    through the generic seam, not a concrete typed field core validates).

**Test to add (drives the guard directly, no boot):** a unit test that builds two decls both
claiming `"streams"` and asserts `check_owned_config_claims` returns `Err`, and one asserting the
voice decl alone returns `Ok` against the real `CORE_OWNED_CONCRETE_SECTIONS`.

---

## 6. `build_runtime` off real config (behind `runtime`)

`crates/busbar-voice/src/runtime/mod.rs:94` — `build_runtime` currently ignores `_section` and
builds dev defaults (fresh engine, `LocalMeteringPort`, `EchoToolExecutor`, zero `Pricing`).
Change the BODY (not the signature — it is the frozen `PlaneDecl::build_runtime` fn-pointer):

1. Downcast `section` via `section.downcast_ref::<StreamsCfg>()` (the value core passes is
   `cfg.streams.as_any()`, the `PlaneCfg::as_any` of `StreamsCfg`). `None` (absent/other) → keep
   today's empty defaults.
2. From `StreamsCfg`, seed `VoiceRuntime`'s `pricing` from the session/rate config, the locked
   `SessionConfig` (VAD, formats, `max_output_tokens`), and carry `session_max_secs` /
   `context_window_tokens` as the session ceilings the pump enforces.
3. **MeteringHost** stays the D2 hop: `build_runtime`'s dev path keeps `LocalMeteringPort`; the
   PRODUCTION lease is bound at session-open via `build_runtime_hosted(host)` (`:114`) where the
   topology transport holds the `LiveHostFactory` and upcasts `Arc<dyn EngineHost>` →
   `Arc<dyn MeteringHost>`. No host crosses the `build_runtime` fn-pointer seam (it carries none) —
   this is why "voice needs only MeteringHost" is satisfiable without touching the composition root.

In a `plane-voice` build WITHOUT `runtime`, `build_runtime` is `None` (skeleton) — the plane still
DECLARES `streams:` and PARSES/validates it (the §4 hooks are unconditional), but builds no runtime
object. That is the honest dev-only interim.

---

## 7. `voice-conformance.yml` + `verdict-covers-every-leg.py`

### 7a. New leg — `boot-validate`

Add a job to `.github/workflows/voice-conformance.yml`, structured like `replay` (`:128-149`),
`needs: gate-selftest`. It builds the binary WITH `plane-voice` and runs `busbar --validate` over a
fixture `config.yaml` that carries a `streams:` block, asserting (a) a valid `streams:` boots-clean
(exit 0) and (b) a `streams:` naming an unknown key is REFUSED by `deny_unknown_fields` (exit 1) —
proving the owned `parse_section` is actually reached at `--validate`, not bypassed:

```yaml
  boot-validate:
    name: boot --validate parses the owned streams: section
    needs: gate-selftest
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@1.98.0
      - uses: Swatinem/rust-cache@v2
      - name: Build busbar with the voice plane
        run: cargo build -p busbar --features plane-voice
      - name: A valid streams: validates clean; an unknown key is refused
        run: |
          set -euo pipefail
          bash testing/voice-conformance/voice-conformance.sh --leg boot-validate | tee voice-boot-validate.log
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: voice-boot-validate
          path: voice-boot-validate.log
          if-no-files-found: warn
```

### 7b. Wire it into the verdict (`:200-244`) — REQUIRED, else the leg is vacuous-green-invisible

- Add `- boot-validate` to the `verdict.needs:` list (`:204-209`).
- Add `BOOT_VALIDATE: ${{ needs.boot-validate.result }}` to the `env:` (`:217-222`) and a
  `strict boot-validate "$BOOT_VALIDATE"` line to the script (`:234-238`).

### 7c. `verdict-covers-every-leg.py` "set update"

**No code edit to the linter is required** — it is discovery-based, not enumerated: it takes the
workflow's job set MINUS `verdict` and holds it to SET EQUALITY with `verdict.needs`, and requires
each name to appear in the verdict script (`testing/verdict-covers-every-leg.py:59-103`). The "set
update" is therefore satisfied entirely by 7b: adding `boot-validate` to BOTH `needs` and the
script keeps the set equal. The leg count rises 5 → 6, clearing `MIN_LEGS = 5` (`:43`). If 7b is
forgotten, the linter's own `--selftest`/lint (run in `gate-selftest`, `:75-86`) FAILS with
`UNJUDGED LEG: job boot-validate … not in verdict.needs` — which is the intended tripwire.

---

## 8. Collision with Stage A (transport)

Stage A (`docs/design/plane4-seam-audit-A-transport.md`) and M5 **both touch config parse +
registry**, so they will textually collide:

- **`crates/busbar-core/src/config/mod.rs`** — both add/modify `DeployCfg` fields and the
  `use crate::plane::config::{…}` import (`:32`). M5 adds `streams:`; Stage A touches transport
  config. Merge by hand; the field additions are independent lines but the import list is one line.
- **`crates/busbar-core/src/plane/config.rs`** — both add `*Section` newtypes near `:291-305`.
- **`crates/busbar-voice/src/lib.rs` PLANE_DECL** — Stage A may fill transport-facing hooks
  (`routes`) while M5 fills `parse_section`/`owned_config_sections`; same struct literal, adjacent
  fields. Land whichever merges first, then rebase the other onto the filled decl rather than the
  skeleton.

Recommend landing M5 (config-seam) FIRST — it is self-contained and its dup-claim + `--validate`
legs are cheap to prove — then rebasing Stage A onto the filled `PLANE_DECL` / `streams:` field.

---

## Summary (≤8 lines)

1. `Cargo.toml`: add optional `busbar-voice` dep + `plane-voice` feature (`dep:busbar-voice`,
   `busbar-voice/runtime`, `busbar-core/plane-voice`) — NOT in `default` (voice is dev-only).
2. `main.rs`: one push in `register_planes`, one extend in `register_diagnostics`, both
   `#[cfg(feature="plane-voice")]`; leave the hostless-egress gate alone (voice needs only MeteringHost).
3. `lib.rs`: `owned_config_sections=["streams"]`, `parse_section=Some(...)`,
   `default_section=Some(...)`; `build_runtime` body reads real `StreamsCfg`.
4. New `StreamsCfg` (reuses `ir::config::SessionConfig`/`IrVad` + 3 limits: 3600s/32k/4096, VAD
   silence default 500) impl `PlaneCfg`; core gets a `StreamsSection` newtype + one `streams:`
   `DeployCfg` field through the generic seam.
5. Dup-claim guard admits `streams` (∉ core-concrete) and REFUSES any second claimant; add a direct
   unit test.
6. CI: a `boot-validate` leg + verdict `needs`/script update; the linter is discovery-based so no
   `.py` edit, only the yml set.

**File:** `docs/design/playbook/m5-voice-boot.md`

## Top 3 risks

1. **`build_runtime` gets no host at its seam.** The frozen fn-pointer carries no `MeteringHost`, so
   the real D2 lease can only bind at session-open via `LiveHostFactory` in the topology transport —
   NOT in `build_runtime`. If a reviewer expects `build_runtime` itself to bind the live host, the
   design will read as incomplete; it is correct (matches mcp/a2a, which reach the host at
   call-time), but the "wire build_runtime to read real config" ask covers config only, not the host.
2. **`plane-voice` absent from `default` is a real behavioral fork.** Every mcp/a2a mirror line is
   `default`-on; voice is not. A copy-paste that also adds `plane-voice` to `default` (`Cargo.toml:71`)
   would ship the dev-only plane, changing the default artifact and the config-schema snapshot
   (a new `streams:` key). The deviation must be deliberate and snapshot-guarded.
3. **Stage A merge collision on `config/mod.rs` + `plane/config.rs` + `PLANE_DECL`.** Both stages
   edit the same DeployCfg import line, the same newtype cluster, and the same decl literal. A blind
   merge can drop one stage's field or re-introduce the skeleton `None`s. Land M5 first, rebase Stage
   A onto the filled decl.
