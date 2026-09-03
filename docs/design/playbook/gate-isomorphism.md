<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# The 4-plane BEHAVIOURAL ISOMORPHISM gate

*Design for the gate that mechanically asserts **"no plane does X that a sibling plane
cannot"** across `{llm, mcp, a2a, voice}`, and **"core's config parse + admin surface
names no plane noun as a concrete parse target."***

> Owner's ruling, recorded (and slipped) repeatedly — the reason this is a gate and not a
> paragraph: *"LLM == MCP == A2A — just different protocols not different pathway through
> engine at all."* Prose has a half-life of days; only machine gates have held
> (`crates/busbar/tests/capability_equality.rs`, `PLANE_LEDGER`, the hygiene lints).

This document specifies TWO new mechanisms and shows why the existing four
(`plane-noun-gate.sh`, `plane-delete-test.sh`, `capability_equality.rs` totality,
`plane-abi-neutrality.sh`) leave a residual hole that neither closes.

**Orthogonality note, up front.** `scripts/plane-noun-gate.sh` is NOT this gate. It counts
LLM *billing/prompting vocabulary* (`tokens_input`, `rate_card`, `reasoning_effort`,
`Billing::Tokens` — the ~208-hit meter) that is frozen into the neutral crates and STAYS in
core until the M1–M5 eviction moves relocate it. That is a *vocabulary-leak debt meter on one
axis (LLM nouns in neutral code)*. The isomorphism gate here measures a DIFFERENT axis: (a)
whether every plane fills the same `PlaneDecl` seam set consistently, and (b) whether core's
config parser names the four *section* nouns (`tools`/`agents`/`pools`/`streams`) as concrete
parse targets. A tree can be green on one and red on the other; they never substitute.

---

## 0. The seam set — `PlaneDecl` is the isomorphism contract

There are two `PlaneDecl` structs, and the distinction matters:

| struct | location | role in this gate |
|---|---|---|
| the **registry** `PlaneDecl` | `crates/busbar-substrate/src/plane/registry.rs:180` | THE semantic seam set. ~30 fields, each replacing one arm of one `match self` on `busbar_core::plane::Plane`. This is what the isomorphism gate reasons over. |
| the **ABI** `PlaneDecl` | `crates/busbar-plugin/src/hot/decl.rs:132` (`#[repr(C)]`) | The frozen FFI export surface (`Option<…Fn>` slots + the non-vacuity invariant: `admin_routes: Some ⇒ non-vacuous`). Its own floor test already guards it; the isomorphism gate does NOT restate it, only cross-references it (§6, Risk 3). |

The registry `PlaneDecl` is a plain Rust struct, so the compiler already enforces the
**structural** half of isomorphism: every plane crate that constructs a `PlaneDecl`
(`busbar_llm::PLANE_DECL`, `busbar_mcp::PLANE_DECL`, `busbar_a2a::PLANE_DECL`,
`busbar_voice::PLANE_DECL`) must name EVERY field or fail to compile, and adding a field forces
all four decls to be updated. A plane cannot silently omit a hook. Every field is either a
value / `Some(fn)` (the plane fills the hook) or an explicit `None` (the plane opts out).

`busbar-voice/src/lib.rs:84` is the canonical "fills the same shape or explicitly None"
witness: a skeleton plane that declares its identity (`key`, `config_section: "streams"`,
`scope_kinds`, `audit_kind`, `wire_format_names`) and returns `None`/empty from every runtime
hook. Structural isomorphism holds by construction. **What is NOT yet mechanically checked is
the *semantic* half: whether each `None` is a legitimate capability difference or a silent
gap.** That is the hole this gate fills.

---

## 1. What "isomorphism" concretely asserts

**Assertion I1 (structural).** Every installed plane constructs the *same* registry
`PlaneDecl` field set. *Already enforced by the type system* — recorded here so the gate can
assert it did not regress (a field made `#[cfg]`-conditional per plane, or a plane decl behind
a feature that drops a field, would break it silently at the ABI edge).

**Assertion I2 (semantic — the new content).** For every `PlaneDecl` *hook* field `f` and
every ordered pair of planes `(p, q)`, it is FORBIDDEN that `p.f = Some(_)` while `q.f = None`
UNLESS the asymmetry is *accounted for*. Concretely, reflect the installed decls into a
Some/None matrix `field × plane` and, for each cell that is `None` while a sibling is `Some`,
demand exactly one of:

1. **legitimate capability difference** — the `(capability, plane)` cell in
   `qa/capability-equality.json` is `not-applicable` *with an argument ≥ 60 chars* (the ledger
   already enforces the argument length; `capability_equality.rs:239`). Example: the LLM plane's
   `hydrate: None` — it has no durable state; the ledger's N/A argument says so.
2. **pinned gap** — the ledger cell is `missing` (the work queue). The `None` is a known TODO,
   named on every full-gate run. Example: voice's `build`/`start`/`config_validate` = `None`
   today, pinned to voice's column.
3. **proven-elsewhere** — the ledger cell is `proven` and the capability reaches the plane
   through a *different* seam than field `f` (rare; requires the cell's `test` to be named).

A `None` that is asymmetric with a sibling `Some` and maps to **no ledger cell at all** is the
failure mode the gate exists to catch: *a plane quietly not doing something a sibling does, with
nobody having decided that is correct.* This is the mechanical form of "never llm does X that
voice doesn't."

**How to tell a difference from a gap, mechanically:** the discriminator is the
capability-equality ledger, not a human reading the doc-comment. The gate joins two facts it can
both compute — (a) the Some/None vector per field, read from the actual `&'static PlaneDecl`
values via `merged_boot_plane_decls`; (b) the ledger state per `(capability, plane)`, read from
`qa/capability-equality.json`. An asymmetric `None` with a ledger state is *declared* (difference
or gap); an asymmetric `None` with no ledger state is *undeclared* → RED. The field→capability
correspondence is a small pinned map inside the test (each `PlaneDecl` hook names the capability
it implements — e.g. `hydrate → durable-restore`, `admin_routes → admin-surface`,
`config_validate → config-write-grammar`), and that map is itself floor-checked so it cannot
silently shrink.

---

## 2. The four-noun assertion — core names no plane noun as a parse target

The four *section* nouns, one per plane, are the top-level `config.yaml` keys whose mere
existence declares a plane (`PlaneDecl::config_section`, `registry.rs:198`):

| noun | plane | `config_section` |
|---|---|---|
| `tools` | mcp | `busbar_mcp::PLANE_DECL.config_section = "tools"` |
| `agents` | a2a | `"agents"` |
| `pools` | llm | (llm data-plane section) |
| `streams` | voice | `busbar_voice`… `config_section: "streams"` |

**Assertion N1.** In `crates/busbar-core/src`, none of `tools | agents | pools | streams` may
appear as a *concrete config parse target* — i.e. as a match arm resolving a section, a serde
field/rename bound to the literal, or a positional lookup `root.get(Value::from("<noun>"))` /
`.get("<noun>")` that steers deserialization — EXCEPT through the legitimate seam.

**The legitimate seam** (the one allowed path, never counted): core reads a plane's section
*through* `PlaneDecl::config_section` / `PlaneDecl::owned_config_sections`
(`registry.rs:536`), folded by `config::config_sections_from` and parsed via
`PlaneDecl::parse_section` (`registry.rs:450`). Core stamps a registered plane's section
*without a literal* — the whole point of the config-seam. So the allowlist is exactly the seam
plumbing plus the dup-claim guard (`check_owned_config_claims`, `registry.rs:556`).

**Today this assertion is RED, by design (a debt meter, not yet a hard gate).** Core still names
all four literally — e.g. `config/named_map.rs:66` (`NamedMapSection::Tools => "tools"`,
`Agents => "agents"`), the concrete `DeployCfg.pools` / `tools` / `agents` fields
(`config/mod.rs:409,427,492`), `config/migrate.rs` (`pools`, `streams`), and
`config-schema.snapshot.json`. Stage-1 of the config-seam pins `owned_config_sections = &[]` for
every plane (`registry.rs:530`): nothing has moved yet. So the four-noun meter starts non-zero
and the section-eviction moves drive it to zero — *exactly the posture of `plane-noun-gate.sh`
and `plane-grep-gate.sh`*: report a NUMBER now, arm the hard gate with a one-flag flip
(`GREP_GATE_REPORT_ONLY=0`) the day it reaches zero.

**Curation is mandatory** (Risk 1). `pools`/`tools`/`agents` are heavy homonyms in core that are
NOT parse targets and must not be swept in: role grants (`allowed_pools`,
`config/mod.rs:672`), failover maps (`tool_pools`/`agent_pools`, `config/mod.rs:503`), the frozen
legacy-format migrator (`migrate.rs` operates on *past* on-disk shapes — frozen contract, not the
live grammar), the `config-schema.snapshot.json` fixture, and all `*/tests/*` / doc-comment
prose. The needle is the *parse-steering* occurrence (match arm, `serde(rename)`, `get(literal)`
that selects deserialization), not every mention — the same discipline `plane-noun-gate.sh`
applies to promote `provider`/`model` only in pricing context.

---

## 3. What delete-test + totality already cover — and the residual gap

| existing mechanism | what it proves | why it is NOT the isomorphism gate |
|---|---|---|
| `plane-delete-test.sh` (strong-form) | Removing `crates/busbar-<P>` leaves neutral crates + bin compiling — core names no plane *TYPE*. | A **string literal** (`"tools"`) survives crate deletion untouched; delete-test is blind to noun-as-parse-target. And "compiles without the crate" says nothing about whether the plane *fills the same hooks* as its siblings. |
| `capability_equality.rs` — `PLANE_CRATE_LEDGER_COLUMNS` totality (`:361`) | Every workspace plane crate maps to ≥1 ledger column; the pinned matrix *tiles* capability × plane with no hole/dup. | It is a **hand-pinned JSON ledger**, not derived from the `PlaneDecl` Some/None reality. It can pin a cell `missing` while the decl's field is actually `Some` (or vice-versa) and never notice — the ledger and the decls are never reconciled. It checks the *claim*, not the *wiring*. |
| `plane-abi-neutrality.sh` | The plane ABI (`busbar-plugin/src/hot`) names no protocol/role noun. | Guards the ABI *vocabulary*, one crate. Says nothing about per-plane hook symmetry or core's config parse targets. |
| `plane-noun-gate.sh` | LLM *billing* nouns in neutral crates (the ~208 meter). | Orthogonal axis (§Orthogonality). Different nouns, different crates, different debt. |

**The residual gap a new check must fill:**

- **G1 (semantic seam-fill).** Nobody reconciles the *actual* Some/None vector of the installed
  `PlaneDecl`s against the ledger. An asymmetric `None` with no ledger cell — llm does X, voice
  silently doesn't, undeclared — passes every existing gate.
- **G2 (config parse target).** Nobody greps core for the four *section* nouns as parse targets.
  Delete-test misses it (survives as a literal), the ledger misses it (it tracks capabilities,
  not config grammar ownership), `plane-noun-gate` misses it (it tracks billing vocab).

---

## 4. Script, test, or both — **both** (each where it can actually see the fact)

The two assertions live at different altitudes, so they need different instruments:

### 4a. `scripts/plane-config-noun-gate.sh` — a SHELL gate (Assertion N1)

A grep gate, sibling of `plane-noun-gate.sh` / `plane-grep-gate.sh`, because N1 is a
*text/naming* assertion over core source. It:

- sources `scripts/plane-keys.sh` for `{llm, mcp, a2a, voice}` — never restates the plane set —
  and resolves the four section nouns from each plane's declared `config_section` (so a fifth
  plane's noun is scanned with no edit; the same single-source discipline the totality test
  reads `plane-keys.sh` for);
- scans `crates/busbar-core/src/**.rs` (non-test, comment-stripped) for each noun as a
  *parse-steering* occurrence, with the §2 curation allowlist (role grants, failover pools,
  frozen migrator, schema snapshot);
- prints a per-noun table + a DISTINCT-LINE debt total (a line hit by two nouns is one leak),
  copies the raw hit list to `PLANE_NOUN_HITS_OUT` — byte-for-byte the `plane-noun-gate.sh`
  reporting shape;
- **report-only today** (`GREP_GATE_REPORT_ONLY=1`, EXIT 0); `=0` arms the hard gate at DoD;
- carries a `--selftest` that plants a fixture with a known parse-target leak and a known
  allowlisted homonym and asserts the meter counts the first and not the second (house rule: a
  gate that cannot fail is worse than none — the `plane-delete-test.sh` / `structure-lint.sh`
  posture).

### 4b. `crates/busbar/tests/plane_isomorphism.rs` — a RUST TEST (Assertion I2 + I1)

A test, not a script, because it MUST read the actual `&'static PlaneDecl` values — a shell grep
cannot tell whether `hydrate: None` truly holds across every installed plane; only Rust reflecting
over `merged_boot_plane_decls` (the same canonical fold core boots from) can. Modelled on
`capability_equality.rs` — the house oracle pattern. It:

- builds the Some/None matrix `field × plane` from the installed decls (one row per hook field —
  `build`, `hydrate`, `start`, `admin_routes`, `openapi`, `routes`, `config_validate`,
  `parse_section`, `named_def_*`, `card_*`, …);
- reads `qa/capability-equality.json` and, for each asymmetric `None` (a `None` where a sibling
  plane is `Some`), asserts the pinned `field→capability` map resolves to a ledger cell whose
  state (`not-applicable` w/ argument, `missing`, or `proven`) *declares* the asymmetry — an
  undeclared asymmetric `None` is RED (G1);
- asserts I1 structurally: the field count is a floor-checked constant, so a per-plane
  `#[cfg]`-dropped field reddens;
- floor-checks its own `field→capability` map length so it cannot silently shrink to prove
  nothing (the `MIN_CAPABILITIES`/`MIN_PROVEN` discipline of `capability_equality.rs:83`);
- carries the same fixture-driven RED/GREEN self-tests through the real verify fn (a green fixture
  passes and counts honestly; an undeclared asymmetric `None` fixture is red; a declared one
  passes) — proving the gate *fires*.

---

## 5. Wiring into `verify-1.6.0-done.sh`

`verify-1.6.0-done.sh` is the 1.6.0 acceptance umbrella (today its role is filled by
`scripts/full-gate.sh`, which auto-discovers any `scripts/*.sh` and runs it — so the shell gate
lands the moment the file is dropped in `scripts/`). Wiring:

- **4a (`plane-config-noun-gate.sh`)** — auto-discovered by `full-gate.sh`; report-only, so
  non-blocking today. `verify-1.6.0-done.sh` calls it *explicitly by name* as a pinned 1.6.0
  acceptance gate (so it is never merely "discovered") and, at DoD, runs it with
  `GREP_GATE_REPORT_ONLY=0` to make the four-noun meter blocking. Its `--selftest` is added to the
  must-run self-test list (`full-gate.sh` §--selftest, `full-gate.sh:205`) so a broken meter is
  refused rather than trusted.
- **4b (`plane_isomorphism.rs`)** — runs under the normal `cargo test` leg the umbrella already
  drives, and its verdict line is surfaced by `scripts/capability-equality-summary.py` alongside
  the equality ledger (`full-gate.sh:254,338`), so the isomorphism gap is *named on every run* the
  same way the equality gap is. `verify-1.6.0-done.sh` asserts the test is present and green as a
  pinned 1.6.0 gate.

At DoD both are BLOCKING and both are green: core's config parser names no section noun (all four
sections evicted onto the seam, `owned_config_sections` non-empty), and every asymmetric `None`
across the four planes is a ledger-declared difference or a ledger-pinned gap.

---

## 6. Distinguishing real isomorphism from the billing-vocab count (recap)

| | plane-noun-gate.sh (billing) | THIS gate (isomorphism) |
|---|---|---|
| axis | LLM *billing/prompting* nouns (`tokens_input`, `rate_card`) | (I2) `PlaneDecl` hook symmetry; (N1) config *section* nouns |
| scope | neutral crates (core, substrate, api, plugin) | (I2) installed plane decls; (N1) `busbar-core` config parse |
| driven to 0 by | M1–M5 vocabulary eviction | (I2) reconciling decls↔ledger; (N1) section-eviction onto the seam |
| relationship | **orthogonal** — green on one says nothing about the other | |

---

## Top 3 risks

1. **Homonym drowning in the four-noun grep.** `pools`/`tools`/`agents` are pervasive legitimate
   homonyms in core (role grants, `tool_pools`/`agent_pools` failover, the frozen legacy
   migrator, the schema snapshot). Without `plane-noun-gate`-grade curation (count only
   *parse-steering* occurrences; allowlist the migrator + snapshot + role/failover uses) the
   meter measures noise, not debt, and gets ignored — the exact fate a debt meter must avoid.
2. **The Rust isomorphism test becoming decorative.** If `plane_isomorphism.rs` merely re-reads
   the ledger JSON it proves nothing the ledger doesn't already. Its whole value is *reflecting
   the actual Some/None of the `&'static PlaneDecl` values* and *reconciling* them against the
   ledger; the `field→capability` map and the "asymmetric-None-must-map-to-a-ledger-cell" join
   are load-bearing and must be self-tested to fire, or the gate is theatre.
3. **Two `PlaneDecl` types drifting.** The gate reasons over the *registry* decl (the semantic
   seam); the *ABI* decl (`hot/decl.rs`) carries its own non-vacuity invariant
   (`admin_routes: Some ⇒ non-vacuous`) guarded by a separate floor test. If the two decls'
   hook sets diverge (a registry hook with no ABI slot, or vice-versa), isomorphism proven on one
   is silent on the other. The gate must pin — and floor-check — the correspondence between the
   two hook sets, or an extracted (FFI) plane can satisfy the registry gate while violating the
   ABI's vacuity rule.
