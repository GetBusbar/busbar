# The NO-DEFERRAL gate — `scripts/no-deferral-gate.sh` (spec)

Status: **SPEC** (design; the script is not yet written). This document is the authoritative
specification for a CI gate whose single claim is: **the shipped source tree contains nothing
known-and-deferred.** A green from this gate means every capability the tree declares, it also
implements — no `todo!()` a caller can reach, no self-labelled "SKELETON / dev-only until DoD"
that a shipping feature depends on.

The gate is a *witness*, in the same family as `scripts/plane-abi-neutrality.sh` and
`scripts/plane-purity-lint.sh`: it greps a precisely-scoped file set for a precisely-defined
marker set, asserts the count is exactly the allowlisted floor, and fails loudly (and by default)
on any drift. It is designed so that it **cannot be satisfied by renaming a marker** — see §3.

---

## 0. The evidence this spec is built on (verified 2026-09-02, branch `integration/plane-extraction`)

- **Workspace membership.** Both `busbar-plugin` and `busbar-voice` are default members of the
  root `[workspace]` (`Cargo.toml:13` and `:10`). Both compile in a plain `cargo build`.
- **The only real deferral *macro* calls in shipping source are in `hot/`.** Scanning every
  non-test `crates/**/*.rs` for actual `unimplemented!(`/`todo!(` *invocations* (comment lines
  excluded) yields **exactly 51 sites, all under `crates/busbar-plugin/src/hot/`**:
  `hot/host.rs` (44) + `hot/decl.rs` (7). These are the `PlaneHostVtable::STUB` / `PlaneDecl::STUB`
  const fixtures and their backing `mod stub`.
- **`busbar-voice` has ZERO real macro calls.** Its `todo!()` occurrences
  (`ir/mod.rs:25`, `runtime/session.rs:4`) are *doc-comment mentions* ("the pump body the skeleton
  left `todo!()`"), not invocations. Voice's actual debt is the **phrase** markers
  `SKELETON` (17 lines across 5 src files) and `dev-only until DoD` (4 lines).
- **`plane_host/vtable.rs` mentions `unimplemented!()` only to DENY it** ("no `unimplemented!()`
  stub remains … the Phase-1 fan-out filled every slot"). These are anti-markers and must not
  count — a naive grep would fail the tree on a comment that asserts the *absence* of deferral.
- **`busbar-voice` is NOT wired into the binary.** `crates/busbar/src/main.rs` pushes
  `busbar_llm`, `busbar_mcp`, `busbar_a2a` `PLANE_DECL`s into `installed`; there is no
  `busbar_voice::PLANE_DECL`. Voice's live runtime is behind the `runtime` cargo feature
  (`lib.rs:40` `#[cfg(feature = "runtime")]`, `Cargo.toml` `required-features = ["runtime"]`),
  **OFF by default**.
- **`busbar-voice` is nonetheless FULL-scope in 1.6.0.** `docs/design/plane4-duplex-session-1.6.0-plan.md`
  is the AUTHORITATIVE execution plan and states the owner pulled Plane 4 into 1.6.0 "at FULL scope"
  (both topologies ship). So voice's skeleton markers are **real 1.6.0 debt that must clear when
  voice ships**, not a permanent exemption.

---

## 1. Exact patterns and file globs

### 1a. File scope

```
INCLUDE:  crates/**/*.rs
EXCLUDE:  **/tests/**            # integration test trees
EXCLUDE:  **/*test*.rs          # unit-test-heavy modules (…/tests.rs, *_tests.rs)
EXCLUDE:  **/benches/**  **/examples/**
EXCLUDE:  docs/**  *.md          # design docs legitimately DISCUSS deferral
```

Scan is over source only. Markers in tests and docs are legitimate (a test may name a "skeleton
config"; a design doc discusses deferral by definition).

### 1b. Two marker classes — matched differently

**Class A — deferral MACRO invocations** (a caller can reach these):

```
regex:  ^[[:space:]]*(pub[[:space:]]+.*)?(unimplemented|todo|unreachable_placeholder)![[:space:]]*\(
```

Matched only as a **statement at line start** (after optional leading whitespace / attributes),
never inside a `//` / `///` / `//!` comment. This is what excludes the `plane_host/vtable.rs`
anti-markers and the voice doc-comment mentions. (`unreachable!()` is deliberately **not** banned:
it asserts an invariant, not a deferral.)

**Class B — deferral PHRASE labels** (authors self-declaring debt, usually in comments):

```
regex (case-insensitive, word-ish boundaries):
  \bSKELETON\b
  dev-only[[:space:]]+until
  until[[:space:]]+DoD
  \bHONEST[[:space:]]+PENDING\b
  \bTODO\b   \bFIXME\b   \bXXX\b   \bHACK\b
```

Class B is matched **including in comments** — that is the whole point; these are the author's own
"I deferred this" labels.

### 1c. Deliberately NOT blanket-banned (would make the gate noisy AND gameable)

`PENDING`, `not yet`, `placeholder`, `Pending` as bare words are **excluded from the ban regex.**
The inventory found ~120 such hits and essentially all are legitimate domain vocabulary:
`TrustState::Pending`, breaker "pending cooldown", `drain_pending()`, MCP "pending ids",
`caller_ask_pending`, "not yet created cell inherits health lazily". Banning them would (a) drown
the signal and (b) invite gaming by rewording a real deferral into "not currently wired" prose.
Deferral is instead proven by the **narrow, deliberate** tokens of Class A/B plus the positive
state-assertion of §3.

---

## 2. The ALLOWLIST (each entry justified as NOT a 1.6.0 deferral)

The allowlist is **exhaustive and per-site** (file + kind), single-sourced in the script. Any
Class-A/B hit not on it fails the gate. Any allowlist entry that stops matching (the marker was
resolved) also fails — a stale exemption is a bug (`--selftest` in §3).

| # | Site(s) | Marker | Count | Why it is NOT a 1.6.0 deferral |
|---|---------|--------|-------|--------------------------------|
| A1 | `crates/busbar-plugin/src/hot/host.rs` | `unimplemented!()` in `mod stub` + `PlaneHostVtable::STUB` | 44 | **Compile-surface WITNESS, not a capability.** `::STUB` is a `const` fixture whose only purpose is to type-check that every one of the ABI's `extern "C-unwind"` fn-pointer slots has a real, well-typed signature (`hot/host.rs:652-655`: "it is a compile-surface fixture, not a runnable host"). It is `ADDITIVE and UNUSED — nothing in the engine calls it` (`hot/mod.rs:11-13`). The engine never dispatches to a `STUB` vtable; invoking a slot panics **by design**. Nothing shipped depends on it resolving, so it is not "known-and-deferred" — it is a fixture that ships as-is. Tracked by the plane-ABI foundation effort (`docs/design/1.6.0-protocols-as-plugins.md`), where the *real* hosts live off `busbar_substrate::`/`busbar_api::`, not off `STUB`. |
| A2 | `crates/busbar-plugin/src/hot/decl.rs` | `unimplemented!()` in `PlaneDecl::STUB` stub plane | 7 | Same rationale as A1 for the plane-DECL side: a full stub `PlaneDecl` that PROVES the export surface's shape. `decl.rs:227` "the EXACT" signature witness. Additive/unused compile fixture. |
| A3 | `crates/busbar-plugin/src/hot/mod.rs`, `hot/decl.rs`, `hot/host.rs` | `SKELETON` in doc comments describing the lane | small | These label the *lane itself* as the FOUNDATION skeleton whose disposition is A1/A2. Covered by the same tracked foundation effort; not a per-feature deferral. |
| A4 | `crates/busbar-core/src/plane_host/mod.rs`, `plane_host/vtable.rs` | `unimplemented!()` **mentions** | 5 | **Anti-markers.** They assert the *absence* of stubs ("no `unimplemented!()` stub remains"). They match Class A only if the comment-exclusion in §1b regresses; kept here as an explicit allowlist so a reviewer sees they were considered, and `--selftest` proves the comment filter still excludes them. |
| A5 | `crates/busbar-voice/src/bin/voice-conform.rs` | `skeleton` (lowercase, domain term) | 4 | Not deferral: "IR concept **skeleton**" is the conformance tool's name for the ordered event sequence a transcript must replay (`voice-conform.rs:471,497,506`). Domain vocabulary, matched only because Class B is case-insensitive. Allowlisted by exact file+phrase. |

**Allowlist floor total: 60 marker lines** (51 macro calls + the 9 doc/domain phrase lines above),
all in `busbar-plugin/hot/*`, `busbar-core/plane_host/*` (anti-markers), and `voice-conform.rs`.

### On the memory that `plane-abi-neutrality.sh` "fails on a banned noun in hot/*"

**Verified false today.** Running `scripts/plane-abi-neutrality.sh` prints
`ok plane-abi-neutrality: 0 banned nouns in hot/`. That gate scans `hot/` for *protocol/role
nouns* (llm, mcp, voice, …) in **declarations**, not for deferral markers, and it passes. The two
gates are orthogonal: neutrality governs *what the hot ABI names things*; this gate governs
*whether shipping code defers*. `hot/*` being allowlisted here does not weaken neutrality's scan of
the same tree.

---

## 3. Why the gate is un-gameable

1. **Two independent detectors, not one.** Class A catches the compilable deferral (`todo!()`),
   Class B catches the self-declared label (`SKELETON`). You cannot satisfy the gate by deleting
   the *word* `SKELETON` while leaving a `todo!()` pump body — Class A still fires. And you cannot
   delete a `todo!()` by replacing it with a silent `Ok(Default::default())` sham, because (4).

2. **The allowlist is a FLOOR, checked both directions.** The gate asserts the marker count equals
   the allowlist exactly. Adding a new marker fails (count too high). *Silently removing an
   allowlisted marker also fails* (count too low) until the human updates the allowlist — so a
   deferral cannot be "laundered" by moving it to a file that already had exemptions.

3. **Renaming a marker cannot help.** The banned set is a fixed regex; a synonym you invent
   (`STUBBED`, `WIP`, `LATER`) is not matched, but neither does it *satisfy* the gate — the real
   `todo!()` / missing wiring it hides is still caught by Class A, by `cargo build`/`clippy`
   (a real body must compile and be `#[warn(unused)]`-clean), and by the paired state assertion:

4. **State assertion for the ONE in-scope debt (voice).** For `busbar-voice`, the gate does not
   merely count words — it asserts the *shipping state* the words describe. When the voice DoD lands
   (§4), the gate flips its voice expectation: `PLANE_DECL.handler` must be `Some(_)` and `verbs`
   non-empty in the **default** (non-`runtime`) build, and `busbar_voice::PLANE_DECL` must be
   `push`ed in `crates/busbar/src/main.rs`. So you cannot ship voice by deleting the `SKELETON`
   comment while `handler: None` remains — the positive assertion fails independently of the text.

5. **`--selftest`.** Like `full-gate.sh`, the script proves its own discovery: it asserts each
   allowlist entry still matches (no stale exemptions), that the comment-exclusion still drops the
   `plane_host/vtable.rs` anti-markers, and that it finds a non-trivial minimum number of files
   (a discovery step that finds nothing must not pass everything). Unknown is not green.

---

## 4. REAL 1.6.0 debt the build MUST clear

Exactly **one tracked debt item**, and it is `busbar-voice`:

- **`busbar-voice` is a declared SKELETON that must reach DoD before 1.6.0 GA.** The plane
  declares its noun but `mounts nothing, admits no one, and builds no runtime object` in the
  default build (`lib.rs:104`, `handler: None`, `verbs: &[]`, `lib.rs:145-154`); the live duplex
  pump is behind `#[cfg(feature = "runtime")]` (OFF by default) and voice is *not* installed in the
  binary. Marker surface: **`SKELETON` ×17 + `dev-only until DoD` ×4 = 21 deferral-marker lines
  across 5 source files** (`lib.rs`, `ir/mod.rs`, `ir/usage.rs`, `runtime/mod.rs`,
  `runtime/session.rs`).
- Because the 1.6.0 plan makes Plane 4 **full-scope**, these 21 markers are **hard debt**: when
  voice ships they MUST be removed AND the §3.4 state assertion MUST pass (real `handler`, real
  `verbs`, runtime compiled into prod, `PLANE_DECL` installed). Until then the gate keeps voice on
  the allowlist **with a DoD deadline annotation** — an allowlist entry that is a *tracked* debt,
  visibly distinct from the permanent fixtures (A1–A5).

The `hot/*` stubs (A1/A2, 51 sites) are **NOT** on this list: they are foundation compile-surface
fixtures whose real hosts are a separate protocols-as-plugins effort, not a voice/1.6.0-GA blocker.

**Count of real 1.6.0 debt items: 1** (busbar-voice; 21 marker lines / 5 files), which the build
MUST clear before voice ships in 1.6.0.

---

## 5. Wiring into `verify-1.6.0-done.sh`

`scripts/verify-1.6.0-done.sh` does not exist yet; this gate is a named step it will call. Contract:

```sh
# in verify-1.6.0-done.sh, alongside the other release witnesses
run_gate scripts/no-deferral-gate.sh            # nothing known-and-deferred in shipped src
```

- **Exit semantics.** `no-deferral-gate.sh` is `set -euo pipefail`, exits `0` only when the marker
  count equals the allowlist floor AND (once voice DoD lands) the voice state assertion passes;
  non-zero otherwise, printing every offending `file:line`.
- **Discovery, not a hand-list.** Like `full-gate.sh`, `verify-1.6.0-done.sh` should *discover*
  this gate from CI rather than hard-code it; add `no-deferral-gate.sh` to `.github/workflows/ci.yml`
  so `full-gate.sh` picks it up automatically and the local/CI claim stays identical.
- **Ordering.** Run it AFTER `cargo build`/`clippy` (a marker hidden behind a non-compiling body is
  caught earlier) and alongside `plane-abi-neutrality.sh` / `plane-purity-lint.sh` in the
  "boundary witnesses" group — same tree, orthogonal properties.
- **The 1.6.0 flip.** `verify-1.6.0-done.sh` gates the release; its call to this gate is the
  mechanical enforcement of "voice's 21 markers cleared." On the commit that ships voice, the
  allowlist's voice DoD entry is removed and the §3.4 state assertion arms — if either the markers
  remain or the handler is still `None`, `verify-1.6.0-done.sh` cannot go green.

---

## Summary

- The only real deferral **macro** calls in shipping source are **51 `unimplemented!()` sites, all
  in `busbar-plugin/src/hot/`** (`STUB` compile-surface fixtures) — **allowlisted**, not debt.
- `busbar-voice` is FULL-scope in 1.6.0 but ships today as a **SKELETON** (handler `None`, runtime
  feature-gated OFF, not installed in the binary): **21 marker lines / 5 files = the one real
  1.6.0 debt item**, which MUST clear when voice ships.
- The gate uses two orthogonal detectors (macro + phrase), an exhaustive **floor-checked** allowlist,
  and a **positive state assertion** for voice, so it cannot be satisfied by renaming or laundering
  a marker.
- The stale memory that `plane-abi-neutrality.sh` fails on a banned noun in `hot/*` is **false
  today** — that gate passes and is orthogonal to this one.
- Plugs into `verify-1.6.0-done.sh` as a discovered CI step; arms the voice DoD assertion on the
  commit that ships voice.
</content>
