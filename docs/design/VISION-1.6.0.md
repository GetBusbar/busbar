# Busbar 1.6.0 — The Architecture Vision (authoritative)

This document is the single source of truth for the 1.6.0 architecture. The owner sets the vision;
the architect (the driving assistant) enforces it and hands agents bounded implementation tasks with
**no design leeway**. Agents do not architect. If an agent needs a design decision, it asks the
architect; if the architect needs a vision decision, it asks the owner. Do not lose this to context
compaction — re-read it after any summary.

## The disease we are curing
Old 1.5.5/1.6: **one `busbar` crate** with the core, the 4 planes, and the 16 dialects all mangled
together. Core had special-case knowledge of individual planes. That entanglement is the defect.

## The cure: core is a generic plugin host
You run **core**. You drop in **plugins**: planes, transports, stores, secrets, hooks, exports.
Core does everything the **same way for everything**. It does not know or care whether there are
0 planes or 100. It just has plugins, addressed by **kind**.

### Law 0 — the whole invariant, in one line
**Every plugin is isolated from everything except through its ABI to core. Core is isolated to only
communicate over its ABI to plugins and to know what kind a plugin is. That's it. Neither ever needs
more info.**

This is the sufficiency claim, and it is total: a plugin's *only* channel to the world is its ABI to
core; core's *only* knowledge of a plugin is its ABI and its **kind**. If either side ever appears to
need more than that — core wanting to know *which* plane this is, a plugin wanting to reach another
plugin — the design is wrong, not the invariant. Every law below is a corollary of this one.

## The laws (non-negotiable)

1. **Core speaks plugin ABIs only, and has ZERO instance logic.** Core never contains
   `if this plane is X then do Y`. Core knows a fixed set of plugin **kinds** and treats every
   instance of a kind **identically**. No plugin-instance name ever appears in core logic.

2. **No lateral edges.** A plugin never names, imports, or talks to another plugin — same kind or
   different kind. Plane↔plane, dialect↔dialect, plugin↔plugin: forbidden. **Core orchestrates
   everything**; all coordination flows through core over the ABI.

3. **Plane asks, core provides.** A plane declares a *need* (e.g. "I want an HTTP session"). **Core**
   creates it from a transport and hands it over. A plane never grabs a transport or another plugin
   itself.

4. **1 crate = 1 plugin = 1 plane, self-contained and droppable.** Everything a plane needs lives in
   its one crate. Drop one crate into the plugins folder → core now knows about LLMs, or MCP, or a
   VPN, or whatever is next. No cross-crate sprawl to make one plugin work.

5. **Dialects are internal to their plane — NOT a plugin kind.** One plane owns one IR; that IR *is*
   the plane. One plane speaks 1+ dialects. Dialects live **inside the plane crate** as clean code
   (e.g. `src/dialects/openai.rs`, `src/dialects/anthropic.rs`). Adding a dialect (e.g. `mcpv2`) =
   add a file in that plane crate; the plane's shape does not change and **core does not change at
   all**. Whether a plane uses an internal trait to organize its dialects is **that plane's own,
   standalone decision** — never imposed by core or the contract.

6. **Billing is declared once and priced generically.** A plane declares its **units** (tokens,
   streams, audio-seconds, tool-calls, …) once. Core captures the quantities and prices them against
   the **rate card the user registered**. Units rarely change — a frozen schema — which is what keeps
   the money path byte-identical to 1.5.5.

## What this means for the gates
The purity gates (`plane-purity`, `kind-isolation`) exist to **enforce Laws 1 and 2**: no plugin
instance named in core/neutral crates, no lateral plugin naming. They are **servants of the vision,
not the vision**. Consequences:
- A plane naming its **own** dialects/vendors is correct (Law 5) — it is internal. A gate that reds
  on that is **scoped wrong**, and the fix is the gate's scope, not the code.
- `plane-grep-gate` and `plane-noun-gate` are **report-only debt meters**, explicitly **excluded**
  from the done-oracle (`00-MASTER-PLAN.md`, `verify-1.6.0-done.sh`). They do **not** gate the
  release and must never drive architecture (e.g. splitting a plane into per-dialect crates to make
  a substring count hit zero — that violates Laws 4 and 5).

## Rejected (do not resurrect)
- **D36 "dialect as a plugin kind" / per-dialect crates** (`busbar-plane-<plane>-<dialect>`). A
  dialect is not a plugin kind and gets no crate of its own (Law 5). No crate is ever kind "dialect".
- **The contract-level `Dialect` trait / `DialectMeta` / `DIALECT_ABI`** — an over-abstraction the
  contract imposed on every plane, inert besides. **Removed** in the commit that added this doc.

### Kept on purpose — do not confuse with the above
- The purity gate's **"dialect" vocabulary axis** (the `× dialect` matrix column and the vendor list
  `openai/gemini/anthropic/bedrock/cohere/responses`) STAYS. It is the mechanism that enforces
  **Law 1**: a neutral/core crate must name no vendor instance; a plane may name its own. It is a
  vocabulary scan, not a claim that any crate is a dialect plugin.
- The inert `Kind::Dialect` enum variant + its PENDING-kind gate scaffolding are **not** removed yet:
  excising them is deep gate + design-doc surgery with real thrash risk and **zero done-oracle
  benefit** (nothing reds because of them). Tracked as a **post-green cleanup**, not release work.

## Why the oracle / turnstile exists
The oracle (byte-identity vs the published 1.5.5) and the purity gates, run by the turnstile engine
on **every commit**, exist to guarantee two things:

1. **The laws hold on every commit** — no commit may introduce an instance-branch in core, a lateral
   plugin edge, or a vendor name in a neutral crate. The gates are the per-commit proof of Laws 0–2.
2. **1.6.0 + the LLM plane is indistinguishable from 1.5.5 — to the user.** Install 1.6.0, configure
   only the LLM plane, and it must **look, act, and feel identical to 1.5.5**: same config schema,
   same wire bytes, same behavior — provably, cell by cell, against the published 1.5.5 binary. The
   new planes (MCP, A2A, streams) are **purely additive and off by default**; a user turns them on in
   config — "config mcp/a2a/streams and boom, new features" — and nothing about the existing money
   path changes. That byte-identity is non-negotiable and is the reason the oracle is never waived.

## How "done" is proven
- Quality is proven by the **byte-identity oracle** (money path vs the 1.5.5 golden), the crate's own
  **tests**, **clippy**, and **`/codeaudit` looped to two consecutive zero-finding reports** — not by
  a substring grep. A crate that owns vendor names (a plane) is proven clean by these, not by the
  meter that (correctly) does not scan it.
- The release is done when **`scripts/verify-1.6.0-done.sh` exits 0** (its groups are the real
  oracle: build, plane-purity, byte-identity/parity, config-stability, no-deferral, conformance,
  design-bindings, changelog, plane-delete) and dev CI is green.
