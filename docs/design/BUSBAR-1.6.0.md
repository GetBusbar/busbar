# BUSBAR 1.6.0 — THE DOCUMENT

**This file is the whole specification.** It replaced and deleted five predecessors
(`VISION-1.6.0.md`, `1.6.0-plane-extraction-LOCKED.md`, `DECISIONS.md`, `1.6.0-PLAN.md`,
`1.6.0-plane-abi-taxonomy.md`). If you are a new session: read **Part 0**, say "got it", and drill
into the Part you need. Nothing else in `docs/design/` outranks this file.

**Authority order inside this document** (was DECISIONS #14, now structural):
Part 1 (Vision/Laws) > Part 3 (Plane seam) > Part 2 (the 78 Locked Decisions) > Part 5 (Execution plan).
Where a checklist disagrees with a Law or an owner ruling, the Law and the owner win.

**How to cite.** The 78 decision rows keep their numbers verbatim — they are cited from source
comments, `qa/*.toml` gate ledgers, workflow YAML and commit messages. `#41`, `#67`, `#78` and the
rest mean exactly what they meant before this collapse. Cite a row; never re-litigate it.

| Part | What it is | Who wrote it |
|---|---|---|
| 0 | Orientation — the whole release in one screen | new |
| 1 | The Vision: Law 0 and Laws 1–7 | verbatim |
| 2 | The 78 Locked Decisions (LAW + enforcing gate) | verbatim |
| 3 | The plane-extraction seam, LOCKED v4 | verbatim |
| 4 | The plane ABI neutral taxonomy, v5 | verbatim |
| 5 | The execution plan: waves W0–W8 | verbatim |
| 6 | The release engine: branches, turnstile, train, Latchkey, cost | new |
| 7 | Ground-clearing session log (2026-09-21) — state of the tree | new |

---

# PART 0 — READ THIS FIRST

## What 1.6.0 is

One sentence: **core stops being a monolith that knows about protocols, and becomes a thin engine
that hosts plugins.**

1.5.5 was one `busbar` crate with the core, the planes and every dialect mangled together, and core
carried special-case knowledge of individual protocols. That entanglement is the defect 1.6.0 cures.
In 1.6.0 you run **core** and drop in **plugins**; core does everything the same way for everything
and does not know or care whether there are zero planes or a hundred.

## The vocabulary (get this right or you will design the wrong thing)

**7 plugin kinds** (#3): `store`, `secret`, `auth`, `hook`, `export`, **`plane`**, **`transport`**.
- `auth` is ONE kind. Inbound-verify and outbound-sign are two *operations* of it. Direction is a
  usage mode, not a kind. There is no "egress-auth" kind.
- `transport` is ONE kind, bidirectional. A plane declares its needs as `(transport, auth)` per direction.
- **NOT kinds:** `control` (admin/oauth2 are cleanliness crates), `dialect` (lives inside a plane),
  `unit` (core's own workflow).

**5 planes** (#48): `llm`, `mcp`, `a2a`, **`streaming`**, `decisions` (jev).
- The fourth plane is **streaming**, not "voice". Crate `busbar-plane-streaming`, feature
  `plane-streaming` (#18). **Voice is a dialect inside the streaming plane**, one capability among N.
  This distinction is load-bearing: name the plane "voice" and you have named an instance where a
  category belongs, which is exactly what the neutrality witness exists to catch.

**A dialect** is a thing INSIDE a plane — the llm plane has 6, mcp has 1, a2a has 1, streaming has N.
A dialect is not a plugin and not a kind. Nobody drops in a dialect; they drop in an updated plane
plugin that supports more dialects. Adding one is a new file in that plane's crate, and **core does
not change at all**.

**2 ABI lanes, split by heat** (#30):
- **HOT / POD** — `plane` + `transport`. In-memory, `repr(C)`, sub-microsecond.
- **COLD / JSON** — `store`, `secret`, `auth`, `hook`, `export`.

Every plugin has **both** ABIs and can be **compiled in OR dropped into `plugins/`** — same contract,
same loading path. Those are the only two requirements; there is no third (#2).

**Rejected, do not resurrect:** D36 (dialect as a plugin kind / per-dialect crates) and D37 (a
`control` plugin kind). If a stale checklist reports these as "todo", it is wrong — ignore it.

## The laws in one breath

**Law 0:** every plugin is isolated from everything except through its ABI to core; core is isolated
to communicating over that ABI and knowing what **kind** a plugin is. That's it. Neither side ever
needs more. If either appears to need more, the design is wrong, not the invariant.

Everything else is a corollary: core has zero instance logic (1); no lateral plugin edges (2); the
plane asks and core provides (3); one crate = one plugin = one plane (4); dialects are internal (5);
billing is declared once and priced generically (6); every plugin is off until its config verb
appears (7). Full text in Part 1.

## What "done" means

Dev-green on **one SHA**, with nothing outstanding, deferred or niggling:

1. `scripts/verify-1.6.0-done.sh` exits 0 across its **22** groups — full run, never `--fast`
   (exit 3 is PROVISIONAL, not spendable), every bless/repoint env var empty.
   *(The script declared 21 while 22 `begin_group` blocks existed, so `floor_is_honest` refused to
   score anything at all. Fixed this session — see Part 7.)*
2. Construction standing-reds **empty** — `ship-ready` green, not merely `--posture`-tolerated.
   Hard clause: every `Family::Neutral` crate names **ZERO** plane/control/transport/dialect instance
   vocabulary in source, ceiling 0 and ARMED, with no ratchet row able to raise it.
3. Every entry in `testing/shadow-oracle/accepted-differences.json` revisited and re-signed-off —
   each one is a crack in "LLM-only ≡ 1.5.5".
4. Laws 0–7 hold on the SHA; byte-identity green; config-gated loading verified.
5. Nothing niggling: no dead scaffolding, docs and version bump landed, changelog complete.

## The two things that are never negotiable

**The oracle is never waived.** 1.6.0 configured with only the LLM plane must be byte-identical to
the published 1.5.5 — same config schema, same wire bytes, same behaviour, proven cell by cell
against the real binary. The new planes are purely additive and off by default. A genuine divergence
is **PARKED for the owner** with cell + diff + root-cause + recommendation. It is never self-approved
(#10/#59).

**Money bytes are sacred — and the model is LOCKED.** Say it exactly this way, because saying it any
other way leads people to debug the wrong thing:

> **Two independent systems: the LEDGER and the RATECARD. Money is a VIEW.**
> **money = f(ledger, ratecard)**, derived at read time.
> **Money is never wrong. If a number looks wrong, the LEDGER is wrong or the RATECARD is wrong.**

A request produces `output_tokens: 27`. The ratecard says what an output token costs. The view does
the multiplication when someone asks. Nothing anywhere ever stores `$2` — a price is the answer to a
question, never a fact in a row (#42/#43/#44/#66/#71/#77). Integer-only, unitless, no floats.

So a money investigation has exactly TWO questions, and every finding must name one:

- **Is the LEDGER right?** Did the plane write the true counts — nothing dropped, doubled, silently
  zeroed, or filed under the wrong class. *(G-1 was this: Gemini's fourth token term was dropped, so
  the ledger said 190 where 222 happened. Cohere reading a float count as `unwrap_or(0)` is this: 27
  recorded as 0.)*
- **Is the RATECARD right?** Right rates, the right dated card resolved for that instant, right
  currency, and an unpriced class REFUSES rather than silently answering zero (#42).

Anything that is neither — an overflow, a rounding that is not integer-exact, two copies of a divisor
that can disagree — is not a money dispute at all. It is a **broken derivation**: the view failing to
compute `f` correctly from correct inputs. Name it as that.

"Under-billed" and "over-billed" are symptoms, never findings. The finding is *the ledger recorded X
where Y happened*, or *the ratecard resolved card A where card B was in force*.

**The standard is a bank auditor.** Would it pass? If not it is wrong, and the ledger or the ratecard
gets FIXED. A wrong money decision is never signed off — and an agent never self-approves one
(#10/#59); it is PARKED for the owner with cell, diff, root cause and recommendation.

Enforced by `cargo run -p xtask -- gate money-invariants`: no money-path record carries a
plugin/plane identity (#77(1)), no durable record stores a price (#77(3)), and the facts line is
sealed only in core/kernel crates (#77(2)).

**Banned words:** defer, 1.6.x, later, "out of scope for 1.6.0". It is 1.6.0-or-bust.

## Who decides what

The owner sets the vision. The **architect** (the driving assistant) owns the seams and hands agents
bounded implementation tasks with no design leeway. **Agents implement; agents do not design.** If an
agent needs a design decision it asks the architect; if the architect needs a vision decision it asks
the owner. Root-cause first: agent laziness is fixed at the root, never brought for sign-off.


---

# PART 1 — THE VISION: LAW 0 AND LAWS 1–7

> *Absorbed verbatim from `VISION-1.6.0.md`, which this document replaced. Highest authority in this document.*


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

7. **Config-gated loading — every plugin is off until its config verb is used.** Core loads a plugin
   **iff** its configuration section is present. No verb configured → that plugin is never loaded.
   This holds for **all** kinds, not just planes: don't configure a SQL store → it is never loaded;
   don't configure the plane verbs (`pools` = LLM, `tools` = MCP, `agents` = A2A, `streams` = voice)
   → those planes are never loaded. This is the *mechanism* behind "LLM-only ≡ 1.5.5": with only
   `pools` configured, only the LLM plane loads and the bytes are identical to 1.5.5; add `tools` /
   `agents` / `streams` and the MCP / A2A / streams planes load — purely additive, nothing else
   changes. A plugin that loads (or costs anything) without its verb configured is a bug.

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
- The `× dialect` column itself is a **neutral-only tripwire**: its ceiling is armed at 0 for every
  `Family::Neutral` crate, and it is deliberately **NOT measured** for plane/dialect crates
  (`xtask/src/gates/kind_isolation/matrix.rs:528-536` — the one column with no owner to strike
  itself out, because the plane crate *is* where the vendor names live until the split lands). Its
  sole purpose is catching a vendor name leaking into a neutral crate, not policing a plane's own
  dialects.

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

## Definition of Done — the checklist (owner-set; do not lose to compaction)
"Done" is **dev-green 1.6.0 with nothing outstanding, deferred, or niggling** — the point where the
architect can honestly say *"there is nothing left to do; it is perfection until users test it."*
Concretely, ALL of:
1. `scripts/verify-1.6.0-done.sh` exits 0 on one SHA, and dev CI is green on it.
2. **Construction standing-reds are EMPTY** — `ship-ready` green, not merely `--posture`-tolerated.
   The LLM-engine rebuild is done (no 1117-line request-path fn; terminal doors only in the Audit
   step; the price named only where the card lives; one pick site; ports-only tests; holds clean).
   **The hard clause:** every `Family::Neutral` crate — `kernel`, `core`, `caps`, `contract`,
   `contract-transport`, `grammar`, `substrate`, `api`, `timing`, `plugin-abi`/`plugin-tooling`,
   `unit`, `store`, `auth`, `secret`, `hooks`, `export`, **and the composition root** — names
   **ZERO** `plane`/`control`/`transport`/`dialect` instance vocabulary in source: ceiling 0,
   ARMED (the `law0-neutral-instance` class in `xtask/src/gates/kind_isolation/matrix.rs`), and no
   `[[cell]]` ratchet row in `qa/kind-isolation.toml` can raise it. Cargo.toml manifest names are
   excepted (manifest edges are already governed by `kind-isolation:deps`). A plane/kind-home crate
   naming its **own** kind's vocabulary is correct (Law 5) and is never measured by this class.
   "Done" means source count == 0 for every neutral × `{plane, control, transport, dialect}` cell —
   not "held flat" at whatever count it measures today.
3. **Every accepted 1.5.5 deviation is revisited and re-signed-off.** Walk
   `testing/shadow-oracle/accepted-differences.json` entry by entry: each is a crack in "LLM-only ≡
   1.5.5". Eliminate the ones that can be eliminated (make the bytes match); for any that genuinely
   must remain, re-confirm the justification consciously — no deviation is inherited unexamined.
4. The laws (0–7) hold on the SHA: purity/kind-isolation/plane-delete green, byte-identity (parity)
   green, config-gated loading verified, additive planes conform.
5. Nothing niggling: no dead scaffolding worth removing left behind (e.g. finish or excise the inert
   `Kind::Dialect` remnant), docs + version bump landed, changelog complete.

## How "done" is proven
- Quality is proven by the **byte-identity oracle** (money path vs the 1.5.5 golden), the crate's own
  **tests**, **clippy**, and **`/codeaudit` looped to two consecutive zero-finding reports** — not by
  a substring grep. A crate that owns vendor names (a plane) is proven clean by these, not by the
  meter that (correctly) does not scan it.
- The release is done when **`scripts/verify-1.6.0-done.sh` exits 0** (its groups are the real
  oracle: build, plane-purity, byte-identity/parity, config-stability, no-deferral, conformance,
  design-bindings, changelog, plane-delete) and dev CI is green.

---

# PART 2 — THE 78 LOCKED DECISIONS

> *Absorbed verbatim from `DECISIONS.md`, which this document replaced. Row numbers are cited from source comments, gate ledgers and commit messages — they are permanent. Cite a row; never re-litigate it.*


Rule: a decision here is LAW and states the CURRENT truth — facts only. When a decision changes, its
row is rewritten to the new truth; rows never carry an override trail ("ignore X, do Y", "AMENDS",
"CANCELLED", dated rulings). If it has an enforcing gate, drift turns the gate RED — it cannot be
re-opened in conversation. If "Gate" says TODO, adding that gate is itself a task. Never re-litigate a
row here; cite it. Only VISION-1.6.0.md and 1.6.0-plane-extraction-LOCKED.md outrank this file.

| # | Decision (LAW) | Enforcing gate |
|---|----------------|----------------|
| 1 | **Architecture = core + plugins.** Core is a thin engine running ONE uniform per-unit governance workflow (Authenticate·Verify·Approve·Admit·Route·Meter·Audit) that every plane's data passes through. Core names ZERO plane types. | plane-purity (reverse), plane-abi-neutrality grep, teller-steps |
| 2 | **A PLUGIN IS A PLUGIN — exactly TWO requirements, every kind (plane included):** (1) compiled-in OR dropped-in (same contract, one loading path); (2) communicates ONLY over the ABI. No third requirement. **A PLUGIN = A 3rd PARTY — ACCEPTANCE TEST:** a plugin SELF-REGISTERS via `busbar_plugin_sdk::export_<kind>_plugin!` and TESTS ITSELF; the kernel never tests it and never names it — not in code and NOT in its own tests. The grep for a concrete instance noun stays neutral INCLUDING under `tests/`: if the kernel names or tests a specific plugin by name, it has stopped treating it as a 3rd party and the row is violated. | kind-isolation, instance-noun-neutrality, construction:ports-only-tests, token-auth cdylib proof |
| 3 | **Plugin kinds (7):** store, secret, auth, hook, export, PLANE, TRANSPORT. A kind = a capability core brokers by key, swappable (compiled-in OR dropped-in over the ABI), of which core names no concrete instance. **Direction (inbound/outbound) is a usage mode, never a kind boundary.** TRANSPORT is one kind, bidirectional: a plane declares a transport need and, if core lacks that carrier, you install the transport plugin too — impls busbar-transport-{http,ws,stdio,tcp,tls,sse,grpc}; transport-key = server-side facet of transport. AUTH is ONE kind: inbound-verify and outbound-sign/decorate are two OPERATIONS of the auth kind, not two kinds — there is NO separate "egress-auth" kind (the code's `auth`/`egress-auth` split is an ABI detail inside one kind). A plane declares its needs as (transport, auth) per direction — inbound {transport=X, auth=Y}, outbound {transport=A, auth=B}. NOT kinds: control (admin/oauth2 = cleanliness crates, #5), dialect (inside a plane, #4), unit (core's governance workflow). Impls: store(store-example-plugin, store-memory, +external pg/mysql/valkey/sqlite), secret(secret-example-plugin), auth(auth-static-plugin/token-auth; outbound schemes bearer/mTLS/SigV4/GCP/SPKI-pin currently internal units, drop-in packaging owed), hook(hook-test-plugin), export(export-prometheus, export-webhook, export-file, export-otlp — OWNER RULING 2026-09-18: the four built-in sinks in busbar-core/src/export/{prometheus,webhook,file} + observability otlp were COMPILED-IN-ONLY "half plugins" violating #11 both-ways; they are finished into real both-ways export-kind plugins over the COLD/JSON export ABI (#30), self-testing (#2), and export-example-plugin is then DELETED; behavior stays byte-identical to 1.5.5 — oracle-gated on the export/metrics path), plane(busbar-plane-{llm,mcp,a2a,streaming,decision} — 5 planes, #48), transport(7 carriers above). | kind-isolation:registry (7 kinds) |
| 4 | **A DIALECT is a thing INSIDE a plane** (llm 6, mcp 1, a2a 1, streaming N). It is NOT a plugin and NOT a kind. No per-dialect crates, no Dialect trait/kind. | kind-isolation:truths (dialect kind ⇒ RED) |
| 5 | **admin & oauth2 are NOT plugins.** They are compiled-in cleanliness crates, one-way dep on core, off the hot path. There is no "control" plugin kind. | kind-isolation:registry/truths |
| 6 | **One crate per plane** `busbar-plane-<x>`, pure. ALL plane logic — dialects, codecs, modes — folds INTO that one crate; there is NO separate `busbar-*-codec` crate (#39). A plane opens no socket; all wire I/O is the transport plugin's (#7/#40). The plane crate's dep closure names no kernel/core type (#40). | construction loc/surface ceilings; no busbar-*-codec crate |
| 7 | **A plane opens NO socket.** It declares transport needs as data at registration and asks core for a transport; ALL socket/DNS/pool/TLS/retry/breaker I/O lives in shared transport crate(s). Hot read/write = POD-by-pointer, zero-alloc, zero per-token host crossings. | source-denylist (hyper/reqwest/tokio-net out of plane closure) — TODO arm; perf/alloc gate |
| 8 | **Broker law:** plugins never talk to each other. Each declares needs+capabilities; core brokers by capability key (registry lookup, core names no concrete plugin). Coupling only ever points down (at core/contract). | plane-abi-neutrality, kind-isolation:deps |
| 9 | **Byte-identity = USER-OBSERVABLE contract, not internal-structure.** A 1.5.5 user upgrades to 1.6.0 and notices nothing. Internals may be rewritten freely; the oracle proves no user-visible byte moved. | shadow-oracle diff vs golden/1.5.5 (NEVER waived) |
| 10 | **The oracle's sole job:** prove no user-visible byte changed. A RED cell is a QUESTION, not a failure. Agent-laziness is root-caused and fixed without owner involvement. Every genuine RED cell that has a 1.5.5 golden is PARKED for owner sign-off (cell + exact diff + root-cause + recommendation) — never silently self-fixed — while the run continues on other fronts. Money-path bytes are sacred. | shadow-oracle; parked-divergence log; accept-register requires owner sign-off |
| 11 | **1.6.0 ships TWO distributions, one contract; both-ways is REQUIRED for every plugin kind incl. PLANE.** Every plugin is compiled-in OR dropped-in over the same contract and one loading path (#2). DEFAULT distribution = everything compiled in; BARE-BONES = core + drop-in plugins. The folder-drop loader for every kind (planes included) is in the cut. **Compiled-in vs dropped-in is a BUILD/packaging property, NOT a development-coupling one:** every plugin is developed INDEPENDENTLY (exactly as in 1.5.5 — no plugin's source depends on the kernel's internals to be built), the DEFAULT build simply compiles them in, and the repo-per-plugin split is a post-ship `git mv` (packaging), never a precondition for developing or shipping a plugin in isolation. | build gate (both distributions green) + per-kind drop-in conformance rig — TODO arm bare-bones + drop-in rig |
| 12 | **1.6.0 = 1.5.5 + MCP + A2A + STREAMING + DECISIONS(jev).** The added planes bring the roster to 5 (llm/mcp/a2a/streaming/decisions, #48); live realtime voice is ONE capability the streaming plane carries, not its name (streaming does more than voice). New planes are additive, config-reached (add tools/agents/streams/decisions to config); they never touch the existing 1.5.5 experience. The internal re-architecture IS 1.6.0 (else it's just 1.5.5). | conformance (mcp/a2a/streaming/decisions rigs) + oracle (1.5.5 unchanged) |
| 13 | **Marketing = vision; docs = truth.** A vision↔truth delta is a decision (agree/disagree → new row here), not an auto-fix. Owner updates marketing to fact-based AFTER code lands. | (process) |
| 14 | **Authoritative docs = VISION-1.6.0.md + 1.6.0-plane-extraction-LOCKED.md + this file.** Every other design doc is reconciled to them or deleted. No stale line may survive for an agent to resurrect. | doc-reconciliation pass |
| 15 | **Banned words:** defer / 1.6.x / later / "out of scope for 1.6.0". 1.6.0-or-bust. Feature-need changes come to owner with a real case; agent-laziness = fix the root. | (process) |
| 16 | **Worst-case ship date: Wed 2026-10-08 17:00 PDT.** Moves only on a named MAJOR EVENT (Commit-C non-decomposable + divergence cascade; systemic HIGH reopening money path; fleet outage). | 1.6.0-PLAN.md status |
| 17 | **One feature per plane, no `root-*`.** The per-plane compile knob is exactly `plane-<x>` (pull the plane crate + enable core's plane edge). END STATE default = `["auth-admin-tokens","hook-ranking","plane-llm","plane-mcp","plane-a2a","plane-streaming","plane-decision"]`. The whole `root-*` family is gone (`teller-waist` is unconditional; the tower dep folds where used). The collapse runs inside the switch-over cutover cleanup — never as a standalone edit (dropping `root-llm` before `teller-waist` is unconditional would unwire the llm unit-plane path). | build (both distributions) green + target default line |
| 18 | **The fourth plane is STREAMING, not voice.** Voice is ONE capability/dialect inside the streaming plane; streaming can carry more than voice. No `voice` as a plane/kind/crate/feature name: the streaming plane's crate is `busbar-plane-streaming`, feature `plane-streaming`; ALL logic (dialects incl. voice, codecs, modes) lives in that one plane crate — no `busbar-streaming-codec` crate (#6/#39). The rename is byte-identical (naming/packaging, not behavior). | grep: no `voice` as a plane/kind/crate/feature name; the streaming plane is `streaming` |
| 19 | **busbar-core and busbar-voice are DELETED in 1.6.0 — the deletion is the release.** #1 requires core to name zero planes; #12 makes the internal re-architecture the release. busbar-core dissolves per #36/#37 into `busbar-kernel` (loop) + the 8 `busbar-kernel-<name>` workflow crates + `busbar-core-{admin,oauth2,substrate}`; the fat plane crates collapse to ONE `busbar-plane-<x>` each (codecs/dialects fold IN, #39); busbar-voice is deleted (voice = a streaming dialect, #18). Byte-identical LOC move, oracle-proven; ~30-crate in-tree end state (#39). Executed as a parallel wave fan-out. | kind-isolation-ship:legacy-drain = 0; ~30-crate in-tree end state; shadow-oracle byte-green on every money move |
| 20 | **Transport-seam #7 extraction is IN the 1.6.0 cut.** The fat plane crates are engine+I/O; the pure `busbar-plane-*` crates enforce purity gates (no tokio/reqwest/async/std::net, no kernel-crate names, no money words, #40). The per-plane collapse is proven byte-identical: (a) ALL plane logic incl. codecs/dialects → the ONE `busbar-plane-<x>` crate (#39 — no codec crate); (b) socket/pool/TLS/transport I/O → the transport plugin (#7/#40 — a plane opens no socket); (c) the engine-proper (App/state/session/secret/plane-registry/cost/governance) → `busbar-kernel`. A spot oracle box (zero-idle, terminate on close) proves each money move. | plane-purity gates green on each `busbar-plane-*`; source-denylist armable; kind-isolation-ship green; shadow-oracle byte-green |
| 21 | **A plane crate is PURE and self-contained — ONE crate holds all its logic.** `busbar-plane-<x>` holds ALL of the plane's logic — dialects, codecs, modes (#6/#39) — with no I/O, no kernel/core-crate names in its dep closure (#40). There is NO separate codec crate. The crate that dies is the fat `busbar-<x>` engine: its I/O moves to the transport plugin (#7/#40) and its remaining logic into the one plane crate. | plane-purity gates green; no busbar-*-codec crate; fat busbar-<x> engine crate deleted |

| 22 | **The money-live cutover runs unattended when oracle-green.** Retargeting each plane's live PLANE_DECL/serve onto the plane-adapter + kernel-units + transport spine, the money one-book collapse, and deleting busbar-core/busbar-voice execute autonomously; any step proven shadow-oracle byte-identical vs 1.5.5 lands. A genuine byte divergence not root-caused to agent-laziness is PARKED (cell + diff + root-cause + recommendation) and the run continues elsewhere — the ledger is never blessed upward, the oracle never waived. | shadow-oracle byte-green per step; parked-divergence log; ledger-nondecreasing |
| 23 | **Streaming cost hold settles end-of-turn.** The streaming plane (new; no 1.5.5 golden) reserves on admit and settles per completed turn, mirroring the llm plane's per-unit meter. | streaming conformance rig: reserve-on-admit + per-turn settle |
| 24 | **D38 `amend_rate_history` is a real 1.6.0 money-path admin verb** — additive new admin surface (no 1.5.5 golden; it does not alter existing money cells). Spec + build it. | admin verb present + tested; oracle: existing money cells unchanged |

| 25 | **No serial phases — the money book is reached through ONE seam.** A byte-identical pass-through stub lands the money-book seam (trait + DTO) immediately, so every caller (kernel, planes, cost/governance, admin) compiles and proceeds in parallel against a stable interface. The consolidated one-book is built BEHIND the seam concurrently and activated by a one-line composition flip, shadow-oracle byte-proven — an atomic moment, not a blocking phase. Required money goldens (e.g. mid-stream upstream-error) are recorded up front in parallel, never a prerequisite that stalls work. | money-book seam present + byte-identical stub oracle-green; one-book flip oracle-green; no "serialization point" survives in the plan |

| 26 | **The teller loop dispatches by capability KEY — core names ZERO concrete callers; no `if is_admin`/`if is_mcp` chain.** Today the loop hardcodes `if is_admin { admin } else { refuse }` and NO plane is on it (admin is a cleanliness crate, NOT a plane — #5). 1.6.0 replaces that branch with a registry/capability-keyed dispatch table (#1 uniform workflow + #8 broker-by-key): every caller — admin and each plane — registers a `Units` implementation keyed by capability; the loop looks it up and dispatches, naming nobody. With only admin registered it is byte-identical. Each plane is then onboarded independently against the seams below and flipped on one at a time, oracle-proven — no `if/else` chain, no serial pole. Enabling seams, each built BOTH ends and byte-safe (unused until a plane opts in): (S1) DISPATCH — the capability-keyed loop + additive `register_units(key, impl)`; (S2) MONEY-BOOK — a settling seam + byte-identical pass-through stub over the shared durability book (#25), so exit arms compose behind it; (S3) HOST-CAPS — outbound egress trust-anchor/SPKI-pin/client-identity, inbound agent-card JWS/pin, server-side SSE reframe, exposed as composition-root-owned seams; (S4) HOT-ABI + drop-in loader — de-stub `busbar-plugin/hot`, loader `open_plane` + `supported_abi("plane")` + manifest claim-sealing + plane cdylib SDK + bare-bones distribution (#11). | teller-steps: loop names zero concrete callers (grep) + dispatch is table-keyed; each seam's both-ends present; per-plane flip shadow-oracle byte-green |

| 27 | **No step waits on another where a seam or fixed artifact can decouple it (generalizes #25/#26).** (a) The 1.5.5 GOLDEN is a fixed reference recorded from the 1.5.5 binary UP FRONT in parallel — only the diff needs a 1.6.0 candidate, so golden-recording never waits on a green build. (b) The busbar-core DRAIN moves each engine step behind a per-step facade/re-export in busbar-core, so steps relocate to their unit crates in ANY order (no L0→L3 chain; App/state behind a composition facade is not "last"). (c) The two arch audits run continuously against the rolling frozen SHA (they score the LOCKED architecture, fixed once the #26 seams are set), converging as code lands. (d) Plane onboarding + boot-chain assembly are additive registrations into the #26 table — parallel, never a single builder. (e) Integration stays near-parallel via disjoint per-crate agent ownership. (f) The fleet scales to prove N candidates concurrently. | the plan carries no "must finish before" that a landed seam/facade removes |

| 28 | **The loop's answer shape is two-variant `PlaneAnswer`; live streams settle per sub-unit, not by final byte count.** NAME: the two-variant type is `PlaneAnswer`, NOT `PlaneDispatch` — the shipped `PlaneDispatch` trait (`crates/busbar/src/root/transports.rs:483`, RouteLeg carrier, `DrivenOnce`; `LlmNode` builds on it) KEEPS its name and role. They COEXIST: `PlaneDispatch` carries bytes through Route; `PlaneAnswer` is what the loop settles / hands to the outer async handler. A caller's serving body produces either `Unary(status, headers, body)` — buffered, crosses the sync channel and settles at Encode on the final byte count (the admin cleanliness caller + all unary verbs, incl. SSE materialized after dispatch) — or `Live(Response)` — a live body the outer async handler serves directly, governed at admit (auth/verify/approve/admit/audit ran unary), bypassing the Encode-emits-bytes path. llm keeps its RouteLeg and emits `Live`; admin + unary verbs emit `Unary`. Live-stream settlement is the plane's, through the money-book seam at its natural sub-unit boundary: streaming voice reserves-on-admit + settles per completed turn (#23); a non-billed notification channel (e.g. an mcp subscription listen stream — new plane, no 1.5.5 billing) is admission-governed and zero-metered. A plane-neutral `PlaneInFlight` binding table on ProductionUnits keyed by `ctx.key` carries per-request state (bytes/frame/principal/creds at ingress; answer at Route), mirroring `AdminUnitTable`. GOVERNANCE MODE: planes are ALREADY loop-served plane-faithfully — MCP/A2A/voice/llm-native ride a SECOND teller loop (`crates/busbar-substrate/src/teller/`) via `run_gauntlet[_session]`→`GauntletAdapter`→substrate `run_unit`, which already carries a real arena (`DispatchScope`, `crates/busbar-substrate/src/plane_host/scope.rs`) through verify/approve/admit. The keystone is therefore NOT a per-plane admin-bytes bridge and NOT "first plane on the loop" — it is LOOP UNIFICATION: lift the `DispatchScope` arena onto kernel `busbar-kernel::teller::run_unit`, re-point the gauntlet riders (`busbar-llm/src/native_ingress.rs`, `busbar-a2a/.../receive.rs`, `busbar-mcp/.../method.rs`, voice `topology`, `duplex_ws.rs`) at the one kernel loop, collapse the substrate loop's TWO audit doors (`teller/run.rs` `audit_refused` + admitted/abandoned) to the kernel loop's single audit step, then DELETE `crates/busbar-substrate/src/teller/` (~973 prod LOC). Prove MCP end-to-end byte-identical on the unified loop first (existing plane-faithful governance UNCHANGED — no rewrite, no asymmetry), then the rest ride the same seam. This is the single wave that clears §11a→9 AND makes §11b's per-token/POD perf+alloc benches measurable in production. LOOP-UNIFICATION IMPLEMENTATION RULINGS (three seams): (1) **THIN VERBATIM RIDER is the onboard** — the gauntlet riders re-point at the kernel loop VERBATIM, with NO `bind_book`, the kernel exit settles NOTHING, and metering stays in `drive`; full-governance-on-exit is a §11b refinement, not part of the unification. (2) **FLIP SEAM = composition-tier host selection** — a plane calls `ctx.host.run_gauntlet` UNCHANGED; the composition root installs a kernel-loop-backed host, per-plane-keyed and oracle-gated, so a plane flips onto the unified loop by composition, never by editing the plane. (3) **SESSION SEAM = Option C-on-A** — the kernel governs-to-admit then hands back to the plane, returning `PlaneAnswer::Live` (empty / `ZeroHold`, no exit-settle, no `bind_book`); the plane keeps its plane-side reserve + per-turn/per-frame settle. Option B (kernel owns session settlement) is REJECTED. `PlaneAnswer` is the answer shape at the unified boundary. | teller-steps: plane onboarded via the loop (admin template); live verbs byte-identical on the conformance rig; loop names no concrete caller |

| 29 | **During the drain, the money oracle runs via `bin/oracle` DIRECTLY on a fleet box — NOT through `prove-remote.sh`.** `prove-remote.sh` gates the shadow oracle behind `xtask gate --all`, which exits 1 if ANY gate is RED; the 5 core-deletion completeness gates (construction, kind-isolation, ship-ready, structure-lint, audit-ledger) are expected-RED until busbar-core deletion lands, so that wrapper is CIRCULAR (money cutovers need the oracle → the wrapper needs the gates green → the gates need the cutovers). The money byte-proof therefore runs `bin/oracle record`+`replay` directly on a fleet box (docker present), scoped to the money families, vs the 1.5.5 golden. This is NOT waiving the oracle — it still runs and must be byte-green; only the circular gate wrapper is bypassed. The 5 core-deletion gates do NOT gate the money oracle. PROVEN: the kernel-loop llm path is money-parity byte-faithful to legacy (switch-over golden 25/25 — loop==legacy on every fixture), so per-plane money cutovers are dual-write-then-flip-authority, not from-scratch byte reproduction. | money proofs use bin/oracle direct; loop==legacy switch-over golden green |
| 30 | **Each plugin kind is bound to exactly ONE ABI lane, chosen by HEAT — a plugin uses the tier matched to its heat, NOT both.** There are two lanes on one seam (LOCKED §2/§3): the HOT/POD-memory lane (`#[repr(C)]` by pointer, zero-alloc, zero per-token host crossings, <1µs — LOCKED §8) and the COLD/JSON lane (serialize-per-call, off the per-token path). **The discriminator is the per-TOKEN streaming inner loop:** a kind that runs inside it is HOT; everything else is COLD. **HOT/POD lane = plane, transport** — the only kinds in the per-token loop; both are NEW in 1.6.0 (neither existed in 1.5.5), so there is no 1.5.5 byte-identity constraint on them. **COLD/JSON lane = store, secret, auth, hook, export** — all five existed in 1.5.5 as cold JSON plugins *by deliberate design* (busbar hook.rs: "off the request hot path… a serialize per call never touches request latency"); each fires per-request-once or at boot/write-behind, NEVER per-token: store=write-behind, secret=config/boot resolve, auth=one admission check per request (cached), hook=per-request phases (inbound transform mutates request IR ×N gates; decide redirects lanes ×hops; outbound is a read-only notify tap once at response head — none per-token), export=write-behind sink. Keeping the five on JSON is REQUIRED for 1.5.5 byte-identity (they ARE JSON in 1.5.5; moving them to POD would rewrite them and risk the oracle). Corollary: the "every plugin has BOTH ABIs" shorthand is SUPERSEDED — the law is "both LANES exist on the seam; each kind is assigned to one." | kind-abi-lane gate: plane/transport declare hot(POD) ABI, store/secret/auth/hook/export declare cold(JSON) ABI; a kind declaring the wrong lane ⇒ RED; per-token-loop grep = {plane,transport} only |
| 31 | **Plugin topology = ONE repo per plugin, outside `busbar`. OWNER-LOCKED 2026-09-18.** A plugin is a 3rd party (#2), so it lives in its own GitHub repo — never inside the `busbar` (core) repo, and never bundled into a shared plugins-monorepo (a monorepo invites cross-plugin coupling / shared test utils, which #2 forbids). This is the true 3rd-party model and matches the existing 10 clean external repos (store-{mysql,postgres,sqlite,valkey}, auth-{github,ldap,oidc}, hashicorp-vault, headroom-hook, webrequest-hook). New plugins (incl. the 4 promoted export sinks — export-{prometheus,webhook,file,otlp}, #3) are created as NEW repos templated from those 10. The DEFAULT distribution still compiles a plugin in by depending on its repo (compiled-in vs dropped-in = packaging only, #11) — the plugin SOURCE never re-enters `busbar`. **The multi-repo drift risk (the 10 had drifted to 4 different pre-1.5.5 core pins — 1.5.0/1.5.2/1.5.3/1.5.4 — because each `.busbar-ref` was bumped independently) is solved by TOOLING, not topology:** a release-train step bumps every plugin repo's `.busbar-ref` to the released core SHA in one lockstep pass (the reusable `plugin-ci.yml` already materializes core as a sibling), and this tooling is EXPANDED to cover every new plugin repo as it is created. Independent repos + one-command lockstep pin. | plugin repos live under GetBusbar/<plugin>, never crates/ in busbar; release-train pin-bump covers all plugin repos incl. new ones; no plugins-monorepo |
| 32 | **Release-train CI across all repos — OWNER-RATIFIED 2026-09-18.** BRANCH FLOW is `dev → qa → main` in EVERY repo (busbar + all 20+ plugin repos + downstream tooling); **never push to `main` directly** — promotion happens only through CI, driven by the busbar main build. All development lands on `dev`; nothing advances past `dev` until the busbar main build conducts it. CONDUCTOR = **turnstile** (the existing merge-queue/land + EC2-fleet orchestrator, extended to drive releases). The train, on a busbar release SHA: (A) core 21-group done-oracle green on CORE_SHA (single source of truth); (B) PIN-LOCKSTEP — one turnstile dispatch rewrites every manifest repo's `.busbar-ref` → CORE_SHA on `dev` (kills the multi-repo drift that left plugins pinned to 1.5.0/1.5.2/1.5.3/1.5.4); (C) per-plugin verify via the reusable `plugin-ci.yml` (two-leg matrix, real service containers, pack+sign gate); (D) REVERSE CONSUMER-VERIFY — busbar's DEFAULT distribution build git-deps each `compiled_in_default` plugin at its bumped SHA and runs the oracle byte-identical (a BUILD-only concern — plugin SOURCE never re-enters busbar); (E) all green → turnstile promotes each repo dev→qa→main, tags, publishes signed cdylibs + busbar binary, fires downstream bumps (homebrew/helm/tf-provider). ROSTER = a single manifest `busbar/.github/plugin-repos.json` (`{repo,crate,kind,alias,service,compiled_in_default}`); adding a plugin = one line, and the train + a scheduled `drift-check` guard auto-cover it. | branch protection: no direct main push in any repo; turnstile conducts dev→qa→main; manifest-driven pin-lockstep + consumer-verify + drift-check green before any promotion |
| 33 | **Plugin infrastructure = exactly TWO crates atop the ONE contract crate (#38). OWNER-LOCKED 2026-09-18.** (1) `busbar-plugin-sdk` = **what plugins use** (author side): the shared FFI machinery + the 7 `export_<kind>_plugin!` macros + per-kind dispatch. The ABI SPEC ITSELF does NOT live here — it STAYS in `busbar-contract` (#38); the sdk depends on contract for it. There is **NO `testkit`** (dead — not a crate and not a feature): each plugin **self-tests** (#2); the kernel tests no plugin. (2) `busbar-plugin-loader` = **how core loads plugins** (host side): open/verify/identify/call + signature verify (former `busbar-plugin-sign`) + tarball pack (former `busbar-plugin-pack`). `loader` depends on `sdk` (`default-features=false`). **A KIND is a match-arm, not a crate; an INSTANCE is a repo** (#31). Plugin infra = `busbar-plugin-sdk` + `busbar-plugin-loader`, both over `busbar-contract`. | plugin-infra crate count = 2 (sdk + loader); no busbar-plugin / -sign / -pack / -testkit crate; no `testkit` feature anywhere; ABI spec lives in busbar-contract (#38); sign+pack in loader; kinds are match-arms; instances are repos |
| 34 | **Universal crate naming = `busbar-<major>-<…>`, where a KIND is its own major. OWNER-RATIFIED 2026-09-18 (scheme A).** `major` ∈ { `plugin` (the plugin ABI MACHINERY only — now just `busbar-plugin-sdk` + `busbar-plugin-loader`, #33), `core` (the engine), OR a plugin KIND: `store`/`secret`/`auth`/`hook`/`export`/`plane`/`transport` }. A store plugin is `busbar-store-postgres` (store stuff — the word `plugin` is RESERVED for the contract machinery, never prefixed onto instances). `plane`/`transport` already follow this (`busbar-plane-mcp`, `busbar-transport-http`); the outliers to align are the external store/secret/auth/hook repos (`store-postgres`→`busbar-store-postgres`, `hashicorp-vault`→`busbar-secret-vault`, `auth-oidc`→`busbar-auth-oidc`, `{headroom,webrequest}-hook`→`busbar-hook-{…}`) plus in-tree `busbar-hooks-ranking`→`busbar-hook-ranking`, `busbar-auth-static-plugin`→`busbar-auth-static`. Kernel/core tier per #36/#37: the 14 `busbar-unit-*` retire into the 8 `busbar-kernel-<name>` (#36); `busbar-{admin,oauth2}`→`busbar-core-{admin,oauth2}` and old substrate→`busbar-core-substrate` (#37); `busbar-kernel` KEEPS its name (its own tier, #37); `caps`/`grammar`/`timing` are KILLED/folded (#37), not renamed; `busbar-contract-transport` FOLDS INTO `busbar-contract` (#38, no rename). `busbar` (the binary) stays. Codecs fold into the plane crate — NO `busbar-*-codec` crate (#39). **TIMING:** scheme locked now; in-tree `git mv`+Cargo-repoint runs as ONE atomic wave once the open codeaudit-fix branches fold (renaming 60 crates against live branches = conflict hell); the external GitHub repo renames (+redirects, homebrew/helm/tf) ride the release-train wave, not mid-1.6.0. **ALL plugin instances = `busbar-<kind>-<name>`** (owner-confirmed 2026-09-18): `busbar-store-postgres`, `busbar-transport-http`, `busbar-secret-vault`, `busbar-auth-oidc`, `busbar-hook-headroom`, `busbar-export-prometheus`, `busbar-plane-mcp`. **RESOLVED (was OPEN):** the `busbar-api`/`busbar-contract` smell is settled by #35 — not a rename but a fold (sealed ABI→`busbar-contract` #38, kernel+money records→core); `busbar-api` retires. | crate names conform to busbar-<major>-<…>; all plugin instances are busbar-<kind>-<name>; `plugin` only on ABI machinery; kinds are majors; a naming gate greps for non-conforming crate names |
| 35 | **`busbar-api` + `busbar-contract` are NOT a layered pair — they fold into the 2 infra crates + core. OWNER-LOCKED 2026-09-18; analysis a6a9bda.** The two crates are independent siblings (neither deps the other) that COLLIDE on five false-friend names — `Store`, `StoreError`, `SecretError`, `SecretRef`, `AuthOutcome` — each a *different* type sharing an identifier (e.g. contract::Store = 22-method `Plugin`-bound journal ABI; api::Store = 31-method domain-record CRUD bound to nothing). Not duplication, not layering: two generations of "the plugin contract crate." DISPOSITION: (a) the **sealed plugin-visible ABI** — the closed `Kind` taxonomy + `KindMarker`/`Plugin` base + one capability trait per kind + bounded/grammar vocab — is the neutral ABI both sides name, so it lands in **`busbar-contract`** (#38 — the ONE ABI crate, NOT the sdk); (b) the **kernel vocab + money-path durable records** — `Scratch`(the renamed arena, #41)/`Unit`/`Ctx`/`Facts`/`Ir`/`RoutePlan` and the serde wire records `VirtualKey`(HAND-written wire)/`UsageLedger`/`MeteringRow`/`AuditRecord`/`PlaneRecord`/`CredentialSecret` — are **CORE**, not plugin infra, and move under the core-naming pass (next agenda). **BYTE-IDENTITY GUARD:** the money-path records relocate module-path-ONLY — serde field names / wire bytes must not change; `VirtualKey`'s hand-written `virtual_key_wire` module travels verbatim; the oracle proves it. The five colliding api-side names de-collide on the move (`RecordStore`/`RecordStoreError`/`SecretModuleError`/`SecretConfigRef`/`AuthVerdict` or equivalents chosen at implementation). `busbar-api` as a distinct crate is RETIRED. | no busbar-api crate post-fold; sealed-ABI types in busbar-contract (#38); kernel+money records in core (byte-identical, oracle-gated); zero false-friend name collisions remain |
| 36 | **Kernel workflow = 8 crates in 4 groups; the word "unit" is retired. OWNER-LOCKED 2026-09-18.** The 14 `busbar-unit-*` crates collapse to **8 `busbar-kernel-<name>`** crates (flat names, group is conceptual only). GATES (the 3 door decisions — who → may → afford): `busbar-kernel-identity` (authN: verify/sign credentials, in or out — egress-auth folded in, no direction in the name), `busbar-kernel-scope` (authZ: declared bar, ceilings, revocation), `busbar-kernel-budget` (the afford gate: try_admit/refund, D7 check-then-charge). MONEY: `busbar-kernel-ledger` (the book — rates+usage+ledger merged, three modules; persists via wal). EGRESS: `busbar-kernel-egress` (the upstream leg — walk + swrr weighting + pre-dial guard; trust folded in), `busbar-kernel-breaker` (trip/cooldown/fast-fail per pool,dest). JOURNAL: `busbar-kernel-wal` (the write-ahead append primitive — ledger AND audit ship through it), `busbar-kernel-audit` (the one append-only chain). EXITS from the unit set: `verbs` → `busbar-core-admin` (admin owns its own execution — no codec/exec split, since admin is a cleanliness crate not a plane); the TLS secret→config provisioning (`unit-transport-key`) → **kernel-side machinery** (never a plugin; the tls plugin gets an opaque config handle over the ABI, #40). `busbar-kernel` itself = the loop/registry/teller/sessions. | no busbar-unit-* crates; 8 busbar-kernel-<name> crates; naming gate greps the set |
| 37 | **Core dissolves to 3 crates; no plugin-kind name in the core tier. OWNER-LOCKED 2026-09-18.** `busbar-core` is deleted (#19); the surviving compiled-in scaffolding = exactly **`busbar-core-admin`** (cleanliness: admin codec + verb execution), **`busbar-core-oauth2`** (cleanliness: OAuth AS), **`busbar-core-substrate`** (shared util foundation — the pure half of old substrate: json/eventstream/media/sigv4 codecs, proto registry, catalogue, diagnostics, breaker helpers; ≈13–15k LOC, ≈ today's `busbar-substrate-values`). The fat `busbar-substrate` (30k runtime shell) is DELETED — its runtime half drains to the kernel-8/units, `plane_host/` deleted, pure-value leaves (civil/duration/clock/config-enums/audit-vocab) → `busbar-contract`. RULE (a kind is a plugin, never a core crate): **no `busbar-core-<kind>` ever** — kills `busbar-core-hooks` (hook is a kind → `busbar-hook-*`). TIER meaning: `busbar-kernel*` = the engine+workflow (the loop); `busbar-core-*` = compiled-in scaffolding around it (surfaces above: admin/oauth2 dep kernel one-way; foundation below: substrate, which the kernel does NOT depend on). Killed/folded: `busbar-core-{hooks,config,caps,grammar,timing}`, `busbar-substrate-values`(name) → contract/kernel/binary. | only busbar-core-{admin,oauth2,substrate} carry busbar-core-*; no core-<kind> crate |
| 38 | **`busbar-contract` is the ONE contract/ABI crate; `contract` is a reserved major. OWNER-LOCKED 2026-09-18 (amends #33/#35).** ALL seven kinds' capability traits + Kind taxonomy + BOTH lanes' wire types (COLD/JSON and HOT/`repr(C)`, #30) + the neutral vocab (ids, grammar, caps, values, wire, civil/duration, audit vocab) live in **one crate: `busbar-contract`**. NO per-kind contract crate — `busbar-contract-transport` FOLDS IN (a KIND is a match-arm, not a crate, #33; contract already depended on it and already had a `transport.rs`). It is the neutral ABI both sides name, so it is **un-prefixed on purpose** — `contract` is its own reserved major in scheme A alongside `plugin`/`core`/`kind` (prefixing it `plugin-`/`core-` would lie about ownership). **AMENDS #33/#35:** the sealed ABI does NOT fold into `busbar-plugin-sdk`; it STAYS in `busbar-contract` (the kernel/units depend on it and must not depend on the author SDK). Plugin machinery = 2 crates atop the 1 contract: `busbar-plugin-sdk` (author-side FFI/macros/dispatch; NO testkit — dead, #33) and `busbar-plugin-loader` (host-side open/verify/call + sign + pack). `busbar-api` still retires; its money records → `busbar-kernel-ledger` (byte-identical, oracle-gated). | exactly one *-contract crate (busbar-contract); no busbar-*-contract; sdk/loader depend on contract |
| 39 | **Every plugin = 1 repo = 1 crate, all 7 kinds; the busbar repo holds NO plugin source. OWNER-LOCKED 2026-09-18 (amends #19).** Plane and transport are plugin kinds, so each instance is its own repo exactly like store/secret/auth/hook/export (#31). Codecs, dialects and modes FOLD INTO the plane crate — **planes = exactly 5 crates** `busbar-plane-{llm,mcp,a2a,streaming,decision}` (decision=jev, #48; no `busbar-*-codec`, no `busbar-plane-mcp-host`). The `busbar` repo contains ONLY: the binary, `busbar-kernel` + the 8, `busbar-core-{admin,oauth2,substrate}`, `busbar-contract`, `busbar-plugin-sdk`, `busbar-plugin-loader`. EVERY plugin instance (planes 5, transports 7, store {memory,postgres,mysql,sqlite,valkey}, secret {vault}, auth {static,github,ldap,oidc}, hook {ranking,headroom,webrequest}, export {prometheus,webhook,file,otlp}) lives in its OWN repo. The default distribution COMPILES a subset in by **git-depending on those repos** (compiled-in vs dropped-in = packaging only, #11) — plugin SOURCE never re-enters busbar. There is no in-tree plugin. | busbar repo has zero plugin crates; 1 plugin = 1 repo = 1 crate for all 7 kinds; planes = 5 crates (incl. decision) |
| 40 | **Plugin capability isolation — plugins talk to busbar ONLY over the ABI, enforced physically on the plugin→busbar channel. OWNER-LOCKED 2026-09-18.** Treat every plugin as untrusted 3rd party. THREE walls: (a) **dep-wall** — a plugin crate's entire workspace dependency closure = `busbar-contract` and nothing else; a RED-provable `kind-isolation` CI gate runs `cargo metadata` on every `busbar-<kind>-*` crate and asserts closure ∩ {kernel, core-*, any secret impl, any other plugin} = ∅ (you cannot `use` what you cannot name). (b) **capability-ABI** — secrets and every privileged resource cross ONLY as opaque `#[repr(C)]` handles with ZERO byte-accessor on the plugin surface; there is no symbol a plugin can call to obtain raw material. (c) **FFI vtable** — a dropped-in cdylib calls back into busbar ONLY through the host-callback function pointers the kernel handed it at init (= the ABI); no kernel-internal symbol is in its link table, so `kernel.somethingMalicious()` is unrepresentable. SECRETS: the SECRET kind returns material to the KERNEL; the kernel resolves+audits; NO other plugin ever receives raw secret bytes — e.g. TLS: the kernel reads the secret, audits, builds the rustls config, hands the transport plugin an OPAQUE config handle it can use but not disassemble. HONEST CEILING: (a)+(b)+(c) physically wall channel-1 (plugin→busbar) for native, plus mandatory code-signing at load (loader refuses unsigned). Channel-2 (plugin→OS: fs/net/host-RAM) is walled only by a runtime sandbox. **1.6.0 model = posture A** (native + code-signing + capability-ABI + dep-wall). **Posture B** (WASM confinement of the COLD kinds — esp. `secret` — to wall channel-2) is OWNER-TABLED, not in the 1.6.0 crate/security model. | kind-isolation dep-gate green (RED-provable); no secret-bytes type on the ABI surface; loader refuses unsigned; posture A |

| 41 | **Scratch memory GROWS on demand — never a fixed cap, never a crash. OWNER-LOCKED 2026-09-20 (kills the "arena" model + its fixed-4KiB-refuse design).** Per-request scratch: trait `Scratch` (in `busbar-contract`), impl **`ScratchPad`**, module `busbar-kernel::scratch` — the name "arena" is DEAD everywhere (`ArenaBytes`→`Scratch*`). Backed by an audited chunk-chaining bump allocator (bumpalo); `busbar-kernel` stays `forbid(unsafe)`, dep NOT added to `busbar-contract`. **It GROWS ON DEMAND by adding chunks — it never crashes and never issues a size-based refusal (`ArenaExhausted`/`ArenaBudget` for size is GONE).** The old fixed-4 KiB-cap-that-refuses (`set_allocation_limit`, per-worker fixed pool, backpressure-past-N) is KILLED. 4 KiB is only a STARTING size (a perf hint, MEASURED by the architect across planes and reported, not guessed); a big request pays one heap grow instead of crashing. **Shrinks back** to the starting size after a big request (no worker permanently hoards). **Abuse-only backstop**: a ceiling set absurdly high that only a runaway/attack could hit; on trip it cleanly refuses THAT ONE request, never panics. Kernel-owned; planes are size-blind. Proof case: jev (~5 KB responses) throws `ArenaExhausted` on the fixed 4 KiB today — the live bug this fixes. Runtime unchanged (`!Send`, thread-per-core LocalSet). | scratch grows (no set_allocation_limit ceiling); zero `ArenaExhausted`/size-refuse on the serve path; jev ~5KB serves; grow-then-shrink test; abuse-backstop test refuses-one-not-panics; grep: no "arena"/"Arena" type names |
| 42 | **THE MONEY MODEL — one model, locked across six rows; read them together: #42 (this — the billing switch), #43 (plugins pricing-blind, pricing is a read-time view), #44 (flat fee = one dimension, never rounded), #66 (unitless — no currency/symbol), #71 (ledger = raw counts, hot path carries no money math), #77 (the 10 core invariants). These are FACETS, not duplicates — each is cited by number (incl. granular #77(1)/#77.8) across the gates, CI, and kernel/ledger code, so the numbers are load-bearing anchors and stay. — Billing is OPTIONAL per plane; rate_card PRESENCE is the switch; there is NO `billing:on/off` flag. OWNER-LOCKED 2026-09-20.** rate_card PRESENT ⇒ billed: a hit class not priced ⇒ **REFUSE** (money-sacred, never a silent 0). rate_card ABSENT ⇒ NOT billed: a cost request reads **0**, serve free, no metering, no ledger charge, no afford-gate, no boot-refusal — busbar runs as a pure failover/routing proxy (the "user X wants failover on breaker-trip, doesn't care about billing" case). **A cost request returns: the price if billing-on & priced; FAILS if billing-on & unpriced; 0 if billing-off. A silent 0 is ONLY ever returned when rate_card is absent.** This EQUALS 1.5.5 (`config.yaml:394` "absent = tokens price 0; present = EVERY configured model needs an entry") — no divergence, now scoped per plane. `cheapest` with billing off: all candidates read 0 → tie → cost hook is a no-op → route by failover/health/weight. An unbilled plane STILL gets admission/concurrency + breaker enforcement (proxy, not unlimited); audit still records the request (no spend). | billing-off plane: cost=0, serves, zero meter/ledger rows, no boot-refusal, breaker+concurrency still enforced; billing-on + unpriced class ⇒ refuse; silent-0 appears only when rate_card absent |
| 43 | **rate_card + fees are CORE-owned; plugins are PRICING-BLIND; pricing is a read-time VIEW. OWNER-LOCKED 2026-09-20.** A plane plugin NEVER sees its rate card or fees. Pricing is CORE functionality, not a plane/plugin concern. A plane emits USAGE FACTS only (e.g. `output_utok: 17`); the ledger records the fact once; **pricing is a read-time VIEW** core lays over recorded facts using the rate card (read-time conversion never stored — money model). `rate_card` + `fees` are RESERVED, core-owned config sub-keys: authored in config alongside a plane's own settings for ergonomics, but core **STRIPS them from the blob before it crosses the plugin ABI** (mirrors the `pools:` reserved-section-keys pattern, `config.yaml:187`; extends #40 — as secrets never cross the ABI, money never crosses it). **ENFORCEMENT + MEASURED VIOLATION (2026-09-22, owner restated this as \"planes always ledger\" / \"it's a kernel default all planes run through\"):** a plane appends its counts UNCONDITIONALLY — no branch, no knowledge of billing state. `rate_card` is optional per plane IN CONFIG (#47); the switch is a READ-TIME property of the money VIEW, kernel-side, so \"billing off\" means the VIEW reads 0 (#42), never that the plane skipped the ledger. #42's \"optional per plane\" always described the CONFIG KEY and the VIEW, never a conditional inside plane code. **The code does not match:** plane crates carry money references where this row says they carry none — `busbar-plane-streaming` 41, `-a2a` 30, `-mcp` 29, `-llm` 16, `-decision` 9 (matching `rate_card|nanos|price|spend`) — and each `crates/busbar/src/root/units_*.rs` REIMPLEMENTS the same rulings: `units_a2a` 5 accrue/3 rate_card_version/37 nanos-hold, `units_llm` 5/1/37, `units_mcp` 2/4/26, `units_voice` 7/2/61. **The duplication is the defect generator and today proved it:** `UnitKey::new(0)` was fixed at `units_a2a.rs:1019` while the identical bug still sits at `units_mcp.rs:1481` — independently written, independently wrong. END STATE: ONE kernel-side implementation of accrual, provenance and keying; a plane emits counts per its declared class and nothing else. | RED-provable gate: zero `rate_card`/price/nanos/spend references in any `busbar-plane-*` crate; accrual+provenance+keying in exactly ONE kernel-side place; no reserved money sub-key (`rate_card`,`fees`) ever appears in the serialized blob handed to any plugin; plane plugins have no pricing type on their surface; ledger stores facts, price computed at read |
| 44 | **Money model is plane-agnostic: flat fee is one dimension, never rounded. OWNER-LOCKED 2026-09-20.** A flat/static fee is ONE plane-agnostic pricing dimension on the rate card (applied per-request or per-session), identical for every plane, and **NEVER rounded**. Per-unit rates use each plan's own declared units (tokens/seconds/frames/…); only a "per-N-units" division term uses banker's (half-to-even) rounding; card-build-time quantization stays half-away-from-zero (byte-identity). The LLM per-request fee stays a straight multiply (no division, no rounding) — it is NOT re-expressed as a per-unit term. Rate-card version is **VISIBLE** on usage/audit reports (pricing provenance), not internal-only. | flat fee never divides/rounds for any plane; only per-N-units terms round (banker's); card-build quantization unchanged (oracle byte-identity); rate_card_version surfaced on usage+audit endpoints |
| 45 | **Streaming/voice: a session holds a capacity slot for its whole life; first billable cut = OpenAI+Gemini+Twilio; media stack is adopted. OWNER-LOCKED 2026-09-20.** A live session HOLDS a capacity slot for its whole life — one admission end-to-end (one accept, one billing key, one cleanup), guaranteed capacity to continue (1.5.5 parity N/A — it had no streaming). First billable voice cut = **OpenAI Realtime + Gemini Live + Twilio telephony**; browser WebRTC (Pipecat/LiveKit class) follows in the same release. Media stack for the browser/phone audio leg = **ADOPT an existing open-source realtime-media framework**, NOT a hand-built native pump (server-to-server bridges don't need it). | session = one admission/one billing key/one cleanup, slot held for life; first-cut dialects = openai-realtime+gemini-live+twilio; media leg uses an adopted framework, not an in-house pump |
| 46 | **The `cheapest` hook is plane-agnostic; expected-units profile is plane-declared with an operator override. OWNER-LOCKED 2026-09-20.** `cheapest` ranks on estimated total cost = Σ over billing classes of `price-per-unit × expected-units`; it names ZERO plane/llm concepts (neutrality witness / protocol-noun grep-ban covers it). For quantities a request can't reveal up front (voice seconds, relay frames), the plane declares a default `expected_units` per metered class (neutral, travels with the class); an operator MAY override per-pool/per-hook in hook settings to tune ranking without a plugin rebuild. Precedence: operator override wins if present, else plane default; empty/unknown price ⇒ sorted LAST, never 0. | cheapest carries no plane/llm noun (grep); expected_units default is plane-declared; operator override honored; unknown price sorts last (never 0) |

| 47 | **1.6.0 config = one section per plane; `models` nests under `pools`; rate_card+fees are per-plane reserved keys. OWNER-LOCKED 2026-09-20.** Each plane gets its OWN top-level config section: **`pools`** (llm), **`tools`** (mcp), **`agents`** (a2a), **`decisions`** (jev, #48), **`streams`** (streaming). `models:` is NO LONGER a top-level key — it **nests under `pools`** (the llm plane section). `rate_card` + `fees` are RESERVED core-owned sub-keys inside each plane's section (#43): core strips them before the blob crosses the plugin ABI. rate_card entry shape is the existing `RateEntryCfg` (`input_utok`/`output_utok`/`cache_read_utok`/`cache_write_utok`, `busbar-substrate/src/config/sections.rs:324`); `fees` = `{ per_request | per_session }` (#44). Top-level infra keys unchanged from 1.5.5 (`listen`, `admin_listen`, `identity-providers`, `auth`, `providers`, `groups`, `store`, `export`, `plugins`, `security`, `advanced`). Back-compat: 1.5.5's flat top-level `rate_card`/`per_request_fee` load as the `pools` (llm) plane's reserved keys, byte-identical. | config has a section per plane (pools/tools/agents/decisions/streams); no top-level `models` (nests under pools); rate_card/fees per-plane and stripped at the ABI (#43 gate); 1.5.5 flat rate_card still loads as llm |
| 48 | **jev is the `decisions` plane — planes = 5, not 4. OWNER-LOCKED 2026-09-20 (amends #18/#39).** jev (typesafe.ai decision API; ~5 KB unbounded responses — the Scratch proof case, #41) is a busbar PLANE, configured under the `decisions:` section (#47). The locked plane roster becomes **5**: llm, mcp, a2a, streaming, **decisions(jev)** — amending #18/#39's count of 4. Plane rules are otherwise unchanged (1 plugin = 1 repo = 1 crate, #39; HOT/POD lane, #30). | plane roster = 5 incl. decisions(jev); `decisions:` config section exists; jev crate is its own repo like the other planes |

| 49 | **The kernel knows NO plane or transport STRINGS — everything is data from config + each plane's `CONFIG_VERB`. OWNER-LOCKED 2026-09-20.** Core/kernel contains zero plane-instance literals ("llm"/"mcp"/"a2a"/"streaming"/"decisions") and zero transport-protocol/scheme literals ("http"/"https"/"ftp"/"anthropic"/"openai"/…). The config SECTION name for a plane comes from that plane crate's `PlaneMeta::CONFIG_VERB` const (pools/tools/agents/streams/decisions, #47) — the plane owns its verb, core hardcodes none. The transport wire (`protocol`, `base_url`, `error_map`) is DATA read from the `providers.yaml` catalog (`providers_file:`, `config/mod.rs:1146`) merged with config `providers:` creds at startup (`mod.rs:2016/2077`); the kernel dials whatever resolves, inventing no scheme. `providers` = the transport-config verb (global, all planes); the per-plane target invoked over it is `models` (pools/streams/decisions) / `servers` (tools) / `agents` (agents), uniform schema `{ provider, protocol?/dialect? (override, #51), upstream_model?, error_map? (override, #51), …caps }` (no `id:` key — map key IS the id). This is the neutrality witness in force: a plane/transport is added by config + a plane crate's const, never by editing core. | grep gate: kernel/core crates contain no plane-instance or transport-scheme string literal; plane config verbs come only from PlaneMeta::CONFIG_VERB consts; transport protocol/base_url resolved from providers.yaml+config, never hardcoded |

| 50 | **Transport is selected by the provider's base_url SCHEME; each transport plugin DECLARES the scheme(s) it serves. OWNER-LOCKED 2026-09-20 (reconciles #49; resolves the "providers vs transport verb" conflict).** `providers:` remains the transport CONNECTION-config verb (#49) — base_url + credential ref per upstream. Each TRANSPORT plugin declares the URL scheme SET it handles: e.g. `busbar-transport-http` serves `http`+`https`; a websocket transport serves `ws`+`wss`; a stdio transport serves `stdio`; etc. (that declared scheme-set is what the owner calls the transport's "own config verb"). At BOOT the kernel matches every provider's base_url **scheme** against the registered transport plugins' declared scheme-sets and initializes the matching plugin; **no match ⇒ fail closed**, naming the provider + the unserved scheme. The kernel names no scheme string (#49) — the mapping is data: provider base_url (config) × plugin-declared schemes (plugin). Adding a new wire = drop in a `busbar-transport-<x>` declaring its scheme(s), reboot, zero kernel edits. So `providers` (connection) and per-transport scheme declaration are COMPLEMENTARY, not competing: there is no separate top-level config section per transport. | boot matches base_url scheme → the transport plugin declaring that scheme; unmatched scheme ⇒ fail-closed naming provider+scheme; kernel contains no scheme literal (#49 gate); transport plugin manifest declares its served scheme-set |

| 51 | **A provider is a CONNECTION with a DEFAULT wire protocol; the plane resolves and can OVERRIDE it, and the plane always interprets it fail-closed. OWNER-LOCKED 2026-09-20 (amends #49).** A `providers:` entry = connection (`base_url`, `api_key`, `path`/`path_base`) PLUS a **default `protocol`** (and default `error_map`) supplied by the shipped `providers.yaml` catalog. The default stays on the provider ON PURPOSE — with 100+ catalog entries, an operator must NOT have to know e.g. that `z.ai` speaks the openai wire protocol; the catalog knows it. **But the wire format is ultimately the PLANE's**: a plane's model entry may **OVERRIDE** the protocol/dialect (e.g. the same `anthropic` connection used on the streaming plane with a streaming protocol when Anthropic ships one). Resolution: model override if present, else the provider/catalog default. `error_map` follows the same rule (catalog default on the provider, per-model override). **The PLANE then interprets the resolved dialect against what it supports: knows it ⇒ use it; doesn't ⇒ FAIL (fail-closed)** — e.g. the decisions plane (only jev) handed `anthropic` fails. Dialect validation is the plane's job, never the kernel's; the kernel opens the transport from the base_url scheme (#50) and hands the plane the connection + resolved dialect. Model entry = `{ provider, protocol?/dialect? (override), upstream_model?, error_map? (override), …caps }`. Provider keeps `protocol`/`error_map` (byte-compatible with 1.5.5); the model-side override is NEW/additive — minimal migration. | provider = connection + default protocol/error_map (catalog-supplied); model may override protocol+error_map; resolution = model-override-else-provider-default; plane interprets resolved dialect, unknown ⇒ fail-closed; kernel validates no dialect |

| 52 | **Admin API ↔ config = full parity, enforced by a build gate. OWNER-LOCKED 2026-09-20.** Every config-file setting is ALSO settable live over the admin API; the admin API and the config file are ONE schema (two front doors: file at boot, admin at runtime). A RED-provable build gate fails if any config field lacks a matching admin route, so the two can never drift. | config↔admin parity gate: every config field has an admin route; build fails on any gap |
| 53 | **The secret-hygiene scan is a hard release blocker. OWNER-LOCKED 2026-09-20.** The scan for in-the-clear secrets (bare-`String` holds etc.) moves from report-only to BLOCKING: a bare/unwrapped secret fails the ship gate. The currently-flagged holds must be fixed (wrapped in the `Secret` type, #54) before 1.6.0 cuts. | secret-hygiene gate blocks the ship gate (RED on any bare secret); flagged holds fixed before cut |
| 54 | **Secrets use a dedicated `Secret` type, not a bare string + lint. OWNER-LOCKED 2026-09-20.** A first-class `Secret<T>` (not merely a `Redacted` wrapper + gate): the TYPE itself enforces the safety — it cannot be passed into disallowed code paths (type-level flow restriction), and its `Debug`/`Display`/`.to_string()` render `REDACTED` (never the value). Raw value access is a single explicit sealed method (KernelSeal, #40). Stronger than "String + if-checks." | secret material is `Secret<T>`; Debug/Display/to_string ⇒ REDACTED; no bare-String secret survives the #53 gate; raw access only via the sealed accessor |
| 55 | **1.6.0 ships on plugin security posture A; OS-level sandbox tabled — OWNER-CONFIRMED 2026-09-20 (affirms #40).** 1.6.0 walls plugins via code-signing (loader refuses unsigned) + the dep-wall + capability-ABI/KernelSeal (#40); confining a plugin from the OS (files/network — "channel-2", WASM posture B) is a known, accepted follow-on, NOT a cut blocker. Plugins remain signed + trusted-only. | ship 1.6.0 posture A; WASM/OS-sandbox not a cut gate; loader refuses unsigned |

| 56 | **CI runner priority = Latchkey-primary; money/oracle allowed on Latchkey; EC2 zero-idle burst-only. OWNER-LOCKED 2026-09-20 (reverses the shipped EC2-only + GH-first defaults).** Latchkey is the PRIMARY runner (LK > EC2) — its self-healing "red→green" risk is proven solved, so **money/oracle jobs MAY run on Latchkey** (`allow_money_on_latchkey` → true), reversing the earlier EC2-only default. **GitHub-hosted is used only for jobs known not to hit resource limits.** **EC2 sits at floor 0 when idle and bursts only** when LK (and safe GH) can't absorb load — no always-on on-demand floor. | autoscaler: LK primary (LK>EC2); allow_money_on_latchkey=true; GH only for resource-light jobs; EC2 ondemand_floor=0, burst-only |
| 57 | **One core `--approve` cascades to the pinned plugin bumps. OWNER-LOCKED 2026-09-20.** The owner approves a busbar-core release ONCE at qa/main; the release train pins every plugin repo's `.busbar-ref` to that core SHA and promotes them automatically (#32) — no separate per-plugin-repo human approval. One gate, not twenty. | release train: single owner --approve on core cascades dev→qa→main to all pinned plugin repos; no per-repo approve gate |
| 58 | **Doc policy: one canonical doc per topic, edited in place, delete-don't-supersede — ALL docs. OWNER-LOCKED 2026-09-20.** Exactly one canonical document per topic; edit it in place; a new doc is allowed ONLY if the old one is deleted. Never leave an outdated/superseded doc lying around (stale docs are how the ledger rotted — a-superseded-by-b-superseded-by-c). Applies to EVERY doc — design docs, READMEs, playbooks. | no superseded/duplicate docs; one canonical doc per topic; a new doc requires the old deleted in the same change |

| 59 | **The cell safety-net is locked policy; every accepted-gap needs explicit owner sign-off. OWNER-LOCKED 2026-09-20.** The oracle tracks every expected result-cell and flags any that silently vanishes (a golden SKIP is never a pass; the owed-baseline regression gate stands). Adding an entry to the accepted-gaps register ALWAYS requires explicit owner approval — an agent may NEVER self-approve a gap under the owner's name (same bar as a money-byte divergence). | owed-baseline/cell-vanish gate active; accepted-gaps entry requires owner sign-off; agent-added gap = RED |
| 60 | **"2× fresh audit" = loop the full audit to zero-found on a RE-RUN, never trust one 'done'. OWNER-LOCKED 2026-09-20.** Done means: run the full `/codeaudit` over all code → fix to 0 issues → run the full audit AGAIN → still 0. Repeat until a fresh pass finds nothing; a single pass that says "done" is not trusted (the skill already fans sonnet+opus but does not catch everything first time). Convergence = two consecutive clean full passes. | ship/done gate requires two consecutive clean full-audit passes (re-run finds zero), not a single pass |
| 61 | **Force-push rule: own working branches only, `--force-with-lease`, never a shared branch. OWNER-LOCKED 2026-09-20.** An agent may force-push ONLY its own `land-*`/`keep-*` working branches, always with `--force-with-lease`, and NEVER a shared branch (`dev`/`qa`/`main`) or a repo the owner doesn't own. | force-push limited to own land-*/keep-* branches with --force-with-lease; shared branches never force-pushed |

| 62 | **A mid-stream cut is NOT a refund — the customer pays for what actually streamed. OWNER-LOCKED 2026-09-20 ("LOCKED AGREED").** If a live/streaming request is cut off mid-answer (breaker, disconnect, auth revoked, timeout), busbar bills for what was actually delivered up to the cut — it does not refund or zero the charge. Consistent with #43/#45: the plane reports the units actually streamed; the ledger records them; the money view prices them. A cut is an interruption, not a reversal of incurred cost. | mid-stream cut bills streamed units to the cut point; no refund/zeroing on cut; plane reports actual streamed units |

| 63 | **Hook behaviour is BYTE/BEHAVIOUR-IDENTICAL to 1.5.5 — 1.6.0 changes only the crate home. OWNER-LOCKED 2026-09-20 (owner-reviewed).** No change to WHERE hooks fire (the four points: request/inbound-rewrite, candidate, routing/decide, response/read-only tap), to fire-once semantics (per request — per gate on rewrite, per hop on decide — NEVER per token), to fail-closed handling (a broken/unparseable reply REJECTS the request; strictest wins: reject > restrict > abstain > allow), or to the grant model (two dials defaulting to nothing: `argument` none/ro/rw + `identity` none/ro; never sees secrets/tokens/price tables). The ONLY 1.6.0 change is relocation to a plugin crate `busbar-hook-<name>` (`busbar-hook-ranking`, #34/#37/#39) computing no money (#43). Oracle proves hook behaviour unchanged. | hook fire-points/fire-once/fail-closed/grants identical to 1.5.5 (oracle byte-green); only the crate home moves to busbar-hook-<name> |

| 64 | **Parity packets #3 (NEUT-U-auth) and #4 (BOOT-135) = APPROVED. OWNER-LOCKED 2026-09-20.** #3: the `auth:` unknown-key error's "expected one of" list gains `operator_pub` (a real new 1.6.0 auth field, D38 operator-sealing); exit code + main error unchanged — approved, oracle re-blesses `neutrality|NEUT-U-auth|validate`. #4: a boot-time archive-read error's embedded THIRD-PARTY library text changed; busbar's own format string + exit code unchanged — approved (twin of the already-accepted BOOT-141), oracle re-blesses `boot.refusal|BOOT-135|boot`. Packets #1/#2 (PutConfigSettings restart-defer) = root-fix bugs, not sign-offs; #5 (boot-lines port) = harness flake. | oracle re-blesses exactly NEUT-U-auth + BOOT-135 cells; #1/#2 fixed at root; #5 stabilized |

| 65 | **Zero-trust plugin model: every KernelSeal must be cryptographically UNFORGEABLE before 1.6.0 ships. OWNER-LOCKED 2026-09-20 (hardens #40; a signed plugin is still not trusted to bypass a seal).** A validly-signed plugin passing the loader is NOT trusted to forge a capability seal. TODAY the picture is mixed: the SECRET-accessor seal (raw secret bytes) IS sealed/shipped (`contract-secret-seal`), but the DESTINATION/capability seal (`VerifiedDestination`/KernelSeal) is **forgeable in-process** (a doctest constructs a fake one) — undercutting #40. 1.6.0 makes ALL kernel seals unforgeable (constructible only by the kernel; no public/forgeable constructor, RED-provable) as a CUT requirement, not a follow-on. | no public/forgeable KernelSeal constructor (incl. VerifiedDestination); a gate proves no non-kernel code can mint a seal; ships blocking |

| 66 | **Money is UNITLESS abstract cost — no currency type, no symbol. OWNER-LOCKED 2026-09-20 (clarifies #44; matches 1.5.5 "abstract cost units, busbar attaches no currency").** The rate card is plain numbers (e.g. `1.87` per output token); busbar attaches NO currency and NO symbol. There is no default reporting currency and no "unpriced-currency" concept — pricing is just numbers from the rate card. (Reverses an earlier USD-default suggestion.) | no currency type/symbol anywhere in the money path; rate card + ledger + views are unitless numbers |
| 67 | **`predev` is the permanent WIP branch; `dev` is release-train-write-only. OWNER-LOCKED 2026-09-20 (amends #32).** All work-in-progress lands on `predev` in every repo; the release train is the ONLY writer of `dev` (then `dev→qa→main`, #32). Keeps `dev` always-promotable. | WIP lands on predev; dev is written only by the train; branch protection enforces no direct dev writes |
| 68 | **The conformance MUST-set is a HARD gate before dev-green. OWNER-LOCKED 2026-09-20.** No dev-green until the conformance suite (the MUST set) is landed and passing; nothing ships on stubbed MUSTs (this requires landing the `integration/conformance-b` stack). | dev-green blocked until conformance MUST-set is landed + green; no stubbed MUSTs at dev-green |
| 69 | **Cross-protocol error translation to the client's format = 1.5.5-identical. OWNER-LOCKED 2026-09-20.** When a client speaks one protocol and busbar routes to an upstream speaking another, an upstream error is remapped through busbar's neutral form back into the client's protocol format — same as 1.5.5 (oracle byte-green). The dialect's `error_map` (#51) feeds this. | cross-protocol error remap = client's format, byte-identical to 1.5.5 (oracle-gated) |
| 70 | **Plugin authenticity is unforgeable; default signed-only; admin explicit opt-in for unsigned/third-party. OWNER-LOCKED 2026-09-20 (affirms #40).** A dropped-in plugin is cryptographically signed; the loader verifies it against busbar's EMBEDDED release key (busbar-signed = zero-config verify) or an allowlisted third-party ed25519 publisher — a busbar-signed plugin cannot be forged. DEFAULT: signed-only (`plugins.trust.allow_unsigned=false`, `allow_third_party=false`, `config.yaml:428`); the loader refuses unsigned/non-allowlisted. Admin may DELIBERATELY relax via `allow_unsigned`/`allow_third_party` + publisher allowlist; `min_versions` gives anti-downgrade floors. Distinct from the in-process KernelSeal (#65). | loader refuses unsigned/non-allowlisted by default; busbar release key embedded; admin opt-in toggles honored; min_versions anti-downgrade |

| 71 | **Ledger event = the plane's raw usage COUNTS per class; pricing is read-time; seals are zero-cost — the hot path carries no money math. OWNER-LOCKED 2026-09-20 (makes #43/#66 concrete + a perf invariant).** A plane's whole money obligation is to emit ONE fact per unit: raw counts keyed by plane-declared class strings — e.g. `{output_tokens: 27, input_tokens: 42, cache_read: 3}` for llm, `{seconds: 12}` for streaming, `{frames: 400}` etc. The ledger APPENDS those counts verbatim (write-behind, per-unit — NOT per-token). The MONEY VIEW computes `Σ count × rate_card(class, card_at(ts))` only at READ time, in the kernel — never on the serving path. PERF INVARIANT: (a) capability seals/tokens are zero-sized compile-time proofs — `&KernelSeal` etc. compile to nothing, 0 ns on the hot path; (b) no rate lookup / multiply / currency math runs on the request path; the per-token inner loop (plane+transport POD lane, #30) touches no money. | plane emits counts-per-class only (no price); ledger append is write-behind per-unit; pricing computed at read; no money arithmetic or non-ZST token on the per-token/hot path (perf gate) |

| 72 | **The kernel unit is a 10-stage typestate pipeline; each stage's pass is the key the next stage requires. OWNER-LOCKED 2026-09-20 (names the ONE concept behind "seals/tokens/stamps").** The ten stages, in order (`busbar-caps/src/step.rs:42`): **Arrival → Decode → Authenticate → Verify → Approve → Admit → Route → Meter → Audit → Encode.** Each stage, on passing, produces a zero-sized typed **pass** (`UnitToken<Stage>`) that the NEXT stage takes as input — so stages cannot be skipped or reordered (compile-enforced), and a refusal produces no pass so the chain stops fail-closed (drops to Audit/refuse). There are exactly TWO flavors of the one idea: (1) **stage-pass** — one per stage; (2) **capability grant** — a few extra proofs authorizing a specific privileged action, minted at the stage that earns them: `VerifiedDestination` (dial this upstream, minted at Verify, required by Route), `EgressAuthToken` (sign outbound), `LedgerToken`/`ExitToken` (write the book, at Meter/Audit). Root: `KernelSeal` mints any of them and nothing else can (#65). All are zero-cost at runtime (#71). | pipeline order Arrival→…→Encode enforced by per-stage pass tokens (compile-time); refusal = no pass = fail-closed; capability grants ride Verify/Admit/Route/Meter; only KernelSeal (kernel-only, #65) mints |

| 73 | **Capability-proof vocabulary unifies to two words: `Pass` (per stage) + `Grant` (per privileged action). OWNER-LOCKED 2026-09-20.** The current type-name zoo (`KernelSeal`, `UnitToken<Stage>`, `AdmitToken`, `VerifiedDestination`, `EgressAuthToken`, `LedgerToken`, `ExitToken`, `HoldCell`, …) renames to ONE scheme: a per-stage **`Pass`** (the 10 stage-passes, #72) and a per-capability **`Grant`** (dial/sign/write-money/…), both minted only by the kernel root (still `KernelSeal` or renamed at implementation, kernel-only per #65). Same zero-cost mechanism, far fewer terms. Exact rename map proposed at implementation for owner ok; the Pass/Grant proof types land in `busbar-contract`/`busbar-kernel` (`busbar-caps` is killed/folded, #37). | capability-proof types are exactly `Pass<stage>` + `Grant<capability>` + one kernel root minter; no other proof-type names survive; rename map owner-approved |

| 74 | **Per-call binding of capability proofs: cheap generation-id in-process, kernel-MAC'd handle at the untrusted ABI. OWNER-LOCKED 2026-09-20 (closes the runtime-binding gaps under #72/#65).** IN-PROCESS (trusted kernel stages): keep compile-time typestate + stack-scoping as the order proof (#72), PLUS a per-request **generation id (`u64`)** carried in the unit context that stages compare (~1 ns, NO crypto) — makes cross-flow binding explicit and catches a stray/stored pass without any hot-path crypto cost (#71 holds). A full keyed-hash chain across all 10 stages was REJECTED (10× HMAC/request = hot-path tax on trusted-vs-trusted code). AT THE UNTRUSTED PLUGIN ABI (where a plugin can store/replay a handle): the handle a plugin holds is **kernel-MAC'd, bound to a per-request kernel secret + generation** (AACS-like keyed derivation, NOT a plain hash — plain hashes are forgeable); the kernel verifies it on every ABI call, so a plugin cannot forge, reuse across flows, or replay a stale handle. ONE check per ABI crossing (per-request, NOT per-token) — off the hot loop. Realizes the #65 zero-trust posture at runtime. | in-process: per-request u64 generation compared by stages, no crypto; ABI handle = kernel-MAC(per-request secret+generation), verified each crossing; forged/replayed/cross-flow handle ⇒ reject; no per-token crypto |

| 75 | **Channel-2 (plugin→OS/RAM) residual is ACCEPTED because trust is first-party-only by default; drop-in hijack is impossible without an explicit admin opt-in. OWNER-LOCKED 2026-09-20 (risk-acceptance rationale for #55/#40/#70).** The capability model (Pass/Grant #72–#74) does NOT sandbox a plugin from the OS/process RAM — a native cdylib that ignores the ABI could read secrets/the MAC key. That hole is UNREACHABLE by an outside attacker: default trust is signed + FIRST-PARTY-ONLY (loader refuses unsigned/non-allowlisted, #70); running a 3rd-party/untrusted plugin requires a DELIBERATE admin opt-in (`allow_third_party`/`allow_unsigned` + publisher allowlist). So "drop a hostile .so in and hijack" cannot happen by default. RESIDUAL (named, accepted): supply-chain / signing-key compromise of an explicitly-trusted publisher — signing proves origin, not good behavior. This is the standard native-plugin trust model (nginx/Postgres/kernel modules); posture B (WASM/OS sandbox, #55) would further contain it and is the known tabled follow-on, NOT a 1.6.0 cut blocker. | default posture first-party-only (loader refuses untrusted); 3rd-party requires admin opt-in; channel-2 residual documented + accepted; posture B tabled |

| 76 | **Lossless carry / zero-waiver is the product's core differentiator. OWNER LAW (genesis, `4f245182`).** busbar carries EVERY field 100% losslessly across protocols — "we don't leave things on the floor" is what we sell. Implement all and translate all where possible; an un-looked-at field is a MAJOR violation, not an acceptable gap. Cross-protocol no-equivalent = drop + warn + covered by a test; wrong-typed input = a native ingress error envelope (never a silent coercion). Waivers are very minimal — each a recorded, tested exception, never a silent drop. Owner: *"We sell this product as being able to carry every field 100% losslessly … 307 fields un looked at is major violation"*; *"implement all and translate all where possible, thats literally the product"*; *"IR completion is key. we don't leave things on floor, its our differentiator."* | IR/field-coverage: every source field mapped-or-(dropped+warned+tested); waiver register minimal + tested; wrong-typed ingress → native error envelope |
| 77 | **Money-model core invariants (complements #42/#43/#44/#62/#66/#71). OWNER-LOCKED (`f9c0fb91`).** (1) **Pricing keys live on their OWN noun, never on a plugin/plane** — money/ledger keyed by `(principal, meter_class[, lane], units, timestamp)`; money types hold NO plugin/plane field, so per-plugin/per-plane pricing is UNREPRESENTABLE (not merely banned). "Different price per plane" = planes DECLARE different meter-class strings (llm `tokens`, mcp `calls`, a2a `hops`, streaming `audio-seconds`) an operator prices — same capability, zero plugin identity. (2) **ONE sealed FACTS line per unit, written ONCE at the END** — never edited; no early accrual, no refunds, no adjusting lines. (3) **Price is NEVER stored — money is a read-time conversion** (rate rows only ever ADDED; retroactive repricing is free, dated view #dated-card/S0). (4) **Classes are STRINGS declared by the plane** (data); a flat fee = the `request` class (#44). (5) **Unpriced class = BOOT REFUSAL** when billing is on; free is an EXPLICIT zero row, never silent (#42). (6) **Budgets** enforced over any operator window ($/min,$/hr,$/week) per key/group via in-memory holds released when the line is written, hydrated from store on restart; `concurrent` stays a limit, not a budget. (7) **`on_exhaustion` = finish-unit (default) | cut-stream** — a cut is NOT a refusal (#62): it settles a closed Abort arm carrying class+cap+delivered-qty, costs one row. (8) **Integer-only math, NO floating point on any money path** (the 1.6.0 model is UNITLESS — no currency/minor-units, #66); new per-N-units terms use banker's rounding (#44); the legacy 1.5.5 path reproduces its existing rounding byte-identically. (9) **8-verb admin surface** — the dispute/overdraft/adjustment verbs (`adjust, resolve_slice, resolve_dispute, set_dispute_max_age`, overdraft-ceiling) are REMOVED. (10) **"No flags"** — a single group-commit durability mode. | money types carry no plugin/plane field; one sealed facts-line per unit written at end; price never stored (read-time view); unpriced⇒boot-refusal (billing on); integer-only + banker's; 8-verb admin surface (no dispute/overdraft verbs); oracle byte-green on the money path |

| 78 | **CI cost model = job-tier-by-cadence + $100 hard cap; mutation testing is optional. OWNER-LOCKED 2026-09-20.** Runner spend is priority-1 (the whole point of the autoscaler). Latchkey bills PER JOB-MINUTE, rounded up per job; idle/warm/parked runners are FREE (LK's always-on warm-small baseline is theirs, not billed) — so "0 jobs = $0" is already true; the lever is job-minutes, not infra. **Hard cap $100/period** total infra; **$50 soft-alarm, $80 review** → on breach find the top workflow and cut its trigger/right-size. Cost driver was measured: gate-mutants = 69% of runner-minutes, 89% of minutes on `latchkey-xlarge`. **Job tiers by cadence (a job runs where it belongs, once):** (a) **push** (integration/**, dev, qa + PR) = `ci` only — fmt/clippy/build/test + the required gate battery (structure-lint, construction-gate, ship-ready, shadow-oracle) = fast dev feedback; (b) **qa gate** (push qa) = conformance (a2a/mcp/voice), codeql, security, release-stage — the exhaustive "may this ship" set, run ONCE per promotion; (c) **main** = release/verify only, NO test-gates (qa→main is same-SHA fast-forward, so qa's checks ride the commit — re-testing on main is duplicate spend); (d) **manual** = gate-mutants (workflow_dispatch only); (e) **scheduled/reusable** = monthly-refresh/oracle-store-cells/security-weekly, and workflow_call reusables. **Mutation testing (gate-mutants) is TEST-ENHANCING, not release-breaking** — it measures whether the test suite catches injected bugs; it finds no product bugs and hardens no release. So it is MANUAL-ONLY and 100% OPTIONAL: REMOVED from qa+main branch protection (`scripts/ci-branch-protection.sh`) and the `ship-ready` gate no longer owes/reads a mutation verdict (`xtask/src/gates/ship_ready.rs`). **Nothing does the same job twice** — `keep-proof` was ~75% a re-run of `ci` on the same commit, so it is DISPATCH-ONLY now (its one unique capability, the hand-back-SCOPED shadow-oracle, stays on demand). The turnstile RE-RUNS the battery itself (never reads CI statuses), so it is the promotion arbiter and CI is per-push feedback — that macro overlap is by design. Workflow-file RENAMES to a cadence prefix (`push-`/`qa-`/`manual-`/`sched-`/`reusable-`) ride the W6 atomic rename wave (#34), NOT piecemeal now (name/path renames break required-check names, `workflow_run` links, cosign identity, and cross-repo `uses:`). | LK bill ≤ $100/period (soft-alarm $50); ci=push-only, conformance/codeql/security=qa-only, no test-gate on main, gate-mutants=dispatch-only + not a required check + not owed by ship-ready; keep-proof=dispatch-only; cost-watch checks the LK Cost-Analysis each period |
| 79 | **Rate cards are a DATED HISTORY; a posting prices against the card IN FORCE when it arrived. OWNER-LOCKED 2026-09-22 (resolves the #44 "rate-card history" park; makes "latest" precise in #42/#43/#71).** "Price against the latest rate card" means the latest card whose `effective_from` had arrived at the posting's instant — NOT the latest card ever authored. Cards are APPLIED WITH AN EFFECTIVE DATE. Owner's worked example: a user signs PAYG at 10; three months later signs month-to-month and the rate becomes 5; later signs a yearly prepaid and it becomes 1. The first three months keep pricing at 10 forever. **Publishing a new card never reprices the window before its `effective_from`.** The resolution key is the posting's own arrival instant (`arrived_ms`) against the dated history — NOT a version stamped into the posting, so history is recoverable backward, not merely forward; `rate_card_version` stays pure reporting provenance (#44: VISIBLE on usage/audit), never the pricing input. A **back-dated correction** (an entry whose `effective_from` lies in the past) DOES reprice exactly the window `[effective_from, effective_until)` — that is the sanctioned repair path for "the ratecard was wrong" (Part 1: money is never wrong, the ledger or the ratecard is wrong), it is an APPEND and a signed admin act, never an edit. Engine already exists and is reachable: `crates/busbar/src/root/kernel.rs:262` (`effective_from`), `:291` (window recompute), `root/units_admin/mod.rs:679` (signed back-dated entry). The owed work is that `GET /admin/usage` does not consult it — it reprices flat off the current card. | `GET /admin/usage` resolves each posting through the dated history by `arrived_ms`, not the newest card; publishing a forward-dated card leaves every prior posting's price byte-identical; a back-dated correction reprices exactly its window and nothing outside it; no pricing path reads `PostingStamp.rate_card_version` |
| 80 | **The oracle is 100% Rust, 0% Python — INCLUDING the corpus generator. OWNER-LOCKED 2026-09-22 (closes the oracle's Divergence 1).** "0% Python" was scoped to the 12 files in `GetBusbar/busbar-oracle` (5,726 lines); it also binds a **13th, uncounted file inside busbar itself** — `testing/shadow-oracle/cells/__init__.py` (1,825 lines), the authoritative generator that WRITES the 2,318-entry `cells.json`. The Rust port today covers only the VALIDATOR half (`busbar-oracle cells --check`: duplicate-id + floor checks over the committed corpus); the GENERATOR half is unported, so corpus drift is not merely passing — **it is not being checked at all**. **MEASURED 2026-09-22 — the diagnosis held, the remedy was cheaper than scoped:** a byte-identical Rust port already existed (`busbar-release`'s `crates/busbar-release-corpus`, commit `fbdf19b`, 2026-09-18) with its own insertion-order JSON value type and CPython `json.dumps(indent=2)` writer; what was missing was the WIRING — the judge binary had no `--generate` verb and `cells --check` never called the generator, so the drift hole was open exactly as described even though the code to close it was sitting there. Closed by wiring, not by re-porting. Python DELETED; Rust, CPython and the committed corpus all agree on sha256 `0c84a376…`; the committed corpus was NOT stale. RULING: port the generator into `busbar-release-oracle` beside the validator, prove it emits a **byte-identical** `cells.json` differentially against the Python (same standard the `apply-mutation` port met over 213 real mutations), then DELETE the Python. Rejected alternatives: keeping it as a declared out-of-band data-authoring step (leaves one Python file in busbar forever and drift unverified), and promoting `cells.json` to hand-maintained source of truth (loses programmatic regeneration of 2,318 cells). The one permanent, documented python3 boundary that SURVIVES is `apply-deferred-decisions.py` (`recorder/live.rs:1856`), which is the product's own migration tool, not the judge — same class as the `jq` dependency. | `cells/__init__.py` deleted; `busbar-oracle cells --generate` emits the committed `cells.json` byte-for-byte; a differential test runs both and asserts equality; `git ls-files '*.py'` under `testing/shadow-oracle/` returns ONLY `scripts/apply-deferred-decisions.py` (the one surviving boundary named in this row's body); drift-check runs in CI |
| 81 | **UNIT COUNTS ARE EXACT FRACTIONAL QUANTITIES — never rounded, never refused, never binary floats. OWNER-LOCKED 2026-09-22. AMENDS #77(8) and #44; a KNOWING, SIGNED divergence from 1.5.5.** Owner's words: *"27.5 imo is 27.5… you spent 27.5 tokens not 27 not 28."* A usage count is a MEASUREMENT and the measurement is whatever the plane observed. `27` is 27; `27.0` is 27; **`27.5` is 27.5**; `0.001` is 0.001. No rounding up, no rounding down, no banker's rounding, no refusal on ingest. **#77(8) is amended, not reversed:** the ban on BINARY FLOATING POINT (`f32`/`f64`) on any money path STANDS and strengthens — what changes is that the exact type is now DECIMAL, not integer. Reason the ban survives the ruling: `f64` cannot represent `27.1` (it stores `27.100000000000001421…`), because binary floating point holds only fractions with power-of-two denominators — so `f64` would break this very ruling on the next value. **REPRESENTATION: exact fixed-point decimal** — an `i128` mantissa at ONE fixed scale of 6 (micro-units) across every count and every plane: `27.5` is stored `27_500_000`, read back `27.5`. **RANGE — CORRECTED 2026-09-22 by measurement:** i128 at scale 6 holds ~1.7e32 in memory, but the LEGACY STORE WIRE caps it far lower — `legacy_usage.rs`'s `TierTokensDelta` fields are `i64`, so an ABI-2 store plugin tops out near **9.2e12 whole units**. Quote that number, not the i128 one, for anything that crosses the store ABI. **PARSING IS THE LOAD-BEARING DETAIL: read the JSON number's DECIMAL TEXT, never its `f64` value** (`serde_json`'s `arbitrary_precision`, or the raw token) — a count that transits `f64` has already lost exactness before any conversion can save it. `read_count_u64` (`crates/busbar-llm-codec/src/usage_count.rs`) is superseded by the decimal reader; its float branch exists only because `.as_u64().unwrap_or(0)` silently recorded float-spelled counts as ZERO and shipped that way in v1.5.5. **A value that will not fit the declared scale EXACTLY is a REFUSAL (#42), never a rounded guess** — money-sacred: busbar never invents a digit. Pricing stays `Σ count × rate` (#71) in exact fixed-point; a per-N-units division term still uses banker's rounding (#44), because a DIVISION can genuinely be inexact where a MEASUREMENT cannot. Unitless still holds (#66): scale is precision, not currency. **1.5.5 DIVERGENCE IS EXPECTED AND SIGNED** — oracle cells that moved because 1.5.5 truncated or zeroed a fractional count cite THIS ROW as their authority; the owner ruled *"if thats a change from 1.5.5 thats fine as its necessary."* | no `f32`/`f64` on any money path (gate, RED-provable); counts parse from decimal text, never through `f64`; `27.5` round-trips as `27.5` and `27.1` as `27.1`; a count that will not fit scale-6 exactly REFUSES; Σ over a million rows is order-independent and reproducible byte-for-byte **PERSISTED FORM (measured 2026-09-22):**no quantity**. **Zero existing chains are invalidated by a count-representation change.** (b) **The persisted surface is TINY:** twelve fields across four structs (`UsageLedger`, `TierTokens`, `MeteringRow`, and the wire twins), every one an LLM token tier or a request counter, all bare JSON integers; `usage_units` is 1.6.0-new (zero hits at v1.5.5) so **no ambiguous population exists in the field**. The single conversion point is `plugin-loader/src/store_adapter.rs:461`, inside a read-only run-once first-boot path. (c) **A RESCALE IS FORBIDDEN.** `api/src/usage_migration.rs:26-33` states its crash-safety proof: a mid-scan crash re-runs the whole scan, which is safe only because re-folding an already-folded row adds zero. **`× 10^6` is not idempotent** — run twice, get `10^12`. The protocol that is safe for the existing fold is unsafe for a rescale. (d) **THE FORM IS A DISCRIMINATOR**, the pattern this tree has already shipped three times — `AuditEntry.scheme` (`legacy/entry.rs:95-120`), `TaskEventRow.digest_version` (`busbar-a2a/src/taskstore.rs:148-153`), `needs_legacy_usage_wire` (`legacy_usage.rs:34-40`). One `#[serde(default)]` field plus a branch at the read: ABSENT ⇒ whole units (the v1.5.5 shape), PRESENT ⇒ scale 6. Old rows self-identify; nothing is rewritten; out-of-tree ABI-2 binaries keep receiving exactly the four-tier whole-unit wire they receive today. (e) **COUNTS, CAPS AND RATES RESCALE IN ONE COMMIT OR NOT AT ALL.** `busbar-kernel-budget/src/decide.rs:334-349` and `kernel/src/governance/state.rs:1926-1941` compare counts against `tokens_cap`/`tokens_input_cap`, which are **unscaled operator config** — a one-sided change makes every limit wrong by 1e6. Likewise the price multiply (`kernel-ledger/src/cost/posting.rs:320-322`, `cost/rate.rs:435`, `kernel-budget/src/price.rs:113-118`) **overbills by 1e6** unless rates move with it; do NOT "fix" that by dividing — #44 permits rounding only on a per-N-units term, and a measurement is not a division. (f) **PARKED, narrow, and currently unreachable:** a genuinely fractional count destined for an ABI-2 store has nowhere to go — four `i64` columns cannot hold it, truncating violates #81, and refusing breaks a working deployment on upgrade, which `migration.rs:57-62` names as the one outcome a migration may not produce. It REFUSES (#42) pending an owner ruling. This cannot fire today: no provider has been shown to emit a fractional count on the wire (Cohere's spec renders `18.0` for the streaming `message-end` it bills from, but no capture exists). Also note `legacy_usage.rs:23-25` already silently DROPS any unit key outside the reserved four, so non-LLM plane counts never reach a published store at all — a separate, older defect. (g) **No gate protects this** — nothing inventories persisted-field representations (`field_inventory.rs` covers dialect wire only), so a scale mismatch between busbar and a published store plugin would not be caught. A gate is owed.  See the full derivation in the commit that landed this row. | a scale-discriminated row round-trips; a v1.5.5 row with no discriminator reads as whole units unchanged; the first-boot conversion runs once and is provably safe to re-run; caps/rates/counts scale in one commit (a test asserts a cap still bites at the same real quantity); an ABI-2 store receives byte-identical four-tier whole-unit wire; a fractional count bound for an ABI-2 store REFUSES rather than truncating |
| 82 | **The audit chain is SIGNED IN CORE at seal time; the admin API EXPOSES it for PULL; anchoring and publishing are CLOUD, not core. OWNER-LOCKED 2026-09-22.** Today the chain is tamper-EVIDENT but unsigned and unanchored, so it proves only the internal consistency of a file the operator fully controls. **CORE OWES (1.6.0):** (a) **sign at seal time, in the process that sealed it**, ed25519 over the digest `AuditChain::digest_of` already computes — a signature applied later by a receiver proves only that the receiver got those bytes, not that the node produced them, so this half CANNOT be added later without leaving every prior record unprovable; (b) three admin READ verbs — the **head** (seq, hash, signature, key id, wall), a **record range by seq** (fields + hash + signature, so a puller verifies the chain itself rather than trusting the answer), and the **public key set**; (c) **the digest recipe becomes published, versioned public contract** — the exact length-prefixed field order — because if only busbar can verify busbar's chain it is a claim, not evidence; (d) **head history is retained FOREVER, independently of record retention** — a head is ~100 bytes, a year of hourly heads is under a megabyte, and a puller offline while records were pruned must not lose that window's anchor. **CORE MUST NOT:** publish, push, hold a cloud credential, or open any outbound connection for this. PULL model: the node answers, it never phones home — works behind a firewall, and an airgapped operator can `curl` it. **CLOUD (a separate product, not this repo):** pulls heads, timestamps, counter-signs, publishes a third-party verification page. Anchoring is definitionally outside core — **a node cannot anchor to itself.** **CLAIM BOUNDARY, and it is load-bearing: signing ALONE does not close the gap.** An operator holding the signing key can rewrite the chain AND re-sign it; what defeats that is an externally-recorded head, which a rewrite cannot match. So self-hosted may honestly claim *signed and tamper-evident* — "prove it to yourself and your auditor" — and only an externally-anchored head earns *"prove it to a counterparty who trusts neither of us."* Do not let the marketing claim outrun which of the two is deployed. | records carry an ed25519 signature minted at seal time in-process; admin exposes head + range-by-seq + public keys, read-only; core makes no outbound connection and holds no cloud credential for audit; the digest field order is documented and a third-party verifier reproduces a known chain WITHOUT the busbar binary; head history survives a record-retention pass that prunes its records |
| 83 | **EVERY CRATE HAS A DEFINITION, AND MEMBERSHIP FOLLOWS FROM THE DEFINITION — not the other way round. CONTRACT = SHAPES, globally. OWNER-LOCKED 2026-09-22.** Owner's words: *"first define every crate, then answer these by asking what fits the definition. if nothing we discuss a new crate. if 2 crates have same or split definitions we fix by merging"* and *"contract to me is exactly that, the shapes of anything, so it's logical to live there… this is global. contracts = shapes."* **THE PROCEDURE, and it replaces argument-by-precedent:** (1) every crate carries a ONE-LINE definition of the KIND of thing that lives in it; (2) a file's home is decided by asking which definition it fits — never by where it happens to be, never by who wrote it; (3) if nothing fits, that is an OWNER conversation about a new crate, not an agent's judgement call; (4) if two crates share a definition they MERGE; (5) if one crate holds two definitions it SPLITS. **`busbar-core-substrate` is the worked example and the reason the rule exists:** it holds pure ABI-shaped value leaves AND runtime machinery (a SigV4 signer, an eventstream parser, an SSE proxy, a protocol registry) — two definitions in one crate, so it splits (see #83a). **CONTRACT = SHAPES** is the first definition fixed: `busbar-contract` holds the SHAPE of anything — the data and its wire encoding — and `busbar-kernel-ledger` holds the SEMANTICS, what the shapes MEAN and what may be done with them. That resolves #40's store-plugin problem: a plugin needs `PlaneRecord`/`UsageLedger`/`VirtualKey`'s shapes, not the ledger's rules, so the shapes move and the money one-book leaves every plugin's dependency closure. **THE DOWNSIDES, stated so nobody is surprised later:** (a) contract's surface ceiling (`contract_caps`, 7,012) becomes the most-pressured number in the tree and will need honest raises, not exemptions; (b) contract is in EVERY plugin's closure, so anything landed there is compile cost for every plugin — a shape with a heavy dependency does not belong; (c) contract becomes the single most ABI-sensitive crate, where one shape change is a breaking change everywhere at once, which is an argument for getting shapes right rather than for keeping them scattered; (d) the line "shape vs semantics" is not self-evident for a type carrying validation — the test is whether the RULE could differ between two honest implementations (semantics) or whether every implementation must agree byte-for-byte (shape). | every crate in the roster has a written one-line definition; no two definitions overlap; no crate has two; a new file's placement is justified by citing a definition; `busbar-contract` holds shapes only — a gate proves no SigV4-class runtime machinery lands there |
| 84 | **A KERNEL CHANGE MUST NEVER FORCE A THIRD-PARTY PLUGIN TO REBUILD. The SDK is the plugin surface; its closure is SHAPES ONLY; the ABI version is the sole compatibility promise. OWNER-LOCKED 2026-09-22.** Owner: *"a kernel change shouldn't mean all 3rd party plugins need updating, it would be a nightmare"* and *"plugins need to not be forced to change often."* **MEASURED, and the nightmare is LIVE:** every plugin in the tree depends on `busbar-plugin-sdk` + `busbar-api` — **not** on `busbar-contract` — and the closure is `plugin → plugin-sdk → busbar-api → busbar-kernel-ledger → busbar-contract`. **A third-party store plugin transitively links the money one-book.** Change a ledger type and every third-party plugin must rebuild, even though nothing it names moved. **THREE LAYERS INSULATE A THIRD PARTY, and only the first is absolute:** (1) **the C ABI** — a dropped-in `.so` links SYMBOLS, not Rust crates, so a kernel change that does not move the `repr(C)` layout cannot reach it; this is the strongest guarantee busbar has and #3 already provides it; (2) **the SDK's compile-time closure** — for a plugin built from source, what it LINKS is what can force a rebuild; (3) **the ABI version** — a third party pins "I implement store ABI v5" and nothing short of bumping 5 may break them. **TODAY LAYER 3 IS DISHONEST:** a plugin can compile against `STORE_ABI(5)`, touch nothing that changed, and still break, because the topology links semantics the version does not cover. The version promises a stability the crate graph does not deliver. **THE RULE:** a plugin's compile-time closure is exactly `busbar-plugin-sdk`; the SDK's own closure is exactly `busbar-contract` (shapes, #83). **Nothing on the plugin path may link a crate holding SEMANTICS** — not the kernel, not the ledger, not `busbar-api`. **`busbar-api` is the villain**: it is the single crate dragging the ledger onto the plugin path, which is the real reason #35 retires it. **THE WITNESS, and without it this row is only a wish:** a test that builds a plugin against a PINNED OLDER SDK and asserts it still loads. "We do not break third parties" must be checkable, not aspirational. **STRENGTHENED BY THE OWNER, same day, and this is the real target:** *\"the ABI was meant to isolate plugins so they never used any `busbar-*`\"* / *\"plugins can only speak json or memory\"* / *\"they shouldn't need or HAVE any imports of other crates.\"* So the rule above is not strong enough. **THE PLUGIN CONTRACT IS A SPECIFICATION, NOT A CRATE.** Two lanes, per #3: (i) **JSON lane** — a published SCHEMA; the plugin takes bytes, parses them with whatever it likes, returns bytes; zero busbar imports, genuinely; (ii) **MEMORY lane** — a published `repr(C)` LAYOUT plus an ABI version, shipped as a **generated header** (a `.h` for C/C++/Zig authors, a generated `.rs` snippet for Rust authors), **not as a linkable crate**. That is how libc and Vulkan work: you ship a header, not a library. **`busbar-plugin-sdk` therefore becomes OPTIONAL CONVENIENCE for first-party ergonomics, never a requirement** — a third party may ignore it entirely and talk the published spec. **THE FINDING THAT MAKES THIS URGENT: no plugin built this way has ever existed.** Every plugin in the tree — including all five examples (`auth-static-plugin`, `store-example-plugin`, `secret-example-plugin`, `hook-test-plugin`, `export-example-plugin`, `plane-example`) — depends on `busbar-plugin-sdk`. The zero-import path the ABI was designed for has never been demonstrated, so it is UNPROVEN, not working. Build one and it becomes the acceptance test. **FINAL FORM, owner 2026-09-22 — and it MERGES rather than splits:** *\"plugins use sdk, sdk uses nothing busbar-*\"* and *\"only when a new sdk is released should plugins update — that feels normal.\"* So the rule is two lines: **(1) a plugin's busbar closure is EXACTLY `busbar-plugin-sdk` — one crate; (2) the SDK's own busbar closure is EMPTY.** A plugin updates when, and only when, a new SDK ships. That is a normal, announced, expected event — the same relationship every good SDK has with its users. What is NOT normal, and is what busbar has today, is that one dependency transitively dragging the kernel's money ledger. **CONSEQUENCE UNDER #83: `busbar-contract` and `busbar-plugin-sdk` SHARE A DEFINITION — \"the plugin contract\" — so they MERGE (#83 step 4), they do not split.** One crate, zero busbar dependencies, holding the shapes in BOTH encodings (JSON schema + `repr(C)`) plus the author-facing ergonomics. The kernel depends on it (the kernel implements the host side of the contract, which is the right direction); plugins depend on it; nothing else is in the closure. `busbar-plugin`'s ABI declarations and the plugin-facing half of `busbar-api` fold INTO it; `busbar-api`'s ledger edge dies because ledger SEMANTICS stay in the ledger (#83). **This SUPERSEDES #84a — do not split `busbar-contract` into a family.** The earlier split reasoning (~8,700 lines no plugin references) was measuring the right problem and reaching for the wrong instrument: the fix is that the non-plugin two-thirds (caps, grammar, transport registry) were never the plugin contract and leave, not that the contract fragments. Roster shrinks, not grows. Once the SDK re-exports shapes only, whether those shapes live in one crate or four is an INTERNAL matter a third party never sees — the split becomes tidiness, not protection. | **A PLUGIN WITH ZERO `busbar-*` DEPENDENCIES loads and serves, on BOTH lanes** — that reference plugin exists in-tree and is the witness; `cargo tree` for it names no busbar crate at all; the published JSON schema and the generated `repr(C)` header are the only artifacts an author needs; a plugin built against ABI vN-1 still loads under vN (RED-provable); the ABI version is the only thing whose change may break a third party; first-party plugins MAY use the SDK but a gate proves at least one does not |
| 85 | **EVERY plugin response carries a uniform OBSERVABILITY ENVELOPE — `{ result, metrics[], diagnostics[] }`. One shape for every kind, not a per-kind bolt-on. OWNER-LOCKED 2026-09-22.** Owner: *"design the abi correctly and implement it. log changes from 1.5.5 but lets not accept a bad abi."* **THE DEFECT:** the export ABI is an effect-free one-way wire — `ExportResponse::Delivered` is a UNIT variant, and the cold tier has no host-callback vtable — so a sink cannot report the metrics it produced or the diagnostics it raised. That made the four `busbar-export-*` roster crates unbuildable: `file` increments `FILE_LOGS_ROTATED_TOTAL`/`FILE_LOGS_ROTATE_FAILED_TOTAL` and raises five registered diagnostics; `prometheus` renders a process-global recorder fed by ~57 kernel sites; `webhook`'s POST must ride the host's SSRF-guarded egress. None of it crosses the wire. **THIS IS NOT AN EXPORT PROBLEM — IT IS AN ASYMMETRY #3 FORBIDS.** The HOOK kind already has the back-channel (`busbar_api::hooks::HookStatus.metrics`, `crates/api/src/hooks.rs:326`), which the engine validates, bounds and folds into the exposition at `busbar-kernel/src/hooks/scrape.rs`. #3 says *"a plugin is a plugin — two universal rules, identical for every kind"*; one kind having a back-channel and another not is exactly the divergence that law bans. **THE RULE:** every kind's response is `{ result, metrics[], diagnostics[] }` — `result` is the kind-specific answer, the other two are universal. The plugin REPORTS; **the host VALIDATES, BOUNDS and DECIDES.** A plugin never mutates a host counter and never performs a host-owned effect (Part 4 Axis 3: the host always owns the SSRF/pin/breaker/meter chokepoint). **IT CLOSES A LIVE #11 HOLE:** today a COMPILED-IN plugin can reach the process-global `metrics` recorder while the same crate built as a dropped-in cdylib gets its own and silently loses the counters — so compiled-in ≡ dropped-in is asserted but FALSE. Under the envelope that reach is not representable, and the equivalence becomes true. **VERSIONING:** this bumps the ABI, and the bump is the honest outcome — a logged, signed 1.5.5 divergence beats a wire that cannot carry what a plugin did. Note the ABI surface is ALSO carrying eleven separate version constants (`STORE_ABI`, `TRANSPORT_ABI`, `EXPORT_ABI_VERSION`, `HOOK_ABI_VERSION`, `SECRET_ABI_VERSION`, `AUTH_ABI_VERSION`, `ABI_VERSION`, `ABI_MAJOR`, `ABI_MINOR`, `ABI_MAGIC`, `POD_VERSION`) — collapsing those to ONE number is the natural completion of #3 and of #84's *"plugins update only when a new SDK ships"* (a third party should pin one number, not eleven). **That collapse is DESIGNED, not yet ruled** — it is a wide-blast-radius change and wants its own owner word. **THE ORACLE CANNOT SEE ANY OF THIS:** the 1.5.5 golden configures no file/webhook/otlp sink, and `ops.scrape\|metrics\|key` carries 15 families, none of them `busbar_file_logs_*`. Oracle-green here is necessary and nowhere near sufficient — the corpus is OWED cells that configure a file and a webhook sink, or this whole surface ships unwitnessed. **HOOKS ARE A FUNCTIONAL FIXED POINT while this lands (owner 2026-09-22: \"hooks have not changed in 1.6.0, one of the few things... if abi changes ok but functionally they have not been touched\").** Since this envelope is MODELLED on the hook kind, reshaping it must not move hook BEHAVIOUR. 1.5.5 is authoritative and readable — 24 hook paths at `v1.5.5`, incl. `crates/api/src/hooks.rs`, `busbar/src/hooks/{mod,plugin,wire,scrape}.rs` and the tests that ARE the contract (`hooks/tests/{scrape_tests,tests}.rs`, `proxy/tests/hook_opt_in_projection_tests.rs`). So: diff 1.5.5 against trunk FIRST and report any drift already there as a defect rather than preserving it; model the envelope on 1.5.5's `HookStatus.metrics`, not trunk's copy; and treat 1.5.5's hook tests as the acceptance suite — **if a 1.5.5 hook test cannot be expressed against the new shape, the SHAPE is wrong**: stop, never weaken the test. | 1.5.5's hook tests pass verbatim against the reshaped hook path; every kind's response carries `metrics[]` + `diagnostics[]`; the host bounds and folds them (hook's `scrape.rs` path is the model); a plugin reaching a process-global recorder is unrepresentable; a compiled-in and a dropped-in build of the SAME crate produce byte-identical `/metrics` exposition (RED-provable — this is #11's real test); the four `busbar-export-*` crates exist and their JSONL + exposition byte-match the compiled-in sinks; new oracle cells configure file and webhook sinks |

<!-- PENDING (execution, not decisions — all owner rulings captured in rows above):
MONEY SIGN-OFFS (all closed): S0 dated-card (F1/F2/F3, re-bless 3 cells) APPROVED (money model / dated-card
rows); parity packets #3/#4 APPROVED (#64); P1–P6 + empty-reply + Gemini-shortfall + wrong-provider +
voice-tool-args = BUGS to fix so bytes match 1.5.5 (plane reports truth, #43/#71), NOT sign-offs; audit
redaction = leave byte-identical (owner ruled). No money sign-off remains open.
STILL TO EXECUTE (no owner decision owed): (1) BRANCH RECONCILIATION — rows #41–#77 live on
land/conformance-turnstile-wiring; the land/decisions-consolidation ledger has its own #41–#45 with different
content — merge/renumber at fold; (2) architect-owned follow-ups: Pass/Grant rename map (#73), minimal-token
audit (#72/#73), transport roster + scheme-sets (#50/#51). Then execute 1.6.0-PLAN.md waves to DEV-GREEN.
DONE 2026-09-20: deleted 1.6.0-arena-model.md; added lossless-carry (#76) + money invariants (#77);
edit-in-place stale-row fixes (codec-crate #6/#18/#19/#20/#21/#34; planes 4→5 #3/#12/#17/#18/#19/#39; testkit
#33/#38; ABI-spec-home #33/#34/#35; Arena→Scratch #35; #49 schema; #38 testkit-feature removed; #73 caps home;
#35/#34 reordered). #28/#29 verified CORRECT as-is (MCP is proof-order; #28 already states plane-agnostic
loop-unify). -->

Commit authorship comes from git config (GitHub noreply). No AI attribution, ever.

---

# PART 3 — THE PLANE-EXTRACTION SEAM (LOCKED v4)

> *Absorbed verbatim from `1.6.0-plane-extraction-LOCKED.md`, which this document replaced. Outranks Part 2 where they disagree.*


Owner ruling: **repr(C) plugin ABI NOW** (full dynamic-load parity with token-auth). Survived 3
adversarial rounds (r1: 9 spine-adjacent breaks fixed; r2: ~10 refinements, 0 spine breaks; r3: 0 spine
breaks, RR1/RR2/RR3/RR7/RR8 survived, RR3b + 2 mechanical fixes folded here). Pin: `db7fcd68`.

> **SEAM SHAPE (§2-§4) is SUPERSEDED by `DESIGN-v5-taxonomy.md`** — the neutral primitive taxonomy
> (carrier axis / scope hierarchy / 2-tier egress / WorkItem reserved-shape / re-derived capability set)
> after a 5-protocol neutrality panel + 3 re-panels. The SPINE below (§0-§1 law/forcing, repr(C)+sized/
> append-only/major-airlock versioning, HOT/COLD, §5 chain, §6 state, §7 migration, §8 gates, §11
> acceptance) STANDS. Design status: **RATIFIED** — 17 adversarial passes (r1-r3 spine: 9 breaks fixed,
> 0 spine breaks; 5-protocol neutrality panel; 3 re-panels all RATIFY after the duplex-in/CostHold-out/
> WorkItem-lock/server-rename corrections). Implementation-ready, pending owner "go" on Phase 0.

## Locked decisions (owner-ratified 2026-08-22)
1. **repr(C) plugin ABI NOW** — full dynamic-load parity with token-auth (not a deferred/in-process trait).
2. **1.6.0 is the FINAL release — there is no "after."** The extraction lands INSIDE 1.6.0 and BLOCKS the
   cut. Must be as rock-solid as the rest of the release.
3. **HOT/COLD split:** HOT plugins (mcp/a2a) use the POD-fast lane; COLD capability plugins
   (store/secret/auth/hook/export) KEEP the existing JSON lane, UNCHANGED — no rewrite of shipping code
   or the 4 external store repos. Same plug, different lane by heat. Does not violate the Law.
4. **Plane `.so` trust = identical to current plugins:** operator-configured; busbar signs its own; third
   parties may ship unsigned and the operator may allow them. Reuse `plugin-sign` + config toggle.
5. **Coding held** until explicit owner "go." Phase 0 (perf spike) is the first step when cleared.

## 0. Law
Plugin behavior ⟂ linkage. Compiled-in vs plugins-folder = packaging only. Seam ALWAYS used. ONE code
path. Every plugin (store/secret/auth/hook/export AND mcp/a2a) speaks the same protocol; token-auth is
the proof. **`core/src/mcp/` and `core/src/a2a/` cease to exist.** Core names ZERO plane types. This
OVERRIDES the shipped D8 deferral (`plane/host.rs:11-17`) per owner: "no 1.6.x, design the final."

## 1. Forcing argument
Dynamic load crosses `.so`; Rust `dyn`/`Arc`/enums can't; one code path ⇒ static uses the same repr(C)
ABI ⇒ mcp/a2a are protocol-plane plugin KINDS on `plugin-abi`, dogfooding the host-vtable statically and
dynamically identically.

## 2. ABI — two tiers on one seam (meets the <1µs budget)
- **POD-fast tier (hot, per-request):** args borrowed `(ptr,len)` or `#[repr(C)]` POD by pointer; results
  by value (`u64`/`#[repr(u8)]` enum) or into a caller `&mut MaybeUninit<Out>` the callee fully writes
  INSIDE `catch_unwind`, marking init only on Ok (precedent: `plugin-sdk/boundary.rs`). NO `Vec` return,
  NO malloc, NO serde on hot calls. (Deletes the shipped `plane/host.rs:61-119` `-> Result<Vec<u8>>`.)
- **Bytes tier (cold/variable):** owned bytes for config, tool-result bodies, chain digest-input bytes.
- **repr discipline:** every shared enum `#[repr(u8)]`.
- **Soundness:** vtable fns `extern "C-unwind"`; `free` never panics; opaque plane-state handle `Send+Sync`.
- **Budget:** ~10 POD-fast calls/req × 2-5ns (static) / +1-3ns (PLT) = tens of ns; zero alloc/serde/
  per-token crossing ⇒ ~100× under 1µs. PROVEN by a step-0 perf spike before full build (§7).

## 3. core → plane: `PlaneDecl` (full surface) + two ingress kinds
Registered built-in (composition root) or dynamic (loader reads export symbol) — SAME decl, SAME
`PlaneDispatch`. `PlaneDecl` carries (restoring the full surface, ADV-R3-2):
- vocabulary (name/section-key/scope/label), `config_validate(raw)->parsed`,
  `build(BuildCtx{secrets-already-resolved})->opaque_handle`, `hydrate/start`,
- **admin_routes() + openapi()** — the admin-verb/OpenAPI contribution with the non-vacuity invariant
  (`plane/registry.rs:264-292`); MUST NOT be dropped.
- ingress, TWO kinds: **route** (HTTP + gRPC-as-axum-POST `a2a/grpc.rs:123`) and **stream** (MCP
  `stdio_serve`: host owns the pipe, pumps frames into the same `dispatch`; plane never touches the fd).

Every `dispatch(req_bytes, sink)` runs inside a host-owned **DispatchScope** (§4).

## 4. plane → core: `PlaneHost` + DispatchScope arena
Plane holds `host` + its OWN opaque state + HANDLE-IDS to host-side objects. Never holds a live
`Transport`/`GovState`/`Admission`/`VirtualKey`/secret.

**DispatchScope (leak fix):** core owns each dispatch invocation and opens a per-invocation arena. EVERY
host handle the plane takes (AdmissionId, EgressId, PipeId, verify-leadership) is arena-registered; when
the dispatch future ENDS or is DROPPED (disconnect/cancel/panic/parked-at-await), the arena Drop reclaims
ALL — running the real `Admission::drop` (`store/planes.rs:357-360`), closing egress, killing subprocs.
RAII across FFI, scoped to what core controls. (RR8 confirmed: tokio drops the future on cancel for both
ingress kinds; hardening note: assert the arena Drop is synchronous on abort in a test.)

| Capability | Tier | Notes |
|---|---|---|
| `govern_admit(&Facts)->Decision`, `meter_charge(&Usage)` | POD | |
| `breaker_admit(&Key)->AdmissionId`, `breaker_settle(AdmissionId,&Signal)` | POD | arena reclaims on scope-drop; `failover::walk` pool-select + admit + the `pre_admitted` handoff (`relay.rs:1508-1512`) is ONE atomic cluster |
| `verify_lookup(&Key)->Hit\|Lead\|Follow`, `verify_store(&Key,verdict,ttl)` | POD | host owns cache + single-flight; PLANE fetches. No cycle (verify precedes admission `method.rs:1188`<`1551`; verify fetch takes no admission `connect.rs:273`) |
| `egress_open(&EgressDesc)->(EgressId,EgressHead)`, `egress_poll`, `egress_write`, `egress_close` | POD hdr + bytes | host owns reqwest + resolve-then-pin + SPKI + mTLS(`client_identity`). `EgressHead` (post-connect, pre-body) carries `observed_spki`. Streaming poll validated (`a2a/transport.rs:612-625` already `chunk().await`+Continue/Stop) |
| `subprocess_open(&CmdDesc)->PipeId`, `pipe_read/write`, `subprocess_close` | POD hdr + bytes | MCP stdio egress: governed `tokio::process` (host owns lifecycle + COMMAND-ALLOWLIST); server→client sampling over stdio is refused today (`peer.rs:305-330`) so no stdio reentrancy |
| `run_operation(&OpDesc)->OpResult` | POD hdr + bytes | MCP HTTP sampling re-enters busbar's LLM pipeline (`sampling.rs:281`). RR7 hardening: carry a depth-bound + reuse the originating request's budget/audit correlation to avoid double-count |
| `journal_append(scope, content_suffix_bytes, &FramingDesc)->seq`, `journal_read(q)->rows` | bytes + POD desc | §5. `FramingDesc{ framing: Framing::{LengthPrefixed\|PipeSeparated}, digests_scope: bool }` — host frames the prelude in that stream's framing (ADV-FINAL) |
| `approvals_redeem`, `quarantine_op`, `auth_resolve`, `metrics_emit`, `clock_now` | POD | **NO `secret_resolve`** (confinement, `host.rs:67-69`). Per-request creds — A2A per-hop bearer `mint_from` (`creds.rs:411`, `receive.rs:1475`), MCP RFC 8693 token-exchange (`egress.rs:62`, `issue.rs:146`) — are NOT build-time. They resolve HOST-SIDE: `egress_open` takes a credential-REF (which pool/hop/exchange); the host mints + injects the header app-layer; the plane passes a ref and NEVER holds plaintext (ADV-FINAL — a confinement *improvement*, not just a removal) |

## 5. Chain: keep plane framing; cleave ONLY the position cache (RR3b — simpler than v3)
KEY REALIZATION (ADV-R3-1): the digest + seq authority are ALREADY host-side in `audit::digest`/`seal`/
`Chain::append`. v3's re-framing was an unnecessary regression that broke byte-exactness (two shipped
framings: calllog `LengthPrefixed` `calllog.rs:177`, provenance/admin `PipeSeparated`
`provenance.rs:125`/`admin/audit.rs:108`; admin carries NO scope field `admin/audit.rs:150-158`).
LOCKED design:
- The plane KEEPS its record type + `digest_fields`, and emits ONLY the **content SUFFIX bytes** (its own
  fields, in its own framing) — NOT the prelude.
- The host owns the **prelude framing** (ADV-FINAL correction — it is NOT "Chain::append byte-identical";
  the host must re-frame `prev_hash / [scope] / seq` in EACH stream's framing and join the plane's
  suffix). The plane passes a per-stream `FramingDesc{ framing, digests_scope }` so the host reproduces
  the EXACT legacy bytes: `LengthPrefixed` for calllog, `PipeSeparated` for provenance/admin, and
  `digests_scope=false` for admin (which never digested scope, `admin/audit.rs:150-158`).
- What moves HOST-SIDE is more than the position cache (ADV-FINAL): the per-scope last-seq/hash POSITION
  CACHE + LRU, the **write-ordering invariant**, the **durable sink**, and the **stored body** — all into
  a generic scope-keyed `audit::Journal` that names no plane type. `verify_chain` re-digests stored bytes.
- GATE: a boot-verify golden that replays GENUINE **pre-change captured fixtures** (NOT regenerated by the
  new code — non-circular) across all THREE framings PLUS genesis (empty prev_hash) and admin-no-scope,
  proving an old store verifies byte-identically after the change.

## 6. State: opaque handle owned plane-side
Plane allocates state, hands core `*mut c_void` + `free`; core stores in `plane_slots`, never downcasts,
frees via ABI on config swap. Replaces `mcp_runtime: Arc<dyn Any>` and A2A's typed `App::a2a`.

## 7. Migration — green + tests-pass at EVERY commit
"Wire the seam in place, THEN relocate." No commit both moves files AND changes behavior; atomic
transaction-CLUSTERS flip in one in-place commit. RR6: no type cycle (all handle types built in step 1).
0. **PERF SPIKE:** rewrite ONE hot call to the POD-fast shape; criterion-measure plugin-vs-in-core <1µs
   empirically. Gate the whole effort on this proving out. (Also fold the §perf-forensics wins here:
   cache `pool_upstream_creds`, shrink `Candidate`, lazy `now()` — free budget headroom for the seam.)
1. Build full `PlaneHost` (POD-fast) + repr(C) ABI data + DispatchScope arena; host-side impl. Unused.
2. Dogfood IN PLACE, one edge-class OR atomic cluster per commit (green after each) — the 374-edge
   inversion. Clusters: {failover::walk pool-select + breaker admit + settle + pre_admitted handoff},
   {verify lookup+fetch+store}.
3. Chain (§5) in place: cleave the position cache host-side; convert record sites to `journal_append`;
   boot-verify golden green. Plane framing untouched.
4. State slots → opaque handle: add `crate::a2a::runtime()` accessor (MCP-parity), migrate the typed read
   at `appbuild.rs:1690-1698`, THEN erase `App::a2a`; flip both slots to §6, delete `Arc<dyn Any>`.
5. Physically relocate core/src/mcp→busbar-mcp, core/src/a2a→busbar-a2a (mechanical — code names only
   PlaneHost/PlaneDecl/ABI-data). Record-shape modules move; the position-cache + chain stay in core::audit.
6. Tests: plane UNIT tests → plane crates + `plane-testkit` mock host. Mixed chain/integration suites
   (`calllog_tests.rs` names `PlaneCallLog` + `verify_chain`) → new `busbar-plane-tests` integ crate
   depending on BOTH; genuinely-mixed bodies split at the assertion level. No mock implements the chain.
   Delete the `#[cfg(test)] #[path]` dual-compile.
7. Delete empty core/src/{mcp,a2a}. Turn on seam witnesses (§8).

## 8. Enforcement witnesses (CI-gated)
- **Seam A**: core naming any plane type / `crate::mcp::` / `crate::a2a::` = 0.
- **Seam B**: plane crates reaching core outside PlaneHost/PlaneDecl/ABI-data = 0.
- **Perf gate (<1µs)**: criterion, plugin-host-vtable vs direct-call baseline, delta<1µs p50 AND p99; a
  per-token host-call counter on the streaming path asserted == 0. Proven first by step-0 spike.
- **Alloc gate**: `#[global_allocator]` counter = 0 allocs across the ISOLATED POD host-call batch.
- **LLM-untouched**: LLM byte-identity goldens + freeze witness unchanged/0.
- **Chain-compat golden**: old-store boot-verify over all 3 streams (§5).

## 9. A2A off-seam (validated): receive.rs needs only a `{tool,arguments}` projection for the hooks gate,
no LLM IR. A2A dispatch = the same `PlaneDecl::dispatch`. No codec cell.

## 11. Acceptance: rerun the two architecture audits as CUT GATES (owner, 2026-08-22)
The audits that diagnosed the problem are the acceptance test that it's fixed. Both rerun post-extraction
(fresh opus agents, no prior context) and GATE the 1.6.0 cut:

### 11a. Plane-symmetry ("siblings") review — target ≥ 9/10 (was 4/10)
Baseline `ARCH-SYMMETRY-REVIEW.md`: 4/10 (Seam B an 8, Seam A a 2). To EARN ≥9, the rerun must find the
following resolved (the extraction resolves each by construction — this is the checklist):
- A2A is a REAL crate, not a 19-line shell; no plane body in `core/src/a2a` (seam witness A = 0).
- All planes ride ONE seam uniformly (PlaneHost/PlaneDecl) — no "LLM full / MCP thin / A2A absent" spread.
  Seam A must score like Seam B.
- `PlaneHost` (+ cost carrier) has REAL production riders (dogfooded, step 2) — no "0-caller ABI".
- The 5 mislabeled `plane/` modules moved to their plane crates (or the chain/position-cache generically
  renamed) — no single-protocol detail under a neutral name.
- A2A's 2642-line off-seam `receive.rs` rides `PlaneDecl::dispatch`; egress centralized host-side (the
  host-guard duplication gone); error taxonomy no longer a third divergent spelling.
- No-op/awkward-fit count per plane ≈ 0.

### 11b. Core-engine quality review — target ≥ 9/10 (HOLD, must not regress)
Baseline `CORE-ENGINE-QUALITY.md`: 9/10 (alloc 9, locking 9, algorithmic 9, memory 10, cleanliness 7,
tests/benches 8). The rerun must confirm:
- Hot-path alloc/lock/memory dimensions HELD (the <1µs + no-per-token-crossing gates protect them).
- The LLM money path byte-identical + freeze 0 (extraction didn't touch it).
- tests/benches SHOULD RISE 8→9: the perf gate + alloc gate add the criterion benches the audit flagged
  as missing; also fold the 1.5.1→1.5.4 perf-regression wins (pool_upstream_creds HashMap lookup,
  Candidate SignalBag widening, unconditional now()) for headroom.
- Net engine score ≥ 9 (regression below 9 fails the cut).

## 10. What this buys (the sell)
- **The claim becomes true, not aspirational**: mcp/a2a are plugins in the SAME sense as token-auth —
  drop a `.so` in the folder or compile it in, identical behavior, linkage is packaging. Seam witnesses
  prove core names zero plane types and planes touch only the ABI.
- **~84k LOC leave core**; core/src/{mcp,a2a} deleted; the neutral engine gets smaller and its blast
  radius shrinks.
- **<1µs hot-path tax, CI-proven** — repr(C) POD-by-pointer, zero per-token crossings; the LLM money path
  is untouched (delta 0).
- **The unvalidated seams get dogfooded**: PlaneHost/CostBreakdown gain a real rider (step 2), so the ABI
  is shaped by the real plane, not the imagined one.
- **The audit chain stays exactly one chain**, byte-compatible with every deployed store (golden-gated).
- **The arch-review's 4/10 becomes real siblings**: both planes ride ONE seam, error taxonomy and egress
  centralize, the plane/ mislabel resolves.

---

# PART 4 — THE PLANE ABI NEUTRAL TAXONOMY (v5)

> *Absorbed verbatim from `1.6.0-plane-abi-taxonomy.md`, which this document replaced. MACHINE-READ: `xtask/src/gates/plane_abi_neutrality.rs` parses the first `banned set` line below as its mandate. Do not reword that line.*


Merges into DESIGN-LOCKED §2-§4 (the seam SHAPE). Spine unchanged: Law §0, forcing §1, repr(C)+
versioning (sized/append-only/major-airlock), HOT/COLD tiers, opaque state §6, migration §7, gates §8,
acceptance §11 all HOLD. This doc replaces the *capability/carrier/scope/metering* shape after the
5-protocol neutrality panel proved the locked §4 was ENUMERATED from mcp/a2a/llm, not DERIVED.

Panel result: capability-shaped at the CORE (proven neutral by the tunnel foil), protocol-shaped at two
EDGES (ingress shape; four MCP-flavored capabilities). Fix = derive from a primitive taxonomy, implement
only what the 3 real planes use, everything else append-only.

## The derivation question
NOT "what do mcp/a2a/llm call in core?" (enumeration → over-fit). INSTEAD: **"what does a governed
execution-boundary proxy offer ANY carrier of work?"** Answer = 4 axes + a small primitive set.

## Axis 1 — CARRIER (ingress), an OPEN axis, not the closed {route,stream} enum
A carrier is "a source of work-items + a way to emit," decoupled from "a reply is mandatory." Points:
| Carrier | reply? | initiator | real planes | status |
|---|---|---|---|---|
| request/response | yes | remote | llm, mcp(http), a2a(http+grpc-as-POST) | IMPLEMENT |
| response-stream (req→streamed resp) | yes, streamed | remote | llm-stream, a2a relay, mcp subscribe | IMPLEMENT |
| duplex-session (independent in/out) | n/a | either | **MCP stdio-serve**, (RTP-class) | **IMPLEMENT** (MCP stdio-serve is its 1.6.0 rider — REPANEL-2 BREAK: busbar-as-MCP-server originates requests + pushes unsolicited notifications; req/resp+stream can't carry it) |
| subscription/pull (host-initiated, reply-less) | no | host | (MQ-class) | EXTENSION POINT |
| accept-loop (many concurrent stateful sockets) | protocol | remote | (DB-wire-class) | EXTENSION POINT |
`PlaneDecl` declares which carrier(s) it provides; the host drives them uniformly.

**WorkItem reserved-shape invariant (LOCKED + WITNESSED — REPANEL-1 keystone).** `dispatch` generalizes
from `(req_bytes, sink)` to a **`WorkItem`** that is a SIZED, `#[repr(C)]`, append-only-versioned struct
carrying a `kind`-tagged **inbound handle** and a `kind`-tagged **emit handle**. From DAY ONE the tags
RESERVE all representations even though only some code paths ship: inbound ∈ {finite-buffer, stream,
absent}; emit ∈ {reply, stream, unsolicited, absent}. Implementing "only the 3 planes' carriers" must
NOT collapse `WorkItem` to a bare `(ptr,len)+sink` — that would force a breaking reshape on the first
exotic carrier. A CI witness asserts `WorkItem` carries the kind tags and can represent absent/duplex
inbound+emit. This struct is THE extensibility keystone: with it, a new carrier is an append-only minor
bump (new `#[repr(u8)]` kind variant + a vtable slot at the end); without it, the append-only claim is
prose. The 3 planes ride {request/response, response-stream, duplex-session}; pull/accept-loop are
append-only additions.

## Axis 2 — SCOPE (lifetime hierarchy), not the single per-dispatch arena
Every host handle is acquired AT a scope; the host reclaims on that scope's end/drop. Three scopes:
| Scope | reclaim trigger | holds | real planes |
|---|---|---|---|
| dispatch | work-item future ends/drops (disconnect/cancel/panic) | admission, one-shot egress, verify-leadership | all |
| session/connection | connection close | per-conn state, pooled backend conn, in-flight leases | a2a session; (DB-wire) |
| durable/unit-of-work | explicit complete/expire (survives the process) | task rows, deferred-callback context | a2a tasks (accept-then-callback) |
A per-CONNECTION opaque state slot joins the per-plane one (§6). The async plane parks a durable
work-handle at 202 and resumes via nested lookup — NOT reclaimed at future-drop (the v4 arena bug).

## Axis 3 — EGRESS, two governed tiers (host ALWAYS owns the SSRF/pin/breaker/meter chokepoint)
| Tier | shape | governs | subsumes |
|---|---|---|---|
| HTTP-request | reqwest one-shot + resolve-then-pin + SPKI + mTLS + HTTP head | url/ip/spki | today's mcp/a2a http |
| governed raw-connection | host opens a pinned, SSRF-checked, metered BYTE channel; plane frames on top; duplex | address/allowlist | **subprocess (MCP stdio) AND raw sockets (DB-wire/tunnel/RTP)** — subprocess is NOT a separate capability |
Both are `egress_open(&EgressDesc{ kind: Http|RawConn|Subprocess, ... })`; kind is data, the governance
is one path. Removes the 4 subprocess capability slots as protocol-specific furniture.

## Axis 4 — METERING, money-scalar (reserve/settle is an EXTENSION POINT, not 1.6.0)
`CostBreakdown` is already a neutral money scalar (tunnel foil: byte-metering fits via `top("Bytes",…)`),
and `Usage` is opaque-component (tokens|bytes|frames|queries) — that covers all 3 shipping planes:
A2A meters once per hop (`a2a/meter.rs`), MCP charges per discrete round (`mcp/method.rs::charge_round`),
LLM per-token path is untouched. So per-request `meter_charge` is the 1.6.0 implement-set.
**reserve/settle (`CostHold`) is DEMOTED to an EXTENSION POINT** (REPANEL-2 + REPANEL-3 both: zero
production callers among the 3 planes; its only justification was the *deferred* RTP carrier, so shipping
it trips acceptance gate §11a "no 0-caller ABI" and v5's own "implement only what the 3 planes use"
rule). The `CostHold` TYPE stays in place (fully tested) for the future high-rate-carrier minor bump —
it's a reserved shape, not implemented wiring.

## The re-derived CAPABILITY set (implement only what 3 planes use; rest = extension points)
NEUTRAL CORE (tunnel-proven, all/most planes): `govern_admit`, `meter_charge` + `cost_reserve/settle`,
`egress_open`(2-tier)/`poll`/`write`/`close`, `breaker_admit->AdmissionId`/`breaker_settle`,
`journal_append(scope,content_bytes,&FramingDesc)`/`journal_read`, `metrics_emit`, `clock_now`,
`auth_resolve`. Egress carries a credential-REF (host mints per-hop bearer / RFC8693; plane never holds
plaintext). NO `secret_resolve`.

NEUTRAL, DERIVED FROM THE PANEL (add these — the reply-shape hid them):
- ingress **work-item settle** (`ack | nack | dead-letter`) — the dual of `breaker_settle`; a reply IS
  the ack for req/resp, so it was invisible until MQ. Neutral for any carrier.
- ordered-processing **lease** (a partition/ordering handle, like AdmissionId) — for ordered carriers.
- **nested-dispatch** (`route_suboperation(work_bytes)->result`) — REPLACES `run_operation`; the host
  routes an opaque sub-request through the SAME router, never knowing it's LLM. Dissolves the MCP→LLM
  coupling (worst over-fit). MCP sampling uses it; it names no protocol.
- durable **work-handle + resume-lookup** — the durable-scope primitive (was `tasks_op`); a2a async uses it.

TRUST FAMILY (neutral over a generic COUNTERPARTY, not "MCP server"): `verify_lookup`/`verify_store`
(host cache + single-flight, plane fetches), counterparty **drift-quarantine**, one-time **approval
redeem**. Used by mcp (server digest) AND a2a (card fingerprint). Phrased for "counterparty," never
"MCP." If a piece proves single-plane after wiring, it moves INTO that plugin (the owner's 1-plane rule).

## What moves OUT of the host ABI (no-op-matrix verdict)
- `subprocess_open/pipe` → an EgressDesc.kind (raw-connection tier). Not a capability.
- `run_operation` → `nested-dispatch` (neutral). Not LLM-named.
- `quarantine`/`approvals` → trust family, counterparty-phrased; relocate to plugin if single-plane.

## Neutrality witness (add to §8): no host capability name, ABI type, OR CARRIER NAME may contain a
protocol/role noun — banned set `llm|mcp|a2a|tool|agent|sampling|task|server|card|round|prompt`
(REPANEL-1: the old set omitted `server|card`, so it couldn't catch its own `server-stream` leak — now
renamed `response-stream`). The grep gate runs over the ABI crate INCLUDING the carrier-variant names and
this witness's own token list = 0. Machine check that "derived, not enumerated" STAYS true as
capabilities are added.

## Scope discipline for 1.6.0 (keep it tight — post-re-panel)
IMPLEMENT: carriers {request/response, response-stream, **duplex-session** (MCP stdio-serve rider)}; the
**WorkItem reserved-shape** (sized/versioned, kind-tagged inbound+emit, witnessed); scopes {dispatch,
session [riders: MCP stdio-serve + A2A relay], durable [rider: A2A tasks]}; egress {http, raw-connection
incl subprocess}; metering {**charge only**}; neutral core + trust-family + nested-dispatch (depth-bounded,
RR7) + work-handle.
DO NOT implement (no 1.6.0 rider — EXTENSION POINTS, each an append-only minor bump when its protocol
arrives): subscription/pull + accept-loop carriers; ingress work-item settle (ack/nack/dead-letter);
ordered-processing lease; **metering reserve/settle (`CostHold`)**. The TAXONOMY + the WorkItem reserved
shape guarantee each is a clean add, never a break. That is "fits-or-cleanly-extends for the next 5."

---

# PART 5 — THE EXECUTION PLAN: WAVES W0–W8

> *Absorbed verbatim from `1.6.0-PLAN.md`, which this document replaced. Lowest authority — where this disagrees with a Law or an owner ruling, the Law and the owner win.*


Read this + DECISIONS.md before any status/architecture claim. This is the ONE plan (#58). It is
seam-decoupled (#25/#27): waves overlap behind stable both-ends seams — the wave numbers are a
dependency order, not a stop-the-world sequence.

## Dates
- **Owner-need target:** throw everything, no quality drop, no defer.
- **Honest worst-case floor: Wed 2026-10-08 17:00 PDT** (never slips silently; moves only on a named
  MAJOR EVENT, DECISIONS #16).

## DONE = DEV-GREEN (the definition every wave drives to)
DEV-GREEN is reached when ALL of the following hold and turnstile boards ADMIT:
1. **Oracle byte-identical vs the 1.5.5 golden on every family** (money sacred, #9/#10). The ONLY
   accepted diffs are the owner-approved re-blesses: S0 dated-card (F1/F2/F3, 3 cells), NEUT-U-auth
   `operator_pub`, BOOT-135 wording (#64). Everything else byte-green.
2. **All P-item behaviours match 1.5.5** — refusal-reason collapse, unary/empty terminality,
   wrong-provider attribution, voice tool-args, Gemini usage — fixed as BUGS, not signed (#43/#71).
3. **The full xtask gate battery is GREEN** — construction, kind-isolation (7 kinds, dep-wall allowlist
   ⊆ {busbar-contract, busbar-plugin-sdk}, #40), plane-purity, kind-abi-lane (#30), naming (#34),
   no-codec-crate (#39), no-testkit (#33), kernel-string-neutrality (#49), transport-scheme fail-closed
   (#50), seal-witness (KernelSeal kernel-only/unforgeable, #65), Pass/Grant per-call binding (#74),
   admin↔config parity (#52), secret-hygiene blocking (#53), legacy-drain = 0 (#19/#37).
4. **Conformance MUST-set landed + green for all 5 planes** (llm/mcp/a2a/streaming/decisions), incl.
   landing `integration/conformance-b` (#68).
5. **Two arch audits ≥9/10 + audit-ledger clean + two consecutive clean `/codeaudit` passes** (#60).
6. **turnstile BOARD = ADMIT → train ff `predev`→`dev` = DEV-GREEN** (#32/#67).

## Real tip / branch flow
Work lands on **`predev`**; the release train is the only writer of `dev` (#67). Turnstile conducts;
the autoscaler (Latchkey-primary, EC2 floor-0 burst-only, #56) supplies the fleet.

---

## THE WAVES (max agents; disjoint per-crate ownership #27e; every agent red-before-green; every
## money-touching step shadow-oracle-gated; each wave loops `/codeaudit` to 2 clean passes #60)

### W0 — Foundations (DONE / verify)
- DECISIONS.md ledger perfect (conflict-audit to 2 clean passes).
- Oracle-rust port live in busbar-release; `busbar-oracle` deleted.
- Autoscaler live (LK-primary, #56).
- 1.5.5 GOLDEN recorded up front from the 1.5.5 binary (#27a) — the fixed diff reference.

### W1 — Seams both-ends (unblocks all parallelism; additive/dormant, byte-safe) [#25/#26/#27]
Agents (parallel): (a) money-book seam + byte-identical pass-through stub (#25); (b) capability-keyed
dispatch table + `register_units(key,impl)` (#26 S1); (c) HOST-CAPS seams — egress trust/SPKI/identity,
inbound agent-card JWS, SSE reframe (#26 S3); (d) HOT-ABI de-stub + drop-in loader `open_plane` +
manifest claim-sealing + plane cdylib SDK + bare-bones distribution (#26 S4/#11); (e) busbar-core drain
facades — per-step re-export so steps relocate in any order (#27b). Nothing swaps the shipped path yet.

### W2 — Loop-unify + kernel-8 + Scratch + Pass/Grant [#28/#36/#41/#65/#72–74]
Agents: (a) lift the dispatch scope onto the ONE kernel `teller::run_unit`; re-point every plane's
gauntlet rider (llm/a2a/mcp/streaming) at it; collapse the substrate loop's two audit doors; DELETE
`busbar-substrate/teller`. Prove MCP end-to-end byte-identical FIRST (proof case), then every plane
rides the same seam. (b) collapse 14 `busbar-unit-*` → 8 `busbar-kernel-<name>` (#36). (c) `Scratch`
trait in busbar-contract + `ScratchPad` grow-on-demand in busbar-kernel::scratch; MEASURE + report the
start size (#41). (d) unify capability proofs to Pass (per stage) + Grant (per action); make
`KernelSeal` kernel-only/unforgeable (#65); per-request u64 generation in-process + kernel-MAC'd ABI
handle (#72/#73/#74).

### W3 — Money one-book + P-item bug fixes [#25/#42/#43/#77]
Agents: (a) consolidate to `busbar-kernel-ledger` (rates+usage+ledger); plane emits raw usage COUNTS
per class; ledger appends once, sealed, at unit end; PRICE is a read-time view; pricing keyed on its own
noun (no plugin/plane field, per-plugin pricing unrepresentable); unpriced⇒boot-refusal when billing on;
integer-only, unitless (#66/#77); billing optional by rate_card presence (#42); rate_card+fees are
reserved core-owned config keys stripped before the plugin blob (#43). (b) FIX every P-item bug to match
1.5.5 (#43/#71). Oracle money-green (S0 the only accepted money diff).

### W4 — Core dissolve + legacy drain [#19/#37]
Agents: delete `busbar-core`; land `busbar-core-{admin,oauth2,substrate}`; drain fat substrate runtime
into the kernel-8; delete `busbar-voice` (voice = streaming dialect, #18). Gate: legacy-drain = 0.

### W5 — Folds: planes / contract / plugin-infra / config [#39/#38/#35/#33/#40/#47/#49/#51]
Agents (parallel, disjoint): (a) planes → 5 one-crate each, codecs/dialects fold IN; add the
`decisions` plane crate `busbar-plane-decision` (jev dialect, #48). (b) `busbar-contract` = the ONE ABI
crate (fold contract-transport); `busbar-api` retires, money records → busbar-kernel-ledger
byte-identical (#38/#35). (c) plugin infra = `busbar-plugin-sdk` + `busbar-plugin-loader`, no testkit;
dep-wall allowlist gate (#40). (d) CONFIG reshape: per-plane sections (pools/tools/agents/decisions/
streams), `models` under pools, provider = connection + default protocol/error_map overridable
per-model, plane interprets fail-closed (#47/#49/#51); rate_card+fees stripped at the ABI (#43);
`--migrate-config` for the provider reshape.

### W6 — Naming rename [#34/#78]
One agent, ONE atomic `git mv` + Cargo-repoint wave to the `busbar-<major>` scheme (busbar-hook-ranking,
busbar-<kind>-<name>, etc.) — run once the open fix-branches fold, to avoid conflict hell. External repo
renames ride the release-train wave, not mid-1.6.0.
- **CI workflow renames (cadence prefixes, #78).** The uncoupled workflow files were already renamed
  (`qa-*` / `manual-*` / `sched-*` / `fleet-*`). W6 renames the COUPLED set that a piecemeal rename would
  break — `ci`, `release`, `docker`, `verify-deploy`, `build-artifact`, `plugin-ci`, `plugin-consumer-verify`,
  `plugin-functional`, `prepare-release`, `qa-gate`, `release-stage`, `gate-mutants` — each PAIRED with its
  coupling update: branch-protection required-check contexts (the `name:`), `workflow_run: workflows:[…]`
  lists (qa-gate←"CI"; verify-deploy←"Release","Docker"), the cosign/sigstore identity pinned to
  `…/workflows/docker.yml@…`, cross-repo `uses: GetBusbar/busbar/.github/workflows/<file>@…` in every plugin
  repo, and `gh workflow run <file/name>` in RELEASE.md/playbooks.
- **Reconcile historical doc references** to the OLD workflow filenames in the same atomic pass — the
  migration/reference/playbook docs (`docs/ci/latchkey-migration.md`, `.github/required-status-checks.md`,
  `docs/ci/feature-sets.md`, `docs/design/playbook/*`, `docs/{a2a,mcp}.md`, `1.6.0-proof-dashboard.md`)
  still name `a2a-conformance.yml`, `codeql.yml`, `security.yml`, `keep-proof.yml`, `release-fleet.yml`,
  etc. Update them to the renamed files (`qa-conformance-a2a.yml`, `qa-codeql.yml`, `qa-security.yml`,
  `manual-keep-proof.yml`, `fleet-autoscaler.yml`, …) so no stale path survives the rename.

### W7 — Conformance-b + full gate battery [#68/#30/#32/#40/#49/#50/#52/#53/#65]
Agents: (a) land `integration/conformance-b`; conformance MUST-set green for all 5 planes (#68). (b)
arm + green every gate in the DONE battery above (each RED-provable, red-before-green).

### W8 — BOARD → DEV-GREEN [#32/#67]
turnstile runs gates + oracle + conformance → BOARD verdict. On ADMIT, the train fast-forwards
`predev`→`dev`. **DEV-GREEN.**

---

## Orchestration shape (per wave)
- **1 lead** (defines the wave's seams/order) + **N implementer agents** (disjoint crates) + **1
  verifier** (runs the oracle + the wave's gates) + **1 adversarial audit pair** (opus + sonnet, #60).
- Turnstile conducts; the LK-primary autoscaler provides the fleet (#56).
- A wave does not "complete" until its gates are green, its oracle is byte-identical, and `/codeaudit`
  returns two consecutive clean passes (#60).
- Seams (W1) mean W2–W5 overlap heavily; W6 (rename) and W8 (board) are the two serialization points.

## Rolling, cross-cutting (run continuously, not a wave)
- **Frozen-SHA arch audits** (two, ≥9/10) against the rolling tip (#27c) — converge as code lands.
- **Golden re-record** on fleet boxes for any unverified cells; **money moves proven per-step** on a
  spot oracle box (zero-idle, terminate on close).

## UNATTENDED SAFETY (owner away)
Blind-swarm ONLY additive/dormant/purely-local work the oracle can prove byte-identical. Any step that
SWAPS the shipped request path or touches the money book waits for a green candidate binary + serial
execution + is surfaced to the owner. Money is sacred; deny-and-fix on any user-visible byte; never
self-approve a billed-byte change. Quality + byte-identity outrank raw agent count.

## Anti-recurrence
- Every settled decision is a DECISIONS.md row with an enforcing gate; drift → RED, not re-litigation.
- VISION + 1.6.0-plane-extraction-LOCKED + DECISIONS authoritative; all other docs reconciled or
  deleted (#14/#58). One canonical doc per topic, edited in place.
- READ-FIRST hook + this file re-read every turn; cite-or-ask, never guess.

## Open execution items feeding the waves (from the ledger PENDING)
- Verify + carry the lossless-carry (#76) and money invariants (#77) into implementation gates.
- Architect follow-ups (no owner Q): Pass/Grant rename map (#73), minimal-token audit (#72/#73),
  transport roster + scheme-sets (#50/#51).
- Branch reconciliation: fold `land/conformance-turnstile-wiring` (#41–#77) with
  `land/decisions-consolidation` numbering.

## GRANULAR EXECUTION TABLE (LOCKED) — line-by-line, each step's GREEN condition
Each row is DONE only when its **GREEN when** is objectively true. A wave's GATE row must be green before
the next serialization point. Owner = lead(L)+implementers(N)+verifier(V)+adversarial pair(A).

| # | Task | GREEN when (objective) | Dep |
|---|------|------------------------|-----|
| **P0.1** | Commit CI-cost overhaul (right-size, EC2→LK, timeouts, cadence gating, gate-mutants decouple, OpenSSF) | committed on land/conformance-turnstile-wiring; all 23 workflows parse; `ci-umbrella --selftest` exit 0; 0 EC2 | — |
| **P0.2** | Clean workflow set reaches `main` (train) | `main` carries the renamed/cheap workflows | P0.1 |
| **P0.3** | Re-enable workflows + drop `gate-mutants` from qa/main protection + reassert | `gh workflow list` all active; qa/main protection has no `gate-mutants`; `ci-branch-protection.sh` runs clean | P0.2 |
| **P0.4** | Autoscaler EC2-off deployed (LK primary, spot spillover on approval) | fleet-control tick: latchkey-only, ec2 disabled, 0 on-demand; $-watch armed ($100 cap/$50 alarm #78) | P0.1 |
| **W0.1** | DECISIONS ledger clean | 2 consecutive clean conflict-audits (#60) — DONE | — |
| **W0.2** | oracle-rust live; `busbar-oracle` deleted | replay-selftest exit 0; `cells --check` OK, no data-format drift | — |
| **W0.3** | 1.5.5 GOLDEN recorded | golden artifact present, digest pinned (#27a) | — |
| **W1.a** | Money-book seam + byte-identical pass-through stub | oracle byte-identical (money path unchanged) | W0 |
| **W1.b** | Capability-keyed dispatch table + `register_units(key,impl)` | build + dispatch-table selftest green | W0 |
| **W1.c** | HOST-CAPS seams (egress trust/SPKI, inbound JWS, SSE reframe) | build + seam tests; oracle byte-identical | W0 |
| **W1.d** | HOT-ABI de-stub + drop-in `open_plane` loader + manifest claim-seal + cdylib SDK | loader loads a signed plane cdylib; token-auth proof passes; oracle byte-identical | W0 |
| **W1.e** | busbar-core drain facades (per-step re-export) | build; steps relocatable in any order; oracle byte-identical | W0 |
| **W1.GATE** | Seams both-ends complete, dormant | full oracle byte-identical; shipped path unchanged | W1.a-e |
| **W2.a** | Lift dispatch onto ONE `teller::run_unit`; MCP proof FIRST | MCP oracle byte-identical on the unified loop | W1.GATE |
| **W2.b** | Re-point every plane at run_unit; delete `busbar-substrate/teller` | each plane (llm/a2a/mcp/streaming) oracle byte-identical; teller gone; build | W2.a |
| **W2.c** | 14 `busbar-unit-*` → 8 `busbar-kernel-<name>` (#36) | kind-isolation gate green (8 crates); dep-wall allowlist ⊆ {contract,plugin-sdk} | W2.b |
| **W2.d** | Scratch trait + ScratchPad grow-on-demand (#41) | scratch tests (grow/shrink/never-crash) pass; measured start size reported | W2.b |
| **W2.e** | KernelSeal kernel-only/unforgeable + per-call Pass/Grant (#65/#72-74) | seal-witness gate green; per-call binding test; zero-hot-path-cost bench | W2.c |
| **W2.GATE** | Loop-unify + kernel-8 + Scratch + Pass/Grant | all planes byte-identical; kernel-8; W2 gates green | W2.a-e |
| **W3.a** | Consolidate `busbar-kernel-ledger` (rates+usage+ledger) | build; ledger tests green | W2.GATE |
| **W3.b** | Plane emits raw counts; sealed facts-line once at end; price=read-time view | money-invariants gate (#77) green; per-plugin pricing = compile-fail test | W3.a |
| **W3.c** | Unpriced⇒boot-refusal; billing-optional by rate_card; integer-only unitless | boot-refusal test; billing-off zero-row test; no-float gate green | W3.a |
| **W3.d** | Fix every P-item to match 1.5.5 (#43/#71) | each P-item oracle byte-identical | W3.a |
| **W3.GATE** | Money one-book + P-fixes | oracle money-green; S0 the only accepted money diff | W3.a-d |
| **W4.a** | Delete `busbar-core` → core-{admin,oauth2,substrate} | build; one-way-dep gate green | W3.GATE |
| **W4.b** | Drain fat substrate runtime into kernel-8 | legacy-drain = 0 gate green | W4.a |
| **W4.c** | Delete `busbar-voice` (voice = streaming dialect #18) | no busbar-voice; streaming plane serves voice; oracle byte-identical | W4.a |
| **W4.GATE** | Core dissolve + legacy drain | legacy-drain=0; build; oracle byte-identical | W4.a-c |
| **W5.a** | Planes → 5 one-crate each; codecs/dialects fold in; add `busbar-plane-decision` (jev #48) | no-codec-crate + plane-purity gates green; exactly 5 plane crates | W4.GATE |
| **W5.b** | `busbar-contract` = the ONE ABI crate; `busbar-api` retires; money records→ledger | kind-abi-lane gate green; build; oracle byte-identical | W4.GATE |
| **W5.c** | Plugin infra = `busbar-plugin-sdk` + `busbar-plugin-loader`, no testkit | no-testkit gate + dep-wall allowlist gate green | W4.GATE |
| **W5.d** | Config reshape (per-plane sections, models-under-pools, provider=connection+default-proto) + `--migrate-config` | admin↔config parity (#52) + kernel-string-neutrality (#49) + transport-scheme fail-closed (#50) gates green; migrate-config test | W4.GATE |
| **W5.GATE** | Folds complete | all fold gates green; oracle byte-identical | W5.a-d |
| **W6.a** | Atomic `git mv` → `busbar-<kind>-<name>` + Cargo repoint (#34) | naming gate green; build | W5.GATE |
| **W6.b** | CI workflow renames (coupled set) + historical-doc reconciliation (#78) | required-check names rewired in branch protection; all workflows parse; consistent | W5.GATE |
| **W6.GATE** | Naming rename | naming gate green; build; CI intact | W6.a-b |
| **W7.a** | Land `integration/conformance-b` (#68) | branch merged | W2.GATE |
| **W7.b** | Conformance MUST-set green all 5 planes | conformance gate green ×5 (llm/mcp/a2a/streaming/decisions) | W7.a |
| **W7.c** | Arm + green every gate in the DONE battery, each red-provable | full xtask gate battery green; every gate `--selftest` proves red-ability | W6.GATE |
| **W7.GATE** | Conformance-b + full battery | conformance ×5 green + full gate battery green | W7.a-c |
| **W8.a** | 2 arch audits ≥9/10 + 2 consecutive clean `/codeaudit` (#60) | audit-ledger clean; two clean passes | W7.GATE |
| **W8.b** | Turnstile BOARD = gates + oracle + conformance | BOARD verdict = ADMIT | W8.a, all GATEs |
| **W8.c** | Train ff `predev`→`dev` (#32/#67) | ref moves; **DEV-GREEN 100%** | W8.b |

Commit authorship comes from git config (GitHub noreply). No AI attribution, ever.

---

# PART 6 — THE RELEASE ENGINE

Everything in Parts 1–5 describes the product. This Part describes the machine that ships it. It
lives in **two repos**, and that split is the single most common source of "I can't find the
autoscaler" confusion.

## The branch roster (#67) — four branches, and no others

| Branch | Rule | CI |
|---|---|---|
| `predev` | **permanent WIP.** Every in-flight session lands here and forks from here. | **None, deliberately.** Developers commit freely; a finished session runs turnstile to reach `dev`. |
| `dev` | **release-train-write-only.** "Next version's WIP, nowhere near done." | full `ci.yml` |
| `qa` | promotion target | full CI + the real-media matrix |
| `main` | **a push here cuts a release** — tag, GitHub Release, container promotion, `latest` moved. Irreversible. | release orchestration |

**Never push `dev`, `qa` or `main` by hand.** `--force-with-lease` is permitted only on `predev`
(#61), which carries no protection rule and no ruleset.

## The two repos

**`GetBusbar/busbar`** — the product. `crates/`, `xtask/` (every gate), `scripts/` (including
`verify-1.6.0-done.sh`, the definition of done), `conformance/`, `testing/shadow-oracle/`.

**`GetBusbar/busbar-release`** — the engine, five crates:

| Crate | Job |
|---|---|
| `busbar-release-turnstile` | The gate. Runs the batteries and returns a **BOARD** verdict — `ADMIT` or deny. Nothing reaches `dev` without it. |
| `busbar-release-train` | The mover. Fast-forwards `predev` → `dev` → `qa` → `main` in lockstep, refusing unless every precondition holds. |
| `busbar-release-oracle` | The byte-identity oracle: this build vs the published 1.5.5 binary. |
| `busbar-release-autoscaler` | Runner capacity. Ships the **`busbar-fleet`** binary (`src/bin/busbar-fleet.rs`) — this is the "fleet" tool; there is no separate fleet crate. |
| `busbar-release-corpus` | The recorded request corpus the oracle replays. |

Its workflows: `turnstile.yml`, `fleet-control.yml`, `oracle-rerecord.yml`, `docker-autoscaler.yml`, `ci.yml`.

## Where CI runs, and what it costs

CI runs on **Latchkey**, not EC2. The EC2 fleet is retired: it was costing ~$2k and is confirmed
fully torn down — zero instances, zero volumes, zero NAT gateways, zero elastic IPs. Latchkey is
both cheaper and the money oracle's home (**#56 wins over #29** — the oracle rides Latchkey, it does
not need a dedicated fleet box; `CI_RUNNER_ONDEMAND_FLOOR` is 0, not 2).

**#78 sets the budget: $50 soft alarm / $80 review / $100 hard cap.** `scripts/cost-watch.py`
enforces it with a strict exit-code contract (`0` clear / `2` alarm / `3` review / `1` cap breach /
`4` tool error) plus a self-test.

Three facts about measuring that cost, each of which cost real time to learn:

1. **GitHub's job wall-clock over-counts by roughly 2.4–3×.** A job's `started_at`→`completed_at`
   span includes Latchkey's queue and provisioning wait (~65–80s even for a trivial `echo`).
   Latchkey bills `duration_ms` — execution only. Any dollar figure derived from GitHub's job spans
   is an **estimate**, and must be labelled as one.
2. **Latchkey has no usage or billing endpoint.** Verified against the public OpenAPI spec and by
   live-probing `/usage /billing /account /costs /me /whoami /quota` — all 404. `GET /jobs` returns
   `duration_ms` but caps at the **100 most-recent jobs org-wide**, with no date filter and no
   pagination, so it structurally cannot reconstruct a multi-thousand-job period total. It is a
   cross-check, not a source of truth.
3. **There is a free-tier pool** (32,000 min/period, including a 30,000 bonus that expires
   2026-09-30). Subtracting a threshold amplifies estimate error, so the free-tier-adjusted "actual"
   figure is *less* reliable than the raw would-be figure, not more.

**Measured, 7-day window (2026-09-21):** total would-be **$1,710.23**. `gate-mutants` = **$1,245.94
= 72.86%**, `CI` = 21.08%, `keep-proof` = 6.00%, everything else <0.1%. Two independent methods
agree: `cost-watch.py` says $1,245.94, direct job-minute summation says $1,239.86.

The *shape* of that 73% matters more than the number. It was not steady-state cost — it was **23
dispatches inside a 36-hour window, 22 of them failed or cancelled**, each one re-paying the full
24-shard × ~45-min fan-out at ~$56 an attempt. Someone was iterating on a fix and the gate charged
full freight for every try. The lever is therefore not "delete the gate" but **make a failing
dispatch cheap**: the default `shards` input drops 24 → 8 for routine dispatches (24 stays available
explicitly; the same mutants are tested either way, only the fixed per-shard overhead changes).

A second "waste" finding was raised and then **disproved on inspection — do not act on it.** The
claim was that `check`, `migration-corpus`, `executable-config-lint` and `no-plugins-gate` all
compile the workspace with identical inputs under four separate cache keys, so a lockfile bump costs
four full compiles instead of one plus three reuses. The inputs really are identical, but the
conclusion does not follow: **all four declare `needs: [preflight]` and nothing else, so they run
concurrently.** On a cold cache all four miss at the same instant, all four compile regardless of
key naming, and only one save wins the race. Unifying the keys cannot convert those four compiles
into one plus three reuses, because there is no earlier writer to reuse. The only real effect is
second-order — one cache entry instead of four, so less storage and less LRU eviction pressure —
which does not justify churning a 3,000-line workflow. Left alone deliberately.

The owner's "one Rust build, all downstream jobs use it" instinct was **already implemented for the
release slice** and should not be re-done: `build-release` (`ci.yml:1896`) builds the release binary
once and `plane-rigs`, `perf-build-gate` and `shadow-oracle` download that artifact. The debug slice
never got the same treatment. The other ~15 compiling jobs each prove a genuinely distinct
feature/profile closure — collapsing those would silently drop coverage, so they are **not** waste.

## Promotion — measured 2026-09-21, and mostly NOT blocked

The four defects previously listed here were audited against the live repo. **Two were real and are
now fixed, one was a misdiagnosis, and one dissolves on the first promotion.** Corrected:

1. **`gate-mutants` required on `qa` + `main` while `disabled_manually` — REAL, NOW FIXED.** It was
   still a required context on both branches, and a disabled `workflow_dispatch`-only workflow can
   never report, so both branches could never go green. Removed from `qa` and `main` via the
   surgical `required_status_checks/contexts` DELETE endpoint — **not** a wholesale protection PUT,
   which would have silently reset unrelated settings. `main` went 7 contexts → 6, `qa` 5 → 4; every
   other setting is byte-identical. Pre-change protection JSON for both branches is backed up at
   `~/Developer/tmp/protection-backup/{main,qa}.json`. Note `ci-branch-protection.sh:43-47` declared
   this intent but had never been run against the live repo.

2. **`ship-ready` / `construction gate (…)` missing on `dev`/`qa`/`main` — REAL, but SELF-HEALING,
   not a deadlock.** Measured job-name counts: `origin/qa` has 0 of each; `origin/main` has 0 of
   each **plus** 0 for `record the staged digest` (three missing, not the two previously recorded);
   the consolidated trunk has 7 and 14. This does not deadlock, because **check runs attach to a
   SHA and qa→main is a fast-forward** — a contract `release.yml` enforces by machine, resolving the
   staged record by head SHA and refusing outright if none exists (`release.yml:530`, and the
   fast-forward contract stated at `release.yml:49-51`). So the first promotion that carries the
   trunk's `ci.yml` onto `qa` produces those runs against that SHA, and `main`'s fast-forward
   inherits them. The contexts are unreportable *on today's stale tips*; they are not unreportable
   in the flow that will actually run.

3. **`turnstile admit` denies on a missing subcommand — MISDIAGNOSIS, withdrawn.**
   `cargo xtask conformance check --musts` **exists and runs**, and `--selftest` proves it can both
   admit and deny. Turnstile denies for real, honest reasons: 10 suites are STALE (verdict commit ≠
   candidate sha) and 7 have never run. That is the gate working, not a broken gate.

4. **`turnstile-dispatch.yml` was never pushed — REAL, NOW LANDED AND CORRECTED.** Recovered from
   the worktree on `land/turnstile-dispatch` (`83954bb02`). It is the cross-repo bridge: turnstile
   lives in `busbar-release` and reacts to a `repository_dispatch` of type `turnstile-admit`, which
   GitHub's native `on: push` cannot send across repos, so this side has to fire it.

   It was **not** simply repointed from `integration/**` to `predev`, because that would have been
   wrong. The file fired `on: push` to the incoming lane, and predev's defining rule is that it
   carries no automatic CI — developers commit to it freely and a *finished* session runs the
   turnstile. Admitting a candidate runs the full battery suite; firing that on every push to a
   branch built for frequent unfinished commits would burn the batteries dozens of times a day
   against trees nobody claims are ready — a false signal and a standing money leak (#78). The push
   trigger is therefore **removed entirely** and the workflow is `workflow_dispatch`-only, with an
   optional `sha` input defaulting to the dispatched ref's head. Re-adding `on: push` would
   reintroduce precisely the automatic-CI-on-predev that #67 rules out.

   Still owner-blocked: the `TURNSTILE_DISPATCH_TOKEN` secret (fine-grained PAT, Contents:read +
   Actions:write on `GetBusbar/busbar-release`) is not provisioned. `GITHUB_TOKEN` cannot substitute
   — it is scoped to the repo the workflow runs in. The workflow fails loudly and by name when the
   secret is absent, which is the correct behaviour.

## Deleting branches is free

No `on: delete` trigger, no `on: create`, no catch-all push glob — zero workflow runs and zero
job-minutes. (The comment at `ci.yml:23` claiming `branches: ['**']` is stale; the real trigger list
is narrow.) Deleting `pr/*` auto-closes those PRs, which also fires nothing, because `closed` is not
in the default `pull_request` types.


---

# PART 7 — THE MAP TO DONE

**This Part is a MAP, not a log.** It says where the tree is, what is left, and what only the owner
can decide. Everything below is state and goes stale — unlike Parts 1–6. **When an item is done,
delete the row.** Narrative belongs in commit messages; this file holds the route.

## Where the tree is — measured 2026-09-22

| | Value |
|---|---|
| Done-oracle (`scripts/verify-1.6.0-done.sh`) | **6 / 22 groups GREEN** |
| `cargo xtask gate construction` | **12 FAIL rows** (was 109) |
| `cargo check --workspace --all-targets` | builds |
| Crates | **57** → roster target **34** (#83a) |
| Plugin dependency closure (#40) | **6** busbar crates → target **1** |
| Money oracle (PARITY) | **GREEN — 0 divergences vs published 1.5.5** |
| Trunk | `consolidated/1.6.0`, 85+ commits ahead of `integration/1.6.0-dev-green`, **nothing pushed** |

## THE MAP — what stands between here and done

### 1. The crate fold: 57 → 34
Twenty-two crates still fold. Biggest single move is `busbar-llm-codec` (103k lines) into
`busbar-plane-llm`. #19 requires each fold be a **byte-identical LOC move, oracle-proven**. A fold
that loses tests lost code — check counts before and after, every time.

**Worked example — `busbar-grammar`, done.** Landed as `pub mod grammar;` in `busbar-contract` with
its three adversarial/mutation files travelling in the same commit, to
`crates/busbar-contract/tests/{adversarial,json_scanner,mutation_hardening}.rs`. Copy that shape.

### 2. #40 — the ABI seams live in the wrong crates *(largest architectural item)*
The ABI a plugin must implement is defined in the crate that **consumes** it:

| Edge | Why it exists |
|---|---|
| `busbar-api` → `busbar-kernel-ledger` | a store plugin implements `Store`; those records live in the money crate |
| `busbar-plane-decision` → `busbar-kernel` | `PlaneDecl` is defined in the kernel and types its fields against `EngineHost`, `PlaneStore`, `axum::body::Bytes` |
| `busbar-kernel` → `busbar-substrate-values` | #37 says the kernel must NOT depend on its own foundation; it does, and inherits four of its features |

**This is a redefinition, not a refactor.** Two prior attempts to move `PlaneDecl` into contract were
correctly refused — moving a type that names `EngineHost` into the neutral crate drags the internals
along and makes contract the thing it exists to prevent. The work is plugin-facing forms expressed in
contract's own vocabulary, converting at the seam.
`busbar-plane-decision`'s invariance test stays RED as the only automated witness.

### 3. The 16 red done-oracle groups
- **Honest reds I created by making the harness truthful** — `PLANE-DELETE` (the locked 5-plane
  roster has no on-disk `decisions` crate), `TELLER-STEPS` (`rigs-ledger` exists as no CLI anywhere —
  upstream work in `busbar-release`), `STORE-QA`.
- **Real gaps** — `KIND-ISOLATION` (`busbar-core-admin` is kind `core` and implements `Plane`),
  `AUDIT-LEDGER`, `EQUALITY`, `DESIGN`, `INSTANCE-NOUN` (27 rows, burns to 0).
- **Drift** — `BYTE-IDENTITY` (openapi goldens), `CHANGELOG`, `CONFIG-STABILITY`, `NO-DEFERRAL`,
  `PUBLIC-HYGIENE`, `TEST`, `KERNEL`, `BUILD`.

### 4. Zero Python in the money oracle
Engine is already Rust (`busbar-release-oracle`, Phase C). Remaining, per the engine's own
`PORT-REMAINING.md` cutover checklist:
1. **Re-record the golden with the Rust engine** so `meta.json.harness_rev` is Rust-native — until
   then cross-tool replay needs `--allow-harness-skew`.
2. **`testing/shadow-oracle/scripts/*.sh` still shell to `python3 mock-upstream.py` / `capture-exec.py`**
   via `BUSBAR_ORACLE_TOOL_DIR`. Needs a Rust mock — a busbar-side change.
3. **One stale MONEY golden cell**: `billing|key-usage|after-upstream-down` records a charge where a
   down upstream should cost 0. The re-record fixes it.
4. Only then: delete `oracle.pin` and the Python dependency.

### 5. Branch collapse to predev / dev / qa / main (#67)
817 remote branches. Git-provable deletion is exhausted (38 ancestors deleted; zero branches share
trunk's tree). The rest needs the symbol-harvest content proof — **patch-id is useless because the
rename waves moved every path; symbols survive a rename.** 78 adjudicated, 749 in flight.
Ledger: `~/Downloads/busbar-branch-harvest-ledger-2026-09-21.tsv`.

### 6. One security fix ready to port
**Every TLS private-key read in production is unaudited.** `AccessJournal` is built and tested;
`transport_key_token()` has callers in exactly two files — its definition and the test file. Trunk
admits it: *"the only thing that ever registered a listener's TLS config was the transport's own
tests."* Contradicts the owner's ruling that the kernel audits secret access. Every seam exists, so
it is a port (`origin/queue-rebased-A3plus`), not a re-implementation.

## OWNER DECISIONS — nothing moves on these without a ruling

**Money (#10/#59 — a billed-byte change is never self-approved):**

1. **Float token counts.** `serde_json`'s `as_u64()` returns `None` for `27.0`, so the house idiom
   `.as_u64().unwrap_or(0)` recorded real counts as **zero** for any provider spelling them as
   floats. **Shipped in v1.5.5** (five sites in the released Cohere reader). Fixed at one seam across
   all six dialects. **Oracle-neutral** — the corpus contains no float-encoded cell, which is
   precisely why it shipped. Question: should the corpus GAIN one? It is the only way the oracle can
   ever see this class, and it would legitimately diverge from the 1.5.5 golden.
2. ~~**Rate-card history.**~~ **RULED 2026-09-22 → #79.** Cards are a DATED HISTORY; a posting
   prices against the card in force at its own `arrived_ms`. Publishing a new card never touches the
   window before its `effective_from`; a back-dated correction reprices exactly its window and is a
   signed append. The engine exists and is reachable (`root/kernel.rs:262`/`:291`,
   `root/units_admin/mod.rs:679`). Owed: wire `GET /admin/usage` to resolve through it instead of
   flat off the newest card, and reword the CHANGELOG line (which says an edit "stops repricing
   history" — too strong; a back-dated correction is *supposed* to reprice). `rate_card_version`
   hardcoded `0` is now a reporting-provenance defect, NOT a pricing defect — resolution keys off
   the timestamp, so history stays recoverable backward.
3. **B13 double-count.** `main.rs` calls `flush_budgets`/`flush_metering` a second, ungated time on
   two shutdown paths, outside the gate `spawn_budget_flusher` holds. A narrow interleaving lets B
   snapshot against A's un-advanced baseline and double-count A's in-flight delta.

**Architecture:**
4. **`busbar-core-substrate`** — kept in the roster on the owner's word (*"keep it and figure it out
   later"*), questioned by him three times, and the measure agent he asked for was never run.
5. **`busbar-core-admin` implements `Plane`.** The gate advises "make a new plugin kind" — but #3
   excludes admin and the `control` kind was CANCELLED. A cleanliness crate should implement no
   plugin entry face at all; how admin's verbs reach the loop without one is unsettled.

### 11. THE FOUR EXPORT PLUGINS CANNOT BE EXTRACTED OVER THE ABI AS IT STANDS — measured 2026-09-22

Four roster slots (`busbar-export-{prometheus,webhook,file,otlp}`) do not exist, and an attempt to
build them returned **0 of 4, deliberately**. The blocker is structural, not effort:

**The export ABI is an effect-free one-way wire.** `ExportResponse::Delivered` is a UNIT variant —
no back-channel — and the cold tier has no host-callback vtable (that is HOT/plane only). Every
sink produces host-side effects the wire cannot carry: `file` increments
`FILE_LOGS_ROTATED_TOTAL`/`FILE_LOGS_ROTATE_FAILED_TOTAL` and raises five registered diagnostics;
`webhook`'s POST rides `busbar_kernel::egress::engine::send_bounded` behind `validate_webhook_url`
(and Part 4 Axis 3 says the host ALWAYS owns the SSRF/pin/breaker/meter chokepoint, so plugin-side
HTTP is forbidden by design); `prometheus` renders the process-global recorder written by ~57 kernel
emit sites. **And `otlp` is not a sink at all** — it is a `tracing-subscriber` layer installed once
at boot (`busbar-kernel/src/observability.rs:421`).

**Also measured: `DynExport::deliver` has ZERO production callers.** `plugin-loader/src/export.rs:10`
says so itself — the seam proves a plugin LOADS, nothing more. So the host-side delivery driver does
not exist either. This is not "finish three sinks over an existing ABI."

**The trap to name:** a COMPILED-IN plugin could reach the same process-global recorder and appear
to preserve the counters, while the same crate built as a dropped-in cdylib gets its own recorder
and silently loses them. That breaks #11's compiled-in ≡ dropped-in equivalence and is not a
legitimate path.

**The oracle cannot catch any of this** — the 1.5.5 golden configures no file/webhook/otlp sink, and
`ops.scrape|metrics|key` carries 15 families, none of them `busbar_file_logs_*`. Oracle-green here
is necessary and nowhere near sufficient.

**RECOMMENDED SHAPE (owner ruling needed):** add `ExportRequest::Status` +
`ExportResponse::Status { metrics, diagnostics }`, mirroring the hook kind's existing
`busbar_api::hooks::HookStatus.metrics` (`crates/api/src/hooks.rs:326`), which the engine already
validates, bounds and folds into the exposition at `busbar-kernel/src/hooks/scrape.rs`. **Additive,
no `EXPORT_ABI_VERSION` bump** — the `Routes` op is the precedent: a sink that cannot decode an op
answers `STATUS_UNSUPPORTED` and keeps loading. Only then is the extraction provable, by
byte-comparing JSONL output and the `/metrics` exposition before and after.

**Consequence for the roster: 34 is unreachable until this lands.** Four of its slots are these.

### SEQUENCING TRAP — `PlaneDecl` MUST dissolve BEFORE the plane folds, or #40 reopens 5× wider

Measured 2026-09-22. **This is a hard ordering constraint on W3/W4/W5, not advice.**

`crates/busbar-plane-decision` is the ONLY live #40 violation today, and its whole `busbar-kernel`
edge exists for `src/registry.rs` — **129 lines, provably dead**: `PLANE_DECL` is named only by that
crate's own tests, and `crates/busbar/src/main.rs` never names the crate (`register_planes()`
installs `busbar_llm::`/`busbar_mcp::`/`busbar_a2a::`/`busbar_voice::PLANE_DECL`). Deleting it takes
`cargo test --workspace` out of red — that is **hours**, and it is the only part of #40 on the
dev-green path.

**THE TRAP:** `PlaneDecl` is survivable today only because those four `PLANE_DECL` exporters are the
LEGACY engine crates `busbar-llm`/`-mcp`/`-a2a`/`-voice`, which are kernel-side by classification.
**When #19/#39 fold them into `busbar-plane-*`, each plane crate inherits a `PLANE_DECL` and
therefore a `busbar-kernel` edge** — recreating the violation across four more crates, in four crates
that are supposed to be the clean ones. Dissolve `PlaneDecl` FIRST.

**Why the two prior `PlaneDecl` moves were refused — the reasoning is recorded and correct.**
Commit `250cda583`: *"Moving a type that names `EngineHost` into the neutral crate does not make it
neutral — it drags the internals along and makes contract the thing it exists to prevent."* A struct
literal must name every field's type even when the value is `None`, so hosting `PlaneDecl` in
contract drags `PlaneAdmission`, `PlaneRouteSpec` (which names `axum::body::Bytes`/`http::HeaderMap`),
`AdminRouteSpec`, `PlaneBootCtx`→`PlaneStore`+`EngineHost`, `PlaneSlots`, `ContainerGateSink`,
`PlaneCfg`, `EngineTablesView`, `NamedDefView`, `ProviderDef/Deploy/Cfg`. **Measured drag: ~22,000
LOC plus `axum` into the ABI crate.** Both refusals were right.

**But a THIRD option exists and was never refused** — only dropped. Commit `ae0622694`
(`origin/delete/keep-plane-decl-contract-recut-2`) is not a naive move: it is a plain-DATA
`PlaneDeclaration` in contract with the fn-pointer table staying kernel-side, **+192 LOC, bounded**.
No recorded reason for abandoning it; it was archived in the #67 branch collapse and never merged.
That is the shape to revisit. **Note #30 disqualifies nothing here** — `PlaneDecl` is read once at
boot, and store/secret/auth/hook/export are on the COLD/JSON lane by #30 itself, so there is no
per-frame adaptation cost anywhere in the #40 work.

**TWO GATES ARE LYING, both verified:**
- `construction:manifest-allowlist` is fully GREEN and **cannot see this violation** —
  `busbar-plane-decision` is not in `qa/construction.toml`'s `[gate.plugin_kinds].plane` list at all.
  It also reads only DECLARED `[dependencies]`, not the transitive closure, despite its own `why`
  text claiming otherwise. The gate written to catch #40 is blind to the only crate that breaks it.
- `ceiling-rose`/`ceiling-slack` compare against a **stale base (`dc7bb323`)** and report ~123
  raises that are not raises. Every ceiling declaration made against them today is judged against
  nonsense. Known prior art: the base ref was renamed away and the gate *silently falls back to
  `HEAD~1`* while its own comment says an unestablishable base "is RED, never green."

**ALSO MEASURED: two generations of the plugin ABI ship side by side.** Gen-1 (1.5.5-era) is what
every in-tree plugin actually implements — `busbar-api` traits + `busbar-plugin`'s cold-JSON lane +
the SDK macros. Gen-2 (the 1.6.0 design, already built in `busbar-contract`) has real riders for
**plane and transport only** — all 5 planes `impl Plane`, all 7 transports `impl Transport` — and
**ZERO production riders for store/secret/hook** (fixtures only). They collide on five false-friend
names, which is exactly what #35 is about. Any #84 work must know which generation it is touching.

### 12. THE ORACLE IS STRUCTURALLY BLIND TO PLANE MONEY — measured 2026-09-22, and it cannot self-heal

Fixing B09 (`crates/busbar/src/root/units_a2a.rs`) produced a green oracle that means **nothing**, on
three independent grounds, each verified:

1. **The module is unreachable from the path the recorder drives.** `A2aUnits::new` has exactly ONE
   call site in the workspace — `root/tests/units_a2a.rs:1728`, under `#[cfg(test)]`. `main.rs` names
   `root::units_a2a` once (`:1062`) only to call `scope_policy`, a boot-time table builder that
   constructs no unit. A2A is served by `busbar_a2a::PLANE_DECL` (`main.rs:679`), and that crate has
   zero references to `units_a2a`. Structurally airtight: `crates/busbar/Cargo.toml` declares only
   `[[bin]]`, no `[lib]`, so nothing outside the binary can import the module at all.
2. **Of the 468 a2a cells in the corpus, ZERO mention money, billing, usage, ledger or rate_card.**
   All are protocol-level.
3. **The 1.5.5 golden contains exactly ONE a2a-named cell** — `neutrality|routes|a2a-shaped-404`, a
   404 with empty `usage`/`audit`/`metrics`, because 1.5.5 had no a2a plane. **There is no a2a money
   golden to diverge from, and there never can be** — the golden is 1.5.5 and 1.5.5 had no a2a.

**So no oracle cell anywhere would catch an a2a money regression — today, or after a2a is switched
onto the serving path.** The same hole almost certainly exists for mcp, streaming and decision: every
plane that did not exist in 1.5.5 is money-invisible to a golden recorded from 1.5.5. **This is the
structural limit of the oracle as a money witness, and no amount of re-recording fixes it.** The
corpus is OWED money cells for every post-1.5.5 plane, authored rather than recorded — and until they
exist, "oracle green" on a plane money path is an absence of evidence, not evidence of absence.

**CORRECTED 2026-09-22 — I OVERCLAIMED THIS AND THE SECOND LEG FALLS.** §12's own caveat said *"if
someone finds a positive money assertion in a rig, the second leg falls."* It fell, twice, and the
grep that missed them looked only under `testing/`:
- **`scripts/a2a-subject/h2-meter-row.sh` and `scripts/mcp-subject/h2-meter-row.sh` assert positive
  money and GATE IN CI TODAY.** They boot the real release binary, serve a real `message/send` /
  `tools/call`, read `GET /api/v1/admin/keys/<kid>/usage` before and after, and assert
  `req_delta -eq 1` and `spend_delta -eq 1`. Gating steps at `ci.yml:2060` and `:2073`
  (`plane-rigs`, no `continue-on-error`), on every PR and on dev/qa/main.
- **The voice rig asserts an exact amount and gates:** `legs/metering-lease.sh` →
  `voice-conform.rs:probe_metering_lease` fails unless `cap == Some(4_000)` and
  `lease.settled_nanos() == 4_000`.

**THE TRUE GAP, verified and narrower: NO witness anywhere — corpus, rig or test — PRICES a
post-1.5.5 plane THROUGH A RATE CARD.** The structural reason is one line of rig config:
`scripts/a2a-subject/h2-lib.sh:85-94` sets `per_request_fee: 1` and **has no `rate_card:` key at
all** — which under #42 is a BILLING-OFF deployment. So the a2a/mcp rigs assert the flat fee (#44)
only and *cannot* exercise a priced class by construction. The voice rig's `price_usage` is a harness
stub (`voice-conform.rs:1057`, flat 1 nano/unit over a `FixtureHost`), also not a card.

Uncovered on a2a, mcp, streaming and decision: per-declared-class counts (a2a `bytes`; mcp
`tool_calls`+`bytes`; streaming's seven; decision `decision`); price = Σ count × rate (#71); the card
in force at `arrived_ms` (#79); an unpriced class REFUSING rather than billing zero (#42); a
nanos/spend budget biting at the right quantity (the existing `h2-admit-refusal` bites on a
`requests:1/day` COUNT budget — a different quantity). **The refusal half IS genuinely covered** by
`h2-admit-refusal` (a2a+mcp) and `admit-refusal` (voice) — reuse those shapes, do not rewrite them.

**THE SINGLE HIGHEST-LEVERAGE EDIT IN THIS ENTIRE FINDING:** add a `rate_card:` block to both
`h2-lib.sh` files. One edit converts two already-gating rigs from billing-off to billing-on and makes
every subsequent pricing leg possible.

**LANDED 2026-09-22, and it bought more than expected on one side and less on the other.** Both
`h2-lib.sh` files now write `rate_card: {}` (an EMPTY but PRESENT card — the most a billing-on
deployment of these planes can say, for the reason §13(2) measures). MORE than expected: the switch
is not cosmetic, because `plane_host/govern.rs:226` gates the whole metering write on it, so the
old subject wrote NO metering row for a served call and both `h2-meter-row.sh` legs now carry a
third, genuinely new gating assertion — the meter proving it RAN, rather than the admission counter
standing in for it. LESS than expected: the two flat-fee deltas those legs already assert did NOT
move, and the reason is measured rather than assumed — `GET /keys/<id>/usage` reads the BUDGET CELL
that `try_admit` bumps one step before the meter, on a path with no card gate at all. Six new
gating legs sit beside the twelve (`h2-class-price.sh`, `h2-card-epoch.sh`, `h2-unpriced-refuses.sh`
per plane, wired in `ci.yml` with no `continue-on-error`); they are RED today on the three
disagreements parked in §13, which is the outcome that makes them witnesses rather than decoration.

**AND THE ORACLE CANNOT BE MADE TO HELP — measured in the engine, three independent locks.** (1) The
diff loop iterates only cells the GOLDEN LEDGER marks PASS (`run.rs:1464-1482`); a cell with no golden
row never reaches `compare()` — it is not even `missing.golden`. (2) Gaps do not touch the verdict:
`rc` is set only by `owed.is_empty()` or `diverging_total > 0` (`run.rs:2223`), so **an authored money
cell added to the corpus today is a silent no-op that can never fail**. (3) `run.rs:1021` hard-refuses
any accepted-difference naming `missing.golden`. There is also **no assertion field in the cell
schema** — every key across all 2318 cells was enumerated; `why` is prose the engine reads once and
never evaluates. Ledger: 916 PASS / 1402 SKIP; all 468 a2a and all 912 mcp cells are SKIP with one
verbatim reason (*"proven by its conformance rig, not recorded here"*); **zero streaming and zero
decision cells exist at any status.** So the oracle's role IS bounded to 1.5.5 parity by construction —
that is the design, not a defect, and the witness belongs in the rigs.

**ONE SAFE-DIRECTION NOTE:** `missing.candidate` IS in the money class set (`differ.rs:70-84`, weight
10) while `missing.golden` is not — so the port-band collision manifests as a money-class RED, never a
false green. But it means any money-class red seen on 2026-09-22 should be re-checked against the port
collision before it is believed.

**THE ORIGINAL SECOND LEG, kept for the record:** The obvious
rebuttal is that the oracle was only ever a 1.5.5 PARITY net and new-plane correctness belongs to the
conformance rigs. Measured: it does not. The a2a harness and supplement contain **zero** mentions of
`spend`/`billing`/`ledger`/`rate_card` (an earlier 9-of-27 count was matching `usage`/`meter` in
unrelated senses). The mcp rig has no money assertion. The voice rig's 16 "money" files are
**COMMENTS asserting the NEGATIVE** — e.g. `voice-conformance/legs/admit-refusal.sh:16`, *"(c) no
ledger posting landed"*. That is genuine coverage of the refusal path and worth keeping, but it
proves only that nothing was posted when nothing should be — never that the RIGHT amount was posted
when something should be.

*Evidential caveat, stated because it matters:* a negative grep is weak on its own. The claim rests
on TWO independent routes agreeing — no 1.5.5 golden can exist for a post-1.5.5 plane (structural,
not a gap), and no rig asserts a positive money value (grep, refutable). If someone finds a positive
money assertion in a rig, the second leg falls and only the first stands.

**Corollary for every agent report:** a NEUTRAL oracle on a post-1.5.5 plane must be reported as
"the oracle cannot see this", never as "no divergence". Those are different claims.

### 13. PARKED — the a2a accrual semantics need a billed-byte sign-off (#10/#59)

B09's fix changes what an a2a unit accrues against its hold from `request_bytes` to
`request_bytes × bytes_nanos`. **No observable byte moves today** (the module is unreachable, above),
so there is no oracle cell to park — but the SEMANTICS must be signed before a2a is switched on.
Recommendation: **approve.** The accrual and the hold are now provably the same denomination by
construction (`AccrualMeter` is nano-units, `busbar-kernel/src/teller.rs:246`; the hold is sized in
nanos by `Estimate::pre_tier_nanos`), and the ledger's raw counts per declared class are unchanged
(#71 — a2a declares one class, `bytes`, `busbar-plane-a2a/src/meta.rs:46`).

A clock hazard worth keeping: `bindings.now` is whole SECONDS while `effective_from` is MILLISECONDS
(`root/kernel.rs:435`). Resolving a rate card at a seconds-valued instant matches only the from-zero
opening entry and reports it forever — the same lie with a lookup in front of it. Any #79 resolution
needs a millisecond binding.

**THREE FIGURES MEASURED 2026-09-22 when §12's rate-card edit landed, parked here with both sides
of each disagreement rather than tuned away.** The edit put `rate_card: {}` into both rigs'
`h2-lib.sh`, which converts their subject from a billing-OFF node to a billing-ON one (#42). What
that bought, and what it exposed, was measured end-to-end against the release binary — one served
`message/send`, one key, one before/after read on every money surface the admin API has.

1. **The ledger implies 0 and the node bills 1, and the defect is in the LEDGER, not the card.**
   `Σ count × rate` over a2a's one declared class comes to **0**, because the serving path posts
   `UsageComponent::Queries` with amount `0` (`busbar-a2a/src/a2a/receive.rs:729`; mcp's twin at
   `busbar-mcp/src/mcp/method.rs:2510`) — a quantity of zero for an exchange that moved a document.
   Observed spend is **1 cent**, the flat fee (#44), and nothing else. The two agree numerically
   only because the class term is zero, which is agreement by absence. This is the same sign-off
   this section already parks: until the plane reports the byte it billed, "approve the billed-byte
   semantics" is approving an arithmetic nobody can observe. `scripts/{a2a,mcp}-subject/h2-class-price.sh`
   is now the gating witness and is RED on exactly this.
2. **No card can name a plane's declared class, so the product has an unsettable factor.** `rate_card:`
   is keyed by CONFIG MODEL NAME and every key is validated against `models:`
   (`busbar-kernel/src/config_validate/mod.rs:1465-1472`), and an entry's only members are the four
   LLM token tiers (`RateEntryCfg`, `config/sections.rs:324`, `deny_unknown_fields`). Measured:
   `rate_card: { bytes: { input_utok: 2 } }` fails `--validate` with *"rate_card names model 'bytes',
   which is not defined under models:"*. So `rate(bytes)` and `rate(tool_calls)` are not numbers an
   operator can set — #47's per-plane `rate_card`/`fees` reserved keys are the design answer and are
   not implemented. Until they are, #71's `Σ count × rate` is unreachable on every post-1.5.5 plane
   for every operator, not merely unexercised by the rigs.
3. **A THIRD DISAGREEMENT, and it is between two rulings rather than between a rig and a ledger.**
   `plane_host/govern.rs:226` gates the whole `record_metering` write on `cost.pricing_enabled()`
   (`rate_card.is_some()`, `cost.rs:649`). Measured, same traffic, same plane, one config key apart:
   billing OFF ⇒ `GET /api/v1/admin/usage` answers `by_model: []`, `total.requests: 0`; billing ON ⇒
   one row, `{model: "agent:probe", provider: "a2a", requests: 1, spend_micros: 10000}`, every token
   tier 0. #42 sanctions this in terms (*"rate_card ABSENT ⇒ … no metering, no ledger charge"*). The
   owner's later ruling does not: *planes always ledger* — a plane emits raw counts per declared
   class unconditionally, and pricing is a READ-TIME view (#71/#43), which a write-time card lookup
   contradicts. ~~**OWNER CALL OWED:**~~ **RULED 2026-09-22 — THE LEDGER WRITE IS UNCONDITIONAL AND
   `govern.rs:226` IS THE DEFECT.** The card decides only whether a READ can turn counts into money.
   #42 stays true exactly as written — rate_card presence IS the billing switch — because **billing
   is the read, not the write**; a plane whose ledger write depends on a card is a plane that knows
   about money, which is what #43/#71 forbid and what #77(3) ("price is NEVER stored") rules out.
   The owner's words the ruling applies: *"planes always ledger"*; *"its a kernal default all planes
   run though. no tunring things on or off by plane"*; *"Billing is OPTIONAL per plane; rate_card
   PRESENCE is the switch… AGREED. but its not an on off in the plane."* **The fix is owed in
   `busbar-kernel/src/plane_host/`, not here**, and it WILL move oracle cells — a deployment with no
   card starts producing metering rows where it produced none — so every moved cell is PARKED, not
   blessed. **The witness is written and gates now:**
   `scripts/{a2a,mcp}-subject/h2-ledger-unconditional.sh` makes the same assertion twice against one
   binary with the card as the only difference (card present = the control that proves the read
   works; card absent = the claim), so it is RED today on the defect and goes GREEN when the fix
   lands, with no edit to the leg.

   **ONE THING THE RULING DOES NOT SETTLE, and the leg deliberately does not assert:** whether an
   UNCARDED deployment should nonetheless bill #44's flat fee. Measured: with `rate_card:` absent,
   `GET /keys/<id>/usage` reports **`spend_cents: 1`** — the configured `per_request_fee`. #42's own
   words say an uncarded node should *"serve free, no metering, no ledger charge"*, which reads as
   **0**; but `root/kernel.rs`'s `card_from_config` states the opposite in terms — *"absent prices
   every class at nothing and still charges the flat fee, which is exactly what the previous release
   bills for that deployment"* — and `RateCard::absent_in` carries the fee by construction
   (`kernel-ledger/src/cost/rate.rs:184`). Both figures, both authorities: **0 by #42's wording, 1 by
   the 1.5.5-compatibility design and the shipped code.** A second ruling is owed; until it lands
   `h2-unpriced-refuses.sh` asserts the SHIPPED figure (1) rather than picking a side, and says so.

### ON THE CRITICAL PATH — each costs the owner ~60 seconds and unblocks ~2 agent-days

Measured 2026-09-22 against the 2026-09-25 09:00 PDT dev-green target. Two of the three critical-path
roots of the crate collapse are owner decisions that cost ZERO agent-time. Everything below is
prepared; only the word is missing.

6. ~~**The `#35`/`#40` record-shape seam.**~~ **RULED 2026-09-22 → #83: YES, proceed.** Record
   SHAPES move to `busbar-contract`; ledger SEMANTICS stay in `busbar-kernel-ledger`. Generalised by
   the owner into a global rule — *"contract = shapes"* — so this is no longer a one-off seam but an
   instance of #83. Original finding kept for the evidence: A store plugin implements `Store` and handles
   `PlaneRecord`/`UsageLedger`/`VirtualKey` — the store kind's whole ABI — and those types live only
   in `busbar-kernel-ledger`. So **the money one-book rides inside every plugin's dependency
   closure** (measured: 6 busbar crates, via `crates/api/src/store.rs`'s re-export shim). Retiring
   `busbar-api` alone does NOT fix it. The seam Part 7 already recorded is: record *shapes* →
   `busbar-contract`, ledger *semantics* → `busbar-kernel-ledger`. **It is a money-path type move,
   so #10/#59 forbids self-approval.** Blocks W6 entirely, and W6 blocks the only #40 witness
   (`busbar-plane-decision`'s `tests/{purity,invariance}.rs`, red today BY DESIGN — they go green
   when the edge closes, and that flip is the proof).

7. ~~**The `voice.*` → `streaming.*` constant rename.**~~ **RULED 2026-09-22: proceed — and it
   never needed a ruling.** Owner: *"streaming is new in 1.6.0 so nothing should 'change'."*
   VERIFIED: v1.5.5 contains **zero** voice — no plane, no `voice.session.open`, no
   `voice.interrupt`, no `voice.pacing`, no `voice-key`, not one file matching `voice`
   (`git ls-tree -r --name-only v1.5.5 | grep -ic voice` → 0). So no shipped ledger or audit row
   anywhere carries these constants and the rename cannot move a billed byte. **My earlier
   "measured: #18's claim is false" was right that two in-tree crates differ and WRONG about the
   consequence** — #18's "byte-identical (naming/packaging, not behavior)" holds in the only sense
   that matters. No corpus cell is owed. Original finding kept for the evidence: #18 locks the plane's name as streaming, and
   #18 asserts the rename is "byte-identical (naming/packaging, not behavior)". **Measured: that is
   false.** Five constants change VALUE — `OP_SESSION_OPEN` (`voice.session.open` →
   `streaming.session.open`), `FACT_INTERRUPT_AUDIO_PLAYED_MS`, `EGRESS_PACING_FACT_KEY`,
   `claims::SCHEME` (`voice-key` → `streaming-key`), `PlaneMeta::KEY`. An `OpClassId` is a METERING
   AND AUDIT KEY: it lands in usage-ledger rows, metering rows and audit records. Billed-byte
   adjacent ⇒ #10/#59 ⇒ never self-approved. Question is two parts: (a) may the values change, and
   (b) does the oracle corpus gain a cell for it? Note #81's precedent — the owner ruled a necessary
   1.5.5 divergence acceptable — but that ruling was scoped to unit counts and does not extend here
   by itself.

8. ~~**`busbar-core-substrate`**~~ **RULED 2026-09-22 → SPLIT (#83a). The roster becomes 34.**
   Owner chose the split and generalised the reasoning into #83: a crate holding two definitions is
   a crate that splits. Pure ABI-shaped value leaves (`ir/*`, `billing`, `wire`, `media`, `json`,
   `lossless`) → `busbar-contract` (shapes); runtime machinery (SigV4 signer, eventstream parser,
   SSE proxy, protocol registry, breaker, diagnostics catalogue) → `busbar-kernel` (semantics); the
   crate dies. **`billing::Usage` is a money-path type move and rides the same #83 sign-off.** This
   supersedes the earlier "keep it and figure it out later" — the figuring out is done. The
   measurement that forced it: 14,084 LOC / 42 files. Nine crates depend on it (`busbar-contract`'s
   edge is dev-only, so the plugin closure is unaffected). It is TWO things welded together: pure
   ABI-shaped value leaves (`ir/*`, `billing`, `wire`, `media`, `json`, `lossless`) AND runtime
   machinery (a SigV4 signer, an eventstream parser, an SSE proxy, a protocol registry, a breaker, a
   diagnostics catalogue). Ten of the kernel's 23 references are **re-export shims** — e.g.
   `kernel/src/ir/handle.rs` is 14 lines whose body is one `pub use`. The other thirteen are real:
   the kernel genuinely consumes `billing::Usage` (8 sites), `proto::registry`, `handlers::*`,
   `IrFacts`. **So #37's "the kernel does NOT depend on the foundation" cannot hold as written** —
   one crate is serving two tiers in opposite directions, because substrate holds both the kernel's
   own billing vocabulary AND the projection traits the planes must implement without seeing the
   kernel (the orphan-rule fix the extraction existed for). Folding it into the kernel breaks #40
   for five plane crates; folding it into contract puts a SigV4 signer in the ABI crate and blows
   `contract_caps` (7,012) past ~20k; splitting it makes the roster 34 and moves `billing::Usage`,
   a money-path type. Either the rule narrows (e.g. "the kernel may consume the foundation's value
   leaves but must not be BUILT by it") or the crate splits. **Owner call; the rename in W7 is safe
   either way.**

9. **A fractional count bound for an ABI-2 store (#81a(f)).** Four `i64` columns cannot hold it;
   truncating violates #81; refusing breaks a working deployment on upgrade, which
   `api/src/usage_migration.rs:57-62` names as the one outcome a migration may not produce. Parked
   as a REFUSAL (#42). **Currently unreachable** — no provider has been shown to emit a fractional
   count on the wire — so this does not block the cut, but it is the one hole in #81.

10. ~~**`plugin-testkit` — park, do not delete.**~~ **RULED 2026-09-22: DELETE.** Owner: *"delete
    it. wtf is a testkit."* #33 stands as written; the roster line naming a `testkit feature` on
    `busbar-plugin-sdk` is corrected to drop it. My park recommendation is withdrawn — the earlier
    reasoning was: #33's "there is NO testkit" rests on
    five owner expressions of dislike and no kill, and the roster he approved still reads
    `busbar-plugin-sdk (author machinery + testkit feature)`. Deleting shipped code on an
    over-claiming doc row is the failure mode this section exists to prevent.

## Traps this tree has already sprung — do not re-learn them

- **`git grep -E` does NOT honour `\b`.** Use `-P`. And never grep a concatenated `git archive`
  blob — that produced a false CRITICAL SSRF finding.
- **A missing check is not a vulnerability until you show the line executes.** Two findings were
  escalated wrongly this way in one night. "Is the guard absent?" and "does anything call it?" are
  two questions; the second decides severity.
- **`ledger sync --write` launders audited code into unaudited scopes.** A fold moves code, the gate
  flags the new scope missing, sync adds it unaudited and deletes the old scope's record, and the
  gate goes green. Moved scopes must CARRY their audit record.
- **A checklist that outlives its decision will quietly re-litigate it.** `qa/kind-isolation.toml`
  was steering at `busbar-control-admin` — a kind the owner killed. `ARCHITECTURE.md` §1.4 and ~20
  references in the kind-isolation gate still call `control` a kind.
- **Blanket `git add` with concurrent agents sweeps up their uncommitted work.** One commit absorbed
  three agents' changes including a billing fix. Stage explicit paths.

## THE CRATE ROSTER — OWNER-LOCKED 2026-09-22, **33 crates**. THE ROSTER *IS* THE DEFINITIONS (#83)

> **33 LOCKED** by the owner 2026-09-22, after the chain 35 → 34 (#83a splits `busbar-core-substrate`,
> two definitions) → 33 (#84 merges `busbar-contract` + `busbar-plugin-sdk`, one definition).
> **DRIFT BOUND, owner's words: "it may change but only ±3-5, not 20."** Under #83 the count is an
> OUTPUT of the definitions, not a target — but a proposal that moves it by more than ~5 is evidence
> the DEFINITIONS are wrong, not that the number should follow. Bring that to the owner, do not absorb it.
> Still unsettled and inside that band: 6 HOMELESS crates (fit no definition ⇒ owner conversation,
> #83 step 3) and 4 roster slots with no crate (`busbar-export-*`; `otlp` has no implementation anywhere).
> **A fifth row writes the same cheque:** def 29 `busbar-auth-static` is described as an instance the
> default distribution SHIPS, and the only thing on disk is `auth-static-plugin`, which is test-only —
> no manifest in the tree names it, not even as a dev-dependency. Either def 29 is really row 35–40's
> kind, or a shipped instance is owed and does not exist. Owner's to resolve; measured, not acted on.
>
> **OUTSIDE the band, flagged not absorbed: row 35–40 takes the count 33 → 39, which is +6.** The six
> ABI fixtures were HOMELESS; defining them is what un-homes them, and the definition is clean (see
> the row). But this file's own rule is that a move of more than ~5 is evidence the DEFINITIONS are
> wrong rather than a number to follow, so it is recorded here for the owner rather than treated as
> settled. The counter-argument, for that conversation: the six are ONE definition, exactly as rows
> 21–27 are one definition over seven crates — on a per-DEFINITION basis the roster moves 24 → 25.

**This supersedes every earlier count in this document.** It is the owner's own roster, recovered
verbatim from the 2026-09-20 transcript where he pasted it himself, re-presented to him on
2026-09-22 and locked: *"OTHER than substrate I agree 100% so keep it and figure it out later"* →
*"lock it in"*. **34, not 35:** `busbar-core-substrate` was ruled a SPLIT on 2026-09-22 (#83a).

Per **#83**, each row is a DEFINITION of the KIND that lives there, not a list of contents. A file's
home is decided by asking which definition it fits. Nothing fits ⇒ owner conversation (#83 step 3).

| # | Crate | Definition — the KIND that lives here |
|---|---|---|
| 1 | `busbar` | The composition root: the only place that names which crates exist and wires them at boot. Decides nothing a library could decide. |
| 2 | `busbar-kernel` | The dispatch loop and the seams every step plugs into — one thread of control, owning nothing a step owns. |
| 3 | `busbar-kernel-identity` | The AUTHENTICATE step: a presented credential resolved to a principal, and nothing about what that principal may do. |
| 4 | `busbar-kernel-scope` | The APPROVE step: the scope lattice a grant is tested against, as a pure predicate. |
| 5 | `busbar-kernel-budget` | The ADMISSION step: may this proceed against a cap — check-then-charge over a bucket chain. |
| 6 | `busbar-kernel-ledger` | What money MEANS: settlement, posting, pricing, derivation, recompute. One book, and never the shape of a record. |
| 7 | `busbar-kernel-egress` | The one chokepoint that SENDS: pool selection, the attempt walk, exhaustion terminals. |
| 8 | `busbar-kernel-breaker` | When to stop trying an upstream: the failure classifier and the trip/cooldown state it drives. |
| 9 | `busbar-kernel-wal` | The durable append-only MEDIUM — framing, sequencing, group commit, recovery. It never reads what a record means. |
| 10 | `busbar-kernel-audit` | The tamper-evident record of what was done and by whom, written onto that medium. |
| 11 | `busbar-core-admin` | The operator-facing verbs and their HTTP/OpenAPI surface. Serves operators, never traffic. |
| 12 | `busbar-core-oauth2` | The OAuth 2.1 authorization-server protocol as busbar speaks it. |
| 13 | `busbar-contract` | The SHAPE of everything crossing the plugin seam — the data, its wire encoding, the traits a plugin implements. No rule an honest implementation could set differently; no dependency heavier than the seam. |
| 14 | `busbar-plugin-sdk` | The author-facing machinery for WRITING and PACKAGING a plugin: the macros and entry glue an author links, and the tool they run to ship one. Never anything the host calls. |
| 15 | `busbar-plugin-loader` | The host-facing machinery for FETCHING, VERIFYING, LOADING and SUPERVISING a plugin. |
| 16–20 | `busbar-plane-{llm,mcp,a2a,streaming,decision}` | Everything ONE protocol needs and no other protocol may name — its wire dialects, its decode/encode face, its session and turn rules. Nothing that prices, admits or dials. |
| 21–27 | `busbar-transport-{grpc,http,sse,stdio,tcp,tls,ws}` | One carrier's framing and connection lifecycle, driven blind. Moves bytes; names no plane, protocol or policy. |
| 28 | `busbar-store-memory` | The in-process `store` instance the default distribution ships. |
| 29 | `busbar-auth-static` | The static-token `auth` instance the default distribution ships. |
| 30 | `busbar-hook-ranking` | The ranking `hook` instance the default distribution ships. |
| 31–34 | `busbar-export-{prometheus,webhook,file,otlp}` | One `export` instance per destination format. **It renders; it never decides.** See the six properties below. |
| 35–40 | `plane-example` · `store-example-plugin` · `auth-static-plugin` · `secret-example-plugin` · `export-example-plugin` · `hook-test-plugin` | **One fixture per plugin kind: the in-tree proof that the kind's ABI loads and behaves identically BOTH WAYS** — linked as an `rlib` and `dlopen`'d as a `cdylib`, one source, two artifacts. `crate-type = ["rlib", "cdylib"]`. Carries no product behaviour and ships in no distribution; its kind-purity rules are read from its DIRECTORY, which is why it is a crate and not a file. |

**THE `export` KIND — OWNER-LOCKED 2026-09-22 ("AGREED 100%"), six properties.** The roster rows
above name the INSTANCES; this names the KIND, and the absence of a kind definition is precisely how
`otlp` drifted into being a `tracing-subscriber` layer in `init_logging` rather than an export.

> **export** — the kind that turns busbar's observations into another system's format.

1. **Read-only on the observation stream.** It cannot change what busbar does, refuse a request, or
   alter a record. If it can, it is a HOOK, not an exporter.
2. **It owns the destination's format** — Prometheus text, OTLP protobuf, JSONL. Core owns none of
   them. That is the whole point of it being a plugin.
3. **Its failure is never the request's problem.** Down, slow or broken must not touch a served
   request: off the hot path, buffered, shed under pressure.
4. **Money-blind and pricing-blind**, exactly like planes (#43/#71). It reports what happened; it
   never computes what it cost.
5. **Both ABIs, compiled-in or dropped-in** — the two universal rules of #3, no exception for this kind.
6. **It declares its carrier; it does not open one — through the SAME mechanism a plane uses.**
   Owner, 2026-09-22: *"treat exports very similar to planes in transport sense. how they request and
   manage should be identical."* **IDENTICAL, NOT ANALOGOUS.** An exporter declares needs as
   **(transport, auth) per direction** through the one declaration shape and the one lifecycle the
   kernel already offers planes — not a second, export-flavoured copy of it. If a reader can tell
   from the kernel code whether a carrier was requested by a plane or by an exporter, the seam is
   wrong. Push or pull is the EXPORTER's choice — that is a format-and-destination decision and
   belongs where the knowledge is — but the carrier is the kernel's to provide. An exporter that
   opens its own socket is doing a transport's job, and the SSRF/pin/breaker chokepoint stays where
   Part 4 Axis 3 puts it.

   *Consequence, stated so it is not discovered later:* a second consumer of the carrier seam means
   that seam can no longer be shaped around one kind's needs. Whatever `kind: transport` becomes, it
   answers to planes and exporters on the same terms.

**Property 6 makes `kind: transport` load-bearing for a fifth consumer, which changes how its absence
reads.** Measured 2026-09-22: `transport` was never built as a plugin kind on EITHER ABI generation
— no cold lane, no hot lane, no `load_transport`/`open_transport`; `busbar-contract/src/transport/registry.rs:19`
says so in its own words (*"Transports are in-tree and never dynamically loaded, so there is no loader
window to police"*). Meanwhile 4 of 4 protocols wrote their own private dial stack instead: MCP's
`mcp/client/*` (8,233 lines, **36% of that crate**), LLM's own `Hop`/`attempt` with no dependency on
`busbar-kernel-egress` at all, A2A's private `pub(crate) trait Transport` in `fetch.rs`, and Voice's
`ProviderDial`/`Detached`. Four independent implementations routing around an interface is evidence
about the interface — but the reading changes with a fifth consumer that has not yet had the chance
to route around it: not "the abstraction does not fit", but "nobody finished it, so everyone went
around it." **That is the open question, and it is the owner's scope call, not an agent's.**


**Why row 35–40 is a definition and not scaffolding.** The release's central claim is that each
plugin can be compiled into the binary OR dropped into `plugins/` — *same contract, same loading
path*. A claim with no witness is a hope, and these fixtures are the witness. `export-example-plugin`
is the proof that this is load-bearing: its consumer,
`plugin-loader/src/tests/export_conformance_tests.rs`, calls itself **"THE #11 TEST — one crate,
built BOTH ways, must be observationally identical"**, and it exists because the two builds were
NOT. A `cdylib` statically links its own copy of the `metrics` facade, so *"every counter a
dropped-in sink incremented went into a registry nobody ever scrapes"*, while the same source
compiled in linked the host's recorder and worked. Two builds, two observable behaviours, and
nothing in the tree said so.

That witness needs BOTH artifacts from ONE source, which is why these stay crates rather than
becoming `busbar-plugin-sdk/examples/*`. The move was considered and refused on evidence: an example
target can never be a Cargo dependency, so the rlib half of the proof cannot survive it; and a
fixture that moves into the SDK is scanned as TCB, so the `store`/`secret`/`hook` purity rules stop
reading it — `forbid-unsafe:hook-test-plugin`, `forbid-unsafe:secret-example-plugin` and
`forbid-unsafe-deny:store-example-plugin` pass today only because the fixture is a crate DIRECTORY
matched by its kind glob. Trading `#![forbid(unsafe_code)]` on plugin fixtures for four fewer
directory entries is a bad trade, and `ceiling-census` would have called it correctly.

**Only `plane` and `export` hold that witness today.** Measured 2026-09-22: those two are the only
fixtures anything links the rlib of. The blocker for the rest is upstream of the fixtures —
`busbar_plugin_sdk::dispatch_export_enveloped` is the SDK's ONLY enveloped dispatch (#85 covered
`export` and no other kind), and the envelope is what makes "observationally identical" testable at
all. `auth-static-plugin` gained its `rlib` on 2026-09-22 so it CAN carry one; `dispatch_auth` is
still un-enveloped, so it does not yet.

### THE 57 ON DISK, AGAINST THOSE DEFINITIONS — measured at `1cc110dbd`, 2026-09-22

`git ls-files 'crates/*/Cargo.toml'` = **57**. Closure measured at **6** (`busbar-grammar` already folded).
**28 CLEAN + 4 FOLD + 12 SPLIT + 4 MERGE + 6 HOMELESS + 3 no-content = 57.** Every crate is placed.

**CLEAN — one definition, contents fit (22).** `busbar-kernel-{identity,scope,budget,egress,breaker,wal}`
(defs 3,4,5,7,8,9) · `busbar-oauth2` (12, rename only) · `busbar-contract` (13) · `plugin-sdk` (14) ·
`plugin-loader` (15) · `busbar-plane-{llm,mcp,a2a}` (16–18) · the 7 `busbar-transport-*` (21–27) ·
`store-memory` (28) · `hooks-ranking` (30) · the six ABI fixtures `plane-example`,
`store-example-plugin`, `auth-static-plugin`, `secret-example-plugin`, `export-example-plugin`,
`hook-test-plugin` (35–40 — moved out of HOMELESS 2026-09-22 when the definition landed).

**FOLD — clean, one definition, destination already known (4).** `busbar-llm-codec` (63,070 surf) ·
`busbar-mcp-codec` · `busbar-a2a-codec` · `busbar-voice-codec` → each is a WIRE DIALECT, which def
16–20 absorbs. They are not homeless; they are pre-fold.

**SPLIT — two or more definitions in one crate (12 crates, 9 rows).**

| Crate | Definitions it holds | Where each goes |
|---|---|---|
| `busbar-substrate-values` | ABI-shaped value leaves / runtime machinery | `ir/*` `billing` `media` `wire` `lossless` → 13. `diagnostics` (2,940) `proto` `handlers` `sigv4` `eventstream` `breaker` `proxy` `profile` **and `json`** → 2. Crate dies. |
| `busbar-kernel-ledger` | Record SHAPES / ledger SEMANTICS | `records.rs` (604 surf) → 13, **less** its `scope_kinds` `RwLock` registry (~30), which is runtime state ⇒ 2. `settle` `checkpoint` `recompute` `cost/*` `usage/*` `totals` `verify` `identity` `migration` `legacy` stay (def 6). |
| `api` | Plugin contracts / I-O machinery / migration logic / shim | `auth` `hooks` `secret` `operation` `signal` `redacted` (727) → 13. `durable.rs` (110, real `fsync` path) → 2. `usage_migration.rs` (66) → 6. `store.rs` (9) is a pure `pub use` shim → delete. Crate dies. |
| `busbar-kernel` | ≥6 kinds | Residual grab-bag: `config/`+`config_validate/` (31k), `plane_host/` (18k), `governance/` (12k), `auth/` (11k, duplicates def 3's territory), `plane/` (11k), `egress/` (9k, duplicates def 7's). Def 2 is `teller.rs` + the seams; the rest is owed a home. |
| `busbar-core-admin` | HTTP surface / verb semantics | **CLOSED 2026-09-22 — the plane entry face is DELETED, not re-homed.** `admin_codec/codec.rs` (the `Plane` impl) and its exclusive tails are gone: that trait is how TRAFFIC enters the dispatch loop and this crate serves operators, never traffic (#3/#5/#83 def 11). It was never dispatched through — an admin request arrives on `admin_listen`, is matched against `admin_codec::verbs::resolve`, and walks the loop as the ADMIN UNITS (`crates/busbar/src/root/units_admin`). `kind-isolation:faces` FAIL → PASS; `construction:kernel-seal-impls` FAIL → PASS with it (the deleted test harness held the tree's last untracked `KernelSeal` forgery). `admin_codec/` is now the closed verb table, the one claim and the frozen error envelope — DECLARATIONS, no entry face. `v1/` (12.8k) = def 11. Top-level `keys/verb/rate/restart/posture/…` (4.7k) = verb-execution semantics, still owed a home; the crate split is a later wave. |
| `busbar-llm` · `busbar-mcp` · `busbar-a2a` · `busbar-voice` | Protocol orchestration / plane entry face | Session, turn and dialect rules → 16–20. But `unit/{admit,approve,meter,route}` and `runtime/metering.rs` decide admission and price — that is defs 5/6, not a plane. |
| `busbar-plane-decision` | Adapter / codec / kernel-side `PlaneDecl` builder | Adapter+codec = def 20 (#39 ruled the 113-LOC codec too small to split out). `registry.rs` names `busbar-kernel` — its own header calls it a #40 violation. |
| `busbar-kernel-audit` | Record shape / a second chain mechanism | `record.rs`+`amend.rs` = def 10. `legacy/{chain,entry}.rs` (1,019) is a self-contained hash chain — def 9's KIND, kept only so 1.5.5 digests still verify. |
| `busbar` | Composition / real logic | `root/{policy,money_book,ledger_identity,gauntlet_kernel}.rs` is unit logic in the wiring harness. |

**MERGE — two crates, one definition (4 crates + 1 type pair).**

| Pair | Shared definition | Survivor |
|---|---|---|
| `busbar-plane-streaming` ↔ `busbar-plane-voice` | def 16–20 | **`busbar-plane-streaming`** (the #18 name). 6 files byte-identical; `claims.rs` differs by one literal; `meta.rs` by renamed consts. **CORRECTED 2026-09-22 — the earlier 'dead fork' call was WRONG and is withdrawn.** `-streaming` is indeed registered 0 times with 0 dependents, but that means UNWIRED, not stale: it is the NEWER code. **Neither crate is a superset.** `-voice` has ONE fix `-streaming` lacks (`74712b303` P5 — folds every decoded IR event in order, dispatches a tool call on `CallClose` with accumulated arguments). `-streaming` has THREE `-voice` lacks, one of them MONEY: `e15713578` *\"paired turn routes to the DIALED upstream (money-byte fix)\"* — voice `plane.rs:433` hardcodes `UpstreamIdx(0)` and `:439` `.first()`, so a gemini-live session with openai declared first bills EVERY TURN on the wrong provider's lane; `9882d8122` CRITICAL empty/raw Unit-0 egress (voice's `encode_egress` is still a raw pass-through, so the provider gets an empty first message and `session.update` is silently never applied); and `dd3bfbda9`'s plane-half error-code fix. Test counts also invert the earlier claim: **streaming 44, voice 37**, and 8 streaming-only tests are the red-before-green witnesses for those three fixes. **RULING: `busbar-plane-streaming` is the BASE**; port `74712b303` forward (one commit, ~112 lines + 108 of tests) rather than three including a money fix. The two fix-sets are disjoint by function — voice's touches `decode_response`/`progress_from_server_event`, streaming's touch `encode_egress`/`verify`/`decode_twilio_frame`/`open_or_relay`/`ingress_from_client_event`. We accept losing voice's git history on the rename: a known money-path regression outranks history. |
| `busbar-plugin` ↔ `busbar-contract` | def 13 | `busbar-contract`. `hot/host.rs` is `PlaneHostVtable`, a `#[repr(C)]` fn-pointer struct; `cold/*` is the JSON wire schema for the six C symbols. Both are *the shape of what crosses the seam* — contract's definition verbatim. Collapses a closure crate. |
| `secret-ref` ↔ `busbar-contract` | def 13 | `busbar-contract`. `SecretRef{module,settings}` + its hand-written grammar + the schema mirror. Pure shape, `serde`+`serde_json` only. **Name collision to de-conflict on the move:** `busbar_contract::kinds::SecretRef` is already a different type (`pub struct SecretRef(pub String)`) — do what #35 did with `Store`→`RecordStore`. |
| `busbar_contract::kinds::Store` ↔ `busbar_kernel_ledger::records::RecordStore` | def 13 | One crate, two traits, one plugin kind. Both are the persistence face a store plugin implements. Resolve on the `records.rs` move. |

**HOMELESS — fits no definition. #83 step 3: owner conversation, NOT an agent's new crate (6).**

| Crate | Surf | What it is | Why nothing fits |
|---|---|---|---|
| `busbar-timing` | 524 | Feature-gated, default-OFF per-method micro-timing; compiles to `()` when off. | An instrument, not a shape, step, plane, transport or instance. Named by kernel, llm, llm-codec, substrate-values. |
| `busbar-core-transport` | 171 | Inbound connection-security build seam: reads `tls:`, resolves key material, builds the opaque `ConnectionSecurity`. | Def 21–27 forbids naming policy and this resolves secrets. Not def 2. Pairs with the row below. |
| `busbar-unit-transport-key` | 268 | The surviving TLS secret→`TransportKeyHandle` step (**not** the killed `busbar-transport-key`; #36 names this one as the one exit from the unit collapse). | Same gap. These two are one kernel-side key-provisioning kind with no roster slot. |
| `plugin-sign` | 451 | Manifest schema + canonical signing bytes + trust-policy evaluation. | Split by #83(d): the manifest/canonical-bytes half is SHAPE, the trust policy is not. But the shape half drags `ed25519-dalek`+`sha2` ⇒ barred from 13 by downside (b). |
| `plugin-pack` | 383 | `[[bin]]` CLI that packs/signs a plugin tarball — for third-party authors, not this build. | Not def 1 (that is the busbar binary). No tooling slot in the roster. |
| `auth-admin-tokens` | 29 | Live, default-on: `kernel/src/auth/mod.rs:978` dispatches `"admin-tokens"` to it. Constant-time both-carrier admin credential compare. | **It DOES fit def 3** — "a presented credential resolved to a principal" — and `kernel-identity/admin.rs` already holds the admin chain's no-module posture. So MERGE into 3, *unless* the owner holds that an auth module is always an INSTANCE (def 29's kind), in which case the roster owes a second auth-instance slot. **That is the ruling needed.** |

**Not homeless, no content:** `busbar-core-hooks` (31 LOC of doc comment, **0 surface, 0 dependents**) —
an announced empty namespace; delete. `busbar-core-config` (12 surf) — a fragment of def 2's config
kind, not a definition; fold. `plugin-testkit` — owner ruled DELETE 2026-09-22.

**Four roster slots have no crate.** `busbar-export-{prometheus,webhook,file}` exist only as
`busbar-kernel/src/export/{prometheus,webhook,file}.rs` (136/212/209 LOC); **`otlp` has no
implementation anywhere** — config and admin surface reference it, no `otlp.rs` exists.

### WHAT #83 COSTS CONTRACT — measured with `scripts/loc-surface.py`, the ceiling's own counter

**`contract_caps` is ALREADY BREACHED and the raise is owed, not optional.** Contract measures
**7,426** at `1cc110dbd` against a declared **7,012**. The gap is **exactly 414** — the
`busbar-grammar` fold raised `rules.loc-ceilings.caps_contract_ceiling` 5238→5652 (+414) and did
**not** raise its pair, contradicting `qa/construction.toml`'s own rule that *"the two rows are ONE
owner decision measured two ways."* First owed raise: **7,012 → 7,426**, carrying no new content.

| Move | Surface into contract |
|---|---|
| `api` plugin contracts (`auth` `hooks` `secret` `operation` `signal` `redacted`) | 727 |
| `kernel-ledger` `records.rs`, less the `scope_kinds` registry | ~604 |
| `substrate-values` `ir/*` | 508 |
| `secret-ref` (whole crate) | 274 |
| `substrate-values` `media` `billing` `wire` `lossless` | 198 |
| **#83 subtotal** | **~2,311** |
| `busbar-plugin` (MERGE; ~3,269 with its tests re-homed under `src/tests/`) | +3,269 |

So **`contract_caps` 7,012 → ~9,750** for #83 as ruled, and **→ ~13,100** if the `busbar-plugin`
merge lands with it. Precedent is on the record: *"#40 is owner-locked and the ceiling is not."*

**Counting artifact, so the raise is not over-spent:** the counter skips `src/tests/**` but NOT
tests elsewhere under `src/`. **1,532 of contract's current 7,426 is `caps/tests/*`**, and
`records_tests.rs` (730) and `busbar-plugin`'s tests (1,441) would likewise count unless re-homed
under `src/tests/`. Land moved tests at the skipped path.

### THE #83(d) TEST, APPLIED TO THE FOUR BORDERLINE CALLS

*Could the RULE differ between two honest implementations (⇒ semantics) or must every one agree
byte-for-byte (⇒ shape)?*

1. **`substrate-values/json.rs` → NOT contract, against #83a's file list.** Two independent reasons.
   (a) It holds `MAX_JSON_DEPTH = 128` and a pre-parse depth scan, self-described as *"a SECURITY
   floor, not an operational tunable."* A second honest implementation could set 64 and still be
   correct ⇒ **semantics**. (b) It is the sonic-rs seam — a SIMD JSON engine — and contract is in
   every plugin's closure ⇒ **#83 downside (b)**. It goes to def 2.
2. **`VirtualKey`'s wire partition → shape, but its registry is not.** `records.rs:182-214`
   serializes through `scope_kinds::{is_registered,wire_field_for}`, a process-global
   `RwLock<BTreeSet<String>>`. The `allowed_{kind}s` NAMING CONVENTION is frozen and every
   implementation must emit it identically ⇒ **shape**. WHICH kinds are registered is deployment
   state ⇒ **machinery**. The convention travels to 13; the registry stays in 2.
3. **`diagnostics/` (2,940 — substrate's single largest module) → def 2, not 13.** A `BUSBAR-NNNN`
   code is an implementation's own vocabulary for its own internal failures; nothing on any wire and
   no plugin must agree with it ⇒ **semantics**. Keeping it out of contract is worth more than every
   other substrate call combined.
4. **`RecordStore` (141) → contract, with `records.rs`.** It is the trait a store plugin
   IMPLEMENTS; its method set must be agreed byte-for-byte or no plugin links ⇒ **shape**. The
   settlement rules it is *called by* stay in def 6 — that is the #35/#40 seam, honoured exactly.

### HEAVY-DEPENDENCY FLAGS (#83 downside (b)) — contract is `serde` + `futures` today

| Incoming | Drags | Verdict |
|---|---|---|
| `json.rs` | **sonic-rs** (SIMD, arch-specific) | **REFUSE** — see #83(d) above |
| `plugin-sign` manifest half | **ed25519-dalek**, **sha2** | **REFUSE** — signing verification is def 2/15 |
| `ir/*`, `wire.rs`, `lossless.rs` | **serde_json** (today contract's DEV dep only) | Accept, but it becomes a NORMAL dep for every plugin — state it in the raise |
| `media.rs`, `wire.rs` | **bytes** | Accept — leaf, opens nothing |
| `wire.rs` (`WireBody.content_type`) | **http** | Accept — header vocabulary only, opens nothing |

**35 in-tree crates**, plus the external plugin repos (store {postgres,mysql,sqlite,valkey}, secret
{vault}, auth {github,ldap,oidc}, hook {headroom,webrequest}).

### Three things this roster settles, and one it does not

**1. `busbar-transport-key` is DEAD — killed twice, for two different reasons.** The owner first
caught the packaging dodge: *"we are hiding 2 creates as 1 to bypass some rule."* Then he went
further and killed the design itself: *"plugins can never ever do x y z"*, *"we said all plugins ONLY
communicate over abi, this would violate that and we need to make it impossible to do so."* Secret
handling is kernel-side; the TLS plugin receives an **opaque config handle** over the ABI and never
sees a key byte. Transports are therefore **7**, not 8.

**2. The plugin instances stay IN-TREE.** `store-memory`, `auth-static`, `hook-ranking` and the four
exports are the default distribution's compiled-in set and they live in the busbar repo. This is the
group an earlier derivation dropped, which is exactly why that derivation came out at 28 instead of
35.

**3. #39's "16" does NOT carry the owner's signature.** #39's literal text — *"The `busbar` repo
contains ONLY: the binary, `busbar-kernel` + the 8, `busbar-core-{admin,oauth2,substrate}`,
`busbar-contract`, `busbar-plugin-sdk`, `busbar-plugin-loader`"* — is 16 crates, and it traces to an
assistant **correcting the owner's pasted list** mid-conversation by moving planes, transports and
instances out to their own repos. **The owner never affirmed that correction**, and it contradicts
the number he did affirm twice: *"you say we have 64 right now and need to get to ~30, i agree."*
Where #39's count and this roster disagree, **this roster wins** — it is the owner's own list, read
back to him and locked.

**4. ~~`busbar-core-substrate` is KEPT~~ — SETTLED 2026-09-22 → SPLIT (#83a).** It held two
definitions, so it splits and the crate dies; the roster is **34**. The *"keep it and figure it out
later"* that kept it is superseded — the figuring out is done, and generalised into #83.

### ONE DISCREPANCY, FLAGGED NOT RESOLVED

The owner's 2026-09-20 paste listed **4 planes**. Earlier on 2026-09-22 he said
*"busbar-plane-llm, -mcp, -a2a, -streaming, -decision AGREED"*, and #48 makes `decision` (jev) the
fifth plane. This roster carries **5** on the strength of that later explicit agreement.
**If the decisions plane is not a 1.6.0 crate, this roster is 33 and row 20 comes out.**

### Provenance — what the owner ACTUALLY said, and three rows that claim more authority than they hold

A full extraction of all 1,031 owner messages from the 2026-09-20 transcript, separating owner
speech (`role: user`) from assistant assertion, found the roster is **substantially owner-authored** —
more so than the doc credited:

- **The kernel-8 names are his.** *"identity and scope. i think if we do auth it should be authz and
  authn which i agree i hate so drop both"*; asked to choose between `admission`/`budget` and
  `money`/`ledger` he answered *"budget and ledger"*; and *"audit and ledger are both records using
  wal"* is his rationale for the shared primitive.
- **Core-3 is his own proposal, near-verbatim:** *"My lean: 3 durable core crates —
  busbar-core-admin, busbar-core-oauth2, busbar-core-substrate — plus the neutral vocab living in
  busbar-contract."*
- **admin/oauth2 are not planes, emphatically:** *"You ask me this every 6 hrs. admin and oauth ARE
  NOT PLANES!!!!!! They are creates and key to ther kernel just in crates for segregation
  cleanliness."*
- **The plugin-isolation law is his:** *"so my bigger question is, how do you prevent that? in code,
  compile time. plugins can never ever do x y z"* → *"we said all plugins ONLY communicate over abi…
  we need to make it impossible to do so."*
- **Scheme A ratified:** *"I like A best. show me A everywhere."*

**Three rows carry more authority than the record supports. Flagged, not changed:**

1. **#33's "There is NO testkit (dead — not a crate and not a feature)" rests on nothing he ruled.**
   His complete words on testkit are *"plugin-testkit feels wrong to have"*, *"either eay testkit
   feels very wrong"*, *"testkit we discuss next, i dont see why it exists anywhere"*, *"testkit i
   still hate"*, *"the mystery testkit im going to fight about"*. He never delivered a kill. The very
   roster he approved with *"SOLID design"* still reads `busbar-plugin-sdk (author machinery +
   **testkit feature**)`, unrebutted. He tolerated it while hating it; the row states it is dead.

2. **#19 and #39 contradict each other, and that contradiction is what caused the 9/20 blow-up.**
   #19 says *"~30-crate **in-tree** end state (#39)"*, but #39 as written yields exactly 16 in-tree.
   "~30" only works as a whole-topology count (in-tree + external repos). When the assistant
   correctly recited "16", the owner said *"this is not what we locked"* — his memory of ~30 collided
   with the doc's own inconsistent framing of what ~30 counts. **The roster above resolves this: the
   number is in-tree, and it is 35.**

3. **The "~30" figure originated with the ASSISTANT, not the owner.** He said *"total was like 30 not
   60"* from memory, then *"you say we have 64 right now and need to get to ~30, i agree"* — agreeing
   to a number he was handed. Not a defect, but the doc should not cite ~30 as his independent
   derivation. **What he authored is the LIST; the count follows from it.** That is why this roster
   leads with names and derives 35, rather than leading with a number.

**Also: the `~31` tally was never recomputed after `busbar-transport-key` died.** The count that
produced it included transport-key as an 8th transport; fifteen minutes later his own catch removed
it, and no one re-tallied. So every later citation of "~30/~31" is one crate stale at minimum —
another reason the list, not the number, is authoritative.

**One caution about calling anything final.** The 9/20 session ended with him saying *"nothng final
no final status until all agents say yes"*, with three audit agents still running. That refusal
applied to THAT session's roster. **This roster is locked on a fresh 2026-09-22 reading-back**, where
he reviewed the table group by group and said *"OTHER than substrate I agree 100%"* then *"lock it
in"*. That is the sign-off; the earlier refusal is superseded, not ignored.

### What the tree looks like against it

**57 crates on disk at `1cc110dbd`; 34 is the target, so 23 still go.** The `-host` crates and
`busbar-grammar` are already folded. The largest single remaining move is `busbar-llm-codec`
(103k lines) into `busbar-plane-llm`.

### #37's tier rule is violated: the kernel DOES depend on substrate

**#37 (OWNER-LOCKED) defines the `busbar-core-*` tier in two halves:** *"surfaces above: admin/oauth2
dep kernel one-way; **foundation below: substrate, which the kernel does NOT depend on**."*

Measured, the kernel does depend on it, and not incidentally:

- `crates/busbar-kernel/Cargo.toml:43` — `busbar-substrate-values = { path = ... }`, a **normal**
  dependency, not dev-only
- It also **inherits four of substrate's features** (`dispatch`, `relay`, `runtime`, `test-support`
  at lines 214–216, 257), so the kernel's own feature surface is defined partly in terms of it
- **23 files** under `crates/busbar-kernel/src/` name `busbar_substrate_values`

So the direction of dependency between the engine and the foundation beneath it is currently
inverted relative to the locked rule. This is the same class of problem as the #40 closure violation
below — a tier boundary asserted in the spec and not enforced by anything in the build.

Worth noting what is NOT wrong: `busbar-contract`'s edge to substrate is **dev-only**, so it does not
widen the plugin closure. That one is fine.

### #40 IS VIOLATED BY SIX CRATES, AND ONE OF THEM IS THE MONEY BOOK

**#40 says the plugin dependency closure is `busbar-contract` and nothing else.** Measured with
`cargo tree -p busbar-auth-static-plugin --edges normal`, a real plugin's actual closure is **six**
busbar crates:

```
busbar-api · busbar-contract · busbar-kernel-ledger
busbar-plugin · busbar-plugin-sdk · busbar-secret-ref
```

**`busbar-kernel-ledger` — the money one-book — is in every third-party plugin's compile closure.**
Note also that plugins do not depend on `busbar-contract` *directly* at all; they name
`busbar-plugin-sdk` and `busbar-api`, and reach contract only transitively.

**Root cause, and it is a known staging state rather than an accident.** `crates/api/src/store.rs`
is an explicit re-export shim: #35 / W3.a relocated the durable money records and the `Store` trait
into `busbar_kernel_ledger::records`, and `busbar-api` was kept standing to re-export them under
their original names so dependents did not have to move. Its own header says it "does NOT retire yet
(that is W5.b)". So the ledger rides into the plugin closure through a back-compat shim that has not
been retired.

**But retiring `busbar-api` alone does not fix it, and this is the part that needs a ruling.** A
**store plugin implements the `Store` trait** and handles `PlaneRecord`, `UsageLedger`, `VirtualKey`
and the unit constants. Those are not incidental to plugins — they are the store kind's whole ABI. So
the types genuinely must be reachable from a plugin, and today the only place they exist is the
ledger crate.

That puts **#35 and #40 in direct tension**: #35 says the money records live in the one book, #40
says a plugin sees only the contract.

**The seam I would draw** — recorded as a recommendation, not executed, because it moves money-path
record types and the tree currently has five agents live in it:

> **Record SHAPES are ABI and belong in `busbar-contract`. Ledger SEMANTICS — one book, settlement,
> postings, derivation — stay in `busbar-kernel-ledger`.**

A plugin must agree on the *shape* of what it persists; it must never participate in what the book
*means*. That split honours #35 (the book is still one place, and it is the only thing that settles)
and #40 (the plugin closure collapses to contract) without weakening either. It also keeps the locked
money model intact: planes write the ledger, money stays a view, and a plugin linking against a
record shape gains no ability to price anything.

Until that lands, **#40 cannot be claimed as satisfied**. The `busbar-grammar` fold already took the
closure from seven to six — necessary, nowhere near sufficient.

### Ordering, and the one real hazard

The plane folds are the bulk of it and they are independent of each other, so llm / mcp / a2a /
streaming can run in parallel. **The streaming fold is the dangerous one** and should not be run
concurrently with anything else: `busbar-plane-streaming` (4,750 lines) and `busbar-plane-voice`
(4,396) are near-duplicates — 7 of 14 files byte-identical, 3 substantially diverged — and the
**dead** one is `busbar-plane-streaming` (registered in `registry.rs` zero times) while the **live**
one is `busbar-plane-voice`. So the correctly-named crate is the empty shell and the working code is
in the crate whose name #18 forbids. A careless "keep the one that builds" collapses to the wrong
side; a careless "keep the correctly-named one" deletes the working plane. It also touches
`units_voice.rs`, which is a money file.

Do the folds **after** the current fix wave lands, not during: these are whole-crate moves and they
will conflict with every in-flight edit.


## Standing rules for anyone working this tree

- `git -C <path>` — never `cd <path> && git`.
- No `Co-Authored-By` and no AI attribution on any commit, ever.
- `--force-with-lease` only on your own `land-*`/`keep-*` branches, and on `predev`.
- Every agent works a **disjoint** slice; every change is red-before-green; the red evidence goes in
  the commit body.
- Run build and test commands in the **foreground**. Roughly fifteen agents in this session
  backgrounded their own scans and then waited forever for a notification that was never coming.
- The oracle is never waived. Money bytes are never self-approved. A divergence is PARKED for the
  owner with cell, diff, root cause and recommendation.
