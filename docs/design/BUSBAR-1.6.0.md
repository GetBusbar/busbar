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
| 43 | **rate_card + fees are CORE-owned; plugins are PRICING-BLIND; pricing is a read-time VIEW. OWNER-LOCKED 2026-09-20.** A plane plugin NEVER sees its rate card or fees. Pricing is CORE functionality, not a plane/plugin concern. A plane emits USAGE FACTS only (e.g. `output_utok: 17`); the ledger records the fact once; **pricing is a read-time VIEW** core lays over recorded facts using the rate card (read-time conversion never stored — money model). `rate_card` + `fees` are RESERVED, core-owned config sub-keys: authored in config alongside a plane's own settings for ergonomics, but core **STRIPS them from the blob before it crosses the plugin ABI** (mirrors the `pools:` reserved-section-keys pattern, `config.yaml:187`; extends #40 — as secrets never cross the ABI, money never crosses it). | RED-provable gate: no reserved money sub-key (`rate_card`,`fees`) ever appears in the serialized blob handed to any plugin; plane plugins have no pricing type on their surface; ledger stores facts, price computed at read |
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

# PART 7 — GROUND-CLEARING SESSION LOG (2026-09-21)

This Part is the handoff. It records what the ground-clearing session changed, what is proven, and
what is still open. **Everything below this line is state, not law** — it goes stale, unlike Parts
1–5. When an item here is done, delete the row.

## What the session was for

The code was close; the ground under it was not. Three compounding problems: 980 remote branches
across two divergent integration lineages each holding work the other needed; 187 markdown docs of
which only three were permitted to be authoritative, so agents steered by whatever stale checklist
they met first; and a release engine that could not promote. This session cleared the ground and
produced this document. It deliberately did **not** run the release.

## Safety net

Full bundle at `~/Downloads/busbar-all-refs-2026-09-21.bundle` (all 2547 refs, `git bundle verify`
exit 0), with a ref manifest beside it at `~/Downloads/busbar-refs-2026-09-21.txt`. Two commits
reachable from almost nothing were tagged deliberately: `1e82b3a0f` (`integration/reland`, reachable
from no other ref) and `004f98d89` (the trunk). **Nothing was deleted without being in that bundle
first.**

## The trunk

`integration/1.6.0-dev-green` @ `004f98d89` was ruled trunk over `predev`, which was stale (a
40-row DECISIONS table, 0 of 16 waves). The consolidated result lives on `consolidated/1.6.0` and
becomes `predev`.

## Fixes landed — each red-before-green, evidence in the commit body

Checkpoint `ec21d27f0` — 77 files, +4536/−432. The substantive ones:

| Area | Fix |
|---|---|
| **SSRF / NAT64** | `embedded_ipv4()` now recognises RFC 6052 `64:ff9b::/96` and RFC 8215 `64:ff9b:1::/48` in both `busbar-kernel-egress/src/trust/net.rs` and `busbar-kernel/src/net_guard.rs`. Red proof: `resolve_and_pin` actually pinned `64:ff9b:1:fffe::a9fe:a9fe` — a DNS64-synthesised IMDS address walking straight through the cloud-metadata guard. |
| **Plugin host ABI** | `HostCtx` became `#[repr(C)] { ptr, generation: u32, kind: u8 }` with a `HostGeneration` RAII guard and a `LIVE_GENERATIONS` thread-local, so a stale host handle is detected rather than dereferenced. `ABI_MINOR` 20 → 21. |
| **Ledger** | `redeem_plane_token` defaulted to `Ok(true)` — fail-open on a token redemption. Now `Ok(false)`. `list_keys_since` gained the `k.revision == 0` arm it was missing. |
| **Secrets** | `MAX_SECRET_FILE_BYTES` = 1 MiB with `read_secret_file_bounded` using `Read::take(cap+1)`; an unbounded read was previously possible. |
| **OAuth2** | `percent_decode` now decodes over bytes instead of slicing a `&str` by index — a `%` before a multibyte character panicked an unauthenticated path. |
| **Substrate** | `busbar-substrate-values/src/proto.rs` declaration lookup compared by pointer identity first, then by value, instead of only one. |
| **Streaming codec** | Exact `rate=` token match (`.contains("rate=16000")` also matched `rate=160000`); usage falls back to stated totals; tool payload object-wrapped; `push_call_args` now replaces only when the held buffer is empty or the fragment extends it. |
| **Ceiling gate** | `INTEGRATION_REF` repointed from the renamed-away `origin/integration/oracle-phase0` to `origin/predev`, and an unresolvable base is now **RED** instead of silently falling back to `HEAD~1`. That fallback meant `ceiling-rose` had been measuring one commit rather than the branch — **it surfaced 147 hidden ceiling rises.** |
| **Done oracle** | `scripts/verify-1.6.0-done.sh` declared 21 groups while 22 `begin_group` blocks existed, so `floor_is_honest` refused to score **anything**. Now 22, `--selftest` green, with 12 environment refusals including `SKIP_BOOT_LEG` and the four `BUSBAR_ORACLE_*` vars it previously did not assert. |
| **Cost** | `scripts/cost-watch.py` + `.github/workflows/sched-cost-watch.yml` built from nothing, implementing #78's exit-code contract with a self-test. |

## Branch harvest — method and result

Patch-id is useless here: the rename waves moved every path, so identical work has a different
patch-id on every branch. **Symbols survive renames.** For each branch the method is: extract the
identifiers, string literals and test names it *adds* versus its merge-base, then grep the enriched
trunk for each one. Code paths and doc paths are indexed **separately** — a doc claiming "Landed"
otherwise masks absent code.

This method is what caught the NAT64 loss, where `git grep -l 'ff9b'` returned only `Cargo.lock`.

Buckets: **empty** (no source content the trunk lacks) · **harvested** (all unique symbols found in
trunk) · **survivor** (symbols absent — review and port with path translation).

Two traps worth knowing before trusting any harvest row:
- `git grep -E` does **not** honour `\b`. Extended-regex mode silently returns zero matches for a
  word-boundary pattern. Use `-P`. This single flag was the difference between 969 and 57,701 indexed
  symbols.
- **Never grep a concatenated "trunk blob".** One worker built a blob with `git archive | tar -xO`,
  got a silently-truncated file, and reported a critical SSRF vulnerability that did not exist. Query
  git directly, every time. A false security finding is worse than a missed one.

## THE LOST REGISTER — what the branch harvest recovered

The deep review read ~625 survivor branches across 12 slices, asking one question per branch:
*does the FUNCTION this branch added exist in the current tree, under any name?* Verdicts:
**RENAMED** (present, moved) · **DEAD** (a decision killed it) · **LOST** (gone, and wanted) ·
**UNCLEAR** (say so, never guess).

**Roughly 75–80% RENAMED.** The rename waves genuinely carried the work; the fear that the
consolidation had silently dropped whole subsystems was mostly unfounded. What follows is the
minority that did not survive, ranked by consequence. Each line is evidence-backed against trunk,
not inferred from a missing symbol name.

### FIXED IN THIS SESSION

| What | Where | Commit |
|---|---|---|
| NAT64 embedding unjudged by the **host-string** SSRF guards — `ssrf_blocked_host` guards OAuth token endpoints and MCP tool-call ARGUMENT hosts, so a caller could pass `64:ff9b::a9fe:a9fe` as a literal and reach IMDS with no DNS involved | `net_guard.rs` ×3, `trust/net.rs` ×3 | `a6fe1018b` |
| **MCP confused deputy** — an upstream naming `tools/call` on the response leg had it minted as a real unit and run under the ORIGINAL CALLER's identity, budget and approval grant. Ingress had the check; egress did not | `busbar-plane-mcp/src/plane.rs` | `489b63ab1` |
| `NANOS_PER_CENT` declared **five** times; the admit-vs-bill pair (`price.rs` sizes the hold that gates admission, the ledger bills) could drift | root ×2 (compile-time assert), budget (re-export) | `a1019f041`, `489b63ab1` |
| Served request path reported **zero `WrapSetup`** profiler samples, while the design doc claimed the fix had "Landed" | `unit/route.rs` | `74e0b1770` |

### OPEN — SECURITY, exploitable

1. **MCP task-answer merge bypasses the argument guard.** `mcp/tasks.rs::merge_answers` (:923)
   inserts every caller-supplied key into the tool arguments with no re-screen, and the result goes
   straight to dispatch (:762). The guard ran ONCE, at `create_task`, on the pre-merge arguments. A
   caller passes `url: "https://legit.example.com"`, clears the screen, then `tasks/update` rewrites
   it to `http://169.254.169.254/…` — dispatched unscreened. **Same class as the SSRF fix above, via
   a different door.**
2. **MCP server→busbar direction has no sender mirror** (second instance, distinct from the one
   fixed): `busbar-plane-mcp/src/plane.rs` client-path guard exists, server path re-checked.
3. **Rotate-replay-key idempotency collision.** `busbar-admin/src/keys.rs:1490` builds its
   idempotency cache key by colon-joining two caller-controlled strings; a crafted pair collides and
   a caller is served **a different key's freshly-rotated secret**. A correctly-built sibling exists
   at `verbs.rs:92` — the router calls the wrong one.
4. **Auth-cache revocation bypass.** `busbar-kernel/src/auth/mod.rs::run_chain_cached` re-`put`s on
   a cache HIT, resetting the TTL, so a revoked credential presented faster than its TTL is never
   re-checked. The correct implementation exists at `busbar-kernel-identity/src/chain.rs:198-220`
   and was never ported to the file actually wired to admission.
5. **Unauthenticated A2A push route has no rate limit.** `busbar-a2a/src/a2a/pushback.rs` has MAC +
   replay + size hardening but no bound on volume; a valid token holder can spam durable hash-chain
   writes and outbound webhook deliveries.
6. **Unbounded MCP tool name into the audit chain.** `mcp/method.rs::tools_call` writes
   caller-supplied `params.name` verbatim into a durable chain row with no length bound.
7. **Credential plaintext in `Debug` + no zeroize.** `busbar-kernel/src/arena.rs::CredentialSlab`
   derives `Debug` over raw client credentials and `clear()` is a bare `Vec::clear()`. Named in #53's
   own top-risk list.
8. **mTLS material not retired on config reload.** `plane_host/identity.rs` admits in its own doc
   that it carries no config-generation tag (FIFO-256 cap only); `trust_anchor.rs` has no eviction
   at all. A revoked identity stays live indefinitely at realistic scale.

### OPEN — INTEGRITY (audit / money)

9. **Admin audit-chain digest collision.** `legacy/chain.rs` joins fields with a raw unescaped `|`;
   `resource` carries untrusted upstream text (`units_mcp.rs:1537` interpolates an MCP tool name).
   A `|` in that name shifts every later field boundary, so a REJECTED mutation's digest can collide
   with an APPLIED one's and the chain still "verifies". **Trunk's own `digest_framing_tests.rs`
   already proves a collision pair exists.** PARKED — the fix changes sealed bytes, owner's call
   (recommendation: versioned scheme tag, old records verify under scheme 1).
10. **Audit second-writer detection regressed.** Legacy `append_audit`
    (`store-memory/src/lib.rs:716-729`) refused a fork; the new seam's `append_plane_record`
    (`:757-763`) is a blind upsert. Two processes on one store silently overwrite each other's rows.
11. **Audit rows carry `ts: 0`.** `busbar-kernel/src/audit/journal.rs:543` hardcodes it, and
    `purge_plane_records_before` deletes anything older than the cutoff — so the retention window is
    defeated for the entire class.
12. **Transient audit-write failure drops the record.** `plane/auditlog.rs:542` logs and moves on;
    the old backfill/`durable_high` watermark is gone.
13. **SSRF-blocked call recorded as "dispatched".** `mcp/client/issue.rs:211` maps
    `TransportError::Refused` — the guard stopping the call BEFORE any socket opens — to
    `OUTCOME_DISPATCHED`. The audit chain tells an investigator busbar sent something it never sent.
14. **`rate_card_version: 0` hardcoded** at six sites across `units_mcp/voice/a2a` — violates #44's
    pricing-provenance requirement.
15. **Flat fee silently zero.** `cost/rate.rs:338 per_request_fee()` returns `0` for a currency the
    card doesn't name a fee in. #42 says an unpriced class REFUSES, never silently zeroes.
16. **Third un-clamped rate conversion.** `busbar-kernel/src/cost.rs::RateNanos::from_raw` lacks the
    u64 overflow clamp its canonical sibling has — a config typo saturates to an astronomical charge.
17. **Root ledger book hardcodes `NullShipper`** (`root/durability.rs:701-711`) — never persists,
    whatever the config says.
18. **Durable spend double-counted on shutdown** — `main.rs` flush sites race the spawned flusher.

### OPEN — DURABILITY / AVAILABILITY

19. **TLS `close_notify` has no timeout.** `busbar-transport-tls/src/lib.rs:856-872` calls
    `w.shutdown().await` unbounded; the 250ms `CLOSE_NOTIFY_BUDGET` is gone. A peer that never ACKs
    hangs the task.
20. **WS close reason discarded** — `busbar-transport-ws/src/transport.rs:761` always sends bare
    `Close(None)` despite an unchanged `CloseReason` enum.
21. **Raw TCP connect unbounded** (only the handshake is bounded); WS read pump has no close wakeup.
22. **`"id": null` misread as a notification** — `mcp/client/peer.rs:231` filters null, violating
    JSON-RPC 2.0 §4. Any peer whose encoder spells an absent id as explicit null hangs.
23. **Cohere token counts silently zero** — `llm-codec/src/cohere/reader.rs` uses
    `.as_u64().unwrap_or(0)` on values Cohere specs as JSON floats. A float count bills as zero.
24. **`InFlight::insert` overwrites a duplicate key** instead of refusing — orphans a `HoldCell` and
    permanently inflates the in-flight count.
25. **Plain container image cannot dlopen a plugin.** Not a missing feature — a REGRESSION: the
    Dockerfile once carried `COPY plugins/${TARGETARCH}/lib/ /lib/`, a commit removed it as
    collateral damage while CI kept building and staging those libs. Fix in flight.

### OPEN — CORRECTNESS / OBSERVABILITY

26. Verify's sealed `VerifiedDestination` set never reaches Route/Meter — Route re-derives its own,
    a verify-then-act inconsistency (`teller.rs`).
27. SNI compared byte-wise, not case-insensitively — `registry.rs::transport_overlaps` can clear two
    genuinely overlapping claims.
28. Voice tool-call refusal silently dropped with no client notification
    (`busbar-voice/src/runtime/session.rs:421`).
29. `voice_build` mounts nothing instead of refusing boot when `public_url` is absent.
30. gRPC `MESSAGE_MAX_BYTES_KEY` entirely unwired; HTTP egress doesn't refuse TE+Content-Length
    (the ingress twin does); SSE drops legal bare-field lines.
31. Four xtask/CI-tooling bugs: no child-process timeout, a YAML block-scalar panic on multibyte
    input, a TSV `splitn(4)` that corrupts real 6-column rows, and an unreadable directory read as
    silently empty.

### DELIBERATE — do NOT "restore" these

`contract-kinds` (an 8-kind proposal; `PLUGIN-TREE.md` records it as rejected — the answer is 7,
per #3) · the `Kind::Control`/`Kind::Dialect` families (D36/D37, cancelled) · `AdminSurface` ·
the `units_*_leg.rs`/`plane_mount.rs` shape (#28 chose the gauntlet-kernel-rider design) · the whole
`Arena` fixed-cap model (#41). These appear as survivors because their symbols are absent from
trunk. Absent because they were **decided against**.

## Branch collapse — where it actually stands, and the 39 that matter

**817 remote branches.** Git-provable deletion is EXHAUSTED: 38 provable ancestors were deleted, and
a scan for branches whose source tree under `crates/ xtask/ scripts/ conformance/ testing/` is
already byte-identical to trunk's returned **zero**. So every remaining branch differs in source and
no further deletion can be justified by git alone — the rest needs the content proof.

**83 branches have been adjudicated** by symbol-harvest (extract the identifiers, string literals
and test names a branch ADDS vs its merge-base, then grep the enriched trunk for each — patch-id is
useless here because the rename waves moved every path, but symbols survive a rename). Verdicts:

| Verdict | Count | Meaning |
|---|---|---|
| `survivor` | **43 (≈39 unique)** | symbols absent from trunk — **may hold code the trunk does not have** |
| `harvested` | 39 | every unique symbol found in trunk, superseded under reworded names |
| `empty` | 1 | no source content the trunk lacks |

**The 39 survivors are the point, not the 40 deletions.** Deleting branches saves nothing — there is
no `on: delete` trigger, so keeping them costs zero job-minutes. Losing code costs everything. The
survivor list includes `r5-money-m3` (money), `r5-auth-resolvedkey` (auth), seven
`codeaudit-fix/transport-*` branches, and `integration/reland`, which the safety-net pass found to be
**reachable from no other ref at all**.

The adjudication record — one row per branch with its sha, merge-base date, verdict and the evidence
behind it — is preserved at **`~/Downloads/busbar-branch-harvest-ledger-2026-09-21.tsv`**, beside the
all-refs bundle. It was produced in `~/Developer/tmp/harvest-ledger/`, which is not durable; if that
directory is cleared, the copy in `~/Downloads` is the record.

## Conformance is the LAST gate, not a task — measured 2026-09-21

`cargo xtask conformance check --musts` is RED with **17 rows**, and the split matters more than the
count, because it changes when the work can be done at all.

**10 suites are STALE, not failing.** `llm-{anthropic,bedrock,cohere,gemini,openai,responses}`,
`mcp`, `voice-gemini-live`, `voice-openai-realtime` and one more all hold a real **pass** recorded at
commit `67ee79103050`. They are refused for one reason: the verdict commit does not equal the
candidate sha, and a pass is honoured only if its commit IS the release sha.

**Therefore re-running them now is pure waste**, and would be the exact "spend that buys nothing"
the cost brief warns about. The next commit invalidates every fresh verdict immediately, and the six
LLM suites exercise real provider surfaces. A verdict with a shelf life of one commit is not worth
paying for. **These run once, on the frozen candidate, immediately before turnstile — and nowhere
else.** Any plan that lists "make conformance green" as a mid-flight task is wrong by construction.

**7 suites have genuinely never run**, and these ARE buildable now because they are about missing
capability rather than staleness:

| Suite | State |
|---|---|
| `ws` | Autobahn leg not wired — **currently zero coverage** |
| `tls` | testssl leg not green |
| `h2spec` | HTTP/2 leg not green |
| `slsa-verifier` | not wired as an arm-or-red verdict |
| `oidf-oauth2` | self-hosted OIDF leg not green. The claim is "passes the suite", **never** "certified" (owner ruling 2026-09-19) |
| `jev` | decisions-plane wiring in flight (#48) |

These seven are the real conformance work for 1.6.0. `ws` is the most glaring — a release whose
fourth plane is streaming, carrying a WebSocket transport, with zero Autobahn coverage.

## Unattended wave, 2026-09-21 night — what landed

Twenty commits. Every fix below was red-before-green with the failing output captured, and every one
was verified by re-running the suite myself rather than trusting the agent's report.

**Money — the serious one.** `serde_json`'s `as_u64()` returns `None` for a float-backed number, so
the house idiom `.as_u64().unwrap_or(0)` recorded a real count as **zero** for any provider that
spells counts as floats. Present in all six dialects; **shipped in v1.5.5**. One canonical reader
now serves the whole crate, and a non-vacuous source-scan guard stops the seventh dialect
reinventing it. Gemini was the worst case: its usage is an additive sum, so one float term
contributed zero to a total that still looked plausible (read 89, should have been 172). **Parked
for the owner, not self-approved** — see the PARK section. Second money item also parked: whether a
rate-card edit reprices history.

**Security and integrity.**

| Fix | What it actually allowed |
|---|---|
| admin key-rotate idempotency key | A crafted `(id, header)` pair was served **another caller's cached rotate response**, token material included, without ever holding a valid id |
| audit digest framing | Two materially different audit facts hashed identically — a rejected entry and an applied one could collide by shaping their own fields |
| auth cache re-put on hit | A credential under steady traffic **never expired**, so revoking it did nothing for as long as it kept being used |
| `CredentialSlab` Debug + clear | Credentials printed in the clear by any formatter, and left readable in spare capacity after release |
| Twilio empty `streamSid` | An empty id bound vacuously, so the anti-forgery check compared empty to empty and admitted frames from anyone |
| Twilio media format | Never validated, so a mismatched format was decoded **and timed** wrongly — and duration is a ledger quantity |
| MCP `"id": null` | A request with an explicit null id was read as a notification and never answered — caller hangs forever |
| MCP token exchange | No byte cap; an upstream could stream an unbounded body into memory |
| A2A push route | No volume bound: one token, unbounded durable audit writes and outbound webhooks — busbar as an amplifier |
| `InFlight::insert` | Overwrote a duplicate key, orphaning a hold so its budget stayed reserved forever |
| SNI case comparison | Two overlapping transport claims judged disjoint, so boot cleared a config with two listeners on one name |
| plane-record fork | A second writer silently overwrote a chained record and the store said nothing |
| journal `ts: 0` | Every scoped row looked infinitely old, so retention deleted it immediately |
| three transport hangs | TLS close, and TCP connect at two sites, could park indefinitely |

**Verify→Route seam.** Verify sealed a destination set and dropped it; Route re-derived its own. The
sealed set is now threaded through Route and Meter, so what was checked is provably what was used.
No quantity or arithmetic changed — the trait signatures did, so all six implementors in the binary
were updated.

**Release engine.** `gate-mutants` removed from `qa` and `main` required checks (it was required
while disabled — neither branch could ever go green). The turnstile bridge landed, deliberately
`workflow_dispatch`-only rather than repointed to `predev`. Both detailed in Part 6.

### One process failure, stated plainly

Commit `1772c74706`, whose subject is only `refactor(#41): ArenaExhausted -> ScratchExhausted`,
swept up **three different agents' uncommitted work**: the Cohere billing fix, the auth-cache
revocation fix, and the arena→mask rename. A blanket `git add` ran while agents held the same
working tree. The bytes are correct and the trail is recorded in `1b6c9d4ba`, but a billing change
sitting inside a rename commit is exactly what an auditor fails. Every commit after that point
stages explicit paths and deliberately leaves files belonging to still-running agents alone. **The
habit is the defect, not the one commit.**

## THE CRATE ROSTER — OWNER-LOCKED 2026-09-22, 35 crates

**This supersedes every earlier count in this document.** It is the owner's own roster, recovered
verbatim from the 2026-09-20 transcript where he pasted it himself, re-presented to him on
2026-09-22 and locked: *"OTHER than substrate I agree 100% so keep it and figure it out later"* →
*"lock it in"*.

| # | Group | n | Crates |
|---|---|---|---|
| 1 | Binary | 1 | `busbar` |
| 2–10 | Engine | 9 | `busbar-kernel` + `-identity` `-scope` `-budget` `-ledger` `-egress` `-breaker` `-wal` `-audit` |
| 11–13 | Core | 3 | `busbar-core-admin` · `busbar-core-oauth2` · `busbar-core-substrate` |
| 14–16 | Contract + machinery | 3 | `busbar-contract` · `busbar-plugin-sdk` · `busbar-plugin-loader` |
| 17–21 | Planes | 5 | `busbar-plane-llm` `-mcp` `-a2a` `-streaming` `-decision` |
| 22–28 | Transports | 7 | `busbar-transport-grpc` `-http` `-sse` `-stdio` `-tcp` `-tls` `-ws` |
| 29–35 | Compiled-in plugin instances | 7 | `busbar-store-memory` · `busbar-auth-static` · `busbar-hook-ranking` · `busbar-export-{prometheus,webhook,file,otlp}` |

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

**4. `busbar-core-substrate` is KEPT, with an open question the owner deliberately left open.**
His words: *"OTHER than substrate I agree 100% so keep it and figure it out later."* He has now
questioned it three separate times — *"what is busbar-core-substrate? it feels off"*, *"these two
smell still but you even say they may dissolve… Post-drain it may be a near-empty shell that folds
into kernel, or a real foundation crate. Fire the measure agent?"*, and again on 2026-09-22. The
measure was never run. It is in the roster; whether it survives the drain is not settled.

### ONE DISCREPANCY, FLAGGED NOT RESOLVED

The owner's 2026-09-20 paste listed **4 planes**. Earlier on 2026-09-22 he said
*"busbar-plane-llm, -mcp, -a2a, -streaming, -decision AGREED"*, and #48 makes `decision` (jev) the
fifth plane. This roster carries **5** on the strength of that later explicit agreement, which is why
the total reads 35 rather than 34. **If the decisions plane is not a 1.6.0 crate, this roster is 34
and row 21 comes out.**

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

**58 crates on disk today; 35 is the target, so 23 still go.** The `-host` crates and
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

### #40 IS VIOLATED BY SEVEN CRATES, AND ONE OF THEM IS THE MONEY BOOK

**#40 says the plugin dependency closure is `busbar-contract` and nothing else.** Measured with
`cargo tree -p busbar-auth-static-plugin --edges normal`, a real plugin's actual closure is **seven**
busbar crates:

```
busbar-api · busbar-contract · busbar-grammar · busbar-kernel-ledger
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

Until that lands, **#40 cannot be claimed as satisfied**, and the neatest single step toward it is
the `busbar-grammar` fold below — necessary, but nowhere near sufficient.

### #40 is also violated by grammar — and that fix is a roster fold

**#40 states the plugin dependency closure is `busbar-contract` and nothing else.** Measured, it is
not: `busbar-contract/Cargo.toml` depends on `busbar-grammar`, so every plugin compiling against the
contract drags a second busbar crate into its closure. Grammar types also surface through contract's
own ABI files (`src/bounded.rs`, `src/spans.rs`), so this is not a private implementation detail
hiding behind the seam.

`busbar-grammar` is 568 lines in a single `lib.rs` whose only dependency is `serde`, named by seven
files in total. Folding it into `busbar-contract` as a module satisfies #40 exactly **and** removes a
crate from the roster — the same move answers an architectural invariant and a count.

Two things to carry through the fold rather than lose:
- `busbar-grammar/tests/{adversarial,json_scanner,mutation_hardening}.rs` are adversarial and
  mutation-hardening tests **on a parser**. They must be re-homed, not dropped. Parser hardening
  tests are exactly the coverage that disappears quietly in a crate move.
- `busbar-mcp-codec` does not currently depend on `busbar-contract` and will have to. That is
  acceptable — contract is the universal base — but it is a real dependency addition, not a no-op.

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

## The audit ledger has a fold-shaped blind spot — do not blind-run `ledger sync --write`

`cargo xtask gate audit-ledger` is RED on `missing-scopes`, naming five paths the tree implies and
the register does not carry: `crates/busbar-plane-decision/src` (+ its two test dirs),
`crates/busbar-a2a/src/tests` (new, from the `-host` fold) and `testing/ws-conformance` (new, from
the ws subject becoming a workspace member).

The gate prints its own remediation, `cargo xtask ledger sync --write`. **Running that blind would
quietly destroy audit coverage,** and the roster fold makes this worse every time it runs.

A dry run shows sync would DELETE ~19 records for "path gone from the tree", including
`crates/busbar-plane-{a2a,mcp}-host/src/tests`, `crates/busbar-grammar/tests`,
`crates/busbar-core/**`, `crates/busbar-substrate/**` and `crates/busbar-contract-transport/**`.

**But that code did not vanish — it MOVED.** The `-host` tests are now under `busbar-mcp` and
`busbar-a2a`; grammar's are heading into `busbar-contract`; core and substrate drained into the
kernel-8. So the sequence is:

1. a fold moves audited code into a new scope,
2. the gate flags the new scope as missing,
3. `sync --write` adds the new scope **unaudited** and deletes the old scope's **audit record**,
4. the gate goes green.

Net effect: **audited code is laundered into an unaudited scope, and the gate reports success.** The
ledger's purpose is to make "has this been audited" answerable, and a fold is precisely the operation
that should CARRY an audit forward rather than drop it.

The gate only checks for MISSING scopes. It has no rule for "this scope's code moved somewhere that
is now unaudited", which is the exact shape of the 61→28 roster collapse — so the collapse can silently
zero the audit coverage of the whole tree, one honest-looking green at a time.

**Held deliberately.** The sync is not run until the roster folds settle, and when it is run the
moved scopes need their audit records CARRIED to the new path, not deleted. That is a change to how
`ledger sync` treats a rename-or-fold, not a one-off bookkeeping step.

## Survivor review — transport hardening that was audited, then lost

Seven `codeaudit-fix/transport-*` branches reviewed against trunk. **Six are LOST, one superseded.**
These came from a code audit, so they are disproportionately real hardening — bounds, refusals,
parser limits — and that is exactly the class that goes missing quietly and is noticed only when
exploited. Ranked:

**HIGH — grpc silently ignores the operator's configured message cap.**
`busbar-transport-grpc/src/codec.rs:24` hardcodes `MAX_MESSAGE_BYTES = 4 MiB` and applies it
unconditionally at `client.rs:123` and `server.rs:130`. `busbar-transport-ws` DOES read the operator
key `limits.request_body_max_bytes` (`transport.rs:110`); grpc has zero references to it. So an
operator who sets that key expecting it to bound every transport gets a grpc listener still accepting
4 MiB per message — a silently-larger attack surface on a deployment they believe is capped. The
inconsistency is the danger: the knob works where you test it and not where you don't.

**MEDIUM — the http egress forwards a request-smuggling shape instead of refusing it.**
`busbar-transport-http/src/lib.rs:1470` `complete_message()` refuses a non-chunked
`Transfer-Encoding` but NOT the chunked-body + `Content-Length` co-presence case — which the INGRESS
reader already refuses. It de-chunks, rebuilds with both framing headers stripped, and forwards a
quietly-disambiguated message downstream. Two headers naming two different lengths for one body is
the canonical smuggling primitive; resolving the ambiguity and passing it on is worse than refusing,
because the next hop may resolve it the other way.

**MEDIUM — a TLS truncation attack is indistinguishable from a clean close.**
`busbar-transport-tls/src/lib.rs:387-392` `map_session_err` has no `io::ErrorKind::UnexpectedEof`
arm, so it falls through to `TransportError::Closed` — the identical value an orderly
`close_notify` shutdown produces. A peer that drops the TCP stream mid-session is reported exactly
like an honest close, erasing the one signal that distinguishes "the exchange finished" from "it was
cut off, possibly hiding truncated content." One match arm.

**LOW — billing-honesty test coverage exists for 2 of 7 transports.**
`frame_meta_honesty_catches_inflating_and_deflating_fixtures` exists only in
`busbar-transport-sse` and `busbar-transport-tcp`. grpc, http, stdio, tls and ws have no red-capable
fixture proving `FrameMeta.bytes` — **a billing figure** — cannot drift from the real payload size.
A metering bug in any of those five would ship undetected. Given tonight's float-count defect, a
money quantity with no red-capable test in five of seven transports deserves more weight than "LOW"
suggests.

**LOW — two SSE parsing edge cases.** `proto.rs:110,127`: `SSE_FIELDS` is colon-suffixed and matched
with `starts_with`, so a legal bare field-name line is dropped as a comment while `datastream:` is
wrongly admitted as a field; `proto.rs:153` over-trims `event_type` where the grammar strips only one
leading space.

**Superseded:** `transport-ws` (base) — its PoisonGuard fence, `with_max_message_bytes` and the loud
panic on concurrent `frames()` are all landed verbatim.

**On Autobahn, answered explicitly:** `transport-conformance-skeleton` does NOT hold an Autobahn
harness. Its `tests/conformance.rs` is a trait-shape battery and never mentions Autobahn or fuzzing.
The real harness is `testing/ws-conformance/`, now buildable but still with **zero coverage and no
verdict** — closing that needs a real Docker run, not a branch revival.

## SECURITY — every TLS private-key read in production is UNAUDITED

**Found by the survivor review of `origin/queue-rebased-A3plus`, verified directly.** The audit seam
for secret access is fully built, unit-tested, and **connected to nothing**.

- `AccessJournal` / `AccessPurpose` exist in `crates/busbar-unit-transport-key/src/lib.rs:67,90` —
  an audit trail meant to record every read of TLS/secret key material.
- `busbar_kernel::teller::transport_key_token()` is the capability token required to call
  `provision_server`/`provision_servers`. `git grep -n transport_key_token` finds it in **exactly
  two files: its own definition, and `crates/busbar/src/root/tests/transports.rs`.** Zero
  production callers.
- Trunk's own doc comment says so in the present tense (`teller.rs:141-145`): *"without this the
  unit's `provision_server` and `provision_client` have a parameter no caller in the tree can
  supply, **which is why the only thing that ever registered a listener's TLS config was the
  transport's own tests**."*
- The REAL serving path — `main.rs`'s `serve_listener` → `busbar_core_transport::prepare` →
  `build_server_config` (`busbar-core-transport/src/lib.rs:291,149`) — resolves secrets straight
  through `SecretResolver`. `git grep -c "AccessJournal\|record_access"` on that file → **0**.

### Why this one stings

It contradicts an explicit owner ruling. From the design session: *"that way we lock down plugins
cant touch secretes and **kernel is in charge of auditing secrets already**."* The kernel is supposed
to be the one auditing every secret read — that is the justification for taking secret handling away
from the transport plugin at all. On the live TLS path it audits nothing.

So the property holds on paper (the seam exists), holds in tests (they mint the token), and does not
hold in production (nothing mints it). That is the most dangerous shape a security control can take:
it looks present to a reader, passes its own tests, and is absent where it matters.

### The fix

`origin/queue-rebased-A3plus` wires it: mint `transport_key_token()` at boot, construct a
`BookAccessJournal` (one `Access`-class WAL entry per secret read), and call `provision_servers(...)`.
The symbol is absent from trunk AND from `origin/integration/reland`. Every seam it binds to —
`AccessJournal`, `SecretSource`, `transport_key_token` — already exists on trunk in the same shape,
so this is a port, not a re-implementation. Its posture on failure (warn, not refuse boot) matches
trunk's existing fail-open stance on that slot.

**Note the interaction with the owner's secret ruling:** `busbar-transport-key` was killed as a crate
precisely because *"plugins can never touch secrets"* and secret handling is kernel-side. Wiring the
journal is the other half of that ruling — the half that makes the kernel actually audit what it took
custody of.

## PARKED (money) — a second, ungated shutdown flush may double-count

**Found by the survivor review of `origin/integration/reland` (B13). Not self-approved — it is
billed bytes.**

`spawn_budget_flusher` (`busbar-kernel/src/governance/mod.rs:1211-1268`) now shares one internal
`flush_gate` mutex between its periodic tick and its own shutdown arm, via `tokio::select!` on the
shutdown broadcast. That is a cleaner design than the branch's external `FlushGate` and closes the
race **within that task**.

But `crates/busbar/src/main.rs` still calls `gov.flush_budgets()` / `gov.flush_metering()` a
**second, independent, ungated time** in two places:

- the `--mcp-stdio` exit path (`main.rs:1622-1627`), which never sends on `shutdown_tx` at all — so
  the periodic flusher is **still ticking** while this inline flush runs;
- the listener shutdown tail (`main.rs:1717-1723`), whose own comment explains the intent: *"The
  background flusher's shutdown arm also flushes, but it is a fire-and-forget task that could lose
  the race with process exit; flushing inline here… guarantees durability."*

`flush_budgets` does clear each cell's `dirty` flag under a per-shard write lock **before** the
durable write, which defeats the crude case of two overlapping calls re-snapshotting identical state.
It does not defeat a narrower interleaving: call A snapshots and clears dirty → a new charge lands and
re-marks the cell dirty → call B snapshots that cell against **A's still-un-advanced `flushed_*`
baseline** → B's delta double-counts A's in-flight portion.

Narrower than the original bug, but real, and it is money. The obvious resolution is to route the two
inline shutdown flushes through the same gate `spawn_budget_flusher` already holds — but that changes
shutdown durability semantics on a money path, which is the owner's call, not mine.

## Confirmed and being fixed — three MCP resource-exhaustion bounds

All three were fixed on `integration/reland` and never merged; all three re-confirmed present today.

| Gap | Where | What it allows |
|---|---|---|
| no `MAX_TASK_ANSWERS` | `mcp/tasks.rs:307-311` | `deliver` does an unconditional insert per key. `MAX_RETAINED_TASKS` bounds the number of TASKS, nothing bounds answer keys **within one task** — a caller parked in `input_required` invents fresh keys forever |
| no `MAX_SUBSCRIBED_URIS` | `mcp/subscribe.rs` | no cap and **no dedup** on the URI list a `subscriptions/listen` may name; a repeated URI is both a memory multiplier and a duplicate-delivery multiplier |
| no `MAX_TOOL_NAME_BYTES` | `mcp/method.rs:1257-1273` | **the worst.** `tools_call` opens `CallLog::open(ctx, name, …)` with the caller's raw `params.name` **before any length check**, and that name is written verbatim into `McpCallRecord` — a durable per-call **hash-chain** row. Every refused call grows the durable store by an attacker-chosen amount, permanently, in a structure that participates in chain verification |

The ordering is the fix for the third: bound the name, then open the log — never the reverse. All
three refuse rather than truncate, because a truncated tool name is a different tool name.

## CORRECTION — the A2A grant gap is REAL but NOT REACHABLE. I overstated it.

**I recorded this as a live horizontal privilege escalation. That was wrong, and the error was mine:
I verified the missing check but never verified that the function is reachable.** A second
independent review caught it.

`crates/busbar/src/root/units_a2a.rs::approve()` genuinely lacks the per-agent `scope_allowed`
check — that part stands, and `git grep -c scope_allowed` on the file is still 0. But the module is
named from `crates/busbar/src/main.rs` at **exactly one line (960)**, and only to install scope
entries via `scope_policy(...)`. The code says so itself:

> *"It diverts no byte: the serving path is still the one `register_planes` mounted, which is why the
> conformance battery and the neutrality cells read identically with this on and with it off."*

The **actual** served A2A path is `crates/busbar-a2a/src/a2a/{inbound,receive,registry,serve}.rs`,
and every one of those independently calls `scope_allowed("agent", agent_id)`. So no caller today
reaches the unguarded `approve`, and **no key can reach an agent it was not granted.**

**Severity corrected: not exploitable. It is a latent landmine, not an open door.**

Still worth fixing, for one specific reason: `units_a2a.rs` exists to become a serving path. The
moment it is wired up — which is the direction the root-side composition is heading — the gap
becomes live, and it will be wired up by someone who reasonably assumes the approve step already
authorizes what it is approving. A dormant file with a missing authorization check is a trap laid for
a future change, so the check lands now while the cost is four tests.

### The original finding, retained for the record

### SECURITY — root's A2A leg authorizes the OPERATION but never the AGENT

**Found by the survivor review of `origin/wip/mount-chain-auth-bindings`, and verified directly.**

`crates/busbar/src/root/units_a2a.rs:1173`, `fn approve`, does exactly two checks:

1. `required_scope(CLAIM_A2A, op, scope_policy)` — what scope does this OPERATION need
2. `busbar_kernel_scope::approve(self.grants, needed)` — does the key hold it

Then it proceeds. `self.draft.resource` — the agent being addressed — is read and pushed into
`ScopeFacts`, and the code's own comment says why: *"the resource travels with the approval so the
record names the agent rather than the method."* **It is used for the audit record only. It is never
checked against the key's grant.**

`git grep -cP '\bscope_allowed\b' crates/busbar/src/root/units_a2a.rs` → **0**.

Every sibling that fronts a named resource DOES enforce it — `busbar-a2a/src/a2a/{inbound,receive,
registry,serve}.rs` each ask `scope_allowed("agent", agent_id)`: *"may this key invoke THIS fronted
agent?"* — as do `busbar-voice/src/mount.rs:106`, `busbar-llm/src/unit/verify.rs:300`,
`busbar-kernel/src/plane_host/dispatch.rs:281`, `trust/validate.rs:324` and
`egress_auth/gate.rs:187`. **Root's own A2A leg is the sole exception.**

### What it allows

Any key holding only the operation-class grant — "may send tasks at all" — reaches **every agent the
deployment fronts** through root's leg, regardless of which agent it was actually granted. Two keys
of identical operation-class standing are indistinguishable at this door. That is horizontal
privilege escalation between tenants of the same busbar, and the audit record will faithfully name
the agent that was reached, making it look authorized.

### It has been fixed three times and never landed

The branch commit is itself a `(cherry picked from commit 33cbf492…)`. That source commit exists in
the repo, `git merge-base --is-ancestor 33cbf492 HEAD` returns **false**, and it is reachable from
two further stale branches (`delete/keep-a2a-default-on`, `delete/keep-a2a-on-mount`). So the same
fix was written at least three separate times and lost each time — which is exactly the argument for
having run the survivor review rather than deleting the branches.

### Scope of the fix

Small and isolated: add the `scope_allowed(resource.kind, resource.name)` check beside the existing
operation check, plus the four regression tests the branch carried — all four confirmed absent from
trunk by name. The surrounding architecture is unchanged, so it re-lands rather than needing
re-implementation. **Not a billed-byte change**, so it does not need the owner's sign-off — it makes
refusals happen that policy already says should happen.

## CORRECTION — the budget-hydration finding was OVERSTATED. Downgraded, and re-scoped.

**I recorded this as CRITICAL: "every restart zeroes admission spend for llm/mcp/a2a/streaming."
That claim is not supported. I verified the missing hydration and did not verify which admission
path actually gates customer traffic.** A second review caught it. What is actually established:

**VERIFIED, and still true:**
- `busbar-kernel-budget` has **no hydration function at all** — `git grep -P "fn (hydrate|restore|seed|replay)"` over that crate returns nothing.
- `crates/busbar/src/root/kernel.rs:650` and `units_voice.rs:797` both build `InMemoryCells::new()` empty.
- Both the struct doc and `busbar-kernel-budget/Cargo.toml` claim the cells are "hydrated once at boot". That claim is false wherever those two constructors are the source.

**VERIFIED, and it undoes the severity:**
- **The main admission path DOES hydrate at boot.** `GovState::hydrate_budgets` is called from
  `crates/busbar-kernel/src/appbuild.rs:1158` — production code, not a test. That is the gate
  `ingress/mod.rs` and `plane_host/govern.rs` consult for real traffic.
- **`ProductionUnits.door` is admin-scoped.** It is constructed exactly once in `main.rs:1515` via
  `admin_only_sharing(...)`, mounted on the **admin router** (`root::units_admin::mount`). It is not
  the customer request gate.
- Governance's mechanism is also the **model-compliant** one: it restores raw usage COUNTS and
  re-derives money from the current card at read time, never storing a settled figure. That is
  exactly "money is a view over ledger × ratecard".

**NOT established either way — the one real open question:**
`units_voice.rs:797` builds a `VoiceNode`'s own `Door` empty, and voice IS wired from `main.rs`
(`VoiceNode`, `NodeCalls`, `scope_policy`). Whether that per-node door gates a billing decision, or
is secondary to the governance gate that already hydrates, is **not resolved**. That is the question
worth answering, and it is much narrower than "every plane, every restart".

**Severity: downgraded from CRITICAL to OPEN-AND-NARROW.** No demonstrated cap bypass on the
customer path. A documentation defect is certain — two places assert a hydration guarantee that the
constructors they describe do not provide, which is how this looked like a catastrophe to a reader
(including me).

**Also corrected: the `r5-money-m3` branch fix should NOT be re-landed as written.** Its
`Carried`/`HydratedSpend` stores a **settled cents figure** at boot and accrues onto it. That stores
a price, which the locked model forbids. Trunk's reprice-on-read design is the correct one. The
branch is **OBSOLETE by design on this point**, not lost — a rare case where the un-merged branch is
the wrong answer and trunk is right.

### The original finding, retained for the record

### PARKED — the budget cap is bypassed on every restart (AS ORIGINALLY WRITTEN)

**Found by the survivor-branch review of `origin/r5-money-m3`. This is the single most serious
defect in the session and it is a live budget-cap bypass, not a latent one.**

`ProductionUnits.door` is the admission gate on the real request path for the llm, mcp, a2a and
streaming planes. Its doc comment at `crates/busbar/src/root/kernel.rs:520-521` states:

> *"Its ledger cells are hydrated once, at boot, and are never re-read on the request path."*

**The first half of that sentence is false.** Verified directly:

- `crates/busbar/src/root/kernel.rs:650` — `door: Door::new(InMemoryCells::new())`, constructed EMPTY
- `crates/busbar/src/root/units_voice.rs:797` — a second site, also `InMemoryCells::new()`
- `git grep -P "fn (hydrate|restore|seed|replay)" crates/busbar-kernel-budget/src/` → **no matches.**
  There is no hydration method on `InMemoryCells`, on `CellStore`, or on `Door`. The capability does
  not exist to be called.
- The door is reached on the live path from `units_llm.rs:520`, `units_mcp.rs:914`,
  `units_a2a.rs:1228,1322` and `units_voice.rs:1349,1604`.

`busbar-kernel-budget/Cargo.toml`'s own header repeats the same false claim: *"The cells themselves
are node-local, hydrated once at boot and never re-read on the request path."*

### What it means in money terms

Every process restart zeroes every bucket's admission spend. **A key or group that had fully
exhausted its configured `budget_cap` is fully re-admissible the instant the node restarts**, with no
floor until fresh post-boot traffic re-accrues enough to re-trip the cap. Restarts are routine —
deploys, rolling updates, OOM kills, host maintenance — so a customer can exceed a dollar cap by an
unbounded multiple without doing anything unusual.

Under the locked model this is not the ledger being wrong; the ledger is journaled correctly and
synchronously on every settle. It is the **enforcement gate never reading it back**. The book knows;
the door does not ask.

### Why it was invisible

The documentation asserts the guarantee in two places, so anyone auditing by reading was told the
opposite of the truth. The branch that implemented it — `r5-money-m3`, via `hydrate.rs` — was never
merged, and the symbol-harvest flagged it as a survivor precisely because `hydrate`/`Carried`/
`CarriedSpend` appear nowhere in trunk.

### The owner decision

This is a billed-byte-adjacent change (it makes refusals happen that do not happen today), so it is
not mine to self-approve under #10/#59. But note the asymmetry: **leaving it costs money on every
restart, and fixing it only ever refuses spend that the configured cap already said to refuse.**

Two further findings from the same branch, both real and both lower severity:

- **The audit `Book` is never replayed at boot.** `Ledger::dual_writing` starts with an empty book
  each time (`durability.rs:748-772`), and `journal.replay()` exists but is used only to read the
  migration marker. Every posting IS durably journaled, so the data for exact replay is on-chain and
  simply never read back. This breaks the "ledger sums equal legacy spend" reconciliation identity
  that `durability.rs`'s own module doc states as a release requirement.
- **The book has no retention driver.** `Book::retain_from` and the whole `Checkpoint`/
  `CheckpointAnchor` scaffolding exist with **zero non-test callers**, so the book grows unbounded
  for the life of a node. (In practice the growth resets on restart — which is only true *because*
  of the bug above, so the two defects have been masking each other.)

## PARKED FOR THE OWNER — a billed-byte change I may not self-approve (#10/#59)

**One item. It is the most serious finding of the session and it needs a human call, not because it
is ambiguous but because approving a change to billed bytes is not mine to make.**

### What is wrong

`serde_json::Value::as_u64()` returns `None` for any float-backed JSON number — `27.0` included,
even though it is exactly an integer. The house idiom for reading usage across the LLM dialects is
`.as_u64().unwrap_or(0)`. So when a provider spells a token count as a float, a real count of 27 was
recorded as **zero**. Cohere's real wire responses do exactly this.

Under the locked model this is a **ledger** defect, not a money defect, and that is the worse of the
two. Money is a view over `ledger × ratecard`; it cannot be wrong on its own. If the ledger says the
provider returned nothing, then every view over it faithfully reports nothing, every invoice derived
from it is internally consistent, and the error is invisible at every downstream layer. The read is
the only place it is detectable.

### It is not a 1.6.0 regression — v1.5.5 shipped it

`git grep as_u64 v1.5.5 -- crates/busbar/src/proto/cohere/reader.rs` returns **five sites**
(`416`, `721`, `725`, `970`, `975`), all using the same `.and_then(|v| v.as_u64())`. The defect is in
the released product. The implication is a revenue fact, not an engineering one: **for every
provider that float-encodes usage, shipped busbar has been under-recording work that was actually
performed.** How far back it goes, and whether anything is owed in either direction, is a question
only the owner can answer.

### CORRECTION — I claimed the oracle would go red. Measured, it will not, and that is worse

My first reading was that the golden was recorded by buggy code, so corrected cells would differ and
the oracle would go red — correctly — and clearing it would need an owner re-record.

**Measured against the actual corpus, that is wrong.** Searching every recorded cell and golden for a
float-valued token-count field:

```
grep -rhoE '"[A-Za-z_]*[Tt]okens?[A-Za-z_]*":[[:space:]]*[0-9]+\.[0-9]+' testing/shadow-oracle/
→ (no matches)
```

**There is not one float-encoded count anywhere in the corpus**, even though the corpus does contain
Cohere cells. So:

1. **The fix is oracle-NEUTRAL.** No golden needs re-recording and the oracle will not go red. That
   materially de-risks this item — landing the parse fix does not require an accept-a-difference
   ruling. `accepted-differences.json` is untouched and does not need touching.

2. **But that is precisely why the bug reached production.** The oracle exists to catch money
   divergence, and it recorded only integer-spelled counts — so it was structurally incapable of
   ever seeing this. A provider spelling a count as a float is the single case that mattered, and
   the corpus has zero coverage of it.

**The second point is the more serious finding, and it outlives this bug.** A money oracle with a
blind spot on the money path is worse than a known-red one, because it reports green over the gap.
The corpus needs a cell that records a real float-encoded provider response — otherwise the
regression guard for this defect is a source-scan test in one crate, and nothing at the oracle level
would notice the same class arriving through a different door.

### SECOND PARKED ITEM — does a rate-card edit reprice history?

Found by the bank-auditor walk of all 40 `accepted-differences.json` entries (34 PASS, 1 fixed,
2 parked). Entry **D-3** is **WRONG**, proven empirically rather than by reading code: the
`rate-card-history` oracle scenario was built and run against the current binary, and
`GET /admin/usage` after a mid-window rate-card edit returned `spend_micros: 750090000` — a pure
read-time reprice off the CURRENT card — where the register and a published `CHANGELOG.md` line
both claim `277530000`.

The dated rate-card history engine in `busbar-kernel-ledger` is real and correct. `GET /admin/usage`
was simply never wired to it; `money_book.rs`'s own doc comment admits the seam is "DORMANT".

**This is a policy question, not a bug report, which is why it is parked and not fixed.** Both
answers are consistent with "money is a view over ledger × ratecard" — they differ on *which*
ratecard the view uses:

- **As built:** the view multiplies the ledger by the card in force *now*, so editing a rate
  reprices all history. `derive_spend_cents`' own doc calls this "the operator's rate-card edit
  taking effect retroactively, which is the designed behavior."
- **As the register and CHANGELOG claim:** the view multiplies each ledger row by the card that was
  in force *when that row was written*, so history is immutable once billed.

An auditor would want this stated explicitly, because it decides whether a published invoice can
change after the fact. Nobody but the owner can choose. Rewiring a live billing read path under
audit pressure to satisfy a register entry would be exactly the wrong move, so the register carries
a dated audit note and the code is untouched.

Note this is a multi-crate wiring gap (tracked in-repo as milestone "M6"), not a bounded fix.

### The two parked money items are ONE root cause, and the write side is worse than the read side

D-3 is usually described as "`GET /admin/usage` was never wired to the dated rate-card history".
That is only half of it, and the smaller half.

`PostingStamp` carries a `rate_card_version` field, and it is **hardcoded to `0` at all seven
production posting sites** — `units_a2a.rs:825,1020`, `units_llm.rs:1578`, `units_mcp.rs:1399,1508`,
`units_voice.rs:1840,1944`. The field is real and load-bearing: it is part of the hash-chained audit
amount (`busbar-kernel-audit/src/record.rs:375` digests it), and the migration path honours it
properly (opening balances carry a real version, asserted in tests). Only the LIVE posting path
writes a constant zero.

A real version is available. `busbar-kernel-ledger/src/cost/rate.rs:167` says it outright: *"A card
has no version field. Which card this is, is the number of the history entry that holds it."* The
history engine is `cost/history.rs` and it exists.

**The consequence matters for the owner's decision, and it is not symmetric.** If the ruling is
"history reprices off the current card", the code already does that and only the changelog and
register need retracting. But if the ruling is "each row is priced by the card in force when it was
written", then it cannot be applied to anything already recorded: **every posting ever written says
card version 0**, so the ledger physically cannot say which card priced it. That option is
implementable going forward and **not recoverable backwards**.

So the real question is not only which behaviour is right, but whether the ledger should start
recording the card version now regardless of which way the pricing rule goes — because until it
does, the immutable-history option keeps getting more expensive every day, and the audit chain keeps
attesting a version number that is a placeholder.

**It is worse than an internal register error: the claim is CUSTOMER-FACING.** `CHANGELOG.md`
presents it among the release's breaking changes as "one where a rate-card edit stops repricing
history it should not touch". So 1.6.0 currently ships a written promise about billing behaviour
that the code does not keep. Whichever way the owner rules, one of the two has to move — either the
endpoint is wired to the dated history, or the changelog entry and register row are retracted. It
cannot ship as it stands.

One further register item, **F-011r**, is stale rather than wrong: its "the `at` field was removed"
claim is false — `3c118f729` restored it and the struct's doc comment records the owner rule as
"RESTORED". Whether it folds into F-011 or is deleted depends on the external oracle tool's class
scoring, so it also carries a note rather than an edit.

### What I did do

Fixed the parse, everywhere, at one seam — `crates/busbar-llm-codec/src/usage_count.rs`,
`read_count_u64`. It tries the integer representation, then accepts a float only when it provably
denotes an exact integer; a fractional value is refused rather than rounded, because rounding
invents a quantity no provider ever reported. It also refuses anything at or above 2^53, where an
`f64` can no longer represent consecutive integers and `fract() == 0.0` stops proving anything.

Applied to Cohere (buffered chat, streaming `message-end`, truncated-tail recovery, embeddings
`billed_units`, rerank `search_units`) and being applied across `anthropic`, `bedrock`, `gemini`,
`openai_chat` and `openai_responses`, which all carry the identical idiom.

I did **not** change the `.unwrap_or(0)` fallback itself. With the parse corrected it now fires only
when a count is genuinely absent or genuinely malformed, not on an encoding difference. That
residual case still silently records zero for possibly-real work, and closing it properly means
threading an "unknown" signal from the codec's `IrUsage` through `TokenUsage` into the ledger's
existing `estimated` convention — a cross-crate change, listed below as an open item rather than
smuggled in here.

### The three questions for the owner

1. ~~Re-record the affected golden cells?~~ **WITHDRAWN — measured moot.** The corpus holds no
   float-encoded count, so nothing needs re-recording and the oracle does not go red. See the
   correction above.

   **Replaced by a sharper question: should the corpus GAIN a float-encoded cell?** Doing so is the
   only way the oracle can ever see this class. But recorded against 1.5.5 that cell captures 1.5.5's
   buggy zero, so 1.6.0 would then legitimately diverge from it — which is the bug becoming visible
   at exactly the layer that should show it, and is a billed-byte difference only you can accept. I
   have NOT added the cell, because adding it manufactures precisely the divergence #10/#59 says I
   may not self-approve. My recommendation: add it, and accept the divergence, because an oracle that
   cannot see the money bug it exists to catch is the real defect here.
2. **Does the under-recording in shipped 1.5.5 need any action toward customers?** Purely yours.
3. **Close the residual silent-zero** by threading `estimated` end-to-end, or accept
   `.unwrap_or(0)` as the standing policy for a genuinely malformed count?

### One process failure to note

The Cohere fix bytes are committed in `1772c74706`, whose subject reads only
`refactor(#41): Encode::ArenaExhausted -> ScratchExhausted`. They were uncommitted in a shared
working tree when that commit ran `git add` and were swept up. The bytes are correct; the audit
trail is not. `1b6c9d4ba` states this on the record. History was not rewritten because other work
was live in the tree — but a billing change sitting inside a rename commit is exactly what an
auditor fails, and the habit that caused it (blanket `git add` with concurrent agents editing) is
the thing to fix, not just this one commit.

## Open items — the next session's worklist

**Verified defects, not yet fixed:**

0. **THE PLUGIN ABI STILL SAYS `arena`, AND THE NAME IS NEW IN 1.6.0 — so the owner's own ruling
   applies.** The `#41` rename was carried out properly *in code*: there is not one `ArenaBudget`,
   `arena_budget` or `ArenaExhausted` left, and the wire value is `"scratch_exhausted"`. But the
   **plugin-facing ABI was not renamed**: `busbar-contract/src/unit.rs:538` exposes
   `pub fn arena(&self) -> &'u dyn PlaneAlloc`, and `arena:` remains a parameter name across
   `spans.rs`, `transport/mod.rs` and `unit.rs`. `ARCHITECTURE.md` still says "`Ctx.arena` is the one
   resource handle."

   This matters more than an ordinary stale name for two reasons:
   - **`busbar-contract` IS the plugin dependency closure (#40)** — it is the surface every plugin
     compiles against. A name here is a published contract, not an internal detail.
   - **It is NEW.** Measured: `git grep -P 'fn arena\b' v1.5.5` returns nothing, and `PlaneAlloc`
     does not exist in v1.5.5 at all. So this is not an inherited name that costs compatibility to
     change — it is a 1.6.0 invention, and the owner's standing ruling covers exactly this case:
     *"this is brand new in 1.6.0 … if its new lets code it clean."*

   Once 1.6.0 ships, every third-party plugin is written against `ctx.arena()`, and a concept the
   architecture has explicitly retired becomes permanent in the contract. The window to fix it for
   free closes at the cut.

   **Not started deliberately.** `arena` appears as an identifier across **113 files**, and the
   rename crosses `busbar-contract`, `busbar-kernel`, the planes and the transports — every area
   currently under concurrent edit. It is mechanical, not subtle, and should run as one sweep on a
   quiet tree, verified by the same `git grep -P` that measured it.



1. **The plain container image could not dlopen a user-supplied plugin — FIXED, but the drop-in
   story is still not whole.** The runtime libs now ship in the plain image, extracted once from the
   already-pinned `rust:alpine` digest and copied in unconditionally, so the fix is a property of
   the image rather than of any plugin. Verified by pulling the pinned image's real bytes from the
   registry and confirming the three extracted files form a CLOSED dependency graph on both arches.
   Docker is not available on this machine, so that is **static proof, not a demonstrated load** —
   a real `docker run` still owes us the runtime confirmation.

   **Two further gaps found while proving it, both still open:**

   - **`/etc/busbar/plugins` does not exist in the image, and is not where the default points.**
     The Dockerfile header and `docker/docker-compose.yml` both tell users to drop a plugin tarball
     there. But `default_plugins_dir()` returns the **relative** `"plugins"`, and with no `WORKDIR`
     set that resolves to **`/plugins`** — a different path. It only becomes real if the user mounts
     a `config.yaml` setting `plugins.dir` explicitly. The documented action and the compiled
     default disagree.
   - **Probable ownership mismatch on the fetch flow.** The image runs as `USER 65532:65532`.
     Nothing in the Dockerfile creates that directory, so Docker auto-creates the named volume at
     start — **root-owned by default**. `appbuild.rs` only `create_dir_all`s it when `plugins.fetch`
     is non-empty, so a plain read-only tarball drop is likely fine, but the documented
     fetch-into-volume recipe probably cannot write. Not proven — it needs a real container run.

   Deliberately not guessed at: `FROM scratch` has no shell, so creating that directory means
   staging one through a `COPY`, and choosing between "make the default absolute" and "fix it in the
   image only" is a behaviour decision I would not want to make blind and unverifiable.

1. ~~**The plain container image cannot dlopen a user-supplied plugin.**~~ `Dockerfile:43-45` copies only
   the binary and two YAMLs into `FROM scratch`, while every plugin cdylib must be built
   `-C target-feature=-crt-static` (aarch64-musl silently drops the cdylib otherwise —
   `docker.yml:554`) and therefore dynamically links musl libc/libgcc_s/libstdc++. Those libs are
   extracted only on the `headroom: true` matrix legs and land in the bundled variant, never in the
   plain image — yet the Dockerfile's own header tells users to drop a tarball into
   `/etc/busbar/plugins`. The bundled variant works; the core image does not. **For a release named
   "Protocols as Plugins" this is a blocker.** Fix must be plugin-agnostic: make the runtime libs a
   property of the image, extracted once from the already-pinned `rust:alpine` digest.
2. **`NANOS_PER_CENT` — mostly fixed; ONE unpinned copy remains.** Measured state, five sites:
   `busbar-kernel-ledger/src/cost/mod.rs:86` is canonical (`pub const … u128`);
   `busbar-kernel-budget/src/price.rs:24` is now a `pub use` of it; `units_voice.rs:163` and
   `units_a2a.rs:1050` keep a deliberate `u64` copy (the fee math must saturate at `u64::MAX`, and
   borrowing the ledger's `u128` would silently move that ceiling on a money path) but are pinned by
   `const _: () = assert!(… == busbar_kernel_ledger::cost::NANOS_PER_CENT)`, so editing either copy
   stops the build.

   The remaining one is **`busbar-kernel/src/cost.rs:58`** — same `u128` type as the canonical, but
   neither imported nor asserted, so it can drift silently. It is used once, at line 745, inside
   `derive_spend_cents`.

   It cannot simply be imported: `busbar-kernel` depends on neither `busbar-kernel-ledger` nor
   `busbar-kernel-budget`. Two ways to close it, both dep-graph changes and therefore not made
   blind — (a) add `busbar-kernel-ledger` to `busbar-kernel` and `pub use`, or (b) move the constant
   to `busbar-contract`, which **both** crates already depend on. (b) is tidier but widens the plugin
   dependency closure (#40), so it is a ruling, not a refactor: `NANOS_PER_CENT` is a unit
   *definition* rather than a price, which is an argument for contract, but #40 is deliberately
   narrow.

   Worth stating plainly, because it reads alarming and is not: `derive_spend_cents` is **the locked
   money model working exactly as specified.** It takes ledger units and a rate card and derives
   cents at read time; it stores nothing. Its own doc notes that a row written under an older card
   derives at the new rate and calls that the designed behaviour — which is precisely "money is a
   view over ledger × ratecard". Its saturation is also correct and deliberately fail-closed: it
   pins at `i64::MAX` rather than `as`-casting, because a wrapping cast would land negative, get
   floored to 0 by `.max(0)`, and let an adversarially large ledger derive as **free** and bypass
   every budget cap.

   Note also that `busbar-kernel/src/cost.rs` performs cents arithmetic but is **not** in
   `no-float-money`'s scan set (that gate scans `busbar-kernel-ledger/src` plus four named binary
   files). The gate is correctly scoped — it guards the money *arithmetic* crate — but it does mean
   this file's integer discipline is unenforced.
3. **`rate_card_version: 0` is hardcoded** at six sites across `units_mcp.rs`, `units_voice.rs` and
   `units_a2a.rs`.

**Known doc/gate drift:**

4. ~~`PLANE-DELETE` enumerates `llm/mcp/a2a/voice`~~ — **FIXED, and now HONESTLY RED.** Retitled to
   the locked five. Because a title change alters no exit code, a new step asserts the locked roster
   has no on-disk gap; it fails today naming `decisions`, which has no on-disk crate to strong-form
   test. That red is correct and must stay until the plane is wired — it is the harness telling the
   truth, not a defect.
5. The neutrality mandate at Part 4's `banned set` line lists
   `llm|mcp|a2a|tool|agent|sampling|task|server|card|round|prompt`, and the gate adds `voice`,
   `realtime` and `audio`. It names no `streaming` token. `streaming` is a plane noun and belongs
   there on the merits, but adding it reds the witness wherever the word appears in a neutral crate,
   so it is a scoped burndown rather than a one-line edit — recorded here rather than slipped in
   quietly. **Do the crate rename first** (`busbar-plane-voice` and `busbar-plane-streaming` both
   exist today; #18 says there is one plane and it is `streaming`), then ban the noun.

   **Ruling made this session — `decision` must NOT go in the ban list.** The `decisions` plane (jev,
   #48) declares the key `plane-decision`, and the witness matches banned nouns case-insensitively as
   *substrings*. Banning `decision` therefore forbids `Decision`, `GateDecision` and `VerifyDecision`
   — the admit/throttle/deny verdict types that *are* the primitive governance taxonomy the plane ABI
   is supposed to be derived from. Measured, not assumed: adding the token red `exported-declarations`
   with 7 findings in `crates/busbar-plugin/src/hot/{host,pod}.rs` plus a blown test-path ratchet,
   every one of them core naming its own verdict rather than a plane leaking. A substring witness
   cannot tell those apart, so the plane key is exempted in writing at
   `PRIMITIVE_COLLISION_KEYS` in `xtask/src/gates/plane_abi_neutrality.rs`, following the existing
   `PLANE_DECL` precedent — the ban list is not loosened and no correct primitive is renamed to dodge
   a grep. A genuine leak of that plane is still caught by `plane-purity` and by the
   `law0-neutral-instance` class, both of which key on the crate edge rather than on a noun.
   **Result: `plane-abi-neutrality` is now 6/6 green; `plane-keys-covered` had been red.**
6. ~~`CONFIG_NOUN_FLOOR=16` vs a comment claiming 19~~ — **BOTH WERE WRONG. The measured number is
   17** (pools 5 · tools 3 · agents 2 · streams 7), stable across three runs. It only became
   measurable once `plane-config-noun-gate.sh`'s `CORE_ROOT` was repointed off the deleted
   `busbar-core`. Floor set to 17 with the measurement, its date and its breakdown recorded in the
   comment, so the next reader does not have to re-derive it.
7. ~~Three done-oracle groups red for harness drift~~ — **ALL THREE RESOLVED, and one turned out to
   be a real upstream gap rather than drift.**
   - **`STORE-QA`** was already repointed to `cargo xtask gate service-images`. Its own selftest
     proves it red-able across 10 failure scenarios; the gate runs 8/8 green.
   - **`KERNEL`'s count of 2 is CORRECT** and is now documented rather than merely tolerated. The
     second match is not a loose filter: it is a deliberate anti-vacuity companion added in the same
     commit as the normalizer it guards, proving the normalizer blanks only measured latency and
     framing bytes and never the frame's content. Without it the normalizer could pass by erasing
     the body and make the identity rig green over nothing.
   - **`TELLER-STEPS` is NOT drift — the capability does not exist anywhere.** `rigs-ledger` is not a
     subcommand of the pinned oracle engine (proven by running it, by `--help`'s fourteen
     subcommands, and by the engine's own `PORT-REMAINING.md` recording it as ported to library
     leaves and never re-exposed as a CLI arm). xtask deliberately has no equivalent either, because
     driving the oracle's rig ledger means RUNNING the oracle's code, which the `segregation` gate
     forbids the gate runner from doing. So the group is now an `absent_step`, red by construction,
     naming the upstream gap in `busbar-release` instead of dying on a cryptic clap error.
8. ~~`oracle-rerecord.yml` hardcodes a stale "current predev tip" SHA~~ — **FIXED upstream.** The
   ref input is now `REQUIRED, no default`, and the reasoning is recorded in the input's own
   description: predev and integration branches are force-updated and pruned, so any hardcoded
   default silently goes stale and eventually unreachable, and a wrong ref re-records the MONEY
   reference golden against the wrong tree while the artifact still claims to be the 1.5.5 golden.

**Deliberate design reversals — do not "restore" these:** `contract-kinds` (an 8-kind proposal;
`PLUGIN-TREE.md` records it as rejected — the answer is 7, per #3) and the unadopted portion of
`rename-wave-execution-map`. Both show up as harvest survivors because their symbols are absent from
trunk. Absent because they were *decided against*, not because they were lost.

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
